/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package memory

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/containerd/log"
	"github.com/containerd/stargz-snapshotter/estargz"
	"github.com/containerd/stargz-snapshotter/metadata"
	"github.com/hanwen/go-fuse/v2/fuse"
	digest "github.com/opencontainers/go-digest"
)

type reader struct {
	isReady   bool
	isReadyMu sync.Mutex

	cond *sync.Cond

	r      *estargz.Reader
	rootID uint32

	idMap     map[uint32]*estargz.TOCEntry
	idOfEntry map[string]uint32

	estargzOpts []estargz.OpenOption
}

func newReader(er *estargz.Reader, rootID uint32, idMap map[uint32]*estargz.TOCEntry, idOfEntry map[string]uint32, estargzOpts []estargz.OpenOption) *reader {
	return &reader{r: er, rootID: rootID, idMap: idMap, idOfEntry: idOfEntry, estargzOpts: estargzOpts}
}

func NewReader(sr *io.SectionReader, async bool, opts ...metadata.Option) (metadata.Reader, error) {
	r := &reader{rootID: fuse.FUSE_ROOT_ID, isReady: false, cond: sync.NewCond(&sync.Mutex{})}

	if async {
		log.G(context.Background()).Debugf("async init toc reader \n")
		r.asyncInit(sr, opts...)
		return r, nil
	}
	return r, r.init(sr, opts...)
}

func (r *reader) init(sr *io.SectionReader, opts ...metadata.Option) error {
	var rOpts metadata.Options

	for _, o := range opts {
		if err := o(&rOpts); err != nil {
			return fmt.Errorf("failed to apply option: %w", err)
		}
	}

	telemetry := &estargz.Telemetry{}
	if rOpts.Telemetry != nil {
		telemetry.GetFooterLatency = estargz.MeasureLatencyHook(rOpts.Telemetry.GetFooterLatency)
		telemetry.GetTocLatency = estargz.MeasureLatencyHook(rOpts.Telemetry.GetTocLatency)
		telemetry.DeserializeTocLatency = estargz.MeasureLatencyHook(rOpts.Telemetry.DeserializeTocLatency)
	}
	var decompressors []estargz.Decompressor
	for _, d := range rOpts.Decompressors {
		decompressors = append(decompressors, d)
	}

	erOpts := []estargz.OpenOption{
		estargz.WithTOCOffset(rOpts.TOCOffset),
		estargz.WithTelemetry(telemetry),
		estargz.WithDecompressors(decompressors...),
	}

	er, err := estargz.Open(sr, erOpts...)
	if err != nil {
		return err
	}

	root, ok := er.Lookup("")
	if !ok {
		return err
	}
	rootID, idMap, idOfEntry, err := estargz.AssignIDs(root)
	if err != nil {
		return err
	}

	r.r = er
	r.idMap = idMap
	r.rootID = rootID
	r.idOfEntry = idOfEntry

	r.setReady()
	return err
}

func (r *reader) asyncInit(sr *io.SectionReader, opts ...metadata.Option) chan error {
	errChan := make(chan error, 1)

	go func() {
		//debug
		defer func(t chan error) {
			err := <-errChan
			if err != nil {
				panic(fmt.Sprintf("async init reader err %v", err))
			}
		}(errChan)

		err := r.init(sr, opts...)
		errChan <- err
	}()

	return errChan
}

func (r *reader) TocMetadata() ([]byte, []byte, error) {
	if err := r.WaitReady(); err != nil {
		return nil, nil, err
	}
	toc, ktoc := r.r.KernelToc()

	tocJSON, err := json.Marshal(toc)
	if err != nil {
		return nil, nil, err
	}

	if ktoc == nil {
		return tocJSON, []byte{}, err
	}

	buff, err := ktoc.DumpToBuffer()
	if err != nil {
		fmt.Println(err)
		return tocJSON, []byte{}, err
	}
	return tocJSON, buff.Bytes(), err
}

func (r *reader) RootID() uint32 {
	return r.rootID
}

func (r *reader) TOCDigest() digest.Digest {
	r.WaitReady()
	return r.r.TOCDigest()
}

// setReady 安全地设置 ready 状态并通知所有等待的 goroutine
func (r *reader) setReady() {

	r.isReadyMu.Lock()
	r.isReady = true
	r.isReadyMu.Unlock()
	r.cond.Broadcast() // 唤醒所有等待的 goroutine

}

// WaitReady 阻塞直到 reader 的 ready 字段为 true
func (r *reader) WaitReady() error {
	timeout := time.Duration(10 * time.Second)
	wait := func() <-chan struct{} {
		ch := make(chan struct{})
		go func() {
			r.isReadyMu.Lock()
			isReady := r.isReady
			r.isReadyMu.Unlock()

			r.cond.L.Lock()
			if !isReady {
				r.cond.Wait()
			}
			r.cond.L.Unlock()
			ch <- struct{}{}
		}()
		return ch
	}

	select {
	case <-time.After(timeout):
		r.isReadyMu.Lock()
		r.isReady = true
		r.isReadyMu.Unlock()
		r.cond.Broadcast()
		return fmt.Errorf("timeout(%v)", timeout)
	case <-wait():
		return nil
	}

}

func (r *reader) GetOffset(id uint32) (offset int64, err error) {
	if err := r.WaitReady(); err != nil {
		return 0, err
	}
	e, ok := r.idMap[id]
	if !ok {
		return 0, fmt.Errorf("entry %d not found", id)
	}
	return e.Offset, nil
}

func (r *reader) GetAttr(id uint32) (attr metadata.Attr, err error) {
	if err = r.WaitReady(); err != nil {
		return
	}

	e, ok := r.idMap[id]
	if !ok {
		err = fmt.Errorf("entry %d not found", id)
		return
	}
	// TODO: zero copy
	attrFromTOCEntry(e, &attr)
	return
}

func (r *reader) GetChild(pid uint32, base string) (id uint32, attr metadata.Attr, err error) {
	if err = r.WaitReady(); err != nil {
		return
	}

	e, ok := r.idMap[pid]
	if !ok {
		err = fmt.Errorf("parent entry %d not found", pid)
		return
	}
	child, ok := e.LookupChild(base)
	if !ok {
		err = fmt.Errorf("child %q of entry %d not found", base, pid)
		return
	}
	cid, ok := r.idOfEntry[child.Name]
	if !ok {
		err = fmt.Errorf("id of entry %q not found", base)
		return
	}
	// TODO: zero copy
	attrFromTOCEntry(child, &attr)
	return cid, attr, nil
}

func (r *reader) ForeachChild(id uint32, f func(name string, id uint32, mode os.FileMode) bool) error {
	if err := r.WaitReady(); err != nil {
		return fmt.Errorf("reader ForeachChild %v ", err)
	}
	e, ok := r.idMap[id]
	if !ok {
		return fmt.Errorf("parent entry %d not found len idMap %v", id, len(r.idMap))
	}
	var err error
	e.ForeachChild(func(baseName string, ent *estargz.TOCEntry) bool {
		id, ok := r.idOfEntry[ent.Name]
		if !ok {
			err = fmt.Errorf("id of child entry %q not found", baseName)
			return false
		}
		return f(baseName, id, ent.Stat().Mode())
	})
	return err
}

func (r *reader) GetParentId(id uint32) (uint32, error) {
	if id == r.rootID {
		return uint32(fuse.FUSE_ROOT_ID), nil
	}

	if err := r.WaitReady(); err != nil {
		return 0, err
	}

	e, ok := r.idMap[id]
	if !ok {
		return 0, fmt.Errorf("entry %d not found", id)
	}

	if e.ParentIno > 0 {
		return uint32(e.ParentIno), nil
	}

	return 0, fmt.Errorf("entry %d not found", id)

}
func (r *reader) OpenFile(id uint32) (metadata.File, error) {
	r.WaitReady()
	e, ok := r.idMap[id]
	if !ok {
		return nil, fmt.Errorf("entry %d not found", id)
	}
	sr, err := r.r.OpenFile(e.Name)
	if err != nil {
		return nil, err
	}
	return &file{r, e, sr}, nil
}

func (r *reader) GetFileName(id uint32) (string, error) {
	r.WaitReady()
	e, ok := r.idMap[id]
	if !ok {
		return "", fmt.Errorf("entry %d not found", id)
	}

	return e.Name, nil
}

func (r *reader) OpenFileWithPreReader(id uint32, preRead func(id uint32, chunkOffset, chunkSize int64, chunkDigest string, r io.Reader) error) (metadata.File, error) {
	r.WaitReady()
	e, ok := r.idMap[id]
	if !ok {
		return nil, fmt.Errorf("entry %d not found", id)
	}
	sr, err := r.r.OpenFileWithPreReader(e.Name, func(e *estargz.TOCEntry, chunkR io.Reader) error {
		cid, ok := r.idOfEntry[e.Name]
		if !ok {
			return fmt.Errorf("id of entry %q not found", e.Name)
		}
		return preRead(cid, e.ChunkOffset, e.ChunkSize, e.ChunkDigest, chunkR)
	})
	if err != nil {
		return nil, err
	}
	return &file{r, e, sr}, nil
}

func (r *reader) Clone(sr *io.SectionReader) (metadata.Reader, error) {
	er, err := estargz.Open(sr, r.estargzOpts...)
	if err != nil {
		return nil, err
	}

	return newReader(er, r.rootID, r.idMap, r.idOfEntry, r.estargzOpts), nil
}

func (r *reader) Close() error {
	return nil
}

type file struct {
	r  *reader
	e  *estargz.TOCEntry
	sr *io.SectionReader
}

func (r *file) ChunkEntryForOffset(offset int64) (off int64, size int64, dgst string, ok bool) {
	e, ok := r.r.r.ChunkEntryForOffset(r.e.Name, offset)
	if !ok {
		return 0, 0, "", false
	}
	dgst = e.Digest
	if e.ChunkDigest != "" {
		// NOTE* "reg" also can contain ChunkDigest (e.g. when "reg" is the first entry of
		// chunked file)
		dgst = e.ChunkDigest
	}
	return e.ChunkOffset, e.ChunkSize, dgst, true
}

func (r *file) ReadAt(p []byte, off int64) (n int, err error) {
	return r.sr.ReadAt(p, off)
}

func (r *reader) NumOfNodes() (i int, _ error) {
	r.WaitReady()
	return len(r.idMap), nil
}

// TODO: share it with db pkg
func attrFromTOCEntry(src *estargz.TOCEntry, dst *metadata.Attr) *metadata.Attr {
	dst.Size = src.Size
	dst.ModTime, _ = time.Parse(time.RFC3339, src.ModTime3339)
	dst.LinkName = src.LinkName
	dst.Mode = src.Stat().Mode()
	dst.UID = src.UID
	dst.GID = src.GID
	dst.DevMajor = src.DevMajor
	dst.DevMinor = src.DevMinor
	dst.Xattrs = src.Xattrs
	dst.NumLink = src.NumLink
	dst.Type = src.Type
	return dst
}
