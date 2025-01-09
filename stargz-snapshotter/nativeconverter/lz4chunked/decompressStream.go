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

package lz4chunked

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strconv"
	"sync"

	"github.com/containerd/containerd/content"
	"github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/images"
	"github.com/containerd/containerd/labels"
	"github.com/containerd/containerd/log"
	"github.com/klauspost/compress/zstd"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pierrec/lz4/v4"
	exec "golang.org/x/sys/execabs"
)

type (
	// Compression is the state represents if compressed or not.
	Compression int
)

const (
	// Uncompressed represents the uncompressed.
	Uncompressed Compression = iota
	// Gzip is gzip compression algorithm.
	Gzip
	// Zstd is zstd compression algorithm.
	Zstd
	Lz4
)

const disablePigzEnv = "CONTAINERD_DISABLE_PIGZ"

var (
	initPigz   sync.Once
	unpigzPath string
)

var (
	bufioReader32KPool = &sync.Pool{
		New: func() interface{} { return bufio.NewReaderSize(nil, 32*1024) },
	}
)

// DecompressReadCloser include the stream after decompress and the compress method detected.
type DecompressReadCloser interface {
	io.ReadCloser
	// GetCompression returns the compress method which is used before decompressing
	GetCompression() Compression
}

type readCloserWrapper struct {
	io.Reader
	compression Compression
	closer      func() error
}

func (r *readCloserWrapper) Close() error {
	if r.closer != nil {
		return r.closer()
	}
	return nil
}

func (r *readCloserWrapper) GetCompression() Compression {
	return r.compression
}

type writeCloserWrapper struct {
	io.Writer
	closer func() error
}

func (w *writeCloserWrapper) Close() error {
	if w.closer != nil {
		w.closer()
	}
	return nil
}

type bufferedReader struct {
	buf *bufio.Reader
}

func newBufferedReader(r io.Reader) *bufferedReader {
	buf := bufioReader32KPool.Get().(*bufio.Reader)
	buf.Reset(r)
	return &bufferedReader{buf}
}

func (r *bufferedReader) Read(p []byte) (n int, err error) {
	if r.buf == nil {
		return 0, io.EOF
	}
	n, err = r.buf.Read(p)
	if err == io.EOF {
		r.buf.Reset(nil)
		bufioReader32KPool.Put(r.buf)
		r.buf = nil
	}
	return
}

func (r *bufferedReader) Peek(n int) ([]byte, error) {
	if r.buf == nil {
		return nil, io.EOF
	}
	return r.buf.Peek(n)
}

const (
	zstdMagicSkippableStart = 0x184D2A50
	zstdMagicSkippableMask  = 0xFFFFFFF0
)

var (
	gzipMagic    = []byte{0x1F, 0x8B, 0x08}
	zstdMagic    = []byte{0x28, 0xb5, 0x2f, 0xfd}
	lz4Magic     = []byte{0x04, 0x22, 0x4d, 0x18}
	lz4SkipMagic = []byte{0x50, 0x2a, 0x4D, 0x18}
)

type matcher = func([]byte) bool

func magicNumberMatcher(m []byte) matcher {
	return func(source []byte) bool {
		return bytes.HasPrefix(source, m)
	}
}

// zstdMatcher detects zstd compression algorithm.
// There are two frame formats defined by Zstandard: Zstandard frames and Skippable frames.
// See https://tools.ietf.org/id/draft-kucherawy-dispatch-zstd-00.html#rfc.section.2 for more details.
func zstdMatcher() matcher {
	return func(source []byte) bool {
		if bytes.HasPrefix(source, zstdMagic) {
			// Zstandard frame
			return true
		}
		// skippable frame
		if len(source) < 8 {
			return false
		}
		// magic number from 0x184D2A50 to 0x184D2A5F.
		if binary.LittleEndian.Uint32(source[:4])&zstdMagicSkippableMask == zstdMagicSkippableStart {
			return true
		}
		return false
	}
}
func lz4Matcher() matcher {
	return func(source []byte) bool {

		ret, err := lz4.ValidFrameHeader(source)
		if err != nil {
			return false
		}
		return ret
	}
}

// DetectCompression detects the compression algorithm of the source.
func DetectCompression(source []byte) Compression {
	for compression, fn := range map[Compression]matcher{
		Gzip: magicNumberMatcher(gzipMagic),
		Lz4:  lz4Matcher(),
		Zstd: zstdMatcher(),
	} {
		if fn(source) {
			return compression
		}
	}
	return Uncompressed
}

// DecompressStream decompresses the archive and returns a ReaderCloser with the decompressed archive.
func DecompressStream(archive io.Reader) (DecompressReadCloser, error) {
	buf := newBufferedReader(archive)
	bs, err := buf.Peek(10)
	if err != nil && err != io.EOF {
		// Note: we'll ignore any io.EOF error because there are some odd
		// cases where the layer.tar file will be empty (zero bytes) and
		// that results in an io.EOF from the Peek() call. So, in those
		// cases we'll just treat it as a non-compressed stream and
		// that means just create an empty layer.
		// See Issue docker/docker#18170
		return nil, err
	}
	switch compression := DetectCompression(bs); compression {
	case Uncompressed:
		return &readCloserWrapper{
			Reader:      buf,
			compression: compression,
		}, nil
	case Gzip:
		ctx, cancel := context.WithCancel(context.Background())
		gzReader, err := gzipDecompress(ctx, buf)
		if err != nil {
			cancel()
			return nil, err
		}

		return &readCloserWrapper{
			Reader:      gzReader,
			compression: compression,
			closer: func() error {
				cancel()
				return gzReader.Close()
			},
		}, nil
	case Zstd:
		zstdReader, err := zstd.NewReader(buf)
		if err != nil {
			return nil, err
		}
		return &readCloserWrapper{
			Reader:      zstdReader,
			compression: compression,
			closer: func() error {
				zstdReader.Close()
				return nil
			},
		}, nil
	case Lz4:
		ctx, cancel := context.WithCancel(context.Background())
		lz4Reader, err := lz4Decompress(ctx, buf)
		if err != nil {
			cancel()
			return nil, err
		}
		// lz4Reader := lz4.NewReader(buf)
		return &readCloserWrapper{
			Reader:      lz4Reader,
			compression: compression,
			closer: func() error {
				cancel()
				// lz4Reader.Reset(nil)
				return nil
			},
		}, nil

	default:
		fmt.Println("Uncompressed compression")
		return nil, fmt.Errorf("unsupported compression format %s", (&compression).Extension())
	}
}

// CompressStream compresses the dest with specified compression algorithm.
func CompressStream(dest io.Writer, compression Compression) (io.WriteCloser, error) {
	switch compression {
	case Uncompressed:
		return &writeCloserWrapper{dest, nil}, nil
	case Gzip:
		return gzip.NewWriter(dest), nil
	case Zstd:
		return zstd.NewWriter(dest)
	default:
		return nil, fmt.Errorf("unsupported compression format %s", (&compression).Extension())
	}
}

// Extension returns the extension of a file that uses the specified compression algorithm.
func (compression *Compression) Extension() string {
	switch *compression {
	case Gzip:
		return "gz"
	case Zstd:
		return "zst"
	}
	return ""
}

func gzipDecompress(ctx context.Context, buf io.Reader) (io.ReadCloser, error) {
	initPigz.Do(func() {
		if unpigzPath = detectPigz(); unpigzPath != "" {
			log.L.Debug("using pigz for decompression")
		}
	})

	if unpigzPath == "" {
		return gzip.NewReader(buf)
	}

	return cmdStream(exec.CommandContext(ctx, unpigzPath, "-d", "-c"), buf)
}

func lz4Decompress(ctx context.Context, buf io.Reader) (io.ReadCloser, error) {
	path, err := exec.LookPath("lz4c")
	if err != nil {
		return nil, fmt.Errorf("Lz4 decompress %v", err)
	}
	return cmdStream(exec.CommandContext(ctx, path, "-d", "-c"), buf)
}

func cmdStream(cmd *exec.Cmd, in io.Reader) (io.ReadCloser, error) {
	reader, writer := io.Pipe()

	cmd.Stdin = in
	cmd.Stdout = writer

	var errBuf bytes.Buffer
	cmd.Stderr = &errBuf

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	go func() {
		if err := cmd.Wait(); err != nil {
			writer.CloseWithError(fmt.Errorf("%s: %s", err, errBuf.String()))
		} else {
			writer.Close()
		}
	}()

	return reader, nil
}

func detectPigz() string {
	path, err := exec.LookPath("unpigz")
	if err != nil {
		log.L.WithError(err).Debug("unpigz not found, falling back to go gzip")
		return ""
	}

	// Check if pigz disabled via CONTAINERD_DISABLE_PIGZ env variable
	value := os.Getenv(disablePigzEnv)
	if value == "" {
		return path
	}

	disable, err := strconv.ParseBool(value)
	if err != nil {
		log.L.WithError(err).Warnf("could not parse %s: %s", disablePigzEnv, value)
		return path
	}

	if disable {
		return ""
	}

	return path
}

func IsUncompressedType(mt string) bool {
	switch mt {
	case
		images.MediaTypeDockerSchema2Layer,
		images.MediaTypeDockerSchema2LayerForeign,
		ocispec.MediaTypeImageLayer,
		ocispec.MediaTypeImageLayerNonDistributable:
		return true
	default:
		return false
	}
}

// Media type is changed, e.g., "application/vnd.oci.image.layer.v1.tar+gzip" -> "application/vnd.oci.image.layer.v1.tar"
func LayerConvertFunc(ctx context.Context, cs content.Store, desc ocispec.Descriptor) (*ocispec.Descriptor, error) {
	if !images.IsLayerType(desc.MediaType) || IsUncompressedType(desc.MediaType) {
		// No conversion. No need to return an error here.
		return nil, nil
	}
	info, err := cs.Info(ctx, desc.Digest)
	if err != nil {
		return nil, err
	}
	readerAt, err := cs.ReaderAt(ctx, desc)
	if err != nil {
		return nil, err
	}
	defer readerAt.Close()
	sr := io.NewSectionReader(readerAt, 0, desc.Size)
	newR, err := DecompressStream(sr)
	if err != nil {
		return nil, err
	}
	defer newR.Close()
	ref := fmt.Sprintf("convert-uncompress-from-%s", desc.Digest)
	w, err := content.OpenWriter(ctx, cs, content.WithRef(ref))
	if err != nil {
		return nil, err
	}
	defer w.Close()

	// Reset the writing position
	// Old writer possibly remains without aborted
	// (e.g. conversion interrupted by a signal)
	if err := w.Truncate(0); err != nil {
		return nil, err
	}

	n, err := io.Copy(w, newR)
	if err != nil {
		return nil, err
	}
	if err := newR.Close(); err != nil {
		return nil, err
	}
	// no need to retain "containerd.io/uncompressed" label, but retain other labels ("containerd.io/distribution.source.*")
	labelsMap := info.Labels
	delete(labelsMap, labels.LabelUncompressed)
	if err = w.Commit(ctx, 0, "", content.WithLabels(labelsMap)); err != nil && !errdefs.IsAlreadyExists(err) {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	newDesc := desc
	newDesc.Digest = w.Digest()
	newDesc.Size = n
	newDesc.MediaType = convertMediaType(newDesc.MediaType)
	return &newDesc, nil
}
