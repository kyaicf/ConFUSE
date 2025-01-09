package estargz

import (
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"

	fusefs "github.com/hanwen/go-fuse/v2/fs"
	"golang.org/x/sys/unix"
)

// copy from metadata.reader for assign id
type ReaderWrap struct {
	R      *Reader
	RootID uint32

	IdMap     map[uint32]*TOCEntry
	IdOfEntry map[string]uint32
}

func (r *ReaderWrap) ForeachChild(id uint32, f func(name string, id uint32, mode os.FileMode) bool) error {
	e, ok := r.IdMap[id]
	if !ok {
		return fmt.Errorf("parent entry %d not found", id)
	}
	var err error
	e.ForeachChild(func(baseName string, ent *TOCEntry) bool {
		id, ok := r.IdOfEntry[ent.Name]
		if !ok {
			err = fmt.Errorf("id of child entry %q not found", baseName)
			return false
		}
		return f(baseName, id, ent.Stat().Mode())
	})
	return err
}

func DumpToFile(buffer []byte, path string) error {
	// _, err := os.Stat(path)
	// if os.IsNotExist(err) {
	// 	return err
	// }

	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0664)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = file.Write(buffer)
	if err != nil {
		return err
	}
	return err

}

func ExtractNodeIdAndName(s string) (uint64, string, error) {
	parts := strings.SplitN(s, " ", 2) // 只分割一次
	if len(parts) != 2 {
		return 0, "", fmt.Errorf("input does not contain exactly one space string [%v] ", s)
	}

	num, err := strconv.Atoi(parts[0]) // 将左侧部分转换为整数
	if err != nil {
		return 0, "", fmt.Errorf("failed to convert '%s' to int: %v", parts[0], err)
	}

	varPart := parts[1] // 右侧保持为字符串
	return uint64(num), varPart, nil
}

func (r *ReaderWrap) CollectKeysAndInodes() (res *HashInput, rErr error) {
	hashInput := &HashInput{Keys: make(map[HashKey]fuse.Attr, len(r.IdMap))}

	err := r.collectKeysAndInodes(r.RootID, hashInput)

	return hashInput, err
}

const (
	blockSize         = 4096
	physicalBlockSize = 512
	// physicalBlockRatio is the ratio of blockSize to physicalBlockSize.
	// It can be used to convert from # blockSize-byte blocks to # physicalBlockSize-byte blocks
	physicalBlockRatio = blockSize / physicalBlockSize
)

func FileModeToSystemMode(m os.FileMode) uint32 {
	// Permission bits
	res := uint32(m & os.ModePerm)

	// File type bits
	switch m & os.ModeType {
	case os.ModeDevice:
		res |= syscall.S_IFBLK
	case os.ModeDevice | os.ModeCharDevice:
		res |= syscall.S_IFCHR
	case os.ModeDir:
		res |= syscall.S_IFDIR
	case os.ModeNamedPipe:
		res |= syscall.S_IFIFO
	case os.ModeSymlink:
		res |= syscall.S_IFLNK
	case os.ModeSocket:
		res |= syscall.S_IFSOCK
	default: // regular file.
		res |= syscall.S_IFREG
	}

	// suid, sgid, sticky bits
	if m&os.ModeSetuid != 0 {
		res |= syscall.S_ISUID
	}
	if m&os.ModeSetgid != 0 {
		res |= syscall.S_ISGID
	}
	if m&os.ModeSticky != 0 {
		res |= syscall.S_ISVTX
	}

	return res
}

type Attr struct {
	// Size, for regular files, is the logical size of the file.
	Size int64

	// ModTime is the modification time of the node.
	ModTime time.Time

	// LinkName, for symlinks, is the link target.
	LinkName string

	// Mode is the permission and mode bits.
	Mode os.FileMode

	// UID is the user ID of the owner.
	UID int

	// GID is the group ID of the owner.
	GID int

	// DevMajor is the major device number for device.
	DevMajor int

	// DevMinor is the major device number for device.
	DevMinor int

	// Xattrs are the extended attribute for the node.
	Xattrs map[string][]byte

	// NumLink is the number of names pointing to this node.
	NumLink int

	//  name  to this file.
	Name string

	// Type is one of "dir", "reg", "symlink", "hardlink", "char",
	// "block", "fifo", or "chunk".
	// The "chunk" type is used for regular file data chunks past the first
	// TOCEntry; the 2nd chunk and on have only Type ("chunk"), Offset,
	// ChunkOffset, and ChunkSize populated.
	Type string
}

// entryToAttr converts metadata.Attr to go-fuse's Attr.
func entryToAttr(ino uint64, e Attr, out *fuse.Attr) fusefs.StableAttr {
	out.Ino = ino
	out.Size = uint64(e.Size)
	if e.Mode&os.ModeSymlink != 0 {
		out.Size = uint64(len(e.LinkName))
	}
	out.Blksize = blockSize
	out.Blocks = (out.Size + uint64(out.Blksize) - 1) / uint64(out.Blksize) * physicalBlockRatio
	mtime := e.ModTime
	out.SetTimes(nil, &mtime, nil)
	out.Mode = FileModeToSystemMode(e.Mode)
	out.Owner = fuse.Owner{Uid: uint32(e.UID), Gid: uint32(e.GID)}
	out.Rdev = uint32(unix.Mkdev(uint32(e.DevMajor), uint32(e.DevMinor)))
	out.Nlink = uint32(e.NumLink)
	if out.Nlink == 0 {
		out.Nlink = 1 // zero "NumLink" means one.
	}
	out.Flags = 0 // TODO

	return fusefs.StableAttr{
		Mode: out.Mode,
		Ino:  out.Ino,
		// NOTE: The inode number is unique throughout the lifetime of
		// this filesystem so we don't consider about generation at this
		// moment.
	}
}

func inodeOfID(id uint32) (uint64, error) {
	// 0 is reserved by go-fuse 1 and 2 are reserved by the state dir
	if id > ^uint32(0)-3 {
		return 0, fmt.Errorf("too many inodes")
	}
	return (uint64(0) << 32) | uint64(id), nil
}

func (r *ReaderWrap) collectKeysAndInodes(dirID uint32, hashInput *HashInput) (rErr error) {
	rootID := r.RootID
	r.ForeachChild(dirID, func(name string, id uint32, mode os.FileMode) bool {
		e, err := r.GetAttr(id)
		if err != nil {
			rErr = err
			return false
		}
		if mode.IsDir() {

			out := &fuse.Attr{}
			ino, err := inodeOfID(id)
			if err != nil {
				rErr = err
				return false
			}
			entryToAttr(ino, e, out)
			out.ParentIno = uint64(dirID)

			hashKey := HashKey{NodeId: int32(dirID), Name: name}
			hashInput.Keys[hashKey] = *out

			if err := r.collectKeysAndInodes(id, hashInput); err != nil {
				rErr = err
				return false
			}
			return true
		} else if dirID == rootID && name == TOCTarName ||
			name == NoPrefetchLandmark ||
			name == PrefetchLandmark {

			// We don't need to cache TOC json file
			return true
		}

		// chunk 只需要reg
		if e.Type == "chunk" {
			return true
		}

		out := &fuse.Attr{}
		ino, err := inodeOfID(id)
		if err != nil {
			rErr = err
			return false
		}
		entryToAttr(ino, e, out)
		out.ParentIno = uint64(dirID)
		hashKey := HashKey{NodeId: int32(dirID), Name: name}
		hashInput.Keys[hashKey] = *out

		return true
	})
	return

}

func attrFromTOCEntry(src *TOCEntry, dst *Attr) *Attr {
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
	dst.Name = src.Name
	return dst
}

func (r *ReaderWrap) GetAttr(id uint32) (attr Attr, err error) {

	e, ok := r.IdMap[id]
	if !ok {
		err = fmt.Errorf("entry %d not found", id)
		return
	}
	// TODO: zero copy
	attrFromTOCEntry(e, &attr)
	return
}

func (r *ReaderWrap) GetChild(pid uint32, base string) (id uint32, entry *TOCEntry, err error) {

	e, ok := r.IdMap[pid]
	if !ok {
		err = fmt.Errorf("parent entry %d not found", pid)
		return
	}
	child, ok := e.LookupChild(base)
	if !ok {
		err = fmt.Errorf("child %q of entry %d not found", base, pid)
		return
	}
	cid, ok := r.IdOfEntry[child.Name]
	if !ok {
		err = fmt.Errorf("id of entry %q not found", base)
		return
	}
	entry, ok = r.IdMap[cid]
	if !ok {
		err = fmt.Errorf("child entry %d not found", pid)
		return
	}
	// TODO: zero copy
	// attrFromTOCEntry(child, &attr)
	return cid, entry, nil
}

// assignIDs assigns an to each TOC item and returns a mapping from ID to entry and vice-versa.
func AssignIDs(e *TOCEntry) (rootID uint32, IdMap map[uint32]*TOCEntry, IdOfEntry map[string]uint32, err error) {
	IdMap = make(map[uint32]*TOCEntry)
	IdOfEntry = make(map[string]uint32)
	curID := uint32(0)

	nextID := func() (uint32, error) {
		if curID == math.MaxUint32 {
			return 0, fmt.Errorf("sequence id too large")
		}
		curID++
		return curID, nil
	}

	var mapChildren func(e *TOCEntry) (uint32, error)
	mapChildren = func(e *TOCEntry) (uint32, error) {
		if e.Type == "hardlink" {
			return 0, fmt.Errorf("unexpected type \"hardlink\": this should be replaced to the destination entry")
		}

		var ok bool
		id, ok := IdOfEntry[e.Name]
		if !ok {
			id, err = nextID()
			if err != nil {
				return 0, err
			}
			IdMap[id] = e
			IdOfEntry[e.Name] = id
		}

		e.ForeachChild(func(_ string, ent *TOCEntry) bool {
			ent.ParentIno = uint64(id)
			_, err = mapChildren(ent)
			return err == nil
		})
		if err != nil {
			return 0, err
		}
		return id, nil
	}

	rootID, err = mapChildren(e)
	if err != nil {
		return 0, nil, nil, err
	}
	return rootID, IdMap, IdOfEntry, nil
}
