package passthrough

import (
	"context"
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"github.com/containerd/containerd/log"
)

type FuseBackingMap struct {
	Fd          int32
	Flags       uint32
	NrIntervals uint32
	Padding     uint32
	Intervals   *FuseBackingInterval
}
type FuseBackingInterval struct {
	Start uint32
	Last  uint32
}
type FuseBackingIntervalSet struct {
	BackingId   uint32
	NrIntervals uint32
	Intervals   *FuseBackingInterval
}

const (
	IocNone              = 0x0
	IocWrite             = 0x1
	IocRead              = 0x2
	IocDirshift          = (IocSizeShift + IocSizeBits)
	IocSizeShift         = (IocTypeShift + IocTypeBits)
	IocSizeBits          = 14
	IocTypeShift         = (IocNrShift + IocNrBits)
	IocTypeBits          = 8
	IocNrBits            = 8
	IocNrShift           = 0
	FUSE_BACKING_PARTIAL = (1 << 0)
)

var PageSize = os.Getpagesize()

func IOWR(t, nr, size uintptr) uintptr {
	return IOC(IocRead|IocWrite, t, nr, size)
}
func IOR(t, nr, size uintptr) uintptr {
	return IOC(IocRead, t, nr, size)
}
func IOW(t, nr, size uintptr) uintptr {
	return IOC(IocWrite, t, nr, size)
}
func IOC(dir, t, nr, size uintptr) uintptr {
	return (dir << IocDirshift) | (t << IocTypeShift) | (nr << IocNrShift) | (size << IocSizeShift)
}

const (
	FUSE_DEV_IOC_MAGIC = 229
)

var FUSE_DEV_IOC_CLONE uintptr = IOR((FUSE_DEV_IOC_MAGIC), 0, unsafe.Sizeof(uint32(0)))
var FUSE_DEV_IOC_BACKING_OPEN uintptr = IOW((FUSE_DEV_IOC_MAGIC), 1, unsafe.Sizeof(FuseBackingMap{}))
var FUSE_DEV_IOC_BACKING_CLOSE uintptr = IOW((FUSE_DEV_IOC_MAGIC), 2, unsafe.Sizeof(uint32(0)))
var FUSE_DEV_IOC_BACKING_INTERVALS_SET uintptr = IOW((FUSE_DEV_IOC_MAGIC), 3, unsafe.Sizeof(FuseBackingIntervalSet{}))
var FUSE_DEV_IOC_METADATA_SET uintptr = IOW((FUSE_DEV_IOC_MAGIC), 4, unsafe.Sizeof(uint32(0)))

func IOCTL(fd uintptr, cmd uintptr, arg uintptr) (int32, syscall.Errno) {
	r0, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, cmd, arg)
	val := int32(r0)
	return val, errno
}
func SetBackingIntervals(mountFd int, backingId uint32, intervals []FuseBackingInterval) error {
	nrIntervals := uint32(len(intervals))
	set := FuseBackingIntervalSet{
		BackingId:   backingId,
		NrIntervals: nrIntervals,
	}
	if nrIntervals > 0 {
		set.Intervals = (*FuseBackingInterval)(unsafe.Pointer(&intervals[0]))
	} else {
		set.Intervals = nil
	}
	log.G(context.Background()).Infof("SetBackingIntervals id: %d, nr: %d, intervals: %v", backingId, len(intervals), intervals)
	_, errno := IOCTL(uintptr(mountFd), FUSE_DEV_IOC_BACKING_INTERVALS_SET, uintptr(unsafe.Pointer(&set)))
	if errno != 0 {
		return fmt.Errorf("FUSE_DEV_IOC_BACKING_INTERVALS_SET failed: %v", errno)
	}
	return nil
}
func OpenBacking(mountFd int, fd int32, isPartial bool, intervals []FuseBackingInterval) (uint32, error) {
	nrIntervals := uint32(len(intervals))
	fbMap := FuseBackingMap{
		Fd:          fd,
		NrIntervals: nrIntervals,
	}
	if nrIntervals > 0 {
		fbMap.Intervals = (*FuseBackingInterval)(unsafe.Pointer(&intervals[0]))
	} else {
		fbMap.Intervals = nil
	}
	if isPartial {
		fbMap.Flags |= FUSE_BACKING_PARTIAL
	}
	log.G(context.Background()).Infof("OpenBacking fd: %d, flags: %d, nr: %d, intervals: %v", fd, fbMap.Flags, len(intervals), intervals)
	id, errno := IOCTL(uintptr(mountFd), FUSE_DEV_IOC_BACKING_OPEN, uintptr(unsafe.Pointer(&fbMap)))
	if errno != 0 {
		return 0, fmt.Errorf("FUSE_DEV_IOC_BACKING_OPEN failed: %v", errno)
	}
	return uint32(id), nil
}

func CloseBacking(mountFd int, backingId uint32) error {
	log.G(context.Background()).Infof("CloseBacking id: %d", backingId)
	_, errno := IOCTL(uintptr(mountFd), FUSE_DEV_IOC_BACKING_CLOSE, uintptr(unsafe.Pointer(&backingId)))
	if errno != 0 {
		return fmt.Errorf("FUSE_DEV_IOC_BACKING_CLOSE failed: %v", errno)
	}
	return nil
}

func SetTocMeta(mountFd int, fd int32) error {
	_, errno := IOCTL(uintptr(mountFd), FUSE_DEV_IOC_METADATA_SET, uintptr(unsafe.Pointer(&fd)))
	if errno != 0 {
		return fmt.Errorf("FUSE_DEV_IOC_METADATA_SET failed: %v", errno)
	}
	return nil
}
