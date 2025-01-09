package reader

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"runtime/trace"
	"sort"
	"sync"
	"time"

	"github.com/containerd/log"
	// "github.com/containerd/stargz-snapshotter/cache"

	"github.com/containerd/stargz-snapshotter/fs/config"
	"github.com/containerd/stargz-snapshotter/fs/passthrough"
	"github.com/containerd/stargz-snapshotter/metadata"
	"github.com/panjf2000/ants/v2"
)

var BackingFileSizeThreshold = int64(0)

const (
	backingMetaSuffix           = ".meta"
	tocMetaSuffix               = ".tocMeta"
	lockSuffix                  = ".lock"
	defaultNonBlockPoolCapacity = 300

	defaultPrefetchCacheCapacity = 100
)

var (
	BFDb *BackFileDb
	once sync.Once
)

type TaskArgs struct {
	layer string
	name  string
	attr  metadata.Attr

	db *BackFileDb

	offset  int64
	data    []byte
	created int64
}

type BackFileDb struct {
	ctx          context.Context
	Cfg          config.FuseConfig
	pool         *ants.Pool
	nonBlockPool *ants.Pool

	bfMutexs     sync.Map
	backingFiles sync.Map
	mountFds     sync.Map
}

func GetBackFileDb(cfg config.FuseConfig) (*BackFileDb, error) {
	var err error
	once.Do(func() {
		BFDb = &BackFileDb{
			ctx: context.Background(),
		}

		if !cfg.Passthrough {
			BFDb.Cfg = cfg
			return
		}

		BackingFileSizeThreshold = cfg.BackingFileSizeThreshold

		if cfg.BackingfileStorageDir == "" {
			panic(fmt.Errorf("backingfile StorageDir is nil"))
		}

		if _, err := os.Stat(cfg.BackingfileStorageDir); os.IsNotExist(err) {
			err := os.MkdirAll(cfg.BackingfileStorageDir, os.ModePerm)
			if err != nil {
				panic(fmt.Errorf("open backingfile db  %v ", err))
			}
		}

		BFDb.Cfg = cfg
		BFDb.pool, err = ants.NewPool(100,
			ants.WithPreAlloc(true),
			ants.WithExpiryDuration(10*time.Second))

		nonBlockPoolCapacity := cfg.NonBlockPoolCapacity
		if nonBlockPoolCapacity == 0 {
			nonBlockPoolCapacity = defaultNonBlockPoolCapacity
		}

		BFDb.nonBlockPool, err = ants.NewPool(nonBlockPoolCapacity,
			ants.WithPreAlloc(true),
			ants.WithNonblocking(true),
			ants.WithExpiryDuration(10*time.Second))

		if err != nil {
			panic(fmt.Errorf("open backingfile db  %v ", err))
		}
	})

	return BFDb, err
}

func (db *BackFileDb) SetMountFd(layer string, mountFd int) {
	//all stargz store images share same fuse
	if db.Cfg.StargzStoreMode {
		db.mountFds.Store("stargz-store", mountFd)
	} else {
		db.mountFds.Store(layer, mountFd)
	}

}

func (db *BackFileDb) GetMountFd(layer string) int {
	if db.Cfg.StargzStoreMode {
		mountFd, ok := db.mountFds.Load("stargz-store")
		if !ok {
			return 0
		}
		return mountFd.(int)

	}
	mountFd, ok := db.mountFds.Load(layer)
	if !ok {
		return 0
	}
	return mountFd.(int)
}

func (db *BackFileDb) Lock(layer, filename string) *sync.RWMutex {
	musI, _ := db.bfMutexs.LoadOrStore(layer, &sync.Map{})
	mus := musI.(*sync.Map)
	muI, _ := mus.LoadOrStore(filename, &sync.RWMutex{})
	mu := muI.(*sync.RWMutex)

	mu.Lock()
	return mu
}

func (db *BackFileDb) RLock(layer, filename string) *sync.RWMutex {
	musI, _ := db.bfMutexs.LoadOrStore(layer, &sync.Map{})
	mus := musI.(*sync.Map)
	muI, _ := mus.LoadOrStore(filename, &sync.RWMutex{})
	mu := muI.(*sync.RWMutex)

	mu.RLock()
	return mu
}

func (db *BackFileDb) GetBackFile(layer, filename string) (*BackingFile, error) {
	if !db.Cfg.Passthrough {
		return nil, fmt.Errorf("backfiles db is nil")
	}

	mu := db.Lock(layer, filename)
	defer mu.Unlock()

	// from cache
	bfsI, _ := db.backingFiles.LoadOrStore(layer, &sync.Map{})
	bfs := bfsI.(*sync.Map)
	bfI, ok := bfs.Load(filename)
	if ok {
		bf := bfI.(*BackingFile)
		return bf, nil
	}

	// from file
	storagePath := path.Join(db.Cfg.BackingfileStorageDir, layer, filename)
	bf, err := loadBackingFile(storagePath)
	if err == nil {
		bf.mu = mu
		bfs.Store(filename, bf)
		return bf, nil
	}

	if !os.IsNotExist(err) {
		return nil, err
	}

	// new backing file
	bf = &BackingFile{
		backingFileInfo:      backingFileInfo{Filename: filename, Intervals: []Interval{}, StoragePath: storagePath},
		Id:                   0,
		generation:           0,
		persistentGeneration: 0,
		mu:                   mu,
		isPartial:            true,
	}
	bfs.Store(filename, bf)
	return bf, nil
}

type BackingFile struct {
	backingFileInfo
	Id                   uint32
	isPartial            bool
	generation           uint64
	persistentGeneration uint64
	mu                   *sync.RWMutex
	persistentTimer      *time.Timer
	updateToKernelTimer  *time.Timer
}

func loadBackingFile(storagePath string) (bf *BackingFile, err error) {
	file, err := os.Open(storagePath + backingMetaSuffix)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	bf = &BackingFile{Id: 0, generation: 0, persistentGeneration: 0}
	err = json.NewDecoder(file).Decode(&bf.backingFileInfo)
	bf.isPartial = !bf.Completed
	return bf, err
}

func (bf *BackingFile) remove() (err error) {
	if bf.persistentTimer != nil {
		bf.persistentTimer.Stop()
	}
	if bf.updateToKernelTimer != nil {
		bf.updateToKernelTimer.Stop()
	}

	err = os.Remove(bf.StoragePath + backingMetaSuffix)
	if err != nil {
		return err
	}
	return os.Remove(bf.StoragePath)
}

func (bf *BackingFile) Persistent(ctx context.Context) {
	if bf.persistentTimer != nil {
		return
	}
	bf.persistentTimer = time.AfterFunc(30*time.Second, func() {
		bf.mu.RLock()
		defer bf.mu.RUnlock()

		log.G(ctx).Infof("file %s persistent meta", bf.Filename)

		err := bf.persistent()
		if err == nil {
			bf.persistentGeneration = bf.generation
		} else {
			log.G(ctx).Warningf("file %s persistent meta failed: %v", bf.Filename, err)
		}

		bf.persistentTimer = nil
	})
}

func (bf *BackingFile) UpdateToKernel(ctx context.Context, mountFd int) {
	if bf.updateToKernelTimer != nil {
		return
	}
	bf.updateToKernelTimer = time.AfterFunc(200*time.Millisecond, func() {
		bf.mu.RLock()
		defer bf.mu.RUnlock()

		log.G(ctx).Infof("file %s  update intervals to kernel", bf.Filename)

		var err error = nil
		if bf.Id > 0 && mountFd > 0 {
			if bf.Completed {
				err = passthrough.SetBackingIntervals(mountFd, bf.Id, []passthrough.FuseBackingInterval{{Start: 0, Last: 4294967295}})
			} else {
				err = passthrough.SetBackingIntervals(mountFd, bf.Id, bf.ExportInterval())
			}
		}
		if err != nil {
			log.G(ctx).Warningf("file %s update intervals to kernel failed: %v", bf.Filename, err)
		}

		bf.updateToKernelTimer = nil
	})
}

func WriteToBackingfile(task *TaskArgs) {
	bf, err := task.db.GetBackFile(task.layer, task.name)
	if err != nil {
		log.G(task.db.ctx).Errorf("WriteToBackingfile failed: %v", err)
		return
	}

	bf.mu.Lock()
	defer bf.mu.Unlock()

	if bf.Contains(task.offset, task.offset+int64(len(task.data))-1) {
		mountFd := task.db.GetMountFd(task.layer)
		if bf.Id > 0 && mountFd > 0 {
			bf.UpdateToKernel(task.db.ctx, mountFd)
		}
		return
	}

	err = createLocalBackingfile(bf.StoragePath, task.attr)
	if err != nil {
		log.G(task.db.ctx).Errorf("WriteToBackingfile.createLocalBackingfile: %v \n", err)
		return
	}

	n, err := writeLocalBackingfile(bf.StoragePath, task.data, task.offset)
	if err != nil {
		log.G(task.db.ctx).Errorf("WriteToBackingfile.writeLocalBackingfile: %v\n ", err)
		return
	}

	if n != len(task.data) {
		log.G(task.db.ctx).Warnf("WriteToBackingfile.writeLocalBackingfile:  %v  missing %v bytes write\n", bf.StoragePath, len(task.data)-n)
	}

	log.G(task.db.ctx).Infof("add interval: %v, size: %d, file: %s", Interval{Start: task.offset, End: task.offset + int64(n) - 1}, task.attr.Size, bf.StoragePath)

	bf.AddInterval(Interval{Start: task.offset, End: task.offset + int64(n) - 1})

	if bf.Contains(0, task.attr.Size-1) {
		bf.Completed = true
	}

	bf.Persistent(task.db.ctx)
	mountFd := task.db.GetMountFd(task.layer)
	if bf.Id > 0 && mountFd > 0 {
		bf.UpdateToKernel(task.db.ctx, mountFd)
	}

}

func SubmitTask(db *BackFileDb, task *TaskArgs, nonBlock bool) error {
	if db == nil || !db.Cfg.Passthrough {
		return nil
	}
	taskFunc := func() {
		task.db = db
		WriteToBackingfile(task)

	}

	if nonBlock {
		return db.nonBlockPool.Submit(taskFunc)
	} else {
		return db.pool.Submit(taskFunc)
	}

}

type backingFileInfo struct {
	Filename    string
	Intervals   []Interval `json:"Intervals"`
	Completed   bool
	StoragePath string
}

func (bfi *backingFileInfo) persistent() (err error) {
	err = ensureDirExist(bfi.StoragePath)
	if err != nil {
		return err
	}

	jsonBytes, err := json.MarshalIndent(bfi, "", "    ")
	if err != nil {
		return err
	}

	file, err := os.OpenFile(bfi.StoragePath+backingMetaSuffix, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0664)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.Write(jsonBytes)
	return err
}

type Interval struct {
	Start int64 `json:"start"`
	End   int64 `json:"end"`
}

// 内核backing file interval
type FuseBackingInterval struct {
	Start   uint32
	Last    uint32
	Created int64
}

func (b *BackingFile) Contains(start int64, end int64) bool {
	if b.Intervals == nil {
		b.Intervals = []Interval{}
		return false
	}
	return Contains(b.Intervals, Interval{Start: start, End: end})
}

func (b *BackingFile) AddInterval(interval Interval) {
	if b.Intervals == nil {
		b.Intervals = []Interval{}
	}

	b.Intervals = Merge(append(b.Intervals, interval))
	b.generation++
}

func (bf *BackingFile) ExportInterval() []passthrough.FuseBackingInterval {

	export := []passthrough.FuseBackingInterval{}
	PageSize := os.Getpagesize()
	for _, invFrom := range bf.Intervals {
		var invTo passthrough.FuseBackingInterval
		needAdd := invFrom.Start % int64(PageSize)
		if needAdd > 0 {
			invTo.Start = uint32((int(invFrom.Start)/PageSize + 1))
		} else {
			invTo.Start = uint32((int(invFrom.Start) / PageSize))
		}

		invTo.Last = uint32(int(invFrom.End) / PageSize)

		if invTo.Last < invTo.Start {
			continue
		}
		if invTo.Last == invTo.Start {
			if invFrom.End-invFrom.Start >= int64(PageSize) {
				export = append(export, invTo)
			}
			continue
		}
		export = append(export, invTo)
	}

	return export

}

func Contains(intervals []Interval, interval Interval) bool {
	if intervals == nil {
		return false
	}
	for _, inner := range intervals {
		if inner.Start <= interval.Start && inner.End >= interval.End {
			return true
		}

		if inner.Start > interval.End {
			return false
		}
	}
	return false
}

func Merge(intervals []Interval) []Interval {
	results := []*Interval{}
	form := []Interval{}
	if len(intervals) == 0 {
		return form
	}
	if len(intervals) == 1 {
		// results = append(results, &intervals[0])
		form = append(form, intervals[0])
		return form
	}

	sort.Slice(intervals, func(i, j int) bool { return intervals[i].Start <= intervals[j].Start })

	results = append(results, &intervals[0])

	for i := 1; i < len(intervals); i++ {
		curr := intervals[i]
		last := results[len(results)-1]
		if curr.Start <= last.End+1 {
			last.End = max(curr.End, last.End)

		} else {
			results = append(results, &curr)
		}
	}
	for _, in := range results {
		form = append(form, *in)
	}
	return form
}

func ensureDirExist(path string) error {
	dirPath := filepath.Dir(path)
	if _, err := os.Stat(dirPath); os.IsNotExist(err) {
		err := os.MkdirAll(dirPath, os.ModePerm)
		if err != nil {
			return err
		}
	}
	return nil
}

func GenerateKey(str string) string {
	hash := sha256.New()
	hash.Write([]byte(str))
	hashed := hash.Sum(nil)
	return hex.EncodeToString(hashed)
}

func (db *BackFileDb) RemoveBackFile(layer, filename string) (err error) {
	if !db.Cfg.Passthrough {
		return nil
	}

	mu := db.Lock(layer, filename)
	defer mu.Unlock()

	bfsI, ok := db.backingFiles.Load(layer)
	if !ok {
		return nil
	}
	bfs := bfsI.(*sync.Map)

	bfI, ok := bfs.Load(filename)
	if !ok {
		return nil
	}
	bf := bfI.(*BackingFile)

	err = bf.remove()
	if err != nil {
		return err
	}
	bfs.Delete(filename)

	musI, ok := db.bfMutexs.Load(layer)
	if !ok {
		return nil
	}
	mus := musI.(*sync.Map)
	mus.Delete(filename)
	return nil
}

func RemoveLayer(layer string) (err error) {
	if BFDb != nil {
		return BFDb.RemoveLayer(layer)
	}
	return nil
}

func (db *BackFileDb) RemoveLayer(layer string) (err error) {
	if !db.Cfg.Passthrough {
		return nil
	}

	log.G(db.ctx).Infof("RemoveLayer: %s", layer)

	bfsI, ok := db.backingFiles.Load(layer)
	if !ok {
		return nil
	}
	bfs := bfsI.(*sync.Map)

	bfs.Range(func(key, value any) bool {
		bf := value.(*BackingFile)
		bf.mu.Lock()
		if bf.persistentTimer != nil {
			bf.persistentTimer.Stop()
		}
		if bf.updateToKernelTimer != nil {
			bf.updateToKernelTimer.Stop()
		}
		bf.mu.Unlock()

		return true
	})

	path := path.Join(db.Cfg.BackingfileStorageDir, layer)
	err = os.RemoveAll(path)
	if err != nil {
		return err
	}

	db.backingFiles.Delete(layer)
	db.mountFds.Delete(layer)
	db.bfMutexs.Delete(layer)
	return nil
}

func PersistentBackFile() {
	if BFDb != nil {
		BFDb.PersistentBackFile()
	}
}

func (db *BackFileDb) PersistentBackFile() {
	if !db.Cfg.Passthrough {
		return
	}

	db.backingFiles.Range(func(key, value any) bool {
		bfs := value.(*sync.Map)
		bfs.Range(func(key, value any) bool {
			bf := value.(*BackingFile)
			bf.mu.RLock()

			if bf.generation == bf.persistentGeneration {
				bf.mu.RUnlock()
				return true
			}

			err := bf.persistent()
			if err == nil {
				bf.persistentGeneration = bf.generation
			} else {
				log.G(db.ctx).Warningf("persistent file %s failed: %v", bf.Filename, err)
			}
			bf.mu.RUnlock()
			return true
		})
		return true
	})
}

func (db *BackFileDb) OpenBacking(layer, filename string) (backingId uint32, isPartial bool, err error) {
	defer trace.StartRegion(context.Background(), "fs reader backingfile BackFileDb.OpenBacking").End()
	if !db.Cfg.Passthrough {
		return 0, false, nil
	}
	mountFd := db.GetMountFd(layer)
	if mountFd <= 0 {
		return 0, false, nil
	}

	bf, err := db.GetBackFile(layer, filename)
	if err != nil {
		return 0, false, err
	}

	bf.mu.Lock()
	defer bf.mu.Unlock()

	if bf.Id > 0 {
		return bf.Id, bf.isPartial, nil
	}

	file, err := os.Open(bf.StoragePath)
	if err != nil {
		return 0, false, err
	}
	defer file.Close()

	bf.Id, err = passthrough.OpenBacking(mountFd, int32(file.Fd()), !bf.Completed, bf.ExportInterval())
	if err == nil {
		bf.isPartial = !bf.Completed
	}
	return bf.Id, bf.isPartial, err
}
func (db *BackFileDb) GetTocMetaPath(layer string) (string, error) {
	storagePath := path.Join(db.Cfg.TocMetaStorageDir, layer) + tocMetaSuffix

	err := ensureDirExist(storagePath)
	if err != nil {
		return "", err
	}

	return storagePath, err

}

func (db *BackFileDb) SetTocMeta(layer string) error {
	defer trace.StartRegion(context.Background(), "fs reader backingfile BackFileDb.SetTocMeta").End()

	if !db.Cfg.Passthrough {
		return nil
	}
	tocMetaPath := path.Join(db.Cfg.TocMetaStorageDir, layer) + tocMetaSuffix

	mountFd := db.GetMountFd(layer)
	if mountFd <= 0 {
		return fmt.Errorf("mountFd of layer %v not found", layer)
	}

	//check if exist
	if _, err := os.Stat(tocMetaPath); os.IsNotExist(err) {
		return fmt.Errorf("layer %v toc meta file %v  not found", layer, tocMetaPath)
	}

	file, err := os.Open(tocMetaPath)
	if err != nil {
		return err
	}
	defer file.Close()

	log.G(context.Background()).Infof("SetTocMeta mountFd: %d layer: %v", mountFd, layer)
	return passthrough.SetTocMeta(mountFd, int32(file.Fd()))

}

func (db *BackFileDb) CloseBacking(layer, filename string) error {
	defer trace.StartRegion(context.Background(), "fs reader backingfile BackFileDb.CloseBacking").End()
	if !db.Cfg.Passthrough {
		return nil
	}

	mountFd := db.GetMountFd(layer)
	if mountFd <= 0 {
		return nil
	}

	bf, err := db.GetBackFile(layer, filename)
	if err != nil {
		return err
	}

	bf.mu.Lock()
	defer bf.mu.Unlock()

	if bf.Id <= 0 {
		return nil
	}

	err = passthrough.CloseBacking(mountFd, bf.Id)
	if err != nil {
		return err
	}
	bf.Id = 0
	return nil
}

func createLocalBackingfile(pathStr string, attr metadata.Attr) error {
	if _, err := os.Stat(pathStr); os.IsNotExist(err) {
		dirPath := filepath.Dir(pathStr)
		if _, err := os.Stat(dirPath); os.IsNotExist(err) {
			err := os.MkdirAll(dirPath, os.ModePerm)
			if err != nil {
				return err
			}
		}

		file, err := os.Create(pathStr)
		if err != nil {
			return err
		}
		defer file.Close()

		err = file.Truncate(attr.Size)
		if err != nil {
			return err
		}

		err = file.Chmod(attr.Mode)
		if err != nil {
			return err
		}
		err = file.Chown(attr.UID, attr.GID)
		if err != nil {
			return err
		}

	}

	return nil

}

func writeLocalBackingfile(pathStr string, p []byte, offset int64) (int, error) {

	file, err := os.OpenFile(pathStr, os.O_WRONLY, 0511)

	if err != nil {
		return 0, err
	}

	defer file.Close()
	n, err := file.WriteAt(p, offset)

	return n, err

}

// max 返回两个整数中的最大值
func max(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
