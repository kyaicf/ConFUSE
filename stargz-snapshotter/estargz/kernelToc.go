package estargz

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
)

// one fuse.Attr took 104 bytes
const FuseAttrBytes = 104
const HeaderBytes = 12

type Header struct {
	GraphOffset  uint32
	InodesOffset uint32
	NameOffset   uint32
}

type HashMeta struct {
	Salt1 []uint32  `json:"Salt1"`
	Salt2 []uint32  `json:"Salt2"`
	Graph []uint32  `json:"Graph"`
	Keys  []HashKey `json:"Keys"`
}

type KernelToc struct {
	Header
	HashMeta
	Inodes []fuse.Attr
	Names  []byte
}

type HashInput struct {
	Keys map[HashKey]fuse.Attr
}

func (k *KernelToc) DumpToBuffer() (*bytes.Buffer, error) {

	var buffer bytes.Buffer

	err := binary.Write(&buffer, binary.LittleEndian, k.Header)
	if err != nil {
		return nil, err
	}

	err = binary.Write(&buffer, binary.LittleEndian, k.HashMeta.Salt1)
	if err != nil {
		return nil, err
	}

	err = binary.Write(&buffer, binary.LittleEndian, k.HashMeta.Salt2)
	if err != nil {
		return nil, err
	}

	err = binary.Write(&buffer, binary.LittleEndian, k.HashMeta.Graph)
	if err != nil {
		return nil, err
	}

	err = binary.Write(&buffer, binary.LittleEndian, k.Inodes)
	if err != nil {
		return nil, err
	}

	var namesBuffer bytes.Buffer

	nextOffset := uint32(0)
	if len(k.Keys) > 0 {
		for index, key := range k.Keys {

			name := key.Name
			if len(name) > 0 {
				if len(name) <= 8 {
					copy(k.Inodes[index].Raw[:], name)
					k.Inodes[index].Flags = fuse.FUSE_ATTR_NAME
				} else {
					err = binary.Write(&namesBuffer, binary.LittleEndian, []byte(name))
					if err != nil {
						return nil, err
					}

					//offset
					binary.LittleEndian.PutUint32(k.Inodes[index].Raw[0:4], uint32(nextOffset))
					//length
					binary.LittleEndian.PutUint32(k.Inodes[index].Raw[4:8], uint32(len(name)))
					nextOffset = nextOffset + uint32(len(name))
				}

			}

		}

	} else if len(k.Names) > 0 {
		err = binary.Write(&namesBuffer, binary.LittleEndian, k.Names)
		if err != nil {
			return nil, err
		}

	} else {

		//all names length < 8
		if nextOffset != 0 {
			return nil, fmt.Errorf("dump kerntoc names failed")
		}
	}

	if namesBuffer.Len() > 0 {
		err = binary.Write(&buffer, binary.LittleEndian, namesBuffer.Bytes())
		if err != nil {
			return nil, err
		}
	}

	return &buffer, nil
}

func (k *KernelToc) WriteToFile(path string) (string, error) {

	buffer, err := k.DumpToBuffer()
	if err != nil {
		return path, err
	}
	fmt.Printf("kernel toc write to file %v path %v \n", len(buffer.Bytes()), path)
	err = DumpToFile(buffer.Bytes(), path)
	if err != nil {
		fmt.Println(err)
		return path, err
	}

	return path, nil
}

func SetupAttrOffset(Keys map[HashKey]fuse.Attr) ([]HashKey, []fuse.Attr, error) {
	var keys []HashKey
	var inodes []fuse.Attr

	var namesBuffer bytes.Buffer
	offset := uint32(0)
	for key, inode := range Keys {

		if len(key.Name) <= 8 {
			copy(inode.Raw[:], key.Name)
			inode.Flags = fuse.FUSE_ATTR_NAME
		} else {
			err := binary.Write(&namesBuffer, binary.LittleEndian, []byte(key.Name))
			if err != nil {
				return keys, inodes, err
			}
			//offset
			binary.LittleEndian.PutUint32(inode.Raw[0:4], uint32(offset))
			//length
			binary.LittleEndian.PutUint32(inode.Raw[4:8], uint32(len(key.Name)))
			offset = offset + uint32(len(key.Name))
		}

		//key 和 inode 顺序保持一致 。 生成的下标就是inode下标。
		keys = append(keys, key)
		inodes = append(inodes, inode)
	}

	return keys, inodes, nil
}

func ConvertTocToKTOC(jtoc *JTOC) (*KernelToc, error) {
	er, err := OpenWithJtoc(jtoc)
	if err != nil {
		return nil, err
	}

	root, ok := er.Lookup("")
	if !ok {
		return nil, err
	}
	r := &ReaderWrap{RootID: 1}

	_, IdMap, IdOfEntry, err := AssignIDs(root)
	if err != nil {
		return nil, err
	}
	r.IdMap = IdMap
	r.IdOfEntry = IdOfEntry

	//get hash input and inodes
	res, err := r.CollectKeysAndInodes()
	if err != nil {
		return nil, err
	}
	if len(res.Keys) == 0 {
		return nil, nil
	}

	keys, inodes, err := SetupAttrOffset(res.Keys)
	if err != nil {
		return nil, err
	}

	//record perfect hash execution time
	start := time.Now()
	// get hashMeta

	fmt.Println("------")
	fmt.Printf("perfect hashing %v keys  \n", len(keys))
	hashMeta, err := PerfectHash(keys)

	if err != nil {
		fmt.Printf("CallPerfectHash  %v keys err %v\n", len(keys), err)
		return nil, err
	}
	duration := time.Since(start)
	fmt.Printf("took %v to complete. \n", duration)

	// calculate offset
	graphOffset := len(hashMeta.Salt1)*4*2 + HeaderBytes
	inodesOffset := len(hashMeta.Graph)*4 + graphOffset
	nameOffset := len(inodes)*FuseAttrBytes + inodesOffset
	header := &Header{
		GraphOffset:  uint32(graphOffset),
		InodesOffset: uint32(inodesOffset),
		NameOffset:   uint32(nameOffset)}

	// set up attr
	k := &KernelToc{Header: *header, HashMeta: *hashMeta, Inodes: inodes}
	k.Names = make([]byte, 0)

	fmt.Printf("Ktoc header %+v  inodes %v  keys %v\n", header, len(inodes), len(hashMeta.Keys))

	return k, err
}

func ReadKernelToc(r io.Reader, size int64) (*KernelToc, error) {
	kernelToc := &KernelToc{}
	var (
		GraphOffset  uint32
		InodesOffset uint32
		NameOffset   uint32
		saltLen      uint32
		graphLen     uint32
		inodesLen    uint32
		NameLen      uint32
	)

	err := binary.Read(r, binary.LittleEndian, &GraphOffset)
	if err != nil {
		return nil, err
	}

	err = binary.Read(r, binary.LittleEndian, &InodesOffset)
	if err != nil {
		return nil, err
	}
	err = binary.Read(r, binary.LittleEndian, &NameOffset)
	if err != nil {
		return nil, err
	}

	kernelToc.GraphOffset = GraphOffset
	kernelToc.InodesOffset = InodesOffset
	kernelToc.NameOffset = NameOffset

	saltLen = ((GraphOffset - HeaderBytes) / 4) / 2
	graphLen = (InodesOffset - GraphOffset) / 4
	inodesLen = (NameOffset - InodesOffset) / FuseAttrBytes
	NameLen = (uint32(size) - NameOffset)

	salt1, err := readUint32Slice(r, int(saltLen))
	if err != nil {
		return nil, err
	}

	salt2, err := readUint32Slice(r, int(saltLen))
	if err != nil {
		return nil, err
	}

	graph, err := readUint32Slice(r, int(graphLen))
	if err != nil {
		return nil, err
	}
	inodes, err := readFuseAttr(r, int(inodesLen))
	if err != nil {
		return nil, err
	}

	names := make([]byte, NameLen)
	err = binary.Read(r, binary.LittleEndian, &names)
	if err != nil {
		return nil, err
	}
	kernelToc.Names = names

	kernelToc.Inodes = inodes
	kernelToc.HashMeta = HashMeta{
		Salt1: salt1,
		Salt2: salt2,
		Graph: graph,
	}
	fmt.Printf(" header %+v   inodesLen %v   NameLen %v graphLen %v saltLen %v\n", kernelToc.Header, inodesLen, NameLen, graphLen, saltLen)
	return kernelToc, nil
}

func readUint32Slice(r io.Reader, length int) ([]uint32, error) {
	slice := make([]uint32, length)
	for i := range slice {
		err := binary.Read(r, binary.LittleEndian, &slice[i])
		if err != nil {
			return nil, err
		}
	}
	return slice, nil
}

func readFuseAttr(r io.Reader, length int) ([]fuse.Attr, error) {
	slice := make([]fuse.Attr, length)
	err := binary.Read(r, binary.LittleEndian, &slice)
	if err != nil {
		return nil, err
	}
	return slice, nil
}
