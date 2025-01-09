package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/containerd/stargz-snapshotter/estargz"
	"github.com/hanwen/go-fuse/v2/fuse"
)

func testConvertKernelToc(jtocPath string) {
	jtocFile, err := os.Open(jtocPath)
	if err != nil {
		fmt.Println("无法打开文件:", err)
		return
	}
	defer jtocFile.Close()

	toc := new(estargz.JTOC)
	if err := json.NewDecoder(jtocFile).Decode(&toc); err != nil {
		// fmt.Println("无法获取文件信息:", err)
		fmt.Printf("error decoding TOC JSON: %v", err)
		return
	}

	ktoc, err := estargz.ConvertTocToKTOC(toc)
	if err != nil {
		return
	}

	keys := ktoc.HashMeta.Keys
	S1 := ktoc.HashMeta.Salt1
	S2 := ktoc.HashMeta.Salt2
	G := ktoc.HashMeta.Graph

	success := true
	for _, k := range keys {
		index := getIndex(k, S1, S2, G, uint32(len(S1)), uint32(len(G)), uint32(len(keys)))
		// getIndex(k, S1, S2, G, keys, uint32(len(S1)), uint32(len(G)), uint32(len(keys)))
		if index == -1 {
			success = false
			parentid, buffer := k.NodeId, k.Name
			fmt.Printf("Failed  key [%v] parentid %v , name %v \n", k, parentid, buffer)
			continue
		}

	}

	_, err = ktoc.WriteToFile("stargz.tocmeta")
	if err != nil {
		fmt.Printf("Failed to Write ktoc ToFile  %v\n", err)
	}

	if success {
		fmt.Printf("convert toc success\n")
	}

}

func compareKernelWithToc(ktocPath, jtocPath string, printSuccess bool) {
	ktocFile, err := os.Open(ktocPath)
	if err != nil {
		fmt.Println("无法打开文件:", err)
		return
	}
	defer ktocFile.Close()
	info, _ := ktocFile.Stat()
	ktoc, err := estargz.ReadKernelToc(ktocFile, info.Size())
	if err != nil {
		fmt.Println("ReadKernelToc:", err)
		return
	}
	fmt.Printf("ktoc size %v header %+v \n", info.Size(), ktoc.Header)

	jtocFile, err := os.Open(jtocPath)
	if err != nil {
		fmt.Println("无法打开文件:", err)
		return
	}
	defer jtocFile.Close()

	toc := new(estargz.JTOC)
	if err := json.NewDecoder(jtocFile).Decode(&toc); err != nil {
		// fmt.Println("无法获取文件信息:", err)
		fmt.Printf("error decoding TOC JSON: %v", err)
		return
	}

	S1 := ktoc.HashMeta.Salt1
	S2 := ktoc.HashMeta.Salt2
	G := ktoc.HashMeta.Graph
	er, err := estargz.OpenWithJtoc(toc)
	if err != nil {
		return
	}

	root, ok := er.Lookup("")
	if !ok {
		return
	}
	r := &estargz.ReaderWrap{RootID: 1}

	_, IdMap, IdOfEntry, err := estargz.AssignIDs(root)
	if err != nil {
		return
	}
	// r.r = er
	r.IdMap = IdMap
	r.IdOfEntry = IdOfEntry

	res, _ := r.CollectKeysAndInodes()
	totalCount := 0
	success := 0

	for k := range res.Keys {
		totalCount += 1

		nodeId, lookUpName := k.NodeId, k.Name

		index := getIndex(k, S1, S2, G, uint32(len(S1)), uint32(len(G)), uint32(len(res.Keys)))
		if index == -1 {
			fmt.Printf("key \"%v\"  getindex =-1\n", k)
			continue
		}
		// stub  look up
		lookUpAttr := ktoc.Inodes[index]

		var ktocName string
		var lookUpNameLength uint32
		var lookUpOffset uint32
		if ktoc.Inodes[index].Flags == fuse.FUSE_ATTR_NAME {
			raw1 := ktoc.Inodes[index].Raw[:]
			n := 0
			for n < len(raw1) && raw1[n] != 0 {
				n++
			}
			ktocName = string(raw1[:n])

			lookUpNameLength = uint32(len(ktocName))
			lookUpOffset = 0
		} else {
			lookUpOffset = binary.LittleEndian.Uint32(ktoc.Inodes[index].Raw[0:4])
			lookUpNameLength = binary.LittleEndian.Uint32(ktoc.Inodes[index].Raw[4:8])
			if lookUpOffset >= uint32(0) && lookUpOffset+lookUpNameLength <= uint32(len(ktoc.Names)) {
				ktocName = string(ktoc.Names[lookUpOffset : lookUpOffset+lookUpNameLength])
			} else {
				ktocName = ""
			}
		}

		var tocNodeId uint32
		if nodeId == 1 {
			tocNodeId = 1
		} else {
			tocNodeId = uint32(nodeId)
		}

		targetId, targetEntry, err := r.GetChild(tocNodeId, lookUpName)
		if err != nil {
			fmt.Printf("id of child entry %v  %q not found\n", tocNodeId, lookUpName)
			continue
		}

		if ktocName != lookUpName || nodeId != int32(lookUpAttr.ParentIno) || lookUpAttr.Ino != uint64(targetId) {
			fmt.Println("Failed")
			fmt.Printf("ktocName != lookUpName  \"%v\"  ktocName [%v]  lookUpName [%v]   \n", ktocName != lookUpName, ktocName, lookUpName)
			fmt.Printf(" nodeId != (lookUpAttr.ParentIno) \"%v\"  \n", nodeId != int32(lookUpAttr.ParentIno))
			fmt.Printf("lookUpAttr.Ino != uint64(targetId)  \"%v\"  \n", lookUpAttr.Ino != uint64(targetId))
			fmt.Printf("Lookup key \"%v\"  \n", k)
			fmt.Printf("index is \"%v\"  \n", index)
			fmt.Printf("Inode attr: Ino  %v parent ino %v  size %v mode %v ktoc name %v offset %v length %v \n", lookUpAttr.Ino, lookUpAttr.ParentIno, lookUpAttr.Size, lookUpAttr.Mode, ktocName, lookUpOffset, lookUpNameLength)
			fmt.Printf("toc Entry \"%v\" targetId  %v  parent ino %v  type %v  size %v mode %v \n", targetEntry.Name, targetId, targetEntry.ParentIno, targetEntry.Type, targetEntry.Size, targetEntry.Mode)
			fmt.Println("----")

			continue
		}
		if printSuccess || lookUpName == "bin" {
			fmt.Println("Success")
			fmt.Printf("Lookup key \"%v\"  \n", k)
			fmt.Printf("index is \"%v\"  \n", index)
			fmt.Printf("Inode attr: Ino  %v parent ino %v  size %v mode %v name %v offset %v length %v \n", lookUpAttr.Ino, lookUpAttr.ParentIno, lookUpAttr.Size, lookUpAttr.Mode, ktocName, lookUpOffset, lookUpNameLength)
			fmt.Printf("toc Entry \"%v\" parent ino %v type %v  size %v mode %v \n", targetEntry.Name, targetEntry.ParentIno, targetEntry.Type, targetEntry.Size, targetEntry.Mode)
			fmt.Println("----")
		}

		success += 1
		continue

	}
	fmt.Printf("check %v sucess %v \n", totalCount, success)

}

func getIndex(k estargz.HashKey, S1 []uint32, S2 []uint32, G []uint32, NS, NG, NK uint32) int {
	parentid, buffer := k.NodeId, k.Name

	f1, f2 := uint32(0), uint32(0)

	for i := 0; i < 8; i++ {
		// # Extract byte using bitwise operations
		byteI := uint32((parentid >> (i * 8)) & 0xFF)
		// # Multiply the byte with corresponding salt value and add to sum
		f1 += byteI * S1[i]
		f2 += byteI * S2[i]
	}

	for i := uint32(0); i < uint32(len(buffer)) && i < NS; i++ {
		f1 += S1[i+8] * uint32((buffer[i]))
		f2 += S2[i+8] * uint32((buffer[i]))

	}

	i := uint32((G[f1%NG] + G[f2%NG]) % uint32(NG))
	if i < NK {
		return int(i)
	}
	return -1

}

func main() {
	testConvertKernelToc("stargz.index.json")
	compareKernelWithToc("stargz.tocmeta",
		"stargz.index.json", false)

	// compareKernelWithToc("./data/sha256:ee11c78aebcf70a23d229ec97256ff3125fc70597a8e3589411113f9a6467780.tocMeta",
	// "./data/sha256:ee11c78aebcf70a23d229ec97256ff3125fc70597a8e3589411113f9a6467780.toc", false)
	// testDirCompare()
}

func testDirCompare() {
	dir := "./data" // Replace with the target directory path.
	pairs := findFilePairs(dir)
	for i, pair := range pairs {

		fmt.Printf("layer Count %v compare Toc: %s \n", i+1, pair.Toc)
		compareKernelWithToc(pair.TocMeta,
			pair.Toc, false)
		fmt.Println("-----")
	}
}

type FilePair struct {
	Toc     string
	TocMeta string
}

func findFilePairs(rootDir string) []FilePair {
	var filePairs []FilePair
	fileMap := make(map[string]FilePair)

	err := filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && strings.HasPrefix(info.Name(), "sha256:") {
			// ext := strings.ToLower(filepath.Ext(path))

			if strings.HasSuffix(path, ".toc") {
				baseName := strings.TrimSuffix(path, ".toc")

				fileMap[baseName] = FilePair{Toc: path, TocMeta: baseName + ".tocMeta"}
				// fileMap[baseName] = FilePair{TocMeta: baseName + ".tocMeta"}
			}
		}
		return nil
	})

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	for _, pair := range fileMap {
		if pair.Toc != "" && pair.TocMeta != "" {
			filePairs = append(filePairs, pair)
		}
	}

	return filePairs
}
