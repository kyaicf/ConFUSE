package lz4chunked

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"runtime/trace"

	"github.com/containerd/log"
	"github.com/containerd/stargz-snapshotter/estargz"

	"github.com/opencontainers/go-digest"
	"github.com/pierrec/lz4/v4"
)

const (
	// FooterSize is the size of the footer
	FooterSize            = 32
	frameSkipMagic uint32 = 0x184d2a50
)

var frameSkipMagicBytes = []byte{0x50, 0x2a, 0x4d, 0x18}

type Decompressor struct{}

type traceWrapRead struct {
	r io.ReadCloser
}

func (wr *traceWrapRead) Read(p []byte) (n int, err error) {
	t := trace.StartRegion(context.Background(), "estargz lz4 traceWrapRead.Read")
	defer t.End()
	return wr.r.Read(p)
}

func (wr *traceWrapRead) Close() error {
	return wr.r.Close()
}

func (lz *Decompressor) Reader(r io.Reader) (io.ReadCloser, error) {
	reader := lz4.NewReader(r)
	return &traceWrapRead{r: &Lz4ReadCloser{reader}}, nil

}

type Lz4ReadCloser struct{ *lz4.Reader }

func (r *Lz4ReadCloser) Close() (err error) {
	r.Reader.Reset(nil)
	return nil
}

type Compressor struct {
	CompressionLevel lz4.CompressionLevel
}

func (lz *Compressor) Writer(w io.Writer) (estargz.WriteFlushCloser, error) {

	zw := lz4.NewWriter(w)
	options := []lz4.Option{
		lz4.BlockSizeOption(lz4.BlockSize(lz4.Block4Mb)),
		lz4.ChecksumOption(false),
		lz4.CompressionLevelOption(lz.CompressionLevel),
	}
	if err := zw.Apply(options...); err != nil {
		return nil, err
	}

	return zw, nil

}

func (lz *Compressor) WriteTOCAndFooter(w io.Writer, off int64, toc *estargz.JTOC, diffHash hash.Hash) (digest.Digest, error) {

	tocJSON, err := json.Marshal(toc)
	if err != nil {
		return "", err
	}
	buf := new(bytes.Buffer)
	encoder := lz4.NewWriter(buf)
	options := []lz4.Option{
		lz4.CompressionLevelOption(lz.CompressionLevel),
	}
	if err := encoder.Apply(options...); err != nil {
		return "", err
	}

	if _, err := encoder.Write(tocJSON); err != nil {
		return "", err
	}
	if err := encoder.Close(); err != nil {
		return "", err
	}

	compressedTOC := buf.Bytes()

	compressedTocSize := uint64(len(compressedTOC))
	// 8 is the size of the lz4 skippable frame header + the frame size
	tocOff := uint64(off) + 8

	compressedKtoc, err := lz.getCompressedKtoc(toc)
	if err != nil {
		return "", err
	}

	// 8 is the size of the lz4 skippable frame header + the frame size
	kernelTocOffset := tocOff + compressedTocSize
	tocSize := compressedTocSize + uint64(len(compressedKtoc))
	totalToc := make([]byte, tocSize)
	copy(totalToc[:compressedTocSize], compressedTOC)
	copy(totalToc[compressedTocSize:], compressedKtoc)

	_, err = io.Copy(w, bytes.NewReader(lz4TocBytes(totalToc)))
	if err != nil {
		return "", err
	}

	if _, err := w.Write(lz4FooterBytes(tocOff, tocSize, uint64(kernelTocOffset))); err != nil {
		return "", err
	}

	return digest.FromBytes(tocJSON), err
}

func (lz *Compressor) getCompressedKtoc(toc *estargz.JTOC) ([]byte, error) {
	ktoc, err := estargz.ConvertTocToKTOC(toc)
	if err != nil {
		return []byte{}, err
	}
	if ktoc == nil {
		return []byte{}, err
	}
	ktocBuf, err := ktoc.DumpToBuffer()
	if err != nil {
		return []byte{}, err
	}
	ktocData := ktocBuf.Bytes()

	buf := new(bytes.Buffer)
	encoder := lz4.NewWriter(buf)
	options := []lz4.Option{
		lz4.CompressionLevelOption(lz.CompressionLevel),
	}
	if err := encoder.Apply(options...); err != nil {
		return []byte{}, err
	}

	if _, err := encoder.Write(ktocData); err != nil {
		return []byte{}, err
	}
	if err := encoder.Close(); err != nil {
		return []byte{}, err
	}
	return buf.Bytes(), err
}

func lz4FooterBytes(tocOff uint64, tocSize, kernelTocOffset uint64) []byte {
	footer := make([]byte, FooterSize)
	binary.LittleEndian.PutUint32(footer, frameSkipMagic)
	binary.LittleEndian.PutUint32(footer[4:], uint32(24))
	binary.LittleEndian.PutUint64(footer[8:], uint64(tocOff))
	binary.LittleEndian.PutUint64(footer[16:], uint64(tocSize))
	binary.LittleEndian.PutUint64(footer[24:], uint64(kernelTocOffset))

	log.G(context.Background()).Debugf("lz4 write footer tocOff %v  kernelTocOffset %v tocSize %v\n", tocOff, kernelTocOffset, tocSize)
	return footer
}

func lz4TocBytes(b []byte) []byte {
	footer := make([]byte, len(b)+8)
	binary.LittleEndian.PutUint32(footer, frameSkipMagic)
	binary.LittleEndian.PutUint32(footer[4:], uint32(len(b)))
	copy(footer[8:], b)
	return footer
}

func (lz *Decompressor) ParseTOC(r io.Reader, estargzTocSize, kernelTocSize int64) (toc *estargz.JTOC, ktoc *estargz.KernelToc, tocDgst digest.Digest, err error) {

	totalBuf := make([]byte, kernelTocSize+estargzTocSize)
	n, err := io.ReadFull(r, totalBuf)
	if n != int(kernelTocSize+estargzTocSize) {
		return nil, nil, "", fmt.Errorf("error ReadFull: %w", err)
	}

	//	skip frameheader  + frame size = 8
	tocBuf := bytes.NewBuffer(totalBuf[:estargzTocSize])
	zr := lz4.NewReader(tocBuf)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return nil, nil, "", fmt.Errorf("failed to read from reader: %v", err)
	}

	dgstr := digest.Canonical.Digester()
	toc = new(estargz.JTOC)
	if err := json.NewDecoder(io.TeeReader(zr, dgstr.Hash())).Decode(&toc); err != nil {
		return nil, nil, "", fmt.Errorf("error decoding TOC JSON: %w", err)
	}

	// kernelToc
	kerneltocReader := lz4.NewReader(bytes.NewBuffer(totalBuf[estargzTocSize:]))

	data, err := io.ReadAll(kerneltocReader)

	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		log.G(context.Background()).Debugf("failed to read from kerneltocReader: %v", err)
		return nil, nil, "", fmt.Errorf("failed to read from kerneltocReader: %v", err)
	}
	if len(data) == 0 {
		return toc, nil, dgstr.Digest(), nil
	}

	ktocBuff := bytes.NewBuffer(data)

	ktoc, err = estargz.ReadKernelToc(ktocBuff, int64(len(data)))
	if err != nil {
		return nil, nil, "", fmt.Errorf("ReadKernelToc: %w", err)
	}

	return toc, ktoc, dgstr.Digest(), nil
}

func (lz *Decompressor) DecompressTOC(r io.Reader) (tocJSON io.ReadCloser, err error) {
	// TODO use for metadata
	return nil, fmt.Errorf("no inplemented")
}

func (lz *Decompressor) ParseFooter(p []byte) (blobPayloadSize, tocOffset, kernelTocOffset, tocSize int64, err error) {

	if binary.LittleEndian.Uint32(p[0:4]) != frameSkipMagic {
		return 0, 0, 0, 0, fmt.Errorf("invalid lz4 magic number get %x should be %x  footer len footer %v", p[0:4], frameSkipMagic, len(p))
	}

	offset := binary.LittleEndian.Uint64(p[8:])
	size := binary.LittleEndian.Uint64(p[16:])
	kerneltocOffset := binary.LittleEndian.Uint64(p[24:])
	// 8 is the size of the lz4 skippable frame header + the frame size (see WriteTOCAndFooter)
	return int64(offset - 8), int64(offset), int64(kerneltocOffset), int64(size), nil
}

func (lz *Decompressor) FooterSize() int64 {
	return FooterSize
}
