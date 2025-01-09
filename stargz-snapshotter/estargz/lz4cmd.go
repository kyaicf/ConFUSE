package estargz

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"
)

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

func Lz4CmdReader(ctx context.Context, r io.Reader) (io.ReadCloser, error) {
	// convert使用用cmd 封装  转换镜像的时候
	// github.com/pierrec/lz4/v4 实现的reader不够健壮，解压存在问题。
	path, err := exec.LookPath("lz4c")
	if err != nil {
		return nil, fmt.Errorf("Lz4 decompress %v", err)
	}

	return cmdStream(exec.CommandContext(ctx, path, "-dc"), r)
}
