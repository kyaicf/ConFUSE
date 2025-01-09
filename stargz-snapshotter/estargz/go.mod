module github.com/containerd/stargz-snapshotter/estargz

go 1.22.0

toolchain go1.22.9

require (
	github.com/klauspost/compress v1.17.11
	github.com/opencontainers/go-digest v1.0.0
	github.com/vbatts/tar-split v0.11.6
	golang.org/x/sync v0.9.0
)

require (
	github.com/hanwen/go-fuse/v2 v2.7.2
	github.com/pierrec/lz4/v4 v4.1.21
	golang.org/x/sys v0.26.0
)

require github.com/moby/sys/mountinfo v0.7.2 // indirect
replace github.com/hanwen/go-fuse/v2 => ../go-fuse 