package lz4chunked

import (
	"context"
	"fmt"
	"io"

	// "test/containerd/containerd/archive/compression"

	"github.com/containerd/containerd/content"
	"github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/images"
	"github.com/containerd/containerd/images/converter"
	"github.com/containerd/containerd/images/converter/uncompress"
	"github.com/containerd/containerd/labels"

	// "github.com/containerd/stargz-snapshotter/estargz"
	"github.com/containerd/stargz-snapshotter/estargz"
	"github.com/containerd/stargz-snapshotter/estargz/lz4chunked"
	"github.com/containerd/stargz-snapshotter/util/ioutils"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pierrec/lz4/v4"
	"github.com/sirupsen/logrus"
)

type lz4Compression struct {
	*lz4chunked.Decompressor
	*lz4chunked.Compressor
}

func LayerConvertWithLayerOptsFuncWithCompressionLevel(compressionLevel lz4.CompressionLevel, opts map[digest.Digest][]estargz.Option) converter.ConvertFunc {
	if opts == nil {
		return LayerConvertFuncWithCompressionLevel(compressionLevel)
	}
	return func(ctx context.Context, cs content.Store, desc ocispec.Descriptor) (*ocispec.Descriptor, error) {
		return LayerConvertFuncWithCompressionLevel(compressionLevel, opts[desc.Digest]...)(ctx, cs, desc)
	}
}

func convertMediaType(mt string) string {
	switch mt {
	case images.MediaTypeDockerSchema2LayerGzip:
		return images.MediaTypeDockerSchema2Layer
	case images.MediaTypeDockerSchema2LayerForeignGzip:
		return images.MediaTypeDockerSchema2LayerForeign
	case ocispec.MediaTypeImageLayerGzip, ocispec.MediaTypeImageLayerZstd:
		return ocispec.MediaTypeImageLayer
	case ocispec.MediaTypeImageLayerNonDistributableGzip, ocispec.MediaTypeImageLayerNonDistributableZstd:
		return ocispec.MediaTypeImageLayerNonDistributable
	default:
		return mt
	}
}

func LayerConvertFuncWithCompressionLevel(compressionLevel lz4.CompressionLevel, opts ...estargz.Option) converter.ConvertFunc {
	return func(ctx context.Context, cs content.Store, desc ocispec.Descriptor) (*ocispec.Descriptor, error) {
		if !images.IsLayerType(desc.MediaType) {
			// No conversion. No need to return an error here.
			return nil, nil
		}
		uncompressedDesc := &desc
		// We need to uncompress the archive first
		if !uncompress.IsUncompressedType(desc.MediaType) {
			var err error
			uncompressedDesc, err = LayerConvertFunc(ctx, cs, desc)
			if err != nil {
				return nil, err
			}
			if uncompressedDesc == nil {
				return nil, fmt.Errorf("unexpectedly got the same blob after compression (%s, %q)", desc.Digest, desc.MediaType)
			}
			defer func() {
				if err := cs.Delete(ctx, uncompressedDesc.Digest); err != nil {
					logrus.WithError(err).WithField("uncompressedDesc", uncompressedDesc).Warn("failed to remove tmp uncompressed layer")
				}
			}()
			logrus.Debugf("lz4: uncompressed %s into %s", desc.Digest, uncompressedDesc.Digest)
		}

		info, err := cs.Info(ctx, desc.Digest)
		if err != nil {
			return nil, err
		}
		labelz := info.Labels
		if labelz == nil {
			labelz = make(map[string]string)
		}

		uncompressedReaderAt, err := cs.ReaderAt(ctx, *uncompressedDesc)
		if err != nil {
			return nil, err
		}
		defer uncompressedReaderAt.Close()
		uncompressedSR := io.NewSectionReader(uncompressedReaderAt, 0, uncompressedDesc.Size)

		opts = append(opts, estargz.WithCompression(&lz4Compression{
			new(lz4chunked.Decompressor),
			&lz4chunked.Compressor{
				CompressionLevel: compressionLevel,
			},
		}))

		ctx = context.WithValue(ctx, "CompressionMode", "lz4")

		blob, err := estargz.Build(uncompressedSR, append(opts, estargz.WithContext(ctx))...)
		if err != nil {
			return nil, err
		}
		defer blob.Close()

		ref := fmt.Sprintf("convert-lz4chunked-from-%s", desc.Digest)
		w, err := cs.Writer(ctx, content.WithRef(ref))
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

		// Copy and count the contents
		pr, pw := io.Pipe()
		c := new(ioutils.CountWriter)
		doneCount := make(chan struct{})
		go func() {
			defer close(doneCount)
			defer pr.Close()
			decompressR, err := DecompressStream(pr)
			if err != nil {
				pr.CloseWithError(err)
				return
			}
			defer decompressR.Close()
			_, err = io.Copy(c, decompressR)
			if err != nil {
				pr.CloseWithError(err)
				return
			}

		}()
		n, err := io.Copy(w, io.TeeReader(blob, pw))
		if err != nil {
			return nil, err
		}
		if err := blob.Close(); err != nil {
			return nil, err
		}
		// update diffID label
		labelz[labels.LabelUncompressed] = blob.DiffID().String()
		if err = w.Commit(ctx, n, "", content.WithLabels(labelz)); err != nil && !errdefs.IsAlreadyExists(err) {
			return nil, err
		}
		if err := w.Close(); err != nil {
			return nil, err
		}
		newDesc := desc
		newDesc.MediaType, err = convertMediaTypeToLz4(newDesc.MediaType)
		if err != nil {
			return nil, err
		}
		newDesc.Digest = w.Digest()
		newDesc.Size = n
		if newDesc.Annotations == nil {
			newDesc.Annotations = make(map[string]string, 1)
		}
		tocDgst := blob.TOCDigest().String()
		newDesc.Annotations[labels.LabelUncompressed] = desc.Digest.String()
		newDesc.Annotations[estargz.TOCJSONDigestAnnotation] = tocDgst
		newDesc.Annotations[estargz.StoreUncompressedSizeAnnotation] = fmt.Sprintf("%d", c.Size())

		return &newDesc, nil
	}
}

const MediaTypeImageLayerLz4 = "application/vnd.oci.image.layer.v1.tar+lz4"

func convertMediaTypeToLz4(mt string) (string, error) {
	ociMediaType := converter.ConvertDockerMediaTypeToOCI(mt)
	switch ociMediaType {
	case ocispec.MediaTypeImageLayer, ocispec.MediaTypeImageLayerGzip, ocispec.MediaTypeImageLayerZstd:
		return MediaTypeImageLayerLz4, nil
	case ocispec.MediaTypeImageLayerNonDistributable, ocispec.MediaTypeImageLayerNonDistributableGzip, ocispec.MediaTypeImageLayerNonDistributableZstd: //nolint:staticcheck // deprecated
		return ocispec.MediaTypeImageLayerNonDistributableZstd, nil //nolint:staticcheck // deprecated
	default:
		return "", fmt.Errorf("unknown mediatype %q", mt)
	}
}
