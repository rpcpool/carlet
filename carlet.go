package carlet

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"os"

	commcid "github.com/filecoin-project/go-fil-commcid"
	commp "github.com/filecoin-project/go-fil-commp-hashhash"
	"github.com/ipfs/go-cid"
)

const (
	bufSize          = (4 << 20) / 128 * 127
	varintSize       = 10
	nulRootCarHeader = "\x19" + // 25 bytes of CBOR (encoded as varint :cryingbear: )
		// map with 2 keys
		"\xA2" +
		// text-key with length 5
		"\x65" + "roots" +
		// 1 element array
		"\x81" +
		// tag 42
		"\xD8\x2A" +
		// bytes with length 5
		"\x45" +
		// nul-identity-cid prefixed with \x00 as required in DAG-CBOR: https://github.com/ipld/specs/blob/master/block-layer/codecs/dag-cbor.md#links
		"\x00\x01\x55\x00\x00" +
		// text-key with length 7
		"\x67" + "version" +
		// 1, we call this v0 due to the nul-identity CID being an open question: https://github.com/ipld/go-car/issues/26#issuecomment-604299576
		"\x01"
	maxBlockSize = 2 << 20 // 2 MiB
)

type CarFile struct {
	Name        string  `json:"name" yaml:"name"`
	CommP       cid.Cid `json:"commP" yaml:"commP"`
	PaddedSize  uint64  `json:"paddedSize" yaml:"paddedSize"`
	HeaderSize  uint64  `json:"headerSize" yaml:"headerSize"`   // Header size prefix + actual header size (nulRootCarHeader)
	ContentSize uint64  `json:"contentSize" yaml:"contentSize"` // Actual content size, not including header and padding.
}

// SplitCar splits a car file into smaller car files of the specified target size
func SplitCar(rdr io.Reader, targetSize int, namePrefix string) error {
	streamBuf := bufio.NewReaderSize(rdr, bufSize)
	var streamLen int64

	maybeHeaderLen, err := streamBuf.Peek(varintSize)
	if err != nil {
		return fmt.Errorf("failed to read header: %s", err)
	}

	hdrLen, viLen := binary.Uvarint(maybeHeaderLen)
	if hdrLen <= 0 || viLen < 0 {
		return fmt.Errorf("unexpected header len = %d, varint len = %d", hdrLen, viLen)
	}

	actualViLen, err := io.CopyN(io.Discard, streamBuf, int64(viLen))
	if err != nil {
		return fmt.Errorf("failed to discard header varint: %s", err)
	}
	streamLen += actualViLen

	// ignoring header decoding for now
	actualHdrLen, err := io.CopyN(io.Discard, streamBuf, int64(hdrLen))
	if err != nil {
		return fmt.Errorf("failed to discard header header: %s", err)
	}
	streamLen += actualHdrLen

	var i int
	for {
		f := fmt.Sprintf("%s%d.car", namePrefix, i)
		fmt.Printf("Writing file: %s\n", f)
		fi, err := os.Create(f)
		if err != nil {
			return fmt.Errorf("failed to create file: %s", err)
		}
		if _, err := io.WriteString(fi, nulRootCarHeader); err != nil {
			return fmt.Errorf("failed to write empty header: %s", err)
		}

		var carletLen int64
		for carletLen < int64(targetSize) {
			maybeNextFrameLen, err := streamBuf.Peek(varintSize)
			if err == io.EOF {
				return nil
			}
			if err != nil && err != bufio.ErrBufferFull {
				return fmt.Errorf("unexpected error at offset %d: %s", streamLen, err)
			}
			if len(maybeNextFrameLen) == 0 {
				return fmt.Errorf("impossible 0-length peek without io.EOF at offset %d", streamLen)
			}

			frameLen, viL := binary.Uvarint(maybeNextFrameLen)
			if viL <= 0 {
				// car file with trailing garbage behind it
				return fmt.Errorf("aborting car stream parse: undecodeable varint at offset %d", streamLen)
			}
			if frameLen > 2<<20 {
				// anything over ~2MiB got to be a mistake
				return fmt.Errorf("aborting car stream parse: unexpectedly large frame length of %d bytes at offset %d", frameLen, streamLen)
			}

			actualFrameLen, err := io.CopyN(fi, streamBuf, int64(viL)+int64(frameLen))
			streamLen += actualFrameLen
			carletLen += actualFrameLen
			if err != nil {
				if err != io.EOF {
					return fmt.Errorf("unexpected error at offset %d: %s", streamLen-actualFrameLen, err)
				}
				return nil
			}
		}

		fi.Close()
		i++
	}
}

const (
	_KiB = 1024
	_MiB = _KiB * 1024
)

func alignToPageSize(size int) int {
	alignment := int(os.Getpagesize())
	mask := alignment - 1
	mem := uintptr(size + alignment)
	return int((mem + uintptr(mask)) & ^uintptr(mask))
}

type CarPiecesAndMetadata struct {
	OriginalCarHeaderSize uint64    `json:"originalCarHeaderSize" yaml:"originalCarHeaderSize"` // Size of the original car header, including the size prefix.
	OriginalCarHeader     string    `json:"originalCarHeader" yaml:"originalCarHeader"`         // Base64-encoded original car header (without the size prefix).
	CarPieces             []CarFile `json:"carPieces" yaml:"carPieces"`                         // List of car file pieces.
}

// SplitAndCommp splits a car file into smaller car files but also calculates commP at the same time.
func SplitAndCommp(r io.Reader, targetSize int, namePrefix string) (*CarPiecesAndMetadata, error) {
	return SplitAndCommpWithFileCreatorFunc(r, targetSize, namePrefix, func(fname string) (fileLike, error) {
		return os.Create(fname)
	})
}

// SplitAndCommpNoSavePieces splits a car file into smaller car files withouth saving them to disk.
// This is useful for when you only want to calculate commP and save metadata.
func SplitAndCommpNoSavePieces(r io.Reader, targetSize int, namePrefix string) (*CarPiecesAndMetadata, error) {
	return SplitAndCommpWithFileCreatorFunc(r, targetSize, namePrefix, func(fname string) (fileLike, error) {
		return devNullFile{}, nil
	})
}

type devNullFile struct{}

func (devNullFile) Write(p []byte) (n int, err error) {
	return len(p), nil
}

func (devNullFile) Close() error {
	return nil
}

func (devNullFile) Sync() error {
	return nil
}

func SplitAndCommpWithFileCreatorFunc(
	r io.Reader,
	targetSize int,
	namePrefix string,
	fileCreatorFunc func(string) (fileLike, error),
) (*CarPiecesAndMetadata, error) {
	out := &CarPiecesAndMetadata{}

	streamBuf := bufio.NewReaderSize(r, bufSize)
	var streamLen int64

	actualHeader, streamLen, err := readHeader(streamBuf, streamLen)
	if err != nil {
		return out, err
	}
	originalHeaderSize := streamLen
	out.OriginalCarHeaderSize = uint64(originalHeaderSize)
	out.OriginalCarHeader = base64.StdEncoding.EncodeToString(actualHeader)

	var i int
	for {
		fname := fmt.Sprintf("%s%d.car", namePrefix, i)
		pieceFile, err := fileCreatorFunc(fname)
		if err != nil {
			return out, fmt.Errorf("failed to create file %q: %s", fname, err)
		}
		fiWriteBuffer := bufio.NewWriterSize(pieceFile, alignToPageSize(_MiB*12))
		cp := new(commp.Calc)

		wr := io.MultiWriter(fiWriteBuffer, cp)

		if _, err := io.WriteString(wr, nulRootCarHeader); err != nil {
			return out, fmt.Errorf("failed to write empty header: %s", err)
		}

		var carletLen int64
		for carletLen < int64(targetSize) {
			maybeNextFrameLen, err := streamBuf.Peek(varintSize)
			if err == io.EOF {
				carFile, err := cleanup(cp, namePrefix, i, pieceFile, fiWriteBuffer)
				carFile.HeaderSize = uint64(len(nulRootCarHeader))
				carFile.ContentSize = uint64(carletLen)
				if err != nil {
					return out, err
				}
				out.CarPieces = append(out.CarPieces, carFile)

				return out, nil
			}
			if err != nil && err != bufio.ErrBufferFull {
				return out, fmt.Errorf("unexpected error at offset %d: %s", streamLen, err)
			}
			if len(maybeNextFrameLen) == 0 {
				return out, fmt.Errorf("impossible 0-length peek without io.EOF at offset %d", streamLen)
			}

			frameLen, viL := binary.Uvarint(maybeNextFrameLen)
			if viL <= 0 {
				// car file with trailing garbage behind it
				return out, fmt.Errorf("aborting car stream parse: undecodeable varint at offset %d", streamLen)
			}
			if frameLen > maxBlockSize {
				// anything over ~2MiB got to be a mistake
				return out, fmt.Errorf("aborting car stream parse: unexpectedly large frame length of %d bytes at offset %d", frameLen, streamLen)
			}

			actualFrameLen, err := io.CopyN(wr, streamBuf, int64(viL)+int64(frameLen))
			streamLen += actualFrameLen
			carletLen += actualFrameLen
			if err != nil {
				if err != io.EOF {
					return out, fmt.Errorf("unexpected error at offset %d: %s", streamLen-actualFrameLen, err)
				}
				carFile, err := cleanup(cp, namePrefix, i, pieceFile, fiWriteBuffer)
				carFile.HeaderSize = uint64(len(nulRootCarHeader))
				carFile.ContentSize = uint64(carletLen)
				if err != nil {
					return out, err
				}
				out.CarPieces = append(out.CarPieces, carFile)

				return out, nil
			}
		}

		carFile, err := cleanup(cp, namePrefix, i, pieceFile, fiWriteBuffer)
		carFile.HeaderSize = uint64(len(nulRootCarHeader))
		carFile.ContentSize = uint64(carletLen)
		if err != nil {
			return out, err
		}
		out.CarPieces = append(out.CarPieces, carFile)

		err = resetCP(cp)
		if err != nil {
			return out, err
		}
		i++
	}
}

func readHeader(streamBuf *bufio.Reader, streamLen int64) ([]byte, int64, error) {
	maybeHeaderLen, err := streamBuf.Peek(varintSize)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to read header: %s", err)
	}

	hdrLen, viLen := binary.Uvarint(maybeHeaderLen)
	if hdrLen <= 0 || viLen < 0 {
		return nil, 0, fmt.Errorf("unexpected header len = %d, varint len = %d", hdrLen, viLen)
	}

	actualViLen, err := io.CopyN(io.Discard, streamBuf, int64(viLen))
	if err != nil {
		return nil, 0, fmt.Errorf("failed to discard header varint: %s", err)
	}
	streamLen += actualViLen

	headerBuf := new(bytes.Buffer)

	// ignoring header decoding for now
	actualHdrLen, err := io.CopyN(headerBuf, streamBuf, int64(hdrLen))
	if err != nil {
		return nil, 0, fmt.Errorf("failed to discard header header: %s", err)
	}
	streamLen += actualHdrLen

	return headerBuf.Bytes(), streamLen, nil
}

func resetCP(cp *commp.Calc) error {
	cp.Reset()
	_, err := cp.Write([]byte(nulRootCarHeader))
	return err
}

type fileLike interface {
	io.Writer
	io.Closer
	Sync() error
}

func cleanup(
	cp *commp.Calc,
	namePrefix string,
	index int,
	pieceFile fileLike,
	fBuf *bufio.Writer,
) (CarFile, error) {
	rawCommP, paddedSize, err := cp.Digest()
	if err != nil {
		return CarFile{}, err
	}

	commCid, err := commcid.DataCommitmentV1ToCID(rawCommP)
	if err != nil {
		return CarFile{}, err
	}

	err = fBuf.Flush()
	if err != nil {
		return CarFile{}, err
	}
	err = pieceFile.Sync()
	if err != nil {
		return CarFile{}, err
	}
	pieceFile.Close()

	oldn := fmt.Sprintf("%s%d.car", namePrefix, index)
	newn := fmt.Sprintf("%s%s.car", namePrefix, commCid)

	// if isn't devNullFile, then it's a real file, so we need to rename it
	if _, ok := pieceFile.(devNullFile); ok {
		err = os.Rename(oldn, newn)
		if err != nil {
			return CarFile{}, err
		}
	}

	return CarFile{
		Name:       newn,
		CommP:      commCid,
		PaddedSize: paddedSize,
	}, nil
}
