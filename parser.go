package origin_unwrapper //nolint:stylecheck,revive // wontfix

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/ricochhet/readwrite"
	"github.com/ricochhet/simpleutil"
)

var errUnkNotZero = errors.New("error: unk != 1")

//nolint:funlen,gocognit,gocyclo,cyclop // wontfix
func Parse(data []byte) (readwrite.Section, error) {
	contentID := simpleutil.GetStringFromBytes(data, 0x42, 0x240) //nolint:mnd // wontfix
	reader := bytes.NewReader(data)

	if _, err := reader.Seek(0x242, io.SeekStart); err != nil { //nolint:mnd // wontfix
		return readwrite.Section{}, err
	}

	for {
		var importData readwrite.Import

		if err := binary.Read(reader, binary.LittleEndian, &importData); err != nil {
			break
		}

		if importData.Characteristics == 0 {
			break
		}
	}

	for {
		var iatData readwrite.Thunk

		if err := binary.Read(reader, binary.LittleEndian, &iatData); err != nil {
			break
		}

		if iatData.Function == 0 {
			break
		}
	}

	for {
		var originalData readwrite.Thunk
		if err := binary.Read(reader, binary.LittleEndian, &originalData); err != nil {
			break
		}

		if originalData.Function == 0 {
			break
		}
	}

	if _, err := reader.Seek(72, io.SeekCurrent); err != nil { //nolint:mnd // wontfix
		return readwrite.Section{}, err
	}

	var relocMaxSize uint32

	if err := binary.Read(reader, binary.LittleEndian, &relocMaxSize); err != nil {
		return readwrite.Section{}, fmt.Errorf("error: relocMaxSize %w", err)
	}

	var relocNewSize uint32

	if err := binary.Read(reader, binary.LittleEndian, &relocNewSize); err != nil {
		return readwrite.Section{}, fmt.Errorf("error: relocNewSize %w", err)
	}

	if _, err := reader.Seek(int64(relocMaxSize), io.SeekCurrent); err != nil {
		return readwrite.Section{}, err
	}

	var tls uint32

	if err := binary.Read(reader, binary.LittleEndian, &tls); err != nil {
		return readwrite.Section{}, fmt.Errorf("error: tls %w", err)
	}

	var tlsCallback uint32

	if err := binary.Read(reader, binary.LittleEndian, &tlsCallback); err != nil {
		return readwrite.Section{}, fmt.Errorf("error: tlsCallback %w", err)
	}

	var tlsFirstCallback uint64

	if err := binary.Read(reader, binary.LittleEndian, &tlsFirstCallback); err != nil {
		return readwrite.Section{}, fmt.Errorf("error: tlsFirstCallback %w", err)
	}

	var oep uint32

	if err := binary.Read(reader, binary.LittleEndian, &oep); err != nil {
		return readwrite.Section{}, fmt.Errorf("error: oep %w", err)
	}

	encBlocksCount, _ := reader.ReadByte()
	encBlocks := make([]readwrite.EncBlock, encBlocksCount)

	// for i := 0; i < int(encBlocksCount); i++ {
	// 	encBlocks[i], _ = readwrite.ReadEncBlock(reader)
	// }

	for i := range encBlocksCount {
		encBlocks[i], _ = readwrite.ReadEncBlock(reader)
	}

	if _, err := reader.Seek(393, io.SeekCurrent); err != nil { //nolint:mnd // wontfix
		return readwrite.Section{}, err
	}

	unk, _ := reader.ReadByte()

	if unk != 1 {
		return readwrite.Section{}, errUnkNotZero
	}

	var imageBase uint64

	if err := binary.Read(reader, binary.LittleEndian, &imageBase); err != nil {
		return readwrite.Section{}, fmt.Errorf("error: imageBase %w", err)
	}

	var sizeOfImage uint32

	if err := binary.Read(reader, binary.LittleEndian, &sizeOfImage); err != nil {
		return readwrite.Section{}, fmt.Errorf("error: sizeOfImage %w", err)
	}

	importDir, err := readwrite.ReadDataDir(reader)
	if err != nil {
		return readwrite.Section{}, err
	}

	relocDir, err := readwrite.ReadDataDir(reader)
	if err != nil {
		return readwrite.Section{}, err
	}

	iatDir, err := readwrite.ReadDataDir(reader)
	if err != nil {
		return readwrite.Section{}, err
	}

	return readwrite.Section{
		ContentID:   contentID,
		OEP:         uint64(oep),
		EncBlocks:   encBlocks,
		ImageBase:   imageBase,
		SizeOfImage: sizeOfImage,
		ImportDir:   importDir,
		RelocDir:    relocDir,
		IATDir:      iatDir,
	}, nil
}
