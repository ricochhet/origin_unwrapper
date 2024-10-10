package origin_unwrapper //nolint:stylecheck,revive // wontfix

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"errors"

	"github.com/ricochhet/readwrite"
	"github.com/ricochhet/simpleutil"
)

type DLLEntry struct {
	DLL   string
	Names []string
}

var (
	errPatchImportTable          = errors.New("error: patchImportTable()")
	errTypeAssertion             = errors.New("error: type assertion")
	errNewImportDirectoryDDEntry = errors.New("error: newImportDirectoryDDEntry > 8")
)

//nolint:funlen,gocognit,gocyclo,cyclop // wontfix
func patchImportTable(file *readwrite.Data, address int, dllsToAdd []DLLEntry, addInFront bool) ([]byte, error) {
	if len(dllsToAdd) == 0 {
		return nil, errPatchImportTable
	}

	optionalHeader, ok := file.PE.OptionalHeader.(*pe.OptionalHeader64)
	if !ok {
		return nil, errTypeAssertion
	}

	var importDirectory pe.DataDirectory

	if optionalHeader != nil {
		dataDirectories := optionalHeader.DataDirectory
		if len(dataDirectories) > int(pe.IMAGE_DIRECTORY_ENTRY_IMPORT) {
			importDirectory = dataDirectories[pe.IMAGE_DIRECTORY_ENTRY_IMPORT]
		}
	}

	importDirectoryDDOffset, err := readwrite.ReadDDEntryOffset(file.Bytes, importDirectory.VirtualAddress, importDirectory.Size)
	if importDirectoryDDOffset == -1 || err != nil {
		return nil, err
	}

	importDirectoryBytes, err := readwrite.ReadSectionBytes(file, importDirectory.VirtualAddress, importDirectory.Size)
	if err != nil {
		return nil, err
	}

	var addresses [][]int //nolint:prealloc // wontfix

	var result []byte

	for _, entry := range dllsToAdd {
		addresses = append(addresses, []int{address})
		nameBytes := simpleutil.StringToBytes(entry.DLL)
		result = append(result, nameBytes...)
		address += len(nameBytes)
	}

	var allNameAddresses [][]int //nolint:prealloc // wontfix

	for _, names := range dllsToAdd {
		var nameAddresses []int

		for _, name := range names.Names {
			nameAddresses = append(nameAddresses, address)
			nameBytes := simpleutil.StringToBytes(name)

			result = append(result, 0x00, 0x00) //nolint:mnd // wontfix
			result = append(result, nameBytes...)

			address += 2 + len(nameBytes) //nolint:mnd // wontfix
		}

		allNameAddresses = append(allNameAddresses, nameAddresses)
	}

	for i, nameAddresses := range allNameAddresses {
		addresses[i] = append(addresses[i], address)
		nameAddresses = append(nameAddresses, 0)

		var tmpBuffer bytes.Buffer
		for _, nameAddress := range nameAddresses {
			err := binary.Write(&tmpBuffer, binary.LittleEndian, int64(nameAddress))
			if err != nil {
				panic(err)
			}
		}

		tmp := tmpBuffer.Bytes()
		result = append(result, tmp...)
		address += len(tmp)
	}

	if optionalHeader != nil {
		if len(optionalHeader.DataDirectory) > int(pe.IMAGE_DIRECTORY_ENTRY_IMPORT) {
			importDirectory.VirtualAddress = uint32(address) //nolint:gosec // wontfix
		}
	}

	var newImportDirectoryDDEntry []byte

	newImportDirectoryVirtualAddress := make([]byte, 4) //nolint:mnd // wontfix

	binary.LittleEndian.PutUint32(newImportDirectoryVirtualAddress, uint32(address)) //nolint:gosec // wontfix
	newImportDirectoryDDEntry = append(newImportDirectoryDDEntry, newImportDirectoryVirtualAddress...)

	var addedData []byte

	for _, a := range addresses {
		bytes := make([]byte, 20)                               //nolint:mnd // wontfix
		binary.LittleEndian.PutUint32(bytes[12:], uint32(a[0])) //nolint:gosec // wontfix
		binary.LittleEndian.PutUint32(bytes[16:], uint32(a[1])) //nolint:gosec // wontfix
		addedData = append(addedData, bytes...)
	}

	var newImportDirectoryBytes []byte

	if addInFront {
		newImportDirectoryBytes = append(addedData, importDirectoryBytes...) //nolint:gocritic // wontfix
	} else {
		importDirectoryBytesLength := len(importDirectoryBytes)
		newImportDirectoryBytes = append(importDirectoryBytes[:importDirectoryBytesLength-20], addedData...) //nolint:gocritic // wontfix
		newImportDirectoryBytes = append(newImportDirectoryBytes, importDirectoryBytes[importDirectoryBytesLength-20:]...)
	}

	if optionalHeader != nil {
		if len(optionalHeader.DataDirectory) > int(pe.IMAGE_DIRECTORY_ENTRY_IMPORT) {
			if addInFront {
				newImportDirectorySize := make([]byte, 4)                                                   //nolint:mnd // wontfix
				binary.LittleEndian.PutUint32(newImportDirectorySize, uint32(len(newImportDirectoryBytes))) //nolint:gosec // wontfix
				newImportDirectoryDDEntry = append(newImportDirectoryDDEntry, newImportDirectorySize...)
			}
		}
	}

	if len(newImportDirectoryDDEntry) > 8 { //nolint:mnd // wontfix
		return nil, errNewImportDirectoryDDEntry
	}

	result = append(result, newImportDirectoryBytes...)

	if err := readwrite.WriteBytes(file.Bytes, importDirectoryDDOffset, newImportDirectoryDDEntry); err != nil {
		return nil, err
	}

	return result, nil
}

//nolint:cyclop // wontfix
func AddDLLImports(file *readwrite.Data, section pe.Section, newSectionName string, dllsToAdd []DLLEntry, addInFront bool) error {
	sectionSizeBytes := make([]byte, 2048) //nolint:mnd // wontfix
	binary.LittleEndian.PutUint32(sectionSizeBytes, section.Size)

	if err := readwrite.WriteBytes(file.Bytes, int(section.Offset), sectionSizeBytes); err != nil {
		return err
	}

	imports, err := patchImportTable(file, int(section.VirtualAddress), dllsToAdd, addInFront)
	if err != nil {
		return err
	}

	if err := readwrite.WriteBytes(file.Bytes, int(section.Offset), imports); err != nil {
		return err
	}

	shSize, err := readwrite.ReadSHSize(file.PE)
	if err != nil {
		return err
	}

	shBytes, err := readwrite.ReadSHBytes(file.Bytes, shSize)
	if err != nil {
		return err
	}

	shtFind, err := readwrite.FindBytes(shBytes, readwrite.PadBytes([]byte(section.Name), 8)) //nolint:mnd // wontfix
	if err != nil {
		return err
	}

	if shtFind != -1 {
		offset, err := readwrite.ReadSHEntryOffset(file.Bytes, shtFind)
		if err != nil {
			return err
		}

		if err := readwrite.WriteBytes(file.Bytes, offset, readwrite.PadBytes([]byte(newSectionName), 8)); err != nil { //nolint:mnd // wontfix
			return err
		}

		//nolint:lll // wontfix
		if err := readwrite.WriteBytes(file.Bytes, offset+readwrite.SH32NameSize+readwrite.SH32ByteSize, []byte{0x40, 0x00, 0x00, 0xC0}); err != nil {
			return err
		}
	}

	return nil
}
