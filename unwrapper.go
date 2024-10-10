package origin_unwrapper //nolint:stylecheck,revive // wontfix

import (
	"bytes"
	"crypto/sha1" //nolint:gosec // wontfix
	"debug/pe"
	"encoding/binary"
	"fmt"
	"os"

	"github.com/ricochhet/readwrite"
	"github.com/ricochhet/simplecrypto"
	"github.com/ricochhet/simplelog"
)

//nolint:funlen,gocognit,gocyclo,cyclop // wontfix
func Unwrap(fileMap *readwrite.Data, versionPtr, getDlfKey, dlfKeyPtr, outputPathPtr string, addDllPtr bool) {
	sectionsNum := len(fileMap.PE.Sections)
	sectionHeader := fileMap.PE.Sections[sectionsNum-1]

	if sectionHeader.Name != ".ooa" {
		simplelog.SharedLogger.Fatal("Error: invalid PE File! Section name is not '.ooa'")
	}

	section := fileMap.Bytes[sectionHeader.Offset : sectionHeader.Offset+sectionHeader.Size]
	hash := simplecrypto.GetOoaHash(section)

	versionHash := sha1.New() //nolint:gosec // wontfix
	versionHash.Write([]byte(versionPtr))
	eq := bytes.Compare(hash, versionHash.Sum(nil))

	if eq != 0 {
		simplelog.SharedLogger.Fatal("Error: hash version invalid")
		return
	}

	var sectionData readwrite.Section

	sectionData, err := Parse(section)
	if err != nil {
		simplelog.SharedLogger.Fatalf("Error parsing file: %s", err)
	}

	if sectionData.ImageBase != 0 {
		peHeader, ok := fileMap.PE.OptionalHeader.(*pe.OptionalHeader64)

		if !ok {
			simplelog.SharedLogger.Fatal("Error: type assertion")
		}

		val := peHeader.ImageBase == sectionData.ImageBase

		fmt.Printf("Assert: %t (sectionData.ImageBase != 0)\n", val)
	}

	//nolint:nestif // wontfix
	if len(getDlfKey) != 0 {
		var dlf []byte

		if len(os.Args) > 2 { //nolint:mnd // wontfix
			data, err := os.ReadFile(getDlfKey)
			if err == nil {
				dlf, err = simplecrypto.DecryptDLF(data)
				if err != nil {
					simplelog.SharedLogger.Fatal("Error: DecryptDLF()")
				}
			}
		} else {
			dlf, err = simplecrypto.GetDLFAuto(getDlfKey + sectionData.ContentID)
			if err != nil {
				simplelog.SharedLogger.Fatal("Error: GetDLFAuto()")
			}
		}

		if len(dlf) == 0 {
			simplelog.SharedLogger.Fatal("Error: len(dlf) == 0")
		}

		fmt.Printf("DLF: %s\n", string(dlf))
		dlfKey, err := simplecrypto.DecodeCipherTag(dlf)

		if dlfKey == nil {
			simplelog.SharedLogger.Fatal("Error: failed to get CipherKey from DLF!")
		}

		if err != nil {
			simplelog.SharedLogger.Fatal("Error: DecodeCipherTag()")
		}

		dlfKeyPtr = string(dlfKey)
	}

	newBytes := append([]byte(nil), fileMap.Bytes...)
	elfanew := binary.LittleEndian.Uint32(fileMap.Bytes[60:64])
	fileHeaderSize := uint32(24) //nolint:mnd // wontfix

	for _, block := range sectionData.EncBlocks {
		var decryptHeader *pe.Section

		for _, s := range fileMap.PE.Sections {
			if s.VirtualAddress == block.VA {
				decryptHeader = s
				break
			}
		}

		if decryptHeader == nil {
			panic("(panic)Error: failed to find section for decryption!\n")
		}

		iv := make([]byte, 16) //nolint:mnd // wontfix
		copy(iv, newBytes[decryptHeader.Offset-0x10:decryptHeader.Offset])

		err := simplecrypto.AESDecryptBase64(dlfKeyPtr, iv, newBytes[decryptHeader.Offset:decryptHeader.Offset+decryptHeader.Size])
		if err != nil {
			panic(fmt.Errorf("(panic)Error: %w", err))
		}

		aesCBCPadding := []byte{0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10}

		if bytes.Equal(newBytes[decryptHeader.Offset+decryptHeader.Size-0x10:decryptHeader.Offset+decryptHeader.Size], aesCBCPadding) {
			copy(newBytes[decryptHeader.Offset+decryptHeader.Size-0x10:decryptHeader.Offset+decryptHeader.Size],
				make([]byte, 16)) //nolint:mnd // wontfix
		}
	}

	oepOff := elfanew + fileHeaderSize + 16                                           //nolint:mnd // wontfix
	binary.LittleEndian.PutUint32(newBytes[oepOff:oepOff+4], uint32(sectionData.OEP)) //nolint:gosec // wontfix

	if sectionData.ImportDir.VA != 0 && sectionData.ImportDir.Size != 0 {
		importDirOff := elfanew + fileHeaderSize + 120 //nolint:mnd // wontfix
		binary.LittleEndian.PutUint32(newBytes[importDirOff:importDirOff+4], sectionData.ImportDir.VA)
		binary.LittleEndian.PutUint32(newBytes[importDirOff+4:importDirOff+8], sectionData.ImportDir.Size)
	} else {
		fmt.Printf("Warning: did not fix ImportDir: %v\n", sectionData.ImportDir)
	}

	if sectionData.RelocDir.VA != 0 && sectionData.RelocDir.Size != 0 {
		relocDirOff := elfanew + fileHeaderSize + 152 //nolint:mnd // wontfix
		binary.LittleEndian.PutUint32(newBytes[relocDirOff:relocDirOff+4], sectionData.RelocDir.VA)
		binary.LittleEndian.PutUint32(newBytes[relocDirOff+4:relocDirOff+8], sectionData.RelocDir.Size)
	} else {
		fmt.Printf("Warning: did not fix Weird RelocDir: %v\n", sectionData.RelocDir)
	}

	if sectionData.IATDir.VA != 0 && sectionData.IATDir.Size != 0 {
		iatOff := elfanew + fileHeaderSize + 208 //nolint:mnd // wontfix
		binary.LittleEndian.PutUint32(newBytes[iatOff:iatOff+4], sectionData.IATDir.VA)
		binary.LittleEndian.PutUint32(newBytes[iatOff+4:iatOff+8], sectionData.IATDir.Size)
	} else {
		fmt.Printf("Warning: did not fix Weird IATDir: %v\n", sectionData.IATDir)
	}

	if err := os.WriteFile(outputPathPtr, newBytes, 0o600); err != nil {
		simplelog.SharedLogger.Fatalf("Error writing file: %s", err)
	}

	if addDllPtr {
		addDllToExe, err := readwrite.Open(outputPathPtr)
		if err != nil {
			simplelog.SharedLogger.Fatalf("Error opening file: %s", err)
		}

		dllEntries := []DLLEntry{
			{
				DLL:   "anadius64",
				Names: []string{"anadius"},
			},
		}

		if err := AddDLLImports(addDllToExe, *sectionHeader, ".anadius", dllEntries, true); err != nil {
			panic(fmt.Errorf("(panic)Error: %w", err))
		}

		patchedExeBytes := append([]byte(nil), addDllToExe.Bytes...)

		if err := os.WriteFile(outputPathPtr, patchedExeBytes, 0o600); err != nil {
			simplelog.SharedLogger.Fatalf("Error writing file: %s", err)
		}
	}
}
