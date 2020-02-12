///
/// # Portable Executable Structures
/// 
/// These structs are taken from the specification documented
/// publicly,  For convenience of applying that specification
/// into a rust program, we will use the names of the windows
/// types as defined but translated to native `RUST` types,
/// ```
/// type WORD  = u16,
/// type DWORD = u32,
/// ```
/// The above type definition within RUST allows us to not have
/// ambiguous or significant deviation from the sepcification from
/// Microsoft,
/// 
/// Lastly, reference the `wintypes,rs` file where the translated
/// windows types to rust are kept to keep things clean,
/// 
use crate::structs::pe::wintypes::*,

/// # PE Constants
/// 
pub const IMAGE_DIRECTORY_ENTRY_EXPORT:         WORD   = 0;
pub const IMAGE_DIRECTORY_ENTRY_IMPORT:         WORD   = 1;
pub const IMAGE_DIRECTORY_ENTRY_RESOURCE:       WORD   = 2;
pub const IMAGE_DIRECTORY_ENTRY_EXCEPTION:      WORD   = 3;
pub const IMAGE_DIRECTORY_ENTRY_SECURITY:       WORD   = 4;
pub const IMAGE_DIRECTORY_ENTRY_BASERELOC:      WORD   = 5;
pub const IMAGE_DIRECTORY_ENTRY_DEBUG:          WORD   = 6;
pub const IMAGE_DIRECTORY_ENTRY_COPYRIGHT:      WORD   = 7;
pub const IMAGE_DIRECTORY_ENTRY_GLOBALPTR:      WORD   = 8;
pub const IMAGE_DIRECTORY_ENTRY_TLS:            WORD   = 9;
pub const IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG:    WORD   = 10;
pub const IMAGE_NUMBEROF_DIRECTORY_ENTRIES:     WORD   = 16;
pub const IMAGE_ENCLAVE_SHORT_ID_LENGTH:        WORD   = ENCLAVE_SHORT_ID_LENGTH;
pub const IMAGE_ENCLAVE_LONG_ID_LENGTH:         WORD   = ENCLAVE_LONG_ID_LENGTH; 
/// # Additional Constants used in PE Structures
pub const ENCLAVE_SHORT_ID_LENGTH:              WORD   = 16;
pub const ENCLAVE_LONG_ID_LENGTH:               WORD   = 32;
///
/// # IMAGE_DOS_HEADER
/// 
///
#[derive(Debug)]
pub struct IMAGE_DOS_HEADER {
    pub e_magic:     USHORT,         // Magic Number
    pub e_cblp:      USHORT,         // Bytes on last page of file
    pub e_cp:        USHORT,         // Pages in file
    pub e_crlc:      USHORT,         // Relocations
    pub e_cparhdr:   USHORT,         // Size of Header in pargraphs
    pub e_minalloc:  USHORT,         // Minimum extra paragraphs needed
    pub e_maxalloc:  USHORT,         // Maximum extra paragraphs needed
    pub e_ss:        USHORT,         // Initial (relative) SS value
    pub e_sp:        USHORT,         // Initial SP value
    pub e_csum:      USHORT,         // Checksum
    pub e_ip:        USHORT,         // Initial IP value
    pub e_cs:        USHORT,         // Initial (relative) CS value
    pub e_lfarlc:    USHORT,         // File Address Relocation Table
    pub e_ovno:      USHORT,         // Overlay Number
    pub e_res:       [USHORT, 4],    // Reserved Words
    pub e_oemid:     USHORT,         // OEM Identifier
    pub e_oeminfo:   USHORT,         // OEM Information, e_oemid specific
    pub e_res:       [USHORT, 10],   // Reserved Words
    pub e_lfanew:    LONG            // File Address of new exe header
}


#[derive(Debug)]
pub struct IMAGE_FILE_HEADER {
    pub Machine:                WORD,
    pub NumberOfSections:       WORD,
    pub TimeDateStamp:          DWORD,
    pub PointerToSymbolTable:   DWORD,
    pub NumberOfSymbols:        DWORD,
    pub SizeOfOptionalHeader:   WORD,
    pub Characteristics:        WORD,
}


#[derive(Debug)]
pub struct IMAGE_OPTIONAL_HEADER32 {
    pub Magic:                          WORD,
    pub MajorLinkerVersion:             BYTE,
    pub MinorLinkerVersion:             BYTE,
    pub SizeOfCode:                     DWORD,
    pub SizeOfInitializedData:          DWORD,
    pub SizeOfUninitializedData:        DWORD,
    pub AddressOfEntryPoint:            DWORD,
    pub BaseOfCode:                     DWORD,
    pub BaseOfData:                     DWORD,
    pub ImageBase:                      DWORD,
    pub SectionAlignment:               DWORD,
    pub FileAlignment:                  DWORD,
    pub MajorOperatingSystemVersion:    WORD,
    pub MinorOperatingSystemVersion:    WORD,
    pub MajorImageVersion:              WORD,
    pub MinorImageVersion:              WORD,
    pub MajorSubsystemVersion:          WORD,
    pub MinorSubsystemVersion:          WORD,
    pub Win32VersionValue:              DWORD,
    pub SizeOfImage:                    DWORD,
    pub SizeOfHeaders:                  DWORD,
    pub CheckSum:                       DWORD,
    pub Subsystem:                      WORD,
    pub DllCharacteristics:             WORD,
    pub SizeOfStackReserve:             DWORD,
    pub SizeOfStackCommit:              DWORD,
    pub SizeOfHeapReserve:              DWORD,
    pub SizeOfHeapCommit:               DWORD,
    pub LoaderFlags:                    DWORD,
    pub NumberOfRvaAndSizes:            DWORD,
    pub DataDirectory:                  [IMAGE_DATA_DIRECTORY; IMAGE_NUMBEROF_DIRECTORY_ENTRIES],
}


pub struct IMAGE_OPTIONAL_HEADER64 {
    pub Magic:                          WORD,
    pub MajorLinkerVersion:             BYTE,
    pub MinorLinkerVersion:             BYTE,
    pub SizeOfCode:                     DWORD,
    pub SizeOfInitializedData:          DWORD,
    pub SizeOfUninitializedData:        DWORD,
    pub AddressOfEntryPoint:            DWORD,
    pub BaseOfCode:                     DWORD,
    pub ImageBase:                      ULONGLONG,
    pub SectionAlignment:               DWORD,
    pub FileAlignment:                  DWORD,
    pub MajorOperatingSystemVersion:    WORD,
    pub MinorOperatingSystemVersion:    WORD,
    pub MajorImageVersion:              WORD,
    pub MinorImageVersion:              WORD,
    pub MajorSubsystemVersion:          WORD,
    pub MinorSubsystemVersion:          WORD,
    pub Win32VersionValue:              DWORD,
    pub SizeOfImage:                    DWORD,
    pub SizeOfHeaders:                  DWORD,
    pub CheckSum:                       DWORD,
    pub Subsystem:                      WORD,
    pub DllCharacteristics:             WORD,
    pub SizeOfStackReserve:             ULONGLONG,
    pub SizeOfStackCommit:              ULONGLONG,
    pub SizeOfHeapReserve:              ULONGLONG,
    pub SizeOfHeapCommit:               ULONGLONG,
    pub LoaderFlags:                    DWORD,
    pub NumberOfRvaAndSizes:            DWORD,
    pub DataDirectory:                  [IMAGE_DATA_DIRECTORY; IMAGE_NUMBEROF_DIRECTORY_ENTRIES],
}


#[derive(Debug)]
pub struct IMAGE_DATA_DIRECTORY {
    pub VirtualAddress:  ULONG,
    pub Size:            ULONG
}


#[derive(Debug)]
pub struct IMAGE_NT_HEADERS32 {
    pub Signature:      DWORD,
    pub FileHeader:     IMAGE_FILE_HEADER,
    pub OptionalHeader: IMAGE_OPTIONAL_HEADER32
}


#[derive(Debug)]
pub struct IMAGE_NT_HEADERS64 {
    pub Signature:      DWORD,
    pub FileHeader:     IMAGE_FILE_HEADER,
    pub OptionalHeader: IMAGE_OPTIONAL_HEADER64
}


[derive(Debug)]
pub struct IMAGE_COFF_SYMBOLS_HEADER {
    pub NumberOfSymbols:        DWORD,
    pub LvaToFirstSymbol:       DWORD,
    pub NumberOfLinenumbers:    DWORD,
    pub LvaToFirstLinenumber:   DWORD,
    pub RvaToFirstByteOfCode:   DWORD,
    pub RvaToLastByteOfCode:    DWORD,
    pub RvaToFirstByteOfData:   DWORD,
    pub RvaToLastByteOfData:    DWORD,
}


#[derive(Debug)]
pub struct IMAGE_DEBUG_DIRECTORY {
    pub Characteristics:    DWORD,
    pub TimeDateStamp:      DWORD,
    pub MajorVersion:       WORD,
    pub MinorVersion:       WORD,
    pub Type:               DWORD,
    pub SizeOfData:         DWORD,
    pub AddressOfRawData:   DWORD,
    pub PointerToRawData:   DWORD,
}


#[derive(Debug)]
pub struct IMAGE_DEBUG_MISC {
    pub DataType:   DWORD,
    pub Length:     DWORD,
    pub Unicode:    BOOLEAN,
    pub Reserved:   [BYTE, 3],
    pub Data:       [BYTE, 0],
}


#[derive(Debug)]
pub struct IMAGE_FUNCTION_ENTRY {
    pub StartingAddress:    DWORD,
    pub EndingAddress:      DWORD,
    pub EndOfPrologue:      DWORD,
}


#[derive(Debug)]
pub struct IMAGE_FUNCTION_ENTRY64 {
    pub StartingAddress:                    ULONGLONG,
    pub EndingAddress:                      ULONGLONG,
    pub EndOfPrologueOrUnwindInfoAddress:   ULONGLONG,
}


#[derive(Debug)]
pub struct IMAGE_ROM_HEADERS {
    pub FileHeader:     IMAGE_FILE_HEADER,
    pub OptionalHeader: IMAGE_ROM_OPTIONAL_HEADER,
}


#[derive(Debug)]
pub struct IMAGE_ROM_OPTIONAL_HEADER {
    pub Magic:                      WORD,
    pub MajorLinkerVersion:         BYTE,
    pub MinorLinkerVersion:         BYTE,
    pub SizeOfCode:                 DWORD,
    pub SizeOfInitializedData:      DWORD,
    pub SizeOfUninitializedData:    DWORD,
    pub AddressOfEntryPoint:        DWORD,
    pub BaseOfCode:                 DWORD,
    pub BaseOfData:                 DWORD,
    pub BaseOfBss:                  DWORD,
    pub GprMask:                    DWORD,
    pub CprMask:                    [DWORD; 4],
    pub GpValue:                    DWORD,
}


#[derive(Debug)]
pub struct IMAGE_RUNTIME_FUNCTION_ENTRY {
    pub BeginAddress:       DWORD,
    pub EndAddress:         DWORD,
    pub UnwindInfoAddress:  DWORD,
}


#[derive(Debug)]
pub struct IMAGE_SECTION_HEADER {
    pub Name:                           [BYTE; 8],
    pub PhysicalAddressOrVirtualSize:   DWORD,
    pub VirtualAddress:                 DWORD,
    pub SizeOfRawData:                  DWORD,
    pub PointerToRawData:               DWORD,
    pub PointerToRelocations:           DWORD,
    pub PointerToLinenumbers:           DWORD,
    pub NumberOfRelocations:            WORD,
    pub NumberOfLinenumbers:            WORD,
    pub Characteristics:                DWORD,
}


#[derive(Debug)]
pub struct IMAGE_RESOURCE_DIRECTORY {
    pub Characteristics:        DWORD,
    pub TimeDateStamp:          DWORD,
    pub MajorVersion:           WORD,
    pub MinorVersion:           WORD,
    pub NumberOfNamedEntries:   WORD,
    pub NumberOfIdEntries:      WORD
}



#[derive(Debug)]
pub struct IMAGE_ENCLAVE_CONFIG32 {
    pub Size:                        DWORD,
    pub MinimumRequiredConfigSize:   DWORD,
    pub PolicyFlags:                 DWORD,
    pub NumberOfImports:             DWORD,
    pub ImportList:                  DWORD,
    pub ImportEntrySize:             DWORD,
    pub FamilyID:                    [BYTE; IMAGE_ENCLAVE_SHORT_ID_LENGTH],
    pub ImageID:                     [BYTE; IMAGE_ENCLAVE_SHORT_ID_LENGTH],
    pub ImageVersion:                BYTE,
    pub SecurityVersion:             DWORD,
    pub EnclaveSize:                 DWORD,
    pub NumberOfThreads:             DWORD,
    pub EnclaveFlags:                DWORD,
}


#[derive(Debug)]
struct IMAGE_ENCLAVE_CONFIG64 {
    pub Size:                        DWORD,
    pub MinimumRequiredConfigSize:   DWORD,
    pub PolicyFlags:                 DWORD,
    pub NumberOfImports:             DWORD,
    pub ImportList:                  DWORD,
    pub ImportEntrySize:             DWORD,
    pub FamilyID:                    [BYTE; IMAGE_ENCLAVE_SHORT_ID_LENGTH],
    pub ImageID:                     [BYTE; IMAGE_ENCLAVE_SHORT_ID_LENGTH],
    pub ImageVersion:                BYTE,
    pub SecurityVersion:             DWORD,
    pub EnclaveSize:                 DWORD,
    pub NumberOfThreads:             DWORD,
    pub EnclaveFlags:                DWORD,
} 