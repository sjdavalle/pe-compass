use std::collections::HashMap;
use std::ffi::{ OsString };

// 3rd Parties
use serde_derive::{ Deserialize, Serialize };

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
pub type BYTE       = u8;
pub type UCHAR      = u8;
pub type WORD       = u16;
pub type DWORD      = u32;
pub type QWORD      = u64;
pub type ULONG      = u32;
pub type ULONGLONG  = u64;
pub type LONG       = i32;
pub type BOOLEAN    = BYTE;
///
///
/// # IMAGE_DOS_HEADER
/// 
/// Size: 64 Bytes
///
#[derive(Debug, Copy, PartialEq, Pread, Pwrite, IOread, IOwrite, SizeWith, Deserialize, Serialize)]
#[repr(C)]
pub struct IMAGE_DOS_HEADER {
    pub e_magic:     WORD,         // Magic Number
    pub e_cblp:      WORD,         // Bytes on last page of file
    pub e_cp:        WORD,         // Pages in file
    pub e_crlc:      WORD,         // Relocations
    pub e_cparhdr:   WORD,         // Size of Header in pargraphs
    pub e_minalloc:  WORD,         // Minimum extra paragraphs needed
    pub e_maxalloc:  WORD,         // Maximum extra paragraphs needed
    pub e_ss:        WORD,         // Initial (relative) SS value
    pub e_sp:        WORD,         // Initial SP value
    pub e_csum:      WORD,         // Checksum
    pub e_ip:        WORD,         // Initial IP value
    pub e_cs:        WORD,         // Initial (relative) CS value
    pub e_lfarlc:    WORD,         // File Address Relocation Table
    pub e_ovno:      WORD,         // Overlay Number
    pub e_res:       [WORD; 4],    // Reserved Words
    pub e_oemid:     WORD,         // OEM Identifier
    pub e_oeminfo:   WORD,         // OEM Information, e_oemid specific
    pub e_res2:      [WORD; 10],   // Reserved Words
    pub e_lfanew:    LONG          // File Address of new exe header
}
impl ::std::clone::Clone for IMAGE_DOS_HEADER {
    fn clone(&self) -> Self {
        *self
    }
}
/// # IMAGE_NT_HEADERS32
/// 
/// Size: 248 Bytes
///         Signature:          4  Bytes
///         FileHeader:         20 Bytes
///         OptionalHeader32    224 Bytes
#[derive(Debug, Copy, PartialEq, Pread, Pwrite, IOread, IOwrite, SizeWith, Deserialize, Serialize)]
#[repr(C)]
pub struct IMAGE_NT_HEADERS32 {
    pub Signature:      DWORD,
    pub FileHeader:     IMAGE_FILE_HEADER,
    pub OptionalHeader: IMAGE_OPTIONAL_HEADER32
}
impl ::std::clone::Clone for IMAGE_NT_HEADERS32 {
    fn clone(&self) -> Self {
        *self
    }
}
/// # IMAGE_NT_HEADERS64
/// Size: 268 Bytes
///         Signature:          4   Bytes
///         FileHeader:         20  Bytes
///         OptionalHeader64:   244 Bytes
#[derive(Debug, Copy, PartialEq, Pread, Pwrite, IOread, IOwrite, SizeWith, Deserialize, Serialize)]
#[repr(C)]
pub struct IMAGE_NT_HEADERS64 {
    pub Signature:      DWORD,                  // 4 bytes
    pub FileHeader:     IMAGE_FILE_HEADER,      // 20 bytes
    pub OptionalHeader: IMAGE_OPTIONAL_HEADER64 // 244 bytes
}
impl ::std::clone::Clone for IMAGE_NT_HEADERS64 {
    fn clone(&self) -> Self {
        *self
    }
}
///
/// # IMAGE_FILE_HEADER
/// 
/// Size: 20 Bytes
/// 
#[derive(Debug, Copy, PartialEq, Pread, Pwrite, IOread, IOwrite, SizeWith, Deserialize, Serialize)]
#[repr(C)]
pub struct IMAGE_FILE_HEADER {
    pub Machine:                WORD,   // 2
    pub NumberOfSections:       WORD,   // 2
    pub TimeDateStamp:          DWORD,  // 4
    pub PointerToSymbolTable:   DWORD,  // 4
    pub NumberOfSymbols:        DWORD,  // 4
    pub SizeOfOptionalHeader:   WORD,   // 2
    pub Characteristics:        WORD,   // 2
}
impl ::std::clone::Clone for IMAGE_FILE_HEADER {
    fn clone(&self) -> Self {
        *self
    }
}
/// # IMAGE OPTIONAL HEADERS32
/// Used for 32 Bit files
/// Size: 224 Bytes
///     Standard Fields: 28 Bytes
///     Windows  Fields: 196 Bytes `includes Data Directories Array`
#[derive(Debug, Copy, PartialEq, Pread, Pwrite, IOread, IOwrite, SizeWith, Deserialize, Serialize)]
#[repr(C)]
pub struct IMAGE_OPTIONAL_HEADER32 {
    // Standard Fields
    pub Magic:                          WORD,   // 2    Describes PE Type: 32 or 64 Bit
    pub MajorLinkerVersion:             BYTE,   // 1
    pub MinorLinkerVersion:             BYTE,   // 1
    pub SizeOfCode:                     DWORD,  // 4
    pub SizeOfInitializedData:          DWORD,  // 4
    pub SizeOfUninitializedData:        DWORD,  // 4
    pub AddressOfEntryPoint:            DWORD,  // 4
    pub BaseOfCode:                     DWORD,  // 4
    pub BaseOfData:                     DWORD,  // 4
    // Windows Fields
    pub ImageBase:                      DWORD,  // 4
    pub SectionAlignment:               DWORD,  // 4
    pub FileAlignment:                  DWORD,  // 4
    pub MajorOperatingSystemVersion:    WORD,   // 2
    pub MinorOperatingSystemVersion:    WORD,   // 2
    pub MajorImageVersion:              WORD,   // 2
    pub MinorImageVersion:              WORD,   // 2    
    pub MajorSubsystemVersion:          WORD,   // 2
    pub MinorSubsystemVersion:          WORD,   // 2
    pub Win32VersionValue:              DWORD,  // 4
    pub SizeOfImage:                    DWORD,  // 4
    pub SizeOfHeaders:                  DWORD,  // 4
    pub CheckSum:                       DWORD,  // 4
    pub Subsystem:                      WORD,   // 2
    pub DllCharacteristics:             WORD,   // 2
    pub SizeOfStackReserve:             DWORD,  // 4
    pub SizeOfStackCommit:              DWORD,  // 4
    pub SizeOfHeapReserve:              DWORD,  // 4
    pub SizeOfHeapCommit:               DWORD,  // 4
    pub LoaderFlags:                    DWORD,  // 4 
    pub NumberOfRvaAndSizes:            DWORD,  // 4
    pub DataDirectory:                  [u64; 16usize]  // 8 * 16
}
impl ::std::clone::Clone for IMAGE_OPTIONAL_HEADER32 {
    fn clone(&self) -> Self {
        *self
    }
}
/// # IMAGE OPTIONAL HEADERS64
/// Used for PE64 Bit files.
/// Size = 240 Bytes
///     Standard Fields: 24 Bytes
///     Windows  Fields: 216 Bytes `includes Data_Directory Array`
#[derive(Debug, Copy, PartialEq, Pread, Pwrite, IOread, IOwrite, SizeWith, Deserialize, Serialize)]
#[repr(C)]
pub struct IMAGE_OPTIONAL_HEADER64 {
    // Standard Fields
    pub Magic:                          WORD,       // 2
    pub MajorLinkerVersion:             BYTE,       // 1
    pub MinorLinkerVersion:             BYTE,       // 1
    pub SizeOfCode:                     DWORD,      // 4
    pub SizeOfInitializedData:          DWORD,      // 4
    pub SizeOfUninitializedData:        DWORD,      // 4
    pub AddressOfEntryPoint:            DWORD,      // 4
    pub BaseOfCode:                     DWORD,      // 4
    // Windows Fields
    pub ImageBase:                      ULONGLONG,  // 8
    pub SectionAlignment:               DWORD,      // 4
    pub FileAlignment:                  DWORD,      // 4
    pub MajorOperatingSystemVersion:    WORD,       // 2
    pub MinorOperatingSystemVersion:    WORD,       // 2
    pub MajorImageVersion:              WORD,       // 2
    pub MinorImageVersion:              WORD,       // 2
    pub MajorSubsystemVersion:          WORD,       // 2
    pub MinorSubsystemVersion:          WORD,       // 2
    pub Win32VersionValue:              DWORD,      // 4
    pub SizeOfImage:                    DWORD,      // 4
    pub SizeOfHeaders:                  DWORD,      // 4
    pub CheckSum:                       DWORD,      // 4
    pub Subsystem:                      WORD,       // 2
    pub DllCharacteristics:             WORD,       // 2
    pub SizeOfStackReserve:             ULONGLONG,  // 8
    pub SizeOfStackCommit:              ULONGLONG,  // 8
    pub SizeOfHeapReserve:              ULONGLONG,  // 8
    pub SizeOfHeapCommit:               ULONGLONG,  // 8
    pub LoaderFlags:                    DWORD,      // 4
    pub NumberOfRvaAndSizes:            DWORD,      // 4
    pub DataDirectory:                  [u64; 16usize] // 8 * 16
}
impl ::std::clone::Clone for IMAGE_OPTIONAL_HEADER64 {
    fn clone(&self) -> Self {
        *self
    }
}
/// # IMAGE_SECTION_HEADER
/// Size: 40 Bytes
/// 
/// 
#[derive(Debug, Copy, PartialEq, Pread, Pwrite, IOread, IOwrite, SizeWith, Deserialize, Serialize)]
#[repr(C)]
pub struct IMAGE_SECTION_HEADER {
    pub Name:                           [BYTE; 8], // 8
    pub VirtualSize:                    DWORD,
    pub VirtualAddress:                 DWORD,  // 4
    pub SizeOfRawData:                  DWORD,  // 4
    pub PointerToRawData:               DWORD,  // 4
    pub PointerToRelocations:           DWORD,  // 4
    pub PointerToLinenumbers:           DWORD,  // 4
    pub NumberOfRelocations:            WORD,   // 2
    pub NumberOfLinenumbers:            WORD,   // 2
    pub Characteristics:                DWORD,  // 4
}
impl ::std::clone::Clone for IMAGE_SECTION_HEADER {
    fn clone(&self) -> Self {
        *self
    }
}
/// # IMAGE_DATA_DIRECTORY
/// There are 16 data directory structs.
/// 
#[derive(Debug, Copy, PartialEq, Pread, Pwrite, IOread, IOwrite, SizeWith, Deserialize, Serialize)]
#[repr(C)]
pub struct IMAGE_DATA_DIRECTORY {
    pub VirtualAddress:  DWORD,
    pub Size:            DWORD
}
impl ::std::clone::Clone for IMAGE_DATA_DIRECTORY {
    fn clone(&self) -> Self {
        *self
    }
}
///
/* 
#[derive(Debug, PartialEq, Pread, Pwrite, IOread, IOwrite, SizeWith, Deserialize, Serialize)]
#[repr(C)]
pub struct IMAGE_DIRECTORY_ENTRY_IMPORT {

}

impl ::std::clone::Clone for IMAGE_DIRECTORY_ENTRY_IMPORT {
    fn clone(&self) -> Self {
        *self
    }
}
*/
/// # DATA DIRECTORY IMPORT - IMPORT DESCRIPTOR
/// 
/// 
///
#[derive(Debug, Copy, PartialEq, PartialOrd, Pread, Pwrite, IOread, IOwrite, SizeWith, Deserialize, Serialize)]
#[repr(C)]
pub struct IMAGE_IMPORT_DESCRIPTOR {
    pub OriginalFirstThunk: DWORD,
    pub TimeDateStamp:      DWORD,
    pub ForwarderChain:     DWORD,
    pub Name:               DWORD,
    pub FirstThunk:         DWORD,
}
impl ::std::clone::Clone for IMAGE_IMPORT_DESCRIPTOR {
    fn clone(&self) -> Self {
        *self
    }
}

impl IMAGE_IMPORT_DESCRIPTOR {
    /// Allows you to compare the null terminating descriptor
    /// to identify the end of the content for a PE file.
    /// If this matches, the file has no more DLL imports as part of
    /// its `imports`
    pub fn load_null_descriptor() -> Self
    {
        IMAGE_IMPORT_DESCRIPTOR {
            OriginalFirstThunk  : 0,
            TimeDateStamp       : 0,
            ForwarderChain      : 0,
            Name                : 0,
            FirstThunk          : 0
        }
    }
}
///
/// 
/// 
#[derive(Debug, Copy, PartialEq, Pread, Pwrite, IOread, IOwrite, SizeWith, Deserialize, Serialize)]
#[repr(C)]
pub struct IMAGE_THUNK_DATA32 {
    pub AddressOfData:      DWORD,   // PIMAGE_IMPORT_BY_NAME
    pub Function:           DWORD,  // PDWORD
    pub Ordinal:            DWORD,
    pub ForwarderString:    DWORD,  // PBYTE
}

impl ::std::clone::Clone for IMAGE_THUNK_DATA32 {
    fn clone(&self) -> Self {
        *self
    }
}
///
/// 
///
#[derive(Debug, Copy, PartialEq, Pread, Pwrite, IOread, IOwrite, SizeWith, Deserialize, Serialize)]
#[repr(C)]
pub struct IMAGE_THUNK_DATA64 {
    pub AddressOfData:      QWORD,   // PIMAGE_IMPORT_BY_NAME
    pub Function:           QWORD,  // PDWORD
    pub Ordinal:            QWORD,
    pub ForwarderString:    QWORD,  // PBYTE
}
impl ::std::clone::Clone for IMAGE_THUNK_DATA64 {
    fn clone(&self) -> Self {
        *self
    }
}
///
/// 
///
#[derive(Debug, Copy, PartialEq, Pread, Pwrite, IOread, IOwrite, SizeWith, Deserialize, Serialize)]
#[repr(C)]
pub struct IMAGE_IMPORT_BY_NAME {
    pub Hint:   WORD,
    pub Name:   BYTE
}
impl ::std::clone::Clone for IMAGE_IMPORT_BY_NAME {
    fn clone(&self) -> Self {
        *self
    }
}
/// 
/// 
///  
#[derive(Debug, Copy, PartialEq, Pread, Pwrite, IOread, IOwrite, SizeWith)]
#[repr(C)]
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
impl ::std::clone::Clone for IMAGE_COFF_SYMBOLS_HEADER {
    fn clone(&self) -> Self {
        *self
    }
}
///
/// 
/// 
/// 
#[derive(Debug, Copy, PartialEq, Pread, Pwrite, IOread, IOwrite, SizeWith)]
#[repr(C)]
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
impl ::std::clone::Clone for IMAGE_DEBUG_DIRECTORY {
    fn clone(&self) -> Self {
        *self
    }
}
///
/// 
/// 
/// 
#[derive(Debug, Copy, PartialEq, Pread, Pwrite, IOread, IOwrite, SizeWith)]
#[repr(C)]
pub struct IMAGE_DEBUG_MISC {
    pub DataType:   DWORD,
    pub Length:     DWORD,
    pub Unicode:    BOOLEAN,
    pub Reserved:   [BYTE; 3],
    pub Data:       [BYTE; 0],
}
impl ::std::clone::Clone for IMAGE_DEBUG_MISC {
    fn clone(&self) -> Self {
        *self
    }
}
///
/// 
/// 
/// 
#[derive(Debug, Copy, PartialEq, Pread, Pwrite, IOread, IOwrite, SizeWith, Deserialize, Serialize)]
#[repr(C)]
pub struct IMAGE_FUNCTION_ENTRY {
    pub StartingAddress:    DWORD,
    pub EndingAddress:      DWORD,
    pub EndOfPrologue:      DWORD,
}
impl ::std::clone::Clone for IMAGE_FUNCTION_ENTRY {
    fn clone(&self) -> Self {
        *self
    }
}
///
/// 
/// 
/// 
#[derive(Debug, Copy, PartialEq, Pread, Pwrite, IOread, IOwrite, SizeWith, Deserialize, Serialize)]
#[repr(C)]
pub struct IMAGE_FUNCTION_ENTRY64 {
    pub StartingAddress:                    ULONGLONG,
    pub EndingAddress:                      ULONGLONG,
    pub EndOfPrologueOrUnwindInfoAddress:   ULONGLONG,
}
impl ::std::clone::Clone for IMAGE_FUNCTION_ENTRY64 {
    fn clone(&self) -> Self {
        *self
    }
}
#[derive(Debug, Copy, PartialEq, Pread, Pwrite, IOread, IOwrite, SizeWith, Deserialize, Serialize)]
#[repr(C)]
pub struct IMAGE_RUNTIME_FUNCTION_ENTRY {
    pub BeginAddress:       DWORD,
    pub EndAddress:         DWORD,
    pub UnwindInfoAddress:  DWORD,
}
impl ::std::clone::Clone for IMAGE_RUNTIME_FUNCTION_ENTRY {
    fn clone(&self) -> Self {
        *self
    }
}
///
/// 
/// 
/// 
#[derive(Debug, Copy, PartialEq, Pread, Pwrite, IOread, IOwrite, SizeWith)]
#[repr(C)]
pub struct IMAGE_RESOURCE_DIRECTORY {
    pub Characteristics:        DWORD,
    pub TimeDateStamp:          DWORD,
    pub MajorVersion:           WORD,
    pub MinorVersion:           WORD,
    pub NumberOfNamedEntries:   WORD,
    pub NumberOfIdEntries:      WORD
}
impl ::std::clone::Clone for IMAGE_RESOURCE_DIRECTORY {
    fn clone(&self) -> Self {
        *self
    }
}
/// # PE Custom Object Structs - CO_STRUCTS
/// The structs in this file are derived from the specification
/// structs located in the `pe_structs` file.
/// These structs are made for convenience of parsing and validating
/// the inspected file.
/// 
/// For example, to determine what type of PE is involved we need to
/// determine if it is a 32 or 64 bit by inspecting the `Magic` member
/// of the IMAGE_OPTIONAL_HEADER struct and its subsection group called
/// the `Standard Fields` members group.
/// 
/// We create a custom struct that we can read to access that field before
/// we load the relevant PE32 or PE64 struct.
/// 
/// All custom structs have a label that starts with `INSPECT_` when a subsection
/// of the PE Format specification is being validated.
///
/// In contrast, the `PE_32` or `PE_64` structs are a custom object that represent
/// the full values of a file being parsed.
/// 
#[derive(Debug, Copy, PartialEq, Pread, Pwrite, IOread, IOwrite, SizeWith, Deserialize, Serialize)]
#[repr(C)]
pub struct INSPECT_NT_HEADERS {
    pub Signature:      DWORD,
    pub FileHeader:     INSPECT_IMAGE_FILE_HEADER,
    pub OptionalHeader: INSPECT_IMAGE_OPTIONAL_HEADER
}
impl ::std::clone::Clone for INSPECT_NT_HEADERS {
    fn clone(&self) -> Self {
        *self
    }
}
///
/// 
/// 
#[derive(Debug, Copy, PartialEq, Pread, Pwrite, IOread, IOwrite, SizeWith, Deserialize, Serialize)]
#[repr(C)]
pub struct INSPECT_IMAGE_FILE_HEADER {
    pub Machine:                WORD,   // 2
    pub NumberOfSections:       WORD,   // 2
    pub TimeDateStamp:          DWORD,  // 4
    pub PointerToSymbolTable:   DWORD,  // 4
    pub NumberOfSymbols:        DWORD,  // 4
    pub SizeOfOptionalHeader:   WORD,   // 2
    pub Characteristics:        WORD,   // 2
}
impl ::std::clone::Clone for INSPECT_IMAGE_FILE_HEADER {
    fn clone(&self) -> Self {
        *self
    }
}
///
///
///
#[derive(Debug, Copy, PartialEq, Pread, Pwrite, IOread, IOwrite, SizeWith, Deserialize, Serialize)]
#[repr(C)]
pub struct INSPECT_IMAGE_OPTIONAL_HEADER {
    pub Magic:                          WORD,   // 2    Describes PE Type: 32 or 64 Bit
    pub MajorLinkerVersion:             BYTE,   // 1
    pub MinorLinkerVersion:             BYTE,   // 1
    pub SizeOfCode:                     DWORD,  // 4
    pub SizeOfInitializedData:          DWORD,  // 4
    pub SizeOfUninitializedData:        DWORD,  // 4
    pub AddressOfEntryPoint:            DWORD,  // 4
    pub BaseOfCode:                     DWORD,  // 4
    pub BaseOfData:                     DWORD,  // 4
}
impl ::std::clone::Clone for INSPECT_IMAGE_OPTIONAL_HEADER {
    fn clone(&self) -> Self {
        *self
    }
}

/// # PE_OBJECTS
/// These are the final objects used by the application to work with a PE file.
/// After the initial INSPECTION, based on the `Magic` field in the IMAGE_OPTIONAL_HEADER
/// the application will load the relevant 32 or 64 bit object to work with.
/// 
/// It is this PE_OBJECT that is processed throughout the program to achieve its working
/// objective
///
///
#[derive(Debug, Deserialize, Serialize)]
pub struct PE_FILE {
    //pub pename:                 OsString,
    pub petype:                 u16,
    pub ImageDosHeader:         IMAGE_DOS_HEADER,
    pub ImageDosStub:           String,
    pub ImageNtHeaders:         IMAGE_NT_HEADERS,
    pub ImageDataDirectory:     HashMap<String, IMAGE_DATA_DIRECTORY>,
    pub ImageSectionHeaders:    HashMap<String, IMAGE_SECTION_HEADER>,
    pub ImageDLLImports:        Vec<DLL_PROFILE>
}

///
///
///
#[derive(Debug, Copy, Deserialize, Serialize)]
pub enum IMAGE_NT_HEADERS {
    x86(IMAGE_NT_HEADERS32),
    x64(IMAGE_NT_HEADERS64)
}
impl ::std::clone::Clone for IMAGE_NT_HEADERS {
    fn clone(&self) -> Self {
        *self
    }
}
///
///
///
#[derive(Debug, Copy, PartialEq, Pread, Pwrite, IOread, IOwrite, SizeWith, Deserialize, Serialize)]
#[repr(C)]
pub struct PE_DOS_STUB {
    pub upper: [u8; 30],    // Avoid Rust Array 32 Length Error
    pub lower: [u8; 9]
}
impl ::std::clone::Clone for PE_DOS_STUB {
    fn clone(&self) -> Self {
        *self
    }
}
/// # PE_RVA_TRACKER
/// This is a custom object created to track the RVA conversion that leads to
/// physical file offset.  Given the recurrent translation of RVAs, this approach
/// is convenient
/// 
#[derive(Debug)]
#[repr(C)] 
pub struct PE_RVA_TRACKER {
    pub ta:           DWORD,    // Target Address 
    pub va:           DWORD,    // Virtual Address
    pub ra:           DWORD,    // Raw Address
    pub file_offset:  DWORD,    // Within File Location
    pub section_name: String,   // Section Where Target Address resides
    pub entry_name:   String,   // Name of Directory Entry
}

impl PE_RVA_TRACKER {
    pub fn new() -> Self
    {
        PE_RVA_TRACKER {
            ta: 0,
            va: 0,
            ra: 0,
            file_offset: 0,
            section_name: String::with_capacity(8usize),
            entry_name:   String::from("empty")
        }
    }
    ///
    /// 
    /// 
    /// 
    pub fn update(&mut self, _entry_name: &str, _ta: u32, _va: u32, _ra: u32, _name: String)
    {
        self.ta = _ta;
        self.va = _va;
        self.ra = _ra;
        self.section_name = _name;
        self.entry_name = _entry_name.to_string();
    }
    ///
    /// 
    /// 
    /// 
    pub fn get_file_offset(&mut self)
    {
        self.file_offset = self.ta - self.va + self.ra;
    }
    ///
    /// 
    /// 
    ///
    pub fn new_offset_from(&mut self, new_target_address: u32) -> usize
    {
        self.ta = new_target_address;
        self.file_offset = self.ta - self.va + self.ra;
        (self.ta - self.va + self.ra) as usize
    }
}
/// PE DLL IMPORTS - DLL PROFILE
/// 
/// 
///
#[derive(Hash, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct DLL_PROFILE {
    pub name:       String,
    pub imports:    usize,
    pub functions:  Vec<String>
}