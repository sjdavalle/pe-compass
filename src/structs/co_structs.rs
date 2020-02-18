#[ path = "./pe_structs.rs"] mod pe_structs;
use pe_structs::*;

/// # PE Custom Object Structs - CO_STRUCTS
/// The structs in this file are derived from the specification
/// structs located in the `pe_structs` file.
/// These structs are made for convenience of parsing and validating
/// the inspected file.
/// 
/// For example, to determine what type of PE is involved we need to
/// determine if it is a 32 or 64 bit by inspecting the `Magic` member
/// of the IMAGE_OPTIONAL_HEADER struct and its subsection group called
/// the `Standard Fields` struct members group.
/// 
/// We create a custom struct that we can read to access that field before
/// we load the relevant PE32 or PE64 struct.
/// 
/// All custom instructs have a label that starts with `INSPECT_` when a subsection
/// of the PE Format specification is being validated.
///
/// In contrast, the `PE_32` or `PE_64` structs are a custom object that represent
/// the full values of a file being parsed.
/// 
#[derive(Debug, PartialEq, Pread, Pwrite, IOread, IOwrite, SizeWith)]
#[repr(C)]
pub struct INSPECT_NT_HEADERS {
    Signature:      DWORD,
    FileHeader:     INSPECT_IMAGE_FILE_HEADER,
    OptionalHeader: INSPECT_IMAGE_OPTIONAL_HEADER
}

#[derive(Debug, Copy, PartialEq, Pread, Pwrite, IOread, IOwrite, SizeWith)]
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

#[derive(Debug, Copy, PartialEq, Pread, Pwrite, IOread, IOwrite, SizeWith)]
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