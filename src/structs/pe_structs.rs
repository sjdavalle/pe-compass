
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
///
#[derive(Debug, PartialEq, Pread, Pwrite, IOread, IOwrite, SizeWith)]
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
    pub e_lfanew:    LONG            // File Address of new exe header
}
///
/// 
/// 
/// 
#[derive(Debug, PartialEq, Pread, Pwrite, IOread, IOwrite, SizeWith)]
#[repr(C)]
pub struct IMAGE_NT_HEADERS32 {
    pub Signature:      DWORD,
    pub FileHeader:     IMAGE_FILE_HEADER,
    pub OptionalHeader: IMAGE_OPTIONAL_HEADER32
}
///
/// 
/// 
/// 
/// Struct Size
///     
#[derive(Debug, PartialEq, Pread, Pwrite, IOread, IOwrite, SizeWith)]
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
    pub e_lfanew:    LONG            // File Address of new exe header
}
///
/// # IMAGE_FILE_HEADER
/// 
/// 
/// 
#[derive(Debug, Copy, PartialEq, Pread, Pwrite, IOread, IOwrite, SizeWith)]
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
///
/// # IMAGE_OPTIONAL HEADER32
/// 
///
#[derive(Debug, Copy, PartialEq, Pread, Pwrite, IOread, IOwrite, SizeWith)]
#[repr(C)]
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
    pub DataDirectory:                  [u128; 16usize]
}

impl ::std::clone::Clone for IMAGE_OPTIONAL_HEADER32 {
    fn clone(&self) -> Self {
        *self
    }
}
///
/// 
/// 
/// 
#[derive(Debug, PartialEq, Pread, Pwrite, IOread, IOwrite, SizeWith)]
#[repr(C)]
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
    pub DataDirectory:                  [u128; 16usize]
}
///
/// #IMAGE_DATA_DIRECTORY
/// 
/// 
#[derive(Debug, PartialEq, Pread, Pwrite, IOread, IOwrite, SizeWith)]
#[repr(C)]
pub struct IMAGE_DATA_DIRECTORY {
    pub VirtualAddress:  DWORD,
    pub Size:            DWORD
}
///
/// 
/// 
/// 
#[derive(Debug, PartialEq, Pread, Pwrite, IOread, IOwrite, SizeWith)]
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
///
/// 
/// 
/// 
#[derive(Debug, PartialEq, Pread, Pwrite, IOread, IOwrite, SizeWith)]
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
///
/// 
/// 
/// 
#[derive(Debug, PartialEq, Pread, Pwrite, IOread, IOwrite, SizeWith)]
#[repr(C)]
pub struct IMAGE_DEBUG_MISC {
    pub DataType:   DWORD,
    pub Length:     DWORD,
    pub Unicode:    BOOLEAN,
    pub Reserved:   [BYTE; 3],
    pub Data:       [BYTE; 0],
}
///
/// 
/// 
/// 
#[derive(Debug, PartialEq, Pread, Pwrite, IOread, IOwrite, SizeWith)]
#[repr(C)]
pub struct IMAGE_FUNCTION_ENTRY {
    pub StartingAddress:    DWORD,
    pub EndingAddress:      DWORD,
    pub EndOfPrologue:      DWORD,
}
///
/// 
/// 
/// 
#[derive(Debug, PartialEq, Pread, Pwrite, IOread, IOwrite, SizeWith)]
#[repr(C)]
pub struct IMAGE_FUNCTION_ENTRY64 {
    pub StartingAddress:                    ULONGLONG,
    pub EndingAddress:                      ULONGLONG,
    pub EndOfPrologueOrUnwindInfoAddress:   ULONGLONG,
}
///
/// 
/// 
/// 
#[derive(Debug, PartialEq, Pread, Pwrite, IOread, IOwrite, SizeWith)]
#[repr(C)]
pub struct IMAGE_ROM_HEADERS {
    pub FileHeader:     IMAGE_FILE_HEADER,
    pub OptionalHeader: IMAGE_ROM_OPTIONAL_HEADER,
}
///
/// 
/// 
/// 
#[derive(Debug, Copy, PartialEq, Pread, Pwrite, IOread, IOwrite, SizeWith)]
#[repr(C)]
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
impl ::std::clone::Clone for IMAGE_ROM_OPTIONAL_HEADER {
    fn clone(&self) -> Self {
        *self
    }
}
///
/// 
/// 
/// 
#[derive(Debug, PartialEq, Pread, Pwrite, IOread, IOwrite, SizeWith)]
#[repr(C)]
pub struct IMAGE_RUNTIME_FUNCTION_ENTRY {
    pub BeginAddress:       DWORD,
    pub EndAddress:         DWORD,
    pub UnwindInfoAddress:  DWORD,
}
///
/// 
/// 
/// 
#[derive(Debug, PartialEq, Pread, Pwrite, IOread, IOwrite, SizeWith)]
#[repr(C)]
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
///
/// 
/// 
/// 
#[derive(Debug, PartialEq, Pread, Pwrite, IOread, IOwrite, SizeWith)]
#[repr(C)]
pub struct IMAGE_RESOURCE_DIRECTORY {
    pub Characteristics:        DWORD,
    pub TimeDateStamp:          DWORD,
    pub MajorVersion:           WORD,
    pub MinorVersion:           WORD,
    pub NumberOfNamedEntries:   WORD,
    pub NumberOfIdEntries:      WORD
}
///
/// 
/// 
/// 
#[derive(Debug, PartialEq, Pread, Pwrite, IOread, IOwrite, SizeWith)]
#[repr(C)]
pub struct IMAGE_ENCLAVE_CONFIG32 {
    pub Size:                        DWORD,
    pub MinimumRequiredConfigSize:   DWORD,
    pub PolicyFlags:                 DWORD,
    pub NumberOfImports:             DWORD,
    pub ImportList:                  DWORD,
    pub ImportEntrySize:             DWORD,
    pub FamilyID:                    [BYTE; 16],
    pub ImageID:                     [BYTE; 16],
    pub ImageVersion:                BYTE,
    pub SecurityVersion:             DWORD,
    pub EnclaveSize:                 DWORD,
    pub NumberOfThreads:             DWORD,
    pub EnclaveFlags:                DWORD,
}
///
/// 
/// 
/// 
#[derive(Debug, PartialEq, Pread, Pwrite, IOread, IOwrite, SizeWith)]
#[repr(C)]
struct IMAGE_ENCLAVE_CONFIG64 {
    pub Size:                        DWORD,
    pub MinimumRequiredConfigSize:   DWORD,
    pub PolicyFlags:                 DWORD,
    pub NumberOfImports:             DWORD,
    pub ImportList:                  DWORD,
    pub ImportEntrySize:             DWORD,
    pub FamilyID:                    [BYTE; 16],
    pub ImageID:                     [BYTE; 16],
    pub ImageVersion:                BYTE,
    pub SecurityVersion:             DWORD,
    pub EnclaveSize:                 DWORD,
    pub NumberOfThreads:             DWORD,
    pub EnclaveFlags:                DWORD,
}
///
///
///
/// # PE Constants
///
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
///
/// # Additional Constants used in PE Structures
///
///  
pub const ENCLAVE_SHORT_ID_LENGTH:  WORD   = 16;
pub const ENCLAVE_LONG_ID_LENGTH:   WORD   = 32;
///
/// # PE SIGNATURE CONSTANTS
///
///  
pub const IMAGE_DOS_SIGNATURE:       WORD    = 0x5A4D;       // MZ
pub const IMAGE_OS2_SIGNATURE:       WORD    = 0x454E;       // NE
pub const IMAGE_OS2_SIGNATURE_LE:    WORD    = 0x454C;       // LE
pub const IMAGE_VXD_SIGNATURE:       WORD    = 0x454C;       // LE
pub const IMAGE_NT_SIGNATURE:        DWORD   = 0x00004550;   // PE00
///
/// # IMAGE FILE CONSTANTS
/// 
/// 
pub const IMAGE_FILE_RELOCS_STRIPPED:            WORD = 0x0001;  // Relocation info stripped from file.
pub const IMAGE_FILE_EXECUTABLE_IMAGE:           WORD = 0x0002; // File is executable  (i.e. no unresolved external references).
pub const IMAGE_FILE_LINE_NUMS_STRIPPED:         WORD = 0x0004;  // Line nunbers stripped from file.
pub const IMAGE_FILE_LOCAL_SYMS_STRIPPED:        WORD = 0x0008;  // Local symbols stripped from file.
pub const IMAGE_FILE_AGGRESIVE_WS_TRIM:          WORD = 0x0010;  // Aggressively trim working set
pub const IMAGE_FILE_LARGE_ADDRESS_AWARE:        WORD = 0x0020;  // App can handle >2gb addresses
pub const IMAGE_FILE_BYTES_REVERSED_LO:          WORD = 0x0080;  // Bytes of machine word are reversed.
pub const IMAGE_FILE_32BIT_MACHINE:              WORD = 0x0100;  // 32 bit word machine.
pub const IMAGE_FILE_DEBUG_STRIPPED :            WORD = 0x0200;  // Debugging info stripped from file in .DBG file
pub const IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP:    WORD = 0x0400;  // If Image is on removable media, copy and run from the swap file.
pub const IMAGE_FILE_NET_RUN_FROM_SWAP:          WORD = 0x0800;  // If Image is on Net, copy and run from the swap file.
pub const IMAGE_FILE_SYSTEM:                     WORD = 0x1000;  // System File.
pub const IMAGE_FILE_DLL:                        WORD = 0x2000;  // File is a DLL.
pub const IMAGE_FILE_UP_SYSTEM_ONLY:             WORD = 0x4000;  // File should only be run on a UP machine
pub const IMAGE_FILE_BYTES_REVERSED_HI:          WORD = 0x8000;  // Bytes of machine word are reversed.
pub const IMAGE_FILE_MACHINE_UNKNOWN:            WORD = 0;
pub const IMAGE_FILE_MACHINE_TARGET_HOST:        WORD = 0x0001;  // Useful for indicating we want to interact with the host and not a WoW guest.
pub const IMAGE_FILE_MACHINE_I386:               WORD = 0x014c;  // Intel 386.
pub const IMAGE_FILE_MACHINE_R3000:              WORD = 0x0162;  // MIPS little-endian, 0x160 big-endian
pub const IMAGE_FILE_MACHINE_R4000:              WORD = 0x0166;  // MIPS little-endian
pub const IMAGE_FILE_MACHINE_R10000:             WORD = 0x0168;  // MIPS little-endian
pub const IMAGE_FILE_MACHINE_WCEMIPSV2:          WORD = 0x0169;  // MIPS little-endian WCE v2
pub const IMAGE_FILE_MACHINE_ALPHA:              WORD = 0x0184;  // Alpha_AXP
pub const IMAGE_FILE_MACHINE_SH3:                WORD = 0x01a2;  // SH3 little-endian
pub const IMAGE_FILE_MACHINE_SH3DSP:             WORD = 0x01a3;
pub const IMAGE_FILE_MACHINE_SH3E:               WORD = 0x01a4;  // SH3E little-endian
pub const IMAGE_FILE_MACHINE_SH4:                WORD = 0x01a6;  // SH4 little-endian
pub const IMAGE_FILE_MACHINE_SH5:                WORD = 0x01a8;  // SH5
pub const IMAGE_FILE_MACHINE_ARM:                WORD = 0x01c0;  // ARM Little-Endian
pub const IMAGE_FILE_MACHINE_THUMB:              WORD = 0x01c2;  // ARM Thumb/Thumb-2 Little-Endian
pub const IMAGE_FILE_MACHINE_ARMNT:              WORD = 0x01c4;  // ARM Thumb-2 Little-Endian
pub const IMAGE_FILE_MACHINE_AM33:               WORD = 0x01d3;
pub const IMAGE_FILE_MACHINE_POWERPC:            WORD = 0x01F0;  // IBM PowerPC Little-Endian
pub const IMAGE_FILE_MACHINE_POWERPCFP :         WORD = 0x01f1;
pub const IMAGE_FILE_MACHINE_IA64:               WORD = 0x0200;  // Intel 64
pub const IMAGE_FILE_MACHINE_MIPS16:             WORD = 0x0266;  // MIPS
pub const IMAGE_FILE_MACHINE_ALPHA64:            WORD = 0x0284;  // ALPHA64
pub const IMAGE_FILE_MACHINE_MIPSFPU:            WORD = 0x0366;  // MIPS
pub const IMAGE_FILE_MACHINE_MIPSFPU16:          WORD = 0x0466;  // MIPS
pub const IMAGE_FILE_MACHINE_AXP64:              WORD = IMAGE_FILE_MACHINE_ALPHA64;
pub const IMAGE_FILE_MACHINE_TRICORE:            WORD = 0x0520;  // Infineon
pub const IMAGE_FILE_MACHINE_CEF:                WORD = 0x0CEF;
pub const IMAGE_FILE_MACHINE_EBC:                WORD = 0x0EBC;  // EFI Byte Code
pub const IMAGE_FILE_MACHINE_AMD64:              WORD = 0x8664;  // AMD64 (K8)
pub const IMAGE_FILE_MACHINE_M32R:               WORD = 0x9041;  // M32R little-endian
pub const IMAGE_FILE_MACHINE_ARM64:              WORD = 0xAA64;  // ARM64 Little-Endian
pub const IMAGE_FILE_MACHINE_CEE:                WORD = 0xC0EE;
///
/// # IMAGE SUBSYSTEM CONSTANTS
/// 
/// 
pub const IMAGE_SUBSYSTEM_UNKNOWN:                   BYTE = 0;   // Unknown subsystem.
pub const IMAGE_SUBSYSTEM_NATIVE:                    BYTE = 1;   // Image doesn't require a subsystem.
pub const IMAGE_SUBSYSTEM_WINDOWS_GUI:               BYTE = 2;   // Image runs in the Windows GUI subsystem.
pub const IMAGE_SUBSYSTEM_WINDOWS_CUI:               BYTE = 3;   // Image runs in the Windows character subsystem.
pub const IMAGE_SUBSYSTEM_OS2_CUI:                   BYTE = 5;   // image runs in the OS/2 character subsystem.
pub const IMAGE_SUBSYSTEM_POSIX_CUI:                 BYTE = 7;   // image runs in the Posix character subsystem.
pub const IMAGE_SUBSYSTEM_NATIVE_WINDOWS:            BYTE = 8;   // image is a native Win9x driver.
pub const IMAGE_SUBSYSTEM_WINDOWS_CE_GUI:            BYTE = 9;   // Image runs in the Windows CE subsystem.
pub const IMAGE_SUBSYSTEM_EFI_APPLICATION:           BYTE = 10;
pub const IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER:   BYTE = 11; 
pub const IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:        BYTE = 12;
pub const IMAGE_SUBSYSTEM_EFI_ROM:                   BYTE = 13;
pub const IMAGE_SUBSYSTEM_XBOX:                      BYTE = 14;
pub const IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION:  BYTE = 16;
pub const IMAGE_SUBSYSTEM_XBOX_CODE_CATALOG:         BYTE = 17;
///
/// # IMAGE DLL CHARACTERISTICS CONSTANTS
///
/// 

//      IMAGE_LIBRARY_PROCESS_INIT            0x0001     // Reserved.
//      IMAGE_LIBRARY_PROCESS_TERM            0x0002     // Reserved.
//      IMAGE_LIBRARY_THREAD_INIT             0x0004     // Reserved.
//      IMAGE_LIBRARY_THREAD_TERM             0x0008     // Reserved.
pub const IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA:          WORD = 0x0020;  // Image can handle a high entropy 64-bit virtual address space.
pub const IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE:             WORD = 0x0040;  // DLL can move.
pub const IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY:          WORD = 0x0080;  // Code Integrity Image
pub const IMAGE_DLLCHARACTERISTICS_NX_COMPAT:                WORD = 0x0100;  // Image is NX compatible
pub const IMAGE_DLLCHARACTERISTICS_NO_ISOLATION:             WORD = 0x0200;  // Image understands isolation and doesn't want it
pub const IMAGE_DLLCHARACTERISTICS_NO_SEH:                   WORD = 0x0400;  // Image does not use SEH.  No SE handler may reside in this image
pub const IMAGE_DLLCHARACTERISTICS_NO_BIND:                  WORD = 0x0800;  // Do not bind this image.
pub const IMAGE_DLLCHARACTERISTICS_APPCONTAINER:             WORD = 0x1000;  // Image should execute in an AppContainer
pub const IMAGE_DLLCHARACTERISTICS_WDM_DRIVER:               WORD = 0x2000;  // Driver uses WDM model
pub const IMAGE_DLLCHARACTERISTICS_GUARD_CF:                 WORD = 0x4000;  // Image supports Control Flow Guard.
pub const IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE:    WORD = 0x8000;
///
/// # IMAGE DIRECTORY ENTRY CONSTANTS
/// 
/// 
//      IMAGE_DIRECTORY_ENTRY_COPYRIGHT       7   // (X86 usage)
pub const IMAGE_DIRECTORY_ENTRY_ARCHITECTURE:    BYTE = 7;   // Architecture Specific Data
pub const IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT:    BYTE = 11;   // Bound Import Directory in headers
pub const IMAGE_DIRECTORY_ENTRY_IAT:             BYTE = 12;   // Import Address Table
pub const IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT:    BYTE = 13;   // Delay Load Import Descriptors
pub const IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR:  BYTE = 14;   // COM Runtime descriptor
///
/// # IMAGE SECTION CHARACTERISTICS CONSTANTS
/// 
/// 

//      IMAGE_SCN_TYPE_REG                   0x00000000  // Reserved.
//      IMAGE_SCN_TYPE_DSECT                 0x00000001  // Reserved.
//      IMAGE_SCN_TYPE_NOLOAD                0x00000002  // Reserved.
//      IMAGE_SCN_TYPE_GROUP                 0x00000004  // Reserved.
pub const IMAGE_SCN_TYPE_NO_PAD:                DWORD = 0x00000008;  // Reserved.
//      IMAGE_SCN_TYPE_COPY                  0x00000010  // Reserved.

pub const IMAGE_SCN_CNT_CODE:                   DWORD = 0x00000020;  // Section contains code.
pub const IMAGE_SCN_CNT_INITIALIZED_DATA:       DWORD = 0x00000040;  // Section contains initialized data.
pub const IMAGE_SCN_CNT_UNINITIALIZED_DATA:     DWORD = 0x00000080;  // Section contains uninitialized data.

pub const IMAGE_SCN_LNK_OTHER:                  DWORD = 0x00000100;  // Reserved.
pub const IMAGE_SCN_LNK_INFO:                   DWORD = 0x00000200;  // Section contains comments or some other type of information.
//      IMAGE_SCN_TYPE_OVER                  0x00000400  // Reserved.
pub const IMAGE_SCN_LNK_REMOVE:                 DWORD = 0x00000800;  // Section contents will not become part of image.
pub const IMAGE_SCN_LNK_COMDAT:                 DWORD = 0x00001000;  // Section contents comdat.
//                                           0x00002000  // Reserved.
//      IMAGE_SCN_MEM_PROTECTED - Obsolete   0x00004000
pub const IMAGE_SCN_NO_DEFER_SPEC_EXC:          DWORD = 0x00004000;  // Reset speculative exceptions handling bits in the TLB entries for this section.
pub const IMAGE_SCN_GPREL:                      DWORD = 0x00008000; // Section content can be accessed relative to GP
pub const IMAGE_SCN_MEM_FARDATA:                DWORD = 0x00008000;
//      IMAGE_SCN_MEM_SYSHEAP  - Obsolete    0x00010000
pub const IMAGE_SCN_MEM_PURGEABLE:              DWORD = 0x00020000;
pub const IMAGE_SCN_MEM_16BIT:                  DWORD = 0x00020000;
pub const IMAGE_SCN_MEM_LOCKED:                 DWORD = 0x00040000;
pub const IMAGE_SCN_MEM_PRELOAD:                DWORD = 0x00080000;

pub const IMAGE_SCN_ALIGN_1BYTES:               DWORD = 0x00100000;  //
pub const IMAGE_SCN_ALIGN_2BYTES:               DWORD = 0x00200000;  //
pub const IMAGE_SCN_ALIGN_4BYTES:               DWORD = 0x00300000;  //
pub const IMAGE_SCN_ALIGN_8BYTES:               DWORD = 0x00400000;  //
pub const IMAGE_SCN_ALIGN_16BYTES:              DWORD = 0x00500000;  // Default alignment if no others are specified.
pub const IMAGE_SCN_ALIGN_32BYTES:              DWORD = 0x00600000;  //
pub const IMAGE_SCN_ALIGN_64BYTES:              DWORD = 0x00700000;  //
pub const IMAGE_SCN_ALIGN_128BYTES:             DWORD = 0x00800000;  //
pub const IMAGE_SCN_ALIGN_256BYTES:             DWORD = 0x00900000;  //
pub const IMAGE_SCN_ALIGN_512BYTES:             DWORD = 0x00A00000;  //
pub const IMAGE_SCN_ALIGN_1024BYTES:            DWORD = 0x00B00000;  //
pub const IMAGE_SCN_ALIGN_2048BYTES:            DWORD = 0x00C00000;  //
pub const IMAGE_SCN_ALIGN_4096BYTES:            DWORD = 0x00D00000;  //
pub const IMAGE_SCN_ALIGN_8192BYTES:            DWORD = 0x00E00000;  //
// Unused                                    0x00F00000
pub const IMAGE_SCN_ALIGN_MASK:                 DWORD = 0x00F00000;

pub const IMAGE_SCN_LNK_NRELOC_OVFL:            DWORD = 0x01000000;  // Section contains extended relocations.
pub const IMAGE_SCN_MEM_DISCARDABLE:            DWORD = 0x02000000;  // Section can be discarded.
pub const IMAGE_SCN_MEM_NOT_CACHED:             DWORD = 0x04000000;  // Section is not cachable.
pub const IMAGE_SCN_MEM_NOT_PAGED:              DWORD = 0x08000000;  // Section is not pageable.
pub const IMAGE_SCN_MEM_SHARED:                 DWORD = 0x10000000;  // Section is shareable.
pub const IMAGE_SCN_MEM_EXECUTE:                DWORD = 0x20000000;  // Section is executable.
pub const IMAGE_SCN_MEM_READ:                   DWORD = 0x40000000;  // Section is readable.
pub const IMAGE_SCN_MEM_WRITE:                  DWORD = 0x80000000;  // Section is writeable.
