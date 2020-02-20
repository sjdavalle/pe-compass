# pe-compass
A Study of PE Format through the RUST programming language.

# PROJECT STATUS
** IN DEV-MODE** Do not download or use this for your environment yet.

# Documentation Articles
* PE Rich Data Structure: Undocumented: http://bytepointer.com/articles/the_microsoft_rich_header.htm
* PE Things They Did not tell you...: http://bytepointer.com/articles/rich_header_lifewire_vxmags_29A-8.009.htm
* PE MindMap By Ero Carrera: http://www.openrce.org/reference_library/files/reference/PE%20Format.pdf
# To Do
* Finish 32Bit PE Parsing
* Finish 64Bit PE Parsing
* Optimmization Parsing

# Current Progress
Current Code Base is parsing the following structs, validation in progress.

```rust
/// Inspection Code Now returns an enum "PE_FILE" that holds either of
/// a 32 or 64 Bit pe object
x86(
    PE_32 {
        ImageDosHeader: IMAGE_DOS_HEADER {
            e_magic: 23117,
            e_cblp: 144,
            e_cp: 3,
            e_crlc: 0,
            e_cparhdr: 4,
            e_minalloc: 0,
            e_maxalloc: 65535,
            e_ss: 0,
            e_sp: 184,
            e_csum: 0,
            e_ip: 0,
            e_cs: 0,
            e_lfarlc: 64,
            e_ovno: 0,
            e_res: [
                0,
                0,
                0,
                0,
            ],
            e_oemid: 0,
            e_oeminfo: 0,
            e_res2: [
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            ],
            e_lfanew: 128,
        },
        ImageNtHeaders: IMAGE_NT_HEADERS32 {
            Signature: 17744,
            FileHeader: IMAGE_FILE_HEADER {
                Machine: 332,
                NumberOfSections: 18,
                TimeDateStamp: 1580156954,
                PointerToSymbolTable: 816128,
                NumberOfSymbols: 4172,
                SizeOfOptionalHeader: 224,
                Characteristics: 8454,
            },
            OptionalHeader: IMAGE_OPTIONAL_HEADER32 {
                Magic: 267,
                MajorLinkerVersion: 2,
                MinorLinkerVersion: 25,
                SizeOfCode: 635392,
                SizeOfInitializedData: 747520,
                SizeOfUninitializedData: 2560,
                AddressOfEntryPoint: 5120,
                BaseOfCode: 4096,
                BaseOfData: 643072,
                ImageBase: 1642070016,
                SectionAlignment: 4096,
                FileAlignment: 512,
                MajorOperatingSystemVersion: 4,
                MinorOperatingSystemVersion: 0,
                MajorImageVersion: 1,
                MinorImageVersion: 0,
                MajorSubsystemVersion: 4,
                MinorSubsystemVersion: 0,
                Win32VersionValue: 0,
                SizeOfImage: 860160,
                SizeOfHeaders: 1536,
                CheckSum: 958289,
                Subsystem: 3,
                DllCharacteristics: 0,
                SizeOfStackReserve: 2097152,
                SizeOfStackCommit: 4096,
                SizeOfHeapReserve: 1048576,
                SizeOfHeapCommit: 4096,
                LoaderFlags: 0,
                NumberOfRvaAndSizes: 16,
                DataDirectory: [
                    36979669151744,
                    13503377924096,
                    5119601774592,
                    0,
                    0,
                    58239757295616,
                    0,
                    0,
                    0,
                    103079968772,
                    0,
                    0,
                    1872606487024,
                    0,
                    0,
                    0,
                ],
            },
        },
        // Returns the Data Directories that have Data - i.e. != 0 Size
		// Notice only 6 have data from above structure labeled as `DataDirectory`
		// and we parse those 6 structs below as the member `ImageDataDirectory`
        ImageDataDirectory: {
            "IMAGE_DIRECTORY_ENTRY_EXPORT": IMAGE_DATA_DIRECTORY {
                VirtualAddress: 733184,
                Size: 8610,
            },
            "IMAGE_DIRECTORY_ENTRY_BASERELOC": IMAGE_DATA_DIRECTORY {
                VirtualAddress: 761856,
                Size: 13560,
            },
            "IMAGE_DIRECTORY_ENTRY_IAT": IMAGE_DATA_DIRECTORY {
                VirtualAddress: 745968,
                Size: 436,
            },
            "IMAGE_DIRECTORY_ENTRY_IMPORT": IMAGE_DATA_DIRECTORY {
                VirtualAddress: 745472,
                Size: 3144,
            },
            "IMAGE_DIRECTORY_ENTRY_RESOURCE": IMAGE_DATA_DIRECTORY {
                VirtualAddress: 757760,
                Size: 1192,
            },
            "IMAGE_DIRECTORY_ENTRY_TLS": IMAGE_DATA_DIRECTORY {
                VirtualAddress: 753668,
                Size: 24,
            },
        },
    },
)
```
