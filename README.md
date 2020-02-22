# pe-compass
A Study of PE Format through the RUST programming language.

# PROJECT STATUS
** IN DEV-MODE** Do not download or use this for your environment yet.

# Documentation Articles
* PE Rich Data Structure: Undocumented: http://bytepointer.com/articles/the_microsoft_rich_header.htm
* PE Things They Did not tell you...: http://bytepointer.com/articles/rich_header_lifewire_vxmags_29A-8.009.htm
* PE MindMap By Ero Carrera: http://www.openrce.org/reference_library/files/reference/PE%20Format.pdf
* PE MSDN Arcticle:  https://docs.microsoft.com/en-us/windows/win32/debug/pe-format

# To Do
* Finish 32Bit PE Parsing
* Finish 64Bit PE Parsing
* Optimmization Parsing

# Current Progress
Current Code Base is parsing the following structs, validation in progress.

```rust
/// Inspection Code Now returns an enum "PE_FILE" that holds either of
/// a 32 or 64 Bit pe optional headers object
Section Name: .text

Section Name: .data

Section Name: .rdata

Section Name: .bss

Section Name: .edata

Section Name: .idata  

Section Name: .CRT

Section Name: .tls

Section Name: .rsrc

Section Name: .reloc  

Section Name: /4

Section Name: /19

Section Name: /31

Section Name: /45

Section Name: /57     

Section Name: /70

Section Name: /81

Section Name: /92

[
    IMAGE_SECTION_HEADER {
        Name: [
            46,
            116,
            101,
            120,
            116,
            0,
            0,
            0,
        ],
        _union: Misc {
            PhysicalAddress: 635012,
            VirtualSize: 4096,
        },
        VirtualAddress: 635392,
        SizeOfRawData: 1536,
        PointerToRawData: 0,
        PointerToRelocations: 0,
        PointerToLinenumbers: 0,
        NumberOfRelocations: 96,
        NumberOfLinenumbers: 24656,
        Characteristics: 1952539694,
    },
    IMAGE_SECTION_HEADER {
        Name: [
            46,
            100,
            97,
            116,
            97,
            0,
            0,
            0,
        ],
        _union: Misc {
            PhysicalAddress: 7292,
            VirtualSize: 643072,
        },
        VirtualAddress: 7680,
        SizeOfRawData: 636928,
        PointerToRawData: 0,
        PointerToRelocations: 0,
        PointerToLinenumbers: 0,
        NumberOfRelocations: 64,
        NumberOfLinenumbers: 49248,
        Characteristics: 1633972782,
    },
    IMAGE_SECTION_HEADER {
        Name: [
            46,
            114,
            100,
            97,
            116,
            97,
            0,
            0,
        ],
        _union: Misc {
            PhysicalAddress: 75668,
            VirtualSize: 651264,
        },
        VirtualAddress: 75776,
        SizeOfRawData: 644608,
        PointerToRawData: 0,
        PointerToRelocations: 0,
        PointerToLinenumbers: 0,
        NumberOfRelocations: 64,
        NumberOfLinenumbers: 16480,
        Characteristics: 1936941614,
    },
    IMAGE_SECTION_HEADER {
        Name: [
            46,
            98,
            115,
            115,
            0,
            0,
            0,
            0,
        ],
        _union: Misc {
            PhysicalAddress: 2088,
            VirtualSize: 729088,
        },
        VirtualAddress: 0,
        SizeOfRawData: 0,
        PointerToRawData: 0,
        PointerToRelocations: 0,
        PointerToLinenumbers: 0,
        NumberOfRelocations: 128,
        NumberOfLinenumbers: 49248,
        Characteristics: 1633969454,
    },
    IMAGE_SECTION_HEADER {
        Name: [
            46,
            101,
            100,
            97,
            116,
            97,
            0,
            0,
        ],
        _union: Misc {
            PhysicalAddress: 8610,
            VirtualSize: 733184,
        },
        VirtualAddress: 8704,
        SizeOfRawData: 720384,
        PointerToRawData: 0,
        PointerToRelocations: 0,
        PointerToLinenumbers: 0,
        NumberOfRelocations: 64,
        NumberOfLinenumbers: 16432,
        Characteristics: 1633970478,
    },
    IMAGE_SECTION_HEADER {
        Name: [
            46,
            105,
            100,
            97,
            116,
            97,
            0,
            0,
        ],
        _union: Misc {
            PhysicalAddress: 3144,
            VirtualSize: 745472,
        },
        VirtualAddress: 3584,
        SizeOfRawData: 729088,
        PointerToRawData: 0,
        PointerToRelocations: 0,
        PointerToLinenumbers: 0,
        NumberOfRelocations: 64,
        NumberOfLinenumbers: 49200,
        Characteristics: 1414677294,
    },
    IMAGE_SECTION_HEADER {
        Name: [
            46,
            67,
            82,
            84,
            0,
            0,
            0,
            0,
        ],
        _union: Misc {
            PhysicalAddress: 44,
            VirtualSize: 749568,
        },
        VirtualAddress: 512,
        SizeOfRawData: 732672,
        PointerToRawData: 0,
        PointerToRelocations: 0,
        PointerToLinenumbers: 0,
        NumberOfRelocations: 64,
        NumberOfLinenumbers: 49200,
        Characteristics: 1936487470,
    },
    IMAGE_SECTION_HEADER {
        Name: [
            46,
            116,
            108,
            115,
            0,
            0,
            0,
            0,
        ],
        _union: Misc {
            PhysicalAddress: 32,
            VirtualSize: 753664,
        },
        VirtualAddress: 512,
        SizeOfRawData: 733184,
        PointerToRawData: 0,
        PointerToRelocations: 0,
        PointerToLinenumbers: 0,
        NumberOfRelocations: 64,
        NumberOfLinenumbers: 49200,
        Characteristics: 1920168494,
    },
    IMAGE_SECTION_HEADER {
        Name: [
            46,
            114,
            115,
            114,
            99,
            0,
            0,
            0,
        ],
        _union: Misc {
            PhysicalAddress: 1192,
            VirtualSize: 757760,
        },
        VirtualAddress: 1536,
        SizeOfRawData: 733696,
        PointerToRawData: 0,
        PointerToRelocations: 0,
        PointerToLinenumbers: 0,
        NumberOfRelocations: 64,
        NumberOfLinenumbers: 49200,
        Characteristics: 1818587694,
    },
    IMAGE_SECTION_HEADER {
        Name: [
            46,
            114,
            101,
            108,
            111,
            99,
            0,
            0,
        ],
        _union: Misc {
            PhysicalAddress: 13560,
            VirtualSize: 761856,
        },
        VirtualAddress: 13824,
        SizeOfRawData: 735232,
        PointerToRawData: 0,
        PointerToRelocations: 0,
        PointerToLinenumbers: 0,
        NumberOfRelocations: 64,
        NumberOfLinenumbers: 16944,
        Characteristics: 13359,
    },
    IMAGE_SECTION_HEADER {
        Name: [
            47,
            52,
            0,
            0,
            0,
            0,
            0,
            0,
        ],
        _union: Misc {
            PhysicalAddress: 728,
            VirtualSize: 778240,
        },
        VirtualAddress: 1024,
        SizeOfRawData: 749056,
        PointerToRawData: 0,
        PointerToRelocations: 0,
        PointerToLinenumbers: 0,
        NumberOfRelocations: 64,
        NumberOfLinenumbers: 16960,
        Characteristics: 3748143,
    },
    IMAGE_SECTION_HEADER {
        Name: [
            47,
            49,
            57,
            0,
            0,
            0,
            0,
            0,
        ],
        _union: Misc {
            PhysicalAddress: 39128,
            VirtualSize: 782336,
        },
        VirtualAddress: 39424,
        SizeOfRawData: 750080,
        PointerToRawData: 0,
        PointerToRelocations: 0,
        PointerToLinenumbers: 0,
        NumberOfRelocations: 64,
        NumberOfLinenumbers: 16912,
        Characteristics: 3224367,
    },
    IMAGE_SECTION_HEADER {
        Name: [
            47,
            51,
            49,
            0,
            0,
            0,
            0,
            0,
        ],
        _union: Misc {
            PhysicalAddress: 6901,
            VirtualSize: 823296,
        },
        VirtualAddress: 7168,
        SizeOfRawData: 789504,
        PointerToRawData: 0,
        PointerToRelocations: 0,
        PointerToLinenumbers: 0,
        NumberOfRelocations: 64,
        NumberOfLinenumbers: 16912,
        Characteristics: 3486767,
    },
    IMAGE_SECTION_HEADER {
        Name: [
            47,
            52,
            53,
            0,
            0,
            0,
            0,
            0,
        ],
        _union: Misc {
            PhysicalAddress: 6784,
            VirtualSize: 831488,
        },
        VirtualAddress: 7168,
        SizeOfRawData: 796672,
        PointerToRawData: 0,
        PointerToRelocations: 0,
        PointerToLinenumbers: 0,
        NumberOfRelocations: 64,
        NumberOfLinenumbers: 16912,
        Characteristics: 3618095,
    },
    IMAGE_SECTION_HEADER {
        Name: [
            47,
            53,
            55,
            0,
            0,
            0,
            0,
            0,
        ],
        _union: Misc {
            PhysicalAddress: 2236,
            VirtualSize: 839680,
        },
        VirtualAddress: 2560,
        SizeOfRawData: 803840,
        PointerToRawData: 0,
        PointerToRelocations: 0,
        PointerToLinenumbers: 0,
        NumberOfRelocations: 64,
        NumberOfLinenumbers: 16944,
        Characteristics: 3159855,
    },
    IMAGE_SECTION_HEADER {
        Name: [
            47,
            55,
            48,
            0,
            0,
            0,
            0,
            0,
        ],
        _union: Misc {
            PhysicalAddress: 617,
            VirtualSize: 843776,
        },
        VirtualAddress: 1024,
        SizeOfRawData: 806400,
        PointerToRawData: 0,
        PointerToRelocations: 0,
        PointerToLinenumbers: 0,
        NumberOfRelocations: 64,
        NumberOfLinenumbers: 16912,
        Characteristics: 3225647,
    },
    IMAGE_SECTION_HEADER {
        Name: [
            47,
            56,
            49,
            0,
            0,
            0,
            0,
            0,
        ],
        _union: Misc {
            PhysicalAddress: 7379,
            VirtualSize: 847872,
        },
        VirtualAddress: 7680,
        SizeOfRawData: 807424,
        PointerToRawData: 0,
        PointerToRelocations: 0,
        PointerToLinenumbers: 0,
        NumberOfRelocations: 64,
        NumberOfLinenumbers: 16912,
        Characteristics: 3291439,
    },
    IMAGE_SECTION_HEADER {
        Name: [
            47,
            57,
            50,
            0,
            0,
            0,
            0,
            0,
        ],
        _union: Misc {
            PhysicalAddress: 656,
            VirtualSize: 856064,
        },
        VirtualAddress: 1024,
        SizeOfRawData: 815104,
        PointerToRawData: 0,
        PointerToRelocations: 0,
        PointerToLinenumbers: 0,
        NumberOfRelocations: 64,
        NumberOfLinenumbers: 16912,
        Characteristics: 0,
    },
]
PE_FILE {
    petype: 267,
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
    ImageDosStub: "!This program cannot be run in DOS mode",
    ImageNtHeaders: x86(
        IMAGE_NT_HEADERS32 {
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
    ),
    ImageDataDirectory: {
        "IMAGE_DIRECTORY_ENTRY_IMPORT": IMAGE_DATA_DIRECTORY {
            VirtualAddress: 745472,
            Size: 3144,
        },
        "IMAGE_DIRECTORY_ENTRY_RESOURCE": IMAGE_DATA_DIRECTORY {
            VirtualAddress: 757760,
            Size: 1192,
        },
        "IMAGE_DIRECTORY_ENTRY_IAT": IMAGE_DATA_DIRECTORY {
            VirtualAddress: 745968,
            Size: 436,
        },
        "IMAGE_DIRECTORY_ENTRY_EXPORT": IMAGE_DATA_DIRECTORY {
            VirtualAddress: 733184,
            Size: 8610,
        },
        "IMAGE_DIRECTORY_ENTRY_BASERELOC": IMAGE_DATA_DIRECTORY {
            VirtualAddress: 761856,
            Size: 13560,
        },
        "IMAGE_DIRECTORY_ENTRY_TLS": IMAGE_DATA_DIRECTORY {
            VirtualAddress: 753668,
            Size: 24,
        },
    },
}
```
