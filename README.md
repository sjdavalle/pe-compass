# pe-compass
A Study of PE Format through the RUST programming language.


# To Do
* Finish 32Bit PE Parsing
* Finish 64Bit PE Parsing
* Optimmization Parsing

# Current Progress
Current Code Base is parsing the following structs, validation in progress.

```rust
DOS HEADER: 

IMAGE_DOS_HEADER {
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
}


PE  HEADER: 

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
            249093356696378275547488711290880,
            5119601774592,
            1074333897747187070788520122515456,
            0,
            1901489803063056646775402135552,
            0,
            1872606487024,
            0,
            324518565372330574518106047476782,
            6597070402048,
            7721149763919557955369039822848,
            50462635094027027012028823764999292,
            255710240759725591962787489208244109312,
            51598450033085677789198414101377582,
            2768570278815744,
            35730266243814621765380866048,
        ],
    },
}
```
