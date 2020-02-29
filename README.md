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


File Size:          944840
Bytes Content Len:  944840
Vec Content:        944840

[+] Import Address Table Search
Match Found: SectionName: .idata
Index:    5 => Start: 745472 | End: 749568


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
        "IMAGE_DIRECTORY_ENTRY_BASERELOC": IMAGE_DATA_DIRECTORY {
            VirtualAddress: 761856,
            Size: 13560,
        },
        "IMAGE_DIRECTORY_ENTRY_EXPORT": IMAGE_DATA_DIRECTORY {
            VirtualAddress: 733184,
            Size: 8610,
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
    ImageSectionHeaders: {
        "/4": IMAGE_SECTION_HEADER {
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
            VirtualSize: 728,
            VirtualAddress: 778240,
            SizeOfRawData: 1024,
            PointerToRawData: 749056,
            PointerToRelocations: 0,
            PointerToLinenumbers: 0,
            NumberOfRelocations: 0,
            NumberOfLinenumbers: 0,
            Characteristics: 1111490624,
        },
        ".text": IMAGE_SECTION_HEADER {
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
            VirtualSize: 635012,
            VirtualAddress: 4096,
            SizeOfRawData: 635392,
            PointerToRawData: 1536,
            PointerToRelocations: 0,
            PointerToLinenumbers: 0,
            NumberOfRelocations: 0,
            NumberOfLinenumbers: 0,
            Characteristics: 1615855712,
        },
        "/81": IMAGE_SECTION_HEADER {
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
            VirtualSize: 7379,
            VirtualAddress: 847872,
            SizeOfRawData: 7680,
            PointerToRawData: 807424,
            PointerToRelocations: 0,
            PointerToLinenumbers: 0,
            NumberOfRelocations: 0,
            NumberOfLinenumbers: 0,
            Characteristics: 1108344896,
        },
        "/31": IMAGE_SECTION_HEADER {
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
            VirtualSize: 6901,
            VirtualAddress: 823296,
            SizeOfRawData: 7168,
            PointerToRawData: 789504,
            PointerToRelocations: 0,
            PointerToLinenumbers: 0,
            NumberOfRelocations: 0,
            NumberOfLinenumbers: 0,
            Characteristics: 1108344896,
        },
        ".CRT": IMAGE_SECTION_HEADER {
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
            VirtualSize: 44,
            VirtualAddress: 749568,
            SizeOfRawData: 512,
            PointerToRawData: 732672,
            PointerToRelocations: 0,
            PointerToLinenumbers: 0,
            NumberOfRelocations: 0,
            NumberOfLinenumbers: 0,
            Characteristics: 3224371264,
        },
        ".data": IMAGE_SECTION_HEADER {
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
            VirtualSize: 7292,
            VirtualAddress: 643072,
            SizeOfRawData: 7680,
            PointerToRawData: 636928,
            PointerToRelocations: 0,
            PointerToLinenumbers: 0,
            NumberOfRelocations: 0,
            NumberOfLinenumbers: 0,
            Characteristics: 3227516992,
        },
        ".rdata": IMAGE_SECTION_HEADER {
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
            VirtualSize: 75668,
            VirtualAddress: 651264,
            SizeOfRawData: 75776,
            PointerToRawData: 644608,
            PointerToRelocations: 0,
            PointerToLinenumbers: 0,
            NumberOfRelocations: 0,
            NumberOfLinenumbers: 0,
            Characteristics: 1080033344,
        },
        ".idata": IMAGE_SECTION_HEADER {
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
            VirtualSize: 3144,
            VirtualAddress: 745472,
            SizeOfRawData: 3584,
            PointerToRawData: 729088,
            PointerToRelocations: 0,
            PointerToLinenumbers: 0,
            NumberOfRelocations: 0,
            NumberOfLinenumbers: 0,
            Characteristics: 3224371264,
        },
        ".tls": IMAGE_SECTION_HEADER {
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
            VirtualSize: 32,
            VirtualAddress: 753664,
            SizeOfRawData: 512,
            PointerToRawData: 733184,
            PointerToRelocations: 0,
            PointerToLinenumbers: 0,
            NumberOfRelocations: 0,
            NumberOfLinenumbers: 0,
            Characteristics: 3224371264,
        },
        "/57": IMAGE_SECTION_HEADER {
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
            VirtualSize: 2236,
            VirtualAddress: 839680,
            SizeOfRawData: 2560,
            PointerToRawData: 803840,
            PointerToRelocations: 0,
            PointerToLinenumbers: 0,
            NumberOfRelocations: 0,
            NumberOfLinenumbers: 0,
            Characteristics: 1110442048,
        },
        "/70": IMAGE_SECTION_HEADER {
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
            VirtualSize: 617,
            VirtualAddress: 843776,
            SizeOfRawData: 1024,
            PointerToRawData: 806400,
            PointerToRelocations: 0,
            PointerToLinenumbers: 0,
            NumberOfRelocations: 0,
            NumberOfLinenumbers: 0,
            Characteristics: 1108344896,
        },
        ".edata": IMAGE_SECTION_HEADER {
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
            VirtualSize: 8610,
            VirtualAddress: 733184,
            SizeOfRawData: 8704,
            PointerToRawData: 720384,
            PointerToRelocations: 0,
            PointerToLinenumbers: 0,
            NumberOfRelocations: 0,
            NumberOfLinenumbers: 0,
            Characteristics: 1076887616,
        },
        ".rsrc": IMAGE_SECTION_HEADER {
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
            VirtualSize: 1192,
            VirtualAddress: 757760,
            SizeOfRawData: 1536,
            PointerToRawData: 733696,
            PointerToRelocations: 0,
            PointerToLinenumbers: 0,
            NumberOfRelocations: 0,
            NumberOfLinenumbers: 0,
            Characteristics: 3224371264,
        },
        ".reloc": IMAGE_SECTION_HEADER {
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
            VirtualSize: 13560,
            VirtualAddress: 761856,
            SizeOfRawData: 13824,
            PointerToRawData: 735232,
            PointerToRelocations: 0,
            PointerToLinenumbers: 0,
            NumberOfRelocations: 0,
            NumberOfLinenumbers: 0,
            Characteristics: 1110442048,
        },
        ".bss": IMAGE_SECTION_HEADER {
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
            VirtualSize: 2088,
            VirtualAddress: 729088,
            SizeOfRawData: 0,
            PointerToRawData: 0,
            PointerToRelocations: 0,
            PointerToLinenumbers: 0,
            NumberOfRelocations: 0,
            NumberOfLinenumbers: 0,
            Characteristics: 3227517056,
        },
        "/45": IMAGE_SECTION_HEADER {
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
            VirtualSize: 6784,
            VirtualAddress: 831488,
            SizeOfRawData: 7168,
            PointerToRawData: 796672,
            PointerToRelocations: 0,
            PointerToLinenumbers: 0,
            NumberOfRelocations: 0,
            NumberOfLinenumbers: 0,
            Characteristics: 1108344896,
        },
        "/19": IMAGE_SECTION_HEADER {
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
            VirtualSize: 39128,
            VirtualAddress: 782336,
            SizeOfRawData: 39424,
            PointerToRawData: 750080,
            PointerToRelocations: 0,
            PointerToLinenumbers: 0,
            NumberOfRelocations: 0,
            NumberOfLinenumbers: 0,
            Characteristics: 1108344896,
        },
        "/92": IMAGE_SECTION_HEADER {
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
            VirtualSize: 656,
            VirtualAddress: 856064,
            SizeOfRawData: 1024,
            PointerToRawData: 815104,
            PointerToRelocations: 0,
            PointerToLinenumbers: 0,
            NumberOfRelocations: 0,
            NumberOfLinenumbers: 0,
            Characteristics: 1108344896,
        },
    },
    ImageDLLImports: {
        "KERNEL32.dll": [
            "AreFileApisANSI\u{0}",
            "CloseHandle\u{0}",
            "CreateFileA\u{0}",
            "CreateFileMappingA\u{0}\u{0}",
            "CreateFileMappingW\u{0}\u{0}",
            "CreateFileW\u{0}",
            "CreateMutexW\u{0}\u{0}",
            "DeleteCriticalSection\u{0}",
            "DeleteFileA\u{0}",
            "DeleteFileW\u{0}",
            "EnterCriticalSection\u{0}\u{0}",
            "FlushFileBuffers\u{0}\u{0}",
            "FlushViewOfFile\u{0}",
            "FormatMessageA\u{0}\u{0}",
            "FormatMessageW\u{0}\u{0}",
            "FreeLibrary\u{0}",
            "GetCurrentProcess\u{0}",
            "GetCurrentProcessId\u{0}",
            "GetCurrentThreadId\u{0}\u{0}",
            "GetDiskFreeSpaceA\u{0}",
            "GetDiskFreeSpaceW\u{0}",
            "GetFileAttributesA\u{0}\u{0}",
            "GetFileAttributesExW\u{0}\u{0}",
            "GetFileAttributesW\u{0}\u{0}",
            "GetFileSize\u{0}",
            "GetFullPathNameA\u{0}\u{0}",
            "GetFullPathNameW\u{0}\u{0}",
            "GetLastError\u{0}\u{0}",
            "GetModuleHandleA\u{0}\u{0}",
            "GetProcAddress\u{0}\u{0}",
            "GetProcessHeap\u{0}\u{0}",
            "GetSystemInfo\u{0}",
            "GetSystemTime\u{0}",
            "GetSystemTimeAsFileTime\u{0}",
            "GetTempPathA\u{0}\u{0}",
            "GetTempPathW\u{0}\u{0}",
            "GetTickCount\u{0}\u{0}",
            "GetVersionExA\u{0}",
            "GetVersionExW\u{0}",
            "HeapAlloc\u{0}",
            "HeapCompact\u{0}",
            "HeapCreate\u{0}\u{0}",
            "HeapDestroy\u{0}",
            "HeapFree\u{0}\u{0}",
            "HeapReAlloc\u{0}",
            "HeapSize\u{0}\u{0}",
            "HeapValidate\u{0}\u{0}",
            "InitializeCriticalSection\u{0}",
            "InterlockedCompareExchange\u{0}\u{0}",
            "LeaveCriticalSection\u{0}\u{0}",
            "LoadLibraryA\u{0}\u{0}",
            "LoadLibraryW\u{0}\u{0}",
            "LocalFree\u{0}",
            "LockFile\u{0}\u{0}",
            "LockFileEx\u{0}\u{0}",
            "MapViewOfFile\u{0}",
            "MultiByteToWideChar\u{0}",
            "OutputDebugStringA\u{0}\u{0}",
            "OutputDebugStringW\u{0}\u{0}",
            "QueryPerformanceCounter\u{0}",
            "ReadFile\u{0}\u{0}",
            "SetEndOfFile\u{0}\u{0}",
            "SetFilePointer\u{0}\u{0}",
            "SetUnhandledExceptionFilter\u{0}",
            "Sleep\u{0}",
            "SystemTimeToFileTime\u{0}\u{0}",
            "TerminateProcess\u{0}\u{0}",
            "TlsGetValue\u{0}",
            "TryEnterCriticalSection\u{0}",
            "UnhandledExceptionFilter\u{0}\u{0}",
            "UnlockFile\u{0}\u{0}",
            "UnlockFileEx\u{0}\u{0}",
            "UnmapViewOfFile\u{0}",
            "VirtualProtect\u{0}\u{0}",
            "VirtualQuery\u{0}\u{0}",
            "WaitForSingleObject\u{0}",
            "WaitForSingleObjectEx\u{0}",
            "WideCharToMultiByte\u{0}",
            "WriteFile\u{0}",
        ],
        "msvcrt.dll": [
            "__dllonexit\u{0}",
            "__setusermatherr\u{0}\u{0}",
            "_amsg_exit\u{0}\u{0}",
            "_beginthreadex\u{0}\u{0}",
            "_endthreadex\u{0}\u{0}",
            "_errno\u{0}\u{0}",
            "_initterm\u{0}",
            "_iob\u{0}\u{0}",
            "_lock\u{0}",
            "_onexit\u{0}",
            "localtime\u{0}",
            "calloc\u{0}\u{0}",
            "fprintf\u{0}",
            "free\u{0}\u{0}",
            "fwrite\u{0}\u{0}",
            "malloc\u{0}\u{0}",
            "memcmp\u{0}\u{0}",
            "memmove\u{0}",
            "qsort\u{0}",
            "realloc\u{0}",
            "strcmp\u{0}\u{0}",
            "strcspn\u{0}",
            "strlen\u{0}\u{0}",
            "strncmp\u{0}",
            "strrchr\u{0}",
            "_unlock\u{0}",
            "abort\u{0}",
            "vfprintf\u{0}\u{0}",
        ],
    },
}
```
