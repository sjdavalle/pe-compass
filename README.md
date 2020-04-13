# pe-compass
An **Empirical Study** of the PE Format through the RUST language and Databases.

<br />

## Current Support - Focus Areas
- 32 and 64 bit Executables
- Unpacked Executables
- CSV & JSON Database InterChange Formats
- Cross Platform, releases provide binaries for 64bit Debian, MacOsx, Windows
- Parsed output focused on Imports & Exports by Name, Ordinals not focused on

## Current Benchmark Estimations
- Reliably, ~1,400+ files per minute
- Reliably, 50 MB PE files parsed in 500 millis (half a second)

On physical hosts, specially MacOs and Linux, the LLVM support is much faster than Windows compilation via VS.

<br/>

### Benchmark Example: Small Files Average Time | Warm Cache
For small files, I am using Hyperfine with warmups, on MacOS, I am averaging `13 millis` or what this image is saying.

![image](https://user-images.githubusercontent.com/11415591/79046797-f5813d80-7be0-11ea-9c44-d14c8329501a.png)

<br />
<br />

### Benchmark Example: LargeFiles | Excel.exe
The beloved Microsoft `excel.exe` is about 50 MBs in size, and we parse it in `500 millis` or half a second on Windows.

![image](https://user-images.githubusercontent.com/11415591/79021711-43973200-7b4a-11ea-90e6-39c916eeea3a.png)

<br />
<br/>

# Current Progress
Currently, the program is run like this:

## Help Menu
You can get help by using the `-h` switch

```text
$> pe-compass -h

pe-compass v.0.0.10
carlos diaz | @dfirence

A Study of the Portable Executable Format

USAGE:
    pe-compass [SUBCOMMAND]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

SUBCOMMANDS:
    help       Prints this message or the help of the given subcommand(s)
    inspect    Inspect a PE File's Imports Structure
    recurse    Works Recursively with Folders
```

## Help Menu - Subcommands
As the program works in subcommands mode, every `subcommand` has a built-in help menu accessed by the `-h` switch.

The example below, shows how to access the help menu for the `inspect` subcommand mode.

```text
pe-compass-inspect v.0.0.10
carlos diaz | @dfirence

Inspect a PE File's Imports Structure

USAGE:
    pe-compass inspect [FLAGS] [OPTIONS]

FLAGS:
    -c               Provide Output as CSV Format
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -f <PE FILE>            File System Path of PEFILE to inspect
    -o <OUTPUT FILE>        Destination File to Write Output to
```
<br/>

This example shows the options for the `recurse` subcommand

```text
pe-compass-recurse v.0.0.10
carlos diaz | @dfirence

Works Recursively with Folders

USAGE:
    pe-compass recurse [OPTIONS]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -d <Directory PATH>             Target Directory To Recurse Search
    -x <File Extension Name>        Applies Ends With Pattern Match - NON-REGEX
    -f <Pattern NON_REGEX>          A Non-RegEx pattern to filter by
```
<br/>
<br />

## Parse A File
To parse a single file, enter the `subcommand` options `inspect` and use the `-f` switch and filepath of the pe file.

```bash
$> pe-compass inspect -f pe-samples/sqlite3x86.dll
```

To parse a single file and save the parsed output, use the `-o` switch

```bash
$> pe-compass inspect -f pe-samples/sqlite3x86.dll -o sqlite.json
```

To parse a single file and save the parsed output with `CSV` format, use the `-c` switch

```bash
$> pe-compass inspect -f pe-samples/sqlite3x86.dll -o sqlite.csv -c
```
<br />

## Recursive Search
The subcommand `recurse` is used to get a filelisting under a target folder/directory.  This will allow you to first
find files matching your desired criteria **only based** on the filename. 

By building a directory list you can then launch a scan for **parsing** the files in that list with the inspect subcommand options.
<br/>

### Build a list of target filepaths without filtering
To scan a directory, use the `recurse` subcommand and the required `-d` switch followed by the directory path.

```bash
# Note:  This produces any file under the "C:\Windows" folder
$> pe-compass recurse -d C:\Windows
```
<br/>

### Build a list of target filepaths with filtering
You can use the `-f` switch to filter by a string matching anywhere in the filename or absolute file path

```bash
# Recurse the "C:\Windows" folder, and filter for string "foo"

$> pe-compass recurse -d C:\Windows -f foo > C:\targets.txt
```
<br/>

You can instead do another filter that matches as **ends_with** in the filename or absolute file paths

```bash
# Recurse the "C:\Windows" folder, and filter for anything matching at the end with ".exe"
$> pe-compass recurse -d C:\Windows -x .exe > C:\targets.txt

# Do the same but this time for ".dll" files
$> pe-compass recurse -d C:\Windows -x .dll > C:\targets.txt

# Or this time for ".sys" files
$> pe-compass recurse -d C:\Windows -x .sys > C:\targets.txt
```
<br />

One more approach is to use both filters offered by the `-f` and the `-x` to get more granularity, like this:

```bash
# Recurse the "C:\Windows" folder, and filter for the path "foo", and only provide files that end with ".exe"

$> pe-compass recurse -d C:\Windows -f foo -x .exe
```

<br />

## Iterative Inspection (Parsing Many Files)
- To recursively parse files, **you must have built** a list of target file paths as shown above. 
- Then you can use your platform's shell to iterate per line of the targets file you would have created.

Upcoming features will allow `pe-compass` to inspect file content without using iterative for-loops from a shell, stay tuned!

Below are **examples** for using `BASH` on Unix/MacOS/Linux platforms, and the `POWERSHELL` way on Windows Platforms.

### Linux/MacOS/Unix Iterative Inspection
**Step 1**
```bash
$> IFS=$'\n'    # Critical, set this variable before you start
                # Due to Shell Expansion and handling FilePaths with Spaces
```
<br/>

**Step 2 - Create a Folder to Dump Output Files**
```
$> mkdir dumps
```
<br />

**Step 3 - Launch The Parsing**
```bash
# Assumes you want JSON Output
$> for x in $(cat my_targets.txt | tr -d "'"); do base=$(basename $x); pe-compass inspect -f "$x" ./dumps/$base.json; done
```
<br />

```bash
# Assumes you want CSV Output - Use the `-c` switch
# 
$> for x in $(cat my_targets.txt | tr -d "'"); do base=$(basename $x); pe-compass inspect -f "$x" ./dumps/$base.csv -c; done
```
<br />

### Microsoft Windows Iterative Inspection

**Step 1 - Create a Dumps Folder**
```powershell
PS C:\> mkdir dumps
```
<br />

**Step 2 - Launch The Parsing**
```powershell
# Assumes you want JSON Output
PS C:\> Get-Content my_targets.txt | ForEach-Object { $base=[System.IO.Path]::GetFileName($_.Replace("'",""));pe-compass inspect -f $_.Replace("'","") -o .\dumps\$base.json }
```
<br/>

```powershell
# Assumes you want CSV Output
PS C:\> Get-Content my_targets.txt | ForEach-Object { $base=[System.IO.Path]::GetFileName($_.Replace("'",""));pe-compass inspect -f $_.Replace("'","") -o .\dumps\$base.csv -c };
```
<br/>
<br />


# Output Samples - JSON

The output of a file being parsed is shown in the below json example.

- The default output is JSON. 
- So it should be farily easy to build a custom database with this data that leverages JSON Documents.

```bash 
$>  pe-compass inspect -f pe-samples/sqlite3x86.dll
```

 ```json
  {
  "pe_name": "sqlite3x86.dll",
  "pe_type": 267,
  "pe_size": 944840,
  "pe_subsystem": 3,
  "pe_subsystem_caption": "The Windows character (Cosole UI) subsystem",
  "pe_path": "pe-samples/sqlite3x86.dll",
  "pe_timedate_stamp": 1580156954,
  "pe_timedate_human": "2020-01-27T20:29:14.000Z",
  "ImageDLLImports": [
    {
      "name": "kernel32.dll",
      "imports": 79,
      "functions": [
        "AreFileApisANSI",
        "CloseHandle",
        "CreateFileA",
        "CreateFileMappingA",
        "CreateFileMappingW",
        "CreateFileW",
        "CreateMutexW",
        "DeleteCriticalSection",
        "DeleteFileA",
        "DeleteFileW",
        "EnterCriticalSection",
        "FlushFileBuffers",
        "FlushViewOfFile",
        "FormatMessageA",
        "FormatMessageW",
        "FreeLibrary",
        "GetCurrentProcess",
        "GetCurrentProcessId",
        "GetCurrentThreadId",
        "GetDiskFreeSpaceA",
        "GetDiskFreeSpaceW",
        "GetFileAttributesA",
        "GetFileAttributesExW",
        "GetFileAttributesW",
        "GetFileSize",
        "GetFullPathNameA",
        "GetFullPathNameW",
        "GetLastError",
        "GetModuleHandleA",
        "GetProcAddress",
        "GetProcessHeap",
        "GetSystemInfo",
        "GetSystemTime",
        "GetSystemTimeAsFileTime",
        "GetTempPathA",
        "GetTempPathW",
        "GetTickCount",
        "GetVersionExA",
        "GetVersionExW",
        "HeapAlloc",
        "HeapCompact",
        "HeapCreate",
        "HeapDestroy",
        "HeapFree",
        "HeapReAlloc",
        "HeapSize",
        "HeapValidate",
        "InitializeCriticalSection",
        "InterlockedCompareExchange",
        "LeaveCriticalSection",
        "LoadLibraryA",
        "LoadLibraryW",
        "LocalFree",
        "LockFile",
        "LockFileEx",
        "MapViewOfFile",
        "MultiByteToWideChar",
        "OutputDebugStringA",
        "OutputDebugStringW",
        "QueryPerformanceCounter",
        "ReadFile",
        "SetEndOfFile",
        "SetFilePointer",
        "SetUnhandledExceptionFilter",
        "Sleep",
        "SystemTimeToFileTime",
        "TerminateProcess",
        "TlsGetValue",
        "TryEnterCriticalSection",
        "UnhandledExceptionFilter",
        "UnlockFile",
        "UnlockFileEx",
        "UnmapViewOfFile",
        "VirtualProtect",
        "VirtualQuery",
        "WaitForSingleObject",
        "WaitForSingleObjectEx",
        "WideCharToMultiByte",
        "WriteFile"
      ]
    },
    {
      "name": "msvcrt.dll",
      "imports": 28,
      "functions": [
        "__dllonexit",
        "__setusermatherr",
        "_amsg_exit",
        "_beginthreadex",
        "_endthreadex",
        "_errno",
        "_initterm",
        "_iob",
        "_lock",
        "_onexit",
        "_unlock",
        "abort",
        "calloc",
        "fprintf",
        "free",
        "fwrite",
        "localtime",
        "malloc",
        "memcmp",
        "memmove",
        "qsort",
        "realloc",
        "strcmp",
        "strcspn",
        "strlen",
        "strncmp",
        "strrchr",
        "vfprintf"
      ]
    }
  ],
  "ImageDLLExports": {
    "exports": 273,
    "functions": [
      "sqlite3_aggregate_context",
      "sqlite3_aggregate_count",
      "sqlite3_auto_extension",
      "sqlite3_backup_finish",
      "sqlite3_backup_init",
      "sqlite3_backup_pagecount",
      "sqlite3_backup_remaining",
      "sqlite3_backup_step",
      "sqlite3_bind_blob",
      "sqlite3_bind_blob64",
      "sqlite3_bind_double",
      "sqlite3_bind_int",
      "sqlite3_bind_int64",
      "sqlite3_bind_null",
      "sqlite3_bind_parameter_count",
      "sqlite3_bind_parameter_index",
      "sqlite3_bind_parameter_name",
      "sqlite3_bind_pointer",
      "sqlite3_bind_text",
      "sqlite3_bind_text16",
      "sqlite3_bind_text64",
      "sqlite3_bind_value",
      "sqlite3_bind_zeroblob",
      "sqlite3_bind_zeroblob64",
      "sqlite3_blob_bytes",
      "sqlite3_blob_close",
      "sqlite3_blob_open",
      "sqlite3_blob_read",
      "sqlite3_blob_reopen",
      "sqlite3_blob_write",
      "sqlite3_busy_handler",
      "sqlite3_busy_timeout",
      "sqlite3_cancel_auto_extension",
      "sqlite3_changes",
      "sqlite3_clear_bindings",
      "sqlite3_close",
      "sqlite3_close_v2",
      "sqlite3_collation_needed",
      "sqlite3_collation_needed16",
      "sqlite3_column_blob",
      "sqlite3_column_bytes",
      "sqlite3_column_bytes16",
      "sqlite3_column_count",
      "sqlite3_column_database_name",
      "sqlite3_column_database_name16",
      "sqlite3_column_decltype",
      "sqlite3_column_decltype16",
      "sqlite3_column_double",
      "sqlite3_column_int",
      "sqlite3_column_int64",
      "sqlite3_column_name",
      "sqlite3_column_name16",
      "sqlite3_column_origin_name",
      "sqlite3_column_origin_name16",
      "sqlite3_column_table_name",
      "sqlite3_column_table_name16",
      "sqlite3_column_text",
      "sqlite3_column_text16",
      "sqlite3_column_type",
      "sqlite3_column_value",
      "sqlite3_commit_hook",
      "sqlite3_compileoption_get",
      "sqlite3_compileoption_used",
      "sqlite3_complete",
      "sqlite3_complete16",
      "sqlite3_config",
      "sqlite3_context_db_handle",
      "sqlite3_create_collation",
      "sqlite3_create_collation16",
      "sqlite3_create_collation_v2",
      "sqlite3_create_function",
      "sqlite3_create_function16",
      "sqlite3_create_function_v2",
      "sqlite3_create_module",
      "sqlite3_create_module_v2",
      "sqlite3_create_window_function",
      "sqlite3_data_count",
      "sqlite3_data_directory",
      "sqlite3_db_cacheflush",
      "sqlite3_db_config",
      "sqlite3_db_filename",
      "sqlite3_db_handle",
      "sqlite3_db_mutex",
      "sqlite3_db_readonly",
      "sqlite3_db_release_memory",
      "sqlite3_db_status",
      "sqlite3_declare_vtab",
      "sqlite3_drop_modules",
      "sqlite3_enable_load_extension",
      "sqlite3_enable_shared_cache",
      "sqlite3_errcode",
      "sqlite3_errmsg",
      "sqlite3_errmsg16",
      "sqlite3_errstr",
      "sqlite3_exec",
      "sqlite3_expanded_sql",
      "sqlite3_expired",
      "sqlite3_extended_errcode",
      "sqlite3_extended_result_codes",
      "sqlite3_file_control",
      "sqlite3_filename_database",
      "sqlite3_filename_journal",
      "sqlite3_filename_wal",
      "sqlite3_finalize",
      "sqlite3_free",
      "sqlite3_free_table",
      "sqlite3_fts3_may_be_corrupt",
      "sqlite3_fts5_may_be_corrupt",
      "sqlite3_get_autocommit",
      "sqlite3_get_auxdata",
      "sqlite3_get_table",
      "sqlite3_global_recover",
      "sqlite3_hard_heap_limit64",
      "sqlite3_initialize",
      "sqlite3_interrupt",
      "sqlite3_keyword_check",
      "sqlite3_keyword_count",
      "sqlite3_keyword_name",
      "sqlite3_last_insert_rowid",
      "sqlite3_libversion",
      "sqlite3_libversion_number",
      "sqlite3_limit",
      "sqlite3_load_extension",
      "sqlite3_log",
      "sqlite3_malloc",
      "sqlite3_malloc64",
      "sqlite3_memory_alarm",
      "sqlite3_memory_highwater",
      "sqlite3_memory_used",
      "sqlite3_mprintf",
      "sqlite3_msize",
      "sqlite3_mutex_alloc",
      "sqlite3_mutex_enter",
      "sqlite3_mutex_free",
      "sqlite3_mutex_leave",
      "sqlite3_mutex_try",
      "sqlite3_next_stmt",
      "sqlite3_open",
      "sqlite3_open16",
      "sqlite3_open_v2",
      "sqlite3_os_end",
      "sqlite3_os_init",
      "sqlite3_overload_function",
      "sqlite3_prepare",
      "sqlite3_prepare16",
      "sqlite3_prepare16_v2",
      "sqlite3_prepare16_v3",
      "sqlite3_prepare_v2",
      "sqlite3_prepare_v3",
      "sqlite3_profile",
      "sqlite3_progress_handler",
      "sqlite3_randomness",
      "sqlite3_realloc",
      "sqlite3_realloc64",
      "sqlite3_release_memory",
      "sqlite3_reset",
      "sqlite3_reset_auto_extension",
      "sqlite3_result_blob",
      "sqlite3_result_blob64",
      "sqlite3_result_double",
      "sqlite3_result_error",
      "sqlite3_result_error16",
      "sqlite3_result_error_code",
      "sqlite3_result_error_nomem",
      "sqlite3_result_error_toobig",
      "sqlite3_result_int",
      "sqlite3_result_int64",
      "sqlite3_result_null",
      "sqlite3_result_pointer",
      "sqlite3_result_subtype",
      "sqlite3_result_text",
      "sqlite3_result_text16",
      "sqlite3_result_text16be",
      "sqlite3_result_text16le",
      "sqlite3_result_text64",
      "sqlite3_result_value",
      "sqlite3_result_zeroblob",
      "sqlite3_result_zeroblob64",
      "sqlite3_rollback_hook",
      "sqlite3_rtree_geometry_callback",
      "sqlite3_rtree_query_callback",
      "sqlite3_set_authorizer",
      "sqlite3_set_auxdata",
      "sqlite3_set_last_insert_rowid",
      "sqlite3_shutdown",
      "sqlite3_sleep",
      "sqlite3_snprintf",
      "sqlite3_soft_heap_limit",
      "sqlite3_soft_heap_limit64",
      "sqlite3_sourceid",
      "sqlite3_sql",
      "sqlite3_status",
      "sqlite3_status64",
      "sqlite3_step",
      "sqlite3_stmt_busy",
      "sqlite3_stmt_isexplain",
      "sqlite3_stmt_readonly",
      "sqlite3_stmt_status",
      "sqlite3_str_append",
      "sqlite3_str_appendall",
      "sqlite3_str_appendchar",
      "sqlite3_str_appendf",
      "sqlite3_str_errcode",
      "sqlite3_str_finish",
      "sqlite3_str_length",
      "sqlite3_str_new",
      "sqlite3_str_reset",
      "sqlite3_str_value",
      "sqlite3_str_vappendf",
      "sqlite3_strglob",
      "sqlite3_stricmp",
      "sqlite3_strlike",
      "sqlite3_strnicmp",
      "sqlite3_system_errno",
      "sqlite3_table_column_metadata",
      "sqlite3_temp_directory",
      "sqlite3_test_control",
      "sqlite3_thread_cleanup",
      "sqlite3_threadsafe",
      "sqlite3_total_changes",
      "sqlite3_trace",
      "sqlite3_trace_v2",
      "sqlite3_transfer_bindings",
      "sqlite3_update_hook",
      "sqlite3_uri_boolean",
      "sqlite3_uri_int64",
      "sqlite3_uri_key",
      "sqlite3_uri_parameter",
      "sqlite3_user_data",
      "sqlite3_value_blob",
      "sqlite3_value_bytes",
      "sqlite3_value_bytes16",
      "sqlite3_value_double",
      "sqlite3_value_dup",
      "sqlite3_value_free",
      "sqlite3_value_frombind",
      "sqlite3_value_int",
      "sqlite3_value_int64",
      "sqlite3_value_nochange",
      "sqlite3_value_numeric_type",
      "sqlite3_value_pointer",
      "sqlite3_value_subtype",
      "sqlite3_value_text",
      "sqlite3_value_text16",
      "sqlite3_value_text16be",
      "sqlite3_value_text16le",
      "sqlite3_value_type",
      "sqlite3_version",
      "sqlite3_vfs_find",
      "sqlite3_vfs_register",
      "sqlite3_vfs_unregister",
      "sqlite3_vmprintf",
      "sqlite3_vsnprintf",
      "sqlite3_vtab_collation",
      "sqlite3_vtab_config",
      "sqlite3_vtab_nochange",
      "sqlite3_vtab_on_conflict",
      "sqlite3_wal_autocheckpoint",
      "sqlite3_wal_checkpoint",
      "sqlite3_wal_checkpoint_v2",
      "sqlite3_wal_hook",
      "sqlite3_win32_is_nt",
      "sqlite3_win32_mbcs_to_utf8",
      "sqlite3_win32_mbcs_to_utf8_v2",
      "sqlite3_win32_set_directory",
      "sqlite3_win32_set_directory16",
      "sqlite3_win32_set_directory8",
      "sqlite3_win32_sleep",
      "sqlite3_win32_unicode_to_utf8",
      "sqlite3_win32_utf8_to_mbcs",
      "sqlite3_win32_utf8_to_mbcs_v2",
      "sqlite3_win32_utf8_to_unicode",
      "sqlite3_win32_write_debug"
    ]
  },
  "ImageHashSignatures": {
    "md5": "c75916b15535b1bc67d92975921e95e3",
    "sha2": "5479d713d4cc5415a7f1d9272958da290758ac3f0f5bd73dd8f9afbf437745d5"
  }
```
<br/>

# Output Samples - CSV
The output below is for CSV Format. The current format does not provide **COLUMN NAMES**, you can label the columns to your preference. However, it is important that you name your columns according to the data rows and its context being provided.

I prefer to work with SQL like databases, and the CSV imports to different SQL like databases shoudl be fairly easy.

```bash
 $> pe-compass inspect -f pe-samples/sqlite3x86.dll -c 
```
```bash
# Snippet

sqlite3x86.dll,944840,3,1580156954,2020-01-27T20:29:14.000Z,imports,kernel32.dll,AreFileApisANSI,c75916b15535b1bc67d92975921e95e3,5479d713d4cc5415a7f1d9272958da290758ac3f0f5bd73dd8f9afbf437745d5,pe-samples/sqlite3x86.dll
sqlite3x86.dll,944840,3,1580156954,2020-01-27T20:29:14.000Z,imports,kernel32.dll,CloseHandle,c75916b15535b1bc67d92975921e95e3,5479d713d4cc5415a7f1d9272958da290758ac3f0f5bd73dd8f9afbf437745d5,pe-samples/sqlite3x86.dll
sqlite3x86.dll,944840,3,1580156954,2020-01-27T20:29:14.000Z,imports,kernel32.dll,CreateFileA,c75916b15535b1bc67d92975921e95e3,5479d713d4cc5415a7f1d9272958da290758ac3f0f5bd73dd8f9afbf437745d5,pe-samples/sqlite3x86.dll
sqlite3x86.dll,944840,3,1580156954,2020-01-27T20:29:14.000Z,imports,kernel32.dll,CreateFileMappingA,c75916b15535b1bc67d92975921e95e3,5479d713d4cc5415a7f1d9272958da290758ac3f0f5bd73dd8f9afbf437745d5,pe-samples/sqlite3x86.dll
sqlite3x86.dll,944840,3,1580156954,2020-01-27T20:29:14.000Z,imports,kernel32.dll,CreateFileMappingW,c75916b15535b1bc67d92975921e95e3,5479d713d4cc5415a7f1d9272958da290758ac3f0f5bd73dd8f9afbf437745d5,pe-samples/sqlite3x86.dll
sqlite3x86.dll,944840,3,1580156954,2020-01-27T20:29:14.000Z,imports,kernel32.dll,CreateFileW,c75916b15535b1bc67d92975921e95e3,5479d713d4cc5415a7f1d9272958da290758ac3f0f5bd73dd8f9afbf437745d5,pe-samples/sqlite3x86.dll
sqlite3x86.dll,944840,3,1580156954,2020-01-27T20:29:14.000Z,imports,kernel32.dll,CreateMutexW,c75916b15535b1bc67d92975921e95e3,5479d713d4cc5415a7f1d9272958da290758ac3f0f5bd73dd8f9afbf437745d5,pe-samples/sqlite3x86.dll
sqlite3x86.dll,944840,3,1580156954,2020-01-27T20:29:14.000Z,imports,kernel32.dll,DeleteCriticalSection,c75916b15535b1bc67d92975921e95e3,5479d713d4cc5415a7f1d9272958da290758ac3f0f5bd73dd8f9afbf437745d5,pe-samples/sqlite3x86.dll
sqlite3x86.dll,944840,3,1580156954,2020-01-27T20:29:14.000Z,imports,kernel32.dll,DeleteFileA,c75916b15535b1bc67d92975921e95e3,5479d713d4cc5415a7f1d9272958da290758ac3f0f5bd73dd8f9afbf437745d5,pe-samples/sqlite3x86.dll
sqlite3x86.dll,944840,3,1580156954,2020-01-27T20:29:14.000Z,imports,kernel32.dll,DeleteFileW,c75916b15535b1bc67d92975921e95e3,5479d713d4cc5415a7f1d9272958da290758ac3f0f5bd73dd8f9afbf437745d5,pe-samples/sqlite3x86.dll
sqlite3x86.dll,944840,3,1580156954,2020-01-27T20:29:14.000Z,imports,kernel32.dll,EnterCriticalSection,c75916b15535b1bc67d92975921e95e3,5479d713d4cc5415a7f1d9272958da290758ac3f0f5bd73dd8f9afbf437745d5,pe-samples/sqlite3x86.dll
sqlite3x86.dll,944840,3,1580156954,2020-01-27T20:29:14.000Z,imports,kernel32.dll,FlushFileBuffers,c75916b15535b1bc67d92975921e95e3,5479d713d4cc5415a7f1d9272958da290758ac3f0f5bd73dd8f9afbf437745d5,pe-samples/sqlite3x86.dll
sqlite3x86.dll,944840,3,1580156954,2020-01-27T20:29:14.000Z,imports,kernel32.dll,FlushViewOfFile,c75916b15535b1bc67d92975921e95e3,5479d713d4cc5415a7f1d9272958da290758ac3f0f5bd73dd8f9afbf437745d5,pe-samples/sqlite3x86.dll
sqlite3x86.dll,944840,3,1580156954,2020-01-27T20:29:14.000Z,imports,kernel32.dll,FormatMessageA,c75916b15535b1bc67d92975921e95e3,5479d713d4cc5415a7f1d9272958da290758ac3f0f5bd73dd8f9afbf437745d5,pe-samples/sqlite3x86.dll
```
<br />
<br />

# PROJECT STATUS
The project is being developed and you should use the `releases` section
of this project to use stable versions suitable for productive work.

The `Master` branch may not reflect the version of the `releases` section
at times, although you can use the `Master` branch if  you want to be working
with bleeding edge versions.

Note:   If you decide to clone the `Master` branch you should have the stable
        rust toolchain installed in your platform. Once you are setup with the
        stable rustup toolchain, go ahead and compile with `cargo build --release`

<br />
<br />

## USAGE
This project is not focused on building a binary parser, **it is an analytics project**.
The binary provided here with rust is the `workhorse` that is used to baseline a
computer's *on-disk* binaries from filesystem locations.
<br />

## MOTIVATION
Making better decisions with a data driven approach is the main motivation. Seemingly, solving for monotonous time consuming daily tasks is the long term goal.
Before I take action in applying an endpoint security control - I need to be confident in what I am going to disrupt, or what I expect to trigger as false positives
to responsibly manage the effort required in removing these. I don't know of better ways, other than having data to support these needs.

<br/>

### Data Pipelines - Fast & Reliable, Please!

The project is created as a need to build custom datasets and pipelines around 
DLL telemetry and its **context** with large scale requirements - i.e., > ~750K PE Files per day.

By context we mean the informational value afforded by the type of data that can be acquired by DLLs imported in a Portable Executable
file - PE file.

At this time, the focus is to study the `imports` or `IAT` and `exports` or `EAT` tables from a PE file to
identify the meaning of the question: *What is the notion of intent from the PE file?*
<br />

### Better Tooling - Cross Platform Please! TOP 10 Frustrations
I needed a tool that could be run on most environments without the gymnastics of compilation or having 3 codebases.

I used many Python parsers in my past, and binaries provided by many people.  
I hit a stumbling block, as I would move to bigger projects or clients.

I grew so much frustration from:


1. The Python Tools would be slow or unreliable (crash with abnormal PE files)

2. Or the parsers would only support either one of 32bit or 64 bit PEs, but not both :(

3. Or the parsers were awesome, BUT ONLY in GUI Mode

4. Or the parsers are free but DO not provide the IAT and EAT as output, only some random properties

5. Or the Java parsers would break with new Java versions and the developer won't update the code

6. Or the Python, and Java parsers would require the installation of Java and Python Environments

7. Or the Python PIP_FREEZE executable binaries would NOT work across 32 or 64 bit Windows Platforms

8. Or the awesome C# tool created by someone could not run on Linux/MacOS for malware triaging workflows, again slowness :(

9. Or the output provided by the developers would not provide database interchange formats - i.e., CSV or JSON

10. Or worse I could not afford some awesome tool nor would my employers/clients buy them for me and the team :(

<br />


### Education and Mastery - For Everyone (Me, You, and those of tomorrow)
As I grew my skill set, I recognized how much energy and effort is needed to boost/uplift new team members without
good datasets.  People may not initially have malware analysis skills, but they certainly have data analysis experience.

I noticed people of all backgrounds learn faster with data by doing, this motivated me to not loose energy in repeating myself
but rather affording collaboration opportunities to tackle security problems together, regardless of tenure or experience.
<br />


### Grow Existing Security Community Knowledge
As many security researchers and professional programmers have noted, the PE file is
fairly intuitive based on the Microsoft usage of descriptive function names stemming
from *hungarian notation*.

The true power of this project is the custom datasets you can build in a database
for analytics, and it is those analytics that can allow you to better understand
which types of telemetry collection approaches are useful for large-scale visibility
programs tracing computer systems and the programs they run.
<br />
<br />


# Documentation Articles
Title|URL|
-----|---|
PE Rich Data Structure: Undocumented|[LINK](http://bytepointer.com/articles/the_microsoft_rich_header.htm)|
PE Things They Did not tell you...|[LINK](http://bytepointer.com/articles/rich_header_lifewire_vxmags_29A-8.009.htm)|
PE MindMap By Ero Carrera|[LINK](http://www.openrce.org/reference_library/files/reference/PE%20Format.pdf)|
PE MSDN Article|[LINK](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)|
PE Understanding RVAs, Sunshine|[LINK](http://www.sunshine2k.de/reversing/tuts/tut_rvait.htm)|
<br/>

# Documentation Security Centric Resources
Title|URL|
-----|---|
Sans Mind The Gap|[LINK](https://www.sans.org/cyber-security-summit/archives/file/summit-archive-1493841390.pdf)|
Breaking ImpHash|[LINK](https://arxiv.org/pdf/1909.07630.pdf)|
SSDEEP Hashing|[LINK](https://ssdeep-project.github.io/ssdeep/)|
Malware Analysis Center|[LINK](https://practicalsecurityanalytics.com/malware-analysis-center/)|

<br/>

# To Do
* Implement Recursive With File Content Inspection & Validation (non-shell iteration)
* Implement Security Scanning Interfaces for Security Users
* Implement Database Bootstrap Content: SQLITE & PGSQL
* Optimization Parsing: From String to &str lifetimes
* Support Parsing of UPX0 packed sections
* Implement PE Renderer: TABULAR
* Implement Progress Indicators

<br/>
