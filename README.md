# pe-compass
A Study of the PE Format through the RUST programming language.
<br/>
<br/>

# PROJECT STATUS
The project is being developed and you should use the `releases` section
of this project to use stable versions suitable for productive work.

The `Master` branch may not reflect the version of the `releases` section
at times, although you can use the `Master` branch if  you want to be working
with bleeding edge versions.

Note:   If you decide to clone the `Master` branch you should have the stable
        rust toolchain installed in your platform. Once you are setup with the
        stable rustup toolchain, go ahead and compile with `cargo build --release`


# PROJECT USAGE
This project is not focused on building a binary parser, it is an analytics project.
The binary provided here with rust is the `workhorse` that is used to baseline a
computer's *on-disk* binaries from filesystem locations.

The project is created as a need to build custom datasets and pipelines around 
DLL telemetry and its context. By context we mean the informational value afforded
by the type of data that can be acquired by DLLs imported in a Portable Executable
file - PE file.

At this time, the focus is to study the `imports` or `IAT` table from a PE file to
identify the meaning of the question: *What is the notion of intent from the PE file?*

As many security researchers and professional programmers have noted, the PE file is
fairly intuitive based on the Microsoft usage of descriptive function name stemming
from *hungarian notation*.

The true power of this project is the custom datasets you can build in a database
for analytics, and it is those analytics that can allow you to better understand
which types of telemetry collection approaches are useful for large-scale visibility
programs tracing computer systems and the programs they run.
<br/>

# Documentation Articles
Title|URL|
-----|---|
PE Rich Data Structure: Undocumented|[LINK](http://bytepointer.com/articles/the_microsoft_rich_header.htm)|
PE Things They Did not tell you...|[LINK](http://bytepointer.com/articles/rich_header_lifewire_vxmags_29A-8.009.htm)|
PE MindMap By Ero Carrera|[LINK](http://www.openrce.org/reference_library/files/reference/PE%20Format.pdf)|
PE MSDN Article|[LINK](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)|
PE Understanding RVAs, Sunshine|[LINK](http://www.sunshine2k.de/reversing/tuts/tut_rvait.htm)|
<br/>

# To Do
* Implement PE Renderer: CSV & TABULAR
* Implement Recursive Content Inspection & Validation
* Implement Progress Indicators
* Implement Database Workers: SQLITE & PGSQL
* Optimization Parsing: From String to &str lifetimes
* Support Parsing of UPX0 packed sections

<br/>
<hr/>

# Current Progress
Currently, the program is run like this:

## Help Menu
You can get help by using the `-h` switch

```text
$> pe-compass -h

pe-compass v.0.0.8
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
$> pe-compass inspect -h

pe-compass-inspect v.0.0.8
carlos diaz | @dfirence

Inspect a PE File's Imports Structure

USAGE:
    pe-compass inspect [OPTIONS]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -f <PE FILE>            File System Path of PEFILE to inspect
    -o <OUTPUT FILE>        Destination File to Write Output to
```
<br/>
<br/>

## Parse A File
To parse a single file, enter the `subcommand` options `inspect` and use the `-f` switch and filepath of the pe file.

```bash
$> pe-compass inspect -f pe-samples/sqlite3x86.dll
```

To parse a single file and save the parsed output, use the `-o` switch

```bash
$> pe-compass inspect -f pe-samples/sqlite3x86.dll -o sqlite.json
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
$> pe-compass recurse -d C:\Windows
```
<br/>

### Build a list of target filepaths with filtering
You can use the `-f` switch to filter by a string matching anywhere in the filename or absolute file path

```bash
# Recurse the C:\Windows folder, and filter for string "foo"

$> pe-compass recurse -d C:\Windows -f foo > C:\targets.txt
```
<br/>

You can instead do another filter that matches as **endwith** in the filename or absolute file paths

```bash
# Recurse the C:\Windows folder, and filter for anything matching at the end with ".exe"
$> pe-compass recurse -d C:\Windows -x .exe > C:\targets.txt

# Do the same but this time for ".dll" files
$> pe-compass recurse -d C:\Windows -x .dll > C:\targets.txt

# Or this time for ".sys" files
$> pe-compass recurse -d C:\Windows -x .sys > C:\targets.txt
```
<br />

One more approach is to use both filters offered by the `-f` and the `-x` to get more granularity, like this:

```bash
# Recurse the C:\Windows folder, and filter for the path "foo", and only provide files that end with ".exe"

$> pe-compass recurse -d C:\Windows -f foo -x .exe
```

# Output Samples

The output of a file being parsed is shown in the below json output. The default output is JSON. So it should be farily easy to build a custom database
with this data that leverages JSON Documents.  Future releases are going to accomodate CSV and SQL output to build SQL databases <-- My FAVORITE

```json 
 > pe-compass inspect -f pe-samples/sqlite3x86.dll 
{
  "pename": "sqlite3x86.dll",
  "petype": 267,
  "pesubsystem": 3,
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
      "sqlite3_auto_extensions",
      "sqlite3_backup_finish",
      "sqlite3_backup_init",
      "sqlite3_backup_pagecounts",
      "sqlite3_backup_remainings",
      "sqlite3_backup_step",
      "sqlite3_bind_blob",
      "sqlite3_bind_blob64",
      "sqlite3_bind_double",
      "sqlite3_bind_ints",
      "sqlite3_bind_int64s",
      "sqlite3_bind_null",
      "sqlite3_bind_parameter_counts",
      "sqlite3_bind_parameter_indexs",
      "sqlite3_bind_parameter_name",
      "sqlite3_bind_pointers",
      "sqlite3_bind_text",
      "sqlite3_bind_text16",
      "sqlite3_bind_text64",
      "sqlite3_bind_values",
      "sqlite3_bind_zeroblob",
      "sqlite3_bind_zeroblob64",
      "sqlite3_blob_bytess",
      "sqlite3_blob_closes",
      "sqlite3_blob_open",
      "sqlite3_blob_read",
      "sqlite3_blob_reopen",
      "sqlite3_blob_writes",
      "sqlite3_busy_handlers",
      "sqlite3_busy_timeouts",
      "sqlite3_cancel_auto_extension",
      "sqlite3_changes",
      "sqlite3_clear_bindingss",
      "sqlite3_close",
      "sqlite3_close_v2s",
      "sqlite3_collation_neededs",
      "sqlite3_collation_needed16s",
      "sqlite3_column_blob",
      "sqlite3_column_bytess",
      "sqlite3_column_bytes16s",
      "sqlite3_column_counts",
      "sqlite3_column_database_names",
      "sqlite3_column_database_name16s",
      "sqlite3_column_decltype",
      "sqlite3_column_decltype16",
      "sqlite3_column_double",
      "sqlite3_column_ints",
      "sqlite3_column_int64s",
      "sqlite3_column_name",
      "sqlite3_column_name16",
      "sqlite3_column_origin_names",
      "sqlite3_column_origin_name16s",
      "sqlite3_column_table_name",
      "sqlite3_column_table_name16",
      "sqlite3_column_text",
      "sqlite3_column_text16",
      "sqlite3_column_type",
      "sqlite3_column_values",
      "sqlite3_commit_hook",
      "sqlite3_compileoption_get",
      "sqlite3_compileoption_useds",
      "sqlite3_completes",
      "sqlite3_complete16s",
      "sqlite3_configs",
      "sqlite3_context_db_handle",
      "sqlite3_create_collations",
      "sqlite3_create_collation16s",
      "sqlite3_create_collation_v2",
      "sqlite3_create_function",
      "sqlite3_create_function16",
      "sqlite3_create_function_v2s",
      "sqlite3_create_module",
      "sqlite3_create_module_v2s",
      "sqlite3_create_window_functions",
      "sqlite3_data_counts",
      "sqlite3_data_directorys",
      "sqlite3_db_cacheflush",
      "sqlite3_db_config",
      "sqlite3_db_filename",
      "sqlite3_db_handle",
      "sqlite3_db_mutexs",
      "sqlite3_db_readonly",
      "sqlite3_db_release_memory",
      "sqlite3_db_status",
      "sqlite3_declare_vtabs",
      "sqlite3_drop_moduless",
      "sqlite3_enable_load_extension",
      "sqlite3_enable_shared_cache",
      "sqlite3_errcode",
      "sqlite3_errmsgs",
      "sqlite3_errmsg16s",
      "sqlite3_errstrs",
      "sqlite3_execs",
      "sqlite3_expanded_sqls",
      "sqlite3_expired",
      "sqlite3_extended_errcodes",
      "sqlite3_extended_result_codes",
      "sqlite3_file_controls",
      "sqlite3_filename_database",
      "sqlite3_filename_journals",
      "sqlite3_filename_wals",
      "sqlite3_finalizes",
      "sqlite3_frees",
      "sqlite3_free_tables",
      "sqlite3_fts3_may_be_corrupt",
      "sqlite3_fts5_may_be_corrupt",
      "sqlite3_get_autocommits",
      "sqlite3_get_auxdata",
      "sqlite3_get_table",
      "sqlite3_global_recovers",
      "sqlite3_hard_heap_limit64",
      "sqlite3_initializes",
      "sqlite3_interrupt",
      "sqlite3_keyword_check",
      "sqlite3_keyword_count",
      "sqlite3_keyword_names",
      "sqlite3_last_insert_rowid",
      "sqlite3_libversions",
      "sqlite3_libversion_number",
      "sqlite3_limit",
      "sqlite3_load_extensions",
      "sqlite3_log",
      "sqlite3_mallocs",
      "sqlite3_malloc64s",
      "sqlite3_memory_alarms",
      "sqlite3_memory_highwaters",
      "sqlite3_memory_used",
      "sqlite3_mprintf",
      "sqlite3_msize",
      "sqlite3_mutex_alloc",
      "sqlite3_mutex_enter",
      "sqlite3_mutex_frees",
      "sqlite3_mutex_leave",
      "sqlite3_mutex_try",
      "sqlite3_next_stmt",
      "sqlite3_opens",
      "sqlite3_open16s",
      "sqlite3_open_v2",
      "sqlite3_os_ends",
      "sqlite3_os_init",
      "sqlite3_overload_function",
      "sqlite3_prepare",
      "sqlite3_prepare16",
      "sqlite3_prepare16_v2s",
      "sqlite3_prepare16_v3s",
      "sqlite3_prepare_v2s",
      "sqlite3_prepare_v3s",
      "sqlite3_profile",
      "sqlite3_progress_handlers",
      "sqlite3_randomnesss",
      "sqlite3_realloc",
      "sqlite3_realloc64",
      "sqlite3_release_memorys",
      "sqlite3_reset",
      "sqlite3_reset_auto_extensions",
      "sqlite3_result_blob",
      "sqlite3_result_blob64",
      "sqlite3_result_double",
      "sqlite3_result_errors",
      "sqlite3_result_error16s",
      "sqlite3_result_error_code",
      "sqlite3_result_error_nomems",
      "sqlite3_result_error_toobig",
      "sqlite3_result_ints",
      "sqlite3_result_int64s",
      "sqlite3_result_null",
      "sqlite3_result_pointers",
      "sqlite3_result_subtypes",
      "sqlite3_result_text",
      "sqlite3_result_text16",
      "sqlite3_result_text16be",
      "sqlite3_result_text16le",
      "sqlite3_result_text64",
      "sqlite3_result_values",
      "sqlite3_result_zeroblob",
      "sqlite3_result_zeroblob64",
      "sqlite3_rollback_hook",
      "sqlite3_rtree_geometry_callback",
      "sqlite3_rtree_query_callbacks",
      "sqlite3_set_authorizers",
      "sqlite3_set_auxdata",
      "sqlite3_set_last_insert_rowid",
      "sqlite3_shutdowns",
      "sqlite3_sleep",
      "sqlite3_snprintfs",
      "sqlite3_soft_heap_limit",
      "sqlite3_soft_heap_limit64",
      "sqlite3_sourceids",
      "sqlite3_sql",
      "sqlite3_statuss",
      "sqlite3_status64s",
      "sqlite3_steps",
      "sqlite3_stmt_busy",
      "sqlite3_stmt_isexplains",
      "sqlite3_stmt_readonly",
      "sqlite3_stmt_status",
      "sqlite3_str_appends",
      "sqlite3_str_appendall",
      "sqlite3_str_appendchars",
      "sqlite3_str_appendf",
      "sqlite3_str_errcode",
      "sqlite3_str_finishs",
      "sqlite3_str_lengths",
      "sqlite3_str_new",
      "sqlite3_str_reset",
      "sqlite3_str_value",
      "sqlite3_str_vappendfs",
      "sqlite3_strglob",
      "sqlite3_stricmp",
      "sqlite3_strlike",
      "sqlite3_strnicmps",
      "sqlite3_system_errnos",
      "sqlite3_table_column_metadata",
      "sqlite3_temp_directorys",
      "sqlite3_test_controls",
      "sqlite3_thread_cleanups",
      "sqlite3_threadsafes",
      "sqlite3_total_changes",
      "sqlite3_trace",
      "sqlite3_trace_v2s",
      "sqlite3_transfer_bindings",
      "sqlite3_update_hook",
      "sqlite3_uri_boolean",
      "sqlite3_uri_int64",
      "sqlite3_uri_key",
      "sqlite3_uri_parameter",
      "sqlite3_user_data",
      "sqlite3_value_blobs",
      "sqlite3_value_bytes",
      "sqlite3_value_bytes16",
      "sqlite3_value_doubles",
      "sqlite3_value_dup",
      "sqlite3_value_frees",
      "sqlite3_value_frombinds",
      "sqlite3_value_int",
      "sqlite3_value_int64",
      "sqlite3_value_nochanges",
      "sqlite3_value_numeric_types",
      "sqlite3_value_pointer",
      "sqlite3_value_subtype",
      "sqlite3_value_texts",
      "sqlite3_value_text16s",
      "sqlite3_value_text16bes",
      "sqlite3_value_text16les",
      "sqlite3_value_types",
      "sqlite3_version",
      "sqlite3_vfs_finds",
      "sqlite3_vfs_registers",
      "sqlite3_vfs_unregisters",
      "sqlite3_vmprintfs",
      "sqlite3_vsnprintf",
      "sqlite3_vtab_collations",
      "sqlite3_vtab_config",
      "sqlite3_vtab_nochange",
      "sqlite3_vtab_on_conflicts",
      "sqlite3_wal_autocheckpoints",
      "sqlite3_wal_checkpoints",
      "sqlite3_wal_checkpoint_v2",
      "sqlite3_wal_hooks",
      "sqlite3_win32_is_nt",
      "sqlite3_win32_mbcs_to_utf8s",
      "sqlite3_win32_mbcs_to_utf8_v2",
      "sqlite3_win32_set_directory",
      "sqlite3_win32_set_directory16",
      "sqlite3_win32_set_directory8s",
      "sqlite3_win32_sleep",
      "sqlite3_win32_unicode_to_utf8",
      "sqlite3_win32_utf8_to_mbcss",
      "sqlite3_win32_utf8_to_mbcs_v2",
      "sqlite3_win32_utf8_to_unicode",
      "sqlite3_win32_write_debug"
    ]
  },
  "ImageHashSignatures": {
    "md5": "c75916b15535b1bc67d92975921e95e3",
    "sha2": "5479d713d4cc5415a7f1d9272958da290758ac3f0f5bd73dd8f9afbf437745d5"
  }
}
```
<br/>

