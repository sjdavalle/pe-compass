///
/// # Windows Types - Wintypes
/// 
/// This file is a record of Microsoft Windows definitions
/// translated into `RUST` types to accomodate a smoother
/// porting of the PE File Format into this program.
/// 
/// The intention is to keep things simple and remove ambiguity
/// for anyone interested in learning about the PE file format
/// while leveraging the rust programming language.
/// 
/// ```
/// Example: Translation from Windows Types to Rust Type
/// type WORD  = u16;
/// type DWORD = u32;
/// type QWORD = u64;
/// ```
/// 
/// # Note
/// Not every windows type is used here as the program is only
/// focused on the items or required definitions that allow you
/// to parse a PE file.
/// 
pub type BYTE       = u8;
pub type UCHAR      = u8;
pub type WORD       = u16;
pub type DWORD      = u32;
pub type QWORD      = u64;

pub type USHORT     = u16;
pub type ULONG      = u32;
pub type ULONGLONG  = u64;

pub type LONG       = i32;
pub type BOOLEAN    = BYTE;