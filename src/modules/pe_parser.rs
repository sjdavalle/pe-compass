use scroll::{ Pread, LE, BE };

#[path = "../utils/filesystem/file_handler.rs"] mod file_handler;
#[path = "../structs/pe_structs.rs"] mod pe_structs;

use file_handler::FileHandler;
use pe_structs::*;

/// # PE32 
/// This object represents a 32bit Portable Executable
/// 
pub struct PE32 {
    ImageDosHeader: IMAGE_DOS_HEADER,
    IamgeNtHeaders: IMAGE_NT_HEADERS32
}
/// # PE Parser
/// This module is used to parse the structures of the PE Format
/// The parser should accomodate the identification of either a
/// PE32 or PE64 being in scope, and subsequently, providing the
/// relevant logic to parser the in scope object.
///
#[derive(Debug)]
pub struct PEParser {
    handler: FileHandler,
    content: Vec<u8>,
    success: bool,
}
impl PEParser {
    pub fn new(fp: &str) -> Self
    {
        let _file = FileHandler::open(fp, "r");

        if !_file.success {
            std::process::exit(0x0100);

        } else {
            let _fsize = _file.size;
            let _bytes = _file.read_as_bytes(_fsize).unwrap();

            PEParser {
                handler:    _file,
                content:    _bytes,
                success:    true,
            }
        }
    }
    pub fn get_dosheader(&self) -> IMAGE_DOS_HEADER
    {
        let _doshdr: IMAGE_DOS_HEADER = self.content.pread_with(0usize, LE).unwrap();
        _doshdr
    }
    pub fn get_peheader(&self, e_lfanew: i32) -> IMAGE_NT_HEADERS32
    {
        let _offset = e_lfanew as usize;

        let _peheader: IMAGE_NT_HEADERS32 = self.content.pread_with(_offset, LE).unwrap();
        _peheader
    } 
}