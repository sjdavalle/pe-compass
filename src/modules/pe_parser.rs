use std::collections::HashMap;

use scroll::{ Pread, LE };

#[path = "../utils/filesystem/file_handler.rs"] mod file_handler;
use file_handler::FileHandler;

#[path = "../utils/errors/custom_errors.rs"] mod custom_errors;
use custom_errors::exit_process;

#[path = "../structs/pe_structs.rs"] mod pe_structs;
use pe_structs::*;

/// # PE Parser
/// This module is used to parse the structures of the PE Format
/// The parser should accomodate the identification of either a
/// PE32 or PE64 being in scope, and subsequently, providing the
/// relevant logic to parser the in scope object.
///
#[derive(Debug)]
pub struct PeParser {
    handler: FileHandler,
    content: Vec<u8>,
}

impl PeParser {
    /// # Pe Parser New Method
    /// Creates a new instance of the PE Parser Object
    /// and it loads a PE file for parsing.
    /// 
    /// Note:   This is not optimized at this time, right now
    ///         we are focused on correctly parsing the PE format
    /// 
    /// ```
    /// let _pe = PeParser::new("foo.exe");
    /// ```
    pub fn new(fp: &str) -> Self
    {
        let _file = FileHandler::open(fp, "r");
        let _fsize = _file.size;
        if _fsize < 60 {
            std::process::exit(0x0100); // If file size less than 60 bytes exit
        }
        let _bytes = _file.read_as_bytes(_fsize).unwrap();

        PeParser {
            handler: _file,
            content: _bytes,
        }
    }
    /// # PE Parser InspectFile Method
    /// This method initially inspect the consistent headers of the file
    /// to determine if it is a 32 or 64 bit PE.
    /// If the inspection fails, the file is likely not legit.
    /// **Note:**   At this moment Packers are not in scope, so if a UPX0 header
    ///             is in place, the program will crash or not work.
    /// 
    pub fn inspect_file(&self) -> PE_FILE
    {
        let _doshdr: IMAGE_DOS_HEADER = self.get_dosheader();
        let _nt_test: INSPECT_NT_HEADERS = self.inspect_nt_headers(_doshdr.e_lfanew);
        let _petype: u16 = _nt_test.OptionalHeader.Magic;

        match _petype {
            267 => { PE_FILE::x86(self.get_pe32(_doshdr)) },
            523 => { PE_FILE::x64(self.get_pe64(_doshdr)) },
            _   => std::process::exit(0x0100)
        }
    }
    ///
    /// 
    /// 
    fn get_pe32(&self, _doshdr: IMAGE_DOS_HEADER) -> PE_32
    {
        let mut _nt_headers: IMAGE_NT_HEADERS32 = self.get_image_nt_headers32(_doshdr.e_lfanew);
        let _data_dir_offset = &_nt_headers.OptionalHeader.DataDirectory;
        let _data_directories: HashMap<String, IMAGE_DATA_DIRECTORY> = self.get_data_directories(_data_dir_offset);
        PE_32 {
            ImageDosHeader: _doshdr,
            ImageNtHeaders: _nt_headers,
            ImageDataDirectory: _data_directories
        }
    }
    ///
    /// 
    /// 
    fn get_pe64(&self, _doshdr: IMAGE_DOS_HEADER) -> PE_64
    {
        let _nt_headers: IMAGE_NT_HEADERS64 = self.get_image_nt_headers64(_doshdr.e_lfanew);
        let _data_dir_offset = &_nt_headers.OptionalHeader.DataDirectory;
        let _data_directories: HashMap<String, IMAGE_DATA_DIRECTORY> = self.get_data_directories(_data_dir_offset);
        PE_64 {
            ImageDosHeader: _doshdr,
            ImageNtHeaders: _nt_headers,
            ImageDataDirectory: _data_directories
        }
    }
    /// # PE Parser GetDosHeader Method
    /// This parses the initial IMAGE_DOS_HEADER struct from
    /// a byte stream.
    /// 
    /// ```
    /// let _pe = PeParser::new("foo.exe");
    /// 
    /// let _dh: IMAGE_DOS_HEADER = _pe.content.pread(0usize, LE).unwrap();
    /// ```
    pub fn get_dosheader(&self) -> IMAGE_DOS_HEADER
    {
        let _offset = 0 as usize;
        let _doshdr: IMAGE_DOS_HEADER = self.content.pread_with(_offset, LE).unwrap();
        _doshdr
    }
    /// # PE Parser InspectNTHeader Method
    /// This parses a custom object struct (co_struct) of a selected subset of the
    /// IMAGE_OPTIONAL_HEADER to be used in the validation stage which allows you
    /// to easily determine the type of PE 32 or 64 bit in-scope.
    /// 
    /// We are avoiding any inspection of the `RICH` data structure for now.
    pub fn inspect_nt_headers(&self, e_lfanew: i32) -> INSPECT_NT_HEADERS
    {
        let _offset = e_lfanew as usize;
        let _nt_headers: INSPECT_NT_HEADERS = self.content.pread_with(_offset, LE).unwrap();
        _nt_headers
    }
    /// # PE Parser GetImageNTHeaders32 Method
    /// This parses the initial IMAGE_NT_HEADERS32 struct from
    /// a byte stream.
    /// 
    /// ```
    /// let _pe = PeParser::new("foo.exe");
    /// 
    /// let _dh: IMAGE_DOS_HEADER = _pe.content.pread(0usize, LE).unwrap();
    /// ```    
    fn get_image_nt_headers32(&self, e_lfanew: i32) -> IMAGE_NT_HEADERS32
    {
        let _offset = e_lfanew as usize;       
        let _peheader: IMAGE_NT_HEADERS32 = self.content.pread_with(_offset, LE).unwrap();
        _peheader
    }
    /// # PE Parser GetImageNTHeaders64 Method
    /// This parses the initial IMAGE_NT_HEADERS32 struct from
    /// a byte stream.
    /// 
    /// ```
    /// let _pe = PeParser::new("foo.exe");
    /// 
    /// let _dh: IMAGE_DOS_HEADER = _pe.content.pread(0usize, LE).unwrap();
    /// ```    
    fn get_image_nt_headers64(&self, e_lfanew: i32) -> IMAGE_NT_HEADERS64
    {
        let _offset = e_lfanew as usize;       
        let _peheader: IMAGE_NT_HEADERS64 = self.content.pread_with(_offset, LE).unwrap();
        _peheader
    }    
    /// # PE Parser GetDataDirectories Method
    /// This parses the 16 data directories from the OPTIONAL_HEADER to return
    /// a Vector of IMAGE_DATA_DIRECTORY entries.
    /// 
    /// ```
    /// let _pe = PeParser::new("foo.exe")
    /// ```
    fn get_data_directories(&self, data_dir: &[u64; 16usize]) -> HashMap<String, IMAGE_DATA_DIRECTORY>
    {
        let mut _data_directories: Vec<IMAGE_DATA_DIRECTORY> = Vec::with_capacity(16usize);
        let _offset = 0 as usize;

        // Serialize Each Data Directory
        for _d in data_dir.iter() {
            let _bytes = _d.to_le_bytes();
            let _data_dir: IMAGE_DATA_DIRECTORY = _bytes.pread_with(_offset, LE).unwrap();
            _data_directories.push(_data_dir);
        }
        // Now Build the dataMap
        let mut _data_map: HashMap<String, IMAGE_DATA_DIRECTORY> = HashMap::new();
        let mut _type: String = String::with_capacity(32usize);

        for (_idx, _entry) in _data_directories.iter().enumerate() {
            if _entry.Size != 0 {
                match _idx {
                    0   =>  { _type = String::from("IMAGE_DIRECTORY_ENTRY_EXPORT")          ; _data_map.insert(_type, *_entry) },
                    1   =>  { _type = String::from("IMAGE_DIRECTORY_ENTRY_IMPORT")          ; _data_map.insert(_type, *_entry) },
                    2   =>  { _type = String::from("IMAGE_DIRECTORY_ENTRY_RESOURCE")        ; _data_map.insert(_type, *_entry) },
                    3   =>  { _type = String::from("IMAGE_DIRECTORY_ENTRY_EXCEPTION")       ; _data_map.insert(_type, *_entry) },
                    4   =>  { _type = String::from("IMAGE_DIRECTORY_ENTRY_SECURITY")        ; _data_map.insert(_type, *_entry) },
                    5   =>  { _type = String::from("IMAGE_DIRECTORY_ENTRY_BASERELOC")       ; _data_map.insert(_type, *_entry) },
                    6   =>  { _type = String::from("IMAGE_DIRECTORY_ENTRY_DEBUG")           ; _data_map.insert(_type, *_entry) },
                    7   =>  { _type = String::from("IMAGE_DIRECTORY_ENTRY_ARCHITECTURE")    ; _data_map.insert(_type, *_entry) },
                    8   =>  { _type = String::from("IMAGE_DIRECTORY_ENTRY_GLOBALPTR")       ; _data_map.insert(_type, *_entry) },
                    9   =>  { _type = String::from("IMAGE_DIRECTORY_ENTRY_TLS")             ; _data_map.insert(_type, *_entry) },
                   10   =>  { _type = String::from("IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG")     ; _data_map.insert(_type, *_entry) },
                   11   =>  { _type = String::from("IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT")    ; _data_map.insert(_type, *_entry) },
                   12   =>  { _type = String::from("IMAGE_DIRECTORY_ENTRY_IAT")             ; _data_map.insert(_type, *_entry) },
                   13   =>  { _type = String::from("IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT")    ; _data_map.insert(_type, *_entry) },
                   14   =>  { _type = String::from("IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR")  ; _data_map.insert(_type, *_entry) },
                   _    => continue
                };
            }
        }
        _data_map
    }  
}
#[cfg(test)]
mod tests_pe_parser {

}