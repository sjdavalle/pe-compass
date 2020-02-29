use std::collections::{ HashMap, BTreeMap };
use std::ops::Range;

// 3rd Parties
use scroll::{ Pread, LE };

#[path = "../utils/filesystem/file_handler.rs"] mod file_handler;
use file_handler::FileHandler;

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
        
        if _fsize < 64 {
            std::process::exit(0x0100); // If file size less than 64 bytes exit
        }
        // ToDo: Add Validator Code Here for Sigs before reading File
        
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
        let _dos_stub = self.get_dos_stub_string();
        let _doshdr: IMAGE_DOS_HEADER = self.get_dosheader();
    
        let mut _petype: u16;
        let mut _nt_headers: IMAGE_NT_HEADERS;
        
        let mut _image_data_dir: [u64; 16] = [0u64; 16];
        let mut _data_map: BTreeMap<String, IMAGE_DATA_DIRECTORY>;
        let mut _section_table_headers: HashMap<String, IMAGE_SECTION_HEADER>;
        let mut _dll_imports: Vec<DLL_PROFILE>;
        
        //  1st Internal code block
        //  We use this block to drop non-essential data structures and save memory
        //  through the file inspection phase because we have to determine if a file
        //  that needs to be parsed is either a 32 or 64 bit PE.
        {
            let _nt_test: INSPECT_NT_HEADERS = self.inspect_nt_headers(_doshdr.e_lfanew);   // Drop these headers after block
            _petype = _nt_test.OptionalHeader.Magic;

            _nt_headers = match _petype {
                267 => IMAGE_NT_HEADERS::x86(self.get_image_nt_headers32(_doshdr.e_lfanew)),
                523 => IMAGE_NT_HEADERS::x64(self.get_image_nt_headers64(_doshdr.e_lfanew)),
                _   => std::process::exit(0x0100)
            };
            
            _image_data_dir = match &_nt_headers {
                IMAGE_NT_HEADERS::x86(value) => value.OptionalHeader.DataDirectory,
                IMAGE_NT_HEADERS::x64(value) => value.OptionalHeader.DataDirectory
            };

            _data_map = self.get_data_directories(&_image_data_dir);
            _section_table_headers = self.get_section_headers(&_doshdr.e_lfanew, &_nt_test);
        }
        // 2nd Internal code block is used again to keep essential data structures.
        // However, here we want to focus on parsing tedious sections of the file that come from
        // either EAT or IAT tables.
        {
            // Acquire IAT
            let _eimp = _data_map.get("IMAGE_DIRECTORY_ENTRY_IMPORT").unwrap();
 
            let mut _rva_imports: PE_RVA_TRACKER = self.get_rva_from_directory_entry("imports", _eimp, &_section_table_headers);
            _dll_imports = self.get_dll_imports(&_petype, &mut _rva_imports);
        }
        //  Finally build the custom object PE_FILE with the essential data structures
        //  to be used by the program.
        //  Note:   This is the object that represents the goal of the PeParser module.
        //          Remember, this module is only for serializing the file to human structs.
        PE_FILE {
            petype:                 _petype,
            ImageDosHeader:         _doshdr,
            ImageDosStub:           _dos_stub,
            ImageNtHeaders:         _nt_headers,
            ImageDataDirectory:     _data_map,
            ImageSectionHeaders:    _section_table_headers,
            ImageDLLImports:        _dll_imports,
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
    ///
    ///
    ///
    ///
    fn get_dos_stub_string(&self) -> String
    {
        let _offset = 0x4D as usize;
    
        let _dos_stub: PE_DOS_STUB = self.content.pread_with(_offset, LE).unwrap();
        
        let mut _dos_string = String::with_capacity(40usize);
        _dos_string.push_str(std::str::from_utf8(&_dos_stub.upper[..]).unwrap());
        _dos_string.push_str(std::str::from_utf8(&_dos_stub.lower[..]).unwrap());
                
        _dos_string
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
    ///
    /// let _nthdr: IMAGE_NT_HEADERS32 = _pe.get_image_nt_headers32(_dh.e_lfanew);
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
    ///
    /// let _nthdr: IMAGE_NT_HEADERS64 = _pe.get_image_nt_headers64(_dh.e_lfanew);
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
    fn get_data_directories(&self, data_dir: &[u64; 16usize]) -> BTreeMap<String, IMAGE_DATA_DIRECTORY>
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
        let mut _data_map: BTreeMap<String, IMAGE_DATA_DIRECTORY> = BTreeMap::new();
        let mut _type: String;

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
                   _    =>  continue // reserved, undocumented
                };
            }
        }
        _data_map
    }
    /// # Pe Parser GetSectionHeaders Method
    /// This method finds the PE Section Structs and organizes them into a HashMap for ease
    /// of use later.  We want to query a section in other areas by key index such as:
    ///
    /// ```
    /// let _sections: HashMap<String, IMAGE_SECTION_HEADER>;
    ///
    /// _sections = _pe.get_section_headers(e_lfanew, nt_headers);
    ///
    /// let _code_section: IMAGE_SECTION_HEADER;
    ///
    /// _code_section = _sections.get_key_value(".code");
    /// ```
    fn get_section_headers(
        &self,
        e_lfanew: &i32,
        _nt_headers: &INSPECT_NT_HEADERS
    ) -> HashMap<String, IMAGE_SECTION_HEADER>
    {
        const SIZE_OF_SECTION_HEADER: usize  = 40; // 40 Bytes Long

        // Steps:
            //  . Get Number of Sections in Scope for the PE File
        let _numof_pe_sections: usize = _nt_headers.FileHeader.NumberOfSections as usize;
        
            //  . Calculate Total Bytes to Read for All Sections
        let mut _total_bytes_sections = SIZE_OF_SECTION_HEADER * _numof_pe_sections;

            //  . Get Size of Optional Header from FileHeader
        let _sizeof_pe_opthdr: usize = _nt_headers.FileHeader.SizeOfOptionalHeader as usize;

            //  . Calculate The Starting Offset of the OptionalHeader from NtHeaders
        let _offset_starts_opthdr = (e_lfanew + 24) as usize;
        
            //  . Calculate The Starting Offset of the Section Headers
        let mut _offset_starts_sechdr = _offset_starts_opthdr + _sizeof_pe_opthdr;
        
        let mut _section_table_headers: HashMap<String, IMAGE_SECTION_HEADER> = HashMap::new();

        let mut _section_header: IMAGE_SECTION_HEADER;
        let mut _section_name: Vec<u8>;
        
        while _total_bytes_sections != 0 {

            _section_header = self.content.pread_with(_offset_starts_sechdr, LE).unwrap();
            
            _section_name = _section_header.Name.iter()                 // Remove Null Bytes from Section Name
                                                .filter(|x| *x > &0)
                                                .map(|x| *x as u8)
                                                .collect();

                // Build Custom HashMap with section names and section header
            _section_table_headers.insert(String::from_utf8(_section_name).unwrap(), _section_header);

            _total_bytes_sections -= SIZE_OF_SECTION_HEADER;
            _offset_starts_sechdr += SIZE_OF_SECTION_HEADER;            // Increment Offset By 40 Bytes each iteration

        }
        _section_table_headers
    }
    /// # Parse the Import Address Table and Functions
    /// Read the Function Signature Cafefully, we are passing things by reference.
    /// 
    /// The following notes show which struct members of the section header are relevant
    ///
    /// ```
    /// Virtual Size     = VirtualSize          (VS)
    /// Virtual Address  = VritualAddress       (VA)
    /// Raw Size         = SizeOfRawData        (RS)
    /// Raw Address      = PointerToRawdData    (RA)
    /// Reloc Address    = PointerToRelocations (ReLocA)
    /// 
    /// Example:
    ///     (TA)  = 745472
    ///     (VA)x = 745472
    ///     (VA)y = 749568
    /// 
    ///     Section := if { (TA) >= (VA)x && (TA) <= (VA)y };
    /// ```
    ///
    /// The example above reads as, a section of interest is equal to to the true condition.
    /// The true condition is, for a Target Address (TA), it must be less than or equal to the
    /// Virtual Address (VA) of the section.
    /// 
    /// The formula to find the file offset (location within file on disk) is:
    /// ```
    /// File Offset := TA - VA + RA;
    /// ```
    fn get_rva_from_directory_entry(
        &self,
        _entry_name: &str,
        _dir_entry: &IMAGE_DATA_DIRECTORY,
        _section_table: &HashMap<String, IMAGE_SECTION_HEADER>
    ) -> PE_RVA_TRACKER
    {
        let mut _rva_tracker = PE_RVA_TRACKER::new();
        {
            let mut _rvas_x: Vec<&DWORD> = vec![];
            let mut _rvas_y: Vec<&DWORD> = vec![];

            for _v in _section_table.values() {
                _rvas_x.push(&_v.VirtualAddress);
            }
            _rvas_x.sort();             // Sort All VAs from smallest to largest
            
            _rvas_y = _rvas_x.clone();  // Build Second List of VAs
            _rvas_y.push(&0);           // Push Zero Padding to the end 
            _rvas_y.remove(0);          // Remove first element; aligned for zip iter

            let _list_virtual_addresses = _rvas_x.iter().zip(_rvas_y);

            for (_x, _y) in _list_virtual_addresses {
                let _range = Range { start: _x, end: &_y };
                let _ta = &&&_dir_entry.VirtualAddress;

                if _range.contains(_ta) {    
                    if _ta >= &_x && _ta <= &&_y {
                        
                        for (_key, _value) in _section_table.iter() {
                            if &&_value.VirtualAddress == _x {
                                _rva_tracker.update(_entry_name,                            // Dir Entry Name
                                                    ***_ta,                                 // Dir Entry VA; Deref
                                                    **_x,                                   // Section VA; Deref
                                                    _section_table[_key].PointerToRawData,  // Section RA
                                                    _key.to_string());                      // Name of PE Section
                                                    
                                _rva_tracker.get_file_offset();
                            }
                        }
                    }
                }
            }
        }
        _rva_tracker
    }
    ///
    /// 
    /// 
    fn get_dll_imports(&self, _pe_type: &u16, _rva: &mut PE_RVA_TRACKER) -> Vec<DLL_PROFILE>
    {
        const SIZE_OF_IMAGE_IMPORT_DESCRIPTOR: usize = 20 as usize;
        const RANGE_OF_DLL_NAME: usize = 4 as usize;

        let _null_dll = IMAGE_IMPORT_DESCRIPTOR::load_null_descriptor();
        
        let mut _dll: IMAGE_IMPORT_DESCRIPTOR;
        let mut _dll_list: Vec<IMAGE_IMPORT_DESCRIPTOR> = vec![];
        
        let mut _results: Vec<DLL_PROFILE> = vec![];
        let mut _offset: usize = _rva.file_offset as usize;

        // Step 1
        // We begin by getting the DLLs imported by the PE file based on
        // the PE DIRECTORY ENTRY RVA matched from the relevant PE Section
        //
        // 1st Loop Code Block is used to create a list of the DLLs involved
        // Watch the offset change consistently to only parse this area of the PE File
        // Move on to Step 2 after this list is acquired.
        loop {                                                      // Find the Image Descriptors - i.e, DLLs
            _dll = self.content.pread_with(_offset, LE).unwrap();   // Iterate through the file by offset
            _dll_list.push(_dll);                                   // Add each descriptor found to the list

            _offset += SIZE_OF_IMAGE_IMPORT_DESCRIPTOR;             // Advance the file offset by 20 bytes

            if _dll == _null_dll {                                  // Check If Reached End of DLL list
                _dll_list.pop();                                    // remove the null descriptor
                break;
            }
        }
        // Step 2
        // Now that we have all the DLLs involved, let's parse the imports
        // for each of them.
        for _dll in _dll_list {
            // Start By Getting The Name of the DLL involved
            // Watch the _offset variable change consistently.
            //
            // 2nd LOOP Code Block is to land at the DLL Name File Offset
            // From there, walk the bytes to correctly parse the name of the dll.
            _offset = _rva.new_offset_from(_dll.Name);
            let mut _dll_name: String = String::new();
            let mut _s: String = String::new();

            loop {                                         
                let _bytes: u32 = self.content.pread_with(_offset, LE).unwrap();    // Read the DLL Name by 4 byte increment
                let _dbytes = _bytes.to_le_bytes();                                 // Convert Decimal to LE Bytes Array
                _s.push_str(std::str::from_utf8(&_dbytes[..]).unwrap());            // Convert Bytes to String
                if _s.contains(".dll") {                                            // Check if string contains .dll marker for end
                    let _v: Vec<&str> = _s.split(".dll").collect();
                    _dll_name.push_str(_v[0]);
                    _dll_name.push_str(".dll");
                    break;
                }
                _offset += RANGE_OF_DLL_NAME;
            }
            // Step 3
            // Now move into acquiring the IMAGE_THUNK_DATAs for the DLL involved.
            // Create a Vector of IMAGE_THUNK_DATA structs (List). 
            // We use this new list of thunk datas to find the names of the functions
            // for the dll involved.
            //
            // 3rd LOOP Code Block is used to populate this list
            // Watch the offset change again, but now to parse the thunk datas
            let mut _thunk_size: usize = 4 as usize;
            let mut _thunk: IMAGE_THUNK_DATA32;
            let mut _thunk_list: Vec<IMAGE_THUNK_DATA32> = vec![];
            
            if _pe_type == &523u16 {
                _thunk_size = 8 as usize;
            }
            _offset = _rva.new_offset_from(_dll.OriginalFirstThunk);
            
            loop {
                _thunk = self.content.pread_with(_offset, LE).unwrap();
                if _thunk.AddressOfData == 0 {
                    break;
                }
                _thunk_list.push(_thunk);
                _offset += _thunk_size;
            }
            // Step 4
            // Now we parse each thunk data by using the struct member called
            // `AddressOfData` which gives us the file offset location of the 
            // name of the function being imported by the dll involved.
            //
            // 4th LOOP Code Block is used to land on the offset of the function name
            // but we walk 2 bytes ahead to correctly discover the end of the string
            // represensting the function name.
            // Watch the offset change again, but now we are parsing the final piece - function names
            let mut _functions_list: Vec<String> = vec![];
            let mut _function: String = String::new(); 
            let mut _part: u16 = 0;
            for _thunk in _thunk_list {
                _offset = _rva.new_offset_from(_thunk.AddressOfData + 2);
                loop {
                    // Get the Function Names involved.
                    // Advance the cursor 2 bytes at a time.
                    // In each iteration inspect the bytes for the null bytes 0x00.
                    // When null byte is found, the string name terminates and we
                    // can move on to the next thunk.
                    _part = self.content.pread_with(_offset, LE).unwrap();
                    let _bytes = _part.to_le_bytes();
                    _function.push_str(std::str::from_utf8(&_bytes[..]).unwrap());
                    
                    if _bytes[ _bytes.len() - 1] == 0 {
                        // If null byte is in the last position
                        // string ends.  Add the function name to the list.
                        _functions_list.push(_function.clone());
                        break;
                    }
                    _offset += 2;   // advance cursor by 2 bytes
                }
                _function.clear();  // Flush string for reuse, avoid re-alloc
            }
            let _dll_profile = DLL_PROFILE {
                                    name:       _dll_name,
                                    imports:    _functions_list.len(),
                                    functions:  _functions_list
                                };
            _results.push(_dll_profile);
        }
        _results    // Return all _dll_imports       
    }
}
/// # Unit Tests
///
///
#[cfg(test)]
mod tests_pe_parser {
    use super::*;

    fn load_byte_patterns()
    {
        let _dos_header = [ 0x4D,0x5A,0x90,0x00,0x03,0x00,0x00,0x00,0x04,0x00,0x00,0x00,0xFF,0xFF,0x00,0x00,
                            0xB8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x80,0x00,0x00,0x00 ];
    }
}