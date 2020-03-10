use std::io::prelude::*;
use std::io::{ self, BufRead, BufReader, BufWriter, Read, Write };
use std::fs::{ self, File, Metadata };
use std::path::Path;


// 3rd Party
use scroll::{ Pread, LE };


// My Modules
#[path = "../errors/custom_errors.rs"] mod custom_errors;
use custom_errors::exit_process;


#[derive(Debug)]
pub struct FileHandler {
    pub success:    bool,
    pub handle:     File,
    pub name:       String, 
    pub meta:       Metadata,
    pub size:       u64
}
impl FileHandler {
     ///
     ///
     ///
     ///
     pub fn open(fp: &str, mode: &str) -> Self
     {
        let mut _path_string: String = String::from(fp);

        if fp.contains(r"\r\n") {
            _path_string = _path_string.replace("\r\n", "");
        }

        if fp.contains(r"\r") {
            _path_string = _path_string.replace(r"\r", "");
        }

        if fp.contains(r"\n") {
            _path_string = _path_string.replace(r"\n", "");
        }

        let _filepath = Path::new(&_path_string);

        match mode {
            "r"|"rw"|"cra"|"crt" =>  {
                // Sanity Checks
                if _filepath.is_dir() {
                    exit_process("Desired Target is a Folder/Directory. Require a file");
                }
                if !_filepath.exists() {
                    exit_process("Desired Target Does Not Exists.  Require an existent file");
                }
            },
            "crw" =>  { println!("New File To Be Created: {}", fp); },
            _     =>  exit_process("Desired File Mode Not Suppported, Process Exiting...")
        }

        let mut _read       = false;
        let mut _write      = false;
        let mut _create     = false;
        let mut _append     = false;
        let mut _truncate   = false;

        match mode {
            "r"     =>  { _read = true; },
            "rw"    =>  { _read = true; _write = true; },       // Read-Write
            "crw"   =>  { _write = true; _create = true; },     // Create New
            "cra"   =>  { _write = true; _append = true; },     // Create Append
            "crt"   =>  { _write = true; _truncate = true; },   // Create Truncate
            _       =>  exit_process("Desired File Mode Not Suppported, Process Exiting...")
        }

        let _file = fs::OpenOptions::new()
                                    .read(_read)
                                    .write(_write)
                                    .create(_create)
                                    .append(_append)
                                    .write(_write)
                                    .open(_filepath)
                                    .unwrap();

        let _name = _filepath.file_name().unwrap();
        let _name = _name.to_str().unwrap();
        let _name = String::from(_name);          
        let _meta = _filepath.metadata().unwrap();
        let _size = _meta.len();

        FileHandler {
            handle: _file,
            name:   _name,
            meta:   _meta,
            size:   _size,
            success: true
        }
     }
     ///
     /// 
     /// 
     /// 
     pub fn write(&mut self, _content: &String) -> Result<(), Box<dyn std::error::Error>>
     {
        let stdout = io::stdout();
        self.handle.write(_content.as_bytes())?;
        stdout.flush();
        Ok(())
     }
     ///
     ///
     ///
     ///
     pub fn delete(fp: &str) -> Result<(), Box<dyn std::error::Error>>
     {
        let _filepath = Path::new(fp);

        if _filepath.exists() {
            fs::remove_file(_filepath)?;
        } else {
            exit_process("Desired File For Deletion Does Not Exist, Process Exiting");
        }
        Ok(())
     }
     ///
     ///
     ///
     ///
     pub fn read_as_vecbytes(&self, n_bytes: u64) -> Result<Vec<u8>, Box<dyn std::error::Error>>
     {
        //
        let mut _bufr = BufReader::new(&self.handle);
        let mut _bytes: Vec<u8> = Vec::with_capacity(n_bytes as usize);
        _bufr.read_to_end(&mut _bytes)?;
        Ok(_bytes)
     }
     ///
     /// 
     /// 
     /// 
     pub fn read_as_bytesarray(&self, n_bytes: &mut [u8]) -> Result<(), Box<dyn std::error::Error>>
     {
        let mut _bufr = BufReader::new(&self.handle);
        _bufr.read_exact(n_bytes)?;
        Ok(())
     }
 }