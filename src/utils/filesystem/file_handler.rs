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
        let _filepath = Path::new(fp);

        /*
        {
            Add Checks Here: ToDo
        }
        */

        let mut _read       = false;
        let mut _write      = false;
        let mut _create     = false;
        let mut _append     = false;
        let mut _truncate   = false;

        match mode {
            "r"     =>  { _read = true; },
            "rw"    =>  { _read = true; _write = true; },
            "crw"   =>  { _write = true; _create = true; },
            "cra"   =>  { _write = true; _append = true; },
            "crt"   =>  { _write = true; _truncate = true; }, 
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
                                    
        let _meta = _filepath.metadata().unwrap();
        let _size = _meta.len();

        FileHandler {
            handle: _file,
            meta:   _meta,
            size:   _size,
            success: true
        }
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
     pub fn read_as_bytes(&self, n_bytes: u64) -> Result<Vec<u8>, Box<dyn std::error::Error>>
     {
        let mut _bytes: Vec<u8> = Vec::with_capacity(n_bytes as usize);
        let mut _bufr = BufReader::new(&self.handle);

        _bufr.read_to_end(&mut _bytes)?;
        
        Ok(_bytes)
     }
 }