///
/// # File Handler Utility & Helper
/// This module allows you to perform common tasks on the filesystem without
/// having to spread filesystem code logic across the project.
/// Simply import this module and use it to perform the basic functions.
/// 

/// 
use std::io::prelude::*;
use std::io::{ self, BufReader };
use std::fmt::Write;
use std::path::{ Path };
use std::fs::{ self, File, Metadata };

use scroll::{Pread, LE};

use crate::utils::errors::custom_errors::exit_process;
use crate::structs::pe_structs::*;



/// 
/// # File Handler
/// A custom struct that keeps track of the file_handle, metadata, and object.
/// ```
///     let _file = FileHandler::open("foo.txt", "r");
/// ```
/// 
#[derive(Debug)]
pub struct FileHandler {
    pub handle: File,
    pub meta:   Metadata,
    pub successful: bool
}

impl FileHandler {
    pub fn open(p: &str, mode: &str) -> Self
    {
        let mut _read       = false;
        let mut _write      = false;
        let mut _create_new = false;

        match mode {
            "r"   => { _read = true; },
            "w"   => { _write = true; },
            "rw"  => { _read = true; _write = true; },
            "crw" => { _create_new = true; },
            _     => exit_process("Desired File Mode Not Supported")
        };

        let _filepath = Path::new(p);

        if !_filepath.exists() {
            exit_process("Provided Path Does Not Exists.  Require an existing File Path");
        }

        if _filepath.is_dir() {
            exit_process("Provided Path is a Directory.  Require a target File to inspect");
        }

        let _file = fs::OpenOptions::new()
                                    .read(_read)
                                    .write(_write)
                                    .create(_create_new)
                                    .open(_filepath)
                                    .unwrap();
        
        let _meta = _file.metadata().unwrap();

        if _meta.len() == 0 {
            exit_process("Provided File is Zero Size '0', Refusing to continue.  Ensure Target File has content");
        }

        FileHandler {
            handle: _file,
            meta: _meta,
            successful: true
        }
    }
    /*pub fn read_stream(&self, marker: &mut [u8]) -> Result<(), Box<dyn std::error::Error>>
    {
        let mut _bufr = BufReader::new(&self.handle);
        _bufr.read_exact(marker)?;

        let mut _hex = String::with_capacity(255);
        let mut _cnt = 0u8;
        for _x in marker.iter() {
            _cnt += 1;
            write!(&mut _hex, "0x{:<3x}", _x).unwrap();
            if _cnt == 16u8 {
                println!("{}", _hex);
                _hex.clear();
                _cnt = 0
            }
        }
        Ok(())
    }*/
    pub fn read_stream(&self, _bytes: &mut [u8]) -> Result<(), Box<dyn std::error::Error>>
    {
        let mut _bufr = BufReader::new(&self.handle);
                _bufr.read_exact(_bytes)?;

        println!("Buffer State: \n{:#?}", _bufr);

        let _doshdr: IMAGE_DOS_HEADER = _bytes.pread_with(0usize, LE).unwrap();

        println!("DOS HEADER:\n{:#?}", _doshdr);
        println!("\n\n");

        println!("PE Magic Header      : 0x{:x}", _doshdr.e_magic);
        println!("PE Pointer Offset    : 0x{:x}", _doshdr.e_lfanew);
        println!("PE Relocation Offset : 0x{:x}", _doshdr.e_lfarlc);

        let _pe_offset = *&_doshdr.e_lfanew as usize;
        let _pehdr: IMAGE_FILE_HEADER = _bytes.pread_with(_pe_offset, LE).unwrap();

        println!("\n\nPE IMAGE FILE HEADER: \n{:#?}", _pehdr);
        Ok(())
    }
}