///
/// # File Handler Utility & Helper
/// This module allows you to perform common tasks on the filesystem without
/// having to spread filesystem code logic across the project.
/// Simply import this module and use it to perform the basic functions.
/// 
use std::io::prelude::*;
use std::io::{ self, BufReader };
use std::path::{ Path };
use std::fs::{ self, File, Metadata };

use crate::utils::errors::custom_errors::exit_process;

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
}