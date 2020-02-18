#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(unused_imports)]
#![allow(dead_code)]

#[macro_use]
extern crate scroll_derive;
/// Imports: Rust STD Lib

/// Imports: 3rd Party Crates
extern crate scroll;
/// Imports: My Modules & Utils

mod modules;
use modules::pe_parser::*;

fn main() -> Result<(), Box<dyn std::error::Error>>
{
    let _sample = "/home/archir/Documents/my_code/rust/pe-compass/pe-samples/sqlite3x86.dll";

    let _pe = PEParser::new(_sample);
    let _dosheader      = _pe.get_dosheader();
    let _fileheader     = _pe.get_peheader(_dosheader.e_lfanew); 
    let _nt_headers     = _pe.get_image_nt_headers32(_dosheader.e_lfanew);
    let _pe_data_dirs   = _pe.get_data_directories(&_nt_headers.OptionalHeader.DataDirectory);

    println!("\n\nDOS   HEADER: \n\n{:#?}", _dosheader);
    println!("\n\nFILE  HEADER: \n\n{:#?}", _fileheader);
    println!("\n\nOPT   HEADER: \n\n{:#?}", _nt_headers.OptionalHeader);
    println!("\n\nPE DATA DIRS: \n\n{:#?}", _pe_data_dirs);

    Ok(())
}