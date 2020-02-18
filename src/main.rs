#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(unused_imports)]
#![allow(dead_code)]

#[macro_use]
extern crate scroll_derive;
extern crate scroll;

/// Imports: Rust STD Lib

/// Imports: 3rd Party Crates

/// Imports: My Modules & Utils

mod modules;
use modules::pe_parser::PeParser;

fn main() -> Result<(), Box<dyn std::error::Error>>
{
    let _sample = "pe-samples/sqlite3x64.dll";
    //let _sample = "pe-samples/sqlite3x86.dll";
    //let _sample = "pe-samples/7z1900.exe";
    let _pe = PeParser::new(_sample);
    
    let _dosheader      = _pe.get_dosheader(); 
    /*
    let _nt_headers     = _pe.get_image_nt_headers32(_dosheader.e_lfanew);
    let _pe_data_dirs   = _pe.get_data_directories(&_nt_headers.OptionalHeader.DataDirectory);

    println!("\n\nDOS   HEADER: \n\n{:#?}", _dosheader);
    println!("\n\nNT    HEADER: \n\n{:#?}", _nt_headers);
    println!("\n\nPE DATA DIRS: \n\n{:#?}", _pe_data_dirs);
    */
    let _inspected = _pe.inspect_nt_headers(_dosheader.e_lfanew);

    println!("\n\nINSPECTED NT HEADERS:\n\n{:#?}", _inspected);

    Ok(())
}