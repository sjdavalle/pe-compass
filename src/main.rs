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
    let _dosheader = _pe.get_dosheader();
    let _peheader  = _pe.get_peheader(_dosheader.e_lfanew);
    println!("\n\nDOS HEADER: \n\n{:#?}", _dosheader);
    println!("\n\nPE  HEADER: \n\n{:#?}", _peheader);
    println!("\n\nOPT HEADER: \n\n{:#?}", _peheader.OptionalHeader);

    Ok(())
}
    /*let _args = ArgumentsParser::new();
    //println!("{:#?}", _args);
    let _fh = FileHandler::open("/home/archir/Documents/my_code/rust/pe-compass/pe-samples/sqlite3x86.dll", "r");
    let mut _cnt: [u8; 925_000] = [0u8; 925_000];
    _fh.read_stream(&mut _cnt)?;*/