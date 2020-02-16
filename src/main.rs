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
mod utils;
//use utils::args::argument_parser::{ ArgumentsParser };
use utils::filesystem::file_handler::{ FileHandler };
mod structs;
use structs::pe_structs::*;

fn main() -> Result<(), Box<dyn std::error::Error>>
{
    //let _args = ArgumentsParser::new();
    //println!("{:#?}", _args);
    let _fh = FileHandler::open("/home/archir/Documents/my_code/rust/pe-compass/pe-samples/sqlite3x86.dll", "r");
    let mut _cnt: [u8; 64] = [0u8; 64];
    _fh.read_stream(&mut _cnt)?;
    Ok(())
}