#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(unused_imports)]
#![allow(dead_code)]

#[macro_use]
extern crate scroll_derive;
extern crate scroll;
extern crate serde_json;
extern crate serde;
extern crate walkdir;
extern crate clap;
extern crate sha2;
extern crate md5;
extern crate fs2;


mod utils;
use utils::args::argument_parser::ArgumentsParser;

fn main() -> Result<(), Box<dyn std::error::Error>>
{
    let _args = ArgumentsParser::new();
        _args.parse();
    Ok(())
}