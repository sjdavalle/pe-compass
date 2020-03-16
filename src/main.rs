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

/// Imports: Rust STD Lib
use std::path::Path;

/// Imports: 3rd Party Crates
use serde_json::*;
use walkdir::{ WalkDir, DirEntry };

/// Imports: My Modules & Utils
mod modules;
use modules::pe_parser::*;

mod utils;
use utils::filesystem::file_handler::FileHandler;
use utils::args::argument_parser::ArgumentsParser;

fn main() -> Result<()>
{
    let _args = ArgumentsParser::new();
    
    if _args.inputs.is_present("file") {
        let _sample = _args.inputs.value_of("file").unwrap();
        let _pe = PeParser::new(_sample);
        let _file = _pe.inspect_file();
        
        if _args.inputs.is_present("output") {
            let _content = serde_json::to_string(&_file)?;
            let _ov = _args.inputs.value_of("output").unwrap();
            let mut _outfile = FileHandler::open(_ov, "crw");
            _outfile.write(&_content).expect("Could Not Write Content to Desired Output File");
        } else {
            let _content = serde_json::to_string_pretty(&_file)?; 
            println!("{}", _content);
        }
    }

    if _args.inputs.is_present("recurse") {
        let _subcommand = _args.inputs.subcommand_matches("recurse").unwrap();
        if _subcommand.is_present("directory") {
            let _arg = _subcommand.value_of("directory").unwrap();
            let _path = Path::new(&_arg);

            if _path.is_dir() && _path.exists() {
                let mut _filter: &str = "";
                let mut _wants_filter: bool = false;

                if _subcommand.is_present("filter") {
                    _wants_filter = true;
                    _filter = _subcommand.value_of("filter").unwrap();
                }
                for _entry in WalkDir::new(_arg).into_iter().filter_map(|e| e.ok()) {
                    if _wants_filter {
                        let _e = _entry.path().to_str().unwrap();
                        if _e.contains(_filter) {
                            println!("{}",_e);
                        }
                    } else {
                        println!("{}", _entry.path().display());
                    }
                }
            }
        }
    }
    Ok(())
}