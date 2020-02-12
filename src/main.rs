#[allow(dead_code)]
#[allow(unused_imports)]

/// Imports: Rust STD Lib
/// Imports: 3rd Party Crates
/// Imports: My Modules & Utils
mod utils;
use utils::args::argument_parser::{ ArgumentsParser };
use utils::filesystem::file_handler::{ FileHandler };


fn main() -> Result<(), Box<dyn std::error::Error>>
{
    //let _args = ArgumentsParser::new();
    //println!("{:#?}", _args);
    let _fh = FileHandler::open("Cargo.toml", "r");
    if _fh.successful {
        println!("{:#?}", _fh);
        println!("{:#?} Bytes", _fh.meta.len());
    }
    Ok(())
}