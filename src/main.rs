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
    let _fh = FileHandler::open("/home/archir/Documents/my_code/rust/pe-compass/pe-samples/sqlite3x86.dll", "r");
    if _fh.successful {
        println!("{:#?}", _fh);
        println!("{:#?} Bytes", _fh.meta.len());
        let mut _magic_header = [0u8; 128];
        _fh.read_stream(&mut _magic_header)?;
    }
    Ok(())
}