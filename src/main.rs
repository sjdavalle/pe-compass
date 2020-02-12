mod utils;
use utils::args::argument_parser::{ ArgumentsParser };

fn main() -> Result<(), Box<dyn std::error::Error>>
{
    let _args = ArgumentsParser::new();
    println!("{:#?}", _args);
    Ok(())
}