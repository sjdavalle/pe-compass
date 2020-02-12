extern crate clap;

use clap::{ App, Arg, ArgMatches };


#[derive(Debug)]
pub struct ArgumentsParser<'a> {
    inputs: ArgMatches<'a>
}

impl ArgumentsParser<'_> {
    pub fn new() -> Self
    {
        ArgumentsParser {
            inputs: App::new("\n\npe-compass")
                        .author("carlos diaz | @dfirence")
                        .version(" - v.0.0.1")
                        .about("A Study of the Portable Executable Format")
                        .arg(
                            Arg::with_name("file")
                                .short("f")
                                .value_name(" PE FILE ")
                                .help("File System Path of PEFILE to inspect")
                                .takes_value(true)
                        )
                        .get_matches()
        }
    }
}