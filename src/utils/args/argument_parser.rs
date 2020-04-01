use clap::{ App, Arg, ArgMatches, SubCommand };
use walkdir::{ WalkDir, DirEntry };
use serde_json::*;


#[path = "../../modules/pe_parser.rs"]
mod pe_parser;
use pe_parser::PeParser;

#[path = "../filesystem/file_handler.rs"]
mod file_handler;
use file_handler::FileHandler;


/// # ArgumentsParser - Global Variables
/// Convenient metadata used throughout the arguments parser object
static _VERSION: &str = "v.0.0.10"; 
static _AUTHOR: &str = "carlos diaz | @dfirence\n\n";
static _ABOUT: &str = "A Study of the Portable Executable Format";

/// # ArgumentsParser
/// A wrapped object for the program's cli arguments passed by the user.
/// The parsing of the arguments is applied here to keep main clean.
/// 
/// #Example
/// 
/// ```
/// let _args = ArgumentParser::new();
/// ```
#[derive(Debug)]
pub struct ArgumentsParser<'a> {
    pub inputs: ArgMatches<'a>
}
impl ArgumentsParser<'_> {
    /// # ArgumentsParser - Constructor
    /// We instantiate a new instance of the arguments parser with the `new` method.
    /// 
    /// # Example
    /// ```
    /// let _args = ArgumentsParser::new();
    /// 
    /// println!("{:#?}", _args.inputs);    // Argument Values Passed By User
    /// ```
    pub fn new() -> Self
    {
        ArgumentsParser {
            inputs: App::new("\n\npe-compass")
                        .author(_AUTHOR)
                        .version(_VERSION)
                        .about(_ABOUT)
                        .subcommand(
                            SubCommand::with_name("inspect")
                                       .author(_AUTHOR)
                                       .version(_VERSION)
                                       .about("Inspect a PE File's Imports Structure")
                                       .arg(
                                            Arg::with_name("file")
                                                .short("f")
                                                .value_name("PE FILE")
                                                .help("File System Path of PEFILE to inspect")
                                                .takes_value(true)
                                        )
                                        .arg(
                                            Arg::with_name("output")
                                                .short("o")
                                                .value_name("OUTPUT FILE")
                                                .help("Destination File to Write Output to")
                                                .takes_value(true)
                                        )
                        )
                        .subcommand(
                            SubCommand::with_name("recurse")
                                       .author(_AUTHOR)
                                       .version(_VERSION)
                                       .about("Works Recursively with Folders")
                                       .arg(
                                           Arg::with_name("directory")
                                               .short("d")
                                               .value_name("Directory PATH")
                                               .help("Target Directory To Recurse Search")
                                               .takes_value(true)
                                       )
                                       .arg(
                                           Arg::with_name("extension")
                                               .short("x")
                                               .value_name("File Extension Name")
                                               .help("Applies Ends With Pattern Match - NON-REGEX")
                                               .takes_value(true)
                                       )
                                       .arg(
                                           Arg::with_name("filter")
                                               .short("f")
                                               .value_name("Pattern NON_REGEX")
                                               .help("A Non-RegEx pattern to filter by")
                                               .takes_value(true)
                                       )
                        )
                        .get_matches()
        }
    }
    /// # ArgumentsParser Parse
    /// This method starts parsing the passed cli arguments and initiates executions
    /// for the relevant arguments provided by the user.
    ///
    /// # Example
    /// ```
    /// let _args = ArgumentsPaser::new();
    /// 
    /// let results = _args.parse();    // Returns Results From Args
    /// ```
    pub fn parse(&self)
    {
        if self.inputs.is_present("inspect") {
            self.inspect();
        } else if self.inputs.is_present("recurse") {
            self.recurse();
        }
    }
    /// # ArgumentsParser Inspect
    /// Used to parse a PE File and return the internal contents of the PE File.
    /// The contents can be redirected to an output file based on the `o` flag
    /// provided by the user.
    /// 
    /// # Example
    /// ```
    /// let _args = ArgumentsParser::new();
    /// 
    /// _args.parse();  // Parse calls inspect internally as `_args.inspect()`;
    /// ```
    fn inspect(&self)
    {
        let _subcommand = self.inputs.subcommand_matches("inspect").unwrap();

        let _file_sample = match _subcommand.is_present("file") {
            true => _subcommand.value_of("file").unwrap(),
            false => std::process::exit(0x0100)
        };

        let _outfile = match _subcommand.is_present("output") {
            true => _subcommand.value_of("output").unwrap(),
            false => "None"
        };

        let _pe = PeParser::new(_file_sample);
        let _pe = _pe.inspect_file();

        match _outfile {
            "None"  => {
                let _content = serde_json::to_string_pretty(&_pe).expect("Unable To Parse PE Object");
                println!("{}", _content);
            },
            _output => {
                let _content = serde_json::to_string(&_pe).expect("Unable To Parse PE Object");
                let mut _fhandle = FileHandler::open(_outfile, "crw");
                        _fhandle.write(&_content).expect("Unable to Write Desired File Output");
            }
        }
    }
    /// # ArgumentsParser Recurse
    /// This method allows you to parse and execute the cli user params
    /// for the recurse mode. It walks a target folder/directory to get
    /// a listing of the files residing under it.
    fn recurse(&self)
    {
        let _subcommand = self.inputs.subcommand_matches("recurse").unwrap();
        
        let _directory  = match _subcommand.is_present("directory") {
            true => _subcommand.value_of("directory").unwrap(),
            false => std::process::exit(0x0100)
        };

        let _extension = match _subcommand.is_present("extension") {
            true => _subcommand.value_of("extension").unwrap(),
            false => "None"
        };

        let _filter = match _subcommand.is_present("filter") {
            true => _subcommand.value_of("filter").unwrap(),
            false => "None"
        };

        let _path = std::path::Path::new(&_directory);

        if _path.exists() && _path.is_dir() {
            for _entry in WalkDir::new(_path).max_depth(20).into_iter().filter_map(|e| e.ok()) {
                let _e = _entry.path().to_str().unwrap();
                let _e = format!("{}{}{}", "'", _e, "'");
                if _filter == "None" && _extension == "None" {
                    println!("{}", _e);
                } else if _filter != "None" && _extension == "None" {
                    if _e.contains(_filter) { println!("{}", _e); }
                } else if _filter == "None" && _extension != "None" {
                    if _e.ends_with(_extension) { println!("{}", _e); }
                } else if _filter != "None" && _extension != "None" {
                    if _e.contains(_filter) { if _e.ends_with(_extension) { println!("{}", _e); }}
                } else {
                    println!("{}", _e);
                }
            }
        }
    }
}