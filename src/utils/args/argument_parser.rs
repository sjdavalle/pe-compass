use clap::{App, Arg, ArgMatches, SubCommand};
use serde_json::*;
use walkdir::{DirEntry, WalkDir};
use rand::Rng;

#[path = "../../modules/pe_parser.rs"]
mod pe_parser;
use pe_parser::PeParser;

#[path = "../filesystem/file_handler.rs"]
mod file_handler;
use file_handler::FileHandler;

/// # ArgumentsParser - Global Variables
/// Convenient metadata used throughout the arguments parser object
static _VERSION: &str = "v.0.0.11";
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
    pub inputs: ArgMatches<'a>,
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
    pub fn new() -> Self {
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
                                .takes_value(true),
                        )
                        .arg(
                            Arg::with_name("output")
                                .short("o")
                                .value_name("OUTPUT FILE")
                                .help("Destination File to Write Output to")
                                .takes_value(true),
                        )
                        .arg(
                            Arg::with_name("csv")
                                .short("c")
                                .value_name("CSV Format")
                                .help("Provide Output as CSV Format")
                                .takes_value(false),
                        ),
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
                                .takes_value(true),
                        )
                        .arg(
                            Arg::with_name("extension")
                                .short("x")
                                .value_name("File Extension Name")
                                .help("Applies Ends With Pattern Match - NON-REGEX")
                                .takes_value(true),
                        )
                        .arg(
                            Arg::with_name("filter")
                                .short("f")
                                .value_name("Pattern NON_REGEX")
                                .help("A Non-RegEx pattern to filter by")
                                .takes_value(true),
                        ),
                )
                .get_matches(),
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
    pub fn parse(&self) -> Result<()>
    {
        if self.inputs.is_present("inspect") {
            self.inspect();
        } else if self.inputs.is_present("recurse") {
            self.recurse();
        }
        Ok(())
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
    fn inspect(&self) {
        let _subcommand = self.inputs.subcommand_matches("inspect").unwrap();

        let _file_sample = match _subcommand.is_present("file") {
            true => _subcommand.value_of("file").unwrap(),
            false => std::process::exit(0x0100),
        };


        let _wants_csv = match _subcommand.is_present("csv") {
            true  => true,
            false => false
        };

        let _outfile = match _subcommand.is_present("output") {
            true => {
                let mut _extension = "__.dummy";
                let mut _path_string = String::from(_subcommand.value_of("output").unwrap());
                let mut rng = rand::thread_rng();
                let _rand = rng.gen::<u32>();
                let _rand = _rand.to_string();
                if _wants_csv {
                    _extension = "__.csv";
                    _path_string = format!("{}__{}{}", _path_string, _rand, _extension); 
                } else {
                    _extension = "__.json";
                    _path_string = format!("{}__{}{}", _path_string, _rand, _extension);  
                }
                _path_string
            },
            false => "None".to_string()
        };
        let _outfile = &_outfile[..];   // Convert it to &str for later use in OUTFILE Match

        let _pe = PeParser::new(_file_sample);
        if _pe.is_pe {
            let _pe = _pe.inspect_file();
            if _pe.pe_type != 0
                && _pe.pe_subsystem != 0
                && _pe.ImageHashSignatures.md5 != "null".to_string()
            {
                let mut _content: String = String::from("");
                if _wants_csv {
                    if _pe.ImageDLLImports.len() > 0usize {
                        for _dll in _pe.ImageDLLImports.iter() {
                            if _dll.functions.len() > 0usize {
                                for _imp in _dll.functions.iter() {
                                    let _s = format!(
                                        "{},{},{},{},{},{},{},{},{},{},{}\n",
                                        _pe.pe_name,
                                        _pe.pe_size,
                                        _pe.pe_subsystem,
                                        _pe.pe_timedate_stamp,
                                        _pe.pe_timedate_human,
                                        "imports",
                                        _dll.name,
                                        _imp,
                                        _pe.ImageHashSignatures.md5,
                                        _pe.ImageHashSignatures.sha2,
                                        _pe.pe_path
                                    );
                                    _content.push_str(_s.as_str());
                                }
                            }
                        }
                    }
                    if _pe.ImageDLLExports.exports > 0usize {
                        for _func in _pe.ImageDLLExports.functions.iter() {
                            let _s = format!(
                                "{},{},{},{},{},{},{},{},{},{},{}\n",
                                _pe.pe_name,
                                _pe.pe_size,
                                _pe.pe_subsystem,
                                _pe.pe_timedate_stamp,
                                _pe.pe_timedate_human,
                                "exports",
                                _pe.pe_name,
                                _func,
                                _pe.ImageHashSignatures.md5,
                                _pe.ImageHashSignatures.sha2,
                                _pe.pe_path
                            );
                            _content.push_str(_s.as_str());
                        }
                    }
                }


                match _outfile {
                    "None" => {
                        if !_wants_csv {
                            _content = serde_json::to_string_pretty(&_pe)
                                .expect("Unable To Parse PE Object");
                        }
                        print!("{}", _content);
                    },
                    _output => {
                        if !_wants_csv {
                            _content =
                                serde_json::to_string(&_pe).expect("Unable To Parse PE Object");
                        }
                        let mut _fhandle = FileHandler::open(_outfile, "crw");
                        _fhandle
                            .write(&_content)
                            .expect("Unable to Write Desired File Output");
                    }
                }
            }
        }
    }
    /// # ArgumentsParser Recurse
    /// This method allows you to parse and execute the cli user params
    /// for the recurse mode. It walks a target folder/directory to get
    /// a listing of the files residing under it.
    fn recurse(&self) {
        let _subcommand = self.inputs.subcommand_matches("recurse").unwrap();

        let _directory = match _subcommand.is_present("directory") {
            true => _subcommand.value_of("directory").unwrap(),
            false => "None"
        };

        let _extension = match _subcommand.is_present("extension") {
            true => _subcommand.value_of("extension").unwrap(),
            false => "None",
        };

        let _filter = match _subcommand.is_present("filter") {
            true => _subcommand.value_of("filter").unwrap(),
            false => "None",
        };

        let _path = std::path::Path::new(&_directory);

        if _path.exists() && _path.is_dir() {
            for _entry in WalkDir::new(_path)
                .max_depth(20)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                let _e = _entry.path().to_str().unwrap();
                if _filter == "None" && _extension == "None" {
                    let _e = format!("{}{}{}", "'", _e, "'");
                    println!("{}", _e);
                } else if _filter != "None" && _extension == "None" {
                    if _e.contains(_filter) {
                        let _e = format!("{}{}{}", "'", _e, "'");
                        println!("{}", _e);
                    }
                } else if _filter == "None" && _extension != "None" {
                    if _e.ends_with(_extension) || _e.ends_with(&_extension.to_uppercase()) {
                        let _e = format!("{}{}{}", "'", _e, "'");
                        println!("{}", _e);
                    }
                } else if _filter != "None" && _extension != "None" {
                    if _e.contains(_filter) || _e.contains(&_filter.to_lowercase()) {
                        if _e.ends_with(_extension) || _e.ends_with(&_extension.to_uppercase()) {
                            let _e = format!("{}{}{}", "'", _e, "'");
                            println!("{}", _e);
                        }
                    }
                } else {
                    println!("{}", _e);
                }
            }
        }
    }
}
