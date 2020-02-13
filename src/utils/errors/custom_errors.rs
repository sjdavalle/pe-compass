extern crate scroll;
use scroll::{ Error };
use std::fmt::{ self, Display };

pub fn exit_process(msg: &str) {
    println!("\n\n(?) Error | Process Exiting Due to:\n");
    println!("{}", msg);
    std::process::exit(0x0100);
}

#[derive(Debug)]
pub struct ExternalError {}

impl Display for ExternalError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "ExternalError")
    }
}

impl std::error::Error for ExternalError {
    fn description(&self) -> &str {
        "ExternalError"
    }
    fn cause(&self) -> Option<&dyn std::error::Error> { None}
}

impl From<scroll::Error> for ExternalError {
    fn from(err: scroll::Error) -> Self {
        match err {
            _ => ExternalError{},
        }
    }
}