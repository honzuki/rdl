use std::path::PathBuf;

use clap::Parser;

#[derive(Parser)]
pub struct Args {
    /// The name of the target process
    ///
    /// the name does not need to be an exact match, but should
    /// contain enough characteres to uniquely identify the target process.
    #[clap(long, short)]
    pub name: String,

    /// The dll to be injected
    #[clap(long, short)]
    pub dll: PathBuf,
}
