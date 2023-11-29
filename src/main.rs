// Whenever an unsafe function does not have any requirements, we leave 'SAFETY: !' to make it clear that
// we didn't forget to write a SAFETY block, but rather that the function is a safe function that was marked as unsafe

use anyhow::{bail, Context};
use clap::Parser;
use windows::Win32::{
    Foundation::CloseHandle,
    System::Threading::{OpenProcess, PROCESS_ALL_ACCESS},
};

mod config;
mod process;

fn main() -> anyhow::Result<()> {
    let args = config::Args::parse();

    // we need to inject a path that is recognized from the cwd of the injected process
    let dll_canonicalized_path = args
        .dll
        .canonicalize()
        .context("failed to canonicalize the dll path")?;

    let Some(entry) = process::find_by_name(&args.name.to_lowercase())? else {
        bail!("can not find process with name: {}", args.name);
    };

    // SAFETY: !
    let process_handler = unsafe { OpenProcess(PROCESS_ALL_ACCESS, true, entry.th32ProcessID) }?;
    process::inject_dll(process_handler, dll_canonicalized_path.as_os_str())?;
    // SAFETY: !
    unsafe { CloseHandle(process_handler)? };

    Ok(())
}
