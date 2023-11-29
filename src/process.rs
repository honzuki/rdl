use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS,
};

// An helper structure that holds data
// for iterating over a snapshot of the proc list
struct ProcIter {
    snapshot: windows::Win32::Foundation::HANDLE,
    entry: Option<PROCESSENTRY32>,
}

/// Get an iterator of all running processes
///
/// the function returns an error when it fails to generate
/// a snapshot of the current process list
pub fn iter() -> windows::core::Result<impl Iterator<Item = PROCESSENTRY32>> {
    // SAFETY: no requirements, this function is always safe to call
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }?;

    let mut entry = PROCESSENTRY32 {
        dwSize: std::mem::size_of::<PROCESSENTRY32>() as u32,
        ..Default::default()
    };

    // SAFETY: snapshot is valid, and entry is properly initialized with a correct 'dwSize'
    unsafe { Process32First(snapshot, &mut entry) }?;

    Ok(ProcIter {
        snapshot,
        entry: Some(entry),
    })
}

impl Iterator for ProcIter {
    type Item = PROCESSENTRY32;

    fn next(&mut self) -> Option<Self::Item> {
        // take the current entry
        let entry = self.entry.take()?;

        // cache the next entry, if exists
        {
            let mut new_entry = entry;
            // SAFETY: snapshot is valid, new_entry is a copy of a correct entry
            if unsafe { Process32Next(self.snapshot, &mut new_entry) }.is_ok() {
                self.entry = Some(new_entry)
            }
        }

        Some(entry)
    }
}

// helpers

/// Searches for a process by its executable name
///
/// this function will ignore case
pub fn find_by_name(target_name: &str) -> windows::core::Result<Option<PROCESSENTRY32>> {
    Ok(iter()?.find(|entry| {
        String::from_utf8_lossy(&entry.szExeFile)
            .to_lowercase()
            .contains(target_name)
    }))
}
