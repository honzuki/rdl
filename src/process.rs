use std::ffi::{c_void, CString, OsStr};

use windows::{
    core::PCSTR,
    Win32::{
        Foundation::CloseHandle,
        System::{
            Diagnostics::{
                Debug::WriteProcessMemory,
                ToolHelp::{
                    CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32,
                    TH32CS_SNAPPROCESS,
                },
            },
            LibraryLoader::{GetModuleHandleA, GetProcAddress},
            Memory::{VirtualAllocEx, VirtualFreeEx, MEM_COMMIT, MEM_RELEASE, PAGE_READWRITE},
            Threading::{CreateRemoteThread, GetExitCodeThread, WaitForSingleObject, INFINITE},
        },
    },
};

#[derive(thiserror::Error, Debug)]
pub enum InjectErr {
    #[error("failed to allocate memory in the target process")]
    AllocFailed,

    #[error("can not find the load library symbol in the kernel dll")]
    MissingLoadLibrary,

    #[error("{0}")]
    Api(#[from] windows::core::Error),
}

/// Injects a dll into a process
///
/// dll: contains a path to the dll on disk, that is relative to the injected process's cwd
///
/// note: if the function fails, it may leave some allocated memory inside the target process
pub fn inject_dll(
    process: windows::Win32::Foundation::HANDLE,
    dll: &OsStr,
) -> Result<(), InjectErr> {
    let dll = dll.as_encoded_bytes();

    //// Write the dll's path into the target process memory
    // SAFETY: !
    let memory =
        unsafe { VirtualAllocEx(process, None, dll.len() + 1, MEM_COMMIT, PAGE_READWRITE) };

    if memory.is_null() {
        return Err(InjectErr::AllocFailed);
    }

    // SAFETY:
    //  - memory is a valid ptr obtained by a call to `VirtualAllocEx`
    //  - the area was allocated using MEM_COMMIT, which fills it with zero
    //  - we left area for the NULL-terminator at the end of the string
    unsafe {
        WriteProcessMemory(
            process,
            memory,
            dll.as_ptr() as *const c_void,
            dll.len(),
            None,
        )
    }?;

    //// Spawn a thread inside the target process, that will execute `LoadLibraryA` with the dll's path
    // SAFETY: !
    let kernel32 = unsafe {
        let tmp = CString::new("kernel32.dll").unwrap();
        let tmp = PCSTR(tmp.as_ptr() as *const u8);
        GetModuleHandleA(tmp)?
    };
    // SAFETY: !
    let load_library_fn = unsafe {
        let tmp = CString::new("LoadLibraryA").unwrap();
        let tmp = PCSTR(tmp.as_ptr() as *const u8);
        GetProcAddress(kernel32, tmp)
    }
    .ok_or_else(|| InjectErr::MissingLoadLibrary)?;
    // SAFETY: the signature of the function was abstracted by the windows library, but we know that the real signature matches the one below
    let load_library_fn = unsafe {
        std::mem::transmute::<
            unsafe extern "system" fn() -> isize,
            unsafe extern "system" fn(*mut std::ffi::c_void) -> u32,
        >(load_library_fn)
    };
    // SAFETY:
    //  - we can assume that kernel32.dll's address is the same in any process, even under ASLR
    //  - we know that  LoadLibraryA's signature matches that of a spawned thread
    //  - we know that memory points to a valid block of memory that contains the dll's path
    let thread = unsafe {
        CreateRemoteThread(
            process,
            None,
            0,
            Some(load_library_fn),
            Some(memory),
            0,
            None,
        )
    }?;

    //// Wait for the thread to return an free the allocated memory
    // SAFETY: !
    unsafe {
        // we don't really care about the exit code
        let mut exitcode = 0u32;
        WaitForSingleObject(thread, INFINITE);
        GetExitCodeThread(thread, &mut exitcode as *mut u32)
    }?;
    // SAFETY: memory points to a valid block of memory that was allocated using `VirtualAllocEx`
    // dwsize is '0' as required when using 'MEM_RELEASE'
    unsafe { VirtualFreeEx(process, memory, 0, MEM_RELEASE) }?;
    // SAFETY: !
    unsafe { CloseHandle(thread) }?;

    Ok(())
}

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
    // SAFETY: !
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
