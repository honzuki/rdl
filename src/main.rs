mod process;

fn main() {
    let entry = process::find_by_name("firefox")
        .ok()
        .and_then(|entry| entry)
        .expect("can not find the proces");

    println!(
        "{}:\n{:?}",
        String::from_utf8_lossy(&entry.szExeFile),
        entry
    );
}
