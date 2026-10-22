use std::fs;
use std::path::Path;

#[test]
fn source_has_no_hardcoded_operator_name() {
    let needle = String::from_utf8(vec![b'd', b'a', b'n', b'i']).unwrap();
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut hits = Vec::new();
    for relative in ["src", "tests", "README.md", ".github", "Cargo.toml"] {
        visit(&root.join(relative), &needle, &mut hits);
    }
    assert!(hits.is_empty(), "hardcoded operator name in {hits:?}");
}

fn visit(path: &Path, needle: &str, hits: &mut Vec<String>) {
    if !path.exists() {
        return;
    }
    if path.is_file() {
        scan(path, needle, hits);
        return;
    }
    let entries = fs::read_dir(path).unwrap();
    for entry in entries {
        let entry = entry.unwrap();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name == "target" || name == ".git" {
            continue;
        }
        visit(&entry.path(), needle, hits);
    }
}

fn scan(path: &Path, needle: &str, hits: &mut Vec<String>) {
    let Some(text) = fs::read_to_string(path).ok() else {
        return;
    };
    let lowered = text.to_ascii_lowercase();
    let stripped = lowered.replace("daniel", "");
    if stripped.contains(needle) {
        hits.push(path.display().to_string());
    }
}
