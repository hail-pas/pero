use std::{env, fs, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=migrations");
    let mut files: Vec<_> = fs::read_dir("migrations")
        .expect("migrations directory")
        .map(|entry| entry.expect("migration entry").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "sql"))
        .collect();
    files.sort();
    assert!(!files.is_empty(), "at least one migration is required");
    let mut source = String::from("const MIGRATIONS: &[(&str, &str)] = &[\n");
    for path in files {
        let name = path.file_name().unwrap().to_str().unwrap();
        let (version, description) = name.split_once('_').expect("NNN_description.sql");
        assert!(version.len() == 3 && version.bytes().all(|b| b.is_ascii_digit()));
        assert!(
            description
                .strip_suffix(".sql")
                .unwrap()
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b == b'_')
        );
        source.push_str(&format!(
            "({name:?}, include_str!({:?})),\n",
            fs::canonicalize(&path).unwrap()
        ));
    }
    source.push_str("];\n");
    fs::write(
        PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("migrations.rs"),
        source,
    )
    .unwrap();
}
