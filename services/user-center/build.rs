use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

fn main() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let root = Path::new(&manifest_dir);
    let locales_dir = root.join("ui/locales");
    let out_dir = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    let js_out = out_dir.join("i18n.js");

    println!("cargo:rerun-if-changed=ui/locales");

    let mut dict: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();

    for entry in fs::read_dir(&locales_dir).expect("Missing ui/locales directory") {
        let entry = entry.expect("Failed to read locale directory entry");
        let path = entry.path();
        if path.extension().is_none_or(|e| e != "toml") {
            continue;
        }
        let stem = match path.file_stem().and_then(|s| s.to_str()) {
            Some(s) if !s.starts_with('_') && !s.starts_with('.') => s.to_owned(),
            _ => continue,
        };

        let content = fs::read_to_string(&path).expect("Failed to read locale file");
        let table: toml::Table = toml::from_str(&content).expect("Invalid locale TOML");

        dict.insert(stem, flatten(&table, ""));
    }

    assert!(
        !dict.is_empty(),
        "No locale dictionaries found in ui/locales"
    );

    let js = generate_i18n_js(&dict);
    fs::write(&js_out, js).unwrap();
}

fn flatten(table: &toml::Table, prefix: &str) -> BTreeMap<String, String> {
    let mut result = BTreeMap::new();
    for (key, value) in table {
        let dotted = if prefix.is_empty() {
            key.clone()
        } else {
            format!("{prefix}.{key}")
        };
        match value {
            toml::Value::String(s) => {
                result.insert(dotted, s.clone());
            }
            toml::Value::Table(inner) => {
                result.extend(flatten(inner, &dotted));
            }
            _ => {}
        }
    }
    result
}

fn js_locale_key(stem: &str) -> &str {
    match stem {
        s if s.starts_with("zh") => "zh",
        _ => stem,
    }
}

fn generate_i18n_js(dict: &BTreeMap<String, BTreeMap<String, String>>) -> String {
    let locales: BTreeMap<_, _> = dict
        .iter()
        .map(|(stem, map)| (js_locale_key(stem), map))
        .collect();
    format!(
        "// Generated from ui/locales/*.toml\nwindow.PERO_I18N = {};\n",
        serde_json::to_string(&locales).unwrap()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn javascript_dictionary_escapes_all_json_characters() {
        let text = "line one\nline two\t\"quoted\"\\path";
        let dict = BTreeMap::from([(
            "en-US".to_owned(),
            BTreeMap::from([("a\"key".to_owned(), text.to_owned())]),
        )]);
        let js = generate_i18n_js(&dict);
        let json = js
            .split_once("window.PERO_I18N = ")
            .unwrap()
            .1
            .trim_end()
            .trim_end_matches(';');
        let value: serde_json::Value = serde_json::from_str(json).unwrap();
        assert_eq!(value["en-US"]["a\"key"], text);
    }
}
