use std::collections::HashMap;
use std::fs;
use std::path::Path;

fn main() {
    generate_i18n_js();
}

fn generate_i18n_js() {
    let locales_dir = Path::new("ui/locales");
    let output_path = Path::new("ui/static/js/i18n.js");

    if !locales_dir.exists() {
        panic!("ui/locales/ directory not found");
    }

    let mut all: Vec<(String, HashMap<String, String>)> = Vec::new();

    for entry in fs::read_dir(locales_dir).expect("failed to read ui/locales") {
        let entry = entry.expect("failed to read dir entry");
        let path = entry.path();

        if path.extension().map_or(true, |e| e != "toml") {
            continue;
        }

        let locale_name = path
            .file_stem()
            .expect("no file stem")
            .to_str()
            .expect("non-utf8 stem");

        let js_locale = if locale_name == "zh-CN" {
            "zh"
        } else {
            locale_name
        };

        let content = fs::read_to_string(&path).expect("failed to read locale file");
        let value: toml::Value = toml::from_str(&content).expect("failed to parse TOML");
        let flat = flatten(&value, "");

        all.push((js_locale.to_string(), flat));
    }

    all.sort_by(|a, b| a.0.cmp(&b.0));

    let mut js = String::from("window.PERO_I18N = {\n");
    for (locale, keys) in &all {
        js.push_str(&format!("  {locale}: {{\n"));
        let mut sorted_keys: Vec<_> = keys.keys().collect();
        sorted_keys.sort();
        for key in sorted_keys {
            let value = &keys[key];
            let escaped = value
                .replace('\\', "\\\\")
                .replace('"', "\\\"")
                .replace('\n', "\\n");
            js.push_str(&format!("    \"{key}\": \"{escaped}\",\n"));
        }
        js.push_str("  },\n");
    }
    js.push_str("};\n");

    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent).expect("failed to create output dir");
    }
    fs::write(output_path, js).expect("failed to write i18n.js");

    println!("cargo:rerun-if-changed=ui/locales/");
}

fn flatten(value: &toml::Value, prefix: &str) -> HashMap<String, String> {
    let mut result = HashMap::new();
    match value {
        toml::Value::Table(table) => {
            for (key, val) in table {
                let new_prefix = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                };
                result.extend(flatten(val, &new_prefix));
            }
        }
        toml::Value::String(s) => {
            result.insert(prefix.to_string(), s.clone());
        }
        other => {
            result.insert(prefix.to_string(), other.to_string());
        }
    }
    result
}
