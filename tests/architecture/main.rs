use std::fs;
use std::path::{Path, PathBuf};

fn rust_files_under(path: &str) -> Vec<PathBuf> {
    fn visit(path: &Path, files: &mut Vec<PathBuf>) {
        for entry in fs::read_dir(path).expect("read directory") {
            let entry = entry.expect("directory entry");
            let path = entry.path();
            if path.is_dir() {
                visit(&path, files);
            } else if path.extension().and_then(|value| value.to_str()) == Some("rs") {
                files.push(path);
            }
        }
    }

    let mut files = Vec::new();
    visit(Path::new(path), &mut files);
    files
}

#[test]
fn domain_layer_does_not_depend_on_infra_or_openapi_details() {
    let forbidden = [
        "sqlx::FromRow",
        "derive(sqlx::FromRow",
        "utoipa::",
        "ToSchema",
    ];

    let offenders: Vec<_> = rust_files_under("src/domain")
        .into_iter()
        .filter_map(|path| {
            let source = fs::read_to_string(&path).expect("read source file");
            let hits: Vec<_> = forbidden
                .iter()
                .filter(|needle| source.contains(**needle))
                .copied()
                .collect();
            (!hits.is_empty()).then_some((path, hits))
        })
        .collect();

    assert!(
        offenders.is_empty(),
        "domain files must not reference sqlx::FromRow or utoipa::ToSchema: {offenders:#?}"
    );
}

#[test]
fn domain_services_do_not_return_api_response_wrappers() {
    let forbidden = [
        "PageData",
        "MessageResponse",
        "shared::page",
        "shared::message",
    ];

    let offenders: Vec<_> = rust_files_under("src/domain")
        .into_iter()
        .filter(|path| path.file_name().and_then(|value| value.to_str()) == Some("service.rs"))
        .filter_map(|path| {
            let source = fs::read_to_string(&path).expect("read source file");
            let hits: Vec<_> = forbidden
                .iter()
                .filter(|needle| source.contains(**needle))
                .copied()
                .collect();
            (!hits.is_empty()).then_some((path, hits))
        })
        .collect();

    assert!(
        offenders.is_empty(),
        "domain services must return domain/application values, not API response wrappers: {offenders:#?}"
    );
}

#[test]
fn oauth_domain_has_one_service_boundary() {
    let duplicate_files = [
        Path::new("src/domain/oauth/authorize.rs"),
        Path::new("src/domain/oauth/client_service.rs"),
    ];

    let existing: Vec<_> = duplicate_files
        .iter()
        .filter(|path| path.exists())
        .collect();

    assert!(
        existing.is_empty(),
        "oauth duplicate service files should be merged into src/domain/oauth/service.rs: {existing:#?}"
    );
}
