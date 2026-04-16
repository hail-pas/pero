use std::sync::atomic::{AtomicU64, Ordering};

#[allow(dead_code)]
static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

#[allow(dead_code)]
pub fn test_prefix() -> String {
    let id = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("t{}", id)
}

#[allow(dead_code)]
pub fn unique_name(prefix: &str) -> String {
    format!(
        "{}_{}_{}",
        prefix,
        test_prefix(),
        uuid::Uuid::new_v4().to_string().replace('-', "")
    )
}

#[allow(dead_code)]
pub fn unique_email(prefix: &str) -> String {
    format!("{}@test.pero.dev", unique_name(prefix))
}
