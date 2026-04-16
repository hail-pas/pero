use std::sync::atomic::{AtomicU64, Ordering};

static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

pub fn test_prefix() -> String {
    let id = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("t{}", id)
}

pub fn unique_name(prefix: &str) -> String {
    format!(
        "{}_{}_{}",
        prefix,
        test_prefix(),
        uuid::Uuid::new_v4().to_string().replace('-', "")
    )
}

pub fn unique_email(prefix: &str) -> String {
    format!("{}@test.pero.dev", unique_name(prefix))
}
