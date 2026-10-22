use pero_cache_redis::rate_limit_key::rl_token;
use pero_cache_redis::{
    CommandArg, RateLimitOutcome, RedisCacheStore, RedisConfig, rate_limit_check,
};
use std::time::Duration;

#[tokio::test]
#[ignore = "requires dedicated PERO_TEST_REDIS_URL"]
async fn redis_atomic_limits_take_expiry_and_recovery() {
    let url = std::env::var("PERO_TEST_REDIS_URL").expect("dedicated local Redis required");
    assert!(url.starts_with("redis://127.0.0.1:"));
    let config: RedisConfig = serde_json::from_value(
        serde_json::json!({"url":url,"command_timeout_secs":1,"connect_timeout_secs":1}),
    )
    .unwrap();
    let store = RedisCacheStore::from_config(&config).unwrap();
    let id = format!(
        "integration-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let key = rl_token.key(&id).unwrap().with_ttl(Duration::from_secs(2));
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..40 {
        let store = store.clone();
        let key = key.clone();
        tasks.spawn(async move { rate_limit_check(&store, &key, 10).await.unwrap() });
    }
    let mut allowed = 0;
    while let Some(result) = tasks.join_next().await {
        if matches!(result.unwrap(), RateLimitOutcome::Allowed { .. }) {
            allowed += 1;
        }
    }
    assert_eq!(allowed, 10);
    let ttl = store
        .command("PTTL", &[CommandArg::str(key.as_str())])
        .await
        .unwrap()
        .as_i64()
        .unwrap();
    assert!((1..=2000).contains(&ttl));
    tokio::time::sleep(Duration::from_millis(ttl as u64 + 50)).await;
    assert!(matches!(
        rate_limit_check(&store, &key, 10).await.unwrap(),
        RateLimitOutcome::Allowed { current: 1 }
    ));
    store.set(key.clone(), &42).await.unwrap();
    let (a, b) = tokio::join!(store.take(key.clone()), store.take(key.clone()));
    assert_eq!(
        [a.unwrap(), b.unwrap()]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>(),
        vec![42]
    );
    // Server pause models temporary unavailability without restarting another process.
    store
        .command(
            "CLIENT",
            &[
                CommandArg::str("PAUSE"),
                CommandArg::from(3000i64),
                CommandArg::str("ALL"),
            ],
        )
        .await
        .unwrap();
    let started = std::time::Instant::now();
    assert!(store.get(key.clone()).await.is_err());
    assert!(started.elapsed() < Duration::from_millis(2000));
    tokio::time::sleep(Duration::from_millis(2200)).await;
    store.set(key.clone(), &7).await.unwrap();
    assert_eq!(store.take(key).await.unwrap(), Some(7));
}
