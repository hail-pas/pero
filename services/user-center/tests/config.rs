use user_center::config::AppConfig;

#[test]
fn shipped_configuration_and_locales_remain_readable() {
    let mut defaults: toml::Table = toml::from_str(include_str!("../config/default.toml")).unwrap();
    let local: toml::Table = toml::from_str(include_str!("../config/local.toml.example")).unwrap();
    for (section, values) in local {
        if let (Some(toml::Value::Table(base)), toml::Value::Table(overrides)) =
            (defaults.get_mut(&section), &values)
        {
            base.extend(overrides.clone());
        } else {
            defaults.insert(section, values);
        }
    }
    let config: AppConfig = toml::Value::Table(defaults).try_into().unwrap();
    assert_eq!(config.server.port, 8080);
    assert_eq!(config.sso.session_touch_interval_seconds, 0);
    assert_eq!(config.sso.base_url, "http://localhost:8080");
    assert!(!config.sso.cookie_secure);
    for input in [
        include_str!("../config/bootstrap.toml.example"),
        include_str!("../../admin/config/default.toml"),
        include_str!("../../admin/config/local.toml.example"),
        include_str!("../ui/locales/en.toml"),
        include_str!("../ui/locales/zh-CN.toml"),
    ] {
        let table: toml::Table = toml::from_str(input).unwrap();
        assert!(!table.is_empty());
    }
}
