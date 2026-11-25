use user_center::config::AppConfig;

#[test]
fn shipped_configuration_remains_readable() {
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
    assert_eq!(
        config.frontend.static_dir,
        std::path::Path::new("../../frontend/dist")
    );
    assert_eq!(config.sso.session_touch_interval_seconds, 0);
    assert_eq!(config.retention.login_event_days, 90);
    assert_eq!(config.retention.audit_event_days, 365);
    assert_eq!(config.sso.base_url, "http://localhost:8080");
    assert!(!config.sso.cookie_secure);
    let bootstrap: toml::Table =
        toml::from_str(include_str!("../config/bootstrap.toml.example")).unwrap();
    assert!(!bootstrap.is_empty());
}

#[test]
fn shipped_production_secrets_are_not_accepted() {
    use pero_validate_core::Validatable;
    use user_center::config::{PasswordResetConfig, SsoConfig};

    let example: toml::Value =
        toml::from_str(include_str!("../../../deploy/pero/production.toml.example")).unwrap();
    let sso: SsoConfig = example["sso"].clone().try_into().unwrap();
    let reset: PasswordResetConfig = example["password_reset"].clone().try_into().unwrap();
    assert!(sso.validate().is_err());
    assert!(reset.validate().is_err());
}

#[test]
fn https_base_url_requires_secure_cookies() {
    use pero_types::SecretString;
    use pero_validate_core::Validatable;
    use user_center::config::SsoConfig;

    let mut config = SsoConfig {
        cookie_signing_secret: SecretString::new("test-signing-secret-at-least-32-bytes"),
        ..Default::default()
    };
    assert!(config.validate().is_ok());

    config.base_url = "https://auth.example.test".into();
    assert!(config.validate().is_err());

    config.cookie_secure = true;
    assert!(config.validate().is_ok());
}
