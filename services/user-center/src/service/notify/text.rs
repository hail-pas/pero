use super::Payload;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub(crate) enum Locale {
    #[serde(rename = "en")]
    English,
    #[serde(rename = "zh-CN")]
    Chinese,
}

impl Locale {
    pub(crate) fn from_tag(tag: &str) -> Option<Self> {
        let language = tag.trim().split('-').next()?;
        if language.eq_ignore_ascii_case("zh") {
            Some(Self::Chinese)
        } else if language.eq_ignore_ascii_case("en") {
            Some(Self::English)
        } else {
            None
        }
    }

    pub(crate) fn negotiate<'a>(headers: impl IntoIterator<Item = &'a str>) -> Option<Self> {
        let mut preferred = None;
        let mut highest = 0.0;
        for item in headers.into_iter().flat_map(|header| header.split(',')) {
            let (tag, quality) = match item.split_once(';') {
                Some((tag, parameter)) => (
                    tag,
                    parameter
                        .trim()
                        .strip_prefix("q=")
                        .and_then(|quality| quality.parse::<f32>().ok())
                        .unwrap_or(0.0),
                ),
                None => (item, 1.0),
            };
            if quality > highest
                && quality <= 1.0
                && let Some(locale) = Self::from_tag(tag)
            {
                highest = quality;
                preferred = Some(locale);
            }
        }
        preferred
    }

    pub(super) fn header_value(self) -> http::HeaderValue {
        http::HeaderValue::from_static(self.select("en", "zh-CN"))
    }

    fn select<'a>(self, english: &'a str, chinese: &'a str) -> &'a str {
        match self {
            Self::English => english,
            Self::Chinese => chinese,
        }
    }
}

pub(super) fn render(message: &Payload) -> (String, String) {
    let language = message.locale.unwrap_or(Locale::English);
    let title = match message.kind.as_str() {
        "verify_contact" => language.select("Verify your contact details", "验证联系方式"),
        "reset_password" => language.select("Set or reset your password", "设置或重置密码"),
        "enrollment" => language.select(
            "Continue registration or accept an invitation",
            "继续注册或接受邀请",
        ),
        "enrollment_rejected" => {
            language.select("Registration request declined", "注册申请未获批准")
        }
        "tenant_invitation" => language.select("Organization invitation", "组织邀请"),
        "password_changed" => language.select("Your password changed", "你的密码已变更"),
        "password_reset_completed" => language.select("Your password was reset", "你的密码已重置"),
        "admin_password_reset" => language.select(
            "An administrator reset your password",
            "管理员已重置你的密码",
        ),
        "contact_changed" => language.select("Your contact details changed", "你的联系方式已变更"),
        "mfa_enabled" => language.select("Two-factor authentication enabled", "已启用双重验证"),
        "mfa_changed" => language.select("Two-factor authentication changed", "双重验证方式已更换"),
        "mfa_recovery" => language.select("Two-factor authentication recovery", "双重验证恢复通知"),
        "identity_linked" => language.select("A sign-in method was linked", "已绑定新的登录方式"),
        "identity_unlinked" => language.select("A sign-in method was unlinked", "已解绑登录方式"),
        "sessions_revoked" => language.select("Sign-in sessions were revoked", "登录会话已撤销"),
        "new_login" => language.select("New sign-in to your account", "你的账户有新的登录"),
        _ => language.select("Account notification", "账户通知"),
    };
    let subject = format!("Pero · {title}");
    // A non-GSM-7 character changes the encoding of the entire SMS.
    let mut body = if message.channel == "phone" && language == Locale::English {
        format!("Pero: {title}")
    } else {
        subject.clone()
    };
    if let Some(code) = message.code.as_deref().filter(|code| !code.is_empty()) {
        let label = language.select("Verification code:", "验证码：");
        body.push_str(&format!("\n{label} {code}"));
    }
    if !message.link.is_empty() {
        body.push('\n');
        body.push_str(&message.link);
    }
    let guidance = if message.kind == "tenant_invitation" {
        language.select(
            "Ignore this invitation if you weren't expecting it.",
            "如未预期收到邀请，请忽略此通知。",
        )
    } else {
        language.select(
            "If you did not request this, review your account security.",
            "如非本人操作，请检查账户安全。",
        )
    };
    body.push_str("\n\n");
    body.push_str(guidance);
    (subject, body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn language_negotiation_handles_regions_preferences_and_unsupported_languages() {
        assert_eq!(
            Locale::negotiate(["fr-FR, EN-US;q=0.7", "zh-Hant;q=0.9"]),
            Some(Locale::Chinese)
        );
        assert_eq!(
            Locale::negotiate(["zh-CN;q=0, en-GB;q=0.5"]),
            Some(Locale::English)
        );
        assert_eq!(Locale::negotiate(["fr-FR, *;q=0.5"]), None);
    }

    #[test]
    fn queued_notifications_use_their_locale_and_legacy_messages_fall_back() {
        let raw = r#"{"channel":"email","kind":"verify_contact","to":"example@example.test","code":"123456","link":"https://example.test/verify"}"#;
        let mut message: Payload = serde_json::from_str(raw).unwrap();
        let (subject, body) = render(&message);
        assert_eq!(subject, "Pero · Verify your contact details");
        assert!(body.contains("Verification code: 123456"));

        message.locale = Some(Locale::Chinese);
        let (subject, body) = render(&message);
        assert_eq!(subject, "Pero · 验证联系方式");
        assert!(body.contains("验证码： 123456"));
        assert!(body.contains("https://example.test/verify"));
        assert!(!body.contains("verify_contact"));
    }

    #[test]
    fn english_verification_sms_keeps_a_gsm_7_prefix() {
        let raw = r#"{"channel":"phone","kind":"verify_contact","to":"+15555550123","code":"123456","link":"https://example.test/verify","locale":"en"}"#;
        let message: Payload = serde_json::from_str(raw).unwrap();
        let (_, body) = render(&message);
        assert!(body.starts_with("Pero: Verify your contact details\n"));
        assert!(body.is_ascii());
        assert!(body.len() <= 160);
        assert!(body.contains("Verification code: 123456\nhttps://example.test/verify"));
    }
}
