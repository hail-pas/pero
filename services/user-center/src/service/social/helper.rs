pub(crate) fn social_callback_url(base_url: &str, provider_code: &str) -> String {
    pero_utils::oauth::url::issuer_endpoint(
        base_url,
        &format!(
            "sso/social/{}/callback",
            pero_utils::encode::percent_encode(provider_code)
        ),
    )
}

pub(crate) use pero_utils::string::{json_int_field as int_field, json_str_field as str_field};

#[cfg(test)]
mod tests {
    #[test]
    fn callback_encodes_the_provider_as_one_path_segment() {
        assert_eq!(
            super::social_callback_url("https://id.example/tenant/", "idp?#/中文"),
            "https://id.example/tenant/sso/social/idp%3F%23%2F%E4%B8%AD%E6%96%87/callback"
        );
    }
}
