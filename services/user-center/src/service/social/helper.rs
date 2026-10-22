pub(crate) fn social_callback_url(base_url: &str, provider_code: &str) -> String {
    pero_utils::oauth::url::issuer_endpoint(
        base_url,
        &format!("sso/social/{provider_code}/callback"),
    )
}

pub(crate) use pero_utils::string::{json_int_field as int_field, json_str_field as str_field};
