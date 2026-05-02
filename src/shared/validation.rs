pub fn validate_length(
    value: &str,
    min: usize,
    max: usize,
) -> Result<(), validator::ValidationError> {
    let len = value.chars().count();
    if len < min || len > max {
        let mut err = validator::ValidationError::new("length");
        err.add_param(std::borrow::Cow::Borrowed("min"), &min);
        err.add_param(std::borrow::Cow::Borrowed("max"), &max);
        err.add_param(std::borrow::Cow::Borrowed("value"), &len);
        return Err(err);
    }
    Ok(())
}

pub fn validate_email(email: &str) -> Result<(), validator::ValidationError> {
    let parts: Vec<&str> = email.rsplitn(2, '@').collect();
    if parts.len() != 2 {
        return Err(validator::ValidationError::new("invalid_email"));
    }
    let (domain, local) = (parts[0], parts[1]);
    if local.is_empty() || domain.is_empty() {
        return Err(validator::ValidationError::new("invalid_email"));
    }
    if !domain.contains('.') || domain.starts_with('.') || domain.ends_with('.') {
        return Err(validator::ValidationError::new("invalid_email"));
    }
    if local.len() > 64 || domain.len() > 190 || email.len() > 255 {
        return Err(validator::ValidationError::new("invalid_email"));
    }
    Ok(())
}

pub fn validate_phone(phone: &str) -> Result<(), validator::ValidationError> {
    let trimmed = phone.trim();
    if trimmed.is_empty() || trimmed.len() > 20 {
        return Err(validator::ValidationError::new("invalid_phone"));
    }
    let mut chars = trimmed.chars();
    let first = match chars.next() {
        Some(c) => c,
        None => return Err(validator::ValidationError::new("invalid_phone")),
    };
    if !first.is_ascii_digit() && first != '+' {
        return Err(validator::ValidationError::new("invalid_phone"));
    }
    if !chars.all(|c| c.is_ascii_digit() || c == '-' || c == ' ' || c == '(' || c == ')') {
        return Err(validator::ValidationError::new("invalid_phone"));
    }
    Ok(())
}

pub fn validate_email_or_phone(value: &str) -> Result<(), validator::ValidationError> {
    if value.contains('@') {
        validate_email(value)
    } else {
        validate_phone(value)
    }
}

pub fn validate_url(url: &str) -> Result<(), validator::ValidationError> {
    if url::Url::parse(url).is_err() {
        return Err(validator::ValidationError::new("invalid_url"));
    }
    Ok(())
}

pub fn validate_redirect_uri(uri: &str) -> Result<(), validator::ValidationError> {
    match url::Url::parse(uri) {
        Ok(parsed) => {
            if parsed.fragment().is_some() {
                return Err(validator::ValidationError::new("redirect_uri_fragment_not_allowed"));
            }

            if parsed.scheme() == "http" {
                let host = parsed.host_str().unwrap_or_default();
                let is_loopback = host == "localhost" || host == "127.0.0.1" || host == "::1";
                if !is_loopback {
                    return Err(validator::ValidationError::new("http_redirect_uri_only_loopback"));
                }
            }
            Ok(())
        }
        Err(_) => Err(validator::ValidationError::new("invalid_redirect_uri")),
    }
}

pub fn validate_redirect_uris(uris: &[String]) -> Result<(), validator::ValidationError> {

    let mut seen = HashSet::new();
    for uri in uris {
        if !seen.insert(uri) {
            return Err(ValidationError::new("duplicate_redirect_uri"));
        }
        validate_redirect_uri(uri)?;
    }
    Ok(())
}

pub fn validate_non_empty_items(items: &[String]) -> Result<(), validator::ValidationError> {
    if items.iter().any(|item| item.trim().is_empty()) {
        return Err(validator::ValidationError::new("empty_item"));
    }
    Ok(())
}


pub fn validate_pkce_verifier(v: &str) -> Result<(), validator::ValidationError> {
    if !v.chars().all(|c| c.is_ascii_alphanumeric() || "-._~".contains(c)) {
        return Err(validator::ValidationError::new("pkce_verifier_charset"));
    }
    Ok(())
}
