pub fn validate_email(email: &str) -> Result<(), validator::ValidationError> {
    let at = email.find('@');
    let domain_start = match at {
        Some(i) if i > 0 => i + 1,
        _ => return Err(validator::ValidationError::new("invalid_email")),
    };
    let domain = &email[domain_start..];
    if domain.is_empty() || !domain.contains('.') {
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

pub fn validate_url(url: &str) -> Result<(), validator::ValidationError> {
    if url::Url::parse(url).is_err() {
        return Err(validator::ValidationError::new("invalid_url"));
    }
    Ok(())
}

pub fn validate_redirect_uri(uri: &str) -> Result<(), validator::ValidationError> {
    match url::Url::parse(uri) {
        Ok(parsed) => {
            if parsed.scheme() != "http" && parsed.scheme() != "https" {
                return Err(validator::ValidationError::new(
                    "invalid_redirect_uri_scheme",
                ));
            }
            Ok(())
        }
        Err(_) => Err(validator::ValidationError::new("invalid_redirect_uri")),
    }
}

pub fn validate_redirect_uris(uris: &Vec<String>) -> Result<(), validator::ValidationError> {
    for uri in uris {
        validate_redirect_uri(uri)?;
    }
    Ok(())
}
