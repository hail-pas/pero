use cookie::SameSite;

pub struct CookieOptions<'a> {
    pub name: &'a str,
    pub value: &'a str,
    pub http_only: bool,
    pub secure: bool,
    pub same_site: SameSite,
    pub max_age: cookie::time::Duration,
    pub domain: Option<&'a str>,
    pub path: &'a str,
}

pub struct AppCookieConfig<'a> {
    pub secure: bool,
    pub same_site: &'a str,
    pub domain: &'a str,
    pub path: &'a str,
}

pub fn parse_same_site(s: &str) -> SameSite {
    match s {
        "Strict" => SameSite::Strict,
        "None" => SameSite::None,
        _ => SameSite::Lax,
    }
}

pub fn cookie_domain(domain: &str) -> Option<String> {
    if domain.is_empty() {
        None
    } else {
        Some(domain.to_owned())
    }
}

pub fn build_cookie(opts: &CookieOptions<'_>) -> cookie::Cookie<'static> {
    let mut builder = cookie::Cookie::build((opts.name.to_owned(), opts.value.to_owned()))
        .http_only(opts.http_only)
        .secure(opts.secure)
        .same_site(opts.same_site)
        .path(opts.path.to_owned())
        .max_age(opts.max_age);
    if let Some(d) = opts.domain {
        builder = builder.domain(d.to_owned());
    }
    builder.into()
}

pub fn build_app_cookie(
    config: &AppCookieConfig<'_>,
    name: &str,
    value: &str,
    http_only: bool,
    max_age: cookie::time::Duration,
) -> cookie::Cookie<'static> {
    let same_site = parse_same_site(config.same_site);
    let domain = cookie_domain(config.domain);
    build_cookie(&CookieOptions {
        name,
        value,
        http_only,
        secure: config.secure,
        same_site,
        max_age,
        domain: domain.as_deref(),
        path: config.path,
    })
}

pub fn clear_cookie_with_domain(
    name: &str,
    path: &str,
    domain: Option<&str>,
) -> cookie::Cookie<'static> {
    let mut builder = cookie::Cookie::build((name.to_owned(), String::new()))
        .path(path.to_owned())
        .max_age(cookie::time::Duration::ZERO);
    if let Some(domain) = domain.filter(|value| !value.is_empty()) {
        builder = builder.domain(domain.to_owned());
    }
    builder.into()
}

pub fn clear_app_cookie(config: &AppCookieConfig<'_>, name: &str) -> cookie::Cookie<'static> {
    let domain = cookie_domain(config.domain);
    clear_cookie_with_domain(name, config.path, domain.as_deref())
}
