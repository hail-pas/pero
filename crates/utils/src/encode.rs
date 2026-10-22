pub fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    encode_into(&mut out, s);
    out
}

pub fn encode_into(buf: &mut String, s: &str) {
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                buf.push(byte as char);
            }
            _ => {
                buf.push_str(&format!("%{:02X}", byte));
            }
        }
    }
}

pub fn append_query_param(url: &mut String, key: &str, value: &str) {
    if !url.contains('?') {
        url.push('?');
    } else if !url.ends_with('?') && !url.ends_with('&') {
        url.push('&');
    }

    encode_into(url, key);
    url.push('=');
    encode_into(url, value);
}
