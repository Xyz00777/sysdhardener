#[allow(
    clippy::redundant_pub_crate,
    reason = "the sibling filesystem module calls this private serializer"
)]
pub(crate) fn serialize_write_paths(paths: &[String]) -> Option<String> {
    let mut rendered = Vec::with_capacity(paths.len());
    for path in paths {
        if path.contains('\0') {
            return None;
        }
        let quoted = path.contains(char::is_whitespace)
            || path.chars().any(char::is_control)
            || path.contains('"')
            || path.contains('\\');
        let mut escaped = String::with_capacity(path.len());
        for character in path.chars() {
            match character {
                '%' => escaped.push_str("%%"),
                '\\' => escaped.push_str("\\\\"),
                '"' => escaped.push_str("\\\""),
                '\0' => return None,
                '\x07' => escaped.push_str("\\a"),
                '\x08' => escaped.push_str("\\b"),
                '\t' => escaped.push_str("\\t"),
                '\n' => escaped.push_str("\\n"),
                '\x0b' => escaped.push_str("\\v"),
                '\x0c' => escaped.push_str("\\f"),
                '\r' => escaped.push_str("\\r"),
                control if control.is_control() => {
                    let code = u32::from(control);
                    let escape = if code <= 0x7f {
                        format!("\\x{code:02x}")
                    } else {
                        format!("\\u{code:04x}")
                    };
                    escaped.push_str(&escape);
                }
                literal => escaped.push(literal),
            }
        }
        if quoted {
            let mut token = String::with_capacity(escaped.len() + 2);
            token.push('"');
            token.push_str(&escaped);
            token.push('"');
            rendered.push(token);
        } else {
            rendered.push(escaped);
        }
    }
    Some(rendered.join(" "))
}
