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

#[allow(
    clippy::redundant_pub_crate,
    reason = "the sibling filesystem module calls this finding constructor"
)]
pub(crate) fn make_finding(
    directive: &'static str,
    recommended_value: Option<String>,
    coverage: crate::fixture::CoverageQuality,
    event_loss: crate::recommendation::EventLoss,
) -> crate::finding::Finding {
    crate::finding::Finding {
        directive,
        basis: crate::recommendation::FindingBasis::Observation {
            observed: Vec::new(),
        },
        observed_families: Vec::new(),
        recommended_families: Vec::new(),
        not_observed_families: Vec::new(),
        recommended_capabilities: Vec::new(),
        host_supported: true,
        recommended_value,
        provisional: crate::recommendation::ProvisionalStatus::Provisional,
        coverage,
        event_loss,
        contradiction_conditions: Vec::new(),
        compatibility_risk: crate::recommendation::CompatibilityRisk {
            support: crate::compatibility::SupportStatus::Supported,
            verification: crate::compatibility::VerificationStatus::Unverified,
            source_ref: crate::source_id::SourceId::from_static("SRC-01"),
        },
        validation_procedure: crate::recommendation::ValidationProcedure::ConfirmNoOutOfSetUse,
        source_ids: vec![crate::source_id::SourceId::from_static("SRC-01")],
        aggregate_keys: Vec::new(),
    }
}
