// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use std::borrow::Cow;

use crate::error::{LithiumError, Result};
use crate::public::PublicBytes;

const VERSION: &str = "v1";
const MAX_CONTEXT_LEN: usize = 255;

fn validate_segment(seg: &str) -> Result<()> {
    if seg.is_empty() {
        return Err(LithiumError::invalid_context("empty_segment"));
    }
    if !seg.bytes().all(|b| (0x21..=0x7e).contains(&b) && b != b'/') {
        return Err(LithiumError::invalid_context("segment_charset"));
    }
    Ok(())
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Context<'a>(Cow<'a, str>);

impl<'a> Context<'a> {
    pub fn base(root: &'a str) -> Result<Self> {
        validate_segment(root)?;
        if root.len() > MAX_CONTEXT_LEN {
            return Err(LithiumError::invalid_context("too_long"));
        }
        Ok(Self(Cow::Borrowed(root)))
    }

    pub fn add(&self, segment: &str) -> Result<Context<'static>> {
        validate_segment(segment)?;
        let joined = format!("{}/{}", self.0, segment);
        if joined.len() > MAX_CONTEXT_LEN {
            return Err(LithiumError::invalid_context("too_long"));
        }
        Ok(Context(Cow::Owned(joined)))
    }

    pub(crate) fn label(&self) -> PublicBytes {
        PublicBytes::from_slice(format!("{}/{}", self.0, VERSION).as_bytes())
    }

    pub(crate) fn bind_aad(&self, aad: &[u8]) -> PublicBytes {
        let mut out = self.label().as_slice().to_vec();
        if !aad.is_empty() {
            out.push(0);
            out.extend_from_slice(aad);
        }
        PublicBytes::from_slice(&out)
    }

    #[cfg(test)]
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorKind;

    fn is_invalid_context(err: LithiumError) -> bool {
        matches!(err.kind, ErrorKind::InvalidContext { .. })
    }

    #[test]
    fn empty_segment_rejected() {
        assert!(is_invalid_context(Context::base("").unwrap_err()));
        assert!(is_invalid_context(
            Context::base("app").unwrap().add("").unwrap_err()
        ));
    }

    #[test]
    fn slash_injection_rejected() {
        assert!(is_invalid_context(Context::base("app/mail").unwrap_err()));
        assert!(is_invalid_context(
            Context::base("app").unwrap().add("mail/evil").unwrap_err()
        ));
    }

    #[test]
    fn non_printable_bytes_rejected() {
        for bad in [
            "a b",
            " ",
            "a\tb",
            "a\nb",
            "del\u{7f}",
            "nul\0",
            "café",
            "\u{80}",
        ] {
            assert!(
                is_invalid_context(Context::base(bad).unwrap_err()),
                "base({bad:?}) must be rejected"
            );
        }
        assert!(is_invalid_context(
            Context::base("app").unwrap().add("a b").unwrap_err()
        ));
    }

    #[test]
    fn length_limit_enforced() {
        let at_max = "a".repeat(MAX_CONTEXT_LEN);
        let ctx = Context::base(&at_max).unwrap();
        assert_eq!(ctx.as_str(), at_max);

        let too_long = "a".repeat(MAX_CONTEXT_LEN + 1);
        assert!(is_invalid_context(Context::base(&too_long).unwrap_err()));

        let fits_root = "a".repeat(MAX_CONTEXT_LEN - 2);
        let base = Context::base(&fits_root).unwrap();
        assert!(
            base.add("b").is_ok(),
            "253 + '/' + 'b' == 255 is within the limit"
        );

        let over_root = "a".repeat(MAX_CONTEXT_LEN - 1);
        let base = Context::base(&over_root).unwrap();
        assert!(
            is_invalid_context(base.add("b").unwrap_err()),
            "254 + '/' + 'b' == 256 is over the limit"
        );
    }

    #[test]
    fn add_is_non_mutating() {
        let base = Context::base("app").unwrap().add("mail").unwrap();
        let enc = base.add("encrypt").unwrap();
        let mac = base.add("mac").unwrap();

        assert_eq!(base.as_str(), "app/mail");
        assert_eq!(enc.as_str(), "app/mail/encrypt");
        assert_eq!(mac.as_str(), "app/mail/mac");
    }

    #[test]
    fn label_appends_version() {
        let ctx = Context::base("app").unwrap().add("mail").unwrap();
        assert_eq!(ctx.label().as_slice(), &b"app/mail/v1"[..]);
    }

    #[test]
    fn charset_boundaries_are_exact() {
        assert!(Context::base("!").is_ok(), "0x21 is the low bound");
        assert!(Context::base("~").is_ok(), "0x7e is the high bound");
        assert!(
            is_invalid_context(Context::base(" ").unwrap_err()),
            "0x20 is one below the range"
        );
        assert!(
            is_invalid_context(Context::base("\u{7f}").unwrap_err()),
            "0x7f is one above the range"
        );
    }

    #[test]
    fn control_and_invisible_chars_rejected() {
        for bad in [
            "a\rb",
            "a\u{0b}b",
            "a\u{0c}b",
            "a\u{08}b",
            "a\u{1b}b",
            "a\u{1f}b",
            "a\u{a0}b",
            "a\u{200b}b",
            "a\u{feff}b",
            "a\u{202e}b",
        ] {
            assert!(
                is_invalid_context(Context::base(bad).unwrap_err()),
                "base({bad:?}) must be rejected"
            );
        }
    }

    #[test]
    fn only_slash_is_a_separator() {
        let backslash = Context::base("root").unwrap().add("a\\b").unwrap();
        assert_eq!(backslash.as_str(), "root/a\\b");
        assert_ne!(
            backslash.as_str(),
            "root/a/b",
            "backslash must stay a plain byte, not a separator"
        );

        let encoded = Context::base("app").unwrap().add("%2f").unwrap();
        assert_eq!(
            encoded.as_str(),
            "app/%2f",
            "percent-encoding is never decoded into a separator"
        );
    }

    #[test]
    fn dot_segments_have_no_path_semantics() {
        let ctx = Context::base("a")
            .unwrap()
            .add("..")
            .unwrap()
            .add(".")
            .unwrap()
            .add("~")
            .unwrap();
        assert_eq!(
            ctx.as_str(),
            "a/.././~",
            "dot segments are literal, not normalized"
        );
    }

    #[test]
    fn version_segment_cannot_forge_parent_label() {
        let parent = Context::base("app").unwrap();
        let child = parent.add("v1").unwrap();

        assert_eq!(child.as_str(), "app/v1");
        assert_eq!(parent.label().as_slice(), &b"app/v1"[..]);
        assert_ne!(
            child.label().as_slice(),
            parent.label().as_slice(),
            "a segment named v1 must not collide with the parent's versioned label"
        );
        assert_eq!(child.label().as_slice(), &b"app/v1/v1"[..]);
    }

    #[test]
    fn add_over_limit_leaves_base_usable() {
        let root = "a".repeat(MAX_CONTEXT_LEN - 2);
        let base = Context::base(&root).unwrap();
        let before = base.as_str().to_owned();

        assert!(is_invalid_context(base.add("bb").unwrap_err()));
        assert_eq!(base.as_str(), before, "a rejected add must not mutate base");
        assert!(
            base.add("b").is_ok(),
            "base still usable after a rejected add"
        );
    }
}
