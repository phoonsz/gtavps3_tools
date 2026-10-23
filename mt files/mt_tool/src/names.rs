//! Name hashing (Jenkins one-at-a-time) and hash <-> readable-name lookup.

use std::collections::HashMap;
use std::sync::OnceLock;

use crate::constants::{ARRAYINFO, NAMES};

// ============================================================================
// Hashing / names
// ============================================================================

/// Jenkins one-at-a-time hash.
pub(crate) fn joaat(s: &str) -> u32 {
    let mut h: u32 = 0;
    for b in s.bytes() {
        h = h.wrapping_add(u32::from(b));
        h = h.wrapping_add(h << 10);
        h ^= h >> 6;
    }
    h = h.wrapping_add(h << 3);
    h ^= h >> 11;
    h.wrapping_add(h << 15)
}

pub(crate) struct NameTable {
    pub(crate) by_hash: HashMap<u32, &'static str>,
    pub(crate) by_name: HashMap<&'static str, u32>,
}

/// Lazily built lookup tables for [`NAMES`] (hashed once, not on every lookup).
pub(crate) fn names() -> &'static NameTable {
    static TABLE: OnceLock<NameTable> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut by_hash = HashMap::with_capacity(NAMES.len());
        let mut by_name = HashMap::with_capacity(NAMES.len());
        for &name in NAMES {
            let hash = joaat(name);
            by_hash.entry(hash).or_insert(name); // first name wins on a collision
            by_name.insert(name, hash);
        }
        NameTable { by_hash, by_name }
    })
}

/// Readable name for a hash, if we know one.
pub(crate) fn lookup_name(hash: u32) -> Option<&'static str> {
    if hash == ARRAYINFO {
        Some("ARRAYINFO")
    } else {
        names().by_hash.get(&hash).copied()
    }
}

/// Readable name for a hash, or `h_xxxxxxxx` if unknown.
pub(crate) fn known(hash: u32) -> String {
    lookup_name(hash).map_or_else(|| format!("h_{hash:08x}"), str::to_owned)
}

/// Inverse of [`known`]: `ARRAYINFO`, `h_xxxxxxxx` / `m_xxxxxxxx`, a known name,
/// or any other string (which is hashed).
pub(crate) fn parse_tag(s: &str) -> u32 {
    if s == "ARRAYINFO" {
        return ARRAYINFO;
    }
    if let Some(hex) = s.strip_prefix("h_").or_else(|| s.strip_prefix("m_")) {
        if let Ok(v) = u32::from_str_radix(hex, 16) {
            return v;
        }
    }
    names().by_name.get(s).copied().unwrap_or_else(|| joaat(s))
}
