//! Minimal XML parser and XML -> tree.

use std::collections::HashMap;

use crate::constants::{MAX_DEPTH, Res, is_array, is_pointer, ty};
use crate::names::parse_tag;
use crate::schema::Schema;
use crate::tree::{Field, Val};
use crate::xml_write::xml_unescape;

// ============================================================================
// Minimal XML parser
//
// Handles exactly what this tool reads and writes: elements, quoted attributes,
// comments and processing instructions. Text content is ignored.
// ============================================================================

pub(crate) struct XmlNode {
    pub(crate) tag: String,
    pub(crate) attrs: HashMap<String, String>,
    pub(crate) children: Vec<XmlNode>,
}

pub(crate) struct XmlParser<'a> {
    pub(crate) src: &'a [u8],
    pub(crate) pos: usize,
}

impl<'a> XmlParser<'a> {
    pub(crate) fn parse_document(text: &'a str) -> Res<XmlNode> {
        let mut p = XmlParser { src: text.as_bytes(), pos: 0 };
        p.skip_misc()?;
        p.parse_element(0)
    }

    pub(crate) fn peek(&self) -> Option<u8> {
        self.src.get(self.pos).copied()
    }

    pub(crate) fn starts_with(&self, pat: &[u8]) -> bool {
        self.src.get(self.pos..).is_some_and(|rest| rest.starts_with(pat))
    }

    pub(crate) fn skip_ws(&mut self) {
        while self.peek().is_some_and(|b| b.is_ascii_whitespace()) {
            self.pos += 1;
        }
    }

    /// Advances past the next occurrence of `pat`.
    pub(crate) fn skip_past(&mut self, pat: &[u8], what: &str) -> Res<()> {
        let rest = self.src.get(self.pos..).unwrap_or(&[]);
        match rest.windows(pat.len()).position(|w| w == pat) {
            Some(i) => {
                self.pos += i + pat.len();
                Ok(())
            }
            None => Err(format!("unterminated {what}")),
        }
    }

    /// Skips whitespace, comments and processing instructions.
    pub(crate) fn skip_misc(&mut self) -> Res<()> {
        loop {
            self.skip_ws();
            if self.starts_with(b"<!--") {
                self.pos += 4;
                self.skip_past(b"-->", "comment")?;
            } else if self.starts_with(b"<?") {
                self.pos += 2;
                self.skip_past(b"?>", "processing instruction")?;
            } else {
                return Ok(());
            }
        }
    }

    pub(crate) fn parse_name(&mut self) -> String {
        let start = self.pos;
        while self
            .peek()
            .is_some_and(|b| !b.is_ascii_whitespace() && !matches!(b, b'>' | b'/' | b'='))
        {
            self.pos += 1;
        }
        String::from_utf8_lossy(&self.src[start..self.pos]).into_owned()
    }

    pub(crate) fn parse_attr(&mut self, tag: &str) -> Res<(String, String)> {
        let name = self.parse_name();
        if name.is_empty() {
            return Err(format!("malformed attribute in <{tag}> at byte {}", self.pos));
        }
        self.skip_ws();
        if self.peek() != Some(b'=') {
            return Err(format!("expected '=' after attribute '{name}' in <{tag}>"));
        }
        self.pos += 1;
        self.skip_ws();
        let quote = match self.peek() {
            Some(q @ (b'"' | b'\'')) => q,
            _ => return Err(format!("expected a quoted value for '{name}' in <{tag}>")),
        };
        self.pos += 1;
        let start = self.pos;
        while self.peek().is_some_and(|b| b != quote) {
            self.pos += 1;
        }
        if self.peek().is_none() {
            return Err(format!("unterminated value for '{name}' in <{tag}>"));
        }
        let raw = String::from_utf8_lossy(&self.src[start..self.pos]);
        self.pos += 1;
        Ok((name, xml_unescape(&raw)))
    }

    pub(crate) fn parse_element(&mut self, depth: usize) -> Res<XmlNode> {
        if depth > MAX_DEPTH * 2 {
            return Err(format!("XML nested deeper than {} levels", MAX_DEPTH * 2));
        }
        if self.peek() != Some(b'<') {
            return Err(format!("expected '<' at byte {}", self.pos));
        }
        self.pos += 1;
        let tag = self.parse_name();

        let mut attrs = HashMap::new();
        loop {
            self.skip_ws();
            match self.peek() {
                None => return Err(format!("unexpected end of file inside <{tag}>")),
                Some(b'/') => {
                    self.pos += 1;
                    if self.peek() != Some(b'>') {
                        return Err(format!("expected '>' after '/' in <{tag}>"));
                    }
                    self.pos += 1;
                    return Ok(XmlNode { tag, attrs, children: Vec::new() });
                }
                Some(b'>') => {
                    self.pos += 1;
                    break;
                }
                Some(_) => {
                    let (k, v) = self.parse_attr(&tag)?;
                    attrs.insert(k, v);
                }
            }
        }

        let mut children = Vec::new();
        loop {
            while self.peek().is_some_and(|b| b != b'<') {
                self.pos += 1; // text content is ignored
            }
            if self.peek().is_none() {
                return Err(format!("unclosed tag <{tag}>"));
            }
            if self.starts_with(b"<!--") || self.starts_with(b"<?") {
                self.skip_misc()?;
            } else if self.starts_with(b"</") {
                self.pos += 2;
                let close = self.parse_name();
                self.skip_ws();
                if self.peek() != Some(b'>') {
                    return Err(format!("malformed closing tag </{close}>"));
                }
                self.pos += 1;
                if close != tag {
                    return Err(format!("mismatched closing tag </{close}> (expected </{tag}>)"));
                }
                return Ok(XmlNode { tag, attrs, children });
            } else {
                children.push(self.parse_element(depth + 1)?);
            }
        }
    }
}

// ============================================================================
// XML -> tree
// ============================================================================

/// Parses `0x…` or bare hex.
pub(crate) fn parse_hex_u64(s: &str) -> Option<u64> {
    let s = s.trim();
    let digits = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    u64::from_str_radix(digits, 16).ok()
}

pub(crate) fn parse_hex_attr(s: &str) -> Option<u32> {
    parse_hex_u64(s).and_then(|v| u32::try_from(v).ok())
}

/// First present attribute among `keys` (long names are accepted as aliases).
pub(crate) fn attr<'a>(n: &'a XmlNode, keys: &[&str]) -> Option<&'a str> {
    keys.iter().find_map(|k| n.attrs.get(*k).map(String::as_str))
}

pub(crate) fn hex_attr(n: &XmlNode, keys: &[&str]) -> Option<u32> {
    attr(n, keys).and_then(parse_hex_attr)
}

pub(crate) fn is_item_tag(tag: &str) -> bool {
    tag == "i" || tag == "Item"
}

pub(crate) fn child<'a>(n: &'a XmlNode, tag: &str) -> Res<&'a XmlNode> {
    n.children
        .iter()
        .find(|c| c.tag == tag)
        .ok_or_else(|| format!("missing <{tag}>"))
}

/// Decimal or `0x` hexadecimal integer with optional sign.
pub(crate) fn parse_integer(s: &str) -> Option<i128> {
    let s = s.trim();
    let (neg, digits) = match s.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, s.strip_prefix('+').unwrap_or(s)),
    };
    if digits.starts_with(|c: char| c == '+' || c == '-') {
        return None;
    }
    let value = match digits.strip_prefix("0x").or_else(|| digits.strip_prefix("0X")) {
        Some(hex) => i128::from_str_radix(hex, 16).ok()?,
        None => digits.parse::<i128>().ok()?,
    };
    Some(if neg { -value } else { value })
}

pub(crate) fn parse_int<T: TryFrom<i128>>(s: &str, what: &str) -> Res<T> {
    parse_integer(s)
        .and_then(|v| T::try_from(v).ok())
        .ok_or_else(|| format!("invalid {what} value '{s}'"))
}

/// A 32-bit number, or a name that is hashed (`h_xxxxxxxx` and known names included).
pub(crate) fn parse_u32_or_tag(s: &str) -> Res<u32> {
    match parse_integer(s) {
        Some(n) => u32::try_from(n).map_err(|_| format!("value '{s}' does not fit in 32 bits")),
        None => Ok(parse_tag(s)),
    }
}

pub(crate) fn parse_f32(s: &str) -> Res<f32> {
    s.parse().map_err(|_| format!("invalid float '{s}'"))
}

pub(crate) fn parse_floats<const N: usize>(s: &str) -> Res<[f32; N]> {
    let mut out = [0.0f32; N];
    let mut parts = s.split_whitespace();
    for slot in &mut out {
        let part = parts.next().ok_or_else(|| format!("expected {N} floats in '{s}'"))?;
        *slot = parse_f32(part)?;
    }
    if parts.next().is_some() {
        return Err(format!("expected {N} floats in '{s}'"));
    }
    Ok(out)
}

/// The value an empty `v=""` attribute stands for.
pub(crate) fn zero_value(t: u8) -> Val {
    match t {
        ty::BOOL => Val::Bool(false),
        ty::I8 => Val::I8(0),
        ty::U8 | ty::U8_ALT => Val::U8(0),
        ty::I16 => Val::I16(0),
        ty::U16 | ty::U16_ALT => Val::U16(0),
        ty::I32 | ty::I32_ALT => Val::I32(0),
        ty::U32 | ty::U32_ALT | ty::U32_ALT2 => Val::U32(0),
        ty::F32 => Val::F32(0.0),
        ty::VEC3 => Val::Vec3(0.0, 0.0, 0.0),
        ty::VEC4 => Val::Vec4(0.0, 0.0, 0.0, 0.0),
        ty::HASH => Val::Hash(0),
        _ => Val::Null,
    }
}

/// Parses an attribute value as scalar type `t`; malformed input is an error rather
/// than a silent zero.
pub(crate) fn parse_scalar(t: u8, text: &str) -> Res<Val> {
    let s = text.trim();
    if s.is_empty() {
        return Ok(zero_value(t));
    }
    Ok(match t {
        ty::BOOL => match s.to_ascii_lowercase().as_str() {
            "true" | "1" => Val::Bool(true),
            "false" | "0" => Val::Bool(false),
            _ => return Err(format!("invalid bool '{s}'")),
        },
        ty::I8 => Val::I8(parse_int(s, "i8")?),
        ty::U8 | ty::U8_ALT => Val::U8(parse_int(s, "u8")?),
        ty::I16 => Val::I16(parse_int(s, "i16")?),
        ty::U16 | ty::U16_ALT => Val::U16(parse_int(s, "u16")?),
        ty::I32 | ty::I32_ALT => Val::I32(parse_int(s, "i32")?),
        ty::U32 | ty::U32_ALT | ty::U32_ALT2 => Val::U32(parse_u32_or_tag(s)?),
        ty::F32 => Val::F32(parse_f32(s)?),
        ty::VEC3 => {
            let [x, y, z] = parse_floats::<3>(s)?;
            Val::Vec3(x, y, z)
        }
        ty::VEC4 => {
            let [x, y, z, w] = parse_floats::<4>(s)?;
            Val::Vec4(x, y, z, w)
        }
        ty::HASH => Val::Hash(parse_u32_or_tag(s)?),
        _ => Val::Null,
    })
}

pub(crate) fn node_to_fields(
    node: &XmlNode,
    schema: &Schema,
    struct_hash: u32,
    depth: usize,
) -> Res<Vec<Field>> {
    if depth > MAX_DEPTH {
        return Err(format!("XML nested deeper than {MAX_DEPTH} levels at <{}>", node.tag));
    }
    let def = schema.structs.get(&struct_hash);
    let mut fields = Vec::with_capacity(node.children.len());

    for c in &node.children {
        if c.tag.starts_with('_') || is_item_tag(&c.tag) {
            continue;
        }

        let name = hex_attr(c, &["h", "hash"]).unwrap_or_else(|| parse_tag(&c.tag));
        let entry = def.and_then(|d| d.entries.iter().find(|e| e.name == name));

        let f_ty = hex_attr(c, &["t", "type"])
            .and_then(|v| u8::try_from(v).ok())
            .or_else(|| entry.map(|e| e.ty))
            .unwrap_or(ty::I32);
        let mut key = hex_attr(c, &["k", "key"])
            .or_else(|| entry.map(|e| e.key))
            .unwrap_or(0);
        let ptr = match attr(c, &["p", "ptr"]).and_then(parse_hex_u64) {
            Some(p) => Some(p),
            None if is_pointer(f_ty) => Some(0),
            None => None,
        };

        let ctx = |e: String| format!("{e} (in <{}>)", c.tag);
        let val = if matches!(attr(c, &["null"]), Some("true" | "1")) {
            Val::Null
        } else if is_array(f_ty) || c.children.iter().any(|ch| is_item_tag(&ch.tag)) {
            // Element type: explicit attributes win, then the schema's ARRAYINFO.
            let known_elem = def.and_then(|d| d.arrays.get(&name).copied());
            let attr_et = hex_attr(c, &["i", "itemType"]).and_then(|v| u8::try_from(v).ok());
            let attr_ek = hex_attr(c, &["e", "elemKey"]);
            let (et, ek) = match (attr_et, attr_ek) {
                (Some(t), Some(k)) => (t, k),
                (Some(t), None) => (t, known_elem.map_or(0, |(_, k)| k)),
                (None, Some(k)) => (known_elem.map_or(ty::STRUCT, |(t, _)| t), k),
                (None, None) => known_elem.unwrap_or((ty::STRUCT, 0)),
            };

            let mut items = Vec::new();
            for item in c.children.iter().filter(|ch| is_item_tag(&ch.tag)) {
                items.push(if let Some(v) = attr(item, &["v", "value"]) {
                    parse_scalar(et, v).map_err(ctx)?
                } else if !item.children.is_empty() {
                    Val::Struct(node_to_fields(item, schema, ek, depth + 1)?)
                } else {
                    Val::Null
                });
            }
            Val::Array { elem_ty: et, elem_key: ek, items }
        } else if c.children.iter().any(|ch| !ch.tag.starts_with('_')) {
            let inner_hash = hex_attr(c, &["s", "struct"])
                .or_else(|| entry.map(|e| e.key))
                .unwrap_or(0);
            if key == 0 {
                key = inner_hash; // the struct hash doubles as the field key
            }
            Val::Struct(node_to_fields(c, schema, inner_hash, depth + 1)?)
        } else if let Some(v) = attr(c, &["v", "value"]) {
            parse_scalar(f_ty, v).map_err(ctx)?
        } else {
            Val::Null
        };

        fields.push(Field { name, ty: f_ty, key, val, ptr });
    }
    Ok(fields)
}

pub(crate) fn hex_to_bytes<const N: usize>(s: &str) -> Option<[u8; N]> {
    let b = s.as_bytes();
    if b.len() != N * 2 || !b.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    let mut out = [0u8; N];
    for (slot, pair) in out.iter_mut().zip(b.chunks_exact(2)) {
        *slot = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(out)
}
