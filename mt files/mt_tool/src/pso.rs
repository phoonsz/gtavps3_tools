//! Reader for PSO-format (`PSIN` / `PMAP` / `PSCH` / ...) `.ymt` files.
//!
//! This is a port of CodeWalker's read path:
//!   * `Pso.cs` — `PsoFile.Load`, `PsoDataMapSection`, `PsoSchemaSection`,
//!     `PsoStructureInfo`, `PsoStructureEntryInfo`.
//!   * `MetaXml.cs` (`PsoXml`) — `GetXml`, `WriteNode`, `WriteArrayNode`.
//!
//! Every PSO section is big-endian, including `PMAP`, `PSCH` and the values
//! inside `PSIN`. CodeWalker reads all of them with `Endianess.BigEndian`.
//! The byte order does not depend on the file extension.
//!
//! Decoded: Bool, SInt, UInt (signed display, as CodeWalker does), Float,
//! inline structures, pointer structures, and arrays of inline structures.
//! Any other field type fails the conversion with an error that names the
//! structure and field. It does not guess.

#![allow(dead_code)]

use std::collections::HashMap;
use std::fmt;
use std::sync::OnceLock;

use crate::names;

const TAG_PSIN: [u8; 4] = *b"PSIN";
const TAG_PMAP: [u8; 4] = *b"PMAP";
const TAG_PSCH: [u8; 4] = *b"PSCH";

/// `MetaTypeName.ARRAYINFO`: a pseudo field placed before an array that names its element type.
pub(crate) const ARRAYINFO: u32 = 0x0000_0100;

pub(crate) const TY_BOOL: u8 = 0x00;
pub(crate) const TY_UBYTE: u8 = 0x02;
pub(crate) const TY_SINT: u8 = 0x05;
pub(crate) const TY_UINT: u8 = 0x06;
pub(crate) const TY_FLOAT: u8 = 0x07;
pub(crate) const TY_STRING: u8 = 0x0B;
pub(crate) const TY_STRUCT: u8 = 0x0C;
pub(crate) const TY_ARRAY: u8 = 0x0D;
pub(crate) const TY_ENUM: u8 = 0x0E;
pub(crate) const TY_FLAGS: u8 = 0x0F;

pub(crate) const MAX_DEPTH: usize = 64;

/// Names used by the PSO occlusion metadata, taken from CodeWalker's `MetaNames.cs`.
/// Hashes that are not in this table or in the crate's name table are written as
/// `hash_XXXXXXXX`, which matches CodeWalker's output.
const PSO_NAMES: &[&str] = &[
    "naOcclusionInteriorMetadata",
    "naOcclusionPortalInfoMetadata",
    "naOcclusionPortalEntityMetadata",
    "naOcclusionPathNodeMetadata",
    "naOcclusionPathNodeChildMetadata",
    "PortalInfoList",
    "PathNodeList",
    "InteriorProxyHash",
    "PortalIdx",
    "RoomIdx",
    "DestInteriorHash",
    "DestRoomIdx",
    "PortalEntityList",
    "PathNodeChildList",
    "PortalInfoIdx",
    "PathNodeKey",
    "Key",
    "LinkType",
    "MaxOcclusion",
    "EntityModelHashkey",
    "IsDoor",
    "IsGlass",
];

// ============================================================================
// Errors
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PsoError(pub String);

impl fmt::Display for PsoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for PsoError {}

pub(crate) type Res<T> = Result<T, PsoError>;

pub(crate) fn fail<T>(msg: impl Into<String>) -> Res<T> {
    Err(PsoError(msg.into()))
}

// ============================================================================
// Public API
// ============================================================================

/// True if `data` begins with a PSO `PSIN` section.
pub fn is_pso(data: &[u8]) -> bool {
    data.len() >= 4 && data[..4] == TAG_PSIN[..]
}

/// Converts a PSO byte buffer to XML in CodeWalker's layout (CRLF line endings).
///
/// `ptr_width` is the platform pointer width in bytes: 8 for PC `.ymt`, 4 for console
/// `.cmt`. It sets where an array's count sits inside its 8- or 16-byte header.
pub fn pso_to_xml(data: &[u8], ptr_width: usize) -> Res<String> {
    if ptr_width != 4 && ptr_width != 8 {
        return fail(format!("unsupported pointer width {ptr_width}"));
    }
    let r = Be { d: data };
    let sections = locate_sections(&r)?;
    let (root_id, blocks) = read_pmap(&r, sections.pmap)?;
    let (schema, enums) = read_psch(&r, sections.psch)?;
    let root_name = block_by_id(&blocks, root_id)?.name;

    let mut dec = Decoder {
        r,
        blocks,
        schema,
        enums,
        ptr_width,
        out: String::new(),
    };
    dec.out
        .push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n");
    dec.write_struct(0, root_id, 0, root_name, Mode::Structure, 0)?;
    Ok(dec.out)
}

// ============================================================================
// Big-endian reader with bounds checks
// ============================================================================

#[derive(Clone, Copy)]
pub(crate) struct Be<'a> {
    pub(crate) d: &'a [u8],
}

impl<'a> Be<'a> {
    fn bytes(&self, at: usize, n: usize) -> Res<&'a [u8]> {
        let d: &'a [u8] = self.d;
        let end = match at.checked_add(n) {
            Some(e) => e,
            None => return fail(format!("offset overflow at {at:#x}")),
        };
        match d.get(at..end) {
            Some(s) => Ok(s),
            None => fail(format!(
                "read of {n} bytes at {at:#x} runs past end of file ({:#x})",
                self.d.len()
            )),
        }
    }

    fn u8_at(&self, at: usize) -> Res<u8> {
        Ok(self.bytes(at, 1)?[0])
    }

    fn u16_at(&self, at: usize) -> Res<u16> {
        let b = self.bytes(at, 2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn i16_at(&self, at: usize) -> Res<i16> {
        Ok(self.u16_at(at)? as i16)
    }

    fn u32_at(&self, at: usize) -> Res<u32> {
        let b = self.bytes(at, 4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn i32_at(&self, at: usize) -> Res<i32> {
        Ok(self.u32_at(at)? as i32)
    }

    fn f32_at(&self, at: usize) -> Res<f32> {
        Ok(f32::from_bits(self.u32_at(at)?))
    }
}

// ============================================================================
// Sections, data map (PMAP) and schema (PSCH)
// ============================================================================

#[derive(Default)]
pub(crate) struct Sections {
    pub(crate) psin: Option<usize>,
    pub(crate) pmap: usize,
    pub(crate) psch: usize,
}

/// Walks the top-level sections the way `PsoFile.Load` does: tag, big-endian length, next.
pub(crate) fn locate_sections(r: &Be) -> Res<Sections> {
    let mut psin = None;
    let mut pmap = None;
    let mut psch = None;

    let mut p = 0usize;
    while p + 8 <= r.d.len() {
        let t = r.bytes(p, 4)?;
        if !t.iter().all(|&c| (32..127).contains(&c)) {
            break;
        }
        let tag = [t[0], t[1], t[2], t[3]];
        let len = r.u32_at(p + 4)? as usize;
        if len < 8 || len > r.d.len() - p {
            return fail(format!("section at {p:#x} has invalid length {len:#x}"));
        }
        if tag == TAG_PSIN {
            psin.get_or_insert(p);
        } else if tag == TAG_PMAP {
            pmap.get_or_insert(p);
        } else if tag == TAG_PSCH {
            psch.get_or_insert(p);
        }
        p += len;
    }

    let psin = match psin {
        Some(p) => p,
        None => return fail("no PSIN section found"),
    };
    if psin != 0 {
        // Block offsets are file offsets here, which only holds when PSIN is first.
        return fail("PSIN section is not at file offset 0");
    }
    Ok(Sections {
        psin: Some(psin),
        pmap: pmap.ok_or_else(|| PsoError("no PMAP section found".into()))?,
        psch: psch.ok_or_else(|| PsoError("no PSCH section found".into()))?,
    })
}

#[derive(Clone, Copy)]
pub(crate) struct Block {
    pub(crate) name: u32,
    pub(crate) offset: usize,
    pub(crate) length: usize,
}

/// Reads `PMAP`: ident, length, root id, entry count (i16), unknown (i16), then 16-byte entries.
/// If the count is not positive, CodeWalker reads a second count at +16 and skips 8 bytes.
pub(crate) fn read_pmap(r: &Be, base: usize) -> Res<(u32, Vec<Block>)> {
    let root_id = r.u32_at(base + 8)?;
    let mut count = r.i16_at(base + 12)?;
    let mut first = base + 16;
    if count <= 0 {
        count = r.i16_at(base + 16)?;
        first = base + 24;
    }
    if count < 0 {
        return fail("PMAP entry count is negative");
    }

    let mut blocks = Vec::with_capacity(count as usize);
    for i in 0..count as usize {
        let q = first + i * 16;
        blocks.push(Block {
            name: r.u32_at(q)?,
            offset: r.u32_at(q + 4)? as usize,
            length: r.u32_at(q + 12)? as usize,
        });
    }
    Ok((root_id, blocks))
}

/// 1-based block lookup, as `PsoFile.GetBlock` does.
pub(crate) fn block_by_id(blocks: &[Block], id: u32) -> Res<&Block> {
    if id == 0 || id as usize > blocks.len() {
        return fail(format!(
            "block id {id} is out of range (valid 1..={})",
            blocks.len()
        ));
    }
    Ok(&blocks[id as usize - 1])
}

#[derive(Clone)]
pub(crate) struct Field {
    pub(crate) name: u32,
    pub(crate) ty: u8,
    pub(crate) unk: u8,
    pub(crate) offset: usize,
    pub(crate) refkey: u32,
}

#[derive(Clone)]
pub(crate) struct StructDef {
    pub(crate) length: usize,
    pub(crate) fields: Vec<Field>,
}

/// Enum schema: `enum name hash -> [(value name hash, key)]`, in schema order.
pub(crate) type EnumTable = HashMap<u32, Vec<(u32, i32)>>;

/// Reads `PSCH`: ident, length, count, then `count` × (name, offset) pairs.
/// Offsets are relative to the start of the PSCH section.
/// A structure is `u32 type<<24 | unk<<16 | count`, `i32 length`, `u32 unk`,
/// then `count` × 12-byte fields: name, type, unk, offset (u16), refkey.
/// An enum (kind 1) is `u32 1<<24 | count` followed by `count` × (name, key).
pub(crate) fn read_psch(r: &Be, base: usize) -> Res<(HashMap<u32, StructDef>, EnumTable)> {
    let count = r.u32_at(base + 8)? as usize;
    let mut structs = HashMap::with_capacity(count);
    let mut enums = EnumTable::new();

    for i in 0..count {
        let idx = base + 12 + i * 8;
        let name = r.u32_at(idx)?;
        let eo = r.i32_at(idx + 4)?;
        if eo < 0 {
            return fail(format!("schema entry {name:08X} has a negative offset"));
        }
        let at = base + eo as usize;

        let header = r.u32_at(at)?;
        match (header >> 24) as u8 {
            0 => {
                let n = (header & 0xFFFF) as usize;
                let length = r.i32_at(at + 4)?;
                if length < 0 {
                    return fail(format!("schema entry {name:08X} has a negative length"));
                }
                let mut fields = Vec::with_capacity(n);
                for j in 0..n {
                    let q = at + 12 + j * 12;
                    fields.push(Field {
                        name: r.u32_at(q)?,
                        ty: r.u8_at(q + 4)?,
                        unk: r.u8_at(q + 5)?,
                        offset: r.u16_at(q + 6)? as usize,
                        refkey: r.u32_at(q + 8)?,
                    });
                }
                structs.insert(
                    name,
                    StructDef {
                        length: length as usize,
                        fields,
                    },
                );
            }
            1 => {
                let n = (header & 0x00FF_FFFF) as usize;
                let mut vals = Vec::with_capacity(n);
                for j in 0..n {
                    let q = at + 4 + j * 8;
                    vals.push((r.u32_at(q)?, r.i32_at(q + 4)?));
                }
                enums.insert(name, vals);
            }
            kind => {
                return fail(format!("schema entry {name:08X} has unknown kind {kind}"));
            }
        }
    }
    Ok((structs, enums))
}

// ============================================================================
// Names
// ============================================================================

/// Readable name for a hash. Uses the PSO table, then the crate's name table,
/// then `hash_XXXXXXXX`.
pub(crate) fn name_of(hash: u32) -> String {
    static PSO_TABLE: OnceLock<HashMap<u32, &'static str>> = OnceLock::new();
    let table = PSO_TABLE.get_or_init(|| {
        PSO_NAMES
            .iter()
            .map(|&n| (names::joaat(n), n))
            .collect()
    });
    if let Some(n) = table.get(&hash) {
        return (*n).to_string();
    }
    if let Some(n) = names::names().by_hash.get(&hash) {
        return (*n).to_string();
    }
    format!("hash_{hash:08X}")
}

// ============================================================================
// XML generation (CodeWalker `PsoXml.WriteNode` / `WriteArrayNode`)
// ============================================================================

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Open and close the structure with its own name, as the root and named structures do.
    Structure,
    /// Open and close with `<Item>`, as array elements do.
    Item,
    /// No tag of its own. The caller has already written the enclosing element.
    Inline,
}

struct Decoder<'a> {
    r: Be<'a>,
    blocks: Vec<Block>,
    schema: HashMap<u32, StructDef>,
    enums: EnumTable,
    ptr_width: usize,
    out: String,
}

/// XML text escaping as CodeWalker does it (`XmlEscape`): `&`, `<`, `>` and `"`.
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// ASCII decoding as `Encoding.ASCII` does it: bytes above 127 become `?`.
fn ascii(bytes: &[u8]) -> String {
    bytes
        .iter()
        .filter(|&&b| b != 0)
        .map(|&b| if b > 127 { '?' } else { b as char })
        .collect()
}

impl<'a> Decoder<'a> {
    fn line(&mut self, indent: usize, text: &str) {
        for _ in 0..indent {
            self.out.push(' ');
        }
        self.out.push_str(text);
        self.out.push_str("\r\n");
    }

    /// `<name>text</name>`, or `<name />` when the text is empty (CodeWalker's `StringTag`).
    fn text_tag(&mut self, indent: usize, name: &str, text: &str) {
        if text.is_empty() {
            self.line(indent, &format!("<{name} />"));
        } else {
            self.line(indent, &format!("<{name}>{text}</{name}>"));
        }
    }

    /// Absolute file offset, block length and in-block offset of a block pointer.
    /// `None` for a null or out-of-range block id (CodeWalker's `GetBlock` returns null).
    fn block_target(&self, ptr: u32) -> Option<(usize, usize, usize)> {
        let bid = (ptr & 0xFFF) as usize;
        let ofs = ((ptr >> 12) & 0xFFFFF) as usize;
        if bid == 0 || bid > self.blocks.len() {
            return None;
        }
        let b = &self.blocks[bid - 1];
        Some((b.offset + ofs, b.length, ofs))
    }

    /// `DataBlockPointer` string: read up to the first NUL byte (CodeWalker `GetString`).
    fn cstring_at(&self, ptr: u32) -> Res<Option<String>> {
        let Some((mut at, _, _)) = self.block_target(ptr) else {
            return Ok(None);
        };
        let mut bytes = Vec::new();
        loop {
            let b = self.r.u8_at(at)?;
            if b == 0 {
                break;
            }
            bytes.push(b);
            at += 1;
        }
        Ok(Some(ascii(&bytes)))
    }

    /// `CharPointer` string: `Count1` bytes, or `min(Count1, Count2)` when `Count2` is set
    /// (CodeWalker `GetString(CharPointer)`). `None` when the range leaves the block.
    fn counted_string_at(&self, ptr: u32, count1: u16, count2: u16) -> Res<Option<String>> {
        if count1 == 0 {
            return Ok(None);
        }
        let Some((at, blen, ofs)) = self.block_target(ptr) else {
            return Ok(None);
        };
        let len = if count2 != 0 { count1.min(count2) } else { count1 } as usize;
        if ofs + len >= blen {
            return Ok(None);
        }
        Ok(Some(ascii(self.r.bytes(at, len)?)))
    }

    /// Writes one structure instance. `offset` is relative to the start of block `block_id`.
    fn write_struct(
        &mut self,
        indent: usize,
        block_id: u32,
        offset: usize,
        struct_name: u32,
        mode: Mode,
        depth: usize,
    ) -> Res<()> {
        if depth > MAX_DEPTH {
            return fail("structure nesting is too deep");
        }
        let block_offset = block_by_id(&self.blocks, block_id)?.offset;
        let base = block_offset + offset;

        let def = match self.schema.get(&struct_name) {
            Some(d) => d.clone(),
            None => {
                return fail(format!(
                    "no schema for structure {}",
                    name_of(struct_name)
                ))
            }
        };
        let sname = name_of(struct_name);

        match mode {
            Mode::Structure => self.line(indent, &format!("<{sname}>")),
            Mode::Item => self.line(indent, "<Item>"),
            Mode::Inline => {}
        }

        let cind = indent + 1;
        for f in def.fields.iter() {
            if f.name == ARRAYINFO {
                continue;
            }
            let ename = name_of(f.name);
            let eoff = base + f.offset;

            match f.ty {
                TY_ARRAY => {
                    self.write_array(cind, eoff, &def.fields, f.refkey, &ename, &sname, depth)?;
                }
                TY_BOOL => {
                    let v = self.r.u8_at(eoff)? != 0;
                    let text = if v { "true" } else { "false" };
                    self.line(cind, &format!("<{ename} value=\"{text}\" />"));
                }
                TY_SINT => {
                    let v = self.r.i32_at(eoff)?;
                    self.line(cind, &format!("<{ename} value=\"{v}\" />"));
                }
                TY_UINT => {
                    if f.unk != 0 {
                        return fail(format!(
                            "unsupported UInt subtype {} for {sname}.{ename}",
                            f.unk
                        ));
                    }
                    // CodeWalker writes subtype 0 as a signed value.
                    let v = self.r.i32_at(eoff)?;
                    self.line(cind, &format!("<{ename} value=\"{v}\" />"));
                }
                TY_FLOAT => {
                    let v = self.r.f32_at(eoff)?;
                    self.line(cind, &format!("<{ename} value=\"{v}\" />"));
                }
                TY_STRUCT => match f.unk {
                    0 => {
                        // Inline structure: `<name>` with the fields directly inside.
                        self.line(cind, &format!("<{ename}>"));
                        self.write_struct(
                            cind,
                            block_id,
                            offset + f.offset,
                            f.refkey,
                            Mode::Inline,
                            depth + 1,
                        )?;
                        self.line(cind, &format!("</{ename}>"));
                    }
                    3 | 4 => {
                        // Pointer: u32 at the field. Low 12 bits = 1-based block id, next 20 = offset.
                        let ptr = self.r.u32_at(eoff)?;
                        let pbid = ptr & 0xFFF;
                        let pofs = ((ptr >> 12) & 0xFFFFF) as usize;
                        if pbid != 0 && (pbid as usize) <= self.blocks.len() {
                            let tname = name_of(self.blocks[pbid as usize - 1].name);
                            self.line(cind, &format!("<{ename} type=\"{tname}\">"));
                            self.write_struct(
                                cind,
                                pbid,
                                pofs,
                                f.refkey,
                                Mode::Inline,
                                depth + 1,
                            )?;
                            self.line(cind, &format!("</{ename}>"));
                        } else {
                            self.line(cind, &format!("<{ename} />"));
                        }
                    }
                    other => {
                        return fail(format!(
                            "unsupported structure subtype {other} for {sname}.{ename}"
                        ))
                    }
                },
                TY_UBYTE => {
                    let v = self.r.u8_at(eoff)?;
                    self.line(cind, &format!("<{ename} value=\"{v}\" />"));
                }
                TY_ENUM => {
                    // Subtype 0: signed 32-bit key. Subtype 2: byte key.
                    let key: i64 = match f.unk {
                        0 => self.r.i32_at(eoff)? as i64,
                        2 => self.r.u8_at(eoff)? as i64,
                        other => {
                            return fail(format!(
                                "unsupported Enum subtype {other} for {sname}.{ename}"
                            ))
                        }
                    };
                    let vals = self.enums.get(&f.refkey).ok_or_else(|| {
                        PsoError(format!(
                            "no enum schema {} for {sname}.{ename}",
                            name_of(f.refkey)
                        ))
                    })?;
                    // An unknown key gives an empty name, as CodeWalker's HashString(0) does.
                    let text = vals
                        .iter()
                        .find(|(_, k)| *k as i64 == key)
                        .map(|(n, _)| name_of(*n))
                        .unwrap_or_default();
                    self.text_tag(cind, &ename, &text);
                }
                TY_FLAGS => {
                    // Subtypes 0, 1, 2: 32-, 16- and 8-bit masks.
                    let fv: u32 = match f.unk {
                        0 => self.r.u32_at(eoff)?,
                        1 => self.r.u16_at(eoff)? as u32,
                        2 => self.r.u8_at(eoff)? as u32,
                        other => {
                            return fail(format!(
                                "unsupported Flags subtype {other} for {sname}.{ename}"
                            ))
                        }
                    };
                    // The enum is named by the ARRAYINFO entry at `refkey & 0xFFF` (CodeWalker).
                    let idx = (f.refkey & 0xFFF) as usize;
                    let flags_enum = match def.fields.get(idx) {
                        Some(e) if idx != 0xFFF && e.name == ARRAYINFO => Some(e.refkey),
                        _ => None,
                    };
                    match flags_enum.and_then(|k| self.enums.get(&k)) {
                        Some(vals) => {
                            // CodeWalker tests `1 << key`, and C# masks shift counts to 5 bits.
                            let names: Vec<String> = vals
                                .iter()
                                .filter(|(_, k)| fv & (1u32 << (*k as u32 & 31)) != 0)
                                .map(|(n, _)| name_of(*n))
                                .collect();
                            self.text_tag(cind, &ename, &names.join(" "));
                        }
                        None if fv != 0 => {
                            self.line(cind, &format!("<{ename} value=\"{fv}\" />"));
                        }
                        None => self.line(cind, &format!("<{ename} />")),
                    }
                }
                TY_STRING => {
                    let text: Option<String> = match f.unk {
                        // Inline ASCII; the length is the high 16 bits of the reference key.
                        0 => {
                            let len = ((f.refkey >> 16) & 0xFFFF) as usize;
                            Some(ascii(self.r.bytes(eoff, len)?))
                        }
                        // DataBlockPointer: NUL-terminated text in a block.
                        1 | 2 => {
                            let ptr = self.r.u32_at(eoff)?;
                            self.cstring_at(ptr)?
                        }
                        // CharPointer: pointer, Count1, Count2.
                        3 => {
                            let ptr = self.r.u32_at(eoff)?;
                            let c1 = self.r.u16_at(eoff + self.ptr_width)?;
                            let c2 = self.r.u16_at(eoff + self.ptr_width + 2)?;
                            self.counted_string_at(ptr, c1, c2)?
                        }
                        // Hash of the string, resolved through the name table.
                        7 | 8 => {
                            let h = self.r.u32_at(eoff)?;
                            Some(if h == 0 { String::new() } else { name_of(h) })
                        }
                        other => {
                            return fail(format!(
                                "unsupported String subtype {other} for {sname}.{ename}"
                            ))
                        }
                    };
                    let escaped = xml_escape(text.as_deref().unwrap_or(""));
                    self.text_tag(cind, &ename, &escaped);
                }
                other => {
                    return fail(format!(
                        "unsupported field type 0x{other:02x} for {sname}.{ename}"
                    ))
                }
            }
        }

        match mode {
            Mode::Structure => self.line(indent, &format!("</{sname}>")),
            Mode::Item => self.line(indent, "</Item>"),
            Mode::Inline => {}
        }
        Ok(())
    }

    /// Array of strings (CodeWalker `WriteStringItemArray`): one `<Item>` per element, on
    /// its own line. Elements are pointers: `DataBlockPointer` (subtype 2) or
    /// `CharPointer` (subtype 3). Escaped here, unlike CodeWalker, which leaves them raw.
    fn write_string_array(
        &mut self,
        indent: usize,
        field_at: usize,
        ename: &str,
        owner: &str,
        subtype: u8,
    ) -> Res<()> {
        let ptr = self.r.u32_at(field_at)?;
        let count = self.r.u16_at(field_at + self.ptr_width)? as usize;
        if count == 0 {
            self.line(indent, &format!("<{ename} />"));
            return Ok(());
        }
        let Some((base, _, _)) = self.block_target(ptr) else {
            return fail(format!("string array block not found for {owner}.{ename}"));
        };
        // DataBlockPointer is one pointer; CharPointer adds Count1, Count2 and an unknown u32.
        // Hash elements are plain u32 values.
        let stride = match subtype {
            2 => self.ptr_width,
            3 => self.ptr_width + 8,
            _ => 4,
        };

        self.line(indent, &format!("<{ename}>"));
        for n in 0..count {
            let at = base + n * stride;
            let text = match subtype {
                2 => {
                    let elem_ptr = self.r.u32_at(at)?;
                    self.cstring_at(elem_ptr)?.unwrap_or_default()
                }
                3 => {
                    let elem_ptr = self.r.u32_at(at)?;
                    let c1 = self.r.u16_at(at + self.ptr_width)?;
                    let c2 = self.r.u16_at(at + self.ptr_width + 2)?;
                    self.counted_string_at(elem_ptr, c1, c2)?.unwrap_or_default()
                }
                _ => {
                    let h = self.r.u32_at(at)?;
                    if h == 0 { String::new() } else { name_of(h) }
                }
            };
            self.line(indent + 1, &format!("<Item>{}</Item>", xml_escape(&text)));
        }
        self.line(indent, &format!("</{ename}>"));
        Ok(())
    }

    /// Array field: a block pointer at `field_at`, then `u16 count`, `u16 count2`.
    /// The count sits right after the pointer, so it is at `+ptr_width`: +8 on PC
    /// (8-byte pointer, 16-byte header) and +4 on console (4-byte pointer, 8-byte header).
    /// The element type comes from the ARRAYINFO entry that `refkey` points to.
    fn write_array(
        &mut self,
        indent: usize,
        field_at: usize,
        fields: &[Field],
        refkey: u32,
        ename: &str,
        owner: &str,
        depth: usize,
    ) -> Res<()> {
        let ptr = self.r.u32_at(field_at)?;
        let count = self.r.u16_at(field_at + self.ptr_width)? as usize;

        // CodeWalker: index = refkey & 0xFFFF, falling back to refkey & 0xFFF when out of range.
        let mut idx = (refkey & 0xFFFF) as usize;
        if idx >= fields.len() {
            idx = (refkey & 0xFFF) as usize;
        }
        let info = match fields.get(idx) {
            Some(f) => f,
            None => return fail(format!("ARRAYINFO index out of range for {owner}.{ename}")),
        };
        if info.name != ARRAYINFO {
            return fail(format!("ARRAYINFO not found for {owner}.{ename}"));
        }
        // String arrays: subtype 2 holds DataBlockPointers, subtype 3 holds CharPointers,
        // subtypes 7 and 8 hold 32-bit name hashes.
        if info.ty == TY_STRING && matches!(info.unk, 2 | 3 | 7 | 8) {
            return self.write_string_array(indent, field_at, ename, owner, info.unk);
        }
        if info.ty != TY_STRUCT || info.unk != 0 {
            return fail(format!(
                "unsupported array element type 0x{:02x} (subtype {}) for {owner}.{ename}",
                info.ty, info.unk
            ));
        }

        let elem = info.refkey;
        let elem_name = name_of(elem);

        // An empty array needs no element schema (CodeWalker looks it up only when count > 0).
        if count == 0 {
            self.line(indent, &format!("<{ename} itemType=\"{elem_name}\" />"));
            return Ok(());
        }

        let elem_len = match self.schema.get(&elem) {
            Some(d) => d.length,
            None => {
                return fail(format!(
                    "no schema for array element {} in {owner}.{ename}",
                    name_of(elem)
                ))
            }
        };

        self.line(indent, &format!("<{ename} itemType=\"{elem_name}\">"));
        let abid = ptr & 0xFFF;
        let aofs = ((ptr >> 12) & 0xFFFFF) as usize;
        for n in 0..count {
            self.write_struct(
                indent + 1,
                abid,
                aofs + n * elem_len,
                elem,
                Mode::Item,
                depth + 1,
            )?;
        }
        self.line(indent, &format!("</{ename}>"));
        Ok(())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(name: &str) -> Vec<u8> {
        let path = format!("{}/testdata/{name}", env!("CARGO_MANIFEST_DIR"));
        std::fs::read(&path).unwrap_or_else(|e| panic!("cannot read {path}: {e}"))
    }

    /// PC `.ymt` sample. The expected file is a regression snapshot written by this
    /// implementation. It was NOT produced by CodeWalker, so it only guards against changes.
    #[test]
    fn pc_ymt_sample_matches_snapshot() {
        let ymt = sample("1289182.ymt");
        assert!(is_pso(&ymt));
        let got = pso_to_xml(&ymt, 8).expect("decode 1289182.ymt");
        let want = std::fs::read_to_string(format!(
            "{}/testdata/1289182_ymt_pso.xml",
            env!("CARGO_MANIFEST_DIR")
        ))
        .expect("read snapshot");
        assert_eq!(got, want, "output differs from the snapshot");
    }

    /// Console `.cmt` sample: arrays have 4-byte pointers, so counts sit at +4.
    /// The counts were checked against the raw bytes (11 portals, 32 path nodes).
    #[test]
    fn console_cmt_sample_has_expected_counts() {
        let cmt = sample("1273368218.cmt");
        assert!(is_pso(&cmt));
        let got = pso_to_xml(&cmt, 4).expect("decode 1273368218.cmt");
        assert!(!got.contains("rror"), "unexpected error element in output");
        // Lists are children of the root (1 space); their items sit at 2 spaces.
        // Nested items are indented further, so they are not counted here.
        let portals = got.split("\r\n <PortalInfoList").nth(1).unwrap_or("");
        let portals = portals.split("\r\n <PathNodeList").next().unwrap_or("");
        let nodes = got.split("\r\n <PathNodeList").nth(1).unwrap_or("");
        assert_eq!(portals.matches("\r\n  <Item>").count(), 11);
        assert_eq!(nodes.matches("\r\n  <Item>").count(), 32);
    }

    #[test]
    fn escapes_xml_text_like_codewalker() {
        assert_eq!(xml_escape("a&b<c>\"d'"), "a&amp;b&lt;c&gt;&quot;d'");
        assert_eq!(xml_escape("&amp;"), "&amp;amp;");
    }

    #[test]
    fn ascii_drops_nul_and_maps_high_bytes() {
        assert_eq!(ascii(b"ab\0c"), "abc");
        assert_eq!(ascii(&[0x41, 0xE9]), "A?");
    }

    /// PC `.ymt` with enums, flags, UByte and strings (`peds`). Checked for decoding
    /// and for readable string values; there is no CodeWalker reference for it yet.
    #[test]
    fn pc_peds_sample_decodes_strings_and_enums() {
        let peds = sample("peds.ymt");
        assert!(is_pso(&peds));
        let got = pso_to_xml(&peds, 8).expect("decode peds.ymt");
        assert!(got.contains(">Player_One<"), "expected a readable string value");
        assert!(got.contains(">comp_peds_generic<"));
        assert!(!got.contains("rror"), "unexpected error element");
    }

    #[test]
    fn rejects_non_pso() {
        assert!(!is_pso(b"RSC7 not pso"));
        assert!(pso_to_xml(b"RSC7 not pso", 8).is_err());
    }

    #[test]
    fn rejects_bad_pointer_width() {
        assert!(pso_to_xml(&sample("1289182.ymt"), 2).is_err());
    }
}
