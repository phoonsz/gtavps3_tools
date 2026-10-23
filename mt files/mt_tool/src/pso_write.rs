//! Writer for PSO files (`PSIN` / `PMAP` / `PSCH`): the inverse of `pso.rs`.
//!
//! The input is the XML that `pso_to_xml` writes. That XML does not carry the schema,
//! so the schema, the root structure and the trailing sections come from a template PSO
//! of the target build (`--schema` on the command line). The template must be the same
//! kind of file as the output: a console `.cmt` template for a `.cmt` output, a PC `.ymt`
//! template for a `.ymt` output. The template's `PSCH` section is copied byte for byte.
//! Its `PSIG`, `STRE` and `CHKS` sections are copied too and are not recomputed, so any
//! checksum or signature in them no longer matches the new data.
//!
//! Layout, as the reader expects it:
//!   * `PSIN`: `PSIN`, big-endian length, `pppppppp` placeholder, then the data blocks.
//!     Each block starts on a 16-byte boundary. Block offsets are absolute file offsets.
//!   * Pointers: low 12 bits = 1-based block id, high 20 bits = offset inside the block.
//!     A block therefore holds at most 0xFFFFF bytes and there are at most 4095 blocks.
//!   * `PMAP`: root block id 1, then one 16-byte entry per block (name, offset, 0, length).
//!   * Arrays are contiguous elements in one block. Their header is the pointer, then the
//!     count twice (`u16`, `u16`) at `ptr_width`, as the reader reads them.
//!   * Every value is big-endian.
//!
//! Strings are written as the reader decodes them: ASCII only, since the reader maps
//! higher bytes to `?`. A hash field stores the Jenkins hash of the text it is given.

#![allow(dead_code)]

use std::collections::{HashMap, HashSet};

use crate::names;
use crate::pso::{
    block_by_id, fail, locate_sections, name_of, read_pmap, read_psch, Be, Field, EnumTable,
    PsoError, Res, StructDef, ARRAYINFO, MAX_DEPTH, TY_ARRAY, TY_BOOL, TY_ENUM, TY_FLAGS,
    TY_FLOAT, TY_SINT, TY_STRING, TY_STRUCT, TY_UBYTE, TY_UINT,
};

/// Largest offset a pointer can hold (20 bits), so the largest block.
const MAX_BLOCK_LEN: usize = 0xFFFFF;
/// Largest block id a pointer can hold (12 bits).
const MAX_BLOCKS: usize = 0xFFF;
/// Name used for the blocks that hold string data and string arrays.
const STRING_BLOCK: u32 = 0;
/// Placeholder bytes the reader's files carry in the PSIN and PMAP headers.
const PLACEHOLDER: [u8; 8] = *b"pppppppp";

/// Converts the XML written by `pso_to_xml` back into PSO bytes.
///
/// `template` is a PSO file of the target build; its schema, root structure and trailing
/// sections are used. `ptr_width` is 4 for console `.cmt` and 8 for PC `.ymt`. Every field
/// of the template must be present in the XML.
pub fn xml_to_pso(xml: &str, template: &[u8], ptr_width: usize) -> Res<Vec<u8>> {
    let doc = parse_xml(xml)?;
    encode_document(&doc, template, ptr_width)
}

/// What a merge did, for reporting.
#[derive(Default, Debug, Clone)]
pub struct MergeStats {
    /// Template fields replaced by a value from the source.
    pub overwritten: usize,
    /// Template fields the source does not have. They keep the template's value.
    pub kept: usize,
    /// Source fields the target build does not have. They are not written.
    pub dropped: usize,
    /// Array items matched by key and merged.
    pub items_matched: usize,
    /// Template items the source does not have. They are kept as they are.
    pub items_kept: usize,
    /// Source items added to the template because they have every template field.
    pub items_added: usize,
    /// Source items left out because they lack some template field.
    pub items_skipped: usize,
}

/// Writes the source data into the layout of a template PSO of the target build.
///
/// `template_xml` is the template decoded with its own pointer width (the output's width).
/// Each field of the template takes the source's value when the source has that field.
/// Fields that exist only in the template keep the template's value. Fields that exist only
/// in the source are dropped, since the target schema has no place for them. Array items are
/// matched by their first field. An item the source adds is written only if it has every
/// field of the template, so no empty fields are invented.
pub fn merge_to_pso(
    source_xml: &str,
    template_xml: &str,
    template: &[u8],
    ptr_width: usize,
) -> Res<(Vec<u8>, MergeStats)> {
    let source = parse_xml(source_xml)?;
    let base = parse_xml(template_xml)?;
    if source.name != base.name {
        return fail(format!(
            "source root <{}> does not match the template root <{}>",
            source.name, base.name
        ));
    }
    let mut stats = MergeStats::default();
    let merged = merge_node(&base, &source, &mut stats);
    let out = encode_document(&merged, template, ptr_width)?;
    Ok((out, stats))
}

fn encode_document(doc: &Node, template: &[u8], ptr_width: usize) -> Res<Vec<u8>> {
    if ptr_width != 4 && ptr_width != 8 {
        return fail(format!("unsupported pointer width {ptr_width}"));
    }
    let r = Be { d: template };
    let sections = locate_sections(&r)?;
    let (template_root, tblocks) = read_pmap(&r, sections.pmap)?;
    let (schema, enums) = read_psch(&r, sections.psch)?;
    let root_name = block_by_id(&tblocks, template_root)?.name;

    if doc.name != name_of(root_name) {
        return fail(format!(
            "root element <{}> does not match the template root <{}>",
            doc.name,
            name_of(root_name)
        ));
    }
    let root_len = match schema.get(&root_name) {
        Some(d) => d.length,
        None => return fail(format!("no schema for root {}", name_of(root_name))),
    };

    // The root is block 1 at offset 0. It is reserved first and filled in last, so the
    // data it points to can be appended after it.
    let mut enc = Encoder {
        schema: &schema,
        enums: &enums,
        ptr_width,
        blocks: vec![Out {
            name: root_name,
            data: vec![0; root_len],
        }],
        open: HashMap::from([(root_name, 0usize)]),
    };
    let root = enc.encode_struct(doc, root_name, 0)?;
    enc.blocks[0].data.copy_from_slice(&root);

    assemble(&enc.blocks, &template[sections.psch..])
}

/// Merges a source node into a template node (see [`merge_to_pso`]).
fn merge_node(base: &Node, over: &Node, st: &mut MergeStats) -> Node {
    // A leaf in the source (scalar, string, null pointer, empty array) overwrites the template.
    if over.children.is_empty() {
        st.overwritten += 1;
        return Node {
            name: base.name.clone(),
            attrs: over.attrs.clone(),
            text: over.text.clone(),
            children: Vec::new(),
        };
    }
    // The template has no data here. Nothing is invented from the source.
    if base.children.is_empty() {
        st.kept += 1;
        return base.clone();
    }

    let mut out = Node {
        name: base.name.clone(),
        attrs: base.attrs.clone(),
        text: String::new(),
        children: Vec::new(),
    };
    for (k, v) in &over.attrs {
        match out.attrs.iter_mut().find(|(bk, _)| bk == k) {
            Some(slot) => slot.1 = v.clone(),
            None => out.attrs.push((k.clone(), v.clone())),
        }
    }

    let is_array = base.children.iter().all(|c| c.name == "Item");
    if is_array {
        let sample = &base.children[0];
        let mut used = vec![false; over.children.len()];
        for (bidx, bi) in base.children.iter().enumerate() {
            // Items with a key match on it. Items without one (empty first field) match the
            // source item at the same position, if that one has no key either.
            let found = match item_key(bi) {
                Some(key) => over
                    .children
                    .iter()
                    .enumerate()
                    .find(|(j, o)| !used[*j] && item_key(o).as_deref() == Some(key.as_str())),
                None => over
                    .children
                    .get(bidx)
                    .filter(|o| !used[bidx] && item_key(o).is_none())
                    .map(|o| (bidx, o)),
            };
            match found {
                Some((j, o)) => {
                    used[j] = true;
                    st.items_matched += 1;
                    out.children.push(merge_node(bi, o, st));
                }
                None => {
                    st.items_kept += 1;
                    out.children.push(bi.clone());
                }
            }
        }
        for (j, o) in over.children.iter().enumerate() {
            if used[j] {
                continue;
            }
            if complete(o, sample) {
                st.items_added += 1;
                out.children.push(restrict(o, sample, st));
            } else {
                st.items_skipped += 1;
            }
        }
    } else {
        for bc in &base.children {
            match over.children.iter().find(|o| o.name == bc.name) {
                Some(oc) => out.children.push(merge_node(bc, oc, st)),
                None => {
                    st.kept += 1;
                    out.children.push(bc.clone());
                }
            }
        }
        st.dropped += over
            .children
            .iter()
            .filter(|o| !base.children.iter().any(|b| b.name == o.name))
            .count();
    }
    out
}

/// Key that matches array items across builds: the first field's text or value.
fn item_key(item: &Node) -> Option<String> {
    let first = item.children.first()?;
    if !first.children.is_empty() {
        return None;
    }
    let key = first.attr("value").unwrap_or(first.text.as_str());
    if key.is_empty() {
        None
    } else {
        Some(key.to_string())
    }
}

/// Drops the source fields that the template does not have, at every level (they cannot
/// be written to the target). Counted in `dropped`.
fn restrict(over: &Node, sample: &Node, st: &mut MergeStats) -> Node {
    let mut out = Node {
        name: over.name.clone(),
        attrs: over.attrs.clone(),
        text: over.text.clone(),
        children: Vec::new(),
    };
    for oc in &over.children {
        match sample.children.iter().find(|sc| sc.name == oc.name) {
            Some(sc) => out.children.push(restrict(oc, sc, st)),
            None => st.dropped += 1,
        }
    }
    out
}

/// True if `over` has every field that `sample` has, at each level where `sample` has data.
fn complete(over: &Node, sample: &Node) -> bool {
    sample.children.iter().all(|sc| {
        match over.children.iter().find(|o| o.name == sc.name) {
            None => false,
            Some(oc) => sc.children.is_empty() || (!oc.children.is_empty() && complete(oc, sc)),
        }
    })
}

// ============================================================================
// Output file
// ============================================================================

struct Out {
    name: u32,
    data: Vec<u8>,
}

fn align16(n: usize) -> usize {
    (n + 15) & !15
}

/// Writes `PSIN`, `PMAP` and the copied tail. The tail starts at the template's `PSCH`.
fn assemble(blocks: &[Out], tail: &[u8]) -> Res<Vec<u8>> {
    if blocks.len() > MAX_BLOCKS {
        return fail("too many data blocks for PSO pointers (max 4095)");
    }
    let mut out = Vec::new();
    out.extend_from_slice(b"PSIN");
    out.extend_from_slice(&[0; 4]); // length, patched below
    out.extend_from_slice(&PLACEHOLDER);

    let mut entries = Vec::with_capacity(blocks.len());
    for b in blocks {
        out.resize(align16(out.len()), 0);
        entries.push((b.name, out.len(), b.data.len()));
        out.extend_from_slice(&b.data);
    }
    let psin_len = u32::try_from(out.len()).map_err(|_| PsoError("PSIN too large".into()))?;
    out[4..8].copy_from_slice(&psin_len.to_be_bytes());

    // PMAP: tag, length, root id, entry count (i16), placeholder (i16), entries.
    let pmap_len = 16 + 16 * entries.len();
    out.extend_from_slice(b"PMAP");
    out.extend_from_slice(&(pmap_len as u32).to_be_bytes());
    out.extend_from_slice(&1u32.to_be_bytes());
    out.extend_from_slice(&(entries.len() as i16).to_be_bytes());
    out.extend_from_slice(&0x7070i16.to_be_bytes());
    for (name, ofs, len) in entries {
        out.extend_from_slice(&name.to_be_bytes());
        out.extend_from_slice(&(ofs as u32).to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(&(len as u32).to_be_bytes());
    }

    out.extend_from_slice(tail);
    Ok(out)
}

// ============================================================================
// Names and text
// ============================================================================

/// Hash of a name as the XML writes it: `hash_XXXXXXXX` is the raw value (the reader's
/// form for unknown names), anything else is hashed with the crate's hash.
fn hash_of(text: &str) -> u32 {
    if let Some(hex) = text.strip_prefix("hash_") {
        if hex.len() == 8 {
            if let Ok(v) = u32::from_str_radix(hex, 16) {
                return v;
            }
        }
    }
    names::joaat(text)
}

/// Bytes of a text value stored in a PSO string. Non-ASCII text cannot round-trip, since the
/// reader turns every byte above 127 into `?`, so it is refused.
fn ascii_text<'t>(text: &'t str, what: &str) -> Res<&'t [u8]> {
    if !text.is_ascii() || text.contains('\0') {
        return fail(format!("{what}: PSO strings are ASCII; cannot store {text:?}"));
    }
    Ok(text.as_bytes())
}

/// Writes `bytes` into `buf` at `at`. Fails if the write leaves the structure.
fn put(buf: &mut [u8], at: usize, bytes: &[u8]) -> Res<()> {
    match buf.get_mut(at..at + bytes.len()) {
        Some(dst) => {
            dst.copy_from_slice(bytes);
            Ok(())
        }
        None => fail(format!("field at {at:#x} lies outside its structure")),
    }
}

// ============================================================================
// XML input (the subset `pso_to_xml` writes)
// ============================================================================

#[derive(Default, Debug, Clone)]
struct Node {
    name: String,
    attrs: Vec<(String, String)>,
    /// Text of an element without child elements (already unescaped).
    text: String,
    children: Vec<Node>,
}

impl Node {
    fn attr(&self, key: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }
}

/// Parses the XML that `pso_to_xml` writes: elements, double-quoted attributes, text and
/// an optional `<?xml ...?>` declaration. Whitespace between child elements is ignored.
/// Returns the single root element.
fn parse_xml(src: &str) -> Res<Node> {
    struct Open {
        node: Node,
        raw: String,
    }

    let b = src.as_bytes();
    let mut stack = vec![Open {
        node: Node::default(),
        raw: String::new(),
    }];
    let mut i = 0usize;
    while i < b.len() {
        if b[i] != b'<' {
            let end = src[i..].find('<').map_or(b.len(), |p| i + p);
            stack.last_mut().expect("stack").raw.push_str(&src[i..end]);
            i = end;
            continue;
        }
        if src[i..].starts_with("<?") {
            let end = src[i..]
                .find("?>")
                .ok_or_else(|| PsoError("unterminated XML declaration".into()))?;
            i += end + 2;
            continue;
        }
        if src[i..].starts_with("</") {
            let end = src[i..]
                .find('>')
                .map(|p| i + p)
                .ok_or_else(|| PsoError("unterminated closing tag".into()))?;
            let name = src[i + 2..end].trim();
            if stack.len() < 2 {
                return fail(format!("closing tag </{name}> has no opening tag"));
            }
            let mut open = stack.pop().expect("stack");
            if open.node.name != name {
                return fail(format!(
                    "closing tag </{name}> does not match <{}>",
                    open.node.name
                ));
            }
            // Whitespace around child elements is layout, not data.
            if open.node.children.is_empty() {
                open.node.text = unescape(&open.raw)?;
            }
            stack.last_mut().expect("stack").node.children.push(open.node);
            i = end + 1;
            continue;
        }

        let (node, self_closing, next) = parse_start_tag(src, i)?;
        i = next;
        if self_closing {
            stack.last_mut().expect("stack").node.children.push(node);
        } else {
            stack.push(Open {
                node,
                raw: String::new(),
            });
        }
    }

    if stack.len() != 1 {
        return fail(format!("element <{}> is not closed", stack[stack.len() - 1].node.name));
    }
    let mut doc = stack.pop().expect("stack").node;
    if doc.children.len() != 1 {
        return fail("the XML must have exactly one root element");
    }
    Ok(doc.children.remove(0))
}

/// Parses `<name attr="v" ...>` or `<name ... />` starting at `i` (which is at `<`).
/// Returns the node, whether it is self-closing, and the position after the tag.
fn parse_start_tag(src: &str, i: usize) -> Res<(Node, bool, usize)> {
    let b = src.as_bytes();
    let mut p = i + 1;
    let name_start = p;
    while p < b.len() && !b[p].is_ascii_whitespace() && b[p] != b'/' && b[p] != b'>' {
        p += 1;
    }
    if p == name_start {
        return fail(format!("empty element name at byte {i}"));
    }
    let mut node = Node {
        name: src[name_start..p].to_string(),
        ..Node::default()
    };

    loop {
        while p < b.len() && b[p].is_ascii_whitespace() {
            p += 1;
        }
        match b.get(p) {
            None => return fail(format!("tag <{}> is not terminated", node.name)),
            Some(b'>') => return Ok((node, false, p + 1)),
            Some(b'/') if b.get(p + 1) == Some(&b'>') => return Ok((node, true, p + 2)),
            Some(_) => {}
        }
        let key_start = p;
        while p < b.len() && b[p] != b'=' && !b[p].is_ascii_whitespace() {
            p += 1;
        }
        let key = src[key_start..p].to_string();
        while p < b.len() && b[p].is_ascii_whitespace() {
            p += 1;
        }
        if b.get(p) != Some(&b'=') {
            return fail(format!("attribute {key} of <{}> has no value", node.name));
        }
        p += 1;
        while p < b.len() && b[p].is_ascii_whitespace() {
            p += 1;
        }
        if b.get(p) != Some(&b'"') {
            return fail(format!("attribute {key} of <{}> is not quoted", node.name));
        }
        p += 1;
        let val_start = p;
        let val_end = src[p..]
            .find('"')
            .map(|q| p + q)
            .ok_or_else(|| PsoError(format!("attribute {key} of <{}> is not closed", node.name)))?;
        node.attrs.push((key, unescape(&src[val_start..val_end])?));
        p = val_end + 1;
    }
}

/// Reverses `xml_escape` (and `&apos;`). Any other entity is an error.
fn unescape(s: &str) -> Res<String> {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(p) = rest.find('&') {
        out.push_str(&rest[..p]);
        let after = &rest[p..];
        let semi = after
            .find(';')
            .ok_or_else(|| PsoError(format!("unterminated entity in {s:?}")))?;
        let ch = match &after[1..semi] {
            "amp" => '&',
            "lt" => '<',
            "gt" => '>',
            "quot" => '"',
            "apos" => '\'',
            other => return fail(format!("unknown entity &{other};")),
        };
        out.push(ch);
        rest = &after[semi + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

// ============================================================================
// Encoder
// ============================================================================

struct Encoder<'a> {
    schema: &'a HashMap<u32, StructDef>,
    enums: &'a EnumTable,
    ptr_width: usize,
    blocks: Vec<Out>,
    /// For each block name, the block that new data with that name is appended to.
    open: HashMap<u32, usize>,
}

impl<'a> Encoder<'a> {
    /// Appends `bytes` to a block named `name` on a 16-byte boundary and returns the pointer.
    /// A new block is opened when the current one would overflow its offset range.
    fn alloc(&mut self, name: u32, bytes: &[u8]) -> Res<u32> {
        let fits = |blocks: &[Out], i: usize| {
            align16(blocks[i].data.len()) + bytes.len() <= MAX_BLOCK_LEN
        };
        let idx = match self.open.get(&name).copied() {
            Some(i) if fits(&self.blocks, i) => i,
            _ => {
                if bytes.len() > MAX_BLOCK_LEN {
                    return fail("one data object is larger than a block (1 MiB)");
                }
                if self.blocks.len() >= MAX_BLOCKS {
                    return fail("too many data blocks for PSO pointers (max 4095)");
                }
                self.blocks.push(Out {
                    name,
                    data: Vec::new(),
                });
                let i = self.blocks.len() - 1;
                self.open.insert(name, i);
                i
            }
        };
        let block = &mut self.blocks[idx];
        let ofs = align16(block.data.len());
        block.data.resize(ofs, 0);
        block.data.extend_from_slice(bytes);
        Ok((idx as u32 + 1) | ((ofs as u32) << 12))
    }

    /// Pointer to a NUL-terminated copy of `text`, or 0 for empty text (the reader's null).
    fn string_ptr(&mut self, text: &str, what: &str) -> Res<u32> {
        if text.is_empty() {
            return Ok(0);
        }
        let mut bytes = ascii_text(text, what)?.to_vec();
        bytes.push(0);
        self.alloc(STRING_BLOCK, &bytes)
    }

    /// Encodes one structure instance (the reader's `write_struct`) and returns its bytes.
    /// Pointed-to data is allocated as a side effect.
    fn encode_struct(&mut self, node: &Node, struct_name: u32, depth: usize) -> Res<Vec<u8>> {
        if depth > MAX_DEPTH {
            return fail("structure nesting is too deep");
        }
        // Copy the schema reference out of `self`, so field borrows do not block `self`.
        let schema = self.schema;
        let def = match schema.get(&struct_name) {
            Some(d) => d,
            None => return fail(format!("no schema for structure {}", name_of(struct_name))),
        };
        let sname = name_of(struct_name);

        let known: HashSet<String> = def
            .fields
            .iter()
            .filter(|f| f.name != ARRAYINFO)
            .map(|f| name_of(f.name))
            .collect();
        if let Some(bad) = node.children.iter().find(|c| !known.contains(&c.name)) {
            return fail(format!("unexpected element <{}> in <{sname}>", bad.name));
        }

        let mut buf = vec![0u8; def.length];
        for f in def.fields.iter() {
            if f.name == ARRAYINFO {
                continue;
            }
            let ename = name_of(f.name);
            let child = node
                .children
                .iter()
                .find(|c| c.name == ename)
                .ok_or_else(|| PsoError(format!("missing <{ename}> in <{sname}>")))?;
            let at = f.offset;
            let what = format!("{sname}.{ename}");
            self.encode_field(&mut buf, at, f, def, child, &sname, &what, depth)?;
        }
        Ok(buf)
    }

    #[allow(clippy::too_many_arguments)]
    fn encode_field(
        &mut self,
        buf: &mut [u8],
        at: usize,
        f: &Field,
        def: &StructDef,
        child: &Node,
        sname: &str,
        what: &str,
        depth: usize,
    ) -> Res<()> {
        let bad = |what: &str, v: &str| PsoError(format!("bad value {v:?} for {what}"));

        match f.ty {
            TY_ARRAY => {
                self.encode_array(buf, at, &def.fields, f.refkey, child, sname, what, depth)?;
            }
            TY_BOOL => {
                let v = match value_attr(child, what)? {
                    "true" => 1u8,
                    "false" => 0u8,
                    other => return Err(bad(what, other)),
                };
                put(buf, at, &[v])?;
            }
            TY_SINT => {
                let v = value_attr(child, what)?;
                let n: i32 = v.parse().map_err(|_| bad(what, v))?;
                put(buf, at, &n.to_be_bytes())?;
            }
            TY_UINT => {
                if f.unk != 0 {
                    return fail(format!("unsupported UInt subtype {} for {what}", f.unk));
                }
                // The reader prints this field as a signed value, so accept either range.
                let v = value_attr(child, what)?;
                let n: i64 = v.parse().map_err(|_| bad(what, v))?;
                if !(-(1i64 << 31)..(1i64 << 32)).contains(&n) {
                    return Err(bad(what, v));
                }
                put(buf, at, &(n as u32).to_be_bytes())?;
            }
            TY_FLOAT => {
                let v = value_attr(child, what)?;
                let n: f32 = v.parse().map_err(|_| bad(what, v))?;
                put(buf, at, &n.to_bits().to_be_bytes())?;
            }
            TY_UBYTE => {
                let v = value_attr(child, what)?;
                let n: u8 = v.parse().map_err(|_| bad(what, v))?;
                put(buf, at, &[n])?;
            }
            TY_STRUCT => match f.unk {
                0 => {
                    // Inline structure: its bytes sit in the parent at the field offset.
                    let inner = self.encode_struct(child, f.refkey, depth + 1)?;
                    put(buf, at, &inner)?;
                }
                3 | 4 => {
                    // Pointer. An element with no children is the null pointer.
                    let ptr = if child.children.is_empty() {
                        0
                    } else {
                        let block = match child.attr("type") {
                            Some(t) => hash_of(t),
                            None => f.refkey,
                        };
                        let inner = self.encode_struct(child, f.refkey, depth + 1)?;
                        self.alloc(block, &inner)?
                    };
                    put(buf, at, &ptr.to_be_bytes())?;
                }
                other => {
                    return fail(format!("unsupported structure subtype {other} for {what}"))
                }
            },
            TY_ENUM => {
                let vals = match self.enums.get(&f.refkey) {
                    Some(v) => v,
                    None => {
                        return fail(format!(
                            "no enum schema {} for {what}",
                            name_of(f.refkey)
                        ))
                    }
                };
                let key: i64 = if child.text.is_empty() {
                    // Empty text is a key with no name. Pick one the enum does not use.
                    let (mut k, max) = match f.unk {
                        0 => (i32::MIN as i64, i32::MAX as i64),
                        2 => (0, 255),
                        other => return fail(format!("unsupported Enum subtype {other} for {what}")),
                    };
                    while vals.iter().any(|(_, x)| *x as i64 == k) {
                        k += 1;
                        if k > max {
                            return fail(format!("no spare key for empty value in {what}"));
                        }
                    }
                    k
                } else {
                    let target = hash_of(&child.text);
                    match vals.iter().find(|(n, _)| *n == target) {
                        Some((_, x)) => *x as i64,
                        None => return fail(format!("unknown value {:?} for {what}", child.text)),
                    }
                };
                match f.unk {
                    0 => put(buf, at, &(key as i32).to_be_bytes())?,
                    2 => {
                        if !(0..=255).contains(&key) {
                            return fail(format!("enum key {key} does not fit a byte for {what}"));
                        }
                        put(buf, at, &[key as u8])?;
                    }
                    other => return fail(format!("unsupported Enum subtype {other} for {what}")),
                }
            }
            TY_FLAGS => {
                let width = match f.unk {
                    0 => 4usize,
                    1 => 2,
                    2 => 1,
                    other => return fail(format!("unsupported Flags subtype {other} for {what}")),
                };
                // The enum is named by the ARRAYINFO entry at `refkey & 0xFFF` (as the reader).
                let idx = (f.refkey & 0xFFF) as usize;
                let flags_enum = match def.fields.get(idx) {
                    Some(e) if idx != 0xFFF && e.name == ARRAYINFO => Some(e.refkey),
                    _ => None,
                };
                let mask: u32 = match flags_enum.and_then(|k| self.enums.get(&k)) {
                    Some(vals) => {
                        let mut m = 0u32;
                        for tok in child.text.split_whitespace() {
                            let target = hash_of(tok);
                            let (_, key) = vals
                                .iter()
                                .find(|(n, _)| *n == target)
                                .ok_or_else(|| PsoError(format!("unknown flag {tok:?} for {what}")))?;
                            m |= 1u32 << (*key as u32 & 31);
                        }
                        m
                    }
                    // Without an enum the reader writes the raw value, or nothing for zero.
                    None => match child.attr("value") {
                        Some(v) => v.parse::<u32>().map_err(|_| bad(what, v))?,
                        None => 0,
                    },
                };
                if width < 4 && mask >> (width * 8) != 0 {
                    return fail(format!("flags value {mask} does not fit {width} byte(s) for {what}"));
                }
                let bytes = mask.to_be_bytes();
                put(buf, at, &bytes[4 - width..])?;
            }
            TY_STRING => match f.unk {
                // Inline ASCII of a fixed length, padded with NUL bytes.
                0 => {
                    let len = ((f.refkey >> 16) & 0xFFFF) as usize;
                    let bytes = ascii_text(&child.text, what)?;
                    if bytes.len() > len {
                        return fail(format!(
                            "{:?} is longer than the {len}-byte field {what}",
                            child.text
                        ));
                    }
                    let mut field = vec![0u8; len];
                    field[..bytes.len()].copy_from_slice(bytes);
                    put(buf, at, &field)?;
                }
                // DataBlockPointer: a pointer to NUL-terminated text.
                1 | 2 => {
                    let ptr = self.string_ptr(&child.text, what)?;
                    put(buf, at, &ptr.to_be_bytes())?;
                }
                // CharPointer: pointer, Count1, Count2.
                3 => {
                    let ptr = self.string_ptr(&child.text, what)?;
                    let count = char_count(&child.text, what)?;
                    put(buf, at, &ptr.to_be_bytes())?;
                    put(buf, at + self.ptr_width, &count.to_be_bytes())?;
                    put(buf, at + self.ptr_width + 2, &count.to_be_bytes())?;
                }
                // Hash of the text.
                7 | 8 => {
                    let h = if child.text.is_empty() { 0 } else { hash_of(&child.text) };
                    put(buf, at, &h.to_be_bytes())?;
                }
                other => return fail(format!("unsupported String subtype {other} for {what}")),
            },
            other => {
                return fail(format!("unsupported field type 0x{other:02x} for {what}"));
            }
        }
        Ok(())
    }

    /// Writes an array field: pointer, then the count twice at `ptr_width` (the reader's
    /// layout). String arrays (subtypes 2, 3, 7, 8) and arrays of inline structures are
    /// supported, as in the reader.
    #[allow(clippy::too_many_arguments)]
    fn encode_array(
        &mut self,
        buf: &mut [u8],
        at: usize,
        fields: &[Field],
        refkey: u32,
        child: &Node,
        sname: &str,
        what: &str,
        depth: usize,
    ) -> Res<()> {
        // Same ARRAYINFO lookup as the reader: `refkey & 0xFFFF`, else `refkey & 0xFFF`.
        let mut idx = (refkey & 0xFFFF) as usize;
        if idx >= fields.len() {
            idx = (refkey & 0xFFF) as usize;
        }
        let info = match fields.get(idx) {
            Some(f) if f.name == ARRAYINFO => f,
            _ => return fail(format!("ARRAYINFO not found for {what} (owner {sname})")),
        };

        if let Some(bad) = child.children.iter().find(|c| c.name != "Item") {
            return fail(format!("unexpected element <{}> in array {what}", bad.name));
        }
        let items: Vec<&Node> = child.children.iter().collect();
        if items.len() > 0xFFFF {
            return fail(format!("array {what} has more than 65535 items"));
        }
        let count = items.len();

        let (ptr, count) = if count == 0 {
            (0u32, 0usize)
        } else if info.ty == TY_STRING && matches!(info.unk, 2 | 3 | 7 | 8) {
            let p = self.encode_string_array(info.unk, &items, what)?;
            (p, count)
        } else if info.ty == TY_STRUCT && info.unk == 0 {
            if let Some(t) = child.attr("itemType") {
                if hash_of(t) != info.refkey {
                    return fail(format!(
                        "itemType {t} does not match the schema for {what}"
                    ));
                }
            }
            let elem = info.refkey;
            let mut arr = Vec::new();
            for item in &items {
                arr.extend(self.encode_struct(item, elem, depth + 1)?);
            }
            (self.alloc(elem, &arr)?, count)
        } else {
            return fail(format!(
                "unsupported array element type 0x{:02x} (subtype {}) for {what}",
                info.ty, info.unk
            ));
        };

        let count16 = count as u16;
        put(buf, at, &ptr.to_be_bytes())?;
        put(buf, at + self.ptr_width, &count16.to_be_bytes())?;
        put(buf, at + self.ptr_width + 2, &count16.to_be_bytes())?;
        Ok(())
    }

    /// Element array for string subtypes 2 (DataBlockPointer), 3 (CharPointer) and 7/8 (hash).
    /// Stride matches the reader: `ptr_width`, `ptr_width + 8`, or 4.
    fn encode_string_array(&mut self, subtype: u8, items: &[&Node], what: &str) -> Res<u32> {
        let stride = match subtype {
            2 => self.ptr_width,
            3 => self.ptr_width + 8,
            _ => 4,
        };
        let mut arr = vec![0u8; items.len() * stride];
        for (n, item) in items.iter().enumerate() {
            if !item.children.is_empty() {
                return fail(format!("string item in {what} has child elements"));
            }
            let base = n * stride;
            let text = item.text.as_str();
            match subtype {
                2 => {
                    let p = self.string_ptr(text, what)?;
                    put(&mut arr, base, &p.to_be_bytes())?;
                }
                3 => {
                    let p = self.string_ptr(text, what)?;
                    let count = char_count(text, what)?;
                    put(&mut arr, base, &p.to_be_bytes())?;
                    put(&mut arr, base + self.ptr_width, &count.to_be_bytes())?;
                    put(&mut arr, base + self.ptr_width + 2, &count.to_be_bytes())?;
                }
                _ => {
                    let h = if text.is_empty() { 0 } else { hash_of(text) };
                    put(&mut arr, base, &h.to_be_bytes())?;
                }
            }
        }
        self.alloc(STRING_BLOCK, &arr)
    }
}

/// The `value` attribute of a scalar field element.
fn value_attr<'n>(child: &'n Node, what: &str) -> Res<&'n str> {
    child
        .attr("value")
        .ok_or_else(|| PsoError(format!("missing value attribute for {what}")))
}

/// Count1 for a CharPointer string: the byte length, checked against `u16`.
fn char_count(text: &str, what: &str) -> Res<u16> {
    ascii_text(text, what)?;
    u16::try_from(text.len()).map_err(|_| PsoError(format!("text too long for {what}")))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pso::{is_pso, pso_to_xml};

    fn sample(name: &str) -> Vec<u8> {
        let path = format!("{}/testdata/{name}", env!("CARGO_MANIFEST_DIR"));
        std::fs::read(&path).unwrap_or_else(|e| panic!("cannot read {path}: {e}"))
    }

    /// The XML line endings differ between a hand-edited file and the writer's output,
    /// so comparisons ignore carriage returns.
    fn norm(s: &str) -> String {
        s.replace('\r', "")
    }

    /// decode -> encode -> decode must give the same XML.
    fn roundtrip(name: &str, ptr: usize) -> Vec<u8> {
        let src = sample(name);
        let xml = pso_to_xml(&src, ptr).expect("decode source");
        let out = xml_to_pso(&xml, &src, ptr).expect("encode");
        assert!(is_pso(&out), "{name}: output is not a PSO file");
        let back = pso_to_xml(&out, ptr).expect("decode written file");
        assert_eq!(norm(&back), norm(&xml), "{name}: XML changed in the round trip");
        out
    }

    #[test]
    fn pc_ymt_round_trips() {
        roundtrip("1289182.ymt", 8);
    }

    #[test]
    fn console_cmt_round_trips() {
        roundtrip("1273368218.cmt", 4);
    }

    #[test]
    fn pc_peds_round_trips() {
        roundtrip("peds.ymt", 8);
    }

    #[test]
    fn console_peds_round_trips() {
        roundtrip("peds_console.cmt", 4);
    }

    #[test]
    fn edited_string_is_written() {
        let src = sample("peds.ymt");
        let xml = pso_to_xml(&src, 8).expect("decode");
        let edited = xml.replacen(">Player_One<", ">Player_Edit<", 1);
        assert_ne!(edited, xml, "the edit must change the XML");
        let out = xml_to_pso(&edited, &src, 8).expect("encode edited XML");
        let back = pso_to_xml(&out, 8).expect("decode");
        assert_eq!(norm(&back), norm(&edited));
    }

    #[test]
    fn missing_field_is_an_error() {
        let src = sample("peds.ymt");
        let xml = pso_to_xml(&src, 8).expect("decode");
        let broken = xml.replacen("   <hash_ACEC22BE>Player_One</hash_ACEC22BE>\r\n", "", 1);
        assert_ne!(broken, xml);
        let err = xml_to_pso(&broken, &src, 8).unwrap_err();
        assert!(err.0.contains("missing"), "unexpected error: {err}");
    }

    #[test]
    fn unknown_element_is_an_error() {
        let src = sample("peds.ymt");
        let xml = pso_to_xml(&src, 8).expect("decode");
        let broken = xml.replacen("\r\n  </Item>", "\r\n   <bogus />\r\n  </Item>", 1);
        let err = xml_to_pso(&broken, &src, 8).unwrap_err();
        assert!(err.0.contains("unexpected element"), "unexpected error: {err}");
    }

    #[test]
    fn wrong_root_is_an_error() {
        let src = sample("peds.ymt");
        let xml = pso_to_xml(&src, 8).expect("decode");
        let broken = xml.replacen("<hash_DD77771E>", "<hash_00000000>", 1);
        assert!(xml_to_pso(&broken, &src, 8).is_err());
    }

    #[test]
    fn non_ascii_text_is_refused() {
        let src = sample("peds.ymt");
        let xml = pso_to_xml(&src, 8).expect("decode");
        let broken = xml.replacen(">Player_One<", ">Pl\u{e1}yer<", 1);
        assert!(xml_to_pso(&broken, &src, 8).is_err());
    }

    /// Source data merged over a template of the other build: this is the case that failed
    /// with `missing <hash_B5FFF3AB>`. The PC-only field must not reach the console output.
    #[test]
    fn pc_data_merges_into_console_template_without_pc_only_fields() {
        let pc = sample("peds.ymt");
        let console = sample("peds_console.cmt");
        let src = pso_to_xml(&pc, 8).expect("decode pc");
        let base = pso_to_xml(&console, 4).expect("decode console template");
        let (out, st) = merge_to_pso(&src, &base, &console, 4).expect("merge");
        assert!(st.dropped > 0, "PC-only fields should be reported as dropped");
        let back = pso_to_xml(&out, 4).expect("decode merged");
        assert!(!back.contains("B5FFF3AB"), "PC-only field leaked into console output");
    }

    /// Console data merged over a PC template: the PC-only field keeps the template's value.
    #[test]
    fn console_data_merges_into_pc_template_keeping_pc_only_fields() {
        let pc = sample("peds.ymt");
        let console = sample("peds_console.cmt");
        let src = pso_to_xml(&console, 4).expect("decode console");
        let base = pso_to_xml(&pc, 8).expect("decode pc template");
        let (out, st) = merge_to_pso(&src, &base, &pc, 8).expect("merge");
        assert_eq!(st.dropped, 0);
        assert!(st.kept > 0, "template-only fields should be kept");
        let back = pso_to_xml(&out, 8).expect("decode merged");
        assert_eq!(
            back.matches("hash_B5FFF3AB").count(),
            base.matches("hash_B5FFF3AB").count(),
            "the PC-only field must keep the template's lines"
        );
    }

    /// Merging a file into itself changes nothing.
    #[test]
    fn merge_with_same_build_is_identity() {
        let src_bytes = sample("peds.ymt");
        let xml = pso_to_xml(&src_bytes, 8).expect("decode");
        let (out, _) = merge_to_pso(&xml, &xml, &src_bytes, 8).expect("merge");
        let back = pso_to_xml(&out, 8).expect("decode merged");
        assert_eq!(norm(&back), norm(&xml));
    }

    #[test]
    fn unescape_reverses_xml_escape() {
        assert_eq!(unescape("a&amp;b&lt;c&gt;&quot;d&apos;").unwrap(), "a&b<c>\"d'");
        assert!(unescape("&nbsp;").is_err());
    }
}
