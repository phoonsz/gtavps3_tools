//! Tree -> XML.

use std::fmt::Write as _;

use crate::constants::{OUTER_LEN, Res};
use crate::names::{known, lookup_name};
use crate::platform::Layout;
use crate::schema::{Block, Schema};
use crate::tree::{Field, Struct, Val};
use crate::patch::{body_to_chunks, chunks_to_xml};

// ============================================================================
// Tree -> XML
// ============================================================================

pub(crate) fn format_scalar(v: &Val) -> String {
    match v {
        Val::Bool(x) => x.to_string(),
        Val::I8(x) => x.to_string(),
        Val::U8(x) => x.to_string(),
        Val::I16(x) => x.to_string(),
        Val::U16(x) => x.to_string(),
        Val::I32(x) => x.to_string(),
        Val::U32(x) => x.to_string(),
        Val::F32(x) => x.to_string(),
        Val::Hash(x) => known(*x),
        Val::Vec3(a, b, c) => format!("{a} {b} {c}"),
        Val::Vec4(a, b, c, d) => format!("{a} {b} {c} {d}"),
        Val::Null | Val::Struct(_) | Val::Array { .. } => String::new(),
    }
}

pub(crate) fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            _ => out.push(c),
        }
    }
    out
}

pub(crate) fn xml_unescape(s: &str) -> String {
    if !s.contains('&') {
        return s.to_owned();
    }
    // `&amp;` must be last so that "&amp;lt;" decodes to "&lt;", not "<".
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

/// Emits `fields` of struct `struct_hash`, one XML element per field, indented by
/// two spaces per `depth`.
///
/// Fields known to the schema carry no type information in the XML; unknown ones get
/// explicit `t`/`s`/`i`/`e` attributes, and fields without a known name use `<f h="…">`.
pub(crate) fn emit_fields(out: &mut String, fields: &[Field], depth: usize, schema: &Schema, struct_hash: u32) {
    let pad = "  ".repeat(depth);
    let def = schema.structs.get(&struct_hash);

    for f in fields {
        let entry = def.and_then(|d| d.entries.iter().find(|e| e.name == f.name));
        let in_schema = entry.is_some();
        let name = lookup_name(f.name);
        let tag = name.unwrap_or("f");

        let mut attrs = String::new();
        if name.is_none() {
            wr!(attrs, " h=\"0x{:08x}\"", f.name);
        }
        if !in_schema {
            wr!(attrs, " t=\"0x{:02x}\"", f.ty);
        }
        if let Some(p) = f.ptr.filter(|&p| p != 0) {
            wr!(attrs, " p=\"0x{p:x}\"");
        }

        match &f.val {
            Val::Struct(inner) => {
                let inner_hash = entry.map_or(f.key, |e| e.key);
                if !in_schema {
                    wr!(attrs, " s=\"0x{inner_hash:08x}\"");
                }
                wrln!(out, "{pad}<{tag}{attrs}>");
                emit_fields(out, inner, depth + 1, schema, inner_hash);
                wrln!(out, "{pad}</{tag}>");
            }
            Val::Array { elem_ty, elem_key, items } => {
                let (et, ek) = def
                    .and_then(|d| d.arrays.get(&f.name).copied())
                    .unwrap_or((*elem_ty, *elem_key));
                if !in_schema {
                    wr!(attrs, " i=\"0x{et:02x}\"");
                    if ek != 0 {
                        wr!(attrs, " e=\"0x{ek:08x}\"");
                    }
                }
                wrln!(out, "{pad}<{tag}{attrs}>");
                for item in items {
                    match item {
                        Val::Struct(inner) => {
                            wrln!(out, "{pad}  <i>");
                            emit_fields(out, inner, depth + 2, schema, ek);
                            wrln!(out, "{pad}  </i>");
                        }
                        Val::Null => wrln!(out, "{pad}  <i/>"),
                        scalar => {
                            wrln!(out, "{pad}  <i v=\"{}\"/>", xml_escape(&format_scalar(scalar)));
                        }
                    }
                }
                wrln!(out, "{pad}</{tag}>");
            }
            Val::Null => wrln!(out, "{pad}<{tag}{attrs} null=\"true\"/>"),
            scalar => {
                wrln!(out, "{pad}<{tag}{attrs} v=\"{}\"/>", xml_escape(&format_scalar(scalar)));
            }
        }
    }
}

// ============================================================================
// Whole document -> XML
// ============================================================================

pub(crate) fn tree_to_xml(
    root: &Struct,
    schema: &Schema,
    blocks: &[Block],
    root_block_idx: usize,
    lay: Layout,
    outer: &[u8; OUTER_LEN],
    body: &[u8],
) -> Res<String> {
    let mut out = String::with_capacity(body.len() * 2 + 4096);
    let tag = known(root.hash);
    let outer_hex: String = outer.iter().map(|b| format!("{b:02x}")).collect();

    out.push_str("<?xml version=\"1.0\"?>\n");
    wrln!(
        out,
        "<{tag} layout=\"{}\" header=\"{outer_hex}\" rootBlock=\"{}\" sTable=\"0x{:x}\" \
         eTable=\"0x{:x}\" bTable=\"0x{:x}\">",
        lay.name(),
        root_block_idx + 1,
        schema.struct_table_off,
        schema.enum_table_off,
        schema.block_table_off
    );

    wrln!(out, "  <_Schema>");
    for hash in &schema.struct_order {
        let def = &schema.structs[hash];
        wrln!(out, "    <Struct h=\"0x{hash:08x}\" z=\"0x{:x}\" et=\"0x{:x}\">", def.size, def.entry_off);
        for e in &def.entries {
            let name_attr = lookup_name(e.name).map_or(String::new(), |n| format!(" name=\"{n}\""));
            wrln!(
                out,
                "      <F h=\"0x{:08x}\"{name_attr} o=\"0x{:x}\" t=\"0x{:02x}\" k=\"0x{:08x}\"/>",
                e.name,
                e.off,
                e.ty,
                e.key
            );
        }
        wrln!(out, "    </Struct>");
    }
    wrln!(out, "  </_Schema>");

    wrln!(out, "  <_Enums>");
    for hash in &schema.enum_order {
        let vals_off = schema.enum_val_off.get(hash).copied().unwrap_or(0);
        wrln!(out, "    <Enum h=\"0x{hash:08x}\" ev=\"0x{vals_off:x}\">");
        for (key, value) in schema.enums.get(hash).into_iter().flatten() {
            wrln!(out, "      <V h=\"0x{key:08x}\" num=\"{value}\"/>");
        }
        wrln!(out, "    </Enum>");
    }
    wrln!(out, "  </_Enums>");

    wrln!(out, "  <_Blocks>");
    for b in blocks {
        wrln!(out, "    <Block hash=\"0x{:08x}\" size=\"0x{:x}\"/>", b.name, b.data.len());
    }
    wrln!(out, "  </_Blocks>");

    wrln!(out, "  <_Tree>");
    emit_fields(&mut out, &root.fields, 2, schema, root.hash);
    wrln!(out, "  </_Tree>");

    let chunks = body_to_chunks(body, blocks, root_block_idx)?;
    chunks_to_xml(&mut out, &chunks, body.len(), blocks);

    wrln!(out, "</{tag}>");
    Ok(out)
}
