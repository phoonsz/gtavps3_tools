//! Same-layout round trips: the body index ("chunks") and patching the tree into the original body.

use std::collections::HashMap;
use std::fmt::Write as _;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;

use crate::util::{checked_range, table_range};
use crate::constants::{ARRAYINFO, BLOCK_REC, ENTRY_REC, ENUM_REC, ENUM_VAL, HEADER_LEN, MAX_DEPTH, Res, STRUCT_REC, SYSTEM_BASE, scalar_size, ty};
use crate::names::known;
use crate::platform::{Layout, put_enum_count};
use crate::schema::{Block, Schema, decode_ptr};
use crate::tree::{Field, Struct, Val};
use crate::rebuild::write_scalar;
use crate::xml_read::{XmlNode, parse_hex_attr};

// ============================================================================
// Body index ("chunks")
//
// For same-layout round trips the XML carries a map of the original body so that
// bytes the tree cannot express (padding, unknown data, other blocks) survive.
// ============================================================================

#[derive(Clone, Debug)]
pub(crate) enum Chunk {
    /// The first `HEADER_LEN` bytes.
    Header(Vec<u8>),
    /// Everything between the header and the first block (schema tables).
    Tables { off: usize, size: usize, data: Vec<u8> },
    /// A non-root data block, stored verbatim.
    Block { idx: usize, off: usize, size: usize, data: Vec<u8> },
    /// The root block; rebuilt from the tree.
    Root { idx: usize, off: usize, size: usize },
    /// Non-zero bytes between blocks.
    Gap { off: usize, size: usize, data: Vec<u8> },
    /// Zero bytes (not stored).
    Pad { off: usize, size: usize },
    /// Non-zero bytes after the last block.
    Suffix { off: usize, size: usize, data: Vec<u8> },
}

impl Chunk {
    pub(crate) fn size(&self) -> usize {
        match self {
            Chunk::Header(d) => d.len(),
            Chunk::Tables { size, .. }
            | Chunk::Block { size, .. }
            | Chunk::Root { size, .. }
            | Chunk::Gap { size, .. }
            | Chunk::Pad { size, .. }
            | Chunk::Suffix { size, .. } => *size,
        }
    }
}

/// Zero-filled regions become `Pad`; anything else is kept as `Gap` / `Suffix`.
pub(crate) fn filler_chunk(body: &[u8], start: usize, end: usize, is_tail: bool) -> Chunk {
    let data = &body[start..end];
    let size = end - start;
    if data.iter().all(|&b| b == 0) {
        Chunk::Pad { off: start, size }
    } else if is_tail {
        Chunk::Suffix { off: start, size, data: data.to_vec() }
    } else {
        Chunk::Gap { off: start, size, data: data.to_vec() }
    }
}

pub(crate) fn body_to_chunks(body: &[u8], blocks: &[Block], root_block_idx: usize) -> Res<Vec<Chunk>> {
    if body.len() < HEADER_LEN {
        return Err(format!("body is shorter than the {HEADER_LEN:#x}-byte header"));
    }
    let mut chunks = vec![Chunk::Header(body[..HEADER_LEN].to_vec())];

    // Walk the blocks in physical order.
    let mut order: Vec<(usize, usize)> =
        blocks.iter().enumerate().map(|(i, b)| (b.off, i)).collect();
    order.sort_unstable();

    // Tables = everything between the header and the first block.
    let first = order.first().map_or(body.len(), |&(off, _)| off);
    if first < HEADER_LEN {
        return Err("a data block overlaps the header".into());
    }
    if first > HEADER_LEN {
        chunks.push(Chunk::Tables {
            off: HEADER_LEN,
            size: first - HEADER_LEN,
            data: body[HEADER_LEN..first].to_vec(),
        });
    }

    let mut cursor = first;
    for (off, idx) in order {
        if off < cursor {
            return Err(format!("block {} overlaps the previous region", idx + 1));
        }
        if off > cursor {
            chunks.push(filler_chunk(body, cursor, off, false));
        }
        let size = blocks[idx].data.len();
        chunks.push(if idx == root_block_idx {
            Chunk::Root { idx, off, size }
        } else {
            Chunk::Block { idx, off, size, data: blocks[idx].data.clone() }
        });
        cursor = off + size;
    }
    if cursor < body.len() {
        chunks.push(filler_chunk(body, cursor, body.len(), true));
    }
    Ok(chunks)
}

pub(crate) fn chunks_to_xml(out: &mut String, chunks: &[Chunk], total: usize, blocks: &[Block]) {
    let block_name = |idx: usize| blocks.get(idx).map_or(0, |b| b.name);

    wrln!(out, "  <_Body totalSize=\"0x{total:x}\" regions=\"{}\">", chunks.len());
    wrln!(out, "    <!-- layout index; content is rebuilt from schema + tree -->");
    for c in chunks {
        match c {
            Chunk::Header(d) => {
                wrln!(
                    out,
                    "    <Header offset=\"0x0\" size=\"0x{:x}\" data=\"{}\"/>",
                    d.len(),
                    B64.encode(d)
                );
            }
            Chunk::Tables { off, size, data } => {
                wrln!(
                    out,
                    "    <Tables offset=\"0x{off:x}\" size=\"0x{size:x}\" data=\"{}\"/>",
                    B64.encode(data)
                );
            }
            Chunk::Block { idx, off, size, data } => {
                let h = block_name(*idx);
                wrln!(
                    out,
                    "    <Block idx=\"{idx}\" hash=\"0x{h:08x}\" name=\"{}\" offset=\"0x{off:x}\" \
                     size=\"0x{size:x}\" data=\"{}\"/>",
                    known(h),
                    B64.encode(data)
                );
            }
            Chunk::Root { idx, off, size } => {
                let h = block_name(*idx);
                wrln!(
                    out,
                    "    <Root idx=\"{idx}\" hash=\"0x{h:08x}\" name=\"{}\" offset=\"0x{off:x}\" \
                     size=\"0x{size:x}\"/>",
                    known(h)
                );
            }
            Chunk::Gap { off, size, data } => {
                wrln!(
                    out,
                    "    <Gap offset=\"0x{off:x}\" size=\"0x{size:x}\" data=\"{}\"/>",
                    B64.encode(data)
                );
            }
            Chunk::Pad { off, size } => {
                wrln!(out, "    <Pad offset=\"0x{off:x}\" size=\"0x{size:x}\"/>");
            }
            Chunk::Suffix { off, size, data } => {
                wrln!(
                    out,
                    "    <Suffix offset=\"0x{off:x}\" size=\"0x{size:x}\" data=\"{}\"/>",
                    B64.encode(data)
                );
            }
        }
    }
    wrln!(out, "  </_Body>");
}

pub(crate) fn chunks_from_xml(node: &XmlNode) -> Res<Vec<Chunk>> {
    // Required attribute helpers.
    let hex = |c: &XmlNode, key: &str| -> Res<usize> {
        let s = c
            .attrs
            .get(key)
            .ok_or_else(|| format!("<{}> is missing '{key}'", c.tag))?;
        parse_hex_attr(s)
            .map(|v| v as usize)
            .ok_or_else(|| format!("<{}> has an invalid {key}=\"{s}\"", c.tag))
    };
    let data = |c: &XmlNode, size: usize| -> Res<Vec<u8>> {
        let s = c
            .attrs
            .get("data")
            .ok_or_else(|| format!("<{}> is missing 'data'", c.tag))?;
        let bytes = B64
            .decode(s)
            .map_err(|e| format!("<{}> has invalid base64: {e}", c.tag))?;
        if bytes.len() != size {
            return Err(format!(
                "<{}> declares size {size:#x} but carries {:#x} bytes",
                c.tag,
                bytes.len()
            ));
        }
        Ok(bytes)
    };

    let mut chunks = Vec::with_capacity(node.children.len());
    for c in &node.children {
        let chunk = match c.tag.as_str() {
            "Header" => {
                let size = hex(c, "size")?;
                Chunk::Header(data(c, size)?)
            }
            "Tables" => {
                let (off, size) = (hex(c, "offset")?, hex(c, "size")?);
                Chunk::Tables { off, size, data: data(c, size)? }
            }
            "Gap" => {
                let (off, size) = (hex(c, "offset")?, hex(c, "size")?);
                Chunk::Gap { off, size, data: data(c, size)? }
            }
            "Suffix" => {
                let (off, size) = (hex(c, "offset")?, hex(c, "size")?);
                Chunk::Suffix { off, size, data: data(c, size)? }
            }
            "Pad" => Chunk::Pad { off: hex(c, "offset")?, size: hex(c, "size")? },
            "Block" => {
                let (idx, off, size) = (idx_attr(c)?, hex(c, "offset")?, hex(c, "size")?);
                Chunk::Block { idx, off, size, data: data(c, size)? }
            }
            "Root" => {
                Chunk::Root { idx: idx_attr(c)?, off: hex(c, "offset")?, size: hex(c, "size")? }
            }
            _ => continue,
        };
        chunks.push(chunk);
    }
    Ok(chunks)
}

/// The `idx` attribute of `<Block>` / `<Root>` (decimal, 0-based).
pub(crate) fn idx_attr(c: &XmlNode) -> Res<usize> {
    c.attrs
        .get("idx")
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| format!("<{}> has a missing or invalid 'idx'", c.tag))
}

// ============================================================================
// Tree -> binary (patching the original layout)
// ============================================================================

pub(crate) fn put_bytes(body: &mut [u8], off: usize, data: &[u8], what: &str) -> Res<()> {
    let range = checked_range(body.len(), off, data.len(), what)?;
    body[range].copy_from_slice(data);
    Ok(())
}

/// Writes the tree back into blocks whose positions and sizes are fixed.
pub(crate) struct ExactWriter<'a> {
    pub(crate) lay: Layout,
    pub(crate) schema: &'a Schema,
    /// Body offset of each block.
    pub(crate) offs: Vec<usize>,
    /// Size of each block.
    pub(crate) sizes: Vec<usize>,
}

impl ExactWriter<'_> {
    /// Absolute body position of `rel` inside block `blk`, after checking that `len`
    /// bytes fit inside that block.
    pub(crate) fn pos(&self, blk: usize, rel: usize, len: usize) -> Res<usize> {
        let size = *self
            .sizes
            .get(blk)
            .ok_or_else(|| format!("pointer to missing block {}", blk + 1))?;
        match rel.checked_add(len) {
            Some(end) if end <= size => Ok(self.offs[blk] + rel),
            _ => Err(format!(
                "write of {len} bytes at {rel:#x} overflows block {} ({size:#x} bytes)",
                blk + 1
            )),
        }
    }

    pub(crate) fn write_items(
        &self,
        body: &mut [u8],
        elem: (u8, u32),
        items: &[Val],
        blk: usize,
        start: usize,
        depth: usize,
    ) -> Res<()> {
        let (et, ek) = elem;
        let esz = if et == ty::STRUCT {
            self.schema.structs.get(&ek).map_or(0, |d| d.size)
        } else {
            scalar_size(et)
        };
        for (k, item) in items.iter().enumerate() {
            let rel = start + k * esz;
            match item {
                Val::Struct(inner) if et == ty::STRUCT => {
                    self.write_struct(body, ek, blk, rel, inner, depth + 1)?;
                }
                Val::Null => {} // not representable: keep the existing bytes
                _ => {
                    let at = self.pos(blk, rel, esz)?;
                    write_scalar(body, self.lay, et, at, item)?;
                }
            }
        }
        Ok(())
    }

    pub(crate) fn write_struct(
        &self,
        body: &mut [u8],
        hash: u32,
        blk: usize,
        base: usize,
        fields: &[Field],
        depth: usize,
    ) -> Res<()> {
        if depth > MAX_DEPTH {
            return Err(format!("nesting deeper than {MAX_DEPTH} levels at {}", known(hash)));
        }
        let def = self
            .schema
            .structs
            .get(&hash)
            .ok_or_else(|| format!("no struct {}", known(hash)))?;
        let pw = self.lay.ptr_width();

        for entry in def.entries.iter().filter(|e| e.name != ARRAYINFO) {
            let Some(f) = fields.iter().find(|f| f.name == entry.name) else {
                continue;
            };
            let rel = base + entry.off;

            match entry.ty {
                ty::STRUCT => {
                    if let Val::Struct(inner) = &f.val {
                        self.write_struct(body, entry.key, blk, rel, inner, depth + 1)?;
                    }
                }
                ty::PTR => {
                    let at = self.pos(blk, rel, pw)?;
                    let raw = f.ptr.unwrap_or(0);
                    self.lay.put_ptr(body, at, raw);
                    if let (Val::Struct(inner), Some((bi, bo))) = (&f.val, decode_ptr(raw)) {
                        self.write_struct(body, entry.key, bi, bo, inner, depth + 1)?;
                    }
                }
                ty::ARRAY_FIXED => {
                    if let Val::Array { elem_ty, elem_key, items } = &f.val {
                        if items.len() > entry.key as usize {
                            return Err(format!(
                                "array {} has {} items but room for {}",
                                known(entry.name),
                                items.len(),
                                entry.key
                            ));
                        }
                        let elem = def.arrays.get(&entry.name).copied().unwrap_or((*elem_ty, *elem_key));
                        self.write_items(body, elem, items, blk, rel, depth)?;
                    }
                }
                ty::ARRAY_PTR | ty::ARRAY_PTR2 => {
                    let at = self.pos(blk, rel, pw + 4)?;
                    let raw = f.ptr.unwrap_or(0);
                    self.lay.put_ptr(body, at, raw);
                    if let Val::Array { elem_ty, elem_key, items } = &f.val {
                        let count = u16::try_from(items.len()).map_err(|_| {
                            format!("array {} has too many items ({})", known(entry.name), items.len())
                        })?;
                        self.lay.put_u16(body, at + pw, count); // count
                        self.lay.put_u16(body, at + pw + 2, count); // capacity

                        match decode_ptr(raw) {
                            Some((bi, bo)) => {
                                let elem = def
                                    .arrays
                                    .get(&entry.name)
                                    .copied()
                                    .unwrap_or((*elem_ty, *elem_key));
                                self.write_items(body, elem, items, bi, bo, depth)?;
                            }
                            None if !items.is_empty() => {
                                return Err(format!(
                                    "array {} has items but no backing storage; growing an \
                                     empty array is not supported when the original layout \
                                     is preserved",
                                    known(entry.name)
                                ));
                            }
                            None => {}
                        }
                    }
                }
                t => {
                    let at = self.pos(blk, rel, scalar_size(t))?;
                    write_scalar(body, self.lay, t, at, &f.val)?;
                }
            }
        }
        Ok(())
    }
}

/// Writes the schema tables (struct / enum / block) described by `schema` into `body`.
pub(crate) fn write_tables(
    body: &mut [u8],
    lay: Layout,
    schema: &Schema,
    blocks_info: &[(u32, usize)],
    block_phys: &HashMap<usize, usize>,
) -> Res<()> {
    let len = body.len();

    table_range(len, schema.struct_table_off, schema.struct_order.len(), STRUCT_REC, "struct table")?;
    for (i, hash) in schema.struct_order.iter().enumerate() {
        let def = &schema.structs[hash];
        table_range(len, def.entry_off, def.entries.len(), ENTRY_REC, "struct entries")?;
        let rec = schema.struct_table_off + i * STRUCT_REC;
        lay.put_u32(body, rec, *hash);
        lay.put_u32(body, rec + 0x18, def.size as u32);
        lay.put_u16(body, rec + 0x1E, def.entries.len() as u16);
        lay.put_ptr(body, rec + 0x10, def.entry_off as u64 + SYSTEM_BASE);
        for (j, e) in def.entries.iter().enumerate() {
            let q = def.entry_off + j * ENTRY_REC;
            lay.put_u32(body, q, e.name);
            lay.put_u32(body, q + 4, e.off as u32);
            body[q + 8] = e.ty;
            lay.put_u32(body, q + 12, e.key);
        }
    }

    table_range(len, schema.enum_table_off, schema.enum_order.len(), ENUM_REC, "enum table")?;
    for (i, hash) in schema.enum_order.iter().enumerate() {
        let vals = schema.enums.get(hash).map(Vec::as_slice).unwrap_or(&[]);
        let vals_off = schema.enum_val_off.get(hash).copied().unwrap_or(0);
        table_range(len, vals_off, vals.len(), ENUM_VAL, "enum values")?;
        let rec = schema.enum_table_off + i * ENUM_REC;
        lay.put_u32(body, rec, *hash);
        put_enum_count(lay, body, rec + 0x10, vals.len())?;
        lay.put_ptr(body, rec + 8, vals_off as u64 + SYSTEM_BASE);
        for (j, &(key, value)) in vals.iter().enumerate() {
            let q = vals_off + j * ENUM_VAL;
            lay.put_u32(body, q, key);
            lay.put_u32(body, q + 4, value as u32);
        }
    }

    table_range(len, schema.block_table_off, blocks_info.len(), BLOCK_REC, "block table")?;
    for (i, &(hash, size)) in blocks_info.iter().enumerate() {
        let phys = *block_phys
            .get(&i)
            .ok_or_else(|| format!("no data region for block {}", i + 1))?;
        let rec = schema.block_table_off + i * BLOCK_REC;
        lay.put_u32(body, rec, hash);
        lay.put_u32(body, rec + 4, size as u32);
        lay.put_ptr(body, rec + 8, phys as u64 + SYSTEM_BASE);
    }
    Ok(())
}

/// Reconstructs the original body from the chunk index, then applies the (possibly
/// edited) schema and tree on top of it.
pub(crate) fn chunks_to_body(
    chunks: &[Chunk],
    root: &Struct,
    schema: &Schema,
    blocks_info: &[(u32, usize)],
    root_block_idx: usize,
    lay: Layout,
) -> Res<Vec<u8>> {
    let total: usize = chunks.iter().map(Chunk::size).sum();
    let mut body = vec![0u8; total];

    // 1. Verbatim regions; remember where each block lives.
    let mut block_phys: HashMap<usize, usize> = HashMap::new();
    let mut saw_header = false;
    for chunk in chunks {
        match chunk {
            Chunk::Header(d) => {
                put_bytes(&mut body, 0, d, "header")?;
                saw_header = true;
            }
            Chunk::Tables { off, data, .. }
            | Chunk::Gap { off, data, .. }
            | Chunk::Suffix { off, data, .. } => put_bytes(&mut body, *off, data, "region")?,
            Chunk::Block { idx, off, data, .. } => {
                put_bytes(&mut body, *off, data, "block")?;
                block_phys.insert(*idx, *off);
            }
            Chunk::Root { idx, off, .. } => {
                block_phys.insert(*idx, *off);
            }
            Chunk::Pad { .. } => {}
        }
    }
    if !saw_header {
        return Err("no <Header> chunk".into());
    }

    // 2. Tables from the schema. Applied after the verbatim copy so schema edits in the
    //    XML take effect; unchanged schemas reproduce the original bytes.
    write_tables(&mut body, lay, schema, blocks_info, &block_phys)?;

    // 3. The tree.
    let mut offs = vec![0usize; blocks_info.len()];
    for (&idx, &off) in &block_phys {
        *offs
            .get_mut(idx)
            .ok_or_else(|| format!("chunk refers to block {} but there are {}", idx + 1, blocks_info.len()))? = off;
    }
    let sizes: Vec<usize> = blocks_info.iter().map(|&(_, size)| size).collect();
    for (i, (&off, &size)) in offs.iter().zip(&sizes).enumerate() {
        checked_range(total, off, size, "block data")
            .map_err(|e| format!("{e} (block {})", i + 1))?;
    }

    let writer = ExactWriter { lay, schema, offs, sizes };
    writer.write_struct(&mut body, root.hash, root_block_idx, 0, &root.fields, 0)?;
    Ok(body)
}
