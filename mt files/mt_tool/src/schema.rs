//! The struct / enum schema tables and the data-block table, plus block pointers.

use std::collections::HashMap;

use crate::util::{checked_range, sys_offset, table_range};
use crate::constants::{ARRAYINFO, BLOCK_REC, ENTRY_REC, ENUM_REC, ENUM_VAL, HEADER_LEN, Res, STRUCT_REC, is_array};
use crate::names::known;
use crate::platform::{Layout, get_enum_count};

// ============================================================================
// Schema
// ============================================================================

#[derive(Clone, Copy, Debug)]
pub(crate) struct Entry {
    pub(crate) name: u32,
    pub(crate) off: usize,
    pub(crate) ty: u8,
    pub(crate) key: u32,
}

/// Maps each array field to its `(element type, element key)`. An `ARRAYINFO`
/// pseudo-entry describes the next array field that follows it.
pub(crate) fn array_info(entries: &[Entry]) -> HashMap<u32, (u8, u32)> {
    let mut map = HashMap::new();
    let mut pending = None;
    for e in entries {
        if e.name == ARRAYINFO {
            pending = Some((e.ty, e.key));
        } else if is_array(e.ty) {
            if let Some(info) = pending.take() {
                map.insert(e.name, info);
            }
        }
    }
    map
}

#[derive(Clone, Debug)]
pub(crate) struct Def {
    pub(crate) size: usize,
    pub(crate) entries: Vec<Entry>,
    /// Body offset of this struct's entry array (so tables can be written back in place).
    pub(crate) entry_off: usize,
    /// Array element info, derived from `entries` once.
    pub(crate) arrays: HashMap<u32, (u8, u32)>,
}

impl Def {
    pub(crate) fn new(size: usize, entries: Vec<Entry>, entry_off: usize) -> Self {
        let arrays = array_info(&entries);
        Def { size, entries, entry_off, arrays }
    }
}

/// Element info of array field `name`, or an error if its `ARRAYINFO` is missing.
pub(crate) fn array_elem(def: &Def, name: u32) -> Res<(u8, u32)> {
    def.arrays
        .get(&name)
        .copied()
        .ok_or_else(|| format!("array {} has no ARRAYINFO", known(name)))
}

#[derive(Clone, Default)]
pub(crate) struct Schema {
    pub(crate) structs: HashMap<u32, Def>,
    /// Enum name -> `(value name hash, value)` pairs.
    pub(crate) enums: HashMap<u32, Vec<(u32, i32)>>,
    /// Body offset of each enum's value array.
    pub(crate) enum_val_off: HashMap<u32, usize>,
    /// Tables are written back in the order they were read.
    pub(crate) struct_order: Vec<u32>,
    pub(crate) enum_order: Vec<u32>,
    pub(crate) struct_table_off: usize,
    pub(crate) enum_table_off: usize,
    pub(crate) block_table_off: usize,
}

pub(crate) fn parse_schema(body: &[u8], lay: Layout) -> Res<Schema> {
    if body.len() < HEADER_LEN {
        return Err(format!("body is {} bytes, shorter than the {HEADER_LEN:#x}-byte header", body.len()));
    }
    let struct_count = lay.u16(body, 0x48) as usize;
    let enum_count = lay.u16(body, 0x4A) as usize;

    let mut schema = Schema {
        struct_table_off: sys_offset(lay.ptr(body, 0x20), "struct table")?,
        enum_table_off: if enum_count > 0 {
            sys_offset(lay.ptr(body, 0x28), "enum table")?
        } else {
            0
        },
        block_table_off: sys_offset(lay.ptr(body, 0x30), "block table")?,
        ..Schema::default()
    };

    // Structs: 32-byte records pointing at arrays of 16-byte entries.
    let table = schema.struct_table_off;
    table_range(body.len(), table, struct_count, STRUCT_REC, "struct table")?;
    for i in 0..struct_count {
        let rec = table + i * STRUCT_REC;
        let name = lay.u32(body, rec);
        let size = lay.u32(body, rec + 0x18) as usize;
        let count = lay.u16(body, rec + 0x1E) as usize;
        let entries_off = sys_offset(lay.ptr(body, rec + 0x10), "struct entries")
            .map_err(|e| format!("{e} (struct {name:#x})"))?;
        table_range(body.len(), entries_off, count, ENTRY_REC, "struct entries")
            .map_err(|e| format!("{e} (struct {name:#x})"))?;

        let entries = (0..count)
            .map(|n| {
                let q = entries_off + n * ENTRY_REC;
                Entry {
                    name: lay.u32(body, q),
                    off: lay.u32(body, q + 4) as usize,
                    ty: body[q + 8],
                    key: lay.u32(body, q + 12),
                }
            })
            .collect();
        schema.struct_order.push(name);
        schema.structs.insert(name, Def::new(size, entries, entries_off));
    }

    // Enums: 24-byte records pointing at arrays of (name hash, value) pairs.
    let table = schema.enum_table_off;
    table_range(body.len(), table, enum_count, ENUM_REC, "enum table")?;
    for i in 0..enum_count {
        let rec = table + i * ENUM_REC;
        let name = lay.u32(body, rec);
        let count = get_enum_count(lay, body, rec + 0x10);
        let vals_off = sys_offset(lay.ptr(body, rec + 8), "enum values")
            .map_err(|e| format!("{e} (enum {name:#x})"))?;
        table_range(body.len(), vals_off, count, ENUM_VAL, "enum values")
            .map_err(|e| format!("{e} (enum {name:#x})"))?;

        let vals = (0..count)
            .map(|n| {
                let q = vals_off + n * ENUM_VAL;
                (lay.u32(body, q), lay.u32(body, q + 4) as i32)
            })
            .collect();
        schema.enum_order.push(name);
        schema.enums.insert(name, vals);
        schema.enum_val_off.insert(name, vals_off);
    }

    Ok(schema)
}

// ============================================================================
// Blocks and block pointers
// ============================================================================

#[derive(Clone)]
pub(crate) struct Block {
    pub(crate) name: u32,
    pub(crate) data: Vec<u8>,
    /// Body offset of the block's first byte.
    pub(crate) off: usize,
}

/// Splits a block pointer into `(block index, offset)`; `None` for a null pointer.
pub(crate) fn decode_ptr(raw: u64) -> Option<(usize, usize)> {
    let id = (raw & 0xFFF) as usize;
    if id == 0 {
        None
    } else {
        Some((id - 1, ((raw >> 12) & 0xF_FFFF) as usize))
    }
}

pub(crate) fn encode_ptr(block_idx: usize, offset: usize) -> Res<u64> {
    if block_idx >= 0xFFF {
        return Err(format!("block index {block_idx} does not fit in a block pointer"));
    }
    if offset > 0xF_FFFF {
        return Err(format!("offset {offset:#x} does not fit in a 20-bit block pointer"));
    }
    Ok((block_idx as u64 + 1) | ((offset as u64) << 12))
}

pub(crate) fn parse_blocks(body: &[u8], lay: Layout) -> Res<Vec<Block>> {
    let table = sys_offset(lay.ptr(body, 0x30), "block table")?;
    let count = lay.u16(body, 0x4C) as usize;
    table_range(body.len(), table, count, BLOCK_REC, "block table")?;

    let mut blocks = Vec::with_capacity(count);
    for i in 0..count {
        let rec = table + i * BLOCK_REC;
        let name = lay.u32(body, rec);
        let len = lay.u32(body, rec + 4) as usize;
        let off = sys_offset(lay.ptr(body, rec + 8), "block data")
            .map_err(|e| format!("{e} (block {name:#x})"))?;
        let range = checked_range(body.len(), off, len, "block data")
            .map_err(|e| format!("{e} (block {name:#x})"))?;
        blocks.push(Block { name, data: body[range].to_vec(), off });
    }
    Ok(blocks)
}
