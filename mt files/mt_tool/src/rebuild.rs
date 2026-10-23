//! Building a body from scratch (cross-layout conversion): layout computation and the full writer.

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};

use crate::util::{align_up, checked_range};
use crate::constants::{ARRAYINFO, BLOCK_REC, ENTRY_REC, ENUM_REC, ENUM_VAL, HEADER_LEN, MAX_DEPTH, MAX_LAYOUT_PASSES, Res, STRUCT_REC, SYSTEM_BASE, is_array, scalar_size, ty};
use crate::names::known;
use crate::platform::{Layout, put_enum_count};
use crate::schema::{Def, Entry, Schema, array_info, encode_ptr};
use crate::tree::{Field, Struct, Val};
use crate::patch::chunks_to_body;
use crate::document::{Source, pack};

// ============================================================================
// Layout computation (used when rebuilding a body from scratch)
// ============================================================================

#[derive(Clone, Default)]
pub(crate) struct StructLayout {
    pub(crate) size: usize,
    /// One offset per schema entry (including `ARRAYINFO` pseudo-entries).
    pub(crate) offsets: Vec<usize>,
}

/// `(size, alignment)` of a field.
///
/// Alignment rules are heuristic: nested structs and arrays are aligned to 4 bytes
/// regardless of their contents, and struct sizes are not rounded up to their
/// alignment. Verify against a real file of the target platform.
pub(crate) fn field_size_align(
    t: u8,
    key: u32,
    lay: Layout,
    sizes: &HashMap<u32, usize>,
    array_elem: Option<(u8, u32)>,
) -> (usize, usize) {
    match t {
        ty::STRUCT => (sizes.get(&key).copied().unwrap_or(0), 4),
        ty::PTR => (lay.ptr_width(), lay.ptr_width()),
        ty::ARRAY_FIXED => {
            let (et, ek) = array_elem.unwrap_or((0, 0));
            let esz = if et == ty::STRUCT {
                sizes.get(&ek).copied().unwrap_or(0)
            } else {
                scalar_size(et)
            };
            (key as usize * esz, 4)
        }
        ty::ARRAY_PTR | ty::ARRAY_PTR2 => (lay.ptr_width() + 4, lay.ptr_width()),
        t => match scalar_size(t) {
            0 => (0, 1),
            n @ (12 | 16) => (n, 4),
            n => (n, n),
        },
    }
}

pub(crate) fn layout_struct(
    entries: &[Entry],
    arrays: &HashMap<u32, (u8, u32)>,
    lay: Layout,
    sizes: &HashMap<u32, usize>,
) -> StructLayout {
    let mut pos = 0usize;
    let mut offsets = Vec::with_capacity(entries.len());
    for e in entries {
        if e.name == ARRAYINFO {
            offsets.push(pos);
            continue;
        }
        let (size, align) = field_size_align(e.ty, e.key, lay, sizes, arrays.get(&e.name).copied());
        pos = align_up(pos, align);
        offsets.push(pos);
        pos += size;
    }
    StructLayout { size: pos, offsets }
}

/// Computes sizes and field offsets for every struct. Struct sizes depend on nested
/// struct sizes, so they are iterated to a fixed point first.
pub(crate) fn compute_layouts(defs: &[(u32, Vec<Entry>)], lay: Layout) -> HashMap<u32, StructLayout> {
    let arrays: Vec<_> = defs.iter().map(|(_, entries)| array_info(entries)).collect();

    let mut sizes: HashMap<u32, usize> = HashMap::new();
    for _ in 0..MAX_LAYOUT_PASSES {
        let next: HashMap<u32, usize> = defs
            .iter()
            .zip(&arrays)
            .map(|((hash, entries), arr)| (*hash, layout_struct(entries, arr, lay, &sizes).size))
            .collect();
        let stable = next == sizes;
        sizes = next;
        if stable {
            break;
        }
    }

    defs.iter()
        .zip(&arrays)
        .map(|((hash, entries), arr)| (*hash, layout_struct(entries, arr, lay, &sizes)))
        .collect()
}

/// Derives a schema from the tree itself, in discovery (pre-)order so output is
/// deterministic. Each array field is preceded by an `ARRAYINFO` entry.
pub(crate) fn collect_schema(root: &Struct) -> Vec<(u32, Vec<Entry>)> {
    fn walk(
        hash: u32,
        fields: &[Field],
        seen: &mut HashSet<u32>,
        out: &mut Vec<(u32, Vec<Entry>)>,
    ) {
        // The definition is recorded once per struct type, from the first instance seen.
        // Children are still visited for every instance: an early instance can have an
        // empty array whose element type only appears in a later instance's items.
        if seen.insert(hash) {
            let mut entries = Vec::with_capacity(fields.len());
            for f in fields {
                if let Val::Array { elem_ty, elem_key, .. } = &f.val {
                    entries.push(Entry { name: ARRAYINFO, off: 0, ty: *elem_ty, key: *elem_key });
                }
                entries.push(Entry { name: f.name, off: 0, ty: f.ty, key: f.key });
            }
            out.push((hash, entries));
        }

        for f in fields {
            match &f.val {
                Val::Struct(inner) => walk(f.key, inner, seen, out),
                Val::Array { elem_ty: ty::STRUCT, elem_key, items } => {
                    for item in items {
                        if let Val::Struct(inner) = item {
                            walk(*elem_key, inner, seen, out);
                        }
                    }
                }
                _ => {}
            }
        }
    }

    let mut out = Vec::new();
    walk(root.hash, &root.fields, &mut HashSet::new(), &mut out);
    out
}

// ============================================================================
// Scalar writing
// ============================================================================

/// Writes `v` as scalar type `t` at `off`. `Val::Null` is skipped (unknown types and
/// placeholders keep whatever bytes are already there).
pub(crate) fn write_scalar(buf: &mut [u8], lay: Layout, t: u8, off: usize, v: &Val) -> Res<()> {
    if matches!(v, Val::Null) {
        return Ok(());
    }
    checked_range(buf.len(), off, scalar_size(t), "scalar write")?;
    match (t, v) {
        (ty::BOOL, Val::Bool(x)) => buf[off] = u8::from(*x),
        (ty::I8, Val::I8(x)) => buf[off] = *x as u8,
        (ty::U8 | ty::U8_ALT, Val::U8(x)) => buf[off] = *x,
        (ty::I16, Val::I16(x)) => lay.put_u16(buf, off, *x as u16),
        (ty::U16 | ty::U16_ALT, Val::U16(x)) => lay.put_u16(buf, off, *x),
        (ty::I32 | ty::I32_ALT, Val::I32(x)) => lay.put_u32(buf, off, *x as u32),
        (ty::U32 | ty::U32_ALT | ty::U32_ALT2, Val::U32(x)) => lay.put_u32(buf, off, *x),
        (ty::F32, Val::F32(x)) => lay.put_f32(buf, off, *x),
        (ty::VEC3, Val::Vec3(a, b, c)) => {
            lay.put_f32(buf, off, *a);
            lay.put_f32(buf, off + 4, *b);
            lay.put_f32(buf, off + 8, *c);
        }
        (ty::VEC4, Val::Vec4(a, b, c, d)) => {
            lay.put_f32(buf, off, *a);
            lay.put_f32(buf, off + 4, *b);
            lay.put_f32(buf, off + 8, *c);
            lay.put_f32(buf, off + 12, *d);
        }
        (ty::HASH, Val::Hash(x)) => lay.put_u32(buf, off, *x),
        _ => return Err(format!("value {v:?} does not match field type {t:#04x}")),
    }
    Ok(())
}

// ============================================================================
// Tree -> binary (from scratch)
// ============================================================================

/// Serialises a tree into a single freshly allocated block, using computed layouts.
pub(crate) struct FullWriter<'a> {
    pub(crate) buf: Vec<u8>,
    pub(crate) lay: Layout,
    pub(crate) layouts: &'a HashMap<u32, StructLayout>,
    pub(crate) schema: &'a Schema,
    pub(crate) block_idx: usize,
}

impl FullWriter<'_> {
    /// Appends `size` zero bytes at the next `align`-aligned offset and returns it.
    pub(crate) fn alloc(&mut self, size: usize, align: usize) -> usize {
        let off = align_up(self.buf.len(), align);
        self.buf.resize(off + size, 0);
        off
    }

    pub(crate) fn elem_size(&self, et: u8, ek: u32) -> usize {
        if et == ty::STRUCT {
            self.layouts.get(&ek).map_or(0, |l| l.size)
        } else {
            scalar_size(et)
        }
    }

    pub(crate) fn write_items(
        &mut self,
        start: usize,
        elem: (u8, u32),
        items: &[Val],
        depth: usize,
    ) -> Res<()> {
        let (et, ek) = elem;
        let esz = self.elem_size(et, ek);
        for (k, item) in items.iter().enumerate() {
            let p = start + k * esz;
            match item {
                Val::Struct(inner) if et == ty::STRUCT => {
                    self.write_struct(p, ek, inner, depth + 1)?;
                }
                Val::Null => {} // placeholder item: stays zeroed
                _ => write_scalar(&mut self.buf, self.lay, et, p, item)?,
            }
        }
        Ok(())
    }

    pub(crate) fn write_struct(&mut self, off: usize, hash: u32, fields: &[Field], depth: usize) -> Res<()> {
        if depth > MAX_DEPTH {
            return Err(format!("nesting deeper than {MAX_DEPTH} levels at {}", known(hash)));
        }
        // Copy the `'a` references out so they don't keep `self` borrowed.
        let (layouts, schema) = (self.layouts, self.schema);
        let layout = layouts
            .get(&hash)
            .ok_or_else(|| format!("no layout for {}", known(hash)))?;
        let def = schema
            .structs
            .get(&hash)
            .ok_or_else(|| format!("no schema for {}", known(hash)))?;
        let pw = self.lay.ptr_width();

        // Fields are stored in schema order. Scan forward so a field missing from the
        // tree is skipped (left zeroed) without dropping the ones after it.
        let mut next = 0usize;
        for (i, entry) in def.entries.iter().enumerate() {
            if entry.name == ARRAYINFO {
                continue;
            }
            let Some(rel) = fields[next..].iter().position(|f| f.name == entry.name) else {
                continue;
            };
            let f = &fields[next + rel];
            next += rel + 1;
            let fo = off + layout.offsets[i];

            match (entry.ty, &f.val) {
                (ty::STRUCT, Val::Struct(inner)) => {
                    self.write_struct(fo, entry.key, inner, depth + 1)?;
                }
                (ty::PTR, Val::Struct(inner)) => {
                    let size = layouts.get(&entry.key).map_or(0, |l| l.size);
                    let target = self.alloc(size, pw);
                    self.write_struct(target, entry.key, inner, depth + 1)?;
                    let raw = encode_ptr(self.block_idx, target)?;
                    self.lay.put_ptr(&mut self.buf, fo, raw);
                }
                (ty::PTR, _) => self.lay.put_ptr(&mut self.buf, fo, 0),
                (ty::ARRAY_FIXED, Val::Array { elem_ty, elem_key, items }) => {
                    if items.len() > entry.key as usize {
                        return Err(format!(
                            "array {} has {} items but room for {}",
                            known(entry.name),
                            items.len(),
                            entry.key
                        ));
                    }
                    let elem = def.arrays.get(&entry.name).copied().unwrap_or((*elem_ty, *elem_key));
                    self.write_items(fo, elem, items, depth)?;
                }
                (ty::ARRAY_PTR | ty::ARRAY_PTR2, Val::Array { elem_ty, elem_key, items }) => {
                    let elem = def.arrays.get(&entry.name).copied().unwrap_or((*elem_ty, *elem_key));
                    let count = u16::try_from(items.len()).map_err(|_| {
                        format!("array {} has too many items ({})", known(entry.name), items.len())
                    })?;
                    if items.is_empty() {
                        self.lay.put_ptr(&mut self.buf, fo, 0); // empty arrays are null
                    } else {
                        let target = self.alloc(items.len() * self.elem_size(elem.0, elem.1), pw);
                        self.write_items(target, elem, items, depth)?;
                        let raw = encode_ptr(self.block_idx, target)?;
                        self.lay.put_ptr(&mut self.buf, fo, raw);
                    }
                    self.lay.put_u16(&mut self.buf, fo + pw, count); // count
                    self.lay.put_u16(&mut self.buf, fo + pw + 2, count); // capacity
                }
                (t, val) if !is_array(t) && t != ty::STRUCT => {
                    write_scalar(&mut self.buf, self.lay, t, fo, val)?;
                }
                _ => {} // container field whose value is Null: leave zeroed
            }
        }
        Ok(())
    }
}

// ============================================================================
// Rebuilding a body from scratch (cross-layout conversion)
// ============================================================================

/// Builds a complete body for `lay` from the tree alone: all structs are laid out
/// afresh and the whole tree is written into one block. Enums are carried over from
/// `source`.
pub(crate) fn rebuild_body(root: &Struct, lay: Layout, source: &Schema) -> Res<Vec<u8>> {
    let defs = collect_schema(root);
    let layouts = compute_layouts(&defs, lay);

    // Schema with the freshly computed offsets.
    let mut schema = Schema::default();
    for (hash, entries) in &defs {
        let l = &layouts[hash];
        let entries: Vec<Entry> = entries
            .iter()
            .zip(&l.offsets)
            .map(|(e, &off)| Entry { off, ..*e })
            .collect();
        schema.struct_order.push(*hash);
        schema.structs.insert(*hash, Def::new(l.size, entries, 0));
    }

    let root_size = layouts.get(&root.hash).ok_or("no layout for root")?.size;
    let mut writer = FullWriter {
        buf: vec![0u8; root_size],
        lay,
        layouts: &layouts,
        schema: &schema,
        block_idx: 0,
    };
    writer.write_struct(0, root.hash, &root.fields, 0)?;
    let block_data = writer.buf;

    let struct_count = u16::try_from(schema.struct_order.len()).map_err(|_| "too many structs")?;
    let enum_count = u16::try_from(source.enum_order.len()).map_err(|_| "too many enums")?;
    let mut body = vec![0u8; HEADER_LEN];

    // Struct table, each struct followed by its entry array.
    let struct_table_off = body.len();
    body.resize(struct_table_off + STRUCT_REC * usize::from(struct_count), 0);
    for (i, hash) in schema.struct_order.iter().enumerate() {
        let def = &schema.structs[hash];
        let entries_off = body.len();
        body.resize(entries_off + ENTRY_REC * def.entries.len(), 0);

        let rec = struct_table_off + i * STRUCT_REC;
        let entry_count = u16::try_from(def.entries.len())
            .map_err(|_| format!("struct {} has too many fields", known(*hash)))?;
        lay.put_u32(&mut body, rec, *hash);
        lay.put_ptr(&mut body, rec + 0x10, entries_off as u64 + SYSTEM_BASE);
        lay.put_u32(&mut body, rec + 0x18, def.size as u32);
        lay.put_u16(&mut body, rec + 0x1E, entry_count);
        for (j, e) in def.entries.iter().enumerate() {
            let q = entries_off + j * ENTRY_REC;
            lay.put_u32(&mut body, q, e.name);
            lay.put_u32(&mut body, q + 4, e.off as u32);
            body[q + 8] = e.ty;
            lay.put_u32(&mut body, q + 12, e.key);
        }
    }

    // Enum table, each enum followed by its value array. With no enums the table is
    // empty and its pointer simply marks where it would start.
    let enum_table_off = body.len();
    body.resize(enum_table_off + ENUM_REC * usize::from(enum_count), 0);
    for (i, hash) in source.enum_order.iter().enumerate() {
        let vals = source.enums.get(hash).map(Vec::as_slice).unwrap_or(&[]);
        let vals_off = body.len();
        body.resize(vals_off + ENUM_VAL * vals.len(), 0);

        let rec = enum_table_off + i * ENUM_REC;
        lay.put_u32(&mut body, rec, *hash);
        lay.put_ptr(&mut body, rec + 8, vals_off as u64 + SYSTEM_BASE);
        put_enum_count(lay, &mut body, rec + 0x10, vals.len())?;
        for (j, &(key, value)) in vals.iter().enumerate() {
            let q = vals_off + j * ENUM_VAL;
            lay.put_u32(&mut body, q, key);
            lay.put_u32(&mut body, q + 4, value as u32);
        }
    }

    // Block table (one block), then the block data on a 16-byte boundary.
    let block_table_off = body.len();
    body.resize(block_table_off + BLOCK_REC, 0);
    body.resize(align_up(body.len(), 16), 0);
    let block_data_off = body.len();
    body.extend_from_slice(&block_data);

    lay.put_u32(&mut body, 0x1C, 1); // root block index (1-based)
    lay.put_ptr(&mut body, 0x20, struct_table_off as u64 + SYSTEM_BASE);
    lay.put_ptr(&mut body, 0x28, enum_table_off as u64 + SYSTEM_BASE);
    lay.put_ptr(&mut body, 0x30, block_table_off as u64 + SYSTEM_BASE);
    lay.put_u16(&mut body, 0x48, struct_count);
    lay.put_u16(&mut body, 0x4A, enum_count);
    lay.put_u16(&mut body, 0x4C, 1);

    lay.put_u32(&mut body, block_table_off, root.hash);
    lay.put_u32(&mut body, block_table_off + 4, block_data.len() as u32);
    lay.put_ptr(&mut body, block_table_off + 8, block_data_off as u64 + SYSTEM_BASE);

    Ok(body)
}

/// Serialises `src` as a binary file for layout `dst`.
pub(crate) fn encode_binary(src: &Source, dst: Layout) -> Res<Vec<u8>> {
    let body: Cow<[u8]> = if dst != src.layout {
        Cow::Owned(rebuild_body(&src.root, dst, &src.schema)?)
    } else if let Some(chunks) = &src.chunks {
        // Same layout, edited XML: patch the tree into the original body.
        let body = chunks_to_body(
            chunks,
            &src.root,
            &src.schema,
            &src.blocks_info,
            src.root_block_idx,
            dst,
        )?;
        Cow::Owned(body)
    } else if let Some((_, body)) = &src.binary {
        // Untouched binary: recompress the original body.
        Cow::Borrowed(body.as_slice())
    } else {
        Cow::Owned(rebuild_body(&src.root, dst, &src.schema)?)
    };
    pack(&src.outer, &body)
}
