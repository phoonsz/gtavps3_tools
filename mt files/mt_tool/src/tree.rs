//! The in-memory tree model and the binary -> tree reader.

use crate::util::checked_range;
use crate::constants::{ARRAYINFO, MAX_DEPTH, Res, scalar_size, ty};
use crate::names::known;
use crate::platform::Layout;
use crate::schema::{Block, Schema, array_elem, decode_ptr};

// ============================================================================
// Tree model
// ============================================================================

#[derive(Clone, Debug)]
pub(crate) enum Val {
    /// Unknown type, absent value, or placeholder item.
    Null,
    Bool(bool),
    I8(i8),
    U8(u8),
    I16(i16),
    U16(u16),
    I32(i32),
    U32(u32),
    F32(f32),
    Hash(u32),
    Vec3(f32, f32, f32),
    Vec4(f32, f32, f32, f32),
    Struct(Vec<Field>),
    Array { elem_ty: u8, elem_key: u32, items: Vec<Val> },
}

#[derive(Clone, Debug)]
pub(crate) struct Field {
    pub(crate) name: u32,
    pub(crate) ty: u8,
    pub(crate) key: u32,
    pub(crate) val: Val,
    /// Raw block pointer for pointer-typed fields (kept so the original layout can be
    /// patched in place).
    pub(crate) ptr: Option<u64>,
}

#[derive(Clone, Debug)]
pub(crate) struct Struct {
    pub(crate) hash: u32,
    pub(crate) fields: Vec<Field>,
}

// ============================================================================
// Binary -> tree
// ============================================================================

pub(crate) fn read_scalar(lay: Layout, t: u8, b: &[u8], at: usize) -> Val {
    match t {
        ty::BOOL => Val::Bool(b[at] != 0),
        ty::I8 => Val::I8(b[at] as i8),
        ty::U8 | ty::U8_ALT => Val::U8(b[at]),
        ty::I16 => Val::I16(lay.u16(b, at) as i16),
        ty::U16 | ty::U16_ALT => Val::U16(lay.u16(b, at)),
        ty::I32 | ty::I32_ALT => Val::I32(lay.u32(b, at) as i32),
        ty::U32 | ty::U32_ALT | ty::U32_ALT2 => Val::U32(lay.u32(b, at)),
        ty::F32 => Val::F32(lay.f32(b, at)),
        ty::VEC3 => Val::Vec3(lay.f32(b, at), lay.f32(b, at + 4), lay.f32(b, at + 8)),
        ty::VEC4 => Val::Vec4(
            lay.f32(b, at),
            lay.f32(b, at + 4),
            lay.f32(b, at + 8),
            lay.f32(b, at + 12),
        ),
        ty::HASH => Val::Hash(lay.u32(b, at)),
        _ => Val::Null,
    }
}

pub(crate) struct BinReader<'a> {
    pub(crate) schema: &'a Schema,
    pub(crate) blocks: &'a [Block],
    pub(crate) lay: Layout,
}

impl<'a> BinReader<'a> {
    pub(crate) fn block(&self, idx: usize) -> Res<&'a [u8]> {
        self.blocks
            .get(idx)
            .map(|b| b.data.as_slice())
            .ok_or_else(|| format!("pointer to missing block {}", idx + 1))
    }

    pub(crate) fn elem_size(&self, t: u8, key: u32) -> usize {
        if t == ty::STRUCT {
            self.schema.structs.get(&key).map_or(0, |d| d.size)
        } else {
            scalar_size(t)
        }
    }

    pub(crate) fn read_struct(&self, hash: u32, blk: usize, base: usize, depth: usize) -> Res<Vec<Field>> {
        if depth > MAX_DEPTH {
            return Err(format!("nesting deeper than {MAX_DEPTH} levels at {}", known(hash)));
        }
        let def = self
            .schema
            .structs
            .get(&hash)
            .ok_or_else(|| format!("no struct {}", known(hash)))?;
        let data = self.block(blk)?;
        let pw = self.lay.ptr_width();
        let mut fields = Vec::with_capacity(def.entries.len());

        for e in def.entries.iter().filter(|e| e.name != ARRAYINFO) {
            let at = base + e.off;

            // Bytes this field occupies in place. Nested structs and fixed arrays check
            // their own elements.
            let inline = match e.ty {
                ty::STRUCT | ty::ARRAY_FIXED => 0,
                ty::PTR => pw,
                ty::ARRAY_PTR | ty::ARRAY_PTR2 => pw + 4,
                t => scalar_size(t),
            };
            checked_range(data.len(), at, inline, "field")
                .map_err(|err| format!("{err} ({}.{})", known(hash), known(e.name)))?;

            let (val, ptr) = match e.ty {
                ty::STRUCT => {
                    (Val::Struct(self.read_struct(e.key, blk, at, depth + 1)?), None)
                }
                ty::PTR => {
                    let raw = self.lay.ptr(data, at);
                    let val = match decode_ptr(raw) {
                        Some((bi, bo)) => Val::Struct(self.read_struct(e.key, bi, bo, depth + 1)?),
                        None => Val::Null,
                    };
                    (val, Some(raw))
                }
                ty::ARRAY_FIXED => {
                    let (et, ek) = array_elem(def, e.name)?;
                    let items = self.read_items(et, ek, e.key as usize, blk, at, depth)?;
                    (Val::Array { elem_ty: et, elem_key: ek, items }, None)
                }
                ty::ARRAY_PTR | ty::ARRAY_PTR2 => {
                    let (et, ek) = array_elem(def, e.name)?;
                    let raw = self.lay.ptr(data, at);
                    let count = self.lay.u16(data, at + pw) as usize;
                    let items = match decode_ptr(raw) {
                        Some((bi, bo)) => self.read_items(et, ek, count, bi, bo, depth)?,
                        None => Vec::new(),
                    };
                    (Val::Array { elem_ty: et, elem_key: ek, items }, Some(raw))
                }
                t => (read_scalar(self.lay, t, data, at), None),
            };
            fields.push(Field { name: e.name, ty: e.ty, key: e.key, val, ptr });
        }
        Ok(fields)
    }

    /// Reads `count` consecutive elements starting at `start` in block `blk`.
    pub(crate) fn read_items(
        &self,
        et: u8,
        ek: u32,
        count: usize,
        blk: usize,
        start: usize,
        depth: usize,
    ) -> Res<Vec<Val>> {
        if count == 0 {
            return Ok(Vec::new());
        }
        let data = self.block(blk)?;
        let esz = self.elem_size(et, ek);
        if esz == 0 {
            return Err(format!("array element type {et:#04x}/{ek:#x} has unknown size"));
        }
        // The last element must at least start inside the block; this also stops a
        // corrupt count from driving a huge allocation or loop.
        (count - 1)
            .checked_mul(esz)
            .and_then(|n| n.checked_add(start))
            .filter(|&p| p < data.len())
            .ok_or_else(|| format!("array of {count} elements overruns block {}", blk + 1))?;

        let mut items = Vec::with_capacity(count);
        for i in 0..count {
            let p = start + i * esz;
            items.push(if et == ty::STRUCT {
                Val::Struct(self.read_struct(ek, blk, p, depth + 1)?)
            } else {
                checked_range(data.len(), p, esz, "array element")?;
                read_scalar(self.lay, et, data, p)
            });
        }
        Ok(items)
    }
}
