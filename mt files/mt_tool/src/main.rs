//! `mt_tool` — convert `.cmt` (console) and `.ymt` (PC) files to and from XML,
//! and between the two binary layouts.
//!
//! # File format (as understood by this tool)
//!
//! A file is a 16-byte "outer" header followed by a raw-deflate stream. The inflated
//! *body* is laid out as:
//!
//! ```text
//! 0x00  header (0x50 bytes)
//!         0x1C root block index (1-based)    0x20 struct table ptr
//!         0x28 enum table ptr                0x30 block table ptr
//!         0x48 struct count   0x4A enum count   0x4C block count
//! 0x50  struct table, struct entries, enum table, enum values, block table
//! ....  data blocks
//! ```
//!
//! * Table pointers are flat: `SYSTEM_BASE + body offset`.
//! * Pointers *inside* blocks are "block pointers": the low 12 bits hold `block id + 1`
//!   and the next 20 bits hold the offset inside that block.
//! * PC files are little-endian with 8-byte pointers; console files are big-endian
//!   with 4-byte pointers.
//!
//! # Conversion paths
//!
//! * binary -> XML: the tree, schema and a verbatim "body index" are written out.
//! * XML -> binary (same layout, body index present): the original body is
//!   reconstructed byte-for-byte and the edited tree is patched into it.
//! * anything -> other layout: the body is rebuilt from scratch from the tree.
//!
//! Crates: `flate2`, `base64` (0.21+), `libz-sys`.

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::io::Read;
use std::ops::Range;
use std::sync::OnceLock;
use std::{env, fs, process};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use flate2::read::DeflateDecoder;

// ============================================================================
// Constants
// ============================================================================

/// Base added to body offsets in the flat (table) pointers.
const SYSTEM_BASE: u64 = 0x5000_0000;
/// Pseudo-entry that precedes an array field and describes its element type.
const ARRAYINFO: u32 = 0x0000_0100;

/// zlib compression level used when writing (memLevel 9, raw deflate).
const ZLIB_LEVEL: i32 = 9;
/// Maximum struct / XML nesting depth accepted.
const MAX_DEPTH: usize = 64;
/// Upper bound for an inflated body (guards against decompression bombs).
const MAX_BODY_BYTES: u64 = 256 * 1024 * 1024;
/// Iteration cap for the struct-size fixed point in `compute_layouts`.
const MAX_LAYOUT_PASSES: usize = 30;

const OUTER_LEN: usize = 16;
const HEADER_LEN: usize = 0x50;
const STRUCT_REC: usize = 32;
const ENTRY_REC: usize = 16;
const ENUM_REC: usize = 24;
const ENUM_VAL: usize = 8;
const BLOCK_REC: usize = 16;

type Res<T> = Result<T, String>;

/// Names whose hashes we can resolve to readable XML tags.
const NAMES: &[&str] = &[
    "CPedVariationInfo", "bHasTexVariations", "bHasDrawblVariations", "bHasLowLODs",
    "bIsSuperLOD", "availComp", "aComponentData3", "CPVComponentData", "numAvailTex",
    "aDrawblData3", "CPVDrawblData", "propMask", "numAlternatives", "aTexData",
    "CPVTextureData", "texId", "distribution", "clothData", "ownsCloth", "aSelectionSets",
    "CPedSelectionSet", "compInfos", "CComponentInfo", "pedXml_audioID", "pedXml_audioID2",
    "pedXml_expressionMods", "flags", "inclusions", "exclusions", "pedXml_vfxComps",
    "pedXml_flags", "pedXml_compIdx", "pedXml_drawblIdx", "propInfo", "numAvailProps",
    "aPropMetaData", "CPedPropMetaData", "audioId", "expressionMods", "texData",
    "CPedPropTexData", "renderFlags", "propFlags", "anchorId", "propId", "stickyness",
    "aAnchors", "CAnchorProps", "props", "anchor", "dlcName", "inclusionId", "exclusionId",
    "CPedPropInfo",
];

/// Field type tags used in schema entries.
mod ty {
    pub const BOOL: u8 = 0x01;
    /// Struct stored inline; `key` is the struct hash.
    pub const STRUCT: u8 = 0x05;
    /// Block pointer to a struct; `key` is the struct hash.
    pub const PTR: u8 = 0x07;
    pub const I8: u8 = 0x10;
    pub const U8: u8 = 0x11;
    pub const I16: u8 = 0x12;
    pub const U16: u8 = 0x13;
    pub const I32: u8 = 0x14;
    pub const U32: u8 = 0x15;
    pub const F32: u8 = 0x21;
    pub const VEC3: u8 = 0x33;
    pub const VEC4: u8 = 0x34;
    /// 32-bit name hash.
    pub const HASH: u8 = 0x4A;
    /// Fixed-size array stored inline; `key` is the element count.
    pub const ARRAY_FIXED: u8 = 0x50;
    /// Array stored as `{ block ptr, u16 count, u16 capacity }`.
    pub const ARRAY_PTR: u8 = 0x51;
    /// Same storage as `ARRAY_PTR`.
    pub const ARRAY_PTR2: u8 = 0x52;
    // Variants with the same storage as the plain integers above (semantics unknown).
    pub const U8_ALT: u8 = 0x60;
    pub const I32_ALT: u8 = 0x62;
    pub const U32_ALT: u8 = 0x63;
    pub const U16_ALT: u8 = 0x64;
    pub const U32_ALT2: u8 = 0x65;
}

fn is_array(t: u8) -> bool {
    matches!(t, ty::ARRAY_FIXED | ty::ARRAY_PTR | ty::ARRAY_PTR2)
}

fn is_pointer(t: u8) -> bool {
    matches!(t, ty::PTR | ty::ARRAY_PTR | ty::ARRAY_PTR2)
}

/// Storage size in bytes of a scalar type (0 for non-scalars / unknown types).
fn scalar_size(t: u8) -> usize {
    match t {
        ty::BOOL | ty::I8 | ty::U8 | ty::U8_ALT => 1,
        ty::I16 | ty::U16 | ty::U16_ALT => 2,
        ty::I32 | ty::U32 | ty::F32 | ty::HASH | ty::I32_ALT | ty::U32_ALT | ty::U32_ALT2 => 4,
        ty::VEC3 => 12,
        ty::VEC4 => 16,
        _ => 0,
    }
}

// ============================================================================
// Small helpers
// ============================================================================

/// `write!` into a `String` cannot fail; these keep call sites free of `let _ =`.
macro_rules! wr {
    ($dst:expr, $($arg:tt)*) => {{ let _ = write!($dst, $($arg)*); }};
}
macro_rules! wrln {
    ($dst:expr, $($arg:tt)*) => {{ let _ = writeln!($dst, $($arg)*); }};
}

/// Returns `start..start + size` if it lies inside a buffer of `len` bytes.
fn checked_range(len: usize, start: usize, size: usize, what: &str) -> Res<Range<usize>> {
    match start.checked_add(size) {
        Some(end) if end <= len => Ok(start..end),
        _ => Err(format!("{what}: range {start:#x}+{size:#x} exceeds buffer of {len:#x} bytes")),
    }
}

/// Like [`checked_range`] for `count` records of `stride` bytes.
fn table_range(
    len: usize,
    start: usize,
    count: usize,
    stride: usize,
    what: &str,
) -> Res<Range<usize>> {
    let size = count
        .checked_mul(stride)
        .ok_or_else(|| format!("{what}: entry count {count} is too large"))?;
    checked_range(len, start, size, what)
}

/// Converts a flat table pointer into a body offset.
fn sys_offset(raw: u64, what: &str) -> Res<usize> {
    raw.checked_sub(SYSTEM_BASE)
        .and_then(|off| usize::try_from(off).ok())
        .ok_or_else(|| format!("bad {what} pointer {raw:#x}"))
}

fn align_up(x: usize, align: usize) -> usize {
    if align <= 1 { x } else { (x + align - 1) & !(align - 1) }
}

// ============================================================================
// Compression
// ============================================================================

/// Raw deflate at level 9 with memLevel 9 (what the game tools produce).
///
/// `flate2` cannot set memLevel, so this talks to zlib directly.
fn deflate_mem9(data: &[u8]) -> Res<Vec<u8>> {
    use libz_sys as z;

    /// Calls `deflateEnd` on every exit path.
    struct EndGuard(*mut z::z_stream);
    impl Drop for EndGuard {
        fn drop(&mut self) {
            // SAFETY: the pointer refers to a stream successfully initialised by
            // `deflateInit2_` that outlives this guard.
            unsafe { z::deflateEnd(self.0) };
        }
    }

    let in_len = u32::try_from(data.len()).map_err(|_| "input too large for zlib (4 GiB limit)")?;

    // `MaybeUninit` gives correct alignment and a zeroed stream (null allocators and
    // state), which is what `deflateInit2_` expects.
    let mut stream = std::mem::MaybeUninit::<z::z_stream>::zeroed();
    let strm = stream.as_mut_ptr();

    // SAFETY: `strm` points to a live, zeroed, correctly aligned `z_stream`; every
    // field is accessed through the raw pointer and never read as an invalid value.
    unsafe {
        let rc = z::deflateInit2_(
            strm,
            ZLIB_LEVEL,
            z::Z_DEFLATED,
            -15, // raw deflate, 32 KiB window
            9,   // memLevel
            z::Z_DEFAULT_STRATEGY,
            z::zlibVersion(),
            std::mem::size_of::<z::z_stream>() as i32,
        );
        if rc != z::Z_OK {
            return Err(format!("deflateInit2 failed: {rc}"));
        }
        let _guard = EndGuard(strm);

        let cap = z::deflateBound(strm, data.len() as z::uLong) as usize + 64;
        let avail_out = u32::try_from(cap).map_err(|_| "output buffer too large for zlib")?;
        let mut out = vec![0u8; cap];

        (*strm).next_in = data.as_ptr() as *mut u8;
        (*strm).avail_in = in_len;
        (*strm).next_out = out.as_mut_ptr();
        (*strm).avail_out = avail_out;

        let rc = z::deflate(strm, z::Z_FINISH);
        if rc != z::Z_STREAM_END {
            return Err(format!("deflate failed: {rc}"));
        }
        out.truncate((*strm).total_out as usize);
        Ok(out)
    }
}

// ============================================================================
// Hashing / names
// ============================================================================

/// Jenkins one-at-a-time hash.
fn joaat(s: &str) -> u32 {
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

struct NameTable {
    by_hash: HashMap<u32, &'static str>,
    by_name: HashMap<&'static str, u32>,
}

/// Lazily built lookup tables for [`NAMES`] (hashed once, not on every lookup).
fn names() -> &'static NameTable {
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
fn lookup_name(hash: u32) -> Option<&'static str> {
    if hash == ARRAYINFO {
        Some("ARRAYINFO")
    } else {
        names().by_hash.get(&hash).copied()
    }
}

/// Readable name for a hash, or `h_xxxxxxxx` if unknown.
fn known(hash: u32) -> String {
    lookup_name(hash).map_or_else(|| format!("h_{hash:08x}"), str::to_owned)
}

/// Inverse of [`known`]: `ARRAYINFO`, `h_xxxxxxxx` / `m_xxxxxxxx`, a known name,
/// or any other string (which is hashed).
fn parse_tag(s: &str) -> u32 {
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

// ============================================================================
// Platform layout (endianness + pointer width)
// ============================================================================

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Layout {
    /// `.ymt`: little-endian, 8-byte pointers.
    Pc,
    /// `.cmt`: big-endian, 4-byte pointers.
    Console,
}

fn bytes<const N: usize>(b: &[u8], o: usize) -> [u8; N] {
    b[o..o + N].try_into().expect("slice has exactly N bytes")
}

impl Layout {
    fn name(self) -> &'static str {
        match self {
            Layout::Pc => "pc",
            Layout::Console => "console",
        }
    }

    fn is_big_endian(self) -> bool {
        self == Layout::Console
    }

    fn ptr_width(self) -> usize {
        match self {
            Layout::Pc => 8,
            Layout::Console => 4,
        }
    }

    // The accessors below index without bounds checks of their own: callers validate
    // ranges first (see `checked_range`).

    fn u16(self, b: &[u8], o: usize) -> u16 {
        let a = bytes::<2>(b, o);
        if self.is_big_endian() { u16::from_be_bytes(a) } else { u16::from_le_bytes(a) }
    }

    fn u32(self, b: &[u8], o: usize) -> u32 {
        let a = bytes::<4>(b, o);
        if self.is_big_endian() { u32::from_be_bytes(a) } else { u32::from_le_bytes(a) }
    }

    fn f32(self, b: &[u8], o: usize) -> f32 {
        f32::from_bits(self.u32(b, o))
    }

    fn ptr(self, b: &[u8], o: usize) -> u64 {
        match self {
            Layout::Pc => u64::from_le_bytes(bytes::<8>(b, o)),
            Layout::Console => u64::from(self.u32(b, o)),
        }
    }

    fn put_u16(self, b: &mut [u8], o: usize, v: u16) {
        let a = if self.is_big_endian() { v.to_be_bytes() } else { v.to_le_bytes() };
        b[o..o + 2].copy_from_slice(&a);
    }

    fn put_u32(self, b: &mut [u8], o: usize, v: u32) {
        let a = if self.is_big_endian() { v.to_be_bytes() } else { v.to_le_bytes() };
        b[o..o + 4].copy_from_slice(&a);
    }

    fn put_f32(self, b: &mut [u8], o: usize, v: f32) {
        self.put_u32(b, o, v.to_bits());
    }

    fn put_ptr(self, b: &mut [u8], o: usize, v: u64) {
        match self {
            Layout::Pc => b[o..o + 8].copy_from_slice(&v.to_le_bytes()),
            Layout::Console => self.put_u32(b, o, v as u32),
        }
    }
}

/// Enum value counts are `u16` in big-endian files and `u32` in little-endian ones.
fn get_enum_count(lay: Layout, b: &[u8], o: usize) -> usize {
    if lay.is_big_endian() { lay.u16(b, o) as usize } else { lay.u32(b, o) as usize }
}

fn put_enum_count(lay: Layout, b: &mut [u8], o: usize, n: usize) -> Res<()> {
    if lay.is_big_endian() {
        lay.put_u16(b, o, u16::try_from(n).map_err(|_| format!("enum has too many values ({n})"))?);
    } else {
        lay.put_u32(b, o, u32::try_from(n).map_err(|_| format!("enum has too many values ({n})"))?);
    }
    Ok(())
}

// ============================================================================
// Schema
// ============================================================================

#[derive(Clone, Copy, Debug)]
struct Entry {
    name: u32,
    off: usize,
    ty: u8,
    key: u32,
}

/// Maps each array field to its `(element type, element key)`. An `ARRAYINFO`
/// pseudo-entry describes the next array field that follows it.
fn array_info(entries: &[Entry]) -> HashMap<u32, (u8, u32)> {
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
struct Def {
    size: usize,
    entries: Vec<Entry>,
    /// Body offset of this struct's entry array (so tables can be written back in place).
    entry_off: usize,
    /// Array element info, derived from `entries` once.
    arrays: HashMap<u32, (u8, u32)>,
}

impl Def {
    fn new(size: usize, entries: Vec<Entry>, entry_off: usize) -> Self {
        let arrays = array_info(&entries);
        Def { size, entries, entry_off, arrays }
    }
}

/// Element info of array field `name`, or an error if its `ARRAYINFO` is missing.
fn array_elem(def: &Def, name: u32) -> Res<(u8, u32)> {
    def.arrays
        .get(&name)
        .copied()
        .ok_or_else(|| format!("array {} has no ARRAYINFO", known(name)))
}

#[derive(Clone, Default)]
struct Schema {
    structs: HashMap<u32, Def>,
    /// Enum name -> `(value name hash, value)` pairs.
    enums: HashMap<u32, Vec<(u32, i32)>>,
    /// Body offset of each enum's value array.
    enum_val_off: HashMap<u32, usize>,
    /// Tables are written back in the order they were read.
    struct_order: Vec<u32>,
    enum_order: Vec<u32>,
    struct_table_off: usize,
    enum_table_off: usize,
    block_table_off: usize,
}

fn parse_schema(body: &[u8], lay: Layout) -> Res<Schema> {
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
struct Block {
    name: u32,
    data: Vec<u8>,
    /// Body offset of the block's first byte.
    off: usize,
}

/// Splits a block pointer into `(block index, offset)`; `None` for a null pointer.
fn decode_ptr(raw: u64) -> Option<(usize, usize)> {
    let id = (raw & 0xFFF) as usize;
    if id == 0 {
        None
    } else {
        Some((id - 1, ((raw >> 12) & 0xF_FFFF) as usize))
    }
}

fn encode_ptr(block_idx: usize, offset: usize) -> Res<u64> {
    if block_idx >= 0xFFF {
        return Err(format!("block index {block_idx} does not fit in a block pointer"));
    }
    if offset > 0xF_FFFF {
        return Err(format!("offset {offset:#x} does not fit in a 20-bit block pointer"));
    }
    Ok((block_idx as u64 + 1) | ((offset as u64) << 12))
}

fn parse_blocks(body: &[u8], lay: Layout) -> Res<Vec<Block>> {
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

// ============================================================================
// Tree model
// ============================================================================

#[derive(Clone, Debug)]
enum Val {
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
struct Field {
    name: u32,
    ty: u8,
    key: u32,
    val: Val,
    /// Raw block pointer for pointer-typed fields (kept so the original layout can be
    /// patched in place).
    ptr: Option<u64>,
}

#[derive(Clone, Debug)]
struct Struct {
    hash: u32,
    fields: Vec<Field>,
}

// ============================================================================
// Binary -> tree
// ============================================================================

fn read_scalar(lay: Layout, t: u8, b: &[u8], at: usize) -> Val {
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

struct BinReader<'a> {
    schema: &'a Schema,
    blocks: &'a [Block],
    lay: Layout,
}

impl<'a> BinReader<'a> {
    fn block(&self, idx: usize) -> Res<&'a [u8]> {
        self.blocks
            .get(idx)
            .map(|b| b.data.as_slice())
            .ok_or_else(|| format!("pointer to missing block {}", idx + 1))
    }

    fn elem_size(&self, t: u8, key: u32) -> usize {
        if t == ty::STRUCT {
            self.schema.structs.get(&key).map_or(0, |d| d.size)
        } else {
            scalar_size(t)
        }
    }

    fn read_struct(&self, hash: u32, blk: usize, base: usize, depth: usize) -> Res<Vec<Field>> {
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
    fn read_items(
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

// ============================================================================
// Layout computation (used when rebuilding a body from scratch)
// ============================================================================

#[derive(Clone, Default)]
struct StructLayout {
    size: usize,
    /// One offset per schema entry (including `ARRAYINFO` pseudo-entries).
    offsets: Vec<usize>,
}

/// `(size, alignment)` of a field.
///
/// Alignment rules are heuristic: nested structs and arrays are aligned to 4 bytes
/// regardless of their contents, and struct sizes are not rounded up to their
/// alignment. Verify against a real file of the target platform.
fn field_size_align(
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

fn layout_struct(
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
fn compute_layouts(defs: &[(u32, Vec<Entry>)], lay: Layout) -> HashMap<u32, StructLayout> {
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
fn collect_schema(root: &Struct) -> Vec<(u32, Vec<Entry>)> {
    fn walk(
        hash: u32,
        fields: &[Field],
        seen: &mut HashSet<u32>,
        out: &mut Vec<(u32, Vec<Entry>)>,
    ) {
        if !seen.insert(hash) {
            return;
        }
        let mut entries = Vec::with_capacity(fields.len());
        for f in fields {
            if let Val::Array { elem_ty, elem_key, .. } = &f.val {
                entries.push(Entry { name: ARRAYINFO, off: 0, ty: *elem_ty, key: *elem_key });
            }
            entries.push(Entry { name: f.name, off: 0, ty: f.ty, key: f.key });
        }
        out.push((hash, entries));

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
fn write_scalar(buf: &mut [u8], lay: Layout, t: u8, off: usize, v: &Val) -> Res<()> {
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
struct FullWriter<'a> {
    buf: Vec<u8>,
    lay: Layout,
    layouts: &'a HashMap<u32, StructLayout>,
    schema: &'a Schema,
    block_idx: usize,
}

impl FullWriter<'_> {
    /// Appends `size` zero bytes at the next `align`-aligned offset and returns it.
    fn alloc(&mut self, size: usize, align: usize) -> usize {
        let off = align_up(self.buf.len(), align);
        self.buf.resize(off + size, 0);
        off
    }

    fn elem_size(&self, et: u8, ek: u32) -> usize {
        if et == ty::STRUCT {
            self.layouts.get(&ek).map_or(0, |l| l.size)
        } else {
            scalar_size(et)
        }
    }

    fn write_items(
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

    fn write_struct(&mut self, off: usize, hash: u32, fields: &[Field], depth: usize) -> Res<()> {
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
// Tree -> XML
// ============================================================================

fn format_scalar(v: &Val) -> String {
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

fn xml_escape(s: &str) -> String {
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

fn xml_unescape(s: &str) -> String {
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
fn emit_fields(out: &mut String, fields: &[Field], depth: usize, schema: &Schema, struct_hash: u32) {
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
// Body index ("chunks")
//
// For same-layout round trips the XML carries a map of the original body so that
// bytes the tree cannot express (padding, unknown data, other blocks) survive.
// ============================================================================

#[derive(Clone, Debug)]
enum Chunk {
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
    fn size(&self) -> usize {
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
fn filler_chunk(body: &[u8], start: usize, end: usize, is_tail: bool) -> Chunk {
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

fn body_to_chunks(body: &[u8], blocks: &[Block], root_block_idx: usize) -> Res<Vec<Chunk>> {
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

fn chunks_to_xml(out: &mut String, chunks: &[Chunk], total: usize, blocks: &[Block]) {
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

fn chunks_from_xml(node: &XmlNode) -> Res<Vec<Chunk>> {
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
fn idx_attr(c: &XmlNode) -> Res<usize> {
    c.attrs
        .get("idx")
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| format!("<{}> has a missing or invalid 'idx'", c.tag))
}

// ============================================================================
// Tree -> binary (patching the original layout)
// ============================================================================

fn put_bytes(body: &mut [u8], off: usize, data: &[u8], what: &str) -> Res<()> {
    let range = checked_range(body.len(), off, data.len(), what)?;
    body[range].copy_from_slice(data);
    Ok(())
}

/// Writes the tree back into blocks whose positions and sizes are fixed.
struct ExactWriter<'a> {
    lay: Layout,
    schema: &'a Schema,
    /// Body offset of each block.
    offs: Vec<usize>,
    /// Size of each block.
    sizes: Vec<usize>,
}

impl ExactWriter<'_> {
    /// Absolute body position of `rel` inside block `blk`, after checking that `len`
    /// bytes fit inside that block.
    fn pos(&self, blk: usize, rel: usize, len: usize) -> Res<usize> {
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

    fn write_items(
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

    fn write_struct(
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
fn write_tables(
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
fn chunks_to_body(
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

// ============================================================================
// Whole document -> XML
// ============================================================================

fn tree_to_xml(
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

// ============================================================================
// Minimal XML parser
//
// Handles exactly what this tool reads and writes: elements, quoted attributes,
// comments and processing instructions. Text content is ignored.
// ============================================================================

struct XmlNode {
    tag: String,
    attrs: HashMap<String, String>,
    children: Vec<XmlNode>,
}

struct XmlParser<'a> {
    src: &'a [u8],
    pos: usize,
}

impl<'a> XmlParser<'a> {
    fn parse_document(text: &'a str) -> Res<XmlNode> {
        let mut p = XmlParser { src: text.as_bytes(), pos: 0 };
        p.skip_misc()?;
        p.parse_element(0)
    }

    fn peek(&self) -> Option<u8> {
        self.src.get(self.pos).copied()
    }

    fn starts_with(&self, pat: &[u8]) -> bool {
        self.src.get(self.pos..).is_some_and(|rest| rest.starts_with(pat))
    }

    fn skip_ws(&mut self) {
        while self.peek().is_some_and(|b| b.is_ascii_whitespace()) {
            self.pos += 1;
        }
    }

    /// Advances past the next occurrence of `pat`.
    fn skip_past(&mut self, pat: &[u8], what: &str) -> Res<()> {
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
    fn skip_misc(&mut self) -> Res<()> {
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

    fn parse_name(&mut self) -> String {
        let start = self.pos;
        while self
            .peek()
            .is_some_and(|b| !b.is_ascii_whitespace() && !matches!(b, b'>' | b'/' | b'='))
        {
            self.pos += 1;
        }
        String::from_utf8_lossy(&self.src[start..self.pos]).into_owned()
    }

    fn parse_attr(&mut self, tag: &str) -> Res<(String, String)> {
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

    fn parse_element(&mut self, depth: usize) -> Res<XmlNode> {
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
fn parse_hex_u64(s: &str) -> Option<u64> {
    let s = s.trim();
    let digits = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    u64::from_str_radix(digits, 16).ok()
}

fn parse_hex_attr(s: &str) -> Option<u32> {
    parse_hex_u64(s).and_then(|v| u32::try_from(v).ok())
}

/// First present attribute among `keys` (long names are accepted as aliases).
fn attr<'a>(n: &'a XmlNode, keys: &[&str]) -> Option<&'a str> {
    keys.iter().find_map(|k| n.attrs.get(*k).map(String::as_str))
}

fn hex_attr(n: &XmlNode, keys: &[&str]) -> Option<u32> {
    attr(n, keys).and_then(parse_hex_attr)
}

fn is_item_tag(tag: &str) -> bool {
    tag == "i" || tag == "Item"
}

fn child<'a>(n: &'a XmlNode, tag: &str) -> Res<&'a XmlNode> {
    n.children
        .iter()
        .find(|c| c.tag == tag)
        .ok_or_else(|| format!("missing <{tag}>"))
}

/// Decimal or `0x` hexadecimal integer with optional sign.
fn parse_integer(s: &str) -> Option<i128> {
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

fn parse_int<T: TryFrom<i128>>(s: &str, what: &str) -> Res<T> {
    parse_integer(s)
        .and_then(|v| T::try_from(v).ok())
        .ok_or_else(|| format!("invalid {what} value '{s}'"))
}

/// A 32-bit number, or a name that is hashed (`h_xxxxxxxx` and known names included).
fn parse_u32_or_tag(s: &str) -> Res<u32> {
    match parse_integer(s) {
        Some(n) => u32::try_from(n).map_err(|_| format!("value '{s}' does not fit in 32 bits")),
        None => Ok(parse_tag(s)),
    }
}

fn parse_f32(s: &str) -> Res<f32> {
    s.parse().map_err(|_| format!("invalid float '{s}'"))
}

fn parse_floats<const N: usize>(s: &str) -> Res<[f32; N]> {
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
fn zero_value(t: u8) -> Val {
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
fn parse_scalar(t: u8, text: &str) -> Res<Val> {
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

fn node_to_fields(
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

fn hex_to_bytes<const N: usize>(s: &str) -> Option<[u8; N]> {
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

// ============================================================================
// Loaded document
// ============================================================================

/// Everything needed to write any output format, produced by either reader.
struct Source {
    root: Struct,
    layout: Layout,
    outer: [u8; OUTER_LEN],
    schema: Schema,
    /// `(name hash, size)` of every block, in table order.
    blocks_info: Vec<(u32, usize)>,
    root_block_idx: usize,
    /// Original blocks and body; present when loaded from a binary file.
    binary: Option<(Vec<Block>, Vec<u8>)>,
    /// Body index; present when loaded from XML that carried a `<_Body>` section.
    chunks: Option<Vec<Chunk>>,
}

fn xml_to_tree(text: &str) -> Res<Source> {
    let root_node = XmlParser::parse_document(text)?;

    let layout = match attr(&root_node, &["layout"]) {
        Some("pc") => Layout::Pc,
        Some("console") => Layout::Console,
        _ => return Err("root tag missing layout=\"pc|console\"".into()),
    };
    let outer = attr(&root_node, &["header"])
        .and_then(hex_to_bytes::<OUTER_LEN>)
        .ok_or("root tag missing/invalid header")?;
    let root_block_idx = attr(&root_node, &["rootBlock"])
        .and_then(|s| s.parse::<usize>().ok())
        .ok_or("root tag missing rootBlock")?
        .saturating_sub(1);

    let schema_node = child(&root_node, "_Schema")?;
    let enums_node = child(&root_node, "_Enums")?;
    let blocks_node = child(&root_node, "_Blocks")?;
    let tree_node = child(&root_node, "_Tree")?;

    let mut schema = Schema {
        struct_table_off: hex_attr(&root_node, &["sTable"]).unwrap_or(0) as usize,
        enum_table_off: hex_attr(&root_node, &["eTable"]).unwrap_or(0) as usize,
        block_table_off: hex_attr(&root_node, &["bTable"]).unwrap_or(0) as usize,
        ..Schema::default()
    };

    for sn in schema_node.children.iter().filter(|n| n.tag == "Struct") {
        let hash = hex_attr(sn, &["h", "hash"]).ok_or("Struct missing h")?;
        let size = hex_attr(sn, &["z", "size"]).ok_or("Struct missing z")? as usize;
        let entry_off = hex_attr(sn, &["et"]).unwrap_or(0) as usize;

        let mut entries = Vec::new();
        for f in sn.children.iter().filter(|n| n.tag == "F") {
            entries.push(Entry {
                name: hex_attr(f, &["h", "hash"])
                    .or_else(|| attr(f, &["name"]).map(parse_tag))
                    .ok_or("F missing h/name")?,
                off: hex_attr(f, &["o", "off"]).ok_or("F missing o")? as usize,
                ty: hex_attr(f, &["t", "type"])
                    .and_then(|v| u8::try_from(v).ok())
                    .ok_or("F missing t")?,
                key: hex_attr(f, &["k", "key"]).unwrap_or(0),
            });
        }
        schema.struct_order.push(hash);
        schema.structs.insert(hash, Def::new(size, entries, entry_off));
    }

    for en in enums_node.children.iter().filter(|n| n.tag == "Enum") {
        let hash = hex_attr(en, &["h", "hash"]).ok_or("Enum missing h")?;
        let vals_off = hex_attr(en, &["ev"]).unwrap_or(0) as usize;

        let mut vals = Vec::new();
        for v in en.children.iter().filter(|n| n.tag == "V") {
            let key = hex_attr(v, &["h", "hash"]).ok_or("V missing h")?;
            let num = attr(v, &["num"]).and_then(|s| s.parse().ok()).unwrap_or(0);
            vals.push((key, num));
        }
        schema.enum_order.push(hash);
        schema.enums.insert(hash, vals);
        schema.enum_val_off.insert(hash, vals_off);
    }

    let mut blocks_info = Vec::new();
    for bn in blocks_node.children.iter().filter(|n| n.tag == "Block") {
        let hash = hex_attr(bn, &["hash"]).ok_or("Block missing hash")?;
        let size = hex_attr(bn, &["size"]).ok_or("Block missing size")? as usize;
        blocks_info.push((hash, size));
    }

    let root_hash = parse_tag(&root_node.tag);
    let root = Struct { hash: root_hash, fields: node_to_fields(tree_node, &schema, root_hash, 0)? };

    let chunks = root_node
        .children
        .iter()
        .find(|c| c.tag == "_Body")
        .map(chunks_from_xml)
        .transpose()?;

    Ok(Source { root, layout, outer, schema, blocks_info, root_block_idx, binary: None, chunks })
}

// ============================================================================
// Binary file I/O
// ============================================================================

struct BinDoc {
    schema: Schema,
    blocks: Vec<Block>,
    /// 0-based index of the root block.
    root_block_idx: usize,
    outer: [u8; OUTER_LEN],
    body: Vec<u8>,
}

fn read_document(path: &str, lay: Layout) -> Res<BinDoc> {
    let data = fs::read(path).map_err(|e| format!("cannot read {path}: {e}"))?;
    if data.len() < OUTER_LEN {
        return Err("file too short".into());
    }
    let (head, payload) = data.split_at(OUTER_LEN);
    let mut outer = [0u8; OUTER_LEN];
    outer.copy_from_slice(head);

    let mut body = Vec::new();
    DeflateDecoder::new(payload)
        .take(MAX_BODY_BYTES + 1)
        .read_to_end(&mut body)
        .map_err(|e| format!("inflate failed: {e}"))?;
    if body.len() as u64 > MAX_BODY_BYTES {
        return Err(format!("decompressed body exceeds {MAX_BODY_BYTES} bytes"));
    }

    let schema = parse_schema(&body, lay)?;
    let blocks = parse_blocks(&body, lay)?;
    let root_idx = lay.u32(&body, 0x1C) as usize;
    if root_idx == 0 || root_idx > blocks.len() {
        return Err(format!("invalid root index {root_idx}"));
    }
    Ok(BinDoc { schema, blocks, root_block_idx: root_idx - 1, outer, body })
}

fn load_binary(path: &str, lay: Layout) -> Res<Source> {
    let doc = read_document(path, lay)?;
    let root_hash = doc.blocks[doc.root_block_idx].name;

    let fields = BinReader { schema: &doc.schema, blocks: &doc.blocks, lay }
        .read_struct(root_hash, doc.root_block_idx, 0, 0)
        .map_err(|e| format!("tree error: {e}"))?;
    let blocks_info = doc.blocks.iter().map(|b| (b.name, b.data.len())).collect();

    Ok(Source {
        root: Struct { hash: root_hash, fields },
        layout: lay,
        outer: doc.outer,
        schema: doc.schema,
        blocks_info,
        root_block_idx: doc.root_block_idx,
        binary: Some((doc.blocks, doc.body)),
        chunks: None,
    })
}

/// Deflates `body` and prepends the outer header.
fn pack(outer: &[u8; OUTER_LEN], body: &[u8]) -> Res<Vec<u8>> {
    let compressed = deflate_mem9(body).map_err(|e| format!("compress error: {e}"))?;
    let mut out = Vec::with_capacity(OUTER_LEN + compressed.len());
    out.extend_from_slice(outer);
    out.extend_from_slice(&compressed);
    Ok(out)
}

// ============================================================================
// Rebuilding a body from scratch (cross-layout conversion)
// ============================================================================

/// Builds a complete body for `lay` from the tree alone: all structs are laid out
/// afresh and the whole tree is written into one block. Enums are carried over from
/// `source`.
fn rebuild_body(root: &Struct, lay: Layout, source: &Schema) -> Res<Vec<u8>> {
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
fn encode_binary(src: &Source, dst: Layout) -> Res<Vec<u8>> {
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

// ============================================================================
// Main
// ============================================================================

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Fmt {
    Cmt,
    Ymt,
    Xml,
}

impl Fmt {
    fn from_path(path: &str) -> Res<Fmt> {
        let lower = path.to_lowercase();
        if lower.ends_with(".cmt") {
            Ok(Fmt::Cmt)
        } else if lower.ends_with(".ymt") {
            Ok(Fmt::Ymt)
        } else if lower.ends_with(".xml") {
            Ok(Fmt::Xml)
        } else {
            Err(format!("unknown extension: {path}"))
        }
    }

    /// Binary layout implied by the format (`None` for XML, which stores its own).
    fn layout(self) -> Option<Layout> {
        match self {
            Fmt::Cmt => Some(Layout::Console),
            Fmt::Ymt => Some(Layout::Pc),
            Fmt::Xml => None,
        }
    }
}

fn convert(input: &str, in_fmt: Fmt, output: &str, out_fmt: Fmt) -> Res<()> {
    if in_fmt == Fmt::Xml && out_fmt == Fmt::Xml {
        return Err("both files are XML; nothing to convert".into());
    }

    let src = match in_fmt.layout() {
        Some(lay) => load_binary(input, lay)?,
        None => {
            let text = fs::read_to_string(input).map_err(|e| format!("cannot read {input}: {e}"))?;
            xml_to_tree(&text).map_err(|e| format!("xml parse error: {e}"))?
        }
    };
    let dst_layout = out_fmt.layout().unwrap_or(src.layout);

    match out_fmt {
        Fmt::Xml => {
            let (blocks, body) = src
                .binary
                .as_ref()
                .map(|(blocks, body)| (blocks.as_slice(), body.as_slice()))
                .ok_or("internal error: XML output needs a binary source")?;
            let xml = tree_to_xml(
                &src.root,
                &src.schema,
                blocks,
                src.root_block_idx,
                src.layout,
                &src.outer,
                body,
            )
            .map_err(|e| format!("xml write error: {e}"))?;
            fs::write(output, xml).map_err(|e| format!("cannot write {output}: {e}"))?;
        }
        Fmt::Cmt | Fmt::Ymt => {
            let bytes = encode_binary(&src, dst_layout).map_err(|e| format!("write error: {e}"))?;
            fs::write(output, bytes).map_err(|e| format!("cannot write {output}: {e}"))?;
        }
    }

    eprintln!(
        "done: {input} ({}) -> {output} ({})",
        src.layout.name(),
        dst_layout.name()
    );
    Ok(())
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        let prog = args.first().map_or("mt_tool", String::as_str);
        eprintln!("usage: {prog} <input> <output>");
        eprintln!("  .cmt = console  |  .ymt = pc  |  .xml = either");
        process::exit(2);
    }

    let formats = Fmt::from_path(&args[1]).and_then(|i| Ok((i, Fmt::from_path(&args[2])?)));
    let (in_fmt, out_fmt) = match formats {
        Ok(f) => f,
        Err(e) => {
            eprintln!("{e}");
            process::exit(2);
        }
    };

    if let Err(e) = convert(&args[1], in_fmt, &args[2], out_fmt) {
        eprintln!("error: {e}");
        process::exit(1);
    }
}
