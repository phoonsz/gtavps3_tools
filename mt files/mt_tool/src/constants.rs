//! File-format constants, known names and the field type tags.

// ============================================================================
// Constants
// ============================================================================

/// Base added to body offsets in the flat (table) pointers.
pub(crate) const SYSTEM_BASE: u64 = 0x5000_0000;
/// Pseudo-entry that precedes an array field and describes its element type.
pub(crate) const ARRAYINFO: u32 = 0x0000_0100;

/// zlib compression level used when writing (memLevel 9, raw deflate).
pub(crate) const ZLIB_LEVEL: i32 = 9;
/// Maximum struct / XML nesting depth accepted.
pub(crate) const MAX_DEPTH: usize = 64;
/// Upper bound for an inflated body (guards against decompression bombs).
pub(crate) const MAX_BODY_BYTES: u64 = 256 * 1024 * 1024;
/// Iteration cap for the struct-size fixed point in `compute_layouts`.
pub(crate) const MAX_LAYOUT_PASSES: usize = 30;

pub(crate) const OUTER_LEN: usize = 16;
pub(crate) const HEADER_LEN: usize = 0x50;
pub(crate) const STRUCT_REC: usize = 32;
pub(crate) const ENTRY_REC: usize = 16;
pub(crate) const ENUM_REC: usize = 24;
pub(crate) const ENUM_VAL: usize = 8;
pub(crate) const BLOCK_REC: usize = 16;

pub(crate) type Res<T> = Result<T, String>;

/// Names whose hashes we can resolve to readable XML tags.
pub(crate) const NAMES: &[&str] = &[
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
pub(crate) mod ty {
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

pub(crate) fn is_array(t: u8) -> bool {
    matches!(t, ty::ARRAY_FIXED | ty::ARRAY_PTR | ty::ARRAY_PTR2)
}

pub(crate) fn is_pointer(t: u8) -> bool {
    matches!(t, ty::PTR | ty::ARRAY_PTR | ty::ARRAY_PTR2)
}

/// Storage size in bytes of a scalar type (0 for non-scalars / unknown types).
pub(crate) fn scalar_size(t: u8) -> usize {
    match t {
        ty::BOOL | ty::I8 | ty::U8 | ty::U8_ALT => 1,
        ty::I16 | ty::U16 | ty::U16_ALT => 2,
        ty::I32 | ty::U32 | ty::F32 | ty::HASH | ty::I32_ALT | ty::U32_ALT | ty::U32_ALT2 => 4,
        ty::VEC3 => 12,
        ty::VEC4 => 16,
        _ => 0,
    }
}
