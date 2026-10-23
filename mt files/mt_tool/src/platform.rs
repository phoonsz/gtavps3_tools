//! Platform layout: endianness and pointer width (`.ymt` PC vs `.cmt` console).

use crate::constants::Res;

// ============================================================================
// Platform layout (endianness + pointer width)
// ============================================================================

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Layout {
    /// `.ymt`: little-endian, 8-byte pointers.
    Pc,
    /// `.cmt`: big-endian, 4-byte pointers.
    Console,
}

pub(crate) fn bytes<const N: usize>(b: &[u8], o: usize) -> [u8; N] {
    b[o..o + N].try_into().expect("slice has exactly N bytes")
}

impl Layout {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Layout::Pc => "pc",
            Layout::Console => "console",
        }
    }

    pub(crate) fn is_big_endian(self) -> bool {
        self == Layout::Console
    }

    pub(crate) fn ptr_width(self) -> usize {
        match self {
            Layout::Pc => 8,
            Layout::Console => 4,
        }
    }

    // The accessors below index without bounds checks of their own: callers validate
    // ranges first (see `checked_range`).

    pub(crate) fn u16(self, b: &[u8], o: usize) -> u16 {
        let a = bytes::<2>(b, o);
        if self.is_big_endian() { u16::from_be_bytes(a) } else { u16::from_le_bytes(a) }
    }

    pub(crate) fn u32(self, b: &[u8], o: usize) -> u32 {
        let a = bytes::<4>(b, o);
        if self.is_big_endian() { u32::from_be_bytes(a) } else { u32::from_le_bytes(a) }
    }

    pub(crate) fn f32(self, b: &[u8], o: usize) -> f32 {
        f32::from_bits(self.u32(b, o))
    }

    pub(crate) fn ptr(self, b: &[u8], o: usize) -> u64 {
        match self {
            Layout::Pc => u64::from_le_bytes(bytes::<8>(b, o)),
            Layout::Console => u64::from(self.u32(b, o)),
        }
    }

    pub(crate) fn put_u16(self, b: &mut [u8], o: usize, v: u16) {
        let a = if self.is_big_endian() { v.to_be_bytes() } else { v.to_le_bytes() };
        b[o..o + 2].copy_from_slice(&a);
    }

    pub(crate) fn put_u32(self, b: &mut [u8], o: usize, v: u32) {
        let a = if self.is_big_endian() { v.to_be_bytes() } else { v.to_le_bytes() };
        b[o..o + 4].copy_from_slice(&a);
    }

    pub(crate) fn put_f32(self, b: &mut [u8], o: usize, v: f32) {
        self.put_u32(b, o, v.to_bits());
    }

    pub(crate) fn put_ptr(self, b: &mut [u8], o: usize, v: u64) {
        match self {
            Layout::Pc => b[o..o + 8].copy_from_slice(&v.to_le_bytes()),
            Layout::Console => self.put_u32(b, o, v as u32),
        }
    }
}

/// Enum value counts are `u16` in big-endian files and `u32` in little-endian ones.
pub(crate) fn get_enum_count(lay: Layout, b: &[u8], o: usize) -> usize {
    if lay.is_big_endian() { lay.u16(b, o) as usize } else { lay.u32(b, o) as usize }
}

pub(crate) fn put_enum_count(lay: Layout, b: &mut [u8], o: usize, n: usize) -> Res<()> {
    if lay.is_big_endian() {
        lay.put_u16(b, o, u16::try_from(n).map_err(|_| format!("enum has too many values ({n})"))?);
    } else {
        lay.put_u32(b, o, u32::try_from(n).map_err(|_| format!("enum has too many values ({n})"))?);
    }
    Ok(())
}
