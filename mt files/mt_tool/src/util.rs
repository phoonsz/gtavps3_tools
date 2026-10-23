//! Small shared helpers: logging macros and bounds-checked range arithmetic.

use std::ops::Range;

use crate::constants::{Res, SYSTEM_BASE};

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
pub(crate) fn checked_range(len: usize, start: usize, size: usize, what: &str) -> Res<Range<usize>> {
    match start.checked_add(size) {
        Some(end) if end <= len => Ok(start..end),
        _ => Err(format!("{what}: range {start:#x}+{size:#x} exceeds buffer of {len:#x} bytes")),
    }
}

/// Like [`checked_range`] for `count` records of `stride` bytes.
pub(crate) fn table_range(
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
pub(crate) fn sys_offset(raw: u64, what: &str) -> Res<usize> {
    raw.checked_sub(SYSTEM_BASE)
        .and_then(|off| usize::try_from(off).ok())
        .ok_or_else(|| format!("bad {what} pointer {raw:#x}"))
}

pub(crate) fn align_up(x: usize, align: usize) -> usize {
    if align <= 1 { x } else { (x + align - 1) & !(align - 1) }
}
