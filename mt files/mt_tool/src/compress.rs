//! Raw deflate with the exact zlib settings the game tools use.

use crate::constants::{Res, ZLIB_LEVEL};

// ============================================================================
// Compression
// ============================================================================

/// Raw deflate at level 9 with memLevel 9 (what the game tools produce).
///
/// `flate2` cannot set memLevel, so this talks to zlib directly.
pub(crate) fn deflate_mem9(data: &[u8]) -> Res<Vec<u8>> {
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
