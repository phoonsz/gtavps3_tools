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
//! # Usage
//!
//! ```text
//! mt_tool <input file|folder> [--to cmt|ymt|xml] [output file|folder]
//! ```
//!
//! * With no `--to`, `.cmt` becomes `.ymt` and `.ymt` becomes `.cmt`.
//! * With no output, files go to `./output` and keep their name (new extension only).
//! * A folder input converts every `.cmt` / `.ymt` / `.xml` file directly inside it.
//!
//! Crates: `flate2`, `base64` (0.21+), `libz-sys`.

#[macro_use]
mod util;
mod constants;
mod compress;
mod names;
mod platform;
mod schema;
mod tree;
mod rebuild;
mod patch;
mod xml_write;
mod xml_read;
mod document;
mod cli;
mod pso;
mod pso_write;

fn main() {
    cli::run();
}
