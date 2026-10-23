//! A loaded document (`Source`) and binary file I/O.

use std::io::Read;
use std::path::Path;
use std::fs;

use flate2::read::DeflateDecoder;

use crate::constants::{MAX_BODY_BYTES, OUTER_LEN, Res};
use crate::compress::deflate_mem9;
use crate::names::parse_tag;
use crate::platform::Layout;
use crate::schema::{Block, Def, Entry, Schema, parse_blocks, parse_schema};
use crate::tree::{BinReader, Struct};
use crate::patch::{Chunk, chunks_from_xml};
use crate::xml_read::{XmlParser, attr, child, hex_attr, hex_to_bytes, node_to_fields};

// ============================================================================
// Loaded document
// ============================================================================

/// Everything needed to write any output format, produced by either reader.
pub(crate) struct Source {
    pub(crate) root: Struct,
    pub(crate) layout: Layout,
    pub(crate) outer: [u8; OUTER_LEN],
    pub(crate) schema: Schema,
    /// `(name hash, size)` of every block, in table order.
    pub(crate) blocks_info: Vec<(u32, usize)>,
    pub(crate) root_block_idx: usize,
    /// Original blocks and body; present when loaded from a binary file.
    pub(crate) binary: Option<(Vec<Block>, Vec<u8>)>,
    /// Body index; present when loaded from XML that carried a `<_Body>` section.
    pub(crate) chunks: Option<Vec<Chunk>>,
}

pub(crate) fn xml_to_tree(text: &str) -> Res<Source> {
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

pub(crate) struct BinDoc {
    pub(crate) schema: Schema,
    pub(crate) blocks: Vec<Block>,
    /// 0-based index of the root block.
    pub(crate) root_block_idx: usize,
    pub(crate) outer: [u8; OUTER_LEN],
    pub(crate) body: Vec<u8>,
}

pub(crate) fn read_document(path: &Path, lay: Layout) -> Res<BinDoc> {
    let data = fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
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

pub(crate) fn load_binary(path: &Path, lay: Layout) -> Res<Source> {
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
pub(crate) fn pack(outer: &[u8; OUTER_LEN], body: &[u8]) -> Res<Vec<u8>> {
    let compressed = deflate_mem9(body).map_err(|e| format!("compress error: {e}"))?;
    let mut out = Vec::with_capacity(OUTER_LEN + compressed.len());
    out.extend_from_slice(outer);
    out.extend_from_slice(&compressed);
    Ok(out)
}
