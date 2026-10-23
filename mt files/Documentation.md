# mt_tool: how it works

`mt_tool` converts GTA V metadata files between console (`.cmt`) and PC (`.ymt`) layouts, and to and from XML. This page explains everything in one read: the file formats, each conversion path, the PSO reader and writer, the merge rules, the modules, and the known limits.

---

## 1. Quick start

```
mt_tool <input file|folder> [--to cmt|ymt|xml] [--schema FILE] [output file|folder]
```

| Command | What it does |
|---|---|
| `mt_tool a.cmt` | Converts to `.ymt` (default target). Output in `./output/a.ymt`. |
| `mt_tool a.ymt --to xml` | Writes `a.xml`. Works for RSC7 files and for raw PSO files. |
| `mt_tool a.xml --to cmt` | Writes `a.cmt` from the XML, using the layout the XML records. |
| `mt_tool pc.ymt --to cmt --schema console.cmt` | Raw PSO only: writes console-layout data, merged over `console.cmt` (see §6). |
| `mt_tool peds.xml --to cmt --schema peds_console.cmt` | Raw PSO only: writes XML as PSO, using `peds_console.cmt` as the template (see §5). |

Rules:
- With no `--to`, `.cmt` becomes `.ymt` and `.ymt` becomes `.cmt`.
- With no output, files go to `./output` and keep their name (only the extension changes).
- A folder input converts every `.cmt`, `.ymt` and `.xml` file directly inside it.
- The output file's extension must match `--to` when both are given.
- `--schema` must have the extension of the output format. The extension sets the pointer width: `.cmt` = 4 bytes, `.ymt` = 8 bytes.

---

## 2. The two file formats

The tool accepts two kinds of binary input. It detects which one by the first bytes of the file.

### 2.1 RSC7 resource files (the usual game files)

```
16-byte outer header  (magic "RSC7", version, system flags, graphics flags)
raw deflate stream    (the body, inflated)
```

The inflated body starts with a 0x50-byte header, followed by tables and data blocks:

```
0x00  header (0x50 bytes)
        0x1C root block index (1-based)   0x20 struct table pointer
        0x28 enum table pointer           0x30 block table pointer
        0x48 struct count   0x4A enum count   0x4C block count
0x50  struct table, struct entries, enum table, enum values, block table
....  data blocks
```

- Table pointers are flat: `SYSTEM_BASE + body offset`.
- Pointers inside blocks are block pointers: the low 12 bits hold the block id + 1, the high 20 bits hold the offset inside that block.
- PC files are little-endian with 8-byte pointers. Console files are big-endian with 4-byte pointers.

### 2.2 Raw PSO files (`PSIN` ...)

These files start with the tag `PSIN` (no RSC7 wrapper). The tool detects them by content (`pso::is_pso`), not by extension. The layout is:

```
PSIN  (tag, big-endian length, "pppppppp" placeholder, then data blocks)
      each block starts on a 16-byte boundary; block offsets are absolute file offsets
PMAP  (tag, length, root block id, block count (i16), 0x7070, 16-byte entries)
      entry = name hash, offset, unknown (0), length
PSCH  (schema: structures and enums; offsets are relative to PSCH's own start)
PSIG, STRE, CHKS   (trailing sections; STRE is encrypted and not read)
```

- All PSO sections are big-endian, PC and console alike. Only the pointer width differs.
- Pointers are the same as in RSC7: low 12 bits = 1-based block id, high 20 bits = offset.
- The PSCH section lists structures (kind 0) and enums (kind 1). A structure entry has a 12-byte field record: name hash, type, subtype, offset (u16), reference key.

---

## 3. Conversion paths

The entry point is `cli::convert`. The path depends on the input and output.

| Input | Output | Path | Module |
|---|---|---|---|
| RSC7 `.cmt`/`.ymt` | `--to xml` | RSC7 loader → tree → XML | `document`, `tree`, `xml_write` |
| RSC7 `.cmt`/`.ymt` | `.cmt`/`.ymt` | RSC7 loader → tree → rebuilt body | `rebuild`, `patch` |
| XML | `.cmt`/`.ymt` | XML → tree → body (patches the original body when the XML has its chunks, otherwise rebuilds) | `xml_read`, `patch`, `rebuild` |
| raw PSO | `--to xml` | `pso_to_xml` | `pso` |
| raw PSO | `.cmt`/`.ymt` | `pso_to_xml` → merge over `--schema` → `pso_write` | `pso`, `pso_write` |
| XML with `--schema` | `.cmt`/`.ymt` | strict XML → PSO using the template | `pso_write` |

Notes:
- The RSC7 path and the raw PSO path are separate. A raw PSO file never goes through the RSC7 loader, so the RSC7 errors (such as "inflate failed") do not apply to it.
- The XML path only uses the PSO writer when `--schema` is given. Without it, XML goes through the RSC7 writer, which expects the chunks that the RSC7 reader writes.
- Two outputs never overwrite each other or an input in one run. The `claimed` set in `cli.rs` tracks this.

---

## 4. Reading raw PSO (`pso.rs`)

`pso_to_xml(bytes, ptr_width)` returns the XML. `ptr_width` is 4 for `.cmt` and 8 for `.ymt`.

1. **Sections.** `locate_sections` walks the top-level sections (tag, length) from offset 0. PSIN must be at offset 0.
2. **Block table.** `read_pmap` reads the root id and the block list. Block ids are 1-based.
3. **Schema.** `read_psch` reads structures and enums. Structures are shared through `Rc`, so a lookup does not copy fields.
4. **Decoding.** The decoder walks the schema from the root block. Each structure writes one XML element. Its fields are written in schema order.

Field types and how they appear in XML:

| Type | Subtypes | XML |
|---|---|---|
| Bool (0x00) | | `<n value="true" />` |
| UByte (0x02) | | `<n value="N" />` |
| SInt (0x05) | | `<n value="N" />` |
| UInt (0x06) | 0 | `<n value="N" />` (printed signed) |
| Float (0x07) | | `<n value="N" />` |
| String (0x0B) | 0 inline ASCII, 1/2 DataBlockPointer, 3 CharPointer, 7/8 hash | `<n>text</n>` or `<n />` when empty |
| Structure (0x0C) | 0 inline, 3/4 pointer | `<n>...</n>` or `<n type="block">...</n>`; null pointer is `<n />` |
| Array (0x0D) | element = struct (subtype 0) or string (subtypes 2, 3, 7, 8) | `<n itemType="...">` with `<Item>` children; string items are `<Item>text</Item>` |
| Enum (0x0E) | 0 i32 key, 2 u8 key | `<n>Name</n>`; a key with no name gives `<n />` |
| Flags (0x0F) | 0 u32, 1 u16, 2 u8 | names joined by spaces; no enum gives `value="N"` |

Other types make the decoder fail with the field name and type. The tool does not guess.

Output rules follow CodeWalker's `PsoXml`:
- CRLF line endings. Indentation is one space per level.
- Text is escaped: `& < > "`.
- Hashes with a known name print the name. Unknown hashes print `hash_XXXXXXXX`.

---

## 5. Writing raw PSO (`pso_write.rs`)

`xml_to_pso(xml, template, ptr_width)` builds a PSO file from XML. The XML does not carry the schema, so the **template** supplies it: a PSO file of the target build.

### 5.1 What comes from the template

- The schema (`PSCH`), copied byte for byte.
- The root structure name. The XML root element must match it.
- The trailing sections (`PSIG`, `STRE`, `CHKS`), copied as they are. They are not recalculated, so a checksum or signature in them no longer matches the new data.

### 5.2 Output layout

- `PSIN`: tag, length, `pppppppp`, then the data blocks. Each block starts on a 16-byte boundary.
- Block 1 is the root structure at offset 0.
- New data goes into the block that has the same name, until the block would exceed 0xFFFFF bytes. Then a new block is opened. At most 4095 blocks.
- `PMAP`: root id 1, then one entry per block.
- Arrays are contiguous elements in one block. The header is the pointer, then the count twice (`u16`, `u16`) at `ptr_width`.
- All values are big-endian.

### 5.3 Encoding rules per field type

| Type | Rule |
|---|---|
| Bool | `true` = 1, `false` = 0. |
| SInt, UInt | Parsed as integers. UInt is accepted in the signed or unsigned range. |
| Float | Parsed as f32, stored as bits. |
| UByte | Parsed as u8. |
| Structure, inline | Encoded in place. |
| Structure, pointer | `<n />` is the null pointer. Otherwise the struct goes into a block named by its `type` attribute. |
| Enum | Name → key (first match). Empty text gets a key the enum does not use, so it reads back empty. |
| Flags | Names → bits (`1 << (key & 31)`). Bits without a name are lost. |
| String, inline (0) | ASCII, padded with NUL to the field length. Longer text is refused. |
| String, pointer (1, 2, 3) | Text stored NUL-terminated in the string block. Subtype 3 also writes the count twice. |
| String, hash (7, 8) | Jenkins hash of the text (`hash_XXXXXXXX` is taken as the raw value). |
| Array of structs | Items are encoded and placed in one block named by the element type. |
| Array of strings (2, 3, 7, 8) | One element per item, with the stride the reader expects. |

Refused on purpose:
- Non-ASCII text (the reader would show `?`).
- Unknown elements in a structure.
- Missing fields (strict XML mode).
- Field types the reader does not support.

### 5.4 Strict XML mode

`xml_to_pso` requires every field of the template to be present in the XML, and refuses unknown elements. This is the mode for XML that was written from the same build.

---

## 6. Merge mode (raw PSO input with `--schema`)

When the input is a raw PSO file, its data is merged over the template before writing (`pso_write::merge_to_pso`). The template is the base and the source overwrites it where the target has the same field.

Rules:
- **Leaf values** (scalars, strings, null pointers, empty arrays) in the source overwrite the template value.
- **Template-only fields** keep the template's value. Counted as *kept*.
- **Source-only fields** (for example a PC field that the console schema does not have) are dropped. Counted as *dropped*. They are never written.
- **Arrays of structs** match items by the text or value of their first field (for peds, the name). Matched items are merged recursively. Template items with no match are kept. Source items with no match are *added* only if they have every template field; otherwise they are *skipped*. Nothing is zero-filled.
- **Empty first field**: an item with no key matches the source item at the same position, if that one also has no key.
- **Template with no data** for a field: the source does not overwrite it, so nothing is invented.

The summary printed after each run:

```
fields overwritten N, kept from template N, dropped (not in target) N | items matched N, kept N, added N, skipped (incomplete) N
```

- *Matched* counts every array item matched by key, at every level.
- Use the counts to check a merge: `dropped` should equal the number of PC-only fields times the number of items, and `skipped` should be 0 unless the source is missing data.

Known consequence: when a source item is added, the fields it has that the template lacks are dropped (`restrict`).

---

## 7. Names

- Hashes are the Jenkins one-at-a-time hash (`names::joaat`).
- Known names come from two tables: the PSO occlusion names in `pso.rs` (`PSO_NAMES`) and the crate's table in `constants.rs` (`NAMES`).
- Unknown hashes print as `hash_XXXXXXXX`. A name typed in the XML is hashed when written, so it round-trips even if the table does not know it.
- The full CodeWalker dictionary is not included. In peds output about 106k names stay as `hash_XXXXXXXX`.

---

## 8. Module map

| File | Role |
|---|---|
| `main.rs` | Entry point and module list. |
| `cli.rs` | Arguments, output paths, routing for each conversion path, `write_output`. |
| `document.rs` | Loads RSC7 files and XML into a `Source` tree. |
| `compress.rs` | Raw deflate with the game tools' zlib settings. |
| `platform.rs` | `Layout`: endianness and pointer width (PC or console). |
| `constants.rs` | File-format constants, known names, field type tags. |
| `names.rs` | Jenkins hash and name lookups. |
| `schema.rs`, `tree.rs` | RSC7 schema and tree model. |
| `rebuild.rs` | RSC7: builds a body from the tree (cross-layout). |
| `patch.rs` | RSC7: same-layout round trips, body index ("chunks"). |
| `xml_read.rs`, `xml_write.rs` | RSC7 XML parser and writer. |
| `pso.rs` | Raw PSO reader: sections, PMAP, PSCH, decoding to XML. |
| `pso_write.rs` | Raw PSO writer: XML → PSO, merge mode, and the tests for both. |
| `util.rs` | Logging macros and bounds-checked arithmetic. |

Each module's first lines describe its job.

---

## 9. Tests

Run `cargo test`. Twenty tests cover:

- **Decoding:** a PC `.ymt` against a stored snapshot, a console `.cmt` counts check, the PC peds sample (strings and enums), rejection of non-PSO input and bad pointer widths.
- **Round trips** (decode → encode → decode gives the same XML): PC `.ymt`, console `.cmt`, PC peds, console peds (`testdata/peds_console.cmt`).
- **Edits:** a changed string is written; a missing field, an unknown element, a wrong root and non-ASCII text are refused.
- **Merge:** PC data into the console template drops the PC-only field; console data into the PC template keeps the PC-only lines; merging a file into itself changes nothing.

The round trips prove that the writer and reader agree. They do not prove that the game reads the output (see §10).

Testdata:
- `1289182.ymt`: PC sample, with `1289182_ymt_pso.xml` as its snapshot.
- `1273368218.cmt`: console sample.
- `peds.ymt`: PC peds (PSO).
- `peds_console.cmt`: console peds (PSO).

---

## 10. Limits

**Game compatibility is not verified.** Round trips work inside the tool. The output has not been tested in the game, and no CodeWalker reference was available to compare against.

**Checksums are copied, not recalculated.** `PSIG` and `CHKS` come from the template. If the game validates them, edited files will be rejected. The algorithm is unknown.

**Field types not supported yet** (the reader fails on them): SByte, SShort, UShort, Float2/3/4, Map, HFloat, Long, UByte arrays, and array subtypes 1, 2, 4 and 129. Files that use them fail with the field name in the error.

**Hash names:** unknown names stay as `hash_XXXXXXXX` and cannot be read back as names.

**Enums and flags:** values are not checked against CodeWalker. Flag bits without a name are lost. Enum keys without a name are written as a key the enum does not use.

**Strings:** non-ASCII text is refused.

**Merge:**
- Array items are matched by their first field. That works for peds, where the name is unique. Other asset types may need a different key.
- Only one template build is used. There is no field mapping beyond matching names.

**Inputs:**
- Raw PSO input only (starting with `PSIN`). RSC7-wrapped PSO files are not handled by the PSO path.
- The pointer width comes from the extension. A file with the wrong extension will be read with the wrong width.
- The template must be of the same asset type as the data.

**Size:** the PSO writer's layout is about 6% larger than the original on peds, with a different block count (4 instead of 5).

**Position differences:** position values differ between PC and console on `slab_city`. The cause is still unexplained, and may be real content differences or a decoding error.

---

## 11. Glossary

- **Block**: a region of data in a PSO file, named by a hash and found through `PMAP`.
- **Template**: the PSO file given with `--schema`. It supplies the schema and, in merge mode, the base data.
- **Schema**: the structure and enum definitions in `PSCH`.
- **Pointer width**: 4 bytes for console, 8 for PC, used for arrays and string counts.
- **Chunks**: the RSC7 body index, written into the XML so an XML → binary round trip can patch the original body.
