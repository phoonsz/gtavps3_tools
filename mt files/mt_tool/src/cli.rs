//! Command-line interface: argument parsing, output resolution, single-file and folder conversion.
//!
//! Usage: `mt_tool <input file|folder> [--to cmt|ymt|xml] [output file|folder]`

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::{env, fs, process};

use crate::constants::Res;
use crate::platform::Layout;
use crate::rebuild::encode_binary;
use crate::xml_write::tree_to_xml;
use crate::document::{load_binary, xml_to_tree};
use crate::pso::{is_pso, pso_to_xml};
use crate::pso_write::{merge_to_pso, xml_to_pso};

// ============================================================================
// Main
// ============================================================================

/// Folder that receives the converted files when no output is given.
pub(crate) const DEFAULT_OUT_DIR: &str = "output";

pub(crate) const USAGE: &str = "\
usage: mt_tool <input file|folder> [--to cmt|ymt|xml] [--schema FILE] [output file|folder]

  input       a .cmt / .ymt / .xml file, or a folder containing such files
  --to FMT    target format: cmt, ymt or xml
              (default: cmt -> ymt and ymt -> cmt; xml -> the format of its layout)
  --schema F  a PSO file of the target build. Required when the output is a raw PSO
              (a file that starts with PSIN). For PSO input, the input's data is merged
              over this file: fields the target has are overwritten, the rest keep the
              file's values. For XML input, every field must be in the XML.
  output      file or folder to write to (default: ./output)

With no output the converted file keeps its name and only the extension changes
(e.g. ped.cmt -> output/ped.ymt).";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Fmt {
    Cmt,
    Ymt,
    Xml,
}

impl Fmt {
    /// Format implied by a path's extension (case-insensitive).
    pub(crate) fn from_ext(path: &Path) -> Option<Fmt> {
        let ext = path.extension()?.to_str()?.to_ascii_lowercase();
        match ext.as_str() {
            "cmt" => Some(Fmt::Cmt),
            "ymt" => Some(Fmt::Ymt),
            "xml" => Some(Fmt::Xml),
            _ => None,
        }
    }

    /// Parses the value of `--to` (`cmt`, `ymt` or `xml`, with or without a dot).
    pub(crate) fn parse(s: &str) -> Res<Fmt> {
        match s.trim().trim_start_matches('.').to_ascii_lowercase().as_str() {
            "cmt" => Ok(Fmt::Cmt),
            "ymt" => Ok(Fmt::Ymt),
            "xml" => Ok(Fmt::Xml),
            _ => Err(format!("unknown format '{s}' for --to (expected cmt, ymt or xml)")),
        }
    }

    pub(crate) fn ext(self) -> &'static str {
        match self {
            Fmt::Cmt => "cmt",
            Fmt::Ymt => "ymt",
            Fmt::Xml => "xml",
        }
    }

    /// Binary layout implied by the format (`None` for XML, which stores its own).
    pub(crate) fn layout(self) -> Option<Layout> {
        match self {
            Fmt::Cmt => Some(Layout::Console),
            Fmt::Ymt => Some(Layout::Pc),
            Fmt::Xml => None,
        }
    }

    /// Target used when none is requested: cmt <-> ymt. XML has no direction of its
    /// own, so it goes back to the binary format of the layout it records.
    pub(crate) fn default_target(self, src_layout: Layout) -> Fmt {
        match self {
            Fmt::Cmt => Fmt::Ymt,
            Fmt::Ymt => Fmt::Cmt,
            Fmt::Xml => match src_layout {
                Layout::Pc => Fmt::Ymt,
                Layout::Console => Fmt::Cmt,
            },
        }
    }
}

/// Where converted files go.
pub(crate) enum OutSpec {
    /// A folder; each file keeps its name and gets the extension of its new format.
    Dir(PathBuf),
    /// One explicit output file (single-file input only).
    File(PathBuf),
}

impl OutSpec {
    pub(crate) fn path_for(&self, input: &Path, fmt: Fmt) -> Res<PathBuf> {
        match self {
            OutSpec::File(p) => Ok(p.clone()),
            OutSpec::Dir(dir) => {
                let stem = input
                    .file_stem()
                    .ok_or_else(|| format!("{} has no file name", input.display()))?;
                let mut name = stem.to_os_string();
                name.push(".");
                name.push(fmt.ext());
                Ok(dir.join(name))
            }
        }
    }
}

/// Decides whether the output argument is a folder or a file.
///
/// * no output                          -> folder `output`
/// * folder input                       -> always a folder
/// * file input, output is an existing folder, ends in `/` or `\`, or has no
///   `.cmt` / `.ymt` / `.xml` extension -> folder
/// * file input, output has such an extension -> file
pub(crate) fn resolve_output(input_is_dir: bool, arg: Option<&Path>) -> Res<OutSpec> {
    let Some(p) = arg else {
        return Ok(OutSpec::Dir(PathBuf::from(DEFAULT_OUT_DIR)));
    };
    let has_known_ext = Fmt::from_ext(p).is_some();
    let ends_with_sep = p.to_string_lossy().ends_with(|c: char| c == '/' || c == '\\');

    if input_is_dir {
        if has_known_ext && !p.is_dir() {
            return Err(format!(
                "the input is a folder, so the output must be a folder too (got file path {})",
                p.display()
            ));
        }
        Ok(OutSpec::Dir(p.to_path_buf()))
    } else if p.is_dir() || ends_with_sep || !has_known_ext {
        Ok(OutSpec::Dir(p.to_path_buf()))
    } else {
        Ok(OutSpec::File(p.to_path_buf()))
    }
}

/// A path normalised for comparison: parent folder canonicalised (when it exists) and
/// lowercased, so `./in/A.cmt` and `in/a.cmt` compare equal.
pub(crate) fn path_key(p: &Path) -> String {
    let name = p.file_name().map(|n| n.to_os_string()).unwrap_or_default();
    let parent = match p.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    };
    let parent = fs::canonicalize(parent).unwrap_or_else(|_| parent.to_path_buf());
    parent.join(name).to_string_lossy().to_lowercase()
}

/// Reads the `--schema` template. Binary PSO output cannot be written without one.
/// The template must have the extension of the output format: the extension is what sets the
/// pointer width (`.cmt` is 4 bytes, `.ymt` is 8), so a mismatch would give a broken file.
fn read_template(schema: Option<&Path>, out_fmt: Fmt) -> Res<Vec<u8>> {
    let path = schema.ok_or(
        "a raw PSO file needs --schema <a PSO file of the target build> to write its output",
    )?;
    if Fmt::from_ext(path) != Some(out_fmt) {
        return Err(format!(
            "--schema {} must be a .{} file to write a .{} output",
            path.display(),
            out_fmt.ext(),
            out_fmt.ext()
        ));
    }
    let bytes = fs::read(path).map_err(|e| format!("cannot read schema {}: {e}", path.display()))?;
    if !is_pso(&bytes) {
        return Err(format!("--schema {} is not a PSO file", path.display()));
    }
    Ok(bytes)
}

/// Writes one output, refusing paths already claimed in this run.
fn write_output(out_path: &Path, data: Vec<u8>, claimed: &mut HashSet<String>) -> Res<()> {
    if !claimed.insert(path_key(out_path)) {
        return Err(format!(
            "refusing to write {}: it is an input file or was already produced from \
             another input with the same name",
            out_path.display()
        ));
    }
    if let Some(dir) = out_path.parent().filter(|d| !d.as_os_str().is_empty()) {
        fs::create_dir_all(dir)
            .map_err(|e| format!("cannot create folder {}: {e}", dir.display()))?;
    }
    fs::write(out_path, data).map_err(|e| format!("cannot write {}: {e}", out_path.display()))
}

/// Converts one file. `claimed` holds the [`path_key`]s of every input file plus every
/// output produced so far in this run, so an output never overwrites an input, and two
/// inputs that map to the same output name (`a.cmt` and `a.xml` -> `a.ymt`) never
/// silently overwrite each other.
pub(crate) fn convert(
    input: &Path,
    out: &OutSpec,
    to: Option<Fmt>,
    schema: Option<&Path>,
    claimed: &mut HashSet<String>,
) -> Res<()> {
    let in_fmt = Fmt::from_ext(input)
        .ok_or_else(|| format!("unknown extension: {}", input.display()))?;

    // Format fixed by the request itself: `--to`, or the extension of an output file.
    let requested = to.or(match out {
        OutSpec::File(p) => Fmt::from_ext(p),
        OutSpec::Dir(_) => None,
    });
    if in_fmt == Fmt::Xml && requested == Some(Fmt::Xml) {
        return Err("both files are XML; nothing to convert".into());
    }

    // Raw PSO payloads (PSIN/PMAP/PSCH, detected by content) are not RSC7 containers.
    // They are read by pso.rs. Binary output is written by pso_write.rs from the XML and the
    // schema of the `--schema` template.
    if in_fmt != Fmt::Xml {
        let bytes = fs::read(input)
            .map_err(|e| format!("cannot read {}: {e}", input.display()))?;
        if is_pso(&bytes) {
            let in_width = in_fmt.layout().map_or(8, |l| l.ptr_width());
            if requested == Some(Fmt::Xml) {
                let xml = pso_to_xml(&bytes, in_width).map_err(|e| format!("pso error: {e}"))?;
                let out_path = out.path_for(input, Fmt::Xml)?;
                write_output(&out_path, xml.into_bytes(), claimed)?;
                eprintln!("PSO -> XML: {} -> {}", input.display(), out_path.display());
                return Ok(());
            }
            let out_fmt = requested.unwrap_or_else(|| in_fmt.default_target(Layout::Pc));
            let xml = pso_to_xml(&bytes, in_width).map_err(|e| format!("pso error: {e}"))?;
            // The template's own data is the base. The source overwrites what the target has.
            let template = read_template(schema, out_fmt)?;
            let out_width = out_fmt.layout().map_or(8, |l| l.ptr_width());
            let template_xml =
                pso_to_xml(&template, out_width).map_err(|e| format!("schema error: {e}"))?;
            let (data, st) = merge_to_pso(&xml, &template_xml, &template, out_width)
                .map_err(|e| format!("pso write error: {e}"))?;
            let out_path = out.path_for(input, out_fmt)?;
            write_output(&out_path, data, claimed)?;
            eprintln!(
                "PSO: {} -> {} | fields overwritten {}, kept from template {}, dropped (not in target) {} | items matched {}, kept {}, added {}, skipped (incomplete) {}",
                input.display(),
                out_path.display(),
                st.overwritten,
                st.kept,
                st.dropped,
                st.items_matched,
                st.items_kept,
                st.items_added,
                st.items_skipped
            );
            return Ok(());
        }
    }

    // XML written by `pso_to_xml` becomes a raw PSO when a schema template is given.
    // Without `--to`, the template's own format is the target.
    if in_fmt == Fmt::Xml {
        if let Some(template_path) = schema {
            let out_fmt = requested
                .or_else(|| Fmt::from_ext(template_path))
                .ok_or("cannot tell the output format: give --to cmt or --to ymt")?;
            if out_fmt == Fmt::Xml {
                return Err("--schema applies only to .cmt or .ymt output".into());
            }
            let text = fs::read_to_string(input)
                .map_err(|e| format!("cannot read {}: {e}", input.display()))?;
            let template = read_template(Some(template_path), out_fmt)?;
            let out_width = out_fmt.layout().map_or(8, |l| l.ptr_width());
            let data = xml_to_pso(&text, &template, out_width)
                .map_err(|e| format!("pso write error: {e}"))?;
            let out_path = out.path_for(input, out_fmt)?;
            write_output(&out_path, data, claimed)?;
            eprintln!("XML -> PSO: {} -> {}", input.display(), out_path.display());
            return Ok(());
        }
    }

    let src = match in_fmt.layout() {
        Some(lay) => load_binary(input, lay)?,
        None => {
            let text = fs::read_to_string(input)
                .map_err(|e| format!("cannot read {}: {e}", input.display()))?;
            xml_to_tree(&text).map_err(|e| format!("xml parse error: {e}"))?
        }
    };

    let out_fmt = requested.unwrap_or_else(|| in_fmt.default_target(src.layout));
    let dst_layout = out_fmt.layout().unwrap_or(src.layout);

    let out_path = out.path_for(input, out_fmt)?;

    let data: Vec<u8> = match out_fmt {
        Fmt::Xml => {
            let (blocks, body) = src
                .binary
                .as_ref()
                .map(|(blocks, body)| (blocks.as_slice(), body.as_slice()))
                .ok_or("internal error: XML output needs a binary source")?;
            tree_to_xml(
                &src.root,
                &src.schema,
                blocks,
                src.root_block_idx,
                src.layout,
                &src.outer,
                body,
            )
            .map_err(|e| format!("xml write error: {e}"))?
            .into_bytes()
        }
        Fmt::Cmt | Fmt::Ymt => {
            encode_binary(&src, dst_layout).map_err(|e| format!("write error: {e}"))?
        }
    };

    if !claimed.insert(path_key(&out_path)) {
        return Err(format!(
            "refusing to write {}: it is an input file or was already produced from \
             another input with the same name",
            out_path.display()
        ));
    }
    if let Some(dir) = out_path.parent().filter(|d| !d.as_os_str().is_empty()) {
        fs::create_dir_all(dir)
            .map_err(|e| format!("cannot create folder {}: {e}", dir.display()))?;
    }
    fs::write(&out_path, data).map_err(|e| format!("cannot write {}: {e}", out_path.display()))?;

    eprintln!(
        "done: {} ({}) -> {} ({})",
        input.display(),
        src.layout.name(),
        out_path.display(),
        dst_layout.name()
    );
    Ok(())
}

/// The `.cmt` / `.ymt` / `.xml` files directly inside `dir`, sorted by path.
pub(crate) fn list_inputs(dir: &Path) -> Res<Vec<PathBuf>> {
    let entries =
        fs::read_dir(dir).map_err(|e| format!("cannot read folder {}: {e}", dir.display()))?;
    let mut files = Vec::new();
    for entry in entries {
        let path = entry
            .map_err(|e| format!("cannot read folder {}: {e}", dir.display()))?
            .path();
        if path.is_file() && Fmt::from_ext(&path).is_some() {
            files.push(path);
        }
    }
    files.sort();
    Ok(files)
}

pub(crate) struct Cli {
    pub(crate) input: PathBuf,
    pub(crate) output: Option<PathBuf>,
    pub(crate) to: Option<Fmt>,
    pub(crate) schema: Option<PathBuf>,
}

/// `Ok(None)` means help was requested.
pub(crate) fn parse_args(args: &[String]) -> Res<Option<Cli>> {
    let mut positional: Vec<&str> = Vec::new();
    let mut to: Option<Fmt> = None;
    let mut schema: Option<PathBuf> = None;

    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "-h" | "--help" => return Ok(None),
            "--to" => {
                let v = it.next().ok_or("--to needs a value (cmt, ymt or xml)")?;
                to = Some(Fmt::parse(v)?);
            }
            s if s.starts_with("--to=") => to = Some(Fmt::parse(&s["--to=".len()..])?),
            "--schema" => {
                let v = it.next().ok_or("--schema needs a file path")?;
                schema = Some(PathBuf::from(v));
            }
            s if s.starts_with("--schema=") => {
                schema = Some(PathBuf::from(&s["--schema=".len()..]));
            }
            s if s.starts_with("--") => return Err(format!("unknown option '{s}'")),
            s => positional.push(s),
        }
    }

    let mut pos = positional.into_iter();
    let input = pos.next().ok_or("missing <input>")?;
    let output = pos.next();
    if let Some(extra) = pos.next() {
        return Err(format!("unexpected extra argument '{extra}'"));
    }
    Ok(Some(Cli {
        input: PathBuf::from(input),
        output: output.map(PathBuf::from),
        to,
        schema,
    }))
}

/// What to convert and where to put it, validated before anything is touched.
pub(crate) struct Job {
    pub(crate) files: Vec<PathBuf>,
    /// The input was a folder.
    pub(crate) batch: bool,
    pub(crate) out: OutSpec,
    pub(crate) schema: Option<PathBuf>,
}

pub(crate) fn plan(cli: &Cli) -> Res<Job> {
    let meta = fs::metadata(&cli.input)
        .map_err(|e| format!("cannot access {}: {e}", cli.input.display()))?;
    let batch = meta.is_dir();
    let out = resolve_output(batch, cli.output.as_deref())?;

    if let (OutSpec::File(p), Some(t)) = (&out, cli.to) {
        if Fmt::from_ext(p) != Some(t) {
            return Err(format!(
                "--to {} does not match the extension of the output file {}",
                t.ext(),
                p.display()
            ));
        }
    }

    let files = if batch {
        let files = list_inputs(&cli.input)?;
        if files.is_empty() {
            return Err(format!("no .cmt, .ymt or .xml files in {}", cli.input.display()));
        }
        files
    } else {
        if Fmt::from_ext(&cli.input).is_none() {
            return Err(format!("unknown extension: {}", cli.input.display()));
        }
        vec![cli.input.clone()]
    };
    Ok(Job {
        files,
        batch,
        out,
        schema: cli.schema.clone(),
    })
}

/// Runs the job; returns `true` if every file was converted (or deliberately skipped).
pub(crate) fn execute(job: &Job, to: Option<Fmt>) -> bool {
    let mut claimed: HashSet<String> = job.files.iter().map(|f| path_key(f)).collect();
    let (mut ok, mut failed, mut skipped) = (0usize, 0usize, 0usize);

    for file in &job.files {
        // In a folder, XML files have nothing to do when XML is the target.
        if job.batch && to == Some(Fmt::Xml) && Fmt::from_ext(file) == Some(Fmt::Xml) {
            eprintln!("skipped: {} (already XML)", file.display());
            skipped += 1;
            continue;
        }
        match convert(file, &job.out, to, job.schema.as_deref(), &mut claimed) {
            Ok(()) => ok += 1,
            Err(e) => {
                eprintln!("error: {}: {e}", file.display());
                failed += 1;
            }
        }
    }

    if job.batch {
        eprintln!("{ok} converted, {failed} failed, {skipped} skipped");
    }
    failed == 0
}

pub(crate) fn run() {
    let args: Vec<String> = env::args().skip(1).collect();
    let cli = match parse_args(&args) {
        Ok(Some(cli)) => cli,
        Ok(None) => {
            println!("{}", USAGE);
            return;
        }
        Err(e) => {
            eprintln!("error: {e}\n\n{}", USAGE);
            process::exit(2);
        }
    };

    let job = match plan(&cli) {
        Ok(job) => job,
        Err(e) => {
            eprintln!("error: {e}");
            process::exit(2);
        }
    };

    if !execute(&job, cli.to) {
        process::exit(1);
    }
}
