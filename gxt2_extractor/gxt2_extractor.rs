use std::env;
use std::fs::File;
use std::io::{self, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process;

fn usage(p: &str) {
    eprintln!(
"Usage:
  {0} <input.gxt2>
  {0} -i <input.gxt2> -o <out.txt>
  {0} -h | --help

PS3 (big-endian) GXT2:
  magic  'GXT2'
  count  u32 BE
  table  count * (hash u32 BE, offset u32 BE)
  strings null-terminated UTF-8 at each offset",
        p
    );
}

fn default_out(input: &Path) -> PathBuf {
    let mut o = input.to_path_buf();
    o.set_extension("txt");
    o
}

fn u32_be(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

fn read_cstr<R: Read>(r: &mut R) -> io::Result<String> {
    let mut v = Vec::new();
    let mut b = [0u8; 1];
    loop {
        r.read_exact(&mut b)?;
        if b[0] == 0 { break; }
        v.push(b[0]);
        if v.len() > 1_000_000 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "string too long"));
        }
    }
    Ok(String::from_utf8_lossy(&v).into_owned())
}

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    let prog = args.get(0).map(String::as_str).unwrap_or("gxt2_extract");

    let mut input: Option<PathBuf> = None;
    let mut output: Option<PathBuf> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => { usage(prog); process::exit(0); }
            "-i" => {
                i += 1;
                if i >= args.len() { eprintln!("-i needs an argument"); process::exit(1); }
                input = Some(PathBuf::from(&args[i]));
            }
            "-o" => {
                i += 1;
                if i >= args.len() { eprintln!("-o needs an argument"); process::exit(1); }
                output = Some(PathBuf::from(&args[i]));
            }
            s if s.starts_with('-') => { eprintln!("Unknown option: {}", s); usage(prog); process::exit(1); }
            s => {
                if input.is_none() { input = Some(PathBuf::from(s)); }
                else { eprintln!("Extra argument: {}", s); process::exit(1); }
            }
        }
        i += 1;
    }

    let input_path = match input { Some(p) => p, None => { usage(prog); process::exit(1); } };
    let output_path = output.unwrap_or_else(|| default_out(&input_path));

    let mut f = File::open(&input_path)?;
    let file_size = f.metadata()?.len();

    // Header
    let mut hdr = [0u8; 8];
    f.read_exact(&mut hdr)?;

    if &hdr[0..4] != b"GXT2" {
        eprintln!("Not a GXT2 file (first bytes: {:02X?})", &hdr[0..4]);
        process::exit(1);
    }
    let count = u32_be(&hdr[4..8]);

    let table_start = 8u64;
    let table_end = table_start + (count as u64) * 8;

    println!("Input        : {}", input_path.display());
    println!("Output       : {}", output_path.display());
    println!("File size    : {} bytes", file_size);
    println!("Endianness   : big (PS3)");
    println!("Count        : {}", count);
    println!("Table range  : 0x{:08X} .. 0x{:08X}", table_start, table_end);

    if table_end > file_size {
        eprintln!("Count is impossible (table would end past EOF).");
        process::exit(1);
    }
    
    f.seek(SeekFrom::Start(table_start))?;
    let mut probe = [0u8; 48];
    f.read_exact(&mut probe)?;
    for (i, c) in probe.chunks(4).enumerate() {
    let v = u32::from_be_bytes([c[0], c[1], c[2], c[3]]);
    eprintln!("word[{:2}] = 0x{:08X}", i, v);
}

    // Read table
    f.seek(SeekFrom::Start(table_start))?;
    let mut entries: Vec<(u32, u32)> = Vec::with_capacity(count as usize);
    let mut buf = [0u8; 8];
    for _ in 0..count {
        f.read_exact(&mut buf)?;
        let hash = u32_be(&buf[0..4]);
        let off = u32_be(&buf[4..8]);
        entries.push((hash, off));
    }

    // Sanity: first few offsets should be >= table_end and close to it.
    let sample: Vec<u32> = entries.iter().take(5).map(|(_, o)| *o).collect();
    println!("First 5 offsets: {:?}", sample);

    // Write strings
    let out = File::create(&output_path)?;
    let mut w = BufWriter::new(out);

    let mut ok = 0u64;
    let mut skipped = 0u64;

// Sort by hash ascending
entries.sort_by_key(|&(hash, _)| hash);

	for (hash, off) in &entries {
    let o = *off as u64;
    if o >= file_size {
        skipped += 1;
        continue;
    }
    if f.seek(SeekFrom::Start(o)).is_err() {
        skipped += 1;
        continue;
    }
    match read_cstr(&mut f) {
        Ok(s) => {
            writeln!(w, "0x{:08X} = {}", hash, s)?; // <-- uses hash
            ok += 1;
        }
        Err(_) => skipped += 1,
    }
}
    
	w.flush()?;
    println!("Done. Wrote {} strings ({} skipped).", ok, skipped);
    Ok(())
}
