use std::collections::HashMap;
use std::fs;
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use anyhow::{anyhow, Context as _};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use pcode_rs::{context::TranslationFlags, LanguageDefinitions};

use super::BenchArgs;

#[derive(Clone)]
struct Block {
    addr: u64,
    data: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct BlockJson {
    addr: u64,
    data_b64: String,
}

#[derive(Clone, Copy)]
struct BenchmarkResult {
    startup_s: f64,
    process_s: f64,
}

pub fn run_bench(args: BenchArgs) -> anyhow::Result<()> {
    if !(0.0 < args.coverage && args.coverage <= 1.0) {
        return Err(anyhow!("coverage must be in (0, 1]"));
    }

    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf();
    let workdir = repo_root.join("target/xtask");
    fs::create_dir_all(&workdir)?;

    let binary = args
        .binary
        .canonicalize()
        .with_context(|| "binary not found")?;
    println!("Using blocks from '{}' for benchmarking", binary.display());

    let hash = sha256_file_hex(&binary)?;
    let cache_path = workdir.join(format!("blocks_{}.json", &hash[..8]));

    let mut blocks = if cache_path.exists() {
        println!("Loading blocks from cache '{}'...", cache_path.display());
        load_blocks_json(&cache_path)?
    } else {
        println!("Recovering blocks via angr (first run only)...");
        let blocks = gen_blocks_with_angr(&args.python, &binary, &workdir)?;
        save_blocks_json(&cache_path, &blocks)?;
        blocks
    };

    let mut rng = rand::thread_rng();
    if args.coverage < 1.0 {
        blocks.shuffle(&mut rng);
        let take = ((blocks.len() as f64) * args.coverage).ceil() as usize;
        blocks.truncate(take.max(1));
    }
    let num_blocks = blocks.len();
    if num_blocks == 0 {
        return Err(anyhow!("no blocks found for benchmarking"));
    }

    let blocks_total_size: usize = blocks.iter().map(|b| b.data.len()).sum();
    println!(
        "Benchmark includes {} blocks totaling {:.1} KiB",
        num_blocks,
        (blocks_total_size as f64) / 1024.0
    );

    // pcode-rs Lift
    let lift_res = bench_pcoderes_lift(
        &blocks,
        &args.lang,
        args.max_insns,
        args.iter_ops,
        args.iter_varnodes,
    )?;

    // Optionally: pypcode Lift (via Python)
    let mut pypcode_res: Option<BenchmarkResult> = None;
    match bench_pypcode_lift(
        &args.python,
        &cache_path,
        &args.lang,
        args.max_insns,
        args.iter_ops,
        args.iter_varnodes,
        &workdir,
    ) {
        Ok(r) => pypcode_res = Some(r),
        Err(e) => {
            eprintln!("Skipping pypcode: {}", e);
        }
    }

    // Optional correctness verification (requires pypcode)
    if args.verify {
        if let Err(e) = verify_with_pypcode(
            &args.python,
            &cache_path,
            &args.lang,
            args.max_insns,
            args.include_imark,
            args.verify_sample,
            &workdir,
        ) {
            eprintln!("Verification failed: {}", e);
        }
    }

    // Results
    let mut rows: Vec<[String; 6]> = vec![[
        "Benchmark".into(),
        "Startup ms".into(),
        "Process s".into(),
        "KiB/s".into(),
        "kBlock/s".into(),
        "us/Block".into(),
    ]];

    let row_from = |name: &str, r: BenchmarkResult| -> [String; 6] {
        let kib_s = (blocks_total_size as f64) / r.process_s / 1024.0;
        let kblk_s = (num_blocks as f64) / r.process_s / 1000.0;
        let us_per_blk = (r.process_s / (num_blocks as f64)) * 1_000_000.0;
        [
            name.into(),
            format!("{:.3}", r.startup_s * 1000.0),
            format!("{:.3}", r.process_s),
            format!("{:.2}", kib_s),
            format!("{:.2}", kblk_s),
            format!("{:.3}", us_per_blk),
        ]
    };

    rows.push(row_from("pcode-rs Lift", lift_res));
    if let Some(r) = pypcode_res {
        rows.push(row_from("pypcode Lift", r));
    }

    // Pretty print
    print_table(&rows);

    if let Some(csv) = args.csv.as_ref() {
        write_csv(csv, &rows)?;
        println!("Saved CSV to '{}'", csv.display());
    }

    Ok(())
}

fn bench_pcoderes_lift(
    blocks: &[Block],
    lang: &str,
    max_insns: usize,
    iter_ops: bool,
    iter_varnodes: bool,
) -> anyhow::Result<BenchmarkResult> {
    let start = Instant::now();
    let ldefs = LanguageDefinitions::load()?;
    let mut ctx = ldefs
        .get_context(lang)
        .ok_or_else(|| anyhow!("language id not found: {}", lang))?;
    let startup_s = start.elapsed().as_secs_f64();

    let start = Instant::now();
    let mut _sink: u64 = 0;
    for b in blocks {
        let ops = ctx
            .translate(&b.data, b.addr, max_insns, TranslationFlags::default())
            .with_context(|| "translate failed")?;
        if iter_ops || iter_varnodes {
            for op in &ops {
                if iter_ops && !iter_varnodes {
                    _sink = _sink.wrapping_add(1);
                }
                if iter_varnodes {
                    _sink = _sink.wrapping_add(op.inputs.len() as u64);
                }
            }
        }
    }
    let process_s = start.elapsed().as_secs_f64();

    // Prevent the optimizer from dropping loops
    std::io::sink().write_all(&_sink.to_le_bytes()).ok();

    Ok(BenchmarkResult {
        startup_s,
        process_s,
    })
}

fn verify_with_pypcode(
    python: &str,
    blocks_json: &Path,
    lang: &str,
    max_insns: usize,
    include_imark: bool,
    verify_sample: Option<usize>,
    workdir: &Path,
) -> anyhow::Result<()> {
    // Run pcode-rs to get canonical traces
    let pcoderes = canonicalize_pcoderes(blocks_json, lang, max_insns, include_imark)?;
    // Run Python/pypcode to get canonical traces
    let pypcode = canonicalize_pypcode(
        python,
        blocks_json,
        lang,
        max_insns,
        include_imark,
        verify_sample,
        workdir,
    )?;

    let total = pcoderes.len().min(pypcode.len());
    let mut mismatches = 0usize;
    for i in 0..total {
        if pcoderes[i] != pypcode[i] {
            mismatches += 1;
            if mismatches <= 10 {
                eprintln!(
                    "Mismatch at block {}\n  pcode-rs: {}\n  pypcode : {}",
                    i, pcoderes[i], pypcode[i]
                );
            }
        }
    }
    if mismatches > 0 {
        anyhow::bail!("{} mismatches out of {} compared blocks", mismatches, total);
    }
    println!("Verification succeeded on {} blocks", total);
    Ok(())
}

fn canonicalize_pcoderes(
    blocks_json: &Path,
    lang: &str,
    max_insns: usize,
    include_imark: bool,
) -> anyhow::Result<Vec<String>> {
    let s = fs::read_to_string(blocks_json)?;
    let bj: Vec<BlockJson> = serde_json::from_str(&s)?;
    let blocks: Vec<Block> = bj
        .into_iter()
        .map(|b| Block {
            addr: b.addr,
            data: B64.decode(b.data_b64.as_bytes()).unwrap(),
        })
        .collect();

    let ldefs = LanguageDefinitions::load()?;
    let mut ctx = ldefs
        .get_context(lang)
        .ok_or_else(|| anyhow::anyhow!("language id not found: {}", lang))?;

    let mut traces = Vec::with_capacity(blocks.len());
    for b in &blocks {
        let ops = ctx.translate(&b.data, b.addr, max_insns, TranslationFlags::default())?;
        traces.push(canonicalize_ops(&ops, include_imark));
    }
    Ok(traces)
}

fn canonicalize_ops(ops: &[pcode_rs::context::PcodeOp], include_imark: bool) -> String {
    // Canonical form using numeric opcode and normalized space names.
    // Additionally:
    //  - Normalize UNIQUE offsets to a per-block index (0x0, 0x1, ...)
    //  - Mask LOAD/STORE first arg (spaceid const) to 0x0
    use pcode_rs::context::OpCode;
    use std::fmt::Write as _;
    let mut out = String::new();
    let mut uniq_map: HashMap<u64, u64> = HashMap::new();
    let mut next_uniq: u64 = 0;

    let mut map_unique = |off: u64| -> u64 {
        if let Some(v) = uniq_map.get(&off) {
            *v
        } else {
            let v = next_uniq;
            uniq_map.insert(off, v);
            next_uniq += 1;
            v
        }
    };

    for op in ops {
        if !include_imark && matches!(op.opcode, OpCode::IMark) {
            continue;
        }
        let opcode_num: u32 = op.opcode.into();
        let _ = write!(
            out,
            "{}|{}|{}",
            opcode_num,
            if op.output.is_some() { 1 } else { 0 },
            op.inputs.len()
        );
        if let Some(v) = &op.output {
            let off = if matches!(v.space, pcode_rs::context::AddrSpace::Unique) {
                map_unique(v.offset)
            } else {
                v.offset
            };
            let _ = write!(out, "|({},{:#x},{})", space_key(&v.space), off, v.size);
        }
        for (i, v) in op.inputs.iter().enumerate() {
            // Mask spaceid const in LOAD/STORE
            let mut off = v.offset;
            if (matches!(op.opcode, OpCode::Load) || matches!(op.opcode, OpCode::Store))
                && i == 0
                && matches!(v.space, pcode_rs::context::AddrSpace::Constant)
                && v.size as u32 == 8
            {
                off = 0;
            }
            if matches!(v.space, pcode_rs::context::AddrSpace::Unique) {
                off = map_unique(off);
            }
            let _ = write!(out, "|({},{:#x},{})", space_key(&v.space), off, v.size);
        }
        out.push('\n');
    }
    out
}

fn space_key(space: &pcode_rs::context::AddrSpace) -> String {
    match space {
        pcode_rs::context::AddrSpace::Ram => "ram".into(),
        pcode_rs::context::AddrSpace::Register => "register".into(),
        pcode_rs::context::AddrSpace::Unique => "unique".into(),
        pcode_rs::context::AddrSpace::Stack => "stack".into(),
        pcode_rs::context::AddrSpace::Constant => "const".into(),
        pcode_rs::context::AddrSpace::Other(s) => s.to_lowercase(),
    }
}

fn sha256_file_hex(path: &Path) -> anyhow::Result<String> {
    let file = fs::File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let digest = hasher.finalize();
    Ok(digest.iter().map(|b| format!("{:02x}", b)).collect())
}

fn load_blocks_json(path: &Path) -> anyhow::Result<Vec<Block>> {
    let s = fs::read_to_string(path)?;
    let v: Vec<BlockJson> = serde_json::from_str(&s)?;
    Ok(v.into_iter()
        .map(|bj| Block {
            addr: bj.addr,
            data: B64.decode(bj.data_b64.as_bytes()).unwrap(),
        })
        .collect())
}

fn save_blocks_json(path: &Path, blocks: &[Block]) -> anyhow::Result<()> {
    let v: Vec<BlockJson> = blocks
        .iter()
        .map(|b| BlockJson {
            addr: b.addr,
            data_b64: B64.encode(&b.data),
        })
        .collect();
    let s = serde_json::to_string(&v)?;
    fs::write(path, s)?;
    Ok(())
}

fn gen_blocks_with_angr(python: &str, binary: &Path, workdir: &Path) -> anyhow::Result<Vec<Block>> {
    let script = r#"import sys, json, base64
try:
    import angr
    import logging
    logging.getLogger("angr").setLevel(logging.WARNING)
    logging.getLogger("cle").setLevel(logging.WARNING)
    logging.getLogger("pyvex").setLevel(logging.WARNING)
    logging.getLogger("claripy").setLevel(logging.WARNING)
except Exception as e:
    print("ANGR_IMPORT_ERROR:" + str(e), file=sys.stderr)
    sys.exit(2)

if len(sys.argv) < 2:
    print("usage: gen_blocks.py <binary>", file=sys.stderr)
    sys.exit(2)

binary = sys.argv[1]
proj = angr.Project(binary, auto_load_libs=False)
cfg = proj.analyses.CFGFast(resolve_indirect_jumps=False, force_smart_scan=False, show_progressbar=False)
blocks = []
for n in cfg.model.nodes():
    bs = getattr(n, 'byte_string', None)
    if bs:
        blocks.append({"addr": int(n.addr), "data_b64": base64.b64encode(bs).decode('ascii')})
print(json.dumps(blocks))
"#;

    let script_path = workdir.join("gen_blocks.py");
    fs::write(&script_path, script)?;

    let output = Command::new(python)
        .arg(&script_path)
        .arg(binary)
        .current_dir(workdir)
        .output()
        .with_context(|| "failed running Python to build blocks with angr")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("ANGR_IMPORT_ERROR:") {
            return Err(anyhow!(
                "angr is not available. Install with: pip install angr (or set --python), stderr: {}",
                stderr
            ));
        }
        return Err(anyhow!(
            "Python script failed: status {:?}, stderr: {}",
            output.status.code(),
            stderr
        ));
    }
    let stdout = String::from_utf8(output.stdout).context("invalid UTF-8 from Python")?;
    let v: Vec<BlockJson> = serde_json::from_str(&stdout).context("invalid JSON from Python")?;
    Ok(v.into_iter()
        .map(|bj| Block {
            addr: bj.addr,
            data: B64.decode(bj.data_b64.as_bytes()).unwrap(),
        })
        .collect())
}

fn bench_pypcode_lift(
    python: &str,
    blocks_json: &Path,
    lang: &str,
    max_insns: usize,
    iter_ops: bool,
    iter_varnodes: bool,
    workdir: &Path,
) -> anyhow::Result<BenchmarkResult> {
    let script = r#"import sys, json, time, base64
try:
    import pypcode
except Exception as e:
    print("PYPCODE_IMPORT_ERROR:" + str(e), file=sys.stderr)
    sys.exit(2)

if len(sys.argv) < 6:
    print("usage: bench_pypcode.py <lang> <blocks_json> <max_insns> <iter_ops> <iter_varnodes>", file=sys.stderr)
    sys.exit(2)

lang = sys.argv[1]
blocks_path = sys.argv[2]
max_insns = int(sys.argv[3])
iter_ops = bool(int(sys.argv[4]))
iter_varnodes = bool(int(sys.argv[5]))

with open(blocks_path, 'r', encoding='utf-8') as f:
    blocks = json.load(f)

start = time.perf_counter()
ctx = pypcode.Context(lang)
startup_s = time.perf_counter() - start

start = time.perf_counter()
count = 0
for b in blocks:
    addr = int(b['addr'])
    data = base64.b64decode(b['data_b64'])
    if max_insns > 0:
        t = ctx.translate(data, addr, max_instructions=max_insns)
    else:
        t = ctx.translate(data, addr)
    if iter_ops and not iter_varnodes:
        for _ in t.ops:
            count += 1
    if iter_varnodes:
        for op in t.ops:
            count += len(op.inputs)
process_s = time.perf_counter() - start

print(json.dumps({"startup_s": startup_s, "process_s": process_s, "count": count}))
"#;

    let script_path = workdir.join("bench_pypcode.py");
    fs::write(&script_path, script)?;

    let output = Command::new(python)
        .arg(&script_path)
        .arg(lang)
        .arg(blocks_json)
        .arg(max_insns.to_string())
        .arg(if iter_ops { "1" } else { "0" })
        .arg(if iter_varnodes { "1" } else { "0" })
        .current_dir(workdir)
        .output()
        .with_context(|| "failed running Python pypcode benchmark")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("PYPCODE_IMPORT_ERROR:") {
            return Err(anyhow!(
                "pypcode is not available. Install with: pip install pypcode (or set --python). stderr: {}",
                stderr
            ));
        }
        return Err(anyhow!(
            "Python pypcode script failed: status {:?}, stderr: {}",
            output.status.code(),
            stderr
        ));
    }
    let stdout = String::from_utf8(output.stdout).context("invalid UTF-8 from Python")?;
    let v: serde_json::Value = serde_json::from_str(&stdout).context("invalid JSON from Python")?;
    let startup_s = v["startup_s"]
        .as_f64()
        .ok_or_else(|| anyhow!("missing startup_s"))?;
    let process_s = v["process_s"]
        .as_f64()
        .ok_or_else(|| anyhow!("missing process_s"))?;
    Ok(BenchmarkResult {
        startup_s,
        process_s,
    })
}

fn canonicalize_pypcode(
    python: &str,
    blocks_json: &Path,
    lang: &str,
    max_insns: usize,
    include_imark: bool,
    verify_sample: Option<usize>,
    workdir: &Path,
) -> anyhow::Result<Vec<String>> {
    let script = r#"import sys, json, base64
try:
    import pypcode
except Exception as e:
    print("PYPCODE_IMPORT_ERROR:" + str(e), file=sys.stderr)
    sys.exit(2)

if len(sys.argv) < 6:
    print("usage: canon_pypcode.py <lang> <blocks_json> <max_insns> <include_imark> <sample>", file=sys.stderr)
    sys.exit(2)

lang = sys.argv[1]
blocks_path = sys.argv[2]
max_insns = int(sys.argv[3])
include_imark = bool(int(sys.argv[4]))
sample = int(sys.argv[5]) if sys.argv[5] else 0

with open(blocks_path, 'r', encoding='utf-8') as f:
    blocks = json.load(f)
if sample and sample < len(blocks):
    blocks = blocks[:sample]

ctx = pypcode.Context(lang)
OP_MAP = {
    'IMARK':0, 'COPY':1, 'LOAD':2, 'STORE':3, 'BRANCH':4, 'CBRANCH':5, 'BRANCHIND':6,
    'CALL':7, 'CALLIND':8, 'CALLOTHER':9, 'RETURN':10,
    'INT_EQUAL':11, 'INT_NOTEQUAL':12, 'INT_SLESS':13, 'INT_SLESSEQUAL':14, 'INT_LESS':15, 'INT_LESSEQUAL':16,
    'INT_ZEXT':17, 'INT_SEXT':18, 'INT_ADD':19, 'INT_SUB':20, 'INT_CARRY':21, 'INT_SCARRY':22, 'INT_SBORROW':23,
    'INT_2COMP':24, 'INT_NEGATE':25, 'INT_XOR':26, 'INT_AND':27, 'INT_OR':28, 'INT_LEFT':29, 'INT_RIGHT':30, 'INT_SRIGHT':31,
    'INT_MULT':32, 'INT_DIV':33, 'INT_SDIV':34, 'INT_REM':35, 'INT_SREM':36,
    'BOOL_NEGATE':37, 'BOOL_XOR':38, 'BOOL_AND':39, 'BOOL_OR':40,
    'FLOAT_EQUAL':41, 'FLOAT_NOTEQUAL':42, 'FLOAT_LESS':43, 'FLOAT_LESSEQUAL':44, 'FLOAT_NAN':46,
    'FLOAT_ADD':47, 'FLOAT_DIV':48, 'FLOAT_MULT':49, 'FLOAT_SUB':50, 'FLOAT_NEG':51, 'FLOAT_ABS':52, 'FLOAT_SQRT':53,
    'FLOAT_INT2FLOAT':54, 'FLOAT_FLOAT2FLOAT':55, 'FLOAT_TRUNC':56, 'FLOAT_CEIL':57, 'FLOAT_FLOOR':58, 'FLOAT_ROUND':59,
    'MULTIEQUAL':60, 'INDIRECT':61, 'PIECE':62, 'SUBPIECE':63, 'CAST':64, 'PTRADD':65, 'PTRSUB':66, 'SEGMENTOP':67,
    'CPOOLREF':68, 'NEW':69, 'INSERT':70, 'EXTRACT':71, 'POPCOUNT':72, 'LZCOUNT':73, 'MAX':74,
}

def canon_ops(ops):
    s = []
    uniq_map = {}
    next_uniq = 0
    def map_unique(off):
        nonlocal next_uniq
        v = uniq_map.get(off)
        if v is None:
            v = next_uniq
            uniq_map[off] = v
            next_uniq += 1
        return v
    for op in ops:
        name = op.opcode.name
        if not include_imark and name == 'IMARK':
            continue
        code = OP_MAP.get(name, -1)
        parts = [str(code), '1' if op.output is not None else '0', str(len(op.inputs))]
        if op.output is not None:
            ov = op.output
            os = ov.space.name.lower()
            ooff = map_unique(ov.offset) if os == 'unique' else ov.offset
            parts.append(f'({os},{hex(ooff)},{ov.size})')
        for i, iv in enumerate(op.inputs):
            ispc = iv.space.name.lower()
            ioff = iv.offset
            # Mask SLEIGH spaceid constant in LOAD/STORE first argument
            if (name in ('LOAD','STORE')) and i == 0 and ispc == 'const' and iv.size == 8:
                ioff = 0
            if ispc == 'unique':
                ioff = map_unique(ioff)
            parts.append(f'({ispc},{hex(ioff)},{iv.size})')
        s.append('|'.join(parts))
    return '\n'.join(s) + '\n'

traces = []
for b in blocks:
    data = base64.b64decode(b['data_b64'])
    if max_insns > 0:
        t = ctx.translate(data, int(b['addr']), max_instructions=max_insns)
    else:
        t = ctx.translate(data, int(b['addr']))
    traces.append(canon_ops(t.ops))
print(json.dumps(traces))
"#;

    let script_path = workdir.join("canon_pypcode.py");
    fs::write(&script_path, script)?;
    let output = Command::new(python)
        .arg(&script_path)
        .arg(lang)
        .arg(blocks_json)
        .arg(max_insns.to_string())
        .arg(if include_imark { "1" } else { "0" })
        .arg(verify_sample.map(|v| v.to_string()).unwrap_or_default())
        .current_dir(workdir)
        .output()
        .with_context(|| "failed running Python pypcode canonicalizer")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("PYPCODE_IMPORT_ERROR:") {
            return Err(anyhow!(
                "pypcode is not available. Install with: pip install pypcode (or set --python). stderr: {}",
                stderr
            ));
        }
        return Err(anyhow!(
            "Python pypcode canonicalizer failed: status {:?}, stderr: {}",
            output.status.code(),
            stderr
        ));
    }
    let stdout = String::from_utf8(output.stdout).context("invalid UTF-8 from Python")?;
    let v: Vec<String> = serde_json::from_str(&stdout).context("invalid JSON from Python")?;
    Ok(v)
}

fn print_table(rows: &[[String; 6]]) {
    let num_cols = rows.first().map(|r| r.len()).unwrap_or(0);
    if num_cols == 0 {
        return;
    }
    let mut widths = vec![0usize; num_cols];
    for r in rows {
        for (i, c) in r.iter().enumerate() {
            widths[i] = widths[i].max(c.len());
        }
    }
    let header = &rows[0];
    let header_line = (0..num_cols)
        .map(|i| format!("{:width$}", header[i], width = widths[i]))
        .collect::<Vec<_>>()
        .join(" | ");
    println!("{}", "-".repeat(header_line.len()));
    println!("{}", header_line);
    println!("{}", "-".repeat(header_line.len()));
    for r in &rows[1..] {
        let line = (0..num_cols)
            .map(|i| format!("{:width$}", r[i], width = widths[i]))
            .collect::<Vec<_>>()
            .join(" | ");
        println!("{}", line);
    }
}

fn write_csv(path: &Path, rows: &[[String; 6]]) -> anyhow::Result<()> {
    let mut f = fs::File::create(path)?;
    for r in rows {
        let line = r
            .iter()
            .map(|c| {
                if c.contains([',', '"', '\n']) {
                    format!("\"{}\"", c.replace('"', "\"\""))
                } else {
                    c.clone()
                }
            })
            .collect::<Vec<_>>()
            .join(",");
        writeln!(f, "{}", line)?;
    }
    Ok(())
}
