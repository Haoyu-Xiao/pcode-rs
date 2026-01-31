use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use clap::{Args, Parser, Subcommand};

mod bench;

#[derive(Parser)]
#[command(
    name = "xtask",
    version,
    about = "Maintenance tasks for this workspace"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Update cpp/sleigh and cpp/processors from a Ghidra tag
    UpdateGhidra(UpdateGhidraArgs),
    /// Benchmark pcode-rs translation performance
    Bench(BenchArgs),
}

#[derive(Args)]
struct UpdateGhidraArgs {
    /// Ghidra tag, e.g. 12.0.1
    tag: String,
}

#[derive(Args, Debug)]
struct BenchArgs {
    /// Binary to benchmark with
    #[arg(short = 'b', long = "binary")]
    binary: PathBuf,

    /// Percentage in (0,1], sample with replacement
    #[arg(short = 'c', long = "coverage", default_value_t = 1.0)]
    coverage: f64,

    /// Language id for pcode-rs
    #[arg(long = "lang", default_value = "x86:LE:64:default")]
    lang: String,

    /// Write CSV results to a file
    #[arg(long = "csv")]
    csv: Option<PathBuf>,

    /// Python interpreter to use for angr (if blocks cache missing)
    #[arg(long = "python", default_value = "python3")]
    python: String,

    /// Max instructions per block (0 for unlimited)
    #[arg(long = "max-insns", default_value_t = 0)]
    max_insns: usize,

    /// Iterate over ops to simulate consumer cost
    #[arg(long = "iter-ops")]
    iter_ops: bool,

    /// Iterate over all varnodes to simulate heavier consumer cost
    #[arg(long = "iter-varnodes")]
    iter_varnodes: bool,

    /// Verify correctness by comparing with pypcode on the same blocks
    #[arg(long = "verify")]
    verify: bool,

    /// Limit number of blocks for verification (defaults to all selected)
    #[arg(long = "verify-sample")]
    verify_sample: Option<usize>,

    /// Include IMARK ops during verification (default: false)
    #[arg(long = "include-imark")]
    include_imark: bool,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::UpdateGhidra(args) => update_ghidra(&args.tag),
        Commands::Bench(args) => bench::run_bench(args),
    }
}

fn run<I, S>(program: &str, args: I, cwd: &Path) -> anyhow::Result<()>
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    let status = Command::new(program).args(args).current_dir(cwd).status()?;
    if !status.success() {
        anyhow::bail!("command failed: {}", program);
    }
    Ok(())
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> anyhow::Result<()> {
    for entry in walkdir::WalkDir::new(src) {
        let entry = entry?;
        let rel = entry.path().strip_prefix(src).unwrap();
        let target = dst.join(rel);
        if entry.file_type().is_dir() {
            fs::create_dir_all(&target)?;
        } else if entry.file_type().is_file() {
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::copy(entry.path(), &target)?;
        }
    }
    Ok(())
}

fn remove_dir_if_exists(p: &Path) -> anyhow::Result<()> {
    if p.exists() {
        fs::remove_dir_all(p)?;
    }
    Ok(())
}

fn update_ghidra(tag: &str) -> anyhow::Result<()> {
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf();
    let workdir = repo_root.join("target/xtask");
    fs::create_dir_all(&workdir)?;
    let src_dir = workdir.join(format!("ghidra_src_{}", tag));
    if src_dir.exists() {
        fs::remove_dir_all(&src_dir)?;
    }

    let branch = format!("Ghidra_{}_build", tag);
    println!("Cloning Ghidra tag {}...", branch);
    run(
        "git",
        [
            "clone",
            "--depth=1",
            "-b",
            &branch,
            "https://github.com/NationalSecurityAgency/ghidra.git",
            src_dir.to_str().unwrap(),
        ],
        &workdir,
    )?;

    // Paths inside Ghidra
    let decomp_cpp = src_dir.join("Ghidra/Features/Decompiler/src/decompile/cpp");
    let processors = src_dir.join("Ghidra/Processors");
    if !decomp_cpp.is_dir() {
        anyhow::bail!("Missing decompile/cpp at {:?}", decomp_cpp);
    }
    if !processors.is_dir() {
        anyhow::bail!("Missing Processors at {:?}", processors);
    }

    // Dest paths in this repo
    let dst_sleigh = repo_root.join("cpp/sleigh");
    let dst_processors = repo_root.join("cpp/processors");

    println!("Updating cpp/sleigh...");
    remove_dir_if_exists(&dst_sleigh)?;
    fs::create_dir_all(&dst_sleigh)?;
    copy_dir_recursive(&decomp_cpp, &dst_sleigh)?;

    println!("Updating cpp/processors...");
    remove_dir_if_exists(&dst_processors)?;
    fs::create_dir_all(&dst_processors)?;
    copy_dir_recursive(&processors, &dst_processors)?;

    println!("Done. Updated to Ghidra tag {}.", tag);
    Ok(())
}
