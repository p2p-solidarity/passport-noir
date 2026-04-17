//! SRS generation CLI.
//!
//! Reads a compiled Noir circuit JSON, computes the subgroup size for its
//! UltraHonk bytecode, downloads/builds the matching Structured Reference
//! String, and writes it to disk as a bincode blob. The produced `.srs.bin`
//! can be bundled with the iOS app so `generate_noir_proof` does not need to
//! hit the network on first use.
//!
//! Usage:
//!   cargo run --bin gen_srs -- --circuit circuits/target/disclosure.json \
//!                              --out test-vectors/srs/disclosure.srs.bin
//!
//!   # Batch mode: one SRS per circuit under a directory.
//!   cargo run --bin gen_srs -- --circuits-dir circuits/target \
//!                              --out-dir test-vectors/srs
//!
//! Notes:
//!   * Network access required unless a prior run already populated
//!     `~/.cache/noir_srs` (noir-rs caches SRS under that path by default).
//!   * Recursive proofs inflate subgroup size; pass `--recursive` when
//!     generating SRS for aggregation circuits.

use std::fs;
use std::path::{Path, PathBuf};

use noir_rs::barretenberg::srs::{get_srs, localsrs::LocalSrs};
use noir_rs::barretenberg::utils::get_subgroup_size;
use serde_json::Value;

fn print_help() {
    eprintln!(
        "gen_srs — generate bundled SRS blobs for Noir circuits\n\n\
         Usage:\n\
           gen_srs --circuit <path.json> --out <path.srs.bin> [--recursive]\n\
           gen_srs --circuits-dir <dir> --out-dir <dir>      [--recursive]\n"
    );
}

struct Args {
    circuit: Option<String>,
    out: Option<String>,
    circuits_dir: Option<String>,
    out_dir: Option<String>,
    recursive: bool,
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args {
        circuit: None,
        out: None,
        circuits_dir: None,
        out_dir: None,
        recursive: false,
    };

    let mut iter = std::env::args().skip(1);
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                print_help();
                std::process::exit(0);
            }
            "--circuit" => {
                args.circuit = Some(iter.next().ok_or("--circuit requires a value")?);
            }
            "--out" => {
                args.out = Some(iter.next().ok_or("--out requires a value")?);
            }
            "--circuits-dir" => {
                args.circuits_dir = Some(iter.next().ok_or("--circuits-dir requires a value")?);
            }
            "--out-dir" => {
                args.out_dir = Some(iter.next().ok_or("--out-dir requires a value")?);
            }
            "--recursive" => args.recursive = true,
            other => return Err(format!("Unknown argument: {}", other)),
        }
    }

    let single = args.circuit.is_some() || args.out.is_some();
    let batch = args.circuits_dir.is_some() || args.out_dir.is_some();
    if single && batch {
        return Err("--circuit/--out and --circuits-dir/--out-dir are mutually exclusive".into());
    }
    if !single && !batch {
        return Err("Must specify either --circuit/--out or --circuits-dir/--out-dir".into());
    }
    if single && (args.circuit.is_none() || args.out.is_none()) {
        return Err("--circuit and --out must both be set".into());
    }
    if batch && (args.circuits_dir.is_none() || args.out_dir.is_none()) {
        return Err("--circuits-dir and --out-dir must both be set".into());
    }
    Ok(args)
}

fn extract_bytecode(circuit_path: &Path) -> Result<String, String> {
    let raw = fs::read(circuit_path)
        .map_err(|e| format!("Failed to read {}: {}", circuit_path.display(), e))?;
    let json: Value = serde_json::from_slice(&raw)
        .map_err(|e| format!("Failed to parse {}: {}", circuit_path.display(), e))?;
    json["bytecode"]
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| format!("Circuit JSON {} missing 'bytecode'", circuit_path.display()))
}

fn generate_one(circuit_path: &Path, output_path: &Path, recursive: bool) -> Result<(), String> {
    let bytecode = extract_bytecode(circuit_path)?;
    let subgroup_size = get_subgroup_size(&bytecode, recursive);
    println!(
        "{}: subgroup_size = {} (recursive={})",
        circuit_path.display(),
        subgroup_size,
        recursive
    );

    // Downloads SRS from the public points service unless a cache hit is
    // available. None for srs_path means "use the library's default cache".
    let srs = get_srs(subgroup_size, None);
    let local = LocalSrs(srs);

    if let Some(parent) = output_path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create {}: {}", parent.display(), e))?;
        }
    }

    let out_str = output_path
        .to_str()
        .ok_or_else(|| format!("Non-UTF8 path: {}", output_path.display()))?;
    local.save(Some(out_str));
    let size = fs::metadata(output_path)
        .map(|m| m.len())
        .unwrap_or_default();
    println!("  -> wrote {} ({} bytes)", output_path.display(), size);
    Ok(())
}

fn run_batch(circuits_dir: &Path, out_dir: &Path, recursive: bool) -> Result<(), String> {
    let entries = fs::read_dir(circuits_dir)
        .map_err(|e| format!("Failed to read {}: {}", circuits_dir.display(), e))?;
    let mut json_paths: Vec<PathBuf> = entries
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("json"))
        .collect();
    json_paths.sort();

    if json_paths.is_empty() {
        return Err(format!("No *.json files in {}", circuits_dir.display()));
    }

    for path in json_paths {
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| format!("Bad file stem: {}", path.display()))?;
        let out_path = out_dir.join(format!("{}.srs.bin", stem));
        if let Err(err) = generate_one(&path, &out_path, recursive) {
            eprintln!("  SKIP {}: {}", path.display(), err);
        }
    }
    Ok(())
}

fn main() {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: {}\n", e);
            print_help();
            std::process::exit(2);
        }
    };

    let result = if let (Some(circuit), Some(out)) = (&args.circuit, &args.out) {
        generate_one(Path::new(circuit), Path::new(out), args.recursive)
    } else {
        let dir = args.circuits_dir.as_deref().unwrap();
        let out_dir = args.out_dir.as_deref().unwrap();
        run_batch(Path::new(dir), Path::new(out_dir), args.recursive)
    };

    if let Err(err) = result {
        eprintln!("error: {}", err);
        std::process::exit(1);
    }
}
