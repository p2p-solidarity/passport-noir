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
           gen_srs --circuit <path.json> --out <path.srs.bin>           [--recursive]\n\
           gen_srs --circuits-dir <dir> --out-dir <dir>                 [--recursive]\n\
           gen_srs --circuit a.json --circuit b.json --merged-out <f>   [--recursive]\n\n\
         --merged-out writes ONE SRS sized to the largest of the listed\n\
         --circuit files. Because barretenberg's SRS is a prefix (a bigger SRS\n\
         contains every smaller one), that single file serves all of them — so\n\
         the app bundles one blob instead of one per circuit. List only the\n\
         circuits you actually ship, or the SRS is sized to the biggest one.\n"
    );
}

struct Args {
    /// Repeatable. One value = single mode (with --out); multiple = merged
    /// mode (with --merged-out).
    circuit: Vec<String>,
    out: Option<String>,
    circuits_dir: Option<String>,
    out_dir: Option<String>,
    merged_out: Option<String>,
    recursive: bool,
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args {
        circuit: Vec::new(),
        out: None,
        circuits_dir: None,
        out_dir: None,
        merged_out: None,
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
                args.circuit
                    .push(iter.next().ok_or("--circuit requires a value")?);
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
            "--merged-out" => {
                args.merged_out = Some(iter.next().ok_or("--merged-out requires a value")?);
            }
            "--recursive" => args.recursive = true,
            other => return Err(format!("Unknown argument: {}", other)),
        }
    }

    let single = args.out.is_some();
    let merged = args.merged_out.is_some();
    let batch = args.out_dir.is_some();
    let modes = [single, merged, batch].iter().filter(|m| **m).count();
    if modes > 1 {
        return Err("--out, --out-dir and --merged-out are mutually exclusive".into());
    }
    if modes == 0 {
        return Err("Must specify --out, --out-dir, or --merged-out".into());
    }
    if single && args.circuit.len() != 1 {
        return Err("--out requires exactly one --circuit".into());
    }
    if batch && args.circuits_dir.is_none() {
        return Err("--out-dir requires --circuits-dir".into());
    }
    if merged && args.circuit.is_empty() {
        return Err("--merged-out requires one or more --circuit values".into());
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

/// UltraHonk SRS overhead multiplier — matches
/// `noir-rs/.../barretenberg/srs/mod.rs::ULTRA_HONK_SRS_MULTIPLIER`.
/// The prover needs SRS points not just for the gate trace but also
/// for the witness / permutation / lookup polynomials, which
/// empirically runs ~8× the dyadic gate count for standard UltraHonk
/// configurations. Without applying it here the bundled SRS is the
/// right SHAPE but short by 8× — barretenberg then panics inside
/// `generate_noir_proof` with `range end index <N> out of range for
/// slice of length <N/8>` and the prover crashes before producing a
/// proof.
const ULTRA_HONK_SRS_MULTIPLIER: u32 = 8;

fn generate_one(circuit_path: &Path, output_path: &Path, recursive: bool) -> Result<(), String> {
    let bytecode = extract_bytecode(circuit_path)?;
    let subgroup_size = get_subgroup_size(&bytecode, recursive);
    let prover_size = subgroup_size
        .checked_mul(ULTRA_HONK_SRS_MULTIPLIER)
        .ok_or_else(|| {
            format!(
                "subgroup_size {} * {} overflows u32",
                subgroup_size, ULTRA_HONK_SRS_MULTIPLIER
            )
        })?;
    println!(
        "{}: subgroup_size = {} → prover SRS points = {} (recursive={})",
        circuit_path.display(),
        subgroup_size,
        prover_size,
        recursive
    );

    // Downloads SRS from the public points service unless a cache hit is
    // available. None for srs_path means "use the library's default cache".
    let srs = get_srs(prover_size, None);
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

/// Generate ONE SRS sized to the largest circuit in `circuits_dir`.
///
/// barretenberg's SRS is a prefix: `Srs::get(n)` truncates a larger SRS to the
/// first `n` points, so an SRS sized to the biggest circuit verifiably serves
/// every smaller circuit too (confirmed end-to-end against the real prover).
/// Bundling this single blob instead of one per circuit roughly halves the app
/// payload for the OpenAC v3 passport set.
fn run_merged(circuits: &[String], merged_out: &Path, recursive: bool) -> Result<(), String> {
    if circuits.is_empty() {
        return Err("merged mode needs at least one --circuit".into());
    }

    let mut max_prover_size: u32 = 0;
    let mut largest = String::new();
    for circuit in circuits {
        let path = Path::new(circuit);
        let bytecode = match extract_bytecode(path) {
            Ok(b) => b,
            Err(err) => {
                eprintln!("  SKIP {}: {}", path.display(), err);
                continue;
            }
        };
        let subgroup_size = get_subgroup_size(&bytecode, recursive);
        let prover_size = subgroup_size
            .checked_mul(ULTRA_HONK_SRS_MULTIPLIER)
            .ok_or_else(|| format!("subgroup_size {} overflows u32", subgroup_size))?;
        println!(
            "  {}: subgroup_size = {} → prover SRS points = {}",
            path.display(),
            subgroup_size,
            prover_size
        );
        if prover_size > max_prover_size {
            max_prover_size = prover_size;
            largest = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("?")
                .to_string();
        }
    }
    if max_prover_size == 0 {
        return Err("No parseable circuits to size the merged SRS".into());
    }
    println!(
        "merged SRS sized to {} points (largest circuit: {}) — serves all circuits",
        max_prover_size, largest
    );

    let srs = get_srs(max_prover_size, None);
    let local = LocalSrs(srs);
    if let Some(parent) = merged_out.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create {}: {}", parent.display(), e))?;
        }
    }
    let out_str = merged_out
        .to_str()
        .ok_or_else(|| format!("Non-UTF8 path: {}", merged_out.display()))?;
    local.save(Some(out_str));
    let size = fs::metadata(merged_out)
        .map(|m| m.len())
        .unwrap_or_default();
    println!("  -> wrote {} ({} bytes)", merged_out.display(), size);
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

    let result = if let Some(out) = &args.out {
        generate_one(Path::new(&args.circuit[0]), Path::new(out), args.recursive)
    } else if let Some(merged_out) = &args.merged_out {
        run_merged(&args.circuit, Path::new(merged_out), args.recursive)
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
