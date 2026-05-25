// android_zig.rs
// @solidarity/passport-zk-mopro
//
// Drop-in replacement for `cargo run --bin android` (which uses
// `mopro_ffi::app_config::android::build()` → cargo-ndk →
// `--link-libcxx-shared`).
//
// Why we replace it: `barretenberg-rs` downloads a prebuilt
// `libbb-external.a` from AztecProtocol's GitHub releases. That `.a`
// was cross-compiled with Zig (per
// aztec-packages/barretenberg/cpp/CMakePresets.json, preset
// `zig-arm64-android`), so it references libc++ symbols under the
// upstream `__1` inline namespace and bundles Zig's libc++ headers.
//
// Android NDK r25+ ships `libc++_shared.so` under the `__ndk1`
// namespace. `cargo-ndk --link-libcxx-shared` therefore produces a
// `.so` whose 3,978 `_Z…NSt3__1…` references can never be satisfied at
// dlopen time → `UnsatisfiedLinkError: cannot locate symbol …`.
//
// The fix is to use the same toolchain Aztec used: link our cdylib
// with Zig. `cargo zigbuild` invokes `zig cc` / `zig c++` as the
// linker, which statically bundles Zig's `__1`-namespaced libc++ into
// the produced `.so`. Result: a self-contained library that doesn't
// need NDK's `libc++_shared.so` at all and resolves all of
// barretenberg's libc++ references in-process.
//
// What this binary does (matches the lifecycle of
// `mopro_ffi::app_config::android::build`):
//
//   1. For each ABI in $ANDROID_ARCHS, run
//      `cargo zigbuild --target <triple> --release --lib`.
//   2. Copy each produced `.so` into
//      `MoproAndroidBindings/jniLibs/<abi_dir>/lib<name>.so`.
//   3. Run UniFFI's `generate_bindings_library_mode` against ONE of
//      the produced `.so`s to emit the Kotlin bindings to
//      `MoproAndroidBindings/uniffi/<crate>/<crate>.kt`.
//
// Env vars (compatible with the existing build-android.sh):
//   ANDROID_ARCHS    comma-separated list (default: aarch64-linux-android,x86_64-linux-android)
//   CONFIGURATION    release | debug (default: release)
//   ANDROID_NDK_HOME used as the sysroot for Zig (Aztec uses spacedriveapp/ndk-sysroot;
//                    we reuse the installed Android NDK so contributors don't need a
//                    second download)
use std::path::PathBuf;
use std::process::Command;
use std::{env, fs};

use camino::Utf8Path;
// Reach UniFFI through mopro_ffi's re-export (`pub use uniffi::*`) so
// the `mopro_ffi::app!()` macro in src/lib.rs doesn't see two distinct
// `uniffi` paths and refuse to compile.
use mopro_ffi::generate_bindings_library_mode;
use mopro_ffi::CargoMetadataConfigSupplier;
use mopro_ffi::KotlinBindingGenerator;

/// NDK prebuilt host-tag dir (Apple Silicon ships only the
/// `darwin-x86_64` toolchain via Rosetta-style fat binaries, so we
/// hardcode it for both Intel + ARM macs; Linux hosts use
/// `linux-x86_64`).
fn host_tag() -> &'static str {
    if cfg!(target_os = "macos") {
        "darwin-x86_64"
    } else if cfg!(target_os = "linux") {
        "linux-x86_64"
    } else {
        panic!("unsupported host OS for the NDK cross-compile path")
    }
}

/// Map a Rust target triple to the jniLibs ABI directory name Android
/// expects (the gradle convention, not the Rust convention).
fn abi_dir(triple: &str) -> &'static str {
    match triple {
        "aarch64-linux-android" => "arm64-v8a",
        "armv7-linux-androideabi" => "armeabi-v7a",
        "i686-linux-android" => "x86",
        "x86_64-linux-android" => "x86_64",
        other => panic!("unsupported android triple: {other}"),
    }
}

fn project_dir() -> PathBuf {
    // `cargo run --bin android_zig` runs from CARGO_MANIFEST_DIR.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// `lib<crate_name>.so` — UniFFI / cargo's default cdylib filename.
/// Pulled from Cargo.toml so we stay in sync if the crate is renamed.
fn lib_name() -> String {
    let manifest = fs::read_to_string(project_dir().join("Cargo.toml"))
        .expect("read Cargo.toml");
    for line in manifest.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("name") {
            if let Some(eq) = rest.find('=') {
                let raw = rest[eq + 1..].trim().trim_matches('"');
                return format!("lib{}.so", raw.replace('-', "_"));
            }
        }
    }
    panic!("could not read `name` from Cargo.toml");
}

fn main() {
    let archs: Vec<String> = env::var("ANDROID_ARCHS")
        .unwrap_or_else(|_| "aarch64-linux-android,x86_64-linux-android".into())
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let configuration = env::var("CONFIGURATION").unwrap_or_else(|_| "release".into());
    let release_flag = configuration == "release";
    let ndk_home = env::var("ANDROID_NDK_HOME").ok();

    let project = project_dir();
    let build_dir = project.join("build-zig");
    fs::create_dir_all(&build_dir).expect("create build dir");

    let bindings_dest = project.join("MoproAndroidBindings");
    if bindings_dest.exists() {
        fs::remove_dir_all(&bindings_dest).expect("clean bindings dest");
    }
    let jni_libs = bindings_dest.join("jniLibs");
    fs::create_dir_all(&jni_libs).expect("create jniLibs");

    let lib_so = lib_name();
    let mut last_so_path: Option<PathBuf> = None;

    // API 24 (Android 7.0 Nougat) matches the NDK's lib stub layout we
    // point Zig at and the app's minSdkVersion. Bumping this requires
    // re-checking both the NDK `sysroot/usr/lib/<triple>/<api>/` dir
    // and any Rust crate that bumps its own minimum.
    let api_level: u32 = env::var("ANDROID_API_LEVEL")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(24);

    for arch in &archs {
        println!("==> [zig] building for {arch} ({configuration}, API {api_level})");

        // `cargo zigbuild` is a thin wrapper around `cargo build` that
        // sets CC/CXX to `zig cc`/`zig c++` for the target and uses
        // Zig as the linker. We delegate target-rustup install to
        // cargo itself (it'll fetch the std lib if missing). We do
        // NOT pass `--link-libcxx-shared`-equivalent — Zig statically
        // links its own libc++ into the produced cdylib, which is the
        // whole point.
        let mut cmd = Command::new("cargo");
        cmd.arg("zigbuild")
            .arg("--target")
            .arg(arch)
            .arg("--lib")
            .arg("--target-dir")
            .arg(&build_dir);
        if release_flag {
            cmd.arg("--release");
        }

        // Zig 0.16 dropped the bundled Android libc — the `aarch64-linux-android`
        // target has no headers (assert.h, stdio.h, …) without explicit
        // -isystem paths to a real NDK sysroot. Aztec's CMakePresets
        // does the same via spacedriveapp/ndk-sysroot; we point at the
        // installed Android NDK to avoid a second download.
        let ndk_root = ndk_home.clone().unwrap_or_else(|| {
            panic!(
                "ANDROID_NDK_HOME is required so Zig can find Bionic headers \
                 (assert.h, stdio.h, …). Set it to e.g. \
                 $HOME/Library/Android/sdk/ndk/27.1.12297006."
            )
        });
        let sysroot = format!(
            "{}/toolchains/llvm/prebuilt/{}/sysroot",
            ndk_root,
            host_tag()
        );
        let include = format!("{sysroot}/usr/include");
        let arch_include = format!("{sysroot}/usr/include/{arch}");
        let isystem = format!("-isystem {include} -isystem {arch_include}");

        // cc-rs reads CFLAGS_<triple> / CXXFLAGS_<triple>; cargo-zigbuild
        // forwards them to its `zig cc` wrapper unchanged. The
        // underscored form (CFLAGS_aarch64_linux_android) is the one
        // cc-rs prefers — the hyphenated form is a fallback.
        let cflags_key = format!("CFLAGS_{}", arch.replace('-', "_"));
        let cxxflags_key = format!("CXXFLAGS_{}", arch.replace('-', "_"));
        cmd.env(&cflags_key, &isystem);
        cmd.env(&cxxflags_key, &isystem);

        // Link-time: Zig + cargo-zigbuild don't ship Android sysroot
        // libs (libc.so / libdl.so / liblog.so / libm.so / libunwind.a
        // stubs). They live in the NDK at
        // `sysroot/usr/lib/<triple>/<api>/`. Without these `-L` paths
        // the final shared-object link fails with "unable to find
        // dynamic system library 'dl' / 'log' / 'm' / 'c'".
        //
        // We pass them via RUSTFLAGS so rustc forwards each
        // `-Clink-arg=` to its linker (which is the cargo-zigbuild
        // wrapper, i.e. `zig cc`).
        //
        // IMPORTANT: do NOT add `--sysroot=…` here. Zig's clang driver
        // re-roots ALL subsequent `-L` paths against that sysroot,
        // including the absolute ones rustc emits for its own
        // `build/<dep>/out` and `deps/raw-dylibs` directories, which
        // then can't be found. Letting rustc's absolute -L paths stay
        // absolute is the only way the link survives.
        let api_lib_dir = format!("{sysroot}/usr/lib/{arch}/{api_level}");
        let arch_lib_dir = format!("{sysroot}/usr/lib/{arch}");
        let rustflags = format!(
            "-C link-arg=-L{api_lib_dir} -C link-arg=-L{arch_lib_dir}"
        );
        let rustflags_key = format!(
            "CARGO_TARGET_{}_RUSTFLAGS",
            arch.to_uppercase().replace('-', "_")
        );
        cmd.env(&rustflags_key, &rustflags);

        // Pass NDK home through for any build scripts that probe it
        // directly (cmake-rs, bindgen, etc.).
        cmd.env("ANDROID_NDK_HOME", &ndk_root);
        cmd.env("ANDROID_NDK", &ndk_root);

        let status = cmd.spawn().expect("spawn cargo zigbuild").wait().expect("wait");
        if !status.success() {
            panic!("cargo zigbuild failed for {arch}");
        }

        // Locate the produced .so. cargo-zigbuild respects --target-dir
        // and writes to <target-dir>/<triple>/<profile>/<lib>.
        let profile_dir = if release_flag { "release" } else { "debug" };
        let produced = build_dir.join(arch).join(profile_dir).join(&lib_so);
        if !produced.exists() {
            panic!(
                "expected cdylib at {} but it's missing — cargo zigbuild succeeded but didn't produce {lib_so}",
                produced.display()
            );
        }

        let dest_dir = jni_libs.join(abi_dir(arch));
        fs::create_dir_all(&dest_dir).expect("create abi dir");
        let dest = dest_dir.join(&lib_so);
        fs::copy(&produced, &dest).expect("copy cdylib");
        println!("==> [zig] copied {} → {}", produced.display(), dest.display());

        last_so_path = Some(produced);
    }

    // ─── UniFFI Kotlin bindings ───────────────────────────────────
    //
    // UniFFI's library-mode generator reads the cdylib's `.dynsym` to
    // discover exported FFI symbols, so we can hand it any one of the
    // ABIs and get the same bindings out. Match mopro_ffi's layout:
    // <bindings>/uniffi/<crate>/<crate>.kt, which is what
    // HybridPassportZk.kt imports from.
    let source_so = last_so_path.expect("at least one ABI produced a .so");

    let uniffi_config = bindings_dest.join("uniffi_config.toml");
    fs::write(&uniffi_config, "[bindings.kotlin]\nandroid = true\n")
        .expect("write uniffi_config.toml");

    let uniffi_dir = bindings_dest.join("uniffi");
    fs::create_dir_all(&uniffi_dir).expect("create uniffi dir");

    println!("==> [zig] generating UniFFI Kotlin bindings from {}", source_so.display());
    let metadata_supplier = CargoMetadataConfigSupplier::default();
    generate_bindings_library_mode(
        Utf8Path::from_path(&source_so).expect("utf-8 path"),
        None,
        &KotlinBindingGenerator,
        &metadata_supplier,
        None,
        Utf8Path::from_path(&uniffi_dir).expect("utf-8 path"),
        true,
    )
    .expect("uniffi generate_bindings_library_mode");

    println!("==> [zig] done — bindings at {}", bindings_dest.display());
}
