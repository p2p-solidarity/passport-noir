// build.rs
// @solidarity/passport-zk-mopro
//
// Re-export hidden libc++ template VTTs from the Android cdylib so dlopen
// can resolve `_ZTT…basic_ostringstream…` and friends without falling back
// to libc++_shared.so (which doesn't export those template instantiations
// since NDK r25 marked them `_LIBCPP_HIDE_FROM_ABI`).
//
// This handles the *linker* side. The C/C++ deps still have to be built
// with `-fvisibility=default`, which has to come from the env at cargo
// invocation time so cc-rs picks it up — see scripts/build-android.sh.
fn main() {
    let target = std::env::var("TARGET").unwrap_or_default();
    if !target.contains("android") {
        return;
    }
    // Keep the local copy of every dynamic symbol so the dynamic linker
    // can self-resolve VTT references that cc-rs's `-fvisibility=default`
    // pushed into the cdylib's symbol table.
    println!("cargo:rustc-link-arg-cdylib=-Wl,--export-dynamic");
}
