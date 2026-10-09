# Builds the Rust core for Android (arm64) into app/src/main/jniLibs and
# regenerates the UniFFI Kotlin bindings into app/src/main/java/uniffi.
# Run from anywhere: powershell -ExecutionPolicy Bypass -File apps\android\build-rust.ps1
$ErrorActionPreference = "Stop"
$root = Resolve-Path (Join-Path $PSScriptRoot "..\..")
Push-Location $root
try {
    $jni = "apps\android\app\src\main\jniLibs"
    cargo ndk -t arm64-v8a -o $jni build --release -p warpshot-ffi
    if ($LASTEXITCODE -ne 0) { throw "cargo ndk failed" }
    # cargo-ndk copies every .so in the deps folder; only ours is needed.
    Get-ChildItem "$jni\arm64-v8a" -Filter "*.so" | Where-Object { $_.Name -ne "libwarpshot_ffi.so" } | Remove-Item
    # Bindings come from the host build (release .so files are stripped of UniFFI metadata).
    cargo build -p warpshot-ffi
    cargo run -p warpshot-ffi --features bindgen --bin uniffi-bindgen -- generate `
        --library target\debug\warpshot_ffi.dll --language kotlin --no-format `
        --out-dir apps\android\app\src\main\java
    if ($LASTEXITCODE -ne 0) { throw "uniffi-bindgen failed" }
} finally {
    Pop-Location
}
