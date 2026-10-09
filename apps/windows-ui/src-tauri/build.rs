fn main() {
    // Only the app's own `rpc` command gets an `allow-rpc` permission; the
    // capability file grants exactly that plus event listen/unlisten.
    let attrs = tauri_build::Attributes::new()
        .app_manifest(tauri_build::AppManifest::new().commands(&["rpc"]));
    if let Err(e) = tauri_build::try_build(attrs) {
        println!("cargo::error=tauri-build failed: {e:#}");
    }
}
