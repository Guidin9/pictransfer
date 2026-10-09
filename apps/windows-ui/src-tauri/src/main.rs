//! warpshot-ui: stateless settings window. Holds no keys or state; every
//! action goes to warpshot-agent over the named pipe (docs/ipc.md). Exits
//! when its window closes (ADR 0003).
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod pipe;
mod win;

use serde_json::Value;
use tauri::webview::{NewWindowResponse, WebviewWindowBuilder};
use tauri::{Manager, State, Url, WebviewUrl};

const WINDOW_TITLE: &str = "Warpshot";

#[tauri::command]
async fn rpc(
    agent: State<'_, pipe::Agent>,
    method: String,
    params: Option<Value>,
) -> Result<Value, pipe::RpcError> {
    agent.call(&method, params).await
}

/// Only bundled assets may be loaded (threat model T9). In release builds the
/// app origin is `http://tauri.localhost`; `tauri://` covers other schemes and
/// the Vite dev server is allowed in debug builds only.
fn allowed_url(url: &Url) -> bool {
    match url.scheme() {
        "tauri" => true,
        "http" | "https" => match url.host_str() {
            Some("tauri.localhost") => true,
            Some("localhost") if cfg!(debug_assertions) => url.port() == Some(1420),
            _ => false,
        },
        _ => false,
    }
}

fn main() {
    let Some(sid) = win::current_user_sid() else {
        std::process::exit(2);
    };
    let _instance = match win::single_instance(&sid) {
        win::Instance::First(h) => h,
        win::Instance::AlreadyRunning => {
            win::focus_window(WINDOW_TITLE);
            return;
        }
    };

    let result = tauri::Builder::default()
        .setup(move |app| {
            app.manage(pipe::Agent::new(app.handle().clone(), &sid));
            WebviewWindowBuilder::new(app, "main", WebviewUrl::App("index.html".into()))
                .title(WINDOW_TITLE)
                .inner_size(960.0, 680.0)
                .min_inner_size(720.0, 520.0)
                .center()
                .zoom_hotkeys_enabled(false)
                .browser_extensions_enabled(false)
                .general_autofill_enabled(false)
                .on_navigation(allowed_url)
                .on_new_window(|_, _| NewWindowResponse::Deny)
                .on_download(|_, _| false)
                .build()?;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![rpc])
        .run(tauri::generate_context!());
    if result.is_err() {
        std::process::exit(1);
    }
}
