//! `warpshot-agent.exe`: the always-running Windows agent.
//!
//! ```text
//! warpshot-agent                     run the agent (tray, hotkey, pipe server)
//! warpshot-agent --autostart         same, started by HKCU\…\Run at logon
//! warpshot-agent --selftest [--out <file>]
//!                                    exercise non-interactive modules, print JSON
//! warpshot-agent --install-shortcut  create the Start Menu shortcut with the AUMID
//! warpshot-agent --remove-shortcut   remove it
//! warpshot-agent --test-toast        show a sample toast (manual check; needs the shortcut)
//! ```
//!
//! Threads at idle: this UI thread (message loop) and one tokio `current_thread`
//! runtime thread (named-pipe server; later the server WebSocket).

#![windows_subsystem = "windows"]
// Win32 FFI (window procedure, message loop) needs `unsafe`; see lib.rs.
#![allow(unsafe_code)]

use std::{cell::RefCell, process::ExitCode, sync::Arc};

use serde_json::{Value, json};
use warpshot_agent::{
    clipboard,
    hotkey::{self, Hotkey},
    pipe, power, selftest, single_instance, toast,
    tray::{self, MenuCommand, MenuModel, Tray},
    win::wide,
};
use windows_sys::Win32::{
    Foundation::{HWND, LPARAM, LRESULT, WPARAM},
    System::{
        Console::{ATTACH_PARENT_PROCESS, AttachConsole, GetStdHandle, STD_OUTPUT_HANDLE},
        LibraryLoader::GetModuleHandleW,
    },
    UI::WindowsAndMessaging::{
        CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetMessageW, MSG,
        PostQuitMessage, RegisterClassW, TranslateMessage, WM_CLOSE, WM_DESTROY, WM_HOTKEY,
        WM_LBUTTONUP, WM_RBUTTONUP, WNDCLASSW,
    },
};

const HOTKEY_SEND: i32 = 1;

/// UI-thread state reachable from the window procedure.
struct App {
    tray: Option<Tray>,
    menu: MenuModel,
    taskbar_created: u32,
}

thread_local! {
    static APP: RefCell<Option<App>> = const { RefCell::new(None) };
}

fn with_app<R>(f: impl FnOnce(&mut App) -> R) -> Option<R> {
    APP.with(|a| a.try_borrow_mut().ok().and_then(|mut a| a.as_mut().map(f)))
}

/// Hotkey pressed: read the clipboard. TODO(core): hand the content to the
/// transfer layer instead of dropping it.
fn on_hotkey(hwnd: HWND) {
    let content = clipboard::read(hwnd);
    drop(content); // released right away (resource-budget.md §2.6)
    power::trim_working_set();
}

fn on_menu(hwnd: HWND, cmd: MenuCommand) {
    match cmd {
        MenuCommand::Quit => {
            // SAFETY: our own window, on its thread.
            unsafe { DestroyWindow(hwnd) };
        }
        MenuCommand::SetDefaultTarget(i) => {
            with_app(|a| a.menu.default_target = Some(i)); // TODO(core): persist in settings
        }
        // TODO(ui): launch warpshot-ui.exe (settings / device page).
        MenuCommand::Settings | MenuCommand::Device(_) => {}
    }
}

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    match msg {
        WM_HOTKEY if wp == HOTKEY_SEND as usize => {
            on_hotkey(hwnd);
            0
        }
        tray::WM_TRAY => {
            match (lp & 0xffff) as u32 {
                WM_RBUTTONUP => {
                    let model = with_app(|a| a.menu.clone()).unwrap_or_default();
                    if let Some(cmd) = tray::show_menu(hwnd, &model) {
                        on_menu(hwnd, cmd);
                    }
                }
                WM_LBUTTONUP => on_menu(hwnd, MenuCommand::Settings),
                _ => {}
            }
            0
        }
        WM_CLOSE => {
            // SAFETY: our own window, on its thread.
            unsafe { DestroyWindow(hwnd) };
            0
        }
        WM_DESTROY => {
            // SAFETY: plain call on the UI thread.
            unsafe { PostQuitMessage(0) };
            0
        }
        m if m != 0 && with_app(|a| a.taskbar_created == m).unwrap_or(false) => {
            with_app(|a| a.tray.as_ref().map(Tray::readd));
            0
        }
        // SAFETY: default processing with the arguments we received.
        _ => unsafe { DefWindowProcW(hwnd, msg, wp, lp) },
    }
}

/// Requests from warpshot-ui over the named pipe. TODO(core): JSON-RPC methods
/// for pairing, devices, settings and history.
struct AgentRpc;

impl pipe::Handler for AgentRpc {
    async fn call(&self, method: &str, params: Value) -> Result<Value, pipe::RpcError> {
        match method {
            "ping" => Ok(json!("pong")),
            "agent.version" => Ok(json!(env!("CARGO_PKG_VERSION"))),
            // Hotkey recorder: parse + AltGr check on the current and installed layouts.
            "hotkey.check" => {
                let s = params.get("hotkey").and_then(Value::as_str).unwrap_or("");
                let hk = Hotkey::parse(s)
                    .map_err(|e| pipe::RpcError::new(pipe::code::INVALID_PARAMS, &e.to_string()))?;
                Ok(json!({
                    "canonical": hk.to_string(),
                    "altgr_current": hotkey::altgr_conflict_current(&hk).map(|o| o.to_string()),
                    "altgr_layouts": hotkey::altgr_conflicts_installed(&hk)
                        .into_iter()
                        .map(|(id, o)| json!({ "layout": format!("{id:08X}"), "produces": o.to_string() }))
                        .collect::<Vec<_>>(),
                }))
            }
            _ => Err(pipe::RpcError::method_not_found()),
        }
    }
}

/// The one extra thread: a `current_thread` tokio runtime for the pipe server.
fn spawn_runtime_thread() {
    let spawned = std::thread::Builder::new()
        .name("warpshot-rt".into())
        .stack_size(256 * 1024)
        .spawn(|| {
            let Ok(rt) = tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .enable_time()
                .build()
            else {
                return;
            };
            rt.block_on(async {
                let Ok(name) = pipe::pipe_name() else { return };
                // A failed bind means another agent or a squatter owns the name.
                // TODO(core): log the error code and tell the user.
                let Ok(server) = pipe::PipeServer::bind(&name) else {
                    return;
                };
                let _ = server.serve(Arc::new(AgentRpc)).await;
            });
        });
    drop(spawned);
}

fn create_window() -> Option<HWND> {
    let class = wide("WarpshotAgent");
    // SAFETY: class registration and creation of a hidden top-level window owned
    // by this thread; strings outlive the calls.
    let hwnd = unsafe {
        let hinst = GetModuleHandleW(std::ptr::null());
        let wc = WNDCLASSW {
            lpfnWndProc: Some(wndproc),
            hInstance: hinst,
            lpszClassName: class.as_ptr(),
            ..std::mem::zeroed()
        };
        RegisterClassW(&wc);
        CreateWindowExW(
            0,
            class.as_ptr(),
            class.as_ptr(),
            0,
            0,
            0,
            0,
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            hinst,
            std::ptr::null(),
        )
    };
    (!hwnd.is_null()).then_some(hwnd)
}

fn run_agent() -> ExitCode {
    let _instance = match single_instance::acquire() {
        Ok(single_instance::Instance::First(g)) => g,
        // TODO(core): ask the running agent to open its settings window via the pipe.
        Ok(single_instance::Instance::AlreadyRunning) => return ExitCode::SUCCESS,
        Err(_) => return ExitCode::FAILURE,
    };
    let Some(hwnd) = create_window() else {
        return ExitCode::FAILURE;
    };
    let tray = Tray::add(hwnd, "Warpshot").ok();
    APP.with(|a| {
        *a.borrow_mut() = Some(App {
            tray,
            menu: MenuModel::default(),
            taskbar_created: tray::taskbar_created_message(),
        });
    });

    // TODO(core): the hotkey comes from settings.
    if let Ok(hk) = Hotkey::parse(hotkey::DEFAULT_HOTKEY)
        && let Err(hotkey::RegisterError::Taken) = hotkey::register(hwnd, HOTKEY_SEND, &hk)
    {
        let _ = toast::show(&toast::Toast {
            title: "Warpshot hotkey is taken",
            body: "Another app uses Ctrl+Alt+Shift+S. Choose a different hotkey in Settings.",
            ..Default::default()
        });
    }

    spawn_runtime_thread();
    power::set_eco_qos(true);
    power::trim_working_set();

    // SAFETY: standard message loop on the thread that owns `hwnd`.
    unsafe {
        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    hotkey::unregister(hwnd, HOTKEY_SEND);
    APP.with(|a| a.borrow_mut().take()); // drops the tray icon
    ExitCode::SUCCESS
}

/// GUI-subsystem exe: attach to the parent console for CLI output if stdout is not redirected.
fn attach_console() {
    // SAFETY: plain calls; AttachConsole fails harmlessly without a parent console.
    unsafe {
        let h = GetStdHandle(STD_OUTPUT_HANDLE);
        if h.is_null() || h == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
            AttachConsole(ATTACH_PARENT_PROCESS);
        }
    }
}

fn output(args: &[String], text: &str) -> ExitCode {
    let out = args
        .iter()
        .position(|a| a == "--out")
        .and_then(|i| args.get(i.saturating_add(1)));
    match out {
        Some(path) => match std::fs::write(path, format!("{text}\n")) {
            Ok(()) => ExitCode::SUCCESS,
            Err(_) => ExitCode::FAILURE,
        },
        None => {
            attach_console();
            println!("{text}");
            ExitCode::SUCCESS
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("--selftest") => {
            let report = selftest::run();
            output(
                &args,
                &serde_json::to_string_pretty(&report).unwrap_or_default(),
            )
        }
        Some("--install-shortcut") => match toast::install_start_menu_shortcut() {
            Ok(p) => output(&args, &format!("shortcut created: {}", p.display())),
            Err(e) => {
                output(&args, &e.to_string());
                ExitCode::FAILURE
            }
        },
        Some("--remove-shortcut") => match toast::remove_start_menu_shortcut() {
            Ok(()) => output(&args, "shortcut removed"),
            Err(e) => {
                output(&args, &e.to_string());
                ExitCode::FAILURE
            }
        },
        Some("--test-toast") => {
            let img = args.get(1).map(std::path::PathBuf::from);
            let r = toast::show(&toast::Toast {
                title: "Warpshot test",
                body: "If you see this, toasts work.",
                image: img.as_deref(),
                id: Some("test"),
            });
            // Give the notification platform a moment before the process exits.
            std::thread::sleep(std::time::Duration::from_millis(500));
            output(
                &args,
                &r.map_or_else(|e| e.to_string(), |()| "toast shown".into()),
            )
        }
        _ => run_agent(),
    }
}
