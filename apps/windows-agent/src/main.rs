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
//! warpshot-agent --render-flyout DIR write the flyout states as PNGs (off-screen)
//! ```
//!
//! Threads at idle: this UI thread (message loop) and one tokio `current_thread`
//! runtime thread (named-pipe server, server WebSocket, transfers).

#![windows_subsystem = "windows"]
// Win32 FFI (window procedure, message loop) needs `unsafe`; see lib.rs.
#![allow(unsafe_code)]

use std::{cell::RefCell, path::Path, process::ExitCode, sync::Arc};

use tokio::sync::{broadcast, mpsc};
use warpshot_agent::{
    clipboard,
    hotkey::{self, Hotkey},
    image, osd, pipe, power, selftest,
    service::{self, Cmd, Service, UiMsg},
    single_instance, toast,
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
        PostMessageW, PostQuitMessage, RegisterClassW, TranslateMessage, WM_APP, WM_CLOSE,
        WM_DESTROY, WM_HOTKEY, WM_LBUTTONUP, WM_RBUTTONUP, WNDCLASSW,
    },
};

const HOTKEY_SEND: i32 = 1;
/// A boxed [`UiMsg`] from the runtime thread; `lParam` owns the box.
const WM_UI: u32 = WM_APP + 2;

/// UI-thread state reachable from the window procedure.
struct App {
    tray: Option<Tray>,
    menu: MenuModel,
    taskbar_created: u32,
    cmd: mpsc::UnboundedSender<Cmd>,
}

thread_local! {
    static APP: RefCell<Option<App>> = const { RefCell::new(None) };
}

fn with_app<R>(f: impl FnOnce(&mut App) -> R) -> Option<R> {
    APP.with(|a| a.try_borrow_mut().ok().and_then(|mut a| a.as_mut().map(f)))
}

fn show_toast(title: &str, body: &str, image: Option<&Path>) {
    let _ = toast::show(&toast::Toast {
        title,
        body,
        image,
        id: None,
    });
}

/// Hotkey pressed: read the clipboard and hand it to the transfer layer. The
/// flyout answers at once; the service updates it with the result.
fn on_hotkey(hwnd: HWND) {
    match clipboard::read(hwnd) {
        Ok(Some(content)) => {
            let target = with_app(|a| send_target_name(&a.menu)).flatten();
            let text = match target {
                Some(name) => format!("Sending to {name}…"),
                None => "Sending…".to_owned(),
            };
            osd::show(&text, osd::Tone::Busy);
            with_app(|a| a.cmd.send(Cmd::SendClip(content)));
        }
        Ok(None) => osd::show("Nothing to send: the clipboard is empty", osd::Tone::Error),
        Err(_) => osd::show(
            "Nothing sent: the clipboard could not be read",
            osd::Tone::Error,
        ),
    }
    power::trim_working_set();
}

/// The device a hotkey send goes to, as the service picks it: the default
/// target, else the only other device.
fn send_target_name(m: &MenuModel) -> Option<String> {
    match m.default_target {
        Some(i) => m.targets.get(i).cloned(),
        None if m.targets.len() == 1 => m.targets.first().cloned(),
        None => None,
    }
}

/// Opens `warpshot-ui.exe` (next to the agent) if it is installed.
fn open_ui() {
    let ui = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("warpshot-ui.exe")));
    match ui {
        Some(p) if p.is_file() => {
            let _ = std::process::Command::new(p).spawn();
        }
        _ => show_toast(
            "Warpshot",
            "The settings window (warpshot-ui.exe) is not installed next to the agent.",
            None,
        ),
    }
}

fn on_menu(hwnd: HWND, cmd: MenuCommand) {
    match cmd {
        MenuCommand::Quit => {
            // SAFETY: our own window, on its thread.
            unsafe { DestroyWindow(hwnd) };
        }
        MenuCommand::SetDefaultTarget(i) => {
            with_app(|a| {
                a.menu.default_target = Some(i);
                a.cmd.send(Cmd::SetDefaultIndex(i))
            });
        }
        MenuCommand::Settings | MenuCommand::Device(_) => open_ui(),
    }
}

/// Applies a message from the runtime thread.
fn on_ui_msg(hwnd: HWND, msg: UiMsg) {
    match msg {
        UiMsg::Toast { title, body, image } => show_toast(&title, &body, image.as_deref()),
        UiMsg::ClipText(t) => {
            let _ = clipboard::write_text(hwnd, &t);
        }
        UiMsg::ClipImage(path) => {
            let png = std::fs::read(&path).ok().filter(|b| image::is_png(b));
            let _ = match png {
                Some(b) => clipboard::write_png(hwnd, &b),
                None => clipboard::write_files(hwnd, &[path]),
            };
        }
        UiMsg::ClipFiles(paths) => {
            let _ = clipboard::write_files(hwnd, &paths);
        }
        UiMsg::Flyout { text, tone } => osd::show(&text, tone),
        UiMsg::Menu(m) => {
            with_app(|a| a.menu = m);
        }
        UiMsg::Hotkey(s) => {
            if let Ok(hk) = Hotkey::parse(&s) {
                hotkey::unregister(hwnd, HOTKEY_SEND);
                if hotkey::register(hwnd, HOTKEY_SEND, &hk).is_err() {
                    show_toast(
                        "Warpshot hotkey is taken",
                        "Another app uses this hotkey. Choose a different one in Settings.",
                        None,
                    );
                }
            }
        }
    }
    power::trim_working_set();
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
        WM_UI => {
            if lp != 0 {
                // SAFETY: `lp` is a `Box<UiMsg>` leaked by `post_ui` for exactly this message.
                let msg = unsafe { Box::from_raw(lp as *mut UiMsg) };
                on_ui_msg(hwnd, *msg);
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

/// Posts a [`UiMsg`] to the UI thread (`hwnd` as an integer so the closure is `Send`).
fn post_ui(hwnd: usize, msg: UiMsg) {
    let p = Box::into_raw(Box::new(msg));
    // SAFETY: posting to our own window; on success the window procedure takes the box.
    let ok = unsafe { PostMessageW(hwnd as HWND, WM_UI, 0, p as isize) };
    if ok == 0 {
        // SAFETY: not posted, so we still own the box.
        drop(unsafe { Box::from_raw(p) });
    }
}

fn post_toast(hwnd: usize, title: &str, body: String) {
    post_ui(
        hwnd,
        UiMsg::Toast {
            title: title.into(),
            body,
            image: None,
        },
    );
}

/// The one extra thread: a `current_thread` tokio runtime for the pipe server,
/// the server WebSocket and transfers.
fn spawn_runtime_thread(hwnd: usize, mut cmds: mpsc::UnboundedReceiver<Cmd>) {
    let spawned = std::thread::Builder::new()
        .name("warpshot-rt".into())
        .stack_size(1024 * 1024)
        .spawn(move || {
            let Ok(rt) = tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .enable_time()
                .build()
            else {
                return;
            };
            rt.block_on(async move {
                let (events, _) = broadcast::channel(64);
                let sink = Box::new(move |m| post_ui(hwnd, m));
                let svc = match Service::open(sink, events.clone()) {
                    Ok(s) => s,
                    Err(code) => {
                        post_toast(hwnd, "Warpshot could not start", format!("Error: {code}"));
                        return;
                    }
                };
                svc.start().await;
                // A failed bind means another agent or a squatter owns the name.
                match pipe::pipe_name().and_then(|n| pipe::PipeServer::bind(&n)) {
                    Ok(server) => {
                        let rpc = Arc::new(service::Rpc(Arc::clone(&svc)));
                        tokio::spawn(server.serve(rpc, events));
                    }
                    Err(_) => post_toast(
                        hwnd,
                        "Warpshot",
                        "The settings channel is unavailable (pipe-in-use).".into(),
                    ),
                }
                while let Some(cmd) = cmds.recv().await {
                    svc.on_cmd(cmd).await;
                }
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
    // Per-monitor DPI awareness: crisp tray icon, menu and flyout on scaled
    // displays (the flyout sizes itself with GetDpiForWindow).
    // SAFETY: process-wide setting made before any window exists.
    unsafe {
        windows_sys::Win32::UI::HiDpi::SetProcessDpiAwarenessContext(
            windows_sys::Win32::UI::HiDpi::DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2,
        )
    };
    let Some(hwnd) = create_window() else {
        return ExitCode::FAILURE;
    };
    let tray = Tray::add(hwnd, "Warpshot").ok();
    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
    APP.with(|a| {
        *a.borrow_mut() = Some(App {
            tray,
            menu: MenuModel::default(),
            taskbar_created: tray::taskbar_created_message(),
            cmd: cmd_tx,
        });
    });

    // The default hotkey; the service sends `UiMsg::Hotkey` if settings differ.
    if let Ok(hk) = Hotkey::parse(hotkey::DEFAULT_HOTKEY)
        && let Err(hotkey::RegisterError::Taken) = hotkey::register(hwnd, HOTKEY_SEND, &hk)
    {
        let _ = toast::show(&toast::Toast {
            title: "Warpshot hotkey is taken",
            body: "Another app uses Ctrl+Alt+Shift+S. Choose a different hotkey in Settings.",
            ..Default::default()
        });
    }

    spawn_runtime_thread(hwnd as usize, cmd_rx);
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
        Some("--render-flyout") => {
            // Dev check without touching the screen: the flyout states as PNGs.
            let dir = args
                .get(1)
                .map_or_else(|| std::path::PathBuf::from("."), Into::into);
            let states = [
                (
                    "busy",
                    "Sending to Mert adlı kişiye ait S21 FE…",
                    osd::Tone::Busy,
                ),
                ("ok", "Sent to Mert adlı kişiye ait S21 FE", osd::Tone::Ok),
                ("error", "Not sent: device offline", osd::Tone::Error),
            ];
            let mut n = 0u32;
            for (name, text, tone) in states {
                for (theme, dark) in [("light", false), ("dark", true)] {
                    for dpi in [96, 144] {
                        let file = dir.join(format!("flyout-{name}-{theme}-{dpi}.png"));
                        if let Some(png) = osd::render_png(text, tone, dark, dpi)
                            && std::fs::write(&file, png).is_ok()
                        {
                            n = n.saturating_add(1);
                        }
                    }
                }
            }
            output(&args, &format!("{n} flyout images written"))
        }
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
