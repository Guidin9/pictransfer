//! Spike B (throwaway): the agent skeleton measured against the idle budget.
//!
//!   agent-skeleton run      tray + hotkey + server WebSocket (env SPIKE_URL = wss://…/ws?label=…)
//!                           optional env: SPIKE_KEEPALIVE_S (60), SPIKE_EXIT_AFTER_S, SPIKE_STATS (json path)
//!   agent-skeleton bench    B3: DIB → PNG on a synthetic 4K screenshot
//!   agent-skeleton altgr    B4: AltGr conflict check on the Turkish Q layout

#![windows_subsystem = "windows"]

mod clip;
mod ws;

use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

use windows_sys::Win32::{
    Foundation::{HWND, LPARAM, LRESULT, POINT, WPARAM},
    System::{
        LibraryLoader::GetModuleHandleW,
        Threading::{
            GetCurrentProcess, PROCESS_POWER_THROTTLING_CURRENT_VERSION, PROCESS_POWER_THROTTLING_EXECUTION_SPEED,
            PROCESS_POWER_THROTTLING_STATE, ProcessPowerThrottling, SetProcessInformation, SetProcessWorkingSetSize,
        },
    },
    UI::{
        Input::KeyboardAndMouse::{
            GetKeyboardLayoutList, HKL, KLF_NOTELLSHELL, LoadKeyboardLayoutW, MAPVK_VK_TO_VSC, MOD_ALT, MOD_CONTROL,
            MOD_NOREPEAT, MOD_SHIFT, MapVirtualKeyExW, RegisterHotKey, ToUnicodeEx, UnloadKeyboardLayout, VK_CONTROL,
            VK_MENU, VK_SHIFT,
        },
        Shell::{NIF_ICON, NIF_MESSAGE, NIF_TIP, NIM_ADD, NIM_DELETE, NOTIFYICONDATAW, Shell_NotifyIconW},
        WindowsAndMessaging::{
            AppendMenuW, CreatePopupMenu, CreateWindowExW, DefWindowProcW, DestroyMenu, DestroyWindow, DispatchMessageW,
            GetCursorPos, GetMessageW, HWND_MESSAGE, IDI_APPLICATION, LoadIconW, MF_STRING, MSG, PostMessageW,
            PostQuitMessage, RegisterClassW, SetForegroundWindow, TPM_RETURNCMD, TPM_RIGHTBUTTON, TrackPopupMenu,
            TranslateMessage, WM_APP, WM_CLOSE, WM_DESTROY, WM_HOTKEY, WM_RBUTTONUP, WNDCLASSW,
        },
    },
};

#[derive(Default)]
pub struct Stats {
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
    pub connects: AtomicU64,
    pub disconnects: AtomicU64,
    pub pings: AtomicU64,
    pub pongs: AtomicU64,
    pub missed: AtomicU64,
    pub hotkeys: AtomicU64,
    pub last_hotkey_us: AtomicU64,
}

pub static STATS: Stats = Stats {
    bytes_in: AtomicU64::new(0),
    bytes_out: AtomicU64::new(0),
    connects: AtomicU64::new(0),
    disconnects: AtomicU64::new(0),
    pings: AtomicU64::new(0),
    pongs: AtomicU64::new(0),
    missed: AtomicU64::new(0),
    hotkeys: AtomicU64::new(0),
    last_hotkey_us: AtomicU64::new(0),
};

const WM_TRAY: u32 = WM_APP + 1;
const ID_QUIT: usize = 1;

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn trim_working_set() {
    // SAFETY: (-1, -1) trims this process's working set.
    unsafe {
        SetProcessWorkingSetSize(GetCurrentProcess(), usize::MAX, usize::MAX);
    }
}

fn eco_qos(on: bool) {
    let state = PROCESS_POWER_THROTTLING_STATE {
        Version: PROCESS_POWER_THROTTLING_CURRENT_VERSION,
        ControlMask: PROCESS_POWER_THROTTLING_EXECUTION_SPEED,
        StateMask: if on { PROCESS_POWER_THROTTLING_EXECUTION_SPEED } else { 0 },
    };
    // SAFETY: correctly sized PROCESS_POWER_THROTTLING_STATE for ProcessPowerThrottling.
    unsafe {
        SetProcessInformation(
            GetCurrentProcess(),
            ProcessPowerThrottling,
            (&state as *const PROCESS_POWER_THROTTLING_STATE).cast(),
            std::mem::size_of::<PROCESS_POWER_THROTTLING_STATE>() as u32,
        );
    }
}

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    // SAFETY: standard window procedure; all pointers passed to Win32 are valid locals.
    unsafe {
        match msg {
            WM_HOTKEY => {
                let t = Instant::now();
                let png = clip::read_png(hwnd);
                STATS.last_hotkey_us.store(t.elapsed().as_micros() as u64, Ordering::Relaxed);
                STATS.hotkeys.fetch_add(1, Ordering::Relaxed);
                drop(png); // the agent would send it now; the buffer is released right away
                trim_working_set();
                0
            }
            WM_TRAY if (lp as u32 & 0xffff) == WM_RBUTTONUP => {
                let menu = CreatePopupMenu();
                let quit = wide("Quit");
                AppendMenuW(menu, MF_STRING, ID_QUIT, quit.as_ptr());
                let mut pt = POINT { x: 0, y: 0 };
                GetCursorPos(&mut pt);
                SetForegroundWindow(hwnd);
                let cmd = TrackPopupMenu(menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, pt.x, pt.y, 0, hwnd, std::ptr::null());
                DestroyMenu(menu);
                if cmd as usize == ID_QUIT {
                    DestroyWindow(hwnd);
                }
                0
            }
            WM_CLOSE => {
                DestroyWindow(hwnd);
                0
            }
            WM_DESTROY => {
                PostQuitMessage(0);
                0
            }
            _ => DefWindowProcW(hwnd, msg, wp, lp),
        }
    }
}

fn run() {
    let url = std::env::var("SPIKE_URL").unwrap_or_default();
    let keepalive = Duration::from_secs(std::env::var("SPIKE_KEEPALIVE_S").ok().and_then(|v| v.parse().ok()).unwrap_or(60));
    let exit_after: Option<u64> = std::env::var("SPIKE_EXIT_AFTER_S").ok().and_then(|v| v.parse().ok());
    let started = Instant::now();

    // SAFETY: plain Win32 window/tray setup on this (the UI) thread.
    let hwnd = unsafe {
        let hinst = GetModuleHandleW(std::ptr::null());
        let class = wide("WarpshotSpikeB");
        let wc = WNDCLASSW {
            lpfnWndProc: Some(wndproc),
            hInstance: hinst,
            lpszClassName: class.as_ptr(),
            ..std::mem::zeroed()
        };
        RegisterClassW(&wc);
        // Message-only windows cannot own a tray icon's callbacks reliably; use a hidden top-level window.
        let _ = HWND_MESSAGE;
        let hwnd = CreateWindowExW(0, class.as_ptr(), class.as_ptr(), 0, 0, 0, 0, 0, std::ptr::null_mut(), std::ptr::null_mut(), hinst, std::ptr::null());
        let mut nid: NOTIFYICONDATAW = std::mem::zeroed();
        nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
        nid.hWnd = hwnd;
        nid.uID = 1;
        nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
        nid.uCallbackMessage = WM_TRAY;
        nid.hIcon = LoadIconW(std::ptr::null_mut(), IDI_APPLICATION);
        for (i, c) in "Warpshot spike B".encode_utf16().enumerate() {
            nid.szTip[i] = c;
        }
        Shell_NotifyIconW(NIM_ADD, &nid);
        RegisterHotKey(hwnd, 1, MOD_CONTROL | MOD_ALT | MOD_SHIFT | MOD_NOREPEAT, b'S' as u32);
        hwnd
    };

    // The one extra thread: a current_thread tokio runtime for the server WebSocket.
    let hwnd_bits = hwnd as usize;
    std::thread::spawn(move || {
        let Ok(rt) = tokio::runtime::Builder::new_current_thread().enable_io().enable_time().build() else {
            return;
        };
        rt.block_on(async move {
            if let Some(s) = exit_after {
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_secs(s)).await;
                    // SAFETY: posting a message to our own window handle.
                    unsafe { PostMessageW(hwnd_bits as HWND, WM_CLOSE, 0, 0) };
                });
            }
            if url.is_empty() {
                std::future::pending::<()>().await;
            }
            ws::run(url, keepalive, || {
                // Connection setup is work; release its pages afterwards and go back to EcoQoS.
                trim_working_set();
                eco_qos(true);
            })
            .await;
        });
    });

    eco_qos(true);
    trim_working_set();
    // SAFETY: standard message loop; the tray icon is removed before exit.
    unsafe {
        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        let mut nid: NOTIFYICONDATAW = std::mem::zeroed();
        nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
        nid.hWnd = hwnd;
        nid.uID = 1;
        Shell_NotifyIconW(NIM_DELETE, &nid);
    }

    if let Ok(path) = std::env::var("SPIKE_STATS") {
        let s = &STATS;
        let l = |a: &AtomicU64| a.load(Ordering::Relaxed);
        let json = format!(
            "{{\"uptime_s\":{:.0},\"bytes_in\":{},\"bytes_out\":{},\"connects\":{},\"disconnects\":{},\"pings\":{},\"pongs\":{},\"missed\":{},\"hotkeys\":{},\"last_hotkey_us\":{}}}\n",
            started.elapsed().as_secs_f64(),
            l(&s.bytes_in), l(&s.bytes_out), l(&s.connects), l(&s.disconnects),
            l(&s.pings), l(&s.pongs), l(&s.missed), l(&s.hotkeys), l(&s.last_hotkey_us)
        );
        let _ = std::fs::write(path, json);
    }
}

/// B4: does Ctrl+Alt(+Shift)+key produce a character (AltGr) on this layout?
fn altgr_char(hkl: HKL, vk: u16, shift: bool) -> Option<String> {
    let mut ks = [0u8; 256];
    ks[VK_CONTROL as usize] = 0x80;
    ks[VK_MENU as usize] = 0x80;
    if shift {
        ks[VK_SHIFT as usize] = 0x80;
    }
    let mut buf = [0u16; 8];
    // SAFETY: valid key-state array and output buffer; flag 4 leaves the kernel keyboard state unchanged.
    let n = unsafe {
        let sc = MapVirtualKeyExW(vk as u32, MAPVK_VK_TO_VSC, hkl);
        ToUnicodeEx(vk as u32, sc, ks.as_ptr(), buf.as_mut_ptr(), buf.len() as i32, 4, hkl)
    };
    match n {
        0 => None,
        n if n < 0 => Some("<dead key>".into()),
        n => Some(String::from_utf16_lossy(&buf[..n as usize])),
    }
}

fn altgr() -> String {
    // SAFETY: layout list query; a layout we load ourselves is unloaded again.
    unsafe {
        let mut list = [std::ptr::null_mut(); 32];
        let n = GetKeyboardLayoutList(list.len() as i32, list.as_mut_ptr());
        // Turkish Q: language 0x041F, layout (high word) 0x041F.
        let present = list[..n.max(0) as usize].iter().copied().find(|h| (*h as usize & 0xffff_ffff) == 0x041f_041f);
        let (hkl, loaded) = match present {
            Some(h) => (h, false),
            None => (LoadKeyboardLayoutW(wide("0000041F").as_ptr(), KLF_NOTELLSHELL), true),
        };
        let q = altgr_char(hkl, b'Q' as u16, false);
        let s = altgr_char(hkl, b'S' as u16, true);
        if loaded {
            UnloadKeyboardLayout(hkl);
        }
        format!(
            "{{\"layout_was_installed\":{},\"ctrl_alt_q\":{:?},\"ctrl_alt_shift_s\":{:?},\"q_flagged\":{},\"s_clear\":{}}}",
            !loaded,
            q.clone().unwrap_or_default(),
            s.clone().unwrap_or_default(),
            q.is_some(),
            s.is_none()
        )
    }
}

fn main() {
    let cmd = std::env::args().nth(1).unwrap_or_else(|| "run".into());
    let out = std::env::var("SPIKE_OUT").ok();
    let report = |s: String| match &out {
        Some(p) => {
            let _ = std::fs::write(p, s + "\n");
        }
        None => println!("{s}"),
    };
    match cmd.as_str() {
        "bench" => report(clip::bench()),
        "altgr" => report(altgr()),
        _ => run(),
    }
}
