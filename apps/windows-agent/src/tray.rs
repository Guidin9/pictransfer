//! Tray icon and its context menu.
//!
//! The icon belongs to a hidden top-level window (not message-only: those do not
//! receive the `TaskbarCreated` broadcast, which we need to re-add the icon after
//! Explorer restarts). The menu is built on each right-click and destroyed right
//! after, so nothing menu-related stays resident at idle.

use std::io;

use windows_sys::Win32::{
    Foundation::{HWND, POINT},
    UI::{
        Shell::{
            NIF_ICON, NIF_MESSAGE, NIF_TIP, NIM_ADD, NIM_DELETE, NIM_MODIFY, NOTIFYICONDATAW,
            Shell_NotifyIconW,
        },
        WindowsAndMessaging::{
            AppendMenuW, CheckMenuRadioItem, CreatePopupMenu, DestroyMenu, GetCursorPos, HMENU,
            IDI_APPLICATION, LoadIconW, MF_BYCOMMAND, MF_GRAYED, MF_POPUP, MF_SEPARATOR, MF_STRING,
            PostMessageW, RegisterWindowMessageW, SetForegroundWindow, TPM_RETURNCMD,
            TPM_RIGHTBUTTON, TrackPopupMenu, WM_APP, WM_NULL,
        },
    },
};

use crate::win::{last_error, wide};

/// Callback message of the tray icon (`lParam` low word = mouse message).
pub const WM_TRAY: u32 = WM_APP + 1;
const TRAY_ID: u32 = 1;

const ID_SETTINGS: u32 = 1;
const ID_QUIT: u32 = 2;
const ID_DEVICE_BASE: u32 = 100;
const ID_TARGET_BASE: u32 = 1000;
const MAX_ITEMS: usize = 500;

/// The message Explorer broadcasts after it (re)creates the taskbar.
pub fn taskbar_created_message() -> u32 {
    let name = wide("TaskbarCreated");
    // SAFETY: NUL-terminated name.
    unsafe { RegisterWindowMessageW(name.as_ptr()) }
}

/// The tray icon; removed on drop.
#[derive(Debug)]
pub struct Tray {
    hwnd: HWND,
    tip: String,
}

fn nid(hwnd: HWND, tip: &str) -> NOTIFYICONDATAW {
    // SAFETY: NOTIFYICONDATAW is plain data; all-zero is a valid starting value.
    let mut n: NOTIFYICONDATAW = unsafe { std::mem::zeroed() };
    n.cbSize = u32::try_from(std::mem::size_of::<NOTIFYICONDATAW>()).unwrap_or(0);
    n.hWnd = hwnd;
    n.uID = TRAY_ID;
    n.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
    n.uCallbackMessage = WM_TRAY;
    // SAFETY: loads a shared system icon (not owned, never destroyed).
    // TODO: embed the Warpshot icon as a resource (build script) and load it here.
    n.hIcon = unsafe { LoadIconW(std::ptr::null_mut(), IDI_APPLICATION) };
    // Leave room for the terminator (the array is zeroed).
    let cap = n.szTip.len().saturating_sub(1);
    for (dst, src) in n.szTip.iter_mut().take(cap).zip(tip.encode_utf16()) {
        *dst = src;
    }
    n
}

impl Tray {
    /// Adds the icon to the notification area.
    pub fn add(hwnd: HWND, tooltip: &str) -> io::Result<Tray> {
        let n = nid(hwnd, tooltip);
        // SAFETY: fully initialized NOTIFYICONDATAW for a window of this thread.
        if unsafe { Shell_NotifyIconW(NIM_ADD, &n) } == 0 {
            return Err(last_error());
        }
        Ok(Tray {
            hwnd,
            tip: tooltip.to_string(),
        })
    }

    /// Re-adds the icon after Explorer restarted (`TaskbarCreated`).
    pub fn readd(&self) -> bool {
        let n = nid(self.hwnd, &self.tip);
        // SAFETY: as in `add`.
        unsafe { Shell_NotifyIconW(NIM_ADD, &n) != 0 }
    }

    /// Changes the tooltip (status line).
    pub fn set_tooltip(&mut self, tip: &str) -> bool {
        self.tip = tip.to_string();
        let n = nid(self.hwnd, tip);
        // SAFETY: as in `add`.
        unsafe { Shell_NotifyIconW(NIM_MODIFY, &n) != 0 }
    }
}

impl Drop for Tray {
    fn drop(&mut self) {
        let n = nid(self.hwnd, "");
        // SAFETY: removes the icon we added (same hWnd/uID).
        unsafe { Shell_NotifyIconW(NIM_DELETE, &n) };
    }
}

/// A paired device as shown in the menu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceItem {
    pub name: String,
    pub online: bool,
}

/// What the context menu shows. Filled by the agent from the core state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MenuModel {
    pub devices: Vec<DeviceItem>,
    /// Send targets for the default-target radio group.
    pub targets: Vec<String>,
    pub default_target: Option<usize>,
}

/// A menu choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MenuCommand {
    Settings,
    Quit,
    Device(usize),
    SetDefaultTarget(usize),
}

/// Maps a menu item id back to a command.
pub fn command_from_id(id: u32, model: &MenuModel) -> Option<MenuCommand> {
    let idx = |base: u32| usize::try_from(id.checked_sub(base)?).ok();
    match id {
        ID_SETTINGS => Some(MenuCommand::Settings),
        ID_QUIT => Some(MenuCommand::Quit),
        ID_DEVICE_BASE..ID_TARGET_BASE => idx(ID_DEVICE_BASE)
            .filter(|i| *i < model.devices.len())
            .map(MenuCommand::Device),
        _ => idx(ID_TARGET_BASE)
            .filter(|i| *i < model.targets.len())
            .map(MenuCommand::SetDefaultTarget),
    }
}

fn item_id(base: u32, i: usize) -> u32 {
    base.saturating_add(u32::try_from(i).unwrap_or(u32::MAX))
}

/// Builds the popup menu for `model`. The caller destroys it.
fn build_menu(model: &MenuModel) -> HMENU {
    // SAFETY: menus are created, filled with NUL-terminated strings that outlive
    // each call, and returned to the caller who destroys the root (which also
    // destroys attached submenus).
    unsafe {
        let root = CreatePopupMenu();
        let devices = CreatePopupMenu();
        if model.devices.is_empty() {
            AppendMenuW(
                devices,
                MF_STRING | MF_GRAYED,
                0,
                wide("No paired devices").as_ptr(),
            );
        }
        for (i, d) in model.devices.iter().take(MAX_ITEMS).enumerate() {
            let label = format!(
                "{} — {}",
                d.name,
                if d.online { "online" } else { "offline" }
            );
            AppendMenuW(
                devices,
                MF_STRING,
                item_id(ID_DEVICE_BASE, i) as usize,
                wide(&label).as_ptr(),
            );
        }
        AppendMenuW(root, MF_POPUP, devices as usize, wide("Devices").as_ptr());

        let targets = CreatePopupMenu();
        if model.targets.is_empty() {
            AppendMenuW(
                targets,
                MF_STRING | MF_GRAYED,
                0,
                wide("No targets yet").as_ptr(),
            );
        }
        let n = model.targets.len().min(MAX_ITEMS);
        for (i, t) in model.targets.iter().take(n).enumerate() {
            AppendMenuW(
                targets,
                MF_STRING,
                item_id(ID_TARGET_BASE, i) as usize,
                wide(t).as_ptr(),
            );
        }
        if let Some(sel) = model.default_target.filter(|s| *s < n) {
            CheckMenuRadioItem(
                targets,
                ID_TARGET_BASE,
                item_id(ID_TARGET_BASE, n.saturating_sub(1)),
                item_id(ID_TARGET_BASE, sel),
                MF_BYCOMMAND,
            );
        }
        AppendMenuW(root, MF_POPUP, targets as usize, wide("Send to").as_ptr());

        AppendMenuW(root, MF_SEPARATOR, 0, std::ptr::null());
        AppendMenuW(
            root,
            MF_STRING,
            ID_SETTINGS as usize,
            wide("Settings…").as_ptr(),
        );
        AppendMenuW(root, MF_STRING, ID_QUIT as usize, wide("Quit").as_ptr());
        root
    }
}

/// Shows the context menu at the cursor and returns the choice.
pub fn show_menu(hwnd: HWND, model: &MenuModel) -> Option<MenuCommand> {
    let menu = build_menu(model);
    if menu.is_null() {
        return None;
    }
    // SAFETY: standard tray-menu sequence (foreground first so the menu closes on
    // outside clicks; WM_NULL afterwards per the TrackPopupMenu docs).
    let cmd = unsafe {
        let mut pt = POINT { x: 0, y: 0 };
        GetCursorPos(&mut pt);
        SetForegroundWindow(hwnd);
        let cmd = TrackPopupMenu(
            menu,
            TPM_RETURNCMD | TPM_RIGHTBUTTON,
            pt.x,
            pt.y,
            0,
            hwnd,
            std::ptr::null(),
        );
        PostMessageW(hwnd, WM_NULL, 0, 0);
        DestroyMenu(menu);
        cmd
    };
    command_from_id(u32::try_from(cmd).ok()?, model)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn model() -> MenuModel {
        MenuModel {
            devices: vec![DeviceItem {
                name: "Pixel".into(),
                online: true,
            }],
            targets: vec!["Pixel".into(), "Tablet".into()],
            default_target: Some(1),
        }
    }

    #[test]
    fn ids_map_to_commands() {
        let m = model();
        assert_eq!(command_from_id(0, &m), None); // dismissed
        assert_eq!(
            command_from_id(ID_SETTINGS, &m),
            Some(MenuCommand::Settings)
        );
        assert_eq!(command_from_id(ID_QUIT, &m), Some(MenuCommand::Quit));
        assert_eq!(
            command_from_id(ID_DEVICE_BASE, &m),
            Some(MenuCommand::Device(0))
        );
        assert_eq!(command_from_id(ID_DEVICE_BASE + 1, &m), None);
        assert_eq!(
            command_from_id(ID_TARGET_BASE + 1, &m),
            Some(MenuCommand::SetDefaultTarget(1))
        );
        assert_eq!(command_from_id(ID_TARGET_BASE + 2, &m), None);
        assert_eq!(command_from_id(50, &m), None);
    }

    #[test]
    fn menus_build_for_empty_and_full_models() {
        for m in [MenuModel::default(), model()] {
            let h = build_menu(&m);
            assert!(!h.is_null());
            // SAFETY: we own the menu.
            unsafe { DestroyMenu(h) };
        }
    }
}
