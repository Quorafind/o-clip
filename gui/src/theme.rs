//! Dark theme palette and Win32 theming helpers.

use windows::Win32::Foundation::COLORREF;

/// Build a Win32 COLORREF from (R, G, B).
pub const fn rgb(r: u8, g: u8, b: u8) -> COLORREF {
    COLORREF((r as u32) | ((g as u32) << 8) | ((b as u32) << 16))
}

// ── Color palette (VS Code dark inspired) ────────────────────────────────

/// Main window background
pub const BG_WINDOW: COLORREF = rgb(30, 30, 30); // #1E1E1E

/// Alternating list row
pub const BG_LIST_ALT: COLORREF = rgb(37, 37, 38); // #252526

/// Input field background
pub const BG_INPUT: COLORREF = rgb(51, 51, 51); // #333333

/// Selection highlight
pub const BG_SELECTION: COLORREF = rgb(38, 79, 120); // #264F78

/// Primary text
pub const FG_PRIMARY: COLORREF = rgb(204, 204, 204); // #CCCCCC

/// Bright text (selected items)
pub const FG_BRIGHT: COLORREF = rgb(255, 255, 255); // #FFFFFF

// ── Win32 constants ──────────────────────────────────────────────────────

pub const DWMWA_USE_IMMERSIVE_DARK_MODE: u32 = 20;

pub const LVM_FIRST: u32 = 0x1000;
pub const LVM_SETBKCOLOR: u32 = LVM_FIRST + 1;
pub const LVM_SETIMAGELIST: u32 = LVM_FIRST + 3;
pub const LVM_GETHEADER: u32 = LVM_FIRST + 31;
pub const LVM_SETTEXTCOLOR: u32 = LVM_FIRST + 36;
pub const LVM_SETTEXTBKCOLOR: u32 = LVM_FIRST + 38;
pub const LVSIL_SMALL: usize = 1;

pub const EM_SETBKGNDCOLOR: u32 = 0x0443;
pub const EM_SETCHARFORMAT: u32 = 0x0444;
pub const SCF_DEFAULT: usize = 0;
pub const SCF_ALL: usize = 4;
pub const CFM_COLOR: u32 = 0x40000000;
pub const CHARFORMAT2W_SIZE: u32 = 116;

pub const NM_CUSTOMDRAW_CODE: u32 = (-12i32) as u32;
pub const CDDS_PREPAINT: u32 = 1;
pub const CDDS_ITEMPREPAINT: u32 = 0x00010001;
pub const CDRF_NOTIFYITEMDRAW: isize = 0x20;
pub const CDRF_NEWFONT: isize = 2;
pub const CDIS_SELECTED: u32 = 1;

pub const ILC_COLOR32: u32 = 0x0020;

/// Row height for the ListView (pixels).
pub const LIST_ROW_HEIGHT: i32 = 26;

// ── FFI declarations ─────────────────────────────────────────────────────

#[link(name = "dwmapi")]
unsafe extern "system" {
    pub fn DwmSetWindowAttribute(
        hwnd: isize,
        attr: u32,
        value: *const core::ffi::c_void,
        size: u32,
    ) -> i32;
}

#[link(name = "uxtheme")]
unsafe extern "system" {
    pub fn SetWindowTheme(hwnd: isize, sub_app: *const u16, sub_id: *const u16) -> i32;
}

#[link(name = "comctl32")]
unsafe extern "system" {
    pub fn ImageList_Create(cx: i32, cy: i32, flags: u32, initial: i32, grow: i32) -> isize;
}

/// "DarkMode_Explorer\0" in UTF-16.
pub static DARK_EXPLORER: &[u16] = &[
    0x44, 0x61, 0x72, 0x6B, 0x4D, 0x6F, 0x64, 0x65, 0x5F, 0x45, 0x78, 0x70, 0x6C, 0x6F, 0x72, 0x65,
    0x72, 0x00,
];

// ── Struct layouts for NM_CUSTOMDRAW (repr(C), matches Win32 ABI) ────────

#[repr(C)]
pub struct NmHdr {
    pub hwnd_from: isize,
    pub id_from: usize,
    pub code: u32,
}

#[repr(C)]
pub struct NmCustomDraw {
    pub hdr: NmHdr,
    pub draw_stage: u32,
    pub hdc: isize,
    pub rc: [i32; 4],
    pub item_spec: usize,
    pub item_state: u32,
    pub item_lparam: isize,
}

#[repr(C)]
pub struct NmLvCustomDraw {
    pub nmcd: NmCustomDraw,
    pub clr_text: u32,
    pub clr_text_bk: u32,
    pub sub_item: i32,
}

/// Helper: set the dark title bar on a window via DWM.
pub fn set_dark_title_bar(hwnd: isize) {
    let value: u32 = 1;
    unsafe {
        DwmSetWindowAttribute(
            hwnd,
            DWMWA_USE_IMMERSIVE_DARK_MODE,
            &value as *const _ as *const _,
            std::mem::size_of::<u32>() as u32,
        );
    }
}

/// Helper: apply the DarkMode_Explorer visual theme to a control.
pub fn set_dark_explorer_theme(hwnd: isize) {
    unsafe {
        SetWindowTheme(hwnd, DARK_EXPLORER.as_ptr(), std::ptr::null());
    }
}

/// Helper: build a zeroed CHARFORMAT2W buffer with CFM_COLOR and the given text color.
pub fn make_charformat_color(color: COLORREF) -> [u8; CHARFORMAT2W_SIZE as usize] {
    let mut buf = [0u8; CHARFORMAT2W_SIZE as usize];
    buf[0..4].copy_from_slice(&CHARFORMAT2W_SIZE.to_le_bytes());
    buf[4..8].copy_from_slice(&CFM_COLOR.to_le_bytes());
    // dwEffects at offset 8 = 0 (no CFE_AUTOCOLOR → use crTextColor)
    buf[20..24].copy_from_slice(&color.0.to_le_bytes());
    buf
}

// ── Undocumented uxtheme dark-mode APIs (by ordinal) ─────────────────────

/// "uxtheme.dll\0" in UTF-16.
static UXTHEME_DLL: &[u16] = &[
    0x75, 0x78, 0x74, 0x68, 0x65, 0x6D, 0x65, 0x2E, 0x64, 0x6C, 0x6C, 0x00,
];

fn uxtheme_proc(ordinal: usize) -> Option<unsafe extern "system" fn() -> isize> {
    use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
    use windows::core::PCWSTR;
    unsafe {
        let module = LoadLibraryW(PCWSTR(UXTHEME_DLL.as_ptr())).ok()?;
        GetProcAddress(module, windows::core::PCSTR(ordinal as *const u8))
    }
}

/// Call `SetPreferredAppMode(AllowDark)` — must be invoked **before** any
/// window is created so that menus, scrollbars, and other shell-themed
/// controls pick up the dark palette.
pub fn enable_dark_mode_for_app() {
    if let Some(f) = uxtheme_proc(135) {
        // SetPreferredAppMode(AllowDark = 1)
        let f: unsafe extern "system" fn(i32) -> i32 = unsafe { std::mem::transmute(f) };
        unsafe { f(1) };
    }
}

/// Tell the DWM that a specific window participates in dark mode.
pub fn allow_dark_mode_for_window(hwnd: isize) {
    if let Some(f) = uxtheme_proc(133) {
        // AllowDarkModeForWindow(hwnd, TRUE)
        let f: unsafe extern "system" fn(isize, i32) -> i32 = unsafe { std::mem::transmute(f) };
        unsafe { f(hwnd, 1) };
    }
}

/// Flush cached menu theme data so the menu bar redraws in dark mode.
pub fn flush_menu_themes() {
    if let Some(f) = uxtheme_proc(136) {
        let f: unsafe extern "system" fn() = unsafe { std::mem::transmute(f) };
        unsafe { f() };
    }
}
