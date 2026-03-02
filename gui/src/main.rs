#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(windows)]
mod app;

#[cfg(windows)]
mod controls;

#[cfg(windows)]
mod theme;

#[cfg(not(windows))]
fn main() {
    eprintln!("o-clip-gui is Windows-only");
}

#[cfg(windows)]
fn main() {
    app::run();
}
