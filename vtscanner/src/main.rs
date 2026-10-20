#![cfg_attr(windows, windows_subsystem = "windows")]

mod app;
mod config;
mod ffi;
mod lang;
mod scan;

slint::include_modules!();

fn main() -> Result<(), slint::PlatformError> {
    let ui = MainWindow::new()?;
    let runtime = app::Runtime::fmn9gb8213m(&ui);
    ui.show()?;
    slint::run_event_loop_until_quit()?;
    runtime.f2cszgcj9q4();
    let _ = ui.hide();
    Ok(())
}
