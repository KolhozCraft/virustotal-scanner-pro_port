use std::ffi::{c_int, c_void};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use slint::{CloseRequestResponse, ComponentHandle, Timer, TimerMode, Weak};

use crate::config::{self, AppConfig};
use crate::ffi;
use crate::lang::fkpguoca9la;
use crate::scan::{self, fqg0uaz7gwv, Inner};
use crate::{Actions, AppState, Cfg, MainWindow, Tr, UiFlags};

struct TrayContext {
    ui: Weak<MainWindow>,
    inner: Arc<Inner>,
}

pub struct Runtime {
    inner: Arc<Inner>,
    _timer: Timer,
    tray_context: *mut TrayContext,
}

fn f3c1v6k0ykj(ui: &MainWindow, cfg: &AppConfig) {
    let c = ui.global::<Cfg>();
    c.set_topmost(cfg.topmost);
    c.set_theme(cfg.theme.clone().into());
    c.set_sound_on_complete(cfg.sound_on_complete);
    c.set_api_type(cfg.api_type.clone().into());
    c.set_lang(cfg.lang.clone().into());
    c.set_close_to_tray(cfg.close_to_tray);
    c.set_autostart(cfg.autostart);
    ui.global::<AppState>().set_api_key_input(cfg.api_key.clone().into());
}

fn fge7eab6ois(ui: &MainWindow, cfg: &mut AppConfig) {
    let c = ui.global::<Cfg>();
    cfg.topmost = c.get_topmost();
    cfg.theme = c.get_theme().to_string();
    cfg.sound_on_complete = c.get_sound_on_complete();
    cfg.api_type = c.get_api_type().to_string();
    cfg.lang = c.get_lang().to_string();
    cfg.close_to_tray = c.get_close_to_tray();
    cfg.autostart = c.get_autostart();
}

fn fwhhqbvgldy(lang: &str) {
    ffi::ffm3hcvdpot(&fkpguoca9la(lang, "tray_show"), &fkpguoca9la(lang, "tray_exit"));
}

fn fdv7hpnvhzq(ui: &MainWindow, inner: &Inner) {
    let s = inner.f8thc1yza2s();
    let lang = inner.fu0iny2esj5();
    let g = ui.global::<AppState>();
    g.set_scanning(s.scanning);
    g.set_has_file(s.has_file);
    g.set_rescan_enabled(s.rescan_enabled);
    g.set_file_name(s.file_name.into());
    g.set_file_size_text(
        format!("{}: {:.2} {}", fkpguoca9la(&lang, "size"), s.file_size as f64 / 1024.0, fkpguoca9la(&lang, "kb")).into(),
    );
    g.set_file_hash_text(format!("{}: {}", fkpguoca9la(&lang, "sha256"), s.file_hash).into());
    g.set_status_text(s.status_text.into());
    g.set_output_log(s.output_log.into());
    g.set_progress(s.progress);
    g.set_show_check_now(s.show_check_now);
    g.set_requests_used(s.requests_used);
}

fn fezzb1lbhxl(ui: &MainWindow) {
    let _ = ui.show();
    ui.window().set_minimized(false);
    Timer::single_shot(Duration::from_millis(30), ffi::fwtdz6e1dnx);
}

extern "C" fn frbxtz1p7hx(event: c_int, user: *mut c_void) {
    let ctx = unsafe { &*(user as *const TrayContext) };
    match event {
        ffi::TRAY_SHOW => {
            let weak = ctx.ui.clone();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = weak.upgrade() {
                    fezzb1lbhxl(&ui);
                }
            });
        }
        ffi::TRAY_EXIT => {
            ctx.inner.shutting_down.store(true, Ordering::SeqCst);
            let _ = slint::quit_event_loop();
        }
        _ => {}
    }
}

impl Runtime {
    pub fn fmn9gb8213m(ui: &MainWindow) -> Runtime {
        let cfg = config::fc7djsqw6ey();
        let inner = Arc::new(Inner::fr5wcd6erfu(cfg.clone()));

        f3c1v6k0ykj(ui, &cfg);
        inner.f1b6f242zm2(|s| {
            s.status_text = fkpguoca9la(&cfg.lang, "ready");
            s.requests_used = cfg.requests_used;
        });

        let flags = ui.global::<UiFlags>();
        if cfg.api_key.is_empty() {
            flags.set_show_api_key(true);
        }
        if !cfg.thanks_shown {
            flags.set_show_thanks(true);
        }

        ffi::fe2khx20j51(cfg.autostart);

        ui.global::<Tr>()
            .on_fw9qy2wz84z(|lang, key| fkpguoca9la(lang.as_str(), key.as_str()).into());

        Self::f4h9la58jcq(ui, &inner);
        Self::fbqo3msw4ke(ui, &inner);
        Self::f0qbho6he0s(ui, &inner);

        let tray_context = Box::into_raw(Box::new(TrayContext {
            ui: ui.as_weak(),
            inner: Arc::clone(&inner),
        }));
        ffi::fbpp51gxjba(
            frbxtz1p7hx,
            tray_context as *mut c_void,
            "VirusTotal Scanner Pro",
            &fkpguoca9la(&cfg.lang, "tray_show"),
            &fkpguoca9la(&cfg.lang, "tray_exit"),
        );

        fdv7hpnvhzq(ui, &inner);

        let timer = Timer::default();
        {
            let weak = ui.as_weak();
            let inner = Arc::clone(&inner);
            let mut last = inner.generation.load(Ordering::SeqCst);
            timer.start(TimerMode::Repeated, Duration::from_millis(100), move || {
                let current = inner.generation.load(Ordering::SeqCst);
                if current == last {
                    return;
                }
                last = current;
                if let Some(ui) = weak.upgrade() {
                    fdv7hpnvhzq(&ui, &inner);
                }
            });
        }

        Runtime {
            inner,
            _timer: timer,
            tray_context,
        }
    }

    fn f4h9la58jcq(ui: &MainWindow, inner: &Arc<Inner>) {
        let weak = ui.as_weak();
        let inner = Arc::clone(inner);
        ui.global::<Cfg>().on_f7sua4gyqbn(move || {
            let Some(ui) = weak.upgrade() else { return };
            fge7eab6ois(&ui, &mut fqg0uaz7gwv(&inner.config));
            fwhhqbvgldy(&inner.fu0iny2esj5());
            inner.fw5nggku9fs();
        });
    }

    fn fbqo3msw4ke(ui: &MainWindow, inner: &Arc<Inner>) {
        let actions = ui.global::<Actions>();

        {
            let inner = Arc::clone(inner);
            actions.on_fnhej4hffkb(move || {
                if inner.f8thc1yza2s().scanning {
                    return;
                }
                if inner.dialog_open.swap(true, Ordering::SeqCst) {
                    return;
                }
                let owner = ffi::f9ibco8t9ht();
                let inner = Arc::clone(&inner);
                std::thread::spawn(move || {
                    let path = ffi::f2dbwozvkyn(owner);
                    inner.dialog_open.store(false, Ordering::SeqCst);
                    if let Some(path) = path {
                        scan::fvcmqm9ga1b(&inner, path);
                    }
                });
            });
        }

        {
            let inner = Arc::clone(inner);
            actions.on_fkjezlxswmu(move || scan::f77tdc7g0za(&inner));
        }

        {
            let inner = Arc::clone(inner);
            actions.on_fvum2ylkwsn(move || {
                let hash = inner.f8thc1yza2s().file_hash;
                if !hash.is_empty() {
                    ffi::fmhg6umhm2b(&hash);
                }
            });
        }

        {
            let inner = Arc::clone(inner);
            actions.on_f87pe0lfx7z(move || {
                let hash = inner.f8thc1yza2s().file_hash;
                if !hash.is_empty() {
                    ffi::fw6w6bp0vr8(&format!("https://www.virustotal.com/gui/file/{hash}"));
                }
            });
        }

        {
            let inner = Arc::clone(inner);
            actions.on_folpjypdhbi(move || scan::fmsgvhb7jjy(&inner));
        }

        {
            let inner = Arc::clone(inner);
            actions.on_fned47nvlvc(move || inner.check_now.store(true, Ordering::SeqCst));
        }

        {
            let inner = Arc::clone(inner);
            actions.on_f4v66wk7b5u(move || {
                let cfg = fqg0uaz7gwv(&inner.config).clone();
                ffi::fe2khx20j51(cfg.autostart);
                config::fxsak02dyoz(&cfg);
                let ready = fkpguoca9la(&cfg.lang, "ready");
                inner.f1b6f242zm2(|s| s.status_text = ready);
            });
        }

        {
            let weak = ui.as_weak();
            let inner = Arc::clone(inner);
            actions.on_fhg6wxr8spi(move || {
                let cfg = config::fc7djsqw6ey();
                *fqg0uaz7gwv(&inner.config) = cfg.clone();
                if let Some(ui) = weak.upgrade() {
                    f3c1v6k0ykj(&ui, &cfg);
                }
                fwhhqbvgldy(&cfg.lang);
                inner.fw5nggku9fs();
            });
        }

        {
            let weak = ui.as_weak();
            let inner = Arc::clone(inner);
            actions.on_fa45wv5xq9g(move || {
                let Some(ui) = weak.upgrade() else { return };
                let key = ui.global::<AppState>().get_api_key_input().to_string();
                let cfg = {
                    let mut cfg = fqg0uaz7gwv(&inner.config);
                    cfg.api_key = key;
                    config::fxsak02dyoz(&cfg);
                    cfg.clone()
                };
                let msg = fkpguoca9la(&cfg.lang, "api_key_updated");
                inner.f1b6f242zm2(|s| s.status_text = msg);
            });
        }

        {
            let weak = ui.as_weak();
            let inner = Arc::clone(inner);
            actions.on_fp1tj5nd0tc(move || {
                if let Some(ui) = weak.upgrade() {
                    let key = fqg0uaz7gwv(&inner.config).api_key.clone();
                    ui.global::<AppState>().set_api_key_input(key.into());
                }
            });
        }

        {
            let inner = Arc::clone(inner);
            actions.on_f506mozbyu6(move |dont_show| {
                let mut cfg = fqg0uaz7gwv(&inner.config);
                cfg.thanks_shown = dont_show;
                config::fxsak02dyoz(&cfg);
            });
        }
    }

    fn f0qbho6he0s(ui: &MainWindow, inner: &Arc<Inner>) {
        let inner = Arc::clone(inner);
        ui.window().on_close_requested(move || {
            if !fqg0uaz7gwv(&inner.config).close_to_tray {
                inner.shutting_down.store(true, Ordering::SeqCst);
                let _ = slint::quit_event_loop();
            }
            CloseRequestResponse::HideWindow
        });
    }

    pub fn f2cszgcj9q4(self) {
        self.inner.shutting_down.store(true, Ordering::SeqCst);
        ffi::ffdm7bias5y();
        unsafe { drop(Box::from_raw(self.tray_context)) };
    }
}
