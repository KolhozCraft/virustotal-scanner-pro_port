use std::path::PathBuf;

use serde_json::{json, Value};

use crate::ffi;

#[derive(Clone, Debug)]
pub struct AppConfig {
    pub api_key: String,
    pub topmost: bool,
    pub thanks_shown: bool,
    pub api_type: String,
    pub requests_used: i32,
    pub requests_reset_date: String,
    pub lang: String,
    pub theme: String,
    pub sound_on_complete: bool,
    pub close_to_tray: bool,
    pub autostart: bool,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            api_key: String::new(),
            topmost: false,
            thanks_shown: false,
            api_type: "free".into(),
            requests_used: 0,
            requests_reset_date: String::new(),
            lang: "ru".into(),
            theme: "dark".into(),
            sound_on_complete: true,
            close_to_tray: false,
            autostart: false,
        }
    }
}

pub fn fsa0a1t27e1() -> String {
    chrono::Local::now().format("%Y-%m-%d").to_string()
}

fn ftpefwtslki() -> PathBuf {
    let dir = ffi::ffwf5u52t2w().unwrap_or_else(|| ".".into());
    PathBuf::from(dir).join("vt_config.json")
}

fn fez8zg7susy(j: &Value, key: &str, default: &str) -> String {
    j.get(key).and_then(Value::as_str).unwrap_or(default).to_string()
}

fn fxt2mgl6ryl(j: &Value, key: &str, default: bool) -> bool {
    j.get(key).and_then(Value::as_bool).unwrap_or(default)
}

pub fn fc7djsqw6ey() -> AppConfig {
    let mut cfg = AppConfig::default();

    if let Ok(text) = std::fs::read_to_string(ftpefwtslki()) {
        if let Ok(j) = serde_json::from_str::<Value>(&text) {
            if let Some(protected) = j.get("api_key_protected").and_then(Value::as_str) {
                cfg.api_key = ffi::f6gklrmriyj(protected);
            } else if let Some(plain) = j.get("api_key").and_then(Value::as_str) {
                cfg.api_key = plain.to_string();
            }
            cfg.topmost = fxt2mgl6ryl(&j, "topmost", cfg.topmost);
            cfg.thanks_shown = fxt2mgl6ryl(&j, "thanks_shown", cfg.thanks_shown);
            cfg.api_type = fez8zg7susy(&j, "api_type", &cfg.api_type);
            cfg.requests_used = j
                .get("requests_used")
                .and_then(Value::as_i64)
                .map(|v| v as i32)
                .unwrap_or(cfg.requests_used);
            cfg.requests_reset_date = fez8zg7susy(&j, "requests_reset_date", &cfg.requests_reset_date);
            cfg.lang = fez8zg7susy(&j, "lang", &cfg.lang);
            cfg.theme = fez8zg7susy(&j, "theme", &cfg.theme);
            cfg.sound_on_complete = fxt2mgl6ryl(&j, "sound_on_complete", cfg.sound_on_complete);
            cfg.close_to_tray = fxt2mgl6ryl(&j, "close_to_tray", cfg.close_to_tray);
            cfg.autostart = fxt2mgl6ryl(&j, "autostart", cfg.autostart);
        }
    }

    let today = fsa0a1t27e1();
    if cfg.requests_reset_date != today {
        cfg.requests_used = 0;
        cfg.requests_reset_date = today;
        fxsak02dyoz(&cfg);
    }

    cfg
}

pub fn fxsak02dyoz(cfg: &AppConfig) -> bool {
    let protected = if cfg.api_key.is_empty() {
        String::new()
    } else {
        ffi::f9f6tk4560w(&cfg.api_key)
    };

    let j = json!({
        "api_key_protected": protected,
        "topmost": cfg.topmost,
        "thanks_shown": cfg.thanks_shown,
        "api_type": cfg.api_type,
        "requests_used": cfg.requests_used,
        "requests_reset_date": cfg.requests_reset_date,
        "lang": cfg.lang,
        "theme": cfg.theme,
        "sound_on_complete": cfg.sound_on_complete,
        "close_to_tray": cfg.close_to_tray,
        "autostart": cfg.autostart,
    });

    match serde_json::to_string_pretty(&j) {
        Ok(text) => std::fs::write(ftpefwtslki(), text).is_ok(),
        Err(_) => false,
    }
}
