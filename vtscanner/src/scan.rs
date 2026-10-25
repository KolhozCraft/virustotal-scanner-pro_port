use std::io::Read;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::Duration;

use regex::Regex;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::config::{self, AppConfig};
use crate::ffi;
use crate::lang::fkpguoca9la;

const VT_UPLOAD_URL: &str = "https://www.virustotal.com/api/v3/files";
const VT_ANALYSES_URL: &str = "https://www.virustotal.com/api/v3/analyses/";
const VT_FILES_URL: &str = "https://www.virustotal.com/api/v3/files/";
const VT_COMMENTS_URL: &str = "https://www.virustotal.com/api/v3/comments/";

#[derive(Clone, Default)]
pub struct ScanState {
    pub scanning: bool,
    pub has_file: bool,
    pub rescan_enabled: bool,
    pub file_name: String,
    pub file_hash: String,
    pub file_size: u64,
    pub status_text: String,
    pub output_log: String,
    pub progress: f32,
    pub show_check_now: bool,
    pub requests_used: i32,
}

pub struct Inner {
    pub config: Mutex<AppConfig>,
    pub state: Mutex<ScanState>,
    pub generation: AtomicU64,
    pub check_now: AtomicBool,
    pub shutting_down: AtomicBool,
    pub dialog_open: AtomicBool,
    pub current_file: Mutex<Option<String>>,
}

pub fn fqg0uaz7gwv<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl Inner {
    pub fn fr5wcd6erfu(cfg: AppConfig) -> Self {
        Self {
            config: Mutex::new(cfg),
            state: Mutex::new(ScanState::default()),
            generation: AtomicU64::new(1),
            check_now: AtomicBool::new(false),
            shutting_down: AtomicBool::new(false),
            dialog_open: AtomicBool::new(false),
            current_file: Mutex::new(None),
        }
    }

    pub fn f8thc1yza2s(&self) -> ScanState {
        fqg0uaz7gwv(&self.state).clone()
    }

    pub fn f1b6f242zm2(&self, f: impl FnOnce(&mut ScanState)) {
        {
            let mut g = fqg0uaz7gwv(&self.state);
            f(&mut g);
        }
        self.fw5nggku9fs();
    }

    pub fn fw5nggku9fs(&self) {
        self.generation.fetch_add(1, Ordering::SeqCst);
    }

    pub fn fu0iny2esj5(&self) -> String {
        fqg0uaz7gwv(&self.config).lang.clone()
    }

    fn flla6vz4bc4(&self, text: &str) {
        self.f1b6f242zm2(|s| s.status_text = text.to_string());
    }

    fn fr11ipuzom0(&self, p: f32) {
        self.f1b6f242zm2(|s| s.progress = p);
    }

    fn fng8wt4u58a(&self, text: &str) {
        self.f1b6f242zm2(|s| s.output_log.push_str(text));
    }

    fn f9jvnh91tr3(&self) {
        self.f1b6f242zm2(|s| {
            s.scanning = false;
            s.show_check_now = false;
        });
    }

    fn ff3tf18bbk3(&self) {
        let used = {
            let mut cfg = fqg0uaz7gwv(&self.config);
            cfg.requests_used += 1;
            config::fxsak02dyoz(&cfg);
            cfg.requests_used
        };
        self.f1b6f242zm2(|s| s.requests_used = used);
    }

    fn fcqd96cfqla(&self) {
        if fqg0uaz7gwv(&self.config).sound_on_complete {
            ffi::fk0arfdv6e7();
        }
    }
}

fn fhhvlugvcsv() -> String {
    chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string()
}

fn faqux78hncc(path: &str) -> Option<String> {
    let mut file = std::fs::File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = file.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Some(hasher.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

fn f63m2ds2gok(v: &Value, key: &str, default: &str) -> String {
    v.get(key).and_then(Value::as_str).unwrap_or(default).to_string()
}

fn f0saoc801p1(v: &Value, key: &str) -> i64 {
    v.get(key).and_then(Value::as_i64).unwrap_or(0)
}

fn feh03bxc4lg(body: &str) -> String {
    static BY_PREFIX: OnceLock<Regex> = OnceLock::new();
    static BY_UUID: OnceLock<Regex> = OnceLock::new();

    let msg = serde_json::from_str::<Value>(body)
        .ok()
        .and_then(|j| j.get("error")?.get("message")?.as_str().map(str::to_string))
        .unwrap_or_default();
    if msg.is_empty() {
        return String::new();
    }

    let by_prefix = BY_PREFIX.get_or_init(|| Regex::new(r"analysis[=/]([a-zA-Z0-9-]+)").unwrap());
    if let Some(c) = by_prefix.captures(&msg) {
        return c[1].to_string();
    }
    let by_uuid = BY_UUID.get_or_init(|| Regex::new(r"([a-f0-9-]{36})").unwrap());
    if let Some(c) = by_uuid.captures(&msg) {
        return c[1].to_string();
    }
    String::new()
}

struct CommentInfo {
    author: String,
    reputation: i64,
    text: String,
}

fn febi46pnaqn(hash: &str, api_key: &str) -> Vec<CommentInfo> {
    let mut out = Vec::new();
    let resp = ffi::fqsy67c9ih4(&format!("{VT_FILES_URL}{hash}/comments"), api_key, 15000);
    if resp.status != 200 {
        return out;
    }
    let Ok(j) = serde_json::from_str::<Value>(&resp.body) else {
        return out;
    };
    let Some(data) = j.get("data").and_then(Value::as_array) else {
        return out;
    };

    for c in data.iter().take(10) {
        let text = c
            .get("attributes")
            .map(|a| f63m2ds2gok(a, "text", ""))
            .unwrap_or_default();
        let id = f63m2ds2gok(c, "id", "");
        let mut author = "anonymous".to_string();
        let mut reputation = 0;

        if !id.is_empty() {
            let ar = ffi::fqsy67c9ih4(&format!("{VT_COMMENTS_URL}{id}/author"), api_key, 10000);
            if ar.status == 200 {
                if let Ok(aj) = serde_json::from_str::<Value>(&ar.body) {
                    if let Some(d) = aj.get("data") {
                        author = f63m2ds2gok(d, "id", &author);
                        reputation = d.get("attributes").map(|a| f0saoc801p1(a, "reputation")).unwrap_or(0);
                    }
                }
            }
        }

        out.push(CommentInfo { author, reputation, text });
    }
    out
}

fn fnz8xpjlozy(hash: &str, api_key: &str) -> (i64, Value) {
    let resp = ffi::fqsy67c9ih4(&format!("{VT_FILES_URL}{hash}"), api_key, 15000);
    if resp.status != 200 {
        return (0, Value::Null);
    }
    let Ok(j) = serde_json::from_str::<Value>(&resp.body) else {
        return (0, Value::Null);
    };
    let Some(attrs) = j.get("data").and_then(|d| d.get("attributes")) else {
        return (0, Value::Null);
    };
    (
        f0saoc801p1(attrs, "reputation"),
        attrs.get("total_votes").cloned().unwrap_or(Value::Null),
    )
}

#[allow(clippy::too_many_arguments)]
fn f52cw3a9a9t(
    lang: &str,
    file_name: &str,
    file_size: u64,
    hash: &str,
    stats: &Value,
    results: &Value,
    comments: &[CommentInfo],
    reputation: i64,
    total_votes: &Value,
) -> String {
    let bar = "=".repeat(70);
    let dash = "-".repeat(70);
    let tr = |k: &str| fkpguoca9la(lang, k);

    let malicious = f0saoc801p1(stats, "malicious");
    let suspicious = f0saoc801p1(stats, "suspicious");
    let undetected = f0saoc801p1(stats, "undetected");
    let harmless = f0saoc801p1(stats, "harmless");
    let timeout = f0saoc801p1(stats, "timeout");
    let votes_harmless = f0saoc801p1(total_votes, "harmless");
    let votes_malicious = f0saoc801p1(total_votes, "malicious");
    let mark = if reputation > 0 {
        "(+)"
    } else if reputation < 0 {
        "(-)"
    } else {
        "(0)"
    };

    let mut o = String::new();
    o.push_str(&format!("{bar}\n{}\n{bar}\n\n", tr("scan_results_header")));
    o.push_str(&format!("{}: {file_name}\n", tr("file_label")));
    o.push_str(&format!(
        "{}: {:.2} {} ({} {})\n",
        tr("size"),
        file_size as f64 / 1024.0,
        tr("kb"),
        file_size,
        tr("bytes_unit")
    ));
    o.push_str(&format!("{}: {hash}\n", tr("sha256")));
    o.push_str(&format!("{}: {}\n\n", tr("date_label"), fhhvlugvcsv()));
    o.push_str(&format!("{bar}\n{}:\n", tr("stats")));
    o.push_str(&format!("  {}: {harmless}\n", tr("harmless")));
    o.push_str(&format!("  {}: {undetected}\n", tr("undetected")));
    o.push_str(&format!("  {}: {suspicious}\n", tr("suspicious")));
    o.push_str(&format!("  {}: {malicious}\n", tr("malicious")));
    o.push_str(&format!("  {}: {timeout}\n\n", tr("timeout_stats")));
    o.push_str(&format!("{bar}\n{mark} {}: {reputation}\n", tr("reputation")));
    o.push_str(&format!(
        "  {}: {votes_harmless}   {}: {votes_malicious}\n",
        tr("votes_for"),
        tr("votes_against")
    ));
    o.push_str(&format!("{bar}\n\n"));

    if malicious > 0 || suspicious > 0 {
        o.push_str(&format!("!! {}:\n{dash}\n", tr("threats_detected")));
        let mut detected = 0;
        if let Some(map) = results.as_object() {
            for (engine_key, res) in map {
                let category = f63m2ds2gok(res, "category", "");
                if category == "malicious" || category == "suspicious" {
                    detected += 1;
                    let result_text = f63m2ds2gok(res, "result", &tr("unknown_object"));
                    let method = f63m2ds2gok(res, "method", "unknown");
                    let engine = f63m2ds2gok(res, "engine_name", engine_key);
                    let tag = if category == "malicious" { "M" } else { "S" };
                    o.push_str(&format!("[{tag}] {engine} -> {result_text}\n"));
                    o.push_str(&format!("    {}: {method}\n", tr("method_label")));
                }
            }
        }
        o.push_str(&format!("{dash}\n{}: {detected}\n", tr("total_detections")));
    } else {
        o.push_str(&format!("{}\n", tr("no_detections")));
    }

    o.push_str(&format!(
        "\n{}: https://www.virustotal.com/gui/file/{hash}\n",
        tr("full_report")
    ));

    if comments.is_empty() {
        o.push_str(&format!("\n{}\n", tr("no_comments")));
    } else {
        o.push_str(&format!("\n{bar}\n{} ({}):\n{bar}\n", tr("comments"), comments.len()));
        for c in comments {
            let sign = if c.reputation >= 0 { "+" } else { "" };
            o.push_str(&format!("{} ({sign}{}): {}\n", c.author, c.reputation, c.text));
        }
    }

    o
}

pub fn fvcmqm9ga1b(inner: &Arc<Inner>, path: String) {
    if inner.f8thc1yza2s().scanning {
        return;
    }

    let file_name = std::path::Path::new(&path)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.clone());
    let file_size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
    let lang = inner.fu0iny2esj5();

    *fqg0uaz7gwv(&inner.current_file) = Some(path.clone());

    let header = format!(
        "{}\n{}\n\n{}\n{}\n\n{}\n",
        fkpguoca9la(&lang, "scan_start_header"),
        "=".repeat(70),
        fkpguoca9la(&lang, "scan_start_note1"),
        fkpguoca9la(&lang, "scan_start_note2"),
        fkpguoca9la(&lang, "hash_calc"),
    );
    let status = fkpguoca9la(&lang, "hash_calc");
    inner.f1b6f242zm2(|s| {
        s.has_file = true;
        s.rescan_enabled = true;
        s.file_name = file_name.clone();
        s.file_size = file_size;
        s.file_hash.clear();
        s.scanning = true;
        s.progress = 0.0;
        s.show_check_now = false;
        s.output_log = header;
        s.status_text = status;
    });

    inner.check_now.store(false, Ordering::SeqCst);

    let worker_inner = Arc::clone(inner);
    std::thread::spawn(move || fx270gg99w0(worker_inner, path, file_name, file_size));
}

pub fn f77tdc7g0za(inner: &Arc<Inner>) {
    let current = fqg0uaz7gwv(&inner.current_file).clone();
    if let Some(path) = current {
        fvcmqm9ga1b(inner, path);
    }
}

pub fn fmsgvhb7jjy(inner: &Inner) {
    let lang = inner.fu0iny2esj5();
    inner.f1b6f242zm2(|s| {
        s.output_log = format!("{}\n", fkpguoca9la(&lang, "output_cleared"));
        s.status_text = fkpguoca9la(&lang, "ready");
        s.progress = 0.0;
    });
}

fn fx270gg99w0(inner: Arc<Inner>, path: String, file_name: String, file_size: u64) {
    let lang = inner.fu0iny2esj5();
    let api_key = fqg0uaz7gwv(&inner.config).api_key.clone();
    let tr = |k: &str| fkpguoca9la(&lang, k);

    let Some(hash) = faqux78hncc(&path) else {
        inner.fng8wt4u58a(&format!("\n{}\n", tr("error_fail")));
        inner.flla6vz4bc4(&tr("error_fail"));
        inner.f9jvnh91tr3();
        return;
    };

    inner.f1b6f242zm2(|s| s.file_hash = hash.clone());
    inner.flla6vz4bc4(&tr("checking_db"));
    inner.fr11ipuzom0(0.1);

    let report = ffi::fqsy67c9ih4(&format!("{VT_FILES_URL}{hash}"), &api_key, 30000);

    if report.network_error {
        inner.fng8wt4u58a(&format!("\n{}\n", tr("error_network")));
        inner.flla6vz4bc4(&tr("error_network"));
        inner.f9jvnh91tr3();
        return;
    }

    if report.status == 200 {
        if let Ok(j) = serde_json::from_str::<Value>(&report.body) {
            if let Some(attrs) = j.get("data").and_then(|d| d.get("attributes")) {
                let stats = attrs.get("last_analysis_stats").cloned().unwrap_or(Value::Null);
                let results = attrs.get("last_analysis_results").cloned().unwrap_or(Value::Null);
                let has_stats = stats.as_object().map(|o| !o.is_empty()).unwrap_or(false);
                if has_stats {
                    inner.fng8wt4u58a(&format!("{}\n\n", tr("file_found_in_db")));
                    let comments = febi46pnaqn(&hash, &api_key);
                    let (reputation, total_votes) = fnz8xpjlozy(&hash, &api_key);
                    let text = f52cw3a9a9t(
                        &lang, &file_name, file_size, &hash, &stats, &results, &comments, reputation,
                        &total_votes,
                    );
                    let status = tr("ready_report_from_db");
                    inner.f1b6f242zm2(|s| {
                        s.output_log = text;
                        s.progress = 1.0;
                        s.status_text = status;
                    });
                    inner.ff3tf18bbk3();
                    inner.fcqd96cfqla();
                    inner.f9jvnh91tr3();
                    return;
                }
            }
        }
    }

    inner.flla6vz4bc4(&tr("file_not_in_db"));
    inner.fng8wt4u58a(&format!("{}\n", tr("uploading")));
    inner.fr11ipuzom0(0.3);

    let upload = ffi::fq113h7g9xi(VT_UPLOAD_URL, &api_key, &path, "file", &file_name, 120000);

    let analysis_id;
    if upload.network_error {
        inner.fng8wt4u58a(&format!("\n{}\n", tr("error_network")));
        inner.flla6vz4bc4(&tr("error_network"));
        inner.f9jvnh91tr3();
        return;
    } else if upload.status == 409 {
        analysis_id = feh03bxc4lg(&upload.body);
        if analysis_id.is_empty() {
            inner.fng8wt4u58a(&format!("\n{}\n", tr("error_fail")));
            inner.flla6vz4bc4(&tr("error_fail"));
            inner.f9jvnh91tr3();
            return;
        }
    } else if upload.status == 200 {
        analysis_id = serde_json::from_str::<Value>(&upload.body)
            .ok()
            .and_then(|j| j.get("data")?.get("id")?.as_str().map(str::to_string))
            .unwrap_or_default();
        if analysis_id.is_empty() {
            inner.fng8wt4u58a(&format!("\n{}\n", tr("error_fail")));
            inner.flla6vz4bc4(&tr("error_fail"));
            inner.f9jvnh91tr3();
            return;
        }
        inner.fng8wt4u58a(&format!("{}\n", tr("file_uploaded")));
    } else {
        let msg = format!("{} ({})", tr("error_fail"), upload.status);
        inner.fng8wt4u58a(&format!("\n{msg}\n"));
        inner.flla6vz4bc4(&msg);
        inner.f9jvnh91tr3();
        return;
    }

    let analysis_url = format!("{VT_ANALYSES_URL}{analysis_id}");
    inner.fr11ipuzom0(0.4);
    inner.flla6vz4bc4(&tr("waiting_scan"));
    inner.fng8wt4u58a(&format!("{}\n", tr("waiting_scan_text")));
    inner.f1b6f242zm2(|s| s.show_check_now = true);

    const MAX_ATTEMPTS: u32 = 30;
    const POLL_SECONDS: u32 = 15;
    inner.check_now.store(false, Ordering::SeqCst);

    for attempt in 1..=MAX_ATTEMPTS {
        for _ in 0..(POLL_SECONDS * 10) {
            if inner.shutting_down.load(Ordering::SeqCst) {
                return;
            }
            if inner.check_now.swap(false, Ordering::SeqCst) {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        if inner.shutting_down.load(Ordering::SeqCst) {
            return;
        }

        inner.fr11ipuzom0(0.4 + (attempt as f32 * 0.02).min(0.55));

        let ar = ffi::fqsy67c9ih4(&analysis_url, &api_key, 30000);
        if ar.status != 200 {
            continue;
        }

        let Ok(j) = serde_json::from_str::<Value>(&ar.body) else {
            continue;
        };
        let attrs = j
            .get("data")
            .and_then(|d| d.get("attributes"))
            .cloned()
            .unwrap_or(Value::Null);
        let status = f63m2ds2gok(&attrs, "status", "unknown");

        if status == "completed" {
            let stats = attrs.get("stats").cloned().unwrap_or(Value::Null);
            let results = attrs.get("results").cloned().unwrap_or(Value::Null);
            let comments = febi46pnaqn(&hash, &api_key);
            let (reputation, total_votes) = fnz8xpjlozy(&hash, &api_key);
            let text = f52cw3a9a9t(
                &lang, &file_name, file_size, &hash, &stats, &results, &comments, reputation,
                &total_votes,
            );
            let done = tr("scan_complete");
            inner.f1b6f242zm2(|s| {
                s.output_log = text;
                s.progress = 1.0;
                s.status_text = done;
                s.show_check_now = false;
            });
            inner.ff3tf18bbk3();
            inner.fcqd96cfqla();
            inner.f9jvnh91tr3();
            return;
        } else {
            inner.flla6vz4bc4(&format!("{}: [{status}] ({attempt}/{MAX_ATTEMPTS})", tr("status")));
        }
    }

    inner.fng8wt4u58a(&format!(
        "\n{}\n{}: {analysis_url}\n",
        tr("timeout_warning"),
        tr("check_later")
    ));
    inner.flla6vz4bc4(&tr("timeout_warning"));
    inner.f9jvnh91tr3();
}
