use std::ffi::{c_char, c_int, c_void, CStr, CString};

#[repr(C)]
struct RawResponse {
    status: c_int,
    network_error: c_int,
    timed_out: c_int,
    body: *mut c_char,
    body_len: usize,
}

pub type TrayCallback = extern "C" fn(event: c_int, user: *mut c_void);

pub const TRAY_SHOW: c_int = 1;
pub const TRAY_EXIT: c_int = 2;

extern "C" {
    fn f3un4d5fjcu(s: *mut c_char);
    fn f6nep1f9o7n() -> *mut c_char;
    fn fjdckhr30rn(plain: *const c_char) -> *mut c_char;
    fn f2funfd6n3n(b64: *const c_char) -> *mut c_char;
    fn f3uktifcxgm(enable: c_int) -> c_int;
    fn ffzma9z86zi() -> *mut c_void;
    fn fkzznls4w30(owner: *mut c_void) -> *mut c_char;
    fn f32pnbb7me8(url: *const c_char);
    fn f9jwldhl375(text: *const c_char);
    fn fksaxrq228o();
    fn fy4vo2fr45h();
    fn ffy9yybo2ia(url: *const c_char, api_key: *const c_char, timeout_ms: c_int, out: *mut RawResponse);
    fn f1t55yc0vd7(
        url: *const c_char,
        api_key: *const c_char,
        file_path: *const c_char,
        field_name: *const c_char,
        file_name: *const c_char,
        timeout_ms: c_int,
        out: *mut RawResponse,
    );
    fn fs064iemdmn(r: *mut RawResponse);
    fn fuw8nd6w1gk(
        callback: TrayCallback,
        user: *mut c_void,
        tooltip: *const c_char,
        show_label: *const c_char,
        exit_label: *const c_char,
    ) -> c_int;
    fn f8tgjs2kv3w(show_label: *const c_char, exit_label: *const c_char);
    fn fcn40nf3rzw();
}

fn flyxe6dotmx(s: &str) -> CString {
    CString::new(s.replace('\0', "")).unwrap_or_default()
}

unsafe fn ftx4lwpxlzk(p: *mut c_char) -> Option<String> {
    if p.is_null() {
        return None;
    }
    let s = CStr::from_ptr(p).to_string_lossy().into_owned();
    f3un4d5fjcu(p);
    Some(s)
}

pub struct Response {
    pub status: i32,
    pub network_error: bool,
    pub body: String,
}

fn fw557gsoutm(mut raw: RawResponse) -> Response {
    let body = if raw.body.is_null() {
        String::new()
    } else {
        let bytes = unsafe { std::slice::from_raw_parts(raw.body as *const u8, raw.body_len) };
        String::from_utf8_lossy(bytes).into_owned()
    };
    let response = Response {
        status: raw.status,
        network_error: raw.network_error != 0,
        body,
    };
    unsafe { fs064iemdmn(&mut raw) };
    response
}

fn fl2tie7w337() -> RawResponse {
    RawResponse {
        status: 0,
        network_error: 0,
        timed_out: 0,
        body: std::ptr::null_mut(),
        body_len: 0,
    }
}

pub fn fqsy67c9ih4(url: &str, api_key: &str, timeout_ms: i32) -> Response {
    let mut raw = fl2tie7w337();
    let (url, key) = (flyxe6dotmx(url), flyxe6dotmx(api_key));
    unsafe { ffy9yybo2ia(url.as_ptr(), key.as_ptr(), timeout_ms, &mut raw) };
    fw557gsoutm(raw)
}

pub fn fq113h7g9xi(
    url: &str,
    api_key: &str,
    file_path: &str,
    field_name: &str,
    file_name: &str,
    timeout_ms: i32,
) -> Response {
    let mut raw = fl2tie7w337();
    let (url, key, path, field, name) = (flyxe6dotmx(url), flyxe6dotmx(api_key), flyxe6dotmx(file_path), flyxe6dotmx(field_name), flyxe6dotmx(file_name));
    unsafe {
        f1t55yc0vd7(
            url.as_ptr(),
            key.as_ptr(),
            path.as_ptr(),
            field.as_ptr(),
            name.as_ptr(),
            timeout_ms,
            &mut raw,
        )
    };
    fw557gsoutm(raw)
}

pub fn ffwf5u52t2w() -> Option<String> {
    unsafe { ftx4lwpxlzk(f6nep1f9o7n()) }
}

pub fn f9f6tk4560w(plain: &str) -> String {
    let plain = flyxe6dotmx(plain);
    unsafe { ftx4lwpxlzk(fjdckhr30rn(plain.as_ptr())) }.unwrap_or_default()
}

pub fn f6gklrmriyj(b64: &str) -> String {
    let b64 = flyxe6dotmx(b64);
    unsafe { ftx4lwpxlzk(f2funfd6n3n(b64.as_ptr())) }.unwrap_or_default()
}

pub fn fe2khx20j51(enable: bool) -> bool {
    unsafe { f3uktifcxgm(enable as c_int) != 0 }
}

pub fn f9ibco8t9ht() -> usize {
    unsafe { ffzma9z86zi() as usize }
}

pub fn f2dbwozvkyn(owner: usize) -> Option<String> {
    unsafe { ftx4lwpxlzk(fkzznls4w30(owner as *mut c_void)) }
}

pub fn fw6w6bp0vr8(url: &str) {
    let url = flyxe6dotmx(url);
    unsafe { f32pnbb7me8(url.as_ptr()) }
}

pub fn fmhg6umhm2b(text: &str) {
    let text = flyxe6dotmx(text);
    unsafe { f9jwldhl375(text.as_ptr()) }
}

pub fn fk0arfdv6e7() {
    unsafe { fksaxrq228o() }
}

pub fn fwtdz6e1dnx() {
    unsafe { fy4vo2fr45h() }
}

pub fn fbpp51gxjba(callback: TrayCallback, user: *mut c_void, tooltip: &str, show: &str, exit: &str) -> bool {
    let (tooltip, show, exit) = (flyxe6dotmx(tooltip), flyxe6dotmx(show), flyxe6dotmx(exit));
    unsafe { fuw8nd6w1gk(callback, user, tooltip.as_ptr(), show.as_ptr(), exit.as_ptr()) != 0 }
}

pub fn ffm3hcvdpot(show: &str, exit: &str) {
    let (show, exit) = (flyxe6dotmx(show), flyxe6dotmx(exit));
    unsafe { f8tgjs2kv3w(show.as_ptr(), exit.as_ptr()) }
}

pub fn ffdm7bias5y() {
    unsafe { fcn40nf3rzw() }
}
