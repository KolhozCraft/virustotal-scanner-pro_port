use std::env;

fn main() {
    let config = slint_build::CompilerConfiguration::new().with_style("fluent".to_string());
    slint_build::compile_with_config("ui/app.slint", config).expect("slint compilation failed");

    println!("cargo:rerun-if-changed=native");
    println!("cargo:rerun-if-changed=ui");

    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    cc::Build::new()
        .cpp(true)
        .file("native/win32_shell.cpp")
        .std("c++17")
        .define("UNICODE", None)
        .define("_UNICODE", None)
        .define("NOMINMAX", None)
        .define("WIN32_LEAN_AND_MEAN", None)
        .compile("win32_shell");

    for lib in [
        "winhttp", "crypt32", "shell32", "comdlg32", "user32", "ole32", "advapi32",
    ] {
        println!("cargo:rustc-link-lib={lib}");
    }

    let _ = embed_resource::compile("native/resource.rc", embed_resource::NONE).manifest_optional();
}
