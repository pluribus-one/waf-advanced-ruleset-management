fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/transaction_ext.cpp");

    match try_system_modsecurity() {
        Ok(library) => {
            eprintln!("libmodsecurity found on the system:");
            eprintln!("  Name: {:?}", library.libs);
            eprintln!("  Path: {:?}", library.link_paths);
            eprintln!("  Version: {}", library.version);

            cc::Build::new()
                .cpp(true)
                .file("src/transaction_ext.cpp")
                .includes(&library.include_paths)
                .flag("-std=c++17")
                .compile("modsecurity_ext");
        }
        Err(e) => {
            eprintln!("libmodsecurity cannot be found on the system: {e}");
            eprintln!("Vendoring is not supported at this time.");
            std::process::exit(1);
        }
    }
}

/// Tries to use system libmodsecurity. If it is found, it emits the necessary
/// linking directives.
fn try_system_modsecurity() -> Result<pkg_config::Library, pkg_config::Error> {
    let mut cfg = pkg_config::Config::new();
    cfg.atleast_version("3.0.13").probe("modsecurity")
}
