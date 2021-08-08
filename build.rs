extern crate bindgen;

use std::collections::HashSet;
use std::env;
use std::io::Result;
use std::process::Command;
use std::process::Output;

const NGIX_DIR: &str = "../nginx";

#[derive(Debug)]
struct IgnoreMacros(HashSet<String>);

impl bindgen::callbacks::ParseCallbacks for IgnoreMacros {
    fn will_parse_macro(&self, name: &str) -> bindgen::callbacks::MacroParsingBehavior {
        if self.0.contains(name) {
            bindgen::callbacks::MacroParsingBehavior::Ignore
        } else {
            bindgen::callbacks::MacroParsingBehavior::Default
        }
    }
}

// perform make with argument
fn make(arg: &str) -> Result<Output> {
    let current_path = env::current_dir().unwrap();
    let path_name = format!("{}", current_path.display());
    println!("executing make command at {}", path_name);
    let result = Command::new("/usr/bin/make")
        .args(&[arg])
        .current_dir(path_name)
        .output();

    match result {
        Err(e) => {
            return Err(e);
        }

        Ok(output) => {
            println!("status: {}", output.status);
            println!("stdout: {}", String::from_utf8_lossy(&output.stdout));
            println!("stderr: {}", String::from_utf8_lossy(&output.stderr));
            return Ok(output);
        }
    }
}

fn configure() -> Result<Output> {
    make("build")
}

fn generate_binding() {
    println!("cargo:rerun-if-changed=wrapper.h");
    let ignored_macros = IgnoreMacros(
        vec![
            "FP_INFINITE".into(),
            "FP_NAN".into(),
            "FP_NORMAL".into(),
            "FP_SUBNORMAL".into(),
            "FP_ZERO".into(),
            "IPPORT_RESERVED".into(),
        ]
        .into_iter()
        .collect(),
    );
    let bindings = bindgen::Builder::default()
        // The input header we would like to generate
        // bindings for.
        .header("wrapper.h")
        .rustified_enum(".*")
        .default_macro_constant_type(bindgen::MacroTypeVariation::Signed)
        .parse_callbacks(Box::new(ignored_macros))
        .rustfmt_bindings(true)
        .layout_tests(false)
        .detect_include_paths(false)
        .generate_inline_functions(true)
        .bitfield_enum("ngx_output_chain_ctx_t")
        .bitfield_enum("ngx_http_request_t")
        .bitfield_enum("ngx_connection_t")
        .clang_arg(format!("-I{}/src/core", NGIX_DIR))
        .clang_arg(format!("-I{}/src/event", NGIX_DIR))
        .clang_arg(format!("-I{}/src/event/modules", NGIX_DIR))
        .clang_arg(format!("-I{}/src/os/unix", NGIX_DIR))
        .clang_arg(format!("-I{}/objs", NGIX_DIR))
        .clang_arg(format!("-I{}/src/http", NGIX_DIR))
        .clang_arg(format!("-I{}/src/http/modules", NGIX_DIR))
        .clang_arg(format!("-I/usr/lib/clang/6.0/include"))
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");

    bindings
        .write_to_file("src/bindings.rs")
        .expect("Couldn't write bindings!");
}

fn ngx_configure() {
    println!("cargo:rustc-cfg=NGX_HAVE_OPENAT=\"1\"");
    println!("cargo:rustc-cfg=NGX_PTR_SIZE=\"8\"");
}

fn main() {
    configure();
    generate_binding();
    ngx_configure();
}
