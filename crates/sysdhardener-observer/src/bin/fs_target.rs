//! Test target that performs specific filesystem operations:
//! read from /etc/hosts, and write to a temporary file.

use std::fs::File;
use std::io::{Read, Write};

fn main() {
    // Read access to /etc
    if let Ok(mut file) = File::open("/etc/hosts") {
        let mut buf = [0u8; 16];
        let _ = file.read(&mut buf);
    }

    // Write access to /tmp
    let tmp_path = format!("/tmp/sysdhardener-test-{}.tmp", std::process::id());
    if let Ok(mut file) = File::create(&tmp_path) {
        let _ = file.write_all(b"test data\n");
    }
    let _ = std::fs::remove_file(&tmp_path);
}
