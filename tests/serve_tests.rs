//! Integration test for the `batin serve` HTTP daemon (`server` feature).
#![cfg(feature = "server")]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command};
use std::thread::sleep;
use std::time::Duration;

struct ServerGuard(Child);
impl Drop for ServerGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn http_request(port: u16, raw: &[u8]) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    stream.write_all(raw).unwrap();
    let mut resp = String::new();
    stream.read_to_string(&mut resp).unwrap();
    resp
}

fn wait_for_port(port: u16) {
    for _ in 0..50 {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        sleep(Duration::from_millis(100));
    }
    panic!("server did not start on port {port}");
}

#[test]
fn serve_health_and_scan() {
    let port = 18931u16;
    let child = Command::new(env!("CARGO_BIN_EXE_batin"))
        .args(["serve", "--addr", &format!("127.0.0.1:{port}")])
        .spawn()
        .expect("spawn server");
    let _guard = ServerGuard(child);
    wait_for_port(port);

    // Health check.
    let resp = http_request(
        port,
        b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert!(resp.contains("200 OK"));
    assert!(resp.trim_end().ends_with("ok"));

    // POST /scan with a PNG body.
    let png: &[u8] = &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0, 0, 0, 13];
    let mut req = format!(
        "POST /scan HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        png.len()
    )
    .into_bytes();
    req.extend_from_slice(png);
    let resp = http_request(port, &req);
    assert!(resp.contains("200 OK"));
    assert!(resp.contains("\"extension\":\"png\""));

    // Unknown route.
    let resp = http_request(
        port,
        b"GET /nope HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert!(resp.contains("404 Not Found"));
}
