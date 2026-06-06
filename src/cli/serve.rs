//! Minimal HTTP API daemon (`batin serve`, `server` feature).
//!
//! Exposes a small dependency-free HTTP/1.1 service for integration with upload
//! pipelines:
//!
//! - `GET  /health` → `200 ok`
//! - `POST /scan`   → detect the request body, returns the [`FileType`] as JSON
//!
//! The server is intentionally tiny (no web framework). It reads one request
//! per connection, bounds header and body sizes, and shuts down gracefully on
//! SIGINT/SIGTERM.

use super::signal::shutdown_signal;
use batin::{DetectionConfig, FileType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_BODY_BYTES: usize = 64 * 1024 * 1024;

/// Run the HTTP API daemon, bound to `addr` (e.g. `127.0.0.1:8080`).
pub async fn run_serve(addr: String) -> anyhow::Result<()> {
    let listener = TcpListener::bind(&addr).await?;
    let local = listener.local_addr()?;
    println!("batin serve listening on http://{local}");
    println!("  POST /scan   - detect a file in the request body");
    println!("  GET  /health - liveness check");
    println!("Press Ctrl+C to stop.");

    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _peer) = accepted?;
                tokio::spawn(async move {
                    let _ = handle_connection(stream).await;
                });
            }
            _ = &mut shutdown => {
                println!("\nShutdown signal received, stopping server...");
                break;
            }
        }
    }
    Ok(())
}

/// Parsed pieces of an HTTP request we care about.
struct Request {
    method: String,
    target: String,
    body: Vec<u8>,
}

async fn handle_connection(mut stream: TcpStream) -> std::io::Result<()> {
    let request = match read_request(&mut stream).await {
        Ok(Some(req)) => req,
        Ok(None) => return Ok(()),
        Err(status) => return write_response(&mut stream, status, "text/plain", status).await,
    };

    match (request.method.as_str(), request.target.as_str()) {
        ("GET", "/health") | ("GET", "/") => {
            write_response(&mut stream, "200 OK", "text/plain", "ok").await
        }
        ("POST", "/scan") => {
            let config = DetectionConfig::default();
            match FileType::from_bytes(&request.body, &config) {
                Ok(ft) => {
                    let json = serde_json::to_string(&ft)
                        .unwrap_or_else(|_| "{\"error\":\"serialization\"}".to_string());
                    write_response(&mut stream, "200 OK", "application/json", &json).await
                }
                Err(e) => {
                    let json = serde_json::json!({ "error": e.to_string() }).to_string();
                    write_response(&mut stream, "200 OK", "application/json", &json).await
                }
            }
        }
        _ => write_response(&mut stream, "404 Not Found", "text/plain", "not found").await,
    }
}

/// Read and parse a single HTTP request. Returns:
/// - `Ok(Some(req))` on success,
/// - `Ok(None)` if the client closed without sending anything,
/// - `Err(status)` with an HTTP status line for malformed/oversized requests.
async fn read_request(stream: &mut TcpStream) -> Result<Option<Request>, &'static str> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];

    // Read until we have the full header block (CRLFCRLF).
    let header_end = loop {
        let n = stream.read(&mut tmp).await.map_err(|_| "400 Bad Request")?;
        if n == 0 {
            if buf.is_empty() {
                return Ok(None);
            }
            return Err("400 Bad Request");
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
            break pos;
        }
        if buf.len() > MAX_HEADER_BYTES {
            return Err("431 Request Header Fields Too Large");
        }
    };

    let header_text = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let mut lines = header_text.split("\r\n");
    let request_line = lines.next().ok_or("400 Bad Request")?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().ok_or("400 Bad Request")?.to_string();
    let target = parts.next().ok_or("400 Bad Request")?.to_string();

    let mut content_length = 0usize;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("content-length") {
                content_length = value.trim().parse().map_err(|_| "400 Bad Request")?;
            }
        }
    }
    if content_length > MAX_BODY_BYTES {
        return Err("413 Payload Too Large");
    }

    // Body bytes already read past the header, plus whatever remains.
    let mut body = buf[header_end + 4..].to_vec();
    while body.len() < content_length {
        let n = stream.read(&mut tmp).await.map_err(|_| "400 Bad Request")?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
    }
    body.truncate(content_length);

    Ok(Some(Request {
        method,
        target,
        body,
    }))
}

async fn write_response(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    body: &str,
) -> std::io::Result<()> {
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}
