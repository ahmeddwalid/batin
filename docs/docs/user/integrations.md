---
title: Integrations
---

# Integrations

Beyond the CLI and Rust library, Batin can be embedded into other systems.

## HTTP API daemon

Build with the `server` feature and run a small HTTP service:

```bash
cargo build --release --features server
batin serve --addr 127.0.0.1:8080
```

Endpoints:

- `GET /health` → `200 ok`
- `POST /scan` → detect the request body, returns the result as JSON

```bash
curl --data-binary @suspicious.exe http://127.0.0.1:8080/scan
```

The server shuts down gracefully on `SIGINT`/`SIGTERM`.

## C / C++ (FFI)

The `batin-capi` crate builds a C-callable shared/static library:

```bash
cd capi && cargo build --release
```

```c
#include "batin.h"

char *json = batin_detect_json(data, len);
printf("%s\n", json);
batin_free_string(json);
```

See `capi/include/batin.h` for the full header.

## WebAssembly

The `batin-wasm` crate compiles the synchronous detection core to
`wasm32-unknown-unknown` for browser/edge use:

```bash
cd wasm && wasm-pack build --target web
```

```js
import init, { detect_json } from "./pkg/batin_wasm.js";
await init();
const result = JSON.parse(detect_json(new Uint8Array(bytes)));
```

## Online hash reputation

Build with the `online` feature to query VirusTotal for a file hash:

```bash
export VT_API_KEY=...
batin reputation <sha256>
```

This sends the hash (not the file) to a third party and is strictly opt-in.
For offline workflows, use `scan --hash-deny <denylist>` with a local list of
known-bad SHA-256 hashes instead.
