---
title: Custom Signatures
---

# Custom Signatures

Batin ships with 60+ built-in signatures, but you can extend the database at
runtime with your own. This is useful for proprietary formats, emerging file
types, or organisation-specific markers.

## File format

Custom signatures are defined in a JSON file:

```json
{
  "signatures": [
    {
      "magic": "de ad c0 de",
      "offset": 0,
      "extensions": ["dcd"],
      "mime_type": "application/x-deadcode",
      "category": "executable"
    }
  ]
}
```

| Field        | Required | Description                                                            |
| ------------ | -------- | ---------------------------------------------------------------------- |
| `magic`      | yes      | Magic bytes as hex. Whitespace and a leading `0x` are ignored.         |
| `extensions` | yes      | One or more file extensions this signature maps to.                    |
| `mime_type`  | yes      | MIME type to report.                                                   |
| `offset`     | no       | Byte offset of the magic (default `0`).                                |
| `category`   | no       | `image`, `document`, `archive`, `executable`, `multimedia`, `text`, or `unknown` (default). |

## CLI usage

```bash
batin scan suspicious.bin --signatures my-signatures.json
```

Custom signatures are merged with the built-ins before scanning. Built-in
signatures take precedence when both match the same bytes.

## Library usage

```rust
use batin::{load_user_signatures, FileType, DetectionConfig};

load_user_signatures("my-signatures.json")?;
let ft = FileType::from_bytes(data, &DetectionConfig::default())?;
```

You can also build signatures programmatically via `SignatureDatabase::add_signature`.
