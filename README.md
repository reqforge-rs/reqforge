# ReqForge

A config-based HTTP automation engine built with Tauri, React, and Rust.

---

## ⚠️ Disclaimer

**This tool is intended for authorized security testing and educational purposes only.**

By using this software, you agree that:

- You will only use this tool on systems you own or have explicit written permission to test
- You are solely responsible for your actions and any consequences that may arise
- Unauthorized access to computer systems is illegal and punishable by law
- The developers assume no liability for misuse of this software

**Violating computer crime laws can result in severe penalties including fines and imprisonment.** Laws such as the Computer Fraud and Abuse Act (CFAA), Computer Misuse Act, and similar legislation in other jurisdictions apply.

---

## ✨ Features

### 🎨 Visual Config Editor
- **Node-based workflow builder** - Drag and drop blocks to create complex HTTP automation flows
- **Real-time preview** - See your configuration structure as you build
- **Templates** - Save and reuse common configuration patterns
- **Import/Export** - Share configs as JSON files

### 🌐 HTTP Engine
- **Multiple HTTP clients:**
  - `reqwest` - Standard Rust HTTP client
  - `wreq` - TLS fingerprint-capable client with browser emulation
  - External TLS API support for advanced fingerprinting
- **Full HTTP support:**
  - All HTTP methods (GET, POST, PUT, DELETE, PATCH, etc.)
  - Custom headers with variable interpolation
  - Multiple body types: JSON, Form, Multipart, Raw
  - Cookie handling with persistent jar
  - Automatic redirect following (configurable)
  - HTTP/2 support
  - Compression: gzip, brotli, deflate, zstd

### 🔐 TLS Fingerprint Emulation
Bypass TLS fingerprinting with browser emulation profiles:
- **Chrome** - v100 to v137
- **Firefox** - v109, v117, v128, v133-139, Private mode, Android
- **Safari** - v15.3 to v18.2, iOS variants, iPad
- **Edge** - v101, v122, v127, v131, v134
- **Opera** - v116 to v119
- **OkHttp** - v3.9 to v5

### 📊 Job Management
- **Parallel execution** - Run multiple bots concurrently
- **Real-time statistics:**
  - Checks Per Minute (CPM)
  - Hits, Fails, Custom, Invalid, Banned, ToCheck counts
  - Active bot count
  - Progress tracking
- **Progress persistence** - Resume interrupted jobs
- **Auto-save results** - Automatically save hits to files
- **Configurable retry logic** - Retry on timeout with max attempts

### 🔄 Proxy Support
- **Multiple formats:** `host:port`, `host:port:user:pass`, `user:pass@host:port`
- **Protocol support:** HTTP, HTTPS, SOCKS4, SOCKS5
- **Proxy rotation** - Automatic rotation through proxy list
- **Shuffle mode** - Randomize proxy order
- **Concurrent proxy mode** - Multiple bots per proxy
- **Ban detection** - Auto-cycle proxies on ban
- **Cooldown system** - Per-proxy cooldown timers
- **Never ban mode** - Keep using proxies regardless of bans

### 📝 Combo Management
- **Large file support** - Streaming processing for files >10MB
- **Transform operations:**
  - Password length filter (min/max)
  - Domain switcher (change email domains)
  - Special character injection
  - Uppercase first letter
  - Remove duplicates
  - Filter letters-only passwords
  - Filter numbers-only passwords
- **Preview mode** - View first N lines before processing
- **Multiple delimiters** - Supports `:`, `;`, `|`, `,`

### 🔧 Workflow Blocks

#### Request Blocks
| Block | Description |
|-------|-------------|
| `Request` | Standard HTTP request with reqwest |
| `TlsRequest` | TLS fingerprinted request via external API |
| `TlsWreq` | TLS fingerprinted request via wreq library |

#### Parsing Blocks
| Block | Description |
|-------|-------------|
| `Parse` | Extract data using Regex, JSON path, CSS selectors, or between delimiters |
| `KeyCheck` | Conditional logic based on response content (Contains, NotContains, Equal, NotEqual) |

#### String Operations
| Block | Description |
|-------|-------------|
| `ConstantString` | Set a static string variable |
| `ConstantList` | Define a list of values |
| `RandomString` | Generate random alphanumeric string |
| `GetRandomItem` | Pick random item from a list |
| `Replace` | Find and replace in strings |
| `ZipLists` | Combine multiple lists |

#### Encoding Blocks
| Block | Description |
|-------|-------------|
| `Base64Encode` / `Base64Decode` | Base64 encoding/decoding |
| `UrlEncode` / `UrlDecode` | URL encoding/decoding |
| `EncodeHtmlEntities` / `DecodeHtmlEntities` | HTML entity encoding |
| `BytesToBase64` / `Base64ToBytes` | Binary data conversion |

#### Cryptography Blocks
| Block | Description |
|-------|-------------|
| `Hash` | MD4, MD5, SHA1, SHA256, SHA384, SHA512 |
| `HmacSign` | HMAC signing with various algorithms |
| `AesEncrypt` / `AesDecrypt` | AES-128/256-CBC encryption |
| `Pbkdf2Derive` | PBKDF2 key derivation |
| `RsaEncrypt` | RSA public key encryption |

#### OAuth / Auth Helpers
| Block | Description |
|-------|-------------|
| `GenerateCodeVerifier` | PKCE code verifier |
| `GenerateCodeChallenge` | PKCE code challenge (S256) |
| `GenerateState` | OAuth state parameter |
| `GenerateNonce` | Random nonce generation |

#### Utility Blocks
| Block | Description |
|-------|-------------|
| `GenerateUUID4` | UUID v4 generation |
| `GenerateGuid` | GUID generation (uppercase UUID) |
| `RandomInteger` | Random number in range |
| `RandomUserAgent` | Random UA from platform-filtered list |
| `CurrentUnixTime` | Current timestamp |
| `DateToUnixTime` / `UnixTimeToDate` | Date conversion |
| `Delay` | Wait with optional jitter |
| `ClearCookies` | Reset cookie jar |

#### Flow Control
| Block | Description |
|-------|-------------|
| `JumpIF` | Conditional jump based on variable |
| `JumpLabel` | Target label for jumps |
| `Log` | Debug logging |


### 🖥️ User Agent Rotation
- Platform-specific filtering: Desktop, Mobile, Android, iPhone, iPad, Windows, Mac, Linux
- Weighted random selection
- Full browser fingerprint data (viewport, plugins, etc.)

### 🐛 Debug Mode
- Step-through execution
- Real-time log streaming
- Request/response inspection
- Variable state at each step
- Block-level execution tracking

---

## 🚀 Installation

### Prerequisites
- [Node.js](https://nodejs.org/) (v18+)
- [Rust](https://rustup.rs/) (latest stable)
- [Tauri Prerequisites](https://tauri.app/v1/guides/getting-started/prerequisites)

### Build from Source

```bash
# Clone the repository
git clone https://github.com/reqforge-rs/reqforge.git
cd reqforge

# Install dependencies
npm install

# Run in development mode
npm run tauri dev

# Build for production
npm run tauri build
```

---

## 📖 Usage

1. **Create a Configuration** - Use the visual editor to build your HTTP workflow
2. **Import Data** - Load your input data into the Combos manager
3. **Configure Proxies** - (Optional) Add proxy lists for request rotation
4. **Create a Job** - Set up a job with your config, combo, and settings
5. **Run** - Start the job and monitor results in real-time

---

## 📁 Directory Structure

```
reqforge/
├── Configs/        # Saved configurations
├── Combos/         # Input data files
├── Templates/      # Reusable block templates
├── Results/        # Output files (hits, customs, etc.)
└── proxies.json    # Proxy groups
```

---

## ⚖️ Legal Use Cases

- Penetration testing (with written authorization)
- Security research on your own systems
- API testing and automation
- Educational purposes and learning about HTTP protocols
- Bug bounty programs (within scope)
- Load testing your own infrastructure

---

## 🛠️ Tech Stack

- **Frontend:** React 19, TypeScript, Tailwind CSS, React Flow
- **Backend:** Rust, Tauri 2
- **HTTP:** reqwest, wreq
- **Scripting:** Rhai

---

## 📄 License

This project is provided as-is for educational purposes. Use responsibly and legally.

---

## 🤝 Contributing

Contributions are welcome. Please ensure any contributions align with the intended legitimate use cases of this tool.

---

**⚠️ Remember: Always obtain proper authorization before testing any system you do not own.**
