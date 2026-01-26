# ReqForge

A config-based HTTP automation engine built with Tauri, React, and Rust.

https://t.me/ReqForgeRS

## Support the Project

If you find this project useful, consider supporting its development:

| Crypto | Address |
|--------|---------|
| **BTC** | `bc1qpnvfqudfsa2am779x6sz7rz7u64l8qwhkjhf3u` |
| **LTC** | `LfaoSM2Dx7WbFb2htdVx5rr4C3FgJLKvQV` |
| **ETH** | `0x56e660d7A1739bf2a52Ca300283479AC2eDB29B2` |

---

<img width="1920" height="1036" alt="Image" src="https://github.com/user-attachments/assets/25dc2b15-562d-47c6-bb6c-774876fd0a17" />
<img width="1920" height="1036" alt="Image" src="https://github.com/user-attachments/assets/5366ee28-3bca-4545-9050-0ca822d1e6ad" />
<img width="1920" height="1036" alt="Image" src="https://github.com/user-attachments/assets/c6f63c91-7340-49fe-97d9-53a9ffd78cea" />

<img width="1920" height="1036" alt="Image" src="https://github.com/user-attachments/assets/401d9833-f39f-404d-9d02-cd55378e9e13" />


## 🚀 The Ultimate HTTP Automation Suite

ReqForge is an enterprise-grade automation engine designed for speed, stealth, and professional-grade workflow creation. It combines a high-fidelity visual blueprint system with the raw performance of a multi-threaded Rust backend.

### 🧠 Revolutionary Visual Scripting (Blueprint)
*Unleash complex logic through visual clarity.*
- **UE5.6-Inspired Node Editor:** A professional-grade blueprint system featuring high-visibility, color-coded execution wires that turn glowing Amber/Orange and animate during execution.
- **Dynamic Node Indicators:** Real-time status coloring (Green: Success, Red: Error, Orange: Ban, Yellow: Retry) and execution order numbering (#1, #2...) for precise workflow tracking.
- **Smart Workspace Persistence:** Automatic layout saving and restoration, ensuring your node graph remains organized exactly as you left it.
- **Side-by-Side Properties:** A streamlined, collapsible properties panel that adapts to your screen size for an unobstructed workspace.

### 🛡️ Unstoppable HTTP & TLS Engine
*Defeat the most sophisticated bot protections.*
- **Fingerprint Weaver (Jitter):** Actively randomizes TLS profiles, cipher suites, and extension orders during execution to break pattern-based fingerprinting.
- **Precision Browser Emulation:** Latest fingerprints for Chrome (up to v137), Firefox (up to v139), Safari (iOS/macOS), Edge, Opera, and OkHttp.
- **Dual-Engine Architecture:** Use **TlsRequest** for maximum stealth via external Go-based fingerprinting or **TlsWreq** for native, high-performance Rust execution with granular control.
- **Binary Intelligence:** Support for `RAWSOURCE` and `BytesToBase64` allows for seamless processing of binary data, hex-encoded responses, and custom protocols.
- **Automated Networking:** Built-in `Sec-CH-Viewport` injection, automated redirect management, and comprehensive cookie jar handling.

### 🔍 Pro-Level Debugging Suite
*Fix logic errors in milliseconds, not hours.*
- **Variable Time-Travel:** Click any execution log to view the **exact snapshot** of all variables at that specific moment in time.
- **Side-by-Side Log Diff:** Instantly compare response bodies or headers from different requests to spot subtle changes in server behavior.
- **Real-Time Parse Tester:** Built-in utility to test Regex, JSONPath, and CSS Selectors against live data without pausing your workflow.
- **Smart Filtering:** Categorized console tabs (All, Errors) with intelligent noise reduction to focus on critical logic flow.
- **JSON Pretty-Print:** Automatic formatting and highlighting for complex API responses.

### ⚡ Enterprise Performance & Jobs
- **Rust Streaming Core:** Process multi-gigabyte combo files with zero lag using streaming memory-mapped I/O.
- **Massive Parallelism:** Scale to thousands of concurrent bots with optimized resource scheduling.
- **Advanced Proxy Suite:** Support for HTTP/S, SOCKS4/5 with intelligent rotation, ban detection, and per-proxy cooldown timers.
- **Evasion & Persistence:** Built-in ban-loop evasion, maximum retry limits, and job persistence that lets you resume large tasks instantly.

---

<img width="1920" height="1036" alt="Image" src="https://github.com/user-attachments/assets/25dc2b15-562d-47c6-bb6c-774876fd0a17" />
<img width="1920" height="1036" alt="Image" src="https://github.com/user-attachments/assets/5366ee28-3bca-4545-9050-0ca822d1e6ad" />
<img width="1920" height="1036" alt="Image" src="https://github.com/user-attachments/assets/c6f63c91-7340-49fe-97d9-53a9ffd78cea" />

---

## 🔧 Complete Block Library

ReqForge provides a massive library of over 48+ specialized blocks for building any automation workflow.

### 🌐 Networking & Requests
- **Request:** High-performance standard HTTP client.
- **TlsRequest:** Advanced TLS stealth client with Fingerprint Weaver (Jitter) support.
- **TlsWreq:** Native TLS client with manual redirect handling and multipart form support.
- **ClearCookies:** Reset the session state and cookie jar instantly.
- **Delay:** Precision wait times with variable jitter for human-like behavior.

### 🎯 Parsing & Logic
- **Parse:** Multi-match extraction using Regex, JSONPath, CSS Selectors, or Delimiters.
- **KeyCheck:** Conditional logic chains (**Keychains**) with support for `OR`/`AND` and status overrides (SUCCESS, FAIL, BAN, RETRY, CUSTOM).
- **JumpIF:** Flow control that jumps to labels based on variable conditions.
- **JumpLabel:** Named target markers for branching and looping.

### 🔐 Cryptography & Security
- **Hash:** MD4, MD5, SHA-1, SHA-256, SHA-384, SHA-512.
- **HmacSign:** Secure message signing with customizable output formats (Hex, Base64).
- **AesEncrypt / AesDecrypt:** AES-128/256-CBC encryption/decryption with Pkcs7 padding.
- **Pbkdf2Derive:** Robust key derivation with customizable iterations and salt formats.
- **RsaEncrypt:** Manual RSA public key encryption (modulus/exponent based).
- **Checksum:** Automated MD5 checksum generation for salted JSON payloads.

### 🔄 Data Transformation
- **Base64Encode / Base64Decode:** High-speed Base64 processing.
- **UrlEncode / UrlDecode:** URL-safe data encoding and decoding.
- **EncodeHtmlEntities / DecodeHtmlEntities:** Comprehensive HTML entity processing.
- **BytesToBase64 / Base64ToBytes:** Specialized hex/binary to Base64 conversion.
- **Replace:** Find and replace text within variables.
- **Translate:** Key-value mapping for data normalization.
- **ToLowercase / ToUppercase:** Text case transformations.
- **ZipLists:** Combine two separate lists into a single delimited stream.

### 🎲 Utility & Generation
- **RandomString / RandomInteger:** Generate unique data using customizable masks and ranges.
- **GenerateUUID4 / GenerateGuid:** Standard and uppercase unique identifier generation.
- **GenerateCodeVerifier / GenerateCodeChallenge:** Specialized OAuth PKCE helpers (S256).
- **GenerateState / GenerateNonce:** Security parameter generation for auth flows.
- **RandomUserAgent:** Platform-filtered (Windows, Linux, Mac, Android, iOS), weighted UA rotation.
- **CurrentUnixTime:** High-precision UNIX timestamps.
- **UnixTimeToDate / DateToUnixTime / UnixTimeToIso8601:** Versatile date and time format conversions.
- **ForgeRockAuth:** Specialized block for automating ForgeRock PoW (Proof of Work) and auth payloads.

---

## 📝 Configuration & Usage

### Job Settings
- **Bot Count:** Number of concurrent threads.
- **Proxy Mode:** Enable/disable proxy usage globally.
- **Shuffle/Concurrent:** Randomize proxy order and allow multiple bots per proxy.
- **Ban-Loop Evasion:** Automatically detect and stop infinite ban cycles.
- **Retry Logic:** Intelligent retries on timeout with configurable max attempts.
- **Custom Save Targets:** Choose exactly which statuses (Success, Custom, etc.) are saved to disk.

### Combo Transformations
- **Streaming Deduplication:** Remove duplicates from massive files without memory overhead.
- **Domain Switcher:** Mass-replace email domains in your input data.
- **Character Injection:** Automate password modification (uppercase first, append special chars).
- **Delimiter Detection:** Automatic support for `:`, `;`, `|`, and `,` delimiters.

---

## ⚠️ Disclaimer

**This tool is intended for authorized security testing and educational purposes only.**

By using this software, you agree that you will only use it on systems you own or have explicit written permission to test. The developers assume no liability for misuse of this software. Violating computer crime laws can result in severe penalties.

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

## 🛠️ Tech Stack

- **Frontend:** React 19, TypeScript, Tailwind CSS, @xyflow/react
- **Backend:** Rust (Tokio, reqwest, wreq, rhai, serde)
- **Engine:** Tauri 2.0 (Mobile Ready Core)
- **UI:** Custom dark-themed design with Material/UE5 aesthetic

---

**⚠️ Remember: Always obtain proper authorization before testing any system you do not own.**


**⚠️ Remember: Always obtain proper authorization before testing any system you do not own.**
