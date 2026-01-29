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

<img width="1920" height="1036" alt="Image" src="https://github.com/user-attachments/assets/c852c65b-fe5f-4225-a3de-32d1c31ab026" />

<img width="984" height="821" alt="Image" src="https://github.com/user-attachments/assets/7a872cfa-9950-426c-a88d-23fa77f9033e" />

<img width="922" height="407" alt="Image" src="https://github.com/user-attachments/assets/63e71333-12a9-47bf-ae8e-9b082eb8881b" />


# 🛠️ ReqForge

**ReqForge** is a high-performance, cross-platform HTTP automation engine designed for speed, flexibility, and massive scalability. Built with a **Rust** core and a modern **React/Tauri** frontend, it provides an industry-grade environment for crafting complex automation workflows.

---

## 🚀 Key Features

### 🎨 Dual-Mode Creative Suite
- **Blueprint Editor (UE5 Style):** A visual node graph powered by `@xyflow/react`. Features animated execution wires, glowing debug paths, and automatic layout management.
- **Comfort View:** A clean, card-based linear block list for rapid prototyping and straightforward logical flows.
- **Bi-Directional Sync:** Switch between views instantly without losing data or logic structure.

### ⚡ Professional Execution Engine
- **Industrial Multi-threading:** Rust-powered concurrency supporting thousands of concurrent "bots" with minimal overhead.
- **Advanced Proxy Management:** Proxy Groups, rotation, cooldowns, and automatic ban-loop evasion.
- **Memory Efficient:** Uses `mmap` for instant handling of multi-gigabyte combo lists.

---

## 📦 Complete Block Library

ReqForge includes **48 specialized blocks**. Below is the complete list with their descriptions as seen in the editor:

### ⚡ Core
- **HTTP Request:** Send HTTP/HTTPS requests with full control over headers, body, and authentication.
- **Advanced TLS:** HTTP with advanced TLS fingerprinting (Requires external bogdanfinn/tls-client-api forwarder).
- **Native TLS:** Native Rust TLS sending requests via the wreq library.

### 🧠 Logic
- **Parse Data:** Extract data using Regex, JSON path, or Left-Right parsing.
- **Key Check:** Validate responses and set result status (Success, Fail, Ban).
- // (NOT WORKING)  **Rhai Script:** Execute custom logic using the Rhai scripting engine with HTTP support. 

### 📦 Variables
- **Constant String:** Store a fixed string value in a variable.
- **Constant List:** Store a list of values for iteration.
- **Random String:** Generate random text using pattern masks.
- **Random Integer:** Generate a random number within range.
- **Random Pick:** Pick a random item from a list.

### 🔧 Data Ops
- **Base64 Encode:** Encode text to Base64 format.
- **Base64 Decode:** Decode Base64 back to text.
- **Bytes → Base64:** Convert hex bytes to Base64.
- **Base64 → Bytes:** Convert Base64 to hex bytes.
- **Hash:** Create hash (MD5, SHA1, SHA256, etc.).
- **Replace:** Find and replace text in strings.
- **To Lowercase:** Convert text to lowercase.
- **To Uppercase:** Convert text to uppercase.
- **Translate:** Translate text based on a dictionary.
- **URL Encode:** Percent-encode for URLs.
- **URL Decode:** Decode percent-encoded strings.
- **HTML Encode:** Encode special characters to HTML entities.
- **HTML Decode:** Decode HTML entities to characters.
- **Zip Lists:** Combine two lists element-wise.
- **HMAC Sign:** Sign messages using HMAC with configurable algorithm.
- **AES Encrypt:** Encrypt data using AES-CBC with PKCS7 padding.
- **AES Decrypt:** Decrypt AES-CBC encrypted data.
- **PBKDF2 Derive:** Derive cryptographic keys from passwords using PBKDF2-HMAC.
- **Rsa Encrypt:** Encrypt data using RSA public key (modulus + exponent).

### 🔀 Flow Control
- **Jump IF:** Conditional jump based on variable values.
- **Label:** Define a jump target destination.
- **Clear Cookies:** Reset all session cookies.
- **Delay:** Pause execution for a specified duration.

### 🛡️ Anti-Bot
- **ForgeRock Auth:** Auto-fill ForgeRock callbacks (Username/Password) from JSON response.
- **Checksum:** JSON checksum calculation with salt.

### ⚙️ System & Identity
- **Random User Agent:** Generate a random user agent from a list.
- **Unix Time:** Get current Unix timestamp.
- **Date → Unix:** Convert date string to timestamp.
- **Unix → Date:** Format timestamp as date string.
- **Unix → ISO8601:** Convert Unix timestamp to ISO8601 format.
- // (NOT WORKING) **Firefox UA:** Generate a specific Firefox browser profile user agent. // next update this gets removed
- **Generate GUID:** Create a globally unique identifier.
- **Generate UUID4:** Create a random UUID v4.
- **PKCE Verifier:** OAuth 2.0 PKCE code verifier.
- **PKCE Challenge:** OAuth 2.0 PKCE code challenge.
- **OAuth State:** Generate OAuth state parameter.
- **OAuth Nonce:** Generate OAuth nonce value.

---

## 🔍 Pro Debugger Suite
- **Variable Time-Travel:** Snapshot per log showing exact state of all variables.
- **Smart Filtering:** Exclusive views for Logic Flow, Requests, and Errors.
- **Visual Status:** Nodes color-code in real-time (Green/Red/Orange) based on execution.
- **Integrated Tools:** JSON Pretty-print, Side-by-Side Diff, and built-in Parse Tester.

---

## ⏺️ Proxy Recorder
A built-in MITM proxy for capturing and analyzing HTTP/HTTPS traffic in real-time.

- **HTTPS Interception:** Auto-generated CA certificate for secure traffic inspection.
- **Live Capture:** Real-time request/response logging with status, headers, and body.
- **Auto Decompression:** Transparent handling of gzip, brotli, zstd, and deflate responses.
- **Request Details:** Full visibility into method, URL, headers, and body content.
- **JSON Pretty-Print:** Automatic formatting of JSON request/response bodies.
- **CA Export:** Export the CA certificate for installation in browsers or system trust store.


## 🛠️ Tech Stack
- **Backend:** [Rust](https://www.rust-lang.org/)
- **Frontend:** [React 19](https://react.dev/), [TypeScript](https://www.typescriptlang.org/), [Tailwind CSS 4](https://tailwindcss.com/)
- **Desktop Framework:** [Tauri 2](https://tauri.app/)
- **Graph Engine:** [XYFlow (React Flow)](https://reactflow.dev/)
- **Scripting:** [Rhai](https://rhai.rs/)

---

## ⚠️ Disclaimer

**This tool is intended for authorized security testing and educational purposes only.**

By using this software, you agree that you will only use it on systems you own or have explicit written permission to test. The developers assume no liability for misuse of this software. Violating computer crime laws can result in severe penalties.

---


## 🚀 Getting Started

### Prerequisites
- [Rust](https://rustup.rs/)
- [Node.js](https://nodejs.org/) (v18+)

### Installation
```bash
# Clone the repository
git clone https://github.com/reqforge-rs/reqforge.git
cd reqforge

# Install dependencies
npm install

# Run development mode
npm run tauri dev

# Build production binary
npm run tauri build
```

---

## 📄 License
ReqForge is released under the [MIT License](LICENSE).

---

*Built for speed. Engineered for precision.*




**⚠️ Remember: Always obtain proper authorization before testing any system you do not own.**


**⚠️ Remember: Always obtain proper authorization before testing any system you do not own.**
