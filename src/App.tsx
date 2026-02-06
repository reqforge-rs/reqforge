import React, { useState, useEffect, useRef, useMemo, useCallback, Children } from "react";
import { invoke } from "@tauri-apps/api/core";
import { getCurrentWindow } from "@tauri-apps/api/window";
import "./App.css";
import {
  ReactFlow,
  Background,
  BackgroundVariant,
  useNodesState,
  useEdgesState,
  Edge,
  Node,
  MarkerType,
  Panel
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';

// DnD Kit Imports
import {
  DndContext, 
  closestCenter,
  KeyboardSensor,
  PointerSensor,
  useSensor,
  useSensors,
  DragEndEvent
} from '@dnd-kit/core';
import {
  arrayMove,
  SortableContext,
  sortableKeyboardCoordinates,
  verticalListSortingStrategy,
  useSortable
} from '@dnd-kit/sortable';
import { CSS } from '@dnd-kit/utilities';

// --- Types ---

type BlockType =
  | "Request" | "Parse" | "KeyCheck"
  | "RandomString" | "ConstantString" | "ConstantList" | "GetRandomItem"
  | "CurrentUnixTime" | "DateToUnixTime" | "UnixTimeToDate" | "UnixTimeToIso8601"
  | "Base64Encode" | "Base64Decode"
  | "GenerateCodeVerifier" | "GenerateCodeChallenge" | "GenerateState" | "GenerateNonce"
  | "GenerateGuid" | "GenerateUUID4" | "TlsRequest" | "TlsWreq" | "Hash" | "ClearCookies"
  | "JumpIF" | "JumpLabel" | "Script" | "Replace" | "UrlEncode" | "UrlDecode"
  | "ToLowercase" | "ToUppercase" | "Translate"
      | "RandomInteger" | "ZipLists" | "BytesToBase64" | "ForgeRockAuth"  | "HmacSign" | "AesEncrypt" | "AesDecrypt" | "Pbkdf2Derive" | "RsaEncrypt" | "Base64ToBytes"
  | "DecodeHtmlEntities" | "EncodeHtmlEntities" | "Delay" | "RandomUserAgent"
  | "Checksum";

interface MultipartField {
    name: string;
    data: string;
    is_file: boolean;
    content_type?: string;
}
type RequestBodyType = "raw" | "form_urlencoded" | "multipart";

interface Block {
  id: string;
  block_type: BlockType;
  data: any;
  request_body_type?: RequestBodyType;
  multipart_fields?: MultipartField[];
}

interface Config {
  id: string;
  name: string;
  blocks: Block[];
  blueprint?: any;
  lastModified: number;
}

interface RequestDetails {
  url: string;
  method: string;
  request_headers: Record<string, string>;
  request_body: string;
  response_status: number;
  response_url: string;
  response_headers: Record<string, string>;
  response_cookies: Record<string, string>;
  response_body: string;
}

interface ExecutionLog {
  step: string;
  message: string;
  status: string;
  details?: RequestDetails;
  block_id?: string;
  variables?: Record<string, string>;
  duration_ms: number;
}

interface DebugResult {
  logs: ExecutionLog[];
  variables: Record<string, string>;
}

interface Key {
  value: string;
  condition: "Contains" | "NotContains" | "Equal" | "NotEqual";
}

interface Keychain {
  result_status: "SUCCESS" | "FAIL" | "BAN" | "RETRY" | "NONE" | "CUSTOM";
  mode: "OR" | "AND";
  keys: Key[];
  source?: string;
}

interface JumpKey {
  value: string;
  condition: "Contains" | "NotContains" | "Equal" | "NotEqual" | "StartsWith" | "EndsWith" | "Matches";
}

interface JumpChain {
  source: string;
  mode: "OR" | "AND";
  keys: JumpKey[];
  target: string;
}

interface JobSettings {
    id: string;
    name: string;
    config: Config;
    config_id?: string;
    bot_count: number;
    proxy_mode: boolean;
    shuffle_proxies: boolean;
    concurrent_proxy_mode: boolean;
    never_ban_proxy: boolean;
    ban_loop_evasion: number;
    proxy_group: string;
    combo_path: string;
    proxies: string[];
    skip_lines: boolean;
    start_line: number;
    ban_save_interval: number;
    request_delay_ms: number;
    proxy_cooldown_ms: number;
    stop_on_proxy_exhaustion: boolean;
    max_banned_logs: number;
    save_hits: string[];
    deduplicate_combos: boolean;
    retry_on_timeout: boolean;
    max_retries: number;
    max_retries_as_ban: number;
}

interface JobStats {
    tested: number;
    hits: number;
    custom: number;
    fails: number;
    invalid: number;
    banned: number;
    to_check: number;
    errors: number;
    retries: number;
    active_bots: number;
    total_lines: number;
    cpm: number;
    last_line_index: number;
}

interface JobSummary {
    id: string;
    name: string;
    status: "Running" | "Idle";
    stats: JobStats;
    settings: JobSettings;
}

interface ProxyGroup {
    id: string;
    name: string;
    proxies: string[];
}

interface GlobalSettings {
    defaultBanSaveInterval: number;
    defaultBotCount: number;
    defaultBanLoopEvasion: number;
    defaultMaxRetriesAsBan: number;
    defaultMaxBannedLogs: number;
}

const getBlockName = (type: string) => {
    const names: Record<string, string> = {
        TlsRequest: "Advanced TLS",
        TlsWreq: "Native TLS",
        Request: "HTTP Request",
        KeyCheck: "Key Check",
        JumpIF: "Jump IF",
        JumpLabel: "Label",
        ClearCookies: "Clear Cookies",
        RandomString: "Random String",
        ConstantString: "Constant String",
        ConstantList: "Constant List",
        RandomInteger: "Random Integer",
        GetRandomItem: "Random Pick",
        CurrentUnixTime: "Unix Time",
        DateToUnixTime: "Date → Unix",
        UnixTimeToDate: "Unix → Date",
        UnixTimeToIso8601: "Unix → ISO8601",
        Base64Encode: "Base64 Encode",
        Base64Decode: "Base64 Decode",
        GenerateGuid: "Generate GUID",
        GenerateUUID4: "Generate UUID4",
        GenerateCodeVerifier: "PKCE Verifier",
        GenerateCodeChallenge: "PKCE Challenge",
        GenerateState: "OAuth State",
        GenerateNonce: "OAuth Nonce",
        RandomUserAgent: "Random UA",
        BytesToBase64: "Bytes → Base64",
        Base64ToBytes: "Base64 → Bytes",
        EncodeHtmlEntities: "HTML Encode",
        DecodeHtmlEntities: "HTML Decode",
        ZipLists: "Zip Lists",
        HmacSign: "HMAC Sign",
        AesEncrypt: "AES Encrypt",
        AesDecrypt: "AES Decrypt",
        Pbkdf2Derive: "PBKDF2 Derive",
        RsaEncrypt: "RSA Encrypt",
        ForgeRockAuth: "ForgeRock Auth",
        Checksum: "Checksum",
        Script: "Script",
        ToLowercase: "To Lowercase",
        ToUppercase: "To Uppercase",
        Translate: "Translate"
    };
    return names[type] || type;
};

// --- Main App ---

function BlockSelectorModal({ isOpen, onClose, onSelect }: { isOpen: boolean, onClose: () => void, onSelect: (type: string) => void }) {
    const [search, setSearch] = useState("");
    const [activeCategory, setActiveCategory] = useState<string | null>(null);
    const [favorites, setFavorites] = useState<Set<string>>(() => {
        const saved = localStorage.getItem("reqforge_favorites");
        return saved ? new Set(JSON.parse(saved)) : new Set(["Request", "TlsRequest", "TlsWreq", "Parse", "KeyCheck"]);
    });

    useEffect(() => {
        localStorage.setItem("reqforge_favorites", JSON.stringify(Array.from(favorites)));
    }, [favorites]);

    const toggleFavorite = (type: string, e: React.MouseEvent) => {
        e.stopPropagation();
        setFavorites(prev => {
            const next = new Set(prev);
            if (next.has(type)) next.delete(type);
            else next.add(type);
            return next;
        });
    };

    // Memoize categories to prevent re-creation
    const baseCategories = useMemo(() => [
        {
            name: "Core",
            color: "blue",
            gradient: "from-blue-600 to-indigo-700",
            icon: "⚡",
            blocks: [
                { type: "Request", label: "HTTP Request", icon: "🌐", desc: "Send HTTP/HTTPS requests with full control over headers, body, and authentication" },
                { type: "TlsRequest", label: "Advanced TLS", icon: "🔐", desc: "HTTP with advanced TLS fingerprinting (Requires external bogdanfinn/tls-client-api forwarder)" },
                { type: "TlsWreq", label: "Native TLS", icon: "🛡️", desc: "Native Rust TLS sending requests via the wreq library" },
            ]
        },
        {
            name: "Logic",
            color: "amber",
            gradient: "from-amber-500 to-orange-600",
            icon: "🧠",
            blocks: [
                { type: "Parse", label: "Parse Data", icon: "📝", desc: "Extract data using Regex, JSON path, or Left-Right parsing" },
                { type: "KeyCheck", label: "Key Check", icon: "🔑", desc: "Validate responses and set result status (Success, Fail, Ban)" },
            ]
        },
        {
            name: "Variables",
            color: "purple",
            gradient: "from-purple-500 to-violet-600",
            icon: "📦",
            blocks: [
                { type: "ConstantString", label: "Constant String", icon: "📌", desc: "Store a fixed string value in a variable" },
                { type: "ConstantList", label: "Constant List", icon: "📑", desc: "Store a list of values for iteration" },
                { type: "RandomString", label: "Random String", icon: "🎲", desc: "Generate random text using pattern masks" },
                { type: "RandomInteger", label: "Random Integer", icon: "🔢", desc: "Generate a random number within range" },
                { type: "GetRandomItem", label: "Random Pick", icon: "🎯", desc: "Pick a random item from a list" },
            ]
        },
        {
            name: "Data Ops",
            color: "emerald",
            gradient: "from-emerald-500 to-teal-600",
            icon: "🔧",
            blocks: [
                { type: "Base64Encode", label: "Base64 Encode", icon: "🔤", desc: "Encode text to Base64 format" },
                { type: "Base64Decode", label: "Base64 Decode", icon: "🔡", desc: "Decode Base64 back to text" },
                { type: "BytesToBase64", label: "Bytes → Base64", icon: "💾", desc: "Convert hex bytes to Base64" },
                { type: "Base64ToBytes", label: "Base64 → Bytes", icon: "📦", desc: "Convert Base64 to hex bytes" },
                { type: "Hash", label: "Hash", icon: "🔒", desc: "Create hash (MD5, SHA1, SHA256, etc.)" },
                { type: "Replace", label: "Replace", icon: "🔄", desc: "Find and replace text in strings" },
                { type: "ToLowercase", label: "To Lowercase", icon: "abcd", desc: "Convert text to lowercase" },
                { type: "ToUppercase", label: "To Uppercase", icon: "ABCD", desc: "Convert text to uppercase" },
                { type: "Translate", label: "Translate", icon: "🌐", desc: "Translate text based on a dictionary" },
                { type: "UrlEncode", label: "URL Encode", icon: "🔗", desc: "Percent-encode for URLs" },
                { type: "UrlDecode", label: "URL Decode", icon: "🔓", desc: "Decode percent-encoded strings" },
                { type: "EncodeHtmlEntities", label: "HTML Encode", icon: "📝", desc: "Encode special characters to HTML entities" },
                { type: "DecodeHtmlEntities", label: "HTML Decode", icon: "📄", desc: "Decode HTML entities to characters" },
                { type: "ZipLists", label: "Zip Lists", icon: "🤐", desc: "Combine two lists element-wise" },
                { type: "HmacSign", label: "HMAC Sign", icon: "🔏", desc: "Sign messages using HMAC with configurable algorithm" },
                { type: "AesEncrypt", label: "AES Encrypt", icon: "🔐", desc: "Encrypt data using AES-CBC with PKCS7 padding" },
                { type: "AesDecrypt", label: "AES Decrypt", icon: "🔓", desc: "Decrypt AES-CBC encrypted data" },
                { type: "Pbkdf2Derive", label: "PBKDF2 Derive", icon: "🔑", desc: "Derive cryptographic keys from passwords using PBKDF2-HMAC" },
                { type: "RsaEncrypt", label: "RSA Encrypt", icon: "🔒", desc: "Encrypt data using RSA public key (modulus + exponent)" },
            ]
        },
        {
            name: "Flow Control",
            color: "orange",
            gradient: "from-orange-500 to-amber-600",
            icon: "🔀",
            blocks: [
                { type: "JumpIF", label: "Jump IF", icon: "↪️", desc: "Conditional jump based on variable values" },
                { type: "JumpLabel", label: "Label", icon: "🏷️", desc: "Define a jump target destination" },
                { type: "ClearCookies", label: "Clear Cookies", icon: "🍪", desc: "Reset all session cookies" },
                { type: "Delay", label: "Delay", icon: "⏳", desc: "Pause execution for a specified duration" },
            ]
        },
        {
            name: "Anti-Bot",
            color: "red",
            gradient: "from-red-500 to-rose-600",
            icon: "🛡️",
            blocks: [
            
                { type: "ForgeRockAuth", label: "ForgeRock Auth", icon: "🏦", desc: "Auto-fill ForgeRock callbacks (Username/Password) from JSON response" },
                { type: "Checksum", label: "Checksum", icon: "🎰", desc: "JSON checksum calculation with salt" },
            ]
        },
        {
            name: "System",
            color: "emerald",
            gradient: "from-slate-700 to-slate-800",
            icon: "⚙️",
            blocks: [
                { type: "RandomUserAgent", label: "Random User Agent", icon: "🕵️", desc: "Generate a random user agent from a list" },
                { type: "CurrentUnixTime", label: "Unix Time", icon: "⏱️", desc: "Get current Unix timestamp" },
                { type: "DateToUnixTime", label: "Date → Unix", icon: "📅", desc: "Convert date string to timestamp" },
                { type: "UnixTimeToDate", label: "Unix → Date", icon: "📆", desc: "Format timestamp as date string" },
                { type: "UnixTimeToIso8601", label: "Unix → ISO8601", icon: "🕐", desc: "Convert Unix timestamp to ISO8601 format" },
                { type: "GenerateGuid", label: "Generate GUID", icon: "🆔", desc: "Create a globally unique identifier" },
                { type: "GenerateUUID4", label: "Generate UUID4", icon: "🔢", desc: "Create a random UUID v4" },

                { type: "GenerateCodeVerifier", label: "PKCE Verifier", icon: "✅", desc: "OAuth 2.0 PKCE code verifier" },
                { type: "GenerateCodeChallenge", label: "PKCE Challenge", icon: "🎯", desc: "OAuth 2.0 PKCE code challenge" },
                { type: "GenerateState", label: "OAuth State", icon: "🔀", desc: "Generate OAuth state parameter" },
                { type: "GenerateNonce", label: "OAuth Nonce", icon: "🎲", desc: "Generate OAuth nonce value" },
            ]
        },
    ], []);

    const allBlocks = useMemo(() => baseCategories.flatMap(c => c.blocks), [baseCategories]);

    const categories = useMemo(() => {
        const favBlocks = allBlocks.filter(b => favorites.has(b.type));
        const favCategory = {
            name: "Favorites",
            color: "pink",
            gradient: "from-pink-500 to-rose-500",
            icon: "⭐",
            blocks: favBlocks
        };
        // Ensure Favorites category is always at the top
        return [favCategory, ...baseCategories];
    }, [baseCategories, favorites, allBlocks]);

    const filteredCategories = useMemo(() => {
        const s = search.toLowerCase();
        // Filter blocks within each base category (excluding the dynamic Favorites category)
        const filteredBaseCategories = baseCategories.map(cat => ({
            ...cat,
            blocks: cat.blocks.filter(b =>
                !s || b.label.toLowerCase().includes(s) || b.type.toLowerCase().includes(s) || b.desc.toLowerCase().includes(s)
            )
        })).filter(cat => cat.blocks.length > 0);

        // Always show the Favorites category with its selected blocks, unless searching within specific categories
        const favCat = categories.find(c => c.name === "Favorites");
        const favBlocksFiltered = favCat ? { ...favCat, blocks: favCat.blocks.filter(b => 
            !s || b.label.toLowerCase().includes(s) || b.type.toLowerCase().includes(s) || b.desc.toLowerCase().includes(s)
        )} : null;

        let finalCategories = filteredBaseCategories;
        if (favBlocksFiltered && favBlocksFiltered.blocks.length > 0) {
            finalCategories = [favBlocksFiltered, ...filteredBaseCategories];
        }

        return finalCategories;
    }, [search, categories, baseCategories]);

    const displayCategories = useMemo(() => {
        if (activeCategory === "Favorites" && !search) {
            return filteredCategories.filter(cat => cat.name === "Favorites");
        }
        if (activeCategory && !search) {
            return filteredCategories.filter(cat => cat.name === activeCategory);
        }
        // When no specific category is active or searching, exclude "Favorites" from the main display
        return filteredCategories.filter(cat => cat.name !== "Favorites");
    }, [activeCategory, search, filteredCategories]);

    const totalBlocks = useMemo(() => baseCategories.reduce((acc, c) => acc + c.blocks.length, 0), [baseCategories]);

    if (!isOpen) return null;

    return (
        <div className="fixed inset-0 z-[100] flex items-center justify-center p-4 transition-all duration-300" onClick={onClose}>
            <div className="absolute inset-0 bg-black/70 backdrop-blur-md animate-in fade-in duration-200"></div>
            <div
                className="relative w-[1000px] max-h-[80vh] bg-[#0a0a0c] border border-white/[0.03] rounded-2xl shadow-2xl shadow-black overflow-hidden flex transform-gpu transition-all duration-300 animate-in zoom-in-95 fade-in"
                onClick={e => e.stopPropagation()}
            >
                {/* Sidebar */}
                <div className="w-56 bg-[#08080a] border-r border-white/[0.03] flex flex-col">
                    {/* Sidebar Header */}
                    <div className="p-4">
                        <div className="flex items-center gap-3 mb-4">
                            <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-slate-800 to-purple-600 flex items-center justify-center shadow-lg">
                                <span className="text-lg">🧩</span>
                            </div>
                            <div>
                                <h2 className="text-sm font-bold text-white">Add Block</h2>
                                <p className="text-[9px] text-slate-500 font-medium">{totalBlocks} modules</p>
                            </div>
                        </div>
                        {/* Search */}
                        <div className="relative">
                            <svg className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"></path>
                            </svg>
                            <input
                                autoFocus
                                className="w-full bg-white/5 border border-white/[0.03] rounded-lg py-2 pl-9 pr-3 text-xs text-white placeholder-slate-600 focus:outline-none focus:border-white/[0.05]/40 focus:bg-white/[0.07] transition-all"
                                placeholder="Search..."
                                value={search}
                                onChange={e => { setSearch(e.target.value); if (e.target.value) setActiveCategory(null); }}
                            />
                        </div>
                    </div>

                    {/* Category List */}
                    <div className="flex-1 overflow-y-auto py-2 custom-scrollbar">
                        <button
                            onClick={() => setActiveCategory(null)}
                            className={`w-full flex items-center gap-3 px-4 py-2.5 text-left transition-all ${
                                !activeCategory ? 'bg-white/5 text-white' : 'text-slate-400 hover:text-white hover:bg-white/[0.02]'
                            }`}
                        >
                            <span className="text-sm">✨</span>
                            <span className="text-xs font-semibold">All Blocks</span>
                            <span className="ml-auto text-[10px] text-slate-600 font-mono">{totalBlocks}</span>
                        </button>
                        <div className="h-px bg-white/5 my-2 mx-4"></div>
                        {categories.map((cat) => {
                            const matchCount = filteredCategories.find(fc => fc.name === cat.name)?.blocks.length || 0;
                            if (matchCount === 0 && search) return null;
                            return (
                                <button
                                    key={cat.name}
                                    onClick={() => { setActiveCategory(cat.name); setSearch(""); }}
                                    className={`w-full flex items-center gap-3 px-4 py-2.5 text-left transition-all group ${
                                        activeCategory === cat.name
                                            ? `bg-gradient-to-r ${cat.gradient} bg-opacity-10 text-white`
                                            : 'text-slate-400 hover:text-white hover:bg-white/[0.02]'
                                    }`}
                                >
                                    <span className={`text-sm transition-transform group-hover:scale-110 ${activeCategory === cat.name ? 'scale-110' : ''}`}>{cat.icon}</span>
                                    <span className="text-xs font-semibold">{cat.name}</span>
                                    <span className={`ml-auto text-[10px] font-mono ${activeCategory === cat.name ? 'text-white/70' : 'text-slate-600'}`}>
                                        {matchCount}
                                    </span>
                                </button>
                            );
                        })}
                    </div>

                    {/* Sidebar Footer */}
                    <div className="p-3 ">
                        <div className="flex items-center justify-center gap-1.5 text-slate-600">
                            <kbd className="px-1.5 py-0.5 rounded bg-white/5 text-[9px] font-bold border border-white/[0.03]">ESC</kbd>
                            <span className="text-[9px] font-medium">to close</span>
                        </div>
                    </div>
                </div>

                {/* Main Content */}
                <div className="flex-1 flex flex-col min-w-0">
                    {/* Content Header */}
                    <div className="px-6 py-4  bg-white/[0.01] flex items-center justify-between">
                        <div>
                            <h3 className="text-sm font-bold text-white">
                                {activeCategory || (search ? `Search: "${search}"` : 'All Blocks')}
                            </h3>
                            <p className="text-[10px] text-slate-500 mt-0.5">
                                {displayCategories.reduce((acc, c) => acc + c.blocks.length, 0)} blocks available
                            </p>
                        </div>
                        <button
                            onClick={onClose}
                            className="w-8 h-8 flex items-center justify-center bg-white/5 hover:bg-red-500/20 hover:text-red-400 rounded-lg text-slate-500 transition-all"
                        >
                            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12"></path>
                            </svg>
                        </button>
                    </div>

                    {/* Blocks Grid */}
                    <div className="flex-1 overflow-y-auto p-6 custom-scrollbar">
                        {displayCategories.length > 0 ? (
                            <div className="space-y-6">
                                {displayCategories.map((cat) => (
                                    <div key={cat.name}>
                                        {!activeCategory && (
                                            <div className="flex items-center gap-3 mb-3">
                                                <div className={`w-1 h-5 rounded-full bg-gradient-to-b ${cat.gradient}`}></div>
                                                <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">{cat.name}</span>
                                                <div className="h-px flex-1 bg-gradient-to-r from-white/5 to-transparent"></div>
                                            </div>
                                        )}
                                        <div className="grid grid-cols-2 gap-3">
                                            {cat.blocks.map(block => (
                                                <button
                                                    key={block.type}
                                                    onClick={() => { onSelect(block.type); onClose(); }}
                                                    className="relative flex items-start gap-4 p-4 rounded-xl bg-white/[0.02] border border-white/[0.03] hover:bg-white/[0.05] hover:border-white/[0.03] transition-all text-left group overflow-hidden active:scale-[0.98]"
                                                >
                                                    <div className={`absolute inset-0 bg-gradient-to-br ${cat.gradient} opacity-0 group-hover:opacity-[0.03] transition-opacity`}></div>

                                                    <div className={`flex-shrink-0 w-10 h-10 rounded-lg bg-gradient-to-br ${cat.gradient} bg-opacity-20 border border-white/[0.03] flex items-center justify-center text-lg shadow-lg transition-transform group-hover:scale-105`}>
                                                        {block.icon}
                                                    </div>

                                                    <div className="flex-1 min-w-0 relative z-10">
                                                        <div className="flex items-center gap-2 mb-1">
                                                            <span className="font-semibold text-white text-sm group-hover:text-emerald-400 transition-colors truncate">{block.label}</span>
                                                        </div>
                                                        <p className="text-[10px] text-slate-500 leading-relaxed group-hover:text-slate-400 transition-colors line-clamp-2">{block.desc}</p>
                                                    </div>

                                                    <div 
                                                        className="absolute top-2 right-2 p-1.5 rounded-full hover:bg-white/10 text-slate-600 hover:text-yellow-400 transition-all z-20"
                                                        onClick={(e) => toggleFavorite(block.type, e)}
                                                    >
                                                        {favorites.has(block.type) ? (
                                                            <svg className="w-3.5 h-3.5 text-yellow-400 fill-current" viewBox="0 0 24 24"><path d="M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z"></path></svg>
                                                        ) : (
                                                            <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M11.049 2.927c.3-.921 1.603-.921 1.902 0l1.519 4.674a1 1 0 00.95.69h4.915c.969 0 1.371 1.24.588 1.81l-3.976 2.888a1 1 0 00-.363 1.118l1.518 4.674c.3.922-.755 1.688-1.538 1.118l-3.976-2.888a1 1 0 00-1.176 0l-3.976 2.888c-.783.57-1.838-.197-1.538-1.118l1.518-4.674a1 1 0 00-.363-1.118l-3.976-2.888c-.784-.57-.38-1.81.588-1.81h4.914a1 1 0 00.951-.69l1.519-4.674z"></path></svg>
                                                        )}
                                                    </div>


                                                </button>
                                            ))}
                                        </div>
                                    </div>
                                ))}
                            </div>
                        ) : (
                            <div className="flex flex-col items-center justify-center h-full py-16">
                                <div className="w-16 h-16 rounded-2xl bg-white/5 border border-white/[0.03] flex items-center justify-center mb-4">
                                    <span className="text-3xl grayscale opacity-40">🔍</span>
                                </div>
                                <h3 className="text-slate-400 font-semibold text-sm mb-1">No blocks found</h3>
                                <p className="text-slate-600 text-xs text-center max-w-xs">
                                    Try a different search term or browse categories
                                </p>
                            </div>
                        )}
                    </div>
                </div>
            </div>
        </div>
    );
}

function App() {
  const [activeTab, setActiveTab] = useState<"jobs" | "configs" | "data" | "editor" | "settings" | "regex" | "recorder">("configs");
  const [configs, setConfigs] = useState<Config[]>([]);
  const [proxyGroups, setProxyGroups] = useState<ProxyGroup[]>([]);
  const [globalSettings, setGlobalSettings] = useState<GlobalSettings>(() => {
    const saved = localStorage.getItem("reqforge_global_settings");
    return saved ? JSON.parse(saved) : {
        defaultBanSaveInterval: 100,
        defaultBotCount: 50,
        defaultBanLoopEvasion: 100,
        defaultMaxRetriesAsBan: 3,
        defaultMaxBannedLogs: 50,
    };
  });
  
  // Lifted Config Manager State
  const [configView, setConfigView] = useState<"list" | "editor">("list");
  const [activeConfigId, setActiveConfigId] = useState<string | null>(null);
  const [configLogs, setConfigLogs] = useState<Record<string, ExecutionLog[]>>({});

  const refreshConfigs = async () => {
    try {
      const loaded = await invoke<Config[]>("load_configs");
      setConfigs(loaded);
    } catch (e) {
      console.error("Failed to load configs from backend", e);
    }
  };

  const refreshProxies = async () => {
    try {
      const loaded = await invoke<ProxyGroup[]>("load_proxies");
      setProxyGroups(loaded);
    } catch (e) {
      console.error("Failed to load proxies from backend", e);
    }
  };

  useEffect(() => {
    refreshConfigs();
    refreshProxies();
  }, []);


  useEffect(() => { localStorage.setItem("reqforge_global_settings", JSON.stringify(globalSettings)); }, [globalSettings]);

  // Global listener for debug logs - stores logs per config
  useEffect(() => {
    let active = true;
    let unlisten: (() => void) | null = null;

    const setup = async () => {
        const { listen } = await import("@tauri-apps/api/event");
        const stop = await listen<ExecutionLog>("debug-log", (event) => {
            if (active && activeConfigId) {
                setConfigLogs(prev => ({
                    ...prev,
                    [activeConfigId]: [...(prev[activeConfigId] || []), event.payload]
                }));
            }
        });

        if (!active) {
            stop();
        } else {
            unlisten = stop;
        }
    };

    setup();

    return () => {
        active = false;
        if (unlisten) unlisten();
    };
  }, [activeConfigId]);

  return (
    <div className="h-screen w-screen bg-[#0a0a0c] text-white font-sans flex flex-col overflow-hidden">

        {/* Top Navigation Bar */}
        <div data-tauri-drag-region className="w-full h-14 bg-[#0a0a0c]/95 backdrop-blur-xl border-b border-white/[0.05] flex items-center justify-between px-4 shrink-0 z-50">
            <div className="flex items-center gap-3">
                <div className="relative group cursor-default">
                    <div className="absolute -inset-1 bg-gradient-to-r from-slate-800 to-purple-600 rounded-lg blur opacity-25 group-hover:opacity-50 transition duration-1000 group-hover:duration-200"></div>
                    <div className="relative w-9 h-9 rounded-lg bg-[#0a0a0c] ring-1 ring-white/[0.05] flex items-center justify-center shadow-2xl">
                        <span className="text-transparent bg-clip-text bg-gradient-to-br from-emerald-400 to-pink-500 font-black text-xl">R</span>
                    </div>
                </div>
                <div className="flex flex-col">
                    <span className="font-bold text-white text-sm leading-none tracking-tight">ReqForge</span>
                </div>
            </div>
            
            <div className="flex items-center gap-1 bg-[#0a0a0c]/40 p-1.5 rounded-2xl border border-white/[0.03] backdrop-blur-md shadow-xl shadow-black/20">
                <NavBtn label="Jobs" active={activeTab === "jobs"} onClick={() => setActiveTab("jobs")} icon="⚡" />
                <NavBtn label="Configs" active={activeTab === "configs"} onClick={() => setActiveTab("configs")} icon="🛠️" />
                <NavBtn label="Data" active={activeTab === "data"} onClick={() => setActiveTab("data")} icon="📦" />
                <NavBtn label="Editor" active={activeTab === "editor"} onClick={() => setActiveTab("editor")} icon="✏️" />
                <NavBtn label="Recorder" active={activeTab === "recorder"} onClick={() => setActiveTab("recorder")} icon="⏺️" />
                <NavBtn label="Settings" active={activeTab === "settings"} onClick={() => setActiveTab("settings")} icon="⚙️" />
                <NavBtn label="Regex" active={activeTab === "regex"} onClick={() => setActiveTab("regex")} icon="🧠" />
            </div>

            <div className="flex items-center gap-3">
                 <div className="flex items-center gap-2 opacity-50 hover:opacity-100 transition-opacity cursor-default">
                    <div className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></div>
                    <span className="text-[10px] font-mono text-slate-400">v1.0.0</span>
                 </div>
                 <div className="h-6 w-px bg-white/[0.02]"></div>
                 <div className="flex items-center gap-1">
                    <button onClick={() => getCurrentWindow().minimize()} className="w-7 h-7 rounded-md hover:bg-white/[0.02] flex items-center justify-center text-slate-500 hover:text-slate-300 transition-colors">
                        <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M20 12H4" /></svg>
                    </button>
                    <button onClick={() => getCurrentWindow().toggleMaximize()} className="w-7 h-7 rounded-md hover:bg-white/[0.02] flex items-center justify-center text-slate-500 hover:text-slate-300 transition-colors">
                        <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 8V4h16v16h-4M4 8h12v12H4V8z" /></svg>
                    </button>
                    <button onClick={() => getCurrentWindow().close()} className="w-7 h-7 rounded-md hover:bg-red-600/80 flex items-center justify-center text-slate-500 hover:text-white transition-colors">
                        <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
                    </button>
                 </div>
            </div>
        </div>

        <div className="flex-1 overflow-hidden relative">
            <div className={`h-full ${activeTab === "jobs" ? "" : "hidden"}`}>
                <JobsTab 
                    configs={configs} 
                    proxyGroups={proxyGroups} 
                    globalSettings={globalSettings} 
                    onEditConfig={(id) => {
                        setActiveTab("configs");
                        setActiveConfigId(id);
                        setConfigView("editor");
                    }}
                />
            </div>
            <div className={`h-full ${activeTab === "configs" ? "" : "hidden"}`}>
                <ConfigManager
                    configs={configs}
                    setConfigs={setConfigs}
                    view={configView}
                    setView={setConfigView}
                    activeConfigId={activeConfigId}
                    setActiveConfigId={setActiveConfigId}
                    configLogs={configLogs}
                    setConfigLogs={setConfigLogs}
                    onRefresh={refreshConfigs}
                />
            </div>
            <div className={`h-full ${activeTab === "data" ? "" : "hidden"}`}>
                <DataTab groups={proxyGroups} setGroups={setProxyGroups} />
            </div>
            <div className={`h-full ${activeTab === "editor" ? "" : "hidden"}`}>
                <ComboEditorTab isActive={activeTab === "editor"} />
            </div>
            <div className={`h-full ${activeTab === "recorder" ? "" : "hidden"}`}>
                <ProxyRecorder />
            </div>
            <div className={`h-full ${activeTab === "regex" ? "" : "hidden"}`}>
                <RegexTab />
            </div>
            <div className={`h-full ${activeTab === "settings" ? "" : "hidden"}`}>
                <SettingsTab settings={globalSettings} setSettings={setGlobalSettings} />
            </div>
        </div>
    </div>
  );
}

function NavBtn({ label, active, onClick, icon }: { label: string, active: boolean, onClick: () => void, icon: string }) {
    return (
        <button 
            onClick={onClick}
            className={`relative flex items-center gap-2.5 px-6 py-2 rounded-xl text-[11px] font-black uppercase tracking-[0.1em] transition-all duration-500 group overflow-hidden ${
                active 
                ? "text-white shadow-[0_10px_20px_-10px_rgba(16,185,129,0.3)] bg-gradient-to-b from-white/[0.08] to-white/[0.02] ring-1 ring-white/10" 
                : "text-slate-500 hover:text-slate-200 hover:bg-white/[0.03] border border-transparent"
            }`}
        >
            {active && (
                <>
                    <div className="absolute inset-0 bg-gradient-to-br from-emerald-500/10 via-transparent to-purple-500/10 opacity-50"></div>
                    <div className="absolute bottom-0 left-1/2 -translate-x-1/2 w-8 h-[2px] bg-emerald-500 rounded-full blur-[1px]"></div>
                    <div className="absolute bottom-0 left-1/2 -translate-x-1/2 w-4 h-[4px] bg-emerald-400 rounded-full blur-[4px]"></div>
                </>
            )}
            
            <span className={`relative z-10 text-base transition-all duration-500 ${
                active 
                ? "scale-110 rotate-[5deg] drop-shadow-[0_0_10px_rgba(16,185,129,0.8)]" 
                : "grayscale opacity-40 group-hover:grayscale-0 group-hover:opacity-100 group-hover:scale-110"
            }`}>
                {icon}
            </span>
            <span className={`relative z-10 transition-all duration-500 ${active ? "translate-x-0.5" : "group-hover:translate-x-0.5"}`}>
                {label}
            </span>

            {/* Subtle hover glow for inactive tabs */}
            {!active && (
                <div className="absolute inset-0 opacity-0 group-hover:opacity-100 bg-gradient-to-r from-transparent via-white/[0.02] to-transparent transition-opacity duration-700"></div>
            )}
        </button>
    )
}

// --- Jobs Tab ---

function JobsTab({ configs, proxyGroups, globalSettings, onEditConfig }: { configs: Config[], proxyGroups: ProxyGroup[], globalSettings: GlobalSettings, onEditConfig: (id: string) => void }) {
    const [view, setView] = useState<"list" | "create" | "details">("list");
    const [returnView, setReturnView] = useState<"list" | "details">("list");
    const [jobs, setJobs] = useState<JobSummary[]>([]);
    const [activeJobId, setActiveJobId] = useState<string | null>(null);
    const [refreshTrigger, setRefreshTrigger] = useState(0);
    const [isEditMode, setIsEditMode] = useState(false);
    const [search, setSearch] = useState("");
    const [history, setHistory] = useState<Record<string, { cpm: number[], success: number[] }>>({});

    // Table State
    const [selectedJobIds, setSelectedJobIds] = useState<Set<string>>(new Set());
    const [sortConfig, setSortConfig] = useState<{ key: keyof JobSummary | "stats.hits" | "stats.cpm" | "progress", direction: "asc" | "desc" } | null>(null);

    const filteredJobs = useMemo(() => {
        let result = jobs;
        if (search) {
            const lower = search.toLowerCase();
            result = result.filter(j => j.name.toLowerCase().includes(lower) || j.settings.config.name.toLowerCase().includes(lower));
        }
        
        if (sortConfig) {
            result = [...result].sort((a, b) => {
                let aValue: any = a[sortConfig.key as keyof JobSummary];
                let bValue: any = b[sortConfig.key as keyof JobSummary];

                if (sortConfig.key === "stats.hits") {
                    aValue = a.stats.hits + a.stats.custom;
                    bValue = b.stats.hits + b.stats.custom;
                } else if (sortConfig.key === "stats.cpm") {
                    aValue = a.stats.cpm || 0;
                    bValue = b.stats.cpm || 0;
                } else if (sortConfig.key === "progress") {
                     aValue = a.stats.total_lines > 0 ? (a.stats.tested / a.stats.total_lines) : 0;
                     bValue = b.stats.total_lines > 0 ? (b.stats.tested / b.stats.total_lines) : 0;
                }

                if (aValue < bValue) return sortConfig.direction === "asc" ? -1 : 1;
                if (aValue > bValue) return sortConfig.direction === "asc" ? 1 : -1;
                return 0;
            });
        }
        return result;
    }, [jobs, search, sortConfig]);

    const totalHits = useMemo(() => {
        return jobs.reduce((acc, j) => acc + j.stats.hits + j.stats.custom, 0);
    }, [jobs]);

    // Combo Library State
    const [combos, setCombos] = useState<{name: string, lines: number}[]>([]);
    const [useLibrary, setUseLibrary] = useState(true);

    // Form State
    const [jobId, setJobId] = useState("");
    const [newJobName, setNewJobName] = useState("New Job");
    const [selectedConfigId, setSelectedConfigId] = useState("");
    const [botCount, setBotCount] = useState(globalSettings.defaultBotCount);
    const [proxyMode, setProxyMode] = useState(true);
    const [selectedProxyGroupId, setSelectedProxyGroupId] = useState("");
    const [comboPath, setComboPath] = useState("");
    const [banLoopEvasion, setBanLoopEvasion] = useState(globalSettings.defaultBanLoopEvasion);
    const [shuffleProxies, setShuffleProxies] = useState(true);
    const [neverBanProxy, setNeverBanProxy] = useState(true);
    const [requestDelayMs, setRequestDelayMs] = useState(0);
    const [proxyCooldownMs, setProxyCooldownMs] = useState(0);
    const [stopOnProxyExhaustion, setStopOnProxyExhaustion] = useState(false);
    const [deduplicateCombos, setDeduplicateCombos] = useState(true);
    const [retryOnTimeout, setRetryOnTimeout] = useState(false);
    const [maxRetries, setMaxRetries] = useState(3);
    const [maxRetriesAsBan, setMaxRetriesAsBan] = useState(3);
    const [skipLines, setSkipLines] = useState(false);
    const [startLine, setStartLine] = useState(0);
    const [banSaveInterval, setBanSaveInterval] = useState(globalSettings.defaultBanSaveInterval);
    const [maxBannedLogs, setMaxBannedLogs] = useState(globalSettings.defaultMaxBannedLogs || 50);
    const [saveHits, setSaveHits] = useState<string[]>(["SUCCESS", "CUSTOM", "TOCHECK"]);

    useEffect(() => {
        if (view === "create") {
            refreshCombos();
        }
    }, [view]);

    useEffect(() => {
        refreshJobs();
        refreshCombos();
        const interval = setInterval(refreshJobs, 1000);
        return () => clearInterval(interval);
    }, [refreshTrigger]);

    const refreshCombos = async () => {
        try {
            const list = await invoke<{name: string, lines: number}[]>("list_combos");
            setCombos(list);
        } catch (e) {
            console.error(e);
        }
    }

    const refreshJobs = async () => {
        try {
            const list = await invoke<JobSummary[]>("get_jobs_list");
            setJobs(list);
            
            // Update History
            setHistory(prev => {
                const next = { ...prev };
                for (const job of list) {
                    if (job.status === "Running") {
                        const h = next[job.id] || { cpm: [], success: [] };
                        next[job.id] = {
                            cpm: [...h.cpm, job.stats.cpm].slice(-120),
                            success: [...h.success, job.stats.hits + job.stats.custom].slice(-120)
                        };
                    }
                }
                return next;
            });
        } catch (e) {
            console.error(e);
        }
    };

    const resetForm = (nextName?: string) => {
        setJobId(Math.random().toString(36).substring(2, 12));
        setNewJobName(nextName || "New Job");
        setSelectedConfigId("");
        setBotCount(globalSettings.defaultBotCount);
        setProxyMode(true);
        setSelectedProxyGroupId("");
        setComboPath("");
        setBanLoopEvasion(globalSettings.defaultBanLoopEvasion);
        setShuffleProxies(true);
        setNeverBanProxy(true);
        setRequestDelayMs(0);
        setProxyCooldownMs(0);
        setStopOnProxyExhaustion(false);
        setDeduplicateCombos(true);
        setRetryOnTimeout(false);
        setMaxRetries(3);
        setMaxRetriesAsBan(globalSettings.defaultMaxRetriesAsBan || 3);
        setSkipLines(false);
        setStartLine(0);
        setBanSaveInterval(globalSettings.defaultBanSaveInterval);
        setMaxBannedLogs(globalSettings.defaultMaxBannedLogs || 50);
        setSaveHits(["SUCCESS", "CUSTOM", "TOCHECK"]);
        setIsEditMode(false);
    };

    const startCreate = () => {
        const nextNum = jobs.reduce((max, job) => {
            const m = job.name.match(/New Job #(\d+)/);
            return m ? Math.max(max, parseInt(m[1])) : max;
        }, 0) + 1;
        resetForm(`New Job #${nextNum}`);
        setReturnView("list");
        setView("create");
    };

    const loadIntoForm = (job: JobSummary, isClone: boolean, fromView: "list" | "details" = "list") => {
        setJobId(isClone ? Math.random().toString(36).substring(2, 12) : job.id);
        setNewJobName(isClone ? `${job.name} (Clone)` : job.name);
        setSelectedConfigId(job.settings.config_id || job.settings.config.id || "");
        setBotCount(job.settings.bot_count);
        setProxyMode(job.settings.proxy_mode);
        setSelectedProxyGroupId(job.settings.proxy_group);
        setComboPath(job.settings.combo_path);
        setBanLoopEvasion(job.settings.ban_loop_evasion);
        setShuffleProxies(job.settings.shuffle_proxies);
        setNeverBanProxy(job.settings.never_ban_proxy);
        setRequestDelayMs(job.settings.request_delay_ms || 0);
        setProxyCooldownMs(job.settings.proxy_cooldown_ms || 0);
        setStopOnProxyExhaustion(job.settings.stop_on_proxy_exhaustion ?? true);
        setDeduplicateCombos(job.settings.deduplicate_combos || false);
        setRetryOnTimeout(job.settings.retry_on_timeout || false);
        setMaxRetries(job.settings.max_retries || 3);
        setMaxRetriesAsBan(job.settings.max_retries_as_ban || 3);
        setSkipLines(job.settings.skip_lines || false);
        setStartLine(job.settings.start_line || 0);
        setBanSaveInterval(job.settings.ban_save_interval || 100);
        setMaxBannedLogs(job.settings.max_banned_logs || 50);
        setSaveHits(job.settings.save_hits || ["SUCCESS", "CUSTOM"]);
        setIsEditMode(!isClone);
        setReturnView(fromView);
        setView("create");
    }

    const handleCreateJob = async () => {
        if (!selectedConfigId) return alert("Select a config");
        const config = configs.find(c => c.id === selectedConfigId);
        if (!config) return alert("Config not found");

        const proxyGroup = proxyGroups.find(g => g.id === selectedProxyGroupId);
        const proxies = proxyGroup ? proxyGroup.proxies : [];

        const settings: JobSettings = {
            id: jobId,
            name: newJobName,
            config,
            config_id: config.id,
            bot_count: botCount,
            proxy_mode: proxyMode,
            shuffle_proxies: shuffleProxies,
            concurrent_proxy_mode: false,
            never_ban_proxy: neverBanProxy,
            ban_loop_evasion: banLoopEvasion,
            proxy_group: selectedProxyGroupId,
            combo_path: comboPath,
            proxies,
            skip_lines: skipLines,
            start_line: startLine,
            ban_save_interval: banSaveInterval,
            request_delay_ms: requestDelayMs,
            proxy_cooldown_ms: proxyCooldownMs,
            stop_on_proxy_exhaustion: stopOnProxyExhaustion,
            max_banned_logs: maxBannedLogs,
            save_hits: saveHits,
            deduplicate_combos: deduplicateCombos,
            retry_on_timeout: retryOnTimeout,
            max_retries: maxRetries,
            max_retries_as_ban: maxRetriesAsBan,
        };

        try {
            if (isEditMode) {
                await invoke("update_job", { settings });
            } else {
                await invoke("create_job", { settings });
            }
            setView("list");
            setRefreshTrigger(prev => prev + 1);
        } catch (e) {
            alert("Error: " + e);
        }
    };

    const handleDeleteJob = async (id: string, e?: React.MouseEvent) => {
        e?.stopPropagation();
        if(!confirm("Delete job?")) return;
        try {
            await invoke("delete_job", { jobId: id });
            setRefreshTrigger(prev => prev + 1);
            if (activeJobId === id) { setActiveJobId(null); setView("list"); }
        } catch(e) { alert(e); }
    };

    const toggleJobStatus = async (job: JobSummary, e?: React.MouseEvent) => {
        e?.stopPropagation();
        try {
            if (job.status === "Running") {
                await invoke("stop_job", { jobId: job.id });
            } else {
                await invoke("start_job", { jobId: job.id });
            }
        } catch (e) { alert(e); }
    };

    const openJob = (id: string) => {
        setActiveJobId(id);
        setView("details");
    };

    // --- Table Actions ---
    const toggleSelect = (id: string) => {
        const next = new Set(selectedJobIds);
        if (next.has(id)) next.delete(id);
        else next.add(id);
        setSelectedJobIds(next);
    };

    const toggleSelectAll = () => {
        if (selectedJobIds.size === filteredJobs.length) setSelectedJobIds(new Set());
        else setSelectedJobIds(new Set(filteredJobs.map(j => j.id)));
    };

    const handleSort = (key: any) => {
        setSortConfig(current => {
            if (current && current.key === key) {
                return { key, direction: current.direction === "asc" ? "desc" : "asc" };
            }
            return { key, direction: "desc" };
        });
    };

    const bulkAction = async (action: "start" | "stop" | "delete") => {
        if (!confirm(`${action.toUpperCase()} ${selectedJobIds.size} jobs?`)) return;
        
        for (const id of selectedJobIds) {
            try {
                if (action === "delete") await invoke("delete_job", { jobId: id });
                else if (action === "start") await invoke("start_job", { jobId: id });
                else if (action === "stop") await invoke("stop_job", { jobId: id });
            } catch (e) { console.error(e); }
        }
        setRefreshTrigger(prev => prev + 1);
        setSelectedJobIds(new Set());
    };

    // Job List View
    if (view === "list") {
        return (
            <div className="h-full flex flex-col bg-[#0a0a0c]">
                {/* Header */}
                <div className="relative z-30 px-8 pt-10 pb-6">
                    <div className="max-w-7xl mx-auto">
                        <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-6 mb-10">
                            <div>
                                <div className="flex items-center gap-4 mb-3">
                                    <div className="w-12 h-12 rounded-2xl bg-gradient-to-br from-emerald-500/20 to-slate-800/20 border border-emerald-500/30 flex items-center justify-center shadow-2xl shadow-black/10 backdrop-blur-md">
                                        <svg className="w-6 h-6 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"></path>
                                        </svg>
                                    </div>
                                    <div>
                                        <h1 className="text-3xl font-black text-white tracking-tight uppercase">Operations Center</h1>
                                        <p className="text-slate-500 text-xs font-bold uppercase tracking-[0.2em] mt-1">Job Execution & Monitoring</p>
                                    </div>
                                </div>
                            </div>

                            <button
                                onClick={startCreate}
                                className="h-12 bg-emerald-600 hover:bg-emerald-500 text-white px-6 rounded-2xl font-black text-[11px] uppercase tracking-[0.2em] shadow-2xl shadow-emerald-900/20 transition-all duration-500 hover:scale-[1.02] active:scale-95 flex items-center gap-3 border border-emerald-400/20"
                            >
                                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2.5" d="M12 4v16m8-8H4"></path>
                                </svg>
                                Deploy Job
                            </button>
                        </div>

                        {/* Search & Stats Bar */}
                        <div className="flex flex-col lg:flex-row lg:items-center gap-6">
                            <div className="flex-1 relative group">
                                <div className="absolute inset-0 bg-emerald-500/5 rounded-2xl blur-2xl opacity-0 group-focus-within:opacity-100 transition-opacity duration-500"></div>
                                <div className="relative flex items-center">
                                    <svg className="absolute left-5 w-5 h-5 text-slate-500 group-focus-within:text-emerald-500 transition-colors" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2.5" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"></path>
                                    </svg>
                                    <input
                                        type="text"
                                        placeholder="Search operations by name..."
                                        value={search}
                                        onChange={(e) => setSearch(e.target.value)}
                                        className="w-full bg-[#0a0a0c]/80 backdrop-blur-xl border border-white/[0.02] rounded-2xl py-4 pl-14 pr-4 text-sm text-white placeholder-slate-600 focus:outline-none focus:border-emerald-500/30 focus:bg-[#0a0a0c] transition-all duration-500 shadow-2xl shadow-black/40"
                                    />
                                </div>
                            </div>

                            <div className="flex items-center gap-8 px-6 py-4 bg-white/[0.01]/30 border border-white/[0.02] rounded-2xl backdrop-blur-md">
                                <div className="flex items-center gap-3">
                                    <div className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse shadow-[0_0_8px_rgba(16,185,129,0.8)]"></div>
                                    <div>
                                        <p className="text-[10px] font-black text-slate-500 uppercase tracking-widest leading-none">Active</p>
                                        <p className="text-sm font-black text-white mt-1">{jobs.filter(j => j.status === "Running").length} Running</p>
                                    </div>
                                </div>
                                <div className="h-8 w-px bg-white/[0.02]"></div>
                                <div className="flex items-center gap-3">
                                    <div className="w-2 h-2 rounded-full bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.8)]"></div>
                                    <div>
                                        <p className="text-[10px] font-black text-slate-500 uppercase tracking-widest leading-none">Total Hits</p>
                                        <p className="text-sm font-black text-emerald-400 mt-1 tabular-nums">{totalHits.toLocaleString()}</p>
                                    </div>
                                </div>
                                <div className="h-8 w-px bg-white/[0.02]"></div>
                                <div className="flex items-center gap-3">
                                    <div className="w-2 h-2 rounded-full bg-white/[0.05] shadow-[0_0_8px_rgba(59,130,246,0.8)]"></div>
                                    <div>
                                        <p className="text-[10px] font-black text-slate-500 uppercase tracking-widest leading-none">Global CPM</p>
                                        <p className="text-sm font-black text-emerald-400 mt-1 tabular-nums">{jobs.reduce((acc, j) => acc + (j.stats.cpm || 0), 0).toLocaleString()}</p>
                                    </div>
                                </div>
                            </div>
                        </div>

                        {/* Bulk Actions */}
                        {selectedJobIds.size > 0 && (
                            <div className="flex items-center gap-4 mt-6 px-6 py-4 bg-white/[0.01] border border-emerald-500/20 rounded-2xl">
                                <span className="text-[11px] font-black text-emerald-400 uppercase tracking-widest">{selectedJobIds.size} Selected</span>
                                <div className="h-6 w-px bg-emerald-500/20"></div>
                                <button onClick={() => bulkAction("start")} className="px-4 py-2 text-[11px] font-black text-emerald-400 hover:bg-emerald-500/10 rounded-xl transition-all uppercase tracking-wider">Start All</button>
                                <button onClick={() => bulkAction("stop")} className="px-4 py-2 text-[11px] font-black text-amber-400 hover:bg-amber-500/10 rounded-xl transition-all uppercase tracking-wider">Stop All</button>
                                <button onClick={() => bulkAction("delete")} className="px-4 py-2 text-[11px] font-black text-red-400 hover:bg-red-500/10 rounded-xl transition-all uppercase tracking-wider">Delete All</button>
                            </div>
                        )}
                    </div>
                </div>

                {/* Table Content */}
                <div className="flex-1 overflow-y-auto px-8 pb-12 custom-scrollbar relative z-10">
                    <div className="max-w-7xl mx-auto">
                        {filteredJobs.length === 0 ? (
                            <div className="flex flex-col items-center justify-center py-32 bg-[#0a0a0c]/20 border border-white/[0.02] rounded-[2.5rem] border-dashed transition-all duration-500">
                                <div className="w-24 h-24 rounded-[2rem] bg-gradient-to-br from-slate-800 to-slate-900 border border-slate-700 flex items-center justify-center mb-8 shadow-inner relative group">
                                    <div className="absolute inset-0 bg-emerald-500/5 blur-2xl rounded-full group-hover:bg-emerald-500/10 transition-colors"></div>
                                    <svg className="w-10 h-10 text-slate-600 relative z-10 group-hover:text-slate-400 transition-colors" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.5" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"></path>
                                    </svg>
                                </div>
                                <h3 className="text-slate-300 font-black text-lg uppercase tracking-[0.2em] mb-2">{search ? "No Results" : "No Operations"}</h3>
                                <p className="text-slate-600 text-[11px] font-bold uppercase tracking-widest max-w-xs text-center leading-relaxed">
                                    {search
                                        ? "No jobs match your search criteria. Try a different query."
                                        : "Deploy your first job to begin executing operations."}
                                </p>
                            </div>
                        ) : (
                            <div className="space-y-3">
                                {/* Header Row */}
                                <div className="px-8 py-4 flex items-center text-[10px] font-black text-slate-500 uppercase tracking-[0.2em] bg-white/[0.02] rounded-2xl border border-white/[0.03] mb-4">
                                    <div className="w-12 flex justify-center">
                                        <input
                                            type="checkbox"
                                            className="w-4 h-4 rounded border-slate-600 bg-white/[0.02] text-emerald-500 focus:ring-0 focus:ring-offset-0 cursor-pointer"
                                            checked={filteredJobs.length > 0 && selectedJobIds.size === filteredJobs.length}
                                            onChange={toggleSelectAll}
                                        />
                                    </div>
                                    <div className="flex-[2] ml-4">Operation</div>
                                    <div className="flex-1">Status</div>
                                    <div className="flex-[1.5]">Progress</div>
                                    <div className="flex-[2]">Statistics</div>
                                    <div className="flex-1 text-right">Speed</div>
                                    <div className="w-32 text-right">Directives</div>
                                </div>

                                {filteredJobs.map(job => {
                                    const progress = job.stats.total_lines > 0 ? (job.stats.tested / job.stats.total_lines) * 100 : 0;
                                    const isRunning = job.status === "Running";
                                    const isSelected = selectedJobIds.has(job.id);

                                    return (
                                        <div
                                            key={job.id}
                                            onClick={() => openJob(job.id)}
                                            className={`group flex items-center px-8 py-5 bg-white/[0.01] backdrop-blur-xl border ${isSelected ? 'border-emerald-500/40' : 'border-white/[0.03]'} hover:border-white/[0.05] rounded-2xl cursor-pointer transition-all duration-300 hover:scale-[1.01] hover:shadow-[0_10px_30px_rgba(59,130,246,0.1)]`}
                                        >
                                            <div className="w-12 flex justify-center" onClick={(e) => { e.stopPropagation(); toggleSelect(job.id); }}>
                                                <input
                                                    type="checkbox"
                                                    className="w-4 h-4 rounded border-slate-600 bg-white/[0.02] text-emerald-500 focus:ring-0 focus:ring-offset-0 cursor-pointer"
                                                    checked={isSelected}
                                                    readOnly
                                                />
                                            </div>

                                            <div className="flex-[2] flex items-center gap-4 ml-4">
                                                <div className={`w-11 h-11 rounded-xl flex items-center justify-center text-xs font-black border shadow-lg group-hover:scale-105 transition-all duration-300 ${isRunning ? "bg-gradient-to-br from-emerald-500/20 via-slate-700/20 to-slate-900/20 border-emerald-500/30 text-emerald-400 shadow-black/10" : "bg-gradient-to-br from-slate-800 to-slate-900 border-white/[0.03] text-slate-500"}`}>
                                                    {(() => {
                                                        const match = job.name.match(/#(\d+)$/);
                                                        if (match) return `#${match[1]}`;
                                                        return job.name.substring(0, 2).toUpperCase();
                                                    })()}
                                                </div>
                                                <div className="min-w-0">
                                                    <div className="font-bold text-sm text-white group-hover:text-emerald-400 transition-colors truncate leading-tight mb-1.5">{job.name}</div>
                                                    <div className="flex items-center gap-2">
                                                        <span className="flex items-center gap-1.5 px-2 py-0.5 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-[10px] font-black uppercase tracking-tight truncate max-w-[180px]" title={`Config: ${job.settings.config.name}`}>
                                                            <svg className="w-2.5 h-2.5 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="3" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4"></path></svg>
                                                            {job.settings.config.name}
                                                        </span>
                                                        <span className="text-slate-700 font-black">·</span>
                                                        <span className="text-[10px] font-bold text-slate-500 tracking-widest uppercase">{job.settings.bot_count} BOTS</span>
                                                    </div>
                                                </div>
                                            </div>

                                            <div className="flex-1">
                                                <div className={`inline-flex items-center gap-2 px-3 py-1.5 rounded-full text-[10px] font-bold uppercase tracking-wider ${isRunning ? "bg-emerald-500/15 text-emerald-400 ring-1 ring-emerald-500/30" : "bg-white/[0.02]/80 text-slate-500 ring-1 ring-slate-700"}`}>
                                                    <div className={`w-2 h-2 rounded-full ${isRunning ? "bg-emerald-400 animate-pulse shadow-[0_0_8px_rgba(52,211,153,0.8)]" : "bg-slate-600"}`}></div>
                                                    {job.status}
                                                </div>
                                            </div>

                                            <div className="flex-[1.5] px-4">
                                                <div className="flex items-center justify-between text-[10px] mb-1.5">
                                                    <span className="text-slate-400 font-medium tabular-nums">{job.stats.tested.toLocaleString()}<span className="text-slate-600">/{job.stats.total_lines.toLocaleString()}</span></span>
                                                    <span className={`font-bold ${isRunning ? "text-white" : "text-slate-500"}`}>{progress.toFixed(1)}%</span>
                                                </div>
                                                <div className="h-2 bg-white/[0.02]/80 rounded-full overflow-hidden ring-1 ring-white/[0.02]">
                                                    <div className={`h-full rounded-full transition-all duration-1000 ${isRunning ? "bg-gradient-to-r from-emerald-500 via-emerald-600 to-emerald-700" : "bg-slate-600"}`} style={{ width: `${progress}%` }}></div>
                                                </div>
                                            </div>

                                            <div className="flex-[2] flex items-center gap-2">
                                                <div className="flex flex-col items-center px-2 py-1 rounded-lg bg-emerald-500/10 ring-1 ring-emerald-500/20 min-w-[50px]">
                                                    <span className="text-[11px] font-black text-emerald-400 tabular-nums">{(job.stats.hits + job.stats.custom).toLocaleString()}</span>
                                                    <span className="text-[7px] font-bold text-emerald-500/70 uppercase">Hits</span>
                                                </div>
                                                <div className="flex flex-col items-center px-2 py-1 rounded-lg bg-red-500/10 ring-1 ring-red-500/20 min-w-[50px]">
                                                    <span className="text-[11px] font-black text-red-400 tabular-nums">{job.stats.fails.toLocaleString()}</span>
                                                    <span className="text-[7px] font-bold text-red-500/70 uppercase">Fails</span>
                                                </div>
                                                <div className="flex flex-col items-center px-2 py-1 rounded-lg bg-amber-500/10 ring-1 ring-amber-500/20 min-w-[50px]">
                                                    <span className="text-[11px] font-black text-amber-400 tabular-nums">{job.stats.banned.toLocaleString()}</span>
                                                    <span className="text-[7px] font-bold text-amber-500/70 uppercase">Bans</span>
                                                </div>
                                                <div className="flex flex-col items-center px-2 py-1 rounded-lg bg-emerald-500/10 ring-1 ring-emerald-500/20 min-w-[50px]">
                                                    <span className="text-[11px] font-black text-emerald-400 tabular-nums">{job.stats.to_check.toLocaleString()}</span>
                                                    <span className="text-[7px] font-bold text-emerald-500/70 uppercase">Check</span>
                                                </div>
                                            </div>

                                            <div className="flex-1 text-right px-4">
                                                <div className="inline-flex flex-col items-end px-3 py-1.5 rounded-lg bg-emerald-500/10 ring-1 ring-emerald-500/20">
                                                    <span className="text-base font-black text-emerald-400 tabular-nums leading-none">{job.stats.cpm || 0}</span>
                                                    <span className="text-[7px] font-bold text-emerald-500/70 uppercase mt-0.5">CPM</span>
                                                </div>
                                            </div>

                                            <div className="w-32 flex justify-end gap-1.5 opacity-0 group-hover:opacity-100 translate-x-2 group-hover:translate-x-0 transition-all duration-200">
                                                <button
                                                    onClick={(e) => toggleJobStatus(job, e)}
                                                    className={`w-8 h-8 rounded-lg flex items-center justify-center transition-all ${isRunning ? "bg-red-500/15 text-red-400 hover:bg-red-500/25 ring-1 ring-red-500/30" : "bg-emerald-500/15 text-emerald-400 hover:bg-emerald-500/25 ring-1 ring-emerald-500/30"}`}
                                                >
                                                    {isRunning ? (
                                                        <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24"><path d="M6 19h4V5H6v14zm8-14v14h4V5h-4z"/></svg>
                                                    ) : (
                                                        <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24"><path d="M8 5v14l11-7z"/></svg>
                                                    )}
                                                </button>
                                                <button
                                                    onClick={(e) => { e.stopPropagation(); loadIntoForm(job, false); }}
                                                    className="w-8 h-8 rounded-lg bg-white/[0.02] text-slate-400 hover:text-white hover:bg-slate-700 ring-1 ring-slate-700 flex items-center justify-center transition-all"
                                                >
                                                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"></path><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"></path></svg>
                                                </button>
                                                <button
                                                    onClick={(e) => handleDeleteJob(job.id, e)}
                                                    className="w-8 h-8 rounded-lg bg-red-500/10 text-red-400 hover:bg-red-500/20 hover:text-red-300 ring-1 ring-red-500/20 flex items-center justify-center transition-all"
                                                >
                                                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path></svg>
                                                </button>
                                            </div>
                                        </div>
                                    );
                                })}
                            </div>
                        )}
                    </div>
                </div>
            </div>
        );
    }

    // Create Job View
    if (view === "create") {
        return (
            <div className="h-full flex flex-col bg-[#0a0a0c] relative overflow-hidden">
                {/* Header */}
                <div className="relative z-10 px-8 pt-8 pb-4 ">
                    <div className="max-w-3xl mx-auto flex items-center gap-4">
                        <button onClick={() => setView(returnView)} className="text-slate-500 hover:text-white p-2 hover:bg-white/[0.02] rounded-xl transition-all">
                            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M10 19l-7-7m0 0l7-7m-7 7h18"></path></svg>
                        </button>
                        <div className="flex items-center gap-3">
                            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-emerald-500 to-teal-600 flex items-center justify-center shadow-lg shadow-black/25">
                                <svg className="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 4v16m8-8H4"></path>
                                </svg>
                            </div>
                            <div>
                                <h1 className="text-xl font-bold text-white">{isEditMode ? "Edit Job" : "Create New Job"}</h1>
                                <p className="text-slate-500 text-xs">Configure your job settings</p>
                            </div>
                        </div>
                    </div>
                </div>

                {/* Form */}
                <div className="flex-1 overflow-y-auto px-8 py-6 relative z-10 custom-scrollbar">
                    <div className="max-w-3xl mx-auto space-y-6">
                        
                        <div className="properties-section bg-white/[0.01]/30 border border-white/[0.02] rounded-2xl p-6 backdrop-blur-sm relative z-50">
                            <h3 className="text-sm font-black text-slate-300 mb-6 flex items-center gap-2 uppercase tracking-widest">
                                <span className="w-8 h-8 rounded-lg bg-emerald-500/10 flex items-center justify-center text-emerald-400">🚀</span>
                                Deployment Configuration
                            </h3>
                            <div className="space-y-5">
                                <Field label="Operation Name" value={newJobName} onChange={setNewJobName} placeholder="My New Operation" />
                                
                                <div className="grid grid-cols-2 gap-5">
                                    <Select 
                                        label="Target Configuration"
                                        value={selectedConfigId}
                                        onChange={(v) => setSelectedConfigId(v)}
                                    >
                                        <option value="" className="bg-[#0a0a0c]">Select Config...</option>
                                        {configs.map(c => <option key={c.id} value={c.id} className="bg-[#0a0a0c]">{c.name}</option>)}
                                    </Select>
                                    <Field label="Concurrency (Bots)" value={botCount.toString()} onChange={(v) => setBotCount(parseInt(v) || 1)} type="number" />
                                </div>

                                <div className="bg-[#0a0a0c] border border-white/[0.02] rounded-xl p-4">
                                    <div className="flex justify-between items-center mb-3">
                                        <label className="text-[10px] font-black text-slate-500 uppercase tracking-wider">Data Source</label>
                                        <div className="flex items-center gap-3">
                                            <span className={`text-[10px] font-bold transition-colors ${useLibrary ? "text-emerald-400" : "text-slate-500"}`}>{useLibrary ? "Library" : "File Path"}</span>
                                            <Toggle checked={useLibrary} onChange={setUseLibrary} />
                                        </div>
                                    </div>
                                    {useLibrary ? (
                                        <Select 
                                            value={comboPath.split('/').pop() || ""}
                                            onChange={async (v) => {
                                                const name = v;
                                                const base = await invoke<string>("get_combos_path");
                                                setComboPath(`${base}/${name}`);
                                            }}
                                        >
                                            <option value="" className="bg-[#0a0a0c]">Select from Library...</option>
                                            {combos.map(c => <option key={c.name} value={c.name} className="bg-[#0a0a0c]">{c.name} ({c.lines.toLocaleString()} lines)</option>)}
                                        </Select>
                                    ) : (
                                        <Field label="Absolute Path" value={comboPath} onChange={setComboPath} placeholder="/path/to/combo.txt" />
                                    )}
                                </div>
                            </div>
                        </div>

                        <PropertiesSection title="Network Anonymity" icon="🌐">
                            <div className="flex items-center justify-between bg-white/[0.02] border border-white/[0.02] p-3 rounded-xl mb-4">
                                <span className="text-[10px] font-bold text-slate-300 uppercase">Enable Proxy System</span>
                                <Toggle checked={proxyMode} onChange={setProxyMode} />
                            </div>
                            
                            {proxyMode && (
                                <div className="space-y-4 animate-in fade-in duration-300">
                                    <Select 
                                        label="Proxy Group"
                                        value={selectedProxyGroupId} 
                                        onChange={(v) => setSelectedProxyGroupId(v)}
                                    >
                                        <option value="" className="bg-[#0a0a0c]">Direct (No Proxy)</option>
                                        {proxyGroups.map(g => <option key={g.id} value={g.id} className="bg-[#0a0a0c]">{g.name} ({g.proxies.length})</option>)}
                                    </Select>
                                    
                                    <div className="grid grid-cols-2 gap-3">
                                        {[ 
                                            ["Shuffle Proxies", shuffleProxies, setShuffleProxies],
                                            ["Never Ban", neverBanProxy, setNeverBanProxy],
                                            ["Stop on Exhaustion", stopOnProxyExhaustion, setStopOnProxyExhaustion]
                                        ].map(([label, val, setVal]: any) => (
                                            <div key={label} className="flex items-center justify-between bg-white/[0.02] border border-white/[0.02] p-3 rounded-xl">
                                                <span className="text-[10px] font-bold text-slate-400 uppercase">{label}</span>
                                                <Toggle checked={val} onChange={setVal} />
                                            </div>
                                        ))}
                                    </div>
                                    
                                    <div className="grid grid-cols-2 gap-4 pt-2">
                                        <Field label="Request Delay (ms)" value={requestDelayMs.toString()} onChange={(v) => setRequestDelayMs(parseInt(v) || 0)} type="number" />
                                        <Field label="Proxy Cooldown (ms)" value={proxyCooldownMs.toString()} onChange={(v) => setProxyCooldownMs(parseInt(v) || 0)} type="number" />
                                    </div>
                                </div>
                            )}
                        </PropertiesSection>

                        <PropertiesSection title="Optimization Strategy" icon="⚡" defaultOpen={false}>
                            <div className="grid grid-cols-2 gap-3 mb-4">
                                <div className="col-span-2 flex items-center justify-between bg-white/[0.02] border border-white/[0.02] p-3 rounded-xl">
                                    <div className="flex flex-col">
                                        <span className="text-[10px] font-bold text-slate-300 uppercase">Skip Lines</span>
                                        <span className="text-[9px] text-slate-500">Resume from specific index</span>
                                    </div>
                                    <Toggle checked={skipLines} onChange={setSkipLines} />
                                </div>
                                {skipLines && (
                                    <div className="col-span-2 animate-in fade-in">
                                        <Field label="Start Index" value={startLine.toString()} onChange={(v) => setStartLine(parseInt(v) || 0)} type="number" />
                                    </div>
                                )}
                                
                                <div className="flex items-center justify-between bg-white/[0.02] border border-white/[0.02] p-3 rounded-xl">
                                    <span className="text-[10px] font-bold text-slate-400 uppercase">Deduplicate</span>
                                    <Toggle checked={deduplicateCombos} onChange={setDeduplicateCombos} />
                                </div>
                                <div className="flex items-center justify-between bg-white/[0.02] border border-white/[0.02] p-3 rounded-xl">
                                    <span className="text-[10px] font-bold text-slate-400 uppercase">Retry on Error</span>
                                    <Toggle checked={retryOnTimeout} onChange={setRetryOnTimeout} />
                                </div>
                                {retryOnTimeout && (
                                    <div className="animate-in fade-in">
                                <div className="grid grid-cols-2 gap-4">
                                    <Field label="Max Retries" value={maxRetries.toString()} onChange={(v) => setMaxRetries(parseInt(v) || 0)} type="number" />
                                    <Field label="Retries until Ban" value={maxRetriesAsBan.toString()} onChange={(v) => setMaxRetriesAsBan(parseInt(v) || 0)} type="number" />
                                </div>
                                    </div>
                                )}
                            </div>
                        </PropertiesSection>

                        <PropertiesSection title="Data Management" icon="💾" defaultOpen={false}>
                            <div className="space-y-4">
                                <div className="grid grid-cols-2 gap-4">
                                    <Field label="Ban Loop Evasion" value={banLoopEvasion.toString()} onChange={(v) => setBanLoopEvasion(parseInt(v) || 0)} type="number" />
                                    <Field label="Ban Save Interval" value={banSaveInterval.toString()} onChange={(v) => setBanSaveInterval(parseInt(v) || 0)} type="number" />
                                </div>
                                <Field label="Max Banned Logs" value={maxBannedLogs.toString()} onChange={(v) => setMaxBannedLogs(parseInt(v) || 0)} type="number" />
                                
                                <div>
                                    <label className="block text-[10px] font-black text-slate-500 mb-2 uppercase tracking-wider">Save Hits For Status</label>
                                    <div className="flex flex-wrap gap-2">
                                        {["SUCCESS", "FAIL", "BAN", "RETRY", "NONE", "CUSTOM", "TOCHECK"].map(status => (
                                            <button
                                                key={status}
                                                onClick={() => setSaveHits(prev => prev.includes(status) ? prev.filter(s => s !== status) : [...prev, status])}
                                                className={`px-4 py-2 rounded-xl text-[10px] font-bold transition-all border uppercase tracking-wider ${saveHits.includes(status) ? 'bg-emerald-500/20 border-emerald-500 text-emerald-400 shadow-[0_0_10px_rgba(16,185,129,0.2)]' : 'bg-white/[0.02] border-slate-700 text-slate-500 hover:bg-white/[0.02] hover:text-slate-300'}`}
                                            >
                                                {status}
                                            </button>
                                        ))}
                                    </div>
                                </div>
                            </div>
                        </PropertiesSection>

                        {/* Submit Button */}
                        <button onClick={handleCreateJob} className="w-full bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white font-black py-4 rounded-2xl shadow-lg shadow-emerald-600/20 transition-all duration-300 hover:shadow-black/40 hover:scale-[1.01] uppercase tracking-widest text-xs border border-white/[0.03]">
                            {isEditMode ? "Save Changes" : "Initialize Job"}
                        </button>
                    </div>
                </div>
            </div>
        );
    }

    // Details View
    if (view === "details" && activeJobId) {
        return (
            <JobDetails 
                job={jobs.find(j => j.id === activeJobId)!} 
                history={history[activeJobId] || { cpm: [], success: [] }}
                onBack={() => setView("list")}
                onEdit={() => {
                    const job = jobs.find(j => j.id === activeJobId);
                    if (job) loadIntoForm(job, false, "details");
                }}
                onClone={() => {
                    const job = jobs.find(j => j.id === activeJobId);
                    if (job) loadIntoForm(job, true);
                }}
                onDelete={(e) => handleDeleteJob(activeJobId, e)}
                onEditConfig={(configId) => onEditConfig(configId || "")}
            />
        );
    }

    return null;
}


function PerformanceGraph({ history, label, color = "emerald" }: { history: number[], label: string, color?: "emerald" | "amber" | "red" }) {
    if (history.length < 2) return (
        <div className="h-full w-full flex items-center justify-center text-slate-600 text-xs">
            Waiting for data...
        </div>
    );

    const colors = {
        emerald: { stroke: "#10b981" },
        amber: { stroke: "#f59e0b" },
        red: { stroke: "#ef4444" },
    };
    const c = colors[color as keyof typeof colors] || colors.emerald;

    const cleanHistory = history.map(v => (isNaN(v) || !isFinite(v)) ? 0 : v);
    const maxVal = Math.max(...cleanHistory, 5);
    const width = 400;
    const height = 100;
    const padding = 2;

    const graphPoints = cleanHistory.map((val, i) => {
        const x = (i / (cleanHistory.length - 1)) * (width - 2 * padding) + padding;
        const y = height - padding - (val / maxVal) * (height - 2 * padding);
        return { x, y };
    });

    const strokePointsStr = graphPoints.map(p => `${p.x},${p.y}`).join(" ");
    const firstPoint = graphPoints[0];
    const lastPoint = graphPoints[graphPoints.length - 1];
    const fillPointsStr = `${firstPoint.x},${height} ${strokePointsStr} ${lastPoint.x},${height}`;

    return (
        <div className="relative h-full w-full overflow-hidden">
            <svg viewBox={`0 0 ${width} ${height}`} className="w-full h-full" preserveAspectRatio="none">
                <defs>
                    <linearGradient id={`grad-${label}`} x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor={c.stroke} stopOpacity="0.2" />
                        <stop offset="100%" stopColor={c.stroke} stopOpacity="0.0" />
                    </linearGradient>
                </defs>
                <polyline fill={`url(#grad-${label})`} points={fillPointsStr} />
                <polyline fill="none" stroke={c.stroke} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" points={strokePointsStr} />
            </svg>
        </div>
    );
}

function StatsCard({ title, value, subtext, color, icon }: { title: string, value: string | number, subtext?: string, color: string, icon?: React.ReactNode }) {
    const colors: Record<string, { bg: string, text: string, border: string, icon: string }> = {
        emerald: { bg: "hover:bg-emerald-500/5", text: "text-emerald-400", border: "border-emerald-500/20", icon: "text-emerald-500" },
        amber: { bg: "hover:bg-amber-500/5", text: "text-amber-400", border: "border-amber-500/20", icon: "text-amber-500" },
        red: { bg: "hover:bg-red-500/5", text: "text-red-400", border: "border-red-500/20", icon: "text-red-500" },
        purple: { bg: "hover:bg-purple-500/5", text: "text-purple-400", border: "border-purple-500/20", icon: "text-purple-500" },
        slate: { bg: "hover:bg-white/[0.02]", text: "text-slate-300", border: "border-white/[0.03]", icon: "text-slate-400" },
    };
    const c = colors[color] || colors.slate;

    return (
        <div className={`flex items-center justify-between p-3 rounded-xl border border-white/[0.03] bg-white/[0.02] ${c.bg} transition-colors duration-200 group shadow-sm`}>
            <div className="flex items-center gap-3">
                <div className={`w-8 h-8 rounded-lg bg-[#0a0a0c] border border-white/[0.03] flex items-center justify-center ${c.icon}`}>
                    {icon || <div className={`w-2 h-2 rounded-full ${c.text.replace('text-', 'bg-')}`}></div>}
                </div>
                <div>
                    <div className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">{title}</div>
                    {subtext && <div className="text-[9px] text-slate-600 font-medium">{subtext}</div>}
                </div>
            </div>
            <div className={`text-lg font-black tracking-tight ${c.text}`}>{value}</div>
        </div>
    );
}

function JobDetails({ job, history, onDelete, onEdit, onClone, onBack, onEditConfig }: { job: JobSummary, history: { cpm: number[], success: number[] }, onDelete: (e: React.MouseEvent) => void, onEdit: () => void, onClone: () => void, onBack: () => void, onEditConfig: (id?: string) => void }) {
    const [stats, setStats] = useState<JobStats>(job.stats);
    const [recentHits, setRecentHits] = useState<string[]>([]);
    const [recentCustoms, setRecentCustoms] = useState<string[]>([]);
    const [recentToCheck, setRecentToCheck] = useState<string[]>([]);
    const [isRunning, setIsRunning] = useState(job.status === "Running");
    const [showCapture, setShowCapture] = useState(true);
    const [listType, setListType] = useState<"hits" | "customs" | "tocheck">("hits");

    useEffect(() => {
        const fetchStats = async () => {
            try {
                const s = await invoke<JobStats>("get_job_stats", { jobId: job.id });
                const h = await invoke<string[]>("get_recent_hits", { jobId: job.id });
                const c = await invoke<string[]>("get_recent_customs", { jobId: job.id });
                const tc = await invoke<string[]>("get_recent_tocheck", { jobId: job.id }).catch(() => []);
                setStats(s);
                setRecentHits(h);
                setRecentCustoms(c);
                setRecentToCheck(tc);
            } catch (e) {}
        };
        fetchStats();
        const interval = setInterval(fetchStats, 1000);
        return () => clearInterval(interval);
    }, [job.id]);

    useEffect(() => {
        setIsRunning(job.status === "Running");
    }, [job.status]);

    const toggleJob = async () => {
        try {
            if (isRunning) {
                await invoke("stop_job", { jobId: job.id });
            } else {
                await invoke("start_job", { jobId: job.id });
            }
        } catch (e) { alert(e); }
    };

    const progress = stats.total_lines > 0 ? (stats.tested / stats.total_lines) * 100 : 0;
    const currentList = listType === "hits" ? recentHits : (listType === "customs" ? recentCustoms : recentToCheck);

    return (
        <div className="h-full flex flex-col lg:flex-row bg-[#0a0a0c] overflow-hidden">
            {/* Left Panel */}
            <div className="w-full lg:w-[380px] flex flex-col border-r border-white/[0.03] bg-[#0a0a0c]">
                {/* Header */}
                <div className="p-5 ">
                    <div className="flex items-start gap-3 mb-5">
                        <button onClick={onBack} className="p-2 rounded-lg hover:bg-white/[0.02] text-slate-400 hover:text-white transition-colors">
                            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M15 19l-7-7 7-7"></path></svg>
                        </button>
                        <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2 mb-1">
                                <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md text-xs font-medium ${isRunning ? 'bg-emerald-500/10 text-emerald-400' : 'bg-slate-700 text-slate-400'}`}>
                                    <span className={`w-1.5 h-1.5 rounded-full ${isRunning ? 'bg-emerald-500' : 'bg-slate-500'}`}></span>
                                    {isRunning ? "Running" : "Idle"}
                                </span>
                            </div>
                            <h1 className="text-lg font-semibold text-white truncate">{job.name}</h1>
                            <div className="flex items-center gap-1.5 mt-1">
                                <span className="text-[9px] font-black text-slate-600 uppercase tracking-widest">Logic Unit:</span>
                                <span className="text-xs font-black text-emerald-400 uppercase tracking-tight">{job.settings.config.name}</span>
                            </div>
                        </div>
                    </div>

                    {/* Progress */}
                    <div className="mb-5">
                        <div className="flex justify-between text-xs mb-1.5">
                            <span className="text-slate-400">Progress</span>
                            <span className="text-slate-500 tabular-nums">{stats.tested.toLocaleString()} / {stats.total_lines.toLocaleString()}</span>
                        </div>
                        <div className="h-1.5 bg-slate-700 rounded-full overflow-hidden">
                            <div className="h-full bg-white/[0.05] rounded-full transition-all" style={{ width: `${progress}%` }}></div>
                        </div>
                    </div>

                    {/* Controls */}
                    <div className="grid grid-cols-2 gap-2">
                        <button
                            onClick={toggleJob}
                            className={`col-span-2 py-2.5 rounded-lg font-medium text-sm transition-colors ${
                                isRunning
                                    ? 'bg-red-500/10 hover:bg-red-500/20 text-red-400'
                                    : 'bg-emerald-500 hover:bg-white/[0.05] text-white'
                            }`}
                        >
                            {isRunning ? "Stop" : "Start"}
                        </button>
                        {!isRunning && (
                            <>
                                <button onClick={onEdit} className="py-2 rounded-lg bg-white/[0.02] hover:bg-slate-700 text-slate-300 text-sm transition-colors">Settings</button>
                                <button onClick={() => onEditConfig(job.settings.config_id || job.settings.config.id)} className="py-2 rounded-lg bg-white/[0.02] hover:bg-slate-700 text-slate-300 text-sm transition-colors">Config</button>
                                <button onClick={onClone} className="py-2 rounded-lg bg-white/[0.02] hover:bg-slate-700 text-slate-300 text-sm transition-colors">Clone</button>
                                <button onClick={onDelete} className="py-2 rounded-lg bg-white/[0.02] hover:bg-red-500/10 text-slate-300 hover:text-red-400 text-sm transition-colors">Delete</button>
                            </>
                        )}
                    </div>
                </div>

                {/* Stats */}
                <div className="flex-1 overflow-y-auto p-5 custom-scrollbar">
                    <h3 className="text-xs text-slate-500 mb-3">Statistics</h3>
                    <div className="space-y-2">
                        <StatsCard
                            title="Hits"
                            value={stats.hits}
                            color="emerald"
                            icon={<svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>}
                        />
                        <StatsCard
                            title="Custom"
                            value={stats.custom}
                            color="amber"
                            icon={<svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>}
                        />
                        <StatsCard title="CPM" value={stats.cpm || 0} color="emerald" subtext="Checks per minute" icon={<svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path></svg>} />
                        <StatsCard title="Threads" value={`${stats.active_bots}/${job.settings.bot_count}`} color="purple" icon={<svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"></path></svg>} />
                        <StatsCard title="Fails" value={stats.fails} color="slate" icon={<svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12"></path></svg>} />
                        <StatsCard title="Retries" value={stats.retries || 0} color="slate" icon={<svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path></svg>} />
                        <StatsCard title="Errors" value={stats.errors || 0} color="red" icon={<svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>} />
                        <StatsCard title="Banned" value={stats.banned} color="red" icon={<svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>} />
                        <StatsCard title="To Check" value={stats.to_check} color="emerald" icon={<svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>} />
                    </div>
                </div>
            </div>

            {/* Right Panel */}
            <div className="flex-1 flex flex-col bg-[#0a0a0c]">
                {/* Graphs */}
                <div className="p-5 pb-0">
                    <div className="grid grid-cols-2 gap-4">
                        <div className="bg-white/[0.02] border border-white/[0.02] rounded-lg p-4">
                            <div className="flex items-center justify-between mb-3">
                                <span className="text-xs text-slate-400">CPM</span>
                                <span className="text-xs text-emerald-400 font-medium tabular-nums">{stats.cpm || 0}</span>
                            </div>
                            <div className="h-40 rounded-md bg-[#0a0a0c] overflow-hidden">
                                <PerformanceGraph history={history.cpm} label="CPM" color="emerald" />
                            </div>
                        </div>
                        <div className="bg-white/[0.02] border border-white/[0.02] rounded-lg p-4">
                            <div className="flex items-center justify-between mb-3">
                                <span className="text-xs text-slate-400">Hits</span>
                                <span className="text-xs text-emerald-400 font-medium tabular-nums">{stats.hits + stats.custom}</span>
                            </div>
                            <div className="h-40 rounded-md bg-[#0a0a0c] overflow-hidden">
                                <PerformanceGraph history={history.success} label="Success" color="emerald" />
                            </div>
                        </div>
                    </div>
                </div>

                {/* Results Header */}
                <div className="h-14 flex items-center justify-between px-5  mt-4">
                    <div className="flex gap-1 bg-white/[0.02] p-1 rounded-lg">
                        <button
                            onClick={() => setListType("hits")}
                            className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${listType === "hits" ? "bg-emerald-500 text-white" : "text-slate-400 hover:text-white"}`}
                        >
                            Hits ({recentHits.length})
                        </button>
                        <button
                            onClick={() => setListType("customs")}
                            className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${listType === "customs" ? "bg-amber-500 text-white" : "text-slate-400 hover:text-white"}`}
                        >
                            Custom ({recentCustoms.length})
                        </button>
                        <button
                            onClick={() => setListType("tocheck")}
                            className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${listType === "tocheck" ? "bg-white/[0.05] text-white" : "text-slate-400 hover:text-white"}`}
                        >
                            Check ({recentToCheck.length})
                        </button>
                    </div>
                    <div className="flex items-center gap-2">
                        <span className="text-xs text-slate-500">Show capture</span>
                        <Toggle checked={showCapture} onChange={setShowCapture} />
                    </div>
                </div>

                {/* Results List */}
                <div className="flex-1 overflow-y-auto p-5 custom-scrollbar">
                    {currentList.length === 0 ? (
                        <div className="h-full flex flex-col items-center justify-center">
                            <svg className="w-12 h-12 text-slate-700 mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.5" d="M4 6h16M4 12h16m-7 6h7"></path></svg>
                            <p className="text-slate-500 text-sm">No results yet</p>
                        </div>
                    ) : (
                        <div className="bg-white/[0.02] border border-white/[0.02] rounded-lg overflow-hidden">
                            <table className="w-full text-left">
                                <thead>
                                    <tr className=" text-xs text-slate-500">
                                        <th className="px-4 py-3 w-16 font-medium">#</th>
                                        <th className="px-4 py-3 font-medium">Result</th>
                                    </tr>
                                </thead>
                                <tbody className="divide-y divide-slate-800/30">
                                    {currentList.slice().reverse().map((hit, i) => {
                                        let displayHit = showCapture ? hit : hit.split(" | ")[0];
                                        // Remove SUCCESS: or CUSTOM: or TOCHECK: prefix if present
                                        displayHit = displayHit.replace(/^(SUCCESS|CUSTOM|TOCHECK):\s*/i, '');
                                        
                                        const isHits = listType === "hits";
                                        const isCustom = listType === "customs";
                                        const textColor = isHits ? "text-emerald-400" : (isCustom ? "text-amber-400" : "text-emerald-400");

                                        return (
                                            <tr key={i} className="hover:bg-white/[0.02] transition-colors">
                                                <td className="px-4 py-2.5 text-xs text-slate-600 tabular-nums">
                                                    {currentList.length - i}
                                                </td>
                                                <td className={`px-4 py-2.5 font-mono text-xs break-all ${textColor}`}>
                                                    {displayHit}
                                                </td>
                                            </tr>
                                        );
                                    })}
                                </tbody>
                            </table>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
}


// --- Data Tab ---

function DataTab({ groups, setGroups }: { groups: ProxyGroup[], setGroups: React.Dispatch<React.SetStateAction<ProxyGroup[]>> }) {
    const [activeSubTab, setActiveSubTab] = useState<"proxies" | "combos">("proxies");
    
    // Proxy State
    const [proxyName, setProxyName] = useState("");
    const [proxyContent, setProxyContent] = useState("");
    const [proxySearch, setProxySearch] = useState("");

    // Combo Library State
    const [combos, setCombos] = useState<{name: string, lines: number}[]>([]);
    const [comboName, setComboName] = useState("");
    const [comboSearch, setComboSearch] = useState("");
    const [combosPath, setCombosPath] = useState("");

    useEffect(() => {
        refreshCombos();
        invoke<string>("get_combos_path").then(setCombosPath).catch(console.error);
    }, []);

    const refreshCombos = async () => {
        try {
            const list = await invoke<{name: string, lines: number}[]>("list_combos");
            setCombos(list);
        } catch (e) {
            console.error("Failed to list combos", e);
        }
    }

    const addProxyGroup = () => {
        if (!proxyName) return alert("Enter a name");
        const list = proxyContent.split('\n').map(p => p.trim()).filter(p => p);
        if (list.length === 0) return alert("Enter content");

        const newGroup: ProxyGroup = {
            id: Math.random().toString(36).substring(2, 9),
            name: proxyName,
            proxies: list
        };
        const newGroups = [...groups, newGroup];
        setGroups(newGroups);
        invoke("save_proxies", { groups: newGroups }).catch(e => console.error("Failed to save proxies", e));
        setProxyName("");
        setProxyContent("");
    };

    const deleteProxyGroup = (id: string) => {
        if (confirm("Delete this group?")) {
            const newGroups = groups.filter(g => g.id !== id);
            setGroups(newGroups);
            invoke("save_proxies", { groups: newGroups }).catch(e => console.error("Failed to save proxies", e));
        }
    };

    const deleteComboFile = async (name: string) => {
        if (!confirm(`Delete ${name}?`)) return;
        try {
            await invoke("delete_combo", { name });
            refreshCombos();
        } catch (e) {
            alert(e);
        }
    }

    const importFromPath = async () => {
        const path = prompt("Enter the absolute path to your combo file:");
        if (!path) return;
        try {
            const content = await invoke<string>("read_text_file", { path });
            const name = path.split(/[\/\\]/).pop() || "imported_combo.txt";
            await invoke("save_combo", { name, content });
            refreshCombos();
            alert(`Imported "${name}" successfully!`);
        } catch (e) {
            alert("Failed to read or import file: " + e);
        }
    }

    const filteredProxyGroups = groups.filter(g => g.name.toLowerCase().includes(proxySearch.toLowerCase()));
    const totalProxies = groups.reduce((acc, g) => acc + g.proxies.length, 0);

    const filteredCombos = combos.filter(c => c.name.toLowerCase().includes(comboSearch.toLowerCase()));

    return (
        <div className="h-full flex flex-col bg-[#0a0a0c]">
            

            {/* Header */}
            <div className="relative z-30 px-8 pt-8 pb-6">
                <div className="max-w-7xl mx-auto">
                    <div className="flex justify-between items-start mb-8">
                        <div>
                            <div className="flex items-center gap-3 mb-2">
                                <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-slate-700 to-slate-800 flex items-center justify-center shadow-lg shadow-slate-700/25">
                                    <svg className="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4m0 5c0 2.21-3.582 4-8 4s-8-1.79-8-4"></path>
                                    </svg>
                                </div>
                                <h1 className="text-2xl font-black text-white tracking-tight">Data & Proxies</h1>
                            </div>
                            <p className="text-slate-500 text-sm font-medium">Manage proxy groups and your centralized combo library</p>
                        </div>
                    </div>

                    {/* Tab Buttons */}
                    <div className="flex gap-2 mb-6">
                        <button
                            onClick={() => setActiveSubTab("proxies")}
                            className={`flex items-center gap-2 px-5 py-2.5 rounded-xl font-bold text-sm transition-all ${activeSubTab === "proxies" ? "bg-gradient-to-r from-slate-700 to-slate-800 text-white shadow-lg shadow-black" : "bg-[#0a0a0c] text-slate-400 hover:text-white border border-white/[0.03]"}`}
                        >
                            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9"></path></svg>
                            Proxies
                        </button>
                        <button
                            onClick={() => setActiveSubTab("combos")}
                            className={`flex items-center gap-2 px-5 py-2.5 rounded-xl font-bold text-sm transition-all ${activeSubTab === "combos" ? "bg-gradient-to-r from-slate-700 to-slate-800 text-white shadow-lg shadow-black" : "bg-[#0a0a0c] text-slate-400 hover:text-white border border-white/[0.03]"}`}
                        >
                            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path></svg>
                            Combo Library
                        </button>
                    </div>

                    {activeSubTab === "proxies" ? (
                        <>
                            {/* Stats Bar */}
                            <div className="flex items-center gap-6 mb-6">
                                <div className="flex items-center gap-2">
                                    <div className="w-2 h-2 rounded-full bg-white/[0.05] animate-pulse"></div>
                                    <span className="text-slate-400 text-sm font-medium">{groups.length} Groups</span>
                                </div>
                                <div className="h-4 w-px bg-white/[0.02]"></div>
                                <span className="text-slate-500 text-sm">{totalProxies} Total Proxies</span>
                            </div>

                            {/* Search Bar */}
                            <div className="relative group">
                                <div className="absolute inset-0 bg-gradient-to-r from-slate-700/20 to-slate-800/20 rounded-2xl blur-xl opacity-0 group-focus-within:opacity-100 transition-opacity duration-300"></div>
                                <div className="relative flex items-center">
                                    <svg className="absolute left-4 w-5 h-5 text-slate-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"></path>
                                    </svg>
                                    <input
                                        type="text"
                                        placeholder="Search proxy groups..."
                                        value={proxySearch}
                                        onChange={(e) => setProxySearch(e.target.value)}
                                        className="w-full bg-white/[0.01]/80 backdrop-blur-sm border border-white/[0.03] rounded-2xl py-3.5 pl-12 pr-4 text-white placeholder-slate-600 focus:outline-none focus:border-slate-700 focus:bg-white/[0.01] transition-all duration-300"
                                    />
                                </div>
                            </div>
                        </>
                    ) : (
                        <>
                            {/* Stats Bar */}
                            <div className="flex items-center gap-6 mb-6">
                                <div className="flex items-center gap-2">
                                    <div className="w-2 h-2 rounded-full bg-white/[0.05] animate-pulse"></div>
                                    <span className="text-slate-400 text-sm font-medium">{combos.length} Files in Library</span>
                                </div>
                                <div className="h-4 w-px bg-white/[0.02]"></div>
                                <span className="text-slate-500 text-xs font-mono">{combosPath}</span>
                            </div>

                            {/* Search Bar */}
                            <div className="relative group">
                                <div className="absolute inset-0 bg-gradient-to-r from-slate-700/20 to-slate-800/20 rounded-2xl blur-xl opacity-0 group-focus-within:opacity-100 transition-opacity duration-300"></div>
                                <div className="relative flex items-center">
                                    <svg className="absolute left-4 w-5 h-5 text-slate-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"></path>
                                    </svg>
                                    <input
                                        type="text"
                                        placeholder="Search combo library..."
                                        value={comboSearch}
                                        onChange={(e) => setComboSearch(e.target.value)}
                                        className="w-full bg-white/[0.01]/80 backdrop-blur-sm border border-white/[0.03] rounded-2xl py-3.5 pl-12 pr-4 text-white placeholder-slate-600 focus:outline-none focus:border-slate-700 focus:bg-white/[0.01] transition-all duration-300"
                                    />
                                </div>
                            </div>
                        </>
                    )}
                </div>
            </div>

            {/* Content */}
            <div className="flex-1 overflow-hidden px-8 pb-8 relative z-10">
                <div className="max-w-7xl mx-auto h-full">
                    {activeSubTab === "proxies" ? (
                        <div className="h-full flex gap-6">
                            {/* Add Group Panel */}
                            <div className="w-80 bg-[#0a0a0c] backdrop-blur-sm rounded-2xl border border-white/[0.03] flex flex-col overflow-hidden">
                                <div className="p-5  bg-[#0a0a0c]">
                                    <h3 className="text-sm font-bold text-slate-300 flex items-center gap-2">
                                        <svg className="w-4 h-4 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 4v16m8-8H4"></path></svg>
                                        Add Proxy Group
                                    </h3>
                                </div>
                                <div className="flex-1 p-5 flex flex-col">
                                    <button onClick={addProxyGroup} className="w-full mb-4 bg-gradient-to-r from-slate-700 to-slate-800 hover:from-slate-700 hover:to-slate-900 text-white font-bold py-3 rounded-xl shadow-lg shadow-black transition-all duration-300 hover:shadow-slate-700/40">
                                        Save Group
                                    </button>
                                    <Field label="Group Name" value={proxyName} onChange={setProxyName} placeholder="My Proxies" />
                                    <div className="flex-1 mb-4">
                                        <label className="block text-[10px] font-bold text-slate-500 mb-1 uppercase tracking-wider">Proxies (One per line)</label>
                                        <textarea
                                            className="w-full h-full min-h-[200px] bg-white/[0.02] border border-slate-700 rounded-xl p-3 text-xs text-white font-mono resize-none custom-scrollbar focus:border-slate-700 outline-none transition-colors"
                                            value={proxyContent}
                                            onChange={(e) => setProxyContent(e.target.value)}
                                            placeholder="host:port&#10;host:port:user:pass&#10;user:pass@host:port"
                                        ></textarea>
                                    </div>
                                </div>
                            </div>

                            {/* Groups Grid */}
                            <div className="flex-1 bg-[#0a0a0c] backdrop-blur-sm rounded-2xl border border-white/[0.03] overflow-hidden flex flex-col">
                                <div className="p-5  bg-[#0a0a0c]">
                                    <h3 className="text-sm font-bold text-slate-300">Existing Groups</h3>
                                </div>
                                <div className="flex-1 overflow-y-auto p-5 custom-scrollbar">
                                    {filteredProxyGroups.length === 0 ? (
                                        <div className="h-full flex flex-col items-center justify-center py-10">
                                            <div className="w-16 h-16 rounded-2xl bg-white/[0.02] flex items-center justify-center mb-4">
                                                <svg className="w-8 h-8 text-slate-700" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.5" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9"></path>
                                                </svg>
                                            </div>
                                            <p className="text-slate-500 font-medium text-sm">{proxySearch ? "No results found" : "No proxy groups yet"}</p>
                                            <p className="text-slate-600 text-xs mt-1">{proxySearch ? "Try a different search" : "Add your first group"}</p>
                                        </div>
                                    ) : (
                                        <div className="grid grid-cols-2 gap-4">
                                            {filteredProxyGroups.map(g => (
                                                <div key={g.id} className="group relative bg-white/[0.02] hover:bg-white/[0.02] p-5 rounded-2xl border border-slate-700 hover:border-slate-700/30 transition-all duration-300">
                                                    <div className="absolute inset-0 rounded-2xl bg-gradient-to-br from-slate-700/5 to-slate-800/5 opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
                                                    <div className="relative">
                                                        <div className="flex items-start justify-between mb-2">
                                                            <h4 className="font-bold text-lg text-white group-hover:text-white transition-colors">{g.name}</h4>
                                                            <button
                                                                onClick={() => deleteProxyGroup(g.id)}
                                                                className="opacity-0 group-hover:opacity-100 p-2 rounded-lg hover:bg-red-500/20 text-slate-500 hover:text-red-400 transition-all duration-200"
                                                            >
                                                                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path>
                                                                </svg>
                                                            </button>
                                                        </div>
                                                        <div className="flex items-center gap-2">
                                                            <div className="w-2 h-2 rounded-full bg-white/[0.05]"></div>
                                                            <span className="text-sm text-slate-400">{g.proxies.length} Proxies</span>
                                                        </div>
                                                    </div>
                                                </div>
                                            ))}
                                        </div>
                                    )}
                                </div>
                            </div>
                        </div>
                    ) : (
                        <div className="h-full flex gap-6">
                            {/* Add Combo Panel */}
                            <div className="w-80 bg-[#0a0a0c] backdrop-blur-sm rounded-2xl border border-white/[0.03] flex flex-col overflow-hidden">
                                <div className="p-5  bg-[#0a0a0c] flex justify-between items-center">
                                    <h3 className="text-sm font-bold text-slate-300 flex items-center gap-2">
                                        <svg className="w-4 h-4 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 4v16m8-8H4"></path></svg>
                                        Import Combo File
                                    </h3>
                                    <button 
                                        onClick={importFromPath}
                                        className="text-[10px] bg-white/[0.02] hover:bg-slate-700 text-slate-400 px-2 py-1 rounded-lg border border-slate-700 transition-colors"
                                        title="Import from an existing file path"
                                    >
                                        From Path
                                    </button>
                                </div>
                                <div className="flex-1 p-5 flex flex-col">
                                    <Field label="File Name" value={comboName} onChange={setComboName} placeholder="combo.txt" />

                                </div>
                            </div>

                            {/* Combo Grid */}
                            <div className="flex-1 bg-[#0a0a0c] backdrop-blur-sm rounded-2xl border border-white/[0.03] overflow-hidden flex flex-col">
                                <div className="p-5  bg-[#0a0a0c]">
                                    <h3 className="text-sm font-bold text-slate-300">Library Files</h3>
                                </div>
                                <div className="flex-1 overflow-y-auto p-5 custom-scrollbar">
                                    {filteredCombos.length === 0 ? (
                                        <div className="h-full flex flex-col items-center justify-center py-10">
                                            <div className="w-16 h-16 rounded-2xl bg-white/[0.02] flex items-center justify-center mb-4">
                                                <svg className="w-8 h-8 text-slate-700" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.5" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path>
                                                </svg>
                                            </div>
                                            <p className="text-slate-500 font-medium text-sm">{comboSearch ? "No results found" : "Library is empty"}</p>
                                            <p className="text-slate-600 text-xs mt-1">{comboSearch ? "Try a different search" : "Import your first combo file"}</p>
                                        </div>
                                    ) : (
                                        <div className="grid grid-cols-2 lg:grid-cols-3 gap-4">
                                            {filteredCombos.map(combo => (
                                                <div key={combo.name} className="group relative bg-white/[0.02] hover:bg-white/[0.02] p-4 rounded-2xl border border-slate-700 hover:border-slate-700/30 transition-all duration-300">
                                                    <div className="absolute inset-0 rounded-2xl bg-gradient-to-br from-slate-700/5 to-slate-800/5 opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
                                                    <div className="relative">
                                                        <div className="flex items-start justify-between mb-1">
                                                            <h4 className="font-bold text-sm text-white group-hover:text-white transition-colors truncate pr-2" title={combo.name}>{combo.name}</h4>
                                                            <button
                                                                onClick={() => deleteComboFile(combo.name)}
                                                                className="opacity-0 group-hover:opacity-100 p-1.5 rounded-lg hover:bg-red-500/20 text-slate-500 hover:text-red-400 transition-all duration-200"
                                                            >
                                                                <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path>
                                                                </svg>
                                                            </button>
                                                        </div>
                                                        <div className="flex items-center gap-2">
                                                            <div className="w-1.5 h-1.5 rounded-full bg-white/[0.05]"></div>
                                                            <span className="text-[10px] text-slate-400 font-mono">{combo.lines.toLocaleString()} lines</span>
                                                        </div>
                                                    </div>
                                                </div>
                                            ))}
                                        </div>
                                    )}
                                </div>
                            </div>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
}

// --- Regex AI Tab ---

function RegexTab() {
    const [source, setSource] = useState("");
    const [target, setTarget] = useState("");
    const [generatedRegex, setGeneratedRegex] = useState("");
    const [testResult, setTestResult] = useState<string | null>(null);

    const escapeRegex = (string: string) => {
        return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    };

    const generate = () => {
        if (!source || !target) return;
        
        const idx = source.indexOf(target);
        if (idx === -1) {
            setTestResult("Target not found in source!");
            return;
        }

        let left = "";
        let right = "";

        // Improved Left Boundary Search:
        // We want a boundary that is unique and ideally starts after a common delimiter
        for (let len = 3; len <= 60; len++) {
            if (idx - len < 0) break;
            const candidate = source.substring(idx - len, idx);
            
            // Check if this string appears ONLY once before our target
            const matches = source.split(candidate).length - 1;
            
            // We want it to be unique, OR at least contain a full attribute like name="..."
            if (matches === 1 || (len > 10 && candidate.includes('='))) {
                left = candidate;
                // If we found a unique one that looks like an attribute, stop
                if (matches === 1 && (candidate.includes('name=') || candidate.includes('id='))) break;
                if (matches === 1 && len > 15) break; 
            }
        }

        // Improved Right Boundary Search:
        for (let len = 1; len <= 20; len++) {
            if (idx + target.length + len > source.length) break;
            const candidate = source.substring(idx + target.length, idx + target.length + len);
            if (candidate.includes('"') || candidate.includes('>') || candidate.includes(' ') || candidate.includes('\n')) {
                right = candidate;
                break;
            }
        }

        // Construct and clean regex
        const regex = `${escapeRegex(left)}(.*?)${escapeRegex(right)}`;
        setGeneratedRegex(regex);

        try {
            const re = new RegExp(regex);
            const match = re.exec(source);
            if (match && match[1] === target) {
                setTestResult("✅ Verified! Unique pattern found.");
            } else {
                setTestResult("⚠️ Pattern match check failed.");
            }
        } catch (e) {
            setTestResult("❌ Regex error.");
        }
    };

    return (
        <div className="h-full flex flex-col bg-[#0a0a0c]">
            <div className="relative z-30 px-8 pt-8 pb-6">
                <div className="max-w-4xl mx-auto">
                    <div className="flex items-center gap-3 mb-2">
                        <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-pink-500 to-rose-600 flex items-center justify-center shadow-lg shadow-pink-500/25">
                            <span className="text-xl">🧠</span>
                        </div>
                        <h1 className="text-2xl font-black text-white tracking-tight">Regex Pattern</h1>
                    </div>
                    <p className="text-slate-500 text-sm font-medium">Auto-generate extraction patterns from source text</p>
                </div>
            </div>

            <div className="flex-1 overflow-y-auto px-8 pb-8 relative z-10 custom-scrollbar">
                <div className="max-w-4xl mx-auto space-y-6">
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                        <div className="space-y-4">
                            <div>
                                <label className="block text-[10px] font-bold text-slate-500 mb-2 uppercase tracking-wider">1. Source Text</label>
                                <textarea
                                    className="w-full h-64 bg-[#0a0a0c] border border-white/[0.03] rounded-2xl p-4 text-xs font-mono text-slate-300 resize-none outline-none focus:border-pink-500 transition-colors custom-scrollbar"
                                    value={source}
                                    onChange={(e) => setSource(e.target.value)}
                                    placeholder="Paste full response body here (HTML, JSON, etc.)"
                                ></textarea>
                            </div>
                            <div>
                                <label className="block text-[10px] font-bold text-slate-500 mb-2 uppercase tracking-wider">2. Target Value</label>
                                <input
                                    className="w-full bg-[#0a0a0c] border border-white/[0.03] rounded-xl p-3 text-xs font-mono text-white outline-none focus:border-pink-500 transition-colors"
                                    value={target}
                                    onChange={(e) => setTarget(e.target.value)}
                                    placeholder="Paste the exact substring you want to extract"
                                />
                            </div>
                            <button
                                onClick={generate}
                                className="w-full py-3 bg-gradient-to-r from-pink-600 to-rose-600 hover:from-pink-500 hover:to-rose-500 text-white font-bold rounded-xl shadow-lg shadow-pink-600/20 transition-all uppercase tracking-widest text-xs"
                            >
                                Generate Pattern
                            </button>
                        </div>

                        <div className="space-y-4">
                            <div>
                                <label className="block text-[10px] font-bold text-slate-500 mb-2 uppercase tracking-wider">Generated Regex</label>
                                <div className="relative">
                                    <textarea
                                        className="w-full h-32 bg-slate-950 border border-white/[0.03] rounded-2xl p-4 text-sm font-mono text-green-400 resize-none outline-none focus:border-pink-500 transition-colors"
                                        value={generatedRegex}
                                        readOnly
                                    ></textarea>
                                    {generatedRegex && (
                                        <button
                                            onClick={() => { navigator.clipboard.writeText(generatedRegex); }}
                                            className="absolute top-2 right-2 p-2 bg-white/5 hover:bg-white/10 rounded-lg text-slate-400 hover:text-white transition-colors"
                                            title="Copy"
                                        >
                                            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M8 5H6a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2v-1M8 5a2 2 0 002 2h2a2 2 0 002-2M8 5a2 2 0 012-2h2a2 2 0 012 2m0 0h2a2 2 0 012 2v3m2 4H10m0 0l3-3m-3 3l3 3"></path></svg>
                                        </button>
                                    )}
                                </div>
                            </div>

                            {testResult && (
                                <div className={`p-4 rounded-xl border ${testResult.startsWith('✅') ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400' : 'bg-red-500/10 border-red-500/20 text-red-400'}`}>
                                    <div className="text-xs font-bold">{testResult}</div>
                                </div>
                            )}

                            <div className="bg-[#0a0a0c] border border-white/[0.03] rounded-xl p-4">
                                <h4 className="text-[10px] font-bold text-slate-400 uppercase tracking-wider mb-2">Tips</h4>
                                <ul className="text-xs text-slate-500 space-y-1 list-disc list-inside">
                                    <li>Ensure source text contains the exact target value.</li>
                                    <li>The generator looks for unique boundaries left and right.</li>
                                    <li>For JSON, prefer the "JSON" mode in Parse block instead of Regex.</li>
                                </ul>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
}

interface RecordedRequest {
    id: string;
    method: string;
    url: string;
    requestHeaders: Record<string, string>;
    requestBody: string | null;
    status: number | null;
    responseHeaders: Record<string, string>;
    responseBody: string | null;
    duration: number;
    timestamp: number;
    pending: boolean;
}

const TruncatedBody = ({ body, maxLength = 50000 }: { body: string; maxLength?: number }) => {
    const [expanded, setExpanded] = useState(false);
    const isTruncated = body.length > maxLength;
    const displayText = expanded || !isTruncated ? body : body.slice(0, maxLength);

    return (
        <div>
            <div className="break-all whitespace-pre-wrap">{displayText}</div>
            {isTruncated && (
                <button
                    onClick={() => setExpanded(!expanded)}
                    className="mt-2 text-[10px] font-bold text-emerald-400 hover:text-emerald-300 uppercase tracking-wider"
                >
                    {expanded ? `Show Less` : `Show More (${Math.round(body.length / 1024)}KB total)`}
                </button>
            )}
        </div>
    );
};

function ProxyRecorder() {
    const [isRecording, setIsRecording] = useState(false);
    const [port, setPort] = useState(8888);
    const [requests, setRequests] = useState<RecordedRequest[]>([]);
    const [selectedReqId, setSelectedReqId] = useState<string | null>(null);
    const [filter, setFilter] = useState("");
    const [showImages, setShowImages] = useState(false);

    // Repeater State
    const [repeaterOpen, setRepeaterOpen] = useState(false);
    const [repeaterMethod, setRepeaterMethod] = useState("GET");
    const [repeaterUrl, setRepeaterUrl] = useState("");
    const [repeaterHeaders, setRepeaterHeaders] = useState("");
    const [repeaterBody, setRepeaterBody] = useState("");
    const [repeaterResponse, setRepeaterResponse] = useState<{status: number, headers: Record<string, string>, body: string, durationMs: number, responseUrl: string} | null>(null);
    const [repeaterSending, setRepeaterSending] = useState(false);
    const [repeaterError, setRepeaterError] = useState<string | null>(null);

    // Performance: Use a ref for incoming updates to batch them
    const updatesQueue = useRef<RecordedRequest[]>([]);
    
    // Scroll Management
    const listRef = useRef<HTMLDivElement>(null);
    const prevScrollHeight = useRef(0);
    const prevFirstId = useRef<string | null>(null);

    // Custom Highlighting State
    const [keywords, setKeywords] = useState<string[]>(['login', 'sign-in', 'signin', 'auth', 'token', 'session', 'oauth', 'cookie']);
    const [newKeyword, setNewKeyword] = useState("");
    const [showKeywordsMenu, setShowKeywordsMenu] = useState(false);
    const keywordsLoaded = useRef(false);

    // Load keywords from file on mount
    useEffect(() => {
        const loadKeywords = async () => {
            try {
                const loaded = await invoke<string[]>("load_highlight_keywords");
                setKeywords(loaded);
                keywordsLoaded.current = true;
            } catch (e) {
                console.error("Failed to load highlight keywords:", e);
                keywordsLoaded.current = true;
            }
        };
        loadKeywords();
    }, []);

    // Save keywords to file when changed (skip initial load)
    useEffect(() => {
        if (!keywordsLoaded.current) return;
        invoke("save_highlight_keywords", { keywords }).catch(e => console.error("Failed to save highlight keywords:", e));
    }, [keywords]);

    const addKeyword = () => {
        if (newKeyword && !keywords.includes(newKeyword.toLowerCase())) {
            setKeywords([...keywords, newKeyword.toLowerCase()]);
            setNewKeyword("");
        }
    };

    const removeKeyword = (k: string) => {
        setKeywords(keywords.filter(w => w !== k));
    };

    // Initial Fetch
    useEffect(() => {
        const fetchInitial = async () => {
            try {
                const reqs = await invoke<RecordedRequest[]>("get_recorded_requests");
                setRequests(reqs.sort((a, b) => b.timestamp - a.timestamp));
            } catch (e) { console.error(e); }
        };
        fetchInitial();
    }, []);

    // Batching System: Flush queue every 500ms
    useEffect(() => {
        const interval = setInterval(() => {
            if (updatesQueue.current.length > 0) {
                const batch = [...updatesQueue.current];
                updatesQueue.current = []; // Clear queue
                
                setRequests(prev => {
                    // Efficiently merge batch into prev
                    // Using a Map for O(1) lookup during merge if list is huge, 
                    // or just findIndex for simplicity if batch is small.
                    // Given we want to avoid re-rendering entire list if possible, state update is unavoidable.
                    // We just minimize how often it happens.
                    
                    const newMap = new Map(prev.map(r => [r.id, r]));
                    batch.forEach(r => newMap.set(r.id, r));
                    
                    const merged = Array.from(newMap.values());
                    return merged.sort((a, b) => b.timestamp - a.timestamp);
                });
            }
        }, 500); // 500ms throttling
        return () => clearInterval(interval);
    }, []);

    // Event Listener: Push to Queue instead of SetState
    useEffect(() => {
        let unlisten: (() => void) | null = null;
        const setup = async () => {
            const { listen } = await import("@tauri-apps/api/event");
            const stop = await listen<RecordedRequest>("proxy-request-update", (event) => {
                updatesQueue.current.push(event.payload);
            });
            unlisten = stop;
        };
        setup();
        return () => { if (unlisten) unlisten(); };
    }, []);

    const toggleRecording = async () => {
        try {
            if (isRecording) {
                await invoke("stop_recorder");
                setIsRecording(false);
            } else {
                await invoke("start_recorder", { port });
                setIsRecording(true);
            }
        } catch (e) {
            alert("Error: " + e);
        }
    };

    const clearRequests = async () => {
        await invoke("clear_recorded_requests");
        setRequests([]);
        setSelectedReqId(null);
    };

    const [showImportMenu, setShowImportMenu] = useState(false);

    const importAsBlock = (blockType: "Request" | "TlsRequest" | "TlsWreq") => {
        const selected = requests.filter(r => r.id === selectedReqId);
        if (selected.length === 0) return alert("Select a request to import");

        const req = selected[0];
        const headers = Object.entries(req.requestHeaders).map(([k, v]) => `${k}: ${v}`).join("\n");

        let block: Block;

        if (blockType === "Request") {
            block = {
                id: Math.random().toString(36).substring(2, 9),
                block_type: "Request",
                data: {
                    method: req.method,
                    url: req.url,
                    headers: headers,
                    body: req.requestBody || "",
                    request_body_type: "raw",
                    multipart_fields: [],
                    timeout: 15000,
                    max_redirects: 8,
                    auto_redirect: true,
                    read_response: true,
                    security_protocol: "SystemDefault",
                    custom_ciphers: false,
                    cipher_suites: "",
                    use_proxy: true
                }
            };
        } else if (blockType === "TlsRequest") {
            block = {
                id: Math.random().toString(36).substring(2, 9),
                block_type: "TlsRequest",
                data: {
                    request_method: req.method,
                    request_url: req.url,
                    headers: headers,
                    request_body: req.requestBody || "",
                    request_body_type: "raw",
                    multipart_fields: [],
                    tls_client_identifier: "chrome_133",
                    timeout_seconds: 30,
                    follow_redirects: false,
                    insecure_skip_verify: false,
                    with_default_cookie_jar: true,
                    random_tls_extension_order: true,
                    force_http1: false,
                    randomize_header_order: true,
                    without_cookie_jar: false,
                    custom_session_id: "",
                    proxy_url: ""
                }
            };
        } else {
            block = {
                id: Math.random().toString(36).substring(2, 9),
                block_type: "TlsWreq",
                data: {
                    request_method: req.method,
                    request_url: req.url,
                    headers: headers,
                    request_body: req.requestBody || "",
                    request_body_type: "raw",
                    multipart_fields: [],
                    emulation: "chrome133",
                    timeout_seconds: 30,
                    follow_redirects: true,
                    max_redirects: 10,
                    force_http1: false,
                    cookie_store: false,
                    randomize_header_order: false,
                    proxy_url: ""
                }
            };
        }

        navigator.clipboard.writeText(JSON.stringify(block, null, 2));
        setShowImportMenu(false);
        alert(`Block JSON copied to clipboard!`);
    };

    const sendToRepeater = () => {
        if (!selectedReq) return;
        setRepeaterMethod(selectedReq.method);
        setRepeaterUrl(selectedReq.url);
        setRepeaterHeaders(Object.entries(selectedReq.requestHeaders).map(([k, v]) => `${k}: ${v}`).join("\n"));
        setRepeaterBody(selectedReq.requestBody || "");
        setRepeaterResponse(null);
        setRepeaterError(null);
        setRepeaterOpen(true);
    };

    const sendRepeaterRequest = async () => {
        setRepeaterSending(true);
        setRepeaterError(null);
        setRepeaterResponse(null);
        try {
            const headers: Record<string, string> = {};
            repeaterHeaders.split("\n").forEach(line => {
                const idx = line.indexOf(":");
                if (idx > 0) {
                    headers[line.substring(0, idx).trim()] = line.substring(idx + 1).trim();
                }
            });
            const result = await invoke<{status: number, headers: Record<string, string>, body: string, durationMs: number, responseUrl: string}>("send_repeater_request", {
                req: {
                    method: repeaterMethod,
                    url: repeaterUrl,
                    headers,
                    body: repeaterBody || null
                }
            });
            setRepeaterResponse(result);
        } catch (e) {
            setRepeaterError(String(e));
        } finally {
            setRepeaterSending(false);
        }
    };

    const filteredRequests = useMemo(() => requests.filter(r => {
        // Only show GET, POST, OPTIONS, and PUT
        const allowedMethods = ["GET", "POST", "OPTIONS", "PUT"];
        if (!allowedMethods.includes(r.method.toUpperCase())) return false;

        if (!showImages) {
            const ext = r.url.split('?')[0].split('.').pop()?.toLowerCase();
            if (['png', 'jpg', 'jpeg', 'gif', 'svg', 'webp', 'ico', 'css', 'woff', 'woff2', 'js', 'mjs', 'map'].includes(ext || "")) return false;
        }
        if (filter) {
            return r.url.toLowerCase().includes(filter.toLowerCase());
        }
        return true;
    }), [requests, showImages, filter]);

    const selectedReq = useMemo(() => requests.find(r => r.id === selectedReqId), [requests, selectedReqId]);

    // Scroll Anchoring Effect
    React.useLayoutEffect(() => {
        const el = listRef.current;
        if (!el || requests.length === 0) {
            prevScrollHeight.current = 0;
            return;
        }

        const currentScrollHeight = el.scrollHeight;
        const currentFirstId = requests[0]?.id;

        // If new items were added at top (first ID changed) AND we weren't at the very top (scrollTop > 0)
        // OR if a request is selected (we want to stay with the content)
        if (currentFirstId !== prevFirstId.current && prevScrollHeight.current > 0) {
            const delta = currentScrollHeight - prevScrollHeight.current;
            if (delta > 0 && (el.scrollTop > 50 || selectedReqId)) {
                el.scrollTop += delta;
            }
        }

        prevScrollHeight.current = currentScrollHeight;
        prevFirstId.current = currentFirstId;
    }, [requests, selectedReqId]); 

    // Separate component for list item to allow React.memo
    const RequestItem = React.memo(({ req, isSelected, onClick, keywords }: { req: RecordedRequest, isSelected: boolean, onClick: (id: string) => void, keywords: string[] }) => {
        const isAuth = useMemo(() => keywords.some(k => req.url.toLowerCase().includes(k)), [req.url, keywords]);
        
        return (
            <div 
                onClick={() => onClick(req.id)}
                className={`px-4 py-3 border-b border-white/[0.02] cursor-pointer transition-all ${isSelected ? "bg-white/[0.04]" : "hover:bg-white/[0.01]"} ${isAuth ? "bg-yellow-500/5 border-l-2 border-l-yellow-500" : "border-l-2 border-l-transparent"}`}
            >
                <div className="flex items-center justify-between mb-1">
                    <div className="flex items-center gap-2">
                        <span className={`text-[10px] font-black w-12 ${req.method === "GET" ? "text-emerald-400" : req.method === "POST" ? "text-blue-400" : "text-purple-400"}`}>{req.method}</span>
                        {isAuth && <span className="text-[8px] font-black bg-yellow-500 text-black px-1.5 py-0.5 rounded uppercase tracking-wider">Auth</span>}
                    </div>
                    {req.status ? (
                        <span className={`text-[10px] font-bold ${req.status >= 200 && req.status < 300 ? "text-emerald-500" : "text-red-500"}`}>{req.status}</span>
                    ) : (
                        <span className="text-[10px] text-slate-600 italic">Pending...</span>
                    )}
                </div>
                <div className={`text-xs truncate font-mono ${isAuth ? "text-yellow-100" : "text-slate-300"}`}>{req.url}</div>
                <div className="flex justify-between mt-1">
                    <span className="text-[9px] text-slate-600">{req.duration > 0 ? `${req.duration}ms` : ""}</span>
                    <span className="text-[9px] text-slate-600">{new Date(req.timestamp).toLocaleTimeString()}</span>
                </div>
            </div>
        );
    });

    return (
        <div className="h-full flex flex-col bg-[#0a0a0c]">
            {/* Header */}
            <div className="flex items-center justify-between px-6 py-4 bg-[#0a0a0c] border-b border-white/[0.03]">
                <div className="flex items-center gap-4">
                    <div className={`w-3 h-3 rounded-full ${isRecording ? "bg-red-500 animate-pulse shadow-[0_0_10px_red]" : "bg-slate-700"}`}></div>
                    <h2 className="text-sm font-bold text-white">Proxy Recorder</h2>
                    <div className="flex items-center gap-2 bg-white/[0.02] px-3 py-1.5 rounded-lg border border-white/[0.03]">
                        <span className="text-[10px] font-bold text-slate-500 uppercase">Port</span>
                        <input
                            className="bg-transparent w-12 text-[10px] font-mono text-white outline-none text-center"
                            value={port}
                            onChange={(e) => setPort(parseInt(e.target.value) || 8888)}
                            disabled={isRecording}
                        />
                    </div>
                    <button
                        onClick={async () => {
                            try {
                                const certPem = await invoke<string>("export_ca_certificate");
                                const blob = new Blob([certPem], { type: "application/x-pem-file" });
                                const url = URL.createObjectURL(blob);
                                const a = document.createElement("a");
                                a.href = url;
                                a.download = "reqforge_ca.pem";
                                a.click();
                                URL.revokeObjectURL(url);
                            } catch (e) {
                                alert("Error exporting certificate: " + e);
                            }
                        }}
                        className="text-[10px] font-bold text-blue-400 hover:text-blue-300 transition-colors bg-blue-500/10 px-3 py-1.5 rounded-lg border border-blue-500/20"
                        title="Export CA certificate for browser trust"
                    >
                        Export CA
                    </button>
                </div>
                <div className="flex items-center gap-3">
                    <button onClick={clearRequests} className="text-[10px] font-bold text-slate-500 hover:text-white transition-colors">Clear</button>
                    <button
                        onClick={toggleRecording}
                        className={`px-4 py-2 rounded-xl text-[10px] font-black uppercase tracking-widest transition-all ${isRecording ? "bg-white/[0.05] text-white" : "bg-red-500 hover:bg-red-600 text-white shadow-lg shadow-red-500/20"}`}
                    >
                        {isRecording ? "Stop Recording" : "Start Recording"}
                    </button>
                </div>
            </div>

            <div className="flex-1 flex overflow-hidden">
                {/* Request List */}
                <div className="w-1/2 flex flex-col border-r border-white/[0.03]">
                    <div className="p-3 bg-[#0a0a0c] border-b border-white/[0.03] flex flex-col gap-3">
                        <div className="flex gap-3">
                            <input 
                                className="flex-1 bg-white/[0.02] border border-white/[0.03] rounded-lg px-3 py-2 text-xs text-white outline-none focus:border-slate-600"
                                placeholder="Filter URL..."
                                value={filter}
                                onChange={(e) => setFilter(e.target.value)}
                            />
                            <button 
                                onClick={() => setShowImages(!showImages)}
                                className={`px-3 py-2 rounded-lg text-xs font-bold transition-all border ${showImages ? "bg-white/[0.05] text-white border-white/[0.1]" : "text-slate-500 border-transparent hover:bg-white/[0.02]"}`}
                            >
                                Assets
                            </button>
                            <button 
                                onClick={() => setShowKeywordsMenu(!showKeywordsMenu)}
                                className={`px-3 py-2 rounded-lg text-xs font-bold transition-all border ${showKeywordsMenu ? "bg-yellow-500/20 text-yellow-400 border-yellow-500/30" : "text-slate-500 border-transparent hover:bg-white/[0.02]"}`}
                            >
                                Highlights
                            </button>
                        </div>
                        
                        {showKeywordsMenu && (
                            <div className="bg-white/[0.02] border border-white/[0.03] rounded-xl p-3 animate-in slide-in-from-top-2">
                                <div className="flex gap-2 mb-2">
                                    <input 
                                        className="flex-1 bg-black/20 border border-white/[0.05] rounded-lg px-2 py-1.5 text-[10px] text-white outline-none focus:border-yellow-500/50"
                                        placeholder="Add keyword (e.g. login)..."
                                        value={newKeyword}
                                        onChange={(e) => setNewKeyword(e.target.value)}
                                        onKeyDown={(e) => e.key === 'Enter' && addKeyword()}
                                    />
                                    <button onClick={addKeyword} className="bg-white/[0.05] hover:bg-white/[0.1] text-white px-3 rounded-lg text-[10px] font-bold">Add</button>
                                </div>
                                <div className="flex flex-wrap gap-1.5 max-h-24 overflow-y-auto custom-scrollbar">
                                    {keywords.map(k => (
                                        <span key={k} className="flex items-center gap-1.5 px-2 py-1 rounded bg-yellow-500/10 text-yellow-400 border border-yellow-500/20 text-[9px] font-bold">
                                            {k}
                                            <button onClick={() => removeKeyword(k)} className="hover:text-white transition-colors">×</button>
                                        </span>
                                    ))}
                                </div>
                            </div>
                        )}
                    </div>
                    <div 
                        ref={listRef}
                        className="flex-1 overflow-y-auto custom-scrollbar" 
                        style={{overflowAnchor: 'none'}}
                    >
                        {filteredRequests.map(r => (
                            <RequestItem 
                                key={r.id} 
                                req={r} 
                                isSelected={selectedReqId === r.id} 
                                onClick={setSelectedReqId} 
                                keywords={keywords}
                            />
                        ))}
                    </div>
                </div>

                {/* Details Panel */}
                <div className="w-1/2 flex flex-col bg-[#0a0a0c]">
                    {repeaterOpen ? (
                        <div className="flex-1 flex flex-col overflow-hidden">
                            {/* Repeater Header */}
                            <div className="p-4 border-b border-white/[0.03] bg-[#0a0a0c] shrink-0">
                                <div className="flex items-center justify-between mb-3">
                                    <div className="flex items-center gap-2">
                                        <div className="w-2 h-2 rounded-full bg-orange-500 shadow-[0_0_8px_rgba(249,115,22,0.5)]"></div>
                                        <span className="text-sm font-black text-orange-400 uppercase tracking-widest">Repeater</span>
                                    </div>
                                    <button onClick={() => setRepeaterOpen(false)} className="text-slate-500 hover:text-white transition-colors text-xs font-bold">
                                        Back to Inspector
                                    </button>
                                </div>
                                <div className="flex gap-2 mb-3">
                                    <select
                                        value={repeaterMethod}
                                        onChange={(e) => setRepeaterMethod(e.target.value)}
                                        className="bg-white/[0.02] border border-white/[0.05] rounded-lg px-3 py-2 text-xs font-bold text-white outline-none"
                                    >
                                        <option value="GET">GET</option>
                                        <option value="POST">POST</option>
                                        <option value="PUT">PUT</option>
                                        <option value="DELETE">DELETE</option>
                                        <option value="PATCH">PATCH</option>
                                        <option value="HEAD">HEAD</option>
                                        <option value="OPTIONS">OPTIONS</option>
                                    </select>
                                    <input
                                        value={repeaterUrl}
                                        onChange={(e) => setRepeaterUrl(e.target.value)}
                                        className="flex-1 bg-white/[0.02] border border-white/[0.05] rounded-lg px-3 py-2 text-xs font-mono text-white outline-none focus:border-orange-500/50"
                                        placeholder="https://example.com/api"
                                    />
                                </div>
                                <button
                                    onClick={sendRepeaterRequest}
                                    disabled={repeaterSending || !repeaterUrl}
                                    className="w-full bg-orange-500/20 hover:bg-orange-500/30 disabled:opacity-50 disabled:cursor-not-allowed text-orange-400 border border-orange-500/30 rounded-lg py-2.5 text-[10px] font-black uppercase tracking-widest transition-all shadow-sm flex items-center justify-center gap-2"
                                >
                                    {repeaterSending ? (
                                        <>
                                            <svg className="w-3 h-3 animate-spin" fill="none" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>
                                            Sending...
                                        </>
                                    ) : "Send Request"}
                                </button>
                            </div>

                            {/* Repeater Content */}
                            <div className="flex-1 flex flex-col min-h-0 overflow-hidden">
                                {/* Request Editor */}
                                <div className="flex-1 border-b border-white/[0.03] overflow-hidden flex flex-col min-h-0">
                                    <div className="px-4 py-2 bg-[#0a0a0c] border-b border-white/[0.03] flex items-center gap-2">
                                        <div className="w-1.5 h-1.5 rounded-full bg-blue-500"></div>
                                        <span className="text-[10px] font-black text-blue-400 uppercase tracking-widest">Request</span>
                                    </div>
                                    <div className="flex-1 overflow-y-auto p-4 custom-scrollbar space-y-4">
                                        <div>
                                            <h3 className="text-[9px] font-bold text-slate-500 uppercase mb-2 tracking-wider">Headers (one per line: Name: Value)</h3>
                                            <textarea
                                                value={repeaterHeaders}
                                                onChange={(e) => setRepeaterHeaders(e.target.value)}
                                                className="w-full h-28 bg-white/[0.02] border border-white/[0.05] rounded-xl p-3 text-[10px] font-mono text-slate-300 outline-none focus:border-blue-500/50 resize-none custom-scrollbar"
                                                placeholder="Content-Type: application/json&#10;Authorization: Bearer token"
                                            />
                                        </div>
                                        <div>
                                            <h3 className="text-[9px] font-bold text-slate-500 uppercase mb-2 tracking-wider">Body</h3>
                                            <textarea
                                                value={repeaterBody}
                                                onChange={(e) => setRepeaterBody(e.target.value)}
                                                className="w-full h-28 bg-white/[0.02] border border-white/[0.05] rounded-xl p-3 text-[10px] font-mono text-slate-300 outline-none focus:border-blue-500/50 resize-none custom-scrollbar"
                                                placeholder='{"key": "value"}'
                                            />
                                        </div>
                                    </div>
                                </div>

                                {/* Response Display */}
                                <div className="flex-1 overflow-hidden flex flex-col min-h-0">
                                    <div className="px-4 py-2 bg-[#0a0a0c] border-b border-white/[0.03] flex items-center justify-between">
                                        <div className="flex items-center gap-2">
                                            <div className="w-1.5 h-1.5 rounded-full bg-purple-500"></div>
                                            <span className="text-[10px] font-black text-purple-400 uppercase tracking-widest">Response</span>
                                        </div>
                                        {repeaterResponse && (
                                            <div className="flex items-center gap-3">
                                                <span className={`text-[10px] font-bold ${repeaterResponse.status >= 200 && repeaterResponse.status < 300 ? "text-emerald-400" : repeaterResponse.status >= 400 ? "text-red-400" : "text-yellow-400"}`}>
                                                    {repeaterResponse.status}
                                                </span>
                                                <span className="text-[10px] text-slate-500">{repeaterResponse.durationMs}ms</span>
                                            </div>
                                        )}
                                    </div>
                                    <div className="flex-1 overflow-y-auto p-4 custom-scrollbar">
                                        {repeaterError ? (
                                            <div className="bg-red-500/10 border border-red-500/20 rounded-xl p-4 text-red-400 text-xs font-mono">
                                                {repeaterError}
                                            </div>
                                        ) : repeaterResponse ? (
                                            <div className="space-y-4">
                                                <div>
                                                    <h3 className="text-[9px] font-bold text-slate-500 uppercase mb-2 tracking-wider">Response URL</h3>
                                                    <div className="bg-white/[0.02] rounded-xl p-3 border border-white/[0.03] flex items-center justify-between">
                                                        <span className="text-[10px] font-mono text-sky-400 break-all select-text">{repeaterResponse.responseUrl}</span>
                                                        <button
                                                            onClick={() => navigator.clipboard.writeText(repeaterResponse.responseUrl)}
                                                            className="p-1.5 bg-white/5 hover:bg-white/10 rounded-lg text-slate-500 transition-all ml-2 shrink-0"
                                                        >
                                                            <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M8 5H6a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2v-1M8 5a2 2 0 002 2h2a2 2 0 002-2M8 5a2 2 0 012-2h2a2 2 0 012 2m0 0h2a2 2 0 012 2v3m2 4H10m0 0l3-3m-3 3l3 3"></path></svg>
                                                        </button>
                                                    </div>
                                                </div>
                                                <div>
                                                    <h3 className="text-[9px] font-bold text-slate-500 uppercase mb-2 tracking-wider">Headers</h3>
                                                    <div className="bg-white/[0.02] rounded-xl p-3 border border-white/[0.03] space-y-1">
                                                        {Object.entries(repeaterResponse.headers).map(([k, v]) => (
                                                            <div key={k} className="text-[10px] font-mono flex gap-2">
                                                                <span className="text-slate-400 shrink-0 font-bold">{k}:</span>
                                                                <span className="text-slate-300 break-all select-text">{v}</span>
                                                            </div>
                                                        ))}
                                                    </div>
                                                </div>
                                                <div>
                                                    <h3 className="text-[9px] font-bold text-slate-500 uppercase mb-2 tracking-wider">Body ({Math.round(repeaterResponse.body.length / 1024)}KB)</h3>
                                                    <div className="bg-white/[0.02] rounded-xl p-3 border border-white/[0.03] text-[10px] font-mono text-slate-300 select-text max-h-64 overflow-y-auto custom-scrollbar">
                                                        <TruncatedBody body={repeaterResponse.body} />
                                                    </div>
                                                </div>
                                            </div>
                                        ) : (
                                            <div className="flex flex-col items-center justify-center h-full text-slate-600 opacity-50">
                                                <span className="text-xs font-bold uppercase tracking-widest">Send a request to see response</span>
                                            </div>
                                        )}
                                    </div>
                                </div>
                            </div>
                        </div>
                    ) : selectedReq ? (
                        <div className="flex-1 flex flex-col overflow-hidden">
                            {/* Toolbar */}
                            <div className="p-4 border-b border-white/[0.03] bg-[#0a0a0c] shrink-0">
                                <div className="text-xs font-mono text-emerald-400 break-all mb-3 select-text">{selectedReq.url}</div>
                                <div className="flex gap-2">
                                    <button onClick={sendToRepeater} className="flex-1 bg-orange-500/10 hover:bg-orange-500/20 text-orange-400 border border-orange-500/20 rounded-lg py-2.5 text-[10px] font-black uppercase tracking-widest transition-all shadow-sm">
                                        Send to Repeater
                                    </button>
                                    <div className="flex-1 relative">
                                        <button
                                            onClick={() => setShowImportMenu(!showImportMenu)}
                                            className="w-full bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 border border-emerald-500/20 rounded-lg py-2.5 text-[10px] font-black uppercase tracking-widest transition-all shadow-sm"
                                        >
                                            Import as Block ▾
                                        </button>
                                        {showImportMenu && (
                                            <div className="absolute top-full left-0 right-0 mt-1 bg-[#1a1a1f] border border-white/[0.1] rounded-lg overflow-hidden shadow-xl z-50">
                                                <button
                                                    onClick={() => importAsBlock("Request")}
                                                    className="w-full px-4 py-2.5 text-left text-[10px] font-bold text-slate-300 hover:bg-white/[0.05] transition-colors"
                                                >
                                                    🌐 HTTP Request
                                                </button>
                                                <button
                                                    onClick={() => importAsBlock("TlsRequest")}
                                                    className="w-full px-4 py-2.5 text-left text-[10px] font-bold text-slate-300 hover:bg-white/[0.05] transition-colors border-t border-white/[0.05]"
                                                >
                                                    🔐 Advanced TLS
                                                </button>
                                                <button
                                                    onClick={() => importAsBlock("TlsWreq")}
                                                    className="w-full px-4 py-2.5 text-left text-[10px] font-bold text-slate-300 hover:bg-white/[0.05] transition-colors border-t border-white/[0.05]"
                                                >
                                                    🛡️ Native TLS
                                                </button>
                                            </div>
                                        )}
                                    </div>
                                </div>
                            </div>

                            {/* Split View */}
                            <div className="flex-1 flex flex-col min-h-0">
                                {/* Request Section (Top) */}
                                <div className="flex-1 border-b border-white/[0.03] overflow-hidden flex flex-col min-h-0 bg-[#0a0a0c]/50">
                                    <div className="px-4 py-2 bg-[#0a0a0c] border-b border-white/[0.03] flex items-center gap-2 sticky top-0 z-10">
                                        <div className="w-1.5 h-1.5 rounded-full bg-blue-500 shadow-[0_0_8px_rgba(59,130,246,0.5)]"></div>
                                        <span className="text-[10px] font-black text-blue-400 uppercase tracking-widest">Request Payload</span>
                                    </div>
                                    <div className="flex-1 overflow-y-auto p-4 custom-scrollbar space-y-6">
                                        <div>
                                            <h3 className="text-[9px] font-bold text-slate-500 uppercase mb-2 tracking-wider">Headers</h3>
                                            <div className="bg-white/[0.02] rounded-xl p-3 border border-white/[0.03] space-y-1">
                                                {Object.entries(selectedReq.requestHeaders).map(([k, v]) => (
                                                    <div key={k} className="text-[10px] font-mono flex gap-2">
                                                        <span className="text-slate-400 shrink-0 font-bold">{k}:</span>
                                                        <span className="text-slate-300 break-all select-text">{v}</span>
                                                    </div>
                                                ))}
                                            </div>
                                        </div>
                                        {selectedReq.requestBody && (
                                            <div>
                                                <h3 className="text-[9px] font-bold text-slate-500 uppercase mb-2 tracking-wider">Body ({Math.round(selectedReq.requestBody.length / 1024)}KB)</h3>
                                                <div className="bg-white/[0.02] rounded-xl p-3 border border-white/[0.03] text-[10px] font-mono text-slate-300 select-text max-h-64 overflow-y-auto custom-scrollbar">
                                                    <TruncatedBody body={selectedReq.requestBody} />
                                                </div>
                                            </div>
                                        )}
                                    </div>
                                </div>

                                {/* Response Section (Bottom) */}
                                <div className="flex-1 overflow-hidden flex flex-col min-h-0 bg-[#0a0a0c]/50">
                                    <div className="px-4 py-2 bg-[#0a0a0c] border-b border-white/[0.03] flex items-center gap-2 sticky top-0 z-10">
                                        <div className="w-1.5 h-1.5 rounded-full bg-purple-500 shadow-[0_0_8px_rgba(168,85,247,0.5)]"></div>
                                        <span className="text-[10px] font-black text-purple-400 uppercase tracking-widest">Response Data</span>
                                    </div>
                                    <div className="flex-1 overflow-y-auto p-4 custom-scrollbar space-y-6">
                                        <div>
                                            <h3 className="text-[9px] font-bold text-slate-500 uppercase mb-2 tracking-wider">Headers</h3>
                                            <div className="bg-white/[0.02] rounded-xl p-3 border border-white/[0.03] space-y-1">
                                                {Object.entries(selectedReq.responseHeaders).map(([k, v]) => (
                                                    <div key={k} className="text-[10px] font-mono flex gap-2">
                                                        <span className="text-slate-400 shrink-0 font-bold">{k}:</span>
                                                        <span className="text-slate-300 break-all select-text">{v}</span>
                                                    </div>
                                                ))}
                                            </div>
                                        </div>
                                        {selectedReq.responseBody && (
                                            <div>
                                                <h3 className="text-[9px] font-bold text-slate-500 uppercase mb-2 tracking-wider">Body ({Math.round(selectedReq.responseBody.length / 1024)}KB)</h3>
                                                <div className="bg-white/[0.02] rounded-xl p-3 border border-white/[0.03] text-[10px] font-mono text-slate-300 select-text max-h-96 overflow-y-auto custom-scrollbar">
                                                    <TruncatedBody body={selectedReq.responseBody} />
                                                </div>
                                            </div>
                                        )}
                                    </div>
                                </div>
                            </div>
                        </div>
                    ) : (
                        <div className="flex-1 flex flex-col items-center justify-center text-slate-600 opacity-50">
                            <div className="w-16 h-16 rounded-2xl bg-white/[0.05] flex items-center justify-center mb-4">
                                <svg className="w-8 h-8 text-slate-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.5" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"></path><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.5" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"></path></svg>
                            </div>
                            <span className="text-xs font-bold uppercase tracking-widest">Select Request to Inspect</span>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
}

// --- Settings Tab ---

function SettingsTab({ settings, setSettings }: { settings: GlobalSettings, setSettings: (s: GlobalSettings) => void }) {
    const update = (updates: Partial<GlobalSettings>) => {
        setSettings({ ...settings, ...updates });
    };

    return (
        <div className="h-full flex flex-col bg-[#0a0a0c]">
            

            {/* Header */}
            <div className="relative z-30 px-8 pt-8 pb-6">
                <div className="max-w-3xl mx-auto">
                    <div className="flex items-center gap-3 mb-2">
                        <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-purple-500 to-slate-900 flex items-center justify-center shadow-lg shadow-purple-500/25">
                            <svg className="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"></path>
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"></path>
                            </svg>
                        </div>
                        <h1 className="text-2xl font-black text-white tracking-tight">Settings</h1>
                    </div>
                    <p className="text-slate-500 text-sm font-medium">Configure global defaults for your jobs</p>
                </div>
            </div>

            {/* Content */}
            <div className="flex-1 overflow-y-auto px-8 pb-8 relative z-10 custom-scrollbar">
                <div className="max-w-3xl mx-auto space-y-6">
                    {/* Job Defaults */}
                    <div className="bg-[#0a0a0c] backdrop-blur-sm rounded-2xl border border-white/[0.03] overflow-hidden">
                        <div className="p-5  bg-[#0a0a0c]">
                            <h3 className="text-sm font-bold text-slate-300 flex items-center gap-2">
                                <svg className="w-4 h-4 text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path>
                                </svg>
                                Job Defaults
                            </h3>
                        </div>
                        <div className="p-6 space-y-6">
                            <div className="grid grid-cols-2 gap-6">
                                <div>
                                    <label className="block text-[10px] font-bold text-slate-500 mb-2 uppercase tracking-wider">Default Bot Count</label>
                                    <input
                                        type="number"
                                        value={settings.defaultBotCount}
                                        onChange={(e) => update({ defaultBotCount: parseInt(e.target.value) || 1 })}
                                        className="w-full bg-white/[0.02] border border-slate-700 rounded-xl p-3 text-white focus:border-purple-500 outline-none transition-colors"
                                    />
                                    <p className="text-[10px] text-slate-600 mt-1">Number of concurrent workers</p>
                                </div>
                                <div>
                                    <label className="block text-[10px] font-bold text-slate-500 mb-2 uppercase tracking-wider">Ban Loop Evasion</label>
                                    <input
                                        type="number"
                                        value={settings.defaultBanLoopEvasion}
                                        onChange={(e) => update({ defaultBanLoopEvasion: parseInt(e.target.value) || 0 })}
                                        className="w-full bg-white/[0.02] border border-slate-700 rounded-xl p-3 text-white focus:border-purple-500 outline-none transition-colors"
                                    />
                                    <p className="text-[10px] text-slate-600 mt-1">Mark TOCHECK after X bans (0 = disabled)</p>
                                </div>
                                <div>
                                    <label className="block text-[10px] font-bold text-slate-500 mb-2 uppercase tracking-wider">Ban Save Interval</label>
                                    <input
                                        type="number"
                                        value={settings.defaultBanSaveInterval}
                                        onChange={(e) => update({ defaultBanSaveInterval: parseInt(e.target.value) || 0 })}
                                        className="w-full bg-white/[0.02] border border-slate-700 rounded-xl p-3 text-white focus:border-purple-500 outline-none transition-colors"
                                    />
                                    <p className="text-[10px] text-slate-600 mt-1">Save 1 banned every X bans</p>
                                </div>
                                <div>
                                    <label className="block text-[10px] font-bold text-slate-500 mb-2 uppercase tracking-wider">Default Retries until Ban</label>
                                    <input
                                        type="number"
                                        value={settings.defaultMaxRetriesAsBan || 3}
                                        onChange={(e) => update({ defaultMaxRetriesAsBan: parseInt(e.target.value) || 0 })}
                                        className="w-full bg-white/[0.02] border border-slate-700 rounded-xl p-3 text-white focus:border-purple-500 outline-none transition-colors"
                                    />
                                    <p className="text-[10px] text-slate-600 mt-1">Convert line to BAN after X failed retries</p>
                                </div>
                                <div>
                                    <label className="block text-[10px] font-bold text-slate-500 mb-2 uppercase tracking-wider">Max Banned Logs</label>
                                    <input
                                        type="number"
                                        value={settings.defaultMaxBannedLogs || 50}
                                        onChange={(e) => update({ defaultMaxBannedLogs: parseInt(e.target.value) || 0 })}
                                        className="w-full bg-white/[0.02] border border-slate-700 rounded-xl p-3 text-white focus:border-purple-500 outline-none transition-colors"
                                    />
                                    <p className="text-[10px] text-slate-600 mt-1">Maximum detailed banned logs to keep</p>
                                </div>
                            </div>
                        </div>
                    </div>

                    {/* Info Card */}
                    <div className="bg-[#0a0a0c] backdrop-blur-sm rounded-2xl border border-white/[0.03] overflow-hidden">
                        <div className="p-5  bg-[#0a0a0c]">
                            <h3 className="text-sm font-bold text-slate-300 flex items-center gap-2">
                                <svg className="w-4 h-4 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                                </svg>
                                Information
                            </h3>
                        </div>
                        <div className="p-6">
                            <div className="flex items-start gap-4">
                                <div className="w-10 h-10 rounded-xl bg-emerald-500/10 flex items-center justify-center flex-shrink-0">
                                    <svg className="w-5 h-5 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                                    </svg>
                                </div>
                                <div>
                                    <h4 className="font-bold text-white mb-1">Auto-Save Enabled</h4>
                                    <p className="text-slate-400 text-sm">Global settings are saved automatically to your browser's local storage. Changes here will not affect jobs that have already been created.</p>
                                </div>
                            </div>
                        </div>
                    </div>

                    {/* About Card */}
                    <div className="bg-[#0a0a0c] backdrop-blur-sm rounded-2xl border border-white/[0.03] overflow-hidden">
                        <div className="p-5  bg-[#0a0a0c]">
                            <h3 className="text-sm font-bold text-slate-300 flex items-center gap-2">
                                <svg className="w-4 h-4 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z"></path>
                                </svg>
                                About
                            </h3>
                        </div>
                        <div className="p-6">
                            <div className="flex items-center gap-4">
                                <div className="w-12 h-12 rounded-2xl bg-gradient-to-br from-slate-800 to-slate-900 flex items-center justify-center shadow-lg shadow-black/20">
                                    <span className="text-2xl font-black text-white">R</span>
                                </div>
                                <div>
                                    <h4 className="font-bold text-lg text-white">ReqForge</h4>
                                    <p className="text-slate-500 text-sm">Config-based HTTP automation engine</p>
                                </div>
                            </div>
                            <div className="mt-4 pt-4 ">
                                <div className="flex items-center gap-4 text-sm text-slate-500">
                                    <span className="flex items-center gap-1.5">
                                        <div className="w-2 h-2 rounded-full bg-emerald-500"></div>
                                        Ready
                                    </span>
                                    <span className="text-slate-700">•</span>
                                    <span>Built with Rust + Tauri</span>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
}



// --- Config Manager ---

function ConfigManager({ configs, setConfigs, view, setView, activeConfigId, setActiveConfigId, configLogs, setConfigLogs, onRefresh }: {
    configs: Config[],
    setConfigs: React.Dispatch<React.SetStateAction<Config[]>>,
    view: "list" | "editor",
    setView: (v: "list" | "editor") => void,
    activeConfigId: string | null,
    setActiveConfigId: (id: string | null) => void,
    configLogs: Record<string, ExecutionLog[]>,
    setConfigLogs: React.Dispatch<React.SetStateAction<Record<string, ExecutionLog[]>>>,
    onRefresh: () => Promise<void>
}) {

  // Config Templates - stored in Templates folder
  const [templates, setTemplates] = useState<{ id: string; name: string; description: string; blocks: Block[] }[]>([]);

  // Load templates from file system on mount, migrate from localStorage if needed
  useEffect(() => {
    const loadTemplates = async () => {
      try {
        const loaded = await invoke<any[]>('load_templates');
        const mapped = loaded.map(t => ({
          id: t.id,
          name: t.name,
          description: t.description || `${t.blocks?.length || 0} blocks`,
          blocks: t.blocks || []
        }));

        // Migrate localStorage templates to file system (one-time)
        const localStored = localStorage.getItem('configTemplates');
        if (localStored && !localStorage.getItem('templatesMigrated')) {
          try {
            const localTemplates = JSON.parse(localStored);
            const existingIds = new Set(mapped.map(t => t.id));
            for (const t of localTemplates) {
              // Skip default templates (they start with "default-")
              if (t.id.startsWith('default-')) continue;
              if (!existingIds.has(t.id)) {
                await invoke('save_template', { config: { ...t, lastModified: Date.now() } });
                mapped.push(t);
              }
            }
            localStorage.setItem('templatesMigrated', 'true');
            console.log('Migrated localStorage templates to file system');
          } catch (e) {
            console.error('Migration failed:', e);
          }
        }

        setTemplates(mapped);
      } catch (e) {
        console.error('Failed to load templates:', e);
      }
    };
    loadTemplates();
  }, []);

  const saveAsTemplate = async (config: Config) => {
    const newTemplate = {
      id: Math.random().toString(36).substring(2, 12),
      name: config.name,
      description: `${config.blocks.length} blocks`,
      blocks: config.blocks.map(b => ({ ...b, id: "t" + Math.random().toString(36).substring(2, 6) })),
      lastModified: Date.now()
    };
    try {
      await invoke('save_template', { config: newTemplate });
      setTemplates(prev => [...prev, newTemplate]);
    } catch (e) {
      console.error('Failed to save template:', e);
    }
  };

  const deleteTemplate = async (templateId: string) => {
    try {
      await invoke('delete_template', { templateId });
      setTemplates(prev => prev.filter(t => t.id !== templateId));
    } catch (e) {
      console.error('Failed to delete template:', e);
    }
  };

  const createConfig = () => {
    const newConfig: Config = {
      id: Math.random().toString(36).substring(2, 12),
      name: "New Configuration",
      blocks: [],
      lastModified: Date.now(),
    };
    setConfigs(prev => [newConfig, ...prev]);
    setConfigLogs(prev => ({ ...prev, [newConfig.id]: [] }));
    setActiveConfigId(newConfig.id);
    setView("editor");
    invoke("save_config", { config: newConfig }).catch(e => console.error("Auto-save failed", e));
  };

  const createFromTemplate = (templateIndex: number) => {
    const template = templates[templateIndex];
    const newBlocks = template.blocks.map(b => ({
      ...b,
      id: Math.random().toString(36).substring(2, 9)
    }));
    const newConfig: Config = {
      id: Math.random().toString(36).substring(2, 12),
      name: template.name,
      blocks: newBlocks,
      lastModified: Date.now(),
    };
    setConfigs(prev => [newConfig, ...prev]);
    setConfigLogs(prev => ({ ...prev, [newConfig.id]: [] }));
    setActiveConfigId(newConfig.id);
    setView("editor");
    invoke("save_config", { config: newConfig }).catch(e => console.error("Auto-save failed", e));
  };

  const cloneConfig = (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    const configToClone = configs.find(c => c.id === id);
    if (!configToClone) return;

    const newConfig: Config = {
        ...configToClone,
        id: Math.random().toString(36).substring(2, 12),
        name: `${configToClone.name} (Clone)`,
        lastModified: Date.now(),
    };

    setConfigs(prev => [newConfig, ...prev]);
    setConfigLogs(prev => ({ ...prev, [newConfig.id]: [] }));
    invoke("save_config", { config: newConfig }).catch(err => console.error("Clone failed", err));
  };

  const deleteConfig = async (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    if (confirm("Are you sure you want to delete this config?")) {
      setConfigs(prev => prev.filter(c => c.id !== id));
      setConfigLogs(prev => {
        const { [id]: _, ...rest } = prev;
        return rest;
      });
      try { await invoke("delete_config_file", { configId: id }); } catch (err) { console.error(err); }
      if (activeConfigId === id) {
        setActiveConfigId(null);
        setView("list");
      }
    }
  };

  const openConfig = (id: string) => {
    // Clear logs for the new config when switching (keeps other config logs intact)
    setConfigLogs(prev => ({ ...prev, [id]: [] }));
    setActiveConfigId(id);
    setView("editor");
  };

  const updateActiveConfig = (updates: Partial<Config>) => {
    if (!activeConfigId) return;
    setConfigs(prev => prev.map(c =>
      c.id === activeConfigId ? { ...c, ...updates, lastModified: Date.now() } : c
    ));
  };

  const saveConfigToFile = async (config: Config) => {
    try {
      await invoke("save_config", { config });
      alert(`Saved "${config.name}" to Configs folder!`);
    } catch (err) {
      alert(`Failed to save: ${err}`);
    }
  };

  const activeConfig = configs.find(c => c.id === activeConfigId);

  return (
    <div className="h-full w-full bg-white/[0.01] text-white font-sans overflow-hidden">
      {view === "list" ? (
        <ConfigListView
          configs={configs}
          onCreate={createConfig}
          onOpen={openConfig}
          onDelete={deleteConfig}
          onClone={cloneConfig}
          onSaveAsTemplate={saveAsTemplate}
          templates={templates}
          onCreateFromTemplate={createFromTemplate}
          onDeleteTemplate={deleteTemplate}
          onRefresh={onRefresh}
        />
      ) : activeConfig ? (
        <EditorView
          config={activeConfig}
          onUpdate={updateActiveConfig}
          onBack={() => setView("list")}
          onSave={saveConfigToFile}
          realTimeLogs={configLogs[activeConfig.id] || []}
          setRealTimeLogs={(logs) => setConfigLogs(prev => ({ ...prev, [activeConfig.id]: typeof logs === 'function' ? logs(prev[activeConfig.id] || []) : logs }))}
        />
      ) : (
        <div className="flex items-center justify-center h-full text-slate-500">
            <button onClick={() => setView("list")} className="bg-white/[0.02] px-4 py-2 rounded">Config not found. Go back.</button>
        </div>
      )}
    </div>
  );
}

function ConfigListView({ configs, onCreate, onOpen, onDelete, onClone, onSaveAsTemplate, templates, onCreateFromTemplate, onDeleteTemplate, onRefresh }: {
  configs: Config[],
  onCreate: () => void,
  onOpen: (id: string) => void,
  onDelete: (id: string, e: React.MouseEvent) => void,
  onClone: (id: string, e: React.MouseEvent) => void,
  onSaveAsTemplate?: (config: Config) => void,
  templates?: { id: string; name: string; description: string }[],
  onCreateFromTemplate?: (index: number) => void,
  onDeleteTemplate?: (id: string) => void,
  onRefresh: () => Promise<void>
}) {
  const [search, setSearch] = useState("");
  const [currentPage, setCurrentPage] = useState(1);
  const [showTemplates, setShowTemplates] = useState(false);
  const itemsPerPage = 15;

  const filteredConfigs = configs.filter(c =>
    c.name.toLowerCase().includes(search.toLowerCase())
  );

  const totalPages = Math.ceil(filteredConfigs.length / itemsPerPage);
  const startIndex = (currentPage - 1) * itemsPerPage;
  const paginatedConfigs = filteredConfigs.slice(startIndex, startIndex + itemsPerPage);

  useEffect(() => { setCurrentPage(1); }, [search]);

    const getBlockIcon = (type: string) => {
    const icons: Record<string, string> = {
      RandomUserAgent: "🕵️", Request: "🌐", Parse: "📝", KeyCheck: "🔑", Log: "📋", RandomString: "🎲",
      ConstantString: "📌", ConstantList: "📑", GetRandomItem: "🎯", Hash: "🔒",
      JumpIF: "↪️", JumpLabel: "🏷️", ClearCookies: "🍪", TlsRequest: "🔐", TlsWreq: "🛡️",
      Replace: "🔄", UrlEncode: "🔗", UrlDecode: "🔓"
    };
    return icons[type] || "⚡";
  };

  return (
    <div className="h-full flex flex-col bg-[#0a0a0c]">
      {/* Header */}
      <div className="relative z-30 px-8 pt-10 pb-6">
        <div className="max-w-7xl mx-auto">
          <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-6 mb-10">
            <div>
              <div className="flex items-center gap-4 mb-3">
                <div className="w-12 h-12 rounded-2xl bg-white/5 border border-white/[0.03] flex items-center justify-center shadow-2xl shadow-black backdrop-blur-md">
                  <svg className="w-6 h-6 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4"></path>
                  </svg>
                </div>
                <div>
                  <h1 className="text-3xl font-black text-white tracking-tight uppercase">Configuration Vault</h1>
                  <p className="text-slate-500 text-xs font-bold uppercase tracking-[0.2em] mt-1">Attack Logic & Module Management</p>
                </div>
              </div>
            </div>
            
            <div className="flex items-center gap-3">
              <button
                onClick={onRefresh}
                className="h-12 bg-white/5 hover:bg-white/10 text-white px-4 rounded-2xl font-black text-[11px] uppercase tracking-[0.2em] shadow-2xl shadow-black transition-all duration-500 hover:scale-[1.02] active:scale-95 flex items-center gap-2 border border-white/[0.03]"
                title="Refresh configs from disk"
              >
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2.5" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path>
                </svg>
                Refresh
              </button>
            <div className="relative group/create">
              <div className="flex items-center gap-0.5">
                <button
                  onClick={onCreate}
                  className="h-12 bg-white/5 hover:bg-white/10 text-white px-6 rounded-l-2xl font-black text-[11px] uppercase tracking-[0.2em] shadow-2xl shadow-black transition-all duration-500 hover:scale-[1.02] active:scale-95 flex items-center gap-3 border border-white/[0.03]"
                >
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2.5" d="M12 4v16m8-8H4"></path>
                  </svg>
                  Forge Config
                </button>
                {templates && templates.length > 0 && (
                  <button
                    onClick={() => setShowTemplates(!showTemplates)}
                    className="h-12 bg-white/10 hover:bg-white/20 text-white px-4 rounded-r-2xl font-bold text-sm border-l border-white/[0.03] transition-all duration-300 shadow-2xl shadow-black"
                  >
                    <svg className={`w-4 h-4 transition-transform duration-500 ${showTemplates ? 'rotate-180' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2.5" d="M19 9l-7 7-7-7"></path>
                    </svg>
                  </button>
                )}
              </div>
              
              {showTemplates && templates && onCreateFromTemplate && (
                <div className="absolute top-full right-0 mt-3 w-72 bg-[#0a0a0c]/90 backdrop-blur-2xl border border-slate-700 rounded-2xl shadow-[0_20px_50px_rgba(0,0,0,0.5)] z-50 overflow-hidden animate-in fade-in duration-300 ring-1 ring-white/[0.02]">
                  <div className="p-4 bg-white/5">
                    <span className="text-[10px] font-black text-slate-400 uppercase tracking-[0.2em]">Deployment Templates</span>
                  </div>
                  <div className="max-h-[24rem] overflow-y-auto custom-scrollbar">
                    {templates.map((t, i) => (
                      <div key={i} className="flex items-center  last:border-b-0 hover:bg-white/5 transition-all group/item">
                          <button
                              onClick={() => { onCreateFromTemplate(i); setShowTemplates(false); }}
                              className="flex-1 text-left px-5 py-4 outline-none"
                          >
                              <div className="text-[13px] font-black text-white group-hover/item:text-emerald-400 transition-colors uppercase tracking-wide">{t.name}</div>
                              <div className="text-[10px] text-slate-500 font-bold mt-1 opacity-80">{t.description}</div>
                          </button>
                          {onDeleteTemplate && (
                              <button
                                  onClick={(e) => { e.stopPropagation(); onDeleteTemplate(t.id); }}
                                  className="px-4 py-4 text-slate-600 hover:text-red-400 transition-colors opacity-0 group-hover/item:opacity-100"
                              >
                                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2.5" d="M6 18L18 6M6 6l12 12"></path></svg>
                              </button>
                          )}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
            </div>
          </div>

          {/* Search & Stats Bar */}
          <div className="flex flex-col lg:flex-row lg:items-center gap-6">
            <div className="flex-1 relative group">
              <div className="absolute inset-0 bg-white/[0.01] rounded-2xl blur-2xl opacity-0 group-focus-within:opacity-100 transition-opacity duration-500"></div>
              <div className="relative flex items-center">
                <svg className="absolute left-5 w-5 h-5 text-slate-500 group-focus-within:text-emerald-500 transition-colors" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2.5" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"></path>
                </svg>
                <input
                  type="text"
                  placeholder="Search vault by name or identifier..."
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  className="w-full bg-[#0a0a0c]/80 backdrop-blur-xl border border-white/[0.02] rounded-2xl py-4 pl-14 pr-4 text-sm text-white placeholder-slate-600 focus:outline-none focus:border-white/[0.05]/30 focus:bg-[#0a0a0c] transition-all duration-500 shadow-2xl shadow-black/40"
                />
              </div>
            </div>

            <div className="flex items-center gap-8 px-6 py-4 bg-white/[0.01]/30 border border-white/[0.02] rounded-2xl backdrop-blur-md">
              <div className="flex items-center gap-3">
                <div className="w-2 h-2 rounded-full bg-white/[0.05] animate-pulse shadow-[0_0_8px_rgba(59,130,246,0.8)]"></div>
                <div>
                  <p className="text-[10px] font-black text-slate-500 uppercase tracking-widest leading-none">Stored</p>
                  <p className="text-sm font-black text-white mt-1">{configs.length} Configs</p>
                </div>
              </div>
              <div className="h-8 w-px bg-white/[0.02]"></div>
              <div className="flex items-center gap-3">
                <div className="w-2 h-2 rounded-full bg-purple-500 shadow-[0_0_8px_rgba(168,85,247,0.8)]"></div>
                <div>
                  <p className="text-[10px] font-black text-slate-500 uppercase tracking-widest leading-none">Complexity</p>
                  <p className="text-sm font-black text-white mt-1">{configs.reduce((acc, c) => acc + c.blocks.length, 0)} Units</p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Config Content */}
      <div className="flex-1 overflow-y-auto px-8 pb-12 custom-scrollbar relative z-10">
        <div className="max-w-7xl mx-auto">
          {filteredConfigs.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-32 bg-[#0a0a0c]/20 border border-white/[0.02] rounded-[2.5rem] border-dashed transition-all duration-500">
              <div className="w-24 h-24 rounded-[2rem] bg-gradient-to-br from-slate-800 to-slate-900 border border-slate-700 flex items-center justify-center mb-8 shadow-inner relative group">
                <div className="absolute inset-0 bg-white/[0.01] blur-2xl rounded-full group-hover:bg-emerald-500/10 transition-colors"></div>
                <svg className="w-10 h-10 text-slate-600 relative z-10 group-hover:text-slate-400 transition-colors" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.5" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"></path>
                </svg>
              </div>
              <h3 className="text-slate-300 font-black text-lg uppercase tracking-[0.2em] mb-2">{search ? "Search Exhausted" : "Vault Empty"}</h3>
              <p className="text-slate-600 text-[11px] font-bold uppercase tracking-widest max-w-xs text-center leading-relaxed">
                {search 
                    ? "The specified identifier does not exist within the configuration vault." 
                    : "No attack logic has been compiled. Forge your first configuration to begin operations."}
              </p>
            </div>
          ) : (
            <div className="space-y-3">
                {/* Header Row */}
                <div className="px-8 py-4 flex items-center text-[10px] font-black text-slate-500 uppercase tracking-[0.2em] bg-white/[0.02] rounded-2xl border border-white/[0.03] mb-4">
                    <div className="flex-[2]">Identity</div>
                    <div className="flex-1">Architecture</div>
                    <div className="flex-1">Last Compiled</div>
                    <div className="w-40 text-right">Directives</div>
                </div>

                {paginatedConfigs.map(config => (
                    <div 
                        key={config.id} 
                        onClick={() => onOpen(config.id)}
                        className="group flex items-center px-8 py-5 bg-[#0a0a0c] backdrop-blur-xl border border-white/[0.03] hover:border-white/[0.08] rounded-2xl cursor-pointer transition-all duration-300 hover:scale-[1.01] hover:shadow-[0_20px_50px_rgba(0,0,0,0.5)]"
                    >
                        <div className="flex-[2] flex items-center gap-4">
                            <div className="w-10 h-10 rounded-xl bg-white/[0.03] border border-white/[0.03] flex items-center justify-center text-sm shadow-lg group-hover:scale-110 group-hover:rotate-3 transition-all duration-500">
                                {config.blocks.length > 0 ? getBlockIcon(config.blocks[0].block_type) : "⚙️"}
                            </div>
                            <div>
                                <div className="font-black text-base text-white group-hover:text-emerald-400 transition-colors uppercase tracking-tight leading-none mb-1.5">{config.name}</div>
                                <div className="text-[9px] font-black text-slate-600 uppercase tracking-[0.2em] flex items-center gap-2">
                                    <span className="w-1 h-1 rounded-full bg-white/[0.02]"></span>
                                    UUID: {config.id.substring(0, 12)}
                                </div>
                            </div>
                        </div>

                        <div className="flex-1 flex items-center gap-4">
                            <div className="px-2.5 py-1 rounded-lg bg-emerald-500/5 border border-emerald-500/20 text-[10px] font-black text-emerald-400 uppercase tracking-widest">
                                {config.blocks.length} Modules
                            </div>
                            <div className="flex -space-x-1.5 overflow-hidden grayscale opacity-50 group-hover:grayscale-0 group-hover:opacity-100 transition-all">
                                {config.blocks.slice(0, 4).map((b, i) => (
                                    <div key={i} className="w-6 h-6 rounded-full bg-slate-950 border border-white/[0.03] flex items-center justify-center text-[10px] shadow-sm ring-2 ring-[#0d0d0f]" title={b.block_type}>
                                        {getBlockIcon(b.block_type)}
                                    </div>
                                ))}
                            </div>
                        </div>

                        <div className="flex-1">
                            <div className="text-xs text-slate-300 font-black uppercase tracking-tighter">
                                {new Date(config.lastModified).toLocaleDateString(undefined, {month: 'short', day: 'numeric', year: 'numeric'})}
                            </div>
                            <div className="text-[10px] text-slate-600 font-black mt-1 uppercase tracking-widest">
                                Telemetry: {new Date(config.lastModified).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})}
                            </div>
                        </div>

                        <div className="w-40 flex justify-end gap-2 opacity-0 group-hover:opacity-100 translate-x-4 group-hover:translate-x-0 transition-all duration-300">
                            {onSaveAsTemplate && (
                                <button
                                    onClick={(e) => { e.stopPropagation(); onSaveAsTemplate(config); }}
                                    className="w-9 h-9 rounded-xl bg-white/5 text-slate-400 hover:text-emerald-400 hover:bg-emerald-500/10 border border-white/[0.03] flex items-center justify-center transition-all"
                                >
                                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2.5" d="M8 7H5a2 2 0 00-2 2v9a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-3m-1 4l-3 3m0 0l-3-3m3 3V4"></path></svg>
                                </button>
                            )}
                            <button
                                onClick={(e) => { e.stopPropagation(); onClone(config.id, e); }}
                                className="w-9 h-9 rounded-xl bg-white/5 text-slate-400 hover:text-white hover:bg-white/10 border border-white/[0.03] flex items-center justify-center transition-all"
                            >
                                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2.5" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"></path></svg>
                            </button>
                            <button
                                onClick={(e) => { e.stopPropagation(); onDelete(config.id, e); }}
                                className="w-9 h-9 rounded-xl bg-white/5 text-slate-400 hover:text-red-400 hover:bg-red-500/10 border border-white/[0.03] flex items-center justify-center transition-all"
                            >
                                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2.5" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path></svg>
                            </button>
                        </div>
                    </div>
                ))}
            </div>
          )}
        </div>
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="relative z-10 px-8 py-4  bg-[#0a0a0c]/40 backdrop-blur-sm">
          <div className="max-w-7xl mx-auto flex justify-center items-center gap-2">
            <button
              onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
              disabled={currentPage === 1}
              className="px-4 py-2 rounded-xl text-slate-500 hover:text-white disabled:opacity-30 disabled:cursor-not-allowed transition-colors font-bold text-[10px] uppercase tracking-widest"
            >
              Previous
            </button>
            <div className="flex gap-1">
              {Array.from({ length: totalPages }, (_, i) => i + 1).map(page => (
                <button
                  key={page}
                  onClick={() => setCurrentPage(page)}
                  className={`w-8 h-8 rounded-lg font-mono text-xs transition-all ${currentPage === page ? 'bg-emerald-500 text-white shadow-lg shadow-black/20' : 'text-slate-500 hover:bg-white/5 hover:text-slate-300'}`}
                >
                  {page}
                </button>
              ))}
            </div>
            <button
              onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
              disabled={currentPage === totalPages}
              className="px-4 py-2 rounded-xl text-slate-500 hover:text-white disabled:opacity-30 disabled:cursor-not-allowed transition-colors font-bold text-[10px] uppercase tracking-widest"
            >
              Next
            </button>
          </div>
        </div>
      )}
    </div>
  )
}

// --- Config Manager Components ---

function SortableComfortBlock({ block, idx, isSelected, isActive, onClick, onMove, onClone, onDelete, getIcon }: {
    block: Block, 
    idx: number, 
    isSelected: boolean,
    isActive: boolean,
    onClick: () => void,
    onMove: (dir: 'up' | 'down') => void,
    onClone: () => void,
    onDelete: () => void,
    getIcon: (type: string) => string
}) {
    const {
        attributes,
        listeners,
        setNodeRef,
        transform,
        transition,
        isDragging
    } = useSortable({ id: block.id });

    const style = {
        transform: CSS.Transform.toString(transform),
        transition,
        zIndex: isDragging ? 50 : undefined,
        opacity: isDragging ? 0.5 : 1,
    };

    const isDisabled = block.data.disabled || false;

    const getCategoryColor = (type: string) => {
        if (["Request", "TlsRequest", "TlsWreq"].includes(type)) return "bg-blue-500";
        if (["Parse", "KeyCheck"].includes(type)) return "bg-amber-500";
        if (["ConstantString", "ConstantList", "RandomString", "RandomInteger", "GetRandomItem"].includes(type)) return "bg-purple-500";
        if (["Base64Encode", "Base64Decode", "Hash", "Replace", "ToLowercase", "ToUppercase", "Translate", "UrlEncode", "UrlDecode", "EncodeHtmlEntities", "DecodeHtmlEntities", "ZipLists", "HmacSign", "AesEncrypt", "AesDecrypt", "Pbkdf2Derive", "RsaEncrypt", "BytesToBase64", "Base64ToBytes", "GenerateGuid", "GenerateUUID4", "GenerateCodeVerifier", "GenerateCodeChallenge", "GenerateState", "GenerateNonce", "RandomUserAgent", "CurrentUnixTime", "DateToUnixTime", "UnixTimeToDate", "UnixTimeToIso8601"].includes(type)) return "bg-emerald-500";
        if (["JumpIF", "JumpLabel", "ClearCookies", "Delay"].includes(type)) return "bg-orange-500";
                    if (["ForgeRockAuth", "Checksum"].includes(type)) return "bg-red-500";        return "bg-white/[0.05]";
    };

    const getCategoryTextColor = (type: string) => {
        if (["Request", "TlsRequest", "TlsWreq"].includes(type)) return "text-blue-400";
        if (["Parse", "KeyCheck"].includes(type)) return "text-amber-400";
        if (["ConstantString", "ConstantList", "RandomString", "RandomInteger", "GetRandomItem"].includes(type)) return "text-purple-400";
        if (["Base64Encode", "Base64Decode", "Hash", "Replace", "ToLowercase", "ToUppercase", "Translate", "UrlEncode", "UrlDecode", "EncodeHtmlEntities", "DecodeHtmlEntities", "ZipLists", "HmacSign", "AesEncrypt", "AesDecrypt", "Pbkdf2Derive", "RsaEncrypt", "BytesToBase64", "Base64ToBytes", "GenerateGuid", "GenerateUUID4", "GenerateCodeVerifier", "GenerateCodeChallenge", "GenerateState", "GenerateNonce", "RandomUserAgent", "CurrentUnixTime", "DateToUnixTime", "UnixTimeToDate", "UnixTimeToIso8601"].includes(type)) return "text-emerald-400";
        if (["JumpIF", "JumpLabel", "ClearCookies", "Delay"].includes(type)) return "text-orange-400";
        if (["ForgeRockAuth", "Checksum"].includes(type)) return "text-red-400";
        return "text-slate-400";
    };

    const catColor = getCategoryColor(block.block_type);
    const textColor = getCategoryTextColor(block.block_type);

    return (
        <div
            ref={setNodeRef}
            style={style}
            onClick={onClick}
            className={`group relative mx-2 my-1 p-2 rounded-xl transition-all duration-200 border ${
                isSelected 
                ? 'bg-white/[0.08] border-white/[0.08] shadow-xl ring-1 ring-white/[0.05]' 
                : 'bg-white/[0.01] hover:bg-white/[0.03] border-white/[0.03] hover:border-white/[0.03]'
            } ${isActive ? 'ring-2 ring-emerald-500' : ''} ${isDisabled ? 'opacity-30 grayscale' : ''}`}
        >
            <div className="flex items-center gap-3 relative z-10">
                {/* Drag Handle */}
                <div
                    {...attributes}
                    {...listeners}
                    className="text-slate-700 hover:text-slate-400 cursor-grab active:cursor-grabbing"
                    onClick={(e) => e.stopPropagation()}
                >
                    <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2.5" d="M4 8h16M4 16h16"></path>
                    </svg>
                </div>

                {/* Minimal Icon Box */}
                <div className="flex items-center gap-2">
                    <div className={`w-1.5 h-1.5 rounded-full ${catColor} shadow-[0_0_8px_${catColor}]`}></div>
                    <span className="text-sm grayscale group-hover:grayscale-0 transition-all">{getIcon(block.block_type)}</span>
                </div>

                {/* Main Content Area - Horizontal Layout */}
                <div className="flex-1 min-w-0 flex items-center gap-3">
                    <div className="flex items-center gap-2 shrink-0">
                        <span className="text-[9px] font-black font-mono text-slate-700">#{idx + 1}</span>
                        <span className={`font-black text-xs uppercase tracking-tight ${isSelected ? 'text-white' : textColor} transition-colors`}>
                            {getBlockName(block.block_type)}
                        </span>
                    </div>

                    {/* Inline Parameters - Very Compact */}
                    <div className="flex-1 min-w-0 flex items-center gap-2 text-[10px] font-mono">
                        {block.block_type === "Request" || block.block_type === "TlsRequest" || block.block_type === "TlsWreq" ? (
                            <div className="flex items-center gap-2 truncate">
                                <span className="text-emerald-400 font-black">{(block.data.method || block.data.request_method || "GET")}</span>
                                <span className="text-white truncate font-medium">{block.data.url || block.data.request_url}</span>
                            </div>
                        ) : block.block_type === "Parse" ? (
                            <div className="flex items-center gap-1.5 truncate">
                                <span className="text-pink-400 font-bold">({block.data.variable})</span>
                                <span className="text-white">:</span>
                                <span className="text-emerald-400 font-bold">{block.data.mode}</span>
                                <span className="text-slate-600 font-normal">from</span>
                                <span className="text-white font-medium">{block.data.source}</span>
                            </div>
                        ) : block.block_type === "KeyCheck" ? (
                            <span className="text-emerald-400 font-bold">{(block.data.keychains?.length || 0)} KEYCHAINS</span>
                        ) : block.block_type === "JumpIF" ? (
                            <div className="flex items-center gap-1.5">
                                <span className="text-pink-400 font-bold">JUMP</span>
                                <span className="text-white">→</span>
                                <span className="text-emerald-400 font-black">#{(block.data.jump_chains?.[0]?.target) || block.data.target}</span>
                            </div>
                        ) : block.block_type === "JumpLabel" ? (
                            <div className="flex items-center gap-1.5">
                                <span className="text-pink-400 font-bold uppercase">LABEL</span>
                                <span className="text-white">:</span>
                                <span className="text-emerald-400 font-black">#{block.data.label}</span>
                            </div>
                        ) : block.block_type === "Delay" ? (
                            <div className="flex items-center gap-1.5">
                                <span className="text-pink-400 font-bold">WAIT</span>
                                <span className="text-white">:</span>
                                <span className="text-emerald-400 font-black">{block.data.milliseconds}MS</span>
                            </div>
                        ) : block.block_type === "ClearCookies" ? (
                            <span className="text-red-400 font-bold uppercase tracking-widest">WIPE COOKIE JAR</span>
                        ) : block.block_type === "Script" ? (
                            <span className="text-emerald-400 font-bold uppercase tracking-widest">RHAI SCRIPT</span>
                                                    ) : ["Hash", "HmacSign", "AesEncrypt", "AesDecrypt", "Pbkdf2Derive", "RsaEncrypt", "Base64Encode", "Base64Decode", "UrlEncode", "UrlDecode", "BytesToBase64", "Base64ToBytes", "EncodeHtmlEntities", "DecodeHtmlEntities", "RandomString", "ConstantString", "ConstantList", "RandomInteger", "GetRandomItem", "CurrentUnixTime", "DateToUnixTime", "UnixTimeToDate", "UnixTimeToIso8601", "GenerateUUID4", "GenerateGuid", "GenerateState", "GenerateNonce", "RandomUserAgent", "Checksum", "ForgeRockAuth", "Translate", "ToLowercase", "ToUppercase"].includes(block.block_type) ? (                            <div className="flex items-center gap-1.5 truncate">
                                <span className="text-pink-400 font-bold">({block.data.variable || block.data.output_variable})</span>
                                <span className="text-white">:</span>
                                <span className="text-emerald-400 font-black">
                                    {block.block_type === "ConstantString" ? (block.data.value?.length > 20 ? block.data.value.substring(0, 20) + '...' : block.data.value) : 
                                     block.block_type === "RandomString" ? block.data.mask : "DYNAMIC"}
                                </span>
                            </div>
                        ) : null}
                    </div>
                </div>

                {/* Actions - Integrated inline */}
                <div className="flex gap-0.5 opacity-0 group-hover:opacity-100 transition-all duration-200">
                    <button onClick={(e) => {e.stopPropagation(); onMove('up')}} className="w-6 h-6 flex items-center justify-center rounded-md hover:bg-white/10 text-slate-500 hover:text-white transition-all">
                        <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2.5" d="M5 15l7-7 7 7"></path></svg>
                    </button>
                    <button onClick={(e) => {e.stopPropagation(); onMove('down')}} className="w-6 h-6 flex items-center justify-center rounded-md hover:bg-white/10 text-slate-500 hover:text-white transition-all">
                        <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2.5" d="M19 9l-7 7-7-7"></path></svg>
                    </button>
                    <button onClick={(e) => {e.stopPropagation(); onClone()}} className="w-6 h-6 flex items-center justify-center rounded-md hover:bg-white/10 text-slate-500 hover:text-white transition-all">
                        <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2.5" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"></path></svg>
                    </button>
                    <button onClick={(e) => {e.stopPropagation(); onDelete()}} className="w-6 h-6 flex items-center justify-center rounded-md hover:bg-red-500/20 text-slate-500 hover:text-red-400 transition-all">
                        <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2.5" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path></svg>
                    </button>
                </div>
            </div>
        </div>
    );
}


function CodeEditor({ config, onUpdate }: { config: Config, onUpdate: (updates: Partial<Config>) => void }) {
    const [code, setCode] = useState(JSON.stringify(config, null, 2));
    const [error, setError] = useState<string | null>(null);

    useEffect(() => {
        setCode(JSON.stringify(config, null, 2));
    }, [config]);

    const handleChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
        const newVal = e.target.value;
        setCode(newVal);
        try {
            const parsed = JSON.parse(newVal);
            setError(null);
            // Basic validation
            if (!parsed.blocks || !Array.isArray(parsed.blocks)) {
                throw new Error("Config must have a 'blocks' array");
            }
            onUpdate(parsed);
        } catch (err) {
            if (err instanceof Error) {
                setError(err.message);
            } else {
                setError("Invalid JSON");
            }
        }
    };

    return (
        <div className="h-full flex flex-col bg-[#0a0a0c] relative">
            <textarea
                className="flex-1 w-full bg-transparent p-4 font-mono text-xs text-slate-300 outline-none resize-none custom-scrollbar"
                value={code}
                onChange={handleChange}
                spellCheck={false}
            />
            {error && (
                <div className="absolute bottom-4 left-4 right-4 bg-red-500/10 border border-red-500 text-red-400 p-2 rounded text-xs">
                    {error}
                </div>
            )}
        </div>
    );
}





function BlueprintEditor({ config, onUpdate, onSelectBlock, executionLogs = [] }: { config: Config, onUpdate: (updates: Partial<Config>) => void, onSelectBlock: (id: string | null) => void, executionLogs?: ExecutionLog[] }) {


    const [nodes, setNodes, onNodesChange] = useNodesState<Node>([]);


    const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([]);





    // Sync Blocks to Nodes/Edges


    useEffect(() => {


        const newNodes: Node[] = [];


        const newEdges: Edge[] = [];


        const storedLayout = config.blueprint?.layout || {};





        // Helper to get real ID from 1-based index string


        const getRealId = (idxStr: string | undefined) => {


            if (!idxStr) return null;


            const idx = parseInt(idxStr) - 1;


            if (idx >= 0 && idx < config.blocks.length) {


                return config.blocks[idx].id;


            }


            return null;


        };





        // Calculate statuses from logs


        const blockStatuses = new Map<string, string>();


        // Calculate active edges from logs


        const activeEdgeIds = new Set<string>();


        


        for (let i = 0; i < executionLogs.length; i++) {


            const current = executionLogs[i];


            


            // Map status


            if (current.block_id) {


                const realId = getRealId(current.block_id);


                if (realId) {


                    blockStatuses.set(realId, current.status);


                }


            }





            // Map edges


            if (i < executionLogs.length - 1) {


                const next = executionLogs[i+1];


                if (current.block_id && next.block_id) {


                    const currentId = getRealId(current.block_id);


                    const nextId = getRealId(next.block_id);


                    


                    if (currentId && nextId) {


                        activeEdgeIds.add(`e-${currentId}-${nextId}`);


                        activeEdgeIds.add(`j-${currentId}-${nextId}`);


                    }


                }


            }


        }





                config.blocks.forEach((block, index) => {





                    const position = storedLayout[block.id] || { x: 100, y: index * 150 };





                    





                    // Determine Node Styling based on Status - matching Modal aesthetic





                    const status = blockStatuses.get(block.id);





                    let borderColor = status ? '#10b981' : 'rgba(255, 255, 255, 0.1)'; 





                    let bgColor = status ? '#064e3b' : 'rgba(255, 255, 255, 0.02)';





                    let textColor = '#ffffff';





        





                    if (status === 'Success') { 





                        borderColor = '#10b981'; // emerald-500





                        bgColor = 'rgba(16, 185, 129, 0.1)';





                    } else if (status === 'Fail' || status === 'Error') {





                        borderColor = '#ef4444'; // red-500





                        bgColor = 'rgba(239, 68, 68, 0.1)';





                    } else if (status === 'BAN') {





                        borderColor = '#f97316'; // orange-500





                        bgColor = 'rgba(249, 115, 22, 0.1)';





                    } else if (status === 'RETRY') {





                        borderColor = '#eab308'; // yellow-500





                        bgColor = 'rgba(234, 179, 8, 0.1)';





                    }





        





                    newNodes.push({





                        id: block.id,





                        position,





                        data: { label: `#${index + 1} ${block.block_type}`, block },





                        style: { 





                            background: bgColor, 





                            color: textColor, 





                            border: `1px solid ${borderColor}`, 





                            borderRadius: '12px',





                            padding: '12px 16px',





                            minWidth: '200px',





                            boxShadow: status ? `0 0 20px ${borderColor}20` : '0 10px 15px -3px rgba(0, 0, 0, 0.5)',





                            fontFamily: 'monospace',





                            fontSize: '12px',





                            backdropFilter: 'blur(12px)',





                            transition: 'all 0.3s ease'





                        },





                        type: 'default'





                    });





            // Sequential Edges


            if (index < config.blocks.length - 1) {


                const edgeId = `e-${block.id}-${config.blocks[index+1].id}`;


                const isActive = activeEdgeIds.has(edgeId);


                newEdges.push({


                    id: edgeId,


                    source: block.id,


                    target: config.blocks[index+1].id,


                    type: 'default', // Bezier curve like UE


                    animated: isActive,


                    style: { 


                        stroke: isActive ? '#f59e0b' : '#94a3b8', 


                        strokeWidth: isActive ? 3 : 2,


                        filter: isActive ? 'drop-shadow(0 0 4px #f59e0b)' : undefined


                    }


                });


            }





            // Jump Edges


            if (block.block_type === 'JumpIF') {
                // Support both old format (single target) and new format (jump_chains)
                const jumpTargets: string[] = [];

                if (block.data.jump_chains && block.data.jump_chains.length > 0) {
                    // New format: collect targets from all jump chains
                    block.data.jump_chains.forEach((jc: JumpChain) => {
                        if (jc.target && !jumpTargets.includes(jc.target)) {
                            jumpTargets.push(jc.target);
                        }
                    });
                } else if (block.data.target) {
                    // Old format: single target
                    jumpTargets.push(block.data.target);
                }

                jumpTargets.forEach((targetLabel, idx) => {
                    const targetBlock = config.blocks.find(b => b.block_type === 'JumpLabel' && b.data.label === targetLabel);

                    if (targetBlock) {
                        const edgeId = `j-${block.id}-${targetBlock.id}-${idx}`;
                        const isActive = activeEdgeIds.has(edgeId);

                        newEdges.push({
                            id: edgeId,
                            source: block.id,
                            target: targetBlock.id,
                            type: 'default',
                            label: jumpTargets.length > 1 ? `→ ${targetLabel}` : 'True',
                            labelStyle: { fill: isActive ? '#f59e0b' : '#cbd5e1', fontWeight: 700 },
                            labelBgStyle: { fill: '#1e293b', fillOpacity: 0.8 },
                            animated: isActive,
                            style: {
                                stroke: isActive ? '#f59e0b' : '#eab308',
                                strokeWidth: isActive ? 3 : 2,
                                strokeDasharray: '5,5',
                                filter: isActive ? 'drop-shadow(0 0 4px #f59e0b)' : undefined
                            },
                            markerEnd: { type: MarkerType.ArrowClosed, color: isActive ? '#f59e0b' : '#eab308' }
                        });
                    }
                });
            }


        });





        setNodes(newNodes);


        setEdges(newEdges);


    }, [config.blocks, executionLogs]); 





    const onNodeDragStop = useCallback((_event: React.MouseEvent, node: Node) => {


        const layout = { ...config.blueprint?.layout, [node.id]: node.position };


        onUpdate({ blueprint: { ...config.blueprint, layout } });


    }, [config, onUpdate]);





    const onNodeClick = useCallback((_event: React.MouseEvent, node: Node) => {


        onSelectBlock(node.id);


    }, [onSelectBlock]);





    const onNodesDelete = useCallback((nodesToDelete: Node[]) => {


        const idsToDelete = new Set(nodesToDelete.map(n => n.id));


        const newBlocks = config.blocks.filter(b => !idsToDelete.has(b.id));


        if (newBlocks.length !== config.blocks.length) {


            onUpdate({ blocks: newBlocks });


            onSelectBlock(null);


        }


    }, [config.blocks, onUpdate, onSelectBlock]);





        return (





            <div className="h-full w-full bg-[#0a0a0c]">





                <ReactFlow





                    nodes={nodes}





                    edges={edges}





                    onNodesChange={onNodesChange}





                    onEdgesChange={onEdgesChange}





                    onNodeDragStop={onNodeDragStop}





                    onNodeClick={onNodeClick}





                    onNodesDelete={onNodesDelete}





                    fitView





                    minZoom={0.1}





                    proOptions={{ hideAttribution: true }}





                >





                    <Background variant={BackgroundVariant.Dots} color="rgba(255, 255, 255, 0.05)" gap={24} size={1} />





                    <Panel position="top-right" className="bg-[#0a0a0c]/80 p-2 rounded-lg text-[10px] font-black text-slate-500 backdrop-blur-md border border-white/[0.03] uppercase tracking-widest">


                    <div>Drag to arrange</div>


                    <div>Click to edit</div>


                    <div className="flex items-center gap-1 mt-1">


                        <span className="w-2 h-2 rounded-full bg-slate-400"></span> Standard


                        <span className="w-2 h-2 rounded-full bg-amber-500 ml-1"></span> Jump


                    </div>


                </Panel>


            </ReactFlow>


        </div>


    );


}





const TLS_CLIENT_IDENTIFIERS = [
    "random",
    "custom",
    // Chrome
    "chrome_103", "chrome_104", "chrome_105", "chrome_106", "chrome_107", "chrome_108", "chrome_109", "chrome_110", "chrome_111", "chrome_112", 
    "chrome_116_PSK", "chrome_116_PSK_PQ", "chrome_117", "chrome_120", "chrome_124", "chrome_130_PSK", "chrome_131", "chrome_131_PSK", "chrome_133", "chrome_133_PSK",
    "chrome_144", "chrome_144_PSK", "chrome_146", "chrome_146_PSK",
    // Firefox
    "firefox_102", "firefox_104", "firefox_105", "firefox_106", "firefox_108", "firefox_110", "firefox_117", "firefox_120", "firefox_123", "firefox_132", "firefox_133",
    "firefox_135", "firefox_146_PSK", "firefox_147", "firefox_147_PSK",
    // Safari & iOS/iPadOS
    "safari_15_6_1", "safari_16_0", "safari_ios_15_5", "safari_ios_15_6", "safari_ios_16_0", "safari_ios_17_0", "safari_ios_18_0", "safari_ios_18_5", "safari_ios_26_0", "safari_ipad_15_6",
    // Opera
    "opera_89", "opera_90", "opera_91",
    // OkHttp
    "okhttp4_android_7", "okhttp4_android_8", "okhttp4_android_9", "okhttp4_android_10", "okhttp4_android_11", "okhttp4_android_12", "okhttp4_android_13",
    // Custom Clients
    "zalando_ios_mobile", "zalando_android_mobile", "nike_ios_mobile", "nike_android_mobile", "cloudscraper", 
    "mms_ios", "mms_ios_1", "mms_ios_2", "mms_ios_3", 
    "mesh_ios", "mesh_ios_1", "mesh_ios_2", "mesh_android", "mesh_android_1", "mesh_android_2",
    "confirmed_ios", "confirmed_android", "confirmed_android_2"
];

const TLS_REQUEST_PRESETS: Record<string, any> = {
    "Basic": {
        tls_client_identifier: "chrome_133",
        randomize_header_order: true,
        random_tls_extension_order: true,
        follow_redirects: true,
        with_default_cookie_jar: true,
        force_http1: false,
        headers: "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7\nAccept-Language: en-US,en;q=0.9",
        h2_settings_str: "INITIAL_WINDOW_SIZE:65535\nMAX_FRAME_SIZE:16384",
        h2_window_update_increment: "15663105"
    }
};

function Combobox({ value, onChange, options, variables, placeholder }: { value: string, onChange: (v: string) => void, options: string[], variables: string[], placeholder?: string }) {
    const [isOpen, setIsOpen] = useState(false);
    const [search, setSearch] = useState("");
    const wrapperRef = useRef<HTMLDivElement>(null);
    
    const filteredOptions = options.filter(o => !search || o.toLowerCase().includes(search.toLowerCase()));
    const filteredVars = variables.filter(v => !search || v.toLowerCase().includes(search.toLowerCase()));

    useEffect(() => {
        const handleClickOutside = (event: MouseEvent) => {
            if (wrapperRef.current && !wrapperRef.current.contains(event.target as any)) {
                setIsOpen(false);
            }
        };
        if (isOpen) {
            document.addEventListener("mousedown", handleClickOutside);
            const section = wrapperRef.current?.closest('.properties-section');
            if (section) (section as HTMLElement).style.zIndex = "100";
        }
        return () => {
            document.removeEventListener("mousedown", handleClickOutside);
            const section = wrapperRef.current?.closest('.properties-section');
            if (section) (section as HTMLElement).style.zIndex = "50";
        };
    }, [isOpen]);

    return (
        <div className="relative" ref={wrapperRef}>
            <div className="relative group">
                <input
                    className="w-full bg-[#0a0a0c] border border-white/[0.03] rounded-xl px-3 py-2.5 text-xs font-mono text-white placeholder-slate-700 focus:border-emerald-500 focus:bg-[#08080c] focus:ring-1 focus:ring-emerald-500/20 outline-none transition-all duration-200 shadow-sm"
                    value={isOpen ? search : value}
                    onChange={(e) => setSearch(e.target.value)}
                    onFocus={() => { setIsOpen(true); setSearch(""); }}
                />
                <div className="absolute right-3 top-1/2 -translate-y-1/2 pointer-events-none opacity-20 group-hover:opacity-100 transition-opacity">
                    <svg className="w-3.5 h-3.5 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2.5" d="M19 9l-7 7-7-7"></path></svg>
                </div>
            </div>
            {isOpen && (
                <div className="absolute top-full left-0 right-0 z-[1000] mt-2 max-h-[350px] overflow-y-auto bg-[#0a0a0c] border border-white/10 rounded-2xl shadow-[0_20px_50px_rgba(0,0,0,0.9)] custom-scrollbar animate-in fade-in slide-in-from-top-1 duration-200 backdrop-blur-3xl ring-1 ring-white/5">
                    {/* Profiles Section */}
                    <div className="p-2 border-b border-white/[0.03]">
                        <div className="px-3 py-2 text-[10px] font-black text-emerald-500 uppercase tracking-[0.2em] flex items-center gap-2">
                            <span className="w-1 h-1 rounded-full bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.5)]"></span>
                            Handshake Profiles
                        </div>
                        <div className="space-y-0.5">
                            {filteredOptions.length > 0 ? filteredOptions.map(o => (
                                <button
                                    key={o}
                                    onMouseDown={() => { onChange(o); setSearch(o); setIsOpen(false); }}
                                    className={`w-full text-left px-3 py-2.5 text-[11px] rounded-xl transition-all flex items-center justify-between group ${value === o ? 'bg-emerald-500 text-white font-bold shadow-lg shadow-emerald-500/20' : 'text-slate-300 hover:bg-white/[0.05] font-medium'}`}
                                >
                                    <div className="flex items-center gap-3">
                                        <span className={`text-sm transition-transform duration-300 ${value === o ? 'scale-110' : 'group-hover:scale-110'}`}>{o === 'random' ? '🎲' : '🌐'}</span>
                                        <span className="tracking-tight">{o}</span>
                                    </div>
                                    {o === 'random' && <span className={`text-[8px] font-black uppercase tracking-widest px-1.5 py-0.5 rounded ${value === o ? 'bg-white/20' : 'bg-emerald-500/10 text-emerald-400 opacity-0 group-hover:opacity-100 transition-opacity'}`}>Dynamic</span>}
                                </button>
                            )) : <div className="px-3 py-3 text-[10px] text-slate-600 italic font-medium">No matching profiles...</div>}
                        </div>
                    </div>
                    
                    {/* Variables Section */}
                    <div className="p-2 bg-black/20">
                        <div className="px-3 py-2 text-[10px] font-black text-slate-500 uppercase tracking-[0.2em] flex items-center gap-2">
                            <span className="w-1 h-1 rounded-full bg-slate-700"></span>
                            Injection Variables
                        </div>
                        <div className="space-y-0.5">
                            {filteredVars.length > 0 ? filteredVars.map(v => (
                                <button
                                    key={v}
                                    onMouseDown={() => { onChange(v); setSearch(v); setIsOpen(false); }}
                                    className="w-full text-left px-3 py-2.5 text-[11px] text-slate-400 hover:text-emerald-400 hover:bg-emerald-500/10 rounded-xl transition-all flex items-center gap-3 font-medium group"
                                >
                                    <div className="w-5 h-5 rounded-lg bg-white/[0.02] border border-white/[0.03] flex items-center justify-center group-hover:border-emerald-500/30 transition-colors">
                                        <span className="text-[10px]">#</span>
                                    </div>
                                    <span className="tracking-tight">{v}</span>
                                </button>
                            )) : <div className="px-3 py-3 text-[10px] text-slate-700 italic font-medium">No variables detected...</div>}
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}



function EditorView({ config, onUpdate, onBack, onSave, realTimeLogs, setRealTimeLogs }: { 
  config: Config, 
  onUpdate: (updates: Partial<Config>) => void,
  onBack: () => void,
  onSave: (config: Config) => void,
  realTimeLogs: ExecutionLog[],
  setRealTimeLogs: React.Dispatch<React.SetStateAction<ExecutionLog[]>>
}) {
  const [debugInput, setDebugInput] = useState(() => localStorage.getItem("reqforge_debug_input") || "");
  const [proxyInput, setProxyInput] = useState(() => localStorage.getItem("reqforge_debug_proxy") || "");
  const [useProxy, setUseProxy] = useState(() => localStorage.getItem("reqforge_debug_use_proxy") === "true");
  const [, setDebugResult] = useState<DebugResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [selectedBlockId, setSelectedBlockId] = useState<string | null>(null);
  const [showAddMenu, setShowAddMenu] = useState(false);
  const [viewMode, setViewMode] = useState<"code" | "blueprint" | "comfort">("comfort");
  const [showDebugger, setShowDebugger] = useState(true);

  // Panel Resizing State
  const [blockListWidth, setBlockListWidth] = useState(() => parseInt(localStorage.getItem("rb_block_list_width") || "450"));
  const [debuggerWidth, setDebuggerWidth] = useState(() => parseInt(localStorage.getItem("rb_debugger_width") || "600"));
  const [isResizingBlocks, setIsResizingBlocks] = useState(false);
  const [isResizingDebugger, setIsResizingDebugger] = useState(false);

  useEffect(() => {
    localStorage.setItem("rb_block_list_width", blockListWidth.toString());
  }, [blockListWidth]);

  useEffect(() => {
    localStorage.setItem("rb_debugger_width", debuggerWidth.toString());
  }, [debuggerWidth]);

  const handleMouseMove = (e: MouseEvent) => {
    if (isResizingBlocks) {
      setBlockListWidth(Math.max(300, Math.min(window.innerWidth - 600, e.clientX)));
    }
    if (isResizingDebugger) {
      setDebuggerWidth(Math.max(300, Math.min(window.innerWidth - 600, window.innerWidth - e.clientX)));
    }
  };

  const stopResizing = () => {
    setIsResizingBlocks(false);
    setIsResizingDebugger(false);
  };

  useEffect(() => {
    if (isResizingBlocks || isResizingDebugger) {
      window.addEventListener('mousemove', handleMouseMove);
      window.addEventListener('mouseup', stopResizing);
    } else {
      window.removeEventListener('mousemove', handleMouseMove);
      window.removeEventListener('mouseup', stopResizing);
    }
    return () => {
      window.removeEventListener('mousemove', handleMouseMove);
      window.removeEventListener('mouseup', stopResizing);
    };
  }, [isResizingBlocks, isResizingDebugger]);

  // DnD Sensors
  const sensors = useSensors(
    useSensor(PointerSensor, {
        activationConstraint: {
            distance: 5,
        },
    }),
    useSensor(KeyboardSensor, {
        coordinateGetter: sortableKeyboardCoordinates,
    })
  );

  const handleDragEnd = (event: DragEndEvent) => {
    const { active, over } = event;
    if (over && active.id !== over.id) {
        const oldIndex = config.blocks.findIndex(b => b.id === active.id);
        const newIndex = config.blocks.findIndex(b => b.id === over.id);
        onUpdate({ blocks: arrayMove(config.blocks, oldIndex, newIndex) });
    }
  };

  useEffect(() => { localStorage.setItem("reqforge_debug_input", debugInput); }, [debugInput]);
  useEffect(() => { localStorage.setItem("reqforge_debug_proxy", proxyInput); }, [proxyInput]);
  useEffect(() => { localStorage.setItem("reqforge_debug_use_proxy", String(useProxy)); }, [useProxy]);

  const addBlock = (type: BlockType) => {
    let initialData: any = {};
    if (type === "KeyCheck") {
      initialData = { source: "SOURCE", ban_if_no_match: true, keychains: [] };
    } else if (type === "Request") {
      initialData = {
        method: "GET", timeout: 15000, max_redirects: 8, auto_redirect: true,
        read_response: true, security_protocol: "SystemDefault", custom_ciphers: false, cipher_suites: "",
        use_proxy: true,
        headers: "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7\nAccept-Language: en-US,en;q=0.9",
        request_body_type: "raw", // Default to raw
        multipart_fields: [], // Initialize empty array
      };
    } else if (type === "ClearCookies") {
      initialData = {};
    } else if (type === "Delay") {
      initialData = { milliseconds: "1000" };
    } else if (type === "Parse") {
      initialData = { source: "SOURCE", mode: "LR", left: "", right: "", variable: "parsed", capture: false };
    } else if (type === "RandomString") {
      initialData = { variable: "random", mask: "?u?l?d?d?d?d", custom_charset: "" };
    } else if (type === "ConstantString") {
      initialData = { variable: "constString", value: "" };
    } else if (type === "ConstantList") {
      initialData = { variable: "constList", list: "" };
    } else if (type === "GetRandomItem") {
      initialData = { list_variable: "constList", output_variable: "randomItem" };
    } else if (type === "CurrentUnixTime") {
      initialData = { variable: "unixTime", use_utc: true };
    } else if (type === "DateToUnixTime") {
      initialData = { variable: "unixTime", input: "", format: "%Y-%m-%d %H:%M:%S" };
    } else if (type === "UnixTimeToDate") {
      initialData = { variable: "date", input: "", format: "%Y-%m-%d %H:%M:%S" };
    } else if (type === "UnixTimeToIso8601") {
      initialData = { variable: "iso8601", input: "" };
    } else if (type === "Base64Encode") {
      initialData = { variable: "base64", input: "" };
    } else if (type === "Base64Decode") {
      initialData = { variable: "utf8", input: "" };
    } else if (type === "GenerateCodeVerifier") {
      initialData = { variable: "codeVerifier" };
    } else if (type === "GenerateCodeChallenge") {
      initialData = { variable: "codeChallenge", input: "" };
    } else if (type === "GenerateState") {
      initialData = { variable: "state" };
    } else if (type === "GenerateNonce") {
      initialData = { variable: "nonce" };

    } else if (type === "RandomUserAgent") {
      initialData = { variable: "userAgent", platform: "ALL" };
    } else if (type === "GenerateGuid") {
      initialData = { variable: "guid", uppercase: false };
    } else if (type === "GenerateUUID4") {
      initialData = { variable: "UUID", uppercase: false };
    } else if (type === "TlsRequest") {
      initialData = {
        request_url: "https://google.com",
        request_method: "GET",
        request_body: "",
        request_body_type: "raw", // Default to raw
        multipart_fields: [], // Initialize empty array
        tls_client_identifier: "chrome_133",
        timeout_seconds: 30,
        follow_redirects: false,  // Important: false to capture 302 redirects
        insecure_skip_verify: false,
        with_default_cookie_jar: true,
        random_tls_extension_order: true,  // Better fingerprinting
        force_http1: false,
        randomize_header_order: true,  // Better fingerprinting
        without_cookie_jar: false,
        custom_session_id: "",
        proxy_url: "",
        headers: ""
      };
    } else if (type === "TlsWreq") {
      initialData = {
        request_url: "https://example.com",
        request_method: "GET",
        request_body: "",
        request_body_type: "raw", // Default to raw
        multipart_fields: [], // Initialize empty array
        emulation: "chrome133",
        timeout_seconds: 30,
        follow_redirects: true,
        max_redirects: 10,
        force_http1: false,
        cookie_store: false,
        randomize_header_order: false,
        proxy_url: "",
        headers: ""
      };
    } else if (type === "Hash") {
      initialData = { algorithm: "SHA256", variable: "hashed", input: "" };
    } else if (type === "JumpIF") {
      initialData = { jump_chains: [{ source: "SOURCE", mode: "OR", keys: [{ value: "", condition: "Contains" }], target: "LABEL1" }] };
    } else if (type === "JumpLabel") {
      initialData = { label: "LABEL1" };
    } else if (type === "Script") {
      initialData = { script: "// Rhai Script - Variables are available directly\n// Example: USER, PASS, SOURCE, RESPONSE, etc.\n\n// Read a variable\nlet user = USER;\nprint(\"User: \" + user);\n\n// Create new variables (automatically saved)\nlet my_result = \"processed_\" + user;\n\n// The last expression or created variables are saved back\n" };
        } else if (type === "Replace") {
          initialData = { source: "SOURCE", to_replace: "", replacement: "", variable: "replaced" };
        } else if (type === "ToLowercase") {
          initialData = { input: "SOURCE", variable: "lowercase" };
        } else if (type === "ToUppercase") {
          initialData = { input: "SOURCE", variable: "uppercase" };
            } else if (type === "Translate") {
              initialData = { input: "SOURCE", translations: "AF: 93", variable: "translated", use_original: true };        } else if (type === "UrlEncode") {
      initialData = { input: "", variable: "urlEncoded" };
    } else if (type === "UrlDecode") {
      initialData = { input: "", variable: "urlDecoded" };
    } else if (type === "HmacSign") {
      initialData = { algorithm: "SHA256", key: "", message: "", key_format: "utf8", output_format: "hex", variable: "hmac" };
    } else if (type === "AesEncrypt") {
      initialData = { key: "", iv: "", plaintext: "", key_format: "utf8", output_format: "base64", variable: "encrypted" };
    } else if (type === "AesDecrypt") {
      initialData = { key: "", iv: "", ciphertext: "", key_format: "utf8", input_format: "base64", variable: "decrypted" };
    } else if (type === "Pbkdf2Derive") {
      initialData = { password: "", salt: "", salt_format: "utf8", iterations: 10000, key_length: 32, algorithm: "SHA256", output_format: "hex", variable: "derived_key" };
    } else if (type === "RsaEncrypt") {
      initialData = { plaintext: "", modulus: "", exponent: "", variable: "rsaEncrypted" };
    } else if (type === "Base64ToBytes") {
      initialData = { input: "", variable: "hexBytes" };
    } else if (type === "EncodeHtmlEntities") {
      initialData = { input: "", variable: "htmlEncoded" };
    } else if (type === "DecodeHtmlEntities") {
      initialData = { input: "", variable: "htmlDecoded" };
    }


    const newBlock: Block = {
      id: Math.random().toString(36).substring(2, 9),
      block_type: type,
      data: initialData,
    };

    // Insert after selected block if any, otherwise at the end
    const selectedIndex = config.blocks.findIndex(b => b.id === selectedBlockId);
    let newBlocks;
    if (selectedIndex !== -1) {
      newBlocks = [...config.blocks];
      newBlocks.splice(selectedIndex + 1, 0, newBlock);
    } else {
      newBlocks = [...config.blocks, newBlock];
    }

    onUpdate({ blocks: newBlocks });
    setSelectedBlockId(newBlock.id);
    setShowAddMenu(false);
  };

  const updateBlockData = (id: string, newData: any) => {
    onUpdate({
      blocks: config.blocks.map((b) =>
        b.id === id ? { ...b, data: { ...b.data, ...newData } } : b
      ),
    });
  };

  const removeBlock = (id: string) => {
    onUpdate({ blocks: config.blocks.filter((b) => b.id !== id) });
    if (selectedBlockId === id) setSelectedBlockId(null);
  };

  const duplicateBlock = (id: string) => {
    const idx = config.blocks.findIndex(b => b.id === id);
    if (idx === -1) return;
    const blockToClone = config.blocks[idx];
    const newBlock = {
        ...blockToClone,
        id: Math.random().toString(36).substring(2, 9),
    };
    const newBlocks = [...config.blocks];
    newBlocks.splice(idx + 1, 0, newBlock);
    onUpdate({ blocks: newBlocks });
  };

  const moveBlock = (id: string, direction: "up" | "down") => {
    const idx = config.blocks.findIndex(b => b.id === id);
    if (idx === -1) return;
    const newBlocks = [...config.blocks];
    
    if (direction === "up" && idx > 0) {
        [newBlocks[idx], newBlocks[idx - 1]] = [newBlocks[idx - 1], newBlocks[idx]];
    } else if (direction === "down" && idx < newBlocks.length - 1) {
        [newBlocks[idx], newBlocks[idx + 1]] = [newBlocks[idx + 1], newBlocks[idx]];
    }
    onUpdate({ blocks: newBlocks });
  };

  const runDebug = async () => {
    setLoading(true);
    setDebugResult(null);
    setRealTimeLogs([]);
    try {
      const result = await invoke<DebugResult>("run_debug", { config, input: debugInput, proxy: useProxy ? proxyInput : "" });
      setDebugResult(result);
    } catch (error) {
      if (String(error).includes("aborted")) {
          console.log("Debug aborted by user");
      } else {
          console.error(error);
          alert("Error running debug: " + error);
      }
    } finally {
      setLoading(false);
    }
  };

  const stopDebug = async () => {
      try {
          await invoke("stop_debug");
          setLoading(false);
      } catch (e) {
          console.error("Failed to stop debug", e);
      }
  }

  const selectedBlock = config.blocks.find((b) => b.id === selectedBlockId);
  const availableVariables = useMemo(() => getAvailableVariables(config.blocks), [config.blocks]);

  const getBlockIcon = (type: string) => {
    const icons: Record<string, string> = {
      Request: "🌐", Parse: "📝", KeyCheck: "🔑", Log: "📋", RandomString: "🎲",
      ConstantString: "📌", ConstantList: "📑", GetRandomItem: "🎯", Hash: "🔒",
      JumpIF: "↪️", JumpLabel: "🏷️", ClearCookies: "🍪", TlsRequest: "🔐", TlsWreq: "🛡️",
      CurrentUnixTime: "⏱️", DateToUnixTime: "📅", UnixTimeToDate: "📆", UnixTimeToIso8601: "🕐",
      Base64Encode: "🔤", Base64Decode: "🔡", GenerateCodeVerifier: "✅", GenerateCodeChallenge: "🎯",
      GenerateState: "🔀", GenerateNonce: "🎲", GenerateGuid: "🆔", GenerateUUID4: "🔢",
      Script: "📜", Replace: "🔄", UrlEncode: "🔗", UrlDecode: "🔓", RandomUserAgent: "🕵️"
    };
    return icons[type] || "⚡";
  };

  const importFromClipboard = async () => {
      try {
          const text = await navigator.clipboard.readText();
          let parsed;
          try {
              parsed = JSON.parse(text);
          } catch {
              return alert("Clipboard does not contain valid JSON.");
          }

          // Handle single block or array
          const newBlocks = Array.isArray(parsed) ? parsed : [parsed];
          
          // Basic validation
          const validBlocks = newBlocks.filter((b: any) => b && b.block_type && b.data);
          if (validBlocks.length === 0) return alert("No valid ReqForge blocks found in clipboard.");

          // Regenerate IDs to avoid conflicts
          const processed = validBlocks.map((b: any) => ({
              ...b,
              id: Math.random().toString(36).substring(2, 9)
          }));

          onUpdate({ blocks: [...config.blocks, ...processed] });
          alert(`Imported ${processed.length} blocks successfully!`);
      } catch (e) {
          console.error(e);
          alert("Failed to read clipboard permissions.");
      }
  };

  return (
    <div className="h-full flex flex-col bg-[#0a0a0c]">
      {/* Header */}
      <header className="h-16 flex items-center px-5 bg-[#0a0a0c] z-30">
        <button onClick={onBack} className="text-slate-500 hover:text-white mr-4 p-2.5 hover:bg-white/[0.02] rounded-xl transition-all duration-200">
          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M10 19l-7-7m0 0l7-7m-7 7h18"></path></svg>
        </button>
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-slate-800 to-purple-600 flex items-center justify-center shadow-lg shadow-black/20">
            <span className="text-white font-bold text-sm">C</span>
          </div>
          <input
            className="bg-transparent text-xl font-bold text-white outline-none w-64 placeholder-slate-600"
            value={config.name}
            onChange={(e) => onUpdate({ name: e.target.value })}
            placeholder="Config Name"
          />
        </div>
        <div className="flex-1"></div>
        <div className="flex items-center gap-3">
          <div className="flex bg-white/[0.02] rounded-lg p-1">
            
            <button onClick={() => setViewMode("comfort")} className={`px-3 py-1.5 text-xs font-bold rounded-md transition-all ${viewMode === "comfort" ? "bg-emerald-500 text-white shadow-sm" : "text-slate-400 hover:text-white"}`}>Comfort</button>
            <button onClick={() => setViewMode("blueprint")} className={`px-3 py-1.5 text-xs font-bold rounded-md transition-all ${viewMode === "blueprint" ? "bg-emerald-500 text-white shadow-sm" : "text-slate-400 hover:text-white"}`}>Blueprint</button>
            <button onClick={() => setViewMode("code")} className={`px-3 py-1.5 text-xs font-bold rounded-md transition-all ${viewMode === "code" ? "bg-emerald-500 text-white shadow-sm" : "text-slate-400 hover:text-white"}`}>Code</button>
          </div>
          
          <button 
            onClick={() => setShowDebugger(!showDebugger)} 
            className={`p-2 rounded-xl border transition-all duration-300 ${showDebugger ? 'bg-emerald-500/10 border-emerald-500 text-emerald-400 shadow-lg shadow-black/10' : 'bg-white/[0.02] border-slate-700 text-slate-500 hover:text-white'}`}
            title={showDebugger ? "Hide Debugger" : "Show Debugger"}
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z"></path>
            </svg>
          </button>

          <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-white/[0.02] text-slate-400 text-xs font-medium">
            <div className="w-1.5 h-1.5 rounded-full bg-emerald-500"></div>
            {config.blocks.length} Units
          </div>
          <button onClick={importFromClipboard} className="bg-white/[0.05] hover:bg-white/[0.1] text-slate-300 hover:text-white text-xs font-bold px-4 py-2 rounded-xl transition-all border border-white/[0.03] flex items-center gap-2">
            <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"></path></svg>
            Paste Blocks
          </button>
          <button onClick={() => onSave(config)} className="bg-white/5 hover:bg-white/10 text-white text-xs font-black px-5 py-2 rounded-xl transition-all duration-300 border border-white/[0.03] uppercase tracking-widest shadow-xl">
            Commit Logic
          </button>
        </div>
      </header>

      <div className="flex-1 flex overflow-hidden">
        {/* Main Workspace (Resizable Stacker) */}
        <div 
            style={{ width: showDebugger ? `calc(100% - ${debuggerWidth}px)` : '100%' }}
            className="flex flex-col relative bg-[#0a0a0c] h-full"
        >
          <div className="flex-1 flex overflow-hidden relative">
            {/* Left Column: Block List */}
            <div 
                style={{ width: viewMode === 'code' || (viewMode === 'blueprint' && !selectedBlockId) ? '100%' : `${blockListWidth}px` }}
                className="flex flex-col border-r border-white/[0.03] bg-[#0a0a0c] relative group h-full"
            >
              {viewMode === 'code' ? (
                  <CodeEditor config={config} onUpdate={onUpdate} />
              ) : viewMode === 'blueprint' ? (
                  <BlueprintEditor config={config} onUpdate={onUpdate} onSelectBlock={setSelectedBlockId} executionLogs={realTimeLogs} />
              ) : (
              <>
              <div className="p-4 bg-[#0a0a0c] backdrop-blur-sm">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <div className="w-2 h-2 rounded-full bg-white/[0.05] animate-pulse"></div>
                    <h3 className="text-sm font-bold text-slate-300 tracking-tight uppercase">Block Flow</h3>
                  </div>
                  <span className="text-[10px] text-slate-600 font-black bg-white/[0.01] px-2 py-0.5 rounded border border-white/[0.03]">{config.blocks.length} UNITS</span>
                </div>
              </div>
              <div className="flex-1 overflow-y-auto pb-24 custom-scrollbar bg-gradient-to-b from-[#09090b] to-[#09090b]">
                <DndContext sensors={sensors} collisionDetection={closestCenter} onDragEnd={handleDragEnd}>
                    <SortableContext items={config.blocks.map(b => b.id)} strategy={verticalListSortingStrategy}>
                        <div className="p-3 space-y-2.5">
                            {config.blocks.map((block, idx) => (
                                <SortableComfortBlock
                                    key={block.id} block={block} idx={idx} isSelected={selectedBlockId === block.id}
                                    isActive={false} onClick={() => setSelectedBlockId(block.id)}
                                    onMove={(dir) => moveBlock(block.id, dir)} onClone={() => duplicateBlock(block.id)}
                                    onDelete={() => removeBlock(block.id)} getIcon={getBlockIcon}
                                />
                            ))}
                        </div>
                    </SortableContext>
                </DndContext>
              </div>
              </>
              )}

              {/* Resize Handle for Block List */}
              {viewMode !== 'code' && (viewMode !== 'blueprint' || selectedBlockId) && (
                <div 
                  onMouseDown={() => setIsResizingBlocks(true)}
                  className={`absolute right-0 top-0 bottom-0 w-1 cursor-col-resize transition-all z-50 ${isResizingBlocks ? 'bg-white/[0.05] shadow-[0_0_10px_rgba(59,130,246,0.5)]' : 'hover:bg-white/[0.05]/30'}`}
                />
              )}
            </div>

            {/* Right Column: Settings */}
            {(viewMode === 'comfort' || (viewMode === 'blueprint' && selectedBlockId)) && (
            <div className="flex-1 flex flex-col bg-[#0a0a0c] border-l border-white/[0.03] relative z-20 shadow-[inset_10px_0_30px_rgba(0,0,0,0.5)] h-full overflow-hidden">
              <div className="p-4 bg-[#0a0a0c]">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <div className="w-8 h-8 rounded-lg bg-white/[0.02] flex items-center justify-center text-slate-400 border border-white/[0.03]">
                        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2.5" d="M12 6V4m0 2a2 2 0 100 4m0-4a2 2 0 110 4m-6 8a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4m6 6v10m6-2a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4"></path></svg>
                    </div>
                    <h3 className="text-[11px] font-black text-white uppercase tracking-[0.2em]">Parameter Matrix</h3>
                  </div>
                  <div className="flex items-center gap-2">
                    {selectedBlock && (
                        <button onClick={() => removeBlock(selectedBlock.id)} className="flex items-center gap-1.5 text-red-400 hover:text-red-500 text-[10px] font-black uppercase tracking-wider transition-all px-3 py-1.5 rounded-lg hover:bg-red-500/10 border border-red-500/10">
                        <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2.5" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path></svg>
                        Purge
                        </button>
                    )}
                    <button onClick={() => setSelectedBlockId(null)} className="p-1.5 rounded-lg bg-white/5 hover:bg-white/[0.02] text-slate-500 hover:text-white transition-all border border-white/[0.03]" title="De-select">
                        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="3" d="M6 18L18 6M6 6l12 12"></path></svg>
                    </button>
                  </div>
                </div>
              </div>
              <div className="flex-1 overflow-y-auto p-6 pb-64 custom-scrollbar bg-[#0a0a0c]">
                {selectedBlock ? (
                  <div className="max-w-2xl mx-auto animate-in fade-in slide-in-from-right-4 duration-500">
                    <div className="flex items-center gap-5 mb-8 bg-white/[0.02] p-6 rounded-2xl border border-white/[0.03] shadow-xl">
                      <div className="w-16 h-16 rounded-2xl bg-gradient-to-br from-slate-800/20 to-slate-900/20 flex items-center justify-center text-3xl shadow-inner border border-emerald-500/10 transition-transform duration-500 hover:scale-105">
                        {getBlockIcon(selectedBlock.block_type)}
                      </div>
                      <div>
                        <h3 className="font-black text-xl text-white tracking-tighter uppercase">{getBlockName(selectedBlock.block_type)}</h3>
                        <p className="text-[10px] text-slate-600 font-black uppercase tracking-[0.2em] mt-1 flex items-center gap-2">
                            <span className="w-1.5 h-1.5 rounded-full bg-white/[0.01]0"></span>
                            Module ID: {selectedBlock.id}
                        </p>
                      </div>
                    </div>
                    {renderBlockSettings(selectedBlock, updateBlockData, availableVariables)}
                  </div>
                ) : (
                  <div className="h-full flex flex-col items-center justify-center opacity-40">
                    <div className="w-24 h-24 rounded-[2rem] bg-[#0a0a0c] border border-white/[0.03] flex items-center justify-center mb-6 shadow-2xl relative group">
                        <div className="absolute inset-0 bg-white/5 blur-2xl rounded-full group-hover:bg-white/10 transition-all"></div>
                        <svg className="w-10 h-10 text-slate-700 relative z-10" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.5" d="M15 15l-2 5L9 9l11 4-5 2zm0 0l5 5M7.188 2.239l.777 2.897M5.136 7.965l-2.898-.777M13.95 4.05l-2.122 2.122m-5.657 5.656l-2.12 2.122"></path></svg>
                    </div>
                    <p className="text-slate-500 font-black text-xs uppercase tracking-[0.3em]">Module Inactive</p>
                    <p className="text-slate-700 text-[10px] font-bold mt-3 text-center uppercase tracking-widest leading-relaxed max-w-[200px]">Select a block from the flow to interface with its parameter matrix</p>
                  </div>
                )}
              </div>
            </div>
            )}
          </div>

                    {/* Add Block FAB */}
          {viewMode !== 'code' && (
          <div className="absolute bottom-6 left-6 z-40">
              <button
                onClick={() => setShowAddMenu(true)}
                className="w-14 h-14 rounded-2xl shadow-2xl flex items-center justify-center bg-gradient-to-br from-slate-800 to-slate-900 hover:from-slate-800 hover:to-slate-900 shadow-black/40 hover:scale-105 active:scale-95 transition-all duration-300 group"
                title="Add Block"
              >
                <svg className="w-7 h-7 text-white group-hover:rotate-90 transition-transform duration-300" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2.5" d="M12 4v16m8-8H4"></path></svg>
              </button>
          </div>
          )}
          
          <BlockSelectorModal isOpen={showAddMenu} onClose={() => setShowAddMenu(false)} onSelect={(t) => addBlock(t as BlockType)} />
        </div>


        {/* Resize Handle for Debugger Split */}
        {showDebugger && (
            <div 
            onMouseDown={() => setIsResizingDebugger(true)}
            className={`w-1 cursor-col-resize transition-all z-50 ${isResizingDebugger ? 'bg-emerald-500 shadow-[0_0_10px_rgba(16,185,129,0.5)]' : 'hover:bg-emerald-500/30'}`}
            />
        )}

        {/* Right: Debugger (Resizable) */}
        {showDebugger && (
        <div 
          style={{ width: `${debuggerWidth}px` }}
          className="flex flex-col bg-[#0a0a0c] relative overflow-hidden shadow-2xl h-full"
        >
          {/* Debugger Header */}
          <div className="p-4 bg-[#0a0a0c]">
            <div className="flex items-center gap-2">
                <div className="w-1.5 h-1.5 rounded-full bg-emerald-500 shadow-[0_0_5px_rgba(16,185,129,1)] animate-pulse"></div>
                <h3 className="text-sm font-bold text-slate-300 tracking-tight uppercase">Terminal Debugger</h3>
            </div>
          </div>
          
          {/* Debug Controls */}
          <div className="p-5  space-y-4 bg-[#0a0a0c]/40">
            <div className="group">
                <label className="block text-[10px] font-black text-slate-600 mb-2 uppercase tracking-[0.2em] group-focus-within:text-emerald-500 transition-colors">Test Credentials</label>
                <input 
                    className="w-full bg-[#0a0a0c] border border-white/[0.03] rounded-xl p-3 text-sm text-white focus:border-emerald-500 outline-none transition-all font-mono placeholder-slate-700 shadow-inner"
                    value={debugInput}
                    onChange={(e) => setDebugInput(e.target.value)}
                    placeholder="user:pass"
                />
            </div>
            <div className="bg-white/[0.01]/30 border border-white/[0.02] rounded-xl p-3">
                <div className="flex justify-between items-center">
                    <div className="flex flex-col">
                        <label className="text-[10px] font-black text-slate-500 uppercase tracking-widest">Routing Proxy</label>
                        <span className="text-[9px] text-slate-600 mt-0.5 font-bold italic">Bypass local IP filtering</span>
                    </div>
                    <Toggle checked={useProxy} onChange={setUseProxy} />
                </div>
                {useProxy && (
                    <div className="mt-3 animate-in fade-in slide-in-from-top-1 duration-200">
                        <input 
                            className="w-full bg-[#0a0a0c] border border-white/[0.03] rounded-lg p-2 text-xs text-white focus:border-emerald-500 outline-none transition-all font-mono"
                            value={proxyInput}
                            onChange={(e) => setProxyInput(e.target.value)}
                            placeholder="socks5://host:port"
                        />
                    </div>
                )}
            </div>
            <div className="flex gap-2">
                <button
                    onClick={runDebug}
                    disabled={loading}
                    className={`flex-1 py-3 rounded-xl font-black text-xs uppercase tracking-[0.2em] transition-all duration-300 flex items-center justify-center gap-3 shadow-lg ${loading ? 'bg-white/[0.02] text-slate-600 cursor-not-allowed' : 'bg-gradient-to-r from-emerald-600 to-teal-700 hover:from-emerald-500 hover:to-teal-600 text-white shadow-emerald-600/20 hover:shadow-black/40 active:scale-[0.98]'}`}
                >
                    {loading ? (
                        <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>
                    ) : (
                        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2.5" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z"></path><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2.5" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                    )}
                    {loading ? 'Processing...' : 'Execute Sequence'}
                </button>
                {loading && (
                    <button 
                        onClick={stopDebug}
                        className="px-4 py-3 rounded-xl bg-red-500/10 hover:bg-red-500/20 text-red-500 border border-red-500/20 font-black text-[10px] uppercase tracking-widest transition-all"
                    >
                        Stop
                    </button>
                )}
            </div>
          </div>

          {/* Log Stream */}
          <div className="flex-1 overflow-y-auto custom-scrollbar bg-[#0a0a0c] p-4 font-mono">
            <div className="space-y-2">
                {realTimeLogs.length === 0 && (
                    <div className="h-full flex flex-col items-center justify-center opacity-20 py-12">
                    <svg className="w-12 h-12 text-slate-600 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path></svg>
                    <span className="text-[10px] uppercase tracking-widest font-bold">No stream data available</span>
                    </div>
                )}
                {realTimeLogs.map((log, i) => (
                    <LogItem key={i} log={log} prevVariables={i > 0 ? realTimeLogs[i-1].variables : {}} />
                ))}
            </div>
          </div>
        </div>
        )}
      </div>
    </div>
  );
}

function LogItem({ log, prevVariables = {} }: { log: ExecutionLog, prevVariables?: Record<string, string> }) {
  const [expanded, setExpanded] = useState(false);
  const isLongMessage = log.message.length > 20;
  const hasDetails = !!log.details;
  
  // Detect changes in variables
  const currentVars = log.variables || {};
  const changedVars = Object.entries(currentVars).filter(([k, v]) => prevVariables[k] !== v);
  const hasChanges = changedVars.length > 0;

  const canExpand = hasDetails || isLongMessage;
  const [tab, setTab] = useState<"req" | "res" | "msg">(hasDetails ? "res" : "msg");  const [searchTerm, setSearchTerm] = useState("");
  const [matchIndex, setMatchIndex] = useState(0);
  const [matchCount, setMatchCount] = useState(0);
  const [showHtmlPreview, setShowHtmlPreview] = useState(false);

  // Detect if response body looks like HTML
  const isHtmlResponse = hasDetails && log.details?.response_body &&
    (log.details.response_body.toLowerCase().includes('<!doctype html') ||
     log.details.response_body.toLowerCase().includes('<html') ||
     log.details.response_body.toLowerCase().includes('<head>') ||
     log.details.response_body.toLowerCase().includes('<body'));

  const handleSearchKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && matchCount > 0) {
      e.preventDefault();
      setMatchIndex((prev) => (prev + 1) % matchCount);
    }
  };

  const getStepIcon = (step: string) => {
    const icons: Record<string, string> = {
      Start: "🚀", Request: "🌐", TlsRequest: "🔐", TlsWreq: "🛡️", Parse: "📝", KeyCheck: "🔑", End: "🏁",
      GenerateUUID4: "🔢", GenerateGuid: "🆔", Hash: "🔒", JumpIF: "↪️", JumpLabel: "🏷️", Checksum: "🎰",
      Delay: "⏳", RandomString: "🎲", ConstantString: "📌",
      Translate: "🌐", ToLowercase: "abc", ToUppercase: "ABC"
    };
    return icons[step] || "⚡";
  };

  const getStatusStyle = (status: string) => {
    const s = status.toUpperCase();
    switch (s) {
      case "SUCCESS": return "bg-emerald-500/20 text-emerald-400 border-emerald-500/30";
      case "INFO": return "bg-white/[0.03] text-slate-400 border-white/[0.05]";
      case "WARNING": return "bg-amber-500/20 text-amber-400 border-amber-500/30";
      case "ERROR": 
      case "FAIL": return "bg-red-500/20 text-red-400 border-red-500/30";
      case "BAN": return "bg-orange-500/20 text-orange-400 border-orange-500/30";
      case "RETRY": return "bg-yellow-500/20 text-yellow-400 border-yellow-500/30";
      default: return "bg-slate-500/20 text-slate-400 border-slate-500/30";
    }
  };

  const getStepColor = (step: string) => {
    if (step.includes("Request") || step === "TlsWreq") return "text-emerald-400";
    if (step === "Parse") return "text-pink-400";
    if (step === "KeyCheck") return "text-orange-400";
    if (step === "Hash" || step.includes("Aes") || step.includes("Hmac") || step.includes("Pbkdf2") || ["Translate", "ToLowercase", "ToUppercase", "Base64Encode", "Base64Decode", "UrlEncode", "UrlDecode"].includes(step)) return "text-purple-400";
    if (step === "JumpIF" || step === "JumpLabel") return "text-amber-400";
    if (step === "Checksum") return "text-purple-400";
    return "text-slate-400";
  };

  const renderFormattedMessage = (msg: string, step: string) => {
    // Universal regex to catch (VARNAME): VALUE patterns in any step
    const varPatternRegex = /^(\([^)]+\))(: )(.*)$/;
    const varMatch = msg.match(varPatternRegex);

    if (varMatch) {
        return (
            <>
                <span className="text-pink-400 font-bold">{varMatch[1]}</span>
                <span className="text-white font-bold">{varMatch[2]}</span>
                <span className="text-emerald-400 font-bold break-all">{varMatch[3]}</span>
            </>
        );
    }

    // Colorize status and redirects in Request blocks
    if (step.includes("Request") || step === "TlsWreq") {
        const reqRegex = /^(Status: )(\d+)( \(redirects: )(\d+)(, source: )(.*)$/;
        const reqMatch = msg.match(reqRegex);
        if (reqMatch) {
            const statusInt = parseInt(reqMatch[2]);
            const statusColor = statusInt >= 200 && statusInt < 300 ? "text-emerald-400" : "text-red-400";
            return (
                <>
                    <span className="text-white font-bold">{reqMatch[1]}</span>
                    <span className={`${statusColor} font-black`}>{reqMatch[2]}</span>
                    <span className="text-slate-500">{reqMatch[3]}</span>
                    <span className="text-emerald-400 font-black">{reqMatch[4]}</span>
                    <span className="text-slate-500">{reqMatch[5]}</span>
                    <span className="text-white font-medium italic">{reqMatch[6]}</span>
                </>
            );
        }
    }

    // Colorize final bot status
    if (step === "End") {
        const endRegex = /^(Bot ended: )(.*)$/;
        const endMatch = msg.match(endRegex);
        if (endMatch) {
            const status = endMatch[2].toUpperCase();
            let statusColor = "text-slate-400";
            if (status === "SUCCESS") statusColor = "text-emerald-400";
            else if (status === "FAIL" || status === "ERROR") statusColor = "text-red-400";
            else if (status === "BAN") statusColor = "text-orange-400";
            else if (status === "RETRY") statusColor = "text-yellow-400";

            return (
                <>
                    <span className="text-white font-bold">{endMatch[1]}</span>
                    <span className={`${statusColor} font-black`}>{endMatch[2]}</span>
                </>
            );
        }
    }

    return <span className="text-white font-medium">{msg}</span>;
  };

  return (
    <div className={`rounded-xl overflow-hidden transition-all duration-300 ${expanded ? 'bg-[#0a0a0c] border border-white/[0.03] shadow-[0_20px_50px_rgba(0,0,0,0.5)] ring-1 ring-white/[0.02]' : 'bg-[#0a0a0c] hover:bg-[#0a0a0c] border border-transparent hover:border-white/[0.03]'}`}>
      <div
        onClick={() => canExpand && setExpanded(!expanded)}
        className={`flex items-center gap-3 p-3 cursor-pointer transition-colors group`}
      >
        <div className={`w-9 h-9 rounded-xl flex items-center justify-center text-sm shrink-0 border transition-all duration-500 ${expanded ? 'bg-gradient-to-br from-slate-800 to-slate-900 border-slate-700 shadow-lg rotate-3' : 'bg-[#0a0a0c] border-white/[0.03] grayscale group-hover:grayscale-0'}`}>
          {getStepIcon(log.step)}
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-0.5">
            <span className={`text-[10px] font-black uppercase tracking-widest ${getStepColor(log.step)}`}>{getBlockName(log.step)}</span>
            {log.block_id && (
              <span className="text-[9px] font-black font-mono text-slate-500 bg-white/5 px-1.5 py-0.5 rounded border border-white/[0.03]">
                #{log.block_id}
              </span>
            )}
            <span className={`text-[9px] font-black px-2 py-0.5 rounded border uppercase tracking-tighter ${getStatusStyle(log.status)}`}>
              {log.status}
            </span>
            <span className="text-[9px] font-bold text-slate-600 ml-auto tabular-nums">{log.duration_ms}ms</span>
          </div>
          <div className="text-[11px] font-mono truncate leading-relaxed">
            {renderFormattedMessage(log.message, log.step)}
          </div>
        </div>
        {canExpand && (
          <div className={`w-6 h-6 rounded-full flex items-center justify-center transition-all ${expanded ? 'bg-emerald-500/10 text-emerald-400 rotate-90' : 'text-slate-700 group-hover:text-slate-400'}`}>
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="3" d="M9 5l7 7-7 7"></path>
            </svg>
          </div>
        )}
      </div>

      {expanded && (
        <div className=" bg-[#08080c] p-4 animate-in fade-in duration-300">
          
          {/* Tabs */}
          <div className="flex gap-1 mb-4">
            {hasDetails && (
              <button
                onClick={() => setTab("req")}
                className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-all duration-200 ${tab === "req" ? 'bg-emerald-500/20 text-emerald-400' : 'text-slate-500 hover:text-slate-300 hover:bg-white/[0.02]'}`}
              >
                Request
              </button>
            )}
            {hasDetails && (
              <button
                onClick={() => setTab("res")}
                className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-all duration-200 ${tab === "res" ? 'bg-emerald-500/20 text-emerald-400' : 'text-slate-500 hover:text-slate-300 hover:bg-white/[0.02]'}`}
              >
                Response
              </button>
            )}
            <button
              onClick={() => setTab("msg")}
              className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-all duration-200 ${tab === "msg" ? 'bg-purple-500/20 text-purple-400' : 'text-slate-500 hover:text-slate-300 hover:bg-white/[0.02]'}`}
            >
              Message
            </button>
          </div>

          {/* Tab Content */}
          <div className="text-xs font-mono text-slate-300">
            {tab === "req" && log.details ? (
              <div className="space-y-4">
                <div className="flex items-center justify-between p-3 rounded-xl bg-[#0a0a0c] border border-white/[0.02]">
                  <div className="flex items-center gap-3">
                    <span className="font-bold text-emerald-400 bg-emerald-500/20 px-2.5 py-1 rounded-lg text-xs">{log.details.method}</span>
                    <span className="text-emerald-400 break-all text-xs">{log.details.url}</span>
                  </div>
                  <button
                    onClick={() => navigator.clipboard.writeText(log.details?.url || "")}
                    className="p-1.5 bg-white/5 hover:bg-white/10 rounded-lg text-slate-500 transition-all"
                  >
                    <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M8 5H6a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2v-1M8 5a2 2 0 002 2h2a2 2 0 002-2M8 5a2 2 0 012-2h2a2 2 0 012 2m0 0h2a2 2 0 012 2v3m2 4H10m0 0l3-3m-3 3l3 3"></path></svg>
                  </button>
                </div>
                {log.details.response_url && (
                  <div className="flex items-center justify-between p-3 rounded-xl bg-[#0a0a0c] border border-white/[0.02]">
                    <div className="flex items-center gap-3">
                      <span className="font-bold text-sky-400 bg-sky-500/20 px-2.5 py-1 rounded-lg text-xs">RESP URL</span>
                      <span className="text-sky-400 break-all text-xs">{log.details.response_url}</span>
                    </div>
                    <button
                      onClick={() => navigator.clipboard.writeText(log.details?.response_url || "")}
                      className="p-1.5 bg-white/5 hover:bg-white/10 rounded-lg text-slate-500 transition-all"
                    >
                      <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M8 5H6a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2v-1M8 5a2 2 0 002 2h2a2 2 0 002-2M8 5a2 2 0 012-2h2a2 2 0 012 2m0 0h2a2 2 0 012 2v3m2 4H10m0 0l3-3m-3 3l3 3"></path></svg>
                    </button>
                  </div>
                )}
                <div>
                  <div className="text-[10px] font-bold text-slate-500 mb-2 uppercase tracking-wider flex items-center gap-2">
                    <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path></svg>
                    Request Headers
                  </div>
                  <div className="space-y-1 bg-[#0a0a0c] rounded-xl p-3 border border-white/[0.02]">
                    {Object.entries(log.details.request_headers).map(([k, v]) => (
                      <div key={k} className="flex gap-2">
                        <span className="text-orange-400 shrink-0 font-bold">{k}:</span>
                        <span className="text-slate-400 break-all">{v}</span>
                      </div>
                    ))}
                  </div>
                </div>
                {log.details.request_body && (
                  <div>
                    <div className="flex justify-between items-center mb-2">
                        <div className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">Request Body</div>
                        <button 
                            onClick={() => navigator.clipboard.writeText(log.details?.request_body || "")}
                            className="text-[9px] font-black text-slate-600 hover:text-emerald-400 uppercase tracking-widest transition-colors"
                        >
                            Copy Body
                        </button>
                    </div>
                    <div className="bg-[#0a0a0c] border border-white/[0.02] p-3 rounded-xl text-slate-400 break-all whitespace-pre-wrap max-h-60 overflow-y-auto custom-scrollbar shadow-inner">{log.details.request_body}</div>
                  </div>
                )}
              </div>
            ) : tab === "res" && log.details ? (
              <div className="space-y-4">
                <div className="flex items-center justify-between p-3 rounded-xl bg-[#0a0a0c] border border-white/[0.02]">
                  <div className="flex items-center gap-3">
                    <span className={`text-sm font-bold px-2.5 py-1 rounded-lg ${log.details.response_status >= 200 && log.details.response_status < 300 ? 'bg-emerald-500/20 text-emerald-400' : 'bg-red-500/20 text-red-400'}`}>
                        {log.details.response_status}
                    </span>
                  </div>
                </div>
                <div>
                  <div className="text-[10px] font-bold text-slate-500 mb-2 uppercase tracking-wider flex items-center gap-2">
                    <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"></path></svg>
                    Response URL
                  </div>
                  <div className="flex items-center justify-between p-3 rounded-xl bg-[#0a0a0c] border border-white/[0.02]">
                    <span className="text-sky-400 break-all text-xs font-mono">{log.details.response_url || "N/A"}</span>
                    <button
                      onClick={() => navigator.clipboard.writeText(log.details?.response_url || "")}
                      className="p-1.5 bg-white/5 hover:bg-white/10 rounded-lg text-slate-500 transition-all"
                    >
                      <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M8 5H6a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2v-1M8 5a2 2 0 002 2h2a2 2 0 002-2M8 5a2 2 0 012-2h2a2 2 0 012 2m0 0h2a2 2 0 012 2v3m2 4H10m0 0l3-3m-3 3l3 3"></path></svg>
                    </button>
                  </div>
                </div>
                <div>
                  <div className="text-[10px] font-bold text-slate-500 mb-2 uppercase tracking-wider flex items-center gap-2">
                    <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path></svg>
                    Response Headers
                  </div>
                  <div className="space-y-1 bg-[#0a0a0c] rounded-xl p-3 border border-white/[0.02] max-h-60 overflow-y-auto custom-scrollbar">
                    {Object.entries(log.details.response_headers).map(([k, v]) => (
                      <div key={k} className="flex gap-2">
                        <span className="text-orange-400 shrink-0 font-bold">{k}:</span>
                        <span className="text-slate-400 break-all">{v}</span>
                      </div>
                    ))}
                  </div>
                </div>
                {Object.keys(log.details.response_cookies).length > 0 && (
                  <div>
                    <div className="text-[10px] font-bold text-slate-500 mb-2 uppercase tracking-wider flex items-center gap-2">
                      <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                      Cookies
                    </div>
                    <div className="space-y-1 bg-[#0a0a0c] rounded-xl p-3 border border-white/[0.02]">
                      {Object.entries(log.details.response_cookies).map(([k, v]) => (
                        <div key={k} className="flex gap-2">
                          <span className="text-pink-400 shrink-0">{k}:</span>
                          <span className="text-slate-400 break-all">{v}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
                <div>
                  <div className="flex justify-between items-center mb-2">
                    <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider flex items-center gap-2">
                      <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 6h16M4 12h16M4 18h7"></path></svg>
                      Response Body
                    </span>
                    <div className="flex items-center gap-2">
                      {isHtmlResponse && (
                        <button
                          onClick={(e) => { e.stopPropagation(); setShowHtmlPreview(!showHtmlPreview); }}
                          className={`text-[10px] px-2 py-1 rounded transition-colors ${showHtmlPreview ? 'bg-emerald-500/20 text-emerald-400' : 'bg-white/[0.02] text-slate-400 hover:text-white'}`}
                        >
                          {showHtmlPreview ? 'Raw' : 'Preview'}
                        </button>
                      )}
                      {!showHtmlPreview && matchCount > 0 && <span className="text-[10px] text-slate-400 bg-white/[0.02] px-2 py-0.5 rounded font-mono">{matchIndex + 1}/{matchCount}</span>}
                      {!showHtmlPreview && (
                        <input
                          className="bg-[#12121a] border border-white/[0.03] rounded-lg px-3 py-1 text-[10px] text-white outline-none focus:border-emerald-500 w-32 placeholder-slate-600"
                          placeholder="Search..."
                          value={searchTerm}
                          onChange={(e) => { setSearchTerm(e.target.value); setMatchIndex(0); }}
                          onKeyDown={handleSearchKeyDown}
                          onClick={(e) => e.stopPropagation()}
                        />
                      )}
                      <button 
                        onClick={() => navigator.clipboard.writeText(log.details?.response_body || "")}
                        className="text-[9px] font-black text-slate-600 hover:text-emerald-400 uppercase tracking-widest transition-colors"
                      >
                        Copy
                      </button>
                    </div>
                  </div>
                  {showHtmlPreview && isHtmlResponse ? (
                    <iframe
                      srcDoc={log.details.response_body}
                      sandbox="allow-same-origin"
                      className="w-full h-80 bg-white rounded-xl border border-white/[0.02]"
                      title="HTML Preview"
                    />
                  ) : (
                    <div className="bg-[#0a0a0c] border border-white/[0.02] p-3 rounded-xl text-slate-400 break-all whitespace-pre-wrap max-h-80 overflow-y-auto custom-scrollbar shadow-inner">
                      <HighlightedText
                        text={log.details.response_body}
                        term={searchTerm}
                        currentIndex={matchIndex}
                        onMatchesFound={setMatchCount}
                      />
                    </div>
                  )}
                </div>
              </div>
            ) : (
              <div>
                <div className="text-[10px] font-bold text-slate-500 mb-2 uppercase tracking-wider flex items-center gap-2">
                  <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M8 10h.01M12 10h.01M16 10h.01M9 16H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-5l-5 5v-5z"></path></svg>
                  Execution Message
                </div>
                <div className="bg-[#0a0a0c] border border-white/[0.02] p-4 rounded-xl text-slate-300 break-all whitespace-pre-wrap max-h-96 overflow-y-auto custom-scrollbar shadow-inner">
                  {log.message}
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function HighlightedText({ text, term, currentIndex, onMatchesFound }: { text: string, term: string, currentIndex: number, onMatchesFound: (count: number) => void }) {
  const currentRef = useRef<HTMLSpanElement>(null);

  const matches = useMemo(() => {
      if (!term) return null;
      const escapedTerm = term.replace(/[-/\\^$*+?.()|[\]{}]/g, '\\$&');
      const regex = new RegExp(`(${escapedTerm})`, 'gi');
      return text.split(regex);
  }, [text, term]);

  useEffect(() => {
      if (!matches) {
          onMatchesFound(0);
          return;
      }
      const count = Math.floor(matches.length / 2);
      onMatchesFound(count);
  }, [matches, onMatchesFound]);

  useEffect(() => {
      if (currentRef.current) {
          currentRef.current.scrollIntoView({ behavior: 'smooth', block: 'center' });
      }
  }, [currentIndex, term]);

  if (!matches || !term) return <>{text}</>;

  let matchCounter = 0;
  return (
    <>
      {matches.map((part, i) => {
        if (part.toLowerCase() === term.toLowerCase()) {
            const isCurrent = matchCounter === currentIndex;
            matchCounter++;
            return (
                <span
                    key={i}
                    ref={isCurrent ? currentRef : null}
                    className={`font-bold rounded-sm px-0.5 text-white ${isCurrent ? 'bg-orange-500' : 'bg-yellow-500'}`}
                >
                    {part}
                </span>
            );
        }
        return part;
      })}
    </>
  );
}

function Select({ label, value, onChange, options, children, placeholder }: { label?: string, value: string, onChange: (v: string) => void, options?: string[], children?: React.ReactNode, placeholder?: string }) {
    const [isOpen, setIsOpen] = useState(false);
    const [search, setSearch] = useState("");
    const wrapperRef = useRef<HTMLDivElement>(null);
    
    let finalOptions: string[] = options || [];

    const filtered = finalOptions.filter(o => !search || o.toLowerCase().includes(search.toLowerCase()));

    // Process children if provided to extract value/label
    const childrenOptions = useMemo(() => {
        if (options) return null;
        return (React.Children.map(children, (child) => {
            if (child && typeof child === 'object' && 'props' in child) {
                const props = (child as React.ReactElement).props as any;
                const type = (child as React.ReactElement).type;
                
                if (type === 'option') {
                    return {
                        value: props.value,
                        label: props.children,
                        className: props.className
                    };
                }
                if (type === 'optgroup') {
                    return {
                        label: props.label,
                        isGroup: true,
                        children: React.Children.map(props.children, (c: any) => ({
                            value: c.props.value,
                            label: c.props.children,
                            className: c.props.className
                        }))
                    };
                }
            }
            return null;
        }) || []).filter(Boolean);
    }, [children, options]);

    useEffect(() => {
        const handleClickOutside = (event: MouseEvent) => {
            if (wrapperRef.current && !wrapperRef.current.contains(event.target as any)) {
                setIsOpen(false);
            }
        };
        if (isOpen) {
            document.addEventListener("mousedown", handleClickOutside);
            
            // Add ultra-high z-index to parent section when dropdown is open
            const section = wrapperRef.current?.closest('.properties-section');
            if (section) (section as HTMLElement).style.zIndex = "99999";
        }
        return () => {
            document.removeEventListener("mousedown", handleClickOutside);
            // Restore z-index
            const section = wrapperRef.current?.closest('.properties-section');
            if (section) (section as HTMLElement).style.zIndex = "";
        };
    }, [isOpen]);

    return (
        <div className="relative" ref={wrapperRef}>
            {label && (
                <label className="flex items-center gap-1.5 text-[10px] font-black text-slate-500 mb-1.5 uppercase tracking-wider">
                    <span className="w-1 h-1 rounded-full bg-slate-600"></span>
                    {label}
                </label>
            )}
            <div className="relative group">
                <button
                    type="button"
                    onClick={() => setIsOpen(!isOpen)}
                    className={`w-full bg-[#0a0a0c] border rounded-xl px-4 py-2.5 text-xs font-mono text-white flex items-center justify-between transition-all duration-300 shadow-sm ${isOpen ? 'border-emerald-500 ring-1 ring-emerald-500/20' : 'border-white/10 hover:border-white/20'}`}
                >
                    <span className="truncate pr-4">
                        {(() => {
                            if (value) {
                                if (options) return value;
                                // Find label from childrenOptions
                                let foundLabel = value;
                                childrenOptions?.forEach((co: any) => {
                                    if (co.isGroup) {
                                        co.children?.forEach((c: any) => {
                                            if (c.value === value) foundLabel = c.label;
                                        });
                                    } else if (co.value === value) {
                                        foundLabel = co.label;
                                    }
                                });
                                return foundLabel;
                            }
                            return placeholder || "Select...";
                        })()}
                    </span>
                    <svg className={`w-3.5 h-3.5 text-slate-500 transition-transform duration-300 ${isOpen ? 'rotate-180 text-emerald-500' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="3" d="M19 9l-7 7-7-7"></path>
                    </svg>
                </button>

                {isOpen && (
                    <div className="absolute top-full left-0 right-0 z-[99999] mt-2 max-h-[400px] overflow-y-auto bg-[#0a0a0c] border border-white/10 rounded-2xl shadow-[0_25px_60px_-15px_rgba(0,0,0,0.9)] custom-scrollbar animate-in fade-in duration-200 backdrop-blur-3xl ring-1 ring-white/5">
                        {(finalOptions.length > 8 || (childrenOptions && childrenOptions.length > 8)) && (
                            <div className="px-2 pb-2 mb-2 border-b border-white/[0.03]">
                                <input 
                                    autoFocus
                                    className="w-full bg-white/[0.03] border border-white/[0.05] rounded-lg px-3 py-2 text-[10px] text-white placeholder-slate-600 outline-none focus:border-emerald-500/50 transition-all"
                                    placeholder="Search options..."
                                    value={search}
                                    onChange={(e) => setSearch(e.target.value)}
                                    onClick={(e) => e.stopPropagation()}
                                />
                            </div>
                        )}
                        <div className="space-y-0.5">
                            {options ? (
                                filtered.map(o => (
                                    <button
                                        key={o}
                                        type="button"
                                        onMouseDown={(e) => { e.preventDefault(); onChange(o); setIsOpen(false); }}
                                        className={`w-full text-left px-3 py-2 text-[11px] rounded-xl transition-all flex items-center justify-between group ${value === o ? 'bg-emerald-500 text-white font-bold shadow-lg shadow-emerald-500/20' : 'text-slate-400 hover:text-white hover:bg-white/[0.05]'}`}
                                    >
                                        {o}
                                        {value === o && <div className="w-1.5 h-1.5 rounded-full bg-white shadow-[0_0_8px_white]"></div>}
                                    </button>
                                ))
                            ) : (
                                childrenOptions?.map((co: any, idx: number) => {
                                    if (co.isGroup) {
                                        return (
                                            <div key={idx} className="space-y-0.5">
                                                <div className="px-3 py-2 text-[9px] font-black text-slate-600 uppercase tracking-[0.2em] bg-white/[0.01] rounded-lg mt-2 first:mt-0">
                                                    {co.label}
                                                </div>
                                                {co.children?.map((c: any) => (
                                                    <button
                                                        key={c.value}
                                                        type="button"
                                                        onMouseDown={(e) => { e.preventDefault(); onChange(c.value); setIsOpen(false); }} 
                                                        className={`w-full text-left px-4 py-2 text-[11px] rounded-xl transition-all flex items-center justify-between group ${value === c.value ? 'bg-emerald-500 text-white font-bold' : 'text-slate-400 hover:text-white hover:bg-white/[0.05]'}`}
                                                    >
                                                        {c.label}
                                                        {value === c.value && <div className="w-1.5 h-1.5 rounded-full bg-white shadow-[0_0_8px_white]"></div>}
                                                    </button>
                                                ))}
                                            </div>
                                        );
                                    }
                                    return (
                                        <button
                                            key={co.value}
                                            type="button"
                                            onMouseDown={(e) => { e.preventDefault(); onChange(co.value); setIsOpen(false); }} 
                                            className={`w-full text-left px-3 py-2 text-[11px] rounded-xl transition-all flex items-center justify-between group ${value === co.value ? 'bg-emerald-500 text-white font-bold shadow-lg shadow-emerald-500/20' : 'text-slate-400 hover:text-white hover:bg-white/[0.05]'}`}
                                        >
                                            {co.label}
                                            {value === co.value && <div className="w-1.5 h-1.5 rounded-full bg-white shadow-[0_0_8px_white]"></div>}
                                        </button>
                                    );
                                })
                            )}
                        </div>
                    </div>
                )}
            </div>
        </div>
    );
}

function Field({ label, value, onChange, placeholder, type = "text", className }: { label: string, value: string, onChange: (v: string) => void, placeholder?: string, type?: string, className?: string }) {
    return (
        <div className={className}>
            <label className="flex items-center gap-1.5 text-[10px] font-black text-slate-500 mb-1.5 uppercase tracking-widest">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.4)]"></span>
                {label}
            </label>
            <div className="relative group">
                <input
                    type={type}
                    className="w-full bg-[#0a0a0c] border border-white/10 rounded-xl px-3 py-2.5 text-xs font-mono text-emerald-400 placeholder-white/50 focus:border-emerald-500 focus:bg-[#08080a] focus:ring-1 focus:ring-emerald-500/20 outline-none transition-all duration-300 shadow-inner"
                    value={value}
                    onChange={(e) => onChange(e.target.value)}
                    placeholder={placeholder ? `"${placeholder}"` : undefined}
                />
                <div className="absolute inset-0 rounded-xl ring-1 ring-white/[0.02] pointer-events-none group-hover:ring-white/[0.05] transition-all"></div>
            </div>
        </div>
    )
}

function Toggle({ checked, onChange }: { checked: boolean, onChange: (c: boolean) => void }) {
    return (
        <button
            onClick={() => onChange(!checked)}
            className={`relative w-9 h-5 rounded-full transition-all duration-300 ${checked ? 'bg-emerald-500 shadow-[0_0_10px_rgba(16,185,129,0.3)]' : 'bg-white/[0.02] border border-white/[0.03]'}`}
        >
            <div className={`absolute top-1 left-1 w-3 h-3 bg-white rounded-full shadow-lg transition-transform duration-300 ${checked ? 'translate-x-4' : 'translate-x-0'}`}></div>
        </button>
    )
}

function getAvailableVariables(blocks: Block[]): string[] {
    const defaults = ["SOURCE", "STATUS", "URL", "RURL", "HEADERS", "COOKIES", "HEADER_NAME", "COOKIE_NAME", "LOCATION", "RAWSOURCE"];
    const customVars = new Set<string>();
    
    // Add common input variables
    customVars.add("USER");
    customVars.add("PASS");

    blocks.forEach(b => {
        if (b.data.variable) customVars.add(b.data.variable);
        if (b.data.output_variable) customVars.add(b.data.output_variable);
    });
    
    // Remove defaults from custom vars to avoid duplicates in the sorted list
    defaults.forEach(d => customVars.delete(d));

    return [...defaults, ...Array.from(customVars).sort()];
}

function VariableInput({ value, onChange, suggestions, placeholder, className, label }: { value: string, onChange: (v: string) => void, suggestions: string[], placeholder?: string, className?: string, label?: string }) {
    const [showSuggestions, setShowSuggestions] = useState(false);
    
    return (
        <div className="relative group/var-input">
            {label && (
                <label className="flex items-center gap-1.5 text-[10px] font-black text-slate-500 mb-1.5 uppercase tracking-widest">
                    <span className="w-1.5 h-1.5 rounded-full bg-pink-500 shadow-[0_0_8px_rgba(236,72,153,0.4)]"></span>
                    {label}
                </label>
            )}
            <div className="relative">
                <input
                    className={className || "w-full bg-[#0a0a0c] border border-white/10 rounded-xl px-3 py-2.5 text-xs font-mono text-pink-400 placeholder-white/50 focus:border-pink-500 focus:bg-[#08080a] focus:ring-1 focus:ring-pink-500/20 outline-none transition-all duration-300 shadow-inner"}
                    value={value}
                    onChange={(e) => onChange(e.target.value)}
                    onFocus={() => setShowSuggestions(true)}
                    onBlur={() => setTimeout(() => setShowSuggestions(false), 200)}
                    placeholder={placeholder ? `"${placeholder}"` : undefined}
                />
                <div className="absolute right-3 top-1/2 -translate-y-1/2 pointer-events-none opacity-20 group-focus-within/var-input:opacity-100 transition-opacity">
                    <svg className="w-3.5 h-3.5 text-pink-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2.5" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4"></path></svg>
                </div>
            </div>
            {showSuggestions && (
                <div className="absolute top-full left-0 right-0 z-50 mt-1 max-h-48 overflow-y-auto bg-[#0a0a0c] border border-white/[0.03] rounded-xl shadow-2xl custom-scrollbar animate-in fade-in slide-in-from-top-1 duration-200 backdrop-blur-xl">
                    {suggestions.filter(s => !value || s.toLowerCase().includes(value.toLowerCase())).map(s => (
                        <button
                            key={s}
                            onMouseDown={() => onChange(s)}
                            className="w-full text-left px-4 py-2.5 text-xs text-slate-300 hover:bg-pink-500/10 hover:text-pink-400 transition-all flex items-center gap-2  last:border-0 group/item"
                        >
                            <span className="w-1.5 h-1.5 rounded-full bg-pink-500/30 group-hover/item:bg-pink-500 shadow-[0_0_5px_rgba(236,72,153,0.5)] transition-all"></span>
                            {s}
                        </button>
                    ))}
                    {suggestions.length === 0 && (
                        <div className="px-4 py-2.5 text-[10px] text-slate-600 font-bold uppercase tracking-widest italic">No variables found</div>
                    )}
                </div>
            )}
        </div>
    );
}

function PropertiesSection({ title, icon, children, defaultOpen = true }: { title: string, icon?: string, children: React.ReactNode, defaultOpen?: boolean }) {
    const [isOpen, setIsOpen] = useState(defaultOpen);

    return (
        <div className={`properties-section rounded-2xl border transition-all duration-500 mb-4 ${isOpen ? 'bg-[#0a0a0c]/40 border-white/[0.03] shadow-2xl overflow-visible relative z-[50]' : 'bg-white/[0.01] border-white/[0.03] shadow-sm overflow-hidden'}`}>
            <button
                onClick={() => setIsOpen(!isOpen)}
                className={`w-full flex items-center justify-between p-4 transition-all duration-300 ${isOpen ? 'bg-white/[0.02]' : 'hover:bg-white/[0.03]'}`}
            >
                <div className="flex items-center gap-3">
                    <div className={`w-8 h-8 rounded-lg flex items-center justify-center text-sm transition-all duration-500 ${isOpen ? 'bg-white/10 text-white shadow-lg rotate-3' : 'bg-white/[0.02] text-slate-500 grayscale'}`}>
                        {icon || "⚙️"}
                    </div>
                    <span className={`text-[11px] font-black uppercase tracking-[0.2em] transition-colors ${isOpen ? 'text-white' : 'text-slate-500'}`}>
                        {title}
                    </span>
                </div>
                <div className={`w-6 h-6 rounded-full flex items-center justify-center transition-all duration-300 ${isOpen ? 'bg-white/10 text-white rotate-180' : 'text-slate-700 hover:text-slate-400'}`}>
                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="3" d="M19 9l-7 7-7-7"></path>
                    </svg>
                </div>
            </button>
            {isOpen && (
                <div className="p-5 space-y-5 animate-in fade-in duration-300">
                    {children}
                </div>
            )}
        </div>
    );
}

function ParseBlockSettings({ block, handleChange, availableVariables }: { block: Block, handleChange: (f: string, v: any) => void, availableVariables: string[] }) {
    const mode = block.data.mode || 'LR';
    const [regexHelperInput, setRegexHelperInput] = useState("");
    const [regexHelperValue, setRegexHelperValue] = useState("");
    const [testResult, setTestResult] = useState<string | null>(null);
    
        const generateRegex = () => {
        const input = regexHelperInput;
        const value = regexHelperValue.trim();
        if (!input || !value) return;
        
        try {
            const valIdx = input.indexOf(value);
            if (valIdx === -1) {
                alert("Value not found in sample string!");
                return;
            }

            const beforeText = input.substring(0, valIdx);
            const afterText = input.substring(valIdx + value.length);

            // Escape utility
            const esc = (s: string) => s.replace(/[.*+?^${}()|[\\]/g, '\\$&');

            // --- SCAN BACKWARDS for Left Delimiter ---
            let leftDelim = "";
            let i = valIdx - 1;
            let capturedLeft = 0;
            const maxLookBack = 25; 

            while (i >= 0 && capturedLeft < maxLookBack) {
                const char = input[i];
                // Prepend char
                leftDelim = char + leftDelim;
                
                // Heuristics to stop:
                // 1. Found a space AFTER seeing an equals or colon (e.g. `name= value=`)
                if (/\s/.test(char) && /[=:]/.test(leftDelim)) {
                    // We likely captured `name=". The space before it is a good boundary.
                    break; 
                }
                // 2. Found an opening tag `<`
                if (char === '<') break;
                // 3. Found a newline
                if (char === '\n') break;

                i--;
                capturedLeft++;
            }

            // --- SCAN FORWARD for Right Delimiter ---
            let rightDelim = "";
            let j = 0;
            let capturedRight = 0;
            const maxLookAhead = 15;

            while (j < afterText.length && capturedRight < maxLookAhead) {
                const char = afterText[j];
                rightDelim += char;
                
                // Heuristics to stop:
                // 1. Found a quote
                if (/['"]/.test(char)) {
                    // If we have context, check if next char is > or space or /
                    // e.g. `value="123" ` or `value="123"/>`
                    if (j + 1 < afterText.length) {
                        const next = afterText[j+1];
                        if (/[ >/]/.test(next)) {
                             // If it's `/>`, include it
                             if (next === '/' && j + 2 < afterText.length && afterText[j+2] === '>') {
                                 rightDelim += "/>";
                             } else if (next === '>') {
                                 rightDelim += ">";
                             }
                             break;
                        }
                    }
                    // If it's just a quote and we are at the start (value="..."), valid stop
                    break;
                }
                // 2. Found closing tag
                if (char === '>') break;
                // 3. Found newline
                if (char === '\n') break;
                // 4. Found space (if not inside quotes?) - simple case: stop at space
                if (char === ' ' && !/['"]/.test(rightDelim)) break;

                j++;
                capturedRight++;
            }

            // Cleanup
            leftDelim = leftDelim.trim();
            // If left is empty (e.g. value at start of line), fallback to just taking last few chars
            if (!leftDelim) leftDelim = beforeText.slice(-Math.min(5, beforeText.length)).trim();
            
            // Construct Regex with Flexible Quotes
            // We use simple replace for escaped quotes because the input 's' is already escaped by 'esc'
            // 'esc' turns " into \
            // So we look for \
                                                            const makeFlexible = (s: string) => esc(s)
                .replace(/\\\\"/g, "['\\\"]?")
                .replace(/\\\'/g, "['\\\"]?")
                .replace(/\s+/g, "\\s*");
            const flexibleLeft = makeFlexible(leftDelim);
            const flexibleRight = makeFlexible(rightDelim);

            const pattern = `${flexibleLeft}(.*?)${flexibleRight}`;
            
            // Force state update
            handleChange("regex_pattern", pattern);
            handleChange("regex_output", "$1");
            
            alert("Smart Regex Generated and Applied!");
            setRegexHelperValue("");
        } catch (e) {
            console.error("Regex helper error:", e);
        }
    };

    // Live test effect
    useEffect(() => {
        if (block.data.regex_pattern && regexHelperInput) {
            try {
                const re = new RegExp(block.data.regex_pattern, block.data.regex_case_insensitive ? 'i' : '');
                const match = regexHelperInput.match(re);
                if (match) {
                    if (block.data.regex_output === '$1' || !block.data.regex_output) {
                        setTestResult(match[1] || match[0]);
                    } else {
                        setTestResult("MATCH FOUND");
                    }
                } else {
                    setTestResult(null);
                }
            } catch {
                setTestResult("INVALID REGEX");
            }
        } else {
            setTestResult(null);
        }
    }, [block.data.regex_pattern, block.data.regex_output, block.data.regex_case_insensitive, regexHelperInput]);

    return (
        <div className="space-y-4 animate-in fade-in duration-300">
            <div>
                <label className="block text-[10px] font-bold text-slate-500 mb-1 uppercase tracking-wider">OUTPUT VARIABLE</label>
                <VariableInput 
                    value={block.data.variable ?? ""} 
                    onChange={(v) => handleChange("variable", v)} 
                    suggestions={availableVariables}
                    placeholder="parsed"
                    className="w-full bg-[#0a0a0c] border border-white/[0.03] rounded-xl p-2.5 text-sm text-pink-400 font-bold outline-none focus:border-pink-500 transition-colors"
                />
            </div>
            <div>
                <label className="block text-[10px] font-black text-slate-500 mb-1.5 uppercase tracking-[0.1em]">Target Source</label>
                <VariableInput 
                    value={block.data.source ?? ""} 
                    onChange={(v) => handleChange("source", v)} 
                    suggestions={availableVariables}
                    placeholder="SOURCE"
                />
            </div>
            <Select label="Parsing Logic" value={mode} onChange={(v) => handleChange("mode", v)}>
                <option value="LR">LR (Left/Right Delimiters)</option>
                <option value="JSON">JSON (Standard Object Path)</option>
                <option value="Regex">Regex (Pattern Matcher)</option>
            </Select>

            {/* Mode Description */}
            <div className="bg-[#0a0a0c] border border-white/[0.03] rounded-xl p-3">
                <div className="text-[10px] text-slate-400">
                    {mode === 'LR' && (
                        <div className="flex items-start gap-2">
                            <span className="text-emerald-400">💡</span>
                            <div>
                                <span className="font-bold text-slate-300">Left/Right Parsing:</span> Extracts text between two delimiters.
                                <div className="text-slate-500 mt-1">Example: Left: <code className="text-green-400">"token":"</code> Right: <code className="text-green-400">"</code></div>
                            </div>
                        </div>
                    )}
                    {mode === 'JSON' && (
                        <div className="flex items-start gap-2">
                            <span className="text-purple-400">💡</span>
                            <div>
                                <span className="font-bold text-slate-300">JSON Path:</span> Navigate JSON objects using dot notation.
                                <div className="text-slate-500 mt-1">Example: <code className="text-green-400">data.user.id</code> or <code className="text-green-400">items[0].name</code></div>
                            </div>
                        </div>
                    )}
                    {mode === 'Regex' && (
                        <div className="flex items-start gap-2">
                            <span className="text-orange-400">💡</span>
                            <div>
                                <span className="font-bold text-slate-300">Regex:</span> Use capture groups to extract patterns.
                                <div className="text-slate-500 mt-1">Example: <code className="text-green-400">token=([a-f0-9]+)</code> with output <code className="text-green-400">$1</code></div>
                            </div>
                        </div>
                    )}
                </div>
            </div>

            {mode === 'JSON' ? (
                <div className="animate-in slide-in-from-top-1 duration-200">
                    <Field label="JSON Path" value={block.data.json_path || ''} onChange={(v) => handleChange("json_path", v)} placeholder="user.profile.id" />
                </div>
            ) : mode === 'Regex' ? (
                <div className="space-y-4 animate-in slide-in-from-top-1 duration-200">
                    <div className="grid grid-cols-1 gap-4">
                        <Field label="Regex Pattern" value={block.data.regex_pattern || ''} onChange={(v) => handleChange("regex_pattern", v)} placeholder="token=(.*?)" />
                        <Field label="Output Format" value={block.data.regex_output || '$1'} onChange={(v) => handleChange("regex_output", v)} placeholder="$1" />
                    </div>

                    {testResult && (
                        <div className={`p-2 rounded-lg border text-[10px] font-mono flex items-center gap-2 ${testResult === 'INVALID REGEX' ? 'bg-red-500/10 border-red-500/30 text-red-400' : 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'}`}>
                            <span className="font-bold uppercase tracking-widest">{testResult === 'INVALID REGEX' ? 'Error:' : 'Live Match:'}</span>
                            <span className="truncate">{testResult}</span>
                        </div>
                    )}

                    <div className="grid grid-cols-2 gap-4">
                        <div className="flex items-center justify-between bg-white/[0.02] p-2.5 rounded-xl border border-slate-700/30">
                            <span className="text-[10px] text-slate-400 font-bold uppercase tracking-tighter">Case Insensitive</span>
                            <Toggle checked={block.data.regex_case_insensitive || false} onChange={(c) => handleChange("regex_case_insensitive", c)} />
                        </div>
                        <div className="flex items-center justify-between bg-white/[0.02] p-2.5 rounded-xl border border-slate-700/30" title="Allow dot (.) to match newlines">
                            <span className="text-[10px] text-slate-400 font-bold uppercase tracking-tighter">Dot All</span>
                            <Toggle checked={block.data.regex_dot_all !== false} onChange={(c) => handleChange("regex_dot_all", c)} />
                        </div>
                    </div>
                    
                    <div className="p-5 bg-gradient-to-br from-slate-800/10 to-slate-900/5 border border-emerald-500/20 rounded-2xl space-y-4 shadow-xl">
                        <div className="flex items-center justify-between">
                            <div className="flex items-center gap-2.5">
                                <div className="w-8 h-8 rounded-lg bg-emerald-500/10 flex items-center justify-center text-emerald-400 border border-emerald-500/20">🛠️</div>
                                <h4 className="text-[10px] font-black text-emerald-400 uppercase tracking-widest">Regex Pattern Finder</h4>
                            </div>
                        </div>
                        <div className="space-y-3">
                            <div>
                                <label className="block text-[9px] font-bold text-slate-500 uppercase mb-1 ml-1">1. Sample String (Paste HTML/Text)</label>
                                <textarea 
                                    className="w-full h-24 bg-slate-950 border border-white/[0.03] rounded-xl p-3 text-[10px] font-mono text-white resize-none outline-none focus:border-emerald-500 shadow-inner custom-scrollbar"
                                    value={regexHelperInput}
                                    onChange={(e) => setRegexHelperInput(e.target.value)}
                                    placeholder='e.g. <input name="_token" value="930954313292f..."/>'
                                ></textarea>
                            </div>
                            <div>
                                <label className="block text-[9px] font-bold text-slate-500 uppercase mb-1 ml-1">2. Value to Capture (Paste exact text)</label>
                                <input 
                                    className="w-full bg-slate-950 border border-white/[0.03] rounded-xl p-3 text-[10px] font-mono text-white outline-none focus:border-emerald-500 shadow-inner"
                                    value={regexHelperValue}
                                    onChange={(e) => setRegexHelperValue(e.target.value)}
                                    placeholder="Paste the exact part you want to parse out..."
                                />
                            </div>
                            <button 
                                onClick={generateRegex}
                                className="w-full py-3 bg-emerald-500 hover:bg-white/[0.05] text-white text-[10px] font-black uppercase tracking-[0.2em] rounded-xl transition-all shadow-lg shadow-black/20 active:scale-[0.98] border border-emerald-400/20"
                            >
                                Generate & Test Pattern
                            </button>
                        </div>
                    </div>
                </div>
            ) : (
                <div className="grid grid-cols-2 gap-4 animate-in slide-in-from-top-1 duration-200">
                    <Field label="Left Delimiter" value={block.data.left || ''} onChange={(v) => handleChange("left", v)} />
                    <Field label="Right Delimiter" value={block.data.right || ''} onChange={(v) => handleChange("right", v)} />
                </div>
            )}
            
            <div className="flex items-center justify-between bg-white/[0.02] p-3.5 rounded-xl border border-slate-700/30">
                <div className="flex flex-col">
                    <span className="text-[11px] text-slate-300 font-bold uppercase tracking-tight">Recursive</span>
                    <span className="text-[9px] text-slate-500 mt-0.5 font-medium">Extract all instances into a list</span>
                </div>
                <Toggle checked={block.data.recursive || false} onChange={(c) => handleChange("recursive", c)} />
            </div>

            <div className="pt-5  mt-5 space-y-4">
                 <div className="flex items-center justify-between bg-white/[0.02] p-3 rounded-xl border border-slate-700/30">
                    <span className="text-[10px] text-slate-300 font-black uppercase tracking-widest">Capture</span>
                    <Toggle checked={block.data.capture || false} onChange={(c) => handleChange("capture", c)} />
                 </div>
            </div>
        </div>
    );
}

function MultipartFieldsEditor({ multipartFields, onUpdate, availableVariables, block, handleChange }: {
    multipartFields: MultipartField[];
    onUpdate: (fields: MultipartField[]) => void;
    availableVariables: string[];
    block: Block;
    handleChange: (field: string, value: any) => void;
}) {
    const isRaw = block.data.multipart_raw_enabled ?? false;
    const [rawJson, setRawJson] = useState(() => {
        // In Raw mode, we look for a field named 'data'
        const dataField = multipartFields.find(f => f.name === "data" && !f.is_file);
        if (dataField) return dataField.data;
        // Fallback: if no 'data' field, but we have other fields, maybe we just switched
        const firstTextField = multipartFields.find(f => !f.is_file);
        return firstTextField ? firstTextField.data : "";
    });

    const addField = () => {
        onUpdate([...multipartFields, { name: "", data: "", is_file: false }]);
    };

    const updateField = (index: number, fieldName: keyof MultipartField, value: any) => {
        const newFields = [...multipartFields];
        newFields[index] = { ...newFields[index], [fieldName]: value };
        onUpdate(newFields);
    };

    const removeField = (index: number) => {
        onUpdate(multipartFields.filter((_, i) => i !== index));
    };

    const handleRawChange = (val: string) => {
        setRawJson(val);
        const newFields: MultipartField[] = [];
        // Keep existing file fields
        for (const f of multipartFields) {
            if (f.is_file) newFields.push(f);
        }
        // Add/Update the single 'data' field for BestHTTP
        newFields.push({ 
            name: "data", 
            data: val, 
            is_file: false, 
            content_type: "text/plain; charset=utf-8" 
        });
        onUpdate(newFields);
    };

    const toggleRaw = (enabled: boolean) => {
        if (enabled) {
            // When switching to raw, try to find existing data or construct it
            const dataField = multipartFields.find(f => f.name === "data" && !f.is_file);
            const val = dataField ? dataField.data : (multipartFields.find(f => !f.is_file)?.data || "");
            setRawJson(val);
            
            const newFields: MultipartField[] = multipartFields.filter(f => f.is_file);
            newFields.push({ 
                name: "data", 
                data: val, 
                is_file: false, 
                content_type: "text/plain; charset=utf-8" 
            });
            onUpdate(newFields);
        }
        handleChange("multipart_raw_enabled", enabled);
    };

    return (
        <div className="space-y-4">
            <div className="flex items-center justify-between bg-white/[0.02]/20 p-2 rounded-lg border border-white/[0.02] mb-2">
                <div className="flex flex-col ml-1">
                    <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">Editor Mode</span>
                    <span className="text-[8px] text-slate-600 font-medium">Use Raw for GOP3 / BestHTTP</span>
                </div>
                <div className="flex bg-white/[0.01] rounded-md p-0.5 border border-white/[0.03]">
                    <button 
                        type="button"
                        onClick={() => toggleRaw(false)}
                        className={`px-3 py-1 text-[9px] font-bold uppercase tracking-tighter rounded-sm transition-all ${!isRaw ? 'bg-emerald-500 text-white shadow-lg' : 'text-slate-500 hover:text-slate-300'}`}
                    >
                        Table
                    </button>
                    <button 
                        type="button"
                        onClick={() => toggleRaw(true)}
                        className={`px-3 py-1 text-[9px] font-bold uppercase tracking-tighter rounded-sm transition-all ${isRaw ? 'bg-pink-600 text-white shadow-lg' : 'text-slate-500 hover:text-slate-300'}`}
                    >
                        Raw (data)
                    </button>
                </div>
            </div>

            {isRaw ? (
                <div className="animate-in fade-in zoom-in-95 duration-200">
                    <textarea 
                        className="w-full h-48 bg-[#0a0a0c] border border-white/[0.03] rounded-xl p-3 text-xs font-mono text-pink-400/90 resize-none custom-scrollbar focus:border-pink-500 focus:bg-[#08080c] focus:ring-1 focus:ring-pink-500/20 outline-none transition-all duration-200 shadow-inner"
                        value={rawJson} 
                        onChange={(e) => handleRawChange(e.target.value)} 
                        placeholder='{"key": "value"}'
                    ></textarea>
                    <div className="mt-2 text-[9px] text-slate-500 italic flex items-center gap-1.5">
                        <span className="w-1 h-1 rounded-full bg-pink-500"></span>
                        Sends entire input as single field: <code className="text-pink-400 font-bold">name="data"</code>
                    </div>
                </div>
            ) : (
                <div className="space-y-4 animate-in fade-in duration-200">
                    {multipartFields.map((field, index) => (
                        <div key={index} className="bg-[#0a0a0c]/40 border border-white/[0.03] rounded-xl p-3 space-y-3 shadow-sm group hover:border-slate-700 transition-colors">
                            <div className="flex items-center gap-2">
                                <Field
                                    label="Name"
                                    value={field.name}
                                    onChange={(v) => updateField(index, "name", v)}
                                    placeholder="field_name"
                                    className="flex-1"
                                />
                                <div className="flex items-center gap-2">
                                    <span className="text-[10px] font-bold text-slate-400 uppercase">Is File</span>
                                    <Toggle checked={field.is_file} onChange={(c) => updateField(index, "is_file", c)} />
                                </div>
                                <button
                                    onClick={() => removeField(index)}
                                    className="p-1.5 rounded-lg text-slate-600 hover:text-red-400 hover:bg-red-500/10 transition-colors"
                                >
                                    <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12"></path></svg>
                                </button>
                            </div>
                            <VariableInput
                                label="Data"
                                value={field.data}
                                onChange={(v) => updateField(index, "data", v)}
                                suggestions={availableVariables}
                                placeholder={field.is_file ? "Path or <VARIABLE>" : "Value or <VARIABLE>"}
                                className="w-full bg-[#0a0a0c] border border-white/[0.03] rounded-xl p-2.5 text-xs font-mono text-pink-400 placeholder-slate-800 focus:border-pink-500 focus:bg-[#08080a] focus:ring-1 focus:ring-pink-500/20 outline-none transition-all duration-300 shadow-inner"
                            />
                        </div>
                    ))}
                    <button
                        onClick={addField}
                        className="w-full text-[10px] font-black bg-emerald-500/10 text-emerald-400 hover:bg-emerald-500/20 px-3 py-2.5 rounded-xl border border-emerald-500/20 transition-all uppercase tracking-widest flex items-center justify-center gap-1.5 shadow-sm"
                    >
                        <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2.5" d="M12 4v16m8-8H4"></path></svg>
                        Add Field
                    </button>
                </div>
            )}
        </div>
    );
}

function renderBlockSettings(block: Block, updateBlockData: (id: string, data: any) => void, availableVariables: string[] = []) {
    const handleChange = (field: string, value: any) => {
        updateBlockData(block.id, { [field]: value });
    };

    // Common controls for all blocks
    const CommonControls = () => (
        <div className="space-y-3 pb-4 mb-4 ">
            <Field label="Comment" value={block.data.comment || ''} onChange={(v) => handleChange("comment", v)} placeholder="Add a note..." />
            <div className="flex items-center justify-between bg-white/[0.02] border border-white/[0.03] p-3 rounded-xl hover:bg-white/[0.04] transition-all">
                <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">Disabled</span>
                <Toggle checked={block.data.disabled || false} onChange={(c) => handleChange("disabled", c)} />
            </div>
        </div>
    );

    switch (block.block_type) {
        case "Request":
            return (
                <div className="space-y-4">
                    <CommonControls />
                    
                    <PropertiesSection title="Request Details" icon="🌐">
                        <div className="grid grid-cols-4 gap-3">
                            <div className="col-span-1">
                                <Field label="Method" value={block.data.method} onChange={(v) => handleChange("method", v)} />
                            </div>
                            <div className="col-span-3">
                                <Field label="URL" value={block.data.url} onChange={(v) => handleChange("url", v)} placeholder="https://api.example.com" />
                            </div>
                        </div>
                        
                        <div className="mt-4">
                            <label className="flex items-center gap-1.5 text-[10px] font-black text-slate-500 mb-1.5 uppercase tracking-widest">
                                <span className="w-1.5 h-1.5 rounded-full bg-slate-600"></span>
                                Headers
                            </label>
                            <textarea 
                                className="w-full h-64 bg-[#0a0a0c] border border-white/[0.03] rounded-xl p-3 text-xs font-mono text-slate-300 resize-none custom-scrollbar focus:border-emerald-500 focus:bg-[#08080a] focus:ring-1 focus:ring-emerald-500/20 outline-none transition-all duration-300 shadow-inner"
                                value={block.data.headers} 
                                onChange={(e) => handleChange("headers", e.target.value)} 
                                placeholder="User-Agent: ..."
                            ></textarea>
                        </div>
                        
                        <div className="mt-4">
                            <Select 
                                label="Request Body Type" 
                                value={block.data.request_body_type || "raw"} 
                                onChange={(v) => handleChange("request_body_type", v as RequestBodyType)}
                                options={["raw", "form_urlencoded", "multipart"]}
                            />

                            {block.data.request_body_type === "raw" && (
                                <div className="mt-4 animate-in fade-in slide-in-from-top-1 duration-200">
                                    <label className="flex items-center gap-1.5 text-[10px] font-black text-slate-500 mb-1.5 uppercase tracking-widest">
                                        <span className="w-1.5 h-1.5 rounded-full bg-slate-600"></span>
                                        Raw Body
                                    </label>
                                    <textarea 
                                        className="w-full h-24 bg-[#0a0a0c] border border-white/[0.03] rounded-xl p-3 text-xs font-mono text-emerald-400 placeholder-slate-800 focus:border-emerald-500 focus:bg-[#08080a] focus:ring-1 focus:ring-emerald-500/20 outline-none transition-all duration-300 shadow-inner"
                                        value={block.data.body} 
                                        onChange={(e) => handleChange("body", e.target.value)} 
                                        placeholder='{"key": "value"}'
                                    ></textarea>
                                </div>
                            )}

                            {block.data.request_body_type === "form_urlencoded" && (
                                <div className="mt-4 animate-in fade-in slide-in-from-top-1 duration-200">
                                    <label className="flex items-center gap-1.5 text-[10px] font-black text-slate-500 mb-1.5 uppercase tracking-widest">
                                        <span className="w-1.5 h-1.5 rounded-full bg-slate-600"></span>
                                        Form URL-Encoded Body
                                    </label>
                                    <textarea 
                                        className="w-full h-24 bg-[#0a0a0c] border border-white/[0.03] rounded-xl p-3 text-xs font-mono text-emerald-400 placeholder-slate-800 focus:border-emerald-500 focus:bg-[#08080a] focus:ring-1 focus:ring-emerald-500/20 outline-none transition-all duration-300 shadow-inner"
                                        value={block.data.form_urlencoded_body} 
                                        onChange={(e) => handleChange("form_urlencoded_body", e.target.value)} 
                                        placeholder='param1=value1&param2=<VARIABLE>'
                                    ></textarea>
                                </div>
                            )}

                            {block.data.request_body_type === "multipart" && (
                                <div className="mt-4 animate-in fade-in slide-in-from-top-1 duration-200">
                                    <label className="flex items-center gap-1.5 text-[10px] font-black text-slate-500 mb-1.5 uppercase tracking-widest">
                                        <span className="w-1.5 h-1.5 rounded-full bg-slate-600"></span>
                                        Multipart Form Data
                                    </label>
                                    <MultipartFieldsEditor 
                                        multipartFields={block.data.multipart_fields || []} 
                                        onUpdate={(fields) => handleChange("multipart_fields", fields)} 
                                        availableVariables={availableVariables}
                                        block={block}
                                        handleChange={handleChange}
                                    />
                                </div>
                            )}
                        </div>
                    </PropertiesSection>

                    <PropertiesSection title="Configuration" icon="⚙️" defaultOpen={false}>
                        <div className="grid grid-cols-2 gap-4">

                            <VariableInput
                                label="Proxy (Optional)"
                                value={block.data.proxy_url || ""}
                                onChange={(v) => handleChange("proxy_url", v)}
                                suggestions={availableVariables}
                                placeholder="http://user:pass@host:port"
                            />
                        </div>
                        
                        <div className="grid grid-cols-2 gap-3 mt-4">
                            {[
                                ["Use Proxy", "use_proxy"],
                                ["Auto Redirect", "auto_redirect"],
                                ["Read Response", "read_response"],
    
                            ].map(([label, key]) => (
                                <div key={key} className="flex items-center justify-between bg-white/[0.02] border border-white/[0.03] p-3 rounded-xl hover:bg-white/[0.04] transition-all">
                                    <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">{label}</span>
                                    <Toggle checked={block.data[key]} onChange={(c) => handleChange(key, c)} />
                                </div>
                            ))}
                        </div>
                    </PropertiesSection>

                    <PropertiesSection title="Security & TLS" icon="🔒" defaultOpen={false}>
                        <div className="grid grid-cols-2 gap-4">
                            <Select
                                label="HTTP Version"
                                value={block.data.http_version || "Auto"}
                                onChange={(v) => handleChange("http_version", v)}
                            >
                                <option value="Auto">Auto (Default)</option>
                                <option value="1.1">HTTP/1.1</option>
                                <option value="2">HTTP/2</option>
                            </Select>

                            <Select
                                label="TLS Version"
                                value={block.data.tls_version || "Auto"}
                                onChange={(v) => handleChange("tls_version", v)}
                            >
                                <option value="Auto">Auto (Default)</option>
                                <option value="1.2">TLS 1.2</option>
                                <option value="1.3">TLS 1.3</option>
                            </Select>
                        </div>
                    </PropertiesSection>

                    {/* Output Variables Reference */}
                    <div className="bg-[#0a0a0c] border border-white/[0.03] rounded-xl p-4">
                        <div className="flex items-center gap-2 mb-3">
                            <span className="text-[10px] font-black text-slate-500 uppercase tracking-[0.2em]">Output Telemetry</span>
                        </div>
                        <div className="grid grid-cols-2 gap-x-4 gap-y-2 text-[10px]">
                            <div className="flex items-center gap-2">
                                <code className="text-emerald-400 bg-emerald-500/5 px-1.5 py-0.5 rounded font-black border border-emerald-500/10">SOURCE</code>
                                <span className="text-slate-600 font-bold uppercase tracking-tighter">Response Body</span>
                            </div>
                            <div className="flex items-center gap-2">
                                <code className="text-emerald-400 bg-emerald-500/5 px-1.5 py-0.5 rounded font-black border border-emerald-500/10">STATUS</code>
                                <span className="text-slate-600 font-bold uppercase tracking-tighter">Status Code</span>
                            </div>
                            <div className="flex items-center gap-2">
                                <code className="text-emerald-400 bg-emerald-500/5 px-1.5 py-0.5 rounded font-black border border-emerald-500/10">HEADERS</code>
                                <span className="text-slate-600 font-bold uppercase tracking-tighter">Headers</span>
                            </div>
                            <div className="flex items-center gap-2">
                                <code className="text-emerald-400 bg-emerald-500/5 px-1.5 py-0.5 rounded font-black border border-emerald-500/10">COOKIES</code>
                                <span className="text-slate-600 font-bold uppercase tracking-tighter">Cookies</span>
                            </div>
                            <div className="flex items-center gap-2">
                                <code className="text-emerald-400 bg-emerald-500/5 px-1.5 py-0.5 rounded font-black border border-emerald-500/10">URL</code>
                                <span className="text-slate-600 font-bold uppercase tracking-tighter">Final URL</span>
                            </div>
                            <div className="flex items-center gap-2">
                                <code className="text-emerald-400 bg-emerald-500/5 px-1.5 py-0.5 rounded font-black border border-emerald-500/10">LOCATION</code>
                                <span className="text-slate-600 font-bold uppercase tracking-tighter">Redirect Location</span>
                            </div>
                            <div className="flex items-center gap-2">
                                <code className="text-emerald-400 bg-emerald-500/5 px-1.5 py-0.5 rounded font-black border border-emerald-500/10">RAWSOURCE</code>
                                <span className="text-slate-600 font-bold uppercase tracking-tighter">Hex Body</span>
                            </div>
                            <div className="flex items-center gap-2">
                                <code className="text-emerald-400 bg-emerald-500/5 px-1.5 py-0.5 rounded font-black border border-emerald-500/10">HEADER_NAME</code>
                                <span className="text-slate-600 font-bold uppercase tracking-tighter">Specific Header</span>
                            </div>
                            <div className="flex items-center gap-2">
                                <code className="text-emerald-400 bg-emerald-500/5 px-1.5 py-0.5 rounded font-black border border-emerald-500/10">COOKIE_NAME</code>
                                <span className="text-slate-600 font-bold uppercase tracking-tighter">Specific Cookie</span>
                            </div>
                        </div>
                    </div>
                </div>
            );
        case "KeyCheck":
            return (
                <div className="space-y-4">
                    <CommonControls />
                    
                    <div className="flex items-center justify-between bg-white/[0.02] border border-white/[0.03] p-4 rounded-2xl hover:bg-white/[0.04] transition-all">
                        <div className="flex flex-col">
                            <span className="text-[10px] font-black text-slate-300 uppercase tracking-[0.2em]">Global Ban Policy</span>
                            <span className="text-[9px] text-slate-600 font-bold mt-0.5 uppercase tracking-widest">Ban if no keychain matches</span>
                        </div>
                        <Toggle checked={block.data.ban_if_no_match} onChange={(c) => handleChange("ban_if_no_match", c)} />
                    </div>

                    <PropertiesSection title="Keychains" icon="🔑">
                        <div className="space-y-3">
                            <div className="flex justify-end">
                                <button 
                                    onClick={() => handleChange("keychains", [...(block.data.keychains || []), { result_status: "SUCCESS", mode: "OR", keys: [], source: "SOURCE" }])}
                                    className="text-[10px] font-black bg-emerald-500/10 text-emerald-400 hover:bg-emerald-500/20 px-4 py-2 rounded-xl border border-emerald-500/20 transition-all uppercase tracking-widest flex items-center gap-2 shadow-sm"
                                >
                                    <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2.5" d="M12 4v16m8-8H4"></path></svg>
                                    Add Keychain
                                </button>
                            </div>
                            {(block.data.keychains || []).map((kc: Keychain, kIdx: number) => (
                                <div key={kIdx} className="bg-[#0a0a0c] border border-white/[0.03] rounded-2xl p-4 space-y-4 shadow-xl group">
                                    <div className="flex items-center gap-3">
                                        <VariableInput 
                                            className="bg-[#08080a] border border-white/[0.03] rounded-xl text-[10px] px-3 py-2 text-pink-400 font-black outline-none w-32 focus:border-pink-500 shadow-inner"
                                            value={kc.source || ""}
                                            onChange={(v) => {
                                                const newKCs = [...block.data.keychains];
                                                newKCs[kIdx].source = v;
                                                handleChange("keychains", newKCs);
                                            }}
                                            suggestions={availableVariables}
                                            placeholder="SOURCE"
                                        />
                                        <div className="h-5 w-px bg-white/5"></div>
                                        <div className="w-28">
                                            <Select 
                                                value={kc.result_status}
                                                onChange={(v) => {
                                                    const newKCs = [...block.data.keychains];
                                                    newKCs[kIdx].result_status = v as any;
                                                    handleChange("keychains", newKCs);
                                                }}
                                                options={["SUCCESS", "FAIL", "BAN", "RETRY", "NONE", "CUSTOM"]}
                                            />
                                        </div>
                                        <div className="w-20">
                                            <Select 
                                                value={kc.mode}
                                                onChange={(v) => {
                                                    const newKCs = [...block.data.keychains];
                                                    newKCs[kIdx].mode = v as any;
                                                    handleChange("keychains", newKCs);
                                                }}
                                                options={["OR", "AND"]}
                                            />
                                        </div>
                                        <div className="flex-1"></div>
                                        <button 
                                            onClick={() => {
                                                const newKCs = block.data.keychains.filter((_: any, i: number) => i !== kIdx);
                                                handleChange("keychains", newKCs);
                                            }}
                                            className="p-2 rounded-lg text-slate-600 hover:text-red-400 hover:bg-red-500/10 transition-all"
                                        >
                                            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2.5" d="M6 18L18 6M6 6l12 12"></path></svg>
                                        </button>
                                    </div>
                                    <div className="space-y-2.5 pl-4 border-l border-white/[0.03] group-hover:border-white/[0.03] transition-all">
                                        {(kc.keys || []).map((key, keyIdx) => (
                                            <div key={keyIdx} className="flex items-center gap-2">
                                                <div className="w-32">
                                                    <Select 
                                                        value={key.condition}
                                                        onChange={(v) => {
                                                            const newKCs = [...block.data.keychains];
                                                            newKCs[kIdx].keys[keyIdx].condition = v as any;
                                                            handleChange("keychains", newKCs);
                                                        }}
                                                        options={["Contains", "NotContains", "Equal", "NotEqual"]}
                                                    />
                                                </div>
                                                <input 
                                                    className="flex-1 bg-[#08080a] border border-white/[0.03] rounded-xl text-[11px] py-2 px-4 text-white font-mono outline-none focus:border-emerald-500 transition-all placeholder-slate-800 shadow-inner"
                                                    value={key.value}
                                                    onChange={(e) => {
                                                        const newKCs = [...block.data.keychains];
                                                        newKCs[kIdx].keys[keyIdx].value = e.target.value;
                                                        handleChange("keychains", newKCs);
                                                    }}
                                                    placeholder="Value to check..."
                                                />
                                                <button 
                                                    onClick={() => {
                                                        const newKCs = [...block.data.keychains];
                                                        newKCs[kIdx].keys = newKCs[kIdx].keys.filter((_: any, i: number) => i !== keyIdx);
                                                        handleChange("keychains", newKCs);
                                                    }}
                                                    className="text-slate-700 hover:text-red-400 p-1.5 transition-colors"
                                                >
                                                    <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="3" d="M20 12H4"></path></svg>
                                                </button>
                                            </div>
                                        ))}
                                        <button 
                                            onClick={() => {
                                                const newKCs = [...block.data.keychains];
                                                newKCs[kIdx].keys.push({ value: "", condition: "Contains" });
                                                handleChange("keychains", newKCs);
                                            }}
                                            className="text-[10px] font-black text-slate-600 hover:text-emerald-400 flex items-center gap-2 mt-2 transition-all uppercase tracking-widest"
                                        >
                                            <span className="text-lg leading-none">+</span> Add Criteria
                                        </button>
                                    </div>
                                </div>
                            ))}
                        </div>
                    </PropertiesSection>
                </div>
            );
        case "JumpIF":
            return (
                <div className="space-y-4">
                    <CommonControls />

                    <PropertiesSection title="Jump Chains" icon="↪️">
                        <div className="space-y-3">
                            <div className="flex justify-end">
                                <button
                                    onClick={() => handleChange("jump_chains", [...(block.data.jump_chains || []), { source: "SOURCE", mode: "OR", keys: [{ value: "", condition: "Contains" }], target: "LABEL1" }])}
                                    className="text-[10px] font-black bg-orange-500/10 text-orange-400 hover:bg-orange-500/20 px-4 py-2 rounded-xl border border-orange-500/20 transition-all uppercase tracking-widest flex items-center gap-2 shadow-sm"
                                >
                                    <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2.5" d="M12 4v16m8-8H4"></path></svg>
                                    Add Jump Chain
                                </button>
                            </div>
                            {(block.data.jump_chains || []).map((jc: JumpChain, jIdx: number) => (
                                <div key={jIdx} className="bg-[#0a0a0c] border border-white/[0.03] rounded-2xl p-4 space-y-4 shadow-xl group">
                                    <div className="flex items-center gap-3 flex-wrap">
                                        <div className="flex items-center gap-2">
                                            <span className="text-[10px] font-black text-slate-600 uppercase tracking-widest">IF</span>
                                            <VariableInput
                                                className="bg-[#08080a] border border-white/[0.03] rounded-xl text-[10px] px-3 py-2 text-pink-400 font-black outline-none w-32 focus:border-pink-500 shadow-inner"
                                                value={jc.source || ""}
                                                onChange={(v) => {
                                                    const newJCs = [...block.data.jump_chains];
                                                    newJCs[jIdx].source = v;
                                                    handleChange("jump_chains", newJCs);
                                                }}
                                                suggestions={availableVariables}
                                                placeholder="SOURCE"
                                            />
                                        </div>
                                        <div className="w-32">
                                            <Select 
                                                value={jc.mode}
                                                onChange={(v) => {
                                                    const newJCs = [...block.data.jump_chains];
                                                    newJCs[jIdx].mode = v as any;
                                                    handleChange("jump_chains", newJCs);
                                                }}
                                                options={["OR", "AND"]}
                                            />
                                        </div>
                                        <div className="flex items-center gap-2">
                                            <span className="text-[10px] font-black text-orange-400 uppercase tracking-widest">JUMP TO</span>
                                            <input
                                                className="bg-[#08080a] border border-white/[0.03] rounded-xl text-[10px] px-3 py-2 text-orange-400 font-black outline-none w-28 focus:border-orange-500 shadow-inner"
                                                value={jc.target || ""}
                                                onChange={(e) => {
                                                    const newJCs = [...block.data.jump_chains];
                                                    newJCs[jIdx].target = e.target.value;
                                                    handleChange("jump_chains", newJCs);
                                                }}
                                                placeholder="LABEL1"
                                            />
                                        </div>
                                        <div className="flex-1"></div>
                                        <button
                                            onClick={() => {
                                                const newJCs = block.data.jump_chains.filter((_: any, i: number) => i !== jIdx);
                                                handleChange("jump_chains", newJCs);
                                            }}
                                            className="p-2 rounded-lg text-slate-600 hover:text-red-400 hover:bg-red-500/10 transition-all"
                                        >
                                            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2.5" d="M6 18L18 6M6 6l12 12"></path></svg>
                                        </button>
                                    </div>
                                    <div className="space-y-2.5 pl-4 border-l border-white/[0.03] group-hover:border-white/[0.03] transition-all">
                                        {(jc.keys || []).map((key, keyIdx) => (
                                            <div key={keyIdx} className="flex items-center gap-2">
                                                <div className="w-32">
                                                    <Select 
                                                        value={key.condition}
                                                        onChange={(v) => {
                                                            const newJCs = [...block.data.jump_chains];
                                                            newJCs[jIdx].keys[keyIdx].condition = v as any;
                                                            handleChange("jump_chains", newJCs);
                                                        }}
                                                        options={["Contains", "NotContains", "Equal", "NotEqual", "StartsWith", "EndsWith", "Matches"]}
                                                    />
                                                </div>
                                                <input
                                                    className="flex-1 bg-[#08080a] border border-white/[0.03] rounded-xl text-[11px] py-2 px-4 text-white font-mono outline-none focus:border-orange-500 transition-all placeholder-slate-800 shadow-inner"
                                                    value={key.value}
                                                    onChange={(e) => {
                                                        const newJCs = [...block.data.jump_chains];
                                                        newJCs[jIdx].keys[keyIdx].value = e.target.value;
                                                        handleChange("jump_chains", newJCs);
                                                    }}
                                                    placeholder="Match Value..."
                                                />
                                                <button
                                                    onClick={() => {
                                                        const newJCs = [...block.data.jump_chains];
                                                        newJCs[jIdx].keys = newJCs[jIdx].keys.filter((_: any, i: number) => i !== keyIdx);
                                                        handleChange("jump_chains", newJCs);
                                                    }}
                                                    className="text-slate-700 hover:text-red-400 p-1.5 transition-colors"
                                                >
                                                    <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="3" d="M20 12H4"></path></svg>
                                                </button>
                                            </div>
                                        ))}
                                        <button
                                            onClick={() => {
                                                const newJCs = [...block.data.jump_chains];
                                                newJCs[jIdx].keys.push({ value: "", condition: "Contains" });
                                                handleChange("jump_chains", newJCs);
                                            }}
                                            className="text-[10px] font-black text-slate-600 hover:text-orange-400 flex items-center gap-2 mt-2 transition-all uppercase tracking-widest"
                                        >
                                            <span className="text-lg leading-none">+</span> Add Condition
                                        </button>
                                    </div>
                                </div>
                            ))}
                            {(block.data.jump_chains || []).length === 0 && (
                                <div className="text-center py-8 bg-white/[0.01] border border-dashed border-white/[0.03] rounded-2xl">
                                    <p className="text-[10px] font-black text-slate-700 uppercase tracking-[0.2em]">No Branch Logic Defined</p>
                                </div>
                            )}
                        </div>
                    </PropertiesSection>

                    <PropertiesSection title="Jump Delay" icon="⏳" defaultOpen={false}>
                        <div className="flex items-center gap-3">
                            <span className="text-[10px] font-black text-slate-500 uppercase tracking-widest">Delay (ms)</span>
                            <input
                                type="number"
                                className="flex-1 bg-[#08080a] border border-white/[0.03] rounded-xl text-[11px] py-2 px-4 text-white font-mono outline-none focus:border-orange-500 transition-all placeholder-slate-800 shadow-inner"
                                value={block.data.delay_ms || 0}
                                onChange={(e) => handleChange("delay_ms", parseInt(e.target.value) || 0)}
                                placeholder="0"
                                min="0"
                            />
                            <span className="text-[9px] text-slate-600 font-bold">Wait before each jump</span>
                        </div>
                    </PropertiesSection>

                    <div className="bg-white/[0.02] border border-white/[0.03] rounded-xl p-4">
                        <div className="flex items-start gap-3">
                            <span className="text-orange-400 text-sm">⚡</span>
                            <div className="text-[10px] text-slate-500 font-bold uppercase tracking-widest leading-relaxed">
                                <span className="text-white">Execution Rule:</span> First matching chain triggers redirection.
                                <span className="text-slate-700"> Mode selection AND requires all keys to match.</span>
                            </div>
                        </div>
                    </div>
                </div>
            );
        case "Delay":
            return (
                <div className="space-y-4">
                    <CommonControls />
                    <div>
                        <label className="block text-[10px] font-bold text-slate-500 mb-1 uppercase tracking-wider">Delay Duration (ms)</label>
                        <VariableInput
                            value={block.data.milliseconds || ''}
                            onChange={(v) => handleChange("milliseconds", v)}
                            suggestions={availableVariables}
                            placeholder="1000"
                            className="w-full bg-[#0a0a0c] border border-white/[0.03] rounded-xl p-2.5 text-sm text-yellow-400 font-bold outline-none focus:border-yellow-500 transition-colors"
                        />
                        <p className="text-[10px] text-slate-600 mt-1">1000 ms = 1 second</p>
                    </div>
                </div>
            );
        case "Parse":
            return (
                <div className="space-y-4">
                    <CommonControls />
                    <ParseBlockSettings block={block} handleChange={handleChange} availableVariables={availableVariables} />
                </div>
            );
        case "Hash":
            return (
                <div className="space-y-4">
                    <CommonControls />
                    <div>
                        <label className="block text-[10px] font-bold text-slate-500 mb-1 uppercase tracking-wider">OUTPUT VARIABLE</label>
                        <VariableInput
                            value={block.data.variable ?? ""}
                            onChange={(v) => handleChange("variable", v)}
                            suggestions={availableVariables}
                            placeholder="hashed"
                            className="w-full bg-[#0a0a0c] border border-white/[0.03] rounded-xl p-2.5 text-sm text-pink-400 font-bold outline-none focus:border-pink-500 transition-colors"
                        />
                    </div>
                    <Select
                        label="Algorithm"
                        value={block.data.algorithm || "SHA256"}
                        onChange={(v) => handleChange("algorithm", v)}
                        options={["MD4", "MD5", "SHA1", "SHA256", "SHA384", "SHA512"]}
                    />
                    <div>
                        <label className="block text-[10px] font-bold text-slate-500 mb-1 uppercase tracking-wider">Input to Hash</label>
                        <VariableInput
                            value={block.data.input || ''}
                            onChange={(v) => handleChange("input", v)}
                            suggestions={availableVariables}
                            placeholder="String or <VARIABLE>"
                        />
                    </div>

                    {/* Algorithm Reference */}
                    <div className="bg-[#0a0a0c] border border-white/[0.03] rounded-xl p-3">
                        <div className="flex items-center gap-2 mb-2">
                            <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">Algorithm Info</span>
                        </div>
                        <div className="grid grid-cols-2 gap-x-4 gap-y-1.5 text-[10px]">
                            <div className="flex items-center gap-2">
                                <code className="text-red-400 bg-red-500/10 px-1.5 py-0.5 rounded font-bold">MD4</code>
                                <span className="text-slate-500">128-bit (legacy)</span>
                            </div>
                            <div className="flex items-center gap-2">
                                <code className="text-red-400 bg-red-500/10 px-1.5 py-0.5 rounded font-bold">MD5</code>
                                <span className="text-slate-500">128-bit (fast)</span>
                            </div>
                            <div className="flex items-center gap-2">
                                <code className="text-yellow-400 bg-yellow-500/10 px-1.5 py-0.5 rounded font-bold">SHA1</code>
                                <span className="text-slate-500">160-bit</span>
                            </div>
                            <div className="flex items-center gap-2">
                                <code className="text-green-400 bg-green-500/10 px-1.5 py-0.5 rounded font-bold">SHA256</code>
                                <span className="text-slate-500">256-bit (recommended)</span>
                            </div>
                            <div className="flex items-center gap-2">
                                <code className="text-emerald-400 bg-emerald-500/10 px-1.5 py-0.5 rounded font-bold">SHA384</code>
                                <span className="text-slate-500">384-bit</span>
                            </div>
                            <div className="flex items-center gap-2">
                                <code className="text-purple-400 bg-purple-500/10 px-1.5 py-0.5 rounded font-bold">SHA512</code>
                                <span className="text-slate-500">512-bit (secure)</span>
                            </div>
                        </div>
                    </div>
                </div>
            );
        case "HmacSign":
            return (
                <div className="space-y-4">
                    <CommonControls />
                    <div>
                        <label className="block text-[10px] font-bold text-slate-500 mb-1 uppercase tracking-wider">OUTPUT VARIABLE</label>
                        <VariableInput
                            value={block.data.variable ?? "hmac"}
                            onChange={(v) => handleChange("variable", v)}
                            suggestions={availableVariables}
                            placeholder="hmac"
                            className="w-full bg-[#0a0a0c] border border-white/[0.03] rounded-xl p-2.5 text-sm text-pink-400 font-bold outline-none focus:border-pink-500 transition-colors"
                        />
                    </div>
                    <Select
                        label="Algorithm"
                        value={block.data.algorithm || "SHA256"}
                        onChange={(v) => handleChange("algorithm", v)}
                        options={["SHA1", "SHA256", "SHA384", "SHA512"]}
                    />
                    <div>
                        <label className="block text-[10px] font-bold text-slate-500 mb-1 uppercase tracking-wider">Secret Key</label>
                        <VariableInput
                            value={block.data.key || ''}
                            onChange={(v) => handleChange("key", v)}
                            suggestions={availableVariables}
                            placeholder="Secret key or <VARIABLE>"
                        />
                    </div>
                    <div>
                        <label className="block text-[10px] font-bold text-slate-500 mb-1 uppercase tracking-wider">Message to Sign</label>
                        <VariableInput
                            value={block.data.message || ''}
                            onChange={(v) => handleChange("message", v)}
                            suggestions={availableVariables}
                            placeholder="Message or <VARIABLE>"
                        />
                    </div>
                    <div className="grid grid-cols-2 gap-3">
                        <Select
                            label="Key Format"
                            value={block.data.key_format || "utf8"}
                            onChange={(v) => handleChange("key_format", v)}
                            options={["utf8", "hex", "base64"]}
                        />
                        <Select
                            label="Output Format"
                            value={block.data.output_format || "hex"}
                            onChange={(v) => handleChange("output_format", v)}
                            options={["hex", "base64", "base64url"]}
                        />
                    </div>
                </div>
            );
        case "AesEncrypt":
            return (
                <div className="space-y-4">
                    <CommonControls />
                    <div>
                        <label className="block text-[10px] font-bold text-slate-500 mb-1 uppercase tracking-wider">OUTPUT VARIABLE</label>
                        <VariableInput
                            value={block.data.variable ?? "encrypted"}
                            onChange={(v) => handleChange("variable", v)}
                            suggestions={availableVariables}
                            placeholder="encrypted"
                            className="w-full bg-[#0a0a0c] border border-white/[0.03] rounded-xl p-2.5 text-sm text-pink-400 font-bold outline-none focus:border-pink-500 transition-colors"
                        />
                    </div>
                    <div>
                        <label className="block text-[10px] font-bold text-slate-500 mb-1 uppercase tracking-wider">Key (16 or 32 bytes)</label>
                        <VariableInput
                            value={block.data.key || ''}
                            onChange={(v) => handleChange("key", v)}
                            suggestions={availableVariables}
                            placeholder="AES key or <VARIABLE>"
                        />
                    </div>
                    <div>
                        <label className="block text-[10px] font-bold text-slate-500 mb-1 uppercase tracking-wider">IV (16 bytes)</label>
                        <VariableInput
                            value={block.data.iv || ''}
                            onChange={(v) => handleChange("iv", v)}
                            suggestions={availableVariables}
                            placeholder="Initialization vector or <VARIABLE>"
                        />
                    </div>
                    <div>
                        <label className="block text-[10px] font-bold text-slate-500 mb-1 uppercase tracking-wider">Plaintext</label>
                        <VariableInput
                            value={block.data.plaintext || ''}
                            onChange={(v) => handleChange("plaintext", v)}
                            suggestions={availableVariables}
                            placeholder="Text to encrypt or <VARIABLE>"
                        />
                    </div>
                    <div className="grid grid-cols-2 gap-3">
                        <Select
                            label="Key Format"
                            value={block.data.key_format || "utf8"}
                            onChange={(v) => handleChange("key_format", v)}
                            options={["utf8", "hex", "base64"]}
                        />
                        <Select
                            label="Output Format"
                            value={block.data.output_format || "base64"}
                            onChange={(v) => handleChange("output_format", v)}
                            options={["hex", "base64"]}
                        />
                    </div>
                    <div className="bg-[#0a0a0c] border border-white/[0.03] rounded-xl p-3">
                        <div className="text-[10px] text-slate-400">
                            <span className="font-bold text-slate-300">Note:</span> Uses AES-CBC mode with PKCS7 padding. Key must be exactly 16 bytes (AES-128) or 32 bytes (AES-256).
                        </div>
                    </div>
                </div>
            );
        case "AesDecrypt":
            return (
                <div className="space-y-4">
                    <CommonControls />
                    <div>
                        <label className="block text-[10px] font-bold text-slate-500 mb-1 uppercase tracking-wider">OUTPUT VARIABLE</label>
                        <VariableInput
                            value={block.data.variable ?? "decrypted"}
                            onChange={(v) => handleChange("variable", v)}
                            suggestions={availableVariables}
                            placeholder="decrypted"
                            className="w-full bg-[#0a0a0c] border border-white/[0.03] rounded-xl p-2.5 text-sm text-pink-400 font-bold outline-none focus:border-pink-500 transition-colors"
                        />
                    </div>
                    <div>
                        <label className="block text-[10px] font-bold text-slate-500 mb-1 uppercase tracking-wider">Key (16 or 32 bytes)</label>
                        <VariableInput
                            value={block.data.key || ''}
                            onChange={(v) => handleChange("key", v)}
                            suggestions={availableVariables}
                            placeholder="AES key or <VARIABLE>"
                        />
                    </div>
                    <div>
                        <label className="block text-[10px] font-bold text-slate-500 mb-1 uppercase tracking-wider">IV (16 bytes)</label>
                        <VariableInput
                            value={block.data.iv || ''}
                            onChange={(v) => handleChange("iv", v)}
                            suggestions={availableVariables}
                            placeholder="Initialization vector or <VARIABLE>"
                        />
                    </div>
                    <div>
                        <label className="block text-[10px] font-bold text-slate-500 mb-1 uppercase tracking-wider">Ciphertext</label>
                        <VariableInput
                            value={block.data.ciphertext || ''}
                            onChange={(v) => handleChange("ciphertext", v)}
                            suggestions={availableVariables}
                            placeholder="Encrypted data or <VARIABLE>"
                        />
                    </div>
                    <div className="grid grid-cols-2 gap-3">
                        <Select
                            label="Key Format"
                            value={block.data.key_format || "utf8"}
                            onChange={(v) => handleChange("key_format", v)}
                            options={["utf8", "hex", "base64"]}
                        />
                        <Select
                            label="Input Format"
                            value={block.data.input_format || "base64"}
                            onChange={(v) => handleChange("input_format", v)}
                            options={["hex", "base64"]}
                        />
                    </div>
                </div>
            );
        case "Pbkdf2Derive":
            return (
                <div className="space-y-4">
                    <CommonControls />
                    <div>
                        <label className="block text-[10px] font-bold text-slate-500 mb-1 uppercase tracking-wider">OUTPUT VARIABLE</label>
                        <VariableInput
                            value={block.data.variable ?? "derived_key"}
                            onChange={(v) => handleChange("variable", v)}
                            suggestions={availableVariables}
                            placeholder="derived_key"
                            className="w-full bg-[#0a0a0c] border border-white/[0.03] rounded-xl p-2.5 text-sm text-pink-400 font-bold outline-none focus:border-pink-500 transition-colors"
                        />
                    </div>
                    <div>
                        <label className="block text-[10px] font-bold text-slate-500 mb-1 uppercase tracking-wider">Password</label>
                        <VariableInput
                            value={block.data.password || ''}
                            onChange={(v) => handleChange("password", v)}
                            suggestions={availableVariables}
                            placeholder="Password or <VARIABLE>"
                        />
                    </div>
                    <div>
                        <label className="block text-[10px] font-bold text-slate-500 mb-1 uppercase tracking-wider">Salt</label>
                        <VariableInput
                            value={block.data.salt || ''}
                            onChange={(v) => handleChange("salt", v)}
                            suggestions={availableVariables}
                            placeholder="Salt value or <VARIABLE>"
                        />
                    </div>
                    <Select
                        label="Salt Format"
                        value={block.data.salt_format || "utf8"}
                        onChange={(v) => handleChange("salt_format", v)}
                        options={["utf8", "hex", "base64"]}
                    />
                    <div className="grid grid-cols-2 gap-3">
                        <div>
                            <label className="block text-[10px] font-bold text-slate-500 mb-1 uppercase tracking-wider">Iterations</label>
                            <input
                                type="number"
                                className="w-full bg-[#0a0a0c] border border-white/[0.03] rounded-xl p-2.5 text-sm text-white outline-none focus:border-emerald-500 transition-colors"
                                value={block.data.iterations || 10000}
                                onChange={(e) => handleChange("iterations", parseInt(e.target.value) || 10000)}
                                placeholder="10000"
                            />
                        </div>
                        <div>
                            <label className="block text-[10px] font-bold text-slate-500 mb-1 uppercase tracking-wider">Key Length (bytes)</label>
                            <input
                                type="number"
                                className="w-full bg-[#0a0a0c] border border-white/[0.03] rounded-xl p-2.5 text-sm text-white outline-none focus:border-emerald-500 transition-colors"
                                value={block.data.key_length || 32}
                                onChange={(e) => handleChange("key_length", parseInt(e.target.value) || 32)}
                                placeholder="32"
                            />
                        </div>
                    </div>
                    <div className="grid grid-cols-2 gap-3">
                        <Select
                            label="Algorithm"
                            value={block.data.algorithm || "SHA256"}
                            onChange={(v) => handleChange("algorithm", v)}
                            options={["SHA1", "SHA256", "SHA384", "SHA512"]}
                        />
                        <Select
                            label="Output Format"
                            value={block.data.output_format || "hex"}
                            onChange={(v) => handleChange("output_format", v)}
                            options={["hex", "base64", "base64url"]}
                        />
                    </div>
                    <div className="bg-[#0a0a0c] border border-white/[0.03] rounded-xl p-3">
                        <div className="text-[10px] text-slate-400">
                            <span className="font-bold text-slate-300">Tip:</span> Higher iterations = more secure but slower. 10,000+ recommended for passwords.
                        </div>
                    </div>
                </div>
            );
        case "RsaEncrypt":
            return (
                <div className="space-y-4">
                    <CommonControls />
                    <div>
                        <label className="block text-[10px] font-bold text-slate-500 mb-1 uppercase tracking-wider">OUTPUT VARIABLE</label>
                        <VariableInput
                            value={block.data.variable ?? "rsaEncrypted"}
                            onChange={(v) => handleChange("variable", v)}
                            suggestions={availableVariables}
                            placeholder="rsaEncrypted"
                            className="w-full bg-[#0a0a0c] border border-white/[0.03] rounded-xl p-2.5 text-sm text-pink-400 font-bold outline-none focus:border-pink-500 transition-colors"
                        />
                    </div>
                    <div>
                        <label className="block text-[10px] font-bold text-slate-500 mb-1 uppercase tracking-wider">Plain Text (Base64)</label>
                        <VariableInput
                            value={block.data.plaintext || ''}
                            onChange={(v) => handleChange("plaintext", v)}
                            suggestions={availableVariables}
                            placeholder="Base64 encoded plaintext or <VARIABLE>"
                        />
                    </div>
                    <div>
                        <label className="block text-[10px] font-bold text-slate-500 mb-1 uppercase tracking-wider">Modulus (Base64)</label>
                        <VariableInput
                            value={block.data.modulus || ''}
                            onChange={(v) => handleChange("modulus", v)}
                            suggestions={availableVariables}
                            placeholder="RSA modulus (n) in Base64 or <VARIABLE>"
                        />
                    </div>
                    <div>
                        <label className="block text-[10px] font-bold text-slate-500 mb-1 uppercase tracking-wider">Exponent (Base64)</label>
                        <VariableInput
                            value={block.data.exponent || ''}
                            onChange={(v) => handleChange("exponent", v)}
                            suggestions={availableVariables}
                            placeholder="RSA exponent (e) in Base64 or <VARIABLE>"
                        />
                    </div>
                    <div className="bg-[#0a0a0c] border border-white/[0.03] rounded-xl p-3">
                        <div className="text-[10px] text-slate-400">
                            <span className="font-bold text-slate-300">Note:</span> All inputs must be Base64 encoded. Output will be Base64 encoded ciphertext.
                        </div>
                    </div>
                </div>
            );
        case "Base64ToBytes":
            return (
                <div className="space-y-4">
                    <CommonControls />
                    <div>
                        <label className="block text-[10px] font-bold text-slate-500 mb-1 uppercase tracking-wider">OUTPUT VARIABLE</label>
                        <VariableInput
                            value={block.data.variable ?? "hexBytes"}
                            onChange={(v) => handleChange("variable", v)}
                            suggestions={availableVariables}
                            placeholder="hexBytes"
                            className="w-full bg-[#0a0a0c] border border-white/[0.03] rounded-xl p-2.5 text-sm text-pink-400 font-bold outline-none focus:border-pink-500 transition-colors"
                        />
                    </div>
                    <div>
                        <label className="block text-[10px] font-bold text-slate-500 mb-1 uppercase tracking-wider">Base64 Input</label>
                        <VariableInput
                            value={block.data.input || ''}
                            onChange={(v) => handleChange("input", v)}
                            suggestions={availableVariables}
                            placeholder="Base64 string or <VARIABLE>"
                        />
                    </div>
                    <div className="bg-[#0a0a0c] border border-white/[0.03] rounded-xl p-3">
                        <div className="text-[10px] text-slate-400">
                            <span className="font-bold text-slate-300">Output:</span> Hex-encoded bytes (e.g., "48656c6c6f" for "Hello")
                        </div>
                    </div>
                </div>
            );
        case "Script":
            return (
                <div className="flex flex-col h-full space-y-3">
                    <CommonControls />

                    {/* Editor Header */}
                    <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                            <div className="w-7 h-7 rounded-lg bg-orange-500/20 border border-orange-500/30 flex items-center justify-center">
                                <span className="text-sm">📜</span>
                            </div>
                            <div>
                                <span className="text-[11px] font-bold text-white">Rhai Script</span>
                                <span className="text-[9px] text-slate-500 ml-2">Rust-like syntax</span>
                            </div>
                        </div>
                        <div className="flex items-center gap-2">
                            <span className="text-[9px] font-mono text-slate-600 bg-white/[0.02] px-2 py-1 rounded">
                                {(block.data.script || "").split('\n').length} lines
                            </span>
                        </div>
                    </div>

                    {/* Code Editor */}
                    <div className="flex-1 flex flex-col bg-[#0d1117] border border-white/[0.03] rounded-xl overflow-hidden min-h-[300px]">
                        {/* Editor Toolbar */}
                        <div className="flex items-center gap-1 px-3 py-2 bg-[#161b22] ">
                            <div className="flex gap-1.5">
                                <div className="w-3 h-3 rounded-full bg-red-500/80"></div>
                                <div className="w-3 h-3 rounded-full bg-yellow-500/80"></div>
                                <div className="w-3 h-3 rounded-full bg-green-500/80"></div>
                            </div>
                            <span className="ml-3 text-[10px] text-slate-500 font-mono">script.rhai</span>
                        </div>

                        <textarea
                            className="flex-1 w-full bg-transparent p-4 font-mono text-[12px] text-[#c9d1d9] outline-none resize-none custom-scrollbar leading-relaxed"
                            value={block.data.script}
                            onChange={(e) => handleChange("script", e.target.value)}
                            placeholder="// Write your Rhai script here..."
                            spellCheck={false}
                            style={{ tabSize: 2 }}
                        ></textarea>
                    </div>

                    {/* Available Variables */}
                    <div className="bg-[#0a0a0c] border border-white/[0.03] rounded-xl p-3">
                        <div className="flex items-center gap-2 mb-2">
                            <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">Available Variables</span>
                            <span className="text-[9px] text-slate-600">accessed directly by name</span>
                        </div>
                        <div className="flex flex-wrap gap-1.5">
                            {availableVariables.slice(0, 12).map(v => (
                                <code key={v} className="text-[10px] font-mono bg-orange-500/10 text-orange-400 px-2 py-0.5 rounded border border-orange-500/20">
                                    {v}
                                </code>
                            ))}
                            {availableVariables.length > 12 && (
                                <span className="text-[10px] text-slate-500">+{availableVariables.length - 12} more</span>
                            )}
                        </div>
                    </div>

                    {/* Built-in Functions */}
                    <div className="bg-[#0a0a0c] border border-white/[0.03] rounded-xl p-3">
                        <div className="flex items-center gap-2 mb-2">
                            <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">Built-in Functions</span>
                        </div>
                        <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-[10px]">
                            <div><code className="text-emerald-400">uuid4()</code> <span className="text-slate-600">- UUID v4</span></div>
                            <div><code className="text-emerald-400">guid()</code> <span className="text-slate-600">- UUID uppercase</span></div>
                            <div><code className="text-green-400">md5(str)</code> <span className="text-slate-600">- MD5 hash</span></div>
                            <div><code className="text-green-400">sha256(str)</code> <span className="text-slate-600">- SHA256 hash</span></div>
                            <div><code className="text-purple-400">base64_encode(str)</code> <span className="text-slate-600">- Encode</span></div>
                            <div><code className="text-purple-400">base64_decode(str)</code> <span className="text-slate-600">- Decode</span></div>
                            <div><code className="text-white">url_encode(str)</code> <span className="text-slate-600">- URL encode</span></div>
                            <div><code className="text-white">url_decode(str)</code> <span className="text-slate-600">- URL decode</span></div>
                            <div><code className="text-yellow-400">random_int(min, max)</code> <span className="text-slate-600">- Random</span></div>
                            <div><code className="text-yellow-400">http_get(url)</code> <span className="text-slate-600">- GET request</span></div>
                        </div>
                    </div>

                    {/* Quick Reference */}
                    <div className="bg-gradient-to-r from-orange-500/5 to-red-500/5 border border-orange-500/20 rounded-xl p-3">
                        <div className="flex items-start gap-2">
                            <span className="text-orange-400 text-sm">💡</span>
                            <div className="text-[10px] text-slate-400 leading-relaxed space-y-1">
                                <div><code className="text-orange-400 bg-orange-500/10 px-1 rounded">let x = USER;</code> - Read variables directly</div>
                                <div><code className="text-green-400 bg-green-500/10 px-1 rounded">print("msg")</code> - Debug output</div>
                                <div><code className="text-white bg-white/[0.05]/10 px-1 rounded">let new_var = "value";</code> - Create new variables</div>
                                <div><code className="text-purple-400 bg-purple-500/10 px-1 rounded">.to_upper() .to_lower()</code> - String methods</div>
                            </div>
                        </div>
                    </div>
                </div>
            );
        case "RandomString":
            return (
                <div className="space-y-4">
                    <CommonControls />
                    <div>
                        <label className="block text-[10px] font-bold text-slate-500 mb-1 uppercase tracking-wider">OUTPUT VARIABLE</label>
                        <VariableInput
                            value={block.data.variable ?? ""}
                            onChange={(v) => handleChange("variable", v)}
                            suggestions={availableVariables}
                            placeholder="random"
                            className="w-full bg-[#0a0a0c] border border-white/[0.03] rounded-xl p-2.5 text-sm text-pink-400 font-bold outline-none focus:border-pink-500 transition-colors"
                        />
                    </div>
                    <Field label="Mask" value={block.data.mask} onChange={(v) => handleChange("mask", v)} placeholder="?l?l?l?d?d" />

                    {/* Mask Reference */}
                    <div className="bg-[#0a0a0c] border border-white/[0.03] rounded-xl p-3">
                        <div className="flex items-center gap-2 mb-2">
                            <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">Mask Characters</span>
                        </div>
                        <div className="grid grid-cols-2 gap-x-4 gap-y-1.5 text-[10px]">
                            <div className="flex items-center gap-2">
                                <code className="text-purple-400 bg-purple-500/10 px-1.5 py-0.5 rounded font-bold">?l</code>
                                <span className="text-slate-500">lowercase (a-z)</span>
                            </div>
                            <div className="flex items-center gap-2">
                                <code className="text-purple-400 bg-purple-500/10 px-1.5 py-0.5 rounded font-bold">?u</code>
                                <span className="text-slate-500">uppercase (A-Z)</span>
                            </div>
                            <div className="flex items-center gap-2">
                                <code className="text-emerald-400 bg-emerald-500/10 px-1.5 py-0.5 rounded font-bold">?d</code>
                                <span className="text-slate-500">digit (0-9)</span>
                            </div>
                            <div className="flex items-center gap-2">
                                <code className="text-emerald-400 bg-emerald-500/10 px-1.5 py-0.5 rounded font-bold">?h</code>
                                <span className="text-slate-500">hex lower (0-9a-f)</span>
                            </div>
                            <div className="flex items-center gap-2">
                                <code className="text-green-400 bg-green-500/10 px-1.5 py-0.5 rounded font-bold">?H</code>
                                <span className="text-slate-500">hex upper (0-9A-F)</span>
                            </div>
                            <div className="flex items-center gap-2">
                                <code className="text-green-400 bg-green-500/10 px-1.5 py-0.5 rounded font-bold">?a</code>
                                <span className="text-slate-500">alphanumeric</span>
                            </div>
                            <div className="flex items-center gap-2">
                                <code className="text-orange-400 bg-orange-500/10 px-1.5 py-0.5 rounded font-bold">?s</code>
                                <span className="text-slate-500">special (!@#$...)</span>
                            </div>
                            <div className="flex items-center gap-2">
                                <code className="text-orange-400 bg-orange-500/10 px-1.5 py-0.5 rounded font-bold">?c</code>
                                <span className="text-slate-500">custom charset</span>
                            </div>
                        </div>
                        <div className="mt-2 pt-2 ">
                            <div className="text-[9px] text-slate-600">
                                Example: <code className="text-slate-400">?u?l?l?l?d?d?d</code> → <span className="text-green-400">Abc123</span>
                            </div>
                        </div>
                    </div>

                    <Field label="Custom Charset" value={block.data.custom_charset} onChange={(v) => handleChange("custom_charset", v)} placeholder="ABC123!@#" />
                </div>
            );
        case "ConstantString":
            return (
                <div className="space-y-4">
                    <CommonControls />
                    <div>
                        <label className="block text-[10px] font-bold text-slate-500 mb-1 uppercase tracking-wider">OUTPUT VARIABLE</label>
                        <VariableInput
                            value={block.data.variable ?? ""}
                            onChange={(v) => handleChange("variable", v)}
                            suggestions={availableVariables}
                            placeholder="constString"
                            className="w-full bg-[#0a0a0c] border border-white/[0.03] rounded-xl p-2.5 text-sm text-pink-400 font-bold outline-none focus:border-pink-500 transition-colors"
                        />
                    </div>
                    <Field label="Value" value={block.data.value} onChange={(v) => handleChange("value", v)} />

                    {/* Tips */}
                    <div className="bg-[#0a0a0c] border border-white/[0.03] rounded-xl p-3">
                        <div className="flex items-start gap-2 text-[10px]">
                            <span className="text-purple-400">💡</span>
                            <div className="text-slate-400">
                                <span className="font-bold text-slate-300">Tips:</span> Use <code className="text-pink-400">&lt;VAR&gt;</code> syntax to include other variables.
                                <div className="text-slate-500 mt-1">Example: <code className="text-green-400">Bearer &lt;TOKEN&gt;</code> or <code className="text-green-400">&lt;USER&gt;:&lt;PASS&gt;</code></div>
                            </div>
                        </div>
                    </div>
                </div>
            );
        case "ConstantList":
            return (
                <div className="space-y-4">
                    <CommonControls />
                    <div>
                        <label className="block text-[10px] font-bold text-slate-500 mb-1 uppercase tracking-wider">OUTPUT VARIABLE</label>
                        <VariableInput
                            value={block.data.variable ?? ""}
                            onChange={(v) => handleChange("variable", v)}
                            suggestions={availableVariables}
                            placeholder="constList"
                            className="w-full bg-[#0a0a0c] border border-white/[0.03] rounded-xl p-2.5 text-sm text-pink-400 font-bold outline-none focus:border-pink-500 transition-colors"
                        />
                    </div>
                    <div>
                        <label className="block text-[10px] font-bold text-slate-500 mb-1 uppercase tracking-wider">List Items (one per line)</label>
                        <textarea
                            className="w-full h-48 bg-[#0a0a0c] border border-white/[0.03] rounded-xl p-3 text-xs font-mono text-white resize-none custom-scrollbar focus:border-emerald-500 outline-none"
                            value={block.data.list}
                            onChange={(e) => handleChange("list", e.target.value)}
                            placeholder="Enter items, one per line..."
                            spellCheck={false}
                        ></textarea>
                        <p className="text-[10px] text-slate-500 mt-1">
                            {(block.data.list || "").split('\n').filter((l: string) => l.trim()).length} items
                        </p>
                    </div>

                    {/* Usage Tips */}
                    <div className="bg-[#0a0a0c] border border-white/[0.03] rounded-xl p-3">
                        <div className="flex items-center gap-2 mb-2">
                            <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">Usage</span>
                        </div>
                        <div className="space-y-1.5 text-[10px]">
                            <div className="flex items-center gap-2">
                                <code className="text-emerald-400 bg-emerald-500/10 px-1.5 py-0.5 rounded">GetRandomItem</code>
                                <span className="text-slate-500">Pick a random item from list</span>
                            </div>
                            <div className="flex items-center gap-2">
                                <code className="text-purple-400 bg-purple-500/10 px-1.5 py-0.5 rounded">ZipLists</code>
                                <span className="text-slate-500">Combine with another list</span>
                            </div>
                            <div className="flex items-center gap-2">
                                <code className="text-green-400 bg-green-500/10 px-1.5 py-0.5 rounded">Parse (Recursive)</code>
                                <span className="text-slate-500">Extract multiple values into list</span>
                            </div>
                        </div>
                    </div>
                </div>
            );
        case "TlsRequest":
            return (
                <div className="space-y-6">
                    <CommonControls />

                    <PropertiesSection title="Block Presets" icon="✨">
                        <div className="bg-emerald-500/5 border border-emerald-500/20 rounded-xl p-4 mb-4">
                            <p className="text-[10px] text-emerald-400 leading-relaxed font-medium">
                                Choose a preset to instantly apply optimized TLS and HTTP/2 settings for common targets.
                            </p>
                        </div>
                        <Select 
                            label="Quick Preset" 
                            value="" 
                            onChange={(v) => {
                                if (v && TLS_REQUEST_PRESETS[v]) {
                                    updateBlockData(block.id, { ...block.data, ...TLS_REQUEST_PRESETS[v] });
                                    alert(`Applied ${v} preset!`);
                                }
                            }}
                        >
                            <option value="">Select a preset...</option>
                            {Object.keys(TLS_REQUEST_PRESETS).map(name => (
                                <option key={name} value={name}>{name}</option>
                            ))}
                        </Select>
                    </PropertiesSection>
                    
                    <PropertiesSection title="Target / Transport" icon="🌐">
                        <div className="grid grid-cols-3 gap-4">
                            <div className="col-span-1">
                                <label className="block text-[10px] font-bold text-slate-500 mb-1 uppercase tracking-wider">Method</label>
                                <VariableInput value={block.data.request_method} onChange={(v) => handleChange("request_method", v)} suggestions={availableVariables} placeholder="GET" />
                            </div>
                            <div className="col-span-2">
                                <label className="block text-[10px] font-bold text-slate-500 mb-1 uppercase tracking-wider">URL</label>
                                <VariableInput value={block.data.request_url} onChange={(v) => handleChange("request_url", v)} suggestions={availableVariables} placeholder="https://google.com" />
                            </div>
                        </div>
                        <div className="grid grid-cols-2 gap-4 mt-4">
                            <div>
                                <label className="block text-[10px] font-bold text-slate-500 mb-1 uppercase tracking-wider">TLS Client ID</label>
                                <Combobox 
                                    value={block.data.tls_client_identifier} 
                                    onChange={(v) => handleChange("tls_client_identifier", v)} 
                                    options={TLS_CLIENT_IDENTIFIERS} 
                                    variables={availableVariables}
                                    placeholder="chrome_133" 
                                />
                            </div>
                            <div>
                                <label className="block text-[10px] font-bold text-slate-500 mb-1 uppercase tracking-wider">Session ID</label>
                                <VariableInput value={block.data.custom_session_id} onChange={(v) => handleChange("custom_session_id", v)} suggestions={availableVariables} placeholder="Random if empty" />
                            </div>
                        </div>
                        <div className="grid grid-cols-2 gap-4 mt-4">
                            <div>
                                <label className="block text-[10px] font-bold text-slate-500 mb-1 uppercase tracking-wider">Proxy URL</label>
                                <VariableInput value={block.data.proxy_url} onChange={(v) => handleChange("proxy_url", v)} suggestions={availableVariables} placeholder="http://user:pass@host:port" />
                            </div>
                            <div>
                                <label className="block text-[10px] font-bold text-slate-500 mb-1 uppercase tracking-wider">Timeout (Seconds)</label>
                                <VariableInput value={block.data.timeout_seconds_str || "30"} onChange={(v) => handleChange("timeout_seconds_str", v)} suggestions={availableVariables} placeholder="30" />
                            </div>
                        </div>
                    </PropertiesSection>

                    <PropertiesSection title="Payload Data" icon="✉️" defaultOpen={false}>
                        <div className="flex items-center justify-between bg-white/[0.01] p-3 rounded-xl mb-4 border border-emerald-500/10">
                            <div className="flex flex-col">
                                <span className="text-[10px] font-black text-emerald-400 uppercase">Byte Request Mode</span>
                                <span className="text-[9px] text-slate-500">Body should be base64 encoded</span>
                            </div>
                            <Toggle checked={block.data.is_byte_request} onChange={(c) => handleChange("is_byte_request", c)} />
                        </div>
                        <div>
                            <label className="block text-[10px] font-bold text-slate-500 mb-1 uppercase tracking-wider">Headers</label>
                            <textarea className="w-full h-64 bg-[#0a0a0c] border border-white/[0.03] rounded-xl p-3 text-xs font-mono text-white resize-none custom-scrollbar focus:border-emerald-500 outline-none" value={block.data.headers} onChange={(e) => handleChange("headers", e.target.value)} placeholder="User-Agent: ..."></textarea>
                        </div>
                        <div className="mt-4">
                            <label className="block text-[10px] font-bold text-slate-500 mb-1 uppercase tracking-wider">Body</label>
                            <textarea className="w-full h-24 bg-[#0a0a0c] border border-white/[0.03] rounded-xl p-3 text-xs font-mono text-white resize-none custom-scrollbar focus:border-emerald-500 outline-none" value={block.data.request_body} onChange={(e) => handleChange("request_body", e.target.value)} placeholder="Body content..."></textarea>
                        </div>
                    </PropertiesSection>

                    <PropertiesSection title="Network Policy" icon="⚙️" defaultOpen={false}>
                        <div className="grid grid-cols-2 gap-x-4 gap-y-3">
                            {[
                                ["Follow Redirects", "follow_redirects", "Disable to capture 302s"],
                                ["Skip SSL Verify", "insecure_skip_verify", "Skip certificate validation"],
                                ["Cookie Jar", "with_default_cookie_jar", "Maintain cookies in session"],
                                ["Force HTTP/1.1", "force_http1", "Disable HTTP/2"],
                                ["Disable HTTP/2", "disable_http2", ""],
                                ["Disable HTTP/3", "disable_http3", ""],
                                ["Random Header Order", "randomize_header_order", "Randomize header order"],
                                ["Random TLS Order", "random_tls_extension_order", "Better fingerprinting"],
                                ["Byte Response", "is_byte_response", "Response body will be base64"],

                                ["Rotating Proxy", "is_rotating_proxy", "Tell forwarder proxy is rotating"],
                                ["Catch Panics", "catch_panics", "Prevent forwarder crash"],
                                ["Disable IPV4", "disable_ipv4", ""],
                                ["Disable IPV6", "disable_ipv6", ""],
                                ["Debug Logs", "with_debug", "Enable forwarder-side debug logs"]
                            ].map(([label, key, hint]) => (
                                <div key={key} className="flex items-center justify-between bg-white/[0.02] p-3 rounded-xl group" title={hint}>
                                    <div className="flex flex-col">
                                        <span className="text-[10px] text-slate-300 font-bold uppercase tracking-tight">{label}</span>
                                        {hint && <span className="text-[8px] text-slate-500 leading-none">{hint}</span>}
                                    </div>
                                    <Toggle checked={block.data[key]} onChange={(c) => handleChange(key, c)} />
                                </div>
                            ))}
                        </div>
                    </PropertiesSection>

                    <PropertiesSection title="Protocol Weaver" icon="🕸️" defaultOpen={false}>
                        <div className="bg-white/[0.01] border border-emerald-500/20 rounded-xl p-4 mb-4">
                            <div className="flex items-center gap-2 mb-2">
                                <span className="text-emerald-400 text-lg">🕸️</span>
                                <span className="text-emerald-400 font-black text-xs uppercase tracking-widest">Fingerprint Weaver Active</span>
                            </div>
                            <p className="text-[10px] text-slate-400 leading-relaxed">
                                Manually weave low-level protocol frames to bypass advanced anti-bot systems. 
                                Reorder pseudo-headers or define raw H2 frame sequences.
                            </p>
                        </div>

                        <div className="flex items-center justify-between bg-purple-500/5 p-4 rounded-xl mb-4 border border-purple-500/20 group">
                            <div className="flex flex-col">
                                <span className="text-[10px] font-black text-purple-400 uppercase tracking-widest group-hover:text-purple-300 transition-colors">Dynamic Jitter</span>
                                <span className="text-[9px] text-slate-500 leading-tight">Add statistical noise to bypass AI detection</span>
                            </div>
                            <Toggle checked={block.data.with_jitter} onChange={(c) => handleChange("with_jitter", c)} />
                        </div>

                        {block.data.with_jitter && (
                            <div className="bg-purple-500/5 border border-purple-500/10 rounded-xl p-3 mb-4 space-y-2">
                                <div className="flex items-center gap-2">
                                    <div className="w-1.5 h-1.5 rounded-full bg-purple-500 animate-pulse"></div>
                                    <span className="text-[9px] font-bold text-purple-300 uppercase">Jitter Active</span>
                                </div>
                                <p className="text-[9px] text-slate-500 leading-relaxed">
                                    Numerical fields now support ranges (e.g., <span className="text-purple-400 font-mono">1000-5000</span>). 
                                    Lists like <span className="text-purple-400 font-mono">Extension Weaver</span> and <span className="text-purple-400 font-mono">Versions</span> will be automatically shuffled per session.
                                </p>
                            </div>
                        )}

                        <div className="space-y-4">
                            <Field 
                                label="Pseudo Header Order" 
                                value={block.data.pseudo_header_order || ":method,:authority,:scheme,:path"} 
                                onChange={(v) => handleChange("pseudo_header_order", v)} 
                                placeholder=":method,:authority,:scheme,:path" 
                            />
                            
                            <div className="grid grid-cols-2 gap-4">
                                <div>
                                    <label className="block text-[10px] font-black text-slate-500 mb-1.5 uppercase tracking-widest">H2 Window Update</label>
                                    <VariableInput 
                                        value={block.data.h2_window_update_increment || ""} 
                                        onChange={(v) => handleChange("h2_window_update_increment", v)} 
                                        suggestions={availableVariables}
                                        placeholder="e.g. 15663105"
                                    />
                                </div>
                                <div>
                                    <label className="block text-[10px] font-black text-slate-500 mb-1.5 uppercase tracking-widest">H2 Priority Frames</label>
                                    <VariableInput 
                                        value={block.data.h2_priority_frames || ""} 
                                        onChange={(v) => handleChange("h2_priority_frames", v)} 
                                        suggestions={availableVariables}
                                        placeholder="stream_id:weight:dep"
                                    />
                                </div>
                            </div>

                            <div>
                                <label className="block text-[10px] font-black text-slate-500 mb-1.5 uppercase tracking-widest">Extension Weaver (Order)</label>
                                <textarea 
                                    className="w-full h-24 bg-[#0a0a0c] border border-white/[0.03] rounded-xl p-3 text-xs font-mono text-white resize-none custom-scrollbar focus:border-emerald-500 focus:bg-[#08080c] outline-none"
                                    value={block.data.extension_order_str || ""} 
                                    onChange={(e) => handleChange("extension_order_str", e.target.value)} 
                                    placeholder="0,23,65281,10,11,35,16,5,13,18,51,45,43,27,21"
                                ></textarea>
                                <p className="text-[9px] text-slate-600 mt-1 font-medium">Comma-separated extension IDs to force handshake order.</p>
                            </div>
                        </div>
                    </PropertiesSection>

                    
                </div>
            );
        case "TlsWreq":
            return (
                <div className="space-y-4">
                    <CommonControls />
                    {block.data.with_jitter && (
                        <div className="flex items-center gap-2 px-4 py-2 bg-emerald-500/10 border border-emerald-500/20 rounded-xl animate-pulse">
                            <span className="text-emerald-400 text-lg">🧬</span>
                            <span className="text-emerald-400 font-black text-xs uppercase tracking-widest">Fingerprint Weaver Active</span>
                        </div>
                    )}
                    <div className="grid grid-cols-3 gap-4">
                        <div className="col-span-1">
                            <Select 
                                label="Method" 
                                value={block.data.request_method} 
                                onChange={(v) => handleChange("request_method", v)} 
                                options={["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"]} 
                            />
                        </div>
                        <div className="col-span-2">
                            <label className="block text-[10px] font-bold text-slate-500 mb-1 uppercase tracking-wider">URL</label>
                            <VariableInput
                                value={block.data.request_url}
                                onChange={(v) => handleChange("request_url", v)}
                                suggestions={availableVariables}
                                placeholder="https://example.com"
                            />
                        </div>
                    </div>
                    <div>
                        <Select 
                            label="Emulation (Browser Fingerprint)" 
                            value={block.data.emulation} 
                            onChange={(v) => handleChange("emulation", v)}
                        >
                            <optgroup label="Special">
                                <option value="random">🎲 Random (picks random browser each request)</option>
                            </optgroup>
                            <optgroup label="Chrome">
                                {["chrome100", "chrome101", "chrome104", "chrome105", "chrome106", "chrome107", "chrome108", "chrome109", "chrome110", "chrome114", "chrome116", "chrome117", "chrome118", "chrome119", "chrome120", "chrome123", "chrome124", "chrome126", "chrome127", "chrome128", "chrome129", "chrome130", "chrome131", "chrome132", "chrome133", "chrome134", "chrome135", "chrome136", "chrome137", "chrome138", "chrome139", "chrome140", "chrome141", "chrome142", "chrome143"].map(v => <option key={v} value={v}>{v}</option>)}
                            </optgroup>
                            <optgroup label="Firefox">
                                {["firefox109", "firefox117", "firefox128", "firefox133", "firefox135", "firefox136", "firefox139", "firefox142", "firefox143", "firefox144", "firefox145", "firefox146", "firefoxprivate135", "firefoxprivate136", "firefoxandroid135"].map(v => <option key={v} value={v}>{v}</option>)}
                            </optgroup>
                            <optgroup label="Safari">
                                {["safari15.3", "safari15.5", "safari15.6.1", "safari16", "safari16.5", "safari17.0", "safari17.2.1", "safari17.4.1", "safari17.5", "safari17.6", "safari18", "safari18.2", "safari18.3", "safari18.3.1", "safari18.5", "safari26", "safari26.1", "safari26.2", "safariios16.5", "safariios17.2", "safariios17.4.1", "safariios18.1.1", "safariios26", "safariios26.2", "safariipad18", "safariipad26", "safariipad26.2"].map(v => <option key={v} value={v}>{v}</option>)}
                            </optgroup>
                            <optgroup label="Edge">
                                {["edge101", "edge122", "edge127", "edge131", "edge134", "edge135", "edge136", "edge137", "edge138", "edge139", "edge140", "edge141", "edge142"].map(v => <option key={v} value={v}>{v}</option>)}
                            </optgroup>
                            <optgroup label="Opera">
                                {["opera116", "opera117", "opera118", "opera119"].map(v => <option key={v} value={v}>{v}</option>)}
                            </optgroup>
                            <optgroup label="OkHttp (Android)">
                                {["okhttp3.9", "okhttp3.11", "okhttp3.13", "okhttp3.14", "okhttp4.9", "okhttp4.10", "okhttp4.12", "okhttp5"].map(v => <option key={v} value={v}>{v}</option>)}
                            </optgroup>
                        </Select>
                    </div>
                    <div>
                        <label className="block text-[10px] font-bold text-slate-500 mb-1 uppercase tracking-wider">Headers</label>
                        <textarea
                            className="w-full h-64 bg-[#0a0a0c] border border-white/[0.03] rounded-xl p-3 text-xs font-mono text-white resize-none custom-scrollbar focus:border-pink-500 outline-none"
                            value={block.data.headers}
                            onChange={(e) => handleChange("headers", e.target.value)}
                            placeholder="User-Agent: Mozilla/5.0...&#10;Content-Type: application/json"
                        ></textarea>
                    </div>
                    <div>
                        <Select 
                            label="Request Body Type" 
                            value={block.data.request_body_type || "raw"} 
                            onChange={(v) => handleChange("request_body_type", v as RequestBodyType)}
                            options={["raw", "form_urlencoded", "multipart"]}
                        />

                        {block.data.request_body_type === "raw" && (
                            <div className="mt-4 animate-in fade-in slide-in-from-top-1 duration-200">
                                <label className="block text-[10px] font-bold text-slate-500 mb-1 uppercase tracking-wider">Raw Body</label>
                                <textarea
                                    className="w-full h-24 bg-[#0a0a0c] border border-white/[0.03] rounded-xl p-3 text-xs font-mono text-white resize-none custom-scrollbar focus:border-pink-500 outline-none"
                                    value={block.data.request_body}
                                    onChange={(e) => handleChange("request_body", e.target.value)}
                                    placeholder="Request body content..."
                                ></textarea>
                            </div>
                        )}

                        {block.data.request_body_type === "form_urlencoded" && (
                            <div className="mt-4 animate-in fade-in slide-in-from-top-1 duration-200">
                                <label className="block text-[10px] font-bold text-slate-500 mb-1 uppercase tracking-wider">Form URL-Encoded Body (key=value&key2=value2)</label>
                                <textarea
                                    className="w-full h-24 bg-[#0a0a0c] border border-white/[0.03] rounded-xl p-3 text-xs font-mono text-white resize-none custom-scrollbar focus:border-pink-500 outline-none"
                                    value={block.data.form_urlencoded_body}
                                    onChange={(e) => handleChange("form_urlencoded_body", e.target.value)}
                                    placeholder="param1=value1&param2=<VARIABLE>"
                                ></textarea>
                            </div>
                        )}

                        {block.data.request_body_type === "multipart" && (
                            <div className="mt-4 animate-in fade-in slide-in-from-top-1 duration-200">
                                <label className="block text-[10px] font-bold text-slate-500 mb-1 uppercase tracking-wider">Multipart Form Data</label>
                                <MultipartFieldsEditor 
                                    multipartFields={block.data.multipart_fields || []} 
                                    onUpdate={(fields) => handleChange("multipart_fields", fields)} 
                                    availableVariables={availableVariables}
                                    block={block}
                                    handleChange={handleChange}
                                />
                            </div>
                        )}
                    </div>
                    <div className="grid grid-cols-2 gap-4">
                        <div>
                            <label className="block text-[10px] font-bold text-slate-500 mb-1 uppercase tracking-wider">Proxy URL</label>
                            <VariableInput
                                value={block.data.proxy_url}
                                onChange={(v) => handleChange("proxy_url", v)}
                                suggestions={availableVariables}
                                placeholder="http://user:pass@host:port (Empty = Job Default)"
                            />
                        </div>

                    </div>
                    <div className="grid grid-cols-2 gap-4">
                        <Field label="Timeout (s)" value={block.data.timeout_seconds} onChange={(v) => handleChange("timeout_seconds", parseInt(v) || 30)} type="number" />
                        <Field label="Max Redirects" value={block.data.max_redirects} onChange={(v) => handleChange("max_redirects", parseInt(v) || 10)} type="number" />
                    </div>
                    <div className="grid grid-cols-2 gap-x-4 gap-y-3">
                        {[
                            ["Follow Redirects", "follow_redirects", "Automatically follow HTTP redirects"],
                            ["With Jitter", "with_jitter", "Randomize TLS Extension order"],
                            ["Force HTTP/1.1", "force_http1", "Use HTTP/1.1 instead of HTTP/2"],
                            ["Cookie Store", "cookie_store", "Enable built-in cookie jar"],
                            ["Randomize Header Order", "randomize_header_order", "Shuffle header order each request"],

                        ].map(([label, key, hint]) => (
                            <div key={key} className="flex items-center justify-between bg-white/[0.02] p-3 rounded-xl group" title={hint}>
                                <span className="text-xs text-slate-300 font-medium">{label}</span>
                                <Toggle checked={block.data[key]} onChange={(c) => handleChange(key, c)} />
                            </div>
                        ))}
                    </div>
                    <div className="bg-pink-500/10 border border-pink-500/20 rounded-xl p-4">
                        <div className="flex items-center gap-2 mb-2">
                            <span className="text-pink-400 text-lg">🛡️</span>
                            <span className="text-pink-400 font-bold text-sm">Native TLS Fingerprinting</span>
                        </div>
                        <p className="text-xs text-slate-400">
                            Uses wreq library for native Rust TLS fingerprinting. No external service required.
                            TLS extension order is automatically randomized for Chrome/Edge emulations.
                            Supports 75+ browser emulations including Chrome, Firefox, Safari, Edge, Opera, and OkHttp.
                        </p>
                    </div>

                    {/* Output Variables Reference */}
                    <div className="bg-[#0a0a0c] border border-white/[0.03] rounded-xl p-3">
                        <div className="flex items-center gap-2 mb-2">
                            <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">Output Telemetry</span>
                        </div>
                        <div className="grid grid-cols-2 gap-x-4 gap-y-1.5 text-[10px]">
                            <div className="flex items-center gap-2">
                                <code className="text-emerald-400 bg-emerald-500/10 px-1.5 py-0.5 rounded font-black border border-emerald-500/10">SOURCE</code>
                                <span className="text-slate-500 font-bold uppercase tracking-tighter">Response Body</span>
                            </div>
                            <div className="flex items-center gap-2">
                                <code className="text-emerald-400 bg-emerald-500/10 px-1.5 py-0.5 rounded font-black border border-emerald-500/10">STATUS</code>
                                <span className="text-slate-500 font-bold uppercase tracking-tighter">Status Code</span>
                            </div>
                            <div className="flex items-center gap-2">
                                <code className="text-emerald-400 bg-emerald-500/10 px-1.5 py-0.5 rounded font-black border border-emerald-500/10">HEADERS</code>
                                <span className="text-slate-500 font-bold uppercase tracking-tighter">Headers</span>
                            </div>
                            <div className="flex items-center gap-2">
                                <code className="text-emerald-400 bg-emerald-500/10 px-1.5 py-0.5 rounded font-black border border-emerald-500/10">COOKIES</code>
                                <span className="text-slate-500 font-bold uppercase tracking-tighter">Cookies</span>
                            </div>
                            <div className="flex items-center gap-2">
                                <code className="text-emerald-400 bg-emerald-500/10 px-1.5 py-0.5 rounded font-black border border-emerald-500/10">URL</code>
                                <span className="text-slate-500 font-bold uppercase tracking-tighter">Final URL</span>
                            </div>
                            <div className="flex items-center gap-2">
                                <code className="text-emerald-400 bg-emerald-500/10 px-1.5 py-0.5 rounded font-black border border-emerald-500/10">LOCATION</code>
                                <span className="text-slate-500 font-bold uppercase tracking-tighter">Redirect Location</span>
                            </div>
                            <div className="flex items-center gap-2">
                                <code className="text-emerald-400 bg-emerald-500/10 px-1.5 py-0.5 rounded font-black border border-emerald-500/10">RAWSOURCE</code>
                                <span className="text-slate-500 font-bold uppercase tracking-tighter">Hex Body</span>
                            </div>
                            <div className="flex items-center gap-2">
                                <code className="text-emerald-400 bg-emerald-500/10 px-1.5 py-0.5 rounded font-black border border-emerald-500/10">HEADER_NAME</code>
                                <span className="text-slate-500 font-bold uppercase tracking-tighter">Specific Header</span>
                            </div>
                            <div className="flex items-center gap-2">
                                <code className="text-emerald-400 bg-emerald-500/10 px-1.5 py-0.5 rounded font-black border border-emerald-500/10">COOKIE_NAME</code>
                                <span className="text-slate-500 font-bold uppercase tracking-tighter">Specific Cookie</span>
                            </div>
                        </div>
                    </div>
                </div>
            );

        case "ForgeRockAuth":
            return (
                <div className="space-y-4">
                    <CommonControls />
                    <PropertiesSection title="Authentication Details" icon="🏦">
                        <VariableInput 
                            label="JSON Input Source" 
                            value={block.data.source || ""} 
                            onChange={(v) => handleChange("source", v)} 
                            suggestions={availableVariables}
                            placeholder="SOURCE (Default)"
                        />
                        <div className="grid grid-cols-2 gap-4 mt-4">
                            <VariableInput 
                                label="Username Variable" 
                                value={block.data.username_var || "USER"} 
                                onChange={(v) => handleChange("username_var", v)} 
                                suggestions={availableVariables}
                                placeholder="USER"
                            />
                            <VariableInput 
                                label="Password Variable" 
                                value={block.data.password_var || "PASS"} 
                                onChange={(v) => handleChange("password_var", v)} 
                                suggestions={availableVariables}
                                placeholder="PASS"
                            />
                        </div>
                    </PropertiesSection>

                    <PropertiesSection title="Proof-of-Work Automation" icon="⚙️">
                        <div className="flex items-center justify-between bg-white/[0.02] border border-white/[0.02] p-3 rounded-xl mb-4">
                            <div className="flex flex-col">
                                <span className="text-[10px] font-bold text-slate-300 uppercase">Solve PoW Challenge</span>
                                <span className="text-[9px] text-slate-500">Automatically solve SHA-1 puzzles</span>
                            </div>
                            <Toggle checked={block.data.solve_pow} onChange={(c) => handleChange("solve_pow", c)} />
                        </div>
                        
                        <div className="grid grid-cols-2 gap-4">
                            <Field label="Nonce IDToken" value={block.data.id_token_nonce || "IDToken1"} onChange={(v) => handleChange("id_token_nonce", v)} />
                            <Field label="Extra IDToken" value={block.data.id_token_extra || "IDToken5"} onChange={(v) => handleChange("id_token_extra", v)} />
                        </div>
                        <div className="mt-4">
                            <Field label="Extra Value" value={block.data.extra_value || "2"} onChange={(v) => handleChange("extra_value", v)} />
                        </div>
                    </PropertiesSection>

                    <PropertiesSection title="Mapping" icon="🗺️" defaultOpen={false}>
                        <div className="grid grid-cols-2 gap-4">
                            <Field label="Username IDToken" value={block.data.id_token_user || "IDToken3"} onChange={(v) => handleChange("id_token_user", v)} />
                            <Field label="Password IDToken" value={block.data.id_token_pass || "IDToken4"} onChange={(v) => handleChange("id_token_pass", v)} />
                        </div>
                    </PropertiesSection>

                    <PropertiesSection title="Output" icon="💾">
                        <VariableInput
                            label="Generated Payload Variable"
                            value={block.data.variable || "forgeRockPayload"}
                            onChange={(v) => handleChange("variable", v)}
                            suggestions={availableVariables}
                            placeholder="forgeRockPayload"
                        />
                    </PropertiesSection>
                </div>
            );
        case "UnixTimeToIso8601":
            return (
                <div className="space-y-4">
                    <CommonControls />
                    <div>
                        <label className="block text-[10px] font-bold text-slate-500 mb-1 uppercase tracking-wider">OUTPUT VARIABLE</label>
                        <VariableInput
                            value={block.data.variable ?? "iso8601"}
                            onChange={(v) => handleChange("variable", v)}
                            suggestions={availableVariables}
                            placeholder="iso8601"
                            className="w-full bg-[#0a0a0c] border border-white/[0.03] rounded-xl p-2.5 text-sm text-pink-400 font-bold outline-none focus:border-pink-500 transition-colors"
                        />
                    </div>
                    <div>
                        <label className="block text-[10px] font-bold text-slate-500 mb-1 uppercase tracking-wider">Unix Timestamp Input</label>
                        <VariableInput
                            value={block.data.input || ''}
                            onChange={(v) => handleChange("input", v)}
                            suggestions={availableVariables}
                            placeholder="Unix timestamp or <VARIABLE>"
                        />
                    </div>
                    <div className="bg-[#0a0a0c] border border-white/[0.03] rounded-xl p-3">
                        <div className="text-[10px] text-slate-400">
                            <span className="font-bold text-slate-300">Output:</span> ISO8601 format (e.g., "2024-01-15T10:30:00Z")
                        </div>
                    </div>
                </div>
            );
        case "EncodeHtmlEntities":
            return (
                <div className="space-y-4">
                    <CommonControls />
                    <div>
                        <label className="block text-[10px] font-bold text-slate-500 mb-1 uppercase tracking-wider">OUTPUT VARIABLE</label>
                        <VariableInput
                            value={block.data.variable ?? "htmlEncoded"}
                            onChange={(v) => handleChange("variable", v)}
                            suggestions={availableVariables}
                            placeholder="htmlEncoded"
                            className="w-full bg-[#0a0a0c] border border-white/[0.03] rounded-xl p-2.5 text-sm text-pink-400 font-bold outline-none focus:border-pink-500 transition-colors"
                        />
                    </div>
                    <div>
                        <label className="block text-[10px] font-bold text-slate-500 mb-1 uppercase tracking-wider">Input Text</label>
                        <VariableInput
                            value={block.data.input || ''}
                            onChange={(v) => handleChange("input", v)}
                            suggestions={availableVariables}
                            placeholder="Text to encode or <VARIABLE>"
                        />
                    </div>
                    <div className="bg-[#0a0a0c] border border-white/[0.03] rounded-xl p-3">
                        <div className="text-[10px] text-slate-400">
                            <span className="font-bold text-slate-300">Example:</span> &lt; → &amp;lt; | &gt; → &amp;gt; | &amp; → &amp;amp;
                        </div>
                    </div>
                </div>
            );
        case "DecodeHtmlEntities":
            return (
                <div className="space-y-4">
                    <CommonControls />
                    <div>
                        <label className="block text-[10px] font-bold text-slate-500 mb-1 uppercase tracking-wider">OUTPUT VARIABLE</label>
                        <VariableInput
                            value={block.data.variable ?? "htmlDecoded"}
                            onChange={(v) => handleChange("variable", v)}
                            suggestions={availableVariables}
                            placeholder="htmlDecoded"
                            className="w-full bg-[#0a0a0c] border border-white/[0.03] rounded-xl p-2.5 text-sm text-pink-400 font-bold outline-none focus:border-pink-500 transition-colors"
                        />
                    </div>
                    <div>
                        <label className="block text-[10px] font-bold text-slate-500 mb-1 uppercase tracking-wider">Input Text</label>
                        <VariableInput
                            value={block.data.input || ''}
                            onChange={(v) => handleChange("input", v)}
                            suggestions={availableVariables}
                            placeholder="HTML encoded text or <VARIABLE>"
                        />
                    </div>
                    <div className="bg-[#0a0a0c] border border-white/[0.03] rounded-xl p-3">
                        <div className="text-[10px] text-slate-400">
                            <span className="font-bold text-slate-300">Example:</span> &amp;lt; → &lt; | &amp;gt; → &gt; | &amp;amp; → &amp;
                        </div>
                    </div>
                </div>
            );
        case "RandomUserAgent":
            return (
                <div className="space-y-4">
                    <CommonControls />
                    <div>
                        <label className="block text-[10px] font-bold text-slate-500 mb-1 uppercase tracking-wider">OUTPUT VARIABLE</label>
                        <VariableInput
                            value={block.data.variable ?? ""}
                            onChange={(v) => handleChange("variable", v)}
                            suggestions={availableVariables}
                            placeholder="userAgent"
                            className="w-full bg-[#0a0a0c] border border-white/[0.03] rounded-xl p-2.5 text-sm text-pink-400 font-bold outline-none focus:border-pink-500 transition-colors"
                        />
                    </div>
                    <Select
                        label="Platform"
                        value={block.data.platform || "ALL"}
                        onChange={(v) => handleChange("platform", v)}
                        options={["ALL", "Desktop", "Mobile", "Ipad", "Iphone", "Android", "Linux", "Mac", "Windows"]}
                    />
                </div>
            );
        case "Checksum":
            return (
                <div className="space-y-4">
                    <CommonControls />
                    <div>
                        <label className="block text-[10px] font-bold text-slate-500 mb-1 uppercase tracking-wider">OUTPUT VARIABLE</label>
                        <VariableInput
                            value={block.data.variable ?? "gop3Payload"}
                            onChange={(v) => handleChange("variable", v)}
                            suggestions={availableVariables}
                            placeholder="gop3Payload"
                            className="w-full bg-[#0a0a0c] border border-white/[0.03] rounded-xl p-2.5 text-sm text-pink-400 font-bold outline-none focus:border-pink-500 transition-colors"
                        />
                    </div>
                    
                    <PropertiesSection title="Checksum Configuration" icon="🎰">
                        <div>
                            <label className="block text-[10px] font-bold text-slate-500 mb-1 uppercase tracking-wider">JSON Input</label>
                            <VariableInput
                                value={block.data.input || ''}
                                onChange={(v) => handleChange("input", v)}
                                suggestions={availableVariables}
                                placeholder='{"userId": 123, ...} or <JSON_VAR>'
                            />
                        </div>
                        <div className="mt-4">
                            <label className="block text-[10px] font-bold text-slate-500 mb-1 uppercase tracking-wider">Salt</label>
                            <VariableInput
                                value={block.data.salt || '==?d:??@'}
                                onChange={(v) => handleChange("salt", v)}
                                suggestions={availableVariables}
                                placeholder="==?d:??@"
                            />
                        </div>
                    </PropertiesSection>

                    <div className="bg-[#0a0a0c] border border-white/[0.03] rounded-xl p-3">
                        <div className="text-[10px] text-slate-400 leading-relaxed">
                            <span className="font-bold text-slate-300">Logic:</span> Extracts JSON (handles surrounding text) → Strips existing <code className="text-pink-400">"checksum"</code> → Cleans whitespace → Minifies → Appends salt → Generates MD5 (Upper) → Re-inserts <code className="text-pink-400">"checksum"</code> → Outputs final minified JSON.
                        </div>
                    </div>
                </div>
            );
        case "CurrentUnixTime":
            return (
                <div className="space-y-4">
                    <CommonControls />
                    <div>
                        <label className="block text-[10px] font-bold text-slate-500 mb-1 uppercase tracking-wider">OUTPUT VARIABLE</label>
                        <VariableInput
                            value={block.data.variable ?? "unixTime"}
                            onChange={(v) => handleChange("variable", v)}
                            suggestions={availableVariables}
                            placeholder="unixTime"
                            className="w-full bg-[#0a0a0c] border border-white/[0.03] rounded-xl p-2.5 text-sm text-pink-400 font-bold outline-none focus:border-pink-500 transition-colors"
                        />
                    </div>
                    <div className="flex items-center justify-between bg-white/[0.02] border border-white/[0.02] p-3 rounded-xl hover:bg-white/[0.02] transition-colors">
                        <div className="flex flex-col">
                            <span className="text-[10px] font-bold text-slate-400 uppercase tracking-tight">Use UTC</span>
                            <span className="text-[9px] text-slate-500 font-medium mt-0.5">Use UTC timezone instead of local</span>
                        </div>
                        <Toggle checked={block.data.use_utc ?? true} onChange={(c) => handleChange("use_utc", c)} />
                    </div>
                    <div className="bg-[#0a0a0c] border border-white/[0.03] rounded-xl p-3">
                        <div className="text-[10px] text-slate-400">
                            <span className="font-bold text-slate-300">Output:</span> Unix timestamp in seconds (e.g., "1705312200")
                        </div>
                    </div>
                </div>
            );

        case "ToLowercase":
        case "ToUppercase":
            const isUpper = block.block_type === "ToUppercase";
            return (
                <div className="space-y-4">
                    <CommonControls />
                    <PropertiesSection title={isUpper ? "To Uppercase" : "To Lowercase"} icon={isUpper ? "ABCD" : "abcd"}>
                        <div>
                            <label className="block text-[10px] font-bold text-slate-500 mb-1 uppercase tracking-wider">Input String</label>
                            <VariableInput 
                                value={block.data.input || ""} 
                                onChange={(v) => handleChange("input", v)} 
                                suggestions={availableVariables}
                                placeholder="String to convert"
                            />
                        </div>
                    </PropertiesSection>
                    <PropertiesSection title="Output" icon="💾">
                        <VariableInput
                            label="Output Variable"
                            value={block.data.variable || (isUpper ? "uppercase" : "lowercase")}
                            onChange={(v) => handleChange("variable", v)}
                            suggestions={availableVariables}
                            placeholder={isUpper ? "uppercase" : "lowercase"}
                        />
                    </PropertiesSection>
                </div>
            );
        case "Translate":
            return (
                <div className="space-y-4">
                    <CommonControls />
                    <PropertiesSection title="Translate Configuration" icon="🌐">
                        <div>
                            <label className="block text-[10px] font-bold text-slate-500 mb-1 uppercase tracking-wider">Input String</label>
                            <VariableInput 
                                value={block.data.input || ""} 
                                onChange={(v) => handleChange("input", v)} 
                                suggestions={availableVariables}
                                placeholder="String to translate"
                            />
                        </div>
                        <div className="mt-4">
                            <label className="flex items-center gap-1.5 text-[10px] font-black text-slate-500 mb-1.5 uppercase tracking-widest">
                                <span className="w-1.5 h-1.5 rounded-full bg-slate-600"></span>
                                Dictionary (Key:Value or Key=Value)
                            </label>
                            <textarea 
                                className="w-full h-96 bg-[#0a0a0c] border border-white/[0.03] rounded-xl p-3 text-xs font-mono text-white resize-none custom-scrollbar focus:border-emerald-500 focus:bg-[#08080a] focus:ring-1 focus:ring-emerald-500/20 outline-none transition-all duration-300 shadow-inner"
                                value={block.data.translations} 
                                onChange={(e) => handleChange("translations", e.target.value)} 
                                placeholder="AF: 93&#10;AL: 355&#10;US: 1"
                            ></textarea>
                            <p className="text-[9px] text-slate-600 mt-1 font-medium">One mapping per line. Format: <code className="text-emerald-400">Key:Value</code> or <code className="text-emerald-400">Key=Value</code></p>
                        </div>

                        <div className="flex items-center justify-between bg-white/[0.02] border border-white/[0.03] p-3 rounded-xl mt-4">
                            <div className="flex flex-col">
                                <span className="text-[10px] font-bold text-slate-400 uppercase tracking-tight">Use Original</span>
                                <span className="text-[9px] text-slate-500 font-medium mt-0.5">Use input value if no match is found</span>
                            </div>
                            <Toggle checked={block.data.use_original ?? true} onChange={(c) => handleChange("use_original", c)} />
                        </div>
                    </PropertiesSection>
                    <PropertiesSection title="Output" icon="💾">
                        <VariableInput
                            label="Output Variable"
                            value={block.data.variable || "translated"}
                            onChange={(v) => handleChange("variable", v)}
                            suggestions={availableVariables}
                            placeholder="translated"
                        />
                    </PropertiesSection>
                </div>
            );

        case "GenerateUUID4":
        case "GenerateGuid":
            return (
                <div className="space-y-4">
                    <CommonControls />
                    <PropertiesSection title="Output" icon="💾">
                        <VariableInput
                            label="Output Variable"
                            value={block.data.variable || (block.block_type === "GenerateGuid" ? "guid" : "UUID")}
                            onChange={(v) => handleChange("variable", v)}
                            suggestions={availableVariables}
                            placeholder={block.block_type === "GenerateGuid" ? "guid" : "UUID"}
                        />
                    </PropertiesSection>
                    <PropertiesSection title="Formatting" icon="🔡">
                        <div className="flex items-center justify-between bg-white/[0.02] border border-white/[0.03] p-3 rounded-xl">
                            <div className="flex flex-col">
                                <span className="text-[10px] font-bold text-slate-400 uppercase tracking-tight">Uppercase</span>
                                <span className="text-[9px] text-slate-500 font-medium mt-0.5">Generate in UPPERCASE format</span>
                            </div>
                            <Toggle checked={block.data.uppercase ?? false} onChange={(c) => handleChange("uppercase", c)} />
                        </div>
                    </PropertiesSection>
                </div>
            );

        default:
            return (
                <div className="space-y-4">
                    <CommonControls />
                    {(block.data.variable !== undefined || block.data.output_variable !== undefined) && (
                        <div>
                            <label className="block text-[10px] font-bold text-slate-500 mb-1 uppercase tracking-wider">OUTPUT VARIABLE</label>
                            <VariableInput
                                value={block.data.variable || block.data.output_variable || ''}
                                onChange={(v) => handleChange(block.data.variable !== undefined ? "variable" : "output_variable", v)}
                                suggestions={availableVariables}
                                placeholder="Variable name"
                                className="w-full bg-[#0a0a0c] border border-white/[0.03] rounded-xl p-2.5 text-sm text-pink-400 font-bold outline-none focus:border-pink-500 transition-colors"
                            />
                        </div>
                    )}
                    {Object.keys(block.data).map(key => {
                        if (key === "keychains" || key === "script" || key === "comment" || key === "disabled" || key === "variable" || key === "output_variable") return null; // Handled specially or above
                        return (
                            <div key={key}>
                                <label className="block text-[10px] font-bold text-slate-500 mb-1 uppercase tracking-wider">{key.replace(/_/g, " ")}</label>
                                {typeof block.data[key] === "boolean" ? (
                                    <Toggle checked={block.data[key]} onChange={(c) => handleChange(key, c)} />
                                ) : (
                                    <input
                                        className="w-full bg-[#0a0a0c] border border-white/[0.03] rounded-xl p-2.5 text-sm text-white outline-none focus:border-emerald-500 transition-colors"
                                        value={block.data[key]}
                                        onChange={(e) => handleChange(key, e.target.value)}
                                    />
                                )}
                            </div>
                        )
                    })}
                </div>
            );
    }
}

// --- Combo Editor Tab ---

interface TransformConfig {
    length_filter_enabled: boolean;
    length_min: number;
    length_max: number;
    domain_switch_enabled: boolean;
    domain_switch_all: boolean;
    domain_old: string;
    domain_new: string;
    special_char_enabled: boolean;
    special_char: string;
    special_char_position: string;
    uppercase_first: boolean;
    remove_duplicates: boolean;
    remove_letters_only: boolean;
    remove_numbers_only: boolean;
}

interface TransformResult {
    original_count: number;
    new_count: number;
    removed_count: number;
    modified_count: number;
}

function ComboEditorTab({ isActive }: { isActive?: boolean }) {
    const [combos, setCombos] = useState<{name: string, lines: number}[]>([]);
    const [selectedCombo, setSelectedCombo] = useState("");
    const [preview, setPreview] = useState<string[]>([]);
    const [isLoading, setIsLoading] = useState(false);
    const [lastResult, setLastResult] = useState<TransformResult | null>(null);

    // Transform config state
    const [config, setConfig] = useState<TransformConfig>({
        length_filter_enabled: false,
        length_min: 6,
        length_max: 20,
        domain_switch_enabled: false,
        domain_switch_all: true,
        domain_old: "",
        domain_new: "",
        special_char_enabled: false,
        special_char: "!@#$%",
        special_char_position: "end",
        uppercase_first: false,
        remove_duplicates: false,
        remove_letters_only: false,
        remove_numbers_only: false,
    });

    useEffect(() => {
        if (isActive) {
            refreshCombos();
        }
    }, [isActive]);

    useEffect(() => {
        refreshCombos();
    }, []);

    useEffect(() => {
        if (selectedCombo) {
            loadPreview(selectedCombo);
        } else {
            setPreview([]);
        }
    }, [selectedCombo]);

    const refreshCombos = async () => {
        try {
            const list = await invoke<{name: string, lines: number}[]>("list_combos");
            setCombos(list);
        } catch (e) {
            console.error("Failed to list combos", e);
        }
    };

    const loadPreview = async (name: string) => {
        try {
            const lines = await invoke<string[]>("get_combo_preview", { name, limit: 20 });
            setPreview(lines);
        } catch (e) {
            console.error("Failed to load preview", e);
        }
    };

    const applyTransforms = async () => {
        if (!selectedCombo) return alert("Select a combo file first");

        const activeCount = [
            config.length_filter_enabled,
            config.domain_switch_enabled,
            config.special_char_enabled,
            config.uppercase_first,
            config.remove_duplicates,
            config.remove_letters_only,
            config.remove_numbers_only
        ].filter(Boolean).length;

        if (activeCount === 0) return alert("Enable at least one transformation");

        if (!confirm(`Apply ${activeCount} transformation(s) to "${selectedCombo}"? This will overwrite the original file.`)) return;

        setIsLoading(true);
        try {
            const result = await invoke<TransformResult>("apply_combo_transforms", {
                name: selectedCombo,
                config
            });
            setLastResult(result);
            await refreshCombos();
            await loadPreview(selectedCombo);
            alert(`Done! Removed ${result.removed_count} lines, modified ${result.modified_count} lines. New count: ${result.new_count}`);
        } catch (e) {
            alert("Error: " + e);
        } finally {
            setIsLoading(false);
        }
    };

    const updateConfig = <K extends keyof TransformConfig>(key: K, value: TransformConfig[K]) => {
        setConfig(prev => ({ ...prev, [key]: value }));
    };

    const selectedComboData = combos.find(c => c.name === selectedCombo);

    return (
        <div className="h-full flex flex-col bg-[#0a0a0c]">
            

            {/* Header */}
            <div className="relative z-10 px-8 pt-8 pb-6">
                <div className="max-w-7xl mx-auto">
                    <div className="flex items-center gap-3 mb-2">
                        <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-purple-500 to-pink-600 flex items-center justify-center shadow-lg shadow-purple-500/25">
                            <svg className="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"></path>
                            </svg>
                        </div>
                        <h1 className="text-2xl font-black text-white tracking-tight">Combo Editor</h1>
                    </div>
                    <p className="text-slate-500 text-sm font-medium">Transform and clean your combo files with powerful filters</p>
                </div>
            </div>

            {/* Content */}
            <div className="flex-1 overflow-y-auto px-8 pb-8 relative z-10 custom-scrollbar">
                <div className="max-w-7xl mx-auto">
                    <div className="flex gap-6">
                        {/* Left Panel - Combo Selector & Preview */}
                        <div className="w-80 shrink-0 space-y-4">
                            {/* Combo Selector Card */}
                            <div className="bg-[#0a0a0c] backdrop-blur-sm rounded-2xl border border-white/[0.03] p-5">
                                <div className="flex items-center gap-2 mb-4">
                                    <div className="w-8 h-8 rounded-lg bg-purple-500/20 flex items-center justify-center">
                                        <svg className="w-4 h-4 text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path>
                                        </svg>
                                    </div>
                                    <h3 className="text-sm font-bold text-white">Select Combo</h3>
                                </div>

                                <select
                                    value={selectedCombo}
                                    onChange={(e) => setSelectedCombo(e.target.value)}
                                    className="w-full bg-white/[0.02] border border-slate-700 rounded-xl p-3 text-sm text-white focus:border-purple-500 outline-none transition-colors mb-3"
                                >
                                    <option value="">Choose a combo file...</option>
                                    {combos.map(c => (
                                        <option key={c.name} value={c.name}>{c.name} ({c.lines.toLocaleString()} lines)</option>
                                    ))}
                                </select>

                                {selectedComboData && (
                                    <div className="flex items-center gap-2 text-xs text-slate-400">
                                        <div className="w-2 h-2 rounded-full bg-purple-500"></div>
                                        <span>{selectedComboData.lines.toLocaleString()} lines</span>
                                    </div>
                                )}
                            </div>

                            {/* Preview Card */}
                            <div className="bg-[#0a0a0c] backdrop-blur-sm rounded-2xl border border-white/[0.03] p-5">
                                <div className="flex items-center gap-2 mb-4">
                                    <div className="w-8 h-8 rounded-lg bg-slate-700 flex items-center justify-center">
                                        <svg className="w-4 h-4 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"></path>
                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"></path>
                                        </svg>
                                    </div>
                                    <h3 className="text-sm font-bold text-white">Preview</h3>
                                    <span className="text-xs text-slate-500">(first 20 lines)</span>
                                </div>

                                <div className="bg-slate-950 rounded-xl p-3 max-h-64 overflow-y-auto custom-scrollbar">
                                    {preview.length > 0 ? (
                                        <div className="space-y-1">
                                            {preview.map((line, i) => (
                                                <div key={i} className="text-xs font-mono text-slate-400 truncate">
                                                    {line}
                                                </div>
                                            ))}
                                        </div>
                                    ) : (
                                        <div className="text-xs text-slate-600 italic text-center py-4">
                                            Select a combo to preview
                                        </div>
                                    )}
                                </div>
                            </div>

                            {/* Last Result */}
                            {lastResult && (
                                <div className="bg-emerald-500/10 border border-emerald-500/30 rounded-xl p-4">
                                    <div className="text-xs font-bold text-emerald-400 mb-2">Last Operation</div>
                                    <div className="grid grid-cols-2 gap-2 text-xs">
                                        <div className="text-slate-400">Original:</div>
                                        <div className="text-white font-bold">{lastResult.original_count.toLocaleString()}</div>
                                        <div className="text-slate-400">New count:</div>
                                        <div className="text-white font-bold">{lastResult.new_count.toLocaleString()}</div>
                                        <div className="text-slate-400">Removed:</div>
                                        <div className="text-red-400 font-bold">{lastResult.removed_count.toLocaleString()}</div>
                                        <div className="text-slate-400">Modified:</div>
                                        <div className="text-emerald-400 font-bold">{lastResult.modified_count.toLocaleString()}</div>
                                    </div>
                                </div>
                            )}
                        </div>

                        {/* Right Panel - Transformations */}
                        <div className="flex-1 space-y-4">
                            <div className="bg-[#0a0a0c] backdrop-blur-sm rounded-2xl border border-white/[0.03] p-6">
                                <div className="flex items-center gap-2 mb-6">
                                    <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-purple-500 to-pink-500 flex items-center justify-center">
                                        <svg className="w-4 h-4 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 6V4m0 2a2 2 0 100 4m0-4a2 2 0 110 4m-6 8a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4m6 6v10m6-2a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4"></path>
                                        </svg>
                                    </div>
                                    <h3 className="text-lg font-bold text-white">Transformations</h3>
                                </div>

                                <div className="space-y-4">
                                    {/* Password Length Filter */}
                                    <TransformOption
                                        title="Password Length Filter"
                                        description="Keep only passwords within length range"
                                        enabled={config.length_filter_enabled}
                                        onToggle={(v) => updateConfig("length_filter_enabled", v)}
                                        color="emerald"
                                    >
                                        <div className="flex gap-4 mt-3">
                                            <div className="flex-1">
                                                <label className="block text-[10px] font-bold text-slate-500 mb-1 uppercase">Min Length</label>
                                                <input
                                                    type="number"
                                                    value={config.length_min}
                                                    onChange={(e) => updateConfig("length_min", parseInt(e.target.value) || 0)}
                                                    className="w-full bg-white/[0.02] border border-slate-700 rounded-lg p-2 text-sm text-white focus:border-emerald-500 outline-none"
                                                />
                                            </div>
                                            <div className="flex-1">
                                                <label className="block text-[10px] font-bold text-slate-500 mb-1 uppercase">Max Length</label>
                                                <input
                                                    type="number"
                                                    value={config.length_max}
                                                    onChange={(e) => updateConfig("length_max", parseInt(e.target.value) || 100)}
                                                    className="w-full bg-white/[0.02] border border-slate-700 rounded-lg p-2 text-sm text-white focus:border-emerald-500 outline-none"
                                                />
                                            </div>
                                        </div>
                                    </TransformOption>

                                    {/* Domain Switcher */}
                                    <TransformOption
                                        title="Domain Switcher"
                                        description="Replace email domains"
                                        enabled={config.domain_switch_enabled}
                                        onToggle={(v) => updateConfig("domain_switch_enabled", v)}
                                        color="emerald"
                                    >
                                        <div className="space-y-3 mt-3">
                                            <div className="flex gap-2">
                                                <button
                                                    onClick={() => updateConfig("domain_switch_all", true)}
                                                    className={`flex-1 px-3 py-2 rounded-lg text-xs font-bold transition-all ${config.domain_switch_all ? "bg-white/[0.05]/20 text-white border border-slate-700" : "bg-white/[0.02] text-slate-400 border border-slate-700"}`}
                                                >
                                                    All Domains
                                                </button>
                                                <button
                                                    onClick={() => updateConfig("domain_switch_all", false)}
                                                    className={`flex-1 px-3 py-2 rounded-lg text-xs font-bold transition-all ${!config.domain_switch_all ? "bg-white/[0.05]/20 text-white border border-slate-700" : "bg-white/[0.02] text-slate-400 border border-slate-700"}`}
                                                >
                                                    Specific Domain
                                                </button>
                                            </div>
                                            {!config.domain_switch_all && (
                                                <div>
                                                    <label className="block text-[10px] font-bold text-slate-500 mb-1 uppercase">From Domain</label>
                                                    <input
                                                        type="text"
                                                        value={config.domain_old}
                                                        onChange={(e) => updateConfig("domain_old", e.target.value)}
                                                        placeholder="gmail.com"
                                                        className="w-full bg-white/[0.02] border border-slate-700 rounded-lg p-2 text-sm text-white placeholder-slate-600 focus:border-slate-700 outline-none"
                                                    />
                                                </div>
                                            )}
                                            <div>
                                                <label className="block text-[10px] font-bold text-slate-500 mb-1 uppercase">To Domain</label>
                                                <input
                                                    type="text"
                                                    value={config.domain_new}
                                                    onChange={(e) => updateConfig("domain_new", e.target.value)}
                                                    placeholder="example.com"
                                                    className="w-full bg-white/[0.02] border border-slate-700 rounded-lg p-2 text-sm text-white placeholder-slate-600 focus:border-slate-700 outline-none"
                                                />
                                            </div>
                                        </div>
                                    </TransformOption>

                                    {/* Add Special Character */}
                                    <TransformOption
                                        title="Add Special Character"
                                        description="Add special char to passwords that don't have one"
                                        enabled={config.special_char_enabled}
                                        onToggle={(v) => updateConfig("special_char_enabled", v)}
                                        color="orange"
                                    >
                                        <div className="space-y-3 mt-3">
                                            <div>
                                                <label className="block text-[10px] font-bold text-slate-500 mb-1 uppercase">Characters to Add</label>
                                                <input
                                                    type="text"
                                                    value={config.special_char}
                                                    onChange={(e) => updateConfig("special_char", e.target.value)}
                                                    placeholder="!@#$%"
                                                    className="w-full bg-white/[0.02] border border-slate-700 rounded-lg p-2 text-sm text-white font-mono placeholder-slate-600 focus:border-orange-500 outline-none"
                                                />
                                                <p className="text-[10px] text-slate-500 mt-1">One random char will be picked if multiple</p>
                                            </div>
                                            <div className="flex gap-2">
                                                {["start", "end", "random"].map(pos => (
                                                    <button
                                                        key={pos}
                                                        onClick={() => updateConfig("special_char_position", pos)}
                                                        className={`flex-1 px-3 py-2 rounded-lg text-xs font-bold capitalize transition-all ${config.special_char_position === pos ? "bg-orange-500/20 text-orange-400 border border-orange-500" : "bg-white/[0.02] text-slate-400 border border-slate-700"}`}
                                                    >
                                                        {pos}
                                                    </button>
                                                ))}
                                            </div>
                                        </div>
                                    </TransformOption>

                                    {/* Simple Toggles */}
                                    <div className="grid grid-cols-2 gap-4">
                                        <TransformOption
                                            title="First Letter Uppercase"
                                            description="Capitalize first letter of password"
                                            enabled={config.uppercase_first}
                                            onToggle={(v) => updateConfig("uppercase_first", v)}
                                            color="green"
                                            compact
                                        />
                                        <TransformOption
                                            title="Remove Duplicates"
                                            description="Remove duplicate combo lines"
                                            enabled={config.remove_duplicates}
                                            onToggle={(v) => updateConfig("remove_duplicates", v)}
                                            color="purple"
                                            compact
                                        />
                                        <TransformOption
                                            title="Remove Letters-Only"
                                            description="Remove passwords with only letters"
                                            enabled={config.remove_letters_only}
                                            onToggle={(v) => updateConfig("remove_letters_only", v)}
                                            color="red"
                                            compact
                                        />
                                        <TransformOption
                                            title="Remove Numbers-Only"
                                            description="Remove passwords with only numbers"
                                            enabled={config.remove_numbers_only}
                                            onToggle={(v) => updateConfig("remove_numbers_only", v)}
                                            color="yellow"
                                            compact
                                        />
                                    </div>
                                </div>
                            </div>

                            {/* Apply Button */}
                            <button
                                onClick={applyTransforms}
                                disabled={isLoading || !selectedCombo}
                                className={`w-full py-4 rounded-xl font-bold text-sm transition-all ${
                                    isLoading || !selectedCombo
                                        ? "bg-white/[0.02] text-slate-500 cursor-not-allowed"
                                        : "bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-500 hover:to-pink-500 text-white shadow-lg shadow-purple-600/25 hover:shadow-purple-500/40"
                                }`}
                            >
                                {isLoading ? (
                                    <span className="flex items-center justify-center gap-2">
                                        <svg className="animate-spin w-4 h-4" fill="none" viewBox="0 0 24 24">
                                            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                                            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                                        </svg>
                                        Processing...
                                    </span>
                                ) : (
                                    "Apply Transformations"
                                )}
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
}

function TransformOption({
    title,
    description,
    enabled,
    onToggle,
    color,
    compact = false,
    children
}: {
    title: string;
    description: string;
    enabled: boolean;
    onToggle: (v: boolean) => void;
    color: string;
    compact?: boolean;
    children?: React.ReactNode;
}) {
    const colors: Record<string, { bg: string; border: string; dot: string }> = {
        emerald: { bg: "bg-emerald-500/10", border: "border-white/[0.03]", dot: "bg-white/[0.05]" },
        orange: { bg: "bg-orange-500/10", border: "border-orange-500/30", dot: "bg-orange-500" },
        green: { bg: "bg-emerald-500/10", border: "border-emerald-500/30", dot: "bg-emerald-500" },
        purple: { bg: "bg-purple-500/10", border: "border-purple-500/30", dot: "bg-purple-500" },
        red: { bg: "bg-red-500/10", border: "border-red-500/30", dot: "bg-red-500" },
        yellow: { bg: "bg-yellow-500/10", border: "border-yellow-500/30", dot: "bg-yellow-500" },
    };

    const c = colors[color] || colors.emerald;

    return (
        <div className={`rounded-xl border p-4 transition-all ${enabled ? `${c.bg} ${c.border}` : "bg-white/[0.02] border-slate-700"}`}>
            <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                    <div className={`w-2 h-2 rounded-full transition-colors ${enabled ? c.dot : "bg-slate-600"}`}></div>
                    <div>
                        <div className={`text-sm font-bold ${enabled ? "text-white" : "text-slate-400"}`}>{title}</div>
                        {!compact && <div className="text-xs text-slate-500">{description}</div>}
                    </div>
                </div>
                <Toggle checked={enabled} onChange={onToggle} />
            </div>
            {enabled && children && (
                <div className="mt-3 pt-3 border-t border-slate-700">
                    {children}
                </div>
            )}
        </div>
    );
}

export default App;
