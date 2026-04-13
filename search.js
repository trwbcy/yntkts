// yntkts search v4
// - prefix-first fuzzy search
// - fixed contentScore for object red field
// - detectCommand: analyze full cmdline

// ─── levenshtein ────────────────────────────────────────────
function lev(a, b) {
  const m = a.length, n = b.length;
  if (!m) return n;
  if (!n) return m;
  const d = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) d[i][0] = i;
  for (let j = 0; j <= n; j++) d[0][j] = j;
  for (let i = 1; i <= m; i++)
    for (let j = 1; j <= n; j++)
      d[i][j] = a[i-1] === b[j-1] ? d[i-1][j-1] : 1 + Math.min(d[i-1][j], d[i][j-1], d[i-1][j-1]);
  return d[m][n];
}

function skel(s) {
  return s.replace(/[aeiou.]/gi, "").replace(/(.)\1+/g, "$1");
}

function nameScore(q, name) {
  const ql = q.toLowerCase().replace(/\.exe$|\.dll$|\.sh$|\.bat$|\.elf$/i, "").replace(/^\./, "");
  const nl = name.toLowerCase().replace(/\.exe$|\.dll$|\.sh$|\.bat$|\.elf$/i, "").replace(/^\./, "");
  if (!ql) return 0;
  if (nl === ql) return 10000;
  if (nl.startsWith(ql)) return 9000 + (ql.length / nl.length) * 1000;
  if (ql.length === 1) return 0; // single char = prefix only, no contains/fuzzy
  if (nl.includes(ql)) return 7500 + (ql.length / nl.length) * 500;
  const qs = skel(ql), ns = skel(nl);
  if (qs.length >= 2 && ns === qs) return 7000;
  if (qs.length >= 2 && ns.startsWith(qs)) return 6500;
  if (qs.length >= 2 && ns.includes(qs)) return 6000;
  const dist = lev(ql, nl);
  const ratio = 1 - dist / Math.max(ql.length, nl.length);
  if (ratio > 0.6) return ratio * 5500;
  if (qs.length >= 2 && ns.length >= 2) {
    const sd = lev(qs, ns);
    const sr = 1 - sd / Math.max(qs.length, ns.length);
    if (sr > 0.55) return sr * 4500;
  }
  let qi = 0;
  for (let ti = 0; ti < nl.length && qi < ql.length; ti++) {
    if (nl[ti] === ql[qi]) qi++;
  }
  if (qi === ql.length) return 3500 + (ql.length / nl.length) * 1000;
  return 0;
}

function binToText(bin) {
  const red = typeof bin.red === "object"
    ? (bin.red.desc || "") + " " + (bin.red.cmds || []).map(c => c.c + " " + (c.n || "")).join(" ")
    : (bin.red || "");
  return [bin.d, bin.abuse, red, bin.legit, bin.detect, bin.tldr || "",
    bin.c, bin.t.join(" "), bin.m.join(" "), bin.mn.join(" "),
    (bin.chain?.flows || []).join(" "), (bin.tags || []).join(" ")]
    .join(" ").toLowerCase();
}

function contentScore(q, bin) {
  const ql = q.toLowerCase();
  if (ql.length <= 2) return 0;
  const all = binToText(bin);
  if (all.includes(ql)) return 2000 + (ql.length / 20) * 500;
  const tokens = ql.split(/[\s._-]+/).filter(Boolean);
  let hits = 0;
  for (const tok of tokens) if (tok.length > 2 && all.includes(tok)) hits++;
  return hits > 0 ? (hits / tokens.length) * 1500 : 0;
}

export function searchBinaries(db, query, osFilter) {
  if (!query.trim()) return [];
  let pool = osFilter ? db.filter(b => b.os === osFilter || b.os === "cross") : db;
  const results = [];
  for (const b of pool) {
    const ns = nameScore(query, b.n);
    const cs = contentScore(query, b);
    const best = Math.max(ns, cs);
    if (best > 0) results.push({ ...b, _s: best, _nh: ns >= cs });
  }
  results.sort((a, b) => b._s - a._s);
  if (results.length > 0 && results[0]._s >= 6000 && results[0]._nh) {
    const th = results[0]._s * 0.25;
    return results.filter(r => r._s >= th);
  }
  return results.filter(r => r._s > 800);
}

// ─── pattern detection rules ────────────────────────────────
const CMDLINE_PATTERNS = {
  "powershell.exe": [
    { re: /-enc\s+\S+/i,                        sev:"CRITICAL", name:"Base64 encoded command (-enc)",         mitre:"T1059.001", scenarios:["staged payload delivery","fileless malware execution","AMSI/logging bypass","SCCM/Intune exception — verify source process"] },
    { re: /-ep\s+bypass|executionpolicy\s+bypass/i, sev:"HIGH", name:"Execution policy bypass",              mitre:"T1059.001", scenarios:["running unsigned/malicious PS1","dropper script execution"] },
    { re: /iex\s*\(|invoke-expression/i,         sev:"HIGH",     name:"Invoke-Expression (IEX)",              mitre:"T1059.001", scenarios:["in-memory payload exec","download cradle second stage"] },
    { re: /downloadstring|iwr\s+http|invoke-webrequest.*http/i, sev:"HIGH", name:"Download cradle",          mitre:"T1105",     scenarios:["remote payload download","fileless stager","C2 initial check-in"] },
    { re: /amsiutils|amsiinit/i,                  sev:"CRITICAL", name:"AMSI bypass attempt",                 mitre:"T1562.001", scenarios:["malware evading AV scanning in PS session"] },
    { re: /-v\s*2\b|-version\s+2\b/i,             sev:"HIGH",     name:"PowerShell v2 downgrade",             mitre:"T1059.001", scenarios:["bypass Script Block Logging (Event 4104)","evade module logging"] },
    { re: /-w\s+hidden|windowstyle\s+hidden/i,    sev:"MEDIUM",   name:"Hidden window style",                  mitre:"T1564.003", scenarios:["stealthy background execution","dropper hiding presence"] },
    { re: /reflection\.assembly/i,                sev:"HIGH",     name:"Reflective .NET loading",              mitre:"T1620",     scenarios:["fileless .NET assembly in memory","bypass AppLocker/WDAC"] },
    { re: /-nop\b|-noprofile\b/i,                 sev:"MEDIUM",   name:"-NoProfile flag",                      mitre:"T1059.001", scenarios:["bypass profile-based detections","generic malicious PS pattern"] },
  ],
  "pwsh.exe": [
    { re: /-enc\s+\S+/i,                        sev:"CRITICAL", name:"Base64 encoded command (-enc)",         mitre:"T1059.001", scenarios:["same as powershell.exe — check if detection rules cover pwsh.exe","staged payload delivery"] },
    { re: /-ep\s+bypass/i,                       sev:"HIGH",     name:"Execution policy bypass",              mitre:"T1059.001", scenarios:["unsigned script execution","bypass profile controls"] },
    { re: /iex\s*\(|invoke-expression/i,         sev:"HIGH",     name:"Invoke-Expression (IEX)",              mitre:"T1059.001", scenarios:["in-memory execution","download cradle"] },
  ],
  "certutil.exe": [
    { re: /-urlcache/i,                           sev:"HIGH",     name:"-urlcache flag",                       mitre:"T1105",     scenarios:["file download — wget/curl alternative","payload staging from web"] },
    { re: /-decode/i,                             sev:"HIGH",     name:"-decode flag",                         mitre:"T1140",     scenarios:["base64 payload unpacking","staged dropper decode step"] },
    { re: /-encode/i,                             sev:"MEDIUM",   name:"-encode flag",                         mitre:"T1140",     scenarios:["binary encoding for exfil","payload preparation"] },
    { re: /https?:\/\//i,                         sev:"HIGH",     name:"URL in args",                          mitre:"T1105",     scenarios:["remote file download","C2 payload staging"] },
  ],
  "mshta.exe": [
    { re: /https?:\/\//i,                         sev:"CRITICAL", name:"Remote URL in args",                   mitre:"T1218.005", scenarios:["phishing HTA payload from web","ClickFix attack","fileless payload delivery — nothing written to disk"] },
    { re: /vbscript:|javascript:/i,               sev:"CRITICAL", name:"Inline script (vbscript/javascript)",  mitre:"T1218.005", scenarios:["one-liner fileless execution","macro-to-shell bypass","ClickFix inline payload"] },
  ],
  "rundll32.exe": [
    { re: /comsvcs/i,                             sev:"CRITICAL", name:"comsvcs.dll loaded",                   mitre:"T1003.001", scenarios:["LSASS memory dump in progress","credential theft — no external tool needed"] },
    { re: /minidump/i,                            sev:"CRITICAL", name:"MiniDump function call",               mitre:"T1003.001", scenarios:["LSASS dump","credential extraction via native DLL"] },
    { re: /javascript:|vbscript:/i,               sev:"HIGH",     name:"Inline script execution",              mitre:"T1218.011", scenarios:["AppLocker bypass","fileless execution via trusted binary"] },
    { re: /https?:\/\//i,                         sev:"HIGH",     name:"Remote path/URL in args",              mitre:"T1218.011", scenarios:["remote DLL loading","C2 payload via rundll32"] },
  ],
  "regsvr32.exe": [
    { re: /\/i:https?:\/\//i,                     sev:"CRITICAL", name:"Squiblydoo — remote SCT URL",          mitre:"T1218.010", scenarios:["AppLocker bypass via remote scriptlet","ClickFix delivery","phishing macro to shell"] },
    { re: /\/i:/i,                                sev:"HIGH",     name:"/i: flag",                             mitre:"T1218.010", scenarios:["scriptlet execution","COM object abuse"] },
    { re: /scrobj\.dll/i,                         sev:"HIGH",     name:"scrobj.dll loaded",                    mitre:"T1218.010", scenarios:["SCT scriptlet execution","AppLocker bypass"] },
  ],
  "schtasks.exe": [
    { re: /\/create/i,                            sev:"HIGH",     name:"New task creation",                    mitre:"T1053.005", scenarios:["persistence setup","privilege escalation task","C2 persistence"] },
    { re: /\/ru\s+system/i,                       sev:"CRITICAL", name:"Run as SYSTEM",                        mitre:"T1053.005", scenarios:["SYSTEM-level persistence","privilege escalation"] },
    { re: /\/s\s+[\d.]+|\/s\s+\w+\.\w+/i,         sev:"HIGH",     name:"Remote target (/s flag)",              mitre:"T1053.005", scenarios:["lateral movement via remote task creation"] },
    { re: /\/sc\s+minute|\/sc\s+hourly/i,          sev:"HIGH",     name:"High-frequency schedule",             mitre:"T1053.005", scenarios:["C2 beacon persistence","periodic payload execution"] },
  ],
  "wmic.exe": [
    { re: /process\s+call\s+create/i,             sev:"CRITICAL", name:"Process creation via WMI",             mitre:"T1047",     scenarios:["spawn malicious process","bypass direct process monitoring","script-less execution"] },
    { re: /\/node:/i,                             sev:"HIGH",     name:"Remote WMI target",                    mitre:"T1047",     scenarios:["lateral movement via WMI","remote command execution without SMB"] },
    { re: /shadowcopy.*delete|delete.*shadowcopy/i, sev:"CRITICAL", name:"Shadow copy deletion",               mitre:"T1490",     scenarios:["pre-ransomware backup destruction"] },
  ],
  "sc.exe": [
    { re: /\bcreate\b/i,                          sev:"HIGH",     name:"Service creation",                     mitre:"T1543.003", scenarios:["backdoor service persistence","privilege escalation payload"] },
    { re: /binpath\s*=/i,                         sev:"HIGH",     name:"binpath modification",                 mitre:"T1543.003", scenarios:["service hijack","payload path change"] },
    { re: /config|create/i,                       sev:"MEDIUM",   name:"Service config change",                mitre:"T1543.003", scenarios:["service persistence modification"] },
  ],
  "reg.exe": [
    { re: /run|runonce/i,                         sev:"HIGH",     name:"Run key modification",                 mitre:"T1547.001", scenarios:["persistence via Run key","startup payload injection"] },
    { re: /save\s+hklm.{0,30}sam|save\s+hklm.{0,30}system|save\s+hklm.{0,30}security/i, sev:"CRITICAL", name:"SAM/SYSTEM/SECURITY hive dump", mitre:"T1003.002", scenarios:["credential dump preparation","offline NTLM hash extraction"] },
    { re: /runasppl.*\s+0|disableantispyware.*\s+1/i, sev:"CRITICAL", name:"Security control disabled",       mitre:"T1562",     scenarios:["disable LSA Protection","disable Windows Defender"] },
  ],
  "netsh.exe": [
    { re: /portproxy/i,                           sev:"HIGH",     name:"Port proxy rule added",                mitre:"T1090.001", scenarios:["C2 traffic redirection","pivot port forwarding","lateral movement relay"] },
    { re: /firewall.{0,20}off|advfirewall.{0,20}off/i, sev:"CRITICAL", name:"Firewall disabled",              mitre:"T1562.004", scenarios:["defense evasion","allow inbound C2 traffic"] },
    { re: /wlan.{0,10}key=clear/i,                sev:"HIGH",     name:"WiFi password dump",                   mitre:"T1555",     scenarios:["credential harvesting from saved WiFi profiles"] },
    { re: /add\s+helper/i,                        sev:"HIGH",     name:"Helper DLL added",                     mitre:"T1546",     scenarios:["netsh persistence via DLL","DLL loaded every netsh call"] },
  ],
  "msiexec.exe": [
    { re: /\/i\s+https?:\/\//i,                   sev:"HIGH",     name:"Remote MSI install from URL",          mitre:"T1218.007", scenarios:["malicious package delivery from web","payload inside MSI"] },
    { re: /\/y\s+/i,                              sev:"HIGH",     name:"/y flag — DllUnregisterServer exec",   mitre:"T1218.007", scenarios:["DLL execution bypass","AppLocker bypass via msiexec"] },
    { re: /\/q\b|\/qn\b/i,                        sev:"MEDIUM",   name:"Silent install",                       mitre:"T1218.007", scenarios:["stealthy package install","no user prompt"] },
  ],
  "bitsadmin.exe": [
    { re: /\/transfer/i,                          sev:"HIGH",     name:"BITS transfer job",                    mitre:"T1197",     scenarios:["stealthy download (camouflaged as Windows Update)","payload staging"] },
    { re: /setnotifycmdline/i,                    sev:"CRITICAL", name:"SetNotifyCmdLine — auto-exec",         mitre:"T1197",     scenarios:["execute payload automatically after download completes"] },
  ],
  "cmd.exe": [
    { re: /\/c\s+.*powershell/i,                  sev:"HIGH",     name:"Spawning PowerShell",                  mitre:"T1059.003", scenarios:["macro/exploit → cmd → powershell chain","parent process bypass"] },
    { re: /net\s+user.{0,30}\/add/i,              sev:"CRITICAL", name:"Creating backdoor user",               mitre:"T1136.001", scenarios:["backdoor account creation","pre-ransomware user setup"] },
    { re: /certutil.{0,30}-urlcache|bitsadmin.{0,30}\/transfer/i, sev:"HIGH", name:"Download tool invocation", mitre:"T1105", scenarios:["payload download chain via cmd"] },
  ],
  "bash": [
    { re: /\/dev\/tcp\//i,                        sev:"CRITICAL", name:"Reverse shell via /dev/tcp",           mitre:"T1059.004", scenarios:["reverse shell — no external tools needed","RCE post-exploit callback"] },
    { re: /base64\s+-d.*bash|bash.*base64/i,       sev:"HIGH",     name:"Base64 decode piped to bash",         mitre:"T1059.004", scenarios:["encoded payload execution","bypass string-based detection"] },
    { re: /-i\s*>&/i,                             sev:"CRITICAL", name:"Interactive shell redirection",        mitre:"T1059.004", scenarios:["reverse shell setup","full shell handback"] },
  ],
  "nc": [
    { re: /-e\s+\S+/i,                            sev:"CRITICAL", name:"-e flag (execute)",                    mitre:"T1095",     scenarios:["reverse shell — pass shell to remote","bind shell listener"] },
    { re: /\/bin\/bash|\/bin\/sh/i,               sev:"CRITICAL", name:"Shell binary in args",                 mitre:"T1095",     scenarios:["pipe shell to netcat connection","reverse/bind shell"] },
    { re: /-lvnp|-lvp/i,                          sev:"HIGH",     name:"Listener mode (-l flag)",              mitre:"T1095",     scenarios:["bind shell backdoor","incoming connection listener"] },
  ],
  "python": [
    { re: /socket.*connect|s\.connect/i,           sev:"CRITICAL", name:"Socket connection in inline code",    mitre:"T1059.006", scenarios:["Python reverse shell","custom C2 agent"] },
    { re: /-c\s+["']/i,                           sev:"HIGH",     name:"Inline code execution (-c)",           mitre:"T1059.006", scenarios:["one-liner payload","reverse shell","evasion via interpreter"] },
    { re: /subprocess|os\.system|os\.popen/i,      sev:"HIGH",     name:"System command execution",            mitre:"T1059.006", scenarios:["command execution via Python","shell spawning"] },
  ],
  "curl": [
    { re: /\|\s*bash|\|\s*sh/i,                   sev:"CRITICAL", name:"curl piped to shell",                  mitre:"T1059",     scenarios:["fileless script execution from URL","supply chain attack vector"] },
    { re: /-d\s+@?\//i,                           sev:"HIGH",     name:"POST with file data",                  mitre:"T1048",     scenarios:["data exfiltration via HTTP POST","C2 communication"] },
    { re: /-o\s+\/(tmp|dev\/shm)/i,               sev:"HIGH",     name:"Download to /tmp or /dev/shm",         mitre:"T1105",     scenarios:["payload staging to RAM/temp — common dropper path"] },
  ],
  "wget": [
    { re: /-O\s+\/(tmp|dev\/shm)/i,               sev:"HIGH",     name:"Download to /tmp or /dev/shm",         mitre:"T1105",     scenarios:["payload staging","in-memory-ish execution area"] },
    { re: /\|\s*bash|\|\s*sh/i,                   sev:"CRITICAL", name:"wget piped to shell",                  mitre:"T1059",     scenarios:["fileless execution from URL"] },
    { re: /-q.*\.\s*$/i,                          sev:"MEDIUM",   name:"Silent download",                      mitre:"T1105",     scenarios:["quiet payload download"] },
  ],
  "socat": [
    { re: /exec:\s*\/bin|exec:.*bash|exec:.*sh/i,  sev:"CRITICAL", name:"Shell exec via socat",                mitre:"T1095",     scenarios:["full TTY reverse shell","interactive backdoor"] },
    { re: /tcp4-listen|tcp-listen/i,              sev:"HIGH",     name:"Bind listener",                        mitre:"T1095",     scenarios:["bind shell backdoor","incoming connection relay"] },
    { re: /openssl/i,                             sev:"HIGH",     name:"SSL/TLS channel",                      mitre:"T1095",     scenarios:["encrypted reverse shell — bypasses SSL inspection","C2 over TLS"] },
  ],
  "crontab": [
    { re: /\/tmp|\/dev\/shm/i,                    sev:"HIGH",     name:"Script from /tmp or /dev/shm",         mitre:"T1053.003", scenarios:["persistence running payload from temp dir"] },
    { re: /\*\s+\*\s+\*\s+\*\s+\*/i,             sev:"HIGH",     name:"Every-minute cron (*/min)",             mitre:"T1053.003", scenarios:["very frequent C2 callback","periodic beacon execution"] },
    { re: /curl|wget|nc\s|bash\s+-i/i,            sev:"CRITICAL", name:"Network tool in cron",                 mitre:"T1053.003", scenarios:["cron-based C2 poll","persistent reverse shell trigger"] },
  ],
};

// generic patterns applied to ALL binaries
const GENERIC_PATTERNS = [
  { re: /http:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/i, sev:"HIGH",     name:"Direct IP URL (no domain)",  mitre:"T1071.001", scenarios:["C2 infra without DNS","fast-flux IP address"] },
  { re: /\/(tmp|dev\/shm|var\/tmp)\//i,                   sev:"MEDIUM",   name:"Temp path reference",        mitre:"T1105",     scenarios:["dropper staging area","payload hidden in temp"] },
  { re: /c:\\(temp|users\\public|programdata)\\/i,        sev:"MEDIUM",   name:"Suspicious Windows path",    mitre:"T1105",     scenarios:["common attacker staging path"] },
  { re: /base64/i,                                        sev:"MEDIUM",   name:"base64 reference",           mitre:"T1140",     scenarios:["encoded payload","obfuscated command"] },
];

export function detectCommand(cmdline, db) {
  if (!cmdline.trim()) return null;

  const lower = cmdline.trim().toLowerCase();

  // extract binary name — handle full paths
  const rawToken = lower
    .replace(/^"([^"]+)"/, "$1")  // unquote
    .split(/\s+/)[0]
    .replace(/.*[/\\]/, "");       // strip path prefix

  // find matching binary in DB
  let binary = null;
  // exact match first
  for (const b of db) {
    if (b.n.toLowerCase() === rawToken) { binary = b; break; }
  }
  // prefix match fallback
  if (!binary) {
    for (const b of db) {
      const bn = b.n.toLowerCase().replace(/\.exe$|\.dll$|\.sh$|\.bat$/i, "");
      const qt = rawToken.replace(/\.exe$|\.dll$|\.sh$|\.bat$/i, "");
      if (bn === qt || bn.startsWith(qt) || qt.startsWith(bn)) { binary = b; break; }
    }
  }

  // collect patterns
  const binaryKey = binary ? binary.n.toLowerCase().replace(/\.exe$/, "") : null;
  const specificPatterns = [];

  // check binary-specific patterns
  const patternKeys = Object.keys(CMDLINE_PATTERNS);
  for (const key of patternKeys) {
    const bk = key.replace(/\.exe$/, "");
    if (binaryKey === bk || rawToken.includes(bk)) {
      for (const p of CMDLINE_PATTERNS[key]) {
        if (p.re.test(cmdline)) specificPatterns.push(p);
      }
    }
  }

  // check generic patterns
  const genericHits = GENERIC_PATTERNS.filter(p => p.re.test(cmdline));

  const allPatterns = [...specificPatterns, ...genericHits];

  // dedupe mitre
  const mitres = [...new Set(allPatterns.map(p => p.mitre).filter(Boolean))];

  // overall severity = worst
  const sevOrder = { CRITICAL: 3, HIGH: 2, MEDIUM: 1, LOW: 0 };
  const overallSev = allPatterns.reduce((best, p) => {
    return (sevOrder[p.sev] || 0) > (sevOrder[best] || 0) ? p.sev : best;
  }, allPatterns.length ? "LOW" : null);

  return {
    binary,
    rawToken,
    patterns: allPatterns,
    mitres,
    overallSev,
    clean: allPatterns.length === 0,
  };
}

export function genClosureTemplate(b) {
  return `Alert ter-trigger dari [NAMA LOG SOURCE] yang mencatat eksekusi ${b.n} pada asset [IP/HOSTNAME ASSET]

**Key Findings:**
- Source IP: [IP]
- Process: ${b.p}
- Command Line: [COMMAND LINE]
- Parent Process: [PARENT PROCESS]
- Response/Action: [BLOCKED/DETECTED/ALLOWED]
- Timestamp: [TANGGAL WAKTU WIB]
- Teridentifikasi oleh: [NAMA TOOL/SENSOR]

---

**Analysis & Reasoning:**
Eksekusi ${b.n} terdeteksi. Dikategorikan ${b.c} (risk: ${b.r}). ${b.abuse}

MITRE ATT&CK: ${b.m.map((x, i) => `${x} - ${b.mn[i]}`).join(", ")}
Tactic: ${b.t.join(", ")}.

[TAMBAHKAN NARASI INVESTIGASI]

**Conclusion:**
[TINDAKAN REKOMENDASI]

Ticket ditutup sebagai [True Positive / False Positive / Benign Positive] - [KLASIFIKASI].`;
}
