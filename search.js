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
  "mimikatz": [
    { re: /sekurlsa::logonpasswords/i,             sev:"CRITICAL", name:"sekurlsa::logonpasswords",             mitre:"T1003.001", scenarios:["plaintext credential dump from LSASS memory"] },
    { re: /lsadump::sam/i,                        sev:"CRITICAL", name:"lsadump::sam",                         mitre:"T1003.002", scenarios:["SAM database dump — NTLM hash extraction"] },
    { re: /lsadump::dcsync/i,                     sev:"CRITICAL", name:"lsadump::dcsync",                      mitre:"T1003.006", scenarios:["DCSync attack — impersonating DC to pull NTLM hashes"] },
    { re: /kerberos::ptt/i,                       sev:"CRITICAL", name:"kerberos::ptt — Pass the Ticket",      mitre:"T1550.003", scenarios:["lateral movement via stolen Kerberos ticket"] },
    { re: /privilege::debug/i,                    sev:"HIGH",     name:"privilege::debug",                     mitre:"T1134",     scenarios:["gaining SeDebugPrivilege — pre-requisite for most Mimikatz modules"] },
    { re: /token::elevate/i,                      sev:"CRITICAL", name:"token::elevate",                       mitre:"T1134.001", scenarios:["token impersonation — escalating to SYSTEM"] },
    { re: /coffee/i,                              sev:"HIGH",     name:"Mimikatz banner string",               mitre:"T1003",     scenarios:["mimikatz invoked — check full command chain"] },
  ],
  "psexec": [
    { re: /-s\b/i,                                sev:"CRITICAL", name:"Run as SYSTEM (-s)",                   mitre:"T1569.002", scenarios:["SYSTEM shell via PsExec — lateral movement with max priv"] },
    { re: /\\\\[\d.]+\\|\\\\[\w-]+\\/i,           sev:"HIGH",     name:"Remote target (UNC path)",             mitre:"T1021.002", scenarios:["lateral movement to remote host via SMB"] },
    { re: /-accepteula/i,                         sev:"HIGH",     name:"-accepteula flag",                     mitre:"T1569.002", scenarios:["suppresses EULA dialog — common in automated attacker tooling"] },
    { re: /-u\s+\S+\s+-p\s+\S+/i,               sev:"CRITICAL", name:"Explicit credentials (-u / -p)",       mitre:"T1078",     scenarios:["credential stuffing","use of stolen creds for lateral movement"] },
    { re: /-d\b/i,                                sev:"MEDIUM",   name:"Background execution (-d)",            mitre:"T1569.002", scenarios:["detach from parent — stealthy process exec"] },
  ],
  "vssadmin": [
    { re: /delete\s+shadows/i,                    sev:"CRITICAL", name:"Shadow copy deletion",                 mitre:"T1490",     scenarios:["pre-ransomware backup destruction","inhibit recovery"] },
    { re: /create\s+shadow/i,                     sev:"HIGH",     name:"Shadow copy creation",                 mitre:"T1003.003", scenarios:["NTDS.dit copy via shadow — offline credential dump setup"] },
    { re: /resize\s+shadowstorage/i,              sev:"HIGH",     name:"Shadow storage resize",                mitre:"T1490",     scenarios:["reducing shadow storage to prevent backups"] },
    { re: /list\s+shadows/i,                      sev:"MEDIUM",   name:"List shadow copies",                   mitre:"T1082",     scenarios:["attacker enumerating available snapshots"] },
  ],
  "wevtutil.exe": [
    { re: /cl\s|clear-log/i,                      sev:"CRITICAL", name:"Event log cleared (cl)",               mitre:"T1070.001", scenarios:["anti-forensics — covering tracks after compromise"] },
    { re: /\/e:false/i,                           sev:"CRITICAL", name:"Log channel disabled",                 mitre:"T1562.002", scenarios:["disabling event logging to evade detection"] },
    { re: /el\s*$/i,                              sev:"MEDIUM",   name:"Enumerating log channels",             mitre:"T1082",     scenarios:["attacker discovering what logs are available"] },
    { re: /qe\s+Security|qe\s+System/i,          sev:"MEDIUM",   name:"Querying Security/System log",         mitre:"T1033",     scenarios:["attacker reviewing log for detection signatures"] },
  ],
  "ntdsutil": [
    { re: /ifm|install\s+from\s+media/i,         sev:"CRITICAL", name:"IFM snapshot (NTDS.dit copy)",         mitre:"T1003.003", scenarios:["creating offline copy of NTDS.dit — full AD credential dump"] },
    { re: /snapshot|activate\s+instance/i,        sev:"HIGH",     name:"NTDS snapshot",                        mitre:"T1003.003", scenarios:["snapshot-based NTDS.dit access without VSS abuse"] },
    { re: /ac\s+i\s+ntds/i,                       sev:"CRITICAL", name:"Activate NTDS instance",               mitre:"T1003.003", scenarios:["mounting NTDS instance — prelude to credential extraction"] },
  ],
  "rubeus": [
    { re: /kerberoast/i,                          sev:"CRITICAL", name:"Kerberoasting",                        mitre:"T1558.003", scenarios:["dumping TGS tickets for offline cracking","targeting service accounts"] },
    { re: /asreproast/i,                          sev:"CRITICAL", name:"AS-REP Roasting",                      mitre:"T1558.004", scenarios:["attacking accounts with Kerberos pre-auth disabled"] },
    { re: /ptt|pass.*ticket/i,                    sev:"CRITICAL", name:"Pass the Ticket",                      mitre:"T1550.003", scenarios:["injecting stolen Kerberos TGT for lateral movement"] },
    { re: /dump/i,                                sev:"HIGH",     name:"Ticket dump",                          mitre:"T1558",     scenarios:["dumping in-memory Kerberos tickets"] },
    { re: /monitor/i,                             sev:"HIGH",     name:"Ticket monitor mode",                  mitre:"T1558",     scenarios:["real-time interception of new Kerberos tickets"] },
    { re: /s4u/i,                                 sev:"CRITICAL", name:"S4U delegation abuse",                 mitre:"T1134.001", scenarios:["Constrained Delegation abuse","impersonating arbitrary users"] },
  ],
  "sharphound": [
    { re: /-c\s+all|--collectionmethod\s+all/i,  sev:"CRITICAL", name:"Full collection method",               mitre:"T1482",     scenarios:["BloodHound full AD mapping — complete attack path enumeration"] },
    { re: /--zipfilename|--outputdirectory/i,     sev:"HIGH",     name:"Output file specified",                mitre:"T1482",     scenarios:["data collection for BloodHound ingestion"] },
    { re: /--domain\s+/i,                         sev:"HIGH",     name:"Target domain specified",              mitre:"T1482",     scenarios:["cross-domain AD enumeration"] },
    { re: /-c\s+dcom|session|loggedon/i,          sev:"HIGH",     name:"Session/loggedon enumeration",        mitre:"T1033",     scenarios:["mapping who is logged in where — used for targeting"] },
  ],
  "nmap": [
    { re: /-sV\b|-sC\b/i,                         sev:"HIGH",     name:"Service/script scan",                  mitre:"T1046",     scenarios:["service version detection — vulnerability identification"] },
    { re: /-p-\b|--top-ports/i,                   sev:"HIGH",     name:"Full port range scan",                 mitre:"T1046",     scenarios:["comprehensive port discovery on target"] },
    { re: /--script.*vuln|--script.*exploit/i,    sev:"CRITICAL", name:"Vuln/exploit NSE script",              mitre:"T1190",     scenarios:["active exploitation attempt via Nmap scripts"] },
    { re: /-O\b/i,                                sev:"MEDIUM",   name:"OS fingerprinting (-O)",               mitre:"T1082",     scenarios:["enumerating target OS for exploit selection"] },
    { re: /-sn\b|--ping-scan/i,                   sev:"MEDIUM",   name:"Ping scan / host discovery",           mitre:"T1018",     scenarios:["live host discovery across subnet"] },
    { re: /-Pn\b/i,                               sev:"MEDIUM",   name:"Skip host discovery (-Pn)",            mitre:"T1046",     scenarios:["scanning without ping — evading ICMP-based detection"] },
  ],
  "ssh": [
    { re: /-R\s+\d+/i,                            sev:"CRITICAL", name:"Reverse tunnel (-R)",                  mitre:"T1572",     scenarios:["reverse SSH tunnel to C2","port forwarding to bypass firewall"] },
    { re: /-L\s+\d+/i,                            sev:"HIGH",     name:"Local port forward (-L)",              mitre:"T1572",     scenarios:["tunneling traffic through SSH to reach internal services"] },
    { re: /-D\s+\d+/i,                            sev:"HIGH",     name:"Dynamic SOCKS proxy (-D)",             mitre:"T1572",     scenarios:["SOCKS5 proxy for tunneling all traffic through compromised host"] },
    { re: /-o\s+StrictHostKeyChecking=no/i,        sev:"MEDIUM",   name:"Host key checking disabled",          mitre:"T1021.004", scenarios:["automated/non-interactive lateral movement","MITM blind acceptance"] },
    { re: /-i\s+\/tmp|ProxyJump/i,                sev:"HIGH",     name:"Key from temp / ProxyJump",            mitre:"T1021.004", scenarios:["key from staging area","multi-hop lateral movement"] },
    { re: /\/bin\/sh|\/bin\/bash|bash\s+-i/i,     sev:"CRITICAL", name:"Shell forced via SSH",                 mitre:"T1059.004", scenarios:["forced command execution on remote host"] },
  ],
  "chisel": [
    { re: /server.*--reverse/i,                   sev:"CRITICAL", name:"Reverse server mode",                  mitre:"T1572",     scenarios:["C2 server accepting reverse tunnels from compromised hosts"] },
    { re: /client.*R:/i,                          sev:"CRITICAL", name:"Reverse remote forward (R:)",          mitre:"T1572",     scenarios:["tunneling C2 traffic from victim back to attacker"] },
    { re: /socks/i,                               sev:"HIGH",     name:"SOCKS proxy mode",                     mitre:"T1572",     scenarios:["all-traffic proxy through compromised host for lateral movement"] },
    { re: /:\d{4,5}\s+/i,                         sev:"HIGH",     name:"Port forwarding",                      mitre:"T1090.001", scenarios:["relaying traffic through firewall","pivot to internal network"] },
  ],
  "responder": [
    { re: /-I\s+\w+/i,                            sev:"CRITICAL", name:"Interface specified (-I)",             mitre:"T1557.001", scenarios:["LLMNR/NBT-NS poisoning to capture NetNTLM hashes"] },
    { re: /--lm\b|-l\b/i,                         sev:"CRITICAL", name:"LM hash capture mode",                 mitre:"T1557.001", scenarios:["downgrading auth to capture weaker LM hashes"] },
    { re: /-w\b/i,                                sev:"HIGH",     name:"WPAD rogue proxy (-w)",                mitre:"T1557.001", scenarios:["WPAD attack to intercept browser proxy traffic"] },
    { re: /-f\b/i,                                sev:"HIGH",     name:"Fingerprint mode (-f)",                mitre:"T1040",     scenarios:["passive fingerprinting of hosts on network"] },
  ],
  "crackmapexec": [
    { re: /--sam\b/i,                             sev:"CRITICAL", name:"SAM dump (--sam)",                     mitre:"T1003.002", scenarios:["remote SAM credential dump via SMB"] },
    { re: /--lsa\b/i,                             sev:"CRITICAL", name:"LSA secrets dump (--lsa)",             mitre:"T1003.004", scenarios:["extracting LSA secrets — service account creds"] },
    { re: /--ntds\b/i,                            sev:"CRITICAL", name:"NTDS dump (--ntds)",                   mitre:"T1003.003", scenarios:["full AD credential dump from Domain Controller"] },
    { re: /-x\s+\S+|-X\s+\S+/i,                  sev:"CRITICAL", name:"Remote command execution (-x/-X)",     mitre:"T1021.002", scenarios:["cmd/PS execution on remote host via CME"] },
    { re: /--shares\b/i,                          sev:"MEDIUM",   name:"Share enumeration (--shares)",         mitre:"T1135",     scenarios:["mapping accessible SMB shares for data access"] },
    { re: /--pass-pol\b/i,                        sev:"MEDIUM",   name:"Password policy enum",                 mitre:"T1201",     scenarios:["checking lockout policy before brute force"] },
  ],
  "netexec": [
    { re: /--sam\b/i,                             sev:"CRITICAL", name:"SAM dump (--sam)",                     mitre:"T1003.002", scenarios:["remote SAM credential dump — netexec (CME successor)"] },
    { re: /--ntds\b/i,                            sev:"CRITICAL", name:"NTDS dump (--ntds)",                   mitre:"T1003.003", scenarios:["full domain credential dump from DC"] },
    { re: /-x\s+\S+|-X\s+\S+/i,                  sev:"CRITICAL", name:"Remote command execution",             mitre:"T1021.002", scenarios:["lateral movement via remote command exec"] },
    { re: /--local-auth/i,                        sev:"HIGH",     name:"Local auth mode",                      mitre:"T1078.003", scenarios:["spraying local admin credentials across hosts"] },
  ],
  "kerbrute": [
    { re: /userenum\b/i,                          sev:"HIGH",     name:"User enumeration",                     mitre:"T1087.002", scenarios:["enumerating valid domain users via Kerberos AS-REQ — no auth required"] },
    { re: /passwordspray\b/i,                     sev:"CRITICAL", name:"Password spraying",                    mitre:"T1110.003", scenarios:["low-and-slow password spray against AD accounts"] },
    { re: /bruteuser\b|bruteforce\b/i,            sev:"CRITICAL", name:"Brute force",                          mitre:"T1110.001", scenarios:["credential brute force against specific account"] },
    { re: /--dc\s+|--domain\s+/i,                sev:"HIGH",     name:"Target DC/domain specified",           mitre:"T1078",     scenarios:["targeted Kerberos attack against specific domain"] },
  ],
  "find": [
    { re: /-perm\s+-4000|-perm\s+u=s/i,          sev:"HIGH",     name:"SUID binary search",                   mitre:"T1548.001", scenarios:["privilege escalation recon — finding SUID binaries"] },
    { re: /-exec\s+\S+/i,                         sev:"HIGH",     name:"find -exec (command execution)",       mitre:"T1059.004", scenarios:["GTFOBins abuse — executing commands via find -exec"] },
    { re: /-name\s+.*\.key|password|\.pem|\.pfx/i, sev:"HIGH",   name:"Credential file search",               mitre:"T1552.001", scenarios:["searching for private keys, passwords, certificates"] },
    { re: /\/tmp|\/dev\/shm/i,                    sev:"MEDIUM",   name:"Searching temp paths",                 mitre:"T1083",     scenarios:["locating staged payloads in temp directories"] },
  ],
  "iptables": [
    { re: /-F\b|--flush/i,                        sev:"CRITICAL", name:"Flush all rules (-F)",                 mitre:"T1562.004", scenarios:["wiping all firewall rules — exposing host to network"] },
    { re: /-P\s+INPUT\s+ACCEPT|-P\s+FORWARD\s+ACCEPT/i, sev:"CRITICAL", name:"Default ACCEPT policy",         mitre:"T1562.004", scenarios:["allow all traffic by default — defense evasion"] },
    { re: /-A\s+INPUT.*--dport\s+\d+.*ACCEPT/i,  sev:"HIGH",     name:"Inbound port rule added",              mitre:"T1562.004", scenarios:["opening inbound port — C2 listener access"] },
    { re: /-j\s+REDIRECT.*--to-port/i,            sev:"HIGH",     name:"Traffic redirect rule",                mitre:"T1090.001", scenarios:["intercepting or redirecting traffic"] },
  ],
  "launchctl": [
    { re: /load\s+/i,                             sev:"HIGH",     name:"LaunchAgent/Daemon load",              mitre:"T1543.001", scenarios:["loading plist for persistence on macOS"] },
    { re: /start\s+com\.|kickstart/i,             sev:"MEDIUM",   name:"Starting service",                     mitre:"T1543.004", scenarios:["starting custom LaunchDaemon — persistence check"] },
    { re: /\/tmp\/|\/var\/tmp\//i,                sev:"CRITICAL", name:"Service from temp path",               mitre:"T1543.001", scenarios:["launching payload from temp — dropped binary persistence"] },
    { re: /disable\s+/i,                          sev:"HIGH",     name:"Disabling service",                    mitre:"T1562",     scenarios:["disabling security tools (EDR, syslog, etc.)"] },
  ],
  "osascript": [
    { re: /-e\s+["']/i,                           sev:"HIGH",     name:"Inline AppleScript (-e)",              mitre:"T1059.002", scenarios:["one-liner execution — phishing payload","ClickFix macOS variant"] },
    { re: /do\s+shell\s+script/i,                 sev:"HIGH",     name:"Shell command via AppleScript",        mitre:"T1059.002", scenarios:["executing shell commands through AppleScript layer","macOS LOLBin chain"] },
    { re: /with\s+administrator\s+privileges/i,   sev:"CRITICAL", name:"Admin priv request",                   mitre:"T1548",     scenarios:["privilege escalation via AppleScript sudo prompt"] },
    { re: /display\s+dialog.*password/i,          sev:"CRITICAL", name:"Password phishing dialog",             mitre:"T1056.002", scenarios:["fake macOS password prompt to harvest credentials"] },
  ],
  "net.exe": [
    { re: /user\s+\S+\s+\S+\s+\/add/i,           sev:"CRITICAL", name:"Creating local user",                  mitre:"T1136.001", scenarios:["backdoor account creation"] },
    { re: /localgroup\s+administrators\s+.*\/add/i, sev:"CRITICAL", name:"Adding to Administrators",          mitre:"T1098",     scenarios:["privilege escalation — adding user to local admin group"] },
    { re: /use\s+\\\\/i,                          sev:"HIGH",     name:"SMB share mapping (net use)",          mitre:"T1021.002", scenarios:["lateral movement via SMB","mapping attacker share to drop tools"] },
    { re: /view\s+\\\\/i,                         sev:"MEDIUM",   name:"Remote share enumeration",             mitre:"T1135",     scenarios:["discovering accessible SMB shares on remote host"] },
    { re: /group\s+.*\/domain/i,                  sev:"MEDIUM",   name:"Domain group enumeration",             mitre:"T1069.002", scenarios:["AD recon — mapping privileged domain groups"] },
  ],
  "nltest": [
    { re: /\/dclist:|\/domain_trusts/i,           sev:"HIGH",     name:"Domain/trust enumeration",             mitre:"T1482",     scenarios:["AD recon — listing DC and trust relationships","BloodHound precursor"] },
    { re: /\/server:/i,                           sev:"MEDIUM",   name:"Remote server target",                 mitre:"T1033",     scenarios:["querying specific domain controller"] },
    { re: /\/trusted_domains/i,                   sev:"HIGH",     name:"Trust mapping",                        mitre:"T1482",     scenarios:["identifying forest trusts for cross-domain attack paths"] },
  ],
  "dsquery": [
    { re: /\*\s+.*-limit\s+0/i,                  sev:"HIGH",     name:"Unlimited LDAP query",                 mitre:"T1087.002", scenarios:["dumping entire AD object list — mass account enumeration"] },
    { re: /group.*-name.*admin/i,                 sev:"HIGH",     name:"Admin group query",                    mitre:"T1069.002", scenarios:["identifying privileged groups in AD"] },
    { re: /computer.*-limit/i,                    sev:"MEDIUM",   name:"Computer object enumeration",          mitre:"T1018",     scenarios:["mapping all computer objects for target selection"] },
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

export function genClosureTemplate(b, cmdline = "") {
  const cmdLineValue = cmdline.trim() ? cmdline.trim() : "[COMMAND LINE]";
  return `Alert ter-trigger dari [NAMA LOG SOURCE] yang mencatat eksekusi ${b.n} pada asset [IP/HOSTNAME ASSET]

**Key Findings:**
- Source IP: [IP]
- Process: ${b.p}
- Command Line: ${cmdLineValue}
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
