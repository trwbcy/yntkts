# yntkts — ya ndak tau kok tanya saya

> "biar binary yang jawab"

🦆 Fuzzy binary lookup tool for SOC Analysts. Typo-tolerant, case-insensitive, instant results.

## What is this?

SOC Analysts waste time googling binaries during incident investigation. yntkts gives you instant intel on any binary — abuse potential, investigation tips, MITRE ATT&CK mapping, detection guidance, and ready-to-paste closure templates.

Type "pwershle" and it finds `powershell.exe`. Type "mimkatz" and it finds `mimikatz.exe`. No enter needed — results filter in realtime.

## Features

- **Fuzzy search** — consonant skeleton matching, Levenshtein distance, subsequence matching. Handles aggressive typos.
- **Strict filtering** — search "mshta" shows only mshta.exe, not 15 unrelated results
- **60+ binaries** — Windows LOLBins, system binaries, critical processes, offensive tools, Linux/macOS utilities
- **5 intel tabs** per binary:
  - `intel` — abuse potential, red team usage, legitimate use
  - `tips` — step-by-step investigation checklist
  - `mitre` — ATT&CK technique mapping + references
  - `detect` — detection rules/guidance
  - `closure` — copy-paste ready ticket closure template
- **Keyboard navigation** — Arrow keys, Enter, Escape, Ctrl+K

## Project Structure

```
yntkts/
├── db.js        # Binary database (add new binaries here)
├── search.js    # Fuzzy search engine
├── app.jsx      # React UI component
└── README.md
```

## Adding New Binaries

Open `db.js` and add a new entry to the `DB` array:

```javascript
{ n:"binary_name.exe",     // binary name
  c:"lolbin",              // category: lolbin|system|critical|offensive|utility|tool|interpreter|shell
  os:"win",                // os: win|linux|macos|cross
  p:"C:\\full\\path",      // full binary path
  d:"Short description",   // one-liner description
  r:"HIGH",                // risk: CRITICAL|HIGH|MEDIUM|LOW
  m:["T1234.001"],         // MITRE technique IDs
  mn:["Technique Name"],   // MITRE technique names
  t:["Execution"],         // MITRE tactics
  abuse:"How it's abused",
  red:"Red team usage",
  legit:"Legitimate use cases",
  tips:["Investigation tip 1", "Tip 2"],
  detect:"Detection guidance",
  ref:["https://reference-url"] },
```

## Tech Stack

- React (functional components + hooks)
- JetBrains Mono font
- Ubuntu grey theme (#2D2D2D) + pink accent (#E95678)

## Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `↑` `↓` | Navigate results |
| `Enter` | Select binary |
| `Escape` | Back / clear search |
| `Ctrl+K` | Reset everything |

## License

MIT — do whatever you want with it.

---

*Built for SOC Analysts who don't have time for BS.*
