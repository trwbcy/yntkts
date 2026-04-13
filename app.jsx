import { useState, useEffect, useRef, useMemo, useCallback } from "react";
import DB from "./db.js";
import { searchBinaries, detectCommand, genClosureTemplate } from "./search.js";

const RC = { CRITICAL:"#E95678", HIGH:"#FAB795", MEDIUM:"#89DDFF", LOW:"#A8CC8C" };
const CC = { lolbin:"#E95678", system:"#7A7D84", critical:"#B877DB", offensive:"#E95678",
  utility:"#89DDFF", tool:"#FAC863", interpreter:"#FAB795", shell:"#A8CC8C" };
const SV = { CRITICAL:"#E95678", HIGH:"#FAB795", MEDIUM:"#89DDFF", LOW:"#A8CC8C" };

// all binary names for cross-ref linking
const BINARY_NAMES = DB.map(b => b.n).sort((a, b) => b.length - a.length);
const BINARY_MAP = Object.fromEntries(DB.map(b => [b.n.toLowerCase(), b]));

// ─── cross-reference: whole-word boundary matching only ──────
const WORD_BOUNDARY = /[\s,.()\[\]{};:'"!?\/\\→\-]/;
function isAtWordBoundary(str, start, end) {
  const before = start === 0 ? null : str[start - 1];
  const after  = end >= str.length ? null : str[end];
  const ok = (c) => c === null || WORD_BOUNDARY.test(c);
  return ok(before) && ok(after);
}

// Only link names that are ≥4 chars to avoid false positives on "sh","dd","nc","at" inside words
const LINKABLE_NAMES = BINARY_NAMES.filter(n => n.replace(/\.\w+$/, "").length >= 4);

function CrossRef({ text, onSelect }) {
  if (!text || typeof text !== "string") return <span>{text}</span>;
  const parts = [];
  let remaining = text;
  let key = 0;
  while (remaining.length > 0) {
    let earliest = null, earliestIdx = Infinity;
    for (const name of LINKABLE_NAMES) {
      const idx = remaining.toLowerCase().indexOf(name.toLowerCase());
      if (idx !== -1 && idx < earliestIdx && isAtWordBoundary(remaining, idx, idx + name.length)) {
        earliest = name; earliestIdx = idx;
      }
    }
    if (!earliest) { parts.push(<span key={key++}>{remaining}</span>); break; }
    if (earliestIdx > 0) parts.push(<span key={key++}>{remaining.slice(0, earliestIdx)}</span>);
    const matched = remaining.slice(earliestIdx, earliestIdx + earliest.length);
    const bin = BINARY_MAP[earliest.toLowerCase()];
    parts.push(
      <span key={key++} onClick={() => bin && onSelect(bin)}
        style={{ color:"#89DDFF", cursor:"pointer", borderBottom:"1px dashed #89DDFF44", paddingBottom:1 }}
        title={`→ ${earliest}`}>{matched}</span>
    );
    remaining = remaining.slice(earliestIdx + earliest.length);
  }
  return <>{parts}</>;
}

// ─── OS filter config ─────────────────────────────────────────
const OS_OPTS = [
  { id: null,    label: "all" },
  { id: "win",   label: "windows" },
  { id: "linux", label: "linux" },
  { id: "macos", label: "macos" },
];

export default function YNTKTS() {
  const [q, setQ]         = useState("");
  const [sel, setSel]     = useState(null);
  const [idx, setIdx]     = useState(0);
  const [tab, setTab]     = useState(0);
  const [copied, setCopied] = useState(false);
  const [osFilter, setOsFilter] = useState(null);
  const [mode, setMode]   = useState("search"); // "search" | "analyze"
  const [cmdInput, setCmdInput] = useState("");
  const inputRef  = useRef(null);
  const listRef   = useRef(null);

  const res = useMemo(() => searchBinaries(DB, q, osFilter), [q, osFilter]);
  const detection = useMemo(() => mode === "analyze" && cmdInput.trim() ? detectCommand(cmdInput, DB) : null, [cmdInput, mode]);

  useEffect(() => { inputRef.current?.focus(); }, []);
  useEffect(() => { setIdx(0); setSel(null); }, [q, osFilter]);

  const copy = useCallback((t) => {
    navigator.clipboard.writeText(t); setCopied(true); setTimeout(() => setCopied(false), 1800);
  }, []);

  const selectBinary = useCallback((b) => { setSel(b); setTab(0); }, []);

  useEffect(() => {
    const h = (e) => {
      if (e.key === "Escape") {
        if (sel) { setSel(null); setTab(0); inputRef.current?.focus(); }
        else if (mode === "analyze") { setMode("search"); setCmdInput(""); }
        else setQ("");
      }
      if (!sel && mode === "search") {
        if (e.key === "ArrowDown") { e.preventDefault(); setIdx(i => Math.min(i+1, res.length-1)); }
        if (e.key === "ArrowUp")   { e.preventDefault(); setIdx(i => Math.max(i-1, 0)); }
        if (e.key === "Enter" && res[idx]) { e.preventDefault(); selectBinary(res[idx]); }
      }
      if ((e.metaKey||e.ctrlKey) && e.key === "k") { e.preventDefault(); setSel(null); setTab(0); setQ(""); setCmdInput(""); setMode("search"); inputRef.current?.focus(); }
    };
    window.addEventListener("keydown", h); return () => window.removeEventListener("keydown", h);
  }, [sel, res, idx, mode]);

  useEffect(() => {
    if (listRef.current) { const item = listRef.current.children[idx]; if (item) item.scrollIntoView({ block:"nearest" }); }
  }, [idx]);

  const TABS = ["intel", "tips", "mitre", "detect", "closure"];
  const quips = ["ya ndak tau kok tanya saya", "ngetik yang bener wok!", "gak ada wi binary-nya", "gak nemu di database"];
  const quip = quips[Math.abs(q.length) % quips.length];

  return (
    <div style={{ fontFamily:"'JetBrains Mono','Fira Code','Ubuntu Mono',monospace", background:"#2D2D2D", color:"#D3D7CF", minHeight:"100vh", display:"flex", flexDirection:"column" }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600;700&display=swap');
        * { box-sizing:border-box; margin:0; padding:0; }
        ::-webkit-scrollbar { width:5px; } ::-webkit-scrollbar-track { background:#2D2D2D; }
        ::-webkit-scrollbar-thumb { background:#555753; border-radius:2px; }
        ::selection { background:#E95678; color:#1C1C1C; }
        @keyframes quack { 0%,100% { transform:translateY(0) rotate(0deg); } 25% { transform:translateY(-3px) rotate(-6deg); } 75% { transform:translateY(-1px) rotate(4deg); } }
        .duck-bob { animation:quack 2.4s ease-in-out infinite; display:inline-block; cursor:default; }
        .duck-bob:hover { animation:quack 0.5s ease-in-out infinite; }
        .tag-pill { display:inline-block; padding:1px 6px; border-radius:2px; font-size:9px; font-weight:600; letter-spacing:0.04em; border:1px solid; margin-right:4px; margin-top:3px; }
        .os-btn { padding:3px 10px; border-radius:2px; font-size:9px; font-weight:600; letter-spacing:0.06em; cursor:pointer; border:1px solid #3C3C3C; color:#555753; background:transparent; font-family:inherit; transition:all 0.1s; }
        .os-btn:hover { border-color:#E95678; color:#E95678; }
        .os-btn.active { border-color:#E95678; color:#E95678; background:#E9567811; }
        .mode-btn { padding:3px 10px; border-radius:2px; font-size:9px; font-weight:600; letter-spacing:0.06em; cursor:pointer; border:1px solid #3C3C3C; color:#555753; background:transparent; font-family:inherit; }
        .mode-btn.active { border-color:#FAC863; color:#FAC863; background:#FAC86311; }
        .pattern-row { padding:8px 12px; margin-bottom:6px; border-radius:3px; border-left:3px solid; }
        textarea { resize:vertical; }
      `}</style>

      {/* TITLE BAR */}
      <div style={{ background:"#1C1C1C", borderBottom:"1px solid #3C3C3C", padding:"8px 14px", display:"flex", alignItems:"center", justifyContent:"space-between", flexShrink:0 }}>
        <div style={{ display:"flex", flexDirection:"column", gap:1 }}>
          <span style={{ color:"#E95678", fontWeight:700, fontSize:14, letterSpacing:1 }}>yntkts</span>
          <span style={{ color:"#555753", fontSize:7, fontStyle:"italic", letterSpacing:"0.1" }}>(ya ndak tau kok tanya saya)</span>
        </div>
        <div style={{ display:"flex", alignItems:"center", gap:10 }}>
          <span style={{ color:"#555753", fontSize:10 }}>{DB.length} binaries</span>
          <span style={{ color:"#3C3C3C" }}>|</span>
          <span style={{ color:"#555753", fontSize:10 }}>ctrl+k reset</span>
        </div>
      </div>

      <div style={{ flex:1, display:"flex", flexDirection:"column", overflow:"hidden" }}>
        {!sel ? (
          <div style={{ flex:1, display:"flex", flexDirection:"column", overflow:"hidden" }}>

            {/* SEARCH / ANALYZE BAR */}
            <div style={{ borderBottom:"1px solid #3C3C3C", background:"#1C1C1C", padding:"10px 14px", display:"flex", flexDirection:"column", gap:8, flexShrink:0 }}>
              <div style={{ display:"flex", alignItems:"center", gap:8 }}>
                <span className="duck-bob" title="quack">
                  <svg width="22" height="20" viewBox="0 0 22 20" fill="none">
                    <ellipse cx="11" cy="13" rx="8.5" ry="6" fill="#F5C842"/>
                    <ellipse cx="9" cy="14" rx="4" ry="2.2" fill="#E8B830" opacity="0.6"/>
                    <circle cx="16" cy="7.5" r="4.5" fill="#F5C842"/>
                    <circle cx="15" cy="6" r="1.5" fill="#FAD85A" opacity="0.5"/>
                    <circle cx="17.5" cy="6.5" r="1.4" fill="white"/>
                    <circle cx="18" cy="6.5" r="0.7" fill="#1C1C1C"/>
                    <circle cx="18.3" cy="6.1" r="0.25" fill="white"/>
                    <path d="M20.5 8.5 L22 9.5 L20.5 10.5 Z" fill="#E8821A"/>
                    <path d="M20.5 8.5 L22 9 L20.5 9.5 Z" fill="#F4A030"/>
                    <ellipse cx="16.5" cy="8.5" rx="1.2" ry="0.7" fill="#F4907A" opacity="0.5"/>
                    <ellipse cx="11" cy="18.5" rx="7" ry="1" fill="#89DDFF" opacity="0.25"/>
                    <ellipse cx="11" cy="19.2" rx="4.5" ry="0.6" fill="#89DDFF" opacity="0.15"/>
                  </svg>
                </span>

                {mode === "search" ? (
                  <input ref={inputRef} value={q} onChange={e => setQ(e.target.value)}
                    placeholder="ketik nama binary..."
                    style={{ flex:1, background:"transparent", border:"none", outline:"none", color:"#D3D7CF", fontFamily:"inherit", fontSize:13, caretColor:"#E95678" }}
                  />
                ) : (
                  <input ref={inputRef} value={cmdInput} onChange={e => setCmdInput(e.target.value)}
                    placeholder="paste command line... (e.g. powershell.exe -enc ...)"
                    style={{ flex:1, background:"transparent", border:"none", outline:"none", color:"#FAC863", fontFamily:"inherit", fontSize:12, caretColor:"#FAC863" }}
                  />
                )}

                {mode === "search" && q && <span style={{ color:"#555753", fontSize:10 }}>{res.length} found</span>}
                <button className={`mode-btn ${mode === "analyze" ? "active" : ""}`}
                  onClick={() => { setMode(m => m === "search" ? "analyze" : "search"); setTimeout(() => inputRef.current?.focus(), 50); }}>
                  ⚡ analyze
                </button>
              </div>

              {/* OS FILTER + mode hint */}
              <div style={{ display:"flex", alignItems:"center", gap:6 }}>
                {OS_OPTS.map(o => (
                  <button key={o.id || "all"} className={`os-btn ${osFilter === o.id ? "active" : ""}`}
                    onClick={() => setOsFilter(o.id)}>{o.label}</button>
                ))}
                {mode === "analyze" && (
                  <span style={{ marginLeft:8, fontSize:10, color:"#FAC863", fontStyle:"italic" }}>
                    analyze mode — paste cmdline untuk detect suspicious patterns
                  </span>
                )}
              </div>
            </div>

            {/* ANALYZE PANEL */}
            {mode === "analyze" && (
              <div style={{ flex:1, overflow:"auto", padding:16 }}>
                {!cmdInput.trim() && (
                  <div style={{ padding:"36px 20px", textAlign:"center", color:"#555753" }}>
                    <div style={{ fontSize:13, color:"#FAC863", marginBottom:8 }}>⚡ command analyzer</div>
                    <div style={{ fontSize:11, lineHeight:1.8, maxWidth:500, margin:"0 auto" }}>
                      paste full command line — detects suspicious flags, MITRE techniques, dan possible attack scenarios
                    </div>
                    <div style={{ marginTop:16, fontSize:10, color:"#3C3C3C" }}>
                      contoh: <span style={{ color:"#555753" }}>powershell.exe -enc SQBFAFgA...</span>
                    </div>
                  </div>
                )}
                {detection && <DetectionResult d={detection} onSelect={selectBinary} />}
              </div>
            )}

            {/* SEARCH RESULTS */}
            {mode === "search" && (
              <div ref={listRef} style={{ flex:1, overflow:"auto", padding:"2px 0" }}>
                {q && res.length === 0 && (
                  <div style={{ padding:40, textAlign:"center", color:"#555753" }}>
                    <div style={{ fontSize:14, marginBottom:8, color:"#E95678" }}>{quip}</div>
                    <div style={{ fontSize:11 }}>gak nemu "{q}"</div>
                  </div>
                )}
                {!q && (
                  <div style={{ padding:"36px 20px", color:"#555753", textAlign:"center" }}>
                    <div style={{ fontSize:14, marginBottom:6, color:"#E95678", fontWeight:600 }}>
                      ketik nama binary, biar gue yang jawab
                    </div>
                    <div style={{ fontSize:9, lineHeight:0.1, maxWidth:480, fontStyle:"italic", margin:"0 auto" }}>
                      ngetik typo-pun ketemu kok, asal gak totally ngawur! sok atuh mau nyari apa?
                    </div>
                    <div style={{ display:"flex", flexWrap:"wrap", gap:6, justifyContent:"center", marginTop:18 }}>
                      {["lolbin","credential","lateral","persistence","recon","reverse shell","kerberos","defense evasion"].map(t => (
                        <span key={t} onClick={() => { setQ(t); inputRef.current?.focus(); }}
                          style={{ padding:"4px 10px", border:"1px solid #3C3C3C", borderRadius:3, fontSize:10, color:"#7C7C7C", cursor:"pointer" }}
                          onMouseOver={e => { e.target.style.borderColor="#E95678"; e.target.style.color="#E95678"; }}
                          onMouseOut={e => { e.target.style.borderColor="#3C3C3C"; e.target.style.color="#7C7C7C"; }}
                        >{t}</span>
                      ))}
                    </div>
                  </div>
                )}
                {res.map((b, i) => (
                  <div key={b.n+i} onClick={() => selectBinary(b)} onMouseEnter={() => setIdx(i)}
                    style={{
                      display:"flex", alignItems:"flex-start", gap:10, padding:"8px 14px", cursor:"pointer",
                      background: i === idx ? "#323232" : "transparent",
                      borderLeft: i === idx ? "2px solid #E95678" : "2px solid transparent",
                    }}>
                    {/* number */}
                    <span style={{ color:"#555753", fontSize:10, width:22, textAlign:"right", flexShrink:0, marginTop:2 }}>{i+1}</span>
                    {/* name + tags + description */}
                    <div style={{ flex:1, minWidth:0 }}>
                      <div style={{ display:"flex", alignItems:"center", gap:8, flexWrap:"wrap" }}>
                        <span style={{ color:"#D3D7CF", fontWeight:600, fontSize:13 }}>{b.n}</span>
                      </div>
                      <div style={{ marginTop:2 }}>
                        <span className="tag-pill" style={{ color:RC[b.r], borderColor:RC[b.r]+"44" }}>{b.r}</span>
                        <span className="tag-pill" style={{ color:CC[b.c]||"#7C7C7C", borderColor:(CC[b.c]||"#7C7C7C")+"44" }}>{b.c}</span>
                        <span className="tag-pill" style={{ color:"#555753", borderColor:"#3C3C3C" }}>{b.os}</span>
                        {b.t?.slice(0,2).map(t => (
                          <span key={t} className="tag-pill" style={{ color:"#7A7D84", borderColor:"#3C3C3C" }}>{t}</span>
                        ))}
                      </div>
                      <div style={{ color:"#7C7C7C", fontSize:10, fontStyle:"italic", marginTop:3, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>{b.d}</div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        ) : (
          /* ── DETAIL VIEW ── */
          <div style={{ flex:1, display:"flex", flexDirection:"column", overflow:"hidden" }}>
            {/* HEADER */}
            <div style={{ padding:"12px 14px", borderBottom:"1px solid #3C3C3C", background:"#1C1C1C", flexShrink:0 }}>
              <div style={{ display:"flex", alignItems:"center", gap:10, flexWrap:"wrap" }}>
                <span onClick={() => { setSel(null); setTab(0); inputRef.current?.focus(); }}
                  style={{ color:"#E95678", cursor:"pointer", fontSize:12, fontWeight:600 }}>← back</span>
                <span style={{ color:"#D3D7CF", fontWeight:700, fontSize:15 }}>{sel.n}</span>
                <span style={{ color:RC[sel.r], fontSize:10, fontWeight:700, padding:"1px 7px", border:`1px solid ${RC[sel.r]}`, borderRadius:2 }}>{sel.r}</span>
                <span style={{ color:CC[sel.c], fontSize:10 }}>{sel.c}</span>
                {sel.t?.map(t => (
                  <span key={t} style={{ color:"#555753", fontSize:9, padding:"1px 5px", border:"1px solid #3C3C3C", borderRadius:2 }}>{t}</span>
                ))}
                <span style={{ color:"#555753", fontSize:10, marginLeft:"auto" }}>{sel.os}</span>
              </div>
              <div style={{ color:"#555753", fontSize:10, marginTop:3, fontStyle:"italic" }}>{sel.p}</div>
            </div>

            {/* TABS */}
            <div style={{ display:"flex", borderBottom:"1px solid #3C3C3C", background:"#252525", flexShrink:0, overflow:"auto" }}>
              {TABS.map((t, i) => (
                <div key={t} onClick={() => setTab(i)} style={{
                  padding:"8px 14px", fontSize:11, cursor:"pointer",
                  color: tab === i ? "#E95678" : "#7C7C7C",
                  borderBottom: tab === i ? "2px solid #E95678" : "2px solid transparent",
                  fontWeight: tab === i ? 600 : 400, whiteSpace:"nowrap",
                }}>{t}</div>
              ))}
            </div>

            {/* TAB CONTENT */}
            <div style={{ flex:1, overflow:"auto", padding:16 }}>
              {tab === 0 && (
                <div>
                  {/* QUICK TAKE */}
                  {sel.tldr && (
                    <div style={{ marginBottom:20, padding:"12px 14px", background:"#1C1C1C", borderLeft:`3px solid ${RC[sel.r]}`, borderRadius:"0 4px 4px 0" }}>
                      <div style={{ fontSize:9, fontWeight:700, letterSpacing:"0.1em", color:RC[sel.r], marginBottom:6, textTransform:"uppercase" }}>quick take</div>
                      <div style={{ fontSize:12.5, lineHeight:1.75, color:"#D3D7CF" }}>
                        <CrossRef text={sel.tldr} onSelect={selectBinary} />
                      </div>
                    </div>
                  )}

                  {/* ATTACK CHAIN */}
                  {sel.chain && (
                    <div style={{ marginBottom:20 }}>
                      <div style={{ fontSize:9, fontWeight:700, letterSpacing:"0.08em", color:"#FAC863", marginBottom:8, paddingBottom:6, borderBottom:"1px solid #333", textTransform:"uppercase" }}>attack chain</div>
                      <div style={{ fontSize:10, color:"#555753", marginBottom:6 }}>typical stage: <span style={{ color:"#FAC863" }}>{sel.chain.stage}</span></div>
                      {sel.chain.flows?.map((f, i) => (
                        <div key={i} style={{ padding:"6px 10px", marginBottom:4, background:"#1C1C1C", borderRadius:3, border:"1px solid #3C3C3C", fontSize:11, color:"#7C7C7C" }}>
                          <ChainFlow text={f} onSelect={selectBinary} />
                        </div>
                      ))}
                    </div>
                  )}

                  <Sec t="abuse potential" c="#E95678">
                    <P><CrossRef text={sel.abuse} onSelect={selectBinary} /></P>
                  </Sec>
                  <Sec t="red team usage" c="#B877DB">
                    <P><CrossRef text={typeof sel.red === "object" ? sel.red.desc : sel.red} onSelect={selectBinary} /></P>
                    {typeof sel.red === "object" && sel.red.cmds?.length > 0 && (
                      <div style={{ marginTop:10 }}>
                        {sel.red.cmds.map((cmd, i) => (
                          <div key={i} style={{ marginBottom:8 }}>
                            <pre style={{ fontSize:11, lineHeight:1.5, color:"#FAB795", whiteSpace:"pre-wrap", wordBreak:"break-all", padding:"8px 12px", background:"#1C1C1C", border:"1px solid #3C3C3C", borderRadius:3, margin:0 }}>{cmd.c}</pre>
                            {cmd.n && <div style={{ fontSize:10, color:"#7C7C7C", marginTop:3, paddingLeft:4 }}>{cmd.n}</div>}
                          </div>
                        ))}
                      </div>
                    )}
                  </Sec>
                  <Sec t="known legitimate use" c="#A8CC8C">
                    <P><CrossRef text={sel.legit} onSelect={selectBinary} /></P>
                  </Sec>
                </div>
              )}

              {tab === 1 && (
                <div>
                  <div style={{ color:"#E95678", fontSize:11, fontWeight:600, marginBottom:14 }}>INVESTIGATION CHECKLIST — {sel.n}</div>
                  {sel.tips.map((tip, i) => (
                    <div key={i} style={{ display:"flex", gap:10, padding:"8px 0", borderBottom:"1px solid #333" }}>
                      <span style={{ color:"#E95678", fontSize:11, fontWeight:600, minWidth:20, textAlign:"right" }}>{String(i+1).padStart(2,"0")}</span>
                      <span style={{ color:"#D3D7CF", fontSize:12, lineHeight:1.65 }}>
                        <CrossRef text={tip} onSelect={selectBinary} />
                      </span>
                    </div>
                  ))}
                </div>
              )}

              {tab === 2 && (
                <div>
                  <Sec t="mitre att&ck" c="#FAC863">
                    {sel.m.map((m, i) => (
                      <div key={m} style={{ padding:"10px 12px", marginBottom:8, background:"#252525", borderRadius:4, border:"1px solid #3C3C3C" }}>
                        <div style={{ display:"flex", gap:8, alignItems:"center", marginBottom:4 }}>
                          <span style={{ color:"#FAC863", fontSize:11, fontWeight:600 }}>{m}</span>
                          <span style={{ color:"#D3D7CF", fontSize:12 }}>{sel.mn[i]}</span>
                        </div>
                        <div style={{ color:"#7C7C7C", fontSize:11 }}>Tactic: {sel.t.join(", ")}</div>
                      </div>
                    ))}
                  </Sec>
                  <Sec t="references" c="#89DDFF">
                    {sel.ref.map(r => (
                      <div key={r} style={{ fontSize:11, marginBottom:4 }}>
                        <a href={r} target="_blank" rel="noopener noreferrer" style={{ color:"#89DDFF", textDecoration:"none" }}>{r}</a>
                      </div>
                    ))}
                  </Sec>
                </div>
              )}

              {tab === 3 && (
                <div>
                  <Sec t="detection guidance" c="#A8CC8C">
                    <P><CrossRef text={sel.detect} onSelect={selectBinary} /></P>
                  </Sec>
                </div>
              )}

              {tab === 4 && (
                <div>
                  <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:12 }}>
                    <span style={{ color:"#E95678", fontSize:11, fontWeight:600 }}>CLOSURE TEMPLATE — {sel.n}</span>
                    <span onClick={() => copy(genClosureTemplate(sel))} style={{
                      padding:"4px 12px", border:"1px solid #3C3C3C", borderRadius:3, fontSize:10,
                      color: copied ? "#A8CC8C" : "#E95678", cursor:"pointer",
                    }}>{copied ? "copied!" : "copy"}</span>
                  </div>
                  <pre style={{ fontSize:11, lineHeight:1.6, color:"#7C7C7C", whiteSpace:"pre-wrap", padding:14, background:"#1C1C1C", border:"1px solid #3C3C3C", borderRadius:4, maxHeight:350, overflow:"auto" }}>
                    {genClosureTemplate(sel)}
                  </pre>
                  <div style={{ marginTop:12, fontSize:10, color:"#7C7C7C", padding:"8px 12px", background:"#252525", borderRadius:4, border:"1px solid #3C3C3C" }}>
                    replace <span style={{ color:"#E95678" }}>[BRACKETS]</span> → paste ke Notion
                  </div>
                </div>
              )}
            </div>

            {/* STATUS BAR */}
            <div style={{ borderTop:"1px solid #3C3C3C", background:"#1C1C1C", padding:"6px 14px", display:"flex", alignItems:"center", gap:10, flexShrink:0 }}>
              <span style={{ color:"#555753", fontSize:10 }}>esc back</span>
              <span style={{ color:"#3C3C3C" }}>|</span>
              <span style={{ color:"#7C7C7C", fontSize:10 }}>{sel.m.join(" ")} — {sel.t.join(", ")}</span>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ─── attack chain flow renderer ──────────────────────────────
function ChainFlow({ text, onSelect }) {
  const parts = text.split("→").map(p => p.trim());
  return (
    <span>
      {parts.map((p, i) => {
        const bin = BINARY_MAP[p.toLowerCase()];
        return (
          <span key={i}>
            {i > 0 && <span style={{ color:"#3C3C3C", margin:"0 6px" }}>→</span>}
            {bin
              ? <span onClick={() => onSelect(bin)} style={{ color:"#89DDFF", cursor:"pointer" }}>{p}</span>
              : <span style={{ color:"#D3D7CF" }}>{p}</span>
            }
          </span>
        );
      })}
    </span>
  );
}

// ─── detection result panel ──────────────────────────────────
const SEV_ORDER = { CRITICAL:0, HIGH:1, MEDIUM:2, LOW:3 };
function DetectionResult({ d, onSelect }) {
  const sorted = [...d.patterns].sort((a, b) => (SEV_ORDER[a.sev]||9) - (SEV_ORDER[b.sev]||9));
  return (
    <div>
      {/* HEADER */}
      <div style={{ marginBottom:16, padding:"12px 14px", background:"#1C1C1C", borderLeft:`3px solid ${SV[d.overallSev]||"#555753"}`, borderRadius:"0 4px 4px 0" }}>
        <div style={{ display:"flex", alignItems:"center", gap:10, marginBottom:6 }}>
          {d.clean
            ? <span style={{ color:"#A8CC8C", fontSize:12, fontWeight:600 }}>✓ no suspicious patterns detected</span>
            : <span style={{ color:SV[d.overallSev], fontSize:12, fontWeight:600 }}>⚠ {d.patterns.length} suspicious pattern{d.patterns.length > 1 ? "s" : ""} detected</span>
          }
          {d.overallSev && !d.clean && (
            <span style={{ color:SV[d.overallSev], fontSize:10, fontWeight:700, padding:"1px 7px", border:`1px solid ${SV[d.overallSev]}`, borderRadius:2 }}>{d.overallSev}</span>
          )}
        </div>
        {d.binary ? (
          <span style={{ fontSize:11, color:"#555753" }}>
            binary: <span onClick={() => onSelect(d.binary)} style={{ color:"#89DDFF", cursor:"pointer", fontWeight:600 }}>{d.binary.n}</span>
            <span style={{ color:"#3C3C3C", margin:"0 6px" }}>·</span>
            <span style={{ color:RC[d.binary.r] }}>{d.binary.r}</span>
            <span style={{ color:"#3C3C3C", margin:"0 6px" }}>·</span>
            <span style={{ color:CC[d.binary.c]||"#7C7C7C" }}>{d.binary.c}</span>
          </span>
        ) : (
          <span style={{ fontSize:11, color:"#555753" }}>binary <span style={{ color:"#E95678" }}>"{d.rawToken}"</span> tidak ada di database</span>
        )}
        {d.mitres.length > 0 && (
          <div style={{ marginTop:8, display:"flex", flexWrap:"wrap", gap:4 }}>
            {d.mitres.map(m => (
              <span key={m} style={{ fontSize:10, color:"#FAC863", padding:"1px 6px", border:"1px solid #FAC86344", borderRadius:2 }}>{m}</span>
            ))}
          </div>
        )}
      </div>

      {/* PATTERNS */}
      {sorted.map((p, i) => (
        <div key={i} className="pattern-row" style={{ borderLeftColor:SV[p.sev]||"#555753", background:"#1C1C1C22" }}>
          <div style={{ display:"flex", alignItems:"center", gap:8, marginBottom:4 }}>
            <span style={{ color:SV[p.sev], fontSize:10, fontWeight:700, padding:"1px 5px", border:`1px solid ${SV[p.sev]}44`, borderRadius:2 }}>{p.sev}</span>
            <span style={{ color:"#D3D7CF", fontSize:11, fontWeight:600 }}>{p.name}</span>
            {p.mitre && <span style={{ color:"#FAC863", fontSize:10, marginLeft:"auto" }}>{p.mitre}</span>}
          </div>
          <div style={{ marginTop:6 }}>
            <div style={{ fontSize:9, color:"#555753", marginBottom:4, textTransform:"uppercase", letterSpacing:"0.06em" }}>possible scenarios</div>
            {p.scenarios?.map((s, si) => (
              <div key={si} style={{ display:"flex", gap:6, marginBottom:2 }}>
                <span style={{ color:"#3C3C3C", fontSize:10 }}>–</span>
                <span style={{ fontSize:11, color:"#7C7C7C", lineHeight:1.5 }}>{s}</span>
              </div>
            ))}
          </div>
        </div>
      ))}

      {/* LINK TO BINARY */}
      {d.binary && (
        <div style={{ marginTop:12, padding:"8px 12px", background:"#252525", borderRadius:3, border:"1px solid #3C3C3C", fontSize:10, color:"#555753" }}>
          lihat intel lengkap →{" "}
          <span onClick={() => onSelect(d.binary)} style={{ color:"#89DDFF", cursor:"pointer" }}>{d.binary.n}</span>
        </div>
      )}
    </div>
  );
}

// ─── helpers ─────────────────────────────────────────────────
function Sec({ t, c, children }) {
  return (
    <div style={{ marginBottom:22 }}>
      <div style={{ fontSize:9, fontWeight:700, textTransform:"uppercase", letterSpacing:"0.08em", color:c||"#7C7C7C", marginBottom:8, paddingBottom:6, borderBottom:"1px solid #333" }}>{t}</div>
      {children}
    </div>
  );
}
function P({ children }) {
  return <div style={{ fontSize:12, lineHeight:1.7, color:"#D3D7CF" }}>{children}</div>;
}
