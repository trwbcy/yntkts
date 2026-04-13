import { useState, useEffect, useRef, useMemo, useCallback } from "react";
import DB from "./db.js";
import { searchBinaries, genClosureTemplate } from "./search.js";

const RC = {CRITICAL:"#E95678",HIGH:"#FAB795",MEDIUM:"#89DDFF",LOW:"#A8CC8C"};
const CC = {lolbin:"#E95678",system:"#7A7D84",critical:"#B877DB",offensive:"#E95678",
  utility:"#89DDFF",tool:"#FAC863",interpreter:"#FAB795",shell:"#A8CC8C"};

export default function YNTKTS() {
  const [q, setQ] = useState("");
  const [sel, setSel] = useState(null);
  const [idx, setIdx] = useState(0);
  const [tab, setTab] = useState(0);
  const [copied, setCopied] = useState(false);
  const inputRef = useRef(null);
  const listRef = useRef(null);
  const res = useMemo(() => searchBinaries(DB, q), [q]);

  useEffect(() => { inputRef.current?.focus(); }, []);
  useEffect(() => { setIdx(0); setSel(null); }, [q]);

  const copy = useCallback((t) => {
    navigator.clipboard.writeText(t); setCopied(true); setTimeout(() => setCopied(false), 1800);
  }, []);

  useEffect(() => {
    const h = (e) => {
      if (e.key === "Escape") { if (sel) { setSel(null); setTab(0); inputRef.current?.focus(); } else setQ(""); }
      if (e.key === "ArrowDown" && !sel) { e.preventDefault(); setIdx(i => Math.min(i+1, res.length-1)); }
      if (e.key === "ArrowUp" && !sel) { e.preventDefault(); setIdx(i => Math.max(i-1, 0)); }
      if (e.key === "Enter" && !sel && res[idx]) { e.preventDefault(); setSel(res[idx]); setTab(0); }
      if ((e.metaKey||e.ctrlKey) && e.key === "k") { e.preventDefault(); setSel(null); setTab(0); setQ(""); inputRef.current?.focus(); }
    };
    window.addEventListener("keydown", h); return () => window.removeEventListener("keydown", h);
  }, [sel, res, idx]);

  useEffect(() => {
    if (listRef.current) { const item = listRef.current.children[idx]; if (item) item.scrollIntoView({ block: "nearest" }); }
  }, [idx]);

  const TABS = ["intel", "tips", "mitre", "detect", "closure"];
  const quips = ["ya ndak tau kok tanya saya", "binary apa tuh? gak kenal", "coba ketik yang bener dong", "gak ada di database bro"];
  const quip = quips[Math.abs(q.length) % quips.length];

  return (
    <div style={{ fontFamily: "'JetBrains Mono','Fira Code','Ubuntu Mono',monospace", background: "#2D2D2D", color: "#D3D7CF", minHeight: "100vh", display: "flex", flexDirection: "column" }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600;700&display=swap');
        * { box-sizing: border-box; margin: 0; padding: 0; }
        ::-webkit-scrollbar { width: 5px; } ::-webkit-scrollbar-track { background: #2D2D2D; }
        ::-webkit-scrollbar-thumb { background: #555753; border-radius: 2px; }
        ::selection { background: #E95678; color: #1C1C1C; }
      `}</style>

      {/* TITLE BAR — no bullet dots, italic tagline */}
      <div style={{ background: "#1C1C1C", borderBottom: "1px solid #3C3C3C", padding: "8px 14px", display: "flex", alignItems: "baseline", justifyContent: "space-between", flexShrink: 0 }}>
        <div style={{ display: "flex", alignItems: "baseline", gap: 8 }}>
          <span style={{ color: "#E95678", fontWeight: 700, fontSize: 14, letterSpacing: 1 }}>yntkts</span>
          <span style={{ color: "#555753", fontSize: 11, fontStyle: "italic" }}>ya ndak tau kok tanya saya</span>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <span style={{ color: "#555753", fontSize: 10 }}>{DB.length} binaries</span>
          <span style={{ color: "#3C3C3C" }}>|</span>
          <span style={{ color: "#555753", fontSize: 10 }}>ctrl+k reset</span>
        </div>
      </div>

      <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>
        {!sel ? (
          <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>
            {/* SEARCH BAR — TOP, duck emoji */}
            <div style={{ borderBottom: "1px solid #3C3C3C", background: "#1C1C1C", padding: "10px 14px", display: "flex", alignItems: "center", gap: 8, flexShrink: 0 }}>
              <span style={{ fontSize: 15 }}>🦆</span>
              <input ref={inputRef} value={q} onChange={e => setQ(e.target.value)}
                placeholder="ketik nama binary..."
                style={{ flex: 1, background: "transparent", border: "none", outline: "none", color: "#D3D7CF", fontFamily: "inherit", fontSize: 13, caretColor: "#E95678" }}
              />
              {q && <span style={{ color: "#555753", fontSize: 10 }}>{res.length} found</span>}
              <span style={{ color: "#3C3C3C", fontSize: 10 }}>
                <span style={{ color: "#555753" }}>↑↓</span> nav <span style={{ color: "#555753" }}>⏎</span> select
              </span>
            </div>

            {/* RESULTS */}
            <div ref={listRef} style={{ flex: 1, overflow: "auto", padding: "2px 0" }}>
              {q && res.length === 0 && (
                <div style={{ padding: 40, textAlign: "center", color: "#555753" }}>
                  <div style={{ fontSize: 14, marginBottom: 8, color: "#E95678" }}>{quip}</div>
                  <div style={{ fontSize: 11 }}>gak nemu "{q}"</div>
                </div>
              )}
              {!q && (
                <div style={{ padding: "36px 20px", color: "#555753", textAlign: "center" }}>
                  <div style={{ fontSize: 14, marginBottom: 6, color: "#E95678", fontWeight: 600 }}>
                    ketik nama binary, biar gue yang jawab
                  </div>
                  <div style={{ fontSize: 11, lineHeight: 1.8, maxWidth: 480, margin: "0 auto" }}>
                    fuzzy search — "pwershle" nemu powershell, "mimkatz" nemu mimikatz
                  </div>
                  <div style={{ display: "flex", flexWrap: "wrap", gap: 6, justifyContent: "center", marginTop: 18 }}>
                    {["lolbin","credential","lateral","persistence","recon","reverse shell","kerberos","defense evasion"].map(t => (
                      <span key={t} onClick={() => { setQ(t); inputRef.current?.focus(); }}
                        style={{ padding: "4px 10px", border: "1px solid #3C3C3C", borderRadius: 3, fontSize: 10, color: "#7C7C7C", cursor: "pointer" }}
                        onMouseOver={e => { e.target.style.borderColor = "#E95678"; e.target.style.color = "#E95678"; }}
                        onMouseOut={e => { e.target.style.borderColor = "#3C3C3C"; e.target.style.color = "#7C7C7C"; }}
                      >{t}</span>
                    ))}
                  </div>
                </div>
              )}
              {res.map((b, i) => (
                <div key={b.n+i} onClick={() => { setSel(b); setTab(0); }} onMouseEnter={() => setIdx(i)}
                  style={{
                    display: "flex", alignItems: "center", gap: 10, padding: "7px 14px", cursor: "pointer",
                    background: i === idx ? "#3C3C3C" : "transparent",
                    borderLeft: i === idx ? "2px solid #E95678" : "2px solid transparent",
                  }}>
                  <span style={{ color: "#555753", fontSize: 10, width: 22, textAlign: "right", flexShrink: 0 }}>{i+1}</span>
                  <span style={{ color: "#D3D7CF", fontWeight: 500, fontSize: 13 }}>{b.n}</span>
                  <span style={{ color: RC[b.r], fontSize: 10, fontWeight: 600, flexShrink: 0, padding: "0 5px", border: `1px solid ${RC[b.r]}44`, borderRadius: 2 }}>{b.r}</span>
                  <span style={{ color: CC[b.c] || "#7C7C7C", fontSize: 10, flexShrink: 0 }}>{b.c}</span>
                  <span style={{ color: "#7C7C7C", fontSize: 10, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", flex: 1 }}>{b.d}</span>
                  <span style={{ color: "#3C3C3C", fontSize: 10, flexShrink: 0 }}>{b.os}</span>
                </div>
              ))}
            </div>
          </div>
        ) : (
          /* DETAIL VIEW */
          <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>
            <div style={{ padding: "12px 14px", borderBottom: "1px solid #3C3C3C", background: "#1C1C1C", flexShrink: 0 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
                <span onClick={() => { setSel(null); setTab(0); inputRef.current?.focus(); }}
                  style={{ color: "#E95678", cursor: "pointer", fontSize: 12, fontWeight: 600 }}>← back</span>
                <span style={{ color: "#D3D7CF", fontWeight: 700, fontSize: 16 }}>{sel.n}</span>
                <span style={{ color: RC[sel.r], fontSize: 10, fontWeight: 700, padding: "1px 7px", border: `1px solid ${RC[sel.r]}`, borderRadius: 2 }}>{sel.r}</span>
                <span style={{ color: CC[sel.c], fontSize: 10 }}>{sel.c}</span>
                <span style={{ color: "#555753", fontSize: 10, marginLeft: "auto" }}>{sel.os}</span>
              </div>
              <div style={{ color: "#7C7C7C", fontSize: 11, marginTop: 4 }}>{sel.p}</div>
            </div>

            <div style={{ display: "flex", borderBottom: "1px solid #3C3C3C", background: "#252525", flexShrink: 0, overflow: "auto" }}>
              {TABS.map((t, i) => (
                <div key={t} onClick={() => setTab(i)} style={{
                  padding: "8px 14px", fontSize: 11, cursor: "pointer",
                  color: tab === i ? "#E95678" : "#7C7C7C",
                  borderBottom: tab === i ? "2px solid #E95678" : "2px solid transparent",
                  fontWeight: tab === i ? 600 : 400, whiteSpace: "nowrap",
                }}>{t}</div>
              ))}
            </div>

            <div style={{ flex: 1, overflow: "auto", padding: 16 }}>
              {tab === 0 && (<div>
                <Sec t="abuse potential" c="#E95678"><P>{sel.abuse}</P></Sec>
                <Sec t="red team usage" c="#B877DB"><P>{sel.red}</P></Sec>
                <Sec t="known legitimate use" c="#A8CC8C"><P>{sel.legit}</P></Sec>
              </div>)}
              {tab === 1 && (<div>
                <div style={{ color: "#E95678", fontSize: 11, fontWeight: 600, marginBottom: 14 }}>INVESTIGATION CHECKLIST — {sel.n}</div>
                {sel.tips.map((tip, i) => (
                  <div key={i} style={{ display: "flex", gap: 10, padding: "8px 0", borderBottom: "1px solid #333" }}>
                    <span style={{ color: "#E95678", fontSize: 11, fontWeight: 600, minWidth: 20, textAlign: "right" }}>{String(i+1).padStart(2, "0")}</span>
                    <span style={{ color: "#D3D7CF", fontSize: 12, lineHeight: 1.65 }}>{tip}</span>
                  </div>
                ))}
              </div>)}
              {tab === 2 && (<div>
                <Sec t="mitre att&ck" c="#FAC863">
                  {sel.m.map((m, i) => (
                    <div key={m} style={{ padding: "10px 12px", marginBottom: 8, background: "#252525", borderRadius: 4, border: "1px solid #3C3C3C" }}>
                      <div style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 4 }}>
                        <span style={{ color: "#FAC863", fontSize: 11, fontWeight: 600 }}>{m}</span>
                        <span style={{ color: "#D3D7CF", fontSize: 12 }}>{sel.mn[i]}</span>
                      </div>
                      <div style={{ color: "#7C7C7C", fontSize: 11 }}>Tactic: {sel.t.join(", ")}</div>
                    </div>
                  ))}
                </Sec>
                <Sec t="references" c="#89DDFF">
                  {sel.ref.map(r => (<div key={r} style={{ fontSize: 11, marginBottom: 4 }}><a href={r} target="_blank" rel="noopener noreferrer" style={{ color: "#89DDFF", textDecoration: "none" }}>{r}</a></div>))}
                </Sec>
              </div>)}
              {tab === 3 && (<div><Sec t="detection guidance" c="#A8CC8C"><P>{sel.detect}</P></Sec></div>)}
              {tab === 4 && (<div>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
                  <span style={{ color: "#E95678", fontSize: 11, fontWeight: 600 }}>CLOSURE TEMPLATE — {sel.n}</span>
                  <span onClick={() => copy(genClosureTemplate(sel))} style={{
                    padding: "4px 12px", border: "1px solid #3C3C3C", borderRadius: 3, fontSize: 10,
                    color: copied ? "#A8CC8C" : "#E95678", cursor: "pointer",
                  }}>{copied ? "copied!" : "copy"}</span>
                </div>
                <pre style={{ fontSize: 11, lineHeight: 1.6, color: "#7C7C7C", whiteSpace: "pre-wrap", padding: 14, background: "#1C1C1C", border: "1px solid #3C3C3C", borderRadius: 4, maxHeight: 350, overflow: "auto" }}>
                  {genClosureTemplate(sel)}
                </pre>
                <div style={{ marginTop: 12, fontSize: 10, color: "#7C7C7C", padding: "8px 12px", background: "#252525", borderRadius: 4, border: "1px solid #3C3C3C" }}>
                  replace <span style={{ color: "#E95678" }}>[BRACKETS]</span> → paste ke Notion
                </div>
              </div>)}
            </div>

            <div style={{ borderTop: "1px solid #3C3C3C", background: "#1C1C1C", padding: "6px 14px", display: "flex", alignItems: "center", gap: 10, flexShrink: 0 }}>
              <span style={{ color: "#555753", fontSize: 10 }}>esc back</span>
              <span style={{ color: "#3C3C3C" }}>|</span>
              <span style={{ color: "#7C7C7C", fontSize: 10 }}>{sel.m.join(" ")} — {sel.t.join(", ")}</span>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function Sec({ t, c, children }) {
  return (<div style={{ marginBottom: 22 }}>
    <div style={{ fontSize: 10, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.08em", color: c || "#7C7C7C", marginBottom: 8, paddingBottom: 6, borderBottom: "1px solid #333" }}>{t}</div>
    {children}
  </div>);
}
function P({ children }) { return <div style={{ fontSize: 12, lineHeight: 1.7, color: "#D3D7CF" }}>{children}</div>; }
