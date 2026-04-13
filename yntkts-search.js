// yntkts search engine — strict, typo-tolerant

function lev(a,b){const m=a.length,n=b.length;if(!m)return n;if(!n)return m;const d=Array.from({length:m+1},()=>Array(n+1).fill(0));for(let i=0;i<=m;i++)d[i][0]=i;for(let j=0;j<=n;j++)d[0][j]=j;for(let i=1;i<=m;i++)for(let j=1;j<=n;j++)d[i][j]=a[i-1]===b[j-1]?d[i-1][j-1]:1+Math.min(d[i-1][j],d[i][j-1],d[i-1][j-1]);return d[m][n];}

function skel(s){return s.replace(/[aeiou.]/gi,'').replace(/(.)\1+/g,'$1');}

function nameScore(q, name) {
  const ql = q.toLowerCase().replace(/\.exe$/,'').replace(/\.dll$/,'');
  const nl = name.toLowerCase().replace(/\.exe$/,'').replace(/\.dll$/,'');
  if(!ql) return 0;
  if(nl === ql) return 10000;
  if(nl.startsWith(ql)) return 9000 + (ql.length/nl.length)*1000;
  if(nl.includes(ql)) return 8000;
  const qs = skel(ql), ns = skel(nl);
  if(qs.length >= 2 && ns === qs) return 7500;
  if(qs.length >= 2 && ns.startsWith(qs)) return 7000;
  if(qs.length >= 2 && ns.includes(qs)) return 6500;
  const dist = lev(ql, nl);
  const ratio = 1 - dist / Math.max(ql.length, nl.length);
  if(ratio > 0.6) return ratio * 6000;
  if(qs.length >= 2 && ns.length >= 2) {
    const sd = lev(qs, ns), sr = 1 - sd / Math.max(qs.length, ns.length);
    if(sr > 0.55) return sr * 5000;
  }
  let qi = 0;
  for(let ti = 0; ti < nl.length && qi < ql.length; ti++) { if(nl[ti] === ql[qi]) qi++; }
  if(qi === ql.length) return 4000 + (ql.length/nl.length)*1000;
  return 0;
}

function contentScore(q, bin) {
  const ql = q.toLowerCase();
  const all = [bin.d, bin.abuse, bin.red, bin.c, bin.t.join(' '), bin.m.join(' '), bin.mn.join(' ')].join(' ').toLowerCase();
  if(all.includes(ql)) return 2000;
  const tokens = ql.split(/[\s._-]+/).filter(Boolean);
  let hits = 0;
  for(const tok of tokens) if(all.includes(tok)) hits++;
  return hits > 0 ? (hits/tokens.length)*1500 : 0;
}

export function searchBinaries(db, query) {
  if(!query.trim()) return [];
  const results = [];
  for(const b of db) {
    const ns = nameScore(query, b.n);
    const cs = contentScore(query, b);
    const best = Math.max(ns, cs);
    if(best > 0) results.push({...b, _s: best, _nh: ns > cs});
  }
  results.sort((a,b) => b._s - a._s);
  // STRICT: if top is strong name match, filter aggressively
  if(results.length > 0 && results[0]._s >= 6000 && results[0]._nh) {
    const th = results[0]._s * 0.3;
    return results.filter(r => r._s >= th);
  }
  return results.filter(r => r._s > 500);
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

MITRE ATT&CK: ${b.m.map((x,i) => `${x} - ${b.mn[i]}`).join(', ')}
Tactic: ${b.t.join(', ')}.

[TAMBAHKAN NARASI INVESTIGASI]

**Conclusion:**
[TINDAKAN REKOMENDASI]

Ticket ditutup sebagai [True Positive / False Positive / Benign Positive] - [KLASIFIKASI].`;
}
