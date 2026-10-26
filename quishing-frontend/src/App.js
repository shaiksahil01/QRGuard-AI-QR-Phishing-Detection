import React, { useState, useRef, useCallback, useEffect } from 'react';
import axios from 'axios';

const getAPI = () => {
  const h = window.location.hostname;
  return (h === 'localhost' || h === '127.0.0.1')
    ? 'http://127.0.0.1:5000'
    : `http://${h}:5000`;
};
const API = getAPI();

function MatrixBg() {
  const ref = useRef(null);
  useEffect(() => {
    const canvas = ref.current;
    const ctx = canvas.getContext('2d');
    let w = canvas.width = window.innerWidth;
    let h = canvas.height = window.innerHeight;
    const cols = Math.floor(w / 20);
    const drops = Array(cols).fill(1);
    const chars = '01';
    let frame;
    const draw = () => {
      ctx.fillStyle = 'rgba(2,8,20,0.05)'; ctx.fillRect(0, 0, w, h);
      ctx.font = '13px monospace';
      drops.forEach((y, i) => {
        ctx.fillStyle = `rgba(0,255,170,${Math.random() > 0.9 ? 1 : 0.13})`;
        ctx.fillText(chars[Math.floor(Math.random() * chars.length)], i * 20, y * 20);
        if (y * 20 > h && Math.random() > 0.975) drops[i] = 0;
        drops[i]++;
      });
      frame = requestAnimationFrame(draw);
    };
    draw();
    const onResize = () => { w = canvas.width = window.innerWidth; h = canvas.height = window.innerHeight; };
    window.addEventListener('resize', onResize);
    return () => { cancelAnimationFrame(frame); window.removeEventListener('resize', onResize); };
  }, []);
  return <canvas ref={ref} style={{ position:'fixed', inset:0, zIndex:0, opacity:0.28, pointerEvents:'none' }} />;
}

function Gauge({ pct, isPhishing }) {
  const r = 52, circ = 2 * Math.PI * r, dash = (pct / 100) * circ;
  const color = isPhishing ? (pct > 75 ? '#ff3b3b' : pct > 55 ? '#ff7700' : '#ffaa00') : '#00ffaa';
  return (
    <svg width="130" height="130" viewBox="0 0 130 130">
      <circle cx="65" cy="65" r={r} fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="10"/>
      <circle cx="65" cy="65" r={r} fill="none" stroke={color} strokeWidth="10"
        strokeDasharray={`${dash} ${circ}`} strokeLinecap="round" transform="rotate(-90 65 65)"
        style={{ transition:'stroke-dasharray 1.4s cubic-bezier(.4,0,.2,1)', filter:`drop-shadow(0 0 8px ${color})` }}/>
      <text x="65" y="61" textAnchor="middle" fill={color} style={{ fontSize:22, fontWeight:700, fontFamily:'monospace' }}>{pct}%</text>
      <text x="65" y="78" textAnchor="middle" fill="rgba(255,255,255,0.35)" style={{ fontSize:10, fontFamily:'monospace', letterSpacing:1 }}>RISK</text>
    </svg>
  );
}

function Badge({ label, value, danger }) {
  const on = value === 1 || value === true;
  const col = danger ? (on ? '#ff3b3b' : '#00ffaa') : (on ? '#00ffaa' : 'rgba(255,255,255,0.2)');
  return (
    <div style={{ display:'flex', alignItems:'center', gap:6, padding:'6px 12px', borderRadius:20, border:`1px solid ${col}22`, background: on ? `${col}18` : 'rgba(255,255,255,0.03)', fontSize:13, color: on ? col : 'rgba(255,255,255,0.28)', fontFamily:'monospace', whiteSpace:'nowrap' }}>
      <span style={{ width:7, height:7, borderRadius:'50%', background:col, boxShadow: on ? `0 0 6px ${col}` : 'none', flexShrink:0 }}/>{label}
    </div>
  );
}

function LiveRow({ label, data }) {
  if (!data) return null;
  const flagged = data.flagged;
  const col = flagged === true ? '#ff4444' : flagged === false ? '#00ffaa' : '#555';
  return (
    <div style={{ display:'flex', justifyContent:'space-between', alignItems:'flex-start', padding:'9px 12px', borderRadius:8, background:`${col}0d`, border:`1px solid ${col}22` }}>
      <div>
        <div style={{ fontSize:13, color:col, fontWeight:700 }}>{flagged===true?'⚠':flagged===false?'✓':'—'}  {label}</div>
        <div style={{ fontSize:12, color:'rgba(255,255,255,0.3)', marginTop:2 }}>{data.detail}</div>
        {data.total_engines > 0 && <div style={{ fontSize:11, color:'rgba(255,255,255,0.2)', marginTop:1 }}>{data.malicious} malicious · {data.suspicious_count} suspicious / {data.total_engines} engines</div>}
      </div>
      <span style={{ fontSize:11, color:col, background:`${col}22`, padding:'4px 10px', borderRadius:20, fontFamily:'monospace', letterSpacing:1, whiteSpace:'nowrap', alignSelf:'center', flexShrink:0, marginLeft:10 }}>
        {flagged===true?'FLAGGED':flagged===false?'CLEAN':'N/A'}
      </span>
    </div>
  );
}

function qrTypeInfo(url) {
  if (!url) return { icon:'❓', label:'Unknown', color:'#888' };
  const u = url.toLowerCase();
  if (u.startsWith('upi://')) return { icon:'💳', label:'Payment QR', color:'#f59e0b' };
  if (u.includes('maps.google')||u.includes('geo:')) return { icon:'📍', label:'Maps QR', color:'#3b82f6' };
  if (u.startsWith('mailto:')) return { icon:'📧', label:'Email QR', color:'#8b5cf6' };
  if (u.startsWith('tel:')) return { icon:'📱', label:'Phone QR', color:'#06b6d4' };
  if (u.startsWith('wifi:')) return { icon:'📶', label:'WiFi QR', color:'#10b981' };
  if (u.includes('wa.me')) return { icon:'💬', label:'WhatsApp QR', color:'#25d366' };
  if (u.startsWith('http')) return { icon:'🔗', label:'Website URL', color:'#00ffaa' };
  return { icon:'📦', label:'Other', color:'#aaa' };
}

function HistoryCard({ item, selected, onClick }) {
  const col = item.is_phishing ? '#ff4444' : '#00ffaa';
  const qt = qrTypeInfo(item.url);
  return (
    <div onClick={() => onClick(item)} style={{ padding:'12px 14px', borderRadius:10, background: selected ? `${col}0f` : 'rgba(255,255,255,0.025)', border:`1px solid ${selected ? col+'44' : col+'18'}`, cursor:'pointer', transition:'all 0.2s', marginBottom:8 }}>
      <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center' }}>
        <div style={{ display:'flex', alignItems:'center', gap:8, minWidth:0 }}>
          <span style={{ fontSize:15, flexShrink:0 }}>{qt.icon}</span>
          <div style={{ minWidth:0 }}>
            <div style={{ fontSize:13, color:col, fontWeight:700, fontFamily:'monospace' }}>{item.is_phishing?'⚠ PHISHING':'✓ LEGITIMATE'} — {item.confidence}%</div>
            <div style={{ fontSize:12, color:'rgba(255,255,255,0.3)', overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap', maxWidth:280, marginTop:2 }}>{item.url}</div>
          </div>
        </div>
        <div style={{ fontSize:11, color:'rgba(255,255,255,0.18)', whiteSpace:'nowrap', marginLeft:10, flexShrink:0 }}>{item.timestamp}</div>
      </div>
    </div>
  );
}

export default function App() {
  const [tab, setTab]           = useState('scan');
  const [mode, setMode]         = useState('upload');
  const [file, setFile]         = useState(null);
  const [preview, setPreview]   = useState(null);
  const [captured, setCaptured] = useState(false);
  const [result, setResult]     = useState(null);
  const [loading, setLoading]   = useState(false);
  const [error, setError]       = useState(null);
  const [dragging, setDragging] = useState(false);
  const [history, setHistory]   = useState([]);
  const [selHist, setSelHist]   = useState(null);
  const [camStream, setCamStream] = useState(null);
  const [cameras, setCameras]   = useState([]);
  const [camIdx, setCamIdx]     = useState(0);
  const [camReady, setCamReady] = useState(false);

  const fileRef   = useRef();
  const videoRef  = useRef();
  const canvasRef = useRef();

  const fetchHistory = useCallback(async () => {
    try { const r = await axios.get(`${API}/history`); setHistory(r.data.history || []); } catch {}
  }, []);

  useEffect(() => { if (tab === 'history') fetchHistory(); }, [tab, fetchHistory]);

  const handleFile = (f) => {
    if (!f || !f.type.startsWith('image/')) return;
    setFile(f); setPreview(URL.createObjectURL(f)); setResult(null); setError(null); setCaptured(false);
  };

  const onDrop = useCallback((e) => { e.preventDefault(); setDragging(false); handleFile(e.dataTransfer.files[0]); }, []);

  const scanImage = async (imgFile) => {
    if (!imgFile) return;
    setLoading(true); setError(null); setResult(null);
    const fd = new FormData(); fd.append('image', imgFile);
    try {
      const res = await axios.post(`${API}/scan`, fd);
      setResult(res.data); fetchHistory();
    } catch (err) {
      setError(err.response?.data?.error || `Cannot connect to Flask at ${API}. Make sure Flask is running.`);
    }
    setLoading(false);
  };

  const listCameras = async () => {
    try {
      await navigator.mediaDevices.getUserMedia({ video: true });
      const devs = await navigator.mediaDevices.enumerateDevices();
      const cams = devs.filter(d => d.kind === 'videoinput');
      setCameras(cams); return cams;
    } catch { return []; }
  };

  const stopCamera = useCallback(() => {
    if (camStream) camStream.getTracks().forEach(t => t.stop());
    setCamStream(null); setCamReady(false);
  }, [camStream]);

  const startCamera = useCallback(async (idx = 0) => {
    stopCamera();
    try {
      const cams = cameras.length ? cameras : await listCameras();
      const deviceId = cams[idx]?.deviceId;
      const stream = await navigator.mediaDevices.getUserMedia({
        video: deviceId
          ? { deviceId: { exact: deviceId }, width: { ideal: 1280 }, height: { ideal: 720 } }
          : { facingMode: { ideal: 'environment' }, width: { ideal: 1280 }, height: { ideal: 720 } }
      });
      setCamStream(stream); setCamReady(true);
      setPreview(null); setCaptured(false); setResult(null); setError(null);
      if (videoRef.current) { videoRef.current.srcObject = stream; videoRef.current.play(); }
    } catch {
      setError('Camera access denied. Please allow camera permission in your browser settings.');
    }
  }, [cameras, stopCamera]);

  const capturePhoto = () => {
    if (!videoRef.current || !canvasRef.current) return;
    const v = videoRef.current, c = canvasRef.current;
    c.width = v.videoWidth || 1280; c.height = v.videoHeight || 720;
    c.getContext('2d').drawImage(v, 0, 0);
    setPreview(c.toDataURL('image/jpeg', 0.95));
    setCaptured(true); setResult(null); setError(null);
    c.toBlob(blob => setFile(new File([blob], 'captured_qr.jpg', { type:'image/jpeg' })), 'image/jpeg', 0.95);
  };

  const retake = () => { setPreview(null); setCaptured(false); setFile(null); setResult(null); setError(null); };

  useEffect(() => {
    if (mode === 'camera') { listCameras().then(() => startCamera(0)); }
    else stopCamera();
    return () => stopCamera();
  }, [mode]); // eslint-disable-line

  const reset = () => { setFile(null); setPreview(null); setResult(null); setError(null); setCaptured(false); stopCamera(); setMode('upload'); };
  const clearHistory = async () => { try { await axios.delete(`${API}/history/clear`); } catch {} setHistory([]); setSelHist(null); };

  const isPhishing = result?.is_phishing ?? false;
  const riskPct    = result ? Math.round(result.confidence) : 0;
  const qt         = result ? qrTypeInfo(result.url) : null;
  const lc         = result?.live_checks ?? null;
  const di         = result?.domain_info ?? null;
  const ml         = result?.ml ?? null;

  const urlFeatures = result?.url && result?.qr_type === 'url' ? (() => {
    try {
      const u = result.url, p = new URL(u);
      return { has_https: p.protocol==='https:', has_ip: /^\d+\.\d+\.\d+\.\d+$/.test(p.hostname), has_suspicious: /login|verify|secure|update|bank|paypal|confirm|account|password|signin|alert|urgent/i.test(u), has_hyphen: p.hostname.includes('-'), suspicious_tld: /\.(xyz|info|online|biz|click|link|tk|ga|ml)$/i.test(p.hostname), long_url: u.length>75, has_at: u.includes('@'), has_port: !!p.port };
    } catch { return null; }
  })() : null;

  const ps = { background:'rgba(255,255,255,0.025)', border:'1px solid rgba(255,255,255,0.07)', borderRadius:14, padding:18 };
  const ls = { fontSize:10, letterSpacing:2, color:'rgba(0,255,170,0.4)', textTransform:'uppercase', marginBottom:10 };

  return (
    <div style={{ minHeight:'100vh', background:'#020814', position:'relative', overflowX:'hidden', fontFamily:'"Courier New", monospace', color:'#e0fff8' }}>
      <MatrixBg/>
      <div style={{ position:'fixed', inset:0, zIndex:0, pointerEvents:'none', backgroundImage:'linear-gradient(rgba(0,255,170,0.022) 1px,transparent 1px),linear-gradient(90deg,rgba(0,255,170,0.022) 1px,transparent 1px)', backgroundSize:'40px 40px' }}/>
      {[{top:14,left:14,borderTop:'2px solid #00ffaa2a',borderLeft:'2px solid #00ffaa2a'},{top:14,right:14,borderTop:'2px solid #00ffaa2a',borderRight:'2px solid #00ffaa2a'},{bottom:14,left:14,borderBottom:'2px solid #00ffaa2a',borderLeft:'2px solid #00ffaa2a'},{bottom:14,right:14,borderBottom:'2px solid #00ffaa2a',borderRight:'2px solid #00ffaa2a'}].map((s,i)=><div key={i} style={{ position:'fixed', width:30, height:30, zIndex:1, pointerEvents:'none', ...s }}/>)}

      <style>{`
        @keyframes fadeup{from{opacity:0;transform:translateY(16px)}to{opacity:1;transform:translateY(0)}}
        @keyframes glow{0%,100%{text-shadow:0 0 18px #00ffaa44}50%{text-shadow:0 0 36px #00ffaa88}}
        @keyframes spin{from{transform:rotate(0)}to{transform:rotate(360deg)}}
        @keyframes blink{0%,100%{opacity:1}50%{opacity:0.3}}
        @keyframes pulse{0%{box-shadow:0 0 0 0 rgba(0,255,170,0.28)}70%{box-shadow:0 0 0 12px rgba(0,255,170,0)}100%{box-shadow:0 0 0 0 rgba(0,255,170,0)}}
        @keyframes scanline{0%{top:0;opacity:1}50%{top:95%;opacity:1}100%{top:0;opacity:0}}
        .tab-btn:hover{background:rgba(0,255,170,0.07)!important}
        .tab-active{background:rgba(0,255,170,0.11)!important;border-color:#00ffaa44!important;color:#00ffaa!important}
        .mode-btn:hover{background:rgba(0,255,170,0.05)!important}
        .drop-zone:hover{border-color:#00ffaa55!important}
        .scan-btn:hover:not(:disabled){filter:brightness(1.12);transform:translateY(-1px);box-shadow:0 8px 26px rgba(0,255,170,0.3)!important}
        .scan-btn:disabled{opacity:0.4;cursor:not-allowed}
        .sec-btn:hover{background:rgba(255,255,255,0.07)!important}
        ::-webkit-scrollbar{width:3px}
        ::-webkit-scrollbar-thumb{background:#00ffaa33;border-radius:2px}
      `}</style>

      <div style={{ position:'relative', zIndex:2, padding:'14px', maxWidth:960, margin:'0 auto' }}>

        {/* HEADER */}
        <div style={{ textAlign:'center', padding:'28px 0 20px', animation:'fadeup 0.7s ease' }}>
          <div style={{ display:'inline-flex', alignItems:'center', justifyContent:'center', width:62, height:62, borderRadius:'50%', marginBottom:13, position:'relative', background:'rgba(0,255,170,0.07)', border:'2px solid #00ffaa2a', animation:'pulse 2.5s ease-out infinite' }}>
            <div style={{ position:'absolute', inset:-7, borderRadius:'50%', border:'1px solid rgba(0,255,170,0.1)', animation:'spin 9s linear infinite' }}>
              <div style={{ position:'absolute', top:-3, left:'50%', transform:'translateX(-50%)', width:6, height:6, borderRadius:'50%', background:'#00ffaa', boxShadow:'0 0 8px #00ffaa' }}/>
            </div>
            <span style={{ fontSize:24 }}>🛡</span>
          </div>
          <h1 style={{ margin:0, fontSize:24, fontWeight:700, letterSpacing:4, color:'#e0fff8', animation:'glow 3s ease-in-out infinite', textTransform:'uppercase' }}>QR<span style={{ color:'#00ffaa' }}>GUARD</span></h1>
          <p style={{ margin:'5px 0 0', fontSize:9, letterSpacing:3, color:'rgba(0,255,170,0.38)', textTransform:'uppercase' }}>AI · 7 Live Databases · Upload & Live Camera · Scan History</p>
          <div style={{ display:'flex', justifyContent:'center', gap:8, marginTop:14 }}>
            {[['scan','🔍  SCAN'],['history','🕐  HISTORY']].map(([t,label])=>(
              <button key={t} className={`tab-btn ${tab===t?'tab-active':''}`} onClick={()=>setTab(t)}
                style={{ padding:'8px 24px', borderRadius:20, border:'1px solid rgba(255,255,255,0.08)', background:'rgba(255,255,255,0.022)', color:'rgba(255,255,255,0.38)', cursor:'pointer', fontSize:11, letterSpacing:1.5, fontFamily:'monospace', transition:'all 0.2s' }}>
                {label}
              </button>
            ))}
          </div>
        </div>

        {/* SCAN TAB */}
        {tab==='scan' && (
          <div style={{ display:'grid', gridTemplateColumns: result ? '1fr 1.1fr' : '1fr', gap:20, animation:'fadeup 0.6s ease' }}>

            {/* INPUT PANEL */}
            <div style={{ ...ps, display:'flex', flexDirection:'column', gap:14 }}>
              <div style={{ fontSize:10, letterSpacing:2, color:'rgba(0,255,170,0.45)', textTransform:'uppercase', display:'flex', alignItems:'center', gap:8 }}>
                <span style={{ width:7, height:7, borderRadius:'50%', background:'#00ffaa', boxShadow:'0 0 8px #00ffaa', animation:'blink 1.5s infinite' }}/>INPUT TERMINAL
              </div>

              {/* Mode toggle */}
              <div style={{ display:'flex', gap:8 }}>
                {[['upload','📁  Upload'],['camera','📷  Camera']].map(([m,label])=>(
                  <button key={m} className={`mode-btn ${mode===m?'tab-active':''}`}
                    onClick={()=>{ setMode(m); setResult(null); setError(null); setCaptured(false); setPreview(null); setFile(null); }}
                    style={{ flex:1, padding:'9px 0', borderRadius:10, border:'1px solid rgba(255,255,255,0.08)', background: mode===m ? 'rgba(0,255,170,0.09)' : 'rgba(255,255,255,0.022)', color: mode===m ? '#00ffaa' : 'rgba(255,255,255,0.35)', cursor:'pointer', fontSize:12, letterSpacing:1, fontFamily:'monospace', transition:'all 0.2s' }}>
                    {label}
                  </button>
                ))}
              </div>

              {/* UPLOAD MODE */}
              {mode==='upload' && (
                <>
                  <div className="drop-zone" onDrop={onDrop} onDragOver={e=>{e.preventDefault();setDragging(true);}} onDragLeave={()=>setDragging(false)} onClick={()=>fileRef.current.click()}
                    style={{ position:'relative', borderRadius:12, minHeight:210, border:`2px dashed ${dragging?'#00ffaa':'rgba(0,255,170,0.18)'}`, background: dragging?'rgba(0,255,170,0.05)':'rgba(0,0,0,0.22)', cursor:'pointer', display:'flex', alignItems:'center', justifyContent:'center', transition:'all 0.3s', overflow:'hidden' }}>
                    <input type="file" accept="image/*" ref={fileRef} onChange={e=>handleFile(e.target.files[0])} style={{ display:'none' }}/>
                    {preview ? (
                      <>
                        <img src={preview} alt="QR" style={{ maxWidth:'100%', maxHeight:200, borderRadius:8, objectFit:'contain', filter: loading?'brightness(0.35)':'none', transition:'filter 0.3s' }}/>
                        {loading && (
                          <>
                            <div style={{ position:'absolute', inset:0, pointerEvents:'none' }}>
                              <div style={{ position:'absolute', left:0, right:0, height:3, background:'linear-gradient(90deg,transparent,#00ffaa,transparent)', boxShadow:'0 0 18px 4px #00ffaa', animation:'scanline 1.6s ease-in-out infinite' }}/>
                            </div>
                            <div style={{ position:'absolute', bottom:12, left:0, right:0, textAlign:'center', fontSize:11, color:'#00ffaa', letterSpacing:3, animation:'blink 0.8s infinite' }}>ANALYSING...</div>
                          </>
                        )}
                      </>
                    ) : (
                      <div style={{ textAlign:'center', padding:22 }}>
                        <div style={{ fontSize:40, marginBottom:11, opacity:0.28 }}>⬡</div>
                        <div style={{ fontSize:15, color:'rgba(255,255,255,0.38)', marginBottom:5 }}>Drop any QR code here</div>
                        <div style={{ fontSize:12, color:'rgba(255,255,255,0.18)' }}>Payment · Maps · Website · WiFi · Registration</div>
                        <div style={{ marginTop:13, fontSize:11, color:'rgba(0,255,170,0.38)', border:'1px solid rgba(0,255,170,0.15)', display:'inline-block', padding:'5px 16px', borderRadius:20, letterSpacing:1 }}>OR CLICK TO BROWSE</div>
                      </div>
                    )}
                  </div>
                  {file && <div style={{ fontSize:11, color:'rgba(255,255,255,0.22)', display:'flex', justifyContent:'space-between' }}><span>📁 {file.name}</span><span>{(file.size/1024).toFixed(1)} KB</span></div>}
                  <div style={{ display:'flex', gap:10 }}>
                    <button className="scan-btn" onClick={()=>scanImage(file)} disabled={!file||loading}
                      style={{ flex:1, background:'linear-gradient(135deg,#00ffaa,#00c8ff)', color:'#020814', border:'none', borderRadius:11, padding:'14px', fontSize:13, fontWeight:700, letterSpacing:2, cursor:'pointer', textTransform:'uppercase', transition:'all 0.2s', boxShadow:'0 4px 18px rgba(0,255,170,0.22)' }}>
                      {loading?'⟳  ANALYSING...':'⬡  SCAN QR CODE'}
                    </button>
                    {(file||result) && <button className="sec-btn" onClick={reset} style={{ padding:'14px 16px', background:'rgba(255,255,255,0.04)', border:'1px solid rgba(255,255,255,0.09)', borderRadius:11, color:'rgba(255,255,255,0.32)', cursor:'pointer', fontSize:14, transition:'all 0.2s' }}>✕</button>}
                  </div>
                </>
              )}

              {/* CAMERA MODE */}
              {mode==='camera' && (
                <div style={{ display:'flex', flexDirection:'column', gap:10 }}>
                  <div style={{ position:'relative', borderRadius:12, overflow:'hidden', background:'#000', minHeight:230, border:'1px solid rgba(0,255,170,0.2)' }}>
                    <video ref={videoRef} autoPlay playsInline muted style={{ width:'100%', maxHeight:290, objectFit:'cover', display: captured?'none':'block' }}/>
                    {captured && preview && <img src={preview} alt="captured" style={{ width:'100%', maxHeight:290, objectFit:'contain', display:'block', background:'#000' }}/>}
                    <canvas ref={canvasRef} style={{ display:'none' }}/>
                    {camReady && !captured && (
                      <div style={{ position:'absolute', inset:0, pointerEvents:'none' }}>
                        {[{top:10,left:10,borderTop:'3px solid #00ffaa',borderLeft:'3px solid #00ffaa'},{top:10,right:10,borderTop:'3px solid #00ffaa',borderRight:'3px solid #00ffaa'},{bottom:10,left:10,borderBottom:'3px solid #00ffaa',borderLeft:'3px solid #00ffaa'},{bottom:10,right:10,borderBottom:'3px solid #00ffaa',borderRight:'3px solid #00ffaa'}].map((s,i)=><div key={i} style={{ position:'absolute', width:26, height:26, ...s }}/>)}
                        <div style={{ position:'absolute', left:0, right:0, height:2, background:'linear-gradient(90deg,transparent,#00ffaa,transparent)', animation:'scanline 2.5s linear infinite', boxShadow:'0 0 10px #00ffaa' }}/>
                        <div style={{ position:'absolute', bottom:10, left:0, right:0, textAlign:'center', fontSize:11, color:'#00ffaa', letterSpacing:2, animation:'blink 1.5s infinite' }}>POINT AT QR CODE</div>
                      </div>
                    )}
                    {captured && <div style={{ position:'absolute', top:8, right:8, background:'rgba(0,255,170,0.2)', border:'1px solid #00ffaa', borderRadius:8, padding:'4px 10px', fontSize:11, color:'#00ffaa', letterSpacing:1 }}>📸 CAPTURED</div>}
                    {!camReady && !captured && (
                      <div style={{ position:'absolute', inset:0, display:'flex', alignItems:'center', justifyContent:'center', flexDirection:'column', gap:10, color:'rgba(255,255,255,0.22)' }}>
                        <div style={{ fontSize:38 }}>📷</div>
                        <div style={{ fontSize:13 }}>Press START CAMERA</div>
                      </div>
                    )}
                  </div>

                  {/* Controls */}
                  {!captured ? (
                    <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr 1fr', gap:8 }}>
                      <button className="scan-btn" onClick={()=>camStream?stopCamera():startCamera(camIdx)}
                        style={{ padding:'12px 6px', background: camStream?'linear-gradient(135deg,#ff4444,#ff0080)':'linear-gradient(135deg,#00ffaa,#00c8ff)', color:'#020814', border:'none', borderRadius:10, fontSize:11, fontWeight:700, letterSpacing:1, cursor:'pointer', transition:'all 0.2s' }}>
                        {camStream?'⏹ STOP':'▶ START'}
                      </button>
                      <button onClick={capturePhoto} disabled={!camReady}
                        style={{ padding:'12px 6px', background: camReady?'linear-gradient(135deg,#f59e0b,#ff6b00)':'rgba(255,255,255,0.06)', color: camReady?'#020814':'rgba(255,255,255,0.2)', border:'none', borderRadius:10, fontSize:11, fontWeight:700, letterSpacing:1, cursor: camReady?'pointer':'not-allowed', transition:'all 0.2s', boxShadow: camReady?'0 4px 16px rgba(245,158,11,0.3)':'none' }}>
                        📸 CAPTURE
                      </button>
                      <button className="sec-btn" onClick={()=>{ const next=(camIdx+1)%Math.max(cameras.length,1); setCamIdx(next); startCamera(next); }} disabled={!camStream}
                        style={{ padding:'12px 6px', background:'rgba(255,255,255,0.04)', border:'1px solid rgba(255,255,255,0.08)', borderRadius:10, color: camStream?'rgba(255,255,255,0.55)':'rgba(255,255,255,0.18)', cursor: camStream?'pointer':'not-allowed', fontSize:11, transition:'all 0.2s' }}>
                        🔄 SWITCH
                      </button>
                    </div>
                  ) : (
                    <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:8 }}>
                      <button className="scan-btn" onClick={()=>scanImage(file)} disabled={!file||loading}
                        style={{ padding:'14px', background:'linear-gradient(135deg,#00ffaa,#00c8ff)', color:'#020814', border:'none', borderRadius:11, fontSize:13, fontWeight:700, letterSpacing:2, cursor:'pointer', textTransform:'uppercase', transition:'all 0.2s', boxShadow:'0 4px 16px rgba(0,255,170,0.25)' }}>
                        {loading?'⟳ ANALYSING...':'⬡ SCAN QR'}
                      </button>
                      <button className="sec-btn" onClick={retake}
                        style={{ padding:'14px', background:'rgba(255,255,255,0.04)', border:'1px solid rgba(255,255,255,0.1)', borderRadius:11, color:'rgba(255,255,255,0.5)', cursor:'pointer', fontSize:13, letterSpacing:1, transition:'all 0.2s' }}>
                        🔄 RETAKE
                      </button>
                    </div>
                  )}

                  {cameras.length>0 && (
                    <div style={{ fontSize:10, color:'rgba(255,255,255,0.16)', background:'rgba(255,255,255,0.018)', padding:'6px 10px', borderRadius:8, border:'1px solid rgba(255,255,255,0.04)' }}>
                      {cameras.map((c,i)=><div key={c.deviceId} style={{ color: i===camIdx?'#00ffaa':'rgba(255,255,255,0.22)', marginBottom:2 }}>{i===camIdx?'▶':'○'}  {c.label||`Camera ${i+1}`}</div>)}
                    </div>
                  )}

                  <div style={{ fontSize:11, color:'rgba(255,255,255,0.3)', lineHeight:1.8, padding:'10px 12px', borderRadius:9, background:'rgba(0,255,170,0.03)', border:'1px solid rgba(0,255,170,0.08)' }}>
                    <div style={{ color:'#00ffaa', fontWeight:700, marginBottom:5, letterSpacing:1 }}>HOW TO USE:</div>
                    <div>1️⃣ Press <strong style={{ color:'#00ffaa' }}>▶ START</strong> → allow camera</div>
                    <div>2️⃣ Point at QR code</div>
                    <div>3️⃣ Press <strong style={{ color:'#f59e0b' }}>📸 CAPTURE</strong></div>
                    <div>4️⃣ Press <strong style={{ color:'#00ffaa' }}>⬡ SCAN QR</strong></div>
                    <div>5️⃣ Press <strong style={{ color:'rgba(255,255,255,0.5)' }}>🔄 RETAKE</strong> if unclear</div>
                    <div style={{ marginTop:6, fontSize:10, color:'rgba(0,255,170,0.4)' }}>
                      📱 Android: open <strong>http://192.168.x.x:3000</strong> in Chrome
                    </div>
                  </div>
                </div>
              )}

              {error && <div style={{ background:'rgba(255,59,59,0.09)', border:'1px solid rgba(255,59,59,0.24)', borderRadius:11, padding:'12px 15px', fontSize:12, color:'#ff6b6b', lineHeight:1.7 }}>⚠  {error}</div>}
            </div>

            {/* RESULTS */}
            {result && (
              <div style={{ display:'flex', flexDirection:'column', gap:13, animation:'fadeup 0.5s ease', maxHeight:'86vh', overflowY:'auto', paddingRight:2 }}>

                {/* Verdict */}
                <div style={{ borderRadius:14, padding:20, background: isPhishing?'linear-gradient(135deg,rgba(255,59,59,0.13),rgba(180,0,0,0.07))':'linear-gradient(135deg,rgba(0,255,170,0.09),rgba(0,180,120,0.05))', border:`1px solid ${isPhishing?'rgba(255,59,59,0.3)':'rgba(0,255,170,0.3)'}` }}>
                  <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between' }}>
                    <div>
                      <div style={{ fontSize:10, letterSpacing:2, color:'rgba(255,255,255,0.25)', textTransform:'uppercase', marginBottom:7 }}>Final Verdict</div>
                      <div style={{ fontSize:22, fontWeight:700, letterSpacing:2, color: isPhishing?'#ff4444':'#00ffaa', textShadow:`0 0 18px ${isPhishing?'#ff444455':'#00ffaa55'}` }}>{isPhishing?'⚠  PHISHING':'✓  LEGITIMATE'}</div>
                      {qt && <div style={{ marginTop:8, display:'flex', alignItems:'center', gap:6 }}><span style={{ fontSize:13 }}>{qt.icon}</span><span style={{ fontSize:11, color:qt.color, letterSpacing:1, textTransform:'uppercase', fontWeight:700 }}>{qt.label}</span></div>}
                      {result.flags_count>0 && <div style={{ fontSize:11, color:'#ff8888', marginTop:4 }}>⚡ Flagged by {result.flags_count} live database{result.flags_count>1?'s':''}</div>}
                    </div>
                    <Gauge pct={riskPct} isPhishing={isPhishing}/>
                  </div>
                </div>

                {/* UPI */}
                {result.upi_details && (
                  <div style={{ ...ps, background:'rgba(245,158,11,0.06)', border:'1px solid rgba(245,158,11,0.24)' }}>
                    <div style={{ ...ls, color:'#f59e0b' }}>💳 UPI Payment Details</div>
                    <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:8 }}>
                      {[['UPI ID',result.upi_details.upi_id||'N/A'],['Recipient',result.upi_details.name||'Not specified'],['Amount',result.upi_details.amount?`₹${result.upi_details.amount}`:'Not fixed'],['Bank',result.upi_details.known_handle?'✅ Known bank':'⚠ Unknown']].map(([k,v])=>(
                        <div key={k} style={{ padding:'8px 10px', borderRadius:8, background:'rgba(245,158,11,0.05)', border:'1px solid rgba(245,158,11,0.12)' }}>
                          <div style={{ fontSize:10, color:'rgba(245,158,11,0.45)', letterSpacing:1 }}>{k.toUpperCase()}</div>
                          <div style={{ fontSize:13, color:'rgba(255,255,255,0.65)', marginTop:2, wordBreak:'break-all' }}>{v}</div>
                        </div>
                      ))}
                    </div>
                    <div style={{ marginTop:10, fontSize:12, color:'rgba(245,158,11,0.65)', background:'rgba(245,158,11,0.05)', padding:'8px 10px', borderRadius:8, border:'1px solid rgba(245,158,11,0.12)', lineHeight:1.6 }}>ℹ️ UPI QR codes are safe. Payment only completes after you enter your UPI PIN.</div>
                  </div>
                )}

                {/* URL info */}
                <div style={ps}>
                  <div style={ls}>Extracted Content</div>
                  <div style={{ fontSize:12, color:'rgba(255,255,255,0.65)', wordBreak:'break-all', background:'rgba(0,0,0,0.28)', padding:'10px 12px', borderRadius:9, border:'1px solid rgba(255,255,255,0.06)', lineHeight:1.7, fontFamily:'monospace' }}>{result.url}</div>
                  <div style={{ display:'flex', gap:20, marginTop:10, flexWrap:'wrap' }}>
                    {[['Length',`${result.url.length} chars`],['Scheme',result.url.startsWith('https')?'🔒 HTTPS':result.url.startsWith('upi')?'💳 UPI':'⚠ HTTP'],['Risk Score',`${result.confidence}%`]].map(([k,v])=>(
                      <div key={k}><div style={{ fontSize:10, color:'rgba(255,255,255,0.2)', letterSpacing:1 }}>{k.toUpperCase()}</div><div style={{ fontSize:13, color:'rgba(255,255,255,0.55)', marginTop:2 }}>{v}</div></div>
                    ))}
                  </div>
                </div>

                {/* Why phishing/legit */}
                {result.risk_reasons && (
                  <div style={{ borderRadius:14, padding:16, background: isPhishing?'rgba(255,59,59,0.06)':'rgba(0,255,170,0.04)', border:`1px solid ${isPhishing?'rgba(255,59,59,0.2)':'rgba(0,255,170,0.14)'}` }}>
                    <div style={{ ...ls, color: isPhishing?'#ff6666':'#00ffaa', fontWeight:700 }}>{isPhishing?'🚨 Why This Is PHISHING':'✅ Why This Is LEGITIMATE'}</div>
                    {result.risk_reasons.length>0 ? (
                      <div style={{ display:'flex', flexDirection:'column', gap:6 }}>
                        {result.risk_reasons.map((reason,i)=>{
                          const isDanger=isPhishing&&!reason.includes('-');
                          const col=isDanger?'#ff6666':'#00ffaa';
                          return (
                            <div key={i} style={{ display:'flex', alignItems:'flex-start', gap:8, padding:'7px 10px', borderRadius:8, background:`${col}0c`, border:`1px solid ${col}16` }}>
                              <span style={{ color:col, fontSize:12, flexShrink:0 }}>{isDanger?'⚠':'✓'}</span>
                              <span style={{ fontSize:12, color:'rgba(255,255,255,0.65)', lineHeight:1.5 }}>{reason}</span>
                            </div>
                          );
                        })}
                      </div>
                    ) : <div style={{ fontSize:12, color:'rgba(255,255,255,0.3)', fontStyle:'italic' }}>{isPhishing?'Flagged by live database checks.':'No suspicious signals detected.'}</div>}
                    {result.flags_count>0 && <div style={{ marginTop:9, padding:'7px 10px', borderRadius:8, background:'rgba(255,59,59,0.07)', border:'1px solid rgba(255,59,59,0.2)', fontSize:12, color:'#ff8888', lineHeight:1.5 }}>⚡ Flagged by <strong>{result.flags_count}</strong> live internet database{result.flags_count>1?'s':''}</div>}
                    <div style={{ marginTop:9, padding:'8px 10px', borderRadius:8, background: isPhishing?'rgba(255,59,59,0.05)':'rgba(0,255,170,0.04)', border:`1px solid ${isPhishing?'rgba(255,59,59,0.12)':'rgba(0,255,170,0.1)'}`, fontSize:12, color: isPhishing?'#ff8888':'rgba(0,255,170,0.65)', lineHeight:1.7 }}>
                      {isPhishing?'⛔ Do NOT visit this URL. Delete and report this QR code immediately.':'✅ This QR appears safe. Always verify before entering personal information.'}
                    </div>
                  </div>
                )}

                {/* URL features */}
                {urlFeatures && (
                  <div style={ps}>
                    <div style={ls}>URL Security Features</div>
                    <div style={{ display:'flex', flexWrap:'wrap', gap:6 }}>
                      <Badge label="HTTPS" value={urlFeatures.has_https} danger={false}/>
                      <Badge label="IP Address" value={urlFeatures.has_ip} danger={true}/>
                      <Badge label="Phish Keywords" value={urlFeatures.has_suspicious} danger={true}/>
                      <Badge label="Hyphen Domain" value={urlFeatures.has_hyphen} danger={true}/>
                      <Badge label="Suspect TLD" value={urlFeatures.suspicious_tld} danger={true}/>
                      <Badge label="Long URL" value={urlFeatures.long_url} danger={true}/>
                      <Badge label="@ Symbol" value={urlFeatures.has_at} danger={true}/>
                      <Badge label="Custom Port" value={urlFeatures.has_port} danger={true}/>
                    </div>
                  </div>
                )}

                {/* Live checks */}
                {lc && (
                  <div style={ps}>
                    <div style={ls}>Live Database Checks</div>
                    <div style={{ display:'flex', flexDirection:'column', gap:7 }}>
                      <LiveRow label="URLhaus — Malware DB" data={lc.urlhaus}/>
                      <LiveRow label="PhishTank — Phishing DB" data={lc.phishtank}/>
                      <LiveRow label="Google Safe Browsing" data={lc.google_safebrowsing}/>
                      <LiveRow label="VirusTotal (70+ engines)" data={lc.virustotal}/>
                      <LiveRow label="PhishStats — Live Feed" data={lc.phishstats}/>
                      <LiveRow label="IPQualityScore" data={lc.ipqualityscore}/>
                      <LiveRow label="Scamalytics" data={lc.scamalytics}/>
                    </div>
                    {di && (
                      <div style={{ marginTop:12, paddingTop:12, borderTop:'1px solid rgba(255,255,255,0.05)' }}>
                        <div style={{ ...ls, marginBottom:8 }}>WHOIS / Domain Info</div>
                        <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:8 }}>
                          {[['Domain',di.domain],['Registered',di.created],['Registrar',di.registrar],['Age',di.age_days!=null?`${di.age_days} days${di.suspicious?' ⚠ NEW':''}`:'Unknown']].map(([k,v])=>(
                            <div key={k}><div style={{ fontSize:10, color:'rgba(255,255,255,0.18)', letterSpacing:1 }}>{k.toUpperCase()}</div><div style={{ fontSize:12, marginTop:2, wordBreak:'break-all', color: k==='Age'&&di.suspicious?'#ffaa00':'rgba(255,255,255,0.5)' }}>{v||'—'}</div></div>
                          ))}
                        </div>
                      </div>
                    )}
                    {ml && (
                      <div style={{ marginTop:11, padding:'9px 11px', borderRadius:9, background:'rgba(0,255,170,0.04)', border:'1px solid rgba(0,255,170,0.09)' }}>
                        <div style={{ fontSize:10, color:'rgba(0,255,170,0.38)', letterSpacing:2, textTransform:'uppercase', marginBottom:7 }}>ML Model — Random Forest (99.75%)</div>
                        <div style={{ display:'flex', gap:20, flexWrap:'wrap' }}>
                          {[['Prediction',ml.prediction,ml.prediction==='PHISHING'?'#ff4444':'#00ffaa'],['Phish Prob',`${ml.phishing_probability}%`,'rgba(255,255,255,0.5)'],['Confidence',`${ml.confidence}%`,'rgba(255,255,255,0.5)']].map(([k,v,c])=>(
                            <div key={k}><div style={{ fontSize:10, color:'rgba(255,255,255,0.18)' }}>{k.toUpperCase()}</div><div style={{ fontSize:13, color:c }}>{v}</div></div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {/* HISTORY TAB */}
        {tab==='history' && (
          <div style={{ animation:'fadeup 0.6s ease' }}>
            <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:14 }}>
              <div style={{ fontSize:11, letterSpacing:2, color:'rgba(0,255,170,0.38)', textTransform:'uppercase' }}>{history.length} scan{history.length!==1?'s':''} recorded</div>
              {history.length>0 && <button onClick={clearHistory} style={{ padding:'7px 14px', background:'rgba(255,59,59,0.07)', border:'1px solid rgba(255,59,59,0.18)', borderRadius:8, color:'#ff6666', cursor:'pointer', fontSize:11, letterSpacing:1, fontFamily:'monospace' }}>🗑  CLEAR ALL</button>}
            </div>
            {history.length===0 ? (
              <div style={{ textAlign:'center', padding:'60px 20px', color:'rgba(255,255,255,0.18)', fontSize:14 }}>
                <div style={{ fontSize:36, marginBottom:12, opacity:0.22 }}>🕐</div>No scans yet — upload a QR code to get started.
              </div>
            ) : (
              <div style={{ display:'grid', gridTemplateColumns: selHist?'1fr 1fr':'1fr', gap:18 }}>
                <div>{history.map(item=><HistoryCard key={item.id} item={item} selected={selHist?.id===item.id} onClick={h=>setSelHist(selHist?.id===h.id?null:h)}/>)}</div>
                {selHist && (
                  <div style={{ ...ps, animation:'fadeup 0.3s ease', position:'sticky', top:14, maxHeight:'80vh', overflowY:'auto' }}>
                    <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:14 }}>
                      <div style={ls}>Scan Detail</div>
                      <button onClick={()=>setSelHist(null)} style={{ padding:'5px 11px', background:'rgba(255,255,255,0.04)', border:'1px solid rgba(255,255,255,0.08)', borderRadius:7, color:'rgba(255,255,255,0.3)', cursor:'pointer', fontSize:13 }}>✕</button>
                    </div>
                    <div style={{ borderRadius:12, padding:16, marginBottom:12, background: selHist.is_phishing?'rgba(255,59,59,0.09)':'rgba(0,255,170,0.06)', border:`1px solid ${selHist.is_phishing?'rgba(255,59,59,0.25)':'rgba(0,255,170,0.25)'}` }}>
                      <div style={{ fontSize:19, fontWeight:700, color: selHist.is_phishing?'#ff4444':'#00ffaa' }}>{selHist.is_phishing?'⚠ PHISHING':'✓ LEGITIMATE'}</div>
                      <div style={{ fontSize:28, fontWeight:700, color: selHist.is_phishing?'#ff4444':'#00ffaa', marginTop:4 }}>{selHist.confidence}% risk</div>
                    </div>
                    {[['Scanned At',selHist.timestamp],['QR Type',selHist.qr_type?.toUpperCase()],['DB Flags',`${selHist.flags_count} database${selHist.flags_count!==1?'s':''} flagged`],['URL / Content',selHist.url]].map(([k,v])=>(
                      <div key={k} style={{ marginBottom:9, padding:'9px 11px', borderRadius:9, background:'rgba(255,255,255,0.02)', border:'1px solid rgba(255,255,255,0.05)' }}>
                        <div style={{ fontSize:10, color:'rgba(255,255,255,0.18)', letterSpacing:1, textTransform:'uppercase' }}>{k}</div>
                        <div style={{ fontSize:13, color:'rgba(255,255,255,0.55)', marginTop:3, wordBreak:'break-all', lineHeight:1.5 }}>{v}</div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {/* Status bar */}
        <div style={{ marginTop:18, padding:'9px 15px', background:'rgba(255,255,255,0.018)', border:'1px solid rgba(255,255,255,0.05)', borderRadius:9, display:'flex', justifyContent:'space-between', alignItems:'center', flexWrap:'wrap', gap:8 }}>
          <div style={{ display:'flex', gap:16, flexWrap:'wrap' }}>
            {[['MODEL','Random Forest'],['FEATURES','22'],['DATABASES','7 Live'],['ACCURACY','99.75%']].map(([k,v])=>(
              <div key={k} style={{ fontSize:10, letterSpacing:1 }}><span style={{ color:'rgba(255,255,255,0.14)' }}>{k}: </span><span style={{ color:'rgba(0,255,170,0.48)' }}>{v}</span></div>
            ))}
          </div>
          <div style={{ fontSize:10, color:'rgba(255, 255, 255, 0.38)', display:'flex', alignItems:'center', gap:6 }}>
            <span style={{ width:6, height:6, borderRadius:'50%', background:'#00ffaa', display:'inline-block', boxShadow:'0 0 5px #00ffaa', animation:'blink 2s infinite' }}/>
            API: {API}
          </div>
        </div>
        <div style={{ textAlign:'center', padding:'13px 0 6px', fontSize:9, letterSpacing:2, color:'rgba(255, 255, 255, 0.28)', textTransform:'uppercase' }}>QRGuard © 2026 · AI-Based Quishing Detection</div>
      </div>
    </div>
  );
}