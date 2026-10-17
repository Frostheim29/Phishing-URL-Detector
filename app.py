"""PhishGuard URL Threat Intelligence dashboard."""
from __future__ import annotations
import csv, io, json
from datetime import datetime
from html import escape
from pathlib import Path
import pandas as pd
import streamlit as st
from risk_engine import analyze_url_risk

ROOT=Path(__file__).resolve().parent; HISTORY=ROOT/"check_history.csv"; FIELDS=["timestamp","url","result","detail"]
st.set_page_config("PhishGuard | URL Threat Intelligence","PG",layout="wide")

def setup():
    st.markdown("""<style>
    .stApp{background:#06101d;color:#e8f1fa}.block-container{max-width:1220px;padding:2rem 2.4rem 3rem}.stButton>button{border-radius:7px;font-weight:700;letter-spacing:.04em}.stTextInput input{background:#071827!important;border:1px solid #31516e!important;border-radius:7px!important;color:#eff7ff!important;height:48px}
    [data-testid="stSidebar"]{background:#081725;border-right:1px solid #1e3952}[data-testid="stSidebar"] .block-container{padding:1.7rem .9rem}.brand{font-size:1.4rem;color:#72d9ff;font-weight:800;letter-spacing:-.04em}.kicker{font-size:.7rem;letter-spacing:.13em;text-transform:uppercase;color:#86a5bd}.muted{color:#9eb3c6}
    .navlabel{font-size:.82rem;margin:1.3rem 0 .45rem}.navspacer{height:1rem}.status{border-top:1px solid #213d57;margin-top:1.3rem;padding-top:1.1rem}.dot{color:#f5c84e}.hero,.panel,.metric,.kv,.flow,.cap,.reason{background:#0a1b2c;border:1px solid #203c57}.hero{padding:1.4rem 1.5rem;border-radius:11px}.hero-top{display:flex;justify-content:space-between;gap:1rem;align-items:center}.title{font-size:1.65rem;font-weight:780;letter-spacing:-.035em}.operational{color:#7de5b4;font-size:.75rem;letter-spacing:.08em}.panel{padding:1rem 1.1rem;border-radius:9px}.metric{padding:1rem;border-radius:9px;border-top:3px solid var(--tone);min-height:105px}.metric-value{font-size:1.55rem;font-weight:760;margin:.25rem 0}.metric-note{color:#9eb3c6;font-size:.78rem}.section{margin:1.5rem 0 .7rem;font-size:.8rem;letter-spacing:.1em;text-transform:uppercase;color:#9bb5ca}.flow,.cap{padding:.8rem;border-radius:8px;min-height:78px}.flow-n{color:#72d9ff;font-size:.72rem;letter-spacing:.1em}.flow-t{font-weight:700;margin-top:.35rem}.cap p{color:#9eb3c6;font-size:.8rem;margin:.35rem 0 0}.scanrow{margin-top:1.1rem;padding:.8rem;background:#071827;border:1px solid #2e516e;border-radius:8px}.gauge{width:220px;height:220px;border-radius:50%;background:conic-gradient(var(--tone) calc(var(--score)*1%),#132c44 0);display:grid;place-items:center;margin:.5rem auto}.gauge-inner{width:184px;height:184px;border-radius:50%;background:#0a1b2c;display:grid;place-items:center;text-align:center}.score{font-size:3.2rem;font-weight:800;line-height:1}.score-sub{font-size:.78rem;color:#9eb3c6}.scale{display:flex;justify-content:space-between;font-size:.7rem;color:#90a9bd;margin-top:.5rem}.reason{padding:.65rem .75rem;border-radius:7px;margin:.35rem 0;border-left:3px solid var(--tone)}.signal-title{font-weight:700;margin-bottom:.55rem}.badge{display:inline-block;background:#132c44;border:1px solid #31516e;color:#d9eaff;border-radius:99px;padding:.28rem .5rem;font-size:.76rem;margin:.15rem}.pos{border-left:3px solid #36c982}.neg{border-left:3px solid #f6c344}.strong{border-left:3px solid #c2549c}.kv{padding:.65rem .7rem;border-radius:7px;margin:.25rem 0;min-height:62px}.kv-label{font-size:.69rem;color:#90abc1;text-transform:uppercase;letter-spacing:.08em}.kv-value{font-weight:650;margin-top:.25rem;word-break:break-word}.empty{color:#8fa7ba;font-size:.83rem}.history-head{margin-bottom:1rem}.smallcard{background:#0a1b2c;border:1px solid #203c57;padding:.9rem;border-radius:8px;text-align:center}.smallcard b{display:block;font-size:1.25rem;margin-top:.25rem}.about-card{background:#0a1b2c;border-left:3px solid #3daee0;padding:1rem;margin:.6rem 0}.stDataFrame{border:1px solid #203c57;border-radius:8px;overflow:hidden}
    </style>""",unsafe_allow_html=True)
    for k,v in {"page":"Scanner","latest":None,"latest_url":"","batch":None}.items():st.session_state.setdefault(k,v)

def tone(level):return {"Low":"#36c982","Medium":"#f6c344","High":"#ef625f","Critical":"#bd4a9f"}.get(level,"#63c9f3")
def uniq(x):return list(dict.fromkeys(a for a in x if a))
@st.cache_data(show_spinner=False)
def model_status():
    r=analyze_url_risk("https://example.com");return r.get("model_score") is not None
def save(r):
    d={k:r.get(k) for k in ["risk_score","risk_level","verdict","model_score","heuristic_score"]}; exists=HISTORY.exists() and HISTORY.stat().st_size>0
    with HISTORY.open("a",newline="",encoding="utf-8") as f:
        w=csv.DictWriter(f,fieldnames=FIELDS)
        if not exists:w.writeheader()
        w.writerow({"timestamp":datetime.now().strftime("%Y-%m-%d %H:%M:%S"),"url":r.get("url",""),"result":r.get("verdict","Suspicious"),"detail":json.dumps(d)})
def history():
    rows=[]
    if HISTORY.exists():
        with HISTORY.open(newline="",encoding="utf-8") as f:
            for row in csv.DictReader(f):
                try:d=json.loads(row.get("detail",""))
                except (json.JSONDecodeError,TypeError):d={}
                rows.append({"Timestamp":row.get("timestamp","—"),"URL":row.get("url","—"),"Risk Score":d.get("risk_score","—"),"Risk Level":d.get("risk_level","—"),"Verdict":d.get("verdict",row.get("result","—")),"ML Score":d.get("model_score","—"),"Heuristic Score":d.get("heuristic_score","—")})
    return pd.DataFrame(rows,columns=["Timestamp","URL","Risk Score","Risk Level","Verdict","ML Score","Heuristic Score"])
def metric(label,value,note,t):st.markdown(f"<div class='metric' style='--tone:{t}'><div class='kicker'>{escape(label)}</div><div class='metric-value'>{escape(str(value))}</div><div class='metric-note'>{escape(note)}</div></div>",unsafe_allow_html=True)
def kv(label,value):st.markdown(f"<div class='kv'><div class='kv-label'>{escape(label)}</div><div class='kv-value'>{escape(str(value))}</div></div>",unsafe_allow_html=True)
def heading(title,subtitle=""):
    st.markdown(f"<div class='title'>{escape(title)}</div><div class='muted'>{escape(subtitle)}</div>",unsafe_allow_html=True)

def landing():
    st.markdown("<div class='section'>How PhishGuard Works</div>")
    flow=[("01","URL STRUCTURE"),("02","ML ANALYSIS"),("03","RISK ENGINE"),("04","EXPLAINABLE RESULT")]
    cols=st.columns(4)
    for c,(n,t) in zip(cols,flow):
        with c:st.markdown(f"<div class='flow'><div class='flow-n'>{n}</div><div class='flow-t'>{t}</div></div>",unsafe_allow_html=True)
    st.markdown("<div class='section'>What We Check</div>")
    caps=[("STRUCTURAL ANALYSIS","Detect suspicious URL patterns"),("ML CLASSIFICATION","Existing trained phishing classifier"),("EXPLAINABLE RESULTS","Understand why a URL is risky")]
    cols=st.columns(3)
    for c,(t,d) in zip(cols,caps):
        with c:st.markdown(f"<div class='cap'><b>{t}</b><p>{d}</p></div>",unsafe_allow_html=True)
    st.caption("HTTPS  •  IP addresses  •  Suspicious keywords  •  TLDs  •  URL structure  •  Encoding")

def scan_result(r):
    level,score,ml=r.get("risk_level","Medium"),int(r.get("risk_score",0)),r.get("model_score"); t=tone(level)
    st.markdown(f"<div class='panel' style='margin-top:1.1rem'><div class='kicker'>Scan Result</div><b>{escape(r.get('url',''))}</b></div>",unsafe_allow_html=True)
    left,right=st.columns([1,1.45],gap="large")
    with left:
        st.markdown(f"<div class='gauge' style='--score:{score};--tone:{t}' role='img' aria-label='Risk score {score} of 100'><div class='gauge-inner'><div><div class='score'>{score}</div><div class='score-sub'>/ 100</div><b style='color:{t}'>{escape(level.upper())}</b></div></div></div><div class='scale'><span>LOW</span><span>MEDIUM</span><span>HIGH</span><span>CRITICAL</span></div>",unsafe_allow_html=True)
    with right:
        st.markdown("<div class='section' style='margin-top:0'>Assessment</div>",unsafe_allow_html=True)
        metric("Verdict",r.get("verdict","Suspicious"),"Assessment outcome",t); st.markdown("<div style='height:.45rem'></div>",unsafe_allow_html=True)
        a,b=st.columns(2)
        with a:metric("Risk Level",level,"Combined signal level",t)
        with b:metric("ML Score" if ml is not None else "Analysis Mode",f"{ml:.2f}" if isinstance(ml,(int,float)) else "Heuristic Only","Classifier signal" if ml is not None else "Structural analysis",t)
    neg=[x for x in uniq(r.get("negative_signals",[])) if not x.startswith("ML score unavailable")]
    st.markdown("<div class='section'>Why This URL Was Flagged</div>",unsafe_allow_html=True)
    if neg:
        for reason in neg[:5]:st.markdown(f"<div class='reason' style='--tone:{t}'>{escape(reason)}</div>",unsafe_allow_html=True)
    else:st.markdown("<div class='reason' style='--tone:#36c982'>No major structural phishing indicators were detected.</div>",unsafe_allow_html=True)
    if ml is None:st.caption("ML scoring is unavailable; this assessment uses structural heuristics.")
    st.markdown("<div class='section'>Security Signals</div>",unsafe_allow_html=True)
    groups=[("Positive Signals",uniq(r.get("positive_signals",[])),"pos","No positive security signals recorded."),("Negative Signals",neg,"neg","No negative security signals detected."),("Strong Malicious Signals",uniq(r.get("strong_malicious_signals",[])),"strong","No strong malicious structural signals detected.")]
    cols=st.columns(3)
    for c,(name,items,cl,empty) in zip(cols,groups):
        with c:
            st.markdown(f"<div class='panel {cl}'><div class='signal-title'>{name}</div>",unsafe_allow_html=True)
            if items:
                for item in items:st.markdown(f"<span class='badge'>{escape(item)}</span>",unsafe_allow_html=True)
            else:st.markdown(f"<span class='empty'>{empty}</span>",unsafe_allow_html=True)
            st.markdown("</div>",unsafe_allow_html=True)
    intelligence(r.get("analysis",{}))
    with st.expander("Technical Details"):
        st.json(r.get("analysis",{}))

def intelligence(x):
    st.markdown("<div class='section'>URL Intelligence</div>",unsafe_allow_html=True)
    yn=lambda v:"Yes" if v else "No"
    groups=[("Basic Information",[("Protocol",x.get("protocol","—")),("Host",x.get("host","—")),("Domain",x.get("domain","—")),("TLD",x.get("tld") or "—")]),("Network",[("HTTPS",yn(x.get("is_https"))),("IP Address",yn(x.get("is_ip_address"))),("Private / Local IP",yn(x.get("is_localhost_or_private_ip"))),("Port",x.get("port") or "Default"),("Non-standard Port",yn(x.get("has_non_standard_port")))]),("URL Structure",[("URL Length",x.get("url_length","—")),("Domain Length",x.get("domain_length","—")),("Subdomains",x.get("subdomain_count","—")),("Path Segments",x.get("path_segment_count","—")),("Query Parameters",x.get("query_parameter_count","—")),("Hyphen Count",x.get("hyphen_count","—"))]),("Threat Indicators",[("Suspicious Keywords",", ".join(x.get("suspicious_keywords",[])) or "None"),("Suspicious TLD",yn(x.get("has_suspicious_tld"))),("Encoded Characters",yn(x.get("has_encoded_characters"))),("Punycode / IDN",yn(x.get("is_punycode_or_idn")))])]
    cols=st.columns(4)
    for c,(title,items) in zip(cols,groups):
        with c:
            st.markdown(f"<div class='panel'><div class='kicker'>{title}</div>",unsafe_allow_html=True)
            for a,b in items:kv(a,b)
            st.markdown("</div>",unsafe_allow_html=True)

def scanner():
    st.markdown("<div class='hero'><div class='hero-top'><div><div class='title'>URL Risk Scanner</div><div class='muted'>Analyze a URL for phishing indicators and threats.</div></div><div class='operational'>SYSTEM OPERATIONAL</div></div><div class='scanrow'>",unsafe_allow_html=True)
    with st.form("scan"):
        url=st.text_input("Enter or paste a URL",value=st.session_state.latest_url,placeholder="https://example.com")
        go=st.form_submit_button("SCAN URL",type="primary",use_container_width=True)
    st.markdown("</div></div>",unsafe_allow_html=True)
    if go:
        if not url.strip():st.warning("Enter a URL before starting a scan.")
        else:
            try:st.session_state.latest=analyze_url_risk(url);st.session_state.latest_url=url;save(st.session_state.latest)
            except Exception as e:st.error(f"The URL could not be scanned safely: {e}")
    scan_result(st.session_state.latest) if st.session_state.latest else landing()

def history_page():
    heading("Scan History","Review previous URL assessments.");f=history();scores=pd.to_numeric(f["Risk Score"],errors="coerce")
    m=st.columns(4);vals=[len(f),int((f["Risk Level"]=="Low").sum()),int((f["Risk Level"]=="Medium").sum()),int(f["Risk Level"].isin(["High","Critical"]).sum())]
    for c,l,v in zip(m,["Total Scans","Safe","Suspicious","High / Critical"],vals):
        with c:metric(l,v,"Recorded assessments",tone("Low"))
    st.markdown("<div class='section'>Assessment Records</div>",unsafe_allow_html=True)
    if f.empty:st.info("No scans have been recorded yet.")
    else:st.dataframe(f[["Timestamp","URL","Risk Score","Risk Level","Verdict"]],hide_index=True,use_container_width=True)
    with st.expander("History controls"):
        if st.checkbox("I understand this permanently removes all local scan history.") and st.button("Clear history"):
            with HISTORY.open("w",newline="",encoding="utf-8") as h:csv.DictWriter(h,fieldnames=FIELDS).writeheader()
            st.rerun()
def urls_from(u):
    raw=u.getvalue()
    if u.name.lower().endswith(".txt"):return [s.strip() for s in raw.decode("utf-8",errors="replace").splitlines() if s.strip()]
    f=pd.read_csv(io.BytesIO(raw));col=next((c for c in f.columns if str(c).lower()=="url"),f.columns[0] if len(f.columns) else None);return [] if col is None else [str(v).strip() for v in f[col].dropna() if str(v).strip()]
def batch_page():
    heading("Batch URL Scanner","Analyze multiple URLs in one operation.");a,b=st.columns(2)
    with a:st.markdown("<div class='cap'><b>TXT</b><p>One URL per line</p></div>",unsafe_allow_html=True)
    with b:st.markdown("<div class='cap'><b>CSV</b><p>URL column or first column</p></div>",unsafe_allow_html=True)
    u=st.file_uploader("Upload URL list",type=["txt","csv"])
    if u and st.button("ANALYZE BATCH",type="primary"):
        try:urls=urls_from(u)
        except Exception as e:st.error(f"Could not read this file: {e}");urls=[]
        if not urls:st.error("No usable URLs were found in the upload.")
        else:
            bar=st.progress(0);rows=[]
            for i,url in enumerate(urls,1):
                r=analyze_url_risk(url);save(r);rows.append({"URL":r.get("url",url),"Risk Score":r.get("risk_score","—"),"Risk Level":r.get("risk_level","—"),"Verdict":r.get("verdict","—"),"ML Score":r.get("model_score") if r.get("model_score") is not None else "Unavailable","Heuristic Score":r.get("heuristic_score","—")});bar.progress(i/len(urls))
            st.session_state.batch=pd.DataFrame(rows)
    f=st.session_state.batch
    if f is not None and not f.empty:
        s=pd.to_numeric(f["Risk Score"],errors="coerce");m=st.columns(5);vals=[len(f),int((f["Risk Level"]=="Low").sum()),int((f["Risk Level"]=="Medium").sum()),int(f["Risk Level"].isin(["High","Critical"]).sum()),f"{s.mean():.1f}" if s.notna().any() else "—"]
        for c,l,v in zip(m,["Total","Safe","Suspicious","High / Critical","Average Risk"],vals):
            with c:metric(l,v,"Batch result",tone("Low"))
        st.dataframe(f,hide_index=True,use_container_width=True);st.download_button("DOWNLOAD CSV",f.to_csv(index=False).encode(),"phishguard_batch_results.csv","text/csv")
def analytics():
    heading("Analytics","Risk patterns from structured scan history.");f=history();s=pd.to_numeric(f["Risk Score"],errors="coerce");f=f[s.notna()].copy()
    if f.empty:st.info("Analytics will appear after structured scans are recorded.");return
    f["Risk Score"]=pd.to_numeric(f["Risk Score"]);m=st.columns(5);vals=[len(f),int((f["Risk Level"]=="Low").sum()),int((f["Risk Level"]=="Medium").sum()),int(f["Risk Level"].isin(["High","Critical"]).sum()),f"{f['Risk Score'].mean():.1f}"]
    for c,l,v in zip(m,["Total Scans","Safe","Suspicious","High / Critical","Average Risk"],vals):
        with c:metric(l,v,"History insights",tone("Low"))
    a,b=st.columns(2)
    with a:st.subheader("Risk-level distribution");st.bar_chart(f["Risk Level"].value_counts().reindex(["Low","Medium","High","Critical"],fill_value=0),color="#46bde8")
    with b:
        st.subheader("Risk-score distribution")
        if len(f)>1:st.bar_chart(pd.cut(f["Risk Score"],[-1,24,49,74,100],labels=["0–24","25–49","50–74","75–100"]).value_counts().sort_index(),color="#46bde8")
        else:st.caption("At least two structured scans are needed.")
def about():
    heading("About PhishGuard","URL threat intelligence for assistive security screening.")
    cards=[("What is PhishGuard?","An explainable URL-risk assessment tool for phishing indicators and suspicious URL structures."),("How It Works","It combines the existing classifier with transparent structural heuristic signals."),("What It Checks","Protocol, domains, TLDs, IP hosts, keywords, encoding, ports, and URL structure."),("Limitations","The ML score is a classifier signal, not a real-world probability. Trusted domains are not guarantees."),("Security Disclaimer","Use PhishGuard as an assistive layer, not a replacement for investigation, reputation checks, or security controls.")]
    for t,d in cards:st.markdown(f"<div class='about-card'><b>{t}</b><br><span class='muted'>{d}</span></div>",unsafe_allow_html=True)
def sidebar():
    with st.sidebar:
        st.markdown("<div class='brand'>PHISHGUARD</div><div class='kicker'>URL Threat Intelligence</div><div class='navspacer'></div><div class='navlabel'>Navigation</div>",unsafe_allow_html=True)
        nav=[("▣  Scanner","Scanner"),("▤  Scan History","Scan History"),("⇧  Batch Scanner","Batch Scanner"),("◈  Analytics","Analytics"),("ⓘ  About","About")]
        for label,key in nav:
            if st.button(label,key="nav_"+key,use_container_width=True,type="primary" if st.session_state.page==key else "secondary"):st.session_state.page=key;st.rerun()
        st.markdown("<div class='status'><div class='kicker'>System Status</div>",unsafe_allow_html=True)
        if model_status():st.markdown("<b style='color:#72dfad'>● ML + HEURISTIC MODE</b><br><span class='muted'>ML model ready</span>",unsafe_allow_html=True)
        else:st.markdown("<b class='dot'>● HEURISTIC MODE</b><br><span class='muted'>ML model unavailable<br>Structural analysis active</span>",unsafe_allow_html=True)
        st.markdown("</div>",unsafe_allow_html=True)
def main():
    setup();sidebar();{"Scanner":scanner,"Scan History":history_page,"Batch Scanner":batch_page,"Analytics":analytics,"About":about}[st.session_state.page]()
if __name__=="__main__":main()
