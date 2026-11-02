import html

import joblib
import streamlit as st

import phish_utils as pu
import security as sec

st.set_page_config(page_title="PhishCheck", page_icon="🛡️")

CHECKS_PER_MINUTE_SESSION = 10     # per visitor session
CHECKS_PER_MINUTE_GLOBAL = 60      # all visitors together (protects the redirect resolver)
MAX_QR_LINKS = 3                   # links read from one QR image
LEGIT_CUTOFF = 0.80                # model legit score needed for "Likely legit"; 0.5 up to this = "Not sure"
STATUS_TEXT = {
    200: "OK (page loaded)",
    301: "Moved permanently",
    302: "Moved temporarily",
    303: "See other",
    307: "Temporary redirect",
    308: "Permanent redirect",
    403: "Access refused",
    404: "Page not found",
}


def h(s):
    """Minify HTML to one line so Markdown never turns indentation or blank lines into code blocks."""
    return " ".join(line.strip() for line in s.splitlines())


def esc(x):
    return html.escape(str(x))


CSS = """
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');
.stApp{background:#fffff4;color:#14213d;font-family:'Inter',system-ui,-apple-system,'Segoe UI',sans-serif;}
.stApp,[data-testid="stMain"]{overflow-x:hidden;}
#MainMenu,footer,header[data-testid="stHeader"]{display:none;}
.block-container{max-width:760px;padding:3.5rem 1rem 3rem;}
.pc-nav{position:fixed;top:0;left:0;right:0;height:56px;background:#0b1b33;display:flex;align-items:center;justify-content:space-between;padding:0 28px;z-index:1000;color:#fff;}
.pc-brand{display:flex;align-items:center;gap:10px;font-weight:700;font-size:17px;}
.pc-nav span.r{color:#9fb0cc;font-size:13px;}
div.pc-hero{margin:0 calc(50% - 50vw) 28px;width:100vw;background:#f3f3ea;padding:40px 20px 34px;text-align:center;}
.pc-pill{display:inline-block;background:#e7f8ee;color:#127a45;border:1px solid #8fd6b0;border-radius:999px;padding:3px 12px;font-size:12px;font-weight:600;}
div.pc-hero h1{font-size:34px;font-weight:800;color:#0b1b33;margin:14px 0 10px;padding:0;line-height:1.15;letter-spacing:-0.02em;}
div.pc-hero p{color:#4b5a75;font-size:14px;max-width:520px;margin:0 auto;line-height:1.5;}
[data-testid="stForm"]{background:#fff;border:1px solid #dfe2e8;border-radius:12px;padding:28px;}
[data-testid="stWidgetLabel"] p{font-weight:600;font-size:13px;color:#14213d;}
[data-baseweb="input"],[data-baseweb="base-input"]{background:#fff;border-radius:8px;}
[data-baseweb="input"]{border:1px solid #d5d9e2;}
[data-testid="stTextInput"] input{color:#14213d;padding:12px 14px;}
.pc-or{display:flex;align-items:center;gap:14px;color:#8a94a8;font-size:11px;letter-spacing:.08em;margin:10px 0 14px;}
.pc-or:before,.pc-or:after{content:"";flex:1;height:1px;background:#e3e6ec;}
[data-testid="stFileUploaderDropzone"]{border:1.5px dashed #1f3a6b;border-radius:8px;background:#fffff4;min-height:150px;justify-content:center;padding:28px;color:#14213d;}
[data-testid="stFileUploaderDropzone"] button{background:#fff;border:1px solid #c9cfdb;color:#14213d;border-radius:8px;}
.pc-note{font-size:12px;color:#5b6780;margin:12px 0 18px;}
.pc-note b{color:#16a34a;}
[data-testid="stFormSubmitButton"],[data-testid="stFormSubmitButton"]>div{width:100% !important;}
[data-testid="stFormSubmitButton"] button{width:100% !important;background:#2b5fc0;border:none;border-radius:8px;padding:12px 0;}
[data-testid="stFormSubmitButton"] button p{color:#fff;font-weight:600;font-size:15px;}
[data-testid="stFormSubmitButton"] button:hover{background:#244f9f;}
[data-testid="stFormSubmitButton"] button:focus-visible{outline:2px solid #0b1b33;outline-offset:2px;}
[data-testid="stVerticalBlockBorderWrapper"]:has(.pc-res){background:#fff;border:1px solid #dfe2e8;border-radius:12px;padding:12px 14px;margin-top:24px;}
.pc-head{display:flex;justify-content:space-between;align-items:center;font-size:12px;font-weight:600;color:#4b5a75;letter-spacing:.04em;margin-bottom:14px;}
.pc-tag{background:#f1f3f7;border-radius:4px;padding:4px 8px;font-size:10px;color:#3b475c;}
.pc-dot{display:inline-block;width:6px;height:6px;border-radius:50%;background:#d92d20;margin-right:6px;}
.pc-banner{border-radius:8px;padding:14px 16px;margin:4px 0 18px;border:1px solid;font-size:13px;line-height:1.45;}
.pc-banner b{display:block;font-size:17px;margin-bottom:4px;}
.pc-banner.bad{background:#fde4e4;border-color:#f3a7a7;color:#b42318;}
.pc-banner.ok{background:#e4f7ec;border-color:#8fd6b0;color:#146c43;}
.pc-banner.mid{background:#fff3d6;border-color:#f0c96a;color:#8a5a00;}
.pc-sub{font-size:11px;font-weight:700;color:#14213d;letter-spacing:.04em;margin:6px 0 8px;}
.pc-check{display:flex;gap:10px;margin:10px 0;}
.pc-ic{flex:none;width:16px;height:16px;border-radius:50%;display:grid;place-items:center;font-size:10px;font-weight:700;color:#fff;margin-top:2px;}
.pc-ic.fail{background:#d92d20;}
.pc-ic.pass{background:#16a34a;}
.pc-ic.warn{background:#d99100;}
.pc-ic.info{background:#7a869c;}
.pc-check .t{font-size:13px;font-weight:600;color:#14213d;}
.pc-check .d{font-size:12px;color:#5b6780;}
.pc-foot{text-align:center;font-size:12px;color:#6a7589;margin-top:24px;line-height:1.5;}
"""

st.markdown("<style>" + h(CSS) + "</style>", unsafe_allow_html=True)


@st.cache_resource
def load_artifacts():
    art = joblib.load("phishcheck_final.joblib")
    pu.TRANCO_SET = art["tranco"]
    pu.SHORTENER_DOMAINS = art["shorteners"]
    return art


@st.cache_resource
def global_limiter():
    return sec.RateLimiter(CHECKS_PER_MINUTE_GLOBAL, 60)


art = load_artifacts()

if "limiter" not in st.session_state:
    st.session_state.limiter = sec.RateLimiter(CHECKS_PER_MINUTE_SESSION, 60)

n_db = pu.phish_db_count()
db_text = (f"Known-phishing database: {n_db:,} reported links" if n_db
           else "Database not loaded: using the model only")

st.markdown(h(f"""
<div class="pc-nav">
<div class="pc-brand">
<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/><path d="M9 12l2 2 4-4"/></svg>
PhishCheck</div>
<span class="r">Link and QR scanner</span>
</div>
<div class="pc-hero">
<span class="pc-pill">{esc(db_text)}</span>
<h1>Check a link or QR code for phishing</h1>
<p>Paste a URL or upload a QR image. We follow redirects, then check the destination against a reported-phishing database and a trained model.</p>
</div>
"""), unsafe_allow_html=True)


def allowed():
    ok, wait = st.session_state.limiter.hit()
    if not ok:
        st.warning(f"Too many checks from this session. Please wait {wait:.0f} seconds.")
        return False
    ok, wait = global_limiter().hit()
    if not ok:
        st.warning("The service is busy right now. Please try again in a minute.")
        return False
    return True


def check_row(state, title, desc):
    icon = {"fail": "✕", "pass": "✓", "warn": "!", "info": "i"}[state]
    return (f'<div class="pc-check"><span class="pc-ic {state}">{icon}</span>'
            f'<div><div class="t">{esc(title)}</div><div class="d">{esc(desc)}</div></div></div>')


def show(raw):
    url, err = pu.validate_url_input(raw)
    if err:
        st.error(err)
        return
    if not allowed():
        return
    try:
        with st.spinner("Checking..."):
            r = pu.analyze(url, art)
    except Exception:
        st.error("Something went wrong while checking that link. Please try another one.")
        return
    if "error" in r:
        st.error(r["error"])
        return

    checks = []
    if r["known_phish"]:
        where = "The link you entered" if r["match"] == "original" else "The page this link redirects to"
        kind, title = "bad", "Phishing threat detected"
        msg = f"{where} is in the reported-phishing database. Do not open it."
        checks.append(("fail", "Known-phishing database", f"{where} matches a reported phishing link."))
    else:
        p = r["p_legit"]
        tier = pu.tier_from_score(p, LEGIT_CUTOFF)
        if n_db:
            checks.append(("pass", "Known-phishing database", "No match for this link or the page it redirects to."))
        else:
            checks.append(("info", "Known-phishing database", "Not loaded, so only the model was used."))
        if tier == "legit":
            kind, title = "ok", "Likely legit"
            msg = f"The model is {p * 100:.0f}% confident this link is legitimate."
            checks.append(("pass", "Model assessment", f"Legit score {p * 100:.0f}%, above the {LEGIT_CUTOFF:.0%} cutoff."))
        elif tier == "unsure":
            kind, title = "mid", "Unverified"
            msg = (f"{p * 100:.0f}% legit score. The model leans legit but can't confirm it. "
                   "Don't enter passwords or payment details until you've checked the site yourself.")
            checks.append(("warn", "Model assessment", f"Legit score {p * 100:.0f}%, below the {LEGIT_CUTOFF:.0%} cutoff."))
        else:
            kind, title = "bad", "Likely phishing"
            msg = f"The model is {(1 - p) * 100:.0f}% confident this link is a scam."
            checks.append(("fail", "Model assessment", f"Legit score {p * 100:.0f}%. The model leans phishing."))

    chain = r["redirect_chain"]
    if r["resolution_error"]:
        checks.append(("warn", "Redirects", "Could not follow all redirects, so the link was checked as typed."))
    elif len(chain) >= 3:
        checks.append(("warn", "Redirects", f"Passes through {len(chain)} redirects before the final page."))
    elif chain:
        checks.append(("info", "Redirects", f"Passes through {len(chain)} redirect(s) before the final page."))
    else:
        checks.append(("pass", "Redirects", "No redirects."))

    rows = "".join(check_row(*c) for c in checks)
    with st.container(border=True):
        st.markdown(h(f"""
<div class="pc-res"></div>
<div class="pc-head"><span>DETECTION PROFILE</span><span class="pc-tag"><i class="pc-dot"></i>ANALYSIS COMPLETE</span></div>
<div class="pc-banner {kind}"><b>{esc(title)}</b>{esc(msg)}</div>
<div class="pc-sub">HEURISTIC CHECKS:</div>{rows}
<div class="pc-sub" style="margin-top:16px">SCANNED DESTINATION</div>
"""), unsafe_allow_html=True)
        # st.code shows text literally, so a crafted link can never render as markdown or a clickable link
        st.code(r["analysis_url"], language=None)
        if chain:
            with st.expander(f"Redirect chain ({len(chain)})"):
                for i, (hop_url, code) in enumerate(chain, start=1):
                    st.caption(f"{i}. HTTP {code} {STATUS_TEXT.get(code, '')}".strip())
                    st.code(hop_url, language=None)


def scan_qr(img):
    arr, err = sec.load_qr_image(img.getvalue())
    if err:
        st.error(err)
        return
    res = pu.scan_qr_from_image(arr)
    if res["ok"]:
        for link in res["data"][:MAX_QR_LINKS]:
            st.caption("QR code contains:")
            st.code(link, language=None)
            show(link)
    elif "not installed" in (res["error"] or ""):
        st.warning("QR scanning is not available on this server.")
    else:
        st.warning("No QR code was found in that image.")


with st.form("scan_form"):
    url = st.text_input("Paste a link to check", placeholder="https://example.com/login", max_chars=4096)
    st.markdown('<div class="pc-or">OR DROP A QR CODE</div>', unsafe_allow_html=True)
    img = st.file_uploader("QR code image", type=["png", "jpg", "jpeg"], label_visibility="collapsed")
    st.markdown(h("""<div class="pc-note"><b>✓</b> Links and images are checked on the server.
This app doesn't save them. PNG or JPG, up to 2 MB.</div>"""), unsafe_allow_html=True)
    submitted = st.form_submit_button("Check link")

if submitted:
    if not url.strip() and img is None:
        st.error("Paste a link or upload a QR image first.")
    else:
        if url.strip():
            show(url)
        if img is not None:
            scan_qr(img)

st.markdown(h(f"""<div class="pc-foot">Results are likely legit (model confidence {LEGIT_CUTOFF:.0%} or higher),
not sure, or likely phishing. These are the model's confidence scores, not probabilities.<br>
A URL-based risk estimate, not a guarantee. Always verify important links yourself.</div>"""),
            unsafe_allow_html=True)
