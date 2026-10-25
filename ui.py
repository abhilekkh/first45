"""First45 shared look: navbar, light/dark theme, subtle animated background.

Every page calls ui.setup(page) as its first Streamlit command. The theme is one
set of colour tokens (CSS variables) per mode, so custom HTML and Streamlit's own
widgets switch together.
"""
from __future__ import annotations

import html

import streamlit as st

REPO_URL = "https://github.com/abhilekkh/first45"

# Colour tokens per mode. Severity colours are shared by both pages.
THEMES = {
    "dark": {
        "bg": "#0b0f14", "surface": "#11161d", "surface2": "#161c25", "border": "#232c38",
        "text": "#e6edf3", "muted": "#8b98a5", "accent": "#4d8dff", "accent-ink": "#ffffff",
        "dot": "rgba(139,152,165,.16)", "glow": "rgba(77,141,255,.07)",
        "crit": "#ff5c5c", "high": "#ff8a3d", "med": "#f2b33d", "low": "#7d8b99", "ok": "#3fb97a",
        "code": "#0e131a",
    },
    "light": {
        "bg": "#f6f7f9", "surface": "#ffffff", "surface2": "#f1f3f6", "border": "#e2e6eb",
        "text": "#101828", "muted": "#5b6675", "accent": "#1f5eff", "accent-ink": "#ffffff",
        "dot": "rgba(16,24,40,.10)", "glow": "rgba(31,94,255,.06)",
        "crit": "#d92d2d", "high": "#e0611a", "med": "#b7791f", "low": "#64748b", "ok": "#1f8f55",
        "code": "#f3f5f8",
    },
}

LOGO = """<svg width="26" height="26" viewBox="0 0 32 32" fill="none" aria-hidden="true">
<path d="M16 2.5 4.5 7v8.2c0 6.6 4.8 12.4 11.5 14.3 6.7-1.9 11.5-7.7 11.5-14.3V7L16 2.5Z"
 stroke="var(--accent)" stroke-width="2.2" stroke-linejoin="round"/>
<path d="M11 16.2l3.4 3.4L21.5 12.5" stroke="var(--accent)" stroke-width="2.2"
 stroke-linecap="round" stroke-linejoin="round"/></svg>"""


def _css(mode: str) -> str:
    t = THEMES[mode]
    tokens = ";".join(f"--{k}:{v}" for k, v in t.items())
    return f"""<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=IBM+Plex+Sans:wght@400;500;600;700&display=swap');
:root{{{tokens};color-scheme:{mode}}}
html,body,.stApp,[data-testid="stAppViewContainer"]{{background:var(--bg)!important;color:var(--text);
  color-scheme:{mode}!important}}
/* Draw radio/checkbox markers from our own tokens so they read correctly in both
   themes (the native color-scheme is overridden by Streamlit's config otherwise). */
.stRadio input[type="radio"],.stCheckbox input[type="checkbox"]{{appearance:none!important;
  -webkit-appearance:none!important;width:15px!important;height:15px!important;flex:0 0 15px;
  border:1.5px solid var(--muted)!important;background:var(--surface)!important;position:relative;
  cursor:pointer;margin:0}}
.stRadio input[type="radio"]{{border-radius:50%}}
.stCheckbox input[type="checkbox"]{{border-radius:4px}}
.stRadio input[type="radio"]:checked,.stCheckbox input[type="checkbox"]:checked{{
  border-color:var(--accent)!important;background:var(--accent)!important}}
.stRadio input[type="radio"]:checked::after{{content:"";position:absolute;inset:4px;border-radius:50%;
  background:var(--accent-ink)}}
.stCheckbox input[type="checkbox"]:checked::after{{content:"";position:absolute;left:4px;top:1px;width:4px;
  height:8px;border:solid var(--accent-ink);border-width:0 2px 2px 0;transform:rotate(45deg)}}
.stApp, .stApp p, .stApp li, .stApp label, .stApp input, .stApp textarea, .stApp button,
.stApp [data-testid="stMarkdownContainer"]{{font-family:'IBM Plex Sans',system-ui,-apple-system,'Segoe UI',sans-serif}}
[data-testid="stIconMaterial"],.material-symbols-rounded{{font-family:'Material Symbols Rounded'!important}}
.stApp code, .stApp pre, .stApp pre *{{font-family:'IBM Plex Mono',ui-monospace,Consolas,monospace!important}}
h1,h2,h3,h4{{color:var(--text)!important;letter-spacing:-.015em;font-family:'IBM Plex Sans',sans-serif!important}}
.stApp a{{color:var(--accent)}}

/* ---- calm STATIC background: dot grid + soft light (no animation = no lag) ----
   The old version animated two full-viewport fixed layers forever (one of them
   masked), which repaints every frame and makes the whole app feel sluggish and
   drops clicks. A static background looks the same at rest and costs nothing. */
.stApp::before{{content:"";position:fixed;inset:0;z-index:0;pointer-events:none;
  background-image:radial-gradient(var(--dot) 1px,transparent 1.2px);background-size:26px 26px;
  -webkit-mask-image:radial-gradient(ellipse 80% 55% at 50% 0%,#000 40%,transparent 100%);
  mask-image:radial-gradient(ellipse 80% 55% at 50% 0%,#000 40%,transparent 100%)}}
.stApp::after{{content:"";position:fixed;z-index:0;pointer-events:none;width:900px;height:720px;
  left:50%;top:-460px;transform:translateX(-50%);border-radius:50%;opacity:.8;
  background:radial-gradient(circle,var(--glow),transparent 65%)}}
[data-testid="stAppViewContainer"]>*,[data-testid="stMain"]{{position:relative;z-index:1}}

/* ---- chrome: hide Streamlit header + page list (we have our own navbar) ---- */
header[data-testid="stHeader"]{{background:transparent;height:0}}
[data-testid="stToolbar"],[data-testid="stDecoration"],[data-testid="stSidebarNav"]{{display:none!important}}
.block-container{{padding-top:0!important;max-width:1180px}}
section[data-testid="stSidebar"]{{background:var(--surface)!important;border-right:1px solid var(--border)}}

/* ---- navbar ---- */
/* Full-width bar via a cheap 100vw pseudo-element instead of a 100vmax box-shadow
   (that shadow repainted a viewport-sized layer on every scroll = jank). */
.st-key-f45nav{{position:sticky;top:0;z-index:50;margin-bottom:30px;padding:10px 0;background:var(--bg)}}
.st-key-f45nav::before{{content:"";position:absolute;top:0;bottom:0;left:50%;width:100vw;
  transform:translateX(-50%);background:var(--bg);border-bottom:1px solid var(--border);z-index:-1}}
.st-key-f45nav [data-testid="stHorizontalBlock"]{{align-items:center;gap:.5rem;flex-wrap:nowrap!important}}
.st-key-f45nav [data-testid="stColumn"]{{min-width:0!important;width:auto!important}}
@media (max-width:900px){{.f45-brand small{{display:none}}
  .st-key-f45nav [data-testid="stColumn"]:nth-child(2){{display:none}}
  .st-key-f45nav [data-testid="stHorizontalBlock"]{{gap:.25rem}}
  .st-key-f45nav [data-testid="stPageLink"] a{{padding:4px 6px}}}}
@media (max-width:640px){{.st-key-f45nav [data-testid="stColumn"]:nth-child(5){{display:none}}}}
.f45-brand{{display:flex;align-items:center;gap:10px;font-weight:700;font-size:1.08rem;color:var(--text)}}
.f45-brand small{{font-weight:500;color:var(--muted);font-size:.78rem;border-left:1px solid var(--border);
  padding-left:10px;margin-left:2px}}
.st-key-f45nav [data-testid="stPageLink"] a{{border-radius:6px;padding:7px 12px;background:transparent;
  display:flex;align-items:center;min-height:36px}}
/* give every nav control a comfortable click target */
.st-key-f45nav .stButton button{{min-height:38px}}
.st-key-f45nav [data-testid="stPageLink"] a p{{color:var(--muted)!important;font-weight:500;font-size:.92rem;
  white-space:nowrap;overflow:visible}}
.st-key-f45nav [data-testid="stPageLink"],.st-key-f45nav [data-testid="stPageLink"] *{{overflow:visible!important;
  text-overflow:clip!important;max-width:none!important}}
.st-key-f45nav [data-testid="stPageLink"] a:hover p{{color:var(--text)!important}}
.st-key-f45nav [data-testid="stPageLink-NavLink"][aria-current="page"] p,
.st-key-f45nav a[aria-current="page"] p{{color:var(--text)!important}}
.f45-ext a{{color:var(--muted)!important;text-decoration:none;font-size:.92rem;font-weight:500}}
.f45-ext a:hover{{color:var(--text)!important}}

/* ---- hero + section titles ---- */
.f45-eyebrow{{font-family:'IBM Plex Mono',monospace;font-size:.76rem;letter-spacing:.08em;text-transform:uppercase;
  color:var(--accent);margin-bottom:.5rem}}
.f45-h1{{font-size:clamp(1.7rem,3.2vw,2.5rem);font-weight:700;line-height:1.15;letter-spacing:-.025em;
  color:var(--text);margin:0 0 .6rem;max-width:840px}}
.f45-lead{{color:var(--muted);font-size:1.02rem;max-width:760px;line-height:1.6;margin-bottom:1.4rem}}
.f45-section{{font-size:1.18rem;font-weight:600;color:var(--text);margin:1.2rem 0 .7rem}}
.f45-muted{{color:var(--muted)}}

/* ---- step bar (st.radio with key="step") ---- */
.st-key-step [role="radiogroup"]{{display:flex;gap:0;border:1px solid var(--border);border-radius:8px;
  overflow:hidden;background:var(--surface);width:fit-content;flex-wrap:wrap}}
.st-key-step [role="radiogroup"] label{{margin:0!important;padding:9px 18px;border-right:1px solid var(--border);
  cursor:pointer}}
.st-key-step [role="radiogroup"] label:last-child{{border-right:none}}
.st-key-step label[data-testid="stRadioOption"]>div>div:first-child{{display:none}}
.st-key-step [role="radiogroup"] label p{{color:var(--muted)!important;font-weight:500;font-size:.9rem}}
.st-key-step label[data-selected="true"]{{background:var(--surface2);box-shadow:inset 0 -2px 0 var(--accent)}}
.st-key-step label[data-selected="true"] p{{color:var(--text)!important}}

/* ---- cards, metrics, buttons ---- */
[data-testid="stVerticalBlockBorderWrapper"]:has(>div>[data-testid="stVerticalBlock"]),
[data-testid="stExpander"] details{{background:var(--surface);border:1px solid var(--border)!important;border-radius:10px}}
[data-testid="stMetric"]{{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:14px 16px}}
[data-testid="stMetricLabel"] p{{color:var(--muted)!important;font-size:.8rem;text-transform:uppercase;letter-spacing:.05em}}
[data-testid="stMetricValue"]{{font-family:'IBM Plex Mono',monospace;font-weight:500}}
.stButton button,.stDownloadButton button{{border-radius:7px;font-weight:500;border:1px solid var(--border);
  background:var(--surface);color:var(--text);transition:border-color .15s,background .15s}}
.stButton button:hover,.stDownloadButton button:hover{{border-color:var(--accent);color:var(--text)}}
.stButton button[kind="primary"],.stButton button[data-testid="stBaseButton-primary"]{{background:var(--accent);
  border-color:var(--accent);color:var(--accent-ink)}}
.stButton button[kind="primary"] p,.stButton button[data-testid="stBaseButton-primary"] p{{color:var(--accent-ink)!important}}
.stButton button[kind="primary"]:hover{{filter:brightness(1.08)}}
.stButton button:disabled{{opacity:.42;cursor:not-allowed;filter:none}}
[data-testid="stPopoverButton"]{{background:var(--surface)!important;color:var(--text)!important;
  border:1px solid var(--border)!important;border-radius:7px}}
[data-testid="stPopoverButton"]:hover{{border-color:var(--accent)!important}}
[data-testid="stPopoverButton"] p{{color:var(--text)!important}}
.f45-ev+div,.f45-ev{{margin-bottom:.35rem}}
[data-testid="stAlert"]{{border-radius:8px}}
[data-testid="stCode"] pre,.stCode pre{{background:var(--code)!important;border:1px solid var(--border);border-radius:8px}}

/* ---- badges + kill chain ---- */
.f45-badge{{display:inline-block;font-family:'IBM Plex Mono',monospace;font-size:.72rem;font-weight:500;
  letter-spacing:.06em;text-transform:uppercase;padding:3px 8px;border-radius:4px;border:1px solid currentColor}}
.b-crit{{color:var(--crit)}}.b-high{{color:var(--high)}}.b-med{{color:var(--med)}}.b-low{{color:var(--low)}}
.b-ok{{color:var(--ok)}}.b-acc{{color:var(--accent)}}
.f45-dot{{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:8px;vertical-align:middle}}
.d-crit{{background:var(--crit)}}.d-high{{background:var(--high)}}.d-med{{background:var(--med)}}
.d-low{{background:var(--low)}}.d-ok{{background:var(--ok)}}
.f45-host{{display:flex;align-items:center;gap:12px;flex-wrap:wrap}}
.f45-host b{{font-size:1.12rem;font-family:'IBM Plex Mono',monospace;font-weight:500}}
.f45-host span.role{{color:var(--muted);font-size:.88rem}}
.f45-patch{{font-size:.88rem;margin-top:2px}}
.chain{{display:flex;gap:6px;flex-wrap:wrap;align-items:center;margin:10px 0 6px}}
.chain .sep{{color:var(--border);font-size:.9rem}}
.chip{{padding:4px 10px;border-radius:5px;font-size:.8rem;font-weight:500;border:1px solid var(--border);
  color:var(--muted);background:transparent;opacity:.55}}
.chip.on{{opacity:1;color:#fff;border-color:transparent}}
.chip.prev{{opacity:1;color:var(--ok);border-color:var(--ok);text-decoration:line-through}}
.s-recon.on{{background:var(--low)}}.s-exploit_attempt.on{{background:var(--med)}}.s-web_shell.on{{background:var(--high)}}
.s-loader_download.on{{background:var(--high)}}.s-c2_contact.on{{background:var(--crit)}}
.s-ddos.on{{background:#7a1f1f}}
.f45-summary{{display:flex;gap:22px;flex-wrap:wrap;font-size:1rem;margin:.2rem 0 1rem}}
.f45-summary span{{display:flex;align-items:center}}
.f45-ev{{font-family:'IBM Plex Mono',monospace;font-size:.8rem;color:var(--muted)}}
.f45-foot{{margin-top:48px;padding:18px 0 8px;border-top:1px solid var(--border);color:var(--muted);
  font-size:.82rem;display:flex;justify-content:space-between;flex-wrap:wrap;gap:8px}}

/* ---- NATIVE Streamlit widgets: driven by the same tokens so they switch with the theme ---- */
/* text inputs, number inputs, text areas */
.stTextInput input,.stNumberInput input,.stTextArea textarea,[data-baseweb="input"],
[data-baseweb="textarea"],[data-baseweb="base-input"]{{background:var(--surface2)!important;
  color:var(--text)!important;border-color:var(--border)!important;caret-color:var(--text)}}
.stTextInput input::placeholder,.stTextArea textarea::placeholder{{color:var(--muted)!important}}
.stTextInput div[data-baseweb="input"],.stTextArea div[data-baseweb="textarea"]{{border-radius:7px}}
.stTextInput input:focus,.stTextArea textarea:focus,
div[data-baseweb="input"]:focus-within,div[data-baseweb="textarea"]:focus-within{{
  border-color:var(--accent)!important;box-shadow:0 0 0 1px var(--accent)}}
/* selectbox / multiselect / popover triggers (baseweb select + popovers) */
[data-baseweb="select"]>div,[data-baseweb="select"] div[role="button"]{{background:var(--surface2)!important;
  border-color:var(--border)!important;color:var(--text)!important}}
[data-baseweb="popover"] [role="listbox"],[data-baseweb="menu"],[data-baseweb="menu"] li,
[data-baseweb="popover"] div{{background:var(--surface)!important;color:var(--text)!important}}
[data-baseweb="menu"] li:hover{{background:var(--surface2)!important}}
/* radio + checkbox labels and marks */
.stRadio label p,.stCheckbox label p,.stToggle label p,.stSlider label,.stSelectbox label,
.stTextInput label,.stTextArea label,.stNumberInput label,.stFileUploader label,
.stRadio label,.stCheckbox label{{color:var(--text)!important}}
[data-testid="stWidgetLabel"] p,[data-testid="stWidgetLabel"]{{color:var(--muted)!important}}
/* file uploader dropzone */
[data-testid="stFileUploaderDropzone"],[data-testid="stFileUploader"] section{{
  background:var(--surface2)!important;border:1px dashed var(--border)!important;color:var(--text)!important}}
[data-testid="stFileUploaderDropzone"] *{{color:var(--text)!important}}
/* slider track + handle */
.stSlider [data-baseweb="slider"] [role="slider"]{{background:var(--accent)!important}}
.stSlider [data-baseweb="slider"] div[data-testid="stSliderTrack"]{{background:var(--border)!important}}
.stSlider [data-testid="stThumbValue"],.stSlider [data-testid="stTickBarMin"],
.stSlider [data-testid="stTickBarMax"]{{color:var(--muted)!important}}
/* toggle + checkbox box */
[data-baseweb="checkbox"] span[data-testid="stWidgetLabel"]{{color:var(--text)!important}}
.stCheckbox [data-baseweb="checkbox"] div:first-child,
[role="checkbox"]{{border-color:var(--border)!important}}
[role="checkbox"][aria-checked="true"],[data-baseweb="checkbox"] [aria-checked="true"]{{
  background:var(--accent)!important;border-color:var(--accent)!important}}
/* segmented control (the theme switch + any other) */
[data-testid="stSegmentedControl"] button,div[data-baseweb="button-group"] button{{
  background:var(--surface)!important;color:var(--muted)!important;border-color:var(--border)!important}}
[data-testid="stSegmentedControl"] button[aria-checked="true"],
[data-testid="stSegmentedControl"] button[kind="segmented_controlActive"]{{
  background:var(--surface2)!important;color:var(--text)!important;box-shadow:inset 0 -2px 0 var(--accent)}}
/* dataframe / tables */
[data-testid="stDataFrame"],[data-testid="stDataFrameResizable"],.stDataFrame{{
  background:var(--surface)!important;border:1px solid var(--border)!important;border-radius:8px}}
[data-testid="stDataFrame"] [role="columnheader"],[data-testid="stDataFrame"] [role="gridcell"]{{
  background:var(--surface)!important;color:var(--text)!important;border-color:var(--border)!important}}
[data-testid="stTable"] table,[data-testid="stTable"] th,[data-testid="stTable"] td{{
  background:var(--surface)!important;color:var(--text)!important;border-color:var(--border)!important}}
/* expander header, popover panel, toasts, tabs */
[data-testid="stExpander"] summary,[data-testid="stExpander"] summary p{{color:var(--text)!important}}
[data-testid="stExpander"] summary:hover{{color:var(--accent)!important}}
[data-testid="stExpander"] details>div{{background:var(--surface)!important}}
[data-testid="stPopoverBody"],[data-testid="stPopover"] [data-baseweb="popover"] div{{
  background:var(--surface)!important;color:var(--text)!important;border-color:var(--border)!important}}
[data-testid="stToast"]{{background:var(--surface)!important;color:var(--text)!important;
  border:1px solid var(--border)!important}}
.stTabs [data-baseweb="tab"]{{color:var(--muted)!important}}
.stTabs [aria-selected="true"]{{color:var(--text)!important}}
/* progress bar + spinner */
.stProgress [data-testid="stProgressBar"]>div{{background:var(--accent)!important}}
.stProgress [data-testid="stProgressBar"]{{background:var(--border)!important}}
/* alerts keep readable text in both modes */
[data-testid="stAlert"]{{color:var(--text)}}
[data-testid="stAlert"] p,[data-testid="stAlert"] div{{color:var(--text)!important}}
/* metric delta + help icons */
[data-testid="stMetricDelta"]{{color:var(--muted)!important}}
.stMarkdown,.stCaption,[data-testid="stCaptionContainer"] p{{color:var(--muted)}}
.stApp p,.stApp li{{color:var(--text)}}
</style>"""


def setup(page: str, title: str) -> str:
    """Page config + theme + navbar. Returns the active mode ('light' or 'dark')."""
    st.set_page_config(page_title=title, page_icon=":material/shield:", layout="wide",
                       initial_sidebar_state="collapsed")
    ss = st.session_state
    ss.setdefault("theme", "dark")           # one source of truth, shared across both pages
    if ss.theme not in THEMES:
        ss.theme = "dark"
    active = {"app": 3, "device": 4}.get(page, 0)
    st.markdown(_css(ss.theme) + f"""<style>.st-key-f45nav [data-testid="stColumn"]:nth-child({active}) a p
      {{color:var(--text)!important;font-weight:600}}
      .st-key-f45nav [data-testid="stColumn"]:nth-child({active}) a{{box-shadow:inset 0 -2px 0 var(--accent);
      border-radius:0}}</style>""", unsafe_allow_html=True)

    with st.container(key="f45nav"):
        brand, gap, l1, l2, ext, mode = st.columns([3.2, 1.2, 1.5, 1.3, 0.9, 1.5], vertical_alignment="center")
        brand.markdown(f'<div class="f45-brand">{LOGO}First45<small>Advisory to defense</small></div>',
                       unsafe_allow_html=True)
        l1.page_link("app.py", label="Server defense")
        l2.page_link("pages/2_Device_Guard.py", label="Device Guard")
        ext.markdown(f'<div class="f45-ext"><a href="{REPO_URL}" target="_blank">GitHub</a></div>',
                     unsafe_allow_html=True)
        # A plain button is the most reliable single-click switch: a click returns True
        # on that same run, with none of segmented_control's default-vs-stored-state
        # quirks. It shows the mode it will switch TO; ss.theme (shared session_state)
        # carries the choice across both pages.
        switch_to = "light" if ss.theme == "dark" else "dark"
        if mode.button(f"{switch_to.title()} mode", key=f"theme_btn_{page}", width="stretch"):
            ss.theme = switch_to
            st.rerun()                       # re-inject the CSS for the new mode
    return ss.theme


def hero(eyebrow: str, title: str, lead: str) -> None:
    st.markdown(f'<div class="f45-eyebrow">{html.escape(eyebrow)}</div>'
                f'<div class="f45-h1">{html.escape(title)}</div>'
                f'<div class="f45-lead">{lead}</div>', unsafe_allow_html=True)


def section(text: str) -> None:
    st.markdown(f'<div class="f45-section">{html.escape(text)}</div>', unsafe_allow_html=True)


def badge(text: str, level: str) -> str:
    return f'<span class="f45-badge b-{level}">{html.escape(text)}</span>'


def footer() -> None:
    st.markdown('<div class="f45-foot"><span>First45 · MIT licence · Gemma 4 (Apache 2.0) via the Gemini API</span>'
                '<span>AI recommends. A human decides.</span></div>', unsafe_allow_html=True)
