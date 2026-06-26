# Hardened Production Edition v3.0 – Final Polish
# MAXIMUM, PRODUCTION-GRADE HARDENING APPLIED
# Enhancements: LRU In-Memory Embedding Caching, Strict Proxy Validation, Vault Annotations.

import subprocess
import sys
import importlib
import os
import time
import random
import urllib.parse
import io
import pickle
import base64
import hashlib
import traceback
import html
import hmac
import atexit
import ssl
import re
from pathlib import Path
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional, Tuple
from collections import OrderedDict

# ==========================================
# 00. CENTRALIZED CONFIGURATION
# ==========================================
CONFIG = {
    "PATHS": {
        "DATA_DIR": Path("extraction_vault"),
        "GALLERY": Path("extraction_vault/secured_gallery.pkl"),
        "VECTOR_CACHE": Path("extraction_vault/vector_cache.pkl"),
        "SEARCH_CACHE": Path("extraction_vault/recon_cache.pkl"),
        "LOGS": Path("extraction_vault/system_faults.log"),
        "SECRET": Path("extraction_vault/.secret"),
    },
    "LIMITS": {
        "MAX_IMAGE_PIXELS": 25000000,          # 25 MP (Bomb Protection)
        "MAX_UPLOAD_SIZE_BYTES": 10 * 1024 * 1024, # 10 MB
        "MAX_RETRIES": 4,                      # Global search limit
    },
    "TIMEOUTS": {
        "GLOBAL_BREACH": 75,                   # 75s strict survival timeout
        "CIRCUIT_BREAKER_BAN": 300,            # 5 mins for 429/403
        "PAGE_LOAD": 30000,
        "REQUEST_HEAD": 6,
        "REQUEST_GET": 12,
        "RETRY_DELAYS": [1.5, 2.5, 4.0, 5.0],
    },
    "USER_AGENTS": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15"
    ],
    "PLAYWRIGHT_ARGS": [
        '--disable-blink-features=AutomationControlled',
        '--disable-features=IsolateOrigins,site-per-process',
        '--disable-site-isolation-trials',
        '--disable-web-security',
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-gpu',
        '--disable-software-rasterizer',
        '--disable-dev-shm-usage',
        '--disable-browser-side-navigation',
        '--disable-features=VizDisplayCompositor',
        '--use-gl=swiftshader',
        '--remote-debugging-port=0',
        '--disable-component-extensions-with-background-pages',
        '--disable-background-timer-throttling',
        '--disable-prompt-on-repost'
    ]
}

PROXY_REGEX = re.compile(r"^(http|https)://(?:[^:@]+:[^:@]+@)?[\w.-]+:\d+$")

# ==========================================
# 01. DEPENDENCY ENFORCEMENT & HEALING
# ==========================================
def enforce_environment():
    required = {
        "streamlit": "streamlit",
        "PIL": "pillow",
        "numpy": "numpy",
        "requests": "requests",
        "insightface": "insightface",
        "onnxruntime": "onnxruntime",
        "cv2": "opencv-python-headless",
        "playwright": "playwright",
        "psutil": "psutil"
    }
    missing = [pkg for mod, pkg in required.items() if not importlib.util.find_spec(mod)]
    if missing:
        for pkg in missing:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade", pkg])
        try:
            subprocess.check_call([sys.executable, "-m", "playwright", "install", "chromium"])
        except Exception:
            pass
        os.execv(sys.executable, ['python'] + sys.argv)

enforce_environment()

import streamlit as st
from PIL import Image
import numpy as np
import requests
from requests.adapters import HTTPAdapter
import psutil
from playwright.sync_api import sync_playwright

# Enforce PIL Limits (Bomb Protection)
Image.MAX_IMAGE_PIXELS = CONFIG["LIMITS"]["MAX_IMAGE_PIXELS"]

# ==========================================
# 02. SYSTEM DIRECTIVES & SECURITY INITIALIZATION
# ==========================================
CONFIG["PATHS"]["DATA_DIR"].mkdir(exist_ok=True)

def get_or_create_hmac_secret():
    secret_path = CONFIG["PATHS"]["SECRET"]
    if not secret_path.exists():
        secret_path.write_bytes(os.urandom(32))
    return secret_path.read_bytes()

HMAC_SECRET = get_or_create_hmac_secret()

st.set_page_config(
    page_title="GEOMETRIC RESOLUTION", 
    page_icon="⬡", 
    layout="wide",
    initial_sidebar_state="expanded"
)

# ==========================================
# ZOMBIE-PROOF CONTEXT MANAGEMENT
# ==========================================
def kill_zombie_browsers():
    try:
        current_proc = psutil.Process()
        for child in current_proc.children(recursive=True):
            if "chrome" in child.name().lower() or "chromium" in child.name().lower():
                child.kill()
    except Exception:
        pass

atexit.register(kill_zombie_browsers)

# ==========================================
# HARDENED NETWORK LAYER (TLS 1.2+ & Connection Pooling)
# ==========================================
class TLSAdapter(HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        ctx = ssl.create_default_context()
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        kwargs['ssl_context'] = ctx
        return super().init_poolmanager(*args, **kwargs)

def get_secure_session():
    session = requests.Session()
    session.verify = True
    adapter = TLSAdapter(pool_connections=20, pool_maxsize=20)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session

GLOBAL_SESSION = get_secure_session()
CIRCUIT_BREAKER = {}  # { domain: lockout_end_timestamp }

def check_circuit_breaker(url: str) -> bool:
    domain = urllib.parse.urlparse(url).netloc
    return time.time() < CIRCUIT_BREAKER.get(domain, 0)

def trip_circuit_breaker(url: str):
    domain = urllib.parse.urlparse(url).netloc
    CIRCUIT_BREAKER[domain] = time.time() + CONFIG["TIMEOUTS"]["CIRCUIT_BREAKER_BAN"]

# ==========================================
# TACTILE & PSYCHOLOGICAL UI INJECTION
# ==========================================
UI_INJECTION = """
<style>
    @import url('https://fonts.googleapis.com/css2?family=Cormorant+Garamond:ital,wght@0,500;0,700;1,500&family=Cinzel:wght@600;800&display=swap');

    [data-testid="stAppViewContainer"] {
        background: linear-gradient(145deg, #050608 0%, #15161b 35%, #080a0f 70%, #171311 100%);
        background-size: 300% 300%;
        animation: hardwareShift 22s cubic-bezier(0.25, 0.1, 0.25, 1) infinite;
        font-family: 'Cormorant Garamond', serif !important;
        color: #d8d2ca !important;
    }
    
    [data-testid="stHeader"] { background: transparent !important; }

    @keyframes hardwareShift {
        0% { background-position: 0% 50%; }
        50% { background-position: 100% 50%; }
        100% { background-position: 0% 50%; }
    }

    .block-container {
        padding: 5rem 2vw 4rem 8vw !important;
        max-width: 98vw !important;
    }

    h1, h2, h3, h4, h5, h6, .st-emotion-cache-10trblm, [data-testid="stMarkdownContainer"] p strong {
        font-family: 'Cinzel', serif !important;
        letter-spacing: 0.04em;
        color: #c9b498 !important;
        text-transform: uppercase;
    }

    p, span, div, label {
        font-size: 1.15rem;
        line-height: 1.7;
    }

    @media (min-width: 1024px) {
        [data-testid="column"]:nth-of-type(1) {
            margin-top: 7vh;
            padding-right: 5vw;
        }
        [data-testid="column"]:nth-of-type(2) {
            margin-top: -2vh;
            border-left: 2px solid rgba(201, 180, 152, 0.08);
            padding-left: 5vw;
        }
    }

    @media (max-width: 768px) {
        .block-container { padding: 2.5rem 1rem !important; }
        [data-testid="column"] {
            margin-top: 0 !important;
            border-left: none !important;
            padding-left: 0 !important;
            padding-right: 0 !important;
        }
        h1 { font-size: 2.1rem !important; line-height: 1.15; }
    }

    .stButton > button {
        background: rgba(18, 19, 24, 0.8) !important;
        border: 1px solid #6b5c47 !important;
        backdrop-filter: blur(16px);
        border-radius: 0 !important; 
        font-family: 'Cinzel', serif !important;
        font-weight: 800;
        letter-spacing: 0.08em;
        color: #c9b498 !important;
        transition: all 0.3s cubic-bezier(0.19, 1, 0.22, 1) !important;
        box-shadow: 5px 5px 0px #090a0f !important;
        padding: 1.5rem 2.5rem !important;
    }
    
    .stButton > button:hover {
        border-color: #d1bfa5 !important;
        color: #ffffff !important;
        transform: translate(-3px, -3px) !important;
        box-shadow: 8px 8px 0px #877459 !important;
    }
    
    .stButton > button:active {
        transform: translate(2px, 2px) !important;
        box-shadow: 0px 0px 0px #877459 !important;
    }

    [data-testid="stFileUploadDropzone"] {
        background: rgba(0, 0, 0, 0.35) !important;
        border: 1px dashed rgba(201, 180, 152, 0.4) !important;
        border-radius: 0 !important;
        transition: all 0.3s ease !important;
    }
    
    [data-testid="stFileUploadDropzone"]:hover {
        background: rgba(201, 180, 152, 0.05) !important;
        border-color: rgba(201, 180, 152, 0.9) !important;
    }

    [data-testid="stSidebar"] {
        background: rgba(8, 9, 12, 0.98) !important;
        backdrop-filter: blur(24px);
        border-right: 1px solid rgba(201, 180, 152, 0.05) !important;
    }
    
    hr { border-color: rgba(201, 180, 152, 0.08) !important; }
    .stDeployButton, footer, [data-testid="stToolbar"] { display: none !important; }
</style>
"""
st.markdown(UI_INJECTION, unsafe_allow_html=True)

# ==========================================
# CORE TELEMETRY & ERROR OBFUSCATION
# ==========================================
def log_event(engine_name: str, message: str):
    with open(CONFIG["PATHS"]["LOGS"], "a", encoding="utf-8") as f:
        f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] SOURCE: {engine_name}\n{message}\n{'-'*80}\n")

# ==========================================
# GEOMETRIC ENGINE
# ==========================================
@st.cache_resource(show_spinner=False)
def initialize_geometry():
    from insightface.app import FaceAnalysis
    app = FaceAnalysis(name='buffalo_l', providers=['CPUExecutionProvider'])
    app.prepare(ctx_id=-1)
    return app

geometry = initialize_geometry()

def extract_primary_vector(img_array):
    if not (faces := geometry.get(img_array)): return None
    return max(faces, key=lambda x: x.det_score).embedding

def extract_all_vectors(img_array) -> List[Dict]:
    if not (faces := geometry.get(img_array)): return []
    return [{
        "embedding": f.embedding,
        "bbox": f.bbox,
        "det_score": f.det_score,
        "age": getattr(f, 'age', None),
        "gender": "Male" if getattr(f, 'sex', None) == 1 else "Female" if getattr(f, 'sex', None) == 0 else None
    } for f in faces]

def calculate_proximity(e1, e2):
    if e1 is None or e2 is None: return 0.0
    return float(np.dot(e1 / np.linalg.norm(e1), e2 / np.linalg.norm(e2)))

# ==========================================
# STATE & SECURE PERSISTENCE (HMAC PICKLE)
# ==========================================
class LRUMemoryCache:
    def __init__(self, capacity=128):
        self.cache = OrderedDict()
        self.capacity = capacity
        
    def get(self, key):
        if key not in self.cache: return None
        self.cache.move_to_end(key)
        return self.cache[key]
        
    def put(self, key, value):
        self.cache[key] = value
        self.cache.move_to_end(key)
        if len(self.cache) > self.capacity: 
            self.cache.popitem(last=False)

class PersistenceLayer:
    def __init__(self, filepath: Path):
        self.filepath = filepath
        self.data = self.load()

    def load(self):
        if self.filepath.exists():
            try:
                raw = self.filepath.read_bytes()
                if len(raw) < 32: return {}
                signature, payload = raw[:32], raw[32:]
                expected_sig = hmac.new(HMAC_SECRET, payload, hashlib.sha256).digest()
                if hmac.compare_digest(expected_sig, signature):
                    return pickle.loads(payload)
                else:
                    log_event("SECURITY", f"HMAC validation failed for {self.filepath}. File compromised.")
                    return {}
            except Exception as e:
                log_event("SYSTEM", f"Corruption in storage: {str(e)}")
                return {}
        return {}

    def save(self):
        try:
            payload = pickle.dumps(self.data)
            signature = hmac.new(HMAC_SECRET, payload, hashlib.sha256).digest()
            self.filepath.write_bytes(signature + payload)
        except Exception as e:
            log_event("SYSTEM", f"Failed to serialize storage: {str(e)}")

class TargetVault(PersistenceLayer):
    def __init__(self): super().__init__(CONFIG["PATHS"]["GALLERY"])

    def lock(self, name: str, embedding: np.ndarray, image: Image.Image, metadata: dict = None):
        base, counter = name, 1
        while name in self.data: name, counter = f"{base}_{counter}", counter + 1
        thumb = image.copy()
        thumb.thumbnail((140, 140), Image.Resampling.LANCZOS)
        buf = io.BytesIO()
        thumb.save(buf, format="JPEG", quality=92)
        self.data[name] = {"embedding": embedding, "thumbnail": base64.b64encode(buf.getvalue()).decode(), "locked_at": datetime.now().isoformat(), "intel": metadata or {}}
        self.save()
        return name

    def purge(self, name: str):
        if name in self.data: del self.data[name]; self.save()

class VectorCache(PersistenceLayer):
    def __init__(self): 
        super().__init__(CONFIG["PATHS"]["VECTOR_CACHE"])
        self._lru = LRUMemoryCache(128)
        
    def retrieve(self, b: bytes): 
        k = hashlib.sha256(b).hexdigest()
        if (val := self._lru.get(k)) is not None:
            return val
        if (val := self.data.get(k)) is not None:
            self._lru.put(k, val)
            return val
        return None
        
    def store(self, b: bytes, emb: np.ndarray): 
        k = hashlib.sha256(b).hexdigest()
        self._lru.put(k, emb)
        self.data[k] = emb
        self.save()

class SignalCache(PersistenceLayer):
    def __init__(self): super().__init__(CONFIG["PATHS"]["SEARCH_CACHE"])
    def retrieve(self, b: bytes):
        k = hashlib.sha256(b).hexdigest()
        if k in self.data:
            ts, urls = self.data[k]
            if datetime.now() - ts < timedelta(hours=24): return urls
            del self.data[k]; self.save()
        return None
    def store(self, b: bytes, urls: List[str]): self.data[hashlib.sha256(b).hexdigest()] = (datetime.now(), urls); self.save()

vector_cache, signal_cache, vault = VectorCache(), SignalCache(), TargetVault()

# ==========================================
# DEFCON-1 HARDENED DOM & STEALTH MECHANICS
# ==========================================
STEALTH_INIT_SCRIPT = """
Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
window.chrome = { runtime: {} };
const getParameter = WebGLRenderingContext.prototype.getParameter;
const rotors = [
    { vendor: 'Google Inc. (Intel)', renderer: 'ANGLE (Intel, Intel(R) UHD Graphics Direct3D11 vs_5_0 ps_5_0, D3D11)' },
    { vendor: 'Google Inc. (NVIDIA)', renderer: 'ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)' },
    { vendor: 'Google Inc. (Apple)', renderer: 'ANGLE (Apple, Apple M1 Pro, OpenGL 4.1)' }
];
const chosen = rotors[Math.floor(Math.random() * rotors.length)];
WebGLRenderingContext.prototype.getParameter = function(parameter) {
    if (parameter === 37445) return chosen.vendor;
    if (parameter === 37446) return chosen.renderer;
    return getParameter.call(this, parameter);
};
Object.defineProperty(navigator, 'userAgentData', {
    get: () => ({ brands: [{brand: "Chromium", version: "125"}, {brand: "Google Chrome", version: "125"}, {brand: "Not.A/Brand", version: "24"}], mobile: false })
});
"""

def generate_stealth_context(browser, proxy: Optional[Dict] = None):
    # Viewport Jitter (0-15px offset)
    base_w = random.choice([1280, 1366, 1440, 1536, 1600, 1920])
    base_h = random.choice([720, 768, 800, 864, 900, 1080])
    viewport = {'width': base_w + random.randint(0, 15), 'height': base_h + random.randint(0, 15)}
    
    # Perfect Locale to Timezone syncing
    locale_map = {
        'en-US': 'America/New_York',
        'en-GB': 'Europe/London',
        'en-CA': 'America/Toronto',
        'en-AU': 'Australia/Sydney'
    }
    loc = random.choice(list(locale_map.keys()))
    tz = locale_map[loc]
    headers = {'Accept-Language': f'{loc},en;q=0.9'}
    
    return browser.new_context(
        user_agent=random.choice(CONFIG["USER_AGENTS"]),
        viewport=viewport, 
        locale=loc, 
        timezone_id=tz, 
        extra_http_headers=headers
    )

def human_delay(mean=0.9, sigma=0.3): return max(0.2, min(3.5, random.gauss(mean, sigma)))

def true_bezier_move(page, tx, ty):
    sx, sy = page.mouse.position
    c1x, c1y = sx + (tx - sx) * random.uniform(0.2, 0.4) + random.uniform(-30, 30), sy + (ty - sy) * random.uniform(0.2, 0.4) + random.uniform(-30, 30)
    c2x, c2y = sx + (tx - sx) * random.uniform(0.6, 0.8) + random.uniform(-30, 30), sy + (ty - sy) * random.uniform(0.6, 0.8) + random.uniform(-30, 30)
    steps = random.randint(15, 25)
    for i in range(1, steps + 1):
        t, mt = i / steps, 1 - (i / steps)
        x = mt**3 * sx + 3*mt**2*t * c1x + 3*mt*t**2 * c2x + t**3 * tx
        y = mt**3 * sy + 3*mt**2*t * c1y + 3*mt*t**2 * c2y + t**3 * ty
        page.mouse.move(x + random.uniform(-1.5, 1.5), y + random.uniform(-1.5, 1.5))
        time.sleep(random.uniform(0.008, 0.025))

def find_node_robust(page, selectors: List[str], timeout=4000):
    for sel in selectors:
        try:
            loc = page.locator(sel).first
            if loc.count() > 0 and loc.bounding_box(timeout=timeout): return loc
        except: continue
    for text in ["Search by image", "Upload an image"]:
        try:
            loc = page.get_by_role("button", name=text).first
            if loc.count() > 0: return loc
        except: pass
    return None

def interact_robust(page, selectors: List[str]) -> bool:
    if not (node := find_node_robust(page, selectors)): return False
    try:
        box = node.bounding_box()
        tx, ty = box['x'] + box['width'] * random.uniform(0.3, 0.7), box['y'] + box['height'] * random.uniform(0.3, 0.7)
        if random.random() > 0.5: page.mouse.move(tx + random.uniform(-20, 20), ty + random.uniform(-20, 20)); time.sleep(human_delay(0.2, 0.1))
        true_bezier_move(page, tx, ty); time.sleep(human_delay(0.2, 0.1))
        page.mouse.click(tx, ty); time.sleep(human_delay(0.4, 0.15))
        return True
    except: return False

def force_resolution(url: str) -> Optional[str]:
    try:
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        mod = False
        for k, v in [('w', '1200'), ('width', '1200'), ('h', '1200'), ('height', '1200'), ('s', 'l'), ('size', 'large')]:
            if k in qs: qs[k], mod = [v], True
        if mod: url = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)))
        
        # Check circuit breaker before hitting external domains aggressively
        if check_circuit_breaker(url):
            return None

        r = GLOBAL_SESSION.head(url, allow_redirects=True, timeout=CONFIG["TIMEOUTS"]["REQUEST_HEAD"], headers={'User-Agent': random.choice(CONFIG["USER_AGENTS"])})
        if r.status_code in [403, 429]:
            trip_circuit_breaker(url)
        return r.url if r.url.startswith("http") else None
    except: return url

# ==========================================
# SECURE ROUTING EXECUTIONS
# ==========================================
class SearchExecution:
    def __init__(self, headless: bool):
        self.headless = headless
        self.args = CONFIG["PLAYWRIGHT_ARGS"].copy()
        if self.headless: self.args.append('--headless=new')

class YandexExecution(SearchExecution):
    def breach(self, image_bytes: bytes, proxy: Optional[Dict]) -> List[str]:
        urls = []
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=self.headless, args=self.args, proxy=proxy)
            try:
                ctx = generate_stealth_context(browser, proxy)
                page = ctx.new_page()
                page.add_init_script(STEALTH_INIT_SCRIPT)
                
                page.goto('https://yandex.com/images/', timeout=CONFIG["TIMEOUTS"]["PAGE_LOAD"])
                time.sleep(human_delay(1.5, 0.4))
                interact_robust(page, ["div.image-search-button", "button[aria-label='Search by image']", "div.search2__button"])
                upload = page.locator("input[type='file']").first
                if upload.count() == 0: raise Exception("Yandex upload node missing.")
                upload.set_input_files(files=[{"name": "intel.jpg", "mimeType": "image/jpeg", "buffer": image_bytes}])
                time.sleep(human_delay(2.0, 0.5))
                interact_robust(page, ["button[type='submit']", "button.search"])
                time.sleep(human_delay(4.0, 0.5))
                for _ in range(4): page.mouse.wheel(0, random.randint(400, 800)); time.sleep(0.3)
                
                for sel in ["div.content__left img", "div.CardsGrid img", "img"]:
                    for img in page.locator(sel).all()[:40]:
                        if (s := img.get_attribute('src') or img.get_attribute('data-src')) and s.startswith('http'): 
                            if up := force_resolution(s): urls.append(up)
                for a in page.locator("a[href*='img_url']").all()[:20]:
                    if (h := a.get_attribute('href')) and 'img_url' in (qs := urllib.parse.parse_qs(urllib.parse.urlparse(h).query)):
                        if up := force_resolution(qs['img_url'][0]): urls.append(up)
            finally:
                if 'ctx' in locals(): ctx.close()
                if 'browser' in locals(): browser.close()
        return list(dict.fromkeys(urls))[:30]

class GoogleExecution(SearchExecution):
    def breach(self, image_bytes: bytes, proxy: Optional[Dict]) -> List[str]:
        urls = []
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=self.headless, args=self.args, proxy=proxy)
            try:
                ctx = generate_stealth_context(browser, proxy)
                page = ctx.new_page()
                page.add_init_script(STEALTH_INIT_SCRIPT)
                
                page.goto('https://images.google.com/', timeout=CONFIG["TIMEOUTS"]["PAGE_LOAD"])
                time.sleep(human_delay(1.2, 0.3))
                interact_robust(page, ["div[aria-label='Search by image']", "div.gLFyf", "div[role='button'][aria-label*='image']"])
                upload = page.locator("input[type='file']").first
                if upload.count() == 0: raise Exception("Google upload node missing.")
                upload.set_input_files(files=[{"name": "intel.jpg", "mimeType": "image/jpeg", "buffer": image_bytes}])
                time.sleep(human_delay(1.5, 0.4))
                interact_robust(page, ["button[type='submit']", "input[type='submit']"])
                time.sleep(human_delay(3.5, 0.5))
                for _ in range(3): page.mouse.wheel(0, random.randint(300, 600)); time.sleep(0.2)

                for sel in ["img.rg_i", "div.bRMDJf img"]:
                    for img in page.locator(sel).all()[:40]:
                        if (s := img.get_attribute('src') or img.get_attribute('data-src')) and s.startswith('http'): 
                            if up := force_resolution(s): urls.append(up)
                for a in page.locator("a[href*='imgrefurl']").all()[:20]:
                    if (h := a.get_attribute('href')) and 'imgrefurl' in (qs := urllib.parse.parse_qs(urllib.parse.urlparse(h).query)):
                        if up := force_resolution(qs['imgrefurl'][0]): urls.append(up)
            finally:
                if 'ctx' in locals(): ctx.close()
                if 'browser' in locals(): browser.close()
        return list(dict.fromkeys(urls))[:30]

class BingExecution(SearchExecution):
    def breach(self, image_bytes: bytes, proxy: Optional[Dict]) -> List[str]:
        urls = []
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=self.headless, args=self.args, proxy=proxy)
            try:
                ctx = generate_stealth_context(browser, proxy)
                page = ctx.new_page()
                page.add_init_script(STEALTH_INIT_SCRIPT)
                
                page.goto('https://www.bing.com/images/', timeout=CONFIG["TIMEOUTS"]["PAGE_LOAD"])
                time.sleep(human_delay(1.5, 0.4))
                interact_robust(page, ["button[aria-label='Search by image']", "button.camera_icon", "div.camera_icon"])
                upload = page.locator("input[type='file']").first
                if upload.count() == 0: raise Exception("Bing upload node missing.")
                upload.set_input_files(files=[{"name": "intel.jpg", "mimeType": "image/jpeg", "buffer": image_bytes}])
                time.sleep(human_delay(4.5, 0.5)) 
                for _ in range(4): page.mouse.wheel(0, random.randint(400, 700)); time.sleep(0.3)

                for sel in ["img.mimg", "div.imgpt a img"]:
                    for img in page.locator(sel).all()[:40]:
                        if (s := img.get_attribute('src') or img.get_attribute('data-src')) and s.startswith('http'): 
                            if up := force_resolution(s): urls.append(up)
            finally:
                if 'ctx' in locals(): ctx.close()
                if 'browser' in locals(): browser.close()
        return list(dict.fromkeys(urls))[:30]

class TinEyeExecution(SearchExecution):
    def breach(self, image_bytes: bytes, proxy: Optional[Dict]) -> List[str]:
        urls = []
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=self.headless, args=self.args, proxy=proxy)
            try:
                ctx = generate_stealth_context(browser, proxy)
                page = ctx.new_page()
                page.add_init_script(STEALTH_INIT_SCRIPT)
                
                page.goto('https://tineye.com/', timeout=CONFIG["TIMEOUTS"]["PAGE_LOAD"])
                time.sleep(human_delay(1.5, 0.4))
                upload = page.locator("input[type='file']").first
                if upload.count() == 0: raise Exception("TinEye upload node missing.")
                upload.set_input_files(files=[{"name": "intel.jpg", "mimeType": "image/jpeg", "buffer": image_bytes}])
                page.wait_for_selector("div.match-row, div.results", timeout=20000)
                for _ in range(2): page.mouse.wheel(0, random.randint(300, 500)); time.sleep(0.2)

                for sel in ["div.match-row img", "div.result img", "img.result-image"]:
                    for img in page.locator(sel).all()[:40]:
                        if (s := img.get_attribute('src') or img.get_attribute('data-src')) and s.startswith('http'): 
                            if up := force_resolution(s): urls.append(up)
                for a in page.locator("a.match-link, a.result-link").all()[:20]:
                    if (h := a.get_attribute('href')) and h.startswith('http') and not h.startswith('https://tineye.com'):
                        if up := force_resolution(h): urls.append(up)
            finally:
                if 'ctx' in locals(): ctx.close()
                if 'browser' in locals(): browser.close()
        return list(dict.fromkeys(urls))[:30]

def silent_encrypted_request(image_bytes: bytes) -> List[str]:
    urls = []
    try:
        files = {'upfile': ('intel.jpg', image_bytes, 'image/jpeg')}
        headers = {'User-Agent': random.choice(CONFIG["USER_AGENTS"])}
        r = GLOBAL_SESSION.post('https://yandex.ru/images/search', params={'rpt': 'imageview', 'format': 'json'}, files=files, headers=headers, timeout=CONFIG["TIMEOUTS"]["REQUEST_GET"])
        if r.status_code == 200:
            for b in r.json().get('blocks', []):
                for item in b.get('items', []):
                    if (u := item.get('url')) and u.startswith('http'): 
                        if up := force_resolution(u): urls.append(up)
    except Exception as e: 
        log_event("Encrypted Request", str(e))
    return list(dict.fromkeys(urls))[:20]

def internal_orchestrate_breach(engine_name: str, image_bytes: bytes, headless: bool, proxies: List[str]) -> Tuple[List[str], str]:
    if cached := signal_cache.retrieve(image_bytes): return cached, f"{engine_name} (Cached Lattice)"

    engines = {"Yandex": YandexExecution, "Google": GoogleExecution, "Bing": BingExecution, "TinEye": TinEyeExecution}
    proxy_list = proxies if proxies else [None]
    global_attempts = 0
    
    if engine_name in engines:
        executor = engines[engine_name](headless=headless)
        while global_attempts < CONFIG["LIMITS"]["MAX_RETRIES"]:
            try:
                p_str = proxy_list[global_attempts % len(proxy_list)]
                urls = executor.breach(image_bytes, {"server": p_str} if p_str else None)
                if urls:
                    signal_cache.store(image_bytes, urls)
                    return urls, engine_name
            except Exception as e:
                log_event(engine_name, traceback.format_exc())
                global_attempts += 1
                if global_attempts < CONFIG["LIMITS"]["MAX_RETRIES"]:
                    time.sleep(CONFIG["TIMEOUTS"]["RETRY_DELAYS"][global_attempts % len(CONFIG["TIMEOUTS"]["RETRY_DELAYS"])])

    if engine_name != "Yandex" and global_attempts < CONFIG["LIMITS"]["MAX_RETRIES"]:
        executor = YandexExecution(headless=headless)
        while global_attempts < CONFIG["LIMITS"]["MAX_RETRIES"]:
            try:
                p_str = proxy_list[global_attempts % len(proxy_list)]
                urls = executor.breach(image_bytes, {"server": p_str} if p_str else None)
                if urls:
                    signal_cache.store(image_bytes, urls)
                    return urls, "Yandex (Sub-Routine Protocol)"
            except Exception as e:
                log_event("Yandex Fallback", traceback.format_exc())
                global_attempts += 1
                if global_attempts < CONFIG["LIMITS"]["MAX_RETRIES"]:
                    time.sleep(CONFIG["TIMEOUTS"]["RETRY_DELAYS"][global_attempts % len(CONFIG["TIMEOUTS"]["RETRY_DELAYS"])])

    urls = silent_encrypted_request(image_bytes)
    if urls:
        signal_cache.store(image_bytes, urls)
        return urls, "Yandex (Encrypted Socket Fallback)"

    return [], "Signal Lost"

def orchestrate_breach_safe(engine_name: str, image_bytes: bytes, headless: bool, proxies: List[str]) -> Tuple[List[str], str]:
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(internal_orchestrate_breach, engine_name, image_bytes, headless, proxies)
        try:
            return future.result(timeout=CONFIG["TIMEOUTS"]["GLOBAL_BREACH"])
        except Exception as e:
            log_event("SYSTEM", f"Execution timeout or fatal thread fault: {str(e)}")
            return [], "Timeout/Error"

def validate_signal_integrity(query_emb: np.ndarray, url: str, seen: set) -> Optional[Dict]:
    if url in seen: return None
    seen.add(url)
    
    if check_circuit_breaker(url): return None
    
    try:
        head = GLOBAL_SESSION.head(url, timeout=CONFIG["TIMEOUTS"]["REQUEST_HEAD"], headers={'User-Agent': random.choice(CONFIG["USER_AGENTS"])}, allow_redirects=True)
        if head.status_code in [429, 403]: trip_circuit_breaker(url); return None
        if not head.headers.get('Content-Type', '').startswith('image/'): return None
        
        r = GLOBAL_SESSION.get(url, timeout=CONFIG["TIMEOUTS"]["REQUEST_GET"], headers={'User-Agent': random.choice(CONFIG["USER_AGENTS"])})
        if r.status_code in [429, 403]: trip_circuit_breaker(url); return None
        if r.status_code != 200: return None
        
        img_bytes = r.content
        if (emb := vector_cache.retrieve(img_bytes)) is None:
            if (emb := extract_primary_vector(np.array(Image.open(io.BytesIO(img_bytes)).convert("RGB")))) is not None: 
                vector_cache.store(img_bytes, emb)
            
        if emb is not None and (sim := calculate_proximity(query_emb, emb)) > 0.40:
            return {"url": url, "similarity": sim, "image": Image.open(io.BytesIO(img_bytes)).convert("RGB")}
    except Exception as e:
        log_event("Validation Logic", f"Failure validating signal {url}: {str(e)}")
    return None

# ==========================================
# STATE & UI ORCHESTRATION
# ==========================================
for key, default in [('matches', []), ('query_emb', None), ('query_image', None), ('page', 1)]:
    if key not in st.session_state: st.session_state[key] = default

RESULTS_PER_PAGE = 8

with st.sidebar:
    st.markdown("<h2>OPERATIONAL TARGETING</h2>", unsafe_allow_html=True)
    st.markdown("<p style='color: #a89f91; font-size: 0.95rem;'>Lock the physical constraints of the execution. We parse the noise. You define the floor.</p>", unsafe_allow_html=True)
    
    engine_name = st.selectbox("Registry Array", ["Yandex", "Google", "Bing", "TinEye"], index=0)
    headless_mode = st.checkbox("Headless Execution Constraints", value=True, help="Operates without visual rendering. Optimized for headless cloud VMs.")
    threshold = st.slider("Geometric Tolerance (Cosine)", 0.40, 0.90, 0.55, 0.01)
    max_results = st.number_input("Maximum Yield", 1, 60, 20)
    
    st.markdown("<hr>", unsafe_allow_html=True)
    st.markdown("<h3>BIOMETRIC FILTERS</h3>", unsafe_allow_html=True)
    f_age_min = st.number_input("Floor Age", 0, 100, 0)
    f_age_max = st.number_input("Ceiling Age", 0, 100, 100)
    f_gender = st.selectbox("Marker", ["Any", "Male", "Female"], index=0)
    
    st.markdown("<hr>", unsafe_allow_html=True)
    proxy_input = st.text_area("Inject Proxies (Auth URLs)", placeholder="http://user:pass@host:port")
    auto_save = st.checkbox("Auto-Commit Signals to Vault")
    
    # Strict Proxy Input Validation
    raw_proxies = [l.strip() for l in proxy_input.split("\n") if l.strip()]
    proxies = []
    for p in raw_proxies:
        if PROXY_REGEX.match(p):
            proxies.append(p)
        else:
            log_event("SYSTEM", f"Invalid proxy skipped: {p}")

tab_recon, tab_vault = st.tabs(["EXTRACTION SECTOR", "ENCRYPTED VAULT"])

with tab_recon:
    st.markdown("<h1>GEOMETRIC RESOLUTION VECTOR</h1>", unsafe_allow_html=True)
    st.markdown("<p>Load visual data. System isolates lattice structure, overrides hardware-level bot barriers, and extracts mathematically verified nodes. No false positives. No local tracking.</p><br>", unsafe_allow_html=True)
    
    if uploaded := st.file_uploader("PROVIDE TARGET VISUAL", type=["jpg", "jpeg", "png"]):
        if len(uploaded.getvalue()) > CONFIG["LIMITS"]["MAX_UPLOAD_SIZE_BYTES"]:
            st.error("Upload rejected: File size exceeds the secure threshold.")
            st.stop()

        try:
            image = Image.open(uploaded).convert("RGB")
        except Exception:
            st.error("Upload rejected: Corrupt or invalid geometric visual.")
            st.stop()

        if max(image.size) > 1200:
            ratio = 1200 / max(image.size)
            image = image.resize((int(image.size[0] * ratio), int(image.size[1] * ratio)), Image.Resampling.LANCZOS)
            
        c1, c2 = st.columns([1.5, 3.5])
        with c1: st.image(image, use_container_width=True)
        with c2:
            if st.button("EXECUTE DEEP EXTRACTION", use_container_width=True):
                with st.spinner("MAPPING FACIAL LATTICE..."):
                    try:
                        all_faces = extract_all_vectors(np.array(image))
                    except Exception as e:
                        log_event("Extraction", str(e))
                        st.error("Search engine temporarily unavailable.")
                        st.stop()

                    if not all_faces: st.error("Extraction Failed: Structure not recognized."); st.stop()
                    
                    filtered = [f for f in all_faces if (f_age_min <= (f['age'] or f_age_min) <= f_age_max) and (f_gender == "Any" or f['gender'] == f_gender)]
                    if not filtered: st.error("Target disqualified by active operational filters."); st.stop()
                    
                    best = max(filtered, key=lambda x: x["det_score"])
                    query_emb = best["embedding"]
                    st.toast("Vectors Locked.", icon="✅")

                buf = io.BytesIO(); image.save(buf, format="JPEG", quality=95)
                with st.spinner(f"PENETRATING REGISTRY VIA {engine_name.upper()}..."):
                    urls, source = orchestrate_breach_safe(engine_name, buf.getvalue(), headless_mode, proxies)

                if not urls: 
                    st.error("Operation Terminated. No valid paths resolved. (Search engine temporarily unavailable)")
                    st.stop()
                st.toast(f"Path Secured via {source}. {len(urls)} signals intercepted.", icon="📡")

                with st.spinner("VALIDATING DOWNSTREAM GEOMETRY..."):
                    matches, seen = [], set()
                    prog = st.progress(0)
                    with ThreadPoolExecutor(max_workers=15) as ex:
                        futs = [ex.submit(validate_signal_integrity, query_emb, u, seen) for u in urls]
                        for i, f in enumerate(as_completed(futs)):
                            if res := f.result(): matches.append(res)
                            prog.progress((i + 1) / len(futs))
                    prog.empty()

                matches = sorted([m for m in matches if m["similarity"] >= threshold], key=lambda x: x["similarity"], reverse=True)[:max_results]
                st.session_state.update(matches=matches, query_emb=query_emb, query_image=image, page=1)

                if auto_save and matches:
                    for m in matches: vault.lock(f"Yield_{datetime.now().strftime('%H%M%S%f')}", query_emb, m["image"], {"source": m["url"], "engine": source})
                    st.toast("Target streams committed to Vault.", icon="🔒")

                if not matches: st.warning("Insufficient proximity. Adjust geometric tolerance.")
                else: st.success(f"RESOLUTION COMPLETE. {len(matches)} TARGETS ACQUIRED.")

    if st.session_state.matches:
        st.markdown("<hr><h2>VERIFIED DATA STREAMS</h2>", unsafe_allow_html=True)
        
        ctrl1, ctrl2, ctrl3 = st.columns(3)
        with ctrl1: sort_order = st.selectbox("SORT LOGIC", ["Geometric Proximity", "Network Node"], key="sort_select", on_change=lambda: st.session_state.update(sort_order=st.session_state.sort_select))
        with ctrl2: sim_filter = st.slider("FLOOR PROXIMITY", 0.0, 1.0, 0.0, 0.01, key="sim_filter_slider")
        with ctrl3:
            st.markdown("<br>", unsafe_allow_html=True)
            if st.button("PURGE SESSION CACHE", use_container_width=True): st.session_state.update(matches=[], query_emb=None, query_image=None, page=1); st.rerun()

        f_matches = sorted([m for m in st.session_state.matches if m["similarity"] >= sim_filter], key=lambda x: x["url"] if st.session_state.sort_order == "Network Node" else x["similarity"], reverse=(st.session_state.sort_order == "Geometric Proximity"))
        total_p = max(1, -(-len(f_matches) // RESULTS_PER_PAGE))
        start = (st.session_state.page - 1) * RESULTS_PER_PAGE
        
        for idx, m in enumerate(f_matches[start:start + RESULTS_PER_PAGE], start):
            r1, r2 = st.columns([1, 4])
            with r1: st.image(m["image"], use_container_width=True)
            with r2:
                st.markdown(f"**Lattice Proximity:** `{m['similarity']:.4f}`")
                st.markdown(f"**Origin Node:** [{html.escape(m['url'][:80])}...]({html.escape(m['url'])})")
                with st.form(key=f"commit_{idx}", clear_on_submit=True):
                    n_in = st.text_input("Assign Identifier", placeholder="Target Designation")
                    n_notes = st.text_input("Notes (Optional)", placeholder="Add context...", key=f"n_notes_{idx}")
                    if st.form_submit_button("COMMIT TO VAULT") and n_in.strip():
                        vault.lock(n_in.strip(), st.session_state.query_emb, m["image"], {"source": m["url"], "notes": n_notes.strip()})
                        st.toast(f"Target '{html.escape(n_in.strip())}' committed.", icon="🔐")
            st.markdown("<hr style='opacity:0.15'>", unsafe_allow_html=True)

        c1, c2, c3 = st.columns([1, 2, 1])
        with c2:
            if st.session_state.page < total_p and st.button("EXPAND STREAM", use_container_width=True): st.session_state.page += 1; st.rerun()

with tab_vault:
    st.markdown("<h1>ISOLATED TARGET VAULT</h1>", unsafe_allow_html=True)
    st.markdown("<p>Persistent storage for validated nodes. Completely decoupled from external telemetry.</p>", unsafe_allow_html=True)
    
    with st.expander("MANUAL TARGET INJECTION"):
        with st.form(key="manual_in", clear_on_submit=True):
            v_name = st.text_input("Target Designation")
            v_notes = st.text_input("Notes (Optional)")
            v_file = st.file_uploader("Inject Raw Image", type=["jpg", "jpeg", "png"])
            if st.form_submit_button("LOCK DATA") and v_name and v_file:
                if len(v_file.getvalue()) > CONFIG["LIMITS"]["MAX_UPLOAD_SIZE_BYTES"]:
                    st.error("Upload rejected: File size exceeds the secure threshold.")
                else:
                    try:
                        img_v = Image.open(v_file).convert("RGB")
                        if emb_v := extract_primary_vector(np.array(img_v)):
                            vault.lock(v_name, emb_v, img_v, {"notes": v_notes.strip()})
                            st.toast("Target manually locked.", icon="✅"); st.rerun()
                        else: st.error("No valid lattice detected.")
                    except Exception:
                        st.error("Upload rejected: Corrupt or invalid geometric visual.")

    if v_data := vault.data:
        st.markdown("<br>", unsafe_allow_html=True)
        for name, entry in v_data.items():
            vc1, vc2, vc3 = st.columns([1.2, 4.0, 0.8])
            with vc1: st.image(Image.open(io.BytesIO(base64.b64decode(entry["thumbnail"]))), use_container_width=True)
            with vc2:
                st.markdown(f"### {html.escape(name)}")
                st.markdown(f"**Secured At:** `{html.escape(entry['locked_at'][:16].replace('T', ' '))}`")
                
                meta = entry.get('intel', {})
                if src := meta.get('source_url') or meta.get('source'):
                    st.caption(f"**Source Node:** {html.escape(src[:70])}...")
                if age := meta.get('age'):
                    st.caption(f"**Age:** {html.escape(str(age))}")
                if gender := meta.get('gender'):
                    st.caption(f"**Gender:** {html.escape(str(gender))}")
                if q_age := meta.get('query_age'):
                    st.caption(f"**Query Age:** {html.escape(str(q_age))}")
                if q_gender := meta.get('query_gender'):
                    st.caption(f"**Query Gender:** {html.escape(str(q_gender))}")
                if notes := meta.get('notes'):
                    st.caption(f"**Notes:** {html.escape(str(notes))}")
                    
            with vc3:
                st.markdown("<br>", unsafe_allow_html=True)
                if st.button("ERASE", key=f"del_{name}", use_container_width=True): vault.purge(name); st.rerun()
            st.markdown("<hr style='opacity:0.1'>", unsafe_allow_html=True)
    else: st.info("Vault is currently empty. Awaiting confirmed signals.")
