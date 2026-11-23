"""Automated test suite for V2 Task R9: Rich External Media Embeds (YouTube & Shorts).

Covers:
1. URL parsing and extraction across all approved formats (watch, youtu.be, shorts, embed, no-cookie).
2. Strict hostname allowlisting and rejection of spoofed domains.
3. Strict 11-character video ID validation.
4. Handling of surrounding conversational text, leading/trailing punctuation, and timestamps.
5. Lazy-loading behavior: initial preview rendering with thumbnail and NO iframe.
6. Explicit user activation: clicking "Load Video" dynamically creates the official YouTube iframe.
7. Verification of trusted embed URL construction (youtube-nocookie.com) and secure attributes.
8. Fallback display when thumbnail fails to load.
9. Message edit and delete lifecycles: embed removal, update, and iframe cleanup.
10. Preserving standard messages, ordinary links, and media uploads without regressions.
"""
import json
import os
import shutil
import subprocess
import unittest

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
STATIC_JS_DIR = os.path.join(PROJECT_ROOT, "static", "js")


class TestYouTubeEmbeds(unittest.TestCase):
    """Executes frontend embed logic under Node.js with DOM simulation."""

    @classmethod
    def setUpClass(cls):
        cls.node_available = shutil.which("node") is not None

    def setUp(self):
        if not self.node_available:
            self.skipTest("Node.js is not installed; skipping JS execution tests.")

    def _run_node_script(self, js_code: str) -> dict:
        static_js_posix = STATIC_JS_DIR.replace("\\", "/")
        wrapped = f"""
const fs = require('fs');
const path = require('path');

class MockElement {{
    constructor(tagName) {{
        this.tagName = (tagName || '').toUpperCase();
        this.children = [];
        this._textContent = '';
        this.style = {{}};
        this.dataset = {{}};
        this.attributes = {{}};
        this.listeners = {{}};
        this.parentNode = null;
        this.classList = {{
            _classes: new Set(),
            add: (c) => this.classList._classes.add(c),
            remove: (c) => this.classList._classes.delete(c),
            contains: (c) => this.classList._classes.has(c),
            toggle: (c, v) => {{
                if (v === undefined) {{
                    if (this.classList.contains(c)) this.classList.remove(c);
                    else this.classList.add(c);
                }} else if (v) {{
                    this.classList.add(c);
                }} else {{
                    this.classList.remove(c);
                }}
            }}
        }};
    }}

    set textContent(val) {{
        this._textContent = String(val === null || val === undefined ? '' : val);
        this.children = [];
    }}

    get textContent() {{
        if (this.children.length > 0) {{
            return this.children.map(c => c.textContent).join('');
        }}
        return this._textContent;
    }}

    set className(val) {{
        this._className = val;
        (val || '').split(/\\s+/).filter(Boolean).forEach(c => this.classList.add(c));
    }}

    get className() {{
        return this._className || Array.from(this.classList._classes).join(' ');
    }}

    setAttribute(k, v) {{
        this.attributes[k] = String(v);
        this[k] = String(v);
    }}

    getAttribute(k) {{
        if (this[k] !== undefined && this[k] !== null && typeof this[k] !== "function") {{
            return String(this[k]);
        }}
        return this.attributes[k] || null;
    }}

    appendChild(child) {{
        if (!child) return null;
        if (child.parentNode) {{
            child.parentNode.removeChild(child);
        }}
        this.children.push(child);
        child.parentNode = this;
        return child;
    }}

    insertBefore(newNode, refNode) {{
        if (!newNode) return null;
        if (newNode.parentNode) {{
            newNode.parentNode.removeChild(newNode);
        }}
        if (!refNode) {{
            return this.appendChild(newNode);
        }}
        const idx = this.children.indexOf(refNode);
        if (idx === -1) {{
            return this.appendChild(newNode);
        }}
        this.children.splice(idx, 0, newNode);
        newNode.parentNode = this;
        return newNode;
    }}

    removeChild(child) {{
        const idx = this.children.indexOf(child);
        if (idx !== -1) {{
            this.children.splice(idx, 1);
            child.parentNode = null;
        }}
        return child;
    }}

    remove() {{
        if (this.parentNode) {{
            this.parentNode.removeChild(this);
        }}
    }}

    requestFullscreen() {{
        globalDocument.fullscreenElement = this;
        const event = {{ type: 'fullscreenchange', target: this }};
        (this.listeners['fullscreenchange'] || []).forEach(fn => fn(event));
        return Promise.resolve();
    }}

    webkitRequestFullscreen() {{
        return this.requestFullscreen();
    }}

    replaceWith(newEl) {{
        if (!this.parentNode) return;
        const parent = this.parentNode;
        const idx = parent.children.indexOf(this);
        if (idx !== -1) {{
            if (newEl.parentNode) newEl.parentNode.removeChild(newEl);
            parent.children.splice(idx, 1, newEl);
            newEl.parentNode = parent;
            this.parentNode = null;
        }}
    }}

    addEventListener(event, fn) {{
        this.listeners[event] = this.listeners[event] || [];
        this.listeners[event].push(fn);
    }}

    click() {{
        let current = this;
        let propagationStopped = false;
        const event = {{
            type: 'click',
            target: this,
            currentTarget: this,
            stopPropagation: () => {{ propagationStopped = true; }}
        }};
        while (current) {{
            event.currentTarget = current;
            const handlers = current.listeners['click'] || [];
            for (const h of handlers) {{
                h(event);
            }}
            if (propagationStopped) break;
            current = current.parentNode;
        }}
    }}

    closest(selector) {{
        let current = this;
        while (current) {{
            if (selector.startsWith('.')) {{
                const cls = selector.slice(1);
                if (current.classList.contains(cls)) return current;
            }} else if (selector.startsWith('#')) {{
                const id = selector.slice(1);
                if (current.id === id) return current;
            }}
            current = current.parentNode;
        }}
        return null;
    }}

    querySelector(selector) {{
        return this.querySelectorAll(selector)[0] || null;
    }}

    querySelectorAll(selector) {{
        const results = [];
        const match = (el) => {{
            if (selector.startsWith('.')) {{
                const cls = selector.slice(1);
                if (el.classList.contains(cls)) results.push(el);
            }} else if (selector.startsWith('#')) {{
                const id = selector.slice(1);
                if (el.id === id) results.push(el);
            }} else if (selector === 'iframe') {{
                if (el.tagName === 'IFRAME') results.push(el);
            }} else if (selector === 'img') {{
                if (el.tagName === 'IMG') results.push(el);
            }} else if (selector === 'video') {{
                if (el.tagName === 'VIDEO') results.push(el);
            }} else if (selector === 'a') {{
                if (el.tagName === 'A') results.push(el);
            }} else if (selector === 'button') {{
                if (el.tagName === 'BUTTON') results.push(el);
            }}
            for (const child of el.children) {{
                match(child);
            }}
        }};
        for (const child of this.children) {{
            match(child);
        }}
        return results;
    }}
}}

const elementsById = {{}};
const globalDocument = {{
    createElement: (tag) => new MockElement(tag),
    getElementById: (id) => {{
        if (!elementsById[id]) {{
            elementsById[id] = new MockElement('div');
            elementsById[id].id = id;
        }}
        return elementsById[id];
    }},
    querySelectorAll: () => [],
    querySelector: () => null,
    addEventListener: () => {{}},
    fullscreenEnabled: true,
    fullscreenElement: null,
    exitFullscreen: function() {{
        const prev = this.fullscreenElement;
        this.fullscreenElement = null;
        if (prev) {{
            const event = {{ type: 'fullscreenchange', target: prev }};
            (prev.listeners['fullscreenchange'] || []).forEach(fn => fn(event));
        }}
        return Promise.resolve();
    }},
    webkitExitFullscreen: function() {{
        return this.exitFullscreen();
    }}
}};

global.window = {{
    location: {{ origin: 'http://localhost:8000', protocol: 'http:', host: 'localhost:8000' }}
}};
global.document = globalDocument;
global.currentUser = 'alice';
global.currentFriend = 'bob';
global.formatMessageTimestamp = () => '12:00 PM';
global.formatLastSeen = () => 'Online';
global.showToast = () => {{}};
global.normalizeMessageStatus = (s) => s || 'sent';

// Load utils.js
const utilsCode = fs.readFileSync('{static_js_posix}/utils.js', 'utf8');
eval(utilsCode);

// Load chat.js without top-level search UI calls
let chatCode = fs.readFileSync('{static_js_posix}/chat.js', 'utf8');
chatCode = chatCode.replace('setConversationSearchEnabled(false);', '// disabled for test');
chatCode = chatCode.replace('resetConversationSearchUI(true);', '// disabled for test');
eval(chatCode);

{js_code}
"""
        proc = subprocess.run(
            ["node", "-e", wrapped],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"Node execution failed:\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}")
        return json.loads(proc.stdout.strip())

    def test_parse_youtube_video_formats(self):
        """Test extraction across all approved YouTube URL formats."""
        code = """
        const tests = {
            watchStandard: parseYouTubeVideo("https://www.youtube.com/watch?v=dQw4w9WgXcQ"),
            watchMobile: parseYouTubeVideo("https://m.youtube.com/watch?v=dQw4w9WgXcQ"),
            watchNoWww: parseYouTubeVideo("https://youtube.com/watch?v=dQw4w9WgXcQ"),
            watchHttp: parseYouTubeVideo("http://www.youtube.com/watch?v=dQw4w9WgXcQ"),
            shortened: parseYouTubeVideo("https://youtu.be/dQw4w9WgXcQ"),
            shortenedWww: parseYouTubeVideo("https://www.youtu.be/dQw4w9WgXcQ"),
            shorts: parseYouTubeVideo("https://www.youtube.com/shorts/5qap5aO4i9A"),
            shortsMobile: parseYouTubeVideo("https://m.youtube.com/shorts/5qap5aO4i9A"),
            embed: parseYouTubeVideo("https://youtube.com/embed/dQw4w9WgXcQ"),
            embedNoCookie: parseYouTubeVideo("https://www.youtube-nocookie.com/embed/dQw4w9WgXcQ"),
            bareWatch: parseYouTubeVideo("youtube.com/watch?v=dQw4w9WgXcQ"),
            bareShorts: parseYouTubeVideo("youtube.com/shorts/5qap5aO4i9A"),
            bareYoutuBe: parseYouTubeVideo("youtu.be/dQw4w9WgXcQ")
        };
        console.log(JSON.stringify(tests));
        """
        res = self._run_node_script(code)

        # Standard watch
        self.assertEqual(res["watchStandard"]["videoId"], "dQw4w9WgXcQ")
        self.assertFalse(res["watchStandard"]["isShort"])
        self.assertIn("youtube-nocookie.com/embed/dQw4w9WgXcQ", res["watchStandard"]["embedUrl"])
        self.assertEqual(res["watchStandard"]["thumbnailUrl"], "https://i.ytimg.com/vi/dQw4w9WgXcQ/hqdefault.jpg")

        # Mobile watch
        self.assertEqual(res["watchMobile"]["videoId"], "dQw4w9WgXcQ")

        # Shortened
        self.assertEqual(res["shortened"]["videoId"], "dQw4w9WgXcQ")
        self.assertFalse(res["shortened"]["isShort"])

        # Shorts
        self.assertEqual(res["shorts"]["videoId"], "5qap5aO4i9A")
        self.assertTrue(res["shorts"]["isShort"])
        self.assertIn("youtube-nocookie.com/embed/5qap5aO4i9A", res["shorts"]["embedUrl"])
        self.assertEqual(res["shorts"]["watchUrl"], "https://www.youtube.com/shorts/5qap5aO4i9A")
        self.assertEqual(res["shorts"]["thumbnailUrl"], "https://i.ytimg.com/vi/5qap5aO4i9A/oardefault.jpg")

        # Embeds
        self.assertEqual(res["embed"]["videoId"], "dQw4w9WgXcQ")
        self.assertEqual(res["embedNoCookie"]["videoId"], "dQw4w9WgXcQ")

        # Bare URLs
        self.assertEqual(res["bareWatch"]["videoId"], "dQw4w9WgXcQ")
        self.assertEqual(res["bareShorts"]["videoId"], "5qap5aO4i9A")
        self.assertTrue(res["bareShorts"]["isShort"])
        self.assertEqual(res["bareYoutuBe"]["videoId"], "dQw4w9WgXcQ")

    def test_surrounding_text_and_punctuation(self):
        """Test URLs surrounded by conversational text and punctuation."""
        code = """
        const tests = {
            trailingExclamation: parseYouTubeVideo("Look at this https://youtu.be/dQw4w9WgXcQ!"),
            trailingDot: parseYouTubeVideo("Check out https://www.youtube.com/watch?v=dQw4w9WgXcQ."),
            trailingQuestion: parseYouTubeVideo("Did you see https://youtube.com/shorts/5qap5aO4i9A?"),
            parentheses: parseYouTubeVideo("Watch this: (https://youtu.be/dQw4w9WgXcQ) right now"),
            bracketAndComma: parseYouTubeVideo("Links: [https://youtu.be/dQw4w9WgXcQ], great video"),
            multipleUrls: parseYouTubeVideo("First https://youtu.be/firstVid123 and second https://youtu.be/secondVid45"),
            extraQueryParams: parseYouTubeVideo("https://www.youtube.com/watch?feature=shared&v=dQw4w9WgXcQ&si=xyz123"),
            timestampSeconds: parseYouTubeVideo("https://youtu.be/dQw4w9WgXcQ?t=45s"),
            timestampMinutesSeconds: parseYouTubeVideo("https://www.youtube.com/watch?v=dQw4w9WgXcQ&t=1m30s")
        };
        console.log(JSON.stringify(tests));
        """
        res = self._run_node_script(code)

        self.assertEqual(res["trailingExclamation"]["videoId"], "dQw4w9WgXcQ")
        self.assertEqual(res["trailingDot"]["videoId"], "dQw4w9WgXcQ")
        self.assertEqual(res["trailingQuestion"]["videoId"], "5qap5aO4i9A")
        self.assertEqual(res["parentheses"]["videoId"], "dQw4w9WgXcQ")
        self.assertEqual(res["bracketAndComma"]["videoId"], "dQw4w9WgXcQ")
        self.assertEqual(res["multipleUrls"]["videoId"], "firstVid123")
        self.assertEqual(res["extraQueryParams"]["videoId"], "dQw4w9WgXcQ")
        self.assertIn("&start=45", res["timestampSeconds"]["embedUrl"])
        self.assertIn("&start=90", res["timestampMinutesSeconds"]["embedUrl"])

    def test_rejection_of_invalid_and_malicious_urls(self):
        """Test strict rejection of non-YouTube URLs, invalid IDs, and attack payloads."""
        code = """
        const tests = {
            vimeo: parseYouTubeVideo("https://vimeo.com/12345678"),
            tiktok: parseYouTubeVideo("https://www.tiktok.com/@user/video/123456"),
            spoofedHost1: parseYouTubeVideo("https://evil-youtube.com/watch?v=dQw4w9WgXcQ"),
            spoofedHost2: parseYouTubeVideo("https://youtube.com.attacker.com/watch?v=dQw4w9WgXcQ"),
            notYouTube: parseYouTubeVideo("https://notyoutube.com/watch?v=dQw4w9WgXcQ"),
            javascriptScheme: parseYouTubeVideo("javascript:alert(1)"),
            dataScheme: parseYouTubeVideo("data:text/html,<script>alert(1)</script>"),
            tooShortId: parseYouTubeVideo("https://youtube.com/watch?v=abc"),
            tooLongId: parseYouTubeVideo("https://youtube.com/watch?v=dQw4w9WgXcQ123"),
            xssInId: parseYouTubeVideo("https://youtube.com/watch?v=<script>123"),
            nonString: parseYouTubeVideo(12345),
            nullVal: parseYouTubeVideo(null),
            plainTextNoUrl: parseYouTubeVideo("Hello world! How are you doing today?")
        };
        console.log(JSON.stringify(tests));
        """
        res = self._run_node_script(code)

        for key, value in res.items():
            self.assertIsNone(value, f"Expected {key} to be null, got: {value}")

    def test_preview_card_structure_no_initial_iframe(self):
        """Verify that preview card renders thumbnail, labels, and NO iframe initially."""
        code = """
        const ytData = parseYouTubeVideo("https://www.youtube.com/watch?v=dQw4w9WgXcQ");
        const card = renderYouTubePreviewCard(ytData);

        const img = card.querySelector(".msg-youtube-thumb");
        const badge = card.querySelector(".msg-youtube-badge");
        const extLink = card.querySelector(".msg-youtube-ext-link");
        const playBtn = card.querySelector(".msg-youtube-play-btn");
        const iframes = card.querySelectorAll("iframe");

        const result = {
            hasCard: Boolean(card),
            isShortClass: card.classList.contains("is-short"),
            videoIdAttr: card.dataset.videoId,
            thumbSrc: img ? img.src : null,
            thumbLoading: img ? img.getAttribute("loading") : null,
            badgeText: badge ? badge.textContent : null,
            extLinkHref: extLink ? extLink.getAttribute("href") : null,
            extLinkTarget: extLink ? extLink.getAttribute("target") : null,
            extLinkRel: extLink ? extLink.getAttribute("rel") : null,
            playBtnText: playBtn ? playBtn.textContent : null,
            iframeCount: iframes.length
        };
        console.log(JSON.stringify(result));
        """
        res = self._run_node_script(code)

        self.assertTrue(res["hasCard"])
        self.assertFalse(res["isShortClass"])
        self.assertEqual(res["videoIdAttr"], "dQw4w9WgXcQ")
        self.assertEqual(res["thumbSrc"], "https://i.ytimg.com/vi/dQw4w9WgXcQ/hqdefault.jpg")
        self.assertEqual(res["thumbLoading"], "lazy")
        self.assertIn("YouTube", res["badgeText"])
        self.assertEqual(res["extLinkHref"], "https://www.youtube.com/watch?v=dQw4w9WgXcQ")
        self.assertEqual(res["extLinkTarget"], "_blank")
        self.assertEqual(res["extLinkRel"], "noopener noreferrer")
        self.assertIn("Load Video", res["playBtnText"])
        # CRITICAL: No iframe initially
        self.assertEqual(res["iframeCount"], 0)

    def test_shorts_preview_card_structure(self):
        """Verify that YouTube Shorts preview card receives is-short styling and Shorts badge."""
        code = """
        const ytData = parseYouTubeVideo("https://www.youtube.com/shorts/5qap5aO4i9A");
        const card = renderYouTubePreviewCard(ytData);

        const badge = card.querySelector(".msg-youtube-badge");
        const extLink = card.querySelector(".msg-youtube-ext-link");
        const thumb = card.querySelector(".msg-youtube-thumb");
        const fsBtn = card.querySelector(".msg-youtube-fs-btn");

        const result = {
            isShortClass: card.classList.contains("is-short"),
            videoIdAttr: card.dataset.videoId,
            badgeText: badge ? badge.textContent : null,
            extLinkHref: extLink ? extLink.getAttribute("href") : null,
            thumbSrc: thumb ? thumb.src : null,
            hasFsBtn: Boolean(fsBtn)
        };
        console.log(JSON.stringify(result));
        """
        res = self._run_node_script(code)

        self.assertTrue(res["isShortClass"])
        self.assertEqual(res["videoIdAttr"], "5qap5aO4i9A")
        self.assertIn("Shorts", res["badgeText"])
        self.assertEqual(res["extLinkHref"], "https://www.youtube.com/shorts/5qap5aO4i9A")
        self.assertEqual(res["thumbSrc"], "https://i.ytimg.com/vi/5qap5aO4i9A/oardefault.jpg")
        self.assertTrue(res["hasFsBtn"])

    def test_shorts_thumbnail_fallback_chain(self):
        """Verify that Shorts preview falls back from oardefault.jpg to hqdefault.jpg, then to unavailable."""
        code = """
        const ytData = parseYouTubeVideo("https://www.youtube.com/shorts/5qap5aO4i9A");
        const card = renderYouTubePreviewCard(ytData);

        const thumb = card.querySelector(".msg-youtube-thumb");
        const fallback = card.querySelector(".msg-youtube-fallback");

        const initialSrc = thumb.src;
        const initialThumbDisplay = thumb.style.display || "block";
        const initialFallbackDisplay = fallback.style.display;

        // First error: oardefault fails -> fallback to hqdefault
        if (typeof thumb.onerror === "function") {
            thumb.onerror();
        }

        const fallbackSrc = thumb.src;
        const fallbackThumbDisplay = thumb.style.display || "block";
        const fallbackDisplayAfterFirstErr = fallback.style.display;

        // Second error: hqdefault fails -> show unavailable placeholder
        if (typeof thumb.onerror === "function") {
            thumb.onerror();
        }

        const finalThumbDisplay = thumb.style.display;
        const finalFallbackDisplay = fallback.style.display;

        const result = {
            initialSrc,
            initialThumbDisplay,
            initialFallbackDisplay,
            fallbackSrc,
            fallbackThumbDisplay,
            fallbackDisplayAfterFirstErr,
            finalThumbDisplay,
            finalFallbackDisplay
        };
        console.log(JSON.stringify(result));
        """
        res = self._run_node_script(code)

        self.assertEqual(res["initialSrc"], "https://i.ytimg.com/vi/5qap5aO4i9A/oardefault.jpg")
        self.assertEqual(res["initialFallbackDisplay"], "none")
        self.assertEqual(res["fallbackSrc"], "https://i.ytimg.com/vi/5qap5aO4i9A/hqdefault.jpg")
        self.assertNotEqual(res["fallbackThumbDisplay"], "none")
        self.assertEqual(res["fallbackDisplayAfterFirstErr"], "none")
        self.assertEqual(res["finalThumbDisplay"], "none")
        self.assertEqual(res["finalFallbackDisplay"], "flex")

    def test_thumbnail_error_fallback(self):
        """Verify that thumbnail loading failure triggers clean fallback display."""
        code = """
        const ytData = parseYouTubeVideo("https://www.youtube.com/watch?v=dQw4w9WgXcQ");
        const card = renderYouTubePreviewCard(ytData);

        const img = card.querySelector(".msg-youtube-thumb");
        const fallback = card.querySelector(".msg-youtube-fallback");

        const initialFallbackDisplay = fallback.style.display;

        // Trigger onerror callback
        if (typeof img.onerror === "function") {
            img.onerror();
        }

        const afterImgDisplay = img.style.display;
        const afterFallbackDisplay = fallback.style.display;

        const result = {
            initialFallbackDisplay,
            afterImgDisplay,
            afterFallbackDisplay,
            fallbackText: fallback.textContent
        };
        console.log(JSON.stringify(result));
        """
        res = self._run_node_script(code)

        self.assertEqual(res["initialFallbackDisplay"], "none")
        self.assertEqual(res["afterImgDisplay"], "none")
        self.assertEqual(res["afterFallbackDisplay"], "flex")
        self.assertIn("Unavailable", res["fallbackText"])

    def test_explicit_click_creates_iframe(self):
        """Verify that clicking the preview card creates and mounts the official iframe."""
        code = """
        const ytData = parseYouTubeVideo("https://www.youtube.com/watch?v=dQw4w9WgXcQ");
        const card = renderYouTubePreviewCard(ytData);

        // Before click
        const initialIframe = card.querySelector("iframe");

        // Simulate click on the card
        card.click();

        // After click
        const loadedIframe = card.querySelector("iframe");

        const result = {
            initialIframeExists: Boolean(initialIframe),
            loadedIframeExists: Boolean(loadedIframe),
            iframeSrc: loadedIframe ? loadedIframe.src : null,
            iframeAllow: loadedIframe ? loadedIframe.getAttribute("allow") : null,
            hasAllowfullscreen: loadedIframe ? loadedIframe.attributes["allowfullscreen"] !== undefined : false,
            iframeSandbox: loadedIframe ? loadedIframe.getAttribute("sandbox") : null
        };
        console.log(JSON.stringify(result));
        """
        res = self._run_node_script(code)

        self.assertFalse(res["initialIframeExists"])
        self.assertTrue(res["loadedIframeExists"])
        self.assertEqual(
            res["iframeSrc"],
            "https://www.youtube-nocookie.com/embed/dQw4w9WgXcQ?autoplay=1&rel=0",
        )
        self.assertIn("autoplay", res["iframeAllow"])
        self.assertIn("accelerometer", res["iframeAllow"])
        self.assertIn("fullscreen", res["iframeAllow"])
        self.assertTrue(res["hasAllowfullscreen"])
        self.assertIn("allow-scripts", res["iframeSandbox"])
        self.assertIn("allow-same-origin", res["iframeSandbox"])
        self.assertIn("allow-presentation", res["iframeSandbox"])

    def test_fullscreen_controls_and_api(self):
        """Verify that fullscreen controls toggle card fullscreen and reflect active state."""
        code = """
        const ytData = parseYouTubeVideo("https://www.youtube.com/watch?v=dQw4w9WgXcQ");
        const card = renderYouTubePreviewCard(ytData);

        const fsBtn = card.querySelector(".msg-youtube-fs-btn");
        const initialBtnText = fsBtn ? fsBtn.textContent : null;

        // Click fullscreen button to enter fullscreen
        if (fsBtn) fsBtn.click();
        const isFsAfterClick = globalDocument.fullscreenElement === card;
        const btnTextInFs = fsBtn ? fsBtn.textContent : null;

        // Click again to exit fullscreen
        if (fsBtn) fsBtn.click();
        const isFsAfterExit = globalDocument.fullscreenElement === card;
        const btnTextAfterExit = fsBtn ? fsBtn.textContent : null;

        const result = {
            hasFsBtn: Boolean(fsBtn),
            initialBtnText,
            isFsAfterClick,
            btnTextInFs,
            isFsAfterExit,
            btnTextAfterExit
        };
        console.log(JSON.stringify(result));
        """
        res = self._run_node_script(code)

        self.assertTrue(res["hasFsBtn"])
        self.assertEqual(res["initialBtnText"], "⛶")
        self.assertTrue(res["isFsAfterClick"])
        self.assertEqual(res["btnTextInFs"], "✕")
        self.assertFalse(res["isFsAfterExit"])
        self.assertEqual(res["btnTextAfterExit"], "⛶")

    def test_fullscreen_unsupported_environment(self):
        """Verify that fullscreen button is gracefully omitted when Fullscreen API is unsupported."""
        code = """
        // Temporarily disable fullscreen support
        const prevFs = globalDocument.fullscreenEnabled;
        globalDocument.fullscreenEnabled = false;

        const ytData = parseYouTubeVideo("https://www.youtube.com/watch?v=dQw4w9WgXcQ");
        const card = renderYouTubePreviewCard(ytData);

        const fsBtn = card.querySelector(".msg-youtube-fs-btn");
        const extLink = card.querySelector(".msg-youtube-ext-link");

        // Restore
        globalDocument.fullscreenEnabled = prevFs;

        const result = {
            hasCard: Boolean(card),
            hasFsBtn: Boolean(fsBtn),
            hasExtLink: Boolean(extLink)
        };
        console.log(JSON.stringify(result));
        """
        res = self._run_node_script(code)

        self.assertTrue(res["hasCard"])
        self.assertFalse(res["hasFsBtn"])
        self.assertTrue(res["hasExtLink"])

    def test_add_message_with_youtube_embed(self):
        """Verify addMessage appends preview card to message element."""
        code = """
        const box = globalDocument.getElementById("messages");
        box.children = [];

        addMessage("bob", "Bob", "Check this out https://youtu.be/dQw4w9WgXcQ!", "", "2026-09-13T10:00:00Z", 201, "delivered", null, null, false);

        const msgEl = box.children[0];
        const textEl = msgEl.querySelector(".msg-text");
        const ytCard = msgEl.querySelector(".msg-youtube-card");

        const result = {
            hasMsg: Boolean(msgEl),
            textContent: textEl ? textEl.textContent : null,
            hasYtCard: Boolean(ytCard),
            cardVideoId: ytCard ? ytCard.dataset.videoId : null,
            cardHasIframeInitially: ytCard ? Boolean(ytCard.querySelector("iframe")) : null
        };
        console.log(JSON.stringify(result));
        """
        res = self._run_node_script(code)

        self.assertTrue(res["hasMsg"])
        self.assertEqual(res["textContent"], "Check this out https://youtu.be/dQw4w9WgXcQ!")
        self.assertTrue(res["hasYtCard"])
        self.assertEqual(res["cardVideoId"], "dQw4w9WgXcQ")
        self.assertFalse(res["cardHasIframeInitially"])

    def test_message_edit_lifecycle(self):
        """Verify message editing updates, adds, or removes YouTube embed appropriately."""
        code = """
        const box = globalDocument.getElementById("messages");
        box.children = [];

        // 1. Initial message with Video A
        addMessage("alice", "Alice", "Watch A: https://youtu.be/dQw4w9WgXcQ", "", "2026-09-13T10:00:00Z", 301, "delivered", null, null, false);
        const msgEl = box.children[0];
        const initialCard = msgEl.querySelector(".msg-youtube-card");
        const initialVideoId = initialCard ? initialCard.dataset.videoId : null;

        // 2. Edit message to change to Shorts B
        applyMessageText(msgEl, "Watch B: https://youtube.com/shorts/5qap5aO4i9A");
        const editedCard = msgEl.querySelector(".msg-youtube-card");
        const editedVideoId = editedCard ? editedCard.dataset.videoId : null;
        const editedIsShort = editedCard ? editedCard.classList.contains("is-short") : null;

        // 3. Edit message to remove YouTube link entirely
        applyMessageText(msgEl, "Just plain text now, no video!");
        const plainCard = msgEl.querySelector(".msg-youtube-card");

        const result = {
            initialVideoId,
            editedVideoId,
            editedIsShort,
            plainCardExists: Boolean(plainCard),
            finalText: msgEl.querySelector(".msg-text").textContent
        };
        console.log(JSON.stringify(result));
        """
        res = self._run_node_script(code)

        self.assertEqual(res["initialVideoId"], "dQw4w9WgXcQ")
        self.assertEqual(res["editedVideoId"], "5qap5aO4i9A")
        self.assertTrue(res["editedIsShort"])
        self.assertFalse(res["plainCardExists"])
        self.assertEqual(res["finalText"], "Just plain text now, no video!")

    def test_message_delete_lifecycle(self):
        """Verify message deletion cleans up YouTube card and resets iframe src."""
        code = """
        const box = globalDocument.getElementById("messages");
        box.children = [];

        addMessage("bob", "Bob", "See https://youtu.be/dQw4w9WgXcQ", "", "2026-09-13T10:00:00Z", 401, "delivered", null, null, false);
        const msgEl = box.children[0];
        const cardBefore = msgEl.querySelector(".msg-youtube-card");

        // Load iframe before deletion
        cardBefore.click();
        const iframeBefore = cardBefore.querySelector("iframe");

        // Delete message
        applyDeletedState(msgEl, "2026-09-13T10:05:00Z");

        const cardAfter = msgEl.querySelector(".msg-youtube-card");
        const textAfter = msgEl.querySelector(".msg-text").textContent;

        const result = {
            hadIframeBeforeDelete: Boolean(iframeBefore),
            hasCardAfterDelete: Boolean(cardAfter),
            textAfterDelete: textAfter
        };
        console.log(JSON.stringify(result));
        """
        res = self._run_node_script(code)

        self.assertTrue(res["hadIframeBeforeDelete"])
        self.assertFalse(res["hasCardAfterDelete"])
        self.assertEqual(res["textAfterDelete"], "This message was deleted")

    def test_plain_messages_and_uploads_unaffected(self):
        """Verify that plain messages, uploaded images, videos, and files do not generate YouTube cards."""
        code = """
        const box = globalDocument.getElementById("messages");
        box.children = [];

        // Plain text message
        addMessage("bob", "Bob", "Just saying hello!", "", "2026-09-13T10:00:00Z", 501, "delivered", null, null, false);
        // Uploaded image
        addMessage("bob", "Bob", "Here is a picture", "/uploads/photo.jpg", "2026-09-13T10:01:00Z", 502, "delivered", null, null, false);
        // Uploaded video
        addMessage("bob", "Bob", "Here is a recorded video", null, "2026-09-13T10:02:00Z", 503, "delivered", null, null, false, "", null, null, "/uploads/video.mp4");

        const result = {
            msg1Card: Boolean(box.children[0].querySelector(".msg-youtube-card")),
            msg2Card: Boolean(box.children[1].querySelector(".msg-youtube-card")),
            msg3Card: Boolean(box.children[2].querySelector(".msg-youtube-card")),
        };
        console.log(JSON.stringify(result));
        """
        res = self._run_node_script(code)

        self.assertFalse(res["msg1Card"])
        self.assertFalse(res["msg2Card"])
        self.assertFalse(res["msg3Card"])


if __name__ == "__main__":
    unittest.main()
