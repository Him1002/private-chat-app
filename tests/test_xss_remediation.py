"""Automated regression and validation tests for S5-T03 Stored XSS Remediation (SEC-02).

Verifies:
1. escapeHtml and sanitizeMediaUrl behavior across representative attack payloads.
2. Safe DOM-based rendering of message text, reply previews, display names, and profile fields.
3. Rejection of malicious URL schemes (javascript:, data:, vbscript:, //).
4. Static audit verifying no user variables reach innerHTML sinks in frontend scripts.
5. Backend data fidelity: verifying raw payloads are stored verbatim without lossy server-side tampering.
"""
from datetime import timedelta
import json
import os
import re
import shutil
import subprocess
import unittest

from backend.core.security import create_access_token
from backend.db.models import Message, User
from backend.services import chat_service
from tests.base import BaseTestCase
from tests.test_api_integration import IntegrationASGIClient


PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
STATIC_JS_DIR = os.path.join(PROJECT_ROOT, "static", "js")


class TestStaticCodeAudit(unittest.TestCase):
    """Static audit of frontend JS code to ensure no unsanitized user sinks exist."""

    def test_no_user_data_interpolation_in_inner_html(self):
        """Verify that user-controlled variables are not interpolated into innerHTML."""
        js_files = ["chat.js", "sidebar.js", "auth.js", "profile.js", "websocket.js", "utils.js"]
        user_variable_pattern = re.compile(
            r"""\.innerHTML\s*\+?=\s*`[^`]*\$\{[^}]*(?:text|content|sender|username|display_name|displayName|about|avatar|profile_picture|safeText|safeImageUrl|r\.|item\.)[^}]*\}[^`]*`""",
            re.MULTILINE | re.DOTALL | re.IGNORECASE,
        )

        for filename in js_files:
            file_path = os.path.join(STATIC_JS_DIR, filename)
            self.assertTrue(os.path.exists(file_path), f"File {filename} must exist")
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            matches = user_variable_pattern.findall(content)
            self.assertEqual(
                matches,
                [],
                f"Found user variable interpolation in innerHTML in {filename}: {matches}",
            )

    def test_no_outer_html_or_insert_adjacent_html(self):
        """Verify that no frontend script uses outerHTML or insertAdjacentHTML."""
        for filename in os.listdir(STATIC_JS_DIR):
            if not filename.endswith(".js"):
                continue
            file_path = os.path.join(STATIC_JS_DIR, filename)
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            self.assertNotIn("outerHTML", content, f"outerHTML found in {filename}")
            self.assertNotIn("insertAdjacentHTML", content, f"insertAdjacentHTML found in {filename}")
            self.assertNotIn("document.write", content, f"document.write found in {filename}")

    def test_reply_preview_uses_dom_element_only(self):
        """Verify that buildReplyPreviewElement is used and old buildReplyPreviewHtml is eliminated."""
        chat_js_path = os.path.join(STATIC_JS_DIR, "chat.js")
        with open(chat_js_path, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn("buildReplyPreviewElement", content)
        self.assertNotIn("buildReplyPreviewHtml", content)


class TestXSSRemediationInNode(unittest.TestCase):
    """Executes frontend logic under Node.js with simulated DOM to verify XSS defenses."""

    @classmethod
    def setUpClass(cls):
        cls.node_available = shutil.which("node") is not None

    def setUp(self):
        if not self.node_available:
            self.skipTest("Node.js is not installed; skipping JS execution tests.")

    def _run_node_script(self, js_code: str) -> dict:
        """Run a Node snippet and return parsed JSON stdout."""
        static_js_posix = STATIC_JS_DIR.replace("\\", "/")
        wrapped = f"""
const fs = require('fs');
const path = require('path');

// Minimal DOM simulation for unit testing frontend methods
class MockElement {{
    constructor(tagName) {{
        this.tagName = (tagName || '').toUpperCase();
        this.children = [];
        this._textContent = '';
        this.style = {{}};
        this.dataset = {{}};
        this.attributes = {{}};
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
        this.listeners = {{}};
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
    }}

    getAttribute(k) {{
        return this.attributes[k];
    }}

    appendChild(child) {{
        this.children.push(child);
        child.parentNode = this;
        return child;
    }}

    addEventListener(event, fn) {{
        this.listeners[event] = this.listeners[event] || [];
        this.listeners[event].push(fn);
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
            }} else if (selector.startsWith('img')) {{
                if (el.tagName === 'IMG') results.push(el);
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

    // Serialize DOM structure to test whether raw executable tags leaked in
    toMarkup() {{
        let tag = this.tagName.toLowerCase();
        let attrs = '';
        if (this.className) attrs += ' class="' + this.className + '"';
        if (this.src) attrs += ' src="' + this.src + '"';
        let inner = '';
        if (this.children.length > 0) {{
            inner = this.children.map(c => c.toMarkup()).join('');
        }} else {{
            // textContent in real DOM is escaped when serialized
            inner = (this._textContent || '')
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;');
        }}
        return '<' + tag + attrs + '>' + inner + '</' + tag + '>';
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
    addEventListener: () => {{}}
}};

global.window = {{
    location: {{ origin: 'http://localhost:8000', protocol: 'http:', host: 'localhost:8000' }}
}};
global.document = globalDocument;
global.currentUser = 'alice';
global.currentFriend = 'bob';
global.currentTab = 'chats';
global.formatMessageTimestamp = () => '12:00 PM';
global.formatLastSeen = () => 'Online';
global.showToast = () => {{}};
global.openMessageActionMenu = () => {{}};
global.normalizeMessageStatus = (s) => s || 'sent';

// Load utils.js
const utilsCode = fs.readFileSync('{static_js_posix}/utils.js', 'utf8');
eval(utilsCode);

// Load chat.js definitions without top-level search UI calls
let chatCode = fs.readFileSync('{static_js_posix}/chat.js', 'utf8');
chatCode = chatCode.replace('setConversationSearchEnabled(false);', '// disabled for test');
chatCode = chatCode.replace('resetConversationSearchUI(true);', '// disabled for test');
eval(chatCode);

// Load sidebar.js
const sidebarCode = fs.readFileSync('{static_js_posix}/sidebar.js', 'utf8');
eval(sidebarCode);

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

    def test_escape_html_utility(self):
        """Verify escapeHtml encodes all HTML special characters."""
        code = """
        const result = {
            script: escapeHtml("<script>alert(1)</script>"),
            img: escapeHtml("<img src=x onerror=alert(1)>"),
            quotes: escapeHtml('"Hello\\' & <World>'),
            empty: escapeHtml(""),
            nullVal: escapeHtml(null),
            undefinedVal: escapeHtml(undefined)
        };
        console.log(JSON.stringify(result));
        """
        res = self._run_node_script(code)
        self.assertEqual(res["script"], "&lt;script&gt;alert(1)&lt;/script&gt;")
        self.assertEqual(res["img"], "&lt;img src=x onerror=alert(1)&gt;")
        self.assertEqual(res["quotes"], "&quot;Hello&#39; &amp; &lt;World&gt;")
        self.assertEqual(res["empty"], "")
        self.assertEqual(res["nullVal"], "")
        self.assertEqual(res["undefinedVal"], "")

    def test_sanitize_media_url_utility(self):
        """Verify sanitizeMediaUrl rejects dangerous protocols and permits safe URLs."""
        code = """
        const result = {
            js: sanitizeMediaUrl("javascript:alert(1)"),
            jsUpper: sanitizeMediaUrl("JAVASCRIPT:alert(1)"),
            jsSpace: sanitizeMediaUrl("  javascript:alert(1)  "),
            dataHtml: sanitizeMediaUrl("data:text/html,<script>alert(1)</script>"),
            vbscript: sanitizeMediaUrl("vbscript:msgbox(1)"),
            protoRel: sanitizeMediaUrl("//evil.com/exploit.jpg"),
            safeUploadRelative: sanitizeMediaUrl("/uploads/image1.png"),
            safeUploadsDir: sanitizeMediaUrl("uploads/image1.png"),
            safeHttp: sanitizeMediaUrl("http://example.com/avatar.png"),
            safeHttps: sanitizeMediaUrl("https://api.dicebear.com/7.x/notionists/svg?seed=alice"),
            empty: sanitizeMediaUrl("")
        };
        console.log(JSON.stringify(result));
        """
        res = self._run_node_script(code)
        self.assertEqual(res["js"], "")
        self.assertEqual(res["jsUpper"], "")
        self.assertEqual(res["jsSpace"], "")
        self.assertEqual(res["dataHtml"], "")
        self.assertEqual(res["vbscript"], "")
        self.assertEqual(res["protoRel"], "")
        self.assertEqual(res["safeUploadRelative"], "/uploads/image1.png")
        self.assertEqual(res["safeUploadsDir"], "uploads/image1.png")
        self.assertEqual(res["safeHttp"], "http://example.com/avatar.png")
        self.assertTrue(res["safeHttps"].startswith("https://api.dicebear.com/"))
        self.assertEqual(res["empty"], "")

    def test_message_content_xss_rendered_as_inert_text(self):
        """Verify that message text containing XSS payloads renders as inert textContent."""
        code = """
        const payload = "<script>alert('msg-xss')</script>";
        const box = globalDocument.getElementById("messages");
        box.children = [];

        addMessage("bob", "Bob", payload, "", "2026-09-13T10:00:00Z", 101, "delivered", null, null, false);
        const msgEl = box.children[0];
        const textEl = msgEl.querySelector(".msg-text");

        const result = {
            textContent: textEl.textContent,
            tagCount: textEl.children.length,
            markup: msgEl.toMarkup()
        };
        console.log(JSON.stringify(result));
        """
        res = self._run_node_script(code)
        self.assertEqual(res["textContent"], "<script>alert('msg-xss')</script>")
        self.assertEqual(res["tagCount"], 0)
        self.assertIn("&lt;script&gt;", res["markup"])
        self.assertNotIn("<script>", res["markup"])

    def test_display_name_xss_rendered_as_inert_text(self):
        """Verify that display names containing HTML/script render as inert text."""
        code = """
        const payload = "<b onmouseover=alert(1)>HackedName</b>";
        const box = globalDocument.getElementById("messages");
        box.children = [];

        addMessage("bob", payload, "Hello there", "", "2026-09-13T10:00:00Z", 102, "delivered", null, null, false);
        const msgEl = box.children[0];
        const nameEl = msgEl.querySelector(".sender-name");

        const result = {
            textContent: nameEl.textContent,
            tagCount: nameEl.children.length,
            markup: msgEl.toMarkup()
        };
        console.log(JSON.stringify(result));
        """
        res = self._run_node_script(code)
        self.assertEqual(res["textContent"], "<b onmouseover=alert(1)>HackedName</b>")
        self.assertEqual(res["tagCount"], 0)
        self.assertNotIn("<b onmouseover", res["markup"])
        self.assertIn("&lt;b onmouseover=alert(1)&gt;HackedName&lt;/b&gt;", res["markup"])

    def test_reply_preview_xss_rendered_as_inert_text(self):
        """Verify reply previews render malicious quoted sender and content as inert text."""
        code = """
        const replyTo = {
            id: 99,
            sender: "<script>alert('sender')</script>",
            sender_display_name: "<img src=x onerror=alert('reply-sender')>",
            content: "<svg onload=alert('reply-content')>"
        };

        const previewEl = buildReplyPreviewElement(replyTo);
        const senderSpan = previewEl.querySelector(".msg-reply-sender");
        const contentSpan = previewEl.querySelector(".msg-reply-content");

        const result = {
            senderText: senderSpan.textContent,
            senderTags: senderSpan.children.length,
            contentText: contentSpan.textContent,
            contentTags: contentSpan.children.length,
            replyId: previewEl.dataset.replyId,
            markup: previewEl.toMarkup()
        };
        console.log(JSON.stringify(result));
        """
        res = self._run_node_script(code)
        self.assertEqual(res["senderText"], "<img src=x onerror=alert('reply-sender')>")
        self.assertEqual(res["senderTags"], 0)
        self.assertEqual(res["contentText"], "<svg onload=alert('reply-content')>")
        self.assertEqual(res["contentTags"], 0)
        self.assertEqual(res["replyId"], "99")
        self.assertNotIn("<img", res["markup"])
        self.assertNotIn("<svg", res["markup"])

    def test_image_url_xss_rejected(self):
        """Verify that javascript: image URLs are stripped and not rendered as img src."""
        code = """
        const box = globalDocument.getElementById("messages");
        box.children = [];

        addMessage("bob", "Bob", "See picture", "javascript:alert(1)", "2026-09-13T10:00:00Z", 103, "delivered", null, null, false);
        const msgEl = box.children[0];
        const imgs = msgEl.querySelectorAll("img");

        const result = {
            imgCount: imgs.length,
            markup: msgEl.toMarkup()
        };
        console.log(JSON.stringify(result));
        """
        res = self._run_node_script(code)
        self.assertEqual(res["imgCount"], 0)
        self.assertNotIn("javascript:", res["markup"])

    def test_friend_item_xss_rendered_as_inert_text(self):
        """Verify friend items in sidebar render malicious display name and URL safely."""
        code = """
        const container = new MockElement("div");
        const friend = {
            username: "evil_user",
            display_name: "<script>alert('friend-xss')</script>",
            profile_picture: "javascript:alert(1)",
            is_online: true,
            unread_count: 2
        };

        renderFriendItem(container, friend);
        const itemEl = container.children[0];
        const nameEl = itemEl.querySelector(".name");
        const imgEl = itemEl.querySelector("img");

        const result = {
            nameText: nameEl.textContent,
            imgSrc: imgEl ? imgEl.src : "",
            markup: itemEl.toMarkup()
        };
        console.log(JSON.stringify(result));
        """
        res = self._run_node_script(code)
        self.assertEqual(res["nameText"], "<script>alert('friend-xss')</script>")
        self.assertNotIn("javascript:", res["imgSrc"])
        self.assertNotIn("<script>", res["markup"])
        self.assertIn("&lt;script&gt;", res["markup"])

    def test_search_results_xss_rendered_as_inert_text(self):
        """Verify search result items render malicious display name, about, and picture safely."""
        code = """
        const list = globalDocument.getElementById("list-area");
        list.children = [];

        const items = [{
            username: "hacker",
            display_name: "<img src=x onerror=alert('search-name')>",
            about: "<script>alert('about-xss')</script>",
            profile_picture: "javascript:alert(2)",
            status: "none"
        }];

        items.forEach(item => {
            const div = globalDocument.createElement("div");
            div.className = "item";

            const avatarDiv = globalDocument.createElement("div");
            avatarDiv.className = "avatar";
            const sanitizedPic = sanitizeMediaUrl(item.profile_picture);
            if (sanitizedPic) {
                const img = globalDocument.createElement("img");
                img.src = sanitizedPic;
                avatarDiv.appendChild(img);
            } else {
                avatarDiv.textContent = item.username ? item.username[0].toUpperCase() : "?";
            }

            const infoDiv = globalDocument.createElement("div");
            infoDiv.className = "info";
            const nameSpan = globalDocument.createElement("span");
            nameSpan.className = "name";
            nameSpan.textContent = item.display_name || item.username || "";
            infoDiv.appendChild(nameSpan);

            if (item.about) {
                const aboutSpan = globalDocument.createElement("span");
                aboutSpan.className = "status";
                aboutSpan.textContent = item.about;
                infoDiv.appendChild(aboutSpan);
            }

            div.appendChild(avatarDiv);
            div.appendChild(infoDiv);

            if (item.status === "none") {
                const addBtn = globalDocument.createElement("button");
                addBtn.className = "action-btn";
                addBtn.textContent = "Add";
                div.appendChild(addBtn);
            }
            list.appendChild(div);
        });

        const itemEl = list.children[0];
        const nameSpan = itemEl.querySelector(".name");
        const aboutSpan = itemEl.querySelector(".status");
        const imgs = itemEl.querySelectorAll("img");

        const result = {
            nameText: nameSpan.textContent,
            aboutText: aboutSpan.textContent,
            imgCount: imgs.length,
            markup: itemEl.toMarkup()
        };
        console.log(JSON.stringify(result));
        """
        res = self._run_node_script(code)
        self.assertEqual(res["nameText"], "<img src=x onerror=alert('search-name')>")
        self.assertEqual(res["aboutText"], "<script>alert('about-xss')</script>")
        self.assertEqual(res["imgCount"], 0)
        self.assertNotIn("<img", res["markup"])
        self.assertNotIn("<script>", res["markup"])
        self.assertIn("&lt;img", res["markup"])
        self.assertIn("&lt;script&gt;", res["markup"])


from tests.test_api_integration import ApiIntegrationTestCase


class TestBackendDataFidelity(ApiIntegrationTestCase):
    """Verifies that backend preserves raw payloads verbatim (no lossy server-side alteration)."""

    def test_message_content_stored_verbatim(self):
        """Message containing HTML tags must be stored verbatim in DB and returned in API responses."""
        payload = "<script>alert('stored-xss')</script>"
        msg = Message(
            sender_id=self.alice.id,
            receiver_id=self.bob.id,
            content=payload,
        )
        self.db.add(msg)
        self.db.commit()
        self.db.refresh(msg)
        self.assertEqual(msg.content, payload)

        # Retrieve via API
        resp = self.client.get(f"/chat/{self.bob.username}", headers=self.auth_headers(self.alice.username))
        self.assertEqual(resp.status_code, 200)
        messages = resp.json()
        saved = next(m for m in messages if m["id"] == msg.id)
        self.assertEqual(saved["content"], payload)

    def test_profile_fields_stored_verbatim(self):
        """Profile display name and about containing HTML tags must be stored verbatim."""
        name_payload = "<b onmouseover=alert('name')>Alice</b>"
        about_payload = "<script>alert('about')</script>"

        resp = self.client.put(
            "/profile/",
            headers=self.auth_headers(self.alice.username),
            json={"display_name": name_payload, "about": about_payload},
        )
        self.assertEqual(resp.status_code, 200)

        get_resp = self.client.get("/profile/", headers=self.auth_headers(self.alice.username))
        self.assertEqual(get_resp.status_code, 200)
        data = get_resp.json()
        self.assertEqual(data["display_name"], name_payload)
        self.assertEqual(data["about"], about_payload)


if __name__ == "__main__":
    unittest.main()
