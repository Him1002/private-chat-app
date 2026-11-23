function showToast(msg, type = "normal") {
    const container = document.getElementById("toast-container");
    const div = document.createElement("div");
    div.className = `toast ${type}`;
    div.innerText = msg;
    container.appendChild(div);
    
    // Trigger animation
    setTimeout(() => div.classList.add("show"), 10);
    setTimeout(() => {
        div.classList.remove("show");
        setTimeout(() => div.remove(), 300);
    }, 3000);
}

function formatLastSeen(isoStr) {
    if (!isoStr) return "Offline";
    const date = new Date(isoStr + "Z");
    const now = new Date();
    const diffSeconds = Math.floor((now - date) / 1000);
    if (diffSeconds < 60) return "Online";
    if (diffSeconds < 3600) return `${Math.floor(diffSeconds / 60)}m ago`;
    if (diffSeconds < 86400) return `${Math.floor(diffSeconds / 3600)}h ago`;
    return `${Math.floor(diffSeconds / 86400)}d ago`;
}

function formatMessageTimestamp(timestamp) {
    if (!timestamp) return "";
    const date = new Date(timestamp);
    if (Number.isNaN(date.getTime())) return "";

    const day = String(date.getDate()).padStart(2, "0");
    const month = String(date.getMonth() + 1).padStart(2, "0");
    const year = date.getFullYear();

    let hours = date.getHours();
    const minutes = String(date.getMinutes()).padStart(2, "0");
    const seconds = String(date.getSeconds()).padStart(2, "0");
    const meridiem = hours >= 12 ? "PM" : "AM";
    hours = hours % 12;
    hours = hours ? hours : 12;

    return `${day}/${month}/${year} ${String(hours).padStart(2, "0")}:${minutes}:${seconds} ${meridiem}`;
}

function escapeHtml(str) {
    if (str === null || str === undefined) return "";
    return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
}

function sanitizeMediaUrl(url) {
    if (!url || typeof url !== "string") return "";
    const trimmed = url.trim();
    if (!trimmed) return "";

    const lower = trimmed.toLowerCase();
    if (
        lower.startsWith("javascript:") ||
        lower.startsWith("data:") ||
        lower.startsWith("vbscript:") ||
        lower.startsWith("//")
    ) {
        return "";
    }

    if (trimmed.startsWith("/uploads/") || trimmed.startsWith("uploads/") || trimmed.startsWith("/")) {
        return trimmed;
    }

    try {
        const base = (typeof window !== "undefined" && window.location && window.location.origin)
            ? window.location.origin
            : "http://localhost";
        const parsed = new URL(trimmed, base);
        if (parsed.protocol === "http:" || parsed.protocol === "https:") {
            return trimmed;
        }
    } catch (_) {
        return "";
    }

    return "";
}

function handleEnter(e) { if (e.key === "Enter") send(); }

const secureMediaCache = new Map();
const pendingMediaRequests = new Map();

function formatFileSize(bytes) {
    if (!bytes || bytes <= 0) return "0 B";
    const k = 1024;
    const sizes = ["B", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + " " + sizes[i];
}

function seedSecureMediaCache(url, objectUrl) {
    if (url && objectUrl) {
        secureMediaCache.set(url, objectUrl);
    }
}

function revokeSecureMediaCache() {
    for (const objectUrl of secureMediaCache.values()) {
        if (objectUrl && typeof objectUrl === "string" && objectUrl.startsWith("blob:")) {
            try {
                URL.revokeObjectURL(objectUrl);
            } catch (_) {}
        }
    }
    secureMediaCache.clear();
    pendingMediaRequests.clear();
}

async function fetchSecureMediaBlobUrl(url) {
    const validated = sanitizeMediaUrl(url);
    if (!validated) return null;

    // External URLs (e.g. DiceBear), data:, or blob: URLs pass through directly
    if (
        validated.startsWith("http://") ||
        validated.startsWith("https://") ||
        validated.startsWith("blob:") ||
        validated.startsWith("data:")
    ) {
        return validated;
    }

    if (secureMediaCache.has(validated)) {
        return secureMediaCache.get(validated);
    }

    if (pendingMediaRequests.has(validated)) {
        return pendingMediaRequests.get(validated);
    }

    const fetchPromise = (async () => {
        try {
            const authToken = (typeof token !== "undefined" && token) ? token : (typeof AppState !== "undefined" && AppState.token ? AppState.token : "");
            const headers = {};
            if (authToken) {
                headers["Authorization"] = `Bearer ${authToken}`;
            }
            const res = await fetch(validated, { headers });
            if (!res.ok) {
                return null;
            }
            const blob = await res.blob();
            const objectUrl = URL.createObjectURL(blob);
            secureMediaCache.set(validated, objectUrl);
            return objectUrl;
        } catch (_) {
            return null;
        } finally {
            pendingMediaRequests.delete(validated);
        }
    })();

    pendingMediaRequests.set(validated, fetchPromise);
    return fetchPromise;
}

function getDocTypeDetails(filename) {
    const ext = (filename || "").slice((filename || "").lastIndexOf(".")).toLowerCase();
    switch (ext) {
        case ".pdf":
            return { icon: "📕", badge: "PDF", canOpen: true };
        case ".txt":
            return { icon: "📄", badge: "TXT", canOpen: true };
        case ".csv":
            return { icon: "📊", badge: "CSV", canOpen: true };
        case ".json":
            return { icon: "📋", badge: "JSON", canOpen: true };
        case ".docx":
            return { icon: "📘", badge: "DOCX", canOpen: false };
        case ".xlsx":
            return { icon: "📗", badge: "XLSX", canOpen: false };
        case ".pptx":
            return { icon: "📙", badge: "PPTX", canOpen: false };
        default:
            return { icon: "📎", badge: "FILE", canOpen: false };
    }
}

const YOUTUBE_ALLOWED_HOSTS = new Set([
    "youtube.com",
    "www.youtube.com",
    "m.youtube.com",
    "youtu.be",
    "www.youtu.be",
    "youtube-nocookie.com",
    "www.youtube-nocookie.com"
]);
const YOUTUBE_VIDEO_ID_REGEX = /^[A-Za-z0-9_-]{11}$/;

function parseYouTubeTimestamp(timeParam) {
    if (!timeParam || typeof timeParam !== "string") return null;
    const clean = timeParam.trim().toLowerCase();
    if (/^\d+$/.test(clean)) return parseInt(clean, 10);
    const match = clean.match(/^(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s?)?$/);
    if (!match) return null;
    const hours = parseInt(match[1] || "0", 10);
    const minutes = parseInt(match[2] || "0", 10);
    const seconds = parseInt(match[3] || "0", 10);
    const total = hours * 3600 + minutes * 60 + seconds;
    return total > 0 ? total : null;
}

function parseYouTubeVideo(text) {
    if (!text || typeof text !== "string") return null;
    const urlRegex = /(?:https?:\/\/[^\s<>"'`]+|(?:\b(?:www\.|m\.)?youtube(?:-nocookie)?\.com\/[^\s<>"'`]+|\byoutu\.be\/[^\s<>"'`]+))/gi;
    const matches = text.match(urlRegex);
    if (!matches) return null;

    for (const rawMatch of matches) {
        const cleanUrl = rawMatch.replace(/[.,!?:;)\]"']+$/, "");
        if (!cleanUrl) continue;

        let candidateUrl = cleanUrl;
        if (!/^https?:\/\//i.test(candidateUrl)) {
            candidateUrl = "https://" + candidateUrl;
        }

        let urlObj;
        try {
            urlObj = new URL(candidateUrl);
        } catch (_) {
            continue;
        }

        if (urlObj.protocol !== "http:" && urlObj.protocol !== "https:") {
            continue;
        }

        const hostname = urlObj.hostname.toLowerCase();
        if (!YOUTUBE_ALLOWED_HOSTS.has(hostname)) {
            continue;
        }

        let candidateId = "";
        let isShort = false;
        const parts = urlObj.pathname.split("/").filter(Boolean);

        if (hostname === "youtu.be" || hostname === "www.youtu.be") {
            candidateId = parts[0] || "";
            isShort = false;
        } else {
            if (parts[0] === "shorts") {
                candidateId = parts[1] || "";
                isShort = true;
            } else if (parts[0] === "embed") {
                candidateId = parts[1] || "";
                isShort = false;
            } else if (parts[0] === "watch" || urlObj.pathname === "/watch") {
                candidateId = urlObj.searchParams.get("v") || "";
                isShort = false;
            }
        }

        if (!candidateId || !YOUTUBE_VIDEO_ID_REGEX.test(candidateId)) {
            continue;
        }

        const rawTime = urlObj.searchParams.get("t") || urlObj.searchParams.get("start");
        const startSec = parseYouTubeTimestamp(rawTime);
        const startParam = startSec ? `&start=${startSec}` : "";

        return {
            videoId: candidateId,
            isShort: isShort,
            url: candidateUrl,
            embedUrl: `https://www.youtube-nocookie.com/embed/${candidateId}?autoplay=1&rel=0${startParam}`,
            thumbnailUrl: isShort
                ? `https://i.ytimg.com/vi/${candidateId}/oardefault.jpg`
                : `https://i.ytimg.com/vi/${candidateId}/hqdefault.jpg`,
            watchUrl: isShort
                ? `https://www.youtube.com/shorts/${candidateId}`
                : `https://www.youtube.com/watch?v=${candidateId}${startSec ? `&t=${startSec}s` : ""}`
        };
    }

    return null;
}

if (typeof module !== "undefined" && module.exports) {
    module.exports = {
        escapeHtml,
        sanitizeMediaUrl,
        formatMessageTimestamp,
        formatLastSeen,
        showToast,
        handleEnter,
        formatFileSize,
        seedSecureMediaCache,
        revokeSecureMediaCache,
        fetchSecureMediaBlobUrl,
        getDocTypeDetails,
        parseYouTubeVideo,
        parseYouTubeTimestamp
    };
}


