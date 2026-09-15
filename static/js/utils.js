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
        fetchSecureMediaBlobUrl
    };
}

