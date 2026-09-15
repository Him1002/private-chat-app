let currentUploadState = "idle"; // "idle" | "previewing" | "uploading" | "failed"
let currentUploadFile = null;
let currentUploadPreviewUrl = null;
let currentUploadXhr = null;

const CLIENT_MAX_IMAGE_SIZE = 10 * 1024 * 1024; // 10 MB limit
const ALLOWED_IMAGE_MIMES = ["image/jpeg", "image/png", "image/gif", "image/webp"];

function handleFileSelect(inputElement) {
    if (!inputElement || !inputElement.files || inputElement.files.length === 0) return;
    const file = inputElement.files[0];

    if (!currentFriend) {
        showToast("Select a chat first", "error");
        inputElement.value = "";
        return;
    }

    // Client-side pre-validation: size limit
    if (file.size > CLIENT_MAX_IMAGE_SIZE) {
        showToast("Image exceeds 10 MB limit", "error");
        inputElement.value = "";
        return;
    }

    // Client-side pre-validation: MIME type
    if (file.type && !ALLOWED_IMAGE_MIMES.includes(file.type)) {
        showToast("Unsupported or invalid image file type", "error");
        inputElement.value = "";
        return;
    }

    // Cleanup any previous preview
    cleanupUploadPreview();

    currentUploadFile = file;
    currentUploadPreviewUrl = URL.createObjectURL(file);
    currentUploadState = "previewing";

    // Show and populate preview tray
    const tray = document.getElementById("media-preview-tray");
    const thumb = document.getElementById("media-preview-img");
    const nameEl = document.getElementById("media-preview-name");
    const sizeEl = document.getElementById("media-preview-size");
    const track = document.getElementById("media-progress-track");
    const fill = document.getElementById("media-progress-fill");
    const statusEl = document.getElementById("media-preview-status");
    const sendBtn = document.getElementById("media-preview-send-btn");
    const retryBtn = document.getElementById("media-preview-retry-btn");
    const cancelBtn = document.getElementById("media-preview-cancel-btn");

    if (thumb) thumb.src = currentUploadPreviewUrl;
    if (nameEl) nameEl.textContent = file.name || "image";
    if (sizeEl) sizeEl.textContent = typeof formatFileSize === "function" ? formatFileSize(file.size) : `${Math.round(file.size / 1024)} KB`;
    if (track) track.style.display = "none";
    if (fill) fill.style.width = "0%";
    if (statusEl) { statusEl.textContent = ""; statusEl.style.display = "none"; }
    if (sendBtn) sendBtn.style.display = "inline-block";
    if (retryBtn) retryBtn.style.display = "none";
    if (cancelBtn) cancelBtn.style.display = "inline-block";

    if (tray) tray.style.display = "flex";

    inputElement.value = ""; // Reset file input so same file can be re-selected if cancelled
}

function startUpload() {
    if (!currentUploadFile || currentUploadState === "uploading") return;
    if (!currentFriend) {
        showToast("Select a chat first", "error");
        cancelUpload();
        return;
    }

    currentUploadState = "uploading";

    const track = document.getElementById("media-progress-track");
    const fill = document.getElementById("media-progress-fill");
    const statusEl = document.getElementById("media-preview-status");
    const sendBtn = document.getElementById("media-preview-send-btn");
    const retryBtn = document.getElementById("media-preview-retry-btn");

    if (track) track.style.display = "block";
    if (fill) fill.style.width = "0%";
    if (statusEl) {
        statusEl.textContent = "Uploading (0%)...";
        statusEl.style.display = "block";
    }
    if (sendBtn) sendBtn.style.display = "none";
    if (retryBtn) retryBtn.style.display = "none";

    const formData = new FormData();
    formData.append("file", currentUploadFile);

    const xhr = new XMLHttpRequest();
    currentUploadXhr = xhr;

    xhr.open("POST", "/upload");
    if (token) {
        xhr.setRequestHeader("Authorization", `Bearer ${token}`);
    }

    xhr.upload.onprogress = (e) => {
        if (e.lengthComputable) {
            const percent = Math.min(100, Math.round((e.loaded / e.total) * 100));
            if (fill) fill.style.width = `${percent}%`;
            if (statusEl) statusEl.textContent = `Uploading (${percent}%)...`;
        }
    };

    xhr.onload = () => {
        currentUploadXhr = null;
        if (xhr.status >= 200 && xhr.status < 300) {
            try {
                const data = JSON.parse(xhr.responseText);
                if (data && data.url) {
                    // Seed the secure media cache with our local preview blob URL so sender gets instant display
                    if (typeof seedSecureMediaCache === "function" && currentUploadPreviewUrl) {
                        seedSecureMediaCache(data.url, currentUploadPreviewUrl);
                    }

                    // Send chat message via existing WebSocket
                    const payload = {
                        type: "chat",
                        room: currentFriend,
                        text: "",
                        image_url: data.url
                    };
                    if (typeof activeReplyTarget !== "undefined" && activeReplyTarget) {
                        payload.reply_to_message_id = activeReplyTarget.messageId;
                    }
                    const sent = sendSocketPayload(payload);
                    if (!sent) {
                        showToast("Reconnecting chat...", "normal");
                    }
                    if (typeof cancelReplyMode === "function") {
                        cancelReplyMode(true);
                    }

                    closeUploadTrayOnly();
                    return;
                }
            } catch (err) {
                console.error("Failed to parse upload response:", err);
            }
            handleUploadError("Upload failed");
        } else if (xhr.status === 413) {
            handleUploadError("File too large (exceeds limit)");
        } else if (xhr.status === 415) {
            handleUploadError("Unsupported image format");
        } else {
            handleUploadError("Upload failed");
        }
    };

    xhr.onerror = () => {
        currentUploadXhr = null;
        handleUploadError("Network error during upload");
    };

    xhr.onabort = () => {
        currentUploadXhr = null;
        cleanupUploadPreview();
    };

    xhr.send(formData);
}

function handleUploadError(errorMsg) {
    currentUploadState = "failed";
    showToast(errorMsg, "error");

    const track = document.getElementById("media-progress-track");
    const statusEl = document.getElementById("media-preview-status");
    const retryBtn = document.getElementById("media-preview-retry-btn");
    const sendBtn = document.getElementById("media-preview-send-btn");

    if (track) track.style.display = "none";
    if (statusEl) {
        statusEl.textContent = errorMsg;
        statusEl.style.display = "block";
    }
    if (retryBtn) retryBtn.style.display = "inline-block";
    if (sendBtn) sendBtn.style.display = "none";
}

function retryUpload() {
    if (currentUploadState === "failed" && currentUploadFile) {
        startUpload();
    }
}

function cancelUpload() {
    if (currentUploadXhr) {
        currentUploadXhr.abort();
        currentUploadXhr = null;
    }
    cleanupUploadPreview();
}

function closeUploadTrayOnly() {
    currentUploadState = "idle";
    currentUploadFile = null;
    currentUploadPreviewUrl = null;
    const tray = document.getElementById("media-preview-tray");
    if (tray) tray.style.display = "none";
}

function cleanupUploadPreview() {
    if (currentUploadPreviewUrl) {
        try {
            URL.revokeObjectURL(currentUploadPreviewUrl);
        } catch (_) {}
        currentUploadPreviewUrl = null;
    }
    currentUploadFile = null;
    currentUploadState = "idle";
    currentUploadXhr = null;

    const tray = document.getElementById("media-preview-tray");
    if (tray) tray.style.display = "none";
}

// Backward-compatible wrapper for legacy callers
function handleFileUpload(inputElement) {
    handleFileSelect(inputElement);
}

