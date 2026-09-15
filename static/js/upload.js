let currentUploadState = "idle"; // "idle" | "previewing" | "uploading" | "failed"
let currentUploadFile = null;
let currentUploadPreviewUrl = null;
let currentUploadXhr = null;

const CLIENT_MAX_IMAGE_SIZE = 10 * 1024 * 1024; // 10 MB limit
const CLIENT_MAX_VIDEO_SIZE = 50 * 1024 * 1024; // 50 MB limit
const CLIENT_MAX_FILE_SIZE = 25 * 1024 * 1024; // 25 MB limit
const CLIENT_MAX_VIDEO_DURATION = 120; // 120 seconds / 2 minutes
const ALLOWED_IMAGE_MIMES = ["image/jpeg", "image/png", "image/gif", "image/webp"];
const ALLOWED_VIDEO_MIMES = ["video/mp4", "video/webm"];
const ALLOWED_DOCUMENT_EXTS = ["pdf", "txt", "csv", "json", "docx", "xlsx", "pptx"];

function formatDuration(seconds) {
    if (!seconds || isNaN(seconds) || seconds < 0) return "0:00";
    const totalSec = Math.round(seconds);
    const mins = Math.floor(totalSec / 60);
    const secs = totalSec % 60;
    return `${mins}:${secs < 10 ? "0" : ""}${secs}`;
}

function getDocTypeDetails(fileName) {
    const ext = (fileName || "").toLowerCase().split(".").pop();
    switch (ext) {
        case "pdf": return { icon: "📄", badge: "PDF", name: "PDF Document" };
        case "docx": return { icon: "📝", badge: "DOCX", name: "Word Document" };
        case "xlsx": return { icon: "📊", badge: "XLSX", name: "Excel Sheet" };
        case "pptx": return { icon: "📽️", badge: "PPTX", name: "PowerPoint" };
        case "csv": return { icon: "📊", badge: "CSV", name: "CSV Data" };
        case "json": return { icon: "⚙️", badge: "JSON", name: "JSON Data" };
        case "txt": return { icon: "📄", badge: "TXT", name: "Text Document" };
        default: return { icon: "📎", badge: ext.toUpperCase() || "FILE", name: "File" };
    }
}

/* --- ATTACHMENT POPUP CONTROLS --- */
function closeAttachMenu() {
    const menu = document.getElementById("attach-menu");
    if (menu) menu.style.display = "none";
}

function toggleAttachMenu(event) {
    if (event) event.stopPropagation();
    const menu = document.getElementById("attach-menu");
    if (!menu) return;
    menu.style.display = (menu.style.display === "none" || !menu.style.display) ? "flex" : "none";
}

function openGalleryPicker() {
    closeAttachMenu();
    const input = document.getElementById("input-gallery");
    if (input) input.click();
}

function openDocumentPicker() {
    closeAttachMenu();
    const input = document.getElementById("input-document");
    if (input) input.click();
}

function openCameraPicker() {
    closeAttachMenu();
    const input = document.getElementById("input-camera");
    if (input) input.click();
}

// Global click & escape listeners to ensure popup closes per Clarification 5
document.addEventListener("click", (event) => {
    const attachMenu = document.getElementById("attach-menu");
    const attachBtn = document.getElementById("attach-btn");
    if (attachMenu && attachMenu.style.display !== "none") {
        if (!attachMenu.contains(event.target) && !attachBtn.contains(event.target)) {
            closeAttachMenu();
        }
    }
});

window.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
        closeAttachMenu();
    }
});

function handleFileSelect(inputElement) {
    if (!inputElement || !inputElement.files || inputElement.files.length === 0) return;
    const file = inputElement.files[0];

    if (!currentFriend) {
        showToast("Select a chat first", "error");
        inputElement.value = "";
        return;
    }

    const fileNameLower = (file.name || "").toLowerCase();
    const fileExt = fileNameLower.split(".").pop();
    const isVideo = (file.type && file.type.startsWith("video/")) ||
                    fileNameLower.endsWith(".mp4") ||
                    fileNameLower.endsWith(".webm");
    const isDoc = ALLOWED_DOCUMENT_EXTS.includes(fileExt);

    // Pre-validation: size & MIME / extension limits
    if (isVideo) {
        if (file.size > CLIENT_MAX_VIDEO_SIZE) {
            showToast("Video exceeds 50 MB limit", "error");
            inputElement.value = "";
            return;
        }
        if (file.type && !ALLOWED_VIDEO_MIMES.includes(file.type)) {
            showToast("Unsupported video format (MP4 and WebM supported)", "error");
            inputElement.value = "";
            return;
        }
    } else if (isDoc) {
        if (file.size > CLIENT_MAX_FILE_SIZE) {
            showToast("File exceeds 25 MB limit", "error");
            inputElement.value = "";
            return;
        }
    } else {
        if (file.size > CLIENT_MAX_IMAGE_SIZE) {
            showToast("Image exceeds 10 MB limit", "error");
            inputElement.value = "";
            return;
        }
        if (file.type && !ALLOWED_IMAGE_MIMES.includes(file.type)) {
            showToast("Unsupported or invalid image file type", "error");
            inputElement.value = "";
            return;
        }
    }

    // Cleanup any previous preview
    cleanupUploadPreview();

    inputElement.value = ""; // Reset input so same file can be re-selected if cancelled

    // If video, extract duration offscreen before displaying
    if (isVideo) {
        const tempVideo = document.createElement("video");
        tempVideo.preload = "metadata";
        const tempBlobUrl = URL.createObjectURL(file);

        tempVideo.onloadedmetadata = () => {
            const duration = tempVideo.duration;
            URL.revokeObjectURL(tempBlobUrl);
            if (duration && duration > CLIENT_MAX_VIDEO_DURATION) {
                showToast(`Video exceeds 2-minute duration limit (${formatDuration(duration)})`, "error");
                return;
            }
            displayMediaPreview(file, true, duration, false);
        };

        tempVideo.onerror = () => {
            URL.revokeObjectURL(tempBlobUrl);
            displayMediaPreview(file, true, null, false);
        };

        tempVideo.src = tempBlobUrl;
    } else if (isDoc) {
        displayMediaPreview(file, false, null, true);
    } else {
        displayMediaPreview(file, false, null, false);
    }
}

function displayMediaPreview(file, isVideo, duration, isDoc = false) {
    currentUploadFile = file;
    currentUploadPreviewUrl = URL.createObjectURL(file);
    currentUploadState = "previewing";

    const tray = document.getElementById("media-preview-tray");
    const thumbImg = document.getElementById("media-preview-img");
    const thumbVideo = document.getElementById("media-preview-video");
    const thumbDoc = document.getElementById("media-preview-doc-icon");
    const nameEl = document.getElementById("media-preview-name");
    const durationEl = document.getElementById("media-preview-duration");
    const sizeEl = document.getElementById("media-preview-size");
    const track = document.getElementById("media-progress-track");
    const fill = document.getElementById("media-progress-fill");
    const statusEl = document.getElementById("media-preview-status");
    const sendBtn = document.getElementById("media-preview-send-btn");
    const retryBtn = document.getElementById("media-preview-retry-btn");
    const cancelBtn = document.getElementById("media-preview-cancel-btn");

    if (isVideo) {
        if (thumbDoc) { thumbDoc.style.display = "none"; thumbDoc.textContent = ""; }
        if (thumbImg) { thumbImg.style.display = "none"; thumbImg.src = ""; }
        if (thumbVideo) {
            thumbVideo.src = currentUploadPreviewUrl;
            thumbVideo.style.display = "block";
        }
    } else if (isDoc) {
        if (thumbImg) { thumbImg.style.display = "none"; thumbImg.src = ""; }
        if (thumbVideo) { thumbVideo.style.display = "none"; thumbVideo.src = ""; }
        if (thumbDoc) {
            const docInfo = getDocTypeDetails(file.name);
            thumbDoc.textContent = docInfo.icon;
            thumbDoc.title = docInfo.name;
            thumbDoc.style.display = "flex";
        }
    } else {
        if (thumbDoc) { thumbDoc.style.display = "none"; thumbDoc.textContent = ""; }
        if (thumbVideo) { thumbVideo.style.display = "none"; thumbVideo.src = ""; }
        if (thumbImg) {
            thumbImg.src = currentUploadPreviewUrl;
            thumbImg.style.display = "block";
        }
    }

    if (nameEl) nameEl.textContent = file.name || (isVideo ? "video" : (isDoc ? "file" : "image"));

    if (durationEl) {
        if (isVideo && duration) {
            durationEl.textContent = formatDuration(duration);
            durationEl.style.display = "inline-block";
        } else {
            durationEl.textContent = "";
            durationEl.style.display = "none";
        }
    }

    if (sizeEl) {
        sizeEl.textContent = typeof formatFileSize === "function" ? formatFileSize(file.size) : `${Math.round(file.size / 1024)} KB`;
    }

    if (track) track.style.display = "none";
    if (fill) fill.style.width = "0%";
    if (statusEl) { statusEl.textContent = ""; statusEl.style.display = "none"; }
    if (sendBtn) sendBtn.style.display = "inline-block";
    if (retryBtn) retryBtn.style.display = "none";
    if (cancelBtn) cancelBtn.style.display = "inline-block";

    if (tray) tray.style.display = "flex";
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
                    const fileNameLower = (currentUploadFile.name || "").toLowerCase();
                    const fileExt = fileNameLower.split(".").pop();
                    const isVideo = currentUploadFile && (
                        (currentUploadFile.type && currentUploadFile.type.startsWith("video/")) ||
                        fileNameLower.endsWith(".mp4") ||
                        fileNameLower.endsWith(".webm")
                    );
                    const isDoc = currentUploadFile && ALLOWED_DOCUMENT_EXTS.includes(fileExt);

                    // Seed secure media cache with local preview blob URL for instant display
                    if (typeof seedSecureMediaCache === "function" && currentUploadPreviewUrl) {
                        seedSecureMediaCache(data.url, currentUploadPreviewUrl);
                    }

                    // Send chat message via existing WebSocket
                    const payload = {
                        type: "chat",
                        room: currentFriend,
                        text: "",
                        image_url: (!isVideo && !isDoc) ? data.url : null,
                        video_url: isVideo ? data.url : null,
                        file_url: isDoc ? data.url : null,
                        file_name: isDoc ? (data.filename || currentUploadFile.name) : null,
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
            handleUploadError("Unsupported media format");
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

    const thumbImg = document.getElementById("media-preview-img");
    if (thumbImg) { thumbImg.src = ""; thumbImg.style.display = "none"; }

    const thumbVideo = document.getElementById("media-preview-video");
    if (thumbVideo) { thumbVideo.src = ""; thumbVideo.style.display = "none"; }

    const thumbDoc = document.getElementById("media-preview-doc-icon");
    if (thumbDoc) { thumbDoc.textContent = ""; thumbDoc.style.display = "none"; }

    const durationEl = document.getElementById("media-preview-duration");
    if (durationEl) { durationEl.textContent = ""; durationEl.style.display = "none"; }

    const tray = document.getElementById("media-preview-tray");
    if (tray) tray.style.display = "none";
}

// Backward-compatible wrapper for legacy callers
function handleFileUpload(inputElement) {
    handleFileSelect(inputElement);
}


