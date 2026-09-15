let activeMessageEdit = null;
let activeReplyTarget = null;
let activeConversationSearchQuery = "";
let activeConversationSearchRequestId = 0;

const REACTION_EMOJIS = ["👍", "❤️", "😂", "😮", "😢", "😡", "🔥", "👏", "🎉", "💯"];

function closeReactionPicker() {
    const picker = document.querySelector(".reaction-picker");
    if (picker) picker.remove();
}

function openReactionPicker(messageEl) {
    closeReactionPicker();
    closeMessageActionMenu();

    const messageId = messageEl.dataset.messageId;
    if (!messageId) return;

    const picker = document.createElement("div");
    picker.className = "reaction-picker";

    REACTION_EMOJIS.forEach((emoji) => {
        const btn = document.createElement("button");
        btn.type = "button";
        btn.className = "reaction-picker-emoji";
        btn.textContent = emoji;
        btn.addEventListener("click", (e) => {
            e.stopPropagation();
            sendSocketPayload({
                type: "reaction_add",
                message_id: messageId,
                emoji: emoji,
            });
            closeReactionPicker();
        });
        picker.appendChild(btn);
    });

    // Position the picker near the message
    const msgRect = messageEl.getBoundingClientRect();
    const isMe = messageEl.classList.contains("me");
    picker.style.position = "fixed";
    picker.style.zIndex = "2100";

    // Temporarily add to DOM to measure
    picker.style.visibility = "hidden";
    document.body.appendChild(picker);
    const pickerRect = picker.getBoundingClientRect();
    picker.style.visibility = "";

    let left = isMe ? msgRect.right - pickerRect.width : msgRect.left;
    let top = msgRect.top - pickerRect.height - 6;
    if (top < 8) top = msgRect.bottom + 6;
    left = Math.max(8, Math.min(left, window.innerWidth - pickerRect.width - 8));

    picker.style.left = `${left}px`;
    picker.style.top = `${top}px`;
}

function renderMessageReactions(messageEl, reactions) {
    if (!messageEl) return;

    let container = messageEl.querySelector(".msg-reactions");

    if (!reactions || reactions.length === 0) {
        if (container) container.remove();
        return;
    }

    if (!container) {
        container = document.createElement("div");
        container.className = "msg-reactions";
        messageEl.appendChild(container);
    }

    container.innerHTML = "";

    reactions.forEach((r) => {
        const chip = document.createElement("button");
        chip.type = "button";
        chip.className = "reaction-chip";

        const isActive = Array.isArray(r.usernames) && r.usernames.includes(currentUser);
        if (isActive) chip.classList.add("active");

        chip.textContent = `${r.emoji} ${r.count}`;
        chip.title = (r.usernames || []).join(", ");

        chip.addEventListener("click", (e) => {
            e.stopPropagation();
            if (isActive) {
                sendSocketPayload({
                    type: "reaction_remove",
                    message_id: messageEl.dataset.messageId,
                    emoji: r.emoji,
                });
            } else {
                sendSocketPayload({
                    type: "reaction_add",
                    message_id: messageEl.dataset.messageId,
                    emoji: r.emoji,
                });
            }
        });

        container.appendChild(chip);
    });
}

function updateMessageReactions(messageId, reactions) {
    if (!messageId) return;
    const safeId = String(messageId).replace(/[^a-zA-Z0-9_-]/g, "");
    if (!safeId) return;
    // Select all messages with this ID (handles potential duplicate optimistic UI nodes)
    const messageEls = document.querySelectorAll(`.msg[data-message-id="${safeId}"]`);
    if (messageEls.length === 0) {
        console.warn("Message element not found for reactions:", messageId);
        return;
    }
    messageEls.forEach((messageEl) => {
        renderMessageReactions(messageEl, reactions);
    });
}

function setConversationSearchEnabled(enabled) {
    const searchInput = document.getElementById("chat-search-input");
    const clearButton = document.getElementById("chat-search-clear");
    if (searchInput) {
        searchInput.disabled = !enabled;
        if (!enabled) {
            searchInput.value = "";
        }
    }
    if (clearButton) {
        clearButton.disabled = !enabled;
    }
}

function resetConversationSearchUI(clearInput = true) {
    activeConversationSearchQuery = "";
    activeConversationSearchRequestId += 1;

    const resultsEl = document.getElementById("chat-search-results");
    if (resultsEl) {
        resultsEl.innerHTML = "";
        resultsEl.style.display = "none";
    }

    if (clearInput) {
        const searchInput = document.getElementById("chat-search-input");
        if (searchInput) {
            searchInput.value = "";
        }
    }
}

function createSearchResultMeta(message) {
    const senderLabel = message.sender === currentUser ? "You" : message.sender;
    const timeLabel = formatMessageTimestamp(message.timestamp);
    return timeLabel ? `${senderLabel} • ${timeLabel}` : senderLabel;
}

function jumpToMessageById(messageId) {
    if (!messageId) return;
    const safeId = String(messageId).replace(/[^a-zA-Z0-9_-]/g, "");
    if (!safeId) return;
    const target = document.querySelector(`.msg[data-message-id="${safeId}"]`);
    if (!target) {
        showToast("Message not available in this chat", "normal");
        return;
    }

    target.scrollIntoView({ behavior: "smooth", block: "center" });
    selectMessage(target);
    target.classList.add("search-match-flash");
    window.setTimeout(() => target.classList.remove("search-match-flash"), 1500);
}

function renderConversationSearchResults(results, query) {
    const resultsEl = document.getElementById("chat-search-results");
    if (!resultsEl) return;

    resultsEl.innerHTML = "";
    const normalizedQuery = (query || "").trim();
    if (!normalizedQuery) {
        resultsEl.style.display = "none";
        return;
    }

    resultsEl.style.display = "block";

    if (!Array.isArray(results) || results.length === 0) {
        const emptyState = document.createElement("div");
        emptyState.className = "chat-search-empty";
        emptyState.innerText = `No messages found for "${normalizedQuery}"`;
        resultsEl.appendChild(emptyState);
        return;
    }

    results.forEach((message) => {
        const itemButton = document.createElement("button");
        itemButton.type = "button";
        itemButton.className = "chat-search-result-item";
        itemButton.dataset.messageId = String(message.id || "");

        const meta = document.createElement("div");
        meta.className = "chat-search-result-meta";
        meta.innerText = createSearchResultMeta(message);

        const content = document.createElement("div");
        content.className = "chat-search-result-content";
        content.innerText = message.content || "";

        itemButton.appendChild(meta);
        itemButton.appendChild(content);
        itemButton.addEventListener("click", () => {
            jumpToMessageById(message.id);
        });

        resultsEl.appendChild(itemButton);
    });
}

async function searchConversationMessages(query) {
    if (!currentFriend) {
        resetConversationSearchUI(false);
        return;
    }

    const normalizedQuery = (query || "").trim();
    activeConversationSearchQuery = normalizedQuery;
    const requestId = ++activeConversationSearchRequestId;

    if (!normalizedQuery) {
        renderConversationSearchResults([], "");
        return;
    }

    try {
        const response = await fetch(
            `/chat/${encodeURIComponent(currentFriend)}/search?query=${encodeURIComponent(normalizedQuery)}`,
            {
                headers: {
                    "Authorization": `Bearer ${token}`,
                },
            }
        );

        if (requestId !== activeConversationSearchRequestId) return;

        if (!response.ok) {
            renderConversationSearchResults([], normalizedQuery);
            return;
        }

        const results = await response.json();
        renderConversationSearchResults(results, normalizedQuery);
    } catch (error) {
        if (requestId !== activeConversationSearchRequestId) return;
        showToast("Unable to search messages", "error");
    }
}

function handleConversationSearchInput(event) {
    const query = event.target ? event.target.value : "";
    searchConversationMessages(query);
}

function clearConversationSearch() {
    resetConversationSearchUI(true);
}

function startChat(friend, element) {
    //console.log("Friend Object Data:", friend);
    cancelMessageEdit(true);
    cancelReplyMode(true);
    resetConversationSearchUI(true);
    currentFriend = friend.username;
    friend.unread_count = 0;
    if (typeof updateSidebarUnread === "function") {
        updateSidebarUnread(friend.username, 0);
    }

    // UI Updates
    document.querySelectorAll(".item").forEach(el => el.classList.remove("active"));
    if (element) element.classList.add("active");

    document.getElementById("chat-title").innerText = friend.display_name || friend.username;
    if (typeof CallUI !== "undefined" && typeof CallUI.onChatSelected === "function") {
        CallUI.onChatSelected(friend);
    }
    const statusEl = document.getElementById("chat-status");

    // ✓ Using the exact 'is_online' property from your database/server
    if (friend.is_online) {
        statusEl.innerText = "Online";
        statusEl.className = "status online";
        statusEl.style.color = "#2ecc71"; // Green
    } else {
        statusEl.innerText = formatLastSeen(friend.last_seen);
        statusEl.className = "status offline";
        statusEl.style.color = "#888"; // Gray
    }
    statusEl.style.display = ""; // Reset display

    //document.getElementById("chat-status").innerText = formatLastSeen(friend.last_seen);

    // 🔐 CRITICAL: Wipe the "Welcome Screen" or old messages before loading new ones
    document.getElementById("messages").innerHTML = "";

    document.getElementById("msg-input").disabled = false;
    document.getElementById("send-btn").disabled = false;
    setConversationSearchEnabled(true);

    connectWebSocket();
    sendSocketPayload({ type: "join", room: currentFriend });

    //console.log("💥 [STEP 3] Received typing signal from:", data.sender);



    // Mobile Logic
    if (window.innerWidth <= 768) {
        document.body.classList.add("view-chat");
        document.body.classList.remove("view-list");
    }
}

function showTyping(sender) {
    if (sender === currentUser) return;

    const indicator = document.getElementById("typing-indicator");
    const statusEl = document.getElementById("chat-status");

    if (indicator) {
        indicator.innerText = `${sender} is typing...`;
        indicator.style.display = "block";
        if (statusEl) statusEl.style.display = "none";

        // Clear old timer if exists
        if (window.typingTimeout) clearTimeout(window.typingTimeout);

        // Hide after 3 seconds of silence
        window.typingTimeout = setTimeout(() => {
            indicator.style.display = "none";
            if (statusEl) statusEl.style.display = "";
        }, 3000); // 3000ms
    } else {
        console.error("✘ [STEP 3 FAILED] Could not find #typing-indicator div in HTML");
    }
}

function handleInput() {
    const input = document.getElementById("msg-input");
    const sendBtn = document.getElementById("send-btn");

    // 1. Enable/Disable Send Button
    sendBtn.disabled = (input.value.trim() === "");

    // 2. ✓ SEND TYPING SIGNAL
    // Only send if we have a friend selected and socket is open
    if (currentFriend) {
        console.log("📝 [STEP 1] Sending typing signal to:", currentFriend);

        sendSocketPayload({
            type: "typing",
            room: currentFriend // Tells server who to notify
        });
    } else if (ws) {
        console.warn("⚠️ [STEP 1 FAILED] Cannot send. Friend selected:", currentFriend, "WS State:", ws.readyState);
    }
}
function send() {
    const input = document.getElementById("msg-input");
    if (!currentFriend) return;

    if (activeMessageEdit) {
        const updatedText = input.value.trim();
        if (!updatedText) {
            showToast("Message text cannot be empty", "normal");
            return;
        }

        const sent = sendSocketPayload({
            type: "message_edit",
            room: currentFriend,
            message_id: activeMessageEdit.messageId,
            text: updatedText,
        });
        if (!sent) {
            showToast("Reconnecting chat...", "normal");
        }
        return;
    }

    if (!input.value) return;
    const payload = { type: "chat", room: currentFriend, text: input.value };
    if (activeReplyTarget) {
        payload.reply_to_message_id = activeReplyTarget.messageId;
    }
    const sent = sendSocketPayload(payload);
    if (!sent) {
        showToast("Reconnecting chat...", "normal");
        return;
    }
    input.value = "";
    cancelReplyMode(true);
}

function updateComposerForEditMode() {
    const input = document.getElementById("msg-input");
    const sendBtn = document.getElementById("send-btn");
    const banner = document.getElementById("edit-mode-banner");

    if (!input || !sendBtn || !banner) return;

    if (activeMessageEdit) {
        banner.style.display = "flex";
        sendBtn.innerText = "✔";
        sendBtn.title = "Save edit";
        input.placeholder = "Edit message...";
    } else {
        banner.style.display = "none";
        sendBtn.innerHTML = "&#10148;";
        sendBtn.title = "Send message";
        input.placeholder = "Message...";
    }
}

function isMessageDeleted(messageEl) {
    if (!messageEl) return false;
    return messageEl.dataset.isDeleted === "true" || Boolean(messageEl.dataset.deletedAt);
}

function canEditMessage(messageEl) {
    if (!messageEl || !messageEl.classList.contains("me") || isMessageDeleted(messageEl)) return false;
    if (messageEl.dataset.fileUrl || messageEl.dataset.videoUrl || messageEl.dataset.imageUrl || messageEl.dataset.mediaType === "file") {
        return false;
    }
    const messageText = (messageEl.dataset.text || "").trim();
    return Boolean(messageText);
}

function canDeleteMessage(messageEl) {
    if (!messageEl || !messageEl.classList.contains("me")) return false;
    return !isMessageDeleted(messageEl);
}

function applyDeletedState(messageEl, deletedAt) {
    if (!messageEl) return;

    const deletedText = "This message was deleted";
    messageEl.dataset.isDeleted = "true";
    messageEl.dataset.deletedAt = deletedAt || messageEl.dataset.deletedAt || "";
    messageEl.dataset.text = deletedText;

    const imageEl = messageEl.querySelector("img");
    if (imageEl) imageEl.remove();

    const videoEl = messageEl.querySelector("video");
    if (videoEl) videoEl.remove();

    const fileEl = messageEl.querySelector(".msg-file-card");
    if (fileEl) fileEl.remove();

    const editedEl = messageEl.querySelector(".msg-edited");
    if (editedEl) editedEl.remove();

    let textEl = messageEl.querySelector(".msg-text");
    if (!textEl) {
        textEl = document.createElement("span");
        textEl.className = "msg-text";
        const timeEl = messageEl.querySelector(".msg-time");
        if (timeEl) {
            messageEl.insertBefore(textEl, timeEl);
        } else {
            messageEl.appendChild(textEl);
        }
    }
    textEl.textContent = deletedText;
}

function updateDeletedMessage(messageId, deletedText, deletedAt) {
    if (!messageId) return;

    const messageEl = document.querySelector(`.msg[data-message-id="${messageId}"]`);
    if (!messageEl) return;

    applyDeletedState(messageEl, deletedAt);
    if (activeMessageEdit && String(activeMessageEdit.messageId) === String(messageId)) {
        cancelMessageEdit(true);
    }
}

function enterMessageEditMode(messageEl) {
    if (!canEditMessage(messageEl)) {
        showToast("Only your text messages can be edited", "normal");
        return;
    }

    cancelReplyMode(true);

    const input = document.getElementById("msg-input");
    const messageText = messageEl.dataset.text || "";
    const messageId = messageEl.dataset.messageId;
    if (!input || !messageId) return;

    activeMessageEdit = {
        messageId,
        originalText: messageText,
    };

    input.value = messageText;
    updateComposerForEditMode();
    input.focus();
    input.setSelectionRange(input.value.length, input.value.length);
    document.getElementById("send-btn").disabled = (input.value.trim() === "");
}

function cancelMessageEdit(silent = false) {
    if (!activeMessageEdit) return;

    activeMessageEdit = null;
    updateComposerForEditMode();

    const input = document.getElementById("msg-input");
    if (input) {
        input.value = "";
    }
    handleInput();

    if (!silent) {
        showToast("Edit canceled", "normal");
    }
}

function enterReplyMode(messageEl) {
    if (!messageEl) return;
    const messageId = messageEl.dataset.messageId;
    if (!messageId) return;

    cancelMessageEdit(true);

    const isDeleted = isMessageDeleted(messageEl);
    const senderName = messageEl.querySelector(".sender-name");
    const sender = messageEl.classList.contains("me") ? "You" : (senderName ? senderName.textContent : "");
    let mediaPlaceholder = "";
    if (messageEl.dataset.fileUrl || messageEl.dataset.mediaType === "file") {
        mediaPlaceholder = `📎 ${messageEl.dataset.fileName || "File"}`;
    } else if (messageEl.dataset.videoUrl) {
        mediaPlaceholder = "🎥 Video";
    } else if (messageEl.dataset.imageUrl) {
        const urlLower = messageEl.dataset.imageUrl.toLowerCase();
        mediaPlaceholder = (urlLower.endsWith(".mp4") || urlLower.endsWith(".webm")) ? "🎥 Video" : "📷 Photo";
    }
    let content = isDeleted ? "This message was deleted" : (messageEl.dataset.text || mediaPlaceholder);
    if (!isDeleted && (messageEl.dataset.fileUrl || messageEl.dataset.mediaType === "file")) {
        content = mediaPlaceholder;
    }

    activeReplyTarget = {
        messageId,
        sender,
        content,
    };

    updateComposerForReplyMode();
    const input = document.getElementById("msg-input");
    if (input) input.focus();
}

function cancelReplyMode(silent = false) {
    if (!activeReplyTarget) return;
    activeReplyTarget = null;
    updateComposerForReplyMode();
}

function updateComposerForReplyMode() {
    const banner = document.getElementById("reply-mode-banner");
    if (!banner) return;

    if (activeReplyTarget) {
        const senderEl = banner.querySelector(".reply-banner-sender");
        const contentEl = banner.querySelector(".reply-banner-content");
        if (senderEl) senderEl.textContent = activeReplyTarget.sender;
        if (contentEl) contentEl.textContent = activeReplyTarget.content;
        banner.style.display = "flex";
    } else {
        banner.style.display = "none";
    }
}

function applyEditedIndicator(messageEl, editedAt) {
    if (!messageEl) return;

    const normalizedEditedAt = editedAt || "";
    messageEl.dataset.editedAt = normalizedEditedAt;

    let editedEl = messageEl.querySelector(".msg-edited");
    if (!normalizedEditedAt) {
        if (editedEl) editedEl.remove();
        return;
    }

    if (!editedEl) {
        editedEl = document.createElement("span");
        editedEl.className = "msg-edited";
        editedEl.textContent = "(edited)";
        const timeEl = messageEl.querySelector(".msg-time");
        if (timeEl) {
            messageEl.insertBefore(editedEl, timeEl);
        } else {
            messageEl.appendChild(editedEl);
        }
    }
}

function applyMessageText(messageEl, text) {
    if (!messageEl) return;
    const normalizedText = text || "";
    messageEl.dataset.text = normalizedText;

    let textEl = messageEl.querySelector(".msg-text");
    if (!normalizedText) {
        if (textEl) textEl.remove();
        return;
    }

    if (!textEl) {
        textEl = document.createElement("span");
        textEl.className = "msg-text";
        const imageEl = messageEl.querySelector("img");
        const editedEl = messageEl.querySelector(".msg-edited");
        const timeEl = messageEl.querySelector(".msg-time");
        if (imageEl) {
            imageEl.insertAdjacentElement("afterend", textEl);
        } else if (editedEl) {
            messageEl.insertBefore(textEl, editedEl);
        } else if (timeEl) {
            messageEl.insertBefore(textEl, timeEl);
        } else {
            messageEl.appendChild(textEl);
        }
    }

    textEl.textContent = normalizedText;
}

function updateMessageContent(messageId, text, editedAt) {
    if (!messageId) return;

    const messageEl = document.querySelector(`.msg[data-message-id="${messageId}"]`);
    if (!messageEl) {
        if (!window.pendingMessageEdits) {
            window.pendingMessageEdits = {};
        }
        window.pendingMessageEdits[String(messageId)] = { text, editedAt };
        return;
    }

    applyMessageText(messageEl, text);
    applyEditedIndicator(messageEl, editedAt);

    if (activeMessageEdit && String(activeMessageEdit.messageId) === String(messageId)) {
        activeMessageEdit = null;
        updateComposerForEditMode();
        const input = document.getElementById("msg-input");
        if (input) input.value = "";
        handleInput();
        showToast("Message updated", "normal");
    }
}

function closeMessageActionMenu() {
    const menu = document.querySelector(".message-action-menu");
    if (menu) menu.remove();
    document.querySelectorAll(".msg-menu-trigger").forEach((trigger) => {
        trigger.setAttribute("aria-expanded", "false");
    });
}

function openMessageActionMenu(messageEl, triggerEl) {
    closeMessageActionMenu();
    const canEdit = canEditMessage(messageEl);
    const canDelete = canDeleteMessage(messageEl);

    const menu = document.createElement("div");
    menu.className = "message-action-menu";
    menu.innerHTML = `
        <button type="button" class="message-action-item" data-action="copy">Copy Message</button>
        <button type="button" class="message-action-item" data-action="reply">Reply</button>
        <button type="button" class="message-action-item" data-action="react">React</button>
        <button type="button" class="message-action-item${canEdit ? "" : " disabled"}" data-action="edit"${canEdit ? "" : " disabled"}>Edit</button>
        <button type="button" class="message-action-item${canDelete ? "" : " disabled"}" data-action="delete"${canDelete ? "" : " disabled"}>Delete</button>
        <button type="button" class="message-action-item close" data-action="close">Close</button>
    `;

    const messageRect = messageEl.getBoundingClientRect();
    const triggerRect = triggerEl.getBoundingClientRect();
    const menuWidth = 180;
    const menuHeight = 220;
    const left = Math.min(window.innerWidth - menuWidth - 12, triggerRect.right - 18);
    const top = Math.min(window.innerHeight - menuHeight - 12, messageRect.top + 8);

    menu.style.position = "fixed";
    menu.style.left = `${Math.max(12, left)}px`;
    menu.style.top = `${Math.max(12, top)}px`;
    menu.style.zIndex = "2000";

    menu.addEventListener("click", (event) => {
        const button = event.target.closest(".message-action-item");
        if (!button) return;

        const action = button.dataset.action;
        const selectedText = messageEl.dataset.text || "";

        if (action === "copy") {
            const copyValue = selectedText || (messageEl.dataset.imageUrl || "");
            if (copyValue && navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(copyValue).catch(() => {
                    showToast("Copy unavailable", "normal");
                });
            } else {
                showToast("Copy unavailable", "normal");
            }
        } else if (action === "reply") {
            closeMessageActionMenu();
            enterReplyMode(messageEl);
            return;
        } else if (action === "edit") {
            if (!canEditMessage(messageEl)) {
                showToast("Only your text messages can be edited", "normal");
                closeMessageActionMenu();
                return;
            }
            closeMessageActionMenu();
            enterMessageEditMode(messageEl);
            return;
        } else if (action === "delete") {
            if (!canDeleteMessage(messageEl)) {
                showToast("Only your messages can be deleted", "normal");
                closeMessageActionMenu();
                return;
            }

            closeMessageActionMenu();
            const sent = sendSocketPayload({
                type: "message_delete",
                room: currentFriend,
                message_id: messageEl.dataset.messageId,
            });
            if (!sent) {
                showToast("Reconnecting chat...", "normal");
            }
            return;
        } else if (action === "close") {
            closeMessageActionMenu();
            return;
        } else if (action === "react") {
            event.stopPropagation();
            openReactionPicker(messageEl);
            return;
        }

        closeMessageActionMenu();
    });

    document.body.appendChild(menu);
    triggerEl.setAttribute("aria-expanded", "true");
}

function selectMessage(messageEl) {
    const allMessages = document.querySelectorAll(".msg");
    allMessages.forEach((msg) => {
        const isSelected = msg === messageEl;
        msg.classList.toggle("selected", isSelected);
        const time = msg.querySelector(".msg-time");
        const trigger = msg.querySelector(".msg-menu-trigger");
        if (time) time.style.display = isSelected ? "block" : "none";
        if (trigger) trigger.style.display = isSelected ? "inline-flex" : "none";
    });

    if (!messageEl) {
        closeMessageActionMenu();
        return;
    }

    closeMessageActionMenu();
}

function normalizeMessageStatus(status, isRead) {
    if (status === "read") return "read";
    if (status === "delivered") return "delivered";
    if (isRead) return "read";
    return "sent";
}

function getMessageTickLabel(status) {
    if (status === "read" || status === "delivered") return "✓✓";
    return "✓";
}

function applyMessageStatus(messageEl, status, readAt) {
    if (!messageEl) return;

    const nextStatus = normalizeMessageStatus(status, false);
    messageEl.dataset.status = nextStatus;
    if (readAt) {
        messageEl.dataset.readAt = readAt;
    }

    const statusEl = messageEl.querySelector(".msg-status");
    if (!statusEl) return;

    statusEl.textContent = getMessageTickLabel(nextStatus);
    statusEl.classList.remove("sent", "delivered", "read");
    statusEl.classList.add(nextStatus);
}

function updateMessageStatus(messageId, status, readAt) {
    if (!messageId) return;
    const messageEl = document.querySelector(`.msg[data-message-id="${messageId}"]`);
    if (messageEl) {
        applyMessageStatus(messageEl, status, readAt);
        return;
    }

    if (!window.pendingMessageStatuses) {
        window.pendingMessageStatuses = {};
    }
    window.pendingMessageStatuses[String(messageId)] = { status, readAt };
}

function updateMessagesRead(messageIds, readAt) {
    if (!Array.isArray(messageIds)) return;
    messageIds.forEach((messageId) => {
        updateMessageStatus(messageId, "read", readAt);
    });
}

function buildReplyPreviewElement(replyTo) {
    if (!replyTo) return null;
    const rawSender = replyTo.sender || "Unknown";
    const displayName = replyTo.sender_display_name || rawSender;
    const sender = rawSender === currentUser ? "You" : displayName;
    const content = replyTo.content || "📷 Photo";
    const replyId = replyTo.id ? String(replyTo.id) : "";

    const previewDiv = document.createElement("div");
    previewDiv.className = "msg-reply-preview";
    if (replyId) {
        previewDiv.dataset.replyId = replyId;
    }

    const senderSpan = document.createElement("span");
    senderSpan.className = "msg-reply-sender";
    senderSpan.textContent = sender;

    const contentSpan = document.createElement("span");
    contentSpan.className = "msg-reply-content";
    contentSpan.textContent = content;

    previewDiv.appendChild(senderSpan);
    previewDiv.appendChild(contentSpan);
    return previewDiv;
}

function openImageLightbox(src) {
    if (!src) return;
    const modal = document.getElementById("image-lightbox-modal");
    const img = document.getElementById("lightbox-img");
    if (!modal || !img) return;

    img.src = src;
    modal.style.display = "flex";

    window.addEventListener("keydown", handleLightboxKeyDown);
}

function closeImageLightbox() {
    const modal = document.getElementById("image-lightbox-modal");
    const img = document.getElementById("lightbox-img");
    if (!modal) return;

    modal.style.display = "none";
    if (img) img.src = "";
    window.removeEventListener("keydown", handleLightboxKeyDown);
}

function handleLightboxBackdropClick(event) {
    if (event && event.target && event.target.id === "image-lightbox-modal") {
        closeImageLightbox();
    }
}

function handleLightboxKeyDown(event) {
    if (event && event.key === "Escape") {
        closeImageLightbox();
    }
}

function isDocumentUrl(url) {
    if (!url || typeof url !== "string") return false;
    const clean = url.split("?")[0].toLowerCase();
    const docExts = [".pdf", ".txt", ".csv", ".json", ".docx", ".xlsx", ".pptx"];
    return docExts.some(ext => clean.endsWith(ext));
}

async function openSecureDocument(url) {
    const validated = sanitizeMediaUrl(url);
    if (!validated) return;
    if (typeof secureMediaCache !== "undefined" && secureMediaCache.has(validated)) {
        window.open(secureMediaCache.get(validated), "_blank", "noopener,noreferrer");
        return;
    }
    const newWin = window.open("", "_blank");
    if (newWin) {
        try {
            newWin.opener = null;
            newWin.document.title = "Loading document...";
        } catch (_) {}
    }
    try {
        const blobUrl = await fetchSecureMediaBlobUrl(validated);
        if (blobUrl) {
            if (newWin) {
                newWin.location.href = blobUrl;
            } else {
                window.open(blobUrl, "_blank", "noopener,noreferrer");
            }
        } else {
            if (newWin) newWin.close();
            showToast("Failed to open document", "normal");
        }
    } catch (err) {
        if (newWin) newWin.close();
        showToast("Error opening document", "normal");
    }
}

async function downloadSecureFile(url, fileName) {
    const validated = sanitizeMediaUrl(url);
    if (!validated) return;
    const downloadUrl = validated.includes("?") ? `${validated}&download=1` : `${validated}?download=1`;
    try {
        const authToken = (typeof token !== "undefined" && token) ? token : (typeof AppState !== "undefined" && AppState.token ? AppState.token : "");
        const headers = {};
        if (authToken) {
            headers["Authorization"] = `Bearer ${authToken}`;
        }
        const res = await fetch(downloadUrl, { headers });
        if (!res.ok) {
            showToast("Failed to download file", "normal");
            return;
        }
        const blob = await res.blob();
        const blobUrl = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = blobUrl;
        a.download = fileName || "download";
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        setTimeout(() => URL.revokeObjectURL(blobUrl), 1000);
    } catch (err) {
        showToast("Error downloading file", "normal");
    }
}

function addMessage(sender, senderDisplayName, text, imageUrl, timestamp, messageId, status, readAt, editedAt, isDeleted = false, deletedAt = "", reactions = null, replyTo = null, videoUrl = null, fileUrl = null, fileName = null, fileSize = null, mediaType = null) {
    const box = document.getElementById("messages");
    const isMe = sender === currentUser;
    const deleted = Boolean(isDeleted || text === "This message was deleted");
    const safeText = deleted ? "This message was deleted" : (text || "");

    // Resolve media: document, video, or image
    const rawMedia = fileUrl || videoUrl || imageUrl || "";
    const isDoc = (mediaType === "file") || Boolean(fileUrl) || (rawMedia && isDocumentUrl(rawMedia));
    const isVideo = !isDoc && (mediaType === "video" || Boolean(videoUrl) || (rawMedia && (rawMedia.toLowerCase().endsWith(".mp4") || rawMedia.toLowerCase().endsWith(".webm"))));
    const isImg = !isDoc && !isVideo && (mediaType === "image" || Boolean(imageUrl) || (rawMedia && !rawMedia.toLowerCase().endsWith(".mp4") && !rawMedia.toLowerCase().endsWith(".webm")));

    const safeVideoUrl = deleted ? "" : (isVideo ? rawMedia : "");
    const safeImageUrl = deleted ? "" : (isImg ? rawMedia : "");
    const safeFileUrl = deleted ? "" : (isDoc ? rawMedia : "");
    const safeFileName = deleted ? "" : (fileName || (isDoc ? (text || "Document") : ""));
    const safeFileSize = deleted ? null : fileSize;

    const div = document.createElement("div");
    div.className = `msg ${isMe ? "me" : "friend"}`;
    div.dataset.messageId = messageId || "";
    div.dataset.text = safeText;
    div.dataset.imageUrl = safeImageUrl;
    div.dataset.videoUrl = safeVideoUrl;
    div.dataset.fileUrl = safeFileUrl;
    div.dataset.fileName = safeFileName;
    div.dataset.mediaType = isDoc ? "file" : (isVideo ? "video" : (isImg ? "image" : "text"));
    div.dataset.status = normalizeMessageStatus(status, status === "read");
    div.dataset.editedAt = editedAt || "";
    div.dataset.isDeleted = deleted ? "true" : "false";
    if (deletedAt) {
        div.dataset.deletedAt = deletedAt;
    }
    if (readAt) {
        div.dataset.readAt = readAt;
    }

    // 1. Sender name for friend messages
    if (!isMe) {
        const displayName = senderDisplayName || sender || "";
        const nameEl = document.createElement("span");
        nameEl.className = "sender-name";
        nameEl.textContent = displayName;
        div.appendChild(nameEl);
    }

    // 2. Reply preview (constructed via safe DOM API)
    if (replyTo) {
        const replyPreviewEl = buildReplyPreviewElement(replyTo);
        if (replyPreviewEl) {
            replyPreviewEl.addEventListener("click", (event) => {
                event.stopPropagation();
                const replyId = replyPreviewEl.dataset.replyId;
                if (replyId) jumpToMessageById(replyId);
            });
            div.appendChild(replyPreviewEl);
        }
    }

    // 3. Media image / video / document with secure authenticated loading
    const validatedImageUrl = sanitizeMediaUrl(safeImageUrl);
    const validatedVideoUrl = sanitizeMediaUrl(safeVideoUrl);
    const validatedFileUrl = sanitizeMediaUrl(safeFileUrl);

    if (!deleted && validatedImageUrl) {
        const imgEl = document.createElement("img");
        imgEl.alt = "message image";
        imgEl.className = "msg-image loading";
        div.appendChild(imgEl);

        if (typeof fetchSecureMediaBlobUrl === "function") {
            fetchSecureMediaBlobUrl(validatedImageUrl).then((blobUrl) => {
                if (blobUrl) {
                    imgEl.src = blobUrl;
                    imgEl.classList.remove("loading");
                } else {
                    imgEl.remove();
                }
            }).catch(() => {
                imgEl.remove();
            });
        } else {
            imgEl.src = validatedImageUrl;
        }

        imgEl.addEventListener("click", (e) => {
            e.stopPropagation();
            if (imgEl.src) {
                openImageLightbox(imgEl.src);
            }
        });
    } else if (!deleted && validatedVideoUrl) {
        const videoEl = document.createElement("video");
        videoEl.className = "msg-video loading";
        videoEl.controls = true;
        videoEl.playsInline = true;
        videoEl.preload = "metadata";
        div.appendChild(videoEl);

        if (typeof secureMediaCache !== "undefined" && secureMediaCache.has(validatedVideoUrl)) {
            videoEl.src = secureMediaCache.get(validatedVideoUrl);
            videoEl.classList.remove("loading");
        } else if (typeof fetchSecureMediaBlobUrl === "function") {
            let fetched = false;
            const loadVideo = () => {
                if (fetched) return;
                fetched = true;
                fetchSecureMediaBlobUrl(validatedVideoUrl).then((blobUrl) => {
                    if (blobUrl) {
                        videoEl.src = blobUrl;
                        videoEl.classList.remove("loading");
                    } else {
                        videoEl.classList.remove("loading");
                    }
                }).catch(() => {
                    videoEl.classList.remove("loading");
                });
            };

            // Use IntersectionObserver so video only loads when scrolled into view
            if ("IntersectionObserver" in window) {
                const observer = new IntersectionObserver((entries) => {
                    entries.forEach((entry) => {
                        if (entry.isIntersecting) {
                            loadVideo();
                            observer.disconnect();
                        }
                    });
                }, { rootMargin: "200px" });
                observer.observe(videoEl);
            } else {
                loadVideo();
            }

            // Also load immediately if clicked before observer triggers
            videoEl.addEventListener("play", loadVideo, { once: true });
        } else {
            videoEl.src = validatedVideoUrl;
            videoEl.classList.remove("loading");
        }
    } else if (!deleted && validatedFileUrl) {
        const fileCard = document.createElement("div");
        fileCard.className = "msg-file-card";
        const typeDetails = (typeof getDocTypeDetails === "function")
            ? getDocTypeDetails(safeFileName || validatedFileUrl)
            : { icon: "📎", badge: "FILE", canOpen: false };

        const iconContainer = document.createElement("div");
        iconContainer.className = "msg-file-icon";

        const iconEmoji = document.createElement("span");
        iconEmoji.className = "msg-file-icon-emoji";
        iconEmoji.textContent = typeDetails.icon;

        const iconBadge = document.createElement("span");
        iconBadge.className = "msg-file-icon-badge";
        iconBadge.textContent = typeDetails.badge;

        iconContainer.appendChild(iconEmoji);
        iconContainer.appendChild(iconBadge);
        fileCard.appendChild(iconContainer);

        const infoContainer = document.createElement("div");
        infoContainer.className = "msg-file-info";

        const nameEl = document.createElement("span");
        nameEl.className = "msg-file-name";
        nameEl.textContent = safeFileName || "Document";
        nameEl.title = safeFileName || "Document";

        const metaEl = document.createElement("span");
        metaEl.className = "msg-file-meta";
        const sizeText = safeFileSize ? formatFileSize(safeFileSize) : "";
        metaEl.textContent = sizeText ? `${typeDetails.badge} • ${sizeText}` : typeDetails.badge;

        infoContainer.appendChild(nameEl);
        infoContainer.appendChild(metaEl);
        fileCard.appendChild(infoContainer);

        const actionsContainer = document.createElement("div");
        actionsContainer.className = "msg-file-actions";

        if (typeDetails.canOpen) {
            const openBtn = document.createElement("button");
            openBtn.type = "button";
            openBtn.className = "msg-file-btn open";
            openBtn.textContent = "Open";
            openBtn.title = "Open document in new tab";
            openBtn.addEventListener("click", (e) => {
                e.stopPropagation();
                openSecureDocument(validatedFileUrl);
            });
            actionsContainer.appendChild(openBtn);
        }

        const downloadBtn = document.createElement("button");
        downloadBtn.type = "button";
        downloadBtn.className = "msg-file-btn download";
        downloadBtn.textContent = "Download";
        downloadBtn.title = "Download file";
        downloadBtn.addEventListener("click", (e) => {
            e.stopPropagation();
            downloadSecureFile(validatedFileUrl, safeFileName);
        });
        actionsContainer.appendChild(downloadBtn);

        fileCard.appendChild(actionsContainer);
        div.appendChild(fileCard);
    }

    // 4. Message text
    if (safeText) {
        const isDocDuplicateText = isDoc && !deleted && (safeText === safeFileName || safeText === safeFileUrl);
        if (!isDocDuplicateText) {
            const textEl = document.createElement("span");
            textEl.className = "msg-text";
            textEl.textContent = safeText;
            div.appendChild(textEl);
        }
    }

    // 5. Edited indicator
    if (!deleted && editedAt) {
        const editedEl = document.createElement("span");
        editedEl.className = "msg-edited";
        editedEl.textContent = "(edited)";
        div.appendChild(editedEl);
    }

    // 6. Timestamp
    const timeLabel = formatMessageTimestamp(timestamp);
    if (timeLabel) {
        const timeEl = document.createElement("span");
        timeEl.className = "msg-time";
        timeEl.style.display = "none";
        timeEl.textContent = timeLabel;
        div.appendChild(timeEl);
    }

    // 7. Status ticks for sender
    if (isMe) {
        const statusEl = document.createElement("span");
        statusEl.className = "msg-status";
        div.appendChild(statusEl);
    }

    // 8. Action menu trigger button
    const trigger = document.createElement("button");
    trigger.type = "button";
    trigger.className = "msg-menu-trigger";
    trigger.style.display = "none";
    trigger.setAttribute("aria-label", "Open message actions");
    trigger.textContent = "...";
    trigger.addEventListener("click", (event) => {
        event.stopPropagation();
        openMessageActionMenu(div, trigger);
    });
    div.appendChild(trigger);

    div.addEventListener("click", (event) => {
        if (event.target.closest(".msg-menu-trigger") || event.target.closest(".message-action-menu") || event.target.closest(".message-action-item") || event.target.closest(".msg-reply-preview")) {
            return;
        }
        selectMessage(div);
    });

    box.appendChild(div);
    if (deleted) {
        applyDeletedState(div, deletedAt);
    }
    if (isMe) {
        applyMessageStatus(div, div.dataset.status, readAt);
        if (window.pendingMessageStatuses) {
            const pendingStatus = window.pendingMessageStatuses[String(messageId)];
            if (pendingStatus) {
                applyMessageStatus(div, pendingStatus.status, pendingStatus.readAt);
                delete window.pendingMessageStatuses[String(messageId)];
            }
        }
    }
    if (window.pendingMessageEdits) {
        const pendingEdit = window.pendingMessageEdits[String(messageId)];
        if (pendingEdit) {
            applyMessageText(div, pendingEdit.text);
            applyEditedIndicator(div, pendingEdit.editedAt);
            delete window.pendingMessageEdits[String(messageId)];
        }
    }
    box.scrollTop = box.scrollHeight;

    // Render reactions if present
    if (reactions && Array.isArray(reactions) && reactions.length > 0) {
        renderMessageReactions(div, reactions);
    }
}

document.addEventListener("click", (event) => {
    const clickedMessage = event.target.closest(".msg");
    const clickedTrigger = event.target.closest(".msg-menu-trigger");
    const clickedMenu = event.target.closest(".message-action-menu");
    const clickedPicker = event.target.closest(".reaction-picker");
    const clickedReactionChip = event.target.closest(".reaction-chip");

    // Close picker if clicking outside of it
    if (!clickedPicker) {
        closeReactionPicker();
    }

    if (!clickedMenu && !clickedTrigger && !clickedMessage && !clickedPicker && !clickedReactionChip) {
        const selected = document.querySelector(".msg.selected");
        if (selected) {
            selectMessage(null);
        }
    }
});

setConversationSearchEnabled(false);
resetConversationSearchUI(true);
