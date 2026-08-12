let activeMessageEdit = null;
let activeConversationSearchQuery = "";
let activeConversationSearchRequestId = 0;

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
    const target = document.querySelector(`.msg[data-message-id="${messageId}"]`);
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
        resetConversationSearchUI(true);
        currentFriend = friend.username;
        
        // UI Updates
        document.querySelectorAll(".item").forEach(el => el.classList.remove("active"));
        if (element) element.classList.add("active");
        
        document.getElementById("chat-title").innerText = friend.username;
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
    
    if(indicator){
        indicator.innerText = `${sender} is typing...`;
        indicator.style.display = "block";
    
        // Clear old timer if exists
        if (window.typingTimeout) clearTimeout(window.typingTimeout);

        // Hide after 3 seconds of silence
        window.typingTimeout = setTimeout(() => {
            indicator.style.display = "none";
        }, 3000); // 3000ms
    } else{
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
    const sent = sendSocketPayload({ type: "chat", room: currentFriend, text: input.value });
    if (!sent) {
        showToast("Reconnecting chat...", "normal");
        return;
    }
    input.value = "";
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
        } else {
            showToast(`${button.textContent.trim()} is not available yet`, "normal");
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

function addMessage(sender, text, imageUrl, timestamp, messageId, status, readAt, editedAt, isDeleted = false, deletedAt = "") {
    const box = document.getElementById("messages");
    const isMe = sender === currentUser;
    const deleted = Boolean(isDeleted || text === "This message was deleted");
    const safeText = deleted ? "This message was deleted" : (text || "");
    const safeImageUrl = deleted ? "" : imageUrl || "";

    const div = document.createElement("div");
    div.className = `msg ${isMe ? "me" : "friend"}`;
    div.dataset.messageId = messageId || "";
    div.dataset.text = safeText;
    div.dataset.imageUrl = safeImageUrl;
    div.dataset.status = normalizeMessageStatus(status, status === "read");
    div.dataset.editedAt = editedAt || "";
    div.dataset.isDeleted = deleted ? "true" : "false";
    if (deletedAt) {
        div.dataset.deletedAt = deletedAt;
    }
    if (readAt) {
        div.dataset.readAt = readAt;
    }

    let contentHtml = "";
    if (!deleted && safeImageUrl) {
        contentHtml += `<img src="${safeImageUrl}" onclick="window.open(this.src)" alt="message image">`;
    }
    if (safeText) {
        contentHtml += `<span class="msg-text">${safeText}</span>`;
    }

    const nameHtml = isMe ? "" : `<span class="sender-name">${sender}</span>`;
    const editedHtml = deleted ? "" : (editedAt ? `<span class="msg-edited">(edited)</span>` : "");
    const timeLabel = formatMessageTimestamp(timestamp);
    const timestampHtml = timeLabel ? `<span class="msg-time" style="display:none;">${timeLabel}</span>` : "";
    const statusHtml = isMe ? `<span class="msg-status"></span>` : "";
    const triggerHtml = `<button type="button" class="msg-menu-trigger" style="display:none;" aria-label="Open message actions">...</button>`;

    div.innerHTML = nameHtml + contentHtml + editedHtml + timestampHtml + statusHtml + triggerHtml;

    const trigger = div.querySelector(".msg-menu-trigger");
    if (trigger) {
        trigger.addEventListener("click", (event) => {
            event.stopPropagation();
            openMessageActionMenu(div, trigger);
        });
    }

    div.addEventListener("click", (event) => {
        if (event.target.closest(".msg-menu-trigger") || event.target.closest(".message-action-menu") || event.target.closest(".message-action-item")) {
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
}

document.addEventListener("click", (event) => {
    const clickedMessage = event.target.closest(".msg");
    const clickedTrigger = event.target.closest(".msg-menu-trigger");
    const clickedMenu = event.target.closest(".message-action-menu");

    if (!clickedMenu && !clickedTrigger && !clickedMessage) {
        const selected = document.querySelector(".msg.selected");
        if (selected) {
            selectMessage(null);
        }
    }
});

setConversationSearchEnabled(false);
resetConversationSearchUI(true);
