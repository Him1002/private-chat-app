function connectWebSocket() {
    if (!token) return;

    if (reconnectTimer) {
        clearTimeout(reconnectTimer);
        reconnectTimer = null;
    }

    if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) {
        return;
    }

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    ws = new WebSocket(`${protocol}//${window.location.host}/ws?token=${token}`);

    ws.onopen = () => {
        if (currentFriend) {
            sendSocketPayload({ type: "join", room: currentFriend });
        }
    };

    ws.onmessage = handleSocketMessage;

    ws.onclose = () => {
        ws = null;
        if (shouldReconnectWs && token) {
            reconnectTimer = setTimeout(connectWebSocket, 3000);
        }
    };

    ws.onerror = () => {
        if (ws) ws.close();
    };
}

function disconnectWebSocket() {
    shouldReconnectWs = false;

    if (reconnectTimer) {
        clearTimeout(reconnectTimer);
        reconnectTimer = null;
    }

    if (ws) {
        ws.onclose = null;
        ws.close();
        ws = null;
    }
}

function sendSocketPayload(payload) {
    if (!ws || ws.readyState !== WebSocket.OPEN) {
        connectWebSocket();
        return false;
    }

    ws.send(JSON.stringify(payload));
    return true;
}

function handleSocketMessage(e) {
    const data = JSON.parse(e.data);

    if (data.type === "chat") {
        const indicators = document.querySelectorAll("#typing-indicator, .typing-indicator");
        indicators.forEach(ind => ind.style.display = "none");
        addMessage(data.sender, data.text, data.image_url, data.timestamp, data.id, data.status, data.read_at, data.edited_at, data.is_deleted, data.deleted_at);
    } else if (data.type === "message_updated") {
        if (typeof updateMessageContent === "function") {
            updateMessageContent(data.id, data.text, data.edited_at);
        }
        if (typeof updateMessageStatus === "function") {
            updateMessageStatus(data.id, data.status, data.read_at);
        }
    } else if (data.type === "message_deleted") {
        if (typeof updateDeletedMessage === "function") {
            updateDeletedMessage(data.id, data.text, data.deleted_at);
        }
    } else if (data.type === "typing") {
        if (data.sender === currentFriend) {
            const statusEl = document.getElementById("chat-status");
            statusEl.innerText = "Online";
            statusEl.className = "status online";
            statusEl.style.color = "#2ecc71";
        }

        if (typeof showTyping === "function") {
            showTyping(data.sender);
        }
    } else if (data.type === "message_status") {
        if (typeof updateMessageStatus === "function") {
            updateMessageStatus(data.message_id, data.status, data.read_at);
        }
    } else if (data.type === "messages_read") {
        if (typeof updateMessagesRead === "function") {
            updateMessagesRead(data.message_ids || [], data.read_at);
        }
    } else if (data.type === "error") {
        showToast(data.message || "Chat error", "error");
    }
}

function startPresenceRefresh() {
    stopPresenceRefresh();
    presenceRefreshTimer = setInterval(refreshSidebarForPresence, 15000);
}

function stopPresenceRefresh() {
    if (presenceRefreshTimer) {
        clearInterval(presenceRefreshTimer);
        presenceRefreshTimer = null;
    }
}

function refreshSidebarForPresence() {
    if (!token) return;

    const searchInput = document.getElementById("search-input");
    if (currentTab === 'people' && searchInput && searchInput.value.trim()) {
        return;
    }

    loadSidebar();
}

function updateChatStatus(friend) {
    if (!friend || friend.username !== currentFriend) return;

    const statusEl = document.getElementById("chat-status");
    if (friend.is_online) {
        statusEl.innerText = "Online";
        statusEl.className = "status online";
        statusEl.style.color = "#2ecc71";
    } else {
        statusEl.innerText = formatLastSeen(friend.last_seen);
        statusEl.className = "status offline";
        statusEl.style.color = "#888";
    }
}
