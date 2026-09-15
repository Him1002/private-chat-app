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

    // Call and WebRTC signaling events
    if (data.type === "call.accept") {
        if (typeof WebRTCManager !== "undefined" && typeof WebRTCManager.handleCallAccept === "function") {
            WebRTCManager.handleCallAccept(data.call_id);
        }
    } else if (data.type === "call.reject") {
        if (typeof WebRTCManager !== "undefined" && typeof WebRTCManager.handleCallReject === "function") {
            WebRTCManager.handleCallReject(data.call_id, data.reason);
        }
    } else if (data.type === "call.cancel") {
        if (typeof WebRTCManager !== "undefined" && typeof WebRTCManager.handleCallCancel === "function") {
            WebRTCManager.handleCallCancel(data.call_id);
        }
    } else if (data.type === "call.end") {
        if (typeof WebRTCManager !== "undefined" && typeof WebRTCManager.handleCallEnd === "function") {
            WebRTCManager.handleCallEnd(data.call_id);
        }
    } else if (data.type === "webrtc.offer") {
        if (typeof WebRTCManager !== "undefined" && typeof WebRTCManager.handleWebRTCOffer === "function") {
            WebRTCManager.handleWebRTCOffer(data.call_id, data.sdp);
        }
    } else if (data.type === "webrtc.answer") {
        if (typeof WebRTCManager !== "undefined" && typeof WebRTCManager.handleWebRTCAnswer === "function") {
            WebRTCManager.handleWebRTCAnswer(data.call_id, data.sdp);
        }
    } else if (data.type === "webrtc.ice_candidate") {
        if (typeof WebRTCManager !== "undefined" && typeof WebRTCManager.handleWebRTCICECandidate === "function") {
            WebRTCManager.handleWebRTCICECandidate(data.call_id, data.candidate);
        }
    } else if (data.type === "call.invite") {
        if (typeof WebRTCManager !== "undefined" && typeof WebRTCManager.handleCallInvite === "function") {
            WebRTCManager.handleCallInvite(data);
        }
    } else if (data.type === "chat") {
        const isFromCurrentFriend = (currentFriend && data.sender === currentFriend);
        const isFromMe = (data.sender === currentUser);
        if (isFromCurrentFriend || isFromMe) {
            const indicators = document.querySelectorAll("#typing-indicator, .typing-indicator");
            indicators.forEach(ind => ind.style.display = "none");
            addMessage(
                data.sender,
                data.sender_display_name,
                data.text,
                data.image_url,
                data.timestamp,
                data.id,
                data.status,
                data.read_at,
                data.edited_at,
                data.is_deleted,
                data.deleted_at,
                data.reactions,
                data.reply_to,
                data.video_url,
                data.file_url,
                data.file_name,
                data.file_size,
                data.media_type
            );
        } else if (typeof loadSidebar === "function") {
            loadSidebar();
        }
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
    } else if (data.type === "reaction_update") {
        if (typeof updateMessageReactions === "function") {
            updateMessageReactions(data.message_id, data.reactions || []);
        }
    } else if (data.type === "error") {
        showToast(data.message || "Chat error", "error");
        if (data.call_id && typeof WebRTCManager !== "undefined" && typeof WebRTCManager.cleanupWebRTCCall === "function") {
            WebRTCManager.cleanupWebRTCCall();
        }
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
