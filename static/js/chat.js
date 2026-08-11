function startChat(friend, element) {
        //console.log("Friend Object Data:", friend);
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
    if (!input.value || !currentFriend) return;
    const sent = sendSocketPayload({ type: "chat", room: currentFriend, text: input.value });
    if (!sent) {
        showToast("Reconnecting chat...", "normal");
        return;
    }
    input.value = "";
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

    const menu = document.createElement("div");
    menu.className = "message-action-menu";
    menu.innerHTML = `
        <button type="button" class="message-action-item" data-action="copy">Copy Message</button>
        <button type="button" class="message-action-item" data-action="reply">Reply</button>
        <button type="button" class="message-action-item" data-action="react">React</button>
        <button type="button" class="message-action-item" data-action="edit">Edit</button>
        <button type="button" class="message-action-item" data-action="delete">Delete</button>
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

function addMessage(sender, text, imageUrl, timestamp, messageId) {
    const box = document.getElementById("messages");
    const isMe = sender === currentUser;

    const div = document.createElement("div");
    div.className = `msg ${isMe ? "me" : "friend"}`;
    div.dataset.messageId = messageId || "";
    div.dataset.text = text || "";
    div.dataset.imageUrl = imageUrl || "";

    let contentHtml = "";
    if (imageUrl) {
        contentHtml += `<img src="${imageUrl}" onclick="window.open(this.src)" alt="message image">`;
    }
    if (text) {
        contentHtml += `<span class="msg-text">${text}</span>`;
    }

    const nameHtml = isMe ? "" : `<span class="sender-name">${sender}</span>`;
    const timeLabel = formatMessageTimestamp(timestamp);
    const timestampHtml = timeLabel ? `<span class="msg-time" style="display:none;">${timeLabel}</span>` : "";
    const triggerHtml = `<button type="button" class="msg-menu-trigger" style="display:none;" aria-label="Open message actions">...</button>`;

    div.innerHTML = nameHtml + contentHtml + timestampHtml + triggerHtml;

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
