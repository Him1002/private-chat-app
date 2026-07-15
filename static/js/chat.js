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

function addMessage(sender, text, imageUrl) {
    const box = document.getElementById("messages");
    const isMe = sender === currentUser;

    const div = document.createElement("div");
    div.className = `msg ${isMe ? "me" : "friend"}`;
    let contentHtml = "";
    
    // 1. Show Image if exists
    if (imageUrl) {
        contentHtml += `<img src="${imageUrl}" style="max-width: 100%; border-radius: 12px; display: block; margin-bottom: 5px; cursor:pointer;" onclick="window.open(this.src)">`;
    }
    
    // 2. Show Text if exists
    if (text) {
        contentHtml += `<span>${text}</span>`;
    }
    
    // 3. Add Sender Name (Only for friend)
    let nameHtml = isMe ? "" : `<span class="sender-name">${sender}</span>`;

    div.innerHTML = nameHtml + contentHtml;
    
    box.appendChild(div);
    box.scrollTop = box.scrollHeight;
}
