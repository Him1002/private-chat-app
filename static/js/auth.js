function toggleMode() {
    isRegisterMode = !isRegisterMode;
    document.getElementById("form-title").innerText = isRegisterMode ? "Create Account" : "Login";
    document.getElementById("auth-btn").innerText = isRegisterMode ? "Register" : "Login";
    document.getElementById("toggle-text").innerText = isRegisterMode ? "Have an account? Login" : "Need an account? Register";
}

async function handleAuth() {
    const user = document.getElementById("username").value;
    const pass = document.getElementById("password").value;
    const endpoint = isRegisterMode ? "/register" : "/login";
    const btn = document.getElementById("auth-btn");

    if(!user || !pass) return showToast("Please fill fields", "error");

    btn.innerText = "Processing...";
    btn.disabled = true;

    try {
        const res = await fetch(endpoint, {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({ username: user, password: pass })
        });
        const data = await res.json();
        
        if (res.ok) {
            if (isRegisterMode) {
                showToast("Registered! Please log in.", "success");
                toggleMode();
            } else {
                token = data.access_token;
                currentUser = user;
                document.getElementById("login-screen").style.display = "none";
                document.getElementById("app-container").style.display = "flex";
                shouldReconnectWs = true;
                connectWebSocket();
                startPresenceRefresh();
                loadSidebar();
            }
        } else {
            showToast(data.detail || "Error", "error");
        }
    } catch (e) { showToast("Server error", "error"); }
    
    btn.innerText = isRegisterMode ? "Register" : "Login";
    btn.disabled = false;
}

function logout() {
    // 1. Close session-level work
    disconnectWebSocket();
    stopPresenceRefresh();

    // 2. Destroy Session Data
    token = null;
    currentUser = null;
    currentFriend = null;
    currentTab = 'chats'; // Reset tab

    // 3. 💨 SECURITY WIPE: Clear sensitive HTML
    document.getElementById("list-area").innerHTML = ""; // Wipe contacts
    document.getElementById("messages").innerHTML = "";  // Wipe chat history
    document.getElementById("chat-title").innerText = "Select a Chat"; // Reset Header
    document.getElementById("chat-status").innerText = ""; 
    document.getElementById("msg-input").value = "";
    
    // 4. Disable Inputs
    document.getElementById("msg-input").disabled = true;
    document.getElementById("send-btn").disabled = true;

    // 5. Restore "Empty State" / Welcome Screen
    // We inject the Welcome HTML back into the message box so the next user sees that, not a blank void
    document.getElementById("messages").innerHTML = `
            <div id="welcome-screen" style="height: 100%; display: flex; align-items: center; justify-content: center; color: #555; flex-direction: column;">
                <div style="font-size: 40px; margin-bottom: 10px; opacity:0.5;">💬</div>
                <div style="opacity:0.6;">Select a contact to start chatting securely</div>
            </div>
        `;

    // 6. Switch View
    document.getElementById("app-container").style.display = "none";
    document.getElementById("login-screen").style.display = "flex";
    
    // Clear Form
    document.getElementById("username").value = "";
    document.getElementById("password").value = "";
}
