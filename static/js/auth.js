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
                if (typeof AppState !== "undefined") {
                    AppState.token = token;
                    AppState.currentUser = currentUser;
                }
                if (typeof startNewSessionGeneration === "function") {
                    startNewSessionGeneration();
                }
                document.getElementById("login-screen").style.display = "none";
                document.getElementById("app-container").style.display = "flex";
                shouldReconnectWs = true;
                connectWebSocket();
                startPresenceRefresh();
                loadSidebar();
                if (typeof navigateToSection === "function") {
                    navigateToSection('chats');
                }
                if (typeof initPushNotifications === "function") {
                    initPushNotifications();
                }
                if (typeof pendingChatNavigation === "string" && pendingChatNavigation) {
                    const chatToOpen = pendingChatNavigation;
                    pendingChatNavigation = null;
                    if (typeof navigateToConversation === "function") {
                        navigateToConversation(chatToOpen);
                    }
                }
            }
        } else {
            showToast(data.detail || "Error", "error");
        }
    } catch (e) { showToast("Server error", "error"); }
    
    btn.innerText = isRegisterMode ? "Register" : "Login";
    btn.disabled = false;
}

function logout() {
    // 1. Invalidate active session generation immediately so all in-flight asynchronous requests are discarded
    if (typeof window !== "undefined" && typeof window.invalidateSessionGeneration === "function") {
        window.invalidateSessionGeneration();
    } else if (typeof invalidateSessionGeneration === "function") {
        invalidateSessionGeneration();
    }
    if (typeof window !== "undefined" && typeof window.resetPeopleWorkspaceState === "function") {
        window.resetPeopleWorkspaceState();
    } else if (typeof resetPeopleWorkspaceState === "function") {
        resetPeopleWorkspaceState();
    }

    // 2. Close session-level work
    if (typeof unsubscribePush === "function") {
        unsubscribePush();
    }
    if (typeof cleanupWebRTCCall === "function") {
        cleanupWebRTCCall();
    }
    if (typeof CallUI !== "undefined" && typeof CallUI.cleanup === "function") {
        CallUI.cleanup();
    }
    disconnectWebSocket();
    stopPresenceRefresh();
    if (typeof revokeSecureMediaCache === "function") {
        revokeSecureMediaCache();
    }
    if (typeof cancelVoiceRecording === "function") {
        cancelVoiceRecording();
    }
    if (typeof cancelVoicePreview === "function") {
        cancelVoicePreview();
    }
    if (typeof stopAllPlayingAudios === "function") {
        stopAllPlayingAudios();
    }

    // 3. Destroy Session Data
    token = null;
    currentUser = null;
    currentFriend = null;
    currentTab = 'chats'; // Reset tab
    if (typeof AppState !== "undefined") {
        AppState.token = null;
        AppState.currentUser = null;
        AppState.currentFriend = null;
        AppState.currentTab = 'chats';
        AppState.currentSection = 'chats';
    }
    if (typeof currentSection !== "undefined") {
        currentSection = 'chats';
    }
    if (typeof myProfile !== "undefined") {
        myProfile = {};
    }
    if (typeof window !== "undefined") {
        window.myProfile = {};
        window.cachedFriends = undefined;
    }
    if (typeof navigateToSection === "function") {
        navigateToSection('chats');
    }

    // 4. 💨 SECURITY WIPE: Clear sensitive HTML
    document.getElementById("list-area").innerHTML = ""; // Wipe contacts
    document.getElementById("messages").innerHTML = "";  // Wipe chat history
    const peopleContacts = document.getElementById("people-contacts-list");
    if (peopleContacts) peopleContacts.innerHTML = "";
    const peopleRequests = document.getElementById("people-requests-list");
    if (peopleRequests) peopleRequests.innerHTML = "";
    const peopleSearch = document.getElementById("people-search-list");
    if (peopleSearch) peopleSearch.innerHTML = "";
    const peopleSearchInput = document.getElementById("people-search-input");
    if (peopleSearchInput) peopleSearchInput.value = "";
    const peopleSearchClear = document.getElementById("people-search-clear");
    if (peopleSearchClear) peopleSearchClear.style.display = "none";
    const peopleSearchSection = document.getElementById("people-search-section");
    if (peopleSearchSection) peopleSearchSection.style.display = "none";
    const peopleRequestsSection = document.getElementById("people-requests-section");
    if (peopleRequestsSection) peopleRequestsSection.style.display = "none";
    const peopleContactsSection = document.getElementById("people-contacts-section");
    if (peopleContactsSection) peopleContactsSection.style.display = "";
    // Clear Settings fields
    const pass1 = document.getElementById("change-current-password");
    if (pass1) pass1.value = "";
    const pass2 = document.getElementById("change-new-password");
    if (pass2) pass2.value = "";
    const pass3 = document.getElementById("change-confirm-password");
    if (pass3) pass3.value = "";
    const dispName = document.getElementById("profile-display-name");
    if (dispName) dispName.value = "";
    const aboutInput = document.getElementById("profile-about");
    if (aboutInput) aboutInput.value = "";
    const prevImg = document.getElementById("profile-pic-preview");
    if (prevImg) {
        prevImg.src = "";
        prevImg.style.display = "none";
    }
    const settingsUser = document.getElementById("settings-username");
    if (settingsUser) settingsUser.textContent = "";
    if (typeof clearHomeWorkspace === "function") {
        clearHomeWorkspace();
    }
    document.getElementById("chat-title").innerText = "Select a Chat"; // Reset Header
    document.getElementById("chat-status").innerText = ""; 
    document.getElementById("msg-input").value = "";
    if (typeof resetConversationSearchUI === "function") {
        resetConversationSearchUI(true);
    }
    if (typeof setConversationSearchEnabled === "function") {
        setConversationSearchEnabled(false);
    }
    
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
    const currPassEl = document.getElementById("change-current-password");
    if (currPassEl) currPassEl.value = "";
    const newPassEl = document.getElementById("change-new-password");
    if (newPassEl) newPassEl.value = "";
    const confPassEl = document.getElementById("change-confirm-password");
    if (confPassEl) confPassEl.value = "";
}
