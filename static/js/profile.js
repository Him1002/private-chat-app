let myProfile = {};

/**
 * Opens Settings workspace from sidebar or menu shortcuts.
 */
function openProfile() {
    if (typeof navigateToSection === "function") {
        navigateToSection('settings');
    } else {
        loadSettingsWorkspace();
    }
}

function closeProfile() {
    // Legacy modal compatibility no-op; Settings is an integrated primary workspace.
    const screen = document.getElementById('profile-screen');
    if (screen) screen.style.display = 'none';
}

/**
 * Loads profile information and system status into the dedicated Settings workspace.
 */
async function loadSettingsWorkspace() {
    if (!token) return;

    // Capture active session generation and username before dispatching async network request
    const capturedGeneration = typeof getSessionGeneration === 'function'
        ? getSessionGeneration()
        : (typeof AppState !== 'undefined' && typeof AppState.sessionGeneration === 'number' ? AppState.sessionGeneration : 0);
    const capturedUser = typeof currentUser !== 'undefined'
        ? currentUser
        : (typeof AppState !== 'undefined' ? AppState.currentUser : null);

    // Populate username badge
    const usernameEl = document.getElementById('settings-username');
    if (usernameEl && currentUser) {
        usernameEl.textContent = `@${currentUser}`;
    }

    // Update push notification status badge
    updateSettingsPushStatus();

    // Fetch current profile from backend
    try {
        const authToken = (typeof token !== "undefined" && token) ? token : (typeof AppState !== "undefined" && AppState.token ? AppState.token : "");
        const res = await fetch('/profile/', {
            headers: {
                "Authorization": `Bearer ${authToken}`
            }
        });

        // Session generation guard: discard stale responses if session changed or user logged out during fetch
        if (typeof isSessionValid === 'function') {
            if (!isSessionValid(capturedGeneration, capturedUser)) {
                return;
            }
        } else {
            const activeUser = typeof currentUser !== 'undefined' ? currentUser : (typeof AppState !== 'undefined' ? AppState.currentUser : null);
            if (!token || activeUser !== capturedUser) {
                return;
            }
        }

        if (res.ok) {
            myProfile = await res.json();
            if (typeof window !== "undefined") {
                window.myProfile = myProfile;
            }
            const displayNameInput = document.getElementById('profile-display-name');
            if (displayNameInput) displayNameInput.value = myProfile.display_name || '';

            const aboutInput = document.getElementById('profile-about');
            if (aboutInput) aboutInput.value = myProfile.about || '';

            const preview = document.getElementById('profile-pic-preview');
            if (preview) {
                const safePic = sanitizeMediaUrl(myProfile.profile_picture);
                if (safePic) {
                    if (safePic.startsWith("http://") || safePic.startsWith("https://") || safePic.startsWith("blob:") || safePic.startsWith("data:")) {
                        preview.src = safePic;
                        preview.style.display = 'block';
                    } else if (typeof fetchSecureMediaBlobUrl === "function") {
                        fetchSecureMediaBlobUrl(safePic).then(blobUrl => {
                            if (typeof isSessionValid === 'function' && !isSessionValid(capturedGeneration, capturedUser)) {
                                return;
                            }
                            if (blobUrl) {
                                preview.src = blobUrl;
                                preview.style.display = 'block';
                            } else {
                                preview.src = '';
                                preview.style.display = 'none';
                            }
                        });
                    } else {
                        preview.src = safePic;
                        preview.style.display = 'block';
                    }
                } else {
                    preview.src = '';
                    preview.style.display = 'none';
                }
            }
        }
    } catch (e) {
        console.error("Error fetching profile for settings workspace", e);
    }
}

/**
 * Updates the push notification badge and action button in Settings workspace.
 */
function updateSettingsPushStatus() {
    const statusBadge = document.getElementById('settings-push-status');
    const enableBtn = document.getElementById('settings-push-enable-btn');
    if (!statusBadge) return;

    if (!('Notification' in window)) {
        statusBadge.textContent = 'Unsupported';
        statusBadge.className = 'settings-badge muted';
        if (enableBtn) enableBtn.style.display = 'none';
    } else if (Notification.permission === 'granted') {
        statusBadge.textContent = 'Active';
        statusBadge.className = 'settings-badge success';
        if (enableBtn) enableBtn.style.display = 'none';
    } else if (Notification.permission === 'denied') {
        statusBadge.textContent = 'Blocked in browser';
        statusBadge.className = 'settings-badge error';
        if (enableBtn) enableBtn.style.display = 'none';
    } else {
        statusBadge.textContent = 'Not enabled';
        statusBadge.className = 'settings-badge warning';
        if (enableBtn) enableBtn.style.display = 'inline-block';
    }
}

let isPushRequestPending = false;

/**
 * Requests push notification permissions directly from the Settings workspace.
 * Guards against repeated rapid clicks while browser prompt or subscription is pending.
 */
async function requestPushFromSettings() {
    if (isPushRequestPending) return;
    if (!('Notification' in window)) return;

    const enableBtn = document.getElementById('settings-push-enable-btn');
    isPushRequestPending = true;
    if (enableBtn) {
        enableBtn.disabled = true;
        enableBtn.textContent = 'Enabling...';
    }

    try {
        const perm = await Notification.requestPermission();
        updateSettingsPushStatus();
        if (perm === 'granted' && typeof syncPushSubscriptionIfConfigured === 'function') {
            await syncPushSubscriptionIfConfigured();
        }
    } catch (e) {
        console.debug("Push permission request error from settings:", e);
    } finally {
        isPushRequestPending = false;
        if (enableBtn) {
            enableBtn.disabled = false;
            enableBtn.textContent = 'Enable';
        }
        updateSettingsPushStatus();
    }
}

async function saveProfile() {
    const displayName = document.getElementById('profile-display-name').value;
    const about = document.getElementById('profile-about').value;
    
    try {
        const authToken = (typeof token !== "undefined" && token) ? token : (typeof AppState !== "undefined" && AppState.token ? AppState.token : "");
        const res = await fetch('/profile/', {
            method: 'PUT',
            headers: {
                "Content-Type": "application/json",
                "Authorization": `Bearer ${authToken}`
            },
            body: JSON.stringify({
                display_name: displayName,
                about: about
            })
        });
        
        if (res.ok) {
            showToast("Profile saved", "success");
            if (typeof loadSidebar === "function") {
                loadSidebar();
            }
        } else {
            showToast("Error saving profile", "error");
        }
    } catch (e) {
        showToast("Error saving profile", "error");
    }
}

async function handleProfilePicChange(input) {
    if (!input.files || input.files.length === 0) return;
    
    // Capture active session generation and username before dispatching async upload
    const capturedGeneration = typeof getSessionGeneration === 'function'
        ? getSessionGeneration()
        : (typeof AppState !== 'undefined' && typeof AppState.sessionGeneration === 'number' ? AppState.sessionGeneration : 0);
    const capturedUser = typeof currentUser !== 'undefined'
        ? currentUser
        : (typeof AppState !== 'undefined' ? AppState.currentUser : null);

    const file = input.files[0];
    const localPreviewUrl = URL.createObjectURL(file);
    const formData = new FormData();
    formData.append("file", file);
    
    try {
        const authToken = (typeof token !== "undefined" && token) ? token : (typeof AppState !== "undefined" && AppState.token ? AppState.token : "");
        // Use existing upload endpoint
        const uploadRes = await fetch('/upload', {
            method: 'POST',
            headers: {
                "Authorization": `Bearer ${authToken}`
            },
            body: formData
        });
        
        // Discard stale upload if session became invalid during file upload
        if (typeof isSessionValid === 'function' && !isSessionValid(capturedGeneration, capturedUser)) {
            URL.revokeObjectURL(localPreviewUrl);
            return;
        }

        if (!uploadRes.ok) throw new Error("Upload failed");
        
        const uploadData = await uploadRes.json();

        // Re-validate after parsing upload response
        if (typeof isSessionValid === 'function' && !isSessionValid(capturedGeneration, capturedUser)) {
            URL.revokeObjectURL(localPreviewUrl);
            return;
        }

        const url = uploadData.url;
        
        // Seed secure cache with local preview URL for instant rendering
        if (typeof seedSecureMediaCache === "function") {
            seedSecureMediaCache(url, localPreviewUrl);
        }

        // Update profile picture
        const res = await fetch('/profile/picture', {
            method: 'PUT',
            headers: {
                "Content-Type": "application/json",
                "Authorization": `Bearer ${authToken}`
            },
            body: JSON.stringify({
                profile_picture: url
            })
        });
        
        // Discard stale response if session changed or user logged out during profile picture update
        if (typeof isSessionValid === 'function' && !isSessionValid(capturedGeneration, capturedUser)) {
            URL.revokeObjectURL(localPreviewUrl);
            return;
        }

        if (res.ok) {
            if (typeof myProfile !== "undefined" && myProfile && (!myProfile.username || myProfile.username === capturedUser)) {
                myProfile.profile_picture = url;
            }
            if (typeof window !== "undefined" && window.myProfile && (!window.myProfile.username || window.myProfile.username === capturedUser)) {
                window.myProfile.profile_picture = url;
            }
            const preview = document.getElementById('profile-pic-preview');
            if (preview) {
                preview.src = localPreviewUrl;
                preview.style.display = 'block';
            }
            showToast("Profile picture updated", "success");
        } else {
            showToast("Error updating picture", "error");
        }
    } catch (e) {
        // Discard error notification if session is no longer valid
        if (typeof isSessionValid === 'function' && !isSessionValid(capturedGeneration, capturedUser)) {
            URL.revokeObjectURL(localPreviewUrl);
            return;
        }
        showToast("Error updating picture", "error");
    } finally {
        // reset input
        if (input) input.value = "";
    }
}

async function handleChangePassword() {
    const currentPassInput = document.getElementById("change-current-password");
    const newPassInput = document.getElementById("change-new-password");
    const confirmPassInput = document.getElementById("change-confirm-password");
    const btn = document.getElementById("change-password-btn");

    const currentPass = currentPassInput ? currentPassInput.value : "";
    const newPass = newPassInput ? newPassInput.value : "";
    const confirmPass = confirmPassInput ? confirmPassInput.value : "";

    if (!currentPass || !newPass || !confirmPass) {
        return showToast("Please fill all password fields", "error");
    }

    if (newPass !== confirmPass) {
        return showToast("New password and confirmation do not match", "error");
    }

    if (btn) {
        btn.disabled = true;
        btn.innerText = "Changing...";
    }

    try {
        const authToken = (typeof token !== "undefined" && token) ? token : (typeof AppState !== "undefined" && AppState.token ? AppState.token : "");
        const res = await fetch("/change-password", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Authorization": `Bearer ${authToken}`
            },
            body: JSON.stringify({
                current_password: currentPass,
                new_password: newPass,
                new_password_confirm: confirmPass
            })
        });

        const data = await res.json();

        if (res.ok) {
            showToast("Password changed successfully", "success");
            if (currentPassInput) currentPassInput.value = "";
            if (newPassInput) newPassInput.value = "";
            if (confirmPassInput) confirmPassInput.value = "";
        } else {
            showToast(data.detail || "Error changing password", "error");
        }
    } catch (e) {
        showToast("Server error", "error");
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.innerText = "Change Password";
        }
    }
}

// Global exposure
window.openProfile = openProfile;
window.closeProfile = closeProfile;
window.loadSettingsWorkspace = loadSettingsWorkspace;
window.updateSettingsPushStatus = updateSettingsPushStatus;
window.requestPushFromSettings = requestPushFromSettings;
window.saveProfile = saveProfile;
window.handleProfilePicChange = handleProfilePicChange;
window.handleChangePassword = handleChangePassword;
window.myProfile = myProfile;

