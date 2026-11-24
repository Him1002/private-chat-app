/**
 * ChatSpic Web Push Notification Manager (V2 Task R7)
 * Handles service worker registration, push subscription, permission UX,
 * visibility reporting, and notification click navigation.
 */

let pendingChatNavigation = null;

function isPushSupported() {
    return Boolean(
        window.isSecureContext &&
        'serviceWorker' in navigator &&
        'PushManager' in window &&
        'Notification' in window
    );
}

function urlBase64ToUint8Array(base64String) {
    const padding = '='.repeat((4 - (base64String.length % 4)) % 4);
    const base64 = (base64String + padding)
        .replace(/-/g, '+')
        .replace(/_/g, '/');
    const rawData = window.atob(base64);
    const outputArray = new Uint8Array(rawData.length);
    for (let i = 0; i < rawData.length; ++i) {
        outputArray[i] = rawData.charCodeAt(i);
    }
    return outputArray;
}

async function initPushNotifications() {
    if (!isPushSupported() || !token) {
        return;
    }

    try {
        if (Notification.permission === 'granted') {
            await syncPushSubscriptionIfConfigured();
        } else if (Notification.permission === 'default') {
            const dismissed = localStorage.getItem('push_prompt_dismissed');
            if (!dismissed) {
                showPushPermissionPrompt();
            }
        }
        // If denied, do nothing.
    } catch (err) {
        console.debug("Push notification initialization error:", err);
    }
}

async function syncPushSubscriptionIfConfigured() {
    if (!isPushSupported() || !token) return;

    try {
        const res = await fetch('/push/vapid-public-key', {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        if (!res.ok) return;

        const config = await res.json();
        if (config.enabled && config.public_key) {
            await subscribeToPush(config.public_key);
        }
    } catch (err) {
        console.debug("Push subscription sync error:", err);
    }
}

function showPushPermissionPrompt() {
    const existing = document.getElementById('push-permission-prompt');
    if (existing) return;

    const banner = document.createElement('div');
    banner.id = 'push-permission-prompt';
    banner.className = 'push-permission-banner';
    banner.innerHTML = `
        <div class="push-prompt-content">
            <span class="push-prompt-icon">🔔</span>
            <span class="push-prompt-text">Enable notifications to receive alerts for new messages</span>
            <div class="push-prompt-actions">
                <button id="push-btn-enable" class="push-btn-primary" type="button">Enable</button>
                <button id="push-btn-dismiss" class="push-btn-secondary" type="button">Later</button>
            </div>
        </div>
    `;

    document.body.appendChild(banner);

    const enableBtn = document.getElementById('push-btn-enable');
    const dismissBtn = document.getElementById('push-btn-dismiss');

    if (enableBtn) {
        enableBtn.addEventListener('click', async () => {
            banner.remove();
            try {
                const perm = await Notification.requestPermission();
                if (perm === 'granted') {
                    await enableWebPushSubscription();
                }
            } catch (e) {
                console.debug("Permission request error:", e);
            }
        });
    }

    if (dismissBtn) {
        dismissBtn.addEventListener('click', () => {
            localStorage.setItem('push_prompt_dismissed', 'true');
            banner.remove();
        });
    }
}

async function enableWebPushSubscription() {
    if (!isPushSupported() || !token) return;

    try {
        const res = await fetch('/push/vapid-public-key', {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        if (!res.ok) {
            if (typeof showToast === 'function') {
                showToast("Unable to reach push service", "error");
            }
            return;
        }

        const config = await res.json();
        if (!config.enabled || !config.public_key) {
            if (typeof showToast === 'function') {
                showToast("Web Push is not configured on the server", "info");
            }
            return;
        }

        const success = await subscribeToPush(config.public_key);
        if (success && typeof showToast === 'function') {
            showToast("Notifications enabled!", "success");
        }
    } catch (err) {
        console.debug("Error enabling Web Push:", err);
        if (typeof showToast === 'function') {
            showToast("Failed to enable push notifications", "error");
        }
    }
}

async function subscribeToPush(vapidPublicKey) {
    if (!isPushSupported() || !token || !vapidPublicKey) return false;

    try {
        const reg = await navigator.serviceWorker.register('/sw.js', { scope: '/' });
        await navigator.serviceWorker.ready;

        let sub = await reg.pushManager.getSubscription();
        if (!sub) {
            const appServerKey = urlBase64ToUint8Array(vapidPublicKey);
            sub = await reg.pushManager.subscribe({
                userVisibleOnly: true,
                applicationServerKey: appServerKey,
            });
        }

        const subJson = sub.toJSON();
        if (subJson && subJson.keys) {
            const res = await fetch('/push/subscribe', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify({
                    endpoint: subJson.endpoint,
                    keys: {
                        p256dh: subJson.keys.p256dh,
                        auth: subJson.keys.auth
                    }
                })
            });
            return res.ok;
        }
        return false;
    } catch (err) {
        console.debug("Error subscribing to Web Push:", err);
        return false;
    }
}

async function unsubscribePush() {
    const banner = document.getElementById('push-permission-prompt');
    if (banner) banner.remove();

    if (!isPushSupported()) return;

    try {
        if (token) {
            await fetch('/push/unsubscribe', {
                method: 'POST',
                headers: { 'Authorization': `Bearer ${token}` }
            });
        }

        const reg = await navigator.serviceWorker.getRegistration('/sw.js');
        if (reg) {
            const sub = await reg.pushManager.getSubscription();
            if (sub) {
                await sub.unsubscribe();
            }
        }
    } catch (err) {
        console.debug("Error unsubscribing push:", err);
    }
}

function navigateToConversation(username) {
    if (typeof navigateToSection === "function") {
        navigateToSection('chats');
    }

    if (!username || !token) {
        pendingChatNavigation = username;
        return;
    }

    if (window.cachedFriends && Array.isArray(window.cachedFriends)) {
        const friend = window.cachedFriends.find(f => f.username === username);
        if (friend) {
            startChat(friend);
            return;
        }
    }

    // If friends not loaded or friend not in cache, fetch friends list and open
    const capturedGeneration = typeof getSessionGeneration === 'function' ? getSessionGeneration() : 0;
    const capturedUser = typeof currentUser !== 'undefined' ? currentUser : null;

    fetch('/friends', { headers: { 'Authorization': `Bearer ${token}` } })
        .then(r => r.json())
        .then(friends => {
            if (typeof isSessionValid === 'function' && !isSessionValid(capturedGeneration, capturedUser)) {
                return;
            }
            if (Array.isArray(friends)) {
                window.cachedFriends = friends;
                const friend = friends.find(f => f.username === username);
                if (friend) {
                    startChat(friend);
                }
            }
        })
        .catch(err => console.debug("Error loading friend for notification navigation:", err));
}

// Service worker notification click listener
if ('serviceWorker' in navigator) {
    navigator.serviceWorker.addEventListener('message', (event) => {
        if (event.data && event.data.type === 'NAVIGATE_CONVERSATION') {
            const username = event.data.conversation;
            navigateToConversation(username);
        }
    });
}

// Page visibility change listener for server-side active conversation tracking
document.addEventListener('visibilitychange', () => {
    if (!token || !ws || ws.readyState !== WebSocket.OPEN) return;

    sendSocketPayload({
        type: 'visibility',
        visible: !document.hidden,
        room: currentFriend || null
    });
});

// Check for pending URL navigation on initial script load (e.g. ?chat=alice)
(function checkUrlNavigation() {
    try {
        const params = new URLSearchParams(window.location.search);
        const chatUser = params.get('chat');
        if (chatUser && chatUser.trim()) {
            pendingChatNavigation = chatUser.trim();
            // Clean up the URL query parameter without a page reload
            window.history.replaceState({}, document.title, window.location.pathname);
        }
    } catch (e) {}
})();
