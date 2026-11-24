/**
 * ChatSpic Home / Dashboard Workspace Controller (UI-02F)
 * Manages the dedicated Home workspace grounded in existing session state.
 */

function loadHomeWorkspace() {
    // 1. Authenticated user display
    const user = (typeof AppState !== 'undefined' && AppState.currentUser)
        ? AppState.currentUser
        : (typeof currentUser !== 'undefined' ? currentUser : null);

    const greetingEl = document.getElementById('home-welcome-greeting');
    if (greetingEl) {
        if (user) {
            const cached = (typeof myProfile !== 'undefined' && myProfile)
                ? myProfile
                : (typeof window !== 'undefined' && window.myProfile ? window.myProfile : null);

            // Only use display_name if cached profile belongs to the current authenticated user
            const displayName = (cached && cached.username === user && cached.display_name)
                ? cached.display_name
                : user;

            greetingEl.textContent = `Hello, ${displayName}!`;
        } else {
            greetingEl.textContent = 'Hello!';
        }
    }

    // 2. Contacts and online presence summary from existing session data
    updateHomeStats();
}

function updateHomeStats() {
    const contactsEl = document.getElementById('home-contacts-stat');
    const onlineEl = document.getElementById('home-online-stat');
    const emptyNotice = document.getElementById('home-empty-notice');

    // State A: Not loaded yet or initial contacts request in progress
    if (typeof window.cachedFriends === 'undefined' || window.cachedFriends === null || !Array.isArray(window.cachedFriends)) {
        if (contactsEl) contactsEl.textContent = '--';
        if (onlineEl) onlineEl.textContent = '--';
        if (emptyNotice) emptyNotice.style.display = 'none';
        return;
    }

    const friends = window.cachedFriends;

    // State B: Successfully loaded and confirmed empty
    if (friends.length === 0) {
        if (contactsEl) contactsEl.textContent = '0';
        if (onlineEl) onlineEl.textContent = '0';
        if (emptyNotice) emptyNotice.style.display = 'block';
        return;
    }

    // State C: Successfully loaded with contacts
    const onlineCount = friends.filter(f => f && f.is_online).length;
    if (contactsEl) contactsEl.textContent = String(friends.length);
    if (onlineEl) onlineEl.textContent = String(onlineCount);
    if (emptyNotice) emptyNotice.style.display = 'none';
}

function clearHomeWorkspace() {
    const greetingEl = document.getElementById('home-welcome-greeting');
    if (greetingEl) greetingEl.textContent = 'Hello!';

    const contactsEl = document.getElementById('home-contacts-stat');
    if (contactsEl) contactsEl.textContent = '--';

    const onlineEl = document.getElementById('home-online-stat');
    if (onlineEl) onlineEl.textContent = '--';

    const emptyNotice = document.getElementById('home-empty-notice');
    if (emptyNotice) emptyNotice.style.display = 'none';
}

// Global exposure
window.loadHomeWorkspace = loadHomeWorkspace;
window.updateHomeStats = updateHomeStats;
window.clearHomeWorkspace = clearHomeWorkspace;
