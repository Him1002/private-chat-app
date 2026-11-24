/**
 * Dedicated People Workspace Controller (UI-02D)
 * Manages contacts directory, incoming friend requests, and user search
 * within the dedicated #workspace-people section.
 */

let isPeopleLoading = false;
let peopleSearchTimeout = null;

/**
 * Loads and renders all data for the dedicated People workspace:
 * - Pending incoming friend requests
 * - Friends/contacts directory
 */
async function loadPeopleWorkspace() {
    if (!token) return;
    if (isPeopleLoading) return;
    isPeopleLoading = true;

    // Capture active session generation and username before dispatching async network requests
    const capturedGeneration = typeof getSessionGeneration === 'function'
        ? getSessionGeneration()
        : (typeof AppState !== 'undefined' && typeof AppState.sessionGeneration === 'number' ? AppState.sessionGeneration : 0);
    const capturedUser = typeof currentUser !== 'undefined'
        ? currentUser
        : (typeof AppState !== 'undefined' ? AppState.currentUser : null);

    try {
        const [reqRes, friendRes] = await Promise.all([
            fetch("/friends/requests", { headers: { "Authorization": `Bearer ${token}` } }),
            fetch("/friends", { headers: { "Authorization": `Bearer ${token}` } })
        ]);

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

        if (!reqRes.ok || !friendRes.ok) return;

        const requests = await reqRes.json();
        const friends = await friendRes.json();

        // Final verification before committing to memory and rendering UI
        if (typeof isSessionValid === 'function' && !isSessionValid(capturedGeneration, capturedUser)) {
            return;
        }

        // Update cached friends globally
        window.cachedFriends = friends;

        renderPeopleWorkspace(requests, friends);
    } catch (err) {
        console.error("[People] Error loading people workspace:", err);
    } finally {
        isPeopleLoading = false;
    }
}

/**
 * Renders friend requests and contacts directory into the dedicated People workspace.
 * 
 * @param {Array} requests - Pending friend request objects from /friends/requests
 * @param {Array} friends - Contact objects from /friends
 */
function renderPeopleWorkspace(requests, friends) {
    // 1. Update contact count badge
    const countBadge = document.getElementById("people-count-badge");
    if (countBadge) {
        const count = Array.isArray(friends) ? friends.length : 0;
        countBadge.textContent = `${count} contact${count === 1 ? '' : 's'}`;
    }

    // 2. Render Friend Requests
    const reqSection = document.getElementById("people-requests-section");
    const reqTitle = document.getElementById("people-requests-title");
    const reqList = document.getElementById("people-requests-list");

    if (reqSection && reqList) {
        reqList.innerHTML = "";
        if (Array.isArray(requests) && requests.length > 0) {
            reqSection.style.display = "";
            if (reqTitle) reqTitle.textContent = `Friend Requests (${requests.length})`;
            requests.forEach(r => {
                if (typeof renderFriendRequestItem === "function") {
                    renderFriendRequestItem(reqList, r);
                }
            });
        } else {
            reqSection.style.display = "none";
        }
    }

    // 3. Render Contacts Directory
    const contactsList = document.getElementById("people-contacts-list");
    if (contactsList) {
        contactsList.innerHTML = "";
        if (Array.isArray(friends) && friends.length > 0) {
            friends.forEach(f => {
                if (typeof renderFriendItem === "function") {
                    renderFriendItem(contactsList, f);
                }
            });
        } else {
            contactsList.innerHTML = `
                <div class="people-empty-state">
                    <div class="people-empty-icon" aria-hidden="true">&#128101;</div>
                    <div class="people-empty-title">No contacts yet</div>
                    <div class="people-empty-desc">Use the search bar above to find and add friends.</div>
                </div>
            `;
        }
    }
}

/**
 * Handles input on the People search field with debouncing.
 * 
 * @param {Event} event - Input event
 */
function handlePeopleSearch(event) {
    const query = event.target ? event.target.value.trim() : "";
    const clearBtn = document.getElementById("people-search-clear");
    if (clearBtn) {
        clearBtn.style.display = query ? "flex" : "none";
    }

    if (!query) {
        clearPeopleSearch();
        return;
    }

    clearTimeout(peopleSearchTimeout);
    peopleSearchTimeout = setTimeout(() => {
        executePeopleSearch(query);
    }, 250);
}

/**
 * Clears the People search input and restores requests and contacts views.
 */
function clearPeopleSearch() {
    const input = document.getElementById("people-search-input");
    if (input) input.value = "";

    const clearBtn = document.getElementById("people-search-clear");
    if (clearBtn) clearBtn.style.display = "none";

    const searchSection = document.getElementById("people-search-section");
    const searchList = document.getElementById("people-search-list");
    if (searchList) searchList.innerHTML = "";
    if (searchSection) searchSection.style.display = "none";

    // Restore Contacts section
    const contactsSection = document.getElementById("people-contacts-section");
    if (contactsSection) contactsSection.style.display = "";

    // Restore Requests section only if items exist
    const reqSection = document.getElementById("people-requests-section");
    const reqList = document.getElementById("people-requests-list");
    if (reqSection && reqList && reqList.children.length > 0) {
        reqSection.style.display = "";
    }
}

/**
 * Executes user search against the /search endpoint and renders results.
 * 
 * @param {string} query - The search query string
 */
async function executePeopleSearch(query) {
    if (!token || !query) return;

    // Capture active session generation and username before dispatching async search request
    const capturedGeneration = typeof getSessionGeneration === 'function'
        ? getSessionGeneration()
        : (typeof AppState !== 'undefined' && typeof AppState.sessionGeneration === 'number' ? AppState.sessionGeneration : 0);
    const capturedUser = typeof currentUser !== 'undefined'
        ? currentUser
        : (typeof AppState !== 'undefined' ? AppState.currentUser : null);

    const searchSection = document.getElementById("people-search-section");
    const searchList = document.getElementById("people-search-list");
    const contactsSection = document.getElementById("people-contacts-section");
    const reqSection = document.getElementById("people-requests-section");

    if (searchSection) searchSection.style.display = "";
    if (contactsSection) contactsSection.style.display = "none";
    if (reqSection) reqSection.style.display = "none";

    if (searchList) {
        searchList.innerHTML = `
            <div class="people-empty-state">
                <div class="people-empty-desc">Searching...</div>
            </div>
        `;
    }

    try {
        const res = await fetch(`/search?query=${encodeURIComponent(query)}`, {
            headers: { "Authorization": `Bearer ${token}` }
        });

        // Guard against stale response if user logged out or session switched during search
        if (typeof isSessionValid === 'function' && !isSessionValid(capturedGeneration, capturedUser)) {
            return;
        }

        const results = await res.json();

        if (typeof isSessionValid === 'function' && !isSessionValid(capturedGeneration, capturedUser)) {
            return;
        }

        if (!searchList) return;
        searchList.innerHTML = "";

        if (!Array.isArray(results) || results.length === 0) {
            const escaped = (typeof escapeHtml === "function") ? escapeHtml(query) : query;
            searchList.innerHTML = `
                <div class="people-empty-state">
                    <div class="people-empty-desc">No users found matching "${escaped}"</div>
                </div>
            `;
            return;
        }

        results.forEach(item => {
            if (typeof renderSearchResultItem === "function") {
                renderSearchResultItem(searchList, item);
            }
        });
    } catch (err) {
        console.error("[People] Search error:", err);
        if (typeof isSessionValid === 'function' && !isSessionValid(capturedGeneration, capturedUser)) {
            return;
        }
        if (searchList) {
            searchList.innerHTML = `
                <div class="people-empty-state">
                    <div class="people-empty-desc">Search failed. Please try again.</div>
                </div>
            `;
        }
    }
}

/**
 * Resets People workspace state, pending requests, and timers on session teardown.
 */
function resetPeopleWorkspaceState() {
    isPeopleLoading = false;
    if (peopleSearchTimeout) {
        clearTimeout(peopleSearchTimeout);
        peopleSearchTimeout = null;
    }
}

// Global exposure
window.loadPeopleWorkspace = loadPeopleWorkspace;
window.renderPeopleWorkspace = renderPeopleWorkspace;
window.handlePeopleSearch = handlePeopleSearch;
window.clearPeopleSearch = clearPeopleSearch;
window.executePeopleSearch = executePeopleSearch;
window.resetPeopleWorkspaceState = resetPeopleWorkspaceState;
