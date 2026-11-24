// Application State
const AppState = {
    token: null,
    currentUser: null,
    currentFriend: null,
    currentTab: 'chats',
    currentSection: 'chats',
    sessionGeneration: 0,
    ws: null,
    reconnectTimer: null,
    presenceRefreshTimer: null,
    isRegisterMode: false
};

// DOM Cache
const DOM = {
    // Placeholder for cached DOM elements.
    // Example: loginScreen: null,
    // Example: messageInput: null,
};

// Primary Navigation Destinations
const VALID_PRIMARY_SECTIONS = Object.freeze(['home', 'chats', 'people', 'placeholder', 'settings']);

/**
 * Updates the visual selected state of primary navigation buttons
 * across both the desktop navigation rail and the mobile bottom navigation.
 *
 * @param {string} sectionId - Destination identifier to highlight.
 */
function updateNavigationUI(sectionId) {
    const navButtons = document.querySelectorAll('#app-nav-rail [data-destination], #app-bottom-nav [data-destination]');
    navButtons.forEach(btn => {
        const isCurrent = btn.dataset.destination === sectionId;
        btn.classList.toggle('active', isCurrent);
        if (isCurrent) {
            btn.setAttribute('aria-current', 'page');
        } else {
            btn.removeAttribute('aria-current');
        }
    });
}

/**
 * Primary application navigation controller.
 * Validates the requested destination against supported primary sections,
 * updates central state, synchronizes rail and bottom nav interfaces,
 * and manages section view compatibility.
 *
 * @param {string} sectionId - Target destination ('home', 'chats', 'people', 'placeholder', 'settings')
 * @returns {boolean} True if navigation succeeded, false if invalid/rejected
 */
function navigateToSection(sectionId) {
    if (!sectionId || typeof sectionId !== 'string') {
        console.warn('[Navigation] Invalid section identifier provided:', sectionId);
        return false;
    }

    const target = sectionId.toLowerCase();
    if (!VALID_PRIMARY_SECTIONS.includes(target)) {
        console.warn(`[Navigation] Destination "${sectionId}" is not a recognized primary section. Navigation rejected.`);
        return false;
    }

    // 1. Update state (both AppState and legacy global)
    if (typeof AppState !== 'undefined') {
        AppState.currentSection = target;
    }
    if (typeof currentSection !== 'undefined') {
        currentSection = target;
    }

    // 2. Synchronize navigation controls (rail and bottom nav)
    updateNavigationUI(target);

    // 3. Update active workspace section
    const workspace = document.getElementById('app-workspace');
    if (workspace) {
        workspace.setAttribute('data-active-section', target);
    }

    // 4. Section specific routing / compatibility
    if (target === 'home') {
        // Switch mobile view out of active chat view if open
        if (document.body && document.body.classList.contains('view-chat') && typeof showListView === 'function') {
            showListView();
        }
        // Load dedicated Home workspace data
        if (typeof loadHomeWorkspace === 'function') {
            loadHomeWorkspace();
        }
    } else if (target === 'chats') {
        // Ensure Chats sidebar mode is active without resetting conversation or connection
        if (typeof currentTab !== 'undefined' && currentTab !== 'chats') {
            if (typeof switchTab === 'function') {
                switchTab('chats');
            }
        }
    } else if (target === 'people') {
        // Switch mobile view out of active chat view if open
        if (document.body && document.body.classList.contains('view-chat') && typeof showListView === 'function') {
            showListView();
        }
        // Load dedicated People workspace data
        if (typeof loadPeopleWorkspace === 'function') {
            loadPeopleWorkspace();
        }
    } else if (target === 'placeholder') {
        // Switch mobile view out of active chat view if open
        if (document.body && document.body.classList.contains('view-chat') && typeof showListView === 'function') {
            showListView();
        }
    } else if (target === 'settings') {
        // Switch mobile view out of active chat view if open
        if (document.body && document.body.classList.contains('view-chat') && typeof showListView === 'function') {
            showListView();
        }
        // Load dedicated Settings workspace data
        if (typeof loadSettingsWorkspace === 'function') {
            loadSettingsWorkspace();
        }
    }

    return true;
}

let isPrimaryNavInitialized = false;

/**
 * Initializes centralized event delegation for both desktop navigation rail
 * and mobile bottom navigation. Ensures listeners are bound only once.
 */
function initPrimaryNavigation() {
    if (isPrimaryNavInitialized) return;

    function handleNavClick(event) {
        const btn = event.target.closest('[data-destination]');
        if (!btn) return;
        event.preventDefault();
        const dest = btn.dataset.destination;
        if (dest) {
            navigateToSection(dest);
        }
    }

    const rail = document.getElementById('app-nav-rail');
    if (rail) {
        rail.addEventListener('click', handleNavClick);
    }

    const bottomNav = document.getElementById('app-bottom-nav');
    if (bottomNav) {
        bottomNav.addEventListener('click', handleNavClick);
    }

    // Synchronize initial UI state with AppState.currentSection
    const initialSection = (typeof AppState !== 'undefined' && AppState.currentSection) || 'chats';
    updateNavigationUI(initialSection);
    const workspace = document.getElementById('app-workspace');
    if (workspace) {
        workspace.setAttribute('data-active-section', initialSection);
    }

    isPrimaryNavInitialized = true;
}

// Bind initialization to DOMContentLoaded or execute immediately if DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initPrimaryNavigation);
} else {
    initPrimaryNavigation();
}

/**
 * Session generation management for preventing asynchronous cross-session race conditions.
 */
function getSessionGeneration() {
    return (typeof AppState !== 'undefined' && typeof AppState.sessionGeneration === 'number')
        ? AppState.sessionGeneration
        : 0;
}

function startNewSessionGeneration() {
    if (typeof AppState !== 'undefined') {
        AppState.sessionGeneration = (AppState.sessionGeneration || 0) + 1;
        return AppState.sessionGeneration;
    }
    return 0;
}

function invalidateSessionGeneration() {
    if (typeof AppState !== 'undefined') {
        AppState.sessionGeneration = (AppState.sessionGeneration || 0) + 1;
        return AppState.sessionGeneration;
    }
    return 0;
}

function isSessionValid(generation, username) {
    const currentGen = getSessionGeneration();
    const currentToken = (typeof token !== 'undefined' && token)
        ? token
        : (typeof AppState !== 'undefined' ? AppState.token : null);
    const activeUser = (typeof currentUser !== 'undefined' && currentUser)
        ? currentUser
        : (typeof AppState !== 'undefined' ? AppState.currentUser : null);

    return Boolean(
        currentToken &&
        generation === currentGen &&
        username &&
        activeUser &&
        username === activeUser
    );
}

// Global exposure
window.AppState = AppState;
window.VALID_PRIMARY_SECTIONS = VALID_PRIMARY_SECTIONS;
window.updateNavigationUI = updateNavigationUI;
window.navigateToSection = navigateToSection;
window.initPrimaryNavigation = initPrimaryNavigation;
window.getSessionGeneration = getSessionGeneration;
window.startNewSessionGeneration = startNewSessionGeneration;
window.invalidateSessionGeneration = invalidateSessionGeneration;
window.isSessionValid = isSessionValid;
