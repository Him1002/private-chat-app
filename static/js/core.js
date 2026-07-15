// Application State
const AppState = {
    token: null,
    currentUser: null,
    currentFriend: null,
    currentTab: 'chats',
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

// Shared Utilities
// Future shared utility functions can be added here.
