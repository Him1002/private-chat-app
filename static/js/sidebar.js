function switchTab(tabName) {
    currentTab = tabName;
    
    // Update UI Tabs
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.getElementById(`tab-${tabName}`).classList.add('active');

    // Show/Hide Search
    const searchBox = document.getElementById("search-container");
    if (tabName === 'people') {
        searchBox.style.display = 'block';
    } else {
        searchBox.style.display = 'none';
    }

    // Reload the list
    loadSidebar();
}

async function loadSidebar() {
    if (!token) return;

    const list = document.getElementById("list-area");
    list.innerHTML = "";

    // fetch data
    const [reqRes, friendRes, convRes] = await Promise.all([
        fetch("/friends/requests", {headers: {"Authorization": `Bearer ${token}`}}),
        fetch("/friends", {headers: {"Authorization": `Bearer ${token}`}}),
        fetch("/conversations", {headers: {"Authorization": `Bearer ${token}`}})
    ]);

    if (!reqRes.ok || !friendRes.ok) return;

    const requests = await reqRes.json();
    const friends = await friendRes.json();

    const convMap = {};
    if (convRes && convRes.ok) {
        const conversations = await convRes.json();
        if (Array.isArray(conversations)) {
            conversations.forEach(c => {
                convMap[c.username] = c;
            });
        }
    }

    friends.forEach(f => {
        const conv = convMap[f.username];
        f.unread_count = (currentFriend === f.username) ? 0 : ((conv && typeof conv.unread_count === "number") ? conv.unread_count : 0);
        f.last_message = conv ? conv.last_message : null;
        f.last_message_time = conv ? conv.last_message_time : null;
    });

    const selectedFriend = friends.find(f => f.username === currentFriend);
    if (selectedFriend) updateChatStatus(selectedFriend);

    // === RENDER LOGIC BASED ON TAB ===
    
    if (currentTab === 'chats') {
        // -- CHATS TAB: Only show Friends (Active Chats) --
        // (Ideally, backend should sort by 'last_message_time', for now we show all friends)
        
        if (friends.length === 0) {
            list.innerHTML = "<div style='padding:20px; text-align:center; color:#555;'>No chats yet.<br>Go to 'People' to add friends!</div>";
            return;
        }

        friends.forEach(f => renderFriendItem(list, f));

    } else if (currentTab === 'people') {
        // -- PEOPLE TAB: Requests + Search Results + All Friends --
        
        // 1. Friend Requests
        if (requests.length > 0) {
            list.innerHTML += `<div class="section-title">Requests (${requests.length})</div>`;
            requests.forEach(r => {
                const div = document.createElement("div");
                div.className = "item";
                div.innerHTML = `
                    <div class="avatar" style="background:#d9534f; border:none;">!</div>
                    <div class="info"><span class="name">${r.username}</span></div>
                    <button class="action-btn" onclick="acceptRequest(${r.request_id})" style="background:#28a745">Accept</button>
                `;
                list.appendChild(div);
            });
        }

        // 2. All Friends (Directory)
        list.innerHTML += `<div class="section-title">Your Contacts</div>`;
        friends.forEach(f => renderFriendItem(list, f));
    }
}

async function handleSearch(e) {
    const query = e.target.value;
    if (!query) return loadSidebar(); 

    const res = await fetch(`/search?query=${query}`, {headers: {"Authorization": `Bearer ${token}`}});
    const results = await res.json();
    const list = document.getElementById("list-area");
    list.innerHTML = "";

    if (results.length === 0) list.innerHTML = "<div style='padding:20px;text-align:center;color:#666'>No users found</div>";

    results.forEach(item => {
        const div = document.createElement("div");
        div.className = "item";
        let action = "";

        if (item.status === "none") {
            action = `<button class="action-btn" onclick="addFriend('${item.username}')">Add</button>`;
        } else if (item.status === "pending") {
            action = `<span class="status">Sent</span>`;
        } else {
            action = `<span class="status">Friend</span>`;
        }

        const avatarHtml = item.profile_picture 
            ? `<img src="${item.profile_picture}" style="width: 100%; height: 100%; object-fit: cover; border-radius: 50%;">` 
            : item.username[0].toUpperCase();
            
        const displayName = item.display_name || item.username;

        div.innerHTML = `
            <div class="avatar">${avatarHtml}</div>
            <div class="info">
                <span class="name">${displayName}</span>
                ${item.about ? `<span class="status" style="opacity: 0.7; font-size: 11px;">${item.about}</span>` : ''}
            </div>
            ${action}
        `;
        list.appendChild(div);
    });
}

function updateSidebarUnread(username, count) {
    const unread = Math.max(0, parseInt(count, 10) || 0);
    document.querySelectorAll(`.item[data-username="${username}"]`).forEach(div => {
        const badge = div.querySelector(".unread-badge");
        if (badge) {
            badge.textContent = unread;
            badge.style.display = unread > 0 ? "" : "none";
        }
    });
}

function renderFriendItem(container, f) {
    const div = document.createElement("div");
    div.className = "item";
    div.dataset.username = f.username;
    if (currentTab === 'chats' && currentFriend === f.username) div.classList.add("active");

    const avatarUrl = f.profile_picture || `https://api.dicebear.com/7.x/notionists/svg?seed=${f.username}&backgroundColor=b6e3f4,c0aede,d1d4f9`;
    const displayName = f.display_name || f.username;
    
    // Use Backend "is_online" truth
    const isOnline = f.is_online; 
    const seenText = isOnline ? "Online" : formatLastSeen(f.last_seen);
    const unreadCount = (currentFriend === f.username) ? 0 : (f.unread_count || 0);

    div.innerHTML = `
        <div class="avatar">
            <img src="${avatarUrl}" style="width: 100%; height: 100%; object-fit: cover; border-radius: 50%;">
        </div>
        <div class="info">
            <span class="name">${displayName}</span>
            <span class="status ${isOnline ? 'online' : ''}">${seenText}</span>
        </div>
        <span class="unread-badge" style="${unreadCount > 0 ? '' : 'display: none;'}">${unreadCount}</span>
    `;
    div.onclick = () => startChat(f, div);
    container.appendChild(div);
}

async function addFriend(username) {
    await fetch(`/friends/request/${username}`, { method: "POST", headers: {"Authorization": `Bearer ${token}`}} );
    showToast(`Request sent to ${username}`, "success");
    handleSearch({target: {value: document.getElementById("search-input").value}});
}

async function acceptRequest(id) {
    await fetch(`/friends/accept/${id}`, { method: "POST", headers: {"Authorization": `Bearer ${token}`} });
    showToast("Friend added!", "success");
    loadSidebar();
}
