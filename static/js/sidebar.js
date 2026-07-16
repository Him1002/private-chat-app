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
    const [reqRes, friendRes] = await Promise.all([
        fetch("/friends/requests", {headers: {"Authorization": `Bearer ${token}`}}),
        fetch("/friends", {headers: {"Authorization": `Bearer ${token}`}})
    ]);

    if (!reqRes.ok || !friendRes.ok) return;

    const requests = await reqRes.json();
    const friends = await friendRes.json();
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

        div.innerHTML = `
            <div class="avatar">${item.username[0].toUpperCase()}</div>
            <div class="info"><span class="name">${item.username}</span></div>
            ${action}
        `;
        list.appendChild(div);
    });
}

function renderFriendItem(container, f) {
    const div = document.createElement("div");
    div.className = "item";
    if (currentTab === 'chats' && currentFriend === f.username) div.classList.add("active");

    const avatarUrl = `https://api.dicebear.com/7.x/notionists/svg?seed=${f.username}&backgroundColor=b6e3f4,c0aede,d1d4f9`;
    
    // Use Backend "is_online" truth
    const isOnline = f.is_online; 
    const seenText = isOnline ? "Online" : formatLastSeen(f.last_seen);

    div.innerHTML = `
        <div class="avatar">
            <img src="${avatarUrl}">
        </div>
        <div class="info">
            <span class="name">${f.username}</span>
            <span class="status ${isOnline ? 'online' : ''}">${seenText}</span>
        </div>
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
