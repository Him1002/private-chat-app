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
            const reqTitle = document.createElement("div");
            reqTitle.className = "section-title";
            reqTitle.textContent = `Requests (${requests.length})`;
            list.appendChild(reqTitle);

            requests.forEach(r => {
                const div = document.createElement("div");
                div.className = "item";

                const avatar = document.createElement("div");
                avatar.className = "avatar";
                avatar.style.background = "#d9534f";
                avatar.style.border = "none";
                avatar.textContent = "!";

                const info = document.createElement("div");
                info.className = "info";
                const nameSpan = document.createElement("span");
                nameSpan.className = "name";
                nameSpan.textContent = r.username || "";
                info.appendChild(nameSpan);

                const acceptBtn = document.createElement("button");
                acceptBtn.className = "action-btn";
                acceptBtn.style.background = "#28a745";
                acceptBtn.textContent = "Accept";
                acceptBtn.addEventListener("click", () => acceptRequest(r.request_id));

                div.appendChild(avatar);
                div.appendChild(info);
                div.appendChild(acceptBtn);
                list.appendChild(div);
            });
        }

        // 2. All Friends (Directory)
        const contactsTitle = document.createElement("div");
        contactsTitle.className = "section-title";
        contactsTitle.textContent = "Your Contacts";
        list.appendChild(contactsTitle);
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

    if (results.length === 0) {
        const emptyDiv = document.createElement("div");
        emptyDiv.style.padding = "20px";
        emptyDiv.style.textAlign = "center";
        emptyDiv.style.color = "#666";
        emptyDiv.textContent = "No users found";
        list.appendChild(emptyDiv);
        return;
    }

    results.forEach(item => {
        const div = document.createElement("div");
        div.className = "item";

        const avatarDiv = document.createElement("div");
        avatarDiv.className = "avatar";
        const sanitizedPic = sanitizeMediaUrl(item.profile_picture);
        if (sanitizedPic) {
            const img = document.createElement("img");
            img.src = sanitizedPic;
            img.alt = "";
            img.style.width = "100%";
            img.style.height = "100%";
            img.style.objectFit = "cover";
            img.style.borderRadius = "50%";
            avatarDiv.appendChild(img);
        } else {
            const initial = (item.username && item.username.length > 0) ? item.username[0].toUpperCase() : "?";
            avatarDiv.textContent = initial;
        }

        const infoDiv = document.createElement("div");
        infoDiv.className = "info";
        const nameSpan = document.createElement("span");
        nameSpan.className = "name";
        nameSpan.textContent = item.display_name || item.username || "";
        infoDiv.appendChild(nameSpan);

        if (item.about) {
            const aboutSpan = document.createElement("span");
            aboutSpan.className = "status";
            aboutSpan.style.opacity = "0.7";
            aboutSpan.style.fontSize = "11px";
            aboutSpan.textContent = item.about;
            infoDiv.appendChild(aboutSpan);
        }

        div.appendChild(avatarDiv);
        div.appendChild(infoDiv);

        if (item.status === "none") {
            const addBtn = document.createElement("button");
            addBtn.className = "action-btn";
            addBtn.textContent = "Add";
            addBtn.addEventListener("click", () => addFriend(item.username));
            div.appendChild(addBtn);
        } else if (item.status === "pending") {
            const sentSpan = document.createElement("span");
            sentSpan.className = "status";
            sentSpan.textContent = "Sent";
            div.appendChild(sentSpan);
        } else {
            const friendSpan = document.createElement("span");
            friendSpan.className = "status";
            friendSpan.textContent = "Friend";
            div.appendChild(friendSpan);
        }

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
    div.dataset.username = f.username || "";
    if (currentTab === 'chats' && currentFriend === f.username) div.classList.add("active");

    const fallbackAvatar = `https://api.dicebear.com/7.x/notionists/svg?seed=${encodeURIComponent(f.username || "")}&backgroundColor=b6e3f4,c0aede,d1d4f9`;
    const avatarUrl = sanitizeMediaUrl(f.profile_picture) || fallbackAvatar;
    const displayName = f.display_name || f.username || "";
    
    // Use Backend "is_online" truth
    const isOnline = f.is_online; 
    const seenText = isOnline ? "Online" : formatLastSeen(f.last_seen);
    const unreadCount = (currentFriend === f.username) ? 0 : (f.unread_count || 0);

    const avatarDiv = document.createElement("div");
    avatarDiv.className = "avatar";
    const img = document.createElement("img");
    img.src = avatarUrl;
    img.alt = "";
    img.style.width = "100%";
    img.style.height = "100%";
    img.style.objectFit = "cover";
    img.style.borderRadius = "50%";
    avatarDiv.appendChild(img);

    const infoDiv = document.createElement("div");
    infoDiv.className = "info";
    const nameSpan = document.createElement("span");
    nameSpan.className = "name";
    nameSpan.textContent = displayName;

    const statusSpan = document.createElement("span");
    statusSpan.className = `status ${isOnline ? 'online' : ''}`;
    statusSpan.textContent = seenText;

    infoDiv.appendChild(nameSpan);
    infoDiv.appendChild(statusSpan);

    const badgeSpan = document.createElement("span");
    badgeSpan.className = "unread-badge";
    if (unreadCount <= 0) {
        badgeSpan.style.display = "none";
    }
    badgeSpan.textContent = String(unreadCount);

    div.appendChild(avatarDiv);
    div.appendChild(infoDiv);
    div.appendChild(badgeSpan);

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
