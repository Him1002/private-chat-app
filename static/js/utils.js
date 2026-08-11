function showToast(msg, type = "normal") {
    const container = document.getElementById("toast-container");
    const div = document.createElement("div");
    div.className = `toast ${type}`;
    div.innerText = msg;
    container.appendChild(div);
    
    // Trigger animation
    setTimeout(() => div.classList.add("show"), 10);
    setTimeout(() => {
        div.classList.remove("show");
        setTimeout(() => div.remove(), 300);
    }, 3000);
}

function formatLastSeen(isoStr) {
    if (!isoStr) return "Offline";
    const date = new Date(isoStr + "Z");
    const now = new Date();
    const diffSeconds = Math.floor((now - date) / 1000);
    if (diffSeconds < 60) return "Online";
    if (diffSeconds < 3600) return `${Math.floor(diffSeconds / 60)}m ago`;
    if (diffSeconds < 86400) return `${Math.floor(diffSeconds / 3600)}h ago`;
    return `${Math.floor(diffSeconds / 86400)}d ago`;
}

function formatMessageTimestamp(timestamp) {
    if (!timestamp) return "";
    const date = new Date(timestamp);
    if (Number.isNaN(date.getTime())) return "";

    const day = String(date.getDate()).padStart(2, "0");
    const month = String(date.getMonth() + 1).padStart(2, "0");
    const year = date.getFullYear();

    let hours = date.getHours();
    const minutes = String(date.getMinutes()).padStart(2, "0");
    const seconds = String(date.getSeconds()).padStart(2, "0");
    const meridiem = hours >= 12 ? "PM" : "AM";
    hours = hours % 12;
    hours = hours ? hours : 12;

    return `${day}/${month}/${year} ${String(hours).padStart(2, "0")}:${minutes}:${seconds} ${meridiem}`;
}

function handleEnter(e) { if (e.key === "Enter") send(); }
