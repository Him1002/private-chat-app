async function handleFileUpload(inputElement) {
    const file = inputElement.files[0];
    if (!file) return;
    if (!currentFriend) {
        showToast("Select a chat first", "error");
        inputElement.value = "";
        return;
    }

    const formData = new FormData();
    formData.append("file", file);

    try {
        showToast("Uploading...", "normal");
        const res = await fetch("/upload", {
            method: "POST",
            headers: { "Authorization": `****** },
            body: formData
        });
        
        if (res.ok) {
            const data = await res.json();
            // Send message with Image URL
            const sent = sendSocketPayload({
                type: "chat",
                room: currentFriend,
                text: "",
                image_url: data.url
            });
            if (!sent) {
                showToast("Reconnecting chat...", "normal");
            }
        } else {
            showToast("Upload failed", "error");
        }
    } catch (e) {
        showToast("Error uploading", "error");
    }
    inputElement.value = ""; // Reset
}
