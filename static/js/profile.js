let myProfile = {};

async function openProfile() {
    document.getElementById('profile-screen').style.display = 'flex';
    
    // Fetch current profile
    try {
        const res = await fetch('/profile/', {
            headers: {
                "Authorization": `Bearer ${token}`
            }
        });
        if (res.ok) {
            myProfile = await res.json();
            document.getElementById('profile-display-name').value = myProfile.display_name || '';
            document.getElementById('profile-about').value = myProfile.about || '';
            
            const preview = document.getElementById('profile-pic-preview');
            if (myProfile.profile_picture) {
                preview.src = myProfile.profile_picture;
                preview.style.display = 'block';
            } else {
                preview.src = '';
                preview.style.display = 'none';
            }
        }
    } catch (e) {
        console.error("Error fetching profile", e);
    }
}

function closeProfile() {
    document.getElementById('profile-screen').style.display = 'none';
}

async function saveProfile() {
    const displayName = document.getElementById('profile-display-name').value;
    const about = document.getElementById('profile-about').value;
    
    try {
        const res = await fetch('/profile/', {
            method: 'PUT',
            headers: {
                "Content-Type": "application/json",
                "Authorization": `Bearer ${token}`
            },
            body: JSON.stringify({
                display_name: displayName,
                about: about
            })
        });
        
        if (res.ok) {
            showToast("Profile saved", "success");
            closeProfile();
        } else {
            showToast("Error saving profile", "error");
        }
    } catch (e) {
        showToast("Error saving profile", "error");
    }
}

async function handleProfilePicChange(input) {
    if (!input.files || input.files.length === 0) return;
    
    const file = input.files[0];
    const formData = new FormData();
    formData.append("file", file);
    
    try {
        // Use existing upload endpoint
        const uploadRes = await fetch('/upload', {
            method: 'POST',
            headers: {
                "Authorization": `Bearer ${token}`
            },
            body: formData
        });
        
        if (!uploadRes.ok) throw new Error("Upload failed");
        
        const uploadData = await uploadRes.json();
        const url = uploadData.url;
        
        // Update profile picture
        const res = await fetch('/profile/picture', {
            method: 'PUT',
            headers: {
                "Content-Type": "application/json",
                "Authorization": `Bearer ${token}`
            },
            body: JSON.stringify({
                profile_picture: url
            })
        });
        
        if (res.ok) {
            document.getElementById('profile-pic-preview').src = url;
            document.getElementById('profile-pic-preview').style.display = 'block';
            showToast("Profile picture updated", "success");
        }
    } catch (e) {
        showToast("Error updating picture", "error");
    }
    
    // reset input
    input.value = "";
}
