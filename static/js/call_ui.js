/**
 * Call UI Presentation & Controller Layer for ChatSpic V2 Calling (Phase 3).
 *
 * Responsibilities:
 * - Presentation and user interaction layer for one-to-one voice/video calls.
 * - Subscribes to WebRTCManager events and drives UI states.
 * - Manages header call buttons, outgoing modal, incoming modal, dedicated call screen,
 *   minimized floating bar, in-call controls, and synthesized audio ringtones.
 * - Reuses existing chat state (currentFriend, cachedFriends) without duplicate state.
 * - NEVER duplicates WebRTC signaling, peer connections, or call state machines.
 */

(function () {
    'use strict';

    // UI module state
    let callTimerInterval = null;
    let callDurationSeconds = 0;
    let ringtoneAudioContext = null;
    let ringtoneTimer = null;
    let isCallMinimized = false;
    let pendingInviteData = null;

    /**
     * Contact metadata lookup helper using existing sidebar cachedFriends.
     */
    function getContactInfo(username) {
        if (!username) {
            return {
                username: '',
                displayName: 'Contact',
                avatarUrl: null
            };
        }

        let match = null;
        if (typeof window !== 'undefined' && Array.isArray(window.cachedFriends)) {
            match = window.cachedFriends.find(function (f) {
                return f && f.username === username;
            });
        }

        const displayName = (match && (match.display_name || match.username)) ? (match.display_name || match.username) : username;
        const rawPic = match ? match.profile_picture : null;
        const sanitizedPic = (typeof sanitizeMediaUrl === 'function') ? sanitizeMediaUrl(rawPic) : rawPic;

        return {
            username: username,
            displayName: displayName,
            avatarUrl: sanitizedPic
        };
    }

    /**
     * Update avatar display on a DOM node safely without innerHTML.
     */
    function setAvatarElement(avatarContainerEl, username, avatarUrl) {
        if (!avatarContainerEl) return;
        avatarContainerEl.textContent = '';

        if (avatarUrl) {
            const img = document.createElement('img');
            img.src = avatarUrl;
            img.alt = '';
            img.style.width = '100%';
            img.style.height = '100%';
            img.style.objectFit = 'cover';
            img.onerror = function () {
                avatarContainerEl.textContent = '';
                const fallbackChar = (username && username.length > 0) ? username[0].toUpperCase() : '?';
                avatarContainerEl.textContent = fallbackChar;
            };
            avatarContainerEl.appendChild(img);
        } else {
            const initial = (username && username.length > 0) ? username[0].toUpperCase() : '?';
            avatarContainerEl.textContent = initial;
        }
    }

    /**
     * Format duration seconds as mm:ss (e.g. 02:45).
     */
    function formatDuration(seconds) {
        const s = Math.max(0, Math.floor(seconds || 0));
        const mins = Math.floor(s / 60);
        const secs = s % 60;
        const minsStr = mins < 10 ? '0' + mins : String(mins);
        const secsStr = secs < 10 ? '0' + secs : String(secs);
        return minsStr + ':' + secsStr;
    }

    /**
     * Start the in-call duration timer.
     */
    function startCallTimer() {
        stopCallTimer();
        callDurationSeconds = 0;
        updateTimerDisplay('00:00');

        callTimerInterval = setInterval(function () {
            callDurationSeconds += 1;
            const formatted = formatDuration(callDurationSeconds);
            updateTimerDisplay(formatted);
        }, 1000);
    }

    /**
     * Stop the in-call duration timer.
     */
    function stopCallTimer() {
        if (callTimerInterval) {
            clearInterval(callTimerInterval);
            callTimerInterval = null;
        }
    }

    /**
     * Update all timer display elements.
     */
    function updateTimerDisplay(formattedText) {
        const timerEl = document.getElementById('call-duration-timer');
        if (timerEl) timerEl.textContent = formattedText;

        const minTimerEl = document.getElementById('minimized-duration');
        if (minTimerEl) minTimerEl.textContent = formattedText;
    }

    /**
     * Synthesize audio ringtones using Web Audio API (zero external assets).
     */
    function playRingtone(type) {
        stopRingtone();

        const AudioCtx = window.AudioContext || window.webkitAudioContext;
        if (!AudioCtx) return;

        try {
            ringtoneAudioContext = new AudioCtx();
        } catch (err) {
            return;
        }

        if (ringtoneAudioContext.state === 'suspended') {
            ringtoneAudioContext.resume().catch(function () {});
        }

        function playBurst() {
            if (!ringtoneAudioContext || ringtoneAudioContext.state === 'closed') return;
            const now = ringtoneAudioContext.currentTime;

            if (type === 'outgoing') {
                // Dual-tone 440Hz + 480Hz for 1.6s
                const osc1 = ringtoneAudioContext.createOscillator();
                const osc2 = ringtoneAudioContext.createOscillator();
                const gain = ringtoneAudioContext.createGain();

                osc1.frequency.value = 440;
                osc2.frequency.value = 480;

                gain.gain.setValueAtTime(0.001, now);
                gain.gain.linearRampToValueAtTime(0.12, now + 0.05);
                gain.gain.setValueAtTime(0.12, now + 1.55);
                gain.gain.linearRampToValueAtTime(0.001, now + 1.6);

                osc1.connect(gain);
                osc2.connect(gain);
                gain.connect(ringtoneAudioContext.destination);

                osc1.start(now);
                osc2.start(now);
                osc1.stop(now + 1.65);
                osc2.stop(now + 1.65);
            } else {
                // Incoming chime: two distinct cheerful pulses
                const osc1 = ringtoneAudioContext.createOscillator();
                const osc2 = ringtoneAudioContext.createOscillator();
                const gain1 = ringtoneAudioContext.createGain();
                const gain2 = ringtoneAudioContext.createGain();

                osc1.frequency.value = 523.25; // C5
                osc2.frequency.value = 659.25; // E5

                gain1.gain.setValueAtTime(0.001, now);
                gain1.gain.linearRampToValueAtTime(0.15, now + 0.05);
                gain1.gain.exponentialRampToValueAtTime(0.001, now + 0.4);

                gain2.gain.setValueAtTime(0.001, now + 0.18);
                gain2.gain.linearRampToValueAtTime(0.15, now + 0.22);
                gain2.gain.exponentialRampToValueAtTime(0.001, now + 0.65);

                osc1.connect(gain1);
                osc2.connect(gain2);
                gain1.connect(ringtoneAudioContext.destination);
                gain2.connect(ringtoneAudioContext.destination);

                osc1.start(now);
                osc1.stop(now + 0.45);
                osc2.start(now + 0.18);
                osc2.stop(now + 0.7);
            }
        }

        playBurst();
        const repeatInterval = (type === 'outgoing') ? 3600 : 2600;
        ringtoneTimer = setInterval(playBurst, repeatInterval);
    }

    function stopRingtone() {
        if (ringtoneTimer) {
            clearInterval(ringtoneTimer);
            ringtoneTimer = null;
        }
        if (ringtoneAudioContext) {
            try {
                ringtoneAudioContext.close();
            } catch (err) {}
            ringtoneAudioContext = null;
        }
    }

    /**
     * Set header call buttons enabled/disabled state based on call presence.
     */
    function updateHeaderButtonsState() {
        const voiceBtn = document.getElementById('btn-call-voice');
        const videoBtn = document.getElementById('btn-call-video');
        if (!voiceBtn || !videoBtn) return;

        const state = (typeof WebRTCManager !== 'undefined' && WebRTCManager.getWebRTCState)
            ? WebRTCManager.getWebRTCState()
            : null;

        const isBusy = state && (state.callState !== 'idle' && state.callState !== 'ended' && state.callState !== 'failed');
        voiceBtn.disabled = isBusy;
        videoBtn.disabled = isBusy;
    }

    /**
     * Show or hide active chat header call action buttons.
     */
    function setHeaderCallButtonsVisible(visible) {
        const container = document.getElementById('chat-header-actions');
        if (container) {
            container.style.display = visible ? 'flex' : 'none';
        }
        updateHeaderButtonsState();
    }

    /**
     * Render the Outgoing Call Screen.
     */
    function showOutgoingCallUI(calleeUsername, callType) {
        const modal = document.getElementById('outgoing-call-modal');
        if (!modal) return;

        const info = getContactInfo(calleeUsername);
        const nameEl = document.getElementById('outgoing-callee-name');
        if (nameEl) nameEl.textContent = info.displayName;

        const typeEl = document.getElementById('outgoing-call-type');
        if (typeEl) {
            typeEl.textContent = callType === 'video' ? 'Outgoing Video Call' : 'Outgoing Voice Call';
        }

        const statusEl = document.getElementById('outgoing-call-status');
        if (statusEl) statusEl.textContent = 'Calling...';

        const avatarContainer = document.getElementById('outgoing-avatar-img');
        setAvatarElement(avatarContainer, info.username, info.avatarUrl);

        modal.style.display = 'flex';
        playRingtone('outgoing');
    }

    function hideOutgoingCallUI() {
        const modal = document.getElementById('outgoing-call-modal');
        if (modal) modal.style.display = 'none';
        stopRingtone();
    }

    /**
     * Render the Incoming Call Screen.
     */
    function showIncomingCallUI(inviteData) {
        pendingInviteData = inviteData;
        const modal = document.getElementById('incoming-call-modal');
        if (!modal) return;

        const callerUsername = inviteData.from_username;
        const callType = inviteData.call_type;
        const info = getContactInfo(callerUsername);

        const nameEl = document.getElementById('incoming-caller-name');
        if (nameEl) nameEl.textContent = info.displayName;

        const typeEl = document.getElementById('incoming-call-type');
        if (typeEl) {
            typeEl.textContent = callType === 'video' ? 'Incoming Video Call' : 'Incoming Voice Call';
        }

        const avatarContainer = document.getElementById('incoming-avatar-img');
        setAvatarElement(avatarContainer, info.username, info.avatarUrl);

        modal.style.display = 'flex';
        playRingtone('incoming');
    }

    function hideIncomingCallUI() {
        pendingInviteData = null;
        const modal = document.getElementById('incoming-call-modal');
        if (modal) modal.style.display = 'none';
        stopRingtone();
    }

    /**
     * Show dedicated Connected Call Screen.
     */
    function showConnectedCallScreen(callType, peerUsername) {
        hideOutgoingCallUI();
        hideIncomingCallUI();

        const screen = document.getElementById('call-screen');
        if (!screen) return;

        isCallMinimized = false;
        hideMinimizedBar();

        const info = getContactInfo(peerUsername);
        const nameEl = document.getElementById('call-peer-name');
        if (nameEl) nameEl.textContent = info.displayName;

        const typeBadge = document.getElementById('call-type-badge');
        if (typeBadge) {
            typeBadge.textContent = (callType === 'video') ? 'Video Call' : 'Voice Call';
        }

        const voiceView = document.getElementById('call-voice-view');
        const videoView = document.getElementById('call-video-view');
        const cameraBtn = document.getElementById('btn-call-camera');
        const switchCamBtn = document.getElementById('btn-call-switch-camera');
        const pipBtn = document.getElementById('btn-call-pip');

        if (callType === 'video') {
            if (voiceView) voiceView.style.display = 'none';
            if (videoView) videoView.style.display = 'flex';
            if (cameraBtn) cameraBtn.style.display = 'inline-flex';

            // Feature detection for switch camera
            if (switchCamBtn) {
                if (navigator.mediaDevices && navigator.mediaDevices.enumerateDevices) {
                    navigator.mediaDevices.enumerateDevices().then(function (devices) {
                        const videoInputs = devices.filter(function (d) { return d.kind === 'videoinput'; });
                        switchCamBtn.style.display = videoInputs.length > 1 ? 'inline-flex' : 'none';
                    }).catch(function () {
                        switchCamBtn.style.display = 'none';
                    });
                } else {
                    switchCamBtn.style.display = 'none';
                }
            }

            // Feature detection for PiP
            if (pipBtn) {
                const videoEl = document.getElementById('call-remote-video');
                const canPip = document.pictureInPictureEnabled && videoEl && typeof videoEl.requestPictureInPicture === 'function';
                pipBtn.style.display = canPip ? 'inline-flex' : 'none';
            }
        } else {
            if (voiceView) voiceView.style.display = 'flex';
            if (videoView) videoView.style.display = 'none';
            if (cameraBtn) cameraBtn.style.display = 'none';
            if (switchCamBtn) switchCamBtn.style.display = 'none';
            if (pipBtn) pipBtn.style.display = 'none';

            const voiceAvatar = document.getElementById('call-voice-avatar');
            setAvatarElement(voiceAvatar, info.username, info.avatarUrl);
        }

        // Feature detection for speaker / audio output selection
        const speakerBtn = document.getElementById('btn-call-speaker');
        if (speakerBtn) {
            const hasSetSinkId = typeof HTMLMediaElement !== 'undefined' && 'setSinkId' in HTMLMediaElement.prototype;
            speakerBtn.style.display = hasSetSinkId ? 'inline-flex' : 'none';
        }

        screen.style.display = 'flex';
        updateInCallControlButtons();
        updateHeaderButtonsState();
    }

    function hideConnectedCallScreen() {
        const screen = document.getElementById('call-screen');
        if (screen) screen.style.display = 'none';

        if (document.fullscreenElement) {
            document.exitFullscreen().catch(function () {});
        }
        if (document.pictureInPictureElement) {
            document.exitPictureInPicture().catch(function () {});
        }
    }

    /**
     * Show / Hide Minimized Floating Call Bar.
     */
    function showMinimizedBar(peerUsername) {
        const bar = document.getElementById('call-minimized-bar');
        if (!bar) return;

        const info = getContactInfo(peerUsername);
        const nameEl = document.getElementById('call-minimized-name');
        if (nameEl) nameEl.textContent = info.displayName;

        const avatarEl = document.getElementById('call-minimized-avatar');
        setAvatarElement(avatarEl, info.username, info.avatarUrl);

        bar.style.display = 'flex';
        isCallMinimized = true;
    }

    function hideMinimizedBar() {
        const bar = document.getElementById('call-minimized-bar');
        if (bar) bar.style.display = 'none';
        isCallMinimized = false;
    }

    /**
     * Toggle minimize / restore of the dedicated call screen.
     */
    function minimizeCallScreen() {
        const state = (typeof WebRTCManager !== 'undefined' && WebRTCManager.getWebRTCState)
            ? WebRTCManager.getWebRTCState()
            : null;
        const peer = (typeof WebRTCManager !== 'undefined' && WebRTCManager.getPeerUsername)
            ? WebRTCManager.getPeerUsername()
            : null;

        hideConnectedCallScreen();
        showMinimizedBar(peer);
    }

    function restoreCallScreen() {
        const state = (typeof WebRTCManager !== 'undefined' && WebRTCManager.getWebRTCState)
            ? WebRTCManager.getWebRTCState()
            : null;
        const peer = (typeof WebRTCManager !== 'undefined' && WebRTCManager.getPeerUsername)
            ? WebRTCManager.getPeerUsername()
            : null;

        hideMinimizedBar();
        showConnectedCallScreen(state ? state.callType : 'voice', peer);
    }

    /**
     * Update mic & camera button icons/state in controls bar.
     */
    function updateInCallControlButtons() {
        if (typeof WebRTCManager === 'undefined') return;

        const isAudio = WebRTCManager.isAudioEnabled ? WebRTCManager.isAudioEnabled() : true;
        const isVideo = WebRTCManager.isVideoEnabled ? WebRTCManager.isVideoEnabled() : true;

        const muteBtn = document.getElementById('btn-call-mute');
        if (muteBtn) {
            muteBtn.classList.toggle('off', !isAudio);
            muteBtn.title = isAudio ? 'Mute microphone' : 'Unmute microphone';
            muteBtn.setAttribute('aria-label', muteBtn.title);
        }

        const minMuteBtn = document.getElementById('btn-minimized-mute');
        if (minMuteBtn) {
            minMuteBtn.classList.toggle('off', !isAudio);
            minMuteBtn.title = isAudio ? 'Mute microphone' : 'Unmute microphone';
            minMuteBtn.setAttribute('aria-label', minMuteBtn.title);
        }

        const camBtn = document.getElementById('btn-call-camera');
        if (camBtn) {
            camBtn.classList.toggle('off', !isVideo);
            camBtn.title = isVideo ? 'Turn off camera' : 'Turn on camera';
            camBtn.setAttribute('aria-label', camBtn.title);
        }
    }

    /**
     * Video-to-Voice Fallback Confirmation Prompt.
     */
    function showVoiceFallbackModal(fallbackObj) {
        const modal = document.getElementById('call-fallback-modal');
        if (!modal) return;
        modal.style.display = 'flex';
    }

    function hideVoiceFallbackModal() {
        const modal = document.getElementById('call-fallback-modal');
        if (modal) modal.style.display = 'none';
    }

    /**
     * Clean reset of all Call UI presentation elements.
     */
    function cleanupCallUI() {
        stopCallTimer();
        stopRingtone();
        hideOutgoingCallUI();
        hideIncomingCallUI();
        hideConnectedCallScreen();
        hideMinimizedBar();
        hideVoiceFallbackModal();

        const localVideo = document.getElementById('call-local-video');
        if (localVideo) localVideo.srcObject = null;

        const remoteVideo = document.getElementById('call-remote-video');
        if (remoteVideo) remoteVideo.srcObject = null;

        const remoteAudio = document.getElementById('call-remote-audio');
        if (remoteAudio) remoteAudio.srcObject = null;

        const reconnectingBadge = document.getElementById('call-reconnecting-badge');
        if (reconnectingBadge) reconnectingBadge.style.display = 'none';

        updateHeaderButtonsState();
    }

    /**
     * Map WebRTC error taxonomy to clear, user-friendly toast messages.
     */
    function formatCallError(err) {
        if (!err) return 'Call failed';
        const code = err.code;

        switch (code) {
            case 'PERMISSION_DENIED':
                return 'Microphone or camera permission was denied. Please allow access in browser settings.';
            case 'NO_MICROPHONE':
                return 'No microphone found on this device.';
            case 'NO_CAMERA':
                return 'No camera found on this device.';
            case 'DEVICE_UNAVAILABLE':
                return 'Microphone or camera is currently in use by another application.';
            case 'MEDIA_CONSTRAINTS_FAILED':
                return 'Audio/video constraints could not be satisfied by this device.';
            case 'UNSUPPORTED_BROWSER':
                return 'Calling is not supported in this browser.';
            case 'CONFIG_FETCH_FAILED':
                return 'Unable to connect to the call server.';
            case 'CALL_ALREADY_ACTIVE':
                return 'You are already in an active call.';
            default:
                return err.message || 'Call failed';
        }
    }

    /**
     * Wire DOM event listeners for buttons.
     */
    function initCallUIBindings() {
        // 1. Active Chat Header Buttons
        const voiceBtn = document.getElementById('btn-call-voice');
        if (voiceBtn) {
            voiceBtn.addEventListener('click', function () {
                if (typeof currentFriend === 'string' && currentFriend) {
                    showOutgoingCallUI(currentFriend, 'voice');
                    WebRTCManager.initiateCall(currentFriend, 'voice').catch(function (err) {
                        hideOutgoingCallUI();
                        if (typeof showToast === 'function') {
                            showToast(formatCallError(err), 'error');
                        }
                    });
                }
            });
        }

        const videoBtn = document.getElementById('btn-call-video');
        if (videoBtn) {
            videoBtn.addEventListener('click', function () {
                if (typeof currentFriend === 'string' && currentFriend) {
                    showOutgoingCallUI(currentFriend, 'video');
                    WebRTCManager.initiateCall(currentFriend, 'video').catch(function (err) {
                        hideOutgoingCallUI();
                        if (typeof showToast === 'function') {
                            showToast(formatCallError(err), 'error');
                        }
                    });
                }
            });
        }

        // 2. Outgoing Call Modal Buttons
        const cancelOutgoingBtn = document.getElementById('btn-outgoing-cancel');
        if (cancelOutgoingBtn) {
            cancelOutgoingBtn.addEventListener('click', function () {
                if (typeof WebRTCManager !== 'undefined' && WebRTCManager.cancelCall) {
                    WebRTCManager.cancelCall();
                }
                cleanupCallUI();
            });
        }

        // 3. Incoming Call Modal Buttons
        const acceptIncomingBtn = document.getElementById('btn-incoming-accept');
        if (acceptIncomingBtn) {
            acceptIncomingBtn.addEventListener('click', function () {
                if (pendingInviteData && typeof WebRTCManager !== 'undefined' && WebRTCManager.acceptCall) {
                    const invite = pendingInviteData;
                    hideIncomingCallUI();

                    // Focus conversation with the caller if different
                    if (typeof currentFriend !== 'undefined' && currentFriend !== invite.from_username) {
                        const callerFriend = (window.cachedFriends || []).find(function (f) {
                            return f.username === invite.from_username;
                        });
                        if (callerFriend && typeof startChat === 'function') {
                            startChat(callerFriend);
                        }
                    }

                    WebRTCManager.acceptCall(invite.call_id).catch(function (err) {
                        cleanupCallUI();
                        if (typeof showToast === 'function') {
                            showToast(formatCallError(err), 'error');
                        }
                    });
                }
            });
        }

        const declineIncomingBtn = document.getElementById('btn-incoming-decline');
        if (declineIncomingBtn) {
            declineIncomingBtn.addEventListener('click', function () {
                if (pendingInviteData && typeof WebRTCManager !== 'undefined' && WebRTCManager.rejectCall) {
                    WebRTCManager.rejectCall(pendingInviteData.call_id, 'declined');
                }
                cleanupCallUI();
            });
        }

        // 4. Connected Call Screen Control Buttons
        const muteBtn = document.getElementById('btn-call-mute');
        if (muteBtn) {
            muteBtn.addEventListener('click', function () {
                if (typeof WebRTCManager !== 'undefined' && WebRTCManager.toggleAudio) {
                    WebRTCManager.toggleAudio();
                    updateInCallControlButtons();
                }
            });
        }

        const minMuteBtn = document.getElementById('btn-minimized-mute');
        if (minMuteBtn) {
            minMuteBtn.addEventListener('click', function () {
                if (typeof WebRTCManager !== 'undefined' && WebRTCManager.toggleAudio) {
                    WebRTCManager.toggleAudio();
                    updateInCallControlButtons();
                }
            });
        }

        const camBtn = document.getElementById('btn-call-camera');
        if (camBtn) {
            camBtn.addEventListener('click', function () {
                if (typeof WebRTCManager !== 'undefined' && WebRTCManager.toggleVideo) {
                    WebRTCManager.toggleVideo();
                    updateInCallControlButtons();
                }
            });
        }

        const switchCamBtn = document.getElementById('btn-call-switch-camera');
        if (switchCamBtn) {
            switchCamBtn.addEventListener('click', function () {
                if (typeof WebRTCManager !== 'undefined' && WebRTCManager.switchCamera) {
                    WebRTCManager.switchCamera();
                }
            });
        }

        const endCallBtn = document.getElementById('btn-call-end');
        if (endCallBtn) {
            endCallBtn.addEventListener('click', function () {
                if (typeof WebRTCManager !== 'undefined' && WebRTCManager.endCall) {
                    WebRTCManager.endCall();
                }
                cleanupCallUI();
            });
        }

        const minEndBtn = document.getElementById('btn-minimized-end');
        if (minEndBtn) {
            minEndBtn.addEventListener('click', function () {
                if (typeof WebRTCManager !== 'undefined' && WebRTCManager.endCall) {
                    WebRTCManager.endCall();
                }
                cleanupCallUI();
            });
        }

        const minimizeBtn = document.getElementById('btn-call-minimize');
        if (minimizeBtn) {
            minimizeBtn.addEventListener('click', minimizeCallScreen);
        }

        const expandBtn = document.getElementById('btn-minimized-expand');
        if (expandBtn) {
            expandBtn.addEventListener('click', restoreCallScreen);
        }

        const fullscreenBtn = document.getElementById('btn-call-fullscreen');
        if (fullscreenBtn) {
            fullscreenBtn.addEventListener('click', function () {
                const screen = document.getElementById('call-screen');
                if (!screen) return;
                if (!document.fullscreenElement) {
                    if (screen.requestFullscreen) {
                        screen.requestFullscreen().catch(function () {});
                    }
                } else {
                    if (document.exitFullscreen) {
                        document.exitFullscreen().catch(function () {});
                    }
                }
            });
        }

        const pipBtn = document.getElementById('btn-call-pip');
        if (pipBtn) {
            pipBtn.addEventListener('click', function () {
                const videoEl = document.getElementById('call-remote-video');
                if (!videoEl) return;
                if (document.pictureInPictureElement) {
                    document.exitPictureInPicture().catch(function () {});
                } else if (typeof videoEl.requestPictureInPicture === 'function') {
                    videoEl.requestPictureInPicture().catch(function () {});
                }
            });
        }

        const speakerBtn = document.getElementById('btn-call-speaker');
        if (speakerBtn) {
            speakerBtn.addEventListener('click', async function () {
                if (navigator.mediaDevices && navigator.mediaDevices.selectAudioOutput) {
                    try {
                        const dev = await navigator.mediaDevices.selectAudioOutput();
                        const remoteAudio = document.getElementById('call-remote-audio');
                        const remoteVideo = document.getElementById('call-remote-video');
                        if (remoteAudio && typeof remoteAudio.setSinkId === 'function') {
                            await remoteAudio.setSinkId(dev.deviceId);
                        }
                        if (remoteVideo && typeof remoteVideo.setSinkId === 'function') {
                            await remoteVideo.setSinkId(dev.deviceId);
                        }
                    } catch (err) {
                        // User cancelled audio output picker or browser refused
                    }
                }
            });
        }

        // 5. Video-to-Voice Fallback Confirmation Modal Buttons
        const fallbackVoiceBtn = document.getElementById('btn-fallback-voice');
        if (fallbackVoiceBtn) {
            fallbackVoiceBtn.addEventListener('click', function () {
                hideVoiceFallbackModal();
                if (typeof WebRTCManager !== 'undefined' && WebRTCManager.fallbackToVoice) {
                    WebRTCManager.fallbackToVoice().then(function () {
                        if (typeof showToast === 'function') {
                            showToast('Switched to Voice Call', 'success');
                        }
                    }).catch(function (err) {
                        cleanupCallUI();
                        if (typeof showToast === 'function') {
                            showToast(formatCallError(err), 'error');
                        }
                    });
                }
            });
        }

        const fallbackCancelBtn = document.getElementById('btn-fallback-cancel');
        if (fallbackCancelBtn) {
            fallbackCancelBtn.addEventListener('click', function () {
                hideVoiceFallbackModal();
                if (typeof WebRTCManager !== 'undefined' && WebRTCManager.endCall) {
                    WebRTCManager.endCall();
                }
                cleanupCallUI();
            });
        }
    }

    /**
     * Subscribe to WebRTCManager events to drive Call UI presentation.
     */
    function bindWebRTCManagerEvents() {
        if (typeof WebRTCManager === 'undefined') return;

        // 1. Call state changes
        WebRTCManager.onCallStateChange(function (newState, callId) {
            const state = WebRTCManager.getWebRTCState ? WebRTCManager.getWebRTCState() : null;
            const peer = WebRTCManager.getPeerUsername ? WebRTCManager.getPeerUsername() : null;
            const callType = state ? state.callType : 'voice';

            updateHeaderButtonsState();

            switch (newState) {
                case 'calling':
                    // Outgoing call is in ringing/calling state
                    break;
                case 'connecting':
                    stopRingtone();
                    hideOutgoingCallUI();
                    hideIncomingCallUI();
                    showConnectedCallScreen(callType, peer);
                    updateTimerDisplay('Connecting...');
                    break;
                case 'connected':
                    stopRingtone();
                    startCallTimer();
                    const reconnectingBadge = document.getElementById('call-reconnecting-badge');
                    if (reconnectingBadge) reconnectingBadge.style.display = 'none';
                    break;
                case 'reconnecting':
                    const reconBadge = document.getElementById('call-reconnecting-badge');
                    if (reconBadge) reconBadge.style.display = 'inline-block';
                    break;
                case 'declined':
                    stopRingtone();
                    stopCallTimer();
                    updateTimerDisplay('Declined');
                    setTimeout(cleanupCallUI, 1200);
                    break;
                case 'ended':
                    stopRingtone();
                    stopCallTimer();
                    updateTimerDisplay('Ended');
                    setTimeout(cleanupCallUI, 800);
                    break;
                case 'failed':
                    stopRingtone();
                    stopCallTimer();
                    updateTimerDisplay('Failed');
                    setTimeout(cleanupCallUI, 1400);
                    break;
            }
        });

        // 2. Incoming call invites
        WebRTCManager.onCallInvite(function (inviteData) {
            const state = WebRTCManager.getWebRTCState ? WebRTCManager.getWebRTCState() : null;
            const isCurrentlyInCall = state && (state.callState !== 'idle' && state.callState !== 'ended' && state.callState !== 'failed');

            if (isCurrentlyInCall) {
                // Callee is already in another call: automatically reject with 'busy'
                if (typeof WebRTCManager.rejectCall === 'function') {
                    WebRTCManager.rejectCall(inviteData.call_id, 'busy');
                }
                return;
            }

            showIncomingCallUI(inviteData);
        });

        // 3. Call Rejection (callee declined, busy, or unavailable)
        WebRTCManager.onCallReject(function (callId, reason) {
            stopRingtone();
            hideOutgoingCallUI();
            hideIncomingCallUI();

            const peer = WebRTCManager.getPeerUsername ? WebRTCManager.getPeerUsername() : 'User';
            const info = getContactInfo(peer);

            let msg = 'Call declined';
            if (reason === 'busy') {
                msg = info.displayName + ' is busy on another call';
            } else if (reason === 'unavailable') {
                msg = info.displayName + ' is unavailable';
            }

            if (typeof showToast === 'function') {
                showToast(msg, 'normal');
            }
            cleanupCallUI();
        });

        // 4. Call Cancellation by caller (missed call)
        WebRTCManager.onCallCancel(function (callId) {
            stopRingtone();
            hideIncomingCallUI();

            const peer = WebRTCManager.getPeerUsername ? WebRTCManager.getPeerUsername() : 'Contact';
            const info = getContactInfo(peer);

            if (typeof showToast === 'function') {
                showToast('Missed call from ' + info.displayName, 'normal');
            }
            cleanupCallUI();
        });

        // 5. Call End
        WebRTCManager.onCallEnd(function (callId) {
            stopRingtone();
            stopCallTimer();
            cleanupCallUI();
        });

        // 6. Local MediaStream
        WebRTCManager.onLocalStream(function (stream) {
            const localVideo = document.getElementById('call-local-video');
            if (localVideo) {
                localVideo.srcObject = stream;
            }
            updateInCallControlButtons();
        });

        // 7. Remote MediaStream
        WebRTCManager.onRemoteStream(function (stream) {
            const remoteVideo = document.getElementById('call-remote-video');
            if (remoteVideo) {
                remoteVideo.srcObject = stream;
            }
            const remoteAudio = document.getElementById('call-remote-audio');
            if (remoteAudio) {
                remoteAudio.srcObject = stream;
            }
        });

        // 8. Errors
        WebRTCManager.onCallError(function (errorObj) {
            stopRingtone();
            if (typeof showToast === 'function') {
                showToast(formatCallError(errorObj), 'error');
            }
            cleanupCallUI();
        });

        // 9. Video-to-Voice Fallback
        WebRTCManager.onVoiceFallbackAvailable(function (fallbackObj) {
            showVoiceFallbackModal(fallbackObj);
        });
    }

    // Initialize module on DOM ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', function () {
            initCallUIBindings();
            bindWebRTCManagerEvents();
        });
    } else {
        initCallUIBindings();
        bindWebRTCManagerEvents();
    }

    // Public CallUI interface
    const CallUI = {
        onChatSelected: function (friend) {
            if (friend && friend.username) {
                setHeaderCallButtonsVisible(true);
            } else {
                setHeaderCallButtonsVisible(false);
            }
        },
        onChatDeselected: function () {
            setHeaderCallButtonsVisible(false);
        },
        cleanup: cleanupCallUI
    };

    window.CallUI = CallUI;
})();
