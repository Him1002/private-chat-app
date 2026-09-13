/**
 * WebRTC Core Module for ChatSpic V2 Voice & Video Calling (Phase 2).
 *
 * Responsibilities:
 * - RTCPeerConnection lifecycle management (peer-to-peer 1-to-1 calling)
 * - Local and remote MediaStream handling
 * - ICE server configuration retrieval via authenticated GET /call/config
 * - SDP Offer/Answer negotiation over existing WebSocket signaling channel
 * - Trickle ICE candidate exchange with early candidate queuing
 * - Voice vs Video media constraints
 * - Media device permission handling and structured error taxonomy
 * - Video-to-voice fallback detection (simple check if mic is available)
 * - Connection and ICE state monitoring with reconnecting state mapping
 * - Idempotent resource cleanup on call termination, logout, and page unload
 */

(function () {
    'use strict';

    // Module-level call state
    const CallWebRTCState = {
        callId: null,
        callType: 'voice', // 'voice' | 'video'
        isCaller: false,
        peerConnection: null,
        localStream: null,
        remoteStream: null,
        cachedIceServers: null,
        callState: 'idle', // 'idle' | 'calling' | 'connecting' | 'connected' | 'reconnecting' | 'failed' | 'ended'
        pendingIceCandidates: [],
        lastError: null,
        listeners: {
            stateChange: [],
            localStream: [],
            remoteStream: [],
            error: [],
            voiceFallbackAvailable: [],
            callInvite: []
        }
    };

    /**
     * Browser WebRTC support detection.
     */
    function isWebRTCSupported() {
        return typeof window !== 'undefined' &&
            typeof window.RTCPeerConnection !== 'undefined' &&
            typeof navigator !== 'undefined' &&
            !!navigator.mediaDevices &&
            typeof navigator.mediaDevices.getUserMedia === 'function';
    }

    /**
     * Notify registered stateChange listeners.
     */
    function notifyStateChange(newState) {
        CallWebRTCState.listeners.stateChange.forEach(function (fn) {
            try {
                fn(newState, CallWebRTCState.callId);
            } catch (err) {
                console.error('[WebRTC] stateChange listener error:', err);
            }
        });
    }

    /**
     * Notify registered localStream listeners.
     */
    function notifyLocalStream(stream) {
        CallWebRTCState.listeners.localStream.forEach(function (fn) {
            try {
                fn(stream);
            } catch (err) {
                console.error('[WebRTC] localStream listener error:', err);
            }
        });
    }

    /**
     * Notify registered remoteStream listeners.
     */
    function notifyRemoteStream(stream) {
        CallWebRTCState.listeners.remoteStream.forEach(function (fn) {
            try {
                fn(stream);
            } catch (err) {
                console.error('[WebRTC] remoteStream listener error:', err);
            }
        });
    }

    /**
     * Notify registered error listeners.
     */
    function notifyCallError(errorObj) {
        CallWebRTCState.lastError = errorObj;
        CallWebRTCState.listeners.error.forEach(function (fn) {
            try {
                fn(errorObj);
            } catch (err) {
                console.error('[WebRTC] error listener error:', err);
            }
        });
    }

    /**
     * Notify registered voiceFallbackAvailable listeners.
     */
    function notifyVoiceFallback(fallbackObj) {
        CallWebRTCState.listeners.voiceFallbackAvailable.forEach(function (fn) {
            try {
                fn(fallbackObj);
            } catch (err) {
                console.error('[WebRTC] voiceFallback listener error:', err);
            }
        });
    }

    /**
     * Set the application-level call lifecycle state.
     */
    function setCallLifecycleState(newState) {
        if (CallWebRTCState.callState === newState) return;
        CallWebRTCState.callState = newState;
        notifyStateChange(newState);
    }

    /**
     * Fetch client-safe ICE server configuration from authenticated backend.
     * GET /call/config
     */
    async function fetchIceServers() {
        if (CallWebRTCState.cachedIceServers && CallWebRTCState.cachedIceServers.length > 0) {
            return CallWebRTCState.cachedIceServers;
        }

        const authToken = typeof token !== 'undefined' ? token : null;
        if (!authToken) {
            const err = {
                code: 'CONFIG_FETCH_FAILED',
                message: 'Authentication token missing for call configuration.'
            };
            notifyCallError(err);
            throw err;
        }

        try {
            const res = await fetch('/call/config', {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${authToken}`
                }
            });

            if (!res.ok) {
                throw new Error(`HTTP ${res.status}`);
            }

            const data = await res.json();
            const iceServers = Array.isArray(data.ice_servers) ? data.ice_servers : [];
            CallWebRTCState.cachedIceServers = iceServers;
            return iceServers;
        } catch (rawErr) {
            const callErr = {
                code: 'CONFIG_FETCH_FAILED',
                message: 'Failed to retrieve call network configuration.'
            };
            notifyCallError(callErr);
            throw callErr;
        }
    }

    /**
     * Acquire local user media (audio only or audio + video) with explicit error handling.
     * Implements simple video-to-voice fallback detection if video media fails.
     */
    async function acquireLocalMedia(callType) {
        if (!isWebRTCSupported()) {
            const err = {
                code: 'UNSUPPORTED_BROWSER',
                message: 'Voice and video calling is not supported in this browser.'
            };
            notifyCallError(err);
            throw err;
        }

        const effectiveType = callType === 'video' ? 'video' : 'voice';

        // 1. Voice Call: request microphone only; camera MUST NOT be requested.
        if (effectiveType === 'voice') {
            try {
                const stream = await navigator.mediaDevices.getUserMedia({
                    audio: true,
                    video: false
                });
                CallWebRTCState.localStream = stream;
                notifyLocalStream(stream);
                return stream;
            } catch (rawErr) {
                const mappedErr = mapMediaError(rawErr, 'voice');
                notifyCallError(mappedErr);
                throw mappedErr;
            }
        }

        // 2. Video Call: request microphone + camera.
        try {
            const stream = await navigator.mediaDevices.getUserMedia({
                audio: true,
                video: true
            });
            CallWebRTCState.localStream = stream;
            notifyLocalStream(stream);
            return stream;
        } catch (rawErr) {
            // Video media acquisition failed: check if microphone-only access is available
            let micAvailable = false;
            try {
                const probeStream = await navigator.mediaDevices.getUserMedia({
                    audio: true,
                    video: false
                });
                // Probe succeeded: stop probe tracks immediately
                probeStream.getTracks().forEach(function (t) { t.stop(); });
                micAvailable = true;
            } catch (probeErr) {
                micAvailable = false;
            }

            if (micAvailable) {
                const fallbackErr = {
                    code: 'CAMERA_UNAVAILABLE_MIC_AVAILABLE',
                    canFallbackToVoice: true,
                    message: 'Camera is unavailable or permission was denied, but microphone is available.',
                    originalError: rawErr.name || 'CameraError'
                };
                notifyVoiceFallback(fallbackErr);
                notifyCallError(fallbackErr);
                throw fallbackErr;
            }

            const mappedErr = mapMediaError(rawErr, 'video');
            notifyCallError(mappedErr);
            throw mappedErr;
        }
    }

    /**
     * Map raw DOMException/errors to clean, user-friendly application error objects.
     */
    function mapMediaError(err, type) {
        const name = err ? err.name : '';

        if (name === 'NotAllowedError' || name === 'PermissionDeniedError' || name === 'SecurityError') {
            return {
                code: 'PERMISSION_DENIED',
                message: type === 'video'
                    ? 'Camera or microphone permission was denied.'
                    : 'Microphone permission was denied.'
            };
        }

        if (name === 'NotFoundError' || name === 'DevicesNotFoundError') {
            return {
                code: type === 'video' ? 'NO_CAMERA' : 'NO_MICROPHONE',
                message: type === 'video'
                    ? 'No camera or microphone found on this device.'
                    : 'No microphone found on this device.'
            };
        }

        if (name === 'NotReadableError' || name === 'TrackStartError') {
            return {
                code: 'DEVICE_UNAVAILABLE',
                message: type === 'video'
                    ? 'Camera or microphone is currently in use by another application.'
                    : 'Microphone is currently in use by another application.'
            };
        }

        if (name === 'OverconstrainedError' || name === 'ConstraintNotSatisfiedError') {
            return {
                code: 'MEDIA_CONSTRAINTS_FAILED',
                message: 'Requested audio/video constraints could not be satisfied by device.'
            };
        }

        return {
            code: 'GENERIC_MEDIA_FAILURE',
            message: type === 'video'
                ? 'Unable to access camera or microphone.'
                : 'Unable to access microphone.'
        };
    }

    /**
     * Build RTCPeerConnection with retrieved ICE servers and hook up event listeners.
     */
    function createPeerConnection(iceServers) {
        if (CallWebRTCState.peerConnection) {
            closePeerConnectionOnly();
        }

        const pcConfig = {
            iceServers: Array.isArray(iceServers) ? iceServers : []
        };

        const pc = new RTCPeerConnection(pcConfig);
        CallWebRTCState.peerConnection = pc;

        // 1. Local ICE candidate generation
        pc.onicecandidate = function (event) {
            if (event.candidate && CallWebRTCState.callId) {
                const candidateData = event.candidate.toJSON
                    ? event.candidate.toJSON()
                    : {
                        candidate: event.candidate.candidate,
                        sdpMid: event.candidate.sdpMid,
                        sdpMLineIndex: event.candidate.sdpMLineIndex
                    };

                if (typeof sendSocketPayload === 'function') {
                    sendSocketPayload({
                        type: 'webrtc.ice_candidate',
                        call_id: CallWebRTCState.callId,
                        candidate: candidateData
                    });
                }
            }
        };

        // 2. Remote media track reception
        pc.ontrack = function (event) {
            if (event.streams && event.streams[0]) {
                CallWebRTCState.remoteStream = event.streams[0];
            } else {
                if (!CallWebRTCState.remoteStream) {
                    CallWebRTCState.remoteStream = new MediaStream();
                }
                CallWebRTCState.remoteStream.addTrack(event.track);
            }
            notifyRemoteStream(CallWebRTCState.remoteStream);
        };

        // 3. Connection and ICE state monitoring
        pc.onconnectionstatechange = function () {
            handleConnectionStateChange();
        };

        pc.oniceconnectionstatechange = function () {
            handleConnectionStateChange();
        };

        return pc;
    }

    /**
     * Map RTCPeerConnection connectionState & iceConnectionState into call lifecycle.
     */
    function handleConnectionStateChange() {
        const pc = CallWebRTCState.peerConnection;
        if (!pc) return;

        const connState = pc.connectionState;
        const iceState = pc.iceConnectionState;

        if (connState === 'connected' || iceState === 'connected' || iceState === 'completed') {
            setCallLifecycleState('connected');
        } else if (connState === 'disconnected' || iceState === 'disconnected') {
            // Temporary connectivity loss does NOT immediately destroy peer connection
            setCallLifecycleState('reconnecting');
        } else if (connState === 'failed' || iceState === 'failed') {
            setCallLifecycleState('failed');
        } else if (connState === 'closed' || iceState === 'closed') {
            setCallLifecycleState('ended');
        }
    }

    /**
     * Safely add queued ICE candidates once remote description is active.
     */
    async function flushPendingIceCandidates() {
        const pc = CallWebRTCState.peerConnection;
        if (!pc || !pc.remoteDescription || !pc.remoteDescription.type) return;

        const queued = CallWebRTCState.pendingIceCandidates.slice();
        CallWebRTCState.pendingIceCandidates = [];

        for (let i = 0; i < queued.length; i++) {
            const cand = queued[i];
            try {
                await pc.addIceCandidate(new RTCIceCandidate(cand));
            } catch (err) {
                console.warn('[WebRTC] Error adding queued ICE candidate:', err);
            }
        }
    }

    /**
     * Start WebRTC offer flow for outgoing call after call.accept is received.
     * The caller is always the initial offerer.
     */
    async function startCallerFlow(callId, callType) {
        try {
            CallWebRTCState.callId = callId;
            CallWebRTCState.callType = callType || CallWebRTCState.callType || 'voice';
            CallWebRTCState.isCaller = true;
            setCallLifecycleState('connecting');

            // 1. Acquire required local media if not already acquired
            let stream = CallWebRTCState.localStream;
            if (!stream) {
                stream = await acquireLocalMedia(CallWebRTCState.callType);
            }

            // 2. Fetch ICE servers
            const iceServers = await fetchIceServers();

            // 3. Create RTCPeerConnection
            const pc = createPeerConnection(iceServers);

            // 4. Add local tracks to peer connection
            stream.getTracks().forEach(function (track) {
                pc.addTrack(track, stream);
            });

            // 5. Create SDP offer
            const offer = await pc.createOffer();

            // 6. Set local description
            await pc.setLocalDescription(offer);

            // 7. Send offer through existing WebSocket
            if (typeof sendSocketPayload === 'function') {
                sendSocketPayload({
                    type: 'webrtc.offer',
                    call_id: callId,
                    sdp: pc.localDescription.sdp
                });
            }
        } catch (err) {
            console.error('[WebRTC] Caller flow failed:', err);
            setCallLifecycleState('failed');
            throw err;
        }
    }

    /**
     * Callee flow: handles incoming webrtc.offer.
     */
    async function handleWebRTCOffer(callId, sdp) {
        try {
            // If already on a different call, reject or ignore
            if (CallWebRTCState.callId && CallWebRTCState.callId !== callId) {
                console.warn('[WebRTC] Offer call_id mismatch. Current:', CallWebRTCState.callId, 'Received:', callId);
                return;
            }

            CallWebRTCState.callId = callId;
            CallWebRTCState.isCaller = false;
            setCallLifecycleState('connecting');

            // 1. Acquire required local media if not already acquired
            let stream = CallWebRTCState.localStream;
            if (!stream) {
                stream = await acquireLocalMedia(CallWebRTCState.callType);
            }

            // 2. Fetch ICE servers
            const iceServers = await fetchIceServers();

            // 3. Create RTCPeerConnection
            const pc = createPeerConnection(iceServers);

            // 4. Set remote offer description
            await pc.setRemoteDescription(new RTCSessionDescription({
                type: 'offer',
                sdp: sdp
            }));

            // 5. Process any candidates that arrived before remote description
            await flushPendingIceCandidates();

            // 6. Add local media tracks
            const currentSenders = pc.getSenders();
            stream.getTracks().forEach(function (track) {
                const alreadyAdded = currentSenders.some(function (sender) {
                    return sender.track === track;
                });
                if (!alreadyAdded) {
                    pc.addTrack(track, stream);
                }
            });

            // 7. Create SDP answer
            const answer = await pc.createAnswer();

            // 8. Set local description
            await pc.setLocalDescription(answer);

            // 9. Send answer through existing WebSocket
            if (typeof sendSocketPayload === 'function') {
                sendSocketPayload({
                    type: 'webrtc.answer',
                    call_id: callId,
                    sdp: pc.localDescription.sdp
                });
            }
        } catch (err) {
            console.error('[WebRTC] Callee offer handling failed:', err);
            setCallLifecycleState('failed');
            throw err;
        }
    }

    /**
     * Caller flow: handles incoming webrtc.answer.
     */
    async function handleWebRTCAnswer(callId, sdp) {
        try {
            if (CallWebRTCState.callId && CallWebRTCState.callId !== callId) {
                console.warn('[WebRTC] Answer call_id mismatch:', callId);
                return;
            }

            const pc = CallWebRTCState.peerConnection;
            if (!pc) {
                console.warn('[WebRTC] Received answer without active RTCPeerConnection');
                return;
            }

            await pc.setRemoteDescription(new RTCSessionDescription({
                type: 'answer',
                sdp: sdp
            }));

            // Process any candidates queued while waiting for answer
            await flushPendingIceCandidates();
        } catch (err) {
            console.error('[WebRTC] Answer handling failed:', err);
            setCallLifecycleState('failed');
            throw err;
        }
    }

    /**
     * Handles incoming webrtc.ice_candidate.
     * Safely queues candidates arriving before remote description is set.
     */
    async function handleWebRTCICECandidate(callId, candidate) {
        if (!candidate) return;

        if (CallWebRTCState.callId && CallWebRTCState.callId !== callId) {
            return;
        }

        const pc = CallWebRTCState.peerConnection;

        // If peer connection or remote description not ready yet, queue the candidate
        if (!pc || !pc.remoteDescription || !pc.remoteDescription.type) {
            CallWebRTCState.pendingIceCandidates.push(candidate);
            return;
        }

        try {
            await pc.addIceCandidate(new RTCIceCandidate(candidate));
        } catch (err) {
            console.warn('[WebRTC] Failed to add remote ICE candidate:', err);
        }
    }

    /**
     * Trigger ICE restart for peer connection recovery (used by caller).
     */
    async function restartIce() {
        const pc = CallWebRTCState.peerConnection;
        if (!pc || !CallWebRTCState.callId || !CallWebRTCState.isCaller) {
            return false;
        }

        try {
            setCallLifecycleState('reconnecting');
            const offer = await pc.createOffer({ iceRestart: true });
            await pc.setLocalDescription(offer);

            if (typeof sendSocketPayload === 'function') {
                sendSocketPayload({
                    type: 'webrtc.offer',
                    call_id: CallWebRTCState.callId,
                    sdp: pc.localDescription.sdp
                });
            }
            return true;
        } catch (err) {
            console.error('[WebRTC] ICE restart failed:', err);
            return false;
        }
    }

    /**
     * Closes the RTCPeerConnection instance only without clearing streams.
     */
    function closePeerConnectionOnly() {
        if (CallWebRTCState.peerConnection) {
            const pc = CallWebRTCState.peerConnection;
            pc.onicecandidate = null;
            pc.ontrack = null;
            pc.onconnectionstatechange = null;
            pc.oniceconnectionstatechange = null;
            try {
                pc.close();
            } catch (err) {
                // Ignore close errors
            }
            CallWebRTCState.peerConnection = null;
        }
    }

    /**
     * Single reliable, idempotent cleanup path.
     * Releases local media tracks, clears remote media references,
     * closes RTCPeerConnection, and resets state.
     *
     * Constraint 1: Does NOT send call.end over WebSocket during page unload.
     */
    function cleanupWebRTCCall() {
        // Stop all local media tracks
        if (CallWebRTCState.localStream) {
            try {
                CallWebRTCState.localStream.getTracks().forEach(function (track) {
                    track.stop();
                });
            } catch (err) {
                // Ignore track stop errors
            }
            CallWebRTCState.localStream = null;
        }

        // Clear remote media stream reference
        if (CallWebRTCState.remoteStream) {
            try {
                CallWebRTCState.remoteStream.getTracks().forEach(function (track) {
                    track.stop();
                });
            } catch (err) {
                // Ignore track stop errors
            }
            CallWebRTCState.remoteStream = null;
        }

        // Close and detach RTCPeerConnection
        closePeerConnectionOnly();

        // Reset state
        CallWebRTCState.callId = null;
        CallWebRTCState.callType = 'voice';
        CallWebRTCState.isCaller = false;
        CallWebRTCState.pendingIceCandidates = [];
        CallWebRTCState.lastError = null;

        setCallLifecycleState('ended');
    }

    /**
     * Signaling event handlers dispatched from websocket.js.
     */
    function handleCallAccept(callId) {
        // Callee accepted our outgoing call; initiate WebRTC caller flow
        startCallerFlow(callId, CallWebRTCState.callType).catch(function (err) {
            console.error('[WebRTC] startCallerFlow error after accept:', err);
        });
    }

    function handleCallReject(callId, reason) {
        cleanupWebRTCCall();
    }

    function handleCallCancel(callId) {
        cleanupWebRTCCall();
    }

    function handleCallEnd(callId) {
        cleanupWebRTCCall();
    }

    function handleCallInvite(inviteData) {
        CallWebRTCState.listeners.callInvite.forEach(function (fn) {
            try {
                fn(inviteData);
            } catch (err) {
                console.error('[WebRTC] callInvite listener error:', err);
            }
        });
    }

    /**
     * Prime or update active call context (for Phase 3 call initialization).
     */
    function setCallContext(callId, callType, isCaller) {
        CallWebRTCState.callId = callId;
        CallWebRTCState.callType = callType === 'video' ? 'video' : 'voice';
        CallWebRTCState.isCaller = !!isCaller;
    }

    /**
     * Event listener registration helpers.
     */
    function onCallStateChange(callback) {
        if (typeof callback === 'function') {
            CallWebRTCState.listeners.stateChange.push(callback);
        }
    }

    function onLocalStream(callback) {
        if (typeof callback === 'function') {
            CallWebRTCState.listeners.localStream.push(callback);
        }
    }

    function onRemoteStream(callback) {
        if (typeof callback === 'function') {
            CallWebRTCState.listeners.remoteStream.push(callback);
        }
    }

    function onCallError(callback) {
        if (typeof callback === 'function') {
            CallWebRTCState.listeners.error.push(callback);
        }
    }

    function onVoiceFallbackAvailable(callback) {
        if (typeof callback === 'function') {
            CallWebRTCState.listeners.voiceFallbackAvailable.push(callback);
        }
    }

    function onCallInvite(callback) {
        if (typeof callback === 'function') {
            CallWebRTCState.listeners.callInvite.push(callback);
        }
    }

    // Constraint 1: Page unload cleanup releases only local browser/media resources.
    // Server-side WebSocket disconnect handles call termination authoritative cleanup.
    if (typeof window !== 'undefined') {
        window.addEventListener('beforeunload', function () {
            cleanupWebRTCCall();
        });
        window.addEventListener('pagehide', function () {
            cleanupWebRTCCall();
        });
    }

    // Public API object
    const WebRTCManager = {
        isWebRTCSupported: isWebRTCSupported,
        fetchIceServers: fetchIceServers,
        acquireLocalMedia: acquireLocalMedia,
        startCallerFlow: startCallerFlow,
        handleWebRTCOffer: handleWebRTCOffer,
        handleWebRTCAnswer: handleWebRTCAnswer,
        handleWebRTCICECandidate: handleWebRTCICECandidate,
        restartIce: restartIce,
        cleanupWebRTCCall: cleanupWebRTCCall,
        handleCallInvite: handleCallInvite,
        handleCallAccept: handleCallAccept,
        handleCallReject: handleCallReject,
        handleCallCancel: handleCallCancel,
        handleCallEnd: handleCallEnd,
        setCallContext: setCallContext,
        getLocalStream: function () { return CallWebRTCState.localStream; },
        getRemoteStream: function () { return CallWebRTCState.remoteStream; },
        getWebRTCState: function () {
            return {
                callId: CallWebRTCState.callId,
                callType: CallWebRTCState.callType,
                isCaller: CallWebRTCState.isCaller,
                callState: CallWebRTCState.callState,
                lastError: CallWebRTCState.lastError
            };
        },
        onCallStateChange: onCallStateChange,
        onLocalStream: onLocalStream,
        onRemoteStream: onRemoteStream,
        onCallError: onCallError,
        onVoiceFallbackAvailable: onVoiceFallbackAvailable,
        onCallInvite: onCallInvite
    };

    // Expose to window for application-wide access
    window.WebRTCManager = WebRTCManager;
    window.cleanupWebRTCCall = cleanupWebRTCCall;
    window.startWebRTCCall = startCallerFlow;
    window.getLocalStream = WebRTCManager.getLocalStream;
    window.getRemoteStream = WebRTCManager.getRemoteStream;
})();
