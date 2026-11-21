// ChatSpic Web Push Service Worker (V2 Task R7)
// Dedicated exclusively to Web Push notifications. Does not cache unrelated assets.

self.addEventListener('install', (event) => {
    self.skipWaiting();
});

self.addEventListener('activate', (event) => {
    event.waitUntil(self.clients.claim());
});

self.addEventListener('push', (event) => {
    if (!event.data) {
        return;
    }

    let payload;
    try {
        payload = event.data.json();
    } catch (e) {
        return;
    }

    const title = payload.title || 'ChatSpic';
    const body = payload.body || '';
    const conversation = (payload.data && payload.data.conversation) ? payload.data.conversation : null;
    const tag = payload.tag || (conversation ? `chat-${conversation}` : 'chat-default');

    event.waitUntil((async () => {
        const options = {
            body: body,
            icon: payload.icon || '/static/favicon.ico',
            badge: payload.badge || '/static/favicon.ico',
            tag: tag,
            renotify: true,
            data: {
                conversation: conversation,
                url: (payload.data && payload.data.url) ? payload.data.url : '/'
            }
        };

        return self.registration.showNotification(title, options);
    })());
});

self.addEventListener('notificationclick', (event) => {
    event.notification.close();

    const notifData = event.notification.data || {};
    const conversation = notifData.conversation || null;
    const targetUrl = notifData.url || '/';

    event.waitUntil((async () => {
        const clientList = await self.clients.matchAll({
            type: 'window',
            includeUncontrolled: true
        });

        // Search for an existing window on the same origin
        let existingClient = null;
        for (const client of clientList) {
            try {
                const clientUrl = new URL(client.url);
                if (clientUrl.origin === self.location.origin) {
                    existingClient = client;
                    break;
                }
            } catch (e) {
                // Ignore URL parse error
            }
        }

        if (existingClient) {
            await existingClient.focus();
            if (conversation) {
                existingClient.postMessage({
                    type: 'NAVIGATE_CONVERSATION',
                    conversation: conversation
                });
            }
        } else {
            // Open a new window. Safe conversation identifier only (no secrets/tokens in URL).
            const destination = conversation
                ? `${targetUrl}?chat=${encodeURIComponent(conversation)}`
                : targetUrl;
            await self.clients.openWindow(destination);
        }
    })());
});
