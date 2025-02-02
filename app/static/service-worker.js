const CACHE_NAME = "food-dist-cache-v2";
const OFFLINE_URL = '/offline.html';
const urlsToCache = [
    "/", 
    "/customers", 
    "/add_customer", 
    "/search_customer", 
    "/dashboard", 
    "/static/icons/web-app-manifest-144x144.png", 
    "/static/icons/web-app-manifest-192x192.png", 
    "/static/icons/web-app-manifest-512x512.png"
];

// Install event: Cache static resources
self.addEventListener("install", (event) => {
    console.log("[Service Worker] Install event triggered.");
    event.waitUntil(
        caches.open(CACHE_NAME)
            .then((cache) => {
                console.log("[Service Worker] Caching static URLs:", urlsToCache);
                return cache.addAll(urlsToCache);
            })
            .catch((error) => console.error("[Service Worker] Caching failed during install:", error))
    );
});

// Fetch event: Serve from cache or fetch from network
self.addEventListener("fetch", (event) => {
    console.log(`[Service Worker] Fetch event for: ${event.request.url}`);
    event.respondWith(
        caches.match(event.request).then((cachedResponse) => {
            if (cachedResponse) {
                console.log(`[Service Worker] Serving from cache: ${event.request.url}`);
                return cachedResponse;
            }

            // Handle dynamic routes like /add_order/<customer_id> or /orders/<customer_id>
            const url = new URL(event.request.url);
            if (url.pathname.startsWith("/add_order/") || url.pathname.startsWith("/orders/")) {
                console.log(`[Service Worker] Fetching dynamic route: ${event.request.url}`);
                return fetch(event.request)
                    .then((networkResponse) => {
                        return caches.open(CACHE_NAME).then((cache) => {
                            cache.put(event.request, networkResponse.clone());
                            console.log(`[Service Worker] Cached dynamic route: ${event.request.url}`);
                            return networkResponse;
                        });
                    })
                    .catch(() => caches.match("/")); // Fallback to homepage for dynamic route errors
            }

            // Default behavior for all other requests
            console.log(`[Service Worker] Fetching from network: ${event.request.url}`);
            return fetch(event.request)
                .then((networkResponse) => {
                    return caches.open(CACHE_NAME).then((cache) => {
                        if (event.request.method === "GET") {
                            cache.put(event.request, networkResponse.clone());
                            console.log(`[Service Worker] Cached new resource: ${event.request.url}`);
                        }
                        return networkResponse;
                    });
                })
                .catch(() => {
                    if (event.request.mode === "navigate") {
                        return caches.match("/"); // Fallback for navigation requests
                    }
                    console.error(`[Service Worker] Fetch failed: ${event.request.url}`);
                });
        })
    );
});

// Activate event: Clean up old caches
self.addEventListener("activate", (event) => {
    console.log("[Service Worker] Activate event triggered.");
    event.waitUntil(
        caches.keys().then((cacheNames) => {
            return Promise.all(
                cacheNames.map((cacheName) => {
                    if (cacheName !== CACHE_NAME) {
                        console.log(`[Service Worker] Deleting old cache: ${cacheName}`);
                        return caches.delete(cacheName);
                    }
                })
            );
        })
    );
});