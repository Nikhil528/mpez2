# MPEB Final Fixed

Admin is now protected by a real login page/session. Direct /admin.html is not exposed.

Render env vars: DATABASE_URL, ADMIN_USER, ADMIN_PASSWORD, LICENSE_SECRET, RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET.

Open /admin -> login -> generate annual/lifetime/trial keys.
Annual supports Cash/Online payment mode.
