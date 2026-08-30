# MPEB Final All-in-One (Render)

Includes:
- Render Free deployment files
- PostgreSQL schema + migrations
- ₹499 Razorpay lifetime license
- 1-day trial key
- One key → one browser/system binding through server-side activation
- License activation and validation
- Admin login
- Generate lifetime/trial keys
- Generated/old key list
- Enable/disable
- Device reset
- Key delete
- Razorpay payment verification
- Payment history
- Existing MPEB receipt bookmarklet
- Dynamic Channel ID from MPEB page
- Dynamic Payment Mode (Full Payment / Advance Payment / Split Payment)
- No hard-coded K20240805807035
- No redirect or refresh of MPEB page

## Render environment variables
DATABASE_URL
ADMIN_USER
ADMIN_PASSWORD
LICENSE_SECRET
RAZORPAY_KEY_ID
RAZORPAY_KEY_SECRET

## URLs
/health
/license
/admin
/receipt.js

## Deploy
Upload this folder to GitHub and create a Render Blueprint using render.yaml, then set the required secret environment variables.


## Annual key payment modes
Admin key generator now supports Annual (1 Year), with Cash or Online payment mode. Cash is manual/admin-generated; Online is for recorded online sales. Razorpay checkout remains available for the ₹499 purchase flow.
