# FlightDeck · B737 Question Bank

Cloudflare Pages web application. White/orange UI, 1,264 imported questions, Practice and 60-minute Mock Exam, resume unfinished tests, history and per-account local statistics.

## Cloudflare Pages deployment

1. Upload this project to a GitHub repository. **Do not publish the default NICO password on a live website without changing it.**
2. In Cloudflare, create a D1 database named `flightdeck-academy-db`.
3. In **Workers & Pages → your Pages project → Settings → Bindings**, add a **D1 database binding** named exactly `DB` and select that database. Configure the production binding (and preview if desired).
4. Apply `migrations/0001_auth.sql` to D1 (via Cloudflare D1 console or `npx wrangler d1 execute flightdeck-academy-db --remote --file=./migrations/0001_auth.sql`). This creates the users and sessions tables and an initial NICO account.
5. Connect the GitHub repository to Cloudflare Pages, use no framework, no build command, and output directory `.`. Deploy.
6. Log in as `NICO` / `123456` **only once** and immediately change your password under Settings. The initial password is public in this package and therefore **unsafe for public use until changed**.

## Authentication and data

User accounts and session tokens are stored server-side in Cloudflare D1. Passwords are salted and PBKDF2-hashed (210,000 SHA-256 iterations). Sessions use Secure, HttpOnly, SameSite=Strict cookies. Password changes invalidate all sessions. Registration requires passwords of at least 10 characters.

**Study statistics and unfinished tests are still saved locally in each browser**, now partitioned by user ID. Signing into another device will not sync study records. Use Export/Import Backup in Settings to transfer them. Old anonymous statistics are not automatically migrated; export the old version first and import the backup into your account.

## Security notes

- The starter credential `NICO / 123456` was explicitly requested but is weak and publicly known. Do not launch a public instance while this password is active.
- For a public multi-user launch, add rate limiting and abuse protection (Cloudflare WAF / Turnstile) to login and registration endpoints.
- All source question answers are from the uploaded quiz material and are not verified against current manuals.
- Do not expose D1 credentials or secrets in client-side code.


## Update 2026-11-11
- Registration requires email, username, password (minimum 8 characters), and matching confirmation.
- Apply BOTH migrations in order, including `migrations/0002_email.sql`. Existing NICO account remains available without an email until a future profile update.
- New cockpit hero image is `assets/cockpit-cover.png`.
- Membership cards are PREVIEW ONLY: no Stripe integration, no payments, and no paywall.
- The NICO / 123456 starter credential must be changed before publicly sharing the app.
