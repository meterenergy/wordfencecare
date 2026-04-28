const express    = require("express");
const bodyParser = require("body-parser");
const fs         = require("fs");
const path       = require("path");
const archiver   = require("archiver");
const { v4: uuidv4 } = require("uuid");
const https      = require("https");

const app = express();
app.use(bodyParser.json());
app.use(express.static("public"));

const PORT           = process.env.PORT || 3000;
const PAYSTACK_SECRET = process.env.PAYSTACK_SECRET_KEY || "sk_test_REPLACE_ME";
const BASE_URL       = process.env.BASE_URL || `http://localhost:${PORT}`;
const PRICE_CENTS    = 59000; // $590.00 USD in cents (Paystack uses smallest unit)

// Ensure required folders exist on startup
["generated", "pending"].forEach(dir => {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

// ────────────────────────────────────────────────
// PAGE ROUTES
// ────────────────────────────────────────────────

// Landing page — wordfencecare.com/
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "landing.html"));
});

// Plugin generator/payment form — wordfencecare.com/generate
app.get("/generate", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "generate.html"));
});

// ────────────────────────────────────────────────
// PAYSTACK: STEP 1 — Initialize payment
// Called when user clicks "Pay & Generate Plugin"
// ────────────────────────────────────────────────
app.post("/initiate-payment", (req, res) => {
  const { email, options } = req.body;

  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: "A valid email address is required." });
  }

  const hasOption = options && Object.values(options).some(Boolean);
  if (!hasOption) {
    return res.status(400).json({ error: "Please select at least one security feature." });
  }

  // Store selected options keyed by a unique reference ID
  const ref = uuidv4();
  fs.writeFileSync(
    path.join("pending", `${ref}.json`),
    JSON.stringify({ email, options, createdAt: Date.now() })
  );

  // Build Paystack initialize request body
  const body = JSON.stringify({
    email,
    amount: PRICE_CENTS,
    reference: ref,
    callback_url: `${BASE_URL}/payment-success?ref=${ref}`,
    currency: "USD",
    metadata: {
      custom_fields: [
        {
          display_name: "Product",
          variable_name: "product",
          value: "WordfenceCare Security Plugin"
        }
      ]
    }
  });

  const options_ = {
    hostname: "api.paystack.co",
    port: 443,
    path: "/transaction/initialize",
    method: "POST",
    headers: {
      Authorization: `Bearer ${PAYSTACK_SECRET}`,
      "Content-Type": "application/json",
      "Content-Length": Buffer.byteLength(body)
    }
  };

  const psReq = https.request(options_, psRes => {
    let data = "";
    psRes.on("data", chunk => { data += chunk; });
    psRes.on("end", () => {
      try {
        const parsed = JSON.parse(data);
        if (parsed.status && parsed.data?.authorization_url) {
          res.json({ payment_url: parsed.data.authorization_url });
        } else {
          console.error("Paystack init error:", parsed);
          res.status(500).json({ error: "Payment provider error. Please try again." });
        }
      } catch (e) {
        console.error("Paystack parse error:", e);
        res.status(500).json({ error: "Unexpected error. Please try again." });
      }
    });
  });

  psReq.on("error", e => {
    console.error("Paystack connection error:", e);
    res.status(500).json({ error: "Could not reach payment provider. Check your connection." });
  });

  psReq.write(body);
  psReq.end();
});

// ────────────────────────────────────────────────
// PAYSTACK: STEP 2 — Verify payment & generate plugin
// Paystack redirects the user here after checkout
// ────────────────────────────────────────────────
app.get("/payment-success", (req, res) => {
  const { ref } = req.query;
  if (!ref) return res.status(400).send(errorPage("Missing payment reference."));

  // Server-side verification — never trust frontend alone
  const verifyOpts = {
    hostname: "api.paystack.co",
    port: 443,
    path: `/transaction/verify/${encodeURIComponent(ref)}`,
    method: "GET",
    headers: { Authorization: `Bearer ${PAYSTACK_SECRET}` }
  };

  const vReq = https.request(verifyOpts, vRes => {
    let data = "";
    vRes.on("data", chunk => { data += chunk; });
    vRes.on("end", () => {
      try {
        const parsed = JSON.parse(data);

        if (!parsed.status || parsed.data?.status !== "success") {
          console.error("Payment not successful:", parsed);
          return res.status(402).send(errorPage(
            "Payment was not completed. Please try again.",
            "← Go Back",
            "/generate"
          ));
        }

        // ── Payment confirmed ─────────────────────
        const pendingFile = path.join("pending", `${ref}.json`);
        if (!fs.existsSync(pendingFile)) {
          return res.status(404).send(errorPage(
            "Session expired. Please complete a new purchase.",
            "← Try Again",
            "/generate"
          ));
        }

        const { options } = JSON.parse(fs.readFileSync(pendingFile, "utf8"));
        fs.unlinkSync(pendingFile); // clean up pending session

        // ── Generate the plugin ───────────────────
        const id     = uuidv4();
        const folder = path.join("generated", id);
        fs.mkdirSync(folder, { recursive: true });

        let plugin = `<?php
/*
Plugin Name:  WordfenceCare Security Plugin
Plugin URI:   https://wordfencecare.com
Description:  Custom WordPress security hardening generated by WordfenceCare.
Version:      1.0.0
Author:       WordfenceCare
Author URI:   https://wordfencecare.com
License:      GPL v2 or later
*/

if (!defined('ABSPATH')) exit; // No direct access

`;

        if (options.xmlrpc) {
          plugin += `// ── Disable XML-RPC ──────────────────────────────────────
// XML-RPC is a common brute-force and DDoS attack vector
add_filter('xmlrpc_enabled', '__return_false');

`;
        }

        if (options.hideVersion) {
          plugin += `// ── Hide WordPress Version ───────────────────────────────
// Prevents bots from fingerprinting your WP version
remove_action('wp_head', 'wp_generator');

`;
        }

        if (options.loginLimit) {
          plugin += `// ── Limit Login Attempts ─────────────────────────────────
// Locks out IPs after 5 failed attempts for 15 minutes
add_filter('authenticate', function($user, $username, $password) {
  $ip  = $_SERVER['REMOTE_ADDR'];
  $key = 'wfc_fails_' . md5($ip);
  if ((int) get_transient($key) >= 5) {
    return new WP_Error('too_many_attempts', __('Too many failed logins. Try again in 15 minutes.'));
  }
  return $user;
}, 30, 3);

add_action('wp_login_failed', function() {
  $ip  = $_SERVER['REMOTE_ADDR'];
  $key = 'wfc_fails_' . md5($ip);
  set_transient($key, (int) get_transient($key) + 1, 15 * MINUTE_IN_SECONDS);
});

`;
        }

        if (options.disableFileEdit) {
          plugin += `// ── Disable Theme & Plugin File Editor ───────────────────
// Prevents hackers from editing files via WP admin
if (!defined('DISALLOW_FILE_EDIT')) define('DISALLOW_FILE_EDIT', true);

`;
        }

        if (options.removeRsdLink) {
          plugin += `// ── Remove RSD Link from <head> ──────────────────────────
// Removes WordPress fingerprinting meta from page source
remove_action('wp_head', 'rsd_link');
remove_action('wp_head', 'wlwmanifest_link');

`;
        }

        if (options.disableEmbed) {
          plugin += `// ── Disable oEmbed / WP Embeds ───────────────────────────
// Prevents your site being used to DDoS others via embeds
add_action('init', function() {
  remove_action('rest_api_init', 'wp_oembed_register_route');
  add_filter('embed_oembed_discover', '__return_false');
  remove_filter('oembed_dataparse', 'wp_filter_oembed_result');
  remove_action('wp_head', 'wp_oembed_add_discovery_links');
  remove_action('wp_head', 'wp_oembed_add_host_js');
});

`;
        }

        if (options.secureHeaders) {
          plugin += `// ── Add Security Headers ─────────────────────────────────
// Adds X-Frame-Options, X-Content-Type-Options, etc.
add_action('send_headers', function() {
  header('X-Frame-Options: SAMEORIGIN');
  header('X-Content-Type-Options: nosniff');
  header('X-XSS-Protection: 1; mode=block');
  header('Referrer-Policy: strict-origin-when-cross-origin');
  header('Permissions-Policy: geolocation=(), microphone=(), camera=()');
});

`;
        }

        fs.writeFileSync(path.join(folder, "wordfencecare-security.php"), plugin);

        // ── Zip the plugin folder ─────────────────
        const zipPath = path.join("generated", `${id}.zip`);
        const output  = fs.createWriteStream(zipPath);
        const archive = archiver("zip", { zlib: { level: 9 } });

        archive.on("error", err => {
          console.error("Archive error:", err);
          res.status(500).send(errorPage("Failed to create plugin ZIP. Please contact support."));
        });

        archive.pipe(output);
        archive.directory(folder, "wordfencecare-security");
        archive.finalize();

        output.on("close", () => {
          res.redirect(`/download-page?id=${id}`);
        });

      } catch (e) {
        console.error("Verify parse error:", e);
        res.status(500).send(errorPage("Server error during verification."));
      }
    });
  });

  vReq.on("error", e => {
    console.error("Verify request error:", e);
    res.status(500).send(errorPage("Could not verify payment. Please contact support."));
  });

  vReq.end();
});

// ────────────────────────────────────────────────
// STEP 3 — Download page (after successful payment)
// ────────────────────────────────────────────────
app.get("/download-page", (req, res) => {
  const { id } = req.query;
  const zipPath = id ? path.join("generated", `${id}.zip`) : null;

  if (!id || !fs.existsSync(zipPath)) {
    return res.status(404).send(errorPage("Plugin not found or link has expired."));
  }

  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>Your Plugin is Ready – WordfenceCare</title>
<link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;600;700;800&display=swap" rel="stylesheet"/>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Plus Jakarta Sans', sans-serif; background: #f9fafb; min-height: 100vh; display: flex; flex-direction: column; align-items: center; justify-content: center; padding: 2rem; }
  .card { background: #fff; border-radius: 16px; border: 1px solid #e5e7eb; padding: 3rem 2.5rem; text-align: center; max-width: 480px; width: 100%; box-shadow: 0 8px 32px rgba(0,0,0,0.07); }
  .check { width: 64px; height: 64px; background: #dcfce7; border-radius: 50%; display: flex; align-items: center; justify-content: center; margin: 0 auto 1.5rem; }
  .check svg { width: 32px; height: 32px; stroke: #16a34a; fill: none; stroke-width: 2.5; stroke-linecap: round; stroke-linejoin: round; }
  h1 { font-size: 1.6rem; font-weight: 800; color: #111827; margin-bottom: 0.6rem; }
  p { color: #6b7280; font-size: 0.95rem; margin-bottom: 2rem; line-height: 1.7; }
  .btn { display: inline-block; background: #2f6feb; color: #fff; padding: 14px 32px; border-radius: 9px; text-decoration: none; font-weight: 700; font-size: 1rem; transition: background 0.2s; }
  .btn:hover { background: #1a5fd8; }
  .install-note { font-size: 0.8rem; color: #9ca3af; margin-top: 1.5rem; line-height: 1.6; }
  .install-note code { background: #f3f4f6; padding: 2px 6px; border-radius: 4px; font-size: 0.78rem; }
  .back { display: block; margin-top: 1rem; font-size: 0.82rem; color: #9ca3af; text-decoration: none; }
  .back:hover { color: #2f6feb; }
</style>
</head>
<body>
  <div class="card">
    <div class="check">
      <svg viewBox="0 0 24 24"><polyline points="20,6 9,17 4,12"/></svg>
    </div>
    <h1>Your Plugin is Ready!</h1>
    <p>Payment confirmed. Your custom WordPress security plugin has been generated and is ready to install on your site.</p>
    <a href="/download/${id}" class="btn">⬇ Download Plugin ZIP</a>
    <p class="install-note">
      To install: go to your WordPress admin →<br>
      <code>Plugins → Add New → Upload Plugin</code><br>
      then upload this ZIP file and click Activate.
    </p>
    <a href="/" class="back">← Back to WordfenceCare</a>
  </div>
</body>
</html>`);
});

// ────────────────────────────────────────────────
// STEP 4 — Serve the ZIP file for download
// ────────────────────────────────────────────────
app.get("/download/:id", (req, res) => {
  const zipPath = path.join("generated", `${req.params.id}.zip`);
  if (!fs.existsSync(zipPath)) {
    return res.status(404).send(errorPage("File not found or download link has expired."));
  }
  res.download(zipPath, "wordfencecare-security-plugin.zip");
});

// ────────────────────────────────────────────────
// HELPERS
// ────────────────────────────────────────────────
function errorPage(message, btnText = "← Go Back", btnHref = "/") {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<title>Error – WordfenceCare</title>
<link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;600;700&display=swap" rel="stylesheet"/>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Plus Jakarta Sans', sans-serif; background: #f9fafb; min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 2rem; }
  .card { background: #fff; border-radius: 16px; border: 1px solid #e5e7eb; padding: 2.5rem; text-align: center; max-width: 440px; width: 100%; }
  .icon { font-size: 2.5rem; margin-bottom: 1rem; }
  h2 { font-size: 1.3rem; font-weight: 700; color: #111827; margin-bottom: 0.75rem; }
  p { color: #6b7280; font-size: 0.92rem; margin-bottom: 1.75rem; line-height: 1.7; }
  a { display: inline-block; color: #2f6feb; font-weight: 600; text-decoration: none; font-size: 0.95rem; }
</style>
</head>
<body>
  <div class="card">
    <div class="icon">⚠️</div>
    <h2>Something went wrong</h2>
    <p>${message}</p>
    <a href="${btnHref}">${btnText}</a>
  </div>
</body>
</html>`;
}

// ────────────────────────────────────────────────
// START
// ────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`WordfenceCare server running → http://localhost:${PORT}`);
});
