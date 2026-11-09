# Bot Defense Scanner (proof of concept)

The server-side half of the `bot-defense-check` Claude skill. It takes one URL and returns raw JSON evidence about the site's edge and bot protection. It renders nothing; the skill turns the payload into the AE brief, so all output stays in Claude.

## What it adds over the browser scan

- **Bot vs. browser comparison:** fetches the homepage three ways (browser-like, plain client, labeled bot) and reports whether the site treats them differently
- **Datacenter view:** runs from cloud IPs, the way most scrapers do
- **DNS and network owner:** CNAME chain and ASN through DNS-over-HTTPS
- **Hidden cookies:** reads `Set-Cookie` names, including HttpOnly bot cookies such as `__cf_bm`
- **Redirect hops:** records each one
- **Platform tag inputs:** Drupal major version or non-Drupal CMS

## Guardrails built in

- **Gated:** every call needs the `X-Scan-Key` header. With no key configured, it fails closed.
- **Polite:** four requests to the target per scan (three homepage fetches and robots.txt), with no crawling, forms, or retries.
- **Optional target allowlist:** `ALLOWED_DOMAINS` is off by default (all public domains allowed). When populated, only those domains can be scanned.
- **SSRF guard:** refuses any host or redirect that resolves to a private, loopback, or reserved address. This applies whether or not the allowlist is on.
- **Clean errors:** returns stable codes (`domain_not_found`, `no_response`, `blocked_target`, `redirect_loop`, `invalid_url`, `scan_failed`) that the skill maps to plain-language messages. It never returns a stack trace.
- **No storage:** nothing is logged or saved beyond Vercel's default request logs.

## Deploy (about 10 minutes)

1. Create a GitHub repo with these files: `api/scan.py`, `requirements.txt`, `vercel.json`.
2. In Vercel, select **Add New > Project** and import the repo. No framework preset is needed.
3. Under **Settings > Environment Variables**, add `SCAN_KEY` as a long random string, for example from `openssl rand -hex 32`.
   - Optional `ALLOWED_DOMAINS`: leave it unset to allow scanning any public domain. Populate it with comma-separated domains, such as `acquia.com,yale.edu,liquormarts.ca`, to restrict scans to those domains and their subdomains. Redirects are checked too. Anything else returns `domain_not_allowed`.
4. Deploy, then note the URL, for example `https://bot-defense-scanner.vercel.app`.
5. Test it:

```bash
curl -s -X POST https://YOUR-PROJECT.vercel.app/api/scan \
  -H "X-Scan-Key: $SCAN_KEY" -H "Content-Type: application/json" \
  -d '{"url":"www.liquormarts.ca"}' | python3 -m json.tool
```

6. Have an org admin add the project's domain to Claude's network allowlist under **Organization settings > Capabilities**. That one domain replaces allowlisting every prospect site.
7. Put the URL and key into the skill (Step 2a).

## Notes

- **Hobby plan:** Vercel's Hobby plan is for personal, non-commercial use. Fine for a proof of concept; move to Pro or an Acquia-owned account before AEs depend on it.
- **Timeout:** `maxDuration` is set to 30 seconds. A typical scan takes 2 to 6 seconds. Lower it if your plan rejects the value.
- **Rotating the key:** change `SCAN_KEY` in Vercel and in the skill at the same time.
- **Out of scope:** Salesforce integration is deliberately left out; this is an on-demand tool.
