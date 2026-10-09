# GSM Pray private leader access

This version must be configured before merging into main. If settings or authentication are missing, every API request is denied. Existing Cloudflare KV records are preserved. This does not migrate to a different database.

## What changes for leaders

Approved leaders sign in through Cloudflare Access using their own email. An emailed one-time code can be used without creating a new password. No student details or prayer requests load until the server verifies the signed session. Only emails designated as administrators can edit names, grades, birthdays, active status, or import/delete people. Approved leaders can record prayers and add/remove prayer requests. Administrators can edit history.

## Activation order

1. Back up the production `people`, `week_history`, and `settings` KV values to a secure location. Never commit those values or student exports to GitHub. Do not paste the old password into chat.
2. In Cloudflare Zero Trust, create a self-hosted Access application covering the entire production hostname, not just one page or `/api/data`. Use an exact approved-email allow policy. Do not choose Everyone, bypass, or a whole email domain unless deliberately authorized. Enable One-time PIN or an existing trusted identity provider. Set an eight-hour session initially. Enable Secure and HttpOnly application cookies in the Access settings.
3. Check the production Pages hostname: the built-in Pages Access toggle may protect previews only. For production, use an Access-compatible custom hostname under a domain you manage in Cloudflare if needed. Do not assume the default `pages.dev` hostname is protected. API JWT validation below prevents alternate hostnames from exposing data regardless.
4. Copy the Access team hostname (for example `your-team.cloudflareaccess.com`, without `https://`) and the application's Audience (AUD) tag.
5. In the Pages project's **production** environment variables, add:

   | Variable | Value |
   | --- | --- |
   | `ACCESS_TEAM_DOMAIN` | Exact team hostname from step 4 |
   | `ACCESS_AUD` | Exact application Audience tag |
   | `ACCESS_ALLOWED_EMAILS` | Comma-separated approved leader emails, including administrators |
   | `ACCESS_ADMIN_EMAILS` | Comma-separated administrator emails; start with the owner's verified email |

   Leave `INTERCEDE_KV` bound to the existing production namespace. These access values are configuration, not passwords. Do not use a `VITE_` prefix.
6. Protect preview hostnames separately. Use a different Access application/AUD and a **separate test KV namespace** for preview tests. Never allow a review deployment to write the live roster. If preview variables are absent, the API denies all access by design.
7. Merge the security review branch into main and wait for the Cloudflare build. Setting variables alone does not change the existing public API. Confirm the new deployment is serving the updated code.
8. Test an approved leader and an administrator on Safari and the iPhone Home Screen app. An approved leader should be unable to import or edit names, even by sending a direct API request. Sign out, then try `/api/data`, `/api/history`, `/api/session`, and `/api/data?key=settings`; none should return private information without authentication. Repeat against default Pages and preview hostnames. Direct unauthenticated API requests must receive 401 or an Access login response.
9. Once this deployment is verified, remove the obsolete `password` property from the existing KV `settings` JSON, leaving its name and subtitle. The new app never reads it. If that old password was used elsewhere, change it there too, because the previous public endpoint could reveal it.
10. Ask leaders to reload/reopen the app. This clears known legacy roster/settings/admin keys from localStorage. No new roster data or credentials are persisted in browser storage by this version. Unloaded older clients cannot be remotely wiped; use trusted devices and revoke access when a leader leaves.

## Revocation and ongoing care

Remove a departing leader from BOTH the Access allow policy and `ACCESS_ALLOWED_EMAILS`, redeploy, and revoke their existing Access sessions. Remove administrators from `ACCESS_ADMIN_EMAILS` as needed. Updating the Access policy alone may leave an already issued token valid until its session ends; the server allowlist provides a second check. Protect the GitHub and Cloudflare administrator accounts with MFA. A revoked user may already possess a downloaded copy or screenshot; permissions cannot recover those.

Keep periodic secure backups and test restoration. Do not enable public R2 photo buckets using the old appendix sample: that example is not part of this protected app. External image URLs are blocked by the content security policy until a reviewed private-photo design is added.

The app has a 1 MiB API body limit, bounded prayer strings/roster size, same-origin write checks, no wildcard CORS, no-store API responses, and restrictive static response headers. Access manages login attempts; consider edge rate limiting if usage is abused. KV is eventually consistent and this change does not solve simultaneous-edit races; a transactional database or Durable Object would be a separate reliability improvement.

## Validation

Run `npm test` for the server security regression suite and `npm run build` for the React build. Unit tests use synthetic student data and generated test signing keys only. Complete the production sign-in, logout, role and alternate-host checks above before declaring live privacy protection enabled.

Official references:
- https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/application-token/
- https://developers.cloudflare.com/cloudflare-one/integrations/identity-providers/one-time-pin/
- https://developers.cloudflare.com/pages/functions/plugins/cloudflare-access/
