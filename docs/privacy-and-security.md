# Privacy, safety, and limitations

## Safe behavior

- Submitted URLs are parsed as text only.
- The app does not visit, resolve, or open submitted URLs.
- No URL is sent to an online service.
- The database is read locally from the supplied ZIP file.
- The app has no API key or credential configuration.

## What a match means

An exact match means this URL is present in the supplied URLhaus snapshot. A hostname-only match means other URLhaus records use that hostname; the exact submitted path is not confirmed. These are database results, not an independent live malware scan.

## What no match means

“Not listed” means the URL might be safe, but it could also be new or missing from this local snapshot. The dump can be stale, incomplete, or contain only a different URL path, so this result cannot confirm safety.

## Data limitations

- URLhaus specializes in URLs associated with malware distribution; it is not a complete database of all phishing or malicious URLs.
- Offline and historical records can remain in the dump.
- Matching is based on normalized URL text and exact hostname; complex redirect or domain relationships are not evaluated.
- Refresh the dump from its source to get newer records, then restart the app.
