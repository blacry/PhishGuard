# Database matching rules

PhishGuard does not use heuristic rules to guess whether a URL is malicious. It searches the supplied URLhaus dump.

## URL normalization

`normalize_url()`:

1. Trims whitespace.
2. Adds `https://` when the input has no scheme.
3. Accepts only HTTP and HTTPS URLs with a hostname.
4. Lowercases and IDNA-normalizes the hostname.
5. Ignores the scheme and fragment for matching. The fragment is not sent to a web server, and HTTP/HTTPS scheme variations should not create separate entries for this lookup.
6. Preserves the path and query string.

For example, these compare as the same key:

```text
http://Example.test/a#section
https://example.test/a
```

## Verdicts

### Exact URL match: MALWARE

The canonical full URL is present in `by_url`. The app shows the threat label, URLhaus status, date added, and record ID.

### Host-only match: POTENTIALLY MALICIOUS

The full URL is not listed, but the exact hostname exists in `by_host` for one or more other records. The app shows up to five related records. This is a warning because the specific path may differ.

### No match: NOT LISTED

Neither the full URL nor its hostname appears in the local database. The URL might be safe, but it may also be new or missing from this snapshot, so the result cannot confirm safety.

## Dataset format

The ZIP archive contains `csv.txt`. The file starts with comment lines; a row beginning `# id` supplies the column headings. The loader skips comment lines and reads the `url` field from each data row. Relevant fields include `id`, `dateadded`, `url`, `url_status`, `last_online`, and `threat`.

## Database source

The archive identifies itself as the [URLhaus database](https://urlhaus.abuse.ch/), a project of abuse.ch. See [data/README.md](../data/README.md) for its update timestamp and terms link.
