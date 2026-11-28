# Viva questions and suggested answers

## 1. What does PhishGuard do?

It checks whether a URL appears in a local URLhaus malware URL database and shows an exact-match result, a host-level warning, or no match.

## 2. What is URLhaus?

URLhaus is an abuse.ch project that collects URLs associated with malware distribution. This project uses the supplied CSV dump as a local snapshot.

## 3. Does the app visit the URL?

No. It parses the URL as text and compares it with strings in a local dictionary. It makes no network request to the submitted URL.

## 4. How is the database loaded?

The Python `zipfile` module opens the archive, `csv.reader` reads the CSV member, and the app builds dictionaries for exact URLs and hostnames.

## 5. Why use a dictionary?

A dictionary provides fast key lookup. The canonical URL is the key for exact matches; the hostname is the key for related-host checks.

## 6. What is an exact match?

After normalization, the entire URL path and query match a URL in the dataset. PhishGuard labels that `MALWARE` and displays its database record details.

## 7. Why have a host-only warning?

The exact path might not be in the feed, but another URL on the same hostname is listed. That is useful context, but it is not proof that every page on the host is malicious.

## 8. Does “not listed” mean safe?

No. It only means the local snapshot did not contain that URL or host. The database can be incomplete or outdated.

## 9. Why is the database local?

It avoids API keys and network calls, makes results repeatable, and demonstrates Python file and data handling. The tradeoff is that the user must refresh the snapshot manually.

## 10. What Python concepts are demonstrated?

Functions, dictionaries, loops, conditional statements, exception handling, string processing, URL parsing, ZIP/CSV file handling, and unit tests.

## 11. What are the limitations?

URLhaus does not contain every malicious URL. This app does not inspect page content, redirects, DNS, attachments, or other threat feeds. It can only report what exists in the local dump.

## 12. What could be improved?

The app could support more database formats, show a manual database refresh workflow, improve normalization, and test larger or malformed archives. Any additional source should preserve the same local-only privacy behavior unless the user explicitly chooses otherwise.

## Demo steps

1. Show the loaded record count and snapshot date.
2. Check one URL known to be in the supplied dataset and show its exact-match record.
3. Check a URL on a host with a different listed path and show the related-host warning.
4. Check `https://example.com` and explain that “not listed” is not a safety guarantee.
5. Open the safety tips panel and explain how users can verify links and avoid unexpected downloads.
