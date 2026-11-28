# Local URLhaus database

`full.csv.zip` is the database archive supplied for this project. It contains `csv.txt`, a CSV dump with fields for record ID, date added, URL, URL status, last online time, threat, tags, URLhaus record link, and reporter.

The current supplied snapshot says it was updated on 2026-11-27 17:17:12 UTC and contains 176,240 unique URL records. PhishGuard reads the file directly from the ZIP archive and does not extract or modify it.

## Source and terms

The archive identifies itself as the [abuse.ch URLhaus database](https://urlhaus.abuse.ch/) and includes the [URLhaus terms of use](https://urlhaus.abuse.ch/api/). Keep the source attribution with the dataset when sharing this academic project, and follow the source's current terms.

## Refreshing the database

Replace `full.csv.zip` with a newer compatible URLhaus CSV dump. Restart Streamlit after replacing it so the in-memory cache reloads. The app does not download updates automatically.
