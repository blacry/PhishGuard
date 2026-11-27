# PhishGuard viva documentation

This project is a simple local database checker: it answers whether a URL is listed in the supplied URLhaus malware URL dump.

## Read these guides

1. [Project overview](project-overview.md)
2. [Architecture and lookup flow](architecture-and-flow.md)
3. [Database matching rules](detection-database.md)
4. [Code module guide](code-module-guide.md)
5. [Privacy, safety, and limitations](privacy-and-security.md)
6. [Setup and operation](setup-and-operation.md)
7. [Tests](testing.md)
8. [Viva questions and answers](viva-questions.md)
9. [Safety tips](safety-tips.md)

## Short viva summary

PhishGuard is a Python and Streamlit application that checks a URL against a local URLhaus database snapshot. It reads the CSV file inside the supplied ZIP archive, normalizes URL scheme and fragment differences, and looks for an exact URL match. It also warns if the same hostname has other listed malware URLs. A missing match is reported as “not listed,” not as proof of safety. No URL is opened or sent to an online service.
