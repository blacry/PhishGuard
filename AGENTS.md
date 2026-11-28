# PhishGuard project notes

PhishGuard is a focused local URL lookup app. It checks input against the supplied URLhaus CSV dump in `data/full.csv.zip`.

- Never open submitted URLs or send them to online services.
- A full URL match means it is listed as malware in this snapshot.
- A host-only match is a warning, not an exact URL verdict.
- No match means only “not listed,” never a guarantee of safety.
- Keep implementation and explanations beginner-friendly.
