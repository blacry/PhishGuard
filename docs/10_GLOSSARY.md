# 10 — Glossary

Every technical term used in PhishGuard, explained in simple English.
If you encounter a word you don't understand, look it up here.

---

| Term | Definition |
|------|-----------|
| **API** | Application Programming Interface — a way for programs to talk to each other. PhishGuard's optional feed feature downloads public threat data; it does not submit scanned URLs. |
| **Encryption key** | A secret used to encrypt opt-in stored scan input. If lost, encrypted input cannot be recovered. |
| **Assert** | A Python statement that checks if something is True. If not, the test fails. Used in pytest: `assert result == expected`. |
| **Boolean** | A value that is either `True` or `False`. Our indicator checks return booleans in the `triggered` field. |
| **Cache** | A local copy of data kept for reuse so the program does not repeatedly download the same feed. |
| **Capped score** | A score that has a maximum limit. We cap at 100 using `min(total, 100)` so the scale stays simple. |
| **CLI** | Command Line Interface — a text-based way to interact with a program. You type commands and read text output. No graphics. |
| **CI** | Continuous Integration — automated tests and build checks run when code is pushed or a pull request is opened. |
| **CSV** | Comma-Separated Values — a simple file format where each line is a row and values are separated by commas. Can be opened in Excel. |
| **Dictionary (dict)** | A Python data structure that stores key-value pairs. Like a real dictionary: the word is the key, the definition is the value. `{"name": "PhishGuard", "version": 1}` |
| **DNS** | Domain Name System — translates domain names (google.com) to IP addresses (142.250.x.x). Like a phone book for the internet. |
| **Docstring** | A special string in triple quotes at the start of a function/module that documents what it does. Python's built-in documentation system. |
| **Domain name** | The human-readable address of a website, like `google.com` or `example.com`. |
| **False negative** | When phishing is NOT detected (missed). The tool says "safe" but it's actually phishing. |
| **False positive** | When something safe IS flagged as phishing. The tool says "danger" but it's actually fine. |
| **Precision** | Of the items the detector flags, the share labeled positive in the evaluation set. |
| **Recall** | Of the positive items in the evaluation set, the share the detector flags. |
| **F1 score** | A combined measure of precision and recall. It is low when either measure is low, and is zero when both are zero. |
| **f-string** | A Python string that lets you embed variables: `f"Score is {score}"`. The `f` before the quote enables this. |
| **Function** | A reusable block of code that takes inputs (parameters), does something, and returns an output. Defined with `def`. |
| **GUI** | Graphical User Interface — a visual interface with buttons, windows, etc. PhishGuard uses CLI, not GUI. |
| **Heuristic** | A practical rule-of-thumb that works well most of the time but isn't guaranteed. Our weights are heuristics. |
| **HTTPS** | HyperText Transfer Protocol Secure — encrypts the connection between your browser and the website. The "S" means Secure. |
| **HTTP** | HyperText Transfer Protocol — the insecure version. Data is sent as plain text that anyone on the network can read. |
| **Indicator** | A specific red flag that suggests phishing. Each indicator is checked by one function. Example: "IP address in URL." |
| **IP address** | Internet Protocol address — a numeric address like `192.168.1.1` that identifies a device on a network. |
| **List** | A Python data structure that stores ordered items: `[1, 2, 3]` or `["apple", "banana"]`. |
| **Loop** | Code that repeats. `for` loops repeat for each item. `while` loops repeat until a condition is false. |
| **ML / Machine Learning** | A technique where computers learn patterns from data. PhishGuard v1 does NOT use ML — it uses rules. |
| **OpenPhish Community Feed** | An optional public list of reported phishing URLs. PhishGuard checks it locally and does not treat an absent URL as safe. |
| **Module** | A single `.py` file. You can import functions from one module into another using `import`. |
| **MVP** | Minimum Viable Product — the simplest version that works. Our MVP is the rule-based CLI scanner. |
| **Package** | A folder with an `__init__.py` file. It groups related modules together. `scanners/` is a package. |
| **Parameter** | A variable listed in a function definition. `def check_https(url):` — `url` is the parameter. |
| **Phishing** | A social engineering attack where the attacker pretends to be a trusted entity to steal sensitive information. |
| **Protocol** | The `http://` or `https://` part at the start of a URL. It tells the browser HOW to communicate with the server. |
| **pytest** | A Python testing library. Test functions start with `test_` and use `assert` to verify results. |
| **Regex (Regular Expression)** | A pattern language for matching text. `\d+` matches one or more digits. Used via Python's `re` module. |
| **Return value** | The value a function sends back when it finishes. Specified with the `return` keyword. |
| **Risk score** | A number from 0 to 100 representing how likely something is to be phishing. Higher = more suspicious. |
| **Social engineering** | Manipulating people (not computers) to give up information. Phishing is a type of social engineering. |
| **Static analysis** | Analyzing something by looking at it, not by running/visiting it. We analyze URL structure, not the actual webpage. |
| **String** | A sequence of characters in Python, like `"hello"` or `"http://example.com"`. |
| **String method** | A built-in function you can call on a string: `.lower()`, `.strip()`, `.split()`, `.startswith()`. |
| **Subdomain** | A prefix added before the main domain. In `mail.google.com`, `mail` is a subdomain. |
| **Threat level** | A human-readable label: LOW, MEDIUM, HIGH, or CRITICAL. Usually derived from the heuristic score; a fresh exact public-feed match can separately elevate it to CRITICAL. |
| **try/except** | Python's error handling. Code in `try` runs normally. If it crashes, `except` catches the error instead of stopping the program. |
| **URL** | Uniform Resource Locator — a web address like `https://www.example.com/page`. Has parts: protocol, domain, path. |
| **URL parsing** | Breaking a URL into its components (protocol, domain, subdomains, path, parameters). |
| **Validation** | Checking that data meets certain rules before processing it. "Is this actually a URL?" is validation. |
| **Virtual environment (venv)** | An isolated Python environment. Packages installed in a venv don't affect the system Python. Created with `python -m venv venv`. |
| **Weight** | A number assigned to each indicator representing how suspicious it is. Higher weight = stronger signal. |
| **YAML** | A readable text format for configuration. PhishGuard uses a `.yml` file to tell GitHub Actions when to run tests and build the Docker image; it is not Python code and is not needed to run the CLI. |
| **while True** | An infinite loop that runs forever until explicitly stopped with `break`. Used for menus and servers. |
