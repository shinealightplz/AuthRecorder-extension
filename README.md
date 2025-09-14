AuthRecorder Pro v2.0.0 – Quick‑Start & Troubleshooting Cheat Sheet
This is a distilled reference you can keep on your desktop (or copy into a Markdown note).
👉 All commands are relative to the project root (/authrecorder‑extension).

1. One‑liner Install
bash

# clone & install
git clone https://github.com/shinealightplz/AuthRecorder-extension.git
cd AuthRecorder-extension
python install.py
The script pulls the required PyPI packages (requests, playwright, rich, jinja2, tqdm, optional mitmproxy) and sets up the Playwright browsers.

2. Launching the GUI
bash

python authrecorder_complete.py
Target URL – paste the login page.
Browser Engine – default is Chromium.
Proxy – leave empty for direct; click the MITM button to auto‑start mitmproxy on port 8080.
Pins a “Start Capture” button; stop when the flow completes.

3. Running in CLI Mode
Flag	Value	Description
--cli	mandatory	Enables command‑line mode.
--target-url	<URL>	The page to record.
--browser	chromium 	firefox
--mitm	–	Starts mitmproxy automatically.
--proxy	http://host:port	Forward requests through your own proxy.
--batch	file.txt	One‑line user,password.
--protected	<URL>	URL that requires a successful login to access.
--zip	–	Creates a compressed archive of the capture folder.
--output	path/	Where to write the capture folder.
--log-level	DEBUG/INFO/WARNING/ERROR	Logging verbosity.
Sample Commands
bash

# Simple capture
python authrecorder_complete.py --cli --target-url https://example.com/login

# With the MITM proxy
python authrecorder_complete.py --cli --target-url https://example.com/login --mitm

# Run a batch test
python authrecorder_complete.py \
  --cli \
  --target-url https://example.com/login \
  --batch credentials.txt \
  --protected https://example.com/dashboard
4. Extension Use
Load:
chrome://extensions/ → Developer mode → Load unpacked → authrecorder‑extension/

Activate: Click the icon → “Start recording” → Begin interacting with the site.

Settings:

Proxy: configure MITM or custom proxy.
Granularity: decide whether to capture all XHRs, only fetch calls, etc.
Retention: keep data only for ☑️ days.
Data: The extension streams captured packets and DOM mutations to the local authrecorder process. All data stays under outputs/.

5. Output Folder Structure (after a successful capture)

outputs/
└── 2024‑10‑10_12‑30‑17/
    ├── capture.json          # Raw request/response, DOM snapshots, etc.
    ├── login_requests.py     # Requests‑based login script
    ├── cookie_login.py       # Cookie‑only script
    ├── playwright_adv.py    # Playwright example (requires extra steps)
    ├── cookies.json          # Serialized session cookies
    └── successful_logins.txt # (batch mode) auth results
Tip: capture.json is the single source of truth – you can re‑generate any script from it.

6. Script Generation Basics
python

# Example: generate_requests.py
from authrecorder.generate import RequestsGenerator

gen = RequestsGenerator("stamp2024-10-10_12-30-17/capture.json")
gen.write_script("generated/login_requests.py")
The generator will:

Pull the CSRF token pattern from intercepted responses.
Create a requests.Session() that auto‑harvests cookies.
Compose the final POST/GET verbs with correct payloads.
7. Common Hiccups & Fixes
Problem	Symptom	Fix
Playwright browsers missing	pyinstaller error: “cannot find chromium.bin”	playwright install chromium
MITM port 8080 in use	ConnectionRefusedError	Kill the proccess (`netstat -ano
Extension not receiving data	GUI shows “Connection lost”	1) Re‑load extension after any change. <br>2) Ensure authrecorder_complete.py is still running. <br>3) Verify Chrome/Edge has allow access to file URLs enabled.
Scripts fail with “token not found”	Extension didn't capture the CSRF blob	Increase --granularity to record all network traffic or verify that the request is not blocked by the site’s CSP.
Batch test exits prematurely	error: cannot open credentials.txt	Ensure the file exists in the current directory or supply absolute path.
Long capture timings (minutes)	Scripts take > 15 min to load	Disable extraneous tabs, use headless mode (--browser=chromium) and optional --mitm for more efficient packet filtering.
8. Logging
All logs are written to outputs/authrecorder.log.
Set an environment variable for fine‑grained control:

bash

export AUTHRECORDER_LOG_LEVEL=DEBUG
9. Extending AuthRecorder
Add a new capturer: Edit /src/capturers/.
Add a script template: Edit /src/generators/playwright.py or requests.py.
Unit test: Add a test in tests/ and run pytest.
10. Where to Get Help
Resource	Link
Demo scripts	outputs/ after a capture
Source code	src/
Unit tests	tests/
Issue tracker	GitHub Issues
