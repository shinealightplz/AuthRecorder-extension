AuthRecorder Pro v2.0.0 - Complete Documentation

=== TOOL OVERVIEW ===
AuthRecorder Pro is an advanced authentication flow capture and replay tool designed for security professionals and developers. It provides comprehensive capabilities for recording, analyzing, and replaying complex authentication mechanisms across web applications.

Key capabilities:
- Multi-browser support (Chromium, Firefox, WebKit)
- MITM proxy integration for enhanced capture
- Automatic handling of CSRF tokens, bearer tokens, and session cookies
- Generation of production-ready Python scripts
- Professional GUI with live validation
- CLI mode for automation
- Anti-bot detection capabilities

=== BROWSER EXTENSION DETAILS ===
The AuthRecorder browser extension enhances the core tool's capabilities by:

1. Content Script Features:
- Intercepts and logs all network requests
- Captures DOM changes during authentication flows
- Detects anti-bot protection mechanisms
- Records user interactions with login forms

2. Background Script Features:
- Maintains persistent connection with main application
- Handles message passing between browser and tool
- Manages authentication state tracking
- Processes captured data before sending to main tool

3. Popup Interface:
- Quick access to recording controls
- Visual feedback on capture status
- Configuration options for advanced users
- Help documentation access

4. Settings Page:
- Proxy configuration
- Capture granularity settings
- Data retention policies
- Performance tuning options

=== INSTALLATION ===
1. Tool Installation:
   python install.py

2. Extension Installation:
   - Load unpacked extension from: authrecorder-extesion/
   - Enable in browser developer mode

3. Dependencies:
   - Python 3.8+
   - Playwright browsers
   - mitmproxy (optional)

=== USAGE GUIDE ===
1. GUI Mode:
   - Launch with: python authrecorder_complete.py
   - Configure target URL and options
   - Start capture and interact with login flow
   - Review and export generated scripts

2. CLI Mode:
   Basic capture:
   python authrecorder_complete.py --cli --target-url [URL]

   With MITM:
   python authrecorder_complete.py --cli --target-url [URL] --mitm

   Batch testing:
   python authrecorder_complete.py --cli --target-url [URL] --batch credentials.txt

3. Extension Usage:
   - Click extension icon to start/stop recording
   - Configure via settings page
   - View captured data in real-time

=== FEATURES ===
1. Advanced Capture:
   - Full request/response logging
   - DOM snapshotting
   - Cookie tracking
   - Header analysis

2. Script Generation:
   - Requests-based authentication scripts
   - Playwright automation scripts
   - Cookie-based authentication
   - Multi-step flow handlers

3. Security Features:
   - Local data storage only
   - Secure credential handling
   - Configurable data retention
   - No telemetry

=== TROUBLESHOOTING ===
1. Common Issues:
   - Browser launch failures: Try different browser engine
   - Proxy errors: Check port 8080 availability
   - Capture gaps: Ensure extension is enabled

2. Debugging:
   - Enable debug logs: --log-level DEBUG
   - Check outputs/authrecorder.log
   - Verify extension connectivity

=== SUPPORT ===
For additional assistance:
- Review generated script examples
- Check documentation/ directory
- Examine test cases in tests/
