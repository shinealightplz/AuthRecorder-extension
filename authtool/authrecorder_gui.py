#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AuthRecorder – GUI front‑end
============================================================

Fully‑functional colour‑coded Tkinter UI that talks to the lightweight
capture engine in ``capture.py``.

Dependencies
------------
pip install requests playwright rich jinja2 tqdm mitmproxy
playwright install
"""

import sys
import traceback
import threading
import time
from datetime import datetime
from pathlib import Path

# --------------------------------------------------------------
# Basic Tkinter imports – if unavailable we abort early
# --------------------------------------------------------------
try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox, scrolledtext
except Exception:
    tk = None
    ttk = None
    filedialog = None
    messagebox = None
    scrolledtext = None

# --------------------------------------------------------------
# Import helpers from our local module
# --------------------------------------------------------------
try:
    from capture import (
        record_authentication,     # main capture routine
        collect_scripts,          # write login_requests.py / cookie_login.py / .svb / .anom
        detect_waf_token,         # helper
    )
except Exception as exc:
    print(f"Failed to import capture helpers: {exc}")
    sys.exit(1)

# --------------------------------------------------------------
# Logging helper – rich if available, otherwise plain
# --------------------------------------------------------------
try:
    from rich import print as rprint
except Exception:
    rprint = print


# --------------------------------------------------------------
# Main GUI application
# --------------------------------------------------------------
class AuthRecorderGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("AuthRecorder • WAF‑Bypass & Login Generator")
        self.geometry("1040x720")
        self.minsize(820, 680)

        # ------------------------------------------------------------------
        # Variables – convenient for validation / callbacks
        # ------------------------------------------------------------------
        self.target_url = tk.StringVar()
        self.browser = tk.StringVar(value="chromium")
        self.proxy = tk.StringVar()
        self.use_mitm = tk.BooleanVar()
        self.prod_zip = tk.BooleanVar()
        self.batch_file = tk.StringVar()
        self.protected_url = tk.StringVar()
        self.output_dir = tk.StringVar(value=str(Path.cwd() / "outputs"))
        self.no_proxy = tk.BooleanVar()

        # ------------------------------------------------------------------
        # UI state helpers
        # ------------------------------------------------------------------
        self.capturing = False
        self.capture_thread: threading.Thread | None = None

        # ------------------------------------------------------------------
        # Build all widgets – everything uses grid exclusively
        # ------------------------------------------------------------------
        self._build_widgets()
        self._validate_inputs_integrity()

        # Make `log_it` an alias of `_log` (back‑compatibility)
        self.log_it = self._log

    # ------------------------------------------------------------------
    # Build all widgets – grid for everything (no pack/grid clash)
    # ------------------------------------------------------------------
    def _build_widgets(self):
        """Create all widgets – grid everywhere."""
        # ----------------- HEADER ------------------------------------
        header = ttk.Labelframe(self, text="General Configuration", padding=12)
        header.grid(row=0, column=0, sticky="ew", padx=8, pady=6)
        header.columnconfigure(1, weight=1)

        # 1) Target URL
        ttk.Label(header, text="Target URL *").grid(row=0, column=0, sticky="w")
        url_entry = ttk.Entry(header, textvariable=self.target_url)
        url_entry.grid(row=0, column=1, sticky="ew", padx=(6, 0))
        url_entry.bind("<KeyRelease>", lambda e: self._validate_inputs_integrity())

        # 2) Browser engine
        ttk.Label(header, text="Browser").grid(row=1, column=0, sticky="w")
        browser_box = ttk.Combobox(
            header, width=12, textvariable=self.browser,
            values=["chromium", "firefox", "webkit"], state="readonly"
        )
        browser_box.grid(row=1, column=1, sticky="w", pady=6)

        # ----------------- PROXY / MITM -------------------------------------
        proxy_frame = ttk.Labelframe(header, text="Proxy / MITM", padding=6)
        proxy_frame.grid(row=2, columnspan=2, sticky="ew", pady=10)

        m_check = ttk.Checkbutton(
            proxy_frame, text="Use MITM Proxy (recommended)", variable=self.use_mitm
        )
        m_check.grid(row=0, column=0, sticky="w")

        no_p_check = ttk.Checkbutton(
            proxy_frame, text="No Proxy – direct connection", variable=self.no_proxy
        )
        no_p_check.grid(row=1, column=0, sticky="w", pady=(4, 0))

        ttk.Label(proxy_frame, text="Proxy URL").grid(row=2, column=0, sticky="w")
        proxy_entry = ttk.Entry(proxy_frame, textvariable=self.proxy)
        proxy_entry.grid(row=2, column=1, sticky="ew", padx=(6, 0))

        # ----------------- OUTPUT --------------------------------------------
        output_frame = ttk.Labelframe(header, text="Output", padding=6)
        output_frame.grid(row=3, columnspan=2, sticky="ew", pady=10)

        ttk.Label(output_frame, text="Output folder").grid(row=0, column=0, sticky="w")
        out_entry = ttk.Entry(output_frame, textvariable=self.output_dir)
        out_entry.grid(row=0, column=1, sticky="ew", padx=(6, 0))
        ttk.Button(
            out_entry, text="Browse", command=self._browse_output
        ).grid(row=0, column=2, padx=(6, 0))

        ttk.Checkbutton(
            output_frame, text="Create ZIP archive after run", variable=self.prod_zip
        ).grid(row=1, column=0, sticky="w", pady=4)

        # ----------------- ADVANCED -------------------------------------------
        adv_frame = ttk.Labelframe(header, text="Advanced", padding=6)
        adv_frame.grid(row=4, columnspan=2, sticky="ew", pady=(10, 0))
        adv_frame.columnconfigure(1, weight=1)

        #  Credentials file
        ttk.Label(adv_frame, text="Credentials file (optional)").grid(row=0, column=0, sticky="w")
        batch_entry = ttk.Entry(adv_frame, textvariable=self.batch_file)
        batch_entry.grid(row=0, column=1, sticky="ew", padx=(6, 0))
        ttk.Button(
            batch_entry, text="Browse", command=self._browse_batch
        ).grid(row=0, column=2, padx=(6, 0))

        #  Protected page
        ttk.Label(adv_frame, text="Protected page URL (optional)").grid(row=1, column=0, sticky="w")
        protected_entry = ttk.Entry(adv_frame, textvariable=self.protected_url)
        protected_entry.grid(row=1, column=1, sticky="ew", padx=(6, 0))

        # ----------------- ACTION BUTTONS ------------------------------------
        btn_frame = ttk.Frame(self)
        btn_frame.grid(row=1, column=0, pady=6, sticky="ew")

        start_btn = ttk.Button(
            btn_frame, text="▶ Start Capture", command=self._start_capture, width=18
        )
        start_btn.pack(side="left", padx=6)

        stop_btn = ttk.Button(
            btn_frame, text="⏹ Stop", command=self._stop_capture, state="disabled", width=12
        )
        stop_btn.pack(side="left", padx=6)

        self.start_btn = start_btn
        self.stop_btn = stop_btn

        # ----------------- LOG AREA ------------------------------------------
        log_frame = ttk.LabelFrame(self, text="Live Log", padding=6)
        log_frame.grid(row=2, column=0, sticky="nsew", padx=10, pady=0)
        self.grid_rowconfigure(2, weight=1)    # make this row expand

        self.log = scrolledtext.ScrolledText(
            log_frame,
            state="disabled",
            height=15,
            wrap="word",
            background="black",
            foreground="#f0f0f0",
            insertbackground="#f0f0f0",
            font=("Consolas", 9),
        )
        self.log.pack(fill="both", expand=True)

        # colour‑tags for log levels
        self.log.tag_configure("info", foreground="#3498db")
        self.log.tag_configure("ok", foreground="#27ae60")
        self.log.tag_configure("warn", foreground="#f39c12")
        self.log.tag_configure("err", foreground="#e74c3c")
        self.log.tag_configure("debug", foreground="#95a5a6")

        # ----------------- STATUS BAR ---------------------------------------
        self.status_bar = ttk.Label(
            self, text="● Ready", relief="ridge", anchor="w"
        )
        self.status_bar.grid(row=3, column=0, sticky="ew", pady=(4, 0))

    # ------------------------------------------------------------------
    # Logging helper – colour‑coded per level
    # ------------------------------------------------------------------
    def _log(self, msg: str, level: str = "info"):
        tags = {
            "info": "info",
            "ok": "ok",
            "warn": "warn",
            "err": "err",
            "debug": "debug",
        }
        tag = tags.get(level, "info")
        timestamp = datetime.now().strftime("%H:%M:%S")
        line = f"{timestamp}  {msg}\n"

        self.log.configure(state="normal")
        self.log.insert("end", line, tag)
        self.log.see("end")
        self.log.configure(state="disabled")

    # ------------------------------------------------------------------
    # Browse helpers
    # ------------------------------------------------------------------
    def _browse_output(self):
        folder = filedialog.askdirectory(
            initialdir=self.output_dir.get(), title="Select Output Directory"
        )
        if folder:
            self.output_dir.set(folder)

    def _browse_batch(self):
        file = filedialog.askopenfilename(
            filetypes=[("Text files", "*.txt"), ("CSV", "*.csv"), ("All", "*.*")]
        )
        if file:
            self.batch_file.set(file)

    # ------------------------------------------------------------------
    # Input validation – enable/disable the Start button
    # ------------------------------------------------------------------
    def _validate_inputs_integrity(self):
        url = self.target_url.get().strip()
        ok = url.startswith(("http://", "https://"))
        self.start_btn.config(state="normal" if ok else "disabled")

    # ------------------------------------------------------------------
    # Capture logic – runs in a thread so UI stays responsive
    # ------------------------------------------------------------------
    def _start_capture(self):
        if self.capturing:
            return
        self.capturing = True
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self._log("➡️  Starting capture…", "info")

        # Build command dictionary for the capture helper
        cmd = dict(
            target_url=self.target_url.get(),
            proxy=self.proxy.get() if not self.no_proxy.get() else "",
            browser_type=self.browser.get(),
            mitm=self.use_mitm.get(),
            output_dir=self.output_dir.get(),
            zip=self.prod_zip.get(),
            batch_file=self.batch_file.get(),
            protected_page=self.protected_url.get(),
        )

        def worker():
            try:
                result = record_authentication(
                    target_url=cmd["target_url"],
                    proxy=cmd["proxy"],
                    browser_type=cmd["browser_type"],
                    mitm=cmd["mitm"],
                    output_dir=cmd["output_dir"],
                    zip_destination=cmd["zip"],
                    batch_file=cmd["batch_file"],
                    protected_page=cmd["protected_page"],
                    ansi=False,
                )
                self._log("✅ Capture finished!", "ok")
                self._log(f"  → {result['log_file']}", "info")

                self._log("🚀 Generating helper scripts…", "info")
                collect_scripts(result)
                self._log("✅ All artefacts written.", "ok")
                if cmd["zip"]:
                    self._log("💾 ZIP archive created.", "ok")

            except Exception as exc:
                error_msg = f"❌ Error: {exc}"
                self._log(error_msg, "err")
                traceback.print_exc()
            finally:
                self.capturing = False
                self.start_btn.config(state="normal")
                self.stop_btn.config(state="disabled")

        self.capture_thread = threading.Thread(target=worker, daemon=True)
        self.capture_thread.start()

    # ------------------------------------------------------------------
    def _stop_capture(self):
        # There is no immediate kill – we let the capture finish on its own.
        self._log("⏹  Stop requested – will finish when idle.", "warn")

    # ------------------------------------------------------------------
    # Graceful close
    # ------------------------------------------------------------------
    def exit_handler(self):
        if self.capturing:
            if messagebox.askokcancel(
                "Quit", "A capture is in progress. Really quit?"
            ):
                self.destroy()
        else:
            self.destroy()


# ------------------------------------------------------------------
# Entry point
# ------------------------------------------------------------------
if __name__ == "__main__":
    if not tk:
        print("Tkinter is not available – please install it!")
        sys.exit(1)

    app = AuthRecorderGUI()
    app.protocol("WM_DELETE_WINDOW", app.exit_handler)
    app.mainloop()
