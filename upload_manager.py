import os
import json
import time
import socket
import hashlib
import logging
import threading
import traceback
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple
from html import escape
from urllib.parse import parse_qs, quote_plus, unquote_plus

import requests

try:
    import pwnagotchi.plugins as plugins
    from pwnagotchi.ui.components import LabeledValue
    from pwnagotchi.ui.view import BLACK
except Exception:
    class _DummyPlugin:
        pass
    class plugins:
        Plugin = _DummyPlugin
    class LabeledValue:  # type: ignore
        def __init__(self, **kwargs):
            pass
    BLACK = 0


class UploadManager(plugins.Plugin):
    """
    Handshake Upload Manager for Pwnagotchi.

    Features
    --------
    - Persistent per-file state database.
    - Tracks wpa-sec status.
    - Retry-all, retry-failed, rescan, prune-missing controls.
    - Dry-run mode.
    - Whitelist support.
    - Minimum size and age filters.
    - SHA1 tracking.
    - Dedicated log file.
    - Simple OLED status indicator.
    - Lightweight built-in web UI page and action endpoints.

    Trigger files
    -------------
      - retry_all.trigger
      - retry_failed.trigger
      - rescan.trigger
      - prune_missing.trigger

    Example config.toml
    -------------------
    [main.plugins.upload_manager]
    enabled = true
    handshake_dir = "/home/pi/handshakes"
    db_path = "/home/pi/handshakes/upload_state.json"
    log_path = "/home/pi/upload_manager.log"
    command_dir = "/home/pi/handshakes"
    scan_interval = 300
    min_file_size = 512
    min_file_age = 30
    retry_backoff_seconds = 1800
    max_retries = 25
    dry_run = false
    enable_wpa_sec = true
    wpa_sec_api_key = "YOUR_KEY"
    whitelist = []
    delete_trigger_files = true
    ui_slot = "uploadmgr"
    prune_missing = false
    startup_rescan = true
    max_consecutive_errors = 10
    web_sort = "name"
    """

    __author__ = "OpenAI"
    __version__ = "1.1.0"
    __license__ = "MIT"
    __description__ = "Advanced handshake upload manager for Pwnagotchi"

    DEFAULTS = {
        "handshake_dir": "/home/pi/handshakes",
        "db_path": None,
        "log_path": "/tmp/upload_manager.log",
        "command_dir": None,
        "extra_handshake_dirs": ["/root/handshakes"],
        "scan_recursive": True,
        "scan_interval": 300,
        "min_file_size": 512,
        "min_file_age": 30,
        "retry_backoff_seconds": 1800,
        "max_retries": 25,
        "dry_run": False,
        "enable_wpa_sec": True,
        "delete_trigger_files": True,
        "hash_block_size": 1024 * 1024,
        "connect_timeout": 20,
        "read_timeout": 120,
        "user_agent": "pwnagotchi-upload-manager/1.1",
        "whitelist": [],
        "ui_slot": "uploadmgr",
        "prune_missing": False,
        "startup_rescan": True,
        "max_consecutive_errors": 10,
        "web_sort": "name",
        "allow_duplicate_ssid_uploads": False,
        "wpasec_url": "https://wpa-sec.stanev.org/?submit",
    }

    STATUS_PENDING = "pending"
    STATUS_UPLOADED = "uploaded"
    STATUS_FAILED = "failed"
    STATUS_SKIPPED = "skipped"
    STATUS_FILTERED = "filtered"
    STATUS_INVALID = "invalid"
    STATUS_DUPLICATE = "duplicate"

    def __init__(self):
        self.options = dict(self.DEFAULTS)
        self.running = False
        self.ready = False
        self.internet_available = False
        self._db_lock = threading.RLock()
        self._op_lock = threading.Lock()
        self._worker = None
        self._session = requests.Session()
        self._db: Dict[str, Any] = {
            "meta": {"version": 1, "created": self._utc_now()},
            "files": {}
        }

        self._consecutive_errors = 0
        self._last_internet_event_ts = 0.0
        self._internet_probe_cache = False
        self._internet_probe_ts = 0.0
        # Keep a stable dashboard renderer even if a later edit corrupts method blocks.
        self._render_dashboard = self._render_dashboard_safe

    def _render_dashboard_safe(self, sort_key: str = "name", filter_key: str = "all") -> str:
                counts = self._counts()
                rows = self._sorted_records(sort_key, filter_key)
                internet_state = self._internet_status()

                table_rows = []
                for path, rec in rows:
                        w = rec["services"]["wpa_sec"]
                        fname = escape(rec.get("name", os.path.basename(path)))
                        size = self._human_size(rec.get("size", 0))
                        mtime = escape(rec.get("mtime_iso", ""))
                        filtered = escape(rec.get("filtered_reason") or "")
                        invalid = "Invalid handshake" if rec.get("invalid_handshake") else ""
                        err = escape((w.get("error") or "")[:120])
                        
                        # Build action links based on status
                        actions = []
                        if w["status"] in (self.STATUS_INVALID, self.STATUS_DUPLICATE):
                            actions.append(f"<a class='action-link delete' href='?action=delete_file&target={quote_plus(path)}&sort=name&filter=all'>Delete</a>")
                        elif rec.get("filtered_reason") and w["status"] == self.STATUS_FILTERED:
                            actions.append(f"<a class='action-link delete' href='?action=delete_file&target={quote_plus(path)}&sort=name&filter=all'>Delete</a>")
                        else:
                            actions.append(f"<a class='action-link' href='?action=retry_file&target={quote_plus(path)}&sort=name&filter=all'>Retry</a>")
                        action_html = " ".join(actions)
                        
                        # Determine badge class - use filtered reason badge if filtered
                        badge_class = self._badge_class_for_reason(rec.get("filtered_reason")) if rec.get("filtered_reason") else self._badge_class(w['status'])
                        
                        table_rows.append(
                                f"<tr><td class='fname'>{fname}</td><td>{size}</td><td>{mtime}</td>"
                                f"<td><span class='badge {badge_class}'>{escape(w['status'])}</span></td>"
                                f"<td>{invalid}</td><td>{filtered}</td><td>{err}</td><td>{action_html}</td></tr>"
                        )

                wpa_sec_toggle = "✓ Enabled" if self.options.get('enable_wpa_sec', True) else "✗ Disabled"
                dup_toggle = "✓ Allow Duplicates" if self.options.get('allow_duplicate_ssid_uploads', False) else "✗ Allow Duplicates"
                internet_color = "#22c55e" if internet_state else "#ef4444"
                internet_text = "● Online" if internet_state else "● Offline"

                return f"""
                <h1>Wpa-sec Upload Manager</h1>
                <div class='cards'>
                    <div class='card'><div class='k'>Files</div><div class='v'>{counts['files']}</div></div>
                    <div class='card'><div class='k'>wpa-sec Uploaded</div><div class='v'>{counts['wpa_sec_uploaded']}</div></div>
                    <div class='card'><div class='k'>Failed</div><div class='v'>{counts['failed_total']}</div></div>
                    <div class='card'><div class='k'>Invalid</div><div class='v'>{counts['invalid']}</div></div>
                    <div class='card'><div class='k'>Duplicates</div><div class='v'>{counts['duplicate']}</div></div>
                    <div class='card'><div class='k'>Filtered</div><div class='v'>{counts['filtered']}</div></div>
                    <div class='card'><div class='k'>Skipped</div><div class='v'>{counts['skipped']}</div></div>
                </div>
                <div class='actions'>
                    <a class='action-link' title='Auto uploads enabled/disabled' href='?action=toggle_wpa_sec&sort=name&filter=all'>{wpa_sec_toggle}</a>
                    <a class='action-link' title='Allow/prevent duplicate SSIDs from uploading' href='?action=toggle_dup_uploads&sort=name&filter=all'>{dup_toggle}</a>
                    <a class='action-link' title='Scan files for new handshakes' href='?action=rescan&sort=name&filter=all'>Rescan</a>
                    <a class='action-link' title='Retry all failed uploads' href='?action=retry_all&sort=name&filter=all'>Retry All</a>
                    <a class='action-link' title='Retry only failed uploads' href='?action=retry_failed&sort=name&filter=all'>Retry Failed</a>
                    <a class='action-link' title='Delete all invalid handshakes' href='?action=delete_invalid&sort=name&filter=all'>Delete Invalid</a>
                    <a class='action-link' title='Delete duplicate SSIDs' href='?action=delete_duplicates&sort=name&filter=all'>Delete Duplicates</a>
                    <a class='action-link' title='Reset upload tracking (for testing - may cause duplicates)' href='?action=reset_uploads&sort=name&filter=all' onclick="return confirm('⚠️ WARNING: This will reset upload tracking and can cause duplicate uploads to wpa-sec. Continue?')">Reset Tracking</a>
                </div>
                <div class='toolbar'>
                    <div>
                        <a href='?sort=name&filter=all'>All</a> |
                        <a href='?sort=name&filter=pending'>Pending</a> |
                        <a href='?sort=name&filter=invalid'>Invalid</a> |
                        <a href='?sort=name&filter=duplicate'>Duplicate</a> |
                        <a href='?sort=name&filter=failed'>Failed</a> |
                        <a href='?sort=name&filter=uploaded'>Uploaded</a> |
                        <a href='?sort=mtime&filter=all'>Newest</a> |
                        <a href='?sort=size&filter=all'>Largest</a>
                    </div>
                    <div class='subtle' style="margin-left: auto;"><span style="color: {internet_color}; font-weight: bold;">{internet_text}</span></div>
                </div>
                <table>
                    <thead><tr><th>File</th><th>Size</th><th>Modified</th><th>wpa-sec</th><th>Invalid</th><th>Filtered</th><th>Error</th><th>Action</th></tr></thead>
                    <tbody>{''.join(table_rows) if table_rows else '<tr><td colspan="8">No files match this filter.</td></tr>'}</tbody>
                </table>
                """

    # --------------------------
    # Pwnagotchi lifecycle hooks
    # --------------------------
    def on_loaded(self):
        raw_options = getattr(self, "options", {}) or {}
        try:
            # tomlkit containers do not like None values during in-place update.
            raw_options = dict(raw_options)
        except Exception:
            raw_options = {}

        merged = dict(self.DEFAULTS)
        for k, v in raw_options.items():
            merged[k] = v

        merged["handshake_dir"] = os.path.abspath(os.path.expanduser(str(merged.get("handshake_dir") or "")))

        normalized_extra_dirs = []
        for d in merged.get("extra_handshake_dirs", []) or []:
            d = os.path.abspath(os.path.expanduser(str(d)))
            if d and d != merged["handshake_dir"] and d not in normalized_extra_dirs:
                normalized_extra_dirs.append(d)
        merged["extra_handshake_dirs"] = normalized_extra_dirs

        if not merged.get("db_path"):
            merged["db_path"] = os.path.join(merged["handshake_dir"], "upload_state.json")
        if not merged.get("command_dir"):
            merged["command_dir"] = merged["handshake_dir"]

        self.options = merged

        self._ensure_parent_dirs()
        self._setup_logging()
        self._session.headers.update({"User-Agent": self.options["user_agent"]})

        self._log("info", "plugin loaded")
        self._log("info", f"scan roots: {self._scan_roots()}")
        self._load_db()
        
        # Restore toggle state from database if saved
        try:
            if hasattr(self, "_db") and self._db and "meta" in self._db:
                if self._db["meta"].get("enable_wpa_sec") is not None:
                    self.options["enable_wpa_sec"] = self._db["meta"]["enable_wpa_sec"]
                if self._db["meta"].get("allow_duplicate_ssid_uploads") is not None:
                    self.options["allow_duplicate_ssid_uploads"] = self._db["meta"]["allow_duplicate_ssid_uploads"]
        except Exception as e:
            self._log("error", f"failed restoring toggle state: {e}")
        
        # Record install timestamp on first run (to detect pre-existing handshakes)
        if "install_timestamp" not in self._db.get("meta", {}):
            self._db["meta"]["install_timestamp"] = time.time()
            self._log("info", "first installation detected - pre-existing handshakes will be skipped")

        if self.options.get("startup_rescan", True):
            self._scan_files(prune_missing=self.options.get("prune_missing", False))
            self._save_db()

        self.running = True
        self.ready = True
        self._worker = threading.Thread(target=self._worker_loop, name="upload-manager", daemon=True)
        self._worker.start()

    def on_unload(self, ui):
        self.running = False
        self.ready = False
        self._log("info", "plugin unloading")
        self._save_db()

    def on_ready(self, agent):
        self._log("info", "plugin ready")

    def on_internet_available(self, agent):
        self.internet_available = True
        self._last_internet_event_ts = time.time()
        self._log("info", "internet available")

    def on_internet_lost(self, agent):
        self.internet_available = False
        self._log("info", "internet lost")

    # --------------------------
    # Web UI hooks
    # --------------------------
    def on_webhook(self, path, request):
        try:
            path = (path or "").strip("/")
            if request.method == "POST":
                return self._handle_web_post(path, request)
            return self._handle_web_get(path, request)
        except Exception as e:
            self._log("error", f"webhook error: {e}\n{traceback.format_exc()}")
            return self._html_page("Wpa-sec Upload Manager - Error", f"<h1>Wpa-sec Upload Manager</h1><p>Error: {escape(str(e))}</p>")

    def _handle_web_get(self, path, request):
        qs = getattr(request, "args", None)
        action = (qs.get("action") if qs else None) or ""
        target = (qs.get("target") if qs else None) or None
        if target:
            target = unquote_plus(target)

        message = ""
        if action:
            msg = self._dispatch_web_action(action, target, None)
            message = f"<p><strong>{escape(msg)}</strong></p><script>if(window.history&&window.history.replaceState){{window.history.replaceState({{}}, document.title, window.location.pathname);}}</script>"

        sort_key = (qs.get("sort") if qs else None) or self.options.get("web_sort", "name")
        filter_key = (qs.get("filter") if qs else None) or "all"
        body = message + self._render_dashboard(sort_key=sort_key, filter_key=filter_key)
        return self._html_page("Upload Manager", body)

    def _handle_web_post(self, path, request):
        form = getattr(request, "form", None)
        action = None
        target = None
        if form:
            action = form.get("action")
            target = form.get("target")
        if not action:
            raw = getattr(request, "data", b"")
            if raw:
                parsed = parse_qs(raw.decode("utf-8", errors="ignore"))
                action = parsed.get("action", [None])[0]
                target = parsed.get("target", [None])[0]

        msg = self._dispatch_web_action(action or "", target)
        body = f"""
        <h1>Wpa-sec Upload Manager</h1>
        <p><strong>{escape(msg)}</strong></p>
        <p>Redirecting...</p>
        <script>
        setTimeout(function() {{
            window.location.href = '/plugins/upload_manager';
        }}, 500);
        </script>
        """
        return self._html_page("Upload Manager", body)

    def _dispatch_web_action(self, action: str, target: Optional[str], payload: Optional[Dict[str, str]] = None) -> str:
        action = (action or "").strip().lower()
        if action == "toggle_wpa_sec":
            self.options["enable_wpa_sec"] = not self.options.get("enable_wpa_sec", True)
            self._save_db()
            return f"wpa-sec uploads {'enabled' if self.options['enable_wpa_sec'] else 'disabled'}."
        if action == "toggle_dup_uploads":
            self.options["allow_duplicate_ssid_uploads"] = not self.options.get("allow_duplicate_ssid_uploads", False)
            self._save_db()
            return f"Duplicate SSID uploads {'allowed' if self.options['allow_duplicate_ssid_uploads'] else 'prevented'}."
        if action == "retry_all":
            self._cmd_retry_all()
            return "Retry-all queued."
        if action == "retry_failed":
            self._cmd_retry_failed()
            return "Retry-failed queued."
        if action == "rescan":
            self._cmd_rescan()
            return "Rescan completed."
        if action == "prune_missing":
            self._cmd_prune_missing()
            return "Prune-missing completed."
        if action == "retry_file" and target:
            self._retry_single_file(target)
            return f"Retry queued for {os.path.basename(target)}."
        if action == "delete_file" and target:
            return self._delete_single_file(target)
        if action == "delete_invalid":
            return self._delete_all_invalid()
        if action == "delete_duplicates":
            return self._delete_all_duplicates()
        if action == "reset_uploads":
            return self._reset_uploaded_ssids()
        return "No action taken."

    def _html_page(self, title: str, body: str) -> str:
        return f"""
        <!doctype html>
        <html>
        <head>
          <meta charset='utf-8'>
          <meta name='viewport' content='width=device-width, initial-scale=1'>
          <title>{escape(title)}</title>
          <style>
            body {{ font-family: system-ui, sans-serif; background:#111827; color:#f3f4f6; margin:0; padding:20px; }}
            h1 {{ margin-top:0; }}
            .cards {{ display:grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap:12px; margin:16px 0; }}
            .card {{ background:#1f2937; border:1px solid #374151; border-radius:14px; padding:14px; }}
            .card .k {{ font-size:12px; color:#9ca3af; }}
            .card .v {{ font-size:28px; font-weight:700; margin-top:4px; }}
            .actions {{ display:flex; gap:10px; flex-wrap:wrap; margin:18px 0; }}
            .actions form, .inline {{ display:inline; }}
            button {{ background:#2563eb; color:white; border:none; border-radius:10px; padding:8px 12px; cursor:pointer; }}
            button:hover {{ filter:brightness(1.08); }}
            .action-link {{ display:inline-block; background:#2563eb; color:white; border:none; border-radius:10px; padding:8px 12px; cursor:pointer; text-decoration:none; }}
            .action-link:hover {{ filter:brightness(1.08); }}
            a {{ color:#93c5fd; text-decoration:none; }}
            .toolbar {{ display:flex; justify-content:space-between; gap:12px; margin:18px 0; flex-wrap:wrap; }}
            .subtle {{ color:#9ca3af; font-size:12px; }}
            .key-panel {{ background:#1f2937; border:1px solid #374151; border-radius:14px; padding:14px; margin:16px 0; }}
            .key-panel h2 {{ margin:0 0 12px 0; font-size:18px; }}
            .key-panel form {{ display:grid; grid-template-columns: 1fr; gap:8px; max-width:640px; }}
            .key-panel input {{ border:1px solid #374151; background:#111827; color:#f3f4f6; border-radius:8px; padding:8px 10px; }}
            table {{ width:100%; border-collapse:collapse; background:#111827; }}
            th, td {{ border-bottom:1px solid #374151; padding:10px 8px; text-align:left; vertical-align:top; font-size:13px; }}
            th {{ color:#9ca3af; font-weight:600; }}
            .fname {{ max-width:360px; word-break:break-all; }}
            .badge {{ display:inline-block; border-radius:999px; padding:3px 8px; font-size:12px; font-weight:700; }}
            .badge-uploaded {{ background:#14532d; color:#bbf7d0; }}
            .badge-pending {{ background:#78350f; color:#fde68a; }}
            .badge-failed {{ background:#7f1d1d; color:#fecaca; }}
            .badge-invalid {{ background:#7c2d12; color:#ffedd5; }}
            .badge-duplicate {{ background:#991b1b; color:#fee2e2; }}
            .badge-filtered, .badge-skipped {{ background:#374151; color:#d1d5db; }}
            .action-link.delete {{ color:#ef4444; text-decoration:underline; }}
          </style>
        </head>
        <body>{body}</body>
        </html>
        """

    def _badge_class(self, status: str) -> str:
        return {
            self.STATUS_UPLOADED: "badge-uploaded",
            self.STATUS_PENDING: "badge-pending",
            self.STATUS_FAILED: "badge-failed",
            self.STATUS_INVALID: "badge-invalid",
            self.STATUS_DUPLICATE: "badge-duplicate",
            self.STATUS_FILTERED: "badge-filtered",
            self.STATUS_SKIPPED: "badge-skipped",
        }.get(status, "badge-filtered")
    
    def _badge_class_for_reason(self, reason: Optional[str]) -> str:
        """Get badge class based on filtered reason."""
        if reason == "duplicate_ssid":
            return "badge-duplicate"
        return "badge-filtered"

    def _sorted_records(self, sort_key: str, filter_key: str) -> List[Tuple[str, Dict[str, Any]]]:
        with self._db_lock:
            items = list(self._db["files"].items())

        def include(rec: Dict[str, Any]) -> bool:
            w = rec["services"]["wpa_sec"]["status"]
            if filter_key == "pending":
                return self.STATUS_PENDING == w
            if filter_key == "invalid":
                return self.STATUS_INVALID == w
            if filter_key == "duplicate":
                return self.STATUS_DUPLICATE == w
            if filter_key == "failed":
                return self.STATUS_FAILED == w
            if filter_key == "uploaded":
                return self.STATUS_UPLOADED == w
            return True

        items = [(p, r) for p, r in items if include(r)]

        if sort_key == "mtime":
            items.sort(key=lambda x: x[1].get("mtime", 0), reverse=True)
        elif sort_key == "size":
            items.sort(key=lambda x: x[1].get("size", 0), reverse=True)
        else:
            items.sort(key=lambda x: x[1].get("name", "").lower())
        return items

    # --------------------------
    # Core worker loop
    # --------------------------
    def _worker_loop(self):
        self._log("info", "worker started")
        while self.running:
            try:
                self._handle_trigger_files()
                self._scan_files(prune_missing=self.options.get("prune_missing", False))
                if self._internet_status():
                    self._attempt_uploads()
                self._save_db()
                self._consecutive_errors = 0
            except Exception as e:
                self._consecutive_errors += 1
                self._log("error", f"worker error: {e}\n{traceback.format_exc()}")
                if self._consecutive_errors >= int(self.options["max_consecutive_errors"]):
                    self._log("error", "too many consecutive errors; sleeping extra")
                    time.sleep(60)
            time.sleep(int(self.options["scan_interval"]))

    # --------------------------
    # Discovery and state
    # --------------------------
    def _scan_files(self, prune_missing: bool = False):
        scan_roots = self._scan_roots()
        for root in scan_roots:
            os.makedirs(root, exist_ok=True)
        seen_paths = set()
        file_count = 0
        for root in scan_roots:
            if bool(self.options.get("scan_recursive", True)):
                for dirpath, _, filenames in os.walk(root):
                    for filename in filenames:
                        if not filename.lower().endswith((".pcap", ".cap", ".pcapng")):
                            continue
                        full_path = os.path.join(dirpath, filename)
                        try:
                            stat = os.stat(full_path)
                        except OSError:
                            continue
                        file_count += 1
                        seen_paths.add(full_path)
                        if stat.st_size < int(self.options["min_file_size"]):
                            self._register_or_update_file(full_path, stat, filtered_reason="too_small")
                            continue
                        age = time.time() - stat.st_mtime
                        if age < int(self.options["min_file_age"]):
                            self._register_or_update_file(full_path, stat, filtered_reason="too_new")
                            continue
                        if self._is_whitelisted(filename):
                            self._register_or_update_file(full_path, stat, filtered_reason="whitelisted")
                            continue
                        self._register_or_update_file(full_path, stat, filtered_reason=None)
            else:
                for entry in os.scandir(root):
                    if not entry.is_file() or not entry.name.lower().endswith((".pcap", ".cap", ".pcapng")):
                        continue
                    full_path = entry.path
                    seen_paths.add(full_path)
                    file_count += 1
                    stat = entry.stat()
                    if stat.st_size < int(self.options["min_file_size"]):
                        self._register_or_update_file(full_path, stat, filtered_reason="too_small")
                        continue
                    age = time.time() - stat.st_mtime
                    if age < int(self.options["min_file_age"]):
                        self._register_or_update_file(full_path, stat, filtered_reason="too_new")
                        continue
                    if self._is_whitelisted(entry.name):
                        self._register_or_update_file(full_path, stat, filtered_reason="whitelisted")
                        continue
                    self._register_or_update_file(full_path, stat, filtered_reason=None)

        self._log("info", f"scan complete: roots={scan_roots} files_seen={file_count}")
        
        # Mark duplicate SSIDs (keep first one, mark rest as duplicates if duplicates disabled)
        if not self.options.get("allow_duplicate_ssid_uploads", False):
            self._mark_duplicate_ssids()

        if prune_missing:
            with self._db_lock:
                to_remove = [p for p in self._db["files"].keys() if p not in seen_paths]
                for path in to_remove:
                    self._log("info", f"pruning missing file from db: {path}")
                    self._db["files"].pop(path, None)

    def _register_or_update_file(self, path: str, stat: os.stat_result, filtered_reason: Optional[str]):
        with self._db_lock:
            record = self._db["files"].get(path)
            sha1 = None
            need_hash = record is None or record.get("size") != stat.st_size or record.get("mtime") != stat.st_mtime
            if need_hash:
                sha1 = self._sha1_file(path)

            # Check if this is a pre-existing handshake (older than plugin installation)
            install_ts = self._db.get("meta", {}).get("install_timestamp", 0)
            file_mtime = stat.st_mtime
            is_preexisting = (file_mtime < install_ts) and (record is None)

            if record is None:
                initial_status = self.STATUS_UPLOADED if is_preexisting else None
                self._db["files"][path] = {
                    "path": path,
                    "name": os.path.basename(path),
                    "size": stat.st_size,
                    "mtime": stat.st_mtime,
                    "mtime_iso": self._ts_to_iso(stat.st_mtime),
                    "sha1": sha1,
                    "first_seen": self._utc_now(),
                    "last_seen": self._utc_now(),
                    "filtered_reason": filtered_reason,
                    "services": {
                        "wpa_sec": self._new_service_state(filtered_reason, initial_status=initial_status),
                    },
                }
                # If pre-existing, also track the SSID to prevent "duplicate" uploads
                if is_preexisting:
                    ssid = self._extract_ssid(path)
                    if ssid:
                        if "uploaded_ssids" not in self._db["meta"]:
                            self._db["meta"]["uploaded_ssids"] = []
                        if ssid not in self._db["meta"]["uploaded_ssids"]:
                            self._db["meta"]["uploaded_ssids"].append(ssid)
                            self._log("info", f"pre-existing handshake marked as uploaded: {ssid}")
                return

            record["last_seen"] = self._utc_now()
            record["size"] = stat.st_size
            record["mtime"] = stat.st_mtime
            record["mtime_iso"] = self._ts_to_iso(stat.st_mtime)
            if sha1:
                record["sha1"] = sha1
            prev_filtered = record.get("filtered_reason")
            record["filtered_reason"] = filtered_reason
            if prev_filtered and not filtered_reason:
                s = record["services"]["wpa_sec"]
                if s.get("status") in (self.STATUS_FILTERED, self.STATUS_SKIPPED, self.STATUS_INVALID):
                    s["status"] = self.STATUS_PENDING
                    s["error"] = None
                    s["reason"] = None
            if filtered_reason:
                s = record["services"]["wpa_sec"]
                if s.get("status") != self.STATUS_UPLOADED:
                    # Mark undeletable files as invalid so they can be deleted
                    if filtered_reason in ("too_small", "too_new"):
                        s["status"] = self.STATUS_INVALID
                    else:
                        s["status"] = self.STATUS_FILTERED
                    s["reason"] = filtered_reason
            else:
                # Check if this SSID is a duplicate (already uploaded and duplicates disabled)
                if not self.options.get("allow_duplicate_ssid_uploads", False):
                    ssid = self._extract_ssid(path)
                    uploaded_ssids = set(self._db.get("meta", {}).get("uploaded_ssids", []))
                    if ssid and ssid in uploaded_ssids:
                        s = record["services"]["wpa_sec"]
                        if s.get("status") != self.STATUS_UPLOADED:
                            s["status"] = self.STATUS_DUPLICATE
                            s["reason"] = "duplicate_ssid"

    def _new_service_state(self, filtered_reason: Optional[str], initial_status: Optional[str] = None) -> Dict[str, Any]:
        if initial_status:
            # Use the provided initial status (e.g., for pre-existing files)
            status = initial_status
        elif filtered_reason:
            # Mark undeletable files as invalid so they can be deleted
            if filtered_reason in ("too_small", "too_new"):
                status = self.STATUS_INVALID
            else:
                status = self.STATUS_FILTERED
        else:
            status = self.STATUS_PENDING
        return {"status": status, "reason": filtered_reason, "attempts": 0, "last_attempt": None, "last_success": None, "error": None}

    # --------------------------
    # Upload logic
    # --------------------------
    def _attempt_uploads(self):
        if not self._op_lock.acquire(blocking=False):
            self._log("info", "upload already in progress; skipping")
            return
        try:
            candidates = self._eligible_candidates()
            if not candidates:
                self._log("info", "no eligible uploads this cycle")
                return
            self._log("info", f"eligible files: {len(candidates)}")
            for path, record in candidates:
                if self.options.get("enable_wpa_sec", True):
                    self._maybe_upload_wpasec(path, record)
        finally:
            self._op_lock.release()

    def _eligible_candidates(self) -> List[Tuple[str, Dict[str, Any]]]:
        now = time.time()
        out = []
        with self._db_lock:
            uploaded_ssids = set(self._db.get("meta", {}).get("uploaded_ssids", []))
            for path, record in self._db["files"].items():
                if not os.path.exists(path) or record.get("filtered_reason"):
                    continue
                # Skip if SSID already uploaded (unless duplicates are allowed)
                if not self.options.get("allow_duplicate_ssid_uploads", False):
                    ssid = self._extract_ssid(path)
                    if ssid and ssid in uploaded_ssids:
                        continue
                eligible = False
                svc_name = "wpa_sec"
                svc = record["services"][svc_name]
                # Skip files that shouldn't be uploaded
                if not self._should_try_service(svc):
                    continue
                if svc["status"] == self.STATUS_PENDING:
                    eligible = True
                elif svc["status"] == self.STATUS_FAILED:
                    last_attempt_ts = self._iso_to_ts(svc.get("last_attempt")) or 0
                    if now - last_attempt_ts >= int(self.options["retry_backoff_seconds"]):
                        eligible = True
                if eligible:
                    out.append((path, record))
        return out

    def _extract_ssid(self, path: str) -> Optional[str]:
        """Extract SSID from filename (format: SSID_BSSID.pcap)."""
        try:
            filename = os.path.basename(path)
            # Remove .pcap extension
            name_without_ext = filename.rsplit(".", 1)[0]
            # SSID is everything before the last underscore
            if "_" in name_without_ext:
                ssid = name_without_ext.rsplit("_", 1)[0]
                return ssid if ssid else None
            return None
        except Exception:
            return None

    def _maybe_upload_wpasec(self, path: str, record: Dict[str, Any]):
        api_key = str(self.options.get("wpa_sec_api_key", "")).strip()
        if not api_key:
            self._mark_service_skipped(record, "wpa_sec", "missing_api_key")
            return
        state = record["services"]["wpa_sec"]
        if not self._should_try_service(state):
            return
        self._mark_attempt(record, "wpa_sec")

        try:
            url = self.options["wpasec_url"]
            timeout = (int(self.options["connect_timeout"]), int(self.options["read_timeout"]))
            with open(path, "rb") as fh:
                files = {"file": (os.path.basename(path), fh, "application/vnd.tcpdump.pcap")}
                cookies = {"key": api_key}
                headers = {"User-Agent": "Mozilla/5.0"}
                r = self._session.post(url, files=files, cookies=cookies, headers=headers, timeout=timeout)
            body_preview = self._safe_response_preview(r)
            body_lower = body_preview.lower()
            if r.status_code == 200:
                if "no valid handshakes" in body_lower or "no pmkids" in body_lower:
                    record["invalid_handshake"] = True
                    state["status"] = self.STATUS_INVALID
                    state["reason"] = "no_valid_handshakes"
                    state["error"] = None
                    state["attempts"] = 0
                    self._log("info", f"wpa-sec: {path} has no valid handshakes")
                elif "already submitted" in body_lower or "already uploaded" in body_lower:
                    self._mark_success(record, "wpa_sec", "already_submitted", path)
                    self._log("info", f"wpa-sec: {path} already submitted")
                elif body_preview.strip():
                    self._mark_success(record, "wpa_sec", "uploaded", path)
                    self._log("info", f"wpa-sec uploaded: {path} ({r.status_code}) {body_preview}")
                else:
                    self._mark_failure(record, "wpa_sec", f"http_{r.status_code}: empty_response")
            else:
                self._mark_failure(record, "wpa_sec", f"http_{r.status_code}: {body_preview}")
                self._log("warning", f"wpa-sec upload failed: {path} ({r.status_code}) {body_preview}")
        except Exception as e:
            self._mark_failure(record, "wpa_sec", str(e))
            self._log("error", f"wpa-sec exception for {path}: {e}")

    def _should_try_service(self, state: Dict[str, Any]) -> bool:
        if state["status"] == self.STATUS_UPLOADED:
            return False
        if state["status"] in (self.STATUS_FILTERED, self.STATUS_SKIPPED, self.STATUS_INVALID, self.STATUS_DUPLICATE):
            return False
        if int(state.get("attempts", 0)) >= int(self.options["max_retries"]):
            return False
        return True

    # --------------------------
    # Trigger files / commands
    # --------------------------
    def _handle_trigger_files(self):
        cmd_dir = self.options["command_dir"]
        os.makedirs(cmd_dir, exist_ok=True)
        triggers = {
            "retry_all.trigger": self._cmd_retry_all,
            "retry_failed.trigger": self._cmd_retry_failed,
            "rescan.trigger": self._cmd_rescan,
            "prune_missing.trigger": self._cmd_prune_missing,
        }
        for filename, handler in triggers.items():
            path = os.path.join(cmd_dir, filename)
            if os.path.exists(path):
                self._log("info", f"trigger detected: {filename}")
                handler()
                if self.options.get("delete_trigger_files", True):
                    try:
                        os.remove(path)
                    except OSError:
                        pass

    def _cmd_retry_all(self):
        with self._db_lock:
            for record in self._db["files"].values():
                if record.get("filtered_reason"):
                    continue
                state = record["services"]["wpa_sec"]
                state.update({"status": self.STATUS_PENDING, "error": None, "reason": None, "attempts": 0})
        self._log("info", "command completed: retry_all")

    def _cmd_retry_failed(self):
        with self._db_lock:
            for record in self._db["files"].values():
                state = record["services"]["wpa_sec"]
                if state["status"] == self.STATUS_FAILED:
                    state["status"] = self.STATUS_PENDING
                    state["error"] = None
        self._log("info", "command completed: retry_failed")

    def _cmd_rescan(self):
        self._scan_files(prune_missing=False)
        self._log("info", "command completed: rescan")

    def _cmd_prune_missing(self):
        self._scan_files(prune_missing=True)
        self._log("info", "command completed: prune_missing")

    def _retry_single_file(self, target: str):
        with self._db_lock:
            rec = self._db["files"].get(target)
            if not rec:
                return
            if rec.get("filtered_reason"):
                rec["filtered_reason"] = None
            rec["services"]["wpa_sec"]["status"] = self.STATUS_PENDING
            rec["services"]["wpa_sec"]["error"] = None
            rec["services"]["wpa_sec"]["reason"] = None
            # Allow re-upload by removing from uploaded SSIDs
            ssid = self._extract_ssid(target)
            if ssid and "uploaded_ssids" in self._db["meta"]:
                self._db["meta"]["uploaded_ssids"] = [s for s in self._db["meta"]["uploaded_ssids"] if s != ssid]
        self._log("info", f"command completed: retry_file {target}")

    def _delete_single_file(self, target: str) -> str:
        """Delete a single file from disk and database."""
        try:
            if os.path.exists(target):
                os.remove(target)
                self._log("info", f"deleted file: {target}")
            with self._db_lock:
                if target in self._db["files"]:
                    del self._db["files"][target]
            self._save_db()
            return f"Deleted {os.path.basename(target)}."
        except Exception as e:
            self._log("error", f"failed to delete {target}: {e}")
            return f"Failed to delete {os.path.basename(target)}: {e}"

    def _delete_all_invalid(self) -> str:
        """Delete all files marked as invalid."""
        deleted_count = 0
        failed_count = 0
        with self._db_lock:
            targets_to_delete = []
            for path, rec in list(self._db["files"].items()):
                if rec["services"]["wpa_sec"]["status"] == self.STATUS_INVALID:
                    targets_to_delete.append(path)
            
            for target in targets_to_delete:
                try:
                    if os.path.exists(target):
                        os.remove(target)
                        deleted_count += 1
                        self._log("info", f"deleted invalid file: {target}")
                    if target in self._db["files"]:
                        del self._db["files"][target]
                except Exception as e:
                    failed_count += 1
                    self._log("error", f"failed to delete {target}: {e}")
        
        self._save_db()
        msg = f"Deleted {deleted_count} invalid files."
        if failed_count > 0:
            msg += f" ({failed_count} failed)"
        return msg

    def _delete_all_duplicates(self) -> str:
        """Delete all files marked as duplicates."""
        deleted_count = 0
        failed_count = 0
        with self._db_lock:
            targets_to_delete = []
            for path, rec in list(self._db["files"].items()):
                if rec["services"]["wpa_sec"]["status"] == self.STATUS_DUPLICATE:
                    targets_to_delete.append(path)
            
            for target in targets_to_delete:
                try:
                    if os.path.exists(target):
                        os.remove(target)
                        deleted_count += 1
                        self._log("info", f"deleted duplicate file: {target}")
                    if target in self._db["files"]:
                        del self._db["files"][target]
                except Exception as e:
                    failed_count += 1
                    self._log("error", f"failed to delete {target}: {e}")
        
        self._save_db()
        msg = f"Deleted {deleted_count} duplicate files."
        if failed_count > 0:
            msg += f" ({failed_count} failed)"
        return msg

    def _reset_uploaded_ssids(self) -> str:
        """Clear the uploaded SSID tracking list for testing (doesn't reset duplicates)."""
        with self._db_lock:
            if "uploaded_ssids" in self._db.get("meta", {}):
                count = len(self._db["meta"]["uploaded_ssids"])
                self._db["meta"]["uploaded_ssids"] = []
                # Only reset UPLOADED files back to pending (NOT duplicates)
                for rec in self._db["files"].values():
                    s = rec["services"]["wpa_sec"]
                    if s.get("status") == self.STATUS_UPLOADED:
                        s["status"] = self.STATUS_PENDING
                        s["reason"] = None
        # Re-mark duplicates based on SSID, not uploaded list
        if not self.options.get("allow_duplicate_ssid_uploads", False):
            self._mark_duplicate_ssids()
        self._save_db()
        self._log("info", f"reset uploaded SSID tracking: cleared {count} entries")
        return f"Upload tracking reset. {count} files eligible for re-upload (duplicates preserved)."

    # --------------------------
    # DB persistence
    # --------------------------
    def _load_db(self):
        db_path = self.options["db_path"]
        if not os.path.exists(db_path):
            self._log("info", f"db not found, starting fresh: {db_path}")
            self._db = {"meta": {"version": 1, "created": self._utc_now()}, "files": {}}
            return
        try:
            with open(db_path, "r", encoding="utf-8") as fh:
                self._db = json.load(fh)
            self._log("info", f"db loaded: {db_path}")
        except Exception as e:
            self._log("error", f"failed loading db: {e}")
            self._db = {"meta": {"version": 1, "created": self._utc_now()}, "files": {}}

    def _save_db(self):
        db_path = self.options["db_path"]
        tmp_path = f"{db_path}.tmp"
        with self._db_lock:
            self._db.setdefault("meta", {})
            self._db["meta"]["last_saved"] = self._utc_now()
            self._db["meta"]["enable_wpa_sec"] = self.options.get("enable_wpa_sec", True)
            self._db["meta"]["allow_duplicate_ssid_uploads"] = self.options.get("allow_duplicate_ssid_uploads", False)
            data = json.dumps(self._db, indent=2, sort_keys=True)
        with open(tmp_path, "w", encoding="utf-8") as fh:
            fh.write(data)
        os.replace(tmp_path, db_path)

    # --------------------------
    # Helpers: state mutation
    # --------------------------
    def _mark_attempt(self, record: Dict[str, Any], service: str):
        with self._db_lock:
            s = record["services"][service]
            s["last_attempt"] = self._utc_now()
            s["attempts"] = int(s.get("attempts", 0)) + 1

    def _mark_success(self, record: Dict[str, Any], service: str, reason: str, path: Optional[str] = None):
        with self._db_lock:
            s = record["services"][service]
            s["status"] = self.STATUS_UPLOADED
            s["last_success"] = self._utc_now()
            s["error"] = None
            s["reason"] = reason
            # Track uploaded SSID to prevent duplicates
            if path:
                ssid = self._extract_ssid(path)
                if ssid:
                    if "uploaded_ssids" not in self._db["meta"]:
                        self._db["meta"]["uploaded_ssids"] = []
                    if ssid not in self._db["meta"]["uploaded_ssids"]:
                        self._db["meta"]["uploaded_ssids"].append(ssid)

    def _mark_failure(self, record: Dict[str, Any], service: str, error: str):
        with self._db_lock:
            s = record["services"][service]
            s["status"] = self.STATUS_FAILED
            s["error"] = error[:500]

    def _mark_service_skipped(self, record: Dict[str, Any], service: str, reason: str):
        with self._db_lock:
            s = record["services"][service]
            if s["status"] != self.STATUS_UPLOADED:
                s["status"] = self.STATUS_SKIPPED
                s["reason"] = reason

    # --------------------------
    # Helpers: files / hash / log
    # --------------------------
    def _ensure_parent_dirs(self):
        for k in ("db_path", "log_path"):
            path = self.options.get(k)
            if path:
                os.makedirs(os.path.dirname(path), exist_ok=True)
        os.makedirs(self.options["handshake_dir"], exist_ok=True)
        os.makedirs(self.options["command_dir"] or self.options["handshake_dir"], exist_ok=True)

    def _setup_logging(self):
        self._logger = logging.getLogger("upload_manager")
        self._logger.setLevel(logging.INFO)
        self._logger.handlers = []
        handler = logging.FileHandler(self.options["log_path"])
        handler.setFormatter(logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s"))
        self._logger.addHandler(handler)
        self._logger.propagate = False

    def _log(self, level: str, message: str):
        try:
            getattr(self._logger, level.lower())(message)
        except Exception:
            pass
        try:
            getattr(logging, level.lower())(f"[upload_manager] {message}")
        except Exception:
            pass

    def _sha1_file(self, path: str) -> str:
        h = hashlib.sha1()
        block_size = int(self.options.get("hash_block_size", 1024 * 1024))
        with open(path, "rb") as fh:
            while True:
                chunk = fh.read(block_size)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()

    def _mark_duplicate_ssids(self):
        """Scan database and mark duplicate SSIDs (extras) as DUPLICATE status."""
        with self._db_lock:
            uploaded_ssids = set(self._db.get("meta", {}).get("uploaded_ssids", []))
            
            # Group files by SSID
            ssids = {}
            for path, rec in self._db["files"].items():
                if rec.get("filtered_reason"):  # Skip filtered files
                    continue
                ssid = self._extract_ssid(path)
                if ssid:
                    if ssid not in ssids:
                        ssids[ssid] = []
                    ssids[ssid].append(path)
            
            # Mark duplicates (keep uploaded one, or first if none uploaded)
            for ssid, paths in ssids.items():
                if len(paths) > 1:
                    # Find the uploaded one (if any)
                    keep_path = None
                    if ssid in uploaded_ssids:
                        # Find which file is uploaded
                        for p in paths:
                            if self._db["files"][p]["services"]["wpa_sec"].get("status") == self.STATUS_UPLOADED:
                                keep_path = p
                                break
                    
                    # If none uploaded yet, keep the first one for uploading
                    if not keep_path:
                        keep_path = paths[0]
                    
                    # Mark all others as DUPLICATE
                    for path in paths:
                        if path != keep_path:
                            rec = self._db["files"][path]
                            s = rec["services"]["wpa_sec"]
                            if s.get("status") != self.STATUS_DUPLICATE:
                                s["status"] = self.STATUS_DUPLICATE
                                s["reason"] = "duplicate_ssid"

    def _is_whitelisted(self, filename: str) -> bool:
        for item in self.options.get("whitelist", []):
            if str(item).lower() in filename.lower():
                return True
        return False

    def _safe_response_preview(self, response: requests.Response) -> str:
        try:
            return response.text.strip().replace("\n", " ")[:250]
        except Exception:
            return "<no-body>"

    def _internet_status(self) -> bool:
        now = time.time()

        # Trust a fresh lifecycle callback event for a short period.
        if self.internet_available and (now - self._last_internet_event_ts) <= 90:
            return True

        # Probe at most every 20s to keep UI responsive and avoid socket spam.
        if now - self._internet_probe_ts < 20:
            return self._internet_probe_cache

        self._internet_probe_ts = now
        try:
            sock = socket.create_connection(("1.1.1.1", 53), timeout=2)
            sock.close()
            self._internet_probe_cache = True
            self.internet_available = True
            return True
        except OSError:
            self._internet_probe_cache = False
            self.internet_available = False
            return False

    def _scan_roots(self) -> List[str]:
        roots = []
        primary = str(self.options.get("handshake_dir") or "").strip()
        if primary:
            roots.append(primary)
        for item in self.options.get("extra_handshake_dirs", []) or []:
            item = str(item).strip()
            if item and item not in roots:
                roots.append(item)
        return roots

    def _counts(self) -> Dict[str, int]:
        counts = {"files": 0, "wpa_sec_uploaded": 0, "wpa_sec_pending": 0, "failed_total": 0, "filtered": 0, "skipped": 0, "invalid": 0, "duplicate": 0}
        with self._db_lock:
            for record in self._db["files"].values():
                counts["files"] += 1
                if record.get("filtered_reason"):
                    counts["filtered"] += 1
                svc_name = "wpa_sec"
                state = record["services"][svc_name]["status"]
                if state == self.STATUS_UPLOADED:
                    counts["wpa_sec_uploaded"] += 1
                elif state == self.STATUS_PENDING:
                    counts["wpa_sec_pending"] += 1
                elif state == self.STATUS_INVALID:
                    counts["invalid"] += 1
                elif state == self.STATUS_DUPLICATE:
                    counts["duplicate"] += 1
                if state == self.STATUS_FAILED:
                    counts["failed_total"] += 1
                if state == self.STATUS_SKIPPED:
                    counts["skipped"] += 1
        return counts

    def _human_size(self, value: int) -> str:
        size = float(value)
        for unit in ["B", "KB", "MB", "GB"]:
            if size < 1024 or unit == "GB":
                return f"{size:.1f}{unit}" if unit != "B" else f"{int(size)}B"
            size /= 1024
        return f"{int(value)}B"

    # --------------------------
    # Time helpers
    # --------------------------
    def _utc_now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def _ts_to_iso(self, ts: float) -> str:
        return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()

    def _iso_to_ts(self, value: Optional[str]) -> Optional[float]:
        if not value:
            return None
        try:
            return datetime.fromisoformat(value).timestamp()
        except Exception:
            return None


