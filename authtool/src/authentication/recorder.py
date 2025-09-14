#!/usr/bin/env python3
import json
import logging
from typing import Dict, List, Optional
from datetime import datetime
from pathlib import Path

class AuthRecorder:
    def __init__(self, output_dir: str = "outputs"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.session_data = {
            "timestamp": datetime.now().isoformat(),
            "requests": [],
            "cookies": [],
            "headers": [],
            "tokens": []
        }
        self._setup_logging()

    def _setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.output_dir / "authrecorder.log"),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger("AuthRecorder")

    def capture_request(self, request_data: Dict):
        """Record HTTP request data including headers and cookies"""
        self.session_data["requests"].append({
            "timestamp": datetime.now().isoformat(),
            "method": request_data.get("method"),
            "url": request_data.get("url"),
            "headers": request_data.get("headers", {}),
            "cookies": request_data.get("cookies", {}),
            "body": request_data.get("body")
        })
        self.logger.info(f"Captured request to: {request_data.get('url')}")

    def capture_cookies(self, cookies: List[Dict]):
        """Record browser cookies"""
        self.session_data["cookies"].extend([{
            "timestamp": datetime.now().isoformat(),
            "name": cookie.get("name"),
            "value": cookie.get("value"),
            "domain": cookie.get("domain"),
            "path": cookie.get("path"),
            "expires": cookie.get("expires"),
            "httpOnly": cookie.get("httpOnly", False),
            "secure": cookie.get("secure", False)
        } for cookie in cookies])
        self.logger.info(f"Captured {len(cookies)} cookies")

    def capture_headers(self, headers: Dict):
        """Record important headers like authorization tokens"""
        self.session_data["headers"].append({
            "timestamp": datetime.now().isoformat(),
            "headers": headers
        })
        self.logger.info("Captured headers")

    def capture_token(self, token_type: str, token_value: str, source: str):
        """Record authentication tokens (Bearer, JWT, etc.)"""
        self.session_data["tokens"].append({
            "timestamp": datetime.now().isoformat(),
            "type": token_type,
            "value": token_value,
            "source": source
        })
        self.logger.info(f"Captured {token_type} token from {source}")

    def save_session(self, filename: Optional[str] = None):
        """Save recorded session data to file"""
        if not filename:
            filename = f"auth_session_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        output_path = self.output_dir / filename
        with open(output_path, 'w') as f:
            json.dump(self.session_data, f, indent=2)
        
        self.logger.info(f"Saved session data to: {output_path}")
        return output_path

    def clear_session(self):
        """Reset the current session data"""
        self.session_data = {
            "timestamp": datetime.now().isoformat(),
            "requests": [],
            "cookies": [],
            "headers": [],
            "tokens": []
        }
        self.logger.info("Cleared session data")
