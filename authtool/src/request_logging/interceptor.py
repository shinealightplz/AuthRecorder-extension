#!/usr/bin/env python3
import json
import logging
from typing import Dict, Optional, Callable
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse, parse_qs
import re

class RequestInterceptor:
    def __init__(self, output_dir: str = "outputs"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self._setup_logging()
        self.token_patterns = {
            'bearer': re.compile(r'Bearer\s+([a-zA-Z0-9\-._~+/]+=*)'),
            'jwt': re.compile(r'eyJ[a-zA-Z0-9\-_]+\.eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+'),
            'csrf': re.compile(r'csrf[_-]token["\']\s*:\s*["\']([^"\']+)["\']'),
        }
        self.callbacks = {
            'on_request': [],
            'on_response': [],
            'on_token': []
        }

    def _setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.output_dir / "interceptor.log"),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger("RequestInterceptor")

    def on_request(self, callback: Callable):
        """Register callback for request interception"""
        self.callbacks['on_request'].append(callback)
        return callback

    def on_response(self, callback: Callable):
        """Register callback for response interception"""
        self.callbacks['on_response'].append(callback)
        return callback

    def on_token(self, callback: Callable):
        """Register callback for token detection"""
        self.callbacks['on_token'].append(callback)
        return callback

    def intercept_request(self, request_data: Dict):
        """Process intercepted request"""
        # Extract request details
        method = request_data.get('method', 'GET')
        url = request_data.get('url', '')
        headers = request_data.get('headers', {})
        cookies = request_data.get('cookies', {})
        body = request_data.get('body')

        # Look for authentication tokens in headers
        auth_header = headers.get('Authorization', '')
        if auth_header:
            self._process_auth_header(auth_header)

        # Check for tokens in cookies
        self._process_cookies(cookies)

        # Check for tokens in request body
        if body:
            self._process_body(body)

        # Notify request callbacks
        for callback in self.callbacks['on_request']:
            try:
                callback(request_data)
            except Exception as e:
                self.logger.error(f"Error in request callback: {e}")

    def intercept_response(self, response_data: Dict):
        """Process intercepted response"""
        # Extract response details
        status = response_data.get('status')
        headers = response_data.get('headers', {})
        cookies = response_data.get('cookies', {})
        body = response_data.get('body')

        # Process response headers for tokens
        for header, value in headers.items():
            if any(pattern in header.lower() for pattern in ['token', 'auth', 'jwt']):
                self._notify_token_callbacks('header', value, header)

        # Process response cookies
        self._process_cookies(cookies)

        # Process response body for tokens
        if body:
            self._process_body(body)

        # Notify response callbacks
        for callback in self.callbacks['on_response']:
            try:
                callback(response_data)
            except Exception as e:
                self.logger.error(f"Error in response callback: {e}")

    def _process_auth_header(self, auth_header: str):
        """Process Authorization header for tokens"""
        for token_type, pattern in self.token_patterns.items():
            match = pattern.search(auth_header)
            if match:
                token = match.group(1)
                self._notify_token_callbacks(token_type, token, 'Authorization header')

    def _process_cookies(self, cookies: Dict):
        """Process cookies for tokens"""
        for name, value in cookies.items():
            if any(key in name.lower() for key in ['token', 'auth', 'jwt', 'sess']):
                self._notify_token_callbacks('cookie', value, name)

    def _process_body(self, body: str):
        """Process request/response body for tokens"""
        try:
            if isinstance(body, str):
                # Try to parse as JSON
                try:
                    data = json.loads(body)
                    self._process_json(data)
                except json.JSONDecodeError:
                    # Check for tokens in raw string
                    self._process_raw_body(body)
            elif isinstance(body, dict):
                self._process_json(body)
        except Exception as e:
            self.logger.error(f"Error processing body: {e}")

    def _process_json(self, data: Dict):
        """Process JSON data for tokens"""
        def recursive_search(obj, path=""):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if any(key in k.lower() for key in ['token', 'auth', 'jwt']):
                        self._notify_token_callbacks('json', v, f"{path}/{k}")
                    recursive_search(v, f"{path}/{k}")
            elif isinstance(obj, list):
                for i, v in enumerate(obj):
                    recursive_search(v, f"{path}[{i}]")

        recursive_search(data)

    def _process_raw_body(self, body: str):
        """Process raw body content for tokens"""
        for token_type, pattern in self.token_patterns.items():
            for match in pattern.finditer(body):
                token = match.group(1)
                self._notify_token_callbacks(token_type, token, 'response body')

    def _notify_token_callbacks(self, token_type: str, token_value: str, source: str):
        """Notify token callbacks of detected tokens"""
        for callback in self.callbacks['on_token']:
            try:
                callback(token_type, token_value, source)
            except Exception as e:
                self.logger.error(f"Error in token callback: {e}")
