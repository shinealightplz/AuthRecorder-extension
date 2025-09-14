#!/usr/bin/env python3
import random
import time
from typing import Dict, List, Optional, Union
from datetime import datetime
import json
import logging
from pathlib import Path
import platform
import os

class StealthManager:
    def __init__(self, output_dir: str = "outputs"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self._setup_logging()
        self._load_profiles()
        self.current_profile = None

    def _setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.output_dir / "stealth.log"),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger("StealthManager")

    def _load_profiles(self):
        """Load browser profiles and user agent configurations"""
        self.profiles = {
            'chrome_windows': {
                'navigator': {
                    'userAgent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.81 Safari/537.36',
                    'platform': 'Win32',
                    'language': 'en-US',
                    'languages': ['en-US', 'en'],
                    'plugins': ['PDF Viewer', 'Chrome PDF Viewer', 'Chromium PDF Viewer']
                },
                'webgl': {
                    'vendor': 'Google Inc. (NVIDIA)',
                    'renderer': 'ANGLE (NVIDIA GeForce GTX 1660 Direct3D11 vs_5_0 ps_5_0)'
                }
            },
            'firefox_linux': {
                'navigator': {
                    'userAgent': 'Mozilla/5.0 (X11; Linux x86_64; rv:93.0) Gecko/20100101 Firefox/93.0',
                    'platform': 'Linux x86_64',
                    'language': 'en-US',
                    'languages': ['en-US', 'en'],
                    'plugins': ['PDF Viewer', 'Firefox PDF Viewer']
                },
                'webgl': {
                    'vendor': 'Mesa/X.org',
                    'renderer': 'Mesa DRI Intel(R) UHD Graphics 620 (Kabylake GT2)'
                }
            }
        }

    def apply_stealth_patches(self, page) -> None:
        """Apply stealth patches to avoid detection"""
        self.current_profile = random.choice(list(self.profiles.keys()))
        profile = self.profiles[self.current_profile]

        # Basic navigator properties
        patches = [
            # Navigator properties
            f"Object.defineProperty(navigator, 'userAgent', {{get: () => '{profile['navigator']['userAgent']}'}});",
            f"Object.defineProperty(navigator, 'platform', {{get: () => '{profile['navigator']['platform']}'}});",
            f"Object.defineProperty(navigator, 'language', {{get: () => '{profile['navigator']['language']}'}});",
            
            # WebGL fingerprinting
            """
            const getParameter = WebGLRenderingContext.prototype.getParameter;
            WebGLRenderingContext.prototype.getParameter = function(parameter) {
                if (parameter === 37445) {
                    return 'Intel Open Source Technology Center';
                }
                if (parameter === 37446) {
                    return 'Mesa DRI Intel(R) Iris(TM) Plus Graphics (ICL GT2)';
                }
                return getParameter.apply(this, arguments);
            };
            """,

            # Prevent automation detection
            """
            Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
            Object.defineProperty(navigator, 'automation', {get: () => undefined});
            """,

            # Add noise to canvas fingerprinting
            """
            const originalGetContext = HTMLCanvasElement.prototype.getContext;
            HTMLCanvasElement.prototype.getContext = function(type) {
                const context = originalGetContext.apply(this, arguments);
                if (type === '2d') {
                    const originalFillText = context.fillText;
                    context.fillText = function() {
                        const args = arguments;
                        args[0] = args[0] + ' ';  // Add slight noise
                        return originalFillText.apply(this, args);
                    }
                }
                return context;
            };
            """
        ]

        # Execute all patches
        for patch in patches:
            try:
                page.evaluate(patch)
            except Exception as e:
                self.logger.error(f"Failed to apply patch: {e}")

    def generate_delays(self, min_delay: float = 0.5, max_delay: float = 2.0) -> float:
        """Generate random delays between actions to mimic human behavior"""
        return random.uniform(min_delay, max_delay)

    def randomize_mouse_movements(self, start_x: int, start_y: int, end_x: int, end_y: int, steps: int = 10) -> List[Dict[str, int]]:
        """Generate human-like mouse movement path"""
        points = []
        for i in range(steps + 1):
            t = i / steps
            # Add some randomness to the path
            rand_x = random.randint(-10, 10)
            rand_y = random.randint(-10, 10)
            
            # Calculate point with bezier curve
            x = start_x + (end_x - start_x) * t + rand_x
            y = start_y + (end_y - start_y) * t + rand_y
            
            points.append({"x": int(x), "y": int(y)})
        return points

    def get_random_headers(self) -> Dict[str, str]:
        """Generate random-looking headers"""
        profile = self.profiles[self.current_profile or random.choice(list(self.profiles.keys()))]
        headers = {
            'User-Agent': profile['navigator']['userAgent'],
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Cache-Control': 'max-age=0'
        }
        return headers

    async def execute_with_timing(self, page, action: callable, min_delay: float = 0.5, max_delay: float = 2.0):
        """Execute an action with random timing delays"""
        # Add random delay before action
        await page.wait_for_timeout(self.generate_delays(min_delay, max_delay) * 1000)
        
        # Execute the action
        result = await action()
        
        # Add random delay after action
        await page.wait_for_timeout(self.generate_delays(min_delay, max_delay) * 1000)
        
        return result

    def save_profile(self, filename: Optional[str] = None):
        """Save current stealth profile to file"""
        if not filename:
            filename = f"stealth_profile_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        output_path = self.output_dir / filename
        with open(output_path, 'w') as f:
            json.dump({
                'timestamp': datetime.now().isoformat(),
                'profile': self.current_profile,
                'settings': self.profiles[self.current_profile] if self.current_profile else None
            }, f, indent=2)
        
        self.logger.info(f"Saved stealth profile to: {output_path}")
        return output_path
