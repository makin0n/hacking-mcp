import aiohttp
import asyncio
import sys
import time
import re
from urllib.parse import urljoin, urlparse
from typing import List, Dict, Optional, Set
from playwright.async_api import async_playwright
import os


class WebScanner:
    def __init__(self):
        self.timeout = aiohttp.ClientTimeout(total=15)
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Compatible Security Scanner)'
        }
        
        # 一般的なディレクトリ・ファイル名
        self.common_dirs = [
            'admin', 'administrator', 'login', 'panel', 'control', 'dashboard',
            'wp-admin', 'phpmyadmin', 'cpanel', 'webmail', 'mail',
            'api', 'rest', 'v1', 'v2', 'graphql',
            'backup', 'backups', 'bak', 'old', 'tmp', 'temp',
            'test', 'dev', 'staging', 'beta', 'demo',
            'uploads', 'upload', 'files', 'images', 'img', 'assets',
            'js', 'css', 'static', 'public', 'private',
            'config', 'conf', 'settings', 'env'
        ]
        
        self.common_files = [
            'robots.txt', 'sitemap.xml', 'crossdomain.xml', 'clientaccesspolicy.xml',
            'favicon.ico', '.htaccess', '.htpasswd', 'web.config',
            'config.php', 'config.inc.php', 'configuration.php',
            'settings.php', 'wp-config.php', 'database.php',
            'readme.txt', 'readme.html', 'changelog.txt',
            'phpinfo.php', 'info.php', 'test.php',
            '.env', '.env.local', '.env.production', 'env.js',
            'backup.sql', 'database.sql', 'dump.sql'
        ]
        
        # 技術検出パターン
        self.tech_patterns = {
            'WordPress': [
                r'/wp-content/', r'/wp-includes/', r'wp-json',
                r'WordPress', r'wp-admin'
            ],
            'Drupal': [
                r'/sites/default/', r'/modules/', r'/themes/',
                r'Drupal', r'drupal'
            ],
            'Joomla': [
                r'/components/', r'/modules/', r'/templates/',
                r'Joomla', r'joomla'
            ],
            'Apache': [
                r'Apache/', r'Server: Apache'
            ],
            'Nginx': [
                r'nginx/', r'Server: nginx'
            ],
            'IIS': [
                r'IIS/', r'Server: Microsoft-IIS'
            ],
            'PHP': [
                r'X-Powered-By: PHP', r'\.php', r'PHP/'
            ],
            'ASP.NET': [
                r'X-AspNet-Version', r'X-Powered-By: ASP.NET',
                r'\.aspx', r'\.ashx'
            ],
            'Node.js': [
                r'X-Powered-By: Express', r'Express',
                r'Node.js'
            ],
            'React': [
                r'react', r'React', r'__REACT_DEVTOOLS'
            ],
            'Angular': [
                r'ng-version', r'Angular', r'angular'
            ],
            'Vue.js': [
                r'Vue\.js', r'vue', r'__VUE__'
            ],
            'jQuery': [
                r'jquery', r'jQuery'
            ]
        }
    
    def _validate_url(self, url: str) -> Optional[str]:
        """URL検証と正規化"""
        if not url or not url.strip():
            return None
        
        url = url.strip()
        
        if not url.startswith(('http://', 'https://')):
            url = f"https://{url}"
        
        try:
            parsed = urlparse(url)
            if not parsed.netloc:
                return None
            return url
        except:
            return None
    
    async def get_status(self) -> str:
        """Webスキャナーの状態を確認"""
        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.get('https://httpbin.org/status/200') as response:
                    if response.status == 200:
                        return "Available - HTTP client working with technology detection"
                    else:
                        return f"Available - but test returned {response.status}"
        except Exception as e:
            return f"Available - aiohttp ready (test failed: {str(e)})"
    
    async def check_headers(self, url: str) -> str:
        """WebサイトのHTTPヘッダーを確認"""
        validated_url = self._validate_url(url)
        if not validated_url:
            return "Error: Invalid URL format"
        
        try:
            async with aiohttp.ClientSession(timeout=self.timeout, headers=self.headers) as session:
                start_time = time.time()
                async with session.head(validated_url, allow_redirects=True) as response:
                    response_time = round((time.time() - start_time) * 1000, 2)
                    
                    headers_info = [
                        "=== HTTP HEADERS ===",
                        f"URL: {str(response.url)}",
                        f"Status: {response.status} {response.reason}",
                        f"Response Time: {response_time}ms",
                        "",
                        "Response Headers:"
                    ]
                    for header, value in response.headers.items():
                        headers_info.append(f"  {header}: {value}")
                    
                    return "\n".join(headers_info)
                    
        except aiohttp.ClientError as e:
            return f"Error connecting to {validated_url}: {str(e)}"
        except Exception as e:
            return f"Error checking headers: {str(e)}"
    
    async def check_security_headers(self, url: str) -> str:
        """セキュリティ関連のHTTPヘッダーをチェック"""
        validated_url = self._validate_url(url)
        if not validated_url:
            return "Error: Invalid URL format"
        
        try:
            async with aiohttp.ClientSession(timeout=self.timeout, headers=self.headers) as session:
                async with session.head(validated_url, allow_redirects=True) as response:
                    security_headers = {
                        'X-Frame-Options': 'クリックジャッキング対策',
                        'X-Content-Type-Options': 'MIME型推測攻撃対策',
                        'X-XSS-Protection': 'XSS攻撃対策（古いブラウザ用）',
                        'Strict-Transport-Security': 'HTTPS強制',
                        'Content-Security-Policy': 'コンテンツ読み込み制御',
                        'Referrer-Policy': 'リファラー情報制御',
                        'Permissions-Policy': '機能へのアクセス制御',
                        'Cross-Origin-Embedder-Policy': 'クロスオリジン埋め込み制御'
                    }
                    
                    result = [
                        "=== SECURITY HEADERS ANALYSIS ===",
                        f"URL: {str(response.url)}",
                        f"Status: {response.status}",
                        "=" * 50
                    ]
                    
                    found_count = 0
                    for header, description in security_headers.items():
                        if header.lower() in [h.lower() for h in response.headers]:
                            result.append(f"✅ {header}")
                            result.append(f"   Value: {response.headers.get(header)}")
                            result.append(f"   説明: {description}")
                            found_count += 1
                        else:
                            result.append(f"❌ {header}: 未設定")
                            result.append(f"   説明: {description}")
                        result.append("")
                    
                    result.append(f"セキュリティヘッダー設定状況: {found_count}/{len(security_headers)} 個設定済み")
                    
                    if found_count < len(security_headers) // 2:
                        result.append("⚠️  セキュリティヘッダーの設定が不十分です")
                    else:
                        result.append("✅ 良好なセキュリティヘッダー設定です")
                    
                    return "\n".join(result)
                    
        except aiohttp.ClientError as e:
            return f"Error connecting to {validated_url}: {str(e)}"
        except Exception as e:
            return f"Error checking security headers: {str(e)}"
    
    async def check_robots_txt(self, url: str) -> str:
        """robots.txtファイルの内容を確認"""
        try:
            parsed = urlparse(url)
            robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
            
            async with aiohttp.ClientSession(timeout=self.timeout, headers=self.headers) as session:
                async with session.get(robots_url) as response:
                    result = [
                        "=== ROBOTS.TXT ANALYSIS ===",
                        f"URL: {robots_url}",
                        f"Status: {response.status}",
                        ""
                    ]
                    
                    if response.status == 200:
                        content = await response.text()
                        result.append("Content:")
                        result.append("-" * 40)
                        result.append(content[:2000])
                        if len(content) > 2000:
                            result.append("... (truncated)")
                    elif response.status == 404:
                        result.append("robots.txt not found (404)")
                    else:
                        result.append(f"Unexpected status: {response.status}")
                    
                    return "\n".join(result)
                    
        except aiohttp.ClientError as e:
            return f"Error checking robots.txt: {str(e)}"
        except Exception as e:
            return f"Error: {str(e)}"
    
    async def get_basic_info(self, url: str) -> str:
        """Webサイトの基本情報を取得"""
        try:
            async with aiohttp.ClientSession(timeout=self.timeout, headers=self.headers) as session:
                start_time = time.time()
                async with session.get(url, allow_redirects=True) as response:
                    response_time = round((time.time() - start_time) * 1000, 2)
                    
                    result = [
                        "=== WEB BASIC INFORMATION ===",
                        f"URL: {str(response.url)}",
                        f"Status: {response.status} {response.reason}",
                        f"Response Time: {response_time}ms",
                        ""
                    ]
                    
                    important_headers = ['Server', 'Content-Type', 'Content-Length', 'Last-Modified', 'ETag']
                    result.append("Important Headers:")
                    for header in important_headers:
                        if header in response.headers:
                            result.append(f"  {header}: {response.headers[header]}")
                    
                    if str(response.url).startswith('https://'):
                        result.append("SSL/TLS: Enabled")
                    
                    content_length = response.headers.get('Content-Length')
                    if content_length:
                        result.append(f"Content Size: {round(int(content_length) / 1024, 2)} KB")
                    
                    return "\n".join(result)
                    
        except aiohttp.ClientError as e:
            return f"Error connecting to {url}: {str(e)}"
        except Exception as e:
            return f"Error getting basic info: {str(e)}"
    
    async def technology_detection(self, url: str) -> str:
        """Webサイトで使用されている技術を検出"""
        try:
            async with aiohttp.ClientSession(timeout=self.timeout, headers=self.headers) as session:
                async with session.get(url, allow_redirects=True) as response:
                    content = await response.text()
                    headers_str = str(response.headers)
                    
                    result = [
                        "=== TECHNOLOGY DETECTION ===",
                        f"URL: {str(response.url)}",
                        ""
                    ]
                    
                    detected_techs = {}
                    full_content = headers_str + "\n" + content
                    
                    for tech_name, patterns in self.tech_patterns.items():
                        if any(re.search(p, full_content, re.IGNORECASE) for p in patterns):
                            detected_techs[tech_name] = True
                    
                    if detected_techs:
                        result.append("Detected Technologies:")
                        for tech in detected_techs:
                            result.append(f"  ✅ {tech}")
                    else:
                        result.append("No specific technologies detected.")
                    
                    return "\n".join(result)
                    
        except aiohttp.ClientError as e:
            return f"Error connecting to {url}: {str(e)}"
        except Exception as e:
            return f"Error during technology detection: {str(e)}"
    
    async def directory_scan(self, url: str, wordlist: str = "common") -> str:
        """ディレクトリ・ファイルスキャン"""
        if wordlist == "common": targets = self.common_dirs + self.common_files
        elif wordlist == "dirs": targets = self.common_dirs
        elif wordlist == "files": targets = self.common_files
        else: targets = self.common_dirs + self.common_files
        
        result = [
            "=== DIRECTORY/FILE SCAN ===",
            f"Target: {url}",
            f"Wordlist: {wordlist} ({len(targets)} entries)",
            "Status codes: 200=Found, 403=Forbidden, 401=Auth Required",
            ""
        ]
        
        found_items = []
        
        async def check_path(session, target_path):
            try:
                full_url = urljoin(url, target_path)
                async with session.head(full_url, timeout=10) as response:
                    if response.status in [200, 403, 401, 301, 302]:
                        return f"{response.status} - {target_path}"
            except asyncio.TimeoutError:
                return None
            except aiohttp.ClientError:
                return None
            return None

        async with aiohttp.ClientSession(headers=self.headers) as session:
            tasks = [check_path(session, target) for target in targets]
            for i in range(0, len(tasks), 20):
                chunk = tasks[i:i+20]
                results_chunk = await asyncio.gather(*chunk)
                for item in results_chunk:
                    if item:
                        found_items.append(item)
                print(f"Directory scan progress: {min(i+20, len(tasks))}/{len(tasks)}", file=sys.stderr)

        if found_items:
            result.append("Found paths:")
            result.extend(f"  {item}" for item in sorted(found_items))
        else:
            result.append("No common directories/files found.")
        
        return "\n".join(result)
    
    async def _perform_comprehensive_scan(self, url: str) -> str:
        """実際の包括的スキャンの処理を行うプライベートメソッド"""
        result = [
            f"=== COMPREHENSIVE WEB SCAN ===",
            f"Target: {url}",
            "=" * 60,
            "\n1. Basic Information", "------------------------------", await self.get_basic_info(url),
            "\n2. Technology Detection", "------------------------------", await self.technology_detection(url),
            "\n3. Security Headers", "------------------------------", await self.check_security_headers(url),
            "\n4. robots.txt Analysis", "------------------------------", await self.check_robots_txt(url),
            "\n5. Common Files Scan", "------------------------------", await self.directory_scan(url, "files")
        ]
        return "\n".join(result)

    async def comprehensive_web_scan(self, target: str) -> str:
        """包括的Webスキャン。最初に有効なプロトコルを判別し、そのURLで全ての処理を行う。"""
        if not target.startswith(('http://', 'https://')):
            base_url = target
        else:
            base_url = urlparse(target).netloc
        
        https_url = f"https://{base_url}"
        http_url = f"http://{base_url}"

        workable_url = None
        probe_error_https = ""
        
        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.head(https_url, allow_redirects=True) as response:
                    workable_url = str(response.url).rstrip('/')
                    print(f"[*] Probe successful with HTTPS: {workable_url}", file=sys.stderr)
        except Exception as e:
            probe_error_https = str(e)
            print(f"[-] Probe failed with HTTPS. Falling back to HTTP... ({e})", file=sys.stderr)

            if not workable_url:
                try:
                    async with aiohttp.ClientSession(timeout=self.timeout) as session:
                        async with session.head(http_url, allow_redirects=True) as response:
                            workable_url = str(response.url).rstrip('/')
                            print(f"[*] Probe successful with HTTP: {workable_url}", file=sys.stderr)
                except Exception as e2:
                    return f"Error: Both HTTPS and HTTP probes failed.\n- HTTPS Probe Error: {probe_error_https}\n- HTTP Probe Error: {e2}"
        
        if workable_url:
            return await self._perform_comprehensive_scan(workable_url)
        else:
            return "Error: Could not establish a connection with either HTTPS or HTTP."

    async def take_screenshot(self, url: str, path: str) -> bool:
        """指定されたURLのスクリーンショットを撮影する。HTTPS->HTTPフォールバック対応。"""
        https_url = self._validate_url(url)
        if not https_url: return False
        http_url = https_url.replace('https://', 'http://', 1)

        async def attempt_screenshot(screenshot_url: str):
            async with async_playwright() as p:
                browser = await p.chromium.launch()
                page = await browser.new_page(ignore_https_errors=True)
                await page.goto(screenshot_url, timeout=15000, wait_until='domcontentloaded')
                await page.screenshot(path=path, full_page=True)
                await browser.close()
        
        try:
            print(f"[*] Attempting screenshot: {https_url}", file=sys.stderr)
            await attempt_screenshot(https_url)
            return True
        except Exception as e:
            print(f"[-] HTTPS screenshot failed: {e}. Falling back to HTTP.", file=sys.stderr)
            try:
                print(f"[*] Attempting screenshot: {http_url}", file=sys.stderr)
                await attempt_screenshot(http_url)
                return True
            except Exception as e2:
                print(f"[-] HTTP screenshot also failed: {e2}", file=sys.stderr)
                return False