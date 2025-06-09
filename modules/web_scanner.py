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
        self.timeout = aiohttp.ClientTimeout(total=30)
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
    
    def _validate_url(self, url: str) -> str:
        """URL検証と正規化"""
        if not url or not url.strip():
            return None
        
        url = url.strip()
        
        # httpスキームが無い場合は追加
        if not url.startswith(('http://', 'https://')):
            url = f"https://{url}"
        
        # 基本的なURL検証
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
                async with session.head(validated_url) as response:
                    response_time = round((time.time() - start_time) * 1000, 2)
                    
                    headers_info = []
                    headers_info.append("=== HTTP HEADERS ===")
                    headers_info.append(f"URL: {str(response.url)}")
                    headers_info.append(f"Status: {response.status} {response.reason}")
                    headers_info.append(f"Response Time: {response_time}ms")
                    headers_info.append("")
                    
                    headers_info.append("Response Headers:")
                    for header, value in response.headers.items():
                        headers_info.append(f"  {header}: {value}")
                    
                    return "\n".join(headers_info)
                    
        except aiohttp.ClientError as e:
            # HTTPSで失敗した場合はHTTPを試す
            if validated_url.startswith('https://'):
                http_url = validated_url.replace('https://', 'http://', 1)
                try:
                    async with aiohttp.ClientSession(timeout=self.timeout, headers=self.headers) as session:
                        async with session.head(http_url) as response:
                            return f"HTTPS failed, HTTP successful:\nURL: {http_url}\nStatus: {response.status}"
                except:
                    pass
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
                async with session.head(validated_url) as response:
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
                    
                    result = [f"=== SECURITY HEADERS ANALYSIS ==="]
                    result.append(f"URL: {str(response.url)}")
                    result.append(f"Status: {response.status}")
                    result.append("=" * 50)
                    
                    found_count = 0
                    for header, description in security_headers.items():
                        if header in response.headers:
                            result.append(f"✅ {header}")
                            result.append(f"   Value: {response.headers[header]}")
                            result.append(f"   説明: {description}")
                            found_count += 1
                        else:
                            result.append(f"❌ {header}: 未設定")
                            result.append(f"   説明: {description}")
                        result.append("")
                    
                    result.append(f"セキュリティヘッダー設定状況: {found_count}/{len(security_headers)} 個設定済み")
                    
                    if found_count == 0:
                        result.append("⚠️  セキュリティヘッダーが設定されていません")
                    elif found_count < len(security_headers) // 2:
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
        validated_url = self._validate_url(url)
        if not validated_url:
            return "Error: Invalid URL format"
        
        try:
            parsed = urlparse(validated_url)
            robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
            
            async with aiohttp.ClientSession(timeout=self.timeout, headers=self.headers) as session:
                async with session.get(robots_url) as response:
                    result = [f"=== ROBOTS.TXT ANALYSIS ==="]
                    result.append(f"URL: {robots_url}")
                    result.append(f"Status: {response.status}")
                    result.append("")
                    
                    if response.status == 200:
                        content = await response.text()
                        result.append("Content:")
                        result.append("-" * 40)
                        result.append(content[:2000])  # 最初の2000文字のみ
                        if len(content) > 2000:
                            result.append("... (truncated)")
                    elif response.status == 404:
                        result.append("robots.txt not found (404)")
                        result.append("これは問題ではありませんが、存在する場合はクローラーの動作を制御できます")
                    else:
                        result.append(f"Unexpected status: {response.status}")
                    
                    return "\n".join(result)
                    
        except aiohttp.ClientError as e:
            return f"Error checking robots.txt: {str(e)}"
        except Exception as e:
            return f"Error: {str(e)}"
    
    async def get_basic_info(self, url: str) -> str:
        """Webサイトの基本情報を取得"""
        validated_url = self._validate_url(url)
        if not validated_url:
            return "Error: Invalid URL format"
        
        try:
            async with aiohttp.ClientSession(timeout=self.timeout, headers=self.headers) as session:
                start_time = time.time()
                async with session.get(validated_url) as response:
                    response_time = round((time.time() - start_time) * 1000, 2)
                    
                    result = [f"=== WEB BASIC INFORMATION ==="]
                    result.append(f"URL: {str(response.url)}")
                    result.append(f"Status: {response.status} {response.reason}")
                    result.append(f"Response Time: {response_time}ms")
                    result.append("")
                    
                    # 重要なヘッダー情報
                    important_headers = [
                        'Server', 'Content-Type', 'Content-Length', 
                        'Last-Modified', 'ETag', 'Cache-Control'
                    ]
                    
                    result.append("Important Headers:")
                    for header in important_headers:
                        if header in response.headers:
                            result.append(f"  {header}: {response.headers[header]}")
                    
                    # SSL/TLS情報（HTTPSの場合）
                    if str(response.url).startswith('https://'):
                        result.append("")
                        result.append("SSL/TLS: Enabled")
                    
                    # コンテンツサイズ
                    content_length = response.headers.get('Content-Length')
                    if content_length:
                        size_kb = round(int(content_length) / 1024, 2)
                        result.append(f"Content Size: {size_kb} KB")
                    
                    return "\n".join(result)
                    
        except aiohttp.ClientError as e:
            # HTTPSで失敗した場合はHTTPを試す
            if validated_url.startswith('https://'):
                http_url = validated_url.replace('https://', 'http://', 1)
                try:
                    return await self.get_basic_info(http_url)
                except:
                    pass
            return f"Error connecting to {validated_url}: {str(e)}"
        except Exception as e:
            return f"Error getting basic info: {str(e)}"
    
    async def technology_detection(self, url: str) -> str:
        """Webサイトで使用されている技術を検出"""
        validated_url = self._validate_url(url)
        if not validated_url:
            return "Error: Invalid URL format"
        
        try:
            async with aiohttp.ClientSession(timeout=self.timeout, headers=self.headers) as session:
                async with session.get(validated_url) as response:
                    content = await response.text()
                    headers_str = str(response.headers)
                    
                    result = [f"=== TECHNOLOGY DETECTION ==="]
                    result.append(f"URL: {str(response.url)}")
                    result.append("")
                    
                    detected_techs = {}
                    
                    # ヘッダーとコンテンツから技術を検出
                    full_content = headers_str + "\n" + content
                    
                    for tech_name, patterns in self.tech_patterns.items():
                        matches = []
                        for pattern in patterns:
                            if re.search(pattern, full_content, re.IGNORECASE):
                                matches.append(pattern)
                        
                        if matches:
                            detected_techs[tech_name] = matches
                    
                    if detected_techs:
                        result.append("Detected Technologies:")
                        for tech, patterns in detected_techs.items():
                            result.append(f"  ✅ {tech}")
                            result.append(f"     Detected via: {', '.join(patterns[:3])}")  # 最初の3つのパターンのみ表示
                    else:
                        result.append("No specific technologies detected")
                        result.append("（検出できなかった技術も多数存在する可能性があります）")
                    
                    # 追加情報: レスポンスヘッダーから
                    result.append("")
                    result.append("Additional Info from Headers:")
                    tech_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version', 'X-Generator']
                    for header in tech_headers:
                        if header in response.headers:
                            result.append(f"  {header}: {response.headers[header]}")
                    
                    return "\n".join(result)
                    
        except aiohttp.ClientError as e:
            return f"Error connecting to {validated_url}: {str(e)}"
        except Exception as e:
            return f"Error during technology detection: {str(e)}"
    
    async def directory_scan(self, url: str, wordlist: str = "common") -> str:
        """ディレクトリ・ファイルスキャン（gobuster風）"""
        validated_url = self._validate_url(url)
        if not validated_url:
            return "Error: Invalid URL format"
        
        # wordlistの選択
        if wordlist == "common":
            targets = self.common_dirs + self.common_files
        elif wordlist == "dirs":
            targets = self.common_dirs
        elif wordlist == "files":
            targets = self.common_files
        else:
            targets = self.common_dirs + self.common_files
        
        result = [f"=== DIRECTORY/FILE SCAN ==="]
        result.append(f"Target: {validated_url}")
        result.append(f"Wordlist: {wordlist} ({len(targets)} entries)")
        result.append("Status codes: 200=Found, 403=Forbidden, 401=Auth Required")
        result.append("")
        
        found_items = []
        
        try:
            # 並行スキャン（レート制限付き）
            semaphore = asyncio.Semaphore(10)  # 同時接続数制限
            
            async def check_path(target_path):
                async with semaphore:
                    try:
                        full_url = urljoin(validated_url, target_path)
                        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
                            async with session.head(full_url, headers=self.headers) as response:
                                if response.status in [200, 403, 401, 301, 302]:
                                    return f"{response.status} - {target_path}"
                                return None
                    except:
                        return None
            
            # 並行でパスをチェック
            tasks = [check_path(target) for target in targets]
            
            # チャンク単位で実行（レート制限対策）
            chunk_size = 20
            for i in range(0, len(tasks), chunk_size):
                chunk = tasks[i:i + chunk_size]
                chunk_results = await asyncio.gather(*chunk, return_exceptions=True)
                
                for path_result in chunk_results:
                    if path_result and not isinstance(path_result, Exception):
                        found_items.append(path_result)
                
                # レート制限のため待機
                await asyncio.sleep(0.5)
                
                # 進捗表示
                progress = min(i + chunk_size, len(tasks))
                print(f"Directory scan progress: {progress}/{len(tasks)}", file=sys.stderr)
            
            if found_items:
                result.append("Found paths:")
                for item in found_items:
                    result.append(f"  {item}")
            else:
                result.append("No common directories/files found")
            
            result.append("")
            result.append(f"Scan completed: {len(found_items)} items found out of {len(targets)} checked")
            
            return "\n".join(result)
            
        except Exception as e:
            return f"Error during directory scan: {str(e)}"
    
    async def comprehensive_web_scan(self, url: str) -> str:
        """包括的Webスキャン"""
        validated_url = self._validate_url(url)
        if not validated_url:
            return "Error: Invalid URL format"
        
        result = [f"=== COMPREHENSIVE WEB SCAN ==="]
        result.append(f"Target: {validated_url}")
        result.append("=" * 60)
        
        # 1. 基本情報
        result.append("\n1. Basic Information")
        result.append("-" * 30)
        basic_info = await self.get_basic_info(validated_url)
        result.append(basic_info)
        
        # 2. 技術検出
        result.append("\n2. Technology Detection")
        result.append("-" * 30)
        tech_info = await self.technology_detection(validated_url)
        result.append(tech_info)
        
        # 3. セキュリティヘッダー
        result.append("\n3. Security Headers")
        result.append("-" * 30)
        security_info = await self.check_security_headers(validated_url)
        result.append(security_info)
        
        # 4. robots.txt
        result.append("\n4. robots.txt Analysis")
        result.append("-" * 30)
        robots_info = await self.check_robots_txt(validated_url)
        result.append(robots_info)
        
        # 5. 簡易ディレクトリスキャン（時間短縮のためファイルのみ）
        result.append("\n5. Common Files Scan")
        result.append("-" * 30)
        files_scan = await self.directory_scan(validated_url, "files")
        result.append(files_scan)
        
        return "\n".join(result)

    async def take_screenshot(self, url: str, path: str) -> bool:
        """指定されたURLのスクリーンショットを撮影する"""
        validated_url = self._validate_url(url)
        if not validated_url:
            return False
            
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch()
                page = await browser.new_page(ignore_https_errors=True)
                await page.goto(validated_url, timeout=15000)
                await page.screenshot(path=path, full_page=True)
                await browser.close()
                return True
        except Exception as e:
            print(f"[-] Failed to take screenshot for {url}: {e}")
            return False