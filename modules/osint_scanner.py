#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import ssl
import json
import re
from typing import Dict, List, Optional, Union
from dataclasses import dataclass
from datetime import datetime
import aiohttp
import asyncio
from bs4 import BeautifulSoup
import ipaddress

@dataclass
class OSINTResult:
    """OSINTスキャン結果を格納するデータクラス"""
    target: str
    scan_time: datetime
    domain_info: Optional[Dict] = None
    ip_info: Optional[Dict] = None
    server_info: Optional[Dict] = None
    technologies: Optional[List[Dict]] = None
    security_headers: Optional[Dict] = None
    subdomains: Optional[List[str]] = None

class OSINTScanner:
    """OSINTスキャナークラス"""
    
    def __init__(self):
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        # 一般的なサブドメインのリスト
        self.common_subdomains = [
            'www', 'mail', 'ftp', 'smtp', 'pop', 'imap', 'webmail',
            'admin', 'administrator', 'blog', 'dev', 'development',
            'staging', 'test', 'testing', 'api', 'app', 'apps',
            'auth', 'cdn', 'cloud', 'docs', 'download', 'email',
            'files', 'forum', 'forums', 'git', 'help', 'hosting',
            'intranet', 'login', 'manage', 'management', 'mobile',
            'monitor', 'monitoring', 'mysql', 'new', 'news', 'ns1',
            'ns2', 'old', 'portal', 'remote', 'shop', 'site', 'sites',
            'sql', 'ssh', 'staff', 'stage', 'staging', 'stats',
            'status', 'support', 'sys', 'system', 'test', 'testing',
            'tools', 'vpn', 'web', 'webmail', 'wiki', 'www'
        ]
        
        # 技術スタックのパターン
        self.tech_patterns = {
            # Webフレームワーク
            'Django': r'django|csrfmiddlewaretoken',
            'Flask': r'flask|werkzeug',
            'Ruby on Rails': r'rails|ruby',
            'Laravel': r'laravel|csrf-token',
            'Express.js': r'express|x-powered-by: express',
            'ASP.NET': r'asp\.net|x-aspnet-version',
            'Spring': r'spring|jsessionid',
            
            # CMS
            'WordPress': r'wp-content|wp-includes|wordpress',
            'Drupal': r'drupal|drupal\.js',
            'Joomla': r'joomla|com_content',
            'Magento': r'magento|skin/frontend',
            'Shopify': r'shopify|cdn\.shopify\.com',
            
            # サーバー
            'nginx': r'nginx',
            'Apache': r'apache|x-powered-by: apache',
            'IIS': r'iis|x-powered-by: asp\.net',
            'Tomcat': r'tomcat|jsessionid',
            'Node.js': r'node|x-powered-by: express',
            
            # データベース
            'MySQL': r'mysql|mysqli',
            'PostgreSQL': r'postgresql|postgres',
            'MongoDB': r'mongodb|mongoose',
            
            # フロントエンド
            'React': r'react|react\.js',
            'Angular': r'angular|ng-',
            'Vue.js': r'vue|vue\.js',
            'jQuery': r'jquery|jquery\.js',
            'Bootstrap': r'bootstrap|bootstrap\.css',
            
            # セキュリティ
            'Cloudflare': r'cloudflare|cf-ray',
            'Akamai': r'akamai|akamai-gtm',
            'Imperva': r'incapsula|incap_ses',
            
            # 分析・監視
            'Google Analytics': r'google-analytics|ga\.js',
            'New Relic': r'newrelic|newrelic\.js',
            'Sentry': r'sentry|raven\.js'
        }
        
        # セキュリティヘッダーのチェックリスト
        self.security_headers = {
            'Strict-Transport-Security': 'HSTSの設定',
            'X-Frame-Options': 'クリックジャッキング対策',
            'X-Content-Type-Options': 'MIMEタイプスニッフィング対策',
            'X-XSS-Protection': 'XSS対策',
            'Content-Security-Policy': 'CSPの設定',
            'Referrer-Policy': 'リファラーポリシー',
            'Permissions-Policy': '機能ポリシー',
            'Cross-Origin-Opener-Policy': 'COOPの設定',
            'Cross-Origin-Embedder-Policy': 'COEPの設定',
            'Cross-Origin-Resource-Policy': 'CORPの設定'
        }
        
    async def scan(self, target: str) -> OSINTResult:
        """指定されたターゲットに対してOSINTスキャンを実行"""
        result = OSINTResult(
            target=target,
            scan_time=datetime.now()
        )
        
        try:
            # IPアドレスかドメイン名かを判定
            try:
                ipaddress.ip_address(target)
                is_ip = True
            except ValueError:
                is_ip = False
            
            if is_ip:
                result.ip_info = await self._scan_ip(target)
            else:
                result.domain_info = await self._scan_domain(target)
                result.subdomains = await self._enumerate_subdomains(target)
            
            # サーバー情報の収集
            result.server_info = await self._scan_server(target)
            
            # 技術スタックの検出
            result.technologies = await self._detect_technologies(target)
            
            # セキュリティヘッダーの分析
            result.security_headers = await self._analyze_security_headers(target)
            
        except Exception as e:
            print(f"Error during scan: {str(e)}")
            
        return result
    
    async def _scan_domain(self, domain: str) -> Dict:
        """ドメイン情報の収集"""
        info = {}
        
        try:
            # SSL証明書情報の取得
            try:
                context = ssl.create_default_context()
                with socket.create_connection((domain, 443)) as sock:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        cert = ssock.getpeercert()
                        info['ssl'] = {
                            'issuer': dict(x[0] for x in cert['issuer']),
                            'subject': dict(x[0] for x in cert['subject']),
                            'version': cert['version'],
                            'notBefore': cert['notBefore'],
                            'notAfter': cert['notAfter']
                        }
            except:
                pass
                
        except Exception as e:
            info['error'] = str(e)
            
        return info
    
    async def _scan_ip(self, ip: str) -> Dict:
        """IPアドレス情報の収集"""
        info = {}
        
        try:
            # IP情報の取得（ipinfo.io APIを使用）
            async with aiohttp.ClientSession() as session:
                async with session.get(f'https://ipinfo.io/{ip}/json', timeout=10) as response:
                    if response.status == 200:
                        data = await response.json()
                        info['location'] = {
                            'city': data.get('city', 'Unknown'),
                            'region': data.get('region', 'Unknown'),
                            'country': data.get('country', 'Unknown'),
                            'loc': data.get('loc', 'Unknown')
                        }
                        info['asn'] = data.get('org', 'Unknown')
                        info['hostname'] = data.get('hostname', 'Unknown')
                    else:
                        info['error'] = f"IP情報の取得に失敗しました（ステータスコード: {response.status}）"
                        
        except asyncio.TimeoutError:
            info['error'] = "IP情報の取得がタイムアウトしました"
        except Exception as e:
            info['error'] = f"IP情報の取得中にエラーが発生しました: {str(e)}"
            
        return info
    
    async def _scan_server(self, target: str) -> Dict:
        """サーバー情報の収集"""
        info = {}
        
        # HTTPとHTTPSの両方を試行
        protocols = ['http', 'https']
        
        for protocol in protocols:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(f'{protocol}://{target}', headers=self.headers, ssl=False, timeout=10) as response:
                        headers = dict(response.headers)
                        info['headers'] = headers
                        
                        # サーバー情報の抽出
                        server = headers.get('Server', 'Unknown')
                        if server:
                            info['server'] = server
                            info['protocol'] = protocol
                            break
                            
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                continue
                
        if not info:
            info['error'] = "サーバー情報の取得に失敗しました"
            
        return info
    
    async def _enumerate_subdomains(self, domain: str) -> List[str]:
        """サブドメインの列挙"""
        found_subdomains = set()
        
        try:
            # 一般的なサブドメインのチェック
            for subdomain in self.common_subdomains:
                full_domain = f"{subdomain}.{domain}"
                try:
                    socket.gethostbyname(full_domain)
                    found_subdomains.add(full_domain)
                except:
                    continue
                    
        except Exception as e:
            print(f"サブドメイン列挙中にエラーが発生しました: {str(e)}")
            
        return list(found_subdomains)
    
    async def _detect_technologies(self, target: str) -> List[Dict]:
        """技術スタックの検出"""
        detected_tech = []
        
        # HTTPとHTTPSの両方を試行
        protocols = ['http', 'https']
        
        for protocol in protocols:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(f'{protocol}://{target}', headers=self.headers, ssl=False, timeout=10) as response:
                        html = await response.text()
                        headers = dict(response.headers)
                        
                        # ヘッダーから技術を検出
                        for tech, pattern in self.tech_patterns.items():
                            if re.search(pattern, str(headers), re.I):
                                detected_tech.append({
                                    'name': tech,
                                    'type': 'header',
                                    'confidence': 'high'
                                })
                        
                        # HTMLから技術を検出
                        for tech, pattern in self.tech_patterns.items():
                            if re.search(pattern, html, re.I):
                                detected_tech.append({
                                    'name': tech,
                                    'type': 'html',
                                    'confidence': 'high'
                                })
                        
                        if detected_tech:
                            break
                            
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                continue
                
        return detected_tech
    
    async def _analyze_security_headers(self, target: str) -> Dict:
        """セキュリティヘッダーの分析"""
        headers_analysis = {}
        
        # HTTPとHTTPSの両方を試行
        protocols = ['http', 'https']
        
        for protocol in protocols:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(f'{protocol}://{target}', headers=self.headers, ssl=False, timeout=10) as response:
                        headers = dict(response.headers)
                        
                        for header, description in self.security_headers.items():
                            if header in headers:
                                headers_analysis[header] = {
                                    'present': True,
                                    'value': headers[header],
                                    'description': description
                                }
                            else:
                                headers_analysis[header] = {
                                    'present': False,
                                    'description': description
                                }
                        
                        if headers_analysis:
                            break
                            
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                continue
                
        if not headers_analysis:
            headers_analysis['error'] = "セキュリティヘッダーの分析に失敗しました"
            
        return headers_analysis

def format_result(result: OSINTResult) -> str:
    """スキャン結果を整形して出力"""
    output = []
    output.append(f"OSINTスキャン結果 - {result.target}")
    output.append(f"スキャン時刻: {result.scan_time}")
    
    if result.domain_info:
        output.append("\n=== ドメイン情報 ===")
        if 'ssl' in result.domain_info:
            output.append("\nSSL証明書情報:")
            for key, value in result.domain_info['ssl'].items():
                output.append(f"  {key}: {value}")
    
    if result.ip_info:
        output.append("\n=== IP情報 ===")
        if 'location' in result.ip_info:
            output.append("\n位置情報:")
            for key, value in result.ip_info['location'].items():
                output.append(f"  {key}: {value}")
        if 'asn' in result.ip_info:
            output.append(f"\nASN: {result.ip_info['asn']}")
        if 'hostname' in result.ip_info:
            output.append(f"ホスト名: {result.ip_info['hostname']}")
    
    if result.subdomains:
        output.append("\n=== サブドメイン ===")
        for subdomain in result.subdomains:
            output.append(f"  - {subdomain}")
    
    if result.server_info:
        output.append("\n=== サーバー情報 ===")
        if 'server' in result.server_info:
            output.append(f"\nサーバー: {result.server_info['server']}")
    
    if result.technologies:
        output.append("\n=== 検出された技術 ===")
        for tech in result.technologies:
            output.append(f"  - {tech['name']} (信頼度: {tech['confidence']})")
    
    if result.security_headers:
        output.append("\n=== セキュリティヘッダー ===")
        for header, info in result.security_headers.items():
            status = "✓ 設定あり" if info['present'] else "✗ 未設定"
            output.append(f"\n{header}:")
            output.append(f"  状態: {status}")
            if info['present']:
                output.append(f"  値: {info['value']}")
            output.append(f"  説明: {info['description']}")
    
    return "\n".join(output)

async def main():
    """メイン関数"""
    import sys
    
    if len(sys.argv) != 2:
        print("使用方法: python osint_scanner.py <target>")
        sys.exit(1)
        
    target = sys.argv[1]
    scanner = OSINTScanner()
    result = await scanner.scan(target)
    print(format_result(result))

if __name__ == "__main__":
    asyncio.run(main()) 