import asyncio
import sys
import socket
import re
from typing import List, Dict, Optional

class DNSScanner:
    def __init__(self):
        self.common_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'api', 'dev', 'test', 'staging',
            'blog', 'shop', 'store', 'app', 'mobile', 'beta', 'alpha',
            'secure', 'portal', 'support', 'help', 'docs', 'cdn', 'img',
            'static', 'assets', 'media', 'download', 'vpn', 'remote'
        ]
        
        self.record_types = {
            'A': 'IPv4アドレス',
            'AAAA': 'IPv6アドレス', 
            'MX': 'メールサーバー',
            'NS': 'ネームサーバー',
            'TXT': 'テキストレコード',
            'CNAME': '正規名',
            'SOA': 'Start of Authority',
            'PTR': '逆引き'
        }
    
    def _validate_domain(self, domain: str) -> bool:
        """ドメイン名の基本検証"""
        if not domain or not domain.strip():
            return False
        
        domain = domain.strip().lower()
        
        # 基本的なドメイン形式チェック
        domain_pattern = r'^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?\.([a-zA-Z]{2,}\.?)+$'
        return bool(re.match(domain_pattern, domain))
    
    def _validate_ip(self, ip: str) -> bool:
        """IPアドレスの検証"""
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            return False
    
    async def get_status(self) -> str:
        """DNS機能の状態確認"""
        try:
            # dig コマンドの利用可能性チェック
            process = await asyncio.create_subprocess_exec(
                'dig', '-v',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                version_info = stdout.decode() or stderr.decode()
                return f"Available - {version_info.split()[0] if version_info else 'dig available'}"
            else:
                # digがない場合はnslookupを試す
                return await self._check_nslookup()
        except Exception as e:
            return f"Available - DNS resolution via Python (dig unavailable: {str(e)})"
    
    async def _check_nslookup(self) -> str:
        """nslookupの利用可能性チェック"""
        try:
            process = await asyncio.create_subprocess_exec(
                'nslookup', 'example.com',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                return "Available - nslookup working"
            else:
                return "Available - Python DNS only"
        except:
            return "Available - Python DNS only"
    
    async def dns_lookup(self, domain: str, record_type: str = "A") -> str:
        """DNS レコードを検索"""
        if not self._validate_domain(domain):
            return "Error: Invalid domain format"
        
        record_type = record_type.upper()
        if record_type not in self.record_types:
            return f"Error: Unsupported record type. Available: {', '.join(self.record_types.keys())}"
        
        try:
            # dig コマンドを使用
            cmd = ['dig', '+short', f'@8.8.8.8', domain, record_type]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), 
                timeout=30
            )
            
            result = [f"=== DNS LOOKUP RESULTS ==="]
            result.append(f"Domain: {domain}")
            result.append(f"Record Type: {record_type} ({self.record_types[record_type]})")
            result.append("")
            
            if process.returncode == 0:
                output = stdout.decode().strip()
                if output:
                    result.append("Results:")
                    for line in output.split('\n'):
                        if line.strip():
                            result.append(f"  {line.strip()}")
                else:
                    result.append("No records found")
            else:
                error = stderr.decode().strip()
                result.append(f"DNS query failed: {error}")
            
            return "\n".join(result)
            
        except asyncio.TimeoutError:
            return f"DNS lookup timed out for {domain}"
        except Exception as e:
            # Fallback to Python DNS
            return await self._python_dns_lookup(domain, record_type)
    
    async def _python_dns_lookup(self, domain: str, record_type: str) -> str:
        """Python標準ライブラリでのDNS検索（フォールバック）"""
        try:
            if record_type == "A":
                ip = socket.gethostbyname(domain)
                return f"DNS Lookup (Python fallback):\nDomain: {domain}\nA Record: {ip}"
            else:
                return f"Python DNS fallback only supports A records. Use dig for {record_type} records."
        except socket.gaierror as e:
            return f"DNS resolution failed: {str(e)}"
    
    async def subdomain_enum(self, domain: str, wordlist: str = "common") -> str:
        """サブドメイン列挙"""
        if not self._validate_domain(domain):
            return "Error: Invalid domain format"
        
        if wordlist == "common":
            subdomains_to_check = self.common_subdomains
        else:
            # 将来的に外部wordlistファイルに対応予定
            subdomains_to_check = self.common_subdomains
        
        result = [f"=== SUBDOMAIN ENUMERATION ==="]
        result.append(f"Target Domain: {domain}")
        result.append(f"Wordlist: {wordlist} ({len(subdomains_to_check)} entries)")
        result.append("")
        
        found_subdomains = []
        
        try:
            # 並行してサブドメインをチェック
            tasks = []
            for subdomain in subdomains_to_check:
                full_domain = f"{subdomain}.{domain}"
                tasks.append(self._check_subdomain(full_domain))
            
            # 最大10個ずつ並行実行（レート制限対策）
            chunk_size = 10
            for i in range(0, len(tasks), chunk_size):
                chunk = tasks[i:i + chunk_size]
                chunk_results = await asyncio.gather(*chunk, return_exceptions=True)
                
                for j, subdomain_result in enumerate(chunk_results):
                    if isinstance(subdomain_result, Exception):
                        continue
                    if subdomain_result:
                        found_subdomains.append(subdomain_result)
                
                # レート制限のため少し待機
                await asyncio.sleep(0.1)
            
            if found_subdomains:
                result.append("Found Subdomains:")
                for subdomain_info in found_subdomains:
                    result.append(f"  {subdomain_info}")
            else:
                result.append("No subdomains found from the common wordlist")
            
            result.append("")
            result.append(f"Summary: {len(found_subdomains)} subdomains discovered")
            
            return "\n".join(result)
            
        except Exception as e:
            return f"Error during subdomain enumeration: {str(e)}"
    
    async def _check_subdomain(self, full_domain: str) -> Optional[str]:
        """個別サブドメインの存在確認"""
        try:
            ip = socket.gethostbyname(full_domain)
            return f"{full_domain} -> {ip}"
        except socket.gaierror:
            return None
    
    async def reverse_dns(self, ip: str) -> str:
        """逆引きDNS"""
        if not self._validate_ip(ip):
            return "Error: Invalid IP address format"
        
        try:
            # dig を使用した逆引き
            cmd = ['dig', '+short', '-x', ip]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), 
                timeout=30
            )
            
            result = [f"=== REVERSE DNS LOOKUP ==="]
            result.append(f"IP Address: {ip}")
            result.append("")
            
            if process.returncode == 0:
                output = stdout.decode().strip()
                if output:
                    result.append("Hostname(s):")
                    for line in output.split('\n'):
                        if line.strip():
                            result.append(f"  {line.strip()}")
                else:
                    result.append("No PTR record found")
            else:
                # Python fallback
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                    result.append(f"Hostname (Python fallback): {hostname}")
                except socket.herror:
                    result.append("No PTR record found")
            
            return "\n".join(result)
            
        except asyncio.TimeoutError:
            return f"Reverse DNS lookup timed out for {ip}"
        except Exception as e:
            return f"Error during reverse DNS lookup: {str(e)}"
    
    async def dns_comprehensive(self, domain: str) -> str:
        """包括的DNS調査"""
        if not self._validate_domain(domain):
            return "Error: Invalid domain format"
        
        result = [f"=== COMPREHENSIVE DNS ANALYSIS ==="]
        result.append(f"Target: {domain}")
        result.append("=" * 50)
        
        # 主要レコードタイプを順番に調査
        main_records = ['A', 'AAAA', 'MX', 'NS', 'TXT']
        
        for record_type in main_records:
            result.append(f"\n--- {record_type} Records ---")
            record_result = await self.dns_lookup(domain, record_type)
            # ヘッダー部分を除いて結果のみ追加
            lines = record_result.split('\n')
            if len(lines) > 4:  # ヘッダーをスキップ
                result.extend(lines[4:])
            
            await asyncio.sleep(0.5)  # レート制限対策
        
        # サブドメイン列挙
        result.append(f"\n--- Subdomain Enumeration ---")
        subdomain_result = await self.subdomain_enum(domain)
        # 結果のみ追加
        lines = subdomain_result.split('\n')
        if len(lines) > 4:
            result.extend(lines[4:])
        
        return "\n".join(result)