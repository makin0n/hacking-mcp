import asyncio
import sys
import re
from typing import List, Optional
from lxml import etree

class NmapScanner:
    def __init__(self):
        self.default_options = [
            "-T4"
        ]
    
    def _validate_target(self, target: str) -> bool:
        """基本的なターゲット検証"""
        if not target or not target.strip():
            return False
        
        # 基本的な検証（より詳細な検証は後でutilsモジュールに移動予定）
        target = target.strip()
        
        # 明らかに不正な文字をチェック
        if any(char in target for char in ['|', ';', '&', '`', '$']):
            return False
        
        return True
    
    async def get_status(self) -> str:
        """nmapの状態を確認"""
        try:
            process = await asyncio.create_subprocess_exec(
                "sudo", "nmap", "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                version_line = stdout.decode().split('\n')[0]
                return f"Available - {version_line}"
            else:
                return "Error - nmap not working"
        except Exception as e:
            return f"Error - {str(e)}"
    
    async def basic_scan(self, target: str, options: Optional[List[str]] = None) -> str:
        """基本的なnmapスキャン
        
        Args:
            target: スキャン対象のホスト/ネットワーク
            options: 追加のnmapオプション（例: ["-sV", "-p80,443"]）
        """
        if not self._validate_target(target):
            return "Error: Invalid target format"
        
        try:
            cmd = ["sudo", "nmap", "-oX", "-"] + self.default_options
            if options:
                # 安全なオプションのみ許可
                safe_options = []
                for opt in options:
                    if re.match(r'^(-p[\d,-]+|-sV|-sC|-A|-T\d|-Pn|-F)$', opt):
                        safe_options.append(opt)
                cmd.extend(safe_options)
            
            cmd.append(target)
            
            print(f"Executing: {' '.join(cmd)}", file=sys.stderr)
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), 
                timeout=300  # 5分
            )
            
            if process.returncode == 0:
                return self._parse_xml_output(stdout.decode())
            else:
                return f"Scan failed: {stderr.decode()}"
                
        except asyncio.TimeoutError:
            return "Scan timed out after 5 minutes"
        except Exception as e:
            return f"Error during scan: {str(e)}"
    
    async def detailed_scan(self, target: str, ports: Optional[str] = None) -> str:
        """詳細スキャン（バージョン検出付き）
        
        Args:
            target: スキャン対象のホスト/ネットワーク
            ports: スキャン対象のポート（必須）
        """
        if not self._validate_target(target):
            return "Error: Invalid target format"
        
        # ポートが指定されていない場合はエラー
        if not ports:
            return "Error: Ports must be specified for detailed scan. Please run basic scan first to find open ports, then specify them for detailed scan."
        
        # ポート指定の簡単な検証
        if not re.match(r'^[\d,-]+$', ports):
            return "Error: Invalid port specification. Use format like '80,443' or '1-1000'"
        
        try:
            cmd = [
                "sudo", "nmap", "-oX", "-",
                "-sV",                       # バージョン検出
                "--version-intensity=3",     # バージョン検出の強度を3に下げる
                "-T4",
                f"-p{ports}"                 # 指定されたポートのみをスキャン
            ]
            
            cmd.append(target)
            
            print(f"Executing detailed scan on ports {ports}: {' '.join(cmd)}", file=sys.stderr)
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), 
                timeout=300  # タイムアウトを5分に短縮
            )
            
            if process.returncode == 0:
                return self._parse_xml_output(stdout.decode(), detailed=True)
            else:
                return f"Detailed scan failed: {stderr.decode()}"
                
        except asyncio.TimeoutError:
            return "Detailed scan timed out after 5 minutes"
        except Exception as e:
            return f"Error during detailed scan: {str(e)}"
    
    async def port_scan(self, target: str, ports: str) -> str:
        """指定ポートスキャン"""
        if not self._validate_target(target):
            return "Error: Invalid target format"
        
        # ポート指定の簡単な検証
        if not re.match(r'^[\d,-]+$', ports):
            return "Error: Invalid port specification. Use format like '80,443' or '1-1000'"
        
        try:
            cmd = [
                "sudo", "nmap", "-oX", "-",
                f"-p{ports}",
                "-T4", target
            ]
            
            print(f"Executing port scan: {' '.join(cmd)}", file=sys.stderr)
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), 
                timeout=300
            )
            
            if process.returncode == 0:
                return self._parse_xml_output(stdout.decode())
            else:
                return f"Port scan failed: {stderr.decode()}"
                
        except asyncio.TimeoutError:
            return "Port scan timed out after 5 minutes"
        except Exception as e:
            return f"Error during port scan: {str(e)}"
    
    def _parse_xml_output(self, xml_data: str, detailed: bool = False) -> str:
        """XML出力を解析してフォーマット"""
        try:
            root = etree.fromstring(xml_data.encode())
            
            # スキャン情報の取得
            scan_info = []
            scan_info.append("=== NMAP SCAN RESULTS ===")
            
            # 基本情報
            start_time = root.get("start", "Unknown")
            args = root.get("args", "")
            scan_info.append(f"Command: {args}")
            
            # ホスト情報
            hosts = root.findall(".//host")
            if not hosts:
                scan_info.append("No hosts found")
                return "\n".join(scan_info)
            
            for host in hosts:
                # ホストの状態
                status = host.find(".//status")
                if status is not None:
                    state = status.get("state", "unknown")
                    scan_info.append(f"\nHost Status: {state}")
                
                # IPアドレス情報
                addresses = host.findall(".//address")
                for addr in addresses:
                    addr_type = addr.get("addrtype", "")
                    addr_val = addr.get("addr", "")
                    scan_info.append(f"Address ({addr_type}): {addr_val}")
                
                # ホスト名
                hostnames = host.findall(".//hostname")
                if hostnames:
                    for hostname in hostnames:
                        name = hostname.get("name", "")
                        scan_info.append(f"Hostname: {name}")
                
                # ポート情報
                ports = host.findall(".//port")
                if ports:
                    scan_info.append("\nOpen Ports:")
                    for port in ports:
                        port_id = port.get("portid", "")
                        protocol = port.get("protocol", "")
                        
                        state_elem = port.find(".//state")
                        state = state_elem.get("state", "") if state_elem is not None else ""
                        
                        if state == "open":
                            port_line = f"  {port_id}/{protocol} - {state}"
                            
                            if detailed:
                                service = port.find(".//service")
                                if service is not None:
                                    service_name = service.get("name", "")
                                    product = service.get("product", "")
                                    version = service.get("version", "")
                                    
                                    service_info = []
                                    if service_name:
                                        service_info.append(service_name)
                                    if product:
                                        service_info.append(product)
                                    if version:
                                        service_info.append(version)
                                    
                                    if service_info:
                                        port_line += f" ({' '.join(service_info)})"
                            
                            scan_info.append(port_line)
                else:
                    scan_info.append("\nNo open ports detected")
            
            return "\n".join(scan_info)
            
        except Exception as e:
            return f"Error parsing XML output: {str(e)}\n\nRaw output:\n{xml_data[:500]}..."
    
    def _extract_open_ports_from_result(self, scan_result: str) -> List[str]:
        """スキャン結果から開放ポート番号を抽出"""
        open_ports = []
        
        # 正規表現でポート番号を抽出（より柔軟なパターン）
        port_pattern = r'(\d+)/\w+\s+-\s+open'
        matches = re.findall(port_pattern, scan_result)
        
        # 重複を除去してソート
        unique_ports = sorted(list(set(matches)), key=int)
        
        return unique_ports