#!/usr/bin/env python3
"""
Enhanced Reconnaissance MCP Server with sudo nmap
"""

import asyncio
import json
import logging
import subprocess
import ipaddress
import re
from typing import Dict, List, Optional, Any
import validators
from asyncio_throttle import Throttler
from mcp.server import Server
from mcp.types import (
    Tool, 
    TextContent, 
    CallToolRequest, 
    CallToolResult,
    ListToolsRequest,
    ListToolsResult
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# レート制限設定
throttler = Throttler(rate_limit=5, period=60)

class EnhancedReconMCPServer:
    """強化版偵察MCPサーバ"""
    
    def __init__(self):
        self.server = Server("recon-mcp-enhanced")
        self.setup_handlers()
        
        # ブロック対象IPレンジ
        self.blocked_ranges = [
            ipaddress.ip_network('10.0.0.0/8'),
            ipaddress.ip_network('172.16.0.0/12'),
            ipaddress.ip_network('192.168.0.0/16'),
            ipaddress.ip_network('127.0.0.0/8'),
            ipaddress.ip_network('169.254.0.0/16'),
            ipaddress.ip_network('224.0.0.0/4'),  # マルチキャスト
        ]
        
        # よく使用されるポート定義
        self.common_ports = {
            'web': '80,443,8080,8443,3000,5000',
            'mail': '25,110,143,993,995',
            'db': '1433,3306,5432,27017,6379',
            'remote': '22,23,3389,5900',
            'dns': '53',
            'top100': 'top-ports 100',
            'top1000': 'top-ports 1000'
        }
    
    def setup_handlers(self):
        """ハンドラーの設定"""
        
        @self.server.list_tools()
        async def list_tools() -> ListToolsResult:
            return ListToolsResult(
                tools=[
                    Tool(
                        name="nmap_quick_scan",
                        description="高速ポートスキャン（SYNスキャン使用）",
                        inputSchema={
                            "type": "object",
                            "properties": {
                                "target": {
                                    "type": "string",
                                    "description": "スキャン対象（IP/ドメイン）"
                                },
                                "ports": {
                                    "type": "string",
                                    "enum": ["web", "mail", "db", "remote", "dns", "top100", "top1000", "custom"],
                                    "description": "ポートカテゴリまたはcustom",
                                    "default": "top100"
                                },
                                "custom_ports": {
                                    "type": "string",
                                    "description": "portsがcustomの場合のポート指定（例: '80,443,22' または '1-1000'）"
                                }
                            },
                            "required": ["target"]
                        }
                    ),
                    Tool(
                        name="nmap_service_scan",
                        description="サービス検出スキャン（バージョン情報取得）",
                        inputSchema={
                            "type": "object",
                            "properties": {
                                "target": {"type": "string", "description": "スキャン対象"},
                                "ports": {
                                    "type": "string", 
                                    "description": "スキャンするポート",
                                    "default": "top100"
                                },
                                "aggressive": {
                                    "type": "boolean",
                                    "description": "積極的検出を有効にする",
                                    "default": false
                                }
                            },
                            "required": ["target"]
                        }
                    ),
                    Tool(
                        name="nmap_os_detection",
                        description="OS検出スキャン",
                        inputSchema={
                            "type": "object",
                            "properties": {
                                "target": {"type": "string", "description": "スキャン対象"},
                                "ports": {
                                    "type": "string",
                                    "description": "OS検出用ポート",
                                    "default": "top100"
                                }
                            },
                            "required": ["target"]
                        }
                    ),
                    Tool(
                        name="nmap_vulnerability_scan",
                        description="脆弱性スキャン（NSEスクリプト使用）",
                        inputSchema={
                            "type": "object",
                            "properties": {
                                "target": {"type": "string", "description": "スキャン対象"},
                                "script_category": {
                                    "type": "string",
                                    "enum": ["vuln", "safe", "default", "discovery"],
                                    "description": "NSEスクリプトカテゴリ",
                                    "default": "safe"
                                }
                            },
                            "required": ["target"]
                        }
                    ),
                    Tool(
                        name="nmap_udp_scan",
                        description="UDPポートスキャン",
                        inputSchema={
                            "type": "object",
                            "properties": {
                                "target": {"type": "string", "description": "スキャン対象"},
                                "top_ports": {
                                    "type": "integer",
                                    "description": "スキャンするUDPポート数",
                                    "default": 20,
                                    "minimum": 10,
                                    "maximum": 100
                                }
                            },
                            "required": ["target"]
                        }
                    )
                ]
            )
        
        @self.server.call_tool()
        async def call_tool(request: CallToolRequest) -> CallToolResult:
            async with throttler:
                try:
                    method_name = request.name.replace('-', '_')
                    if hasattr(self, method_name):
                        method = getattr(self, method_name)
                        return await method(request.arguments)
                    else:
                        return CallToolResult(
                            content=[TextContent(type="text", text=f"未知のツール: {request.name}")],
                            isError=True
                        )
                except Exception as e:
                    logger.error(f"ツール実行エラー ({request.name}): {e}")
                    return CallToolResult(
                        content=[TextContent(type="text", text=f"実行エラー: {str(e)}")],
                        isError=True
                    )
    
    def validate_target(self, target: str) -> bool:
        """対象ホストの検証"""
        try:
            if validators.domain(target):
                return True
            
            ip = ipaddress.ip_address(target)
            for blocked_range in self.blocked_ranges:
                if ip in blocked_range:
                    raise ValueError(f"ブロックされたIPレンジ: {target}")
            return True
        except ValueError as e:
            raise ValueError(f"無効な対象: {target} - {str(e)}")
    
    def resolve_ports(self, ports: str, custom_ports: str = None) -> List[str]:
        """ポート指定の解決"""
        if ports == "custom" and custom_ports:
            return ["-p", custom_ports]
        elif ports in self.common_ports:
            port_spec = self.common_ports[ports]
            if port_spec.startswith('top-ports'):
                return ["--top-ports", port_spec.split()[1]]
            else:
                return ["-p", port_spec]
        else:
            return ["--top-ports", "100"]  # デフォルト
    
    async def nmap_quick_scan(self, args: Dict[str, Any]) -> CallToolResult:
        """高速SYNスキャン"""
        target = args.get("target")
        ports = args.get("ports", "top100")
        custom_ports = args.get("custom_ports")
        
        if not target:
            return CallToolResult(
                content=[TextContent(type="text", text="対象ホストが必要です")],
                isError=True
            )
        
        try:
            self.validate_target(target)
        except ValueError as e:
            return CallToolResult(
                content=[TextContent(type="text", text=str(e))],
                isError=True
            )
        
        # SYNスキャンコマンド構築
        nmap_args = ["sudo", "nmap", "-sS", "-n", "--reason"]
        nmap_args.extend(self.resolve_ports(ports, custom_ports))
        nmap_args.extend(["--host-timeout", "30s", "--max-retries", "2"])
        nmap_args.append(target)
        
        return await self.execute_nmap(nmap_args, "高速ポートスキャン")
    
    async def nmap_service_scan(self, args: Dict[str, Any]) -> CallToolResult:
        """サービス検出スキャン"""
        target = args.get("target")
        ports = args.get("ports", "top100")
        aggressive = args.get("aggressive", False)
        
        try:
            self.validate_target(target)
        except ValueError as e:
            return CallToolResult(
                content=[TextContent(type="text", text=str(e))],
                isError=True
            )
        
        # サービス検出コマンド
        nmap_args = ["sudo", "nmap", "-sS", "-sV", "-n"]
        
        if aggressive:
            nmap_args.append("-A")  # 積極的検出
        
        nmap_args.extend(self.resolve_ports(ports))
        nmap_args.extend(["--host-timeout", "60s"])
        nmap_args.append(target)
        
        return await self.execute_nmap(nmap_args, "サービス検出スキャン", timeout=120)
    
    async def nmap_os_detection(self, args: Dict[str, Any]) -> CallToolResult:
        """OS検出スキャン"""
        target = args.get("target")
        ports = args.get("ports", "top100")
        
        try:
            self.validate_target(target)
        except ValueError as e:
            return CallToolResult(
                content=[TextContent(type="text", text=str(e))],
                isError=True
            )
        
        # OS検出コマンド
        nmap_args = ["sudo", "nmap", "-sS", "-O", "-n", "--osscan-guess"]
        nmap_args.extend(self.resolve_ports(ports))
        nmap_args.extend(["--host-timeout", "60s"])
        nmap_args.append(target)
        
        return await self.execute_nmap(nmap_args, "OS検出スキャン", timeout=120)
    
    async def nmap_vulnerability_scan(self, args: Dict[str, Any]) -> CallToolResult:
        """脆弱性スキャン"""
        target = args.get("target")
        script_category = args.get("script_category", "safe")
        
        try:
            self.validate_target(target)
        except ValueError as e:
            return CallToolResult(
                content=[TextContent(type="text", text=str(e))],
                isError=True
            )
        
        # 脆弱性スキャンコマンド
        nmap_args = ["sudo", "nmap", "-sS", "-n", "--script", script_category]
        nmap_args.extend(["--top-ports", "100"])
        nmap_args.extend(["--host-timeout", "90s"])
        nmap_args.append(target)
        
        return await self.execute_nmap(nmap_args, f"脆弱性スキャン（{script_category}）", timeout=180)
    
    async def nmap_udp_scan(self, args: Dict[str, Any]) -> CallToolResult:
        """UDPスキャン"""
        target = args.get("target")
        top_ports = args.get("top_ports", 20)
        
        try:
            self.validate_target(target)
        except ValueError as e:
            return CallToolResult(
                content=[TextContent(type="text", text=str(e))],
                isError=True
            )
        
        # UDPスキャンコマンド
        nmap_args = ["sudo", "nmap", "-sU", "-n"]
        nmap_args.extend(["--top-ports", str(top_ports)])
        nmap_args.extend(["--host-timeout", "60s"])
        nmap_args.append(target)
        
        return await self.execute_nmap(nmap_args, "UDPスキャン", timeout=120)
    
    async def execute_nmap(self, nmap_args: List[str], scan_type: str, timeout: int = 90) -> CallToolResult:
        """nmap実行の共通メソッド"""
        try:
            logger.info(f"{scan_type} 実行中: {' '.join(nmap_args[2:])}")  # sudoを除いてログ出力
            
            result = subprocess.run(
                nmap_args,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            if result.returncode == 0:
                output = self.format_nmap_output(result.stdout, scan_type)
                return CallToolResult(
                    content=[TextContent(type="text", text=output)]
                )
            else:
                error_msg = result.stderr.strip() or "nmapエラーが発生しました"
                return CallToolResult(
                    content=[TextContent(type="text", text=f"{scan_type}エラー: {error_msg}")],
                    isError=True
                )
                
        except subprocess.TimeoutExpired:
            return CallToolResult(
                content=[TextContent(type="text", text=f"{scan_type}がタイムアウトしました")],
                isError=True
            )
        except Exception as e:
            return CallToolResult(
                content=[TextContent(type="text", text=f"{scan_type}実行エラー: {str(e)}")],
                isError=True
            )
    
    def format_nmap_output(self, output: str, scan_type: str) -> str:
        """nmap出力の整形"""
        lines = output.strip().split('\n')
        formatted_lines = [f"=== {scan_type}結果 ===\n"]
        
        important_patterns = [
            r'Nmap scan report for',
            r'Host is up',
            r'PORT\s+STATE\s+SERVICE',
            r'^\d+/\w+\s+(open|closed|filtered)',
            r'Service detection performed',
            r'OS details:',
            r'Network Distance:',
            r'Running:',
            r'\|\s*',  # スクリプト出力
            r'Nmap done:'
        ]
        
        for line in lines:
            line = line.strip()
            if any(re.search(pattern, line, re.IGNORECASE) for pattern in important_patterns):
                formatted_lines.append(line)
            elif line and not line.startswith('#') and 'Starting Nmap' not in line:
                # その他の重要そうな行
                if any(keyword in line.lower() for keyword in ['open', 'closed', 'filtered', 'vulnerability', 'script']):
                    formatted_lines.append(line)
        
        return '\n'.join(formatted_lines) if len(formatted_lines) > 1 else output
    
    async def run(self):
        """サーバー実行"""
        logger.info("Enhanced Recon MCP Server starting")
        # MCPサーバーはstdio経由で通信するため、引数不要
        await self.server.run()

async def main():
    server = EnhancedReconMCPServer()
    await server.run()

if __name__ == "__main__":
    asyncio.run(main())