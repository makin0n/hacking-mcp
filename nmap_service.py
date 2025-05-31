from typing import Dict, List, Optional
from mcp.server.fastmcp import FastMCP
import asyncio
import subprocess
import re
from datetime import datetime
from lxml import etree
from pathlib import Path
import sys
import json

# デバッグ情報を出力
print("Python version:", sys.version, file=sys.stderr)
print("Starting nmap MCP server...", file=sys.stderr)

# MCPサーバーの初期化
mcp = FastMCP("nmap-scanner")

# 定数
OUTPUT_DIR = Path("scan_results")
OUTPUT_DIR.mkdir(exist_ok=True)

# デフォルトのnmapオプション
DEFAULT_OPTIONS = [
    "-T4",        # 適度な積極性のタイミングテンプレート
    "-Pn",        # ホスト検出をスキップ
    "--min-rate=300",  # 1秒あたり最低300パケット
    "--max-retries=2", # 再試行回数を2回に制限
    "--host-timeout=30m"  # ホストあたりの最大タイムアウト30分
]

# FTPスキャン用のNSEスクリプト
FTP_SCRIPTS = [
    "ftp-anon",         # 匿名FTPチェック
    "ftp-vsftpd-backdoor",  # vsftpdバックドアチェック
    "ftp-vuln-*",      # FTP脆弱性チェック
    "ftp-brute"        # FTPブルートフォース可能性チェック
]

# XMLパーサーの設定
PARSER = etree.XMLParser(
    remove_blank_text=True,  # 空白テキストを削除
    resolve_entities=False,   # 外部エンティティを解決しない
    huge_tree=True,          # 大きなXMLツリーを許可
    recover=True             # エラーから回復を試みる
)

@mcp.tool()
async def scan_service_vulnerabilities(target: str, ports: str = None) -> str:
    """指定されたポートのサービスバージョンを検出します"""
    try:
        print(f"Starting vulnerability scan of {target}", file=sys.stderr)
        
        # nmapコマンドの設定
        cmd = [
            "nmap",
            "-sV",           # バージョン検出
            "-sC",           # デフォルトスクリプト
            "--version-intensity=9",  # 最大強度のバージョン検出
            "-Pn",          # ホスト検出をスキップ
            "-T4"           # タイミングテンプレート
        ]
        
        # ポート指定がある場合
        if ports:
            cmd.extend(["-p", ports])
        
        cmd.append(target)
        
        print(f"Command: {' '.join(cmd)}", file=sys.stderr)
        
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), 
                timeout=300  # 5分のタイムアウト
            )
        except asyncio.TimeoutError:
            process.terminate()
            await process.wait()
            return "スキャンが10分でタイムアウトしました"
        
        if process.returncode == 0:
            scan_output = stdout.decode()
            
            # 結果の解析
            findings = []
            
            # サービスとバージョンの検出パターン
            service_patterns = {
                "ftp": r"(\d+)/tcp\s+open\s+ftp\s+([^\s]+)\s+([^\s]+)",
                "ssh": r"(\d+)/tcp\s+open\s+ssh\s+([^\s]+)\s+([^\s]+)",
                "http": r"(\d+)/tcp\s+open\s+http\s+([^\s]+)\s+([^\s]+)"
            }
            
            for service_type, pattern in service_patterns.items():
                matches = re.finditer(pattern, scan_output)
                for match in matches:
                    port, service_name, version = match.groups()
                    
                    # バージョン情報のクリーンアップ
                    version = version.lower().strip()
                    service_name = service_name.lower().strip()
                    
                    finding = f"\nポート {port}/tcp - {service_name} {version}"
                    findings.append(finding)
            
            if findings:
                result = "検出されたサービス:\n" + "\n".join(findings)
                result += "\n\n元のnmapスキャン結果:\n" + scan_output
                result += "\n\n注意: 検出されたサービスの脆弱性情報については、Claude Desktopに問い合わせてください。"
            else:
                result = "サービスは検出されませんでした。\n\nスキャン結果:\n" + scan_output
            
            return result
        else:
            return f"スキャンに失敗しました:\nSTDOUT: {stdout.decode()}\nSTDERR: {stderr.decode()}"
            
    except Exception as e:
        return f"スキャン中にエラーが発生しました: {str(e)}"

@mcp.tool()
async def test_connection() -> str:
    """MCPサーバーの接続をテストします"""
    return "MCP server is working correctly!"

@mcp.tool()
async def test_nmap() -> str:
    """nmapコマンドが実行可能かテストします"""
    try:
        # nmapのバージョンを確認（sudoなし）
        process = await asyncio.create_subprocess_exec(
            "nmap", "--version",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()
        
        if process.returncode == 0:
            return f"nmap is available:\n{stdout.decode()}"
        else:
            return f"nmap error: {stderr.decode()}"
    except Exception as e:
        return f"Error testing nmap: {str(e)}"

@mcp.tool()
async def scan_with_options(target: str, ports: str = None, version: bool = False) -> str:
    """指定されたオプションでnmapスキャンを実行します"""
    try:
        print(f"Starting scan of {target}", file=sys.stderr)
        
        # 基本コマンド
        cmd = ["nmap", "-Pn"]
        
        # ポート指定がある場合
        if ports:
            cmd.extend(["-p", ports])
        
        # バージョン検出
        if version:
            cmd.append("-sV")
            cmd.append("--version-intensity=2")
        
        # ターゲットを追加
        cmd.append(target)
        
        print(f"Command: {' '.join(cmd)}", file=sys.stderr)
        
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), 
                timeout=300  # 5分のタイムアウト
            )
        except asyncio.TimeoutError:
            process.terminate()
            await process.wait()
            return "スキャンが5分でタイムアウトしました"
        
        if process.returncode == 0:
            return f"スキャンが完了しました:\n{stdout.decode()}"
        else:
            return f"スキャンに失敗しました:\nSTDOUT: {stdout.decode()}\nSTDERR: {stderr.decode()}"
            
    except Exception as e:
        return f"スキャン中にエラーが発生しました: {str(e)}"

@mcp.tool()
async def simple_scan(target: str) -> str:
    """シンプルなnmapスキャンを実行します"""
    try:
        print(f"Starting scan of {target}", file=sys.stderr)
        
        # 基本的なnmapコマンド
        cmd = ["nmap", "-Pn", "-F", target]
        print(f"Command: {' '.join(cmd)}", file=sys.stderr)
        
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), 
                timeout=300  # 5分のタイムアウト
            )
        except asyncio.TimeoutError:
            process.terminate()
            await process.wait()
            return "スキャンが5分でタイムアウトしました"
        
        if process.returncode == 0:
            return f"スキャンが完了しました:\n{stdout.decode()}"
        else:
            return f"スキャンに失敗しました:\nSTDOUT: {stdout.decode()}\nSTDERR: {stderr.decode()}"
            
    except Exception as e:
        return f"スキャン中にエラーが発生しました: {str(e)}"

@mcp.tool()
async def quick_ping(target: str) -> str:
    """対象ホストへの簡単な到達性確認を行います"""
    try:
        print(f"Pinging {target}", file=sys.stderr)
        
        # pingコマンド（Alpine Linuxの場合）
        cmd = ["ping", "-c", "3", target]
        print(f"Command: {' '.join(cmd)}", file=sys.stderr)
        
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), 
                timeout=30  # 30秒のタイムアウト
            )
        except asyncio.TimeoutError:
            process.terminate()
            await process.wait()
            return "Pingが30秒でタイムアウトしました"
        
        if process.returncode == 0:
            return f"Ping成功:\n{stdout.decode()}"
        else:
            return f"Ping失敗:\nSTDOUT: {stdout.decode()}\nSTDERR: {stderr.decode()}"
            
    except Exception as e:
        return f"Ping中にエラーが発生しました: {str(e)}"

if __name__ == "__main__":
    try:
        print("Starting FastMCP server...", file=sys.stderr)
        mcp.run()
    except Exception as e:
        print(f"Error starting server: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)