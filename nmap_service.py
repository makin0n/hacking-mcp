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
    "-T5",        # 最も積極的なタイミングテンプレート
    "-Pn",        # ホスト検出をスキップ
    "-F",         # 高速モード（よく使用される100ポートのみスキャン）
    "--min-rate=1000",  # 1秒あたり最低1000パケット
    "--max-retries=1", # 再試行回数を1回に制限
    "--host-timeout=15m"  # ホストあたりの最大タイムアウト15分
]

# XMLパーサーの設定
PARSER = etree.XMLParser(
    remove_blank_text=True,  # 空白テキストを削除
    resolve_entities=False,   # 外部エンティティを解決しない
    huge_tree=True,          # 大きなXMLツリーを許可
    recover=True             # エラーから回復を試みる
)

@mcp.tool()
async def test_connection() -> str:
    """MCPサーバーの接続をテストします"""
    return "MCP server is working correctly!"

@mcp.tool()
async def test_nmap() -> str:
    """nmapコマンドが実行可能かテストします"""
    try:
        # nmapのバージョンを確認
        process = await asyncio.create_subprocess_exec(
            "sudo", "nmap", "--version",
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
async def simple_scan(target: str) -> str:
    """シンプルなnmapスキャンを実行します"""
    try:
        print(f"Starting scan of {target}", file=sys.stderr)
        
        # 最もシンプルなnmapコマンド
        cmd = ["sudo", "nmap", "-Pn", "-F", target]
        print(f"Command: {' '.join(cmd)}", file=sys.stderr)
        
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        # wait_for を使用してタイムアウトを制御
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), 
                timeout=300  # 5分のタイムアウト
            )
        except asyncio.TimeoutError:
            process.terminate()
            await process.wait()
            return "Scan timed out after 5 minutes"
        
        if process.returncode == 0:
            return f"Scan completed successfully:\n{stdout.decode()}"
        else:
            return f"Scan failed:\nSTDOUT: {stdout.decode()}\nSTDERR: {stderr.decode()}"
            
    except Exception as e:
        return f"Error during scan: {str(e)}"

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
            return "Ping timed out after 30 seconds"
        
        if process.returncode == 0:
            return f"Ping successful:\n{stdout.decode()}"
        else:
            return f"Ping failed:\nSTDOUT: {stdout.decode()}\nSTDERR: {stderr.decode()}"
            
    except Exception as e:
        return f"Error during ping: {str(e)}"

if __name__ == "__main__":
    try:
        print("Starting FastMCP server...", file=sys.stderr)
        # FastMCPサーバーの実行
        mcp.run()
    except Exception as e:
        print(f"Error starting server: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)