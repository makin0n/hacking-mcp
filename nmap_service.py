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

# 既知の脆弱性とエクスプロイト情報
VULN_DATABASE = {
    "ftp": {
        "vsftpd": {
            "2.3.4": {
                "cve": "CVE-2011-2523",
                "description": "バックドア脆弱性",
                "exploit_tools": [
                    "metasploit: use exploit/unix/ftp/vsftpd_234_backdoor",
                    "searchsploit: vsftpd 2.3.4"
                ]
            }
        },
        "proftpd": {
            "1.3.3c": {
                "cve": "CVE-2010-4221",
                "description": "リモートコード実行の脆弱性",
                "exploit_tools": [
                    "metasploit: use exploit/unix/ftp/proftpd_modcopy_exec",
                    "searchsploit: ProFTPd 1.3.3c"
                ]
            }
        }
    },
    "ssh": {
        "openssh": {
            "4.3": {
                "cve": "CVE-2006-5229",
                "description": "認証バイパスの脆弱性",
                "exploit_tools": [
                    "metasploit: use exploit/unix/ssh/openssh_compat",
                    "hydra: hydra -l root -P wordlist.txt ssh://<target>"
                ]
            }
        }
    },
    "http": {
        "apache": {
            "2.4.49": {
                "cve": "CVE-2021-41773",
                "description": "パストラバーサルの脆弱性",
                "exploit_tools": [
                    "curl: curl -v 'http://<target>/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd'",
                    "metasploit: use exploit/unix/http/apache_normalize_path"
                ]
            }
        },
        "nginx": {
            "1.20.0": {
                "cve": "CVE-2021-23017",
                "description": "リソース枯渇の脆弱性",
                "exploit_tools": [
                    "ab: ab -n 1000 -c 100 http://<target>/",
                    "slowhttptest: slowhttptest -c 1000 -H -g -o slowhttp -i 10 -r 200 -t GET -u http://<target>"
                ]
            }
        }
    }
}

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
async def scan_ftp(target: str) -> str:
    """FTPサービスの詳細スキャンを実行"""
    try:
        print(f"Starting FTP scan of {target}", file=sys.stderr)
        
        # FTP専用のスキャンコマンド
        cmd = [
            "nmap",
            "-p21",     # FTPポート
            "-sV",      # バージョン検出
            "-sC",      # デフォルトスクリプト
            "--script=" + ",".join(FTP_SCRIPTS),  # FTP特有のスクリプト
            "-T4",
            target
        ]
        
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
            return "Scan timed out after 5 minutes"
        
        if process.returncode == 0:
            scan_output = stdout.decode()
            
            # 結果の解析と推奨事項の追加
            recommendations = []
            
            if "vsftpd 2.3.4" in scan_output:
                recommendations.append(
                    "\n重要な警告: vsftpd 2.3.4には既知のバックドア脆弱性(CVE-2011-2523)が存在します。"
                    "\n推奨対策:"
                    "\n- 直ちに最新バージョンにアップデート"
                    "\n- 一時的な対策として、FTPサービスの無効化を検討"
                )
            
            if "Anonymous FTP login allowed" in scan_output:
                recommendations.append(
                    "\n警告: 匿名FTPログインが許可されています。"
                    "\n推奨対策:"
                    "\n- 匿名ログインの無効化"
                    "\n- アクセス制御の強化"
                )
            
            result = f"スキャン結果:\n{scan_output}"
            if recommendations:
                result += "\n\nセキュリティ推奨事項:" + "\n".join(recommendations)
            
            return result
        else:
            return f"Scan failed:\nSTDOUT: {stdout.decode()}\nSTDERR: {stderr.decode()}"
            
    except Exception as e:
        return f"Error during FTP scan: {str(e)}"

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
            return "Scan timed out after 5 minutes"
        
        if process.returncode == 0:
            return f"Scan completed successfully:\n{stdout.decode()}"
        else:
            return f"Scan failed:\nSTDOUT: {stdout.decode()}\nSTDERR: {stderr.decode()}"
            
    except Exception as e:
        return f"Error during scan: {str(e)}"

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

@mcp.tool()
async def scan_service_vulnerabilities(target: str, ports: str = None) -> str:
    """指定されたポートのサービスバージョンを検出し、既知の脆弱性情報を提供します"""
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
                timeout=600  # 10分のタイムアウト
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
                    
                    # 脆弱性データベースの検索
                    if service_type in VULN_DATABASE:
                        for app, versions in VULN_DATABASE[service_type].items():
                            if app in service_name:
                                for vuln_version, vuln_info in versions.items():
                                    if vuln_version in version:
                                        finding += f"\n  脆弱性: {vuln_info['description']}"
                                        finding += f"\n  CVE: {vuln_info['cve']}"
                                        finding += "\n  エクスプロイト方法:"
                                        for tool in vuln_info['exploit_tools']:
                                            finding += f"\n    - {tool}"
                    
                    findings.append(finding)
            
            if findings:
                result = "検出されたサービスと脆弱性情報:\n" + "\n".join(findings)
                result += "\n\n元のnmapスキャン結果:\n" + scan_output
            else:
                result = "脆弱性は検出されませんでした。\n\nスキャン結果:\n" + scan_output
            
            return result
        else:
            return f"スキャンに失敗しました:\nSTDOUT: {stdout.decode()}\nSTDERR: {stderr.decode()}"
            
    except Exception as e:
        return f"スキャン中にエラーが発生しました: {str(e)}"

if __name__ == "__main__":
    try:
        print("Starting FastMCP server...", file=sys.stderr)
        # FastMCPサーバーの実行
        mcp.run()
    except Exception as e:
        print(f"Error starting server: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)