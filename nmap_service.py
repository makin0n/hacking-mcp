from mcp.server.fastmcp import FastMCP
import asyncio
import subprocess
import sys
import urllib.parse

# MCPサーバーの初期化
mcp = FastMCP("nmap-scanner")

@mcp.tool()
async def scan_service_vulnerabilities(target: str, ports: str = None) -> str:
    """指定されたポートのサービスバージョンを検出します"""
    try:
        # nmapコマンドの設定
        cmd = [
            "nmap",
            "-sV",           # バージョン検出
            "-sC",           # デフォルトスクリプト
            "--version-intensity=9",  # 最大強度のバージョン検出
            "-Pn",          # ホスト検出をスキップ
            "-T4"           # タイミングテンプレート
        ]
        
        if ports:
            cmd.extend(["-p", ports])
        
        cmd.append(target)
        
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
            return "スキャンがタイムアウトしました"
        
        if process.returncode == 0:
            return stdout.decode()
        else:
            return f"スキャンに失敗しました:\n{stderr.decode()}"
            
    except Exception as e:
        return f"エラー: {str(e)}"

@mcp.tool()
async def simple_scan(target: str) -> str:
    """シンプルなnmapスキャンを実行します"""
    try:
        cmd = ["nmap", "-Pn", "-F", target]
        
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), 
                timeout=300
            )
        except asyncio.TimeoutError:
            process.terminate()
            await process.wait()
            return "スキャンがタイムアウトしました"
        
        if process.returncode == 0:
            return stdout.decode()
        else:
            return f"スキャンに失敗しました:\n{stderr.decode()}"
            
    except Exception as e:
        return f"エラー: {str(e)}"

@mcp.tool()
async def quick_ping(target: str) -> str:
    """対象ホストへの到達性確認を行います"""
    try:
        cmd = ["ping", "-c", "3", target]
        
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), 
                timeout=30
            )
        except asyncio.TimeoutError:
            process.terminate()
            await process.wait()
            return "Pingがタイムアウトしました"
        
        if process.returncode == 0:
            return stdout.decode()
        else:
            return f"Ping失敗:\n{stderr.decode()}"
            
    except Exception as e:
        return f"エラー: {str(e)}"

@mcp.tool()
async def dirb_scan(url: str) -> str:
    """WEBサイトの隠しオブジェクトを検索します"""
    try:
        # URLの検証
        parsed_url = urllib.parse.urlparse(url)
        if not parsed_url.scheme or not parsed_url.netloc:
            return "無効なURL形式です"

        cmd = [
            "dirb",
            url,
            "/usr/share/dirb/wordlists/common.txt",  # 基本的なワードリスト
            "-w",          # エラーを表示しない
            "-N", "404",   # 404を除外
        ]
        
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), 
                timeout=600  # 10分
            )
        except asyncio.TimeoutError:
            process.terminate()
            await process.wait()
            return "スキャンがタイムアウトしました"
        
        if process.returncode == 0:
            return stdout.decode()
        else:
            return f"スキャンに失敗しました:\n{stderr.decode()}"
            
    except Exception as e:
        return f"エラー: {str(e)}"

if __name__ == "__main__":
    try:
        mcp.run()
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)