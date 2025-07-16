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
            # findコマンドを一括で実行
            find_command = "find " + " ".join(search_paths) + " \\( -name 'flag*.txt' -o -name 'root.txt' \\) -type f 2>/dev/null"
            found_files_str = await self._run_remote_command(conn, find_command)

            if not found_files_str:
                return "flag*.txtまたはroot.txtファイルは見つかりませんでした。"

            files = found_files_str.split('\n')
            for file_path in files:
                if not file_path:
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