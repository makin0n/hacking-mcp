import asyncio
import subprocess
import os
import re
from typing import List, Dict, Optional

class SSHExplorer:
    """SSH接続後のディレクトリ調査とファイル検索を行うクラス"""
    
    def __init__(self):
        self.current_directory = None
        self.found_files = []
        
    async def explore_current_directory(self) -> str:
        """現在のディレクトリの内容を調査します"""
        try:
            # 現在のディレクトリを取得
            result = await asyncio.create_subprocess_exec(
                'pwd',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await result.communicate()
            current_dir = stdout.decode().strip()
            self.current_directory = current_dir
            
            # ディレクトリの内容を取得
            result = await asyncio.create_subprocess_exec(
                'ls', '-la',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await result.communicate()
            dir_contents = stdout.decode()
            
            return f"現在のディレクトリ: {current_dir}\n\nディレクトリの内容:\n{dir_contents}"
            
        except Exception as e:
            return f"エラーが発生しました: {str(e)}"
    
    async def search_flag_files(self, search_paths: Optional[List[str]] = None) -> str:
        """flag.txtファイルを網羅的に検索します"""
        if search_paths is None:
            search_paths = ['/', '/home', '/var', '/tmp', '/opt', '/usr', '/etc']
        
        found_flags = []
        
        for path in search_paths:
            try:
                # findコマンドでflag.txtファイルを検索
                result = await asyncio.create_subprocess_exec(
                    'find', path, '-name', '*flag*', '-type', 'f', '2>/dev/null',
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await result.communicate()
                files = stdout.decode().strip().split('\n')
                
                for file_path in files:
                    if file_path:
                        found_flags.append(file_path)
                        
            except Exception as e:
                continue
        
        if not found_flags:
            return "flag.txtファイルは見つかりませんでした。"
        
        result_text = "見つかったflagファイル:\n"
        for file_path in found_flags:
            result_text += f"- {file_path}\n"
            
            # ファイルの内容を読み取り
            try:
                content_result = await asyncio.create_subprocess_exec(
                    'cat', file_path,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                content_stdout, content_stderr = await content_result.communicate()
                content = content_stdout.decode().strip()
                
                if content:
                    result_text += f"  内容: {content}\n"
                else:
                    result_text += f"  内容: (空ファイル)\n"
                    
            except Exception as e:
                result_text += f"  内容: 読み取りエラー - {str(e)}\n"
            
            result_text += "\n"
        
        return result_text
    
    async def explore_system_directories(self) -> str:
        """システムの主要ディレクトリを調査します"""
        directories = {
            '/home': 'ユーザーホームディレクトリ',
            '/var': '可変データ',
            '/tmp': '一時ファイル',
            '/opt': 'オプションアプリケーション',
            '/usr': 'ユーザープログラム',
            '/etc': '設定ファイル',
            '/root': 'rootホームディレクトリ'
        }
        
        result_text = "システムディレクトリ調査結果:\n\n"
        
        for dir_path, description in directories.items():
            try:
                # ディレクトリの存在確認
                result = await asyncio.create_subprocess_exec(
                    'ls', '-la', dir_path,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await result.communicate()
                
                if result.returncode == 0:
                    contents = stdout.decode()
                    result_text += f"=== {description} ({dir_path}) ===\n"
                    result_text += f"{contents}\n\n"
                else:
                    result_text += f"=== {description} ({dir_path}) ===\n"
                    result_text += f"アクセス不可または存在しません\n\n"
                    
            except Exception as e:
                result_text += f"=== {description} ({dir_path}) ===\n"
                result_text += f"エラー: {str(e)}\n\n"
        
        return result_text
    
    async def check_hidden_files(self, directory: str = '.') -> str:
        """隠しファイルを検索します"""
        try:
            result = await asyncio.create_subprocess_exec(
                'find', directory, '-name', '.*', '-type', 'f', '2>/dev/null',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await result.communicate()
            hidden_files = stdout.decode().strip().split('\n')
            
            if not hidden_files or hidden_files == ['']:
                return f"{directory}に隠しファイルは見つかりませんでした。"
            
            result_text = f"{directory}の隠しファイル:\n"
            for file_path in hidden_files:
                if file_path:
                    result_text += f"- {file_path}\n"
                    
                    # ファイルサイズを確認
                    try:
                        size_result = await asyncio.create_subprocess_exec(
                            'ls', '-la', file_path,
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.PIPE
                        )
                        size_stdout, size_stderr = await size_result.communicate()
                        size_info = size_stdout.decode().strip()
                        result_text += f"  {size_info}\n"
                        
                        # 小さなファイルの場合は内容も表示
                        if os.path.getsize(file_path) < 1024:  # 1KB未満
                            content_result = await asyncio.create_subprocess_exec(
                                'cat', file_path,
                                stdout=asyncio.subprocess.PIPE,
                                stderr=asyncio.subprocess.PIPE
                            )
                            content_stdout, content_stderr = await content_result.communicate()
                            content = content_stdout.decode().strip()
                            if content:
                                result_text += f"  内容: {content}\n"
                        
                        result_text += "\n"
                        
                    except Exception as e:
                        result_text += f"  エラー: {str(e)}\n\n"
            
            return result_text
            
        except Exception as e:
            return f"隠しファイル検索でエラーが発生しました: {str(e)}"
    
    async def comprehensive_exploration(self) -> str:
        """包括的なディレクトリ調査を実行します"""
        result_text = "=== SSH接続後の包括的ディレクトリ調査 ===\n\n"
        
        # 1. 現在のディレクトリ調査
        result_text += "1. 現在のディレクトリ調査:\n"
        result_text += await self.explore_current_directory()
        result_text += "\n\n"
        
        # 2. flagファイル検索
        result_text += "2. flagファイル検索:\n"
        result_text += await self.search_flag_files()
        result_text += "\n\n"
        
        # 3. 隠しファイル検索
        result_text += "3. 隠しファイル検索:\n"
        result_text += await self.check_hidden_files()
        result_text += "\n\n"
        
        # 4. システムディレクトリ調査
        result_text += "4. システムディレクトリ調査:\n"
        result_text += await self.explore_system_directories()
        
        return result_text 