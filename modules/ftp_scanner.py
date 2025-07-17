# ftp_scanner.py (Fully curl-powered version)

import asyncio
import socket
import os
from typing import Dict, List
from datetime import datetime
import re

class FTPScanner:
    def __init__(self):
        self.timeout = 30
    
    async def scan_ftp_anonymous_login(self, target: str, port: int = 21) -> Dict:
        result = {
            "target": target, "port": port, "timestamp": datetime.now().isoformat(),
            "ftp_server_info": {}, "anonymous_login": {}, "security_issues": [], "recommendations": []
        }
        try:
            result["ftp_server_info"] = await self._get_ftp_server_info(target, port)
            result["anonymous_login"] = await self._test_anonymous_login(target, port)
            result["security_issues"] = self._analyze_security_issues(result["anonymous_login"], result["ftp_server_info"])["issues"]
            result["recommendations"] = self._analyze_security_issues(result["anonymous_login"], result["ftp_server_info"])["recommendations"]
        except Exception as e:
            result["error"] = str(e)
        return result
    
    async def _get_ftp_server_info(self, target: str, port: int) -> Dict:
        info = { "banner": "", "version": "" }
        try:
            # Use curl to get the initial banner
            cmd = f"curl --connect-timeout 10 -v ftp://{target}:{port}/"
            process = await asyncio.create_subprocess_shell(cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            _, stderr = await process.communicate()
            
            lines = stderr.decode('utf-8', errors='ignore').splitlines()
            banner_line = next((line for line in lines if line.startswith('< 220')), None)
            if banner_line:
                info["banner"] = banner_line.replace('< 220 ', '').strip()
                match = re.search(r'vsFTPd\s*(\d+\.\d+(\.\d+)?)', info["banner"], re.IGNORECASE)
                if match:
                    info["version"] = match.group(0)
        except Exception as e:
            info["error"] = str(e)
        return info

    async def _test_anonymous_login(self, target: str, port: int) -> Dict:
        result = {
            "enabled": False, "credentials": [], "access_level": "none",
            "files_accessible": [], "error": None
        }
        cmd = f"curl --connect-timeout {self.timeout} ftp://{target}:{port}/ --user anonymous:"
        process = await asyncio.create_subprocess_shell(cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        stdout, stderr = await process.communicate()

        if process.returncode == 0:
            result["enabled"] = True
            result["credentials"].append({"username": "anonymous", "password": ""})
            files = stdout.decode('utf-8').strip().splitlines()
            parsed_files = []
            for line in files:
                parts = line.split()
                if len(parts) >= 9:
                    parsed_files.append(" ".join(parts[8:]))
            if parsed_files:
                result["files_accessible"] = sorted(list(set(parsed_files)))
                result["access_level"] = "read"
            else:
                result["error"] = "Login successful, but directory is empty."
        else:
            result["enabled"] = True
            error_message = stderr.decode('utf-8').strip()
            result["error"] = f"curl command failed with return code {process.returncode}: {error_message}"
        return result

    def _analyze_security_issues(self, anonymous_result: Dict, server_info: Dict) -> Dict:
        issues = []
        recommendations = []
        if anonymous_result.get("enabled"):
            issues.append("匿名ログインが有効になっています")
            issues.append("認証なしでFTPサーバーにアクセス可能です")
        if len(anonymous_result.get("files_accessible", [])) > 0:
            issues.append(f"匿名ユーザーが{len(anonymous_result['files_accessible'])}個のファイルにアクセス可能です")
        recommendations.append("匿名ログインを無効にしてください")
        recommendations.append("強力な認証メカニズムを実装してください")
        return {"issues": issues, "recommendations": recommendations}
    
    async def generate_report(self, scan_result: Dict) -> str:
        report = []
        report.append("=" * 60)
        report.append("FTP匿名ログイン セキュリティスキャンレポート")
        report.append("=" * 60)
        report.append(f"対象: {scan_result.get('target')}:{scan_result.get('port')}")
        report.append(f"スキャン日時: {scan_result.get('timestamp')}")
        report.append("")
        if scan_result.get("ftp_server_info"):
            server_info = scan_result["ftp_server_info"]
            report.append("【FTPサーバー情報】")
            report.append("-" * 30)
            if server_info.get("banner"): report.append(f"バナー: {server_info['banner']}")
            if server_info.get("version"): report.append(f"バージョン: {server_info['version']}")
            report.append("")
        anonymous = scan_result.get("anonymous_login", {})
        report.append("【匿名ログイン分析】")
        report.append("-" * 30)
        report.append(f"匿名ログイン: {'有効' if anonymous.get('enabled') else '無効'}")
        if anonymous.get('enabled'):
            report.append(f"アクセスレベル: {anonymous.get('access_level', 'none')}")
            if anonymous.get("error"): report.append(f"リスト取得エラー: {anonymous['error']}")
            if anonymous.get("credentials"):
                report.append("使用可能な認証情報:")
                for cred in anonymous["credentials"]:
                    report.append(f"  - ユーザー名: {cred['username']}, パスワード: {cred['password']}")
            if anonymous.get("files_accessible"):
                report.append(f"アクセス可能なファイル数: {len(anonymous['files_accessible'])}")
                report.append("ファイル一覧:")
                for file in anonymous["files_accessible"]: report.append(f"  - {file}")
        report.append("")
        if scan_result.get("security_issues"):
            report.append("【セキュリティ問題】")
            report.append("-" * 30)
            for issue in scan_result["security_issues"]: report.append(f"⚠️  {issue}")
            report.append("")
        if scan_result.get("recommendations"):
            report.append("【セキュリティ推奨事項】")
            report.append("-" * 30)
            for rec in scan_result["recommendations"]: report.append(f"✓ {rec}")
            report.append("")
        report.append("=" * 60)
        return "\n".join(report)

    async def download_file(self, target: str, port: int, username: str, password: str, remote_path: str, local_path: str) -> str:
        # Add --max-time 60 to allow 60 seconds for the entire operation
        cmd = f"curl --silent --show-error --connect-timeout {self.timeout} --max-time 60 -o {local_path} ftp://{target}:{port}/{remote_path} --user {username}:{password}"
        process = await asyncio.create_subprocess_shell(cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        _, stderr = await process.communicate()
        if process.returncode == 0:
            return f"✅ File '{remote_path}' downloaded successfully to '{local_path}'"
        else:
            error_message = stderr.decode('utf-8').strip()
            return f"❌ curl command failed to download file '{remote_path}'. Error: {error_message}"

    async def read_file(self, target: str, port: int, username: str, password: str, remote_path: str, max_size: int = 65536) -> str:
        # Add --max-time 60 to allow 60 seconds for the entire operation
        cmd = f"curl --silent --show-error --connect-timeout {self.timeout} --max-time 60 ftp://{target}:{port}/{remote_path} --user {username}:{password}"
        process = await asyncio.create_subprocess_shell(cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        stdout, stderr = await process.communicate()
        if process.returncode == 0:
            content_bytes = stdout
            if len(content_bytes) > max_size:
                return f"❌ File content exceeds the limit of {max_size / 1024} KB."
            content = content_bytes.decode('utf-8', errors='ignore')
            return f"--- Content of {remote_path} ---\n\n{content}"
        else:
            error_message = stderr.decode('utf-8').strip()
            return f"❌ curl command failed to read file '{remote_path}'. Error: {error_message}"