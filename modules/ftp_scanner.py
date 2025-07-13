import asyncio
import socket
import ftplib
import os
from typing import Dict, List, Optional, Tuple
from datetime import datetime

class FTPScanner:
    def __init__(self):
        self.timeout = 10
        self.anonymous_credentials = [
            ("anonymous", ""),
            ("anonymous", "anonymous"),
            ("anonymous", "guest"),
            ("ftp", ""),
            ("ftp", "ftp"),
            ("guest", ""),
            ("guest", "guest")
        ]
    
    async def scan_ftp_anonymous_login(self, target: str, port: int = 21) -> Dict:
        """FTP匿名ログインのスキャンを実行"""
        result = {
            "target": target,
            "port": port,
            "timestamp": datetime.now().isoformat(),
            "ftp_server_info": {},
            "anonymous_login": {
                "enabled": False,
                "credentials": [],
                "access_level": "none",
                "files_accessible": [],
                "directories_accessible": []
            },
            "security_issues": [],
            "recommendations": []
        }
        
        try:
            # FTPサーバーの基本情報を取得
            server_info = await self._get_ftp_server_info(target, port)
            result["ftp_server_info"] = server_info
            
            # 匿名ログインのテスト
            anonymous_result = await self._test_anonymous_login(target, port)
            result["anonymous_login"] = anonymous_result
            
            # セキュリティ問題の分析
            security_analysis = self._analyze_security_issues(anonymous_result, server_info)
            result["security_issues"] = security_analysis["issues"]
            result["recommendations"] = security_analysis["recommendations"]
            
        except Exception as e:
            result["error"] = str(e)
        
        return result
    
    async def _get_ftp_server_info(self, target: str, port: int) -> Dict:
        """FTPサーバーの基本情報を取得"""
        info = {
            "banner": "",
            "version": "",
            "features": []
        }
        
        try:
            # ソケット接続でバナー情報を取得
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))
            
            # バナー情報を受信
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            info["banner"] = banner
            
            # バナーからバージョン情報を抽出
            if banner:
                # 一般的なFTPサーバーのバージョンパターンを検索
                version_patterns = [
                    r'vsFTPd (\d+\.\d+)',
                    r'ProFTPD (\d+\.\d+)',
                    r'FileZilla Server (\d+\.\d+)',
                    r'Microsoft FTP Service',
                    r'Pure-FTPd (\d+\.\d+)'
                ]
                
                for pattern in version_patterns:
                    import re
                    match = re.search(pattern, banner, re.IGNORECASE)
                    if match:
                        info["version"] = match.group(0)
                        break
            
            sock.close()
            
        except Exception as e:
            info["error"] = str(e)
        
        return info
    
    async def _test_anonymous_login(self, target: str, port: int) -> Dict:
        """匿名ログインをテスト"""
        result = {
            "enabled": False,
            "credentials": [],
            "access_level": "none",
            "files_accessible": [],
            "directories_accessible": []
        }
        
        for username, password in self.anonymous_credentials:
            try:
                # FTP接続を試行
                ftp = ftplib.FTP()
                ftp.connect(target, port, timeout=self.timeout)
                
                # ログイン試行
                login_result = ftp.login(username, password)
                
                if "230" in login_result:  # ログイン成功
                    result["enabled"] = True
                    result["credentials"].append({
                        "username": username,
                        "password": password,
                        "response": login_result
                    })
                    
                    # アクセス可能なファイルとディレクトリを列挙
                    try:
                        # 現在のディレクトリの内容を取得
                        files = ftp.nlst()
                        result["files_accessible"] = files
                        
                        # ディレクトリを特定
                        directories = []
                        for item in files:
                            try:
                                ftp.cwd(item)
                                directories.append(item)
                                ftp.cwd("..")  # 元のディレクトリに戻る
                            except:
                                pass
                        
                        result["directories_accessible"] = directories
                        
                        # アクセスレベルを判定
                        if len(files) > 0:
                            result["access_level"] = "read"
                            if len(directories) > 0:
                                result["access_level"] = "browse"
                        
                    except Exception as e:
                        result["access_level"] = "limited"
                    
                    ftp.quit()
                    break  # 成功したら終了
                
                ftp.quit()
                
            except Exception as e:
                continue
        
        return result
    
    def _analyze_security_issues(self, anonymous_result: Dict, server_info: Dict) -> Dict:
        """セキュリティ問題を分析"""
        issues = []
        recommendations = []
        
        # 匿名ログインが有効な場合
        if anonymous_result["enabled"]:
            issues.append("匿名ログインが有効になっています")
            issues.append("認証なしでFTPサーバーにアクセス可能です")
            
            if anonymous_result["access_level"] in ["read", "browse"]:
                issues.append("匿名ユーザーがファイルやディレクトリにアクセス可能です")
            
            if len(anonymous_result["files_accessible"]) > 0:
                issues.append(f"匿名ユーザーが{len(anonymous_result['files_accessible'])}個のファイルにアクセス可能です")
            
            recommendations.append("匿名ログインを無効にしてください")
            recommendations.append("強力な認証メカニズムを実装してください")
            recommendations.append("アクセス制御リスト（ACL）を設定してください")
        
        # FTPサーバーのバージョン情報から脆弱性をチェック
        if server_info.get("version"):
            version = server_info["version"].lower()
            
            # 古いバージョンのチェック
            if "vsftpd 2.3.4" in version:
                issues.append("vsFTPd 2.3.4は既知のバックドア脆弱性があります")
                recommendations.append("FTPサーバーを最新バージョンにアップデートしてください")
            
            if "proftpd" in version and "1.3.3" in version:
                issues.append("ProFTPD 1.3.3c以前には脆弱性があります")
                recommendations.append("ProFTPDを最新バージョンにアップデートしてください")
        
        # 一般的な推奨事項
        recommendations.append("SFTPまたはFTPSの使用を検討してください")
        recommendations.append("FTP通信の暗号化を実装してください")
        recommendations.append("ログ監視とアラートを設定してください")
        recommendations.append("定期的なセキュリティ監査を実施してください")
        
        return {
            "issues": issues,
            "recommendations": recommendations
        }
    
    async def generate_report(self, scan_result: Dict) -> str:
        """スキャン結果からレポートを生成"""
        report = []
        report.append("=" * 60)
        report.append("FTP匿名ログイン セキュリティスキャンレポート")
        report.append("=" * 60)
        report.append(f"対象: {scan_result['target']}:{scan_result['port']}")
        report.append(f"スキャン日時: {scan_result['timestamp']}")
        report.append("")
        
        # FTPサーバー情報
        if scan_result.get("ftp_server_info"):
            server_info = scan_result["ftp_server_info"]
            report.append("【FTPサーバー情報】")
            report.append("-" * 30)
            if server_info.get("banner"):
                report.append(f"バナー: {server_info['banner']}")
            if server_info.get("version"):
                report.append(f"バージョン: {server_info['version']}")
            report.append("")
        
        # 匿名ログイン結果
        anonymous = scan_result["anonymous_login"]
        report.append("【匿名ログイン分析】")
        report.append("-" * 30)
        report.append(f"匿名ログイン: {'有効' if anonymous['enabled'] else '無効'}")
        
        if anonymous["enabled"]:
            report.append(f"アクセスレベル: {anonymous['access_level']}")
            
            if anonymous["credentials"]:
                report.append("使用可能な認証情報:")
                for cred in anonymous["credentials"]:
                    report.append(f"  - ユーザー名: {cred['username']}, パスワード: {cred['password']}")
            
            if anonymous["files_accessible"]:
                report.append(f"アクセス可能なファイル数: {len(anonymous['files_accessible'])}")
                if len(anonymous["files_accessible"]) <= 10:
                    report.append("ファイル一覧:")
                    for file in anonymous["files_accessible"]:
                        report.append(f"  - {file}")
            
            if anonymous["directories_accessible"]:
                report.append(f"アクセス可能なディレクトリ数: {len(anonymous['directories_accessible'])}")
                report.append("ディレクトリ一覧:")
                for dir in anonymous["directories_accessible"]:
                    report.append(f"  - {dir}")
        
        report.append("")
        
        # セキュリティ問題
        if scan_result.get("security_issues"):
            report.append("【セキュリティ問題】")
            report.append("-" * 30)
            for issue in scan_result["security_issues"]:
                report.append(f"⚠️  {issue}")
            report.append("")
        
        # 推奨事項
        if scan_result.get("recommendations"):
            report.append("【セキュリティ推奨事項】")
            report.append("-" * 30)
            for rec in scan_result["recommendations"]:
                report.append(f"✓ {rec}")
            report.append("")
        
        # エラー情報
        if scan_result.get("error"):
            report.append("【エラー情報】")
            report.append("-" * 30)
            report.append(f"エラー: {scan_result['error']}")
            report.append("")
        
        report.append("=" * 60)
        
        return "\n".join(report)
    
    async def get_status(self) -> str:
        """FTP Scannerの状態確認"""
        return f"Available - FTP Anonymous Login Scanner (Timeout: {self.timeout}s)" 