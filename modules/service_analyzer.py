import asyncio
import re
import sys
from typing import Dict, List, Optional, Tuple

class ServiceAnalyzer:
    def __init__(self):
        # ポート番号とサービスの対応表
        self.port_services = {
            21: {"name": "FTP", "description": "File Transfer Protocol"},
            22: {"name": "SSH", "description": "Secure Shell"},
            23: {"name": "Telnet", "description": "Telnet Protocol"},
            25: {"name": "SMTP", "description": "Simple Mail Transfer Protocol"},
            53: {"name": "DNS", "description": "Domain Name System"},
            80: {"name": "HTTP", "description": "Hypertext Transfer Protocol"},
            110: {"name": "POP3", "description": "Post Office Protocol v3"},
            143: {"name": "IMAP", "description": "Internet Message Access Protocol"},
            443: {"name": "HTTPS", "description": "HTTP over SSL/TLS"},
            993: {"name": "IMAPS", "description": "IMAP over SSL"},
            995: {"name": "POP3S", "description": "POP3 over SSL"},
            1433: {"name": "MSSQL", "description": "Microsoft SQL Server"},
            3306: {"name": "MySQL", "description": "MySQL Database"},
            3389: {"name": "RDP", "description": "Remote Desktop Protocol"},
            5432: {"name": "PostgreSQL", "description": "PostgreSQL Database"},
            5900: {"name": "VNC", "description": "Virtual Network Computing"},
            6379: {"name": "Redis", "description": "Redis Database"},
            8080: {"name": "HTTP-Alt", "description": "Alternative HTTP"},
            8443: {"name": "HTTPS-Alt", "description": "Alternative HTTPS"},
            27017: {"name": "MongoDB", "description": "MongoDB Database"}
        }
        
        # サービス別の脆弱性とセキュリティチェック項目
        self.security_checks = {
            "SSH": {
                "common_issues": [
                    "デフォルトポート22の使用",
                    "パスワード認証の有効化",
                    "rootログインの許可",
                    "古いSSHバージョンの使用"
                ],
                "recommendations": [
                    "ポート番号の変更",
                    "公開鍵認証の使用",
                    "rootログインの無効化",
                    "fail2banの導入",
                    "SSH鍵の定期的な更新"
                ],
                "tools": ["ssh-audit", "nmap --script ssh-*"]
            },
            "HTTP": {
                "common_issues": [
                    "HTTPS未使用",
                    "セキュリティヘッダーの不備",
                    "古いWebサーバーバージョン",
                    "ディレクトリリスティングの有効化"
                ],
                "recommendations": [
                    "HTTPS への移行",
                    "セキュリティヘッダーの設定",
                    "Webサーバーの更新",
                    "適切なアクセス制御の実装"
                ],
                "tools": ["nikto", "dirb", "gobuster", "testssl.sh"]
            },
            "HTTPS": {
                "common_issues": [
                    "弱い暗号化スイートの使用",
                    "期限切れ証明書",
                    "自己署名証明書",
                    "混合コンテンツの存在"
                ],
                "recommendations": [
                    "強い暗号化スイートの使用",
                    "証明書の定期的な更新",
                    "HSTS の有効化",
                    "証明書透明性の監視"
                ],
                "tools": ["testssl.sh", "sslscan", "sslyze"]
            },
            "FTP": {
                "common_issues": [
                    "匿名ログインの許可",
                    "平文での通信",
                    "古いFTPサーバーの使用",
                    "適切なアクセス制御の不備"
                ],
                "recommendations": [
                    "SFTP または FTPS の使用",
                    "匿名アクセスの無効化",
                    "強力な認証の実装",
                    "ログ監視の実装"
                ],
                "tools": ["nmap --script ftp-*", "hydra"]
            },
            "MySQL": {
                "common_issues": [
                    "デフォルトのroot空パスワード",
                    "外部からのアクセス許可",
                    "古いMySQLバージョン",
                    "適切な権限設定の不備"
                ],
                "recommendations": [
                    "強力なパスワードの設定",
                    "外部アクセスの制限",
                    "定期的なアップデート",
                    "最小権限の原則の適用"
                ],
                "tools": ["nmap --script mysql-*", "sqlmap"]
            },
            "RDP": {
                "common_issues": [
                    "デフォルトポート3389の使用",
                    "弱いパスワード",
                    "BlueKeep脆弱性",
                    "ネットワークレベル認証の無効化"
                ],
                "recommendations": [
                    "ポート番号の変更",
                    "強力なパスワードの使用",
                    "VPN経由でのアクセス",
                    "定期的なセキュリティ更新"
                ],
                "tools": ["nmap --script rdp-*", "rdesktop"]
            }
        }
        

    
    async def get_status(self) -> str:
        """Service Analyzerの状態確認"""
        return f"Available - {len(self.port_services)} services, {len(self.security_checks)} security profiles"
    
    def analyze_port(self, port: int, service_name: str = "", version: str = "") -> Dict:
        """単一ポートの詳細分析"""
        analysis = {
            "port": port,
            "service_name": service_name,
            "version": version,
            "known_service": None,
            "security_level": "unknown",
            "issues": [],
            "recommendations": [],
            "tools": []
        }
        
        # 既知のサービスかチェック
        if port in self.port_services:
            analysis["known_service"] = self.port_services[port]
            service_type = self.port_services[port]["name"]
            
            # セキュリティチェック項目の追加
            if service_type in self.security_checks:
                check_info = self.security_checks[service_type]
                analysis["issues"] = check_info["common_issues"]
                analysis["recommendations"] = check_info["recommendations"]
                analysis["tools"] = check_info["tools"]
                
                # セキュリティレベルの評価
                analysis["security_level"] = self._evaluate_security_level(port, service_name, version)
        

        
        return analysis
    
    def _evaluate_security_level(self, port: int, service_name: str, version: str) -> str:
        """セキュリティレベルの評価"""
        risk_factors = 0
        
        # 高リスクポート
        high_risk_ports = [21, 23, 25, 110, 143, 1433, 3306, 3389]
        if port in high_risk_ports:
            risk_factors += 1
        
        # 暗号化されていないプロトコル
        unencrypted_ports = [21, 23, 25, 80, 110, 143]
        if port in unencrypted_ports:
            risk_factors += 1
        
        # バージョン情報から古いソフトウェアを検出
        if version:
            if any(old_version in version.lower() for old_version in ["2.0", "1.0", "old", "legacy"]):
                risk_factors += 1
        
        if risk_factors >= 3:
            return "high_risk"
        elif risk_factors >= 2:
            return "medium_risk"
        elif risk_factors >= 1:
            return "low_risk"
        else:
            return "secure"
    

    
    async def analyze_nmap_results(self, nmap_output: str) -> str:
        """nmapの結果を解析してサービス分析を実行"""
        try:
            result = ["=== PORT SERVICE ANALYSIS ==="]
            result.append("Based on nmap scan results")
            result.append("")
            
            # nmapの出力から開放ポート情報を抽出
            ports_info = self._parse_nmap_output(nmap_output)
            
            if not ports_info:
                result.append("No port information found in nmap output")
                return "\n".join(result)
            
            # 各ポートを分析
            for port_info in ports_info:
                port = port_info.get("port")
                service = port_info.get("service", "")
                version = port_info.get("version", "")
                
                if port:
                    analysis = self.analyze_port(int(port), service, version)
                    
                    result.append(f"Port {port} Analysis:")
                    result.append("-" * 40)
                    
                    if analysis["known_service"]:
                        result.append(f"Service: {analysis['known_service']['name']}")
                        result.append(f"Description: {analysis['known_service']['description']}")
                    
                    if service:
                        result.append(f"Detected Service: {service}")
                    if version:
                        result.append(f"Version: {version}")
                    
                    result.append(f"Security Level: {analysis['security_level'].upper()}")
                    
                    if analysis["issues"]:
                        result.append("\nCommon Security Issues:")
                        for issue in analysis["issues"]:
                            result.append(f"  • {issue}")
                    
                    if analysis["recommendations"]:
                        result.append("\nSecurity Recommendations:")
                        for rec in analysis["recommendations"]:
                            result.append(f"  ✓ {rec}")
                    

                    
                    if analysis["tools"]:
                        result.append("\nRecommended Testing Tools:")
                        for tool in analysis["tools"]:
                            result.append(f"  🔧 {tool}")
                    
                    result.append("\n" + "="*60)
            
            # 全体的なセキュリティサマリー
            result.append("\n=== SECURITY SUMMARY ===")
            high_risk_count = sum(1 for info in ports_info if self._evaluate_security_level(
                int(info.get("port", 0)), info.get("service", ""), info.get("version", "")
            ) == "high_risk")
            
            if high_risk_count > 0:
                result.append(f"⚠️  {high_risk_count} high-risk services detected")
                result.append("Priority: Immediate security review required")
            else:
                result.append("✅ No high-risk services detected")
            
            return "\n".join(result)
            
        except Exception as e:
            return f"Error analyzing nmap results: {str(e)}"
    
    def _parse_nmap_output(self, nmap_output: str) -> List[Dict]:
        """nmap出力からポート情報を抽出"""
        ports_info = []
        
        # 簡単な正規表現でポート情報を抽出
        # フォーマット例: "80/tcp - open (Apache 2.4.41)"
        port_pattern = r'(\d+)/\w+\s+-\s+open(?:\s+\(([^)]+)\))?'
        matches = re.findall(port_pattern, nmap_output)
        
        for match in matches:
            port = match[0]
            service_info = match[1] if len(match) > 1 else ""
            
            # サービス名とバージョンを分離
            service_name = ""
            version = ""
            
            if service_info:
                # "Apache 2.4.41" -> service: "Apache", version: "2.4.41"
                parts = service_info.split()
                if parts:
                    service_name = parts[0]
                    if len(parts) > 1:
                        version = " ".join(parts[1:])
            
            ports_info.append({
                "port": port,
                "service": service_name,
                "version": version
            })
        
        return ports_info
    
    async def quick_port_analysis(self, target: str, port: int) -> str:
        """特定ポートのクイック分析"""
        try:
            analysis = self.analyze_port(port)
            
            result = [f"=== QUICK PORT ANALYSIS ==="]
            result.append(f"Target: {target}")
            result.append(f"Port: {port}")
            result.append("")
            
            if analysis["known_service"]:
                result.append(f"Known Service: {analysis['known_service']['name']}")
                result.append(f"Description: {analysis['known_service']['description']}")
                result.append(f"Security Level: {analysis['security_level'].upper()}")
                result.append("")
                
                if analysis["issues"]:
                    result.append("Common Security Concerns:")
                    for issue in analysis["issues"]:
                        result.append(f"  • {issue}")
                    result.append("")
                
                if analysis["recommendations"]:
                    result.append("Security Recommendations:")
                    for rec in analysis["recommendations"]:
                        result.append(f"  ✓ {rec}")
                    result.append("")
                
                if analysis["tools"]:
                    result.append("Recommended Testing Tools:")
                    for tool in analysis["tools"]:
                        result.append(f"  🔧 {tool}")
            else:
                result.append("Unknown service - manual investigation required")
                result.append("Consider running detailed nmap scan with -sV option")
            
            return "\n".join(result)
            
        except Exception as e:
            return f"Error in quick port analysis: {str(e)}"