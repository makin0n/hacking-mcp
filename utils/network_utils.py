import re
import ipaddress
from urllib.parse import urlparse
import validators

def validate_target(target: str) -> bool:
    """スキャン対象の妥当性を検証"""
    if not target or not target.strip():
        return False
    
    target = target.strip()
    
    # IPアドレスの場合
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        pass
    
    # CIDR記法の場合
    try:
        ipaddress.ip_network(target, strict=False)
        return True
    except ValueError:
        pass
    
    # ドメイン名の場合
    if validators.domain(target):
        return True
    
    # URL形式の場合
    if validators.url(target):
        return True
    
    return False

def extract_domain_from_url(url: str) -> str:
    """URLからドメイン名を抽出"""
    try:
        parsed = urlparse(url)
        return parsed.netloc
    except:
        return url

def is_private_ip(ip: str) -> bool:
    """プライベートIPアドレスかどうか判定"""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except:
        return False

def normalize_target(target: str) -> str:
    """対象を正規化"""
    target = target.strip()
    
    # URLの場合はドメインを抽出
    if target.startswith(('http://', 'https://')):
        return extract_domain_from_url(target)
    
    return target

def get_port_service_name(port: int) -> str:
    """ポート番号から一般的なサービス名を取得"""
    common_ports = {
        21: "FTP",
        22: "SSH", 
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        993: "IMAPS",
        995: "POP3S",
        3389: "RDP",
        5432: "PostgreSQL",
        3306: "MySQL",
        1433: "MSSQL"
    }
    
    return common_ports.get(port, "Unknown")