from typing import Dict, List, Optional
from mcp.server.fastmcp import FastMCP
import asyncio
import subprocess
import re
from datetime import datetime
from lxml import etree
from pathlib import Path
import sys
import json

# MCPサーバーの初期化
mcp = FastMCP("nmap-scanner")

# 定数
OUTPUT_DIR = Path("scan_results")
OUTPUT_DIR.mkdir(exist_ok=True)

# デフォルトのnmapオプション
DEFAULT_OPTIONS = [
    "-T5",        # 最も積極的なタイミングテンプレート
    "-Pn",        # ホスト検出をスキップ
    "--min-rate=300",  # 1秒あたり最低300パケット
    "--max-retries=2", # 再試行回数を2回に制限
    "--host-timeout=30m"  # ホストあたりの最大タイムアウト30分
]

# 詳細スキャン用の追加オプション
DETAILED_SCAN_OPTIONS = [
    "-sV",  # バージョン検出
]

# nmapオプションの日本語説明
NMAP_OPTIONS_JP = {
    "-sV": "バージョン検出を実行します。開いているポートでサービスのバージョンを特定します。",
    "-sC": "デフォルトのスクリプトスキャンを実行します。基本的なセキュリティチェックを行います。",
    "-T5": "最も積極的なタイミングテンプレート。最速のスキャンを実行します。",
    "-Pn": "ホストの存在確認をスキップします。全てのホストがオンラインとして扱われます。",
    "--min-rate": "1秒あたりの最小パケット送信数を指定します。スキャン速度を保証します。",
    "--max-retries": "パケット再送信の最大回数を制限します。応答のないホストの処理を早めます。",
    "--host-timeout": "1つのホストに対する最大スキャン時間を制限します。"
}

# ポート状態の日本語説明
PORT_STATES_JP = {
    "open": "開放",
    "closed": "閉鎖",
    "filtered": "フィルタリング済み",
    "unfiltered": "フィルタリングなし",
    "open|filtered": "開放またはフィルタリング済み",
    "closed|filtered": "閉鎖またはフィルタリング済み"
}

# プロトコルの日本語説明
PROTOCOLS_JP = {
    "tcp": "TCP",
    "udp": "UDP",
    "sctp": "SCTP",
    "ip": "IP"
}

# サービスごとのペネトレーションテストアプローチ
PENTEST_APPROACHES = {
    "http": {
        "description": "Webサーバー",
        "approaches": [
            "ディレクトリ列挙: dirb, gobuster, dirbuster\n    例: gobuster dir -u http://target -w /usr/share/wordlists/dirb/common.txt",
            "脆弱性スキャン: nikto, OWASP ZAP, Burp Suite\n    例: nikto -h http://target",
            "SQLインジェクションテスト: sqlmap\n    例: sqlmap -u http://target/page.php?id=1",
            "XSS脆弱性テスト: XSSer, Burp Suite\n    例: xsser --url http://target/page.php?id=1",
            "Webアプリケーション調査: Burp Suite, OWASP ZAP\n    例: zaproxy -quickurl http://target",
            "SSL/TLS設定チェック: testssl.sh, sslscan\n    例: testssl.sh target"
        ]
    },
    "ssh": {
        "description": "SSHサーバー",
        "approaches": [
            "ブルートフォース攻撃対策の確認: hydra, medusa\n    例: hydra -l user -P /usr/share/wordlists/rockyou.txt ssh://target",
            "弱いSSHキーの使用確認: ssh-audit\n    例: ssh-audit target",
            "古いプロトコルバージョンの確認: ssh-audit\n    例: ssh-audit --level=warn target",
            "SSH設定の監査: lynis\n    例: lynis audit system --tests-category=SSH"
        ]
    },
    "ftp": {
        "description": "FTPサーバー",
        "approaches": [
            "匿名ログインの確認: nmap scripts\n    例: nmap --script ftp-anon target",
            "ブルートフォース攻撃: hydra, medusa\n    例: hydra -L users.txt -P pass.txt ftp://target",
            "FTPバナー情報の収集: nmap scripts\n    例: nmap -sV --script=ftp-* target",
            "既知の脆弱性の確認: searchsploit\n    例: searchsploit vsftpd",
            "設定ファイルの列挙: nmap scripts\n    例: nmap --script ftp-vsftpd-backdoor target"
        ]
    },
    "mysql": {
        "description": "MySQLデータベース",
        "approaches": [
            "デフォルトクレデンシャルの確認: nmap scripts\n    例: nmap --script mysql-empty-password target",
            "ブルートフォース攻撃: hydra, medusa\n    例: hydra -l root -P /usr/share/wordlists/rockyou.txt mysql://target",
            "SQLインジェクション可能性の確認: sqlmap\n    例: sqlmap -u 'http://target/page.php?id=1' --dbs",
            "権限設定の確認: MySQLライブラリ\n    例: mysql -h target -u root -p -e 'SHOW GRANTS'",
            "設定ファイルの監査: lynis\n    例: lynis audit system --tests-category=DATABASES"
        ]
    },
    "smb": {
        "description": "Sambaファイル共有",
        "approaches": [
            "共有フォルダの列挙: enum4linux, smbmap\n    例: enum4linux -a target\n    例: smbmap -H target",
            "NULL認証の確認: nmap scripts\n    例: nmap --script smb-enum-shares target",
            "既知の脆弱性（EternalBlue等）の確認: nmap scripts\n    例: nmap --script smb-vuln* target",
            "ブルートフォース攻撃: hydra, medusa\n    例: hydra -l Administrator -P /usr/share/wordlists/rockyou.txt smb://target",
            "SMBバージョン情報の収集: nmap scripts\n    例: nmap -sV --script=smb-os-discovery target"
        ]
    },
    "rdp": {
        "description": "Windowsリモートデスクトップ",
        "approaches": [
            "ブルートフォース攻撃: hydra, crowbar\n    例: hydra -l administrator -P /usr/share/wordlists/rockyou.txt rdp://target",
            "BlueKeep脆弱性の確認: nmap scripts\n    例: nmap --script rdp-vuln-ms12-020 target",
            "RDPセキュリティ設定の確認: rdp-sec-check\n    例: rdp-sec-check.pl target"
        ]
    },
    "mssql": {
        "description": "Microsoft SQLサーバー",
        "approaches": [
            "デフォルトクレデンシャルの確認: nmap scripts\n    例: nmap --script ms-sql-empty-password target",
            "ブルートフォース攻撃: hydra\n    例: hydra -l sa -P /usr/share/wordlists/rockyou.txt mssql://target",
            "SQLインジェクション: sqlmap\n    例: sqlmap -u 'http://target/page.asp?id=1' --dbms=mssql",
            "設定の監査: PowerUpSQL\n    例: Invoke-SQLAudit -Instance target"
        ]
    }
}

def get_pentest_advice(service_name: str, version: str) -> str:
    """サービスとバージョンに基づいてペネトレーションテストのアドバイスを提供"""
    service_name = service_name.lower()
    base_service = next((s for s in PENTEST_APPROACHES.keys() if s in service_name), None)
    
    if not base_service:
        return f"サービス '{service_name}' に対する具体的なアプローチは登録されていません。\n一般的な手順:\n- バージョン情報の詳細調査\n- 既知の脆弱性データベースの確認\n- サービス固有の設定ミスの確認"

    advice = PENTEST_APPROACHES[base_service]
    result = [
        f"\n{advice['description']}（{service_name}）に対する推奨アプローチ：",
        f"検出されたバージョン: {version if version else '不明'}"
    ]
    
    if version:
        result.append("\n推奨アクション:")
        result.append(f"- searchsploit で '{service_name} {version}' の既知の脆弱性を確認")
        result.append(f"- ExploitDBで '{service_name} {version}' の脆弱性を検索")
        result.append(f"- CVE Details で '{service_name} {version}' の脆弱性を確認")
    
    result.append("\n推奨されるテストとツール:")
    result.extend([f"- {approach}" for approach in advice["approaches"]])
    
    return "\n".join(result)

def get_service_description(service: Dict) -> str:
    """サービス情報を日本語で整形"""
    name = service.get("name", "不明")
    product = service.get("product", "")
    version = service.get("version", "")
    extra = service.get("extrainfo", "")
    
    description = [name]
    if product:
        description.append(f"製品: {product}")
    if version:
        description.append(f"バージョン: {version}")
    if extra:
        description.append(f"追加情報: {extra}")
    
    return " | ".join(description)

# XMLパーサーの設定
PARSER = etree.XMLParser(
    remove_blank_text=True,  # 空白テキストを削除
    resolve_entities=False,   # 外部エンティティを解決しない
    huge_tree=True,          # 大きなXMLツリーを許可
    recover=True             # エラーから回復を試みる
)

async def run_nmap_scan(target: str, options: List[str] = None) -> Dict:
    """nmapスキャンを実行し結果を返します"""
    try:
        # 基本コマンドの設定（デフォルトオプションを含む）
        cmd = ["nmap", "-oX", "-"] + DEFAULT_OPTIONS
        
        # 追加オプションの処理
        if options:
            for opt in options:
                if re.match(r'^(-p|-sV|-sC|-A|-T\d|-Pn|-F|--min-rate|--max-retries|--host-timeout)$', opt):
                    if opt not in cmd:  # 重複を避ける
                        cmd.append(opt)
        
        cmd.append(target)
        print(f"実行コマンド: {' '.join(cmd)}", file=sys.stderr)

        # スキャンの実行（タイムアウト設定付き）
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            limit=1024*1024  # バッファサイズを1MBに設定
        )
        
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=3600)
        except asyncio.TimeoutError:
            process.terminate()
            return {"status": "error", "message": "スキャンがタイムアウトしました（1時間）"}

        if process.returncode != 0:
            return {"status": "error", "message": stderr.decode()}

        # XML結果のパース（lxmlを使用）
        try:
            root = etree.fromstring(stdout, parser=PARSER)
            scan_stats = root.find(".//finished")
            
            return {
                "status": "success",
                "scan_info": {
                    "target": target,
                    "start_time": datetime.fromtimestamp(int(root.get("start", "0"))).strftime("%Y-%m-%d %H:%M:%S"),
                    "args": root.get("args", ""),
                    "scan_time": f"{scan_stats.get('elapsed', '0')}秒" if scan_stats is not None else "不明",
                    "hosts_up": scan_stats.get('up', '0') if scan_stats is not None else "0",
                    "hosts_down": scan_stats.get('down', '0') if scan_stats is not None else "0"
                },
                "hosts": [parse_host(host) for host in root.findall(".//host")]
            }
        except etree.XMLSyntaxError as e:
            return {"status": "error", "message": f"XMLパースエラー: {str(e)}"}

    except Exception as e:
        return {"status": "error", "message": str(e)}

def parse_host(host: etree._Element) -> Dict:
    """ホスト情報をパースします"""
    return {
        "status": host.find(".//status").get("state", "") if host.find(".//status") is not None else "",
        "addresses": [{"type": addr.get("addrtype", ""), "addr": addr.get("addr", "")} 
                     for addr in host.findall(".//address")],
        "hostnames": [{"name": h.get("name", ""), "type": h.get("type", "")} 
                     for h in host.findall(".//hostname")] if host.find(".//hostnames") is not None else [],
        "ports": [parse_port(port) for port in host.findall(".//port")] if host.find(".//ports") is not None else []
    }

def parse_port(port: etree._Element) -> Dict:
    """ポート情報をパースします"""
    service = port.find(".//service")
    return {
        "protocol": port.get("protocol", ""),
        "portid": port.get("portid", ""),
        "state": port.find(".//state").get("state", "") if port.find(".//state") is not None else "",
        "service": {
            "name": service.get("name", ""),
            "product": service.get("product", ""),
            "version": service.get("version", ""),
            "extrainfo": service.get("extrainfo", "")
        } if service is not None else {}
    }

@mcp.tool()
async def show_nmap_options() -> str:
    """利用可能なnmapオプションを表示します"""
    return "\n\n".join([f"{opt}:\n  {desc}" for opt, desc in NMAP_OPTIONS_JP.items()])

@mcp.tool()
async def scan_target(target: str, options: List[str] = None, detailed: bool = False) -> str:
    """指定されたターゲットをスキャンします
    
    Args:
        target: スキャン対象のホスト/ネットワーク
        options: 追加のnmapオプション
        detailed: Trueの場合、開放ポートに対してバージョン検出とスクリプトスキャンを実行
    """
    # 基本スキャンの実行（高速モード）
    base_options = [
        "-F",  # 高速モード（上位100ポート）
        "-Pn",  # ホスト検出をスキップ（必須）
        "-T4",  # 積極的なタイミングテンプレート
        "--min-rate=1000",  # 1秒あたり最低1000パケット
        "--max-retries=2"  # 再試行回数を2回に制限
    ]
    if options:
        # ユーザー指定のオプションを追加（-Fが含まれている場合は除外）
        base_options.extend([opt for opt in options if opt != "-F"])
    
    print("基本的なポートスキャンを実行します（高速モード）", file=sys.stderr)
    base_result = await run_nmap_scan(target, base_options)
    
    if base_result["status"] == "error":
        return f"スキャン失敗: {base_result['message']}"
    
    # 開放ポートの抽出
    open_ports = []
    for host in base_result["hosts"]:
        for port in host["ports"]:
            if port["state"] == "open":
                open_ports.append(port["portid"])
    
    # 詳細スキャンの実行（開放ポートのみ）
    if detailed and open_ports:
        print(f"開放ポート {', '.join(open_ports)} に対して詳細スキャンを実行します", file=sys.stderr)
        detailed_options = [
            f"-p{','.join(open_ports)}",  # 開放ポートのみをスキャン
            "-Pn",  # ホスト検出をスキップ（必須）
            "-sV",  # バージョン検出
            "--version-intensity=4",  # バージョン検出の強度を軽めに設定
            "-T4",  # 積極的なタイミングテンプレート
            "--min-rate=300",  # 1秒あたり最低300パケット
            "--max-retries=2",  # 再試行回数を2回に制限
            "--host-timeout=10m"  # ホストあたりの最大タイムアウト10分
        ]
        if options:
            # ユーザー指定のオプションを追加（-Fは除外）
            detailed_options.extend([opt for opt in options if opt != "-F"])
        
        result = await run_nmap_scan(target, detailed_options)
    else:
        result = base_result
    
    if result["status"] == "error":
        return f"スキャン失敗: {result['message']}"
    
    # 結果の整形
    output = [
        "【スキャン結果】",
        f"実行時刻: {result['scan_info']['start_time']}",
        f"実行時間: {result['scan_info']['scan_time']}",
        f"応答ホスト数: {result['scan_info']['hosts_up']}",
        f"無応答ホスト数: {result['scan_info']['hosts_down']}\n"
    ]
    
    hosts = result["hosts"]
    if not hosts:
        return "スキャン中にアクティブなホストは見つかりませんでした。"
    
    # ホスト情報の表示
    for host in hosts:
        # IPアドレスとホスト名
        addresses = [addr["addr"] for addr in host["addresses"]]
        output.append(f"\n対象ホスト: {', '.join(addresses)}")
        output.append(f"ステータス: {host['status']}")
        
        if host["hostnames"]:
            hostnames = [h["name"] for h in host["hostnames"]]
            output.append(f"ホスト名: {', '.join(hostnames)}")
        
        # ポートスキャン結果
        if host["ports"]:
            output.append("\n検出されたポート:")
            for port in host["ports"]:
                state = PORT_STATES_JP.get(port["state"], port["state"])
                protocol = PROTOCOLS_JP.get(port["protocol"], port["protocol"])
                service_desc = get_service_description(port["service"])
                
                output.append(f"\n  ポート {port['portid']}/{protocol}")
                output.append(f"  状態: {state}")
                output.append(f"  サービス: {service_desc}")
                
                # 詳細スキャンの場合のみペネトレーションテストのアドバイスを表示
                if detailed and port["state"] == "open" and port["service"].get("name"):
                    version = f"{port['service'].get('product', '')} {port['service'].get('version', '')}".strip()
                    advice = get_pentest_advice(port["service"]["name"], version)
                    output.append(f"\n  セキュリティ評価手順:\n{advice}")
        
        output.append("\n" + "="*50)
    
    # 詳細スキャンが無効の場合、詳細スキャンの実行方法を案内
    if not detailed:
        output.append("\n詳細な情報（バージョン、スクリプトスキャン）を取得するには:")
        output.append("await scan_target(target, detailed=True)")
    
    return "\n".join(output)

if __name__ == "__main__":
    try:
        # 明示的にイベントループを取得
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        # MCPサーバーを実行
        loop.run_until_complete(mcp.run(transport="stdio"))
    except KeyboardInterrupt:
        print("プログラムが中断されました", file=sys.stderr)
    except Exception as e:
        print(f"エラーが発生しました: {e}", file=sys.stderr)
    finally:
        # 実行中のタスクをキャンセル
        for task in asyncio.all_tasks(loop):
            task.cancel()
        
        # イベントループを閉じる
        loop.run_until_complete(loop.shutdown_asyncgens())
        loop.close() 