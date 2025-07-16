from mcp.server.fastmcp import FastMCP
import sys
from typing import List, Optional
from datetime import datetime
import os
import tempfile
import shutil
import asyncio

# モジュールのインポート
from modules.nmap_scanner import NmapScanner
from modules.web_scanner import WebScanner
from modules.dns_scanner import DNSScanner
from modules.service_analyzer import ServiceAnalyzer
from modules.ftp_scanner import FTPScanner
from modules.hydra_scanner import HydraScanner
from modules.osint_scanner import OSINTScanner, OSINTResult
from modules.ssh_explorer import SSHExplorer
from utils.report_manager import ReportManager

# 統合MCPサーバーの初期化
mcp = FastMCP("recon-scanner")

# 各スキャナーモジュールのインスタンス化
nmap_scanner = NmapScanner()
web_scanner = WebScanner()
dns_scanner = DNSScanner()
service_analyzer = ServiceAnalyzer()
ftp_scanner = FTPScanner()
hydra_scanner = HydraScanner()
osint_scanner = OSINTScanner()
ssh_explorer = SSHExplorer()

# =============================================================================
# Nmap関連ツール
# =============================================================================

@mcp.tool()
async def nmap_basic_scan(target: str, options: Optional[List[str]] = None) -> str:
    """基本的なnmapスキャンを実行します
    
    Args:
        target: スキャン対象のホスト/ネットワーク
        options: 追加のnmapオプション（例: ["-sV", "-p80,443"]）
    """
    return await nmap_scanner.basic_scan(target, options)

@mcp.tool()
async def nmap_detailed_scan(target: str, ports: str) -> str:
    """詳細なnmapスキャン（バージョン検出付き）を実行します
    
    Args:
        target: スキャン対象のホスト/ネットワーク
        ports: スキャン対象のポート（必須）
    """
    return await nmap_scanner.detailed_scan(target, ports)

@mcp.tool()
async def nmap_port_scan(target: str, ports: str) -> str:
    """指定したポートのみをスキャンします
    
    Args:
        target: スキャン対象のホスト/ネットワーク
        ports: ポート指定（例: "80,443" または "1-1000"）
    """
    return await nmap_scanner.port_scan(target, ports)



# =============================================================================
# Web関連ツール
# =============================================================================

@mcp.tool()
async def web_check_headers(url: str) -> str:
    """WebサイトのHTTPヘッダーを確認します
    
    Args:
        url: チェック対象のURL
    """
    return await web_scanner.check_headers(url)

@mcp.tool()
async def web_check_security(url: str) -> str:
    """Webサイトのセキュリティヘッダーを確認します
    
    Args:
        url: チェック対象のURL
    """
    return await web_scanner.check_security_headers(url)

@mcp.tool()
async def web_check_robots(url: str) -> str:
    """robots.txtの内容を確認します
    
    Args:
        url: チェック対象のURL
    """
    return await web_scanner.check_robots_txt(url)

@mcp.tool()
async def web_basic_info(url: str) -> str:
    """Webサイトの基本情報を取得します（レスポンス時間、ステータス、サーバー情報など）
    
    Args:
        url: チェック対象のURL
    """
    return await web_scanner.get_basic_info(url)

@mcp.tool()
async def web_technology_detection(url: str) -> str:
    """Webサイトで使用されている技術（CMS、フレームワーク、サーバーなど）を検出します
    
    Args:
        url: チェック対象のURL
    """
    return await web_scanner.technology_detection(url)

@mcp.tool()
async def web_directory_scan(url: str, wordlist: str = "common") -> str:
    """Webディレクトリ・ファイルスキャンを実行します（gobuster風）
    
    Args:
        url: チェック対象のURL
        wordlist: 使用するwordlist（"common", "dirs", "files"）
    """
    return await web_scanner.directory_scan(url, wordlist)

@mcp.tool()
async def web_comprehensive_scan(url: str) -> str:
    """包括的Webスキャン（基本情報、技術検出、セキュリティチェック、ファイルスキャン）
    
    Args:
        url: チェック対象のURL
    """
    return await web_scanner.comprehensive_web_scan(url)

# =============================================================================
# DNS関連ツール
# =============================================================================

@mcp.tool()
async def dns_lookup(domain: str, record_type: str = "A") -> str:
    """DNS レコードを検索します
    
    Args:
        domain: 検索対象のドメイン名
        record_type: レコードタイプ（A, AAAA, MX, NS, TXT, CNAME, SOA）
    """
    return await dns_scanner.dns_lookup(domain, record_type)

@mcp.tool()
async def dns_subdomain_enum(domain: str, wordlist: str = "common") -> str:
    """サブドメイン列挙を実行します
    
    Args:
        domain: 対象ドメイン名
        wordlist: 使用するwordlist（現在は"common"のみ）
    """
    return await dns_scanner.subdomain_enum(domain, wordlist)

@mcp.tool()
async def dns_reverse_lookup(ip: str) -> str:
    """逆引きDNS（PTRレコード）検索を実行します
    
    Args:
        ip: 逆引きするIPアドレス
    """
    return await dns_scanner.reverse_dns(ip)

@mcp.tool()
async def dns_comprehensive(domain: str) -> str:
    """包括的DNS調査（全レコードタイプ + サブドメイン列挙）
    
    Args:
        domain: 調査対象のドメイン名
    """
    return await dns_scanner.dns_comprehensive(domain)

# =============================================================================
# ポートサービス分析ツール
# =============================================================================

@mcp.tool()
async def service_analyze_nmap(nmap_output: str) -> str:
    """nmapの結果を解析してサービスのセキュリティ分析を実行します
    
    Args:
        nmap_output: nmapスキャンの結果テキスト
    """
    return await service_analyzer.analyze_nmap_results(nmap_output)

@mcp.tool()
async def service_quick_analysis(target: str, port: int) -> str:
    """特定ポートのクイックセキュリティ分析を実行します
    
    Args:
        target: 対象ホスト
        port: 分析するポート番号
    """
    return await service_analyzer.quick_port_analysis(target, port)

# =============================================================================
# FTP関連ツール
# =============================================================================

@mcp.tool()
async def ftp_anonymous_scan(target: str, port: int = 21) -> str:
    """FTP匿名ログインのセキュリティスキャンを実行します
    
    Args:
        target: スキャン対象のホスト
        port: FTPポート番号（デフォルト: 21）
    """
    scan_result = await ftp_scanner.scan_ftp_anonymous_login(target, port)
    return await ftp_scanner.generate_report(scan_result)

@mcp.tool()
async def ftp_server_info(target: str, port: int = 21) -> str:
    """FTPサーバーの基本情報を取得します
    
    Args:
        target: スキャン対象のホスト
        port: FTPポート番号（デフォルト: 21）
    """
    server_info = await ftp_scanner._get_ftp_server_info(target, port)
    
    result = []
    result.append("=== FTP SERVER INFORMATION ===")
    result.append(f"Target: {target}:{port}")
    result.append("")
    
    if server_info.get("banner"):
        result.append(f"Banner: {server_info['banner']}")
    if server_info.get("version"):
        result.append(f"Version: {server_info['version']}")
    if server_info.get("error"):
        result.append(f"Error: {server_info['error']}")
    
    return "\n".join(result)

@mcp.tool()
async def ftp_download_and_read_files(target: str, filenames: List[str]) -> str:
    """
    【最終安定版】FTPサーバーからファイルを一つずつ、間に遅延を挟んでダウンロードし、内容を読み込んで表示します。

    Args:
        target: FTPサーバーのIPアドレスまたはホスト名
        filenames: 内容を取得したいファイル名のリスト (例: ["task.txt", "locks.txt"])
    """
    temp_dir = tempfile.mkdtemp()
    results = []
    results.append(f"=== FTP File Content Retrieval for {target} ===")
    
    download_success = []
    download_errors = []

    results.append("\n--- Phase 1: Downloading files (with tactical delays) ---")
    for i, filename in enumerate(filenames):
        local_path = os.path.join(temp_dir, filename)
        
        results.append(f"  - Attempting to download: {filename}")
        download_result = await ftp_scanner.download_file(
            target=target, port=21, username="anonymous", password="",
            remote_path=filename, local_path=local_path
        )

        if "✅" in download_result:
            results.append(f"    └ SUCCESS.")
            download_success.append(filename)
        else:
            results.append(f"    └ FAILED. Error: {download_result}")
            download_errors.append(filename)
        
        # 最後のファイルでなければ、サーバーのレート制限を回避するために15秒間の遅延を入れる
        if i < len(filenames) - 1:
            results.append("    - Waiting 15 seconds to bypass server rate-limiting...")
            await asyncio.sleep(15)

    results.append("\n--- Phase 2: Reading downloaded files ---")
    if not download_success:
        results.append("No files were successfully downloaded.")
    else:
        for filename in download_success:
            try:
                local_path = os.path.join(temp_dir, filename)
                with open(local_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                results.append(f"\n--- Content of {filename} ---")
                results.append(content)
            except Exception as e:
                results.append(f"\n--- Failed to read local file {filename} ---")
                results.append(f"Error: {e}")

    shutil.rmtree(temp_dir)
    results.append("\n========================================")
    results.append("Process finished.")
    
    return "\n".join(results)

# =============================================================================
# ブルートフォース攻撃ツール
# =============================================================================

@mcp.tool()
async def ssh_login_test(target: str, username: str, password: str, port: int = 22) -> str:
    """
    指定のIDとPasswordを使用してSSHログインを試し、cron権限昇格の分析も実行します。

    Args:
        target: ログイン対象のIPアドレスまたはホスト名
        username: ログイン試行するユーザー名
        password: ログイン試行するパスワード
        port: SSHサービスのポート番号 (デフォルト: 22)
    """
    return await hydra_scanner.ssh_login_test(target, username, password, port)

@mcp.tool()
async def ssh_cron_privilege_escalation(target: str, username: str, password: str, port: int = 22) -> str:
    """
    SSHログイン後にcronジョブの権限昇格の悪用を試します。

    Args:
        target: ログイン対象のIPアドレスまたはホスト名
        username: ログイン試行するユーザー名
        password: ログイン試行するパスワード
        port: SSHサービスのポート番号 (デフォルト: 22)
    """
    return await hydra_scanner.ssh_login_test(target, username, password, port)

@mcp.tool()
async def ssh_hydra_attack(target: str, username: str, password_list_path: str, port: int = 22) -> str:
    """
    Hydraを使い、SSHに対してパスワードリスト攻撃（ブルートフォース）を実行します。

    Args:
        target: 攻撃対象のIPアドレスまたはホスト名
        username: 攻撃対象のユーザー名
        password_list_path: パスワードリストのパス（Dockerコンテナ内のパス）。
                            事前にftp_download_file等で入手したリストを /tmp/pass.txt などに保存して使用してください。
        port: SSHサービスのポート番号 (デフォルト: 22)
    """
    return await hydra_scanner.ssh_brute_force(target, port, username, password_list_path)

# =============================================================================
# 統合・包括的スキャン機能
# =============================================================================

@mcp.tool()
async def quick_recon(target: str) -> str:
    """クイック偵察：基本的なnmapスキャンとWeb情報取得を実行します
    
    Args:
        target: スキャン対象（IPアドレス、ドメイン名、URL）
    """
    results = []
    
    # 基本的なnmapスキャン
    results.append("=== NETWORK SCAN (Nmap) ===")
    nmap_result = await nmap_scanner.basic_scan(target)
    results.append(nmap_result)
    
    # nmapの結果をサービス分析
    results.append("\n=== SERVICE ANALYSIS ===")
    service_analysis = await service_analyzer.analyze_nmap_results(nmap_result)
    results.append(service_analysis)
    
    # WebサイトかどうかチェックしてWeb分析を実行
    if target.startswith(('http://', 'https://')):
        web_target = target
    elif '.' in target and not '/' in target:
        # ドメイン名の場合はHTTPSを試してからHTTP
        web_target = f"https://{target}"
    else:
        web_target = None
    
    if web_target:
        results.append("\n=== WEB ANALYSIS ===")
        web_result = await web_scanner.get_basic_info(web_target)
        results.append(web_result)
        
        # 技術検出
        results.append("\n=== TECHNOLOGY DETECTION ===")
        tech_result = await web_scanner.technology_detection(web_target)
        results.append(tech_result)
    
    return "\n".join(results)

@mcp.tool()
async def comprehensive_recon(target: str) -> str:
    """包括的偵察：DNS、nmap、Web、サービス分析のフルスキャン
    
    Args:
        target: スキャン対象（ドメイン名推奨）
    """
    results = []
    results.append("=== COMPREHENSIVE RECONNAISSANCE ===")
    results.append(f"Target: {target}")
    results.append("=" * 60)
    
    # 1. DNS包括調査
    if not target.startswith(('http://', 'https://')) and '.' in target:
        results.append("\n1. DNS Investigation")
        results.append("-" * 30)
        dns_result = await dns_scanner.dns_comprehensive(target)
        results.append(dns_result)
    
    # 2. ネットワークスキャン（詳細版）
    results.append("\n2. Network Scan (Detailed)")
    results.append("-" * 30)
    detailed_nmap = await nmap_scanner.detailed_scan(target)
    results.append(detailed_nmap)
    
    # 3. サービス分析
    results.append("\n3. Service Security Analysis")
    results.append("-" * 30)
    service_analysis = await service_analyzer.analyze_nmap_results(detailed_nmap)
    results.append(service_analysis)
    
    # 4. Web包括分析（HTTPサービスが見つかった場合）
    if any(port in detailed_nmap for port in ['80', '443', '8080', '8443']):
        web_target = target
        if not target.startswith(('http://', 'https://')):
            # HTTPSを優先して試行
            web_target = f"https://{target}"
        
        results.append("\n4. Web Application Analysis")
        results.append("-" * 30)
        web_comprehensive = await web_scanner.comprehensive_web_scan(web_target)
        results.append(web_comprehensive)
    
    # 5. FTP匿名ログイン分析（FTPサービスが見つかった場合）
    if any(port in detailed_nmap for port in ['21', '2121']):
        results.append("\n5. FTP Anonymous Login Analysis")
        results.append("-" * 35)
        ftp_result = await ftp_scanner.scan_ftp_anonymous_login(target, 21)
        ftp_report = await ftp_scanner.generate_report(ftp_result)
        results.append(ftp_report)
    
    return "\n".join(results)

@mcp.tool()
async def domain_investigation(domain: str) -> str:
    """ドメイン専用調査：DNS、Whois、Web技術、サブドメインの包括調査
    
    Args:
        domain: 調査対象のドメイン名
    """
    results = []
    results.append("=== DOMAIN INVESTIGATION ===")
    results.append(f"Target Domain: {domain}")
    results.append("=" * 50)
    
    # 1. DNS包括調査
    results.append("\n1. DNS Records Analysis")
    results.append("-" * 30)
    dns_result = await dns_scanner.dns_comprehensive(domain)
    results.append(dns_result)
    
    # 2. Web技術検出
    results.append("\n2. Web Technology Stack")
    results.append("-" * 30)
    https_url = f"https://{domain}"
    tech_result = await web_scanner.technology_detection(https_url)
    results.append(tech_result)
    
    # 3. セキュリティヘッダー分析
    results.append("\n3. Web Security Headers")
    results.append("-" * 30)
    security_result = await web_scanner.check_security_headers(https_url)
    results.append(security_result)
    
    # 4. 基本的なポートスキャン
    results.append("\n4. Basic Port Scan")
    results.append("-" * 30)
    port_result = await nmap_scanner.basic_scan(domain)
    results.append(port_result)
    
    return "\n".join(results)

@mcp.tool()
async def web_security_audit(url: str) -> str:
    """Web セキュリティ監査：包括的なWebアプリケーション セキュリティチェック
    
    Args:
        url: 監査対象のURL
    """
    results = []
    results.append("=== WEB SECURITY AUDIT ===")
    results.append(f"Target: {url}")
    results.append("=" * 50)
    
    # 1. 基本情報とレスポンス分析
    results.append("\n1. Basic Information & Response Analysis")
    results.append("-" * 45)
    basic_info = await web_scanner.get_basic_info(url)
    results.append(basic_info)
    
    # 2. セキュリティヘッダー詳細分析
    results.append("\n2. Security Headers Analysis")
    results.append("-" * 35)
    security_headers = await web_scanner.check_security_headers(url)
    results.append(security_headers)
    
    # 3. 技術スタック検出
    results.append("\n3. Technology Stack Detection")
    results.append("-" * 35)
    tech_detection = await web_scanner.technology_detection(url)
    results.append(tech_detection)
    
    # 4. 共通ファイル・ディレクトリ検索
    results.append("\n4. Common Files & Directories")
    results.append("-" * 35)
    dir_scan = await web_scanner.directory_scan(url, "common")
    results.append(dir_scan)
    
    # 5. robots.txt分析
    results.append("\n5. robots.txt Analysis")
    results.append("-" * 25)
    robots_analysis = await web_scanner.check_robots_txt(url)
    results.append(robots_analysis)
    
    return "\n".join(results)



# =============================================================================
# OSINTツール
# =============================================================================

@mcp.tool()
async def osint_scan(target: str) -> str:
    """OSINTスキャンを実行します
    
    Args:
        target: スキャン対象のドメイン名またはIPアドレス
    """
    try:
        scanner = OSINTScanner()
        result = await scanner.scan(target)
        return format_result(result)
    except Exception as e:
        return f"OSINTスキャン中にエラーが発生しました: {str(e)}"

# =============================================================================
# レポート作成ツール
# =============================================================================

@mcp.tool()
async def comprehensive_recon_with_report(target: str) -> str:
    """包括的偵察を行い、結果をレポートとして保存します"""
    
    # 1. レポートマネージャーを初期化
    report = ReportManager(target)
    print(f"[*] Starting comprehensive recon with reporting for {target}...")
    
    # 2. ネットワークスキャンを実行し、レポートに追記
    # まず基本スキャンで開放ポートを特定
    basic_nmap = await nmap_scanner.basic_scan(target)
    open_ports = nmap_scanner._extract_open_ports_from_result(basic_nmap)
    
    if open_ports:
        ports_str = ",".join(open_ports)
        detailed_nmap = await nmap_scanner.detailed_scan(target, ports_str)
    else:
        detailed_nmap = basic_nmap
    
    report.add_section("Nmap Scan Results", detailed_nmap)
    
    # 3. HTTP/HTTPSサービスがあればスクリーンショットを撮影
    open_ports = nmap_scanner._extract_open_ports_from_result(detailed_nmap)
    web_ports_found = False # Webポートが見つかったかどうかのフラグ
    
    for port in open_ports:
        # 一般的なWebポートをチェック
        if port in ['80', '443', '8080', '8443']:
            web_ports_found = True
            protocol = "https" if port in ['443', '8443'] else "http"
            # ポート番号を含めたURLを生成
            service_url = f"{protocol}://{target}:{port}"
            
            ss_filename = f"{service_url.replace('://', '_').replace(':', '_')}.png"
            ss_path = os.path.join(report.ss_dir, ss_filename)
            
            if await web_scanner.take_screenshot(service_url, ss_path):
                report.add_screenshot(service_url, ss_path)

    # 4. DNSスキャンを実行し、レポートに追記
    dns_result = await dns_scanner.dns_comprehensive(target)
    report.add_section("DNS Analysis", dns_result)

    # 5. Webポートが見つかった場合のみ、Web包括分析を実行
    if web_ports_found:
        # web_scannerが賢くなったので、ターゲットをそのまま渡すだけで良い
        web_comprehensive = await web_scanner.comprehensive_web_scan(target)
        report.add_section("Web Application Analysis", web_comprehensive)
    else:
        report.add_section("Web Application Analysis", "No open web ports (80, 443, 8080, 8443) found. Skipping web scan.")

    # 6. 最後に短い完了メッセージだけを返す
    final_message = f"✅ Scan complete. Full report saved at: {report.report_path}"
    print(final_message) # 念のためコンテナのログにも出力
    return final_message

# =============================================================================
# SSH接続後調査ツール
# =============================================================================

@mcp.tool()
async def ssh_explore_current_directory() -> str:
    """SSH接続後の現在のディレクトリを調査します"""
    return await ssh_explorer.explore_current_directory()

@mcp.tool()
async def ssh_search_flag_files(search_paths: Optional[List[str]] = None) -> str:
    """SSH接続後にflag*.txtやroot.txtファイルを網羅的に検索します
    
    Args:
        search_paths: 検索するパスのリスト（指定しない場合は主要ディレクトリを検索）
    """
    return await ssh_explorer.search_flag_files(search_paths)

@mcp.tool()
async def ssh_explore_system_directories() -> str:
    """SSH接続後にシステムの主要ディレクトリを調査します"""
    return await ssh_explorer.explore_system_directories()

@mcp.tool()
async def ssh_check_hidden_files(directory: str = '.') -> str:
    """SSH接続後に隠しファイルを検索します
    
    Args:
        directory: 検索するディレクトリ（デフォルト: 現在のディレクトリ）
    """
    return await ssh_explorer.check_hidden_files(directory)

@mcp.tool()
async def ssh_comprehensive_exploration() -> str:
    """SSH接続後にflag*.txtやroot.txtファイルを網羅的に検索します"""
    return await ssh_explorer.comprehensive_exploration()

# =============================================================================
# ステータス・ヘルプ機能
# =============================================================================

@mcp.tool()
async def scanner_status() -> str:
    """スキャナーの状態とバージョン情報を表示します"""
    status = [
        "=== RECON SCANNER STATUS ===",
        "",
        f"Nmap Scanner: {await nmap_scanner.get_status()}",
        f"Web Scanner: {await web_scanner.get_status()}",
        f"DNS Scanner: {await dns_scanner.get_status()}",
        f"Service Analyzer: {await service_analyzer.get_status()}",
        f"FTP Scanner: {await ftp_scanner.get_status()}",
        "",
        "=== AVAILABLE TOOL CATEGORIES ===",
        "",
        "🔍 Network Scanning (nmap_*):",
        "  • nmap_basic_scan: 基本ポートスキャン（高速）",
        "  • nmap_detailed_scan: 詳細スキャン（バージョン検出）",
        "  • nmap_port_scan: 指定ポートスキャン",
        "",
        "🌐 Web Application Testing (web_*):",
        "  • web_basic_info: Web基本情報取得",
        "  • web_check_headers: HTTPヘッダー確認",
        "  • web_check_security: セキュリティヘッダー確認",
        "  • web_technology_detection: 技術スタック検出",
        "  • web_directory_scan: ディレクトリ・ファイルスキャン",
        "  • web_comprehensive_scan: 包括的Webスキャン",
        "  • web_security_audit: Webセキュリティ監査",
        "",
        "🔍 DNS Investigation (dns_*):",
        "  • dns_lookup: DNSレコード検索",
        "  • dns_subdomain_enum: サブドメイン列挙",
        "  • dns_reverse_lookup: 逆引きDNS",
        "  • dns_comprehensive: 包括的DNS調査",
        "",
        "🛡️ Service Analysis (service_*):",
        "  • service_analyze_nmap: nmapの結果を分析",
        "  • service_quick_analysis: 特定ポートの分析",
        "",
        "📁 FTP Security (ftp_*):",
        "  • ftp_anonymous_scan: FTP匿名ログインスキャン",
        "  • ftp_server_info: FTPサーバー情報取得",
        "",
        "🚀 Integrated Reconnaissance:",
        "  • quick_recon: クイック偵察（nmap + web基本）",
        "  • comprehensive_recon: 包括的偵察（フルスキャン）",
        "  • domain_investigation: ドメイン専用調査",
        "  • web_security_audit: Webセキュリティ監査",
        "",
        "🔍 SSH Post-Connection Investigation (ssh_*):",
        "  • ssh_explore_current_directory: 現在のディレクトリ調査",
        "  • ssh_search_flag_files: flag*.txtやroot.txtファイル網羅検索",
        "  • ssh_explore_system_directories: システムディレクトリ調査",
        "  • ssh_check_hidden_files: 隠しファイル検索",
        "  • ssh_comprehensive_exploration: flag*.txtやroot.txtファイル検索",
        "",
        "📊 Utility:",
        "  • scanner_status: この状態表示",
        "",
        "=== USAGE EXAMPLES ===",
        "",
        "Basic scans:",
        "  quick_recon('scanme.nmap.org')",
        "  nmap_basic_scan('127.0.0.1')",
        "  web_check_security('https://example.com')",
        "",
        "Comprehensive analysis:",
        "  comprehensive_recon('example.com')",
        "  domain_investigation('github.com')",
        "  web_security_audit('https://httpbin.org')",
        "",
        "Specific investigations:",
        "  dns_comprehensive('google.com')",
        "  web_technology_detection('https://wordpress.org')",
        "  service_quick_analysis('target.com', 22)"
    ]
    return "\n".join(status)

@mcp.tool()
async def show_wordlists() -> str:
    """利用可能なwordlistとその内容を表示します"""
    result = [
        "=== AVAILABLE WORDLISTS ===",
        "",
        "DNS Subdomain Enumeration:",
        f"  • common: {len(dns_scanner.common_subdomains)} entries",
        f"    Examples: {', '.join(dns_scanner.common_subdomains[:10])}...",
        "",
        "Web Directory/File Scanning:",
        f"  • common: {len(web_scanner.common_dirs + web_scanner.common_files)} entries total",
        f"  • dirs: {len(web_scanner.common_dirs)} directories",
        f"    Examples: {', '.join(web_scanner.common_dirs[:10])}...",
        f"  • files: {len(web_scanner.common_files)} files", 
        f"    Examples: {', '.join(web_scanner.common_files[:10])}...",
        "",
        "Usage:",
        "  dns_subdomain_enum('example.com', 'common')",
        "  web_directory_scan('https://example.com', 'dirs')",
        "  web_directory_scan('https://example.com', 'files')"
    ]
    return "\n".join(result)

def format_result(result: OSINTResult) -> str:
    """OSINTスキャン結果を整形して出力"""
    output = []
    output.append(f"OSINTスキャン結果 - {result.target}")
    output.append(f"スキャン時刻: {result.scan_time}")
    
    if result.domain_info:
        output.append("\n=== ドメイン情報 ===")
        if 'whois' in result.domain_info:
            output.append("\nWHOIS情報:")
            for key, value in result.domain_info['whois'].items():
                output.append(f"  {key}: {value}")
                
        if 'dns' in result.domain_info:
            output.append("\nDNSレコード:")
            for record_type, records in result.domain_info['dns'].items():
                output.append(f"  {record_type}:")
                for record in records:
                    output.append(f"    {record}")
                    
        if 'ssl' in result.domain_info:
            output.append("\nSSL証明書情報:")
            for key, value in result.domain_info['ssl'].items():
                output.append(f"  {key}: {value}")
    
    if result.ip_info:
        output.append("\n=== IP情報 ===")
        if 'location' in result.ip_info:
            output.append("\n位置情報:")
            for key, value in result.ip_info['location'].items():
                output.append(f"  {key}: {value}")
        if 'asn' in result.ip_info:
            output.append(f"\nASN: {result.ip_info['asn']}")
        if 'hostname' in result.ip_info:
            output.append(f"ホスト名: {result.ip_info['hostname']}")
    
    if result.server_info:
        output.append("\n=== サーバー情報 ===")
        if 'server' in result.server_info:
            output.append(f"\nサーバー: {result.server_info['server']}")
        if 'technologies' in result.server_info:
            output.append("\n検出された技術:")
            for tech in result.server_info['technologies']:
                output.append(f"  - {tech}")
    
    return "\n".join(output)

if __name__ == "__main__":
    print("Starting Advanced Recon Scanner MCP server...", file=sys.stderr)
    print("Modules loaded: nmap_scanner, web_scanner, dns_scanner, service_analyzer, ftp_scanner, osint_scanner, ssh_explorer", file=sys.stderr)
    print("Features: Network scanning, Web analysis, DNS investigation, Service security analysis, FTP anonymous login scanning, OSINT scanning, SSH post-connection investigation", file=sys.stderr)
    mcp.run()