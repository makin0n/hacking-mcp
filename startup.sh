#!/bin/bash

# ログメッセージをstderrに出力（MCPはstdoutをJSON-RPC専用にするため）
log_message() {
    local message="$1"
    echo "{\"jsonrpc\":\"2.0\",\"method\":\"log\",\"params\":{\"message\":\"$message\"}}" >&2
}

# 初期化処理の出力をすべてstderrにリダイレクトするブロック
{
    # もしapache2が起動していたら停止する
    if service apache2 status >/dev/null 2>&1; then
        service apache2 stop >/dev/null 2>&1 || true
    fi

    # 初期化メッセージ
    log_message "Hacking MCP v1.9.2"
    log_message "=== Network Information ==="

    # パブリックIPの取得
    PUBLIC_IP=$(curl -s https://api.ipify.org)
    log_message "Public IP: $PUBLIC_IP"

    # ローカルIPの取得
    LOCAL_IP=$(hostname -I | awk '{print $1}')
    log_message "Local IP: $LOCAL_IP"

    # サーバー起動メッセージ
    log_message "Starting API Server..."
    log_message "Modules loaded:"
    log_message "- OSINT Scanner"
    log_message "- Vulnerability Scanner"
    log_message "- Network Scanner"
    log_message "- Web Scanner"
    log_message "- DNS Scanner"

    # 機能一覧
    log_message "Features:"
    log_message "- Domain Investigation"
    log_message "- Web Security Audit"
    log_message "- Network Reconnaissance"
    log_message "- Service Analysis"
    log_message "- Vulnerability Assessment"

    # MCPのstdoutを汚さないよう、依存ライブラリの冗長出力を抑える
    export CI=1
    unset PWDEBUG 2>/dev/null || true

} >&2

# サーバー起動（stdoutはMCP専用のため、execでPythonに置換）
exec python main.py