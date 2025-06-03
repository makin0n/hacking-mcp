#!/bin/bash

# JSON-RPC 2.0形式でログを出力する関数
log_message() {
    local msg=$1
    echo "{\"jsonrpc\":\"2.0\",\"method\":\"log\",\"params\":{\"message\":\"$msg\"}}"
}

# 標準出力のバッファリングを無効化
export PYTHONUNBUFFERED=1

log_message "Recon Scanner MCP Server initializing..."

# VPN設定の確認と接続
if [ "$USE_VPN" = "true" ]; then
    log_message "VPN mode enabled - checking configuration..."
    
    # VPN設定ファイルの存在確認
    if [ -f "$VPN_CONFIG_PATH" ]; then
        log_message "VPN config found: $VPN_CONFIG_PATH"
        
        # TUNデバイスの作成（権限が必要な場合）
        if [ ! -c /dev/net/tun ]; then
            log_message "Creating TUN device..."
            sudo mknod /dev/net/tun c 10 200 2>/dev/null || log_message "TUN device creation skipped"
        fi
        
        # 認証ファイルの確認
        AUTH_OPTION=""
        if [ -f "$VPN_AUTH_PATH" ]; then
            log_message "VPN auth file found"
            AUTH_OPTION="--auth-user-pass $VPN_AUTH_PATH"
        fi
        
        # OpenVPN接続の開始
        log_message "Starting OpenVPN connection..."
        openvpn --config "$VPN_CONFIG_PATH" $AUTH_OPTION --daemon
        
        # 接続確認のための待機
        sleep 5
        if ping -c 1 8.8.8.8 >/dev/null 2>&1; then
            log_message "VPN connection established"
        else
            log_message "VPN connection failed"
        fi
    else
        log_message "VPN config not found at: $VPN_CONFIG_PATH"
    fi
fi

# ネットワーク情報の表示
log_message "=== Network Information ==="

# パブリックIPアドレスの取得
PUBLIC_IP=$(curl -s ifconfig.me 2>/dev/null || echo "Unable to detect")
log_message "Public IP: $PUBLIC_IP"

# ローカルIPアドレスの取得（Alpine Linux用に修正）
LOCAL_IP=$(ip addr show | awk '/inet / && !/127.0.0.1/ {gsub(/\/.*/, "", $2); print $2}' | head -n1)
if [ -z "$LOCAL_IP" ]; then
    LOCAL_IP="Unable to detect"
fi
log_message "Local IP: $LOCAL_IP"

# メインアプリケーションの起動
log_message "Starting Advanced Recon Scanner MCP server..."
log_message "Modules loaded: nmap_scanner, web_scanner, dns_scanner, service_analyzer"
log_message "Features: Network scanning, Web analysis, DNS investigation, Service security analysis"

# Pythonアプリケーションの実行（バッファリング無効化）
python -u main.py