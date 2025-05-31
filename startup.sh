#!/bin/bash

echo "=== Recon Scanner MCP Server ==="
echo "Initializing..."

# VPN設定の確認と接続
if [ "$USE_VPN" = "true" ]; then
    echo "VPN mode enabled - checking configuration..."
    
    # VPN設定ファイルの存在確認
    if [ -f "$VPN_CONFIG_PATH" ]; then
        echo "✓ VPN config found: $VPN_CONFIG_PATH"
        
        # TUNデバイスの作成（権限が必要な場合）
        if [ ! -c /dev/net/tun ]; then
            echo "Creating TUN device..."
            sudo mknod /dev/net/tun c 10 200 2>/dev/null || echo "TUN device creation skipped (may already exist)"
        fi
        
        # 認証ファイルの確認
        AUTH_OPTION=""
        if [ -f "$VPN_AUTH_PATH" ]; then
            echo "✓ VPN auth file found"
            AUTH_OPTION="--auth-user-pass $VPN_AUTH_PATH"
        else
            echo "⚠ VPN auth file not found - interactive auth may be required"
        fi
        
        echo "Starting VPN connection..."
        sudo /usr/sbin/openvpn \
            --config "$VPN_CONFIG_PATH" \
            $AUTH_OPTION \
            --daemon \
            --log /tmp/openvpn.log \
            --writepid /tmp/openvpn.pid
        
        # VPN接続の確立を待機
        echo "Waiting for VPN connection..."
        for i in {1..30}; do
            if pgrep -f openvpn > /dev/null; then
                sleep 2
                # 外部接続テスト
                if curl -s --connect-timeout 10 --max-time 15 https://ipinfo.io/ip > /tmp/current_ip.txt 2>/dev/null; then
                    CURRENT_IP=$(cat /tmp/current_ip.txt)
                    echo "✓ VPN connected successfully!"
                    echo "✓ Public IP: $CURRENT_IP"
                    break
                fi
            fi
            echo "  Waiting... ($i/30)"
            sleep 2
        done
        
        # 接続状況の最終確認
        if ! pgrep -f openvpn > /dev/null; then
            echo "❌ VPN connection failed!"
            echo "OpenVPN log:"
            cat /tmp/openvpn.log 2>/dev/null || echo "No log available"
            echo ""
            echo "⚠ Continuing without VPN..."
        fi
        
    else
        echo "❌ VPN config file not found: $VPN_CONFIG_PATH"
        echo "⚠ Continuing without VPN..."
        echo ""
        echo "To use VPN functionality:"
        echo "  1. Mount your VPN config: -v /path/to/vpn:/vpn"
        echo "  2. Set environment: -e USE_VPN=true"
        echo "  3. Add capabilities: --cap-add=NET_ADMIN --device=/dev/net/tun"
    fi
    
else
    echo "VPN mode disabled - running in standard mode"
    echo ""
    echo "To enable VPN mode:"
    echo "  docker run -e USE_VPN=true --cap-add=NET_ADMIN --device=/dev/net/tun -v /path/to/vpn:/vpn ..."
fi

echo ""
echo "=== Network Information ==="
# 現在のネットワーク状況を表示
if command -v curl > /dev/null 2>&1; then
    if CURRENT_IP=$(curl -s --connect-timeout 5 https://ipinfo.io/ip 2>/dev/null); then
        echo "Public IP: $CURRENT_IP"
    else
        echo "Public IP: Unable to detect (network issue or no internet)"
    fi
else
    echo "Public IP: curl not available"
fi

echo "Local IP: $(hostname -i 2>/dev/null || echo 'Not available')"
echo ""

echo "=== Starting MCP Server ==="
echo "Ready to accept connections..."
echo ""

# メインアプリケーションを起動
exec python main.py