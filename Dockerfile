FROM python:3.11-alpine

# 基本パッケージのインストール
RUN apk update && apk add --no-cache \
    nmap \
    nmap-scripts \
    bind-tools \
    dig \
    curl \
    sudo \
    shadow \
    libxml2-dev \
    libxslt-dev \
    gcc \
    musl-dev \
    bash \
    && rm -rf /var/cache/apk/*

# OpenVPN関連パッケージ（オプション機能用）
RUN apk add --no-cache \
    openvpn \
    iptables \
    && rm -rf /var/cache/apk/*

# TUNデバイスの準備（VPN使用時のみ必要）
RUN mkdir -p /dev/net

# 非rootユーザーの作成
RUN adduser -D -s /bin/sh recon

# sudoの設定
RUN echo 'recon ALL=(ALL) NOPASSWD: /usr/bin/nmap' >> /etc/sudoers && \
    echo 'recon ALL=(ALL) NOPASSWD: /usr/bin/nmap *' >> /etc/sudoers && \
    echo 'recon ALL=(ALL) NOPASSWD: /usr/sbin/openvpn' >> /etc/sudoers && \
    echo 'recon ALL=(ALL) NOPASSWD: /sbin/ip' >> /etc/sudoers

# 作業ディレクトリの設定
WORKDIR /app

# 依存関係のコピーとインストール
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# アプリケーションファイルのコピー
COPY main.py .
COPY modules/ ./modules/

# scan_resultsディレクトリの作成
RUN mkdir -p scan_results

# スタートアップスクリプトをコピー
COPY startup.sh .
RUN chmod +x startup.sh

# 権限の設定
RUN chown -R recon:recon /app

# 非rootユーザーに切り替え
USER recon

# 環境変数でVPN使用可否を制御
ENV USE_VPN=false
ENV VPN_CONFIG_PATH=/vpn/client.ovpn
ENV VPN_AUTH_PATH=/vpn/auth.txt

# スタートアップスクリプトを実行
CMD ["./startup.sh"]