FROM python:3.11-slim

# 基本パッケージのインストール
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    nmap \
    dnsutils \
    curl \
    sudo \
    libxml2-dev \
    libxslt-dev \
    gcc \
    bash \
    dos2unix \
    libpcap0.8 \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# OpenVPN関連パッケージ（オプション機能用）
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    openvpn \
    iptables \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# TUNデバイスの準備（VPN使用時のみ必要）
RUN mkdir -p /dev/net

# 非rootユーザーの作成
RUN useradd -m -s /bin/bash recon

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
COPY nse_scripts/ ./nse_scripts/

# scan_resultsディレクトリの作成
RUN mkdir -p scan_results

# スタートアップスクリプトをコピー
COPY startup.sh .
RUN dos2unix startup.sh && chmod +x startup.sh

# 権限の設定
RUN chown -R recon:recon /app

# 非rootユーザーに切り替え
USER recon

# 環境変数でVPN使用可否を制御
ENV USE_VPN=false
ENV VPN_CONFIG_PATH=/vpn/client.ovpn
ENV VPN_AUTH_PATH=/vpn/auth.txt

# スタートアップスクリプトを実行
CMD ["/bin/bash", "./startup.sh"]