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
    lua5.4 \
    iproute2 \
    net-tools \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# 非rootユーザーの作成
RUN useradd -m -s /bin/bash recon

# sudoの設定
RUN echo 'recon ALL=(ALL) NOPASSWD: /usr/bin/nmap' >> /etc/sudoers && \
    echo 'recon ALL=(ALL) NOPASSWD: /usr/bin/nmap *' >> /etc/sudoers

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

# スタートアップスクリプトを実行
CMD ["/bin/bash", "./startup.sh"]