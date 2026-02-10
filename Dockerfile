FROM mcr.microsoft.com/playwright/python:v1.44.0-jammy

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
    iputils-ping \
    iproute2 \
    net-tools \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# 非rootユーザーの作成
RUN useradd -m -s /bin/bash hacker

# sudoの設定
RUN echo 'hacker ALL=(ALL) NOPASSWD: /usr/bin/nmap' >> /etc/sudoers && \
    echo 'hacker ALL=(ALL) NOPASSWD: /usr/bin/nmap *' >> /etc/sudoers

# 作業ディレクトリの設定
WORKDIR /app

# 依存関係のコピーとインストール
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Playwrightのブラウザはベースイメージに含まれているためインストール不要
# RUN python -m playwright install --with-deps

# アプリケーションファイルのコピー
#COPY main.py .
#COPY modules/ ./modules/
#COPY nse_scripts/ ./nse_scripts/
#COPY utils/ ./utils/
COPY . .

# scan_resultsディレクトリの作成
RUN mkdir -p scan_results

# レポート保存用のディレクトリを作成し、全ユーザーに書き込み権限を付与
RUN mkdir -p /app/reports && chmod 777 /app/reports

# スタートアップスクリプトをコピー
COPY startup.sh .
RUN dos2unix startup.sh && chmod +x startup.sh

# 権限の設定
RUN chown -R hacker:hacker /app

# 非rootユーザーに切り替え
USER hacker

# 依存ライブラリの冗長なstdoutを抑える（MCPはstdoutをJSON-RPC専用にするため）
ENV CI=1

# Apache2の自動起動を無効化（もしインストールされていれば）
RUN if [ -f /etc/init.d/apache2 ]; then update-rc.d apache2 disable; fi

# スタートアップスクリプトを実行
CMD ["/bin/bash", "./startup.sh"]