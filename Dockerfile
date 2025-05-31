FROM python:3.11-alpine

# 必要なパッケージのインストール
RUN apk update && apk add --no-cache \
    nmap \
    nmap-scripts \
    bind-tools \
    curl \
    sudo \
    shadow \
    libxml2-dev \
    libxslt-dev \
    gcc \
    musl-dev \
    && rm -rf /var/cache/apk/*

# 非rootユーザーの作成
RUN adduser -D -s /bin/sh recon

# sudoの設定（nmapのみ許可）
RUN echo 'recon ALL=(ALL) NOPASSWD: /usr/bin/nmap' >> /etc/sudoers && \
    echo 'recon ALL=(ALL) NOPASSWD: /usr/bin/nmap *' >> /etc/sudoers

# 作業ディレクトリの設定
WORKDIR /app

# 依存関係のコピーとインストール
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# アプリケーションファイルのコピー
COPY nmap_service.py .

# scan_resultsディレクトリの作成
RUN mkdir -p scan_results

# 権限の設定
RUN chown -R recon:recon /app

# 非rootユーザーに切り替え
USER recon

# アプリケーションの実行
CMD ["python", "nmap_service.py"]