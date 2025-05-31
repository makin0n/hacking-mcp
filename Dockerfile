FROM python:3.11-alpine

# 必要なパッケージのインストール
RUN apk update && apk add --no-cache \
    nmap \
    nmap-scripts \
    bind-tools \
    curl \
    sudo \
    shadow \
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
COPY . .

# 権限の設定
RUN chown -R recon:recon /app

# 非rootユーザーに切り替え
USER recon

# ポートの公開（削除）
# EXPOSE 8000

# ヘルスチェック（削除）
# HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
#     CMD curl -f http://localhost:8000/health || exit 1

# アプリケーションの実行
CMD ["python", "enhanced_mcp_server.py"]