# recon-mcp
recon-mcp is a conversational reconnaissance interface and MCP server.

# Recon MCP Server

Claude DesktopからReconnaissance（偵察）機能を安全に実行するためのMCPサーバです。

## 機能

### 基本機能
- **高速ポートスキャン**: SYNスキャンによる高速スキャン
- **サービス検出**: バージョン情報付きサービス検出
- **OS検出**: ターゲットのOS情報取得
- **脆弱性スキャン**: NSEスクリプトによる脆弱性チェック
- **UDPスキャン**: UDPポートのスキャン

### セキュリティ機能
- プライベートIPレンジへのスキャン防止
- レート制限（1分間に5回まで）
- 実行タイムアウト設定
- 限定的sudo権限（nmapのみ）

## セットアップ

### 1. リポジトリのクローン
```bash
git clone <your-repo-url>
cd recon-mcp
```

### 2. Dockerイメージのビルド
```bash
docker build -t recon-mcp .
```

### 3. 動作テスト
```bash
# 基本テスト
docker run --rm recon-mcp python test_nmap.py

# サーバー起動テスト
docker run --rm -p 8000:8000 recon-mcp
```

### 4. Claude Desktop設定

Claude Desktopの設定ファイルに以下を追加：

```json
{
  "mcpServers": {
    "recon-mcp": {
      "command": "docker",
      "args": [
        "run", "--rm", "-p", "8000:8000", "recon-mcp:latest"
      ],
      "env": {
        "LOG_LEVEL": "INFO"
      }
    }
  }
}
```

## 使用方法

### Claude Desktopでの使用例

```
# 基本的なポートスキャン
webサーバのポートをスキャンしてください
対象: example.com
ポートカテゴリ: web

# サービス検出
example.comのサービス情報を取得してください

# OS検出
example.comのOS情報を調べてください
```

### 利用可能なツール

1. **nmap_quick_scan**
   - 高速SYNスキャン
   - ポートカテゴリ: web, mail, db, remote, dns, top100, top1000, custom

2. **nmap_service_scan**
   - サービス・バージョン検出
   - 積極的検出オプション

3. **nmap_os_detection**
   - OS検出とフィンガープリンティング

4. **nmap_vulnerability_scan**
   - 脆弱性スキャン（NSEスクリプト）
   - カテゴリ: vuln, safe, default, discovery

5. **nmap_udp_scan**
   - UDPポートスキャン

## ポートカテゴリ

- **web**: 80,443,8080,8443,3000,5000
- **mail**: 25,110,143,993,995
- **db**: 1433,3306,5432,27017,6379
- **remote**: 22,23,3389,5900
- **dns**: 53
- **top100**: よく使用される100ポート
- **top1000**: よく使用される1000ポート
- **custom**: カスタムポート指定

## セキュリティ考慮事項

### ブロック対象IPレンジ
- 10.0.0.0/8 (プライベートIPv4)
- 172.16.0.0/12 (プライベートIPv4)
- 192.168.0.0/16 (プライベートIPv4)
- 127.0.0.0/8 (ループバック)
- 169.254.0.0/16 (リンクローカル)
- 224.0.0.0/4 (マルチキャスト)

### 制限事項
- レート制限: 1分間に5回までの実行
- タイムアウト: 各スキャンに適切なタイムアウト設定
- sudo権限: nmapコマンドのみに限定

## トラブルシューティング

### よくある問題

1. **sudo権限エラー**
   ```bash
   # Dockerコンテナ内で確認
   docker exec -it <container> sudo -l
   ```

2. **ポート接続エラー**
   ```bash
   # ポート8000が使用可能か確認
   netstat -tulpn | grep 8000
   ```

3. **nmapインストール確認**
   ```bash
   # nmapバージョン確認
   docker run --rm recon-mcp nmap --version
   ```

### ログ確認
```bash
# コンテナログの確認
docker logs <container-name>

# リアルタイムログ
docker logs -f <container-name>
```

## 開発・カスタマイズ

### 新機能の追加
1. `enhanced_mcp_server.py`にツールを追加
2. `list_tools()`にツール定義を追加
3. 対応するメソッドを実装

### テスト方法
```bash
# 単体テスト
python test_nmap.py

# MCPサーバーテスト
python enhanced_mcp_server.py
```

## 注意事項

- このツールは教育・研究目的での使用を想定しています
- ターゲットへのスキャンは事前に許可を取得してください
- 法的責任は使用者にあります
- 過度なスキャンはネットワークに負荷をかける可能性があります

## ライセンス

MIT License