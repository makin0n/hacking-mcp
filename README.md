# Hacking MCP - 高度なネットワークスキャン・ペネトレーションテストツール

Hacking MCPは、Claude DesktopとDockerを活用した包括的なネットワークスキャン・ペネトレーションテストツールです。
nmap、Hydra、各種セキュリティツールを使用してターゲットシステムの詳細な分析を行い、
Claude Desktopの知識ベースを活用して脆弱性情報と対策を提供します。

## 🚀 特徴

- **Claude Desktopとの統合**: 高度なAI分析による脆弱性評価と対策提案
- **Dockerコンテナ**: 安全で効率的なスキャン環境
- **包括的なスキャン機能**: ポートスキャン、Webスキャン、DNS調査、OSINT調査
- **ペネトレーションテスト機能**: SSHブルートフォース、FTP匿名ログイン、権限昇格
- **自動化された調査**: flagファイル検索、cronジョブ分析、システム調査
- **詳細なレポート生成**: 日本語での分かりやすい結果レポート
- **リアルタイム分析**: スキャン結果の即座なセキュリティ評価

## 🛠️ 機能一覧

### 1. ネットワークスキャン
- **Nmap基本スキャン**: 開放ポートの検出
- **Nmap詳細スキャン**: バージョン検出、サービス識別
- **特定ポートスキャン**: 指定ポートの詳細分析
- **サービス分析**: 検出されたサービスのセキュリティ評価

### 2. Webセキュリティ調査
- **HTTPヘッダー分析**: セキュリティヘッダーの確認
- **技術検出**: CMS、フレームワーク、サーバー技術の識別
- **ディレクトリスキャン**: 隠しディレクトリ・ファイルの探索
- **robots.txt分析**: 検索エンジン向け情報の確認
- **ファイルダウンロード**: 特定ファイルの内容取得
- **包括的Webスキャン**: 全機能を統合した詳細分析

### 3. DNS調査
- **DNSレコード取得**: A、AAAA、MX、NS、TXT、CNAME、SOAレコード
- **サブドメイン列挙**: 自動サブドメイン探索
- **逆引きDNS**: IPアドレスからのホスト名取得
- **包括的DNS調査**: 全レコードタイプ + サブドメイン列挙

### 4. OSINT調査
- **Whois情報**: ドメイン登録情報の取得
- **公開データベース調査**: 各種OSINTソースからの情報収集
- **ネットワーク情報**: ルーティング、AS情報の取得

### 5. ペネトレーションテスト
- **SSHログインテスト**: 単一認証情報でのログイン試行
- **SSHブルートフォース**: Hydraを使用したパスワード攻撃
- **FTP匿名ログイン**: 匿名アクセスのセキュリティ評価
- **権限昇格分析**: cronジョブを活用した権限昇格手法

### 6. システム調査
- **ディレクトリ探索**: 現在ディレクトリの詳細調査
- **flagファイル検索**: flag*.txt、root.txtファイルの網羅的検索
- **隠しファイル検索**: ドットファイル、隠しディレクトリの探索
- **システムディレクトリ調査**: /etc、/var、/tmp等の重要ディレクトリ分析

### 7. 自動化機能
- **cronジョブ作成**: root.txtをコピーする自動化スクリプト
- **権限昇格コマンド追記**: cronjob.shへの権限昇格コマンド追加
- **即座実行**: 作成したcronジョブの即座実行
- **ファイル管理**: 不要ファイルの削除、整理機能

### 8. レポート生成
- **スキャン結果レポート**: 各スキャンの詳細結果
- **セキュリティ評価**: リスクレベルと推奨対策
- **日本語レポート**: 分かりやすい日本語での結果表示

## 📋 必要条件

- **Claude Desktop**: 最新バージョン
- **Docker**: 20.10以上
- **OS**: Windows 10/11、macOS、Linux
- **メモリ**: 最低4GB（推奨8GB以上）
- **ディスク容量**: 最低5GBの空き容量

## 🚀 セットアップ手順

### 1. リポジトリのクローン
```bash
git clone https://github.com/makin0n/hacking-mcp.git
cd hacking-mcp
```

### 2. Dockerイメージのビルド
```bash
# 基本的なビルド
docker build -t hacking-mcp .

# キャッシュを使わずにビルド（問題がある場合）
docker build --no-cache -t hacking-mcp .

# ビルドログを詳細に表示
docker build --progress=plain -t hacking-mcp .
```

**ビルド内容**:
- ベースイメージ: Python 3.11-slim
- インストールツール: nmap、dnsutils、curl、その他のセキュリティツール
- Python依存関係: anthropic、mcp、playwright、paramiko等
- セキュリティ設定: 非rootユーザー（hacker）で実行

### 3. Claude Desktop設定ファイルの配置

#### 基本設定（ボリュームマウントなし）
```bash
# Windows
copy "Claude\claude_desktop_config.json" "%APPDATA%\Claude\claude_desktop_config.json"

# macOS
cp Claude/claude_desktop_config.json ~/Library/Application\ Support/Claude/claude_desktop_config.json

# Linux
cp Claude/claude_desktop_config.json ~/.config/Claude/claude_desktop_config.json
```

#### ボリュームマウント付き設定（推奨）
1. 設定ファイルをコピー:
```bash
# Windows
copy "Claude\claude_desktop_config_with_volume.json" "%APPDATA%\Claude\claude_desktop_config.json"
```

2. 設定ファイル内のパスを実際のパスに変更:
```json
{
  "mcpServers": {
    "hacking-mcp": {
      "command": "docker",
      "args": ["run", "--rm", "-v", "C:/Users/<ユーザー名>/Documents/GitHub/hacking-mcp/reports:/app/reports", "--network", "host", "-i", "hacking-mcp"]
    }
}
```

3. レポートディレクトリを作成:
```bash
mkdir reports
```

### 4. Claude Desktopの起動
Claude Desktopを起動し、MCPサーバーが正常に接続されていることを確認します。

## 📖 使用方法

### 基本的な使用
Claude Desktopで以下のような形式で質問を入力してください：

```
<対象IPアドレス>をスキャンして
```

### 詳細な使用例

#### 1. ネットワークスキャン
```
# 基本スキャン
192.168.1.100の基本的なポートスキャンをして

# 詳細スキャン（ポート指定必須）
192.168.1.100の80番と443番ポートのサービスバージョンを詳しく調べて

# 特定ポートスキャン
192.168.1.100の1-1000番ポートをスキャンして
```

#### 2. Webセキュリティ調査
```
# Webサイトの基本情報
https://example.comの基本情報を取得して

# ディレクトリスキャン
https://example.comのディレクトリスキャンをして

# 技術検出
https://example.comで使用されている技術を検出して

# 包括的Webスキャン
https://example.comの包括的Webスキャンを実行して
```

#### 3. DNS調査
```
# DNSレコード取得
example.comのDNSレコードを取得して

# サブドメイン列挙
example.comのサブドメインを探索して

# 逆引きDNS
192.168.1.100の逆引きDNSを実行して

# 包括的DNS調査
example.comの包括的DNS調査を実行して
```

#### 4. OSINT調査
```
# OSINT調査
192.168.1.100のOSINT調査を実行して

# ドメイン調査
example.comの包括的な調査を実行して
```

#### 5. ペネトレーションテスト
```
# SSHログインテスト
192.168.1.100にユーザー名adminとパスワードpassword123でSSHログインを試して

# SSHブルートフォース攻撃
192.168.1.100にユーザー名adminでパスワードリスト/usr/share/wordlists/rockyou.txtを使用してSSHブルートフォース攻撃を実行して

# FTP匿名ログイン
192.168.1.100のFTP匿名ログインをテストして
```

#### 6. システム調査
```
# 現在ディレクトリの探索
SSH接続後の現在ディレクトリを探索して

# flagファイル検索
SSH接続後のflagファイルを探して

# 隠しファイル検索
SSH接続後の隠しファイルを探して

# 包括的システム調査
SSH接続後の包括的なシステム調査を実行して
```

#### 7. 自動化機能
```
# cronジョブ作成
SSH接続後にroot.txtをコピーするcronジョブを作成して

# 権限昇格コマンド追記
cronjob.shにroot権限取得コマンドを追記して

# 即座実行
作成したcronジョブを即座に実行してroot.txtをコピーして

# ファイル管理
SSH接続後のファイルを整理して
```

#### 8. 包括的調査
```
# クイック調査
192.168.1.100のクイック調査を実行して

# 包括的調査
192.168.1.100の包括的調査を実行して

# Webセキュリティ監査
https://example.comのWebセキュリティ監査を実行して
```

## 🔧 高度な機能

### スキャナーステータス確認
```
スキャナーのステータスを確認して
```

### ワードリスト確認
```
利用可能なワードリストを表示して
```

### レポート生成
```
192.168.1.100の包括的調査をレポート付きで実行して
```

## 📁 プロジェクト構造

```
hacking-mcp/
├── main.py                 # メインMCPサーバー
├── Dockerfile             # Docker設定
├── requirements.txt       # Python依存関係
├── startup.sh            # 起動スクリプト
├── modules/              # スキャナーモジュール
│   ├── nmap_scanner.py   # Nmapスキャン機能
│   ├── web_scanner.py    # Webスキャン機能
│   ├── dns_scanner.py    # DNS調査機能



│   ├── ssh_explorer.py   # SSH調査機能
│   └── service_analyzer.py # サービス分析機能
├── utils/                # ユーティリティ
│   └── report_manager.py # レポート管理機能
├── Claude/               # Claude Desktop設定
│   ├── claude_desktop_config.json
│   └── claude_desktop_config_with_volume.json
└── reports/              # レポート保存ディレクトリ
```

## ⚠️ 注意事項

### 法的・倫理的考慮事項
- **許可された環境でのみ使用**: 所有権のあるシステムまたは明示的な許可を得たシステムでのみ使用してください
- **責任ある使用**: ペネトレーションテストは教育・研究目的で使用してください
- **法的遵守**: 各国の法律・規制を遵守してください

### 技術的注意事項
- **ポート指定**: 詳細スキャンではポート指定が必須です
- **ネットワーク設定**: 一部の機能はネットワーク設定に依存します
- **リソース使用**: 大規模スキャンは時間とリソースを消費します
- **Docker権限**: 一部の機能にはDocker権限が必要です

## 🐛 トラブルシューティング

### Dockerビルドエラー
```bash
# キャッシュクリア
docker system prune -a

# 詳細ログでビルド
docker build --progress=plain --no-cache -t hacking-mcp .
```

### Claude Desktop接続エラー
1. 設定ファイルのパスを確認
2. Dockerイメージが正常にビルドされているか確認
3. ポート競合がないか確認

### スキャンエラー
1. ターゲットの到達可能性を確認
2. ファイアウォール設定を確認
3. 必要な権限があるか確認

## 🤝 貢献

プロジェクトへの貢献を歓迎します：

1. フォークを作成
2. 機能ブランチを作成 (`git checkout -b feature/AmazingFeature`)
3. 変更をコミット (`git commit -m 'Add some AmazingFeature'`)
4. ブランチにプッシュ (`git push origin feature/AmazingFeature`)
5. プルリクエストを作成

## 📄 ライセンス

このプロジェクトは教育・研究目的で提供されています。
使用にあたっては、適切な法的・倫理的考慮を行ってください。

## 📞 サポート

問題や質問がある場合は、GitHubのIssuesページで報告してください。

---

**⚠️ 免責事項**: このツールは教育・研究目的で提供されています。使用にあたっては、適切な法的・倫理的考慮を行い、責任ある使用を心がけてください。
