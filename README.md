# RustGate

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

MITM 対応の HTTP/HTTPS プロキシ。CLI ツールとしてもライブラリ（crate 名: `rustgate-proxy`、lib 名: `rustgate`）としても利用可能。

## 機能

- **HTTP プロキシ** — 平文 HTTP リクエストの転送（hop-by-hop ヘッダ除去対応）
- **CONNECT トンネリング** — HTTPS 通信のパススルー（双方向バイトコピー）
- **MITM モード** — TLS 終端による HTTPS 通信の傍受・閲覧
- **動的証明書生成** — ドメインごとに CA 署名の証明書を自動生成（キャッシュ付き）
- **CA 証明書管理** — 初回起動時にルート CA を `~/.rustgate/` に自動生成・保存（秘密鍵は 0600 権限）
- **リクエスト/レスポンス改変** — `RequestHandler` トレイトによるフック機構
- **IPv6 対応** — `[::1]:443` 形式の CONNECT ターゲットを正しく処理
- **セキュリティ配慮** — ログ出力時にクエリパラメータをマスク、公開バインド時の警告

## アーキテクチャ

```
Client ──TCP──> RustGate Proxy ──TCP/TLS──> Upstream Server
                    |
              +-----+-----+
              |  HTTP判定  |
              +-----+------+
           +--------+--------+
           v        v        v
        HTTP転送  CONNECT   CONNECT
        (平文)   (トンネル)  (MITM)
                  パススルー  TLS終端
```

## インストール

### crates.io から

```bash
cargo install rustgate-proxy
```

### ソースからビルド

```bash
git clone https://github.com/uky007/RustGate-Proxy.git
cd rustgate
cargo build --release
```

## 使い方

### 基本（パススルーモード）

```bash
# デフォルト: 127.0.0.1:8080 で起動
rustgate

# ポート指定
rustgate --port 9090
```

### MITM モード（TLS 傍受）

```bash
rustgate --mitm
```

初回起動時に CA 証明書が `~/.rustgate/ca.pem` に生成されます。

### CLI オプション

```
Usage: rustgate [OPTIONS]

Options:
      --host <HOST>  リッスンアドレス [default: 127.0.0.1]
  -p, --port <PORT>  リッスンポート [default: 8080]
      --mitm         MITM モード（TLS 傍受）を有効化
  -h, --help         Print help
```

### ログレベル

環境変数 `RUST_LOG` で制御:

```bash
RUST_LOG=rustgate=debug rustgate --mitm
RUST_LOG=rustgate=trace rustgate --mitm
```

## 動作確認

### HTTP プロキシ

```bash
curl -x http://localhost:8080 http://httpbin.org/get
```

### HTTPS パススルー

```bash
curl -x http://localhost:8080 https://httpbin.org/get
```

### MITM（TLS 傍受）

CA 証明書を指定して HTTPS リクエスト:

```bash
curl --cacert ~/.rustgate/ca.pem -x http://localhost:8080 https://httpbin.org/get
```

OS に CA 証明書をインストールすれば `--cacert` 不要:

```bash
# macOS
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain ~/.rustgate/ca.pem

# Ubuntu/Debian
sudo cp ~/.rustgate/ca.pem /usr/local/share/ca-certificates/rustgate.crt
sudo update-ca-certificates
```

## ライブラリとして使う

crate 名は `rustgate-proxy`、lib 名は `rustgate` です。

```toml
[dependencies]
rustgate-proxy = "0.1"
```

### カスタムハンドラ

`RequestHandler` トレイトを実装することで、プロキシを通過するリクエスト/レスポンスを改変できます:

```rust
use rustgate::handler::{BoxBody, RequestHandler};
use hyper::{Request, Response};

struct MyHandler;

impl RequestHandler for MyHandler {
    fn handle_request(&self, req: &mut Request<BoxBody>) {
        req.headers_mut()
            .insert("X-Proxied-By", "RustGate".parse().unwrap());
    }

    fn handle_response(&self, res: &mut Response<BoxBody>) {
        res.headers_mut()
            .insert("X-Proxy", "RustGate".parse().unwrap());
    }
}
```

### プロキシサーバーの組み込み

```rust
use rustgate::cert::CertificateAuthority;
use rustgate::handler::LoggingHandler;
use rustgate::proxy::{handle_connection, ProxyState};
use std::sync::Arc;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ca = Arc::new(CertificateAuthority::new().await?);
    let state = Arc::new(ProxyState {
        ca,
        mitm: true,
        handler: Arc::new(LoggingHandler),
    });

    let listener = TcpListener::bind("127.0.0.1:8080").await?;
    loop {
        let (stream, addr) = listener.accept().await?;
        let state = state.clone();
        tokio::spawn(handle_connection(stream, addr, state));
    }
}
```

### 公開モジュール

| モジュール | 説明 |
|-----------|------|
| `rustgate::proxy` | `ProxyState`, `handle_connection`, `parse_host_port` |
| `rustgate::cert` | `CertificateAuthority`, `CertifiedKey` |
| `rustgate::tls` | `make_tls_acceptor`, `connect_tls_upstream` |
| `rustgate::handler` | `RequestHandler` トレイト, `LoggingHandler`, `BoxBody` |
| `rustgate::error` | `ProxyError`, `Result` |

## ファイル構成

```
src/
├── lib.rs        # ライブラリエントリポイント（モジュール公開）
├── main.rs       # CLI エントリポイント
├── proxy.rs      # プロキシハンドラ（HTTP転送 + CONNECT + MITM）
├── cert.rs       # CA証明書管理、動的証明書生成
├── tls.rs        # TLS終端、upstream TLS接続
├── handler.rs    # RequestHandler トレイト定義
└── error.rs      # エラー型定義
tests/
└── integration_test.rs  # 統合テスト
```

## 注意事項

- **MITM 機能は、通信の当事者全員の同意を得た上で使用してください。** 無断での通信傍受は法律に抵触する可能性があります。
- **認証・アクセス制御は未実装です。** ループバック以外のアドレス（`0.0.0.0`、`::`、LAN IP、グローバル IP 等）でバインドするとネットワーク上に公開されます。非ループバックアドレスへのバインド時は起動時に警告が表示されます。信頼できるネットワーク内でのみ使用するか、ファイアウォール等で適切にアクセスを制限してください。
- このツールはセキュリティテスト、デバッグ、教育目的での使用を想定しています。

## ライセンス

[MIT](LICENSE)
