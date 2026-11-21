# uipath-dify-connector

UiPath Orchestrator(OC) 照会アシスタント（Dify ＋ MCP）の設計メモとユーティリティ。

## 構成
- `docs/` — 設計メモ
  - 案1（構造化出力・決定的フロー）: `照会アシスタントA_設計メモ.md`
  - 案2（Function Calling・Agent ノード）: `照会アシスタントA_設計メモ_案2_FunctionCalling.md`
  - いずれも閲覧用 `.html` 同梱
- `masking/mask.py` — ログを LLM に渡す前の PII/機密マスク（標準ライブラリのみ・依存なし）

## マスクの使い方
MCP のログ返却直前に1行:

```python
from mask import mask_records
records, stats = mask_records(records)   # 件数サマリを logging(名 "mask") に残す
```

事前に `masking/mask.py` の `GROUP_COMPANIES` / `CUSTOMER_NAMES` と環境変数 `MASK_SALT` を設定する。

> ⚠ **実値の辞書・`MASK_SALT`・実ログは公開リポジトリに commit しない**（環境変数やローカル設定で持つ）。

## 会社PCでの使い方（clone を import して参照）
MCP サーバは **この repo の clone 内の mask.py を import** して使う（別コピーを作らない＝ drift なし）:

```python
import sys
sys.path.insert(0, r"C:\Users\<you>\uipath-dify-connector\masking")  # clone のパスに合わせる
from mask import mask_records
```

- mask.py の変更は **clone 内で編集 → `git commit` → `git push`**（会社PCから直接反映）。
- MCP は**再起動で最新を読み込む**（Python の import キャッシュのため）。
- `~/mcp-server/mask.py` のような別コピーは置かない（import 一本化）。
- 設計メモ(docs)も同じ repo に同居：**docs は personal PC 側で編集・push／mask.py は会社PC側で編集・push**、と両方向で同期。
