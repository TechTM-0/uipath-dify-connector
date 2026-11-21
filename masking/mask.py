# -*- coding: utf-8 -*-
"""
UiPath OC 照会アシスタント — ログ マスキング
--------------------------------------------------------------------
 ・LLM(Gemini) へ渡す "前" に通す（MCP 出口が最善 / Dify Code ノードでも可）
 ・LLM にはマスクさせない。本モジュールで決定論的に処理する。
 ・設計根拠: docs/照会アシスタントA_設計メモ_案2_FunctionCalling.md 「11. データ取扱い方針」

使い方:
    from mask import mask_records
    records, stats = mask_records(records)   # 既定=未知フィールド削除(allowlist)・件数をログ
    return records
  （単体の自由文なら）
    from mask import mask_text
    safe = mask_text(log["Message"])

件数ログ:
    mask_records は logger 名 "mask"(INFO) にサマリ出力する（★値は残さず件数だけ★）。
      例: mask summary: 6 masked over 3 record(s): EMAIL=1 PATH=3 WINID=2

事前設定（本番前に必須）:
    1. 環境変数 MASK_SALT を設定（未設定だと擬似化が復元可能 → 警告ログが出る）
    2. GROUP_COMPANIES / CUSTOMER_NAMES / KNOWN_HOSTS に実値を入れる
"""
from __future__ import annotations
import os
import re
import hashlib
import logging
from collections import Counter

logger = logging.getLogger("mask")

# ── 擬似化（同じ値 → 同じトークン。秘匿しつつ "同一機/同一顧客" の相関を残す）──
_DEFAULT_SALT = "CHANGE_ME_SET_ENV_MASK_SALT"
_SALT = os.environ.get("MASK_SALT", _DEFAULT_SALT)
if _SALT == _DEFAULT_SALT:
    logger.warning(
        "MASK_SALT 未設定：既定の固定ソルトで動作中。"
        "擬似化トークン(<WINID:..>/<MACHINE:..>/<IP:..>)は総当りで復元可能。"
        "本番前に環境変数 MASK_SALT を設定すること。"
    )

# ── テスト用 strict モード（全マスク）──────────────────────────────
# MASK_MODE=strict で、自由文フィールドは中身を見ずに丸ごと <REDACTED>、未知フィールドは必ず破棄。
# マスク正規表現の精度に依存せず"確実に"漏らさない。フロー開発中に実ログを安全に流すための保険。
# ※ MASK_MODE は Python プロセスに"エクスポート"されている必要がある。起動方法によっては env が
#   引き継がれない → set -a / set +a で export してから起動する等（実測対応）。
_STRICT = os.environ.get("MASK_MODE", "").strip().lower() in ("strict", "paranoid", "all")


def _pseudo(tag: str, value: str) -> str:
    h = hashlib.sha256((_SALT + value).encode("utf-8")).hexdigest()[:8]
    return f"<{tag}:{h}>"


# ── 辞書（★実値に差し替える★。長い名前から順にマッチ）──────────────────
GROUP_COMPANIES = [
    # "〇〇ホールディングス", "△△サービス", "□□システムズ",
]
CUSTOMER_NAMES = [
    # "株式会社サンプル", "山田太郎",
]
KNOWN_HOSTS = [
    # "PC-RPA01", "srv-rpa.corp.local",   ← 既知のホスト名/マシン名/FQDN（自由文中の検出用）
]


def _dict_re(words):
    words = [w for w in words if w]
    if not words:
        return None
    pat = "|".join(map(re.escape, sorted(set(words), key=len, reverse=True)))
    return re.compile(pat)


_RE_COMPANY = _dict_re(GROUP_COMPANIES)
_RE_CUSTOMER = _dict_re(CUSTOMER_NAMES)
_RE_HOST = _dict_re(KNOWN_HOSTS)

# ── 正規表現（適用順に定義）──────────────────────────────────────────
# 1. 秘密鍵ブロック / シークレット（key=value）/ Bearer / JWT
_RE_PRIVKEY = re.compile(
    r"-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----", re.S
)
_RE_SECRET_KV = re.compile(
    r"(?i)\b(password|pwd|passwd|secret|client_secret|api[_-]?key|apikey|token|"
    r"access[_-]?key|authorization)\b\s*[=:]\s*(\"[^\"]*\"|'[^']*'|\S+)"
)
_RE_BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._\-]+")
_RE_JWT = re.compile(r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+")

# 2. パス（UNC → Windows）。パス内のユーザー名/会社名/案件名もまとめて消える
# 空白も区切りに含める（パスの後ろのログ本文を巻き込まないため）。
# ※スペースを含むパス(C:\Program Files\…)は途中までのマスクになる点は許容（v1）。
_RE_UNC = re.compile(r'\\\\[^\\/:*?"<>|\r\n\t ]+(?:\\[^\\/:*?"<>|\r\n\t ]+)*')
_RE_WINPATH = re.compile(r'[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n\t ]+\\)*[^\\/:*?"<>|\r\n\t ]*')

# 3. URL / メール
_RE_URL = re.compile(r"(?i)\bhttps?://[^\s/$.?#][^\s]*")
_RE_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")

# 4. Windows ID（DOMAIN\user）※パスではない単一バックスラッシュ形
_RE_WINID = re.compile(r"\b[A-Za-z][A-Za-z0-9.\-]{0,30}\\[A-Za-z0-9._\-]{2,}")

# 5. 公的ID・金融（文脈語付きで誤検出を抑える）
_RE_MYNUMBER = re.compile(r"(?<!\d)\d{12}(?!\d)")               # マイナンバー12桁
_RE_ACCOUNT = re.compile(r"(?i)(口座|口座番号|account|acct)\D{0,6}(\d{6,8})")
_RE_CARD = re.compile(r"(?<!\d)(?:\d[ \-]?){13,16}(?!\d)")       # +Luhn で確定

# 6. 電話 / 郵便番号
_RE_PHONE = re.compile(r"(?<![\d\-])0\d{1,4}[-(]?\d{1,4}[-)]?\d{3,4}(?![\d\-])")
_RE_ZIP = re.compile(r"(?<!\d)\d{3}-\d{4}(?!\d)")

# 7. IP アドレス
_RE_IP = re.compile(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)")


def _luhn_ok(s: str) -> bool:
    ds = [int(c) for c in s if c.isdigit()]
    if not (13 <= len(ds) <= 16):
        return False
    total, alt = 0, False
    for d in reversed(ds):
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def _mask_path(m: "re.Match") -> str:
    p = m.group(0)
    _base, dot, ext = p.rpartition(".")
    if dot and 1 <= len(ext) <= 5 and "\\" not in ext and "/" not in ext:
        return f"<PATH>.{ext}"   # 診断用に拡張子だけ残す
    return "<PATH>"


def mask_text(text, counter=None):
    """
    自由文（Message / 例外 / カスタム項目）を決定論的にマスクする。
    counter（collections.Counter）を渡すと、種類別のマスク件数をそこに加算する。
    """
    if text is None or text == "":
        return text
    c = counter if counter is not None else Counter()
    t = str(text)
    # 1. シークレット
    t, n = _RE_PRIVKEY.subn("<PRIVATE_KEY>", t); c["PRIVATE_KEY"] += n
    t, n = _RE_SECRET_KV.subn(lambda m: f"{m.group(1)}=<SECRET>", t); c["SECRET"] += n
    t, n = _RE_BEARER.subn("Bearer <TOKEN>", t); c["TOKEN"] += n
    t, n = _RE_JWT.subn("<JWT>", t); c["JWT"] += n
    # 2. パス（UNC → Win）
    t, n = _RE_UNC.subn(_mask_path, t); c["PATH"] += n
    t, n = _RE_WINPATH.subn(_mask_path, t); c["PATH"] += n
    # 3. URL / メール
    t, n = _RE_URL.subn("<URL>", t); c["URL"] += n
    t, n = _RE_EMAIL.subn("<EMAIL>", t); c["EMAIL"] += n
    # 4. Windows ID（擬似化で相関維持）
    t, n = _RE_WINID.subn(lambda m: _pseudo("WINID", m.group(0)), t); c["WINID"] += n
    # 5. 公的ID・金融
    t, n = _RE_MYNUMBER.subn("<MYNUMBER>", t); c["MYNUMBER"] += n
    t, n = _RE_ACCOUNT.subn(lambda m: f"{m.group(1)}<ACCOUNT>", t); c["ACCOUNT"] += n

    def _card_sub(m):
        raw = m.group(0)
        if _luhn_ok(raw):               # Luhn 一致のみマスク＆カウント
            c["CARD"] += 1
            last4 = re.sub(r"\D", "", raw)[-4:]
            return f"<CARD:*{last4}>"
        return raw                      # 不一致はカードでない可能性大 → 触らない
    t = _RE_CARD.sub(_card_sub, t)

    # 6. 電話 / 郵便
    t, n = _RE_PHONE.subn("<PHONE>", t); c["PHONE"] += n
    t, n = _RE_ZIP.subn("<ZIP>", t); c["ZIP"] += n
    # 7. IP（擬似化）
    t, n = _RE_IP.subn(lambda m: _pseudo("IP", m.group(0)), t); c["IP"] += n
    # 8. 会社名 / 顧客名 / 既知ホスト名（辞書）
    if _RE_COMPANY:
        t, n = _RE_COMPANY.subn("<COMPANY>", t); c["COMPANY"] += n
    if _RE_CUSTOMER:
        t, n = _RE_CUSTOMER.subn("<CUSTOMER>", t); c["CUSTOMER"] += n
    if _RE_HOST:
        t, n = _RE_HOST.subn(lambda m: _pseudo("MACHINE", m.group(0)), t); c["MACHINE"] += n
    return t


# ── 構造化ログレコード用（allowlist）────────────────────────────────
# そのまま LLM に渡してよいフィールド（★これが allowlist の正★）
PASSTHROUGH_FIELDS = {
    "Level", "level", "Timestamp", "timeStamp", "TimeStamp",
    "ProcessName", "processName", "JobKey", "jobKey",
    "Key", "key", "Id", "id",            # OC の戻り値の識別子（JobKey=Key / Id）。allowlist に無いと drop されて連鎖が壊れる（実測バグ）
    "State", "state", "ExceptionType",
}
# 自由文として本文マスクをかけるフィールド
FREETEXT_FIELDS = {
    "Message", "message", "RawMessage", "rawMessage", "Details", "Exception",
    "Info", "info",                      # 個人情報が入りうるので本文マスク対象に追加（実測対応）
}
# 擬似化するフィールド（相関を残す）: フィールド名 → タグ
PSEUDO_FIELDS = {
    "RobotName": "ROBOT", "robotName": "ROBOT",
    "MachineName": "MACHINE", "machineName": "MACHINE", "HostMachineName": "MACHINE",
    "MachineId": "MACHINE", "HostMachineId": "MACHINE",
    "WindowsIdentity": "WINID", "windowsIdentity": "WINID",
}

MAX_MESSAGE_CHARS = 2000  # 巨大メッセージは切り詰め


def _mask_value(v, counter):
    """文字列はマスク、dict/list は再帰的に処理（入れ子データ対策）。"""
    if isinstance(v, str):
        return mask_text(v, counter=counter)
    if isinstance(v, dict):
        return {k: _mask_value(x, counter) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [_mask_value(x, counter) for x in v]
    return v


def mask_record(record: dict, drop_unknown: bool = False, counter=None, strict: bool = False) -> dict:
    """
    ログ1レコード(dict)をマスク。
      drop_unknown=True  : allowlist 運用。未知フィールドは落とす（最安全・mask_records の既定）
      drop_unknown=False : 未知フィールドも本文マスクして残す（入れ子は再帰）
      strict=True        : テスト用・全マスク。自由文は中身を見ず <REDACTED>、未知は必ず破棄。
                           正規表現の精度に依存せず確実に漏らさない（routing/連鎖の開発用）。
    counter を渡すと種類別のマスク件数をそこに加算する。
    """
    c = counter if counter is not None else Counter()
    out = {}
    for k, v in record.items():
        if k in PSEUDO_FIELDS:
            if v not in (None, ""):
                out[k] = _pseudo(PSEUDO_FIELDS[k], str(v))
                c[PSEUDO_FIELDS[k]] += 1
            else:
                out[k] = v
        elif k in FREETEXT_FIELDS:
            if strict:
                if v not in (None, ""):
                    out[k] = "<REDACTED>"   # 中身を見ずに丸ごと
                    c["REDACTED"] += 1
                else:
                    out[k] = v
            else:
                s = _mask_value(v, c)   # str はマスク、入れ子は再帰
                if isinstance(s, str) and len(s) > MAX_MESSAGE_CHARS:
                    s = s[:MAX_MESSAGE_CHARS] + "…<TRUNCATED>"
                    c["TRUNCATED"] += 1
                out[k] = s
        elif k in PASSTHROUGH_FIELDS:
            out[k] = v
        elif strict or drop_unknown:
            c["DROPPED_FIELD"] += 1
            continue  # 未知フィールドは落とす（strict は必ず / allowlist）
        else:
            out[k] = _mask_value(v, c)   # 未知も本文マスクして保持（入れ子も再帰）
    return out


def mask_records(records, drop_unknown: bool = True, log: bool = True, strict=None):
    """
    レコード配列をまとめてマスクし、(masked_list, counts) を返す。
    既定 drop_unknown=True ＝ 未知フィールド削除(allowlist)。残すなら False。
    strict=None なら環境変数 MASK_MODE に従う（strict=全マスク・テスト用）。True/False で明示上書き可。
    log=True なら「何を何件マスクしたか」のサマリを logging に残す（★値は残さず件数だけ★）。
    """
    use_strict = _STRICT if strict is None else strict
    c = Counter()
    masked = [mask_record(r, drop_unknown=drop_unknown, counter=c, strict=use_strict)
              for r in records]
    if log:
        mode = "strict" if use_strict else "normal"
        total = sum(c.values())
        if total:
            detail = " ".join(f"{k}={v}" for k, v in sorted(c.items()))
            logger.info("mask summary [%s]: %d masked over %d record(s): %s",
                        mode, total, len(records), detail)
        else:
            logger.info("mask summary [%s]: 0 masked over %d record(s)", mode, len(records))
    return masked, c


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(name)s %(levelname)s %(message)s")
    samples = [
        r"Process InvoiceBot finished. Output: \\fileserver\グループ会社A\請求\invoice_2026.xlsx",
        r"User CORP\t.yamada started on C:\Users\t.yamada\AppData\Local\temp\run.log",
        "Error: connection failed password=P@ssw0rd! host=10.12.3.4 mail=foo@corp.co.jp",
        "連絡先 03-1234-5678 / 〒100-0001 / 口座 1234567 / card 4111 1111 1111 1111",
        "個人番号 123456789012 のレコードを処理しました",
    ]
    for s in samples:
        cnt = Counter()
        out = mask_text(s, counter=cnt)
        print("IN :", s)
        print("OUT:", out)
        print("CNT:", {k: v for k, v in cnt.items() if v})
        print()

    # 入れ子データ ＆ allowlist の挙動
    records = [
        {"Level": "Error", "ProcessName": "InvoiceBot", "Key": "abc-123",
         "WindowsIdentity": r"CORP\t.yamada",
         "Message": r"fail on \\fs\グループ会社A\x.xlsx mail=foo@corp.co.jp",
         "Fields": {"customer_mail": "a@b.co.jp", "ips": ["10.0.0.1", "10.0.0.2"]}},
    ]
    drop, _ = mask_records(records)                       # 既定: 未知"Fields"は削除
    print("DROP :", drop[0])
    keep, counts = mask_records(records, drop_unknown=False)  # 未知も再帰マスクして保持
    print("KEEP :", keep[0])
    print("COUNTS:", {k: v for k, v in counts.items() if v})
    strict, sc = mask_records(records, strict=True)       # テスト用: 全マスク
    print("STRICT:", strict[0])
    print("SCOUNTS:", {k: v for k, v in sc.items() if v})
