# DSSE PAE Compare

[![tests](https://github.com/maomao-1937/dsse-pae-compare/actions/workflows/tests.yml/badge.svg)](https://github.com/maomao-1937/dsse-pae-compare/actions/workflows/tests.yml)

Compare the bytes two saved DSSE fixtures would pass into a signature operation. The report distinguishes a payload type change from a payload byte change and identifies an equality that exists only in a historical low-byte encoding model.

## Quickstart

Requires Python 3.11 or later. Run these bundled examples from the repository root.

```sh
python dsse_pae_compare.py examples/reference.json examples/alternate-base64.json
python dsse_pae_compare.py examples/reference.json examples/legacy-collision.json
python dsse_pae_compare.py examples/reference.json examples/changed-body.json
python dsse_pae_compare.py examples/reference.json examples/invalid.json
```

The second example changes the type. Its normative signing input differs, while the two types map to identical low bytes in the historical model.

```json
{"status":"different","type_same":false,"payload_same":true,"legacy_collision":true,"type_utf8_bytes":[4,8]}
```

## Input and report

Each input is one local regular UTF-8 JSON file of up to 256 KiB. Supply an object with `payloadType` as a string and `payload` as a base64 string. The type can be empty for a fixture and is limited to 4,096 UTF-8 bytes. The decoded payload is limited to 128 KiB. Use either the standard or URL-safe alphabet, with correct padding or no padding. The parser rejects duplicate keys, malformed base64 including nonzero pad bits, a UTF-8 BOM and unpaired surrogates. Additional fields such as `signatures` are parsed as JSON and ignored by the comparison.

| Field | Meaning |
|---|---|
| `type_same` | The UTF-8 type bytes are equal |
| `payload_same` | The base64 inputs decode to equal payload bytes |
| `legacy_collision` | The normative inputs differ, while inputs from the historical model are equal |
| `type_utf8_bytes` | Type byte counts in left, right order |

| Exit | Result |
|---:|---|
| `0` | `same`, identical normative PAE, or successful help |
| `1` | `different`, distinct normative PAE |
| `2` | `invalid`, invalid invocation or fixture, or unavailable stdout |

The normative DSSE model prefixes the type and payload with their byte lengths. The historical model keeps the low byte of each UTF-16 code unit and uses the resulting length. Results cover only the signing-input bytes of the supplied fixtures. Use a trusted local directory because the OS resolves filesystem links and mounts. [DSSE protocol](https://github.com/secure-systems-lab/dsse/blob/master/protocol.md), [historical Sigstore advisory](https://github.com/sigstore/sigstore-js/security/advisories/GHSA-jfc7-64v2-mr8c).

## 中文说明

比较两个 DSSE 样本的签名输入，分别判断类型和负载字节是否变化。`legacy_collision` 为真表示标准 UTF-8 编码下输入不同，历史低字节模型却把它们编码成相同字节。报告只给出判定和类型字节数，检查范围仅限提供的两个样本。

需要 Python 3.11 或更新版本。输入是带 `payloadType` 和 `payload` 的 UTF-8 JSON，分别保存类型字符串和 base64 负载。退出码 `0` 表示标准签名输入相同，`1` 表示不同，`2` 表示参数、输入或输出无效。可直接运行上面的四个示例。
