#!/usr/bin/env python3
"""验收探针：SSH 服务端算法策略批量体检（10 条契约）。

配置以字典形式传入，全部离线判定，不建连接。
基线（未实现 `paramiko.audit`）10 条全 FAIL。
"""
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

RESULTS = []


def probe(name):
    def deco(fn):
        try:
            fn()
        except AssertionError as exc:
            RESULTS.append((name, False, str(exc) or "断言失败"))
        except Exception as exc:
            RESULTS.append((name, False, f"{type(exc).__name__}: {exc}"))
        else:
            RESULTS.append((name, True, ""))
        return fn

    return deco


def audit():
    from paramiko.audit import audit_servers

    return audit_servers


def server(host="10.0.0.1", kex=None, host_keys=None, ciphers=None, macs=None, cert=None):
    return {
        "host": host,
        "kex": kex if kex is not None else ["curve25519-sha256", "diffie-hellman-group16-sha512"],
        "host_keys": host_keys if host_keys is not None else ["ssh-ed25519", "rsa-sha2-512"],
        "ciphers": ciphers if ciphers is not None else ["chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com"],
        "macs": macs if macs is not None else ["hmac-sha2-256-etm@openssh.com", "hmac-sha2-512"],
        "certificate": cert,
    }


@probe("P01 合规配置")
def p01():
    fn = audit()
    out = fn([server()])
    assert hasattr(out, "items") and hasattr(out, "stats"), "需返回 items 与 stats"
    item = out.items[0]
    for key in ("index", "host", "ok", "issues", "weak"):
        assert key in item, f"item 缺字段 {key}"
    assert item["ok"] and item["issues"] == [], f"合规配置不应有问题，实际 {item['issues']}"
    assert item["weak"] == {"kex": [], "host_key": [], "cipher": [], "mac": []}, f"weak 应为空，实际 {item['weak']}"


@probe("P02 弱密钥交换")
def p02():
    fn = audit()
    item = fn([server(kex=["diffie-hellman-group1-sha1", "curve25519-sha256"])]).items[0]
    assert "diffie-hellman-group1-sha1" in item["weak"]["kex"], f"应记弱 kex，实际 {item['weak']['kex']}"
    assert not item["ok"] and "weak_kex" in item["issues"], f"应有 weak_kex，实际 {item['issues']}"


@probe("P03 弱主机密钥")
def p03():
    fn = audit()
    item = fn([server(host_keys=["ssh-dss", "ssh-ed25519"])]).items[0]
    assert "ssh-dss" in item["weak"]["host_key"], f"应记弱主机密钥，实际 {item['weak']['host_key']}"
    assert "weak_host_key" in item["issues"], f"应有 weak_host_key，实际 {item['issues']}"
    rsa1 = fn([server(host_keys=["ssh-rsa"])]).items[0]
    assert "ssh-rsa" in rsa1["weak"]["host_key"], "ssh-rsa（sha1 签名）也应算弱"


@probe("P04 弱对称加密")
def p04():
    fn = audit()
    item = fn([server(ciphers=["3des-cbc", "aes128-cbc"])]).items[0]
    assert set(item["weak"]["cipher"]) == {"3des-cbc", "aes128-cbc"}, f"弱 cipher 不对：{item['weak']['cipher']}"
    assert "weak_cipher" in item["issues"], f"应有 weak_cipher，实际 {item['issues']}"


@probe("P05 弱 MAC")
def p05():
    fn = audit()
    item = fn([server(macs=["hmac-md5", "hmac-sha1-96"])]).items[0]
    assert set(item["weak"]["mac"]) == {"hmac-md5", "hmac-sha1-96"}, f"弱 MAC 不对：{item['weak']['mac']}"
    assert "weak_mac" in item["issues"], f"应有 weak_mac，实际 {item['issues']}"


@probe("P06 现代算法缺失")
def p06():
    fn = audit()
    item = fn([server(kex=["diffie-hellman-group14-sha1"],
                     ciphers=["aes128-cbc"],
                     macs=["hmac-sha1"])]).items[0]
    assert "modern_missing" in item["issues"], f"缺现代算法应报 modern_missing，实际 {item['issues']}"
    detail = " ".join(str(x) for x in item.get("details", []))
    assert detail, "modern_missing 应给出缺少的类别"


@probe("P07 证书过期")
def p07():
    fn = audit()
    expired = server(cert={"subject": "CN=a", "not_before": "2024-01-01T00:00:00Z",
                           "not_after": "2025-01-01T00:00:00Z"})
    item = fn([expired], now="2026-11-18T00:00:00Z").items[0]
    assert "cert_expired" in item["issues"], f"过期证书应报 cert_expired，实际 {item['issues']}"
    good = server(cert={"subject": "CN=a", "not_before": "2026-01-01T00:00:00Z",
                        "not_after": "2030-01-01T00:00:00Z"})
    assert fn([good], now="2026-11-18T00:00:00Z").items[0]["ok"], "有效证书不应报警"


@probe("P08 策略放行弱算法")
def p08():
    fn = audit()
    cfg = server(kex=["diffie-hellman-group14-sha1"])
    strict = fn([cfg]).items[0]
    assert not strict["ok"], "默认应判不合格"
    loose = fn([cfg], policy={"allow_weak": True}).items[0]
    assert loose["ok"], f"allow_weak 时 ok 应为真，实际 {loose['issues']}"
    assert "weak_kex" in loose["issues"], "仍应保留命中的问题码"
    assert loose["severity"] == "warn", f"应降级为 warn，实际 {loose.get('severity')}"


@probe("P09 统计口径与空输入")
def p09():
    fn = audit()
    out = fn([server(), server(host="10.0.0.2", ciphers=["3des-cbc"]),
              {"host": "10.0.0.3"}])
    st = out.stats
    assert st["ok"] == 1 and st["bad"] == 2, f"ok/bad 不对：{st}"
    assert st["by_host"]["10.0.0.2"] >= 1, f"by_host 不对：{st['by_host']}"
    assert st["by_issue"].get("missing_field") == 1, f"缺字段应记 missing_field，实际 {st['by_issue']}"
    empty = fn([])
    assert empty.items == [] and empty.stats["ok"] == 0, "空输入应返回空结构"


@probe("P10 批量性能与既有常量可用")
def p10():
    fn = audit()
    cfgs = [server(host=f"10.0.{i % 250}.{i % 200}") for i in range(2000)]
    t0 = time.perf_counter()
    out = fn(cfgs)
    cost = time.perf_counter() - t0
    assert len(out.items) == 2000, "2000 条应全部产出"
    assert cost < 3.0, f"2000 条耗时 {cost:.2f}s 超过 3s"
    import paramiko

    assert "curve25519-sha256" in paramiko.Transport._preferred_kex, "既有 preferred_kex 被破坏"


def main():
    print("=" * 60)
    print("验收探针：SSH 服务端算法策略批量体检（10 条契约）")
    print("=" * 60)
    passed = sum(1 for _, ok, _ in RESULTS if ok)
    for name, ok, detail in RESULTS:
        print(f"PASS  {name}" if ok else f"FAIL  {name}\n      {detail}")
    print("-" * 60)
    print(f"探针结果：{passed}/{len(RESULTS)} 通过")
    return 0 if passed == len(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
