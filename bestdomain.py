import os
import requests
import argparse
import glob
import sys
import ipaddress

NO_PROXIES = {"http": None, "https": None}
DATA_DIR = "data"


def clean_string(text):
    if not text:
        return ""

    return "".join(c for c in text if c.isprintable() or c == "\n").strip()


def is_valid_ipv4(ip):
    try:
        obj = ipaddress.ip_address(ip)
        return obj.version == 4
    except Exception:
        return False


def get_ip_list(filepath, max_records=15):
    """
    读取 data/proxyip_xx.txt，去除端口，只提取 IPv4 用于 DNS A 记录。
    """
    if not os.path.exists(filepath):
        return []

    try:
        with open(filepath, "r", encoding="utf-8-sig") as f:
            content = f.read()
            clean_content = clean_string(content)

        raw_lines = [line.strip() for line in clean_content.split("\n") if line.strip()]
        ip_list = []

        for line in raw_lines:
            pure_ip = line.split(":", 1)[0].strip()

            if is_valid_ipv4(pure_ip) and pure_ip not in ip_list:
                ip_list.append(pure_ip)

        return ip_list[:max_records]

    except Exception as e:
        print(f"⚠️ 读取文件失败: {filepath} | {e}")
        return []


def cf_success(response):
    """
    Cloudflare API 通常返回 JSON:
    {"success": true, "errors": [], "messages": [], "result": ...}
    这里同时兼容部分非标准响应。
    """
    try:
        data = response.json()
        return response.status_code in [200, 201, 202] and data.get("success") is True
    except Exception:
        return response.status_code in [200, 201, 202]


def cf_error_text(response):
    try:
        return response.text
    except Exception:
        return "unknown error"


def get_cloudflare_zone(api_token, target_domain):
    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json",
    }

    try:
        res = requests.get(
            "https://api.cloudflare.com/client/v4/zones",
            headers=headers,
            params={"name": target_domain},
            proxies=NO_PROXIES,
            timeout=10,
        )

        res.raise_for_status()
        data = res.json()

        if data.get("success") is not True:
            raise Exception(f"Cloudflare API 返回失败: {data}")

        zones = data.get("result", [])

        if not zones:
            raise Exception(f"未找到 Cloudflare Zone: {target_domain}")

        return zones[0]["id"]

    except Exception as e:
        print(f"🚨 获取 Zone 失败: {e}")
        sys.exit(1)


def sync_dns_records(
    api_token,
    zone_id,
    subdomain,
    domain,
    new_ips,
    proxied,
    verbose=False,
    min_ips=2,
    dry_run=False,
    no_delete=False,
):
    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json",
    }

    record_name = domain if subdomain == "@" else f"{subdomain}.{domain}"

    try:
        res = requests.get(
            f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records",
            headers=headers,
            params={"type": "A", "name": record_name, "per_page": 100},
            proxies=NO_PROXIES,
            timeout=10,
        )

        res.raise_for_status()
        data = res.json()

        if data.get("success") is not True:
            raise Exception(f"Cloudflare API 返回失败: {data}")

        existing_records = data.get("result", [])

    except Exception as e:
        print(f"🚨 {record_name} 获取 DNS 记录失败: {e}")
        return

    online_ip_map = {}
    duplicate_record_ids = []

    for rec in existing_records:
        content = rec.get("content")
        record_id = rec.get("id")

        if not content or not record_id:
            continue

        if content in online_ip_map:
            duplicate_record_ids.append((content, record_id))
        else:
            online_ip_map[content] = record_id

    new_ips_set = set(new_ips)

    added = 0
    deleted = 0
    kept = 0
    failed = 0

    allow_delete = not no_delete and len(new_ips) >= min_ips

    if no_delete and verbose:
        print(f"🛡️ {record_name} 已启用 no-delete，本轮不删除 DNS 记录")

    if len(new_ips) < min_ips and not no_delete:
        print(f"⚠️ {record_name} 可用 IP 仅 {len(new_ips)} 个，进入保护模式，本轮不删除旧记录")

    # 删除重复 DNS 记录，仅在允许删除时执行
    if allow_delete and duplicate_record_ids:
        for dup_ip, dup_record_id in duplicate_record_ids:
            if dry_run:
                deleted += 1
                if verbose:
                    print(f"🧪 预览删除重复记录: {record_name} -> {dup_ip}")
                continue

            try:
                res = requests.delete(
                    f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{dup_record_id}",
                    headers=headers,
                    proxies=NO_PROXIES,
                    timeout=10,
                )

                if cf_success(res):
                    deleted += 1
                    if verbose:
                        print(f"🗑️ 删除重复记录: {record_name} -> {dup_ip}")
                else:
                    failed += 1
                    print(f"❌ 删除重复记录失败: {record_name} -> {dup_ip} | {cf_error_text(res)}")

            except Exception as e:
                failed += 1
                print(f"❌ 删除重复记录异常: {record_name} -> {dup_ip} | {e}")

    # 删除已不在新列表里的 DNS 记录
    if allow_delete:
        for online_ip, record_id in online_ip_map.items():
            if online_ip not in new_ips_set:
                if dry_run:
                    deleted += 1
                    if verbose:
                        print(f"🧪 预览删除: {record_name} -> {online_ip}")
                    continue

                try:
                    res = requests.delete(
                        f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record_id}",
                        headers=headers,
                        proxies=NO_PROXIES,
                        timeout=10,
                    )

                    if cf_success(res):
                        deleted += 1
                        if verbose:
                            print(f"🗑️ 删除: {record_name} -> {online_ip}")
                    else:
                        failed += 1
                        print(f"❌ 删除失败: {record_name} -> {online_ip} | {cf_error_text(res)}")

                except Exception as e:
                    failed += 1
                    print(f"❌ 删除异常: {record_name} -> {online_ip} | {e}")

    # 新增 DNS 记录
    for ip in new_ips:
        if ip in online_ip_map:
            kept += 1

            if verbose:
                print(f"⏩ 保持: {record_name} -> {ip}")

            continue

        data = {
            "type": "A",
            "name": record_name,
            "content": ip,
            "ttl": 1,
            "proxied": proxied,
        }

        if dry_run:
            added += 1
            if verbose:
                print(f"🧪 预览新增: {record_name} -> {ip}")
            continue

        try:
            res = requests.post(
                f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records",
                json=data,
                headers=headers,
                proxies=NO_PROXIES,
                timeout=10,
            )

            if cf_success(res):
                added += 1

                if verbose:
                    print(f"✅ 新增: {record_name} -> {ip}")
            else:
                failed += 1
                print(f"❌ 新增失败: {record_name} -> {ip} | {cf_error_text(res)}")

        except Exception as e:
            failed += 1
            print(f"❌ 新增异常: {record_name} -> {ip} | {e}")

    prefix = "🧪 预览" if dry_run else "🌐"
    print(f"{prefix} {record_name} | ✅新增 {added} | 🗑️删除 {deleted} | ⏩保持 {kept} | ❌失败 {failed}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--token", help="Cloudflare API Token")
    parser.add_argument("--domains", required=True, help="Cloudflare Zone 域名，多个用逗号分隔")
    parser.add_argument("--proxied", default="false", help="是否开启 Cloudflare 代理")
    parser.add_argument("--verbose", action="store_true", help="显示详细日志")
    parser.add_argument("--min-ips", type=int, default=2, help="可用 IP 少于该数量时不删除旧 DNS 记录")
    parser.add_argument("--max-records", type=int, default=15, help="每个子域最多同步多少条 A 记录")
    parser.add_argument("--dry-run", action="store_true", help="只预览，不实际修改 Cloudflare")
    parser.add_argument("--no-delete", action="store_true", help="只新增和保持，不删除旧 DNS 记录")

    args = parser.parse_args()

    api_token = args.token or os.getenv("CF_API_TOKEN")

    if not api_token:
        print("🚨 缺少 Cloudflare API Token，请设置 CF_API_TOKEN 或使用 --token")
        sys.exit(1)

    domains = [d.strip() for d in args.domains.split(",") if d.strip()]
    proxied_bool = args.proxied.lower() == "true"

    subdomain_mapping = {}

    for f in glob.glob(os.path.join(DATA_DIR, "proxyip_*.txt")):
        filename = os.path.basename(f)
        tag = filename.replace("proxyip_", "").replace(".txt", "")

        if tag:
            subdomain_mapping[tag] = f

    if not subdomain_mapping:
        print(f"⚠️ 未发现 {DATA_DIR}/proxyip_*.txt，跳过 DNS 同步")
        return

    print("🚀 DNS 同步开始")
    print(f"📁 发现 IP 文件: {', '.join(sorted(subdomain_mapping.keys()))}")

    if args.dry_run:
        print("🧪 当前为 dry-run 预览模式，不会修改 Cloudflare")

    for domain_name in domains:
        print(f"\n📌 主域: {domain_name}")

        zone_id = get_cloudflare_zone(api_token, domain_name)

        for sub, file_path in sorted(subdomain_mapping.items()):
            ips = get_ip_list(file_path, max_records=args.max_records)

            if not ips:
                print(f"⚠️ {sub}.{domain_name} 无可用 IP，跳过")
                continue

            sync_dns_records(
                api_token=api_token,
                zone_id=zone_id,
                subdomain=sub,
                domain=domain_name,
                new_ips=ips,
                proxied=proxied_bool,
                verbose=args.verbose,
                min_ips=args.min_ips,
                dry_run=args.dry_run,
                no_delete=args.no_delete,
            )

    print("\n🎉 DNS 同步完成")


if __name__ == "__main__":
    main()