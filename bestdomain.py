import os
import requests
import argparse
import glob
import sys

# 统一禁用代理，确保直连 Cloudflare API
NO_PROXIES = {'http': None, 'https': None}

def clean_string(text):
    """【核心修复】彻底过滤 BOM 头、零宽字符等不可见干扰字符"""
    if not text:
        return ""
    # 只保留可打印字符
    return "".join(c for c in text if c.isprintable() or c == '\n').strip()

def get_ip_list(filepath):
    """读取本地清洗好的 IP 文件"""
    if not os.path.exists(filepath):
        return []
    try:
        with open(filepath, 'r', encoding='utf-8-sig') as f:
            content = f.read()
            clean_content = clean_string(content)
            ip_list = [line.strip() for line in clean_content.split('\n') if line.strip()]
            # 每个子域名最多保留前 10-20 个，防止 DNS 记录过大
            return ip_list[:15]
    except Exception as e:
        print(f"⚠️ 读取文件 {filepath} 失败: {e}")
        return []

def get_cloudflare_zone(api_token, target_domain):
    """获取 Zone ID"""
    headers = {'Authorization': f'Bearer {api_token}', 'Content-Type': 'application/json'}
    try:
        res = requests.get(
            'https://api.cloudflare.com/client/v4/zones', 
            headers=headers, 
            params={"name": target_domain}, 
            proxies=NO_PROXIES,
            timeout=10
        )
        res.raise_for_status()
        zones = res.json().get('result', [])
        if not zones:
            raise Exception(f"未找到域名 {target_domain}")
        return zones[0]['id']
    except Exception as e:
        print(f"🚨 获取 Zone 失败: {e}")
        sys.exit(1)

def sync_dns_records(api_token, zone_id, subdomain, domain, new_ips, proxied):
    """
    【核心逻辑】同步 DNS 记录：
    1. 获取线上记录
    2. 删除不在新列表中的旧记录
    3. 添加线上没有的新记录
    """
    headers = {'Authorization': f'Bearer {api_token}', 'Content-Type': 'application/json'}
    record_name = domain if subdomain == '@' else f'{subdomain}.{domain}'
    
    # 1. 获取当前线上所有 A 记录
    existing_records = []
    try:
        res = requests.get(
            f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records?type=A&name={record_name}', 
            headers=headers, 
            proxies=NO_PROXIES,
            timeout=10
        )
        existing_records = res.json().get('result', [])
    except Exception as e:
        print(f"⚠️ 获取 {record_name} 线上记录失败: {e}")
        return

    # 构建 线上IP -> 记录ID 的映射
    online_ip_map = {rec["content"]: rec["id"] for rec in existing_records}
    new_ips_set = set(new_ips)

    # 2. 【删除阶段】删除失效的旧节点
    for online_ip, record_id in online_ip_map.items():
        if online_ip not in new_ips_set:
            try:
                requests.delete(
                    f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record_id}', 
                    headers=headers, 
                    proxies=NO_PROXIES,
                    timeout=10
                )
                print(f"🗑️ [删除] {record_name} -> {online_ip} (节点已失效)")
            except Exception as e:
                print(f"❌ 删除失败 {online_ip}: {e}")

    # 3. 【添加阶段】上线新发现的极品节点
    for ip in new_ips:
        if ip not in online_ip_map:
            data = {
                "type": "A",
                "name": record_name,
                "content": ip,
                "ttl": 1,
                "proxied": proxied
            }
            try:
                res = requests.post(
                    f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records', 
                    json=data, 
                    headers=headers, 
                    proxies=NO_PROXIES,
                    timeout=10
                )
                if res.status_code == 200:
                    print(f"✅ [上线] {record_name} -> {ip} (极品新节点)")
            except Exception as e:
                print(f"❌ 添加失败 {ip}: {e}")
        else:
            print(f"⏩ [保持] {record_name} -> {ip} (持续健康)")

def main():
    parser = argparse.ArgumentParser(description="GitHub Actions DNS 同步工具")
    parser.add_argument("--token", help="CF API Token")
    parser.add_argument("--domains", required=True, help="主域名，多个用逗号隔开")
    parser.add_argument("--proxied", default="false", help="是否开启小黄云")
    args = parser.parse_args()

    api_token = args.token or os.getenv("CF_API_TOKEN")
    if not api_token:
        print("🚨 错误: 未找到 CF_API_TOKEN 环境或参数")
        sys.exit(1)

    domains = [d.strip() for d in args.domains.split(",") if d.strip()]
    proxied_bool = args.proxied.lower() == "true"

    # 自动扫描当前目录下所有 proxyip_*.txt 文件
    # 建立映射: { 'hkg': 'proxyip_hkg.txt', 'lax': 'proxyip_lax.txt' ... }
    subdomain_mapping = {}
    for f in glob.glob("proxyip_*.txt"):
        tag = f.replace("proxyip_", "").replace(".txt", "")
        if tag and tag != "all":
            subdomain_mapping[tag] = f
    
    # 增加通用池映射 (all.yourdomain.com)
    if os.path.exists("proxyip.txt"):
        subdomain_mapping["all"] = "proxyip.txt"

    if not subdomain_mapping:
        print("⚠️ 未发现任何 proxyip_*.txt 结果文件，请检查采集脚本输出。")
        return

    print(f"🚀 开始执行 DNS 维护，涉及子域前缀: {list(subdomain_mapping.keys())}")

    for domain_name in domains:
        print(f"\n🌐 正在处理根域: {domain_name}")
        zone_id = get_cloudflare_zone(api_token, domain_name)
        
        for sub, file_path in subdomain_mapping.items():
            ips = get_ip_list(file_path)
            if ips:
                print(f"\n--- 同步子域: {sub}.{domain_name} ---")
                sync_dns_records(api_token, zone_id, sub, domain_name, ips, proxied_bool)
            else:
                print(f"⏩ 子域 {sub} 无可用 IP，跳过")

if __name__ == "__main__":
    main()