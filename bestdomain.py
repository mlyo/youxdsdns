import os
import requests
import argparse
import glob
import sys

NO_PROXIES = {'http': None, 'https': None}

def clean_string(text):
    if not text: return ""
    return "".join(c for c in text if c.isprintable() or c == '\n').strip()

def get_ip_list(filepath):
    """【核心修复】读取文件，去除端口号，只提取纯 IPv4 用于 DNS"""
    if not os.path.exists(filepath): return []
    try:
        with open(filepath, 'r', encoding='utf-8-sig') as f:
            content = f.read()
            clean_content = clean_string(content)
            
            raw_lines = [line.strip() for line in clean_content.split('\n') if line.strip()]
            ip_list = []
            
            for line in raw_lines:
                # 🛑 核心修复点：把 1.2.3.4:443 砍成 1.2.3.4
                pure_ip = line.split(':')[0] 
                
                # 顺手去重
                if pure_ip not in ip_list:
                    ip_list.append(pure_ip)
                    
            return ip_list[:15]
    except Exception as e:
        print(f"⚠️ 读取文件 {filepath} 失败: {e}")
        return []

def get_cloudflare_zone(api_token, target_domain):
    headers = {'Authorization': f'Bearer {api_token}', 'Content-Type': 'application/json'}
    try:
        res = requests.get('https://api.cloudflare.com/client/v4/zones', headers=headers, params={"name": target_domain}, proxies=NO_PROXIES, timeout=10)
        res.raise_for_status()
        zones = res.json().get('result', [])
        if not zones: raise Exception(f"未找到域名 {target_domain}")
        return zones[0]['id']
    except Exception as e:
        print(f"🚨 获取 Zone 失败: {e}")
        sys.exit(1)

def sync_dns_records(api_token, zone_id, subdomain, domain, new_ips, proxied):
    headers = {'Authorization': f'Bearer {api_token}', 'Content-Type': 'application/json'}
    record_name = domain if subdomain == '@' else f'{subdomain}.{domain}'
    
    existing_records = []
    try:
        res = requests.get(f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records?type=A&name={record_name}', headers=headers, proxies=NO_PROXIES, timeout=10)
        existing_records = res.json().get('result', [])
    except Exception as e:
        print(f"⚠️ 获取线上记录失败: {e}")
        return

    online_ip_map = {rec["content"]: rec["id"] for rec in existing_records}
    new_ips_set = set(new_ips)

    for online_ip, record_id in online_ip_map.items():
        if online_ip not in new_ips_set:
            try:
                requests.delete(f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record_id}', headers=headers, proxies=NO_PROXIES, timeout=10)
                print(f"🗑️ [删除] {record_name} -> {online_ip} (节点已失效)")
            except Exception as e:
                print(f"❌ 删除失败 {online_ip}: {e}")

    for ip in new_ips:
        if ip not in online_ip_map:
            data = {"type": "A", "name": record_name, "content": ip, "ttl": 1, "proxied": proxied}
            try:
                res = requests.post(f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records', json=data, headers=headers, proxies=NO_PROXIES, timeout=10)
                if res.status_code == 200:
                    print(f"✅ [上线] {record_name} -> {ip} (极品新节点)")
                else:
                    # 🛑 增加错误日志拦截，如果CF拒绝，直接打印原因
                    print(f"❌ [添加被拒] {ip} | CF返回: {res.text}")
            except Exception as e:
                print(f"❌ 请求异常 {ip}: {e}")
        else:
            print(f"⏩ [保持] {record_name} -> {ip} (持续健康)")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--token", help="CF API Token")
    parser.add_argument("--domains", required=True, help="主域名")
    parser.add_argument("--proxied", default="false", help="是否开启代理")
    args = parser.parse_args()

    api_token = args.token or os.getenv("CF_API_TOKEN")
    domains = [d.strip() for d in args.domains.split(",") if d.strip()]
    proxied_bool = args.proxied.lower() == "true"

    subdomain_mapping = {}
    for f in glob.glob("proxyip_*.txt"):
        tag = f.replace("proxyip_", "").replace(".txt", "")
        if tag and tag != "all":
            subdomain_mapping[tag] = f
    
    if os.path.exists("proxyip.txt"):
        subdomain_mapping["all"] = "proxyip.txt"

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