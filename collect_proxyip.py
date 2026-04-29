import socket
import logging
import urllib.request
import urllib.error
import concurrent.futures
import json
import re
import base64
import csv
import random
from time import sleep

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

# ==================== 数据源配置 ====================

# 🎯 核心配置：国家白名单 (只保留这些国家的节点，大写)
TARGET_COUNTRIES = ['HK', 'US', 'SG', 'JP', 'TW', 'KR'] 

DOMAINS = [
    #'proxyip.fxxk.dedyn.io', 'proxyip.us.fxxk.dedyn.io', 'proxyip.sg.fxxk.dedyn.io',
  #  'proxyip.jp.fxxk.dedyn.io', 'proxyip.hk.fxxk.dedyn.io', 'proxyip.aliyun.fxxk.dedyn.io',
  #  'proxyip.oracle.fxxk.dedyn.io', 'proxyip.digitalocean.fxxk.dedyn.io', 'proxyip.oracle.cmliussss.net'
]

CSV_URLS = [
    "https://raw.githubusercontent.com/xgonce/Cloudflare_IP/refs/heads/main/result.csv"
]

TEXT_URLS = [
  #  "https://raw.githubusercontent.com/ymyuuu/IPDB/refs/heads/main/bestproxy.txt",
]

SUB_URLS = [
    # 填入公开的订阅链接
]

# ===================================================

def extract_ipv4_and_port(text):
    """提取纯 IPv4 和可选端口"""
    pattern = re.compile(r'\b((?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?::\d{1,5})?)\b')
    return set(pattern.findall(text))

def fetch_and_extract(url, is_base64=False):
    ips = set()
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=10) as response:
            content = response.read().decode('utf-8', errors='ignore').strip()
            if is_base64:
                missing_padding = len(content) % 4
                if missing_padding: content += '=' * (4 - missing_padding)
                try: content = base64.b64decode(content).decode('utf-8', errors='ignore')
                except: return ips
            ips.update(extract_ipv4_and_port(content))
    except Exception as e:
        logging.error(f"抓取失败 {url}: {e}")
    return ips

def fetch_csv_ips(url):
    """【拦截点1】解析 CSV，并直接拦截非白名单国家"""
    ips = set()
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=10) as response:
            content = response.read().decode('utf-8-sig') 
            reader = csv.DictReader(content.strip().split('\n'))
            
            for row in reader:
                # 获取国家并转为大写
                country = (row.get('CF归属国') or row.get('country') or '').strip().upper()
                
                # 🛑 拦截：如果 CSV 里的国家不在你的白名单里，直接丢弃，不参与后续测活！
                if country and country not in TARGET_COUNTRIES:
                    continue
                    
                ip = (row.get('IP') or row.get('ip') or '').strip()
                port = str(row.get('端口') or row.get('port') or '443').strip()
                
                if ip and '.' in ip and ':' not in ip:
                    ips.add(f"{ip}:{port}")
    except Exception as e:
        logging.error(f"CSV 抓取失败 {url}: {e}")
    return ips

def check_ip_tcp(ip_str, timeout=2):
    if ':' in ip_str:
        host, port_str = ip_str.split(':', 1)
        port = int(port_str)
    else:
        host = ip_str
        port = 443 
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return ip_str 
    except:
        return None

def get_ip_regions(ip_list):
    results = {}
    pure_ips = [ip.split(':')[0] for ip in ip_list]
    for i in range(0, len(pure_ips), 100):
        chunk = pure_ips[i:i+100]
        try:
            req = urllib.request.Request("http://ip-api.com/batch?fields=query,countryCode", 
                                         data=json.dumps(chunk).encode('utf-8'), 
                                         headers={'Content-Type': 'application/json'})
            with urllib.request.urlopen(req, timeout=10) as response:
                for item in json.loads(response.read().decode('utf-8')):
                    if item.get('countryCode'):
                        results[item['query']] = item['countryCode']
        except:
            pass
        sleep(1.5)
        
    final_results = {}
    for original_ip in ip_list:
        pure_ip = original_ip.split(':')[0]
        if pure_ip in results:
            final_results[original_ip] = results[pure_ip]
    return final_results

def main():
    raw_ips = set()
    logging.info(f"--- 开始多源抓取，仅保留目标国家: {TARGET_COUNTRIES} ---")
    
    for domain in DOMAINS:
        try: raw_ips.add(f"{socket.gethostbyname(domain)}:443")
        except: pass
            
    for url in TEXT_URLS: raw_ips.update(fetch_and_extract(url, is_base64=False))
    for url in SUB_URLS: raw_ips.update(fetch_and_extract(url, is_base64=True))
    for url in CSV_URLS: raw_ips.update(fetch_csv_ips(url))

    raw_ips = {ip for ip in raw_ips if not ip.startswith(('127.', '10.', '192.168.', '172.'))}
    logging.info(f"✅ 抓取完成！候选节点: {len(raw_ips)} 个。")
    if not raw_ips: return

    logging.info("⚡ 开启 100 并发进行 TCP 端口初筛...")
    premium_nodes = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        results = executor.map(check_ip_tcp, raw_ips)
        for ip in results:
            if ip: premium_nodes.append(ip)
                
    logging.info(f"✅ 粗筛完成！存活节点: {len(premium_nodes)} 个。")
    if not premium_nodes: return

    logging.info("🌍 获取归属地并执行白名单过滤...")
    ip_regions = get_ip_regions(premium_nodes)
    
    region_dict = {}
    for ip in premium_nodes:
        country = ip_regions.get(ip, "UNKNOWN").upper()
        
        # 【拦截点2】过滤盲抓的 IP：只允许白名单中的国家进入最终池
        if country not in TARGET_COUNTRIES:
            continue
            
        if country not in region_dict:
            region_dict[country] = []
        region_dict[country].append(ip)

    final_total_ips = []
    
    for country, ips in region_dict.items():
        random.shuffle(ips)
        limited_ips = ips[:10]  # 每个指定国家最多保留 10 个
        region_dict[country] = limited_ips
        final_total_ips.extend(limited_ips)

    with open('proxyip.txt', 'w', encoding='utf-8') as f:
        f.write('\n'.join(final_total_ips) + '\n')
    logging.info(f"💾 总库更新，保留指定国家精英节点共 {len(final_total_ips)} 个")
    
    for country, ips in region_dict.items():
        with open(f'proxyip_{country.lower()}.txt', 'w', encoding='utf-8') as f:
            f.write('\n'.join(ips) + '\n')
        logging.info(f"💾 {country} 地区库: 产出 {len(ips)} 个")

if __name__ == "__main__":
    main()