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
import requests
from time import sleep

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

# ==================== 数据源配置 ====================

# 🎯 你的国家白名单 (专门用来精准拉取 CSV 和最后的分发)
TARGET_COUNTRIES = ['HK', 'US', 'SG', 'JP', 'TW', 'KR'] 
CHECK_API = "https://api.090227.xyz/check?proxyip=" 

DOMAINS = [
    #'proxyip.fxxk.dedyn.io', 'proxyip.us.fxxk.dedyn.io', 'proxyip.sg.fxxk.dedyn.io',
   # 'proxyip.jp.fxxk.dedyn.io', 'proxyip.hk.fxxk.dedyn.io', 'proxyip.aliyun.fxxk.dedyn.io',
   # 'proxyip.oracle.fxxk.dedyn.io', 'proxyip.digitalocean.fxxk.dedyn.io', 'proxyip.oracle.cmliussss.net'
]

CSV_URLS = ["https://raw.githubusercontent.com/xgonce/Cloudflare_IP/refs/heads/main/result.csv"]
TEXT_URLS = [#"https://raw.githubusercontent.com/ymyuuu/IPDB/refs/heads/main/bestproxy.txt"
]
SUB_URLS = []


# ===================================================

def extract_ipv4_and_port(text):
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
    ips = set()
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=10) as response:
            content = response.read().decode('utf-8-sig') 
            reader = csv.DictReader(content.strip().split('\n'))
            for row in reader:
                # 🛑 完美利用你的 TARGET_COUNTRIES 拦截 CSV
                country = (row.get('CF归属国') or row.get('country') or '').strip().upper()
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

def check_ip_api(ip_str):
    try:
        url = f"{CHECK_API}{ip_str}"
        headers = {'User-Agent': 'Mozilla/5.0'}
        res = requests.get(url, headers=headers, timeout=8)
        data = res.json()
        
        if data.get("success") == True:
            # 直接拿顶层的 responseTime 作为延迟
            delay = data.get("responseTime", 999) 
            
            # 顺藤摸瓜，直接摘取 API 查好的真实落地国家和机房
            exit_info = data.get("probe_results", {}).get("ipv4", {}).get("exit", {})
            country = exit_info.get("country", "UNKNOWN").upper()
            colo = exit_info.get("colo", "UNKNOWN").upper()
            
            # 🛑 直接利用现成的 country 字段对照你的白名单拦截！
            if delay < 400 and country in TARGET_COUNTRIES:
                return {"ip": ip_str, "country": country, "colo": colo, "delay": delay}
    except Exception:
        pass
    return None

def main():
    raw_ips = set()
    logging.info(f"--- 开始多源抓取，严格执行国家白名单: {TARGET_COUNTRIES} ---")
    
    for domain in DOMAINS:
        try: raw_ips.add(f"{socket.gethostbyname(domain)}:443")
        except: pass
            
    for url in TEXT_URLS: raw_ips.update(fetch_and_extract(url, is_base64=False))
    for url in SUB_URLS: raw_ips.update(fetch_and_extract(url, is_base64=True))
    for url in CSV_URLS: raw_ips.update(fetch_csv_ips(url))

    raw_ips = {ip for ip in raw_ips if not ip.startswith(('127.', '10.', '192.168.', '172.'))}
    logging.info(f"✅ 抓取完成！符合国家要求/待定节点: {len(raw_ips)} 个。")
    if not raw_ips: return

    logging.info("⚡ 第一道漏斗：开启 100 并发进行 TCP 初筛...")
    alive_ips_basic = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        results = executor.map(check_ip_tcp, raw_ips)
        for ip in results:
            if ip: alive_ips_basic.append(ip)
                
    logging.info(f"✅ 粗筛完成！存活节点: {len(alive_ips_basic)} 个。")
    if not alive_ips_basic: return

    logging.info(f"🎯 第二道漏斗：调用 API 测速并精准匹配国家白名单...")
    premium_nodes = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
        results = executor.map(check_ip_api, alive_ips_basic)
        for res in results:
            if res: 
                premium_nodes.append(res)
                print(f"✨ 极品节点: {res['ip']} | 国家: {res['country']} ({res['colo']}) | 延迟: {res['delay']}ms")

    if not premium_nodes: return

    # --- 阶段 4: 按国家分类、打乱与保存 ---
    country_dict = {}
    for node in premium_nodes:
        country = node['country']
        if country not in country_dict: country_dict[country] = []
        country_dict[country].append(node['ip'])

    final_total_ips = []
    for country, ips in country_dict.items():
        random.shuffle(ips)
        limited_ips = ips[:10]
        country_dict[country] = limited_ips
        final_total_ips.extend(limited_ips)

    with open('proxyip.txt', 'w', encoding='utf-8') as f:
        f.write('\n'.join(final_total_ips) + '\n')
    
    for country, ips in country_dict.items():
        # 完美回归！生成 proxyip_hk.txt 等，无缝对接 bestdomain.py
        with open(f'proxyip_{country.lower()}.txt', 'w', encoding='utf-8') as f:
            f.write('\n'.join(ips) + '\n')
        logging.info(f"💾 {country} 地区节点库产出: {len(ips)} 个")

if __name__ == "__main__":
    main()