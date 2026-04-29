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

# 1. 动态域名源
DOMAINS = [
    'proxyip.fxxk.dedyn.io', 'proxyip.us.fxxk.dedyn.io', 'proxyip.sg.fxxk.dedyn.io',
    'proxyip.jp.fxxk.dedyn.io', 'proxyip.hk.fxxk.dedyn.io', 'proxyip.aliyun.fxxk.dedyn.io',
    'proxyip.oracle.fxxk.dedyn.io', 'proxyip.digitalocean.fxxk.dedyn.io', 'proxyip.oracle.cmliussss.net'
]

# 2. CSV 测速库源
CSV_URLS = [
    "https://raw.githubusercontent.com/xgonce/Cloudflare_IP/refs/heads/main/result.csv"
]

# 3. 纯文本源
TEXT_URLS = [
    "https://raw.githubusercontent.com/ymyuuu/IPDB/refs/heads/main/bestproxy.txt",
]

# 4. 节点订阅源 (支持 V2ray/Clash Base64 格式，可自行添加公开订阅链接)
SUB_URLS = [
    # "https://example.com/sub", 
]

# ===================================================

def extract_ipv4_and_port(text):
    """严格提取纯 IPv4 和可选端口"""
    pattern = re.compile(r'\b((?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?::\d{1,5})?)\b')
    return set(pattern.findall(text))

def fetch_and_extract(url, is_base64=False):
    """抓取常规文本/订阅并提取 IPv4"""
    ips = set()
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=10) as response:
            content = response.read().decode('utf-8', errors='ignore').strip()
            
            if is_base64:
                missing_padding = len(content) % 4
                if missing_padding:
                    content += '=' * (4 - missing_padding)
                try:
                    content = base64.b64decode(content).decode('utf-8', errors='ignore')
                except Exception:
                    return ips
                    
            ips.update(extract_ipv4_and_port(content))
    except Exception as e:
        logging.error(f"抓取失败 {url}: {e}")
    return ips

def fetch_csv_ips(url):
    """精准解析 CSV，严格筛选 IPv4"""
    ips = set()
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=10) as response:
            content = response.read().decode('utf-8-sig') 
            reader = csv.DictReader(content.strip().split('\n'))
            
            for row in reader:
                ip = (row.get('IP') or row.get('ip') or '').strip()
                port = str(row.get('端口') or row.get('port') or '443').strip()
                
                # 严格判断是否为纯 IPv4
                if ip and '.' in ip and ':' not in ip:
                    # 可选：如果需要，可以在这里加过滤逻辑
                    # try:
                    #     speed = float(row.get('速度(Mbps)') or 100)
                    #     if speed < 20: continue
                    # except ValueError: pass
                        
                    ips.add(f"{ip}:{port}")
    except Exception as e:
        logging.error(f"CSV 抓取失败 {url}: {e}")
    return ips

def check_ip_tcp(ip_str, timeout=2):
    """TCP 快速测活 (动态端口支持)"""
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
    """批量查询归属地 (剔除端口后发送，返回时拼回端口)"""
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
        except Exception as e:
            logging.error(f"批量查归属地失败: {e}")
        sleep(1.5)
        
    final_results = {}
    for original_ip in ip_list:
        pure_ip = original_ip.split(':')[0]
        if pure_ip in results:
            final_results[original_ip] = results[pure_ip]
            
    return final_results

def main():
    raw_ips = set()
    
    # --- 阶段 1: 聚合抓取 ---
    logging.info("--- 开始多源聚合抓取 IPv4 ProxyIP ---")
    
    for domain in DOMAINS:
        try:
            ip = socket.gethostbyname(domain)
            raw_ips.add(f"{ip}:443")
        except:
            pass
            
    for url in TEXT_URLS:
        raw_ips.update(fetch_and_extract(url, is_base64=False))
    for url in SUB_URLS:
        raw_ips.update(fetch_and_extract(url, is_base64=True))
    for url in CSV_URLS:
        raw_ips.update(fetch_csv_ips(url))

    # 剔除局域网段
    raw_ips = {ip for ip in raw_ips if not ip.startswith(('127.', '10.', '192.168.', '172.'))}
    logging.info(f"✅ 抓取完成！共提取 {len(raw_ips)} 个候选节点。")

    if not raw_ips:
        return

    # --- 阶段 2: TCP 粗筛 (高并发) ---
    logging.info("⚡ 开启 100 并发进行 TCP 端口初筛...")
    premium_nodes = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        results = executor.map(check_ip_tcp, raw_ips)
        for ip in results:
            if ip:
                premium_nodes.append(ip)
                
    logging.info(f"✅ 粗筛完成！绝对存活节点: {len(premium_nodes)} 个。")

    if not premium_nodes:
        return

    # --- 阶段 3: 查询归属地、分类、打乱与限额保存 ---
    logging.info("🌍 正在使用本地批量查库获取节点归属地...")
    ip_regions = get_ip_regions(premium_nodes)
    
    region_dict = {}
    for ip in premium_nodes:
        country = ip_regions.get(ip, "UNKNOWN")
        if country not in region_dict:
            region_dict[country] = []
        region_dict[country].append(ip)

    final_total_ips = []
    
    for country, ips in region_dict.items():
        # 随机打乱该地区的 IP 列表 (实现动态轮换)
        random.shuffle(ips)
        # 截取前 10 个作为精英代表
        limited_ips = ips[:10]
        region_dict[country] = limited_ips
        final_total_ips.extend(limited_ips)

    # 1. 写入总库
    with open('proxyip.txt', 'w', encoding='utf-8') as f:
        f.write('\n'.join(final_total_ips) + '\n')
    logging.info(f"💾 总库已更新，保留各地区精英节点共 {len(final_total_ips)} 个")
    
    # 2. 写入地区专属子库
    for country, ips in region_dict.items():
        if country != "UNKNOWN":
            with open(f'proxyip_{country.lower()}.txt', 'w', encoding='utf-8') as f:
                f.write('\n'.join(ips) + '\n')
            logging.info(f"💾 {country} 地区专属节点库: 保存 {len(ips)} 个")

if __name__ == "__main__":
    main()