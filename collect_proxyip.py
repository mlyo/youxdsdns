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

CHECK_API = "https://check.proxyip.cmliussss.net/check?proxyip="

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
    """精准解析 CSV，严格筛选 IPv4 和高质量节点"""
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
                    # 可选：如果 CSV 带测速数据，可以在此增加硬性过滤
                    try:
                        speed = float(row.get('速度(Mbps)') or 100) # 若无数据默认放行
                        if speed < 20: 
                            continue # 速度低于 20Mbps 的直接丢弃
                    except ValueError:
                        pass
                        
                    ips.add(f"{ip}:{port}")
    except Exception as e:
        logging.error(f"CSV 抓取失败 {url}: {e}")
    return ips

def check_ip_tcp(ip_str, timeout=2):
    """漏斗第一道：TCP 快速测活 (粗筛)"""
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
    """漏斗第二道：API 深度质检 (精检)"""
    try:
        url = f"{CHECK_API}{ip_str}"
        headers = {'User-Agent': 'Mozilla/5.0'}
        # 允许一定超时时间等待 API 返回
        response = requests.get(url, headers=headers, timeout=8)
        data = response.json()
        
        if data.get("success") == True:
            delay = data.get("delay", 999)
            colo = data.get("colo", "UNKNOWN")
            
            # 只保留延迟低于 400ms 的顶级节点
            if delay < 400:
                return {"ip": ip_str, "colo": colo, "delay": delay}
    except Exception:
        pass
    return None

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

    raw_ips = {ip for ip in raw_ips if not ip.startswith(('127.', '10.', '192.168.', '172.'))}
    logging.info(f"✅ 抓取完成！共提取 {len(raw_ips)} 个候选节点。")

    if not raw_ips:
        return

    # --- 阶段 2: TCP 粗筛 (高并发) ---
    logging.info("⚡ 第一道漏斗：开启 100 并发进行 TCP 端口初筛...")
    alive_ips_basic = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        results = executor.map(check_ip_tcp, raw_ips)
        for ip in results:
            if ip:
                alive_ips_basic.append(ip)
                
    logging.info(f"✅ 粗筛完成！存活节点: {len(alive_ips_basic)} 个。")

    if not alive_ips_basic:
        return

    # --- 阶段 3: API 精检 (受控并发) ---
    logging.info("🎯 第二道漏斗：调用 API 获取真实机房与延迟 (严格限制 30 并发)...")
    premium_nodes = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
        results = executor.map(check_ip_api, alive_ips_basic)
        for res in results:
            if res:
                premium_nodes.append(res)
                logging.info(f"✨ 捕获极品节点: {res['ip']} | 机房: {res['colo']} | 延迟: {res['delay']}ms")

    logging.info(f"🎯 质检完成！最终获得超级节点: {len(premium_nodes)} 个。")

    if not premium_nodes:
        return

    # --- 阶段 4: 分类、打乱与限额保存 ---
    colo_dict = {}
    for node in premium_nodes:
        colo = node['colo']
        if colo not in colo_dict:
            colo_dict[colo] = []
        colo_dict[colo].append(node['ip'])

    final_total_ips = []
    
    for colo, ips in colo_dict.items():
        # 随机打乱该机房的 IP 列表
        random.shuffle(ips)
        # 截取前 10 个作为精英代表
        limited_ips = ips[:10]
        colo_dict[colo] = limited_ips
        final_total_ips.extend(limited_ips)

    # 1. 写入总库 (已去重、限额)
    with open('proxyip.txt', 'w', encoding='utf-8') as f:
        f.write('\n'.join(final_total_ips) + '\n')
    logging.info(f"💾 总库已更新，保留各机房精英节点共 {len(final_total_ips)} 个")
    
    # 2. 写入具体的机房专属子库 (例如 proxyip_hkg.txt)
    for colo, ips in colo_dict.items():
        if colo != "UNKNOWN":
            with open(f'proxyip_{colo.lower()}.txt', 'w', encoding='utf-8') as f:
                f.write('\n'.join(ips) + '\n')
            logging.info(f"💾 {colo} 机房专属节点库: 保存 {len(ips)} 个")

if __name__ == "__main__":
    main()