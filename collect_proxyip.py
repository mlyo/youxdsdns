import os
import glob
import socket
import logging
import urllib.request
import concurrent.futures
import csv
import random
import requests
import argparse
import ipaddress
import re
import sys
import shutil

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(message)s")

# ==================== 基础配置 ====================

OUTPUT_DIR = "data"
TEMP_OUTPUT_DIR = ".data_tmp"

TARGET_COUNTRIES = os.getenv(
    "TARGET_COUNTRIES",
    "HK,US,SG,JP,CA,KR,DE"
).split(",")

TARGET_COUNTRIES = [c.strip().upper() for c in TARGET_COUNTRIES if c.strip()]

CHECK_API_ENDPOINT = "https://api.090227.xyz/check"

API_BATCH_SIZE = 2
API_MAX_WORKERS = 15
TCP_MAX_WORKERS = 100

MAX_DELAY_MS = 400
MAX_PER_COUNTRY = 10

# ==================== 数据源配置 ====================

DOMAINS = [
    # 示例：
    # "proxyip.example.com",
    # "proxyip.us.example.com",
]

CSV_URLS = [
    "https://raw.githubusercontent.com/xgonce/Cloudflare_IP/refs/heads/main/result.csv"
]

TEXT_URLS = [
    # 示例：
    # "https://raw.githubusercontent.com/example/proxyip/main/ip.txt"
]

# ===================================================

VERBOSE = False


def log_detail(message):
    if VERBOSE:
        logging.info(message)


def ensure_output_dir():
    os.makedirs(OUTPUT_DIR, exist_ok=True)


def cleanup_temp_output():
    if os.path.exists(TEMP_OUTPUT_DIR):
        shutil.rmtree(TEMP_OUTPUT_DIR, ignore_errors=True)


def cleanup_old_outputs():
    """
    只清理 data/proxyip*.txt，不删除 data/.gitkeep。
    注意：本函数只会在本轮已经检测到可用 IP 后执行。
    """
    ensure_output_dir()

    for file in glob.glob(os.path.join(OUTPUT_DIR, "proxyip*.txt")):
        try:
            os.remove(file)
            log_detail(f"已清理旧文件: {file}")
        except Exception as e:
            logging.warning(f"清理旧文件失败 {file}: {e}")


def replace_outputs_from_temp():
    """
    将临时目录中的新 IP 库替换到 data/。
    先写临时目录，成功后再替换，降低中途失败造成半成品的风险。
    """
    ensure_output_dir()
    cleanup_old_outputs()

    for file in glob.glob(os.path.join(TEMP_OUTPUT_DIR, "proxyip*.txt")):
        target = os.path.join(OUTPUT_DIR, os.path.basename(file))
        shutil.move(file, target)

    cleanup_temp_output()


def extract_ipv4_and_port(text):
    pattern = re.compile(
        r"\b((?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?::\d{1,5})?)\b"
    )
    return set(pattern.findall(text))


def is_public_ipv4(ip_with_port):
    try:
        host = ip_with_port.split(":", 1)[0].strip()
        ip = ipaddress.ip_address(host)

        return ip.version == 4 and not (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        )
    except Exception:
        return False


def normalize_ip_port(ip, port="443"):
    ip = str(ip or "").strip()
    port = str(port or "443").strip()

    if not ip:
        return None

    if ":" in ip:
        candidate = ip
    else:
        candidate = f"{ip}:{port}"

    if ":" not in candidate:
        return None

    host, port_str = candidate.split(":", 1)

    try:
        obj = ipaddress.ip_address(host)

        if obj.version != 4:
            return None

        port_int = int(port_str)
        if port_int < 1 or port_int > 65535:
            return None

        return f"{host}:{port_int}"
    except Exception:
        return None


def fetch_text_ips(url):
    ips = set()

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=10) as response:
            content = response.read().decode("utf-8", errors="ignore").strip()
            ips.update(extract_ipv4_and_port(content))

    except Exception as e:
        logging.warning(f"TXT 抓取失败: {url} | {e}")

    return ips


def fetch_csv_ips(url):
    """
    支持格式：
    IP,cf-meta-ip,端口,速度(Mbps),CF归属国,机房,TCP延迟(ms),TLS延迟(ms)
    40.233.87.120,2603:c021:4:9a88::1016,443,111.47,CA,YYZ,37.82,59.3
    """
    ips = set()

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=15) as response:
            content = response.read().decode("utf-8-sig", errors="ignore")

        reader = csv.DictReader(content.strip().splitlines())

        for row in reader:
            country = (
                row.get("CF归属国")
                or row.get("country")
                or row.get("Country")
                or ""
            ).strip().upper()

            # CSV 国家只做初筛，最终仍以 API 返回国家为准
            if country and country not in TARGET_COUNTRIES:
                continue

            ip = (
                row.get("IP")
                or row.get("ip")
                or row.get("proxyIP")
                or row.get("proxyip")
                or ""
            ).strip()

            port = (
                row.get("端口")
                or row.get("port")
                or row.get("Port")
                or "443"
            )

            candidate = normalize_ip_port(ip, port)

            if candidate:
                ips.add(candidate)

    except Exception as e:
        logging.warning(f"CSV 抓取失败: {url} | {e}")

    return ips


def check_ip_tcp(ip_str, timeout=2):
    try:
        host, port_str = ip_str.split(":", 1)
        port = int(port_str)

        with socket.create_connection((host, port), timeout=timeout):
            return ip_str

    except Exception:
        return None


def chunk_list(items, size):
    for i in range(0, len(items), size):
        yield items[i:i + size]


def parse_api_item(item):
    try:
        if not isinstance(item, dict):
            return None

        if item.get("success") is not True:
            return None

        candidate = item.get("candidate")

        if not candidate:
            proxy_ip = item.get("proxyIP")
            port = item.get("portRemote") or 443
            candidate = normalize_ip_port(proxy_ip, port)

        candidate = normalize_ip_port(candidate)

        if not candidate:
            return None

        delay = item.get("responseTime", 999)

        try:
            delay = float(delay)
        except Exception:
            delay = 999

        exit_info = (
            item.get("probe_results", {})
            .get("ipv4", {})
            .get("exit", {})
        )

        country = str(exit_info.get("country", "UNKNOWN")).upper()
        colo = str(exit_info.get("colo", item.get("colo", "UNKNOWN"))).upper()

        if delay < MAX_DELAY_MS and country in TARGET_COUNTRIES:
            return {
                "ip": candidate,
                "country": country,
                "colo": colo,
                "delay": delay,
            }

    except Exception:
        pass

    return None


def check_ip_api_batch(ip_batch):
    """
    外部接口支持最多 2 个 ProxyIP：
    https://api.090227.xyz/check?proxyip=ip1:443,ip2:443
    """
    results =       )

        res = requests.get(
            CHECK_API_ENDPOINT,
            params={"proxyip": query},
            headers={"User-Agent": "Mozilla/5.0"},
            timeout=12,
        )

        res.raise_for_status()
        data = res.json()

        if isinstance(data, dict):
            data = [data]

        if not isinstance(data, list):
            return results

        for item in data:
            parsed = parse_api_item(item)
            if parsed:
                results.append(parsed)

    except Exception as e:
        log_detail(f"API 检测失败: {ip_batch} | {e}")

    return results


def write_outputs_to_temp(country_dict, final_total_ips):
    cleanup_temp_output()
    os.makedirs(TEMP_OUTPUT_DIR, exist_ok=True)

    main_file = os.path.join(TEMP_OUTPUT_DIR, "proxyip.txt")

    with open(main_file, "w", encoding="utf-8") as f:
        f.write("\n".join(final_total_ips) + "\n")

    for country, ips in sorted(country_dict.items()):
        filename = os.path.join(TEMP_OUTPUT_DIR, f"proxyip_{country.lower()}.txt")

        with open(filename, "w", encoding="utf-8") as f:
            f.write("\n".join(ips) + "\n")


def main():
    global VERBOSE

    parser = argparse.ArgumentParser()
    parser.add_argument("--verbose", action="store_true", help="显示详细日志")
    args = parser.parse_args()

    VERBOSE = args.verbose

    raw_ips = set()

    logging.info("🚀 开始采集 ProxyIP")
    logging.info(f"🎯 国家白名单: {', '.join(TARGET_COUNTRIES)}")

    # 域名解析
    domain_count = 0
    for domain in DOMAINS:
        try:
            ip = socket.gethostbyname(domain)
            candidate = normalize_ip_port(ip, 443)

            if candidate:
                raw_ips.add(candidate)
                domain_count += 1
                log_detail(f"域名解析成功: {domain} -> {candidate}")

        except Exception as e:
            log_detail(f"域名解析失败: {domain} | {e}")

    # TXT 数据源
    text_count = 0
    for url in TEXT_URLS:
        result = fetch_text_ips(url)
        raw_ips.update(result)
        text_count += len(result)
        log_detail(f"TXT 数据源: {url} | {len(result)} 个")

    # CSV 数据源
    csv_count = 0
    for url in CSV_URLS:
        result = fetch_csv_ips(url)
        raw_ips.update(result)
        csv_count += len(result)
        log_detail(f"CSV 数据源: {url} | {len(result)} 个")

    raw_ips = {ip for ip in raw_ips if is_public_ipv4(ip)}

    logging.info(f"📥 候选 ProxyIP: {len(raw_ips)} 个")
    log_detail(f"来源统计: 域名 {domain_count} 个，TXT {text_count} 个，CSV {csv_count} 个")

    if not raw_ips:
        logging.warning("⚠️ 没有获取到候选 ProxyIP")
        sys.exit(1)

    # TCP 初筛
    alive_ips_basic = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=TCP_MAX_WORKERS) as executor:
        results = executor.map(check_ip_tcp, raw_ips)
        for ip in results:
            if ip:
                alive_ips_basic.append(ip)

    logging.info(f"⚡ TCP 初筛完成: {len(alive_ips_basic)} 个")

    if not alive_ips_basic:
        logging.warning("⚠️ TCP 初筛后没有存活 IP")
        sys.exit(1)

    # API 批量检测
    api_batches = list(chunk_list(alive_ips_basic, API_BATCH_SIZE))
    premium_ips = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=API_MAX_WORKERS) as executor:
        results = executor.map(check_ip_api_batch, api_batches)

        for batch_result in results:
            for item in batch_result:
                premium_ips.append(item)
                log_detail(
                    f"可用 IP: {item['ip']} | 国家: {item['country']} "
                    f"({item['colo']}) | 延迟: {item['delay']}ms"
                )

    logging.info(f"🎯 API 检测完成: 检测 {len(alive_ips_basic)} 个，符合条件 {len(premium_ips)} 个")

    if not premium_ips:
        logging.warning("⚠️ API 检测后没有符合条件的可用 IP")
        sys.exit(1)

    # 按国家分类
    country_dict = {}

    for item in premium_ips:
        country = item["country"]

        if country not in country_dict:
            country_dict[country] = []

        if item["ip"] not in country_dict[country]:
            country_dict[country].append(item["ip"])

    final_total_ips = []

    for country, ips in country_dict.items():
        random.shuffle(ips)
        limited_ips = ips[:MAX_PER_COUNTRY]
        country_dict[country] = limited_ips
        final_total_ips.extend(limited_ips)

    if not final_total_ips:
        logging.warning("⚠️ 没有可写入的可用 IP")
        sys.exit(1)

    try:
        write_outputs_to_temp(country_dict, final_total_ips)
        replace_outputs_from_temp()
    except Exception as e:
        cleanup_temp_output()
        logging.error(f"❌ 写入 IP 库失败: {e}")
        sys.exit(1)

    logging.info(f"📦 输出 {os.path.join(OUTPUT_DIR, 'proxyip.txt')}: {len(final_total_ips)} 个")

    for country, ips in sorted(country_dict.items()):
        logging.info(f"📦 {country}: {len(ips)} 个")

    logging.info("🎉 采集完成")


if __name__ == "__main__":
    main()