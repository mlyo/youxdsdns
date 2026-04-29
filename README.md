# youxdsdns

自动采集可用 ProxyIP，经过 TCP 与外部 API 检测后，按国家生成 IP 库，并自动同步到 Cloudflare DNS A 记录。

## 功能

- 从 CSV / TXT / 域名解析获取候选 ProxyIP
- 自动过滤非公网 IPv4
- TCP 初筛
- API 批量检测
- 按国家生成 IP 库
- 自动同步 Cloudflare DNS
- 支持 GitHub Actions 定时运行
- 支持 Telegram 同步报告
- 定期清理 GitHub Actions 历史记录

## 项目结构

```text
.
├── .github/
│   └── workflows/
│       ├── caiji_proxyip.yml
│       ├── main.yml
│       └── cleanup.yml
├── data/
│   ├── .gitkeep
│   ├── proxyip.txt
│   ├── proxyip_hk.txt
│   ├── proxyip_us.txt
│   └── proxyip_sg.txt
├── bestdomain.py
├── collect_proxyip.py
├── requirements.txt
└── README.md