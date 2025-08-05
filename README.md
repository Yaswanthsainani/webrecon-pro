Here's a comprehensive **README.md** for your WebRecon Pro project with clear requirements, installation, and customization guidance:

```markdown
# WebRecon Pro - Enterprise DAST Scanner

![GitHub](https://img.shields.io/badge/Shell_5.1%2B-Required-blue)
![Nuclei](https://img.shields.io/badge/Nuclei_2.8%2B-Required-red)

## 🔧 Requirements

### Core Dependencies
| Tool | Minimum Version | Installation |
|------|-----------------|--------------|
| [Waymore](https://github.com/xnl-h4ck3r/waymore) | v1.2 | `pip install waymore` |
| [Nuclei](https://github.com/projectdiscovery/nuclei) | v2.8.0 | `go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest` |
| [GF](https://github.com/tomnomnom/gf) | Latest | `go install github.com/tomnomnom/gf@latest` |
| jq | 1.6 | `sudo apt install jq` |


## 🚀 Installation

### Basic Setup
```bash
git clone https://github.com/Yaswanthsainani/webrecon-pro.git
cd webrecon-pro
chmod +x src/webrecon.sh
```

### Configuration
1. **Edit config.yaml**:
```yaml
# ~/webrecon-pro/configs/waymore.yaml
threads: 15
timeout: 45
exclude:
  - "*.png"
  - "*.css"
```

2. **Set Slack Webhook**:
```bash
echo "SLACK_WEBHOOK=https://hooks.slack.com/services/YOUR/KEY" >> .env
```

## 🛠 Custom Modifications

### Key Variables to Adjust
| Variable | File | Purpose |
|----------|------|---------|
| `CONCURRENCY` | `src/webrecon.sh` | Parallel scans (Default: 3) |
| `TIMEOUT` | `src/webrecon.sh` | Per-domain timeout in seconds |
| `GF_PATTERNS` | `src/webrecon.sh` | Vulnerability patterns to check |

### Template Paths
```bash
# Change template directories:
NUCLEI_DAST_TEMPLATES="$HOME/custom-templates/dast"
NUCLEI_EXPOSURES_TEMPLATES="$HOME/custom-templates/exposures"
```

## 🏃 Running the Scanner

### Basic Scan
```bash
./src/webrecon.sh -t example.com
```

### Advanced Options
```bash
./src/webrecon.sh \
  -f targets.txt \    # File with domains
  -c 5 \             # 5 concurrent scans
  -o /mnt/scans \    # Custom output directory
  -v 3               # Maximum verbosity
```

## 📊 Expected Output
```
scan_results/
└── example.com/
    ├── nuclei_dast_results.txt
    ├── sensitive_files.txt
    └── scan.log
```

## 🚨 Troubleshooting
**Error** | **Solution**
----------|------------
`waymore not found` | `export PATH=$PATH:~/.local/bin`
No URLs detected | Increase timeout in `config.yaml`
Slack alerts failing | Verify webhook URL in `.env`

---

> **Pro Tip**: For AWS deployment, use `nohup ./webrecon.sh -f targets.txt &` to run detached sessions.
```

### Key Features of This README:
1. **Visual Badges** - Quick version requirements
2. **Structured Tables** - Easy-to-scan requirements
3. **Copy-Paste Ready** - Directly executable commands
4. **Troubleshooting Section** - Common issues fixed
5. **Customization Guide** - Key variables highlighted

### Recommended Additions:
1. Add a `demo.gif` showing the scan in action
2. Include a `Vagrantfile` for quick testing environments
3. Add a `Dockerfile` for containerized deployment

Would you like me to generate any of these additional files?
