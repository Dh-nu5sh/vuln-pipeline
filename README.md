# Vuln Pipeline

A lightweight **automated vulnerability scanning pipeline** that orchestrates multiple security scanners (Nikto and OpenVAS/GVM) and generates consolidated reports.

This project demonstrates how vulnerability scanning tools can be combined into a **simple DevSecOps-style pipeline** for automated target assessment.

---

## Features

* Automated vulnerability scanning
* Integration with:

  * **Nikto** (web vulnerability scanner)
  * **OpenVAS / GVM** (network vulnerability scanner)
* Automated report generation
* HTML report template
* Organized scan outputs and logs
* Simple pipeline execution via shell script

---

## Project Structure

```
vuln-pipeline
│
├── run_all.sh                 # Pipeline entry script
├── targets.txt                # Target hosts / URLs
│
├── scanner/
│   ├── run_scan.py            # Main scan orchestrator
│   ├── nikto_runner.py        # Executes Nikto scans
│   ├── openvas_runner.py      # Executes OpenVAS scans
│   ├── gvm_runner.py          # GVM automation
│   ├── make_report.py         # Report generation logic
│   ├── report_template.html.j2# HTML report template
│   └── outputs/               # Raw scan results
│
├── logs/                      # Scan logs
├── outputs/                   # Processed outputs
└── automation-logs/           # Tool-specific logs
```

---

## Requirements

* Python 3.10+
* Nikto
* OpenVAS / GVM
* Bash environment

Python dependencies (example):

```
jinja2
python-gvm
```

---

## Setup

Clone the repository:

```
git clone https://github.com/Dh-nu5sh/vuln-pipeline.git
cd vuln-pipeline
```

Install Python dependencies:

```
pip install -r requirements.txt
```

Configure targets in:

```
targets.txt
```

Example:

```
http://example.com
192.168.1.10
```

---

## Running the Pipeline

Execute the pipeline:

```
bash run_all.sh
```

Or run the scanner directly:

```
python scanner/run_scan.py
```

The pipeline will:

1. Read targets
2. Run vulnerability scans
3. Store raw outputs
4. Generate consolidated reports

---

## Output

Results are saved in:

```
scanner/outputs/
outputs/
logs/
```

Generated reports include:

* Raw scanner outputs
* HTML vulnerability reports

---

## Security Note

The following directories should not be tracked in Git:

```
logs/
outputs/
automation-logs/
venv/
secrets.env
```

These are ignored using `.gitignore`.

---

## Future Improvements

* CI/CD integration (GitHub Actions)
* Additional scanners (Nmap, Trivy, Semgrep)
* JSON / API report outputs
* Vulnerability aggregation dashboard

---

## Author

Dhanush
Cybersecurity & DevSecOps Enthusiast
