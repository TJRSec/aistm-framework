# AISTM Security Toolbox

This directory contains the Docker-based security toolbox for the AISTM framework. The toolbox provides a ready-to-use environment with all major free/open-source security tools, libraries, and frameworks referenced in the AISTM Layer 1-4 testing guides.

## Features
- CLI tools for web, API, LLM, and infrastructure security testing
- Python, Node.js, and Go environments with key libraries
- Agentic/LLM red teaming and output validation tools
- All dependencies pre-installed for immediate use

## Setup Instructions

### 1. Build the Toolbox Docker Image

```sh
cd tools/toolbox
# Build the image (tag as aistm-toolbox)
docker build -f Dockerfile.toolbox -t aistm-toolbox:latest .
```

### 2. Run the Toolbox Container

```sh
# Start the toolbox interactively (map ports as needed)
docker run -it --rm aistm-toolbox:latest
```

- To test against the AISTM lab, use `http://host.docker.internal:8847` (on Windows/Mac) or your lab's IP.
- All tools are available in the shell: try `sqlmap`, `nmap`, `garak`, `bandit`, `zap`, etc.

### 3. Updating the Toolbox
- Edit `Dockerfile.toolbox` to add or update tools.
- Rebuild the image as above.


## Tool Breakdown

### Web, API, and Infrastructure Security
- **sqlmap**: Automated SQL injection and database takeover tool
- **nikto**: Web server scanner for vulnerabilities and misconfigurations
- **wfuzz**: Web application fuzzer for brute-forcing parameters and paths
- **hydra**: Fast network logon cracker (brute-force attacks on many protocols)
- **john**: Password cracker supporting many hash types
- **hashcat**: Advanced password recovery and cracking tool
- **gobuster**: Directory and file brute-forcing tool for web servers
- **ffuf**: Fast web fuzzer for content discovery
- **zaproxy**: OWASP ZAP, web application security scanner and proxy
- **commix**: Automated command injection and exploitation tool
- **dotdotpwn**: Directory traversal fuzzer
- **nuclei**: Fast, template-based vulnerability scanner for web and APIs
- **trivy**: Container and filesystem vulnerability scanner
- **kube-hunter**: Kubernetes penetration testing tool
- **nmap**: Network scanner and host discovery tool
- **netcat**: Network utility for reading/writing data across connections
- **lynx**: Text-based web browser (useful for quick HTTP checks)
- **whois, dnsutils, net-tools, jq, curl, wget, unzip**: General network, DNS, and data utilities

### LLM/AI Security Testing & Red Teaming
- **garak**: LLM vulnerability scanner for prompt injection, jailbreaks, and output safety
- **promptfoo**: Red teaming framework for LLMs with OWASP Top 10 presets
- **rebuff**: Prompt injection and output safety testing tool
- **llm-guard**: LLM input/output scanner for prompt injection, sensitive data, and policy violations
- **giskard**: LLM/agent tool call validation and security testing

### Code, Secret, and Static Analysis
- **bandit**: Python code static analyzer for security issues
- **truffleHog**: Secret/key discovery in code repositories
- **detect-secrets**: Secret detection for codebases and CI pipelines

### Python/AI Libraries (for scripting and custom tests)
- **openai, google-generativeai**: Python SDKs for interacting with OpenAI and Google LLM APIs
- **requests, httpx, beautifulsoup4, lxml, scapy, dnspython, pytest**: Scripting, HTTP, parsing, and network utilities

### Node.js Libraries (for custom scripts)
- **sanitize-html, dompurify, validator**: Useful for output validation and custom payload crafting

### Other
- **Go, Python, Node.js**: For running custom tools and scripts

See the Dockerfile for the full list and versions.

## Notes
- The toolbox is intended for local/offensive security testing only.
- For lab setup, see the main lab README.
- For tool usage, consult the official documentation for each tool.
