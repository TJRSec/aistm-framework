#!/bin/bash
set -e

echo "\nAISTM Security Toolbox Container"
echo "---------------------------------"
echo "Tools installed (examples):"
echo "- sqlmap, nikto, wfuzz, hydra, john, hashcat, gobuster, ffuf, zaproxy, lynx, whois, dnsutils, nmap, netcat, curl, wget, jq, bandit, truffleHog, detect-secrets, openai, google-generativeai, etc."
echo "- Python, Node.js, Go, and common security libraries"
echo "- OWASP ZAP in /opt/ZAP_2.14.0"
echo "\nTo use a tool, just run it in this shell."
echo "To hit the lab, use curl, httpx, sqlmap, zaproxy, etc. against http://host.docker.internal:8847 or your lab's IP."
echo "\nType 'exit' to leave the toolbox."
echo
exec bash
