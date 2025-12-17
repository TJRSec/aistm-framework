import os
import sys
import subprocess
import argparse

def build():
    dockerfile = "Dockerfile.toolbox"
    tag = "aistm-toolbox"
    print(f"[+] Building Docker image '{tag}'...")
    subprocess.run(["docker", "build", "-f", dockerfile, "-t", tag, "."], check=True)
    print("[+] Build complete.")

def run():
    tag = "aistm-toolbox"
    print(f"[+] Running '{tag}' container...")
    subprocess.run([
        "docker", "run", "-it", "--rm", "--network=host", tag
    ])

def main():
    parser = argparse.ArgumentParser(description="AISTM Security Toolbox Docker helper")
    parser.add_argument("command", choices=["build", "run", "all"], help="build, run, or both")
    args = parser.parse_args()
    if args.command == "build":
        build()
    elif args.command == "run":
        run()
    elif args.command == "all":
        build()
        run()

if __name__ == "__main__":
    main()
