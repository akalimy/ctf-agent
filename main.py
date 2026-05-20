#!/usr/bin/env python3
import sys, os, argparse
from dotenv import load_dotenv
load_dotenv()

def main():
    parser = argparse.ArgumentParser(description="CTF-Agent: AI binary analysis")
    parser.add_argument("binary", help="Path to binary file")
    parser.add_argument("--mode", choices=["auto","interactive"], default="auto")
    parser.add_argument("--output", default="report/result.md")
    args = parser.parse_args()

    if not os.path.exists(args.binary):
        print(f"[!] File not found: {args.binary}")
        sys.exit(1)

    print("""
╔═══════════════════════════════════════╗
║         CTF-Agent v1.0                ║
║   AI-Powered Binary Analysis System   ║
╚═══════════════════════════════════════╝
""")
    print(f"[*] Target : {args.binary}")
    print(f"[*] Mode   : {args.mode}")
    print("-" * 45)

    from agent.reasoning_agent import CTFReasoningAgent
    agent = CTFReasoningAgent()

    if args.mode == "interactive":
        agent.interactive_mode(args.binary, args.output)
    else:
        report = agent.analyze(args.binary)
        os.makedirs(os.path.dirname(args.output), exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(report)
        print(f"\n[+] Done! Report saved → {args.output}")
        # 打印摘要
        for i, line in enumerate(report.split("\n")):
            if "## AI Analysis" in line or "## 1." in line:
                print("\n".join(report.split("\n")[i:i+25]))
                break

if __name__ == "__main__":
    main()