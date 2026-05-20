"""
Core AI reasoning engine.
Uses DeepSeek Reasoner by default (long-chain reasoning).
Also compatible with any OpenAI-compatible API.
"""
import os, datetime
from openai import OpenAI
from analyzer.binary_analyzer import BinaryAnalyzer
from tools.logger import get_logger

log = get_logger()

SYSTEM_PROMPT = """You are an expert CTF binary exploitation analyst. You know:
- Reverse engineering (x86/x64/ARM assembly, Ghidra, IDA Pro)
- Binary exploitation (stack overflow, heap, ROP chains, format string bugs)
- CTF categories: PWN, Reverse, Crypto, Web, Misc
- Tools: GDB/pwndbg, pwntools, ROPgadget, ltrace, strace, angr, radare2

Give structured, specific, actionable analysis. Name exact functions and techniques.
请始终用中文回答，专业术语可以保留英文。"""

PROMPT_TEMPLATE = """Analyze this CTF binary challenge. All collected data is below.

═══ FILE INFORMATION ═══
{file_info}

═══ SECURITY PROTECTIONS ═══
{checksec}

═══ STRINGS ANALYSIS ═══
{strings}

═══ FUNCTIONS / SYMBOLS ═══
{functions}

Write a full analysis with these exact sections:

## 1. Binary Overview
Type, architecture, likely CTF category.

## 2. Security Protections
Each protection enabled/disabled and what it means for exploitation.

## 3. Key Observations
Interesting strings, suspicious functions, obvious entry points.

## 4. Likely Vulnerability
Most probable vulnerability class and why.

## 5. Next Steps
3-5 specific commands to run next (include actual shell commands).

## 6. Exploitation Strategy
Step-by-step roadmap to get the flag.

## 7. Tips
Gotchas and shortcuts a seasoned player would know.
请用中文输出以上所有分析内容。"""

class CTFReasoningAgent:
    def __init__(self):
        api_key  = os.getenv("DEEPSEEK_API_KEY") or os.getenv("OPENAI_API_KEY", "")
        base_url = os.getenv("API_BASE_URL", "https://api.deepseek.com")
        self.model = os.getenv("MODEL_NAME", "deepseek-reasoner")

        if not api_key:
            raise EnvironmentError(
                "API key missing!\n"
                "Add DEEPSEEK_API_KEY=your_key to your .env file.\n"
                "Register at: https://platform.deepseek.com/"
            )
        self.client = OpenAI(api_key=api_key, base_url=base_url)
        log.info(f"Agent ready | model={self.model}")

    # ── public ────────────────────────────────────────────────────────────

    def analyze(self, binary_path: str) -> str:
        """Auto analysis pipeline."""
        raw = BinaryAnalyzer(binary_path).collect_all()
        print(f"[*] Reasoning with {self.model}...")
        analysis = self._call_ai(PROMPT_TEMPLATE.format(**raw))
        return self._build_report(binary_path, raw, analysis)

    def interactive_mode(self, binary_path: str, output_path: str):
        """Initial analysis then chat loop."""
        report = self.analyze(binary_path)
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(report)
        print(f"[+] Report saved → {output_path}")

        history = [
            {"role": "system",    "content": SYSTEM_PROMPT},
            {"role": "user",      "content": "Binary analysis:\n\n" + report},
            {"role": "assistant", "content": "Analysis done. What do you want to explore?"},
        ]
        print("\n[*] Interactive mode — type 'exit' to quit\n")

        while True:
            try:
                user_input = input("You > ").strip()
            except (KeyboardInterrupt, EOFError):
                break
            if not user_input or user_input.lower() in ("exit", "quit", "q"):
                break

            history.append({"role": "user", "content": user_input})
            resp = self._call_ai_history(history)
            print(f"\nAgent > {resp}\n")
            history.append({"role": "assistant", "content": resp})

            with open(output_path, "a", encoding="utf-8") as f:
                f.write(f"\n---\n**Q:** {user_input}\n\n**A:** {resp}\n")

    # ── private ───────────────────────────────────────────────────────────

    def _call_ai(self, prompt: str) -> str:
        try:
            r = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user",   "content": prompt},
                ],
                max_tokens=2048,
                temperature=0.2,
            )
            return r.choices[0].message.content or "[empty response]"
        except Exception as e:
            return f"[AI call failed: {e}]\nCheck .env API key."

    def _call_ai_history(self, history: list) -> str:
        try:
            r = self.client.chat.completions.create(
                model=self.model, messages=history,
                max_tokens=1024, temperature=0.3,
            )
            return r.choices[0].message.content or "[empty]"
        except Exception as e:
            return f"[Error: {e}]"

    def _build_report(self, path: str, raw: dict, analysis: str) -> str:
        import datetime
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        fence = "```"
        name = os.path.basename(path)

        report  = "# CTF Binary Analysis Report\n\n"
        report += "| Field  | Value |\n"
        report += "|--------|-------|\n"
        report += f"| Target | `{name}` |\n"
        report += f"| Path   | `{path}` |\n"
        report += f"| Model  | {self.model} |\n"
        report += f"| Time   | {now} |\n\n"
        report += "---\n\n"
        report += analysis + "\n\n"
        report += "---\n\n"
        report += "## Raw Data\n\n"
        report += "<details>\n<summary>File Info</summary>\n\n"
        report += f"{fence}\n{raw['file_info']}\n{fence}\n"
        report += "</details>\n\n"
        report += "<details>\n<summary>Security Protections</summary>\n\n"
        report += f"{fence}\n{raw['checksec']}\n{fence}\n"
        report += "</details>\n\n"
        report += "<details>\n<summary>Strings</summary>\n\n"
        report += f"{fence}\n{raw['strings'][:1500]}\n{fence}\n"
        report += "</details>\n\n"
        report += "<details>\n<summary>Functions / Symbols</summary>\n\n"
        report += f"{fence}\n{raw['functions'][:1500]}\n{fence}\n"
        report += "</details>\n\n"
        report += "---\n*Generated by CTF-Agent v1.0*\n"
        return report