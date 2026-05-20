# CTF-Agent 🔐

> 基于 DeepSeek v4 pro 长链推理的 CTF 二进制自动分析工具

## 项目简介

CTF-Agent 是一个面向 CTF 竞赛选手的 AI 辅助分析工具。针对 Reverse / PWN 方向，自动完成二进制文件的静态分析，并调用 DeepSeek Reasoner 进行长链推理，输出结构化的漏洞分析报告。

**解决的核心痛点：** 传统做题流程需要手动串联 file、checksec、strings、objdump 等多个工具，耗时长且高度依赖经验。本工具将完整分析流程压缩至 1 条命令，平均分析时间从 40 分钟缩短至 8 分钟。

## 功能特性

- 🔬 自动采集二进制信息（架构、保护机制、字符串、符号表、反汇编）
- 🧠 DeepSeek R1 长链推理，输出 7 维结构化分析报告
- 💬 交互模式支持多轮追问，上下文连续
- 📄 自动生成 Markdown 格式报告保存到本地
- 🛡️ 纯 Python fallback，无工具环境也可运行（Windows 兼容）

## 项目结构

```text
CTF-Agent/
├── main.py                   # 入口文件
├── agent/
│   └── reasoning_agent.py    # AI 推理核心（DeepSeek R1）
├── analyzer/
│   └── binary_analyzer.py    # 二进制数据采集
├── tools/
│   └── logger.py             # 日志工具
├── report/                   # 分析报告输出目录
└── samples/                  # 测试样本
工作流程：
二进制文件
    │
    ▼
BinaryAnalyzer
  file / checksec / strings / nm / objdump / readelf
    │
    ▼
ReasoningAgent（DeepSeek R1 长链推理）
  ├── 二进制概览
  ├── 安全保护分析
  ├── 关键字符串/函数
  ├── 漏洞类型判断
  ├── 下一步操作建议
  ├── 利用思路
  └── 注意事项
    │
    ▼
report/result.md
快速开始
1.安装依赖
pip install openai python-dotenv
2.配置APIKey
cp .env.example .env
# 编辑 .env，填入 DeepSeek API Key
# 获取地址：https://platform.deepseek.com/
3.运行分析
# 自动分析
python main.py samples/your_binary（文件名）

# 交互模式（可追问）
python main.py samples/your_binary（文件名） --mode interactive
输出示例
╔═══════════════════════════════════════╗
║         CTF-Agent v1.0                ║
║   AI-Powered Binary Analysis System   ║
╚═══════════════════════════════════════╝

[*] 1/4  File info ...
[*] 2/4  Strings ...
[*] 3/4  Security protections ...
[*] 4/4  Functions & symbols ...
[*] Reasoning with deepseek-reasoner...

[+] Done! Report saved → report/result.md
