# CTF Binary Analysis Report

| Field  | Value |
|--------|-------|
| Target | `test` |
| Path   | `samples/test` |
| Model  | deepseek-reasoner |
| Time   | 2026-05-20 16:11:47 |

---

## 1. 二进制概述
- **类型**: ELF 64-bit 可执行文件，x86-64 架构，小端序。
- **来源**: 典型 CTF PWN 类别（二进制漏洞利用）。
- **编译信息**: 由 GCC (Debian 8.3.0-6) 编译，源文件名为 `test.c`，未剥离符号。

## 2. 安全保护
| 保护 | 状态 | 含义 |
|------|------|------|
| RELRO | Partial | GOT 部分可写（.got.plt 可被覆盖），可用于 GOT 覆写攻击。 |
| Stack Canary | 无 | 栈缓冲区溢出可直接覆盖返回地址，无需绕过 canary。 |
| NX（栈不可执行） | 启用 | 无法在栈上执行 shellcode，需使用 ROP 或 ret2libc。 |
| PIE（位置无关） | 启用 | 代码段、数据段地址随机化，需先泄露基址。 |
| 剥离 | 否 | 符号表保留，便于逆向。 |

## 3. 关键观察
- **关键字符串**:
  - `system`（函数名）
  - `/bin/sh`（字符串）
  - `system@@GLIBC_2.2.5`（动态符号）
- **函数**:
  - 只有 `system` 和 `__libc_start_main` 是动态导入的。`system` 的 PLT 入口可用。
  - `main` 存在于 `0x1135`（从 `_start` 调用），但未提供反汇编。
- **入口点**: 无 `gets`/`scanf`/`read` 等输入函数？（需反汇编确认），但很可能存在栈溢出输入点。

## 4. 最可能的漏洞
**栈缓冲区溢出**，因为：
- 无 canary，栈布局易被控制。
- 存在 `system` 函数和 `/bin/sh` 字符串，可直接构造 `system("/bin/sh")` 调用。
- 常见的 CTF 套路：程序通过 `gets`、`read` 或 `scanf` 读取用户输入到固定大小的局部缓冲区，未做边界检查。

## 5. 下一步命令
使用 `gdb`、`pwntools` 和 `readelf` 进行深入分析：

```bash
# 1. 反汇编 main 函数，定位漏洞点
objdump -d ./test | grep -A 50 '<main>'

# 2. 查看 .rodata 段中 /bin/sh 的地址
readelf -x .rodata ./test

# 3. 检查 GOT 表，找到 system@plt 地址
objdump -d ./test | grep -E '@plt>'

# 4. 使用 pwntools 计算偏移（假设漏洞是 gets）
# 在 gdb 中运行，输入长字符串触发 crash，分析 RSP 覆盖位置
gdb ./test -ex "run <<< $(python3 -c 'print("A"*100)')"

# 5. 如果知道偏移，直接构造 rop 链测试（通过 pwntools）
python3 -c "
from pwn import *
elf = ELF('./test')
print('system@plt:', hex(elf.plt['system']))
print('/bin/sh:', hex(next(elf.search(b'/bin/sh'))))
"
```

## 6. 利用策略
1. **确定偏移**：通过崩溃调试或反汇编确定输入缓冲区到返回地址的偏移（例如 0x? bytes）。
2. **泄露 PIE 基址（如果需要）**：PIE 启用，但若程序没有内置泄露函数，可能需要先跳转到某个已知地址（如 `main` 或 `_start`）重新执行，从而通过 `puts` 等输出 GOT 表。但 `system` 和 `/bin/sh` 的地址在加载后是固定的（若开启 PIE，代码段随机，但 PLT 和 .rodata 的偏移不变）。实际上，因为 PIE 存在，我们需要先获得一个泄露来算出 `system@plt` 和 `/bin/sh` 的真实地址。但如果在本地或已知 ASLR 环境下，可直接用泄露函数如 `puts` 打印 GOT 地址。
3. **构造 ROP 链**：
   - 若未启用 PIE（本例启用了，但很多题目在固定地址调试时可先尝试），直接：`pop rdi; ret` 地址 + `/bin/sh` 地址 + `system@plt`。
   - 若 PIE 启用，先通过 `puts@plt` 打印 `puts@got` 获取 libc 地址，再计算 system 和 /bin/sh 的 libc 偏移。但注意，二进制自身没有 `puts` 函数？动态符号只有 `system` 和 `__libc_start_main`，可能没有输出函数？需要检查。
4. **调整策略**：如果二进制只导入了 `system`，需要利用 `system` 自身来输出？可以 `system("echo test")` 确认执行。甚至直接调用 `system("/bin/sh")` 即可。
5. **最终**：将 ROP 链发送到漏洞点，获得 shell。

## 7. 提示
- **无 canary，直接覆盖返回地址**：通常 CTF 入门题，偏移为 8 的倍数（64 位），例如 0x28（40 bytes）或 0x20（32 bytes）。
- **PIE 处理**：如果二进制很小，可以尝试 `call system` 的固定偏移，但 PIE 导致每次基址不同。但若程序打印过某个地址（如 main 的地址），可用泄露算 base。没有泄露的话，可考虑 ret2csu 或 ROP gadget 的巧妙利用。
- **缺失 `pop rdi; ret`**：可以使用 `__libc_csu_init` 中的通用 gadget（俗称 ret2csu），或使用 `execve` 直接 syscall（如果 NX 开启，但可 mprotect 改变权限）。但这里最简单的就是找 `pop rdi; ret`。
- **先检查是否有 system 的 PLT 项**：因为动态符号中有 `system`，所以一定存在 `system@plt`。同时 `/bin/sh` 字符串在 `.rodata` 段，不受 PIE 影响偏移（相对于程序基址）。
- **若无法泄露地址**：尝试 ret2gets 或 ret2plt，利用 `system` 本身的功能：`system("cat flag")` 或 `system("sh")`。但需要参数地址已知。可以调用 `system` 时传入栈上的字符串，但只能传入已经存在的字符串。可直接跳到 `/bin/sh` 地址作为参数。

建议先用本地测试 `gdb` 定位偏移，然后直接用 `system("/bin/sh")` 的 ROP 链（假设 PIE 关闭）测试，看能否弹出 shell。如果不能，再考虑 PIE 泄露。

---

## Raw Data

<details>
<summary>File Info</summary>

```
Path   : D:\OneDrive\桌面\CTF-Agent\samples\test
Size   : 16608 bytes  (16.2 KB)
Magic  : 7F454C46
Format : ELF Binary
Class  : 64-bit
Arch   : x86-64
Endian : Little-endian
```
</details>

<details>
<summary>Security Protections</summary>

```
[*] 'D:\\OneDrive\\桌面\\CTF-Agent\\samples\\test'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    Stripped:   No
```
</details>

<details>
<summary>Strings</summary>

```
Total strings found : 62
Interesting hits    : 3

=== Interesting strings ===
  system
  /bin/sh
  system@@GLIBC_2.2.5

=== First 30 strings ===
  /lib64/ld-linux-x86-64.so.2
  libc.so.6
  system
  __cxa_finalize
  __libc_start_main
  GLIBC_2.2.5
  _ITM_deregisterTMCloneTable
  __gmon_start__
  _ITM_registerTMCloneTable
  []A\A]A^A_
  /bin/sh
  GCC: (Debian 8.3.0-6) 8.3.0
  crtstuff.c
  deregister_tm_clones
  __do_global_dtors_aux
  completed.7325
  __do_global_dtors_aux_fini_array_entry
  frame_dummy
  __frame_dummy_init_array_entry
  test.c
  __FRAME_END__
  __init_array_end
  _DYNAMIC
  __init_array_start
  __GNU_EH_FRAME_HDR
  _GLOBAL_OFFSET_TABLE_
  __libc_csu_fini
  _ITM_deregisterTMCloneTable
  _edata
  system@@GLIBC_2.2.5
```
</details>

<details>
<summary>Functions / Symbols</summary>

```
=== Dynamic symbols (nm -D) ===
w __cxa_finalize@GLIBC_2.2.5
                 w __gmon_start__
                 U __libc_start_main@GLIBC_2.2.5
                 w _ITM_deregisterTMCloneTable
                 w _ITM_registerTMCloneTable
                 U system@GLIBC_2.2.5

=== Symbol table (readelf -s) ===
Symbol table '.dynsym' contains 7 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND 
     1: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND _ITM_deregisterT[...]
     2: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND [...]@GLIBC_2.2.5 (2)
     3: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND [...]@GLIBC_2.2.5 (2)
     4: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND __gmon_start__
     5: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND _ITM_registerTMC[...]
     6: 0000000000000000     0 FUNC    WEAK   DEFAULT  UND [...]@GLIBC_2.2.5 (2)

Symbol table '.symtab' contains 64 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND 
     1: 00000000000002a8     0 SECTION LOCAL  DEFAULT    1 .interp
     2: 00000000000002c4     0 SECTION LOCAL  DEFAULT    2 .note.ABI-tag
     3: 00000000000002e4     0 SECTION LOCAL  DEFAULT    3 .note.gnu.build-id
     4: 0000000000000308     0 SECTION LOCAL  DEFAULT    4 .gnu.hash
     5: 0000000000000330     0 SECTION LOCAL  DEFAULT    5 .dynsym
     6: 00000000000003
```
</details>

---
*Generated by CTF-Agent v1.0*
