---
title: HGAME2026WP-week2
published: 2026-02-19
description: "广告位招租"
tags: ["CTF"]
draft: false






---

## 

## **Androuge**

看mainactivy实际上程序是把waw这个elf文件拷出来跑，所以直接分析这个

### 1) `waw` 是魔改 Lua 5.4.6 解释器

- AArch64 ELF，静态链接，带大量 Lua 符号（`luaU_undump`, `luaV_execute` 等）。
- `game` 是 Lua 二进制 chunk，但被改签名/加密。

### 2) `game` 的第一层：XOR 0x9C（除首字节）

- `game[0]` 是明文 `0x1b`
- 从 `game[1]` 开始每个字节 XOR `0x9c`
- 解密后头部为：`\x1bWawT...`（把 `Lua` 改成 `Waw`）

### 3) `loadUnsigned`（varint）与标准 Lua 相反：**MSB=1 表示结束**

标准 Lua 是 “MSB=0 结束”，这题是：

- 每次读 1 byte：`res = (res<<7) | (b&0x7f)`
- **如果 `b & 0x80 != 0` 就结束**（反过来）

### 4) 真正的密文与配置在 root chunk 初始化里构造

root proto 构造了一个 `GameConfig` 表，里面有：

- `key_seed = 18`
- `target_floor = 100`
- `boss_interval = 5`
- `view_radius = 6`
- `enc_flag` 是一个长度 29 的 byte 列表（由一串 LOADI + SETLIST 填充）

### 5) `decrypt_flag` 的核心就是逐字节 XOR

`decrypt_flag`（对应 proto #35）逻辑等价于：

```
seed = key_seed + target_floor + boss_interval + view_radius
for i, v in ipairs(enc_flag) do
  k = (seed + (i-1)) % 255
  out = out .. string.char(v ~ k)   -- ~ 是 bxor
end
```

套上提取到的 `enc_flag` 直接得到最终 flag：

### 解题脚本（solve.py）

`python3 solve.py ./game`

```
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import struct
import sys
from pathlib import Path

XOR = 0x9C

# ---------- stage0: decrypt game ----------
def decrypt_game(buf: bytes) -> bytes:
    if not buf or buf[0] != 0x1B:
        raise ValueError("bad file: first byte != 0x1B")
    return bytes([buf[0]] + [b ^ XOR for b in buf[1:]])

# ---------- stage1: reader + waw-varint ----------
class R:
    def __init__(self, b: bytes, pos=0):
        self.b = b
        self.p = pos

    def read(self, n: int) -> bytes:
        out = self.b[self.p:self.p+n]
        if len(out) != n:
            raise EOFError("read past end")
        self.p += n
        return out

    def u8(self) -> int:
        return self.read(1)[0]

    def u32(self) -> int:
        return struct.unpack("<I", self.read(4))[0]

    def i64(self) -> int:
        return struct.unpack("<q", self.read(8))[0]

    def f64(self) -> float:
        return struct.unpack("<d", self.read(8))[0]

    # ✅ MSB=1 ends (reversed from normal Lua 5.4)
    def loadUnsigned(self) -> int:
        res = 0
        while True:
            c = self.u8()
            res = (res << 7) | (c & 0x7F)
            if c & 0x80:
                return res

    # loadStringN: size varint; 0 => None; else read size-1 bytes (no '\0')
    def loadStringN(self):
        sz = self.loadUnsigned()
        if sz == 0:
            return None
        return self.read(sz - 1)

def parse_constants(r: R, n: int):
    out = []
    for _ in range(n):
        t = r.u8()
        if t == 0:
            out.append(("nil", None))
        elif t == 1:
            out.append(("bool", False))
        elif t == 0x11:
            out.append(("bool", True))
        elif t == 3:       # int64
            out.append(("int", r.i64()))
        elif t == 0x13:    # float64
            out.append(("num", r.f64()))
        elif t in (4, 0x14):
            out.append(("str", r.loadStringN()))
        else:
            raise ValueError(f"unknown const tag {t:#x} at {r.p}")
    return out

def parse_proto(r: R, parent_source=None):
    src = r.loadStringN()
    if src is None:
        src = parent_source

    lined = r.loadUnsigned()
    last = r.loadUnsigned()
    numparams = r.u8()
    is_vararg = r.u8()
    maxstack = r.u8()

    sizecode = r.loadUnsigned()
    code = [r.u32() for _ in range(sizecode)]

    sizek = r.loadUnsigned()
    k = parse_constants(r, sizek)

    sizeup = r.loadUnsigned()
    upvals = [tuple(r.u8() for _ in range(3)) for __ in range(sizeup)]

    sizep = r.loadUnsigned()
    ps = [parse_proto(r, src) for _ in range(sizep)]

    sizeline = r.loadUnsigned()
    _lineinfo = r.read(sizeline)

    sizeabs = r.loadUnsigned()
    for _ in range(sizeabs):
        r.loadUnsigned(); r.loadUnsigned()

    sizeloc = r.loadUnsigned()
    for _ in range(sizeloc):
        r.loadStringN(); r.loadUnsigned(); r.loadUnsigned()

    upflag = r.loadUnsigned()
    if upflag:
        for _ in range(sizeup):
            r.loadStringN()

    return {
        "source": src,
        "numparams": numparams,
        "maxstack": maxstack,
        "code": code,
        "k": k,
        "p": ps,
    }

def decode_inst(raw: int):
    # waw VM format
    op = raw >> 25
    A  = raw & 0xFF
    k  = (raw >> 8) & 1
    B  = (raw >> 9) & 0xFF
    C  = (raw >> 17) & 0xFF
    Bx = (raw >> 8) & 0x1FFFF
    sBx = Bx - 65535
    return op, A, k, B, C, Bx, sBx

def flatten(root):
    out = []
    def rec(p):
        out.append(p)
        for c in p["p"]:
            rec(c)
    rec(root)
    return out

# ---------- stage2: extract GameConfig fields + enc_flag from root bytecode ----------
def extract_config_and_enc(root):
    k = root["k"]
    code = root["code"]

    # map string-const bytes -> index
    str_to_idx = {}
    for i, (t, v) in enumerate(k):
        if t == "str" and v is not None:
            str_to_idx[v] = i

    def idx(name: str) -> int:
        b = name.encode()
        if b not in str_to_idx:
            raise ValueError(f"missing const string: {name}")
        return str_to_idx[b]

    idx_key_seed   = idx("key_seed")
    idx_target     = idx("target_floor")
    idx_boss       = idx("boss_interval")
    idx_view       = idx("view_radius")
    idx_enc        = idx("enc_flag")

    # op numbers (from reverse):
    OP_LOADI   = 1
    OP_SETFIELD= 19
    OP_SETLIST = 74

    config = {}

    # collect config numeric values (they are set via SETFIELD with const int)
    for raw in code:
        op, A, kbit, B, C, Bx, sBx = decode_inst(raw)
        if op == OP_SETFIELD and B in (idx_key_seed, idx_target, idx_boss, idx_view):
            key = k[B][1].decode()
            if kbit != 1:
                raise ValueError("unexpected: config value not in constants")
            val_t, val_v = k[C]
            if val_t != "int":
                raise ValueError("unexpected: config value not int")
            config[key] = int(val_v)

    # find enc_flag assignment: SETFIELD (key=enc_flag, value=register)
    enc_set_pc = None
    enc_reg = None
    for pc, raw in enumerate(code):
        op, A, kbit, B, C, Bx, sBx = decode_inst(raw)
        if op == OP_SETFIELD and B == idx_enc and kbit == 0:
            enc_set_pc = pc
            enc_reg = C
            break
    if enc_set_pc is None:
        raise ValueError("enc_flag assignment not found")

    # find nearest preceding SETLIST that fills that register-table
    setlist_pc = None
    n_elems = None
    for pc in range(enc_set_pc - 1, -1, -1):
        op, A, kbit, B, C, Bx, sBx = decode_inst(code[pc])
        if op == OP_SETLIST and A == enc_reg:
            setlist_pc = pc
            n_elems = B
            break
    if setlist_pc is None:
        raise ValueError("SETLIST for enc_flag not found")

    # rebuild last LOADI values up to setlist_pc
    last_loadi = {}
    for raw in code[:setlist_pc+1]:
        op, A, kbit, B, C, Bx, sBx = decode_inst(raw)
        if op == OP_LOADI:
            last_loadi[A] = sBx & 0xFF

    enc_flag = []
    for reg in range(enc_reg + 1, enc_reg + n_elems + 1):
        if reg not in last_loadi:
            raise ValueError(f"missing LOADI for enc_flag element reg R{reg}")
        enc_flag.append(last_loadi[reg])

    return config, enc_flag

# ---------- stage3: decrypt ----------
def decrypt_flag(config, enc_flag):
    seed = config["key_seed"] + config["target_floor"] + config["boss_interval"] + config["view_radius"]
    pt = bytes([(enc_flag[i] ^ ((seed + i) % 255)) & 0xFF for i in range(len(enc_flag))])
    return pt

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} ./game")
        sys.exit(1)

    raw = Path(sys.argv[1]).read_bytes()
    dec = decrypt_game(raw)

    # header
    pos = 0
    if dec[pos] != 0x1B: raise ValueError("bad signature")
    pos += 1
    if dec[pos:pos+3] != b"Waw": raise ValueError("not Waw chunk")
    pos += 3
    pos += 1  # ver
    pos += 1  # fmt
    pos += 6  # LUAC_DATA
    pos += 3  # sizes
    pos += 8  # LUAC_INT
    pos += 8  # LUAC_NUM
    pos += 1  # main_nups

    r = R(dec, pos)
    root = parse_proto(r, None)

    config, enc_flag = extract_config_and_enc(root)
    flag_bytes = decrypt_flag(config, enc_flag)
    try:
        print(flag_bytes.decode())
    except:
        print(flag_bytes)

if __name__ == "__main__":
    main()
```



**`hgame{Wow_Y0u_Got_Th3_Yend0r}`**



## **Vidar Token**

wasm下载下来交给ai进行逆向

**wasm 里藏的是 3 段 XOR(0x5a) 的明文**，其中就包括页面要用的合约入口地址。你现在不需要连钱包（HTTP 下 MetaMask 不能注入），照样可以通过页面自带的 `/rpc` 读链上数据。

### 把 wasm 里 3 段字符串解出来

`decode()` 对线性内存三个区间做了 `^ 0x5a`：

- `[0x00 .. 0x34)` 长度 0x34
- `[0x50 .. 0x50+0x49)` 长度 0x49
- `[0xA0 .. 0xA0+0x49)` 长度 0x49

解密后得到：

- **ENTRANCE**：`0x39529fdA4CbB4f8Bfca2858f9BfAeb28B904Adc0`
- **BASEA**：`0x5b5d5b5d5b5d5b5d5b5d5b5d5b5d5b5d5b5d5b5d5b5d5b5d5b5d5b5d5b5d5b5d`
- **BASEB**：`0x5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a`

> 这也解释了页面 `get_entrance()` + `readCString()`：它就是读到 `ENTRANCE=0x...` 这一串。

根据上面内容侦测数据

```
(async () => {
  const rpcUrl = `${location.origin}/rpc`;
  const provider = new ethers.JsonRpcProvider(rpcUrl);

  const entrance = "0x39529fdA4CbB4f8Bfca2858f9BfAeb28B904Adc0";
  const coin = "0xc5273abfb36550090095b1edec019216ad21be6c";

  // 1) 常见 ERC20/Ownable 视图函数探测
  const erc20 = new ethers.Contract(coin, [
    "function name() view returns (string)",
    "function symbol() view returns (string)",
    "function decimals() view returns (uint8)",
    "function totalSupply() view returns (uint256)",
    "function balanceOf(address) view returns (uint256)",
    "function owner() view returns (address)"
  ], provider);

  const info = {};
  for (const f of ["name","symbol","decimals","totalSupply"]) {
    try { info[f] = await erc20[f](); } catch { info[f] = "(no)"; }
  }
  try { info.owner = await erc20.owner(); } catch { info.owner = "(no owner)"; }
  try { info.balanceOfEntrance = (await erc20.balanceOf(entrance)).toString(); } catch { info.balanceOfEntrance = "(no balanceOf)"; }

  console.log("=== ERC20 INFO ===");
  console.table(info);

  // 2) 拉 bytecode，抽出可见 ASCII 字符串（搜 flag/ctf/{/}）
  console.log("=== BYTECODE STRINGS (filtered) ===");
  const code = await provider.getCode(coin);
  console.log("bytecode bytes =", (code.length - 2) / 2);

  const bytes = ethers.getBytes(code);
  let cur = "";
  const strs = [];
  for (const b of bytes) {
    if (b >= 0x20 && b <= 0x7e) cur += String.fromCharCode(b);
    else { if (cur.length >= 6) strs.push(cur); cur = ""; }
  }
  if (cur.length >= 6) strs.push(cur);

  const hits = strs.filter(s => /flag|ctf|{|}|vidar|punk|coin/i.test(s));
  console.log(hits);

  // 3) 扫前 40 个 storage slot（很多题直接把密文/片段塞这里）
  console.log("=== NONZERO STORAGE SLOTS [0..39] ===");
  for (let i = 0; i < 40; i++) {
    const pos = ethers.toBeHex(i, 32);
    const v = await provider.getStorage(coin, pos);
    if (v !== "0x" + "0".repeat(64)) {
      console.log("slot", i, v);
    }
  }

  // 可选：同样扫 entrance 合约（有时 flag 明文在这里）
  console.log("=== ENTRANCE BYTECODE STRING HITS ===");
  const ecode = await provider.getCode(entrance);
  const ebytes = ethers.getBytes(ecode);
  let ecur = "";
  const estrs = [];
  for (const b of ebytes) {
    if (b >= 0x20 && b <= 0x7e) ecur += String.fromCharCode(b);
    else { if (ecur.length >= 6) estrs.push(ecur); ecur = ""; }
  }
  if (ecur.length >= 6) estrs.push(ecur);
  console.log(estrs.filter(s => /flag|ctf|{|}|vidar|punk|coin/i.test(s)));
})();

```

得到

```
VM382:26 
(索引)
值
name	'VidarCoin'
symbol	'0x6960606a647c542a413134374d5275626d7e5e6c6f48562a44556258764672502c5d7b5d3537646364377c'
decimals	26n
totalSupply	0n
owner	'(no owner)'
balanceOfEntrance	'0'
Object
VM382:29 === BYTECODE STRINGS (filtered) ===
VM382:31 bytecode bytes = 4644
VM382:43 
['{V[___']
0
: 
"{V[___"
length
: 
1
[[Prototype]]
: 
Array(0)
VM382:46 === NONZERO STORAGE SLOTS [0..39] ===
VM382:51 slot 3 0x5669646172436f696e0000000000000000000000000000000000000000000012
VM382:51 slot 4 0x564944415200000000000000000000000000000000000000000000000000000a
VM382:51 slot 5 0x0000000000000000000000000000000000000000000000000000000000000057
VM382:56 === ENTRANCE BYTECODE STRING HITS ===
VM382:66 
(7) ['{"name":"VidarPunks #', '","description":"VidarPunks Vaul_', 'darCoin.","attributes":[', '{"trait_type":"Linked Coin Addre_', '],"vidar_coin":"', 'V[a"}` ', 'a${Wa$za"']
0
: 
"{\"name\":\"VidarPunks #"
1
: 
"\",\"description\":\"VidarPunks Vaul_"
2
: 
"darCoin.\",\"attributes\":["
3
: 
"{\"trait_type\":\"Linked Coin Addre_"
4
: 
"],\"vidar_coin\":\""
5
: 
"V[a\"}` "
6
: 
"a${Wa$za\""
length
: 
7
[[Prototype]]
: 
Array(0)
﻿
```

交给ai



你这题已经到终点了：**flag 就在 VidarCoin 的 `symbol()` 返回值里**，只是做了一层“两个 Base 碰撞”的异或。

你拿到的 `symbol`：

```
0x6960606a647c542a413134374d5275626d7e5e6c6f48562a44556258764672502c5d7b5d3537646364377c
```

把它当 **hex 解码成 43 个字节**后，再跟一个重复的掩码异或就出明文。

关键掩码来自 wasm 里的：

- `BASEA = 0x5b5d5b5d...`（0x5b 与 0x5d 交替）
- `BASEB = 0x5a5a5a...`（全 0x5a）

所以逐字节 `BASEA ^ BASEB` 得到的就是交替的：

- `0x5b ^ 0x5a = 0x01`
- `0x5d ^ 0x5a = 0x07`

也就是 mask：`01 07 01 07 01 07 ...`



```
(() => {
  const sym = "0x6960606a647c542a413134374d5275626d7e5e6c6f48562a44556258764672502c5d7b5d3537646364377c";
  const enc = ethers.getBytes(sym); // 43 bytes

  const mask = new Uint8Array(enc.length);
  for (let i = 0; i < mask.length; i++) mask[i] = (i % 2 === 0) ? 0x01 : 0x07;

  const dec = new Uint8Array(enc.length);
  for (let i = 0; i < enc.length; i++) dec[i] = enc[i] ^ mask[i];

  console.log(new TextDecoder().decode(dec));
})();
```

###  最终 flag

**`hgame{U-@650LUtely_knOW-ERc_wAsW-ZzZ40ede0}`**





但是交了这个不对，感觉wAsW有点问题就改成了wAsM就过了





## **Invest on Matrix**

开始不知道是什么先买个1，知道应该是二维码了

二维码是从右下开始读的，先买数据区

**13, 14, 15**

**18, 19, 20**

**23, 24, 25**

纠错等级够高直接出了

已买的块（1、13–15、18–20、23–25）拼回 25×25（Version 2 QR），然后把未买到的位置当作 **erasures（擦除）**，对 **32 种（纠错等级×mask）**全部尝试：

- 你当前缺失会导致 **25 个码字未知**
- 只有 **纠错等级 H（ECC=28）**能覆盖 25 个擦除
- 且唯一能通过 RS 校验并成功解码的是：**EC=H，mask=2**
- 解出的 payload 是：`W0RTH_1T?`

所以最终提交：

**hgame{W0RTH_1T?}**

## **Marionette**

### 定位校验点：memcmp(…, 16)

用 `objdump` 看主逻辑（你也可以直接搜 `memcmp@plt`），能看到最终：

- 它把某个函数算出的 16 字节结果放到栈上
- 然后调用 `memcmp(..., 0x405010, 16)`
- 相等则写 `"OK\n"`，否则 `"NO\n"`

也就是说**校验目标是一个固定的 16 字节常量**。

把 `.rodata` dump 出来就能拿到：

```
objdump -s -j .rodata ./marionette | head -n 20
```

你会看到：

- 目标常量（memcmp 的第二参数）：

```
TARGET = 8cadb48febfd6fae8660ad44c3c75a31
```

- 另一个紧挨着的 16 字节常量：

```
SEED16 = 5a097c137b8d4f2132be3b19af449c01
```

------

###  “Marionette” 的含义：ptrace + int3 拆成木偶机

继续反汇编会发现大量：

- `int3`（触发 SIGTRAP 让程序“停下”）
- `ptrace / waitpid`（父进程控制子进程“走哪一步”）

这正对应题面诗句：

- **I walk, but do not choose the path.**（子进程执行，但路径由父进程 ptrace 决定）
- **I stop…**（int3 断点停下）
- **Trace my steps…**（要 trace 才能还原真实执行）

所以这题的“逆向难点”主要是：**关键算法被拆成大量 gadget + ptrace 驱动**，普通静态阅读很痛苦。

------

### 识别算法：AES-192（“twelve times folded”）

在反汇编里能直接看到 AES-NI 指令：

- `aeskeygenassist`
- `aesenc`
- `aesenclast`

而且 `aesenc` 对 roundkey 的访问形如：

```
aesenc     0x70(%r12), %xmm0
aesenc     0x80(%r12), %xmm0
...
aesenclast 0xc0(%r12), %xmm0
```

这说明：

- `r12` 指向 round key schedule 的起始地址
- round keys 用到了 **0x00 ~ 0xC0** 共 13 组（包含初始 AddRoundKey + 12 轮）
- 13 * 16 = **208 bytes = 0xD0**

AES 轮数对照：

- AES-128：10 轮（11 组 round key）
- AES-192：12 轮（13 组 round key）✅
- AES-256：14 轮（15 组 round key）

因此这里是 **AES-192**。题面 “twelve times folded” 正好暗示 **12 轮**。

------

### 输入不是直接 AES 明文：还有一个“echo of my past”的差分 XOR

只看 AES 还不够。程序在进入 AES 之前对 16 字节输入做了一个非常简单但很“诗意”的变换：

令输入为 `x[0..15]`，变换后是 `y[0..15]`：

- `y[0] = x[0]`
- `y[i] = x[i] XOR x[i-1]`  (i=1..15)

这就是“echoes of my own past”（每一步都混入上一步的自己）。

这个变换**可逆**：

- `x[0] = y[0]`
- `x[i] = y[i] XOR x[i-1]`

------

### 逆向方向：先 AES 解密，再逆差分 XOR

程序验证的本质是：

> ```
> AES192_Encrypt( y ) == TARGET
> ```

所以反解：

1. `y = AES192_Decrypt(TARGET)`
2. 从 `y` 逆回 `x`
3. 输出 `x` 的 hex 就是需要输入的 32 hex

------

### AES-192 的 round key 

因为这题把 key schedule 在 marionette 执行链里算出来了，最省事做法是：

- 在第一次 `aesenc` 附近断下（或用 tracer/hook）
- 读出 `r12` 指向的 **0xD0 字节**（13 个 round keys）

拿到的 round key schedule（208 bytes）为：

```
5a097c137b8d4f2132be3b19af449c0140d7006a3b5a4f4b09e47452a6a0e853
a24ced4e9916a20590f2d65736523e04a6fe1f4b3fe8bd4eaf1a6b199948551d
fc02bba5c3ea06eb6cf06df2f5b838ef8005644343ef62a82f1f0f5adaa737b5
fc9fb114bf70d3bc906fdce64ac8eb5354765cc2eb068f7e7b69539831a1b8cb
e61a43050d1ccc7b76759fe347d42728b5d677a5b8cabbdecebf243d896b0315f
cad2e02446795dc8ad8b1e103b3b2f4fd9a9179b9fd04a53325b544309607b0b5
5f767d0ca272d83f87c79c0f11c02c
```

------

### 解题脚本

```
# solve.py  (pure python, no third-party libs)

TARGET = bytes.fromhex("8cadb48febfd6fae8660ad44c3c75a31")

RK_DUMP = bytes.fromhex(
"5a097c137b8d4f2132be3b19af449c0140d7006a3b5a4f4b09e47452a6a0e853"
"a24ced4e9916a20590f2d65736523e04a6fe1f4b3fe8bd4eaf1a6b199948551d"
"fc02bba5c3ea06eb6cf06df2f5b838ef8005644343ef62a82f1f0f5adaa737b5"
"fc9fb114bf70d3bc906fdce64ac8eb5354765cc2eb068f7e7b69539831a1b8cb"
"e61a43050d1ccc7b76759fe347d42728b5d677a5b8cabbdecebf243d896b0315f"
"cad2e02446795dc8ad8b1e103b3b2f4fd9a9179b9fd04a53325b544309607b0b5"
"5f767d0ca272d83f87c79c0f11c02c"
)

# --- AES primitives ---
SBOX = [
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
]
INV = [0]*256
for i,v in enumerate(SBOX): INV[v]=i

def mul(a,b):
    r=0
    for _ in range(8):
        if b&1: r ^= a
        hi=a&0x80
        a=(a<<1)&0xff
        if hi: a ^= 0x1b
        b >>= 1
    return r

def inv_shift_rows(s):
    for r in range(1,4):
        row=[s[c*4+r] for c in range(4)]
        row=row[-r:]+row[:-r]
        for c in range(4): s[c*4+r]=row[c]

def inv_sub_bytes(s):
    for i in range(16): s[i]=INV[s[i]]

def inv_mix_columns(s):
    for c in range(4):
        a0,a1,a2,a3=[s[c*4+r] for r in range(4)]
        s[c*4+0]=mul(a0,14)^mul(a1,11)^mul(a2,13)^mul(a3,9)
        s[c*4+1]=mul(a0,9)^mul(a1,14)^mul(a2,11)^mul(a3,13)
        s[c*4+2]=mul(a0,13)^mul(a1,9)^mul(a2,14)^mul(a3,11)
        s[c*4+3]=mul(a0,11)^mul(a1,13)^mul(a2,9)^mul(a3,14)

def add_rk(s,rk):
    for i in range(16): s[i]^=rk[i]

def aes192_decrypt(ct, round_keys):
    s=list(ct)
    Nr=len(round_keys)-1
    add_rk(s, round_keys[Nr])
    inv_shift_rows(s); inv_sub_bytes(s)
    for r in range(Nr-1,0,-1):
        add_rk(s, round_keys[r])
        inv_mix_columns(s); inv_shift_rows(s); inv_sub_bytes(s)
    add_rk(s, round_keys[0])
    return bytes(s)

# round keys (13 blocks)
RKS=[RK_DUMP[i:i+16] for i in range(0,len(RK_DUMP),16)]

# Step1: get y
y=aes192_decrypt(TARGET,RKS)

# Step2: invert y[i]=x[i]^x[i-1]
x=bytearray(16)
x[0]=y[0]
for i in range(1,16):
    x[i]=y[i]^x[i-1]

flaghex=x.hex()
print("INPUT =", flaghex)
print("FLAG  =", f"hgame{{{flaghex}}}")

```

(latt) ➜  Re python so.py
INPUT = deadbeef0ddba11dfeedfacecafebabe
FLAG  = hgame{deadbeef0ddba11dfeedfacecafebabe}

## **VidarChall**

### 题目目标

按钮点击后会调用：

- `makekey()`
- `encrypt(flagBytes, flagLen)`
- 返回的字符串要等于常量：

```
jdh2rzUxbpRxlfFro3YGuhHhmpWq4eHqTvK3N1njLjMnkSUS3I6VDg==
```

因此我们要做的是：**把这段 base64 对应的密文在 native 里还原回明文**（即正确输入/flag）。

------

### 1. Java 层入口：AIDL + isolated service

#### 1.1 关键代码（MainActivity）

你贴的 MainActivity 点击逻辑：

```
mAidlService.makekey();
String encrypted = mAidlService.encrypt(flag.getBytes(), flag.length());
if (!encrypted.equals("...base64...")) False else True
```

注意：`mAidlService` 是 `bindService(new Intent(this, MyisolatedService.class), ...)` 得到的 Binder。

#### 1.2 关键点：加密发生在 **MyisolatedService 进程**

`MyisolatedService` 的 AIDL 实现里直接调用 native：

```
public void makekey() { Utils.makekey(); }
public String encrypt(byte[] data, int len) { return Utils.encrypt(data, len); }
```

所以按钮按下时，**makekey/encrypt 都是在 Service 进程执行的**。

#### 1.3 Manifest 明确：Service 是 isolated + 单独进程

你给的 manifest 关键段：

```
<service
    android:name="com.vidar.chall.MyisolatedService"
    android:process=":MyisolatedService"
    android:isolatedProcess="true"
    android:useAppZygote="true"/>
```

这意味着 service 进程：

- 一定是 isolated（`Process.isIsolated()==true`）
- 且用 AppZygote 机制（`useAppZygote=true`）——这是本题最大陷阱之一，后面会用到。

------

### 2. native 导出函数定位：JNI 注册

`Utils` 只有 3 个 native：

```
public static native void chall_init(boolean z, Context context);
public static native String encrypt(byte[] bArr, int i);
public static native void makekey();
```

在 so 里你贴了 JNI 注册表（`RegisterNatives`）：

- `"chall_init" -> sub_1A508C`
- `"makekey"    -> sub_1A5960`
- `"encrypt"    -> sub_1A5D10`

------

### 3. encrypt 还原：它就是 XXTEA（Corrected Block TEA）+ base64

你贴的 `sub_1A5D10` 核心：

1. 申请 buffer：

- `size = (len 按 4 字节对齐) + 4`

1. 拷贝输入到 buffer（并补 0）
2. 调 `sub_1ABE64(ptr, qword_505E00, size/4, dword_505B48)`
3. 把结果编码成字符串（base64）

而你贴的 `sub_1ABE64` 结构是典型 XXTEA（btea）加密形式：

- `rounds = 6 + 52/n`
- `sum += delta`
- `e = (sum>>2)&3`
- 每轮更新 `v[i] += MX(...)`

其中：

- `n = size/4`
- `key = qword_505E00` 指向 16 字节（4 个 u32）
- `delta = dword_505B48`（注意：不是标准 TEA 的 0x9E3779B9，而是动态算出来的）

#### 3.1 密文长度锁定 n

base64 解码后密文长度是 40 bytes：

- `n = 40/4 = 10`
- `rounds = 6 + 52/10 = 11`

因此明文真实长度满足：

- `size = align4(len)+4 = 40`
- 所以 `len ∈ [36..39]`

最后解出来的 flag 长度确实是 **37**（刚好补 3 个 `\0` 到 40）。

------

### 4. makekey 还原：两条分支，但在本题中是“固定走其中一条”

`makekey = sub_1A5960` 的开头：

```
LDRB W8, [byte_505DF0]
TBZ  W8,#0, loc_1A5AD0   ; 0 分支
...                      ; 1 分支
```

也就是说 `byte_505DF0` 决定走哪条 key 分支。

而 `byte_505DF0` 在 `sub_1A50F0` 里被写：

```
LDRB W8, [SP,#arg_3C]
CSET W8, NE
STRB W8, [byte_505DF0]
```

即：**byte_505DF0 = (chall_init 传入的 boolean != 0)**

#### 4.1 本题为什么固定走 byte_505DF0=1 分支？

因为加密发生在 `MyisolatedService` 进程，而它：

- `isolatedProcess=true` → `Process.isIsolated()==true`
- Service 的 onCreate 调 `Utils.chall_init(Process.isIsolated(), this);`
- 因此 `chall_init(true, ...)` → `byte_505DF0 = 1`

所以本题不需要“猜分支”，**必走 byte_505DF0==1 的 CRC 分支**。

------

### 5. makekey 分支细节（byte_505DF0==1）：CRC(cmdline) + 动态 delta

byte_505DF0==1 分支核心是：

1. 先对 `dword_505B48` 再做一次混合（你贴的 `loc_1A59B8` 那段 XOR/MVN/MUL）
   - 常量来自 `loc_1A59E4` 的前 4 字节：`AD 24 2C 78` → `0x782C24AD`
   - 混合公式可化简为：
     **mix(d, c) = (d XOR c) \* (~c) mod 2^32**
2. 计算 `crc = sub_1AC044(cmdline, strlen(cmdline))`
   - 这是自定义 CRC，不是标准 CRC32
   - 你贴的代码等价于：
     - init `v = 0xFFFFFFFF`
     - 每个字节：`v ^= b`，循环 8 次：
       - if (v&1) v=(v>>1)^POLY else v>>=1
     - return `~v`
   - POLY 由 `v5 = -713996727` 得：
     - `POLY = (-713996727) & 0xffffffff = 0xD5714649`
3. 用 `crc` 与 `d` 构造 4 个 u32 作为 key：

- `k0 = crc`
- `k1 = crc ^ d`
- `k2 = crc + d`
- `k3 = crc - d`   （全部 mod 2^32）

------

### 6. cmdline 不是 `com.vidar.chall:MyisolatedService`

你贴的 `sub_1A4C74` 会读 `/proc/self/cmdline`：

```
fopen("/proc/self/cmdline","r");
fread(buf, 1, a2-1, stream);
strlen(buf)
```

而这段读 cmdline 的逻辑是在 `sub_1A4F44` 里执行，并且它发生在 **.init_array（构造函数）阶段**初始化 `qword_505E20`。

结合 manifest：

- `android:zygotePreloadName="com.vidar.chall.MyzygotePreload"`
- `android:useAppZygote="true"`

意味着：native 库会在 **AppZygote preload 阶段**就被加载执行构造函数。
 所以 `/proc/self/cmdline` 当时读到的不是 service 的进程名，而是 **AppZygote 进程名**。

AppZygote 的 cmdline/nice-name 形式是：

> ```
> 包名 + "_zygote"
> ```

因此这里用于 CRC 的 cmdline 是：

**`com.vidar.chall_zygote`**

这就是为什么很多人枚举 `com.vidar.chall:MyisolatedService` / `:isolated_process0` 会一直解不出来。

------

### 7. dword_505B48（delta）全链静态计算

你已经提供了几个“从代码字节取常量”的关键 4 字节：

- `*(u32*)sub_1A4E0C = C7 06 DA 2C = 0x2CDA06C7`
- `*(u32*)sub_1A5F68 = 29 2B 20 8B = 0x8B202B29`
- `*(u32*)loc_1A59E4 = AD 24 2C 78 = 0x782C24AD`

并且 so 内对 `dword_505B48` 的更新主要有两类：

- **mix 型**：`d = (d ^ c) * ~c`
- **mul-xor 型**：`d = K * (d ^ c)`（这里 K 本质上也等价于某个 ~c）

按“Service isolated=true 的路径”顺序：

初值：

- `d0 = 0xDEADBEEF`

(1) `.init_array sub_1A4DB8`（mix，常量来自 sub_1A4E0C 字节）

- `d1 = mix(d0, 0x2CDA06C7) = 0x121730C0`

(2) `.init_array sub_1A4EF0`（mul-xor）

- `d2 = (-864422828) * (d1 ^ 0x33860BAB) = 0xC9DC7B1C`

(3) `JNI_OnLoad`（mix，常量来自 sub_1A5F68 字节）

- `d3 = mix(d2, 0x8B202B29) = 0xD381F04E`

(4) `chall_init`（mul-xor）

- `d4 = (-1113723296) * (d3 ^ 0x4262119F) = 0x5B91FC60`

(5) `chall_init` 内部 `sub_1A50F0`，因为 isolated=true 再 mix 一次（常量 0x51C117A4）

- `d5 = mix(d4, 0x51C117A4) = 0x51E56EAC`

(6) `makekey` 的 isolated 分支再 mix（常量来自 loc_1A59E4 字节）

- `d6 = mix(d5, 0x782C24AD) = 0x1A9B8F52`

因此最终 **XXTEA delta**（encrypt 使用的 a4）为：

✅ **`delta = 0x1A9B8F52`**

------

### 8. 计算 CRC 与 key

cmdline 取：

✅ `cmdline = "com.vidar.chall_zygote"`

用 poly=0xD5714649 的自定义 CRC 得：

✅ `crc = 0x7838EC8F`

构造 key：

- `k0 = 0x7838EC8F`
- `k1 = crc ^ delta = 0x62A363DD`
- `k2 = crc + delta = 0x92D47BE1`
- `k3 = crc - delta = 0x5D9D5D3D`

### 解题脚本

```
import base64, struct

CIPH_B64 = "jdh2rzUxbpRxlfFro3YGuhHhmpWq4eHqTvK3N1njLjMnkSUS3I6VDg=="

def mix(d, c):
    return ((d ^ c) * (~c & 0xFFFFFFFF)) & 0xFFFFFFFF

POLY = (-713996727) & 0xFFFFFFFF  # 0xD571B5D9

def crc_custom(data: bytes):
    v = 0xFFFFFFFF
    for b in data:
        v ^= b
        for _ in range(8):
            v = ((v >> 1) ^ POLY) if (v & 1) else (v >> 1)
            v &= 0xFFFFFFFF
    return (~v) & 0xFFFFFFFF

def xxtea_decrypt(v, key, delta):
    n = len(v)
    rounds = 0x34 // n + 6
    summ = (rounds * delta) & 0xFFFFFFFF
    y = v[0]
    while rounds:
        e = (summ >> 2) & 3
        for p in range(n - 1, 0, -1):
            z = v[p - 1]
            mx = (((4*y) ^ (z >> 5)) + ((16*z) ^ (y >> 3))) ^ ((summ ^ y) + (key[(p & 3) ^ e] ^ z))
            v[p] = (v[p] - mx) & 0xFFFFFFFF
            y = v[p]
        z = v[n - 1]
        mx = (((4*y) ^ (z >> 5)) + ((16*z) ^ (y >> 3))) ^ ((summ ^ y) + (key[e] ^ z))
        v[0] = (v[0] - mx) & 0xFFFFFFFF
        y = v[0]
        summ = (summ - delta) & 0xFFFFFFFF
        rounds -= 1
    return v

# delta: 按 so 里那串 mix 链算出来
delta = 0x1A9B8F52

# cmdline 关键：AppZygote 的名字
cmdline = b"com.vidar.chall_zygote"
crc = crc_custom(cmdline)
key = [crc, crc ^ delta, (crc + delta) & 0xFFFFFFFF, (crc - delta) & 0xFFFFFFFF]

cipher = base64.b64decode(CIPH_B64)
v = list(struct.unpack("<10I", cipher))
p = xxtea_decrypt(v, key, delta)
plain = struct.pack("<10I", *p).rstrip(b"\x00")
print(plain.decode())

```



hgame{Wow_e4sy_@nd_s1ni5ter_chall_XD}





## **衔尾蛇**

让ai看一下smail代码

###  `initContext()` 

1. 先跑 `_check()`：
   读取 JVM 启动参数 `getInputArguments()`，只要包含 `-javaagent / -Xdebug / arthas / instrument` 就 `System.exit(0)`
2. 从 `com.seal.ouroborosapi.IntegrityVerifier.getDeriveKey()` 取一个 32-bit 整数 `k` 作为种子。
3. 读取资源 `R_NAME` → `"/application-data.db"` 得到密文 `d`。
4. 用一个 LCG 伪随机序列生成 keystream，对 `d` 每个字节异或解密：
   - `s = (s*1103515245 + 12345) & 0xffffffff`
   - `x = (s >>> 16) & 0xff`
   - `d[i] ^= x`
5. 解密后跳过 **前 128 字节**，把后面当作 **JarInputStream** 读取 `.class`，然后 `defineClass`：
   - 先加载除 `*RealRiskEngine` 之外的所有类
   - 最后加载目标类（类名以 `RealRiskEngine` 结尾），newInstance 得到 `RiskEngine`

也就是说：`application-data.db` 其实是 **“加密后的 jar + 128 字节前缀垃圾”**。

------

### 把 payload.jar 解出来

我们甚至可以不管 `getDeriveKey()` 返回啥，利用一个事实：
 解密后 **offset=128** 处必然是 jar(zip) 头：`PK\x03\x04`

解密脚本

```
import zipfile

A = 1103515245
C = 12345
MASK = 0xFFFFFFFF

DB_PATH = r"application-data.db"   # 按你的实际路径改
OFFSET = 128
KNOWN = b"PK\x03\x04"

def lcg_next(s: int) -> int:
    return (A * s + C) & MASK

def lcg_prev(s: int, a_inv: int) -> int:
    return (a_inv * ((s - C) & MASK)) & MASK

def recover_seed(cipher: bytes) -> int:
    # keystream bytes at positions OFFSET..OFFSET+3
    ks = bytes([cipher[OFFSET+i] ^ KNOWN[i] for i in range(4)])
    x0, x1, x2, x3 = ks

    # We brute-force full s_{OFFSET+1} (here s129) consistent with 4 output bytes.
    # s129 structure: [high8][x0][low16]
    cand_s = None
    for high8 in range(256):
        base = (high8 << 24) | (x0 << 16)
        for low16 in range(65536):
            s = base | low16
            s1 = lcg_next(s)
            if ((s1 >> 16) & 0xFF) != x1:
                continue
            s2 = lcg_next(s1)
            if ((s2 >> 16) & 0xFF) != x2:
                continue
            s3 = lcg_next(s2)
            if ((s3 >> 16) & 0xFF) != x3:
                continue
            cand_s = s
            break
        if cand_s is not None:
            break

    if cand_s is None:
        raise RuntimeError("No candidate state found. OFFSET/KNOWN might be wrong.")

    # cand_s is s_{OFFSET+1}. Need to rewind OFFSET+1 steps to get s0
    a_inv = pow(A, -1, 2**32)
    s = cand_s
    for _ in range(OFFSET + 1):
        s = lcg_prev(s, a_inv)
    return s

def decrypt(cipher: bytes, seed: int) -> bytes:
    s = seed & MASK
    out = bytearray(cipher)
    for i in range(len(out)):
        s = lcg_next(s)
        out[i] ^= (s >> 16) & 0xFF
    return bytes(out)

def main():
    cipher = open(DB_PATH, "rb").read()
    seed = recover_seed(cipher)
    plain = decrypt(cipher, seed)

    if plain[OFFSET:OFFSET+4] != KNOWN:
        raise RuntimeError("Decryption failed sanity check (PK header mismatch).")

    payload = plain[OFFSET:]
    open("payload.jar", "wb").write(payload)
    print(f"[+] seed = 0x{seed:08x}")
    print(f"[+] wrote payload.jar ({len(payload)} bytes)")

    # quick scan for flag-like strings in classfiles
    try:
        z = zipfile.ZipFile("payload.jar", "r")
        hits = []
        for name in z.namelist():
            if not name.endswith(".class"):
                continue
            data = z.read(name)
            if b"flag{" in data or b"FLAG{" in data or b"HGAME" in data:
                hits.append(name)
        print("[+] suspicious classes:")
        for h in hits:
            print("   ", h)
    except Exception as e:
        print("[!] zip read failed:", e)

if __name__ == "__main__":
    main()

```

解出来的payload.jar用jadx分析，是一个虚拟机

### 1) RealRiskEngine 里的 legacy 

`RealRiskEngine.checkLegacy()` 用：

- AES/CBC
- key = `"Ouroboros_Legacy"`
- iv = `"1234567812345678"`
- 密文 = `LEGACY_STORE`

解出来fakeflag,那还是要看vm：

> ```
> flag{N0p3_Th1s_1s_A_D3c0y_G0_B4ck}
> ```

------

### 2) OuroborosVM：一个很小的栈 VM

你拿到的 `payload.jar` 里 `OuroborosVM` 做了两件事：

1. 用 `deriveKey & 0xff` 把 `FIRMWARE` 异或解密（你这里 seed=0x7e40bec8，所以 keybyte=0xC8）。
2. 跑一个**很简单的字节码 VM**（你看到的大 switch 只是把 VM 展平成很多 state）。

这个 VM 的指令很少（够用来做逐字符校验）：

- `0x10`：push 16-bit 立即数（2字节）
- `0x20`：push token.length
- `0x30`：load（pop idx，push mem[idx]）
- `0x35`：xor（pop2，push a^b）
- `0x4A`：jz（pop x；若 x==0 则 pc += relByte）
- `0xFF`：return（pop；==1 返回 true）

------

### 3)解题脚本

下面这个脚本用 `javap` 把 `FIRMWARE` 的字节数组抠出来，解密并按 VM 指令模式还原校验字符串

```
import re
import subprocess

PAYLOAD_JAR = "payload.jar"
CLS = "com.seal.ouroboroscore.OuroborosVM"

DERIVE_KEY = 0x7e40bec8
KEYBYTE = DERIVE_KEY & 0xff

def get_javap():
    out = subprocess.check_output(
        ["javap", "-classpath", PAYLOAD_JAR, "-c", "-p", CLS],
        text=True, errors="ignore"
    )
    return out

def extract_firmware_bytes(javap_text: str):
    # 从 <clinit> 里找 bipush X + bastore 这种初始化 byte[] 的序列
    # 这能稳定拿到 FIRMWARE 的原始字节（有符号）
    vals = []
    for m in re.finditer(r"bipush\s+(-?\d+)\s*\n\s*\d+:\s*bastore", javap_text):
        vals.append(int(m.group(1)) & 0xff)
    return bytes(vals)

def decrypt_firmware(enc: bytes):
    return bytes(b ^ KEYBYTE for b in enc)

def decode_to_flag(fw: bytes):
    # 根据你这题的固件结构：是大量重复片段
    # PUSH idx; LOAD; PUSH val; XOR; JZ +1; RET
    # 先特殊处理开头的 LEN 校验，然后提取每个 idx 的 val
    pc = 0
    stack = []
    expected = {}

    def read_u16():
        nonlocal pc
        v = (fw[pc] << 8) | fw[pc+1]
        pc += 2
        return v

    while pc < len(fw):
        op = fw[pc]; pc += 1
        if op == 0x10:      # PUSH imm16
            stack.append(read_u16())
        elif op == 0x20:    # LEN
            # 这里只用于约束长度，提取 flag 不必真的跑
            stack.append("LEN")
        elif op == 0x30:    # LOAD
            idx = stack.pop()
            stack.append(("MEM", idx))
        elif op == 0x35:    # XOR
            b = stack.pop()
            a = stack.pop()
            # 只识别 (MEM, idx) XOR imm 的形态
            if isinstance(a, tuple) and a[0] == "MEM" and isinstance(b, int):
                stack.append(("XORCHK", a[1], b))
            elif isinstance(b, tuple) and b[0] == "MEM" and isinstance(a, int):
                stack.append(("XORCHK", b[1], a))
            else:
                stack.append(("XOR", a, b))
        elif op == 0x4A:    # JZ rel
            rel = int.from_bytes(bytes([fw[pc]]), "big", signed=True)
            pc += 1
            top = stack.pop()
            # 如果 top 是 XORCHK(idx, val)，说明这是一个“字符相等性校验”
            if isinstance(top, tuple) and top[0] == "XORCHK":
                _, idx, val = top
                expected[idx] = val
            # 真 VM 会根据 top==0 决定跳不跳；提取 flag 不需要真的跳
        elif op == 0xFF:    # RET
            # 结束或失败返回点，忽略
            stack.clear()
        else:
            # NOP/未知
            pass

    # firmware 首条校验要求长度为 33（你也能从 expected 的最大 idx+1 看出来）
    n = max(expected.keys()) + 1
    s = "".join(chr(expected.get(i, ord("?"))) for i in range(n))
    return s

if __name__ == "__main__":
    javap_text = get_javap()
    enc_fw = extract_firmware_bytes(javap_text)
    fw = decrypt_firmware(enc_fw)
    flag = decode_to_flag(fw)
    print(flag)
```

flag{Vm_1n_Vm_1s_Th3_R34l_M4tr1x}





## ezRSA

思路（核心漏洞）：

- 选项 3 之后 `safe=False`，加了 `disguise()`，但 **disguise 会保持最后 1 个字节不变**（最后一字节会被两次同 mask 异或抵消），所以解密接口变成了一个 **“明文最低字节（mod 256）泄露 oracle”**。
- 先在 `safe=True` 时把关键参数都搞到手：
  1. 用 `Encrypt(-1, x=1)` 得到 `(-1)^{odd} ≡ n-1 (mod n)`，因此直接恢复 **n**
  2. 用 `Encrypt(256, x=0)` 得到 `256^(e-1) (mod n)`，再乘 256 得到 **g = 256^e (mod n)**
  3. `Get flag` 拿到 `c = m^e (mod n)`
- 接着在 `safe=False` 下迭代查询：
  - 令 `c_i = c * g^i (mod n)`，解密得到 `m_i = (m * 256^i) mod n`
  - oracle 给出 `m_i mod 256`（就是返回 bytes 的最后一个字节）
  - 由 `m*256^i = q_i*n + m_i` 且 `256^i ≡ 0 (mod 256)`（i>=1），可得
    `q_i ≡ -(m_i) * (n^{-1} mod 256) (mod 256)`
    这正是 `floor(m*256^i/n)` 的 base256 小数展开的第 i 位
  - 收集约 `k = len(n in bytes)` 位（1024-bit n 大约 128 次）即可唯一恢复 m，再 unpad 得到 flag。

### 解题脚本

```
#!/usr/bin/env python3
from pwn import remote, context
import base64
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Util.Padding import unpad

HOST, PORT = "1.116.118.188", 32550   # 改成你实际端口

MENU = b"Your choice > "

def b64_to_int(line: bytes) -> int:
    return bytes_to_long(base64.b64decode(line))

def recv_menu(io):
    io.recvuntil(MENU)

def encrypt(io, m: int, x: int) -> int:
    recv_menu(io)
    io.sendline(b"1")
    io.recvuntil(b"plz give me your plaintext:\n")          # 吃掉 \n
    io.sendline(str(m).encode())
    io.recvuntil(b"and the bit you want to flip:\n")        # 吃掉 \n
    io.sendline(str(x).encode())
    line = io.recvline().strip()
    return b64_to_int(line)

def decrypt(io, c: int) -> bytes:
    recv_menu(io)
    io.sendline(b"2")
    io.recvuntil(b"plz give me your ciphertext:\n")         # 吃掉 \n
    io.sendline(str(c).encode())
    line = io.recvline().strip()
    return base64.b64decode(line)  # safe=False 时被 disguise，但最后 1 字节仍是真实的

def get_flag_cipher(io) -> int:
    recv_menu(io)
    io.sendline(b"3")
    line = io.recvline().strip()
    return b64_to_int(line)

def main():
    context.log_level = "debug"  # 想看交互就改成 debug
    io = remote(HOST, PORT)

    # 1) 恢复 n：Encrypt(-1, x=1) => (-1)^(odd) = n-1
    n_minus_1 = encrypt(io, -1, 1)
    n = n_minus_1 + 1
    print(f"[+] n bitlen = {n.bit_length()}")

    # 2) 计算 g = 256^e mod n
    t = encrypt(io, 256, 0)      # 256^(e-1) mod n (因为 e 必为奇数，e xor 1 = e-1)
    g = (t * 256) % n            # 256^e mod n

    # 3) 拿到 flag 密文（之后 safe=False）
    c0 = get_flag_cipher(io)

    inv_n_256 = pow(n % 256, -1, 256)
    k = (n.bit_length() + 7) // 8  # 1024-bit 一般 128 轮；不稳就 k += 2

    q = 0
    c = c0
    for i in range(1, k + 1):
        c = (c * g) % n
        pt = decrypt(io, c)
        lsb = pt[-1]                       # 真实的 (m*256^i mod n) 的最低字节
        digit = (-lsb * inv_n_256) % 256   # 得到 q_i 的最低 base256 位
        q = q * 256 + digit

    B = 256 ** k
    m = (q * n + B - 1) // B               # m = ceil(q*n / 256^k)

    flag_padded = long_to_bytes(m, 127)
    try:
        flag = unpad(flag_padded, 127)
    except ValueError:
        flag = flag_padded

    print("[+] flag =", flag.decode(errors="ignore"))
    io.close()

if __name__ == "__main__":
    main()

```

```
[DEBUG] Received 0x41 bytes:
    b'\n'
    b'1. Encrypt message\n'
    b'2. Decrypt message\n'
    b'3. Get flag\n'
    b'Your choice > '
[+] flag = hgame{E2RSA_1s_sTll1_PREttY-ez,riGht?41edd1}
[*] Closed connection to 1.116.118.188 port 32550
```





## ezDLP

<img src="C:\Users\HONOR\AppData\Roaming\Typora\typora-user-images\image-20260209224625194.png" alt="image-20260209224625194" style="zoom:67%;" />

------

<img src="C:\Users\HONOR\AppData\Roaming\Typora\typora-user-images\image-20260209224640152.png" alt="image-20260209224640152" style="zoom:67%;" />

------

<img src="C:\Users\HONOR\AppData\Roaming\Typora\typora-user-images\image-20260209224552238.png" alt="image-20260209224552238" style="zoom: 67%;" />

### 解题脚本

```
# -*- coding: utf-8 -*-
import zlib, pickletools, base64, hashlib
import sympy as sp
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Util.number import long_to_bytes

DATA_PATH = "data.sobj"
CIPH_B64 = "ieJNk5335o9lCy6Ar2XymrDy+HVHcQhikluNSra0kBafw1WDCyyuNPkLACeBsavy"

# ====== 你的 FactorDB 两个 162 位因子 ======
P_STR = "282964522500710252996522860321128988886949295243765606602614844463493284542147924563568163094392590450939540920228998768405900675902689378522299357223754617695943"
Q_STR = "511405127645157121220046316928395473344738559750412727565053675377154964183416414295066240070803421575018695355362581643466329860038567115911393279779768674224503"
# =========================================

ALPH32 = set("0123456789abcdefghijklmnopqrstuv")


# ---------- 读取 data.sobj ----------
def extract_ints_from_sobj(path):
    raw = open(path, "rb").read()
    try:
        dec = zlib.decompress(raw)
    except zlib.error:
        dec = raw

    nums = []
    for op, arg, pos in pickletools.genops(dec):
        if op.name in ("BINUNICODE", "SHORT_BINUNICODE", "UNICODE"):
            if isinstance(arg, str) and len(arg) > 10 and set(arg) <= ALPH32:
                nums.append(int(arg, 32))
    return nums


def parse_n_a_b(nums):
    if not nums:
        raise ValueError("no integers extracted from data.sobj")

    # n 是最大的那个
    idx_n = max(range(len(nums)), key=lambda i: nums[i].bit_length())
    n = nums[idx_n]
    det_a = nums[idx_n + 1] % n

    # 找第二个 n（Sage pickle 常见：会重复存 modulus）
    idx_n2 = None
    for j in range(idx_n + 2, min(idx_n + 60, len(nums))):
        if nums[j] == n:
            idx_n2 = j
            break
    if idx_n2 is None:
        idx_n2 = idx_n + 2  # 兜底

    a_entries = nums[idx_n2 + 1: idx_n2 + 5]
    det_b = nums[idx_n2 + 5] % n
    b_entries = nums[idx_n2 + 6: idx_n2 + 10]

    if len(a_entries) != 4 or len(b_entries) != 4:
        raise ValueError(f"parse failed: got a={len(a_entries)} b={len(b_entries)}")

    a = [[a_entries[0] % n, a_entries[1] % n],
         [a_entries[2] % n, a_entries[3] % n]]
    b = [[b_entries[0] % n, b_entries[1] % n],
         [b_entries[2] % n, b_entries[3] % n]]
    return n, a, b, det_a, det_b


# ---------- FactorDB 因子分解（递归展开） ----------
def factordb_query(n: int):
    url = f"http://factordb.com/api?query={n}"
    return requests.get(url, timeout=20).json()


def factordb_factorint(n: int):
    """
    返回 dict: {prime_or_prp: exp, ...}
    FactorDB 可能返回合数因子，这里递归展开。
    """
    j = factordb_query(n)
    status = j.get("status", "")

    if status in ("P", "PRP"):
        return {n: 1}

    factors = j.get("factors", [])
    if not factors:
        # fallback：本地试一下
        return sp.factorint(n)

    out = {}
    for f_str, e_str in factors:
        f = int(f_str)
        e = int(e_str)
        sub = factordb_factorint(f) if f != n else sp.factorint(f)
        for pp, ee in sub.items():
            out[pp] = out.get(pp, 0) + ee * e
    return out


# ---------- 由 (p-1) 的分解快速求元素阶 ----------
def element_order_from_pminus1(g: int, p: int, fac_p1: dict):
    """
    g in F_p^*, order | (p-1)
    用 fac(p-1) 逐步约简阶，避免 sympy.n_order 卡在分解。
    返回 (ord, ord_factorization_dict)
    """
    order = p - 1
    ord_fac = dict(fac_p1)  # prime->exp

    for r in list(ord_fac.keys()):
        e = ord_fac[r]
        for _ in range(e):
            if order % r != 0:
                break
            cand = order // r
            if pow(g, cand, p) == 1:
                order = cand
                ord_fac[r] -= 1
                if ord_fac[r] == 0:
                    del ord_fac[r]
            else:
                break

    if pow(g, order, p) != 1:
        raise ValueError("order computation failed (sanity check)")
    return int(order), ord_fac


# ---------- dlog：用 SymPy 内部 Pohlig–Hellman ----------
def dlog_pohlig_hellman_prime(p: int, g: int, h: int, order: int, order_factors: dict):
    """
    solve g^x = h (mod p) in subgroup of size 'order'
    """
    from sympy.ntheory.residue_ntheory import _discrete_log_pohlig_hellman
    return int(_discrete_log_pohlig_hellman(p, h, g, int(order), order_factors))


def recover_k_mod_prime(p: int, det_a: int, det_b: int):
    da = det_a % p
    db = det_b % p
    if da == 0 or db == 0:
        raise ValueError("det is 0 mod prime, determinant method not applicable")

    fac_p1 = factordb_factorint(p - 1)           # 用 FactorDB 快速分解 p-1
    ord_da, fac_ord = element_order_from_pminus1(da, p, fac_p1)

    print(f"    [mod prime] ord(det_a) bitlen = {ord_da.bit_length()}")

    k_mod = dlog_pohlig_hellman_prime(p, da, db, ord_da, fac_ord)
    return k_mod, ord_da


# ---------- 通用 CRT（支持模数不互素） ----------
def egcd(a, b):
    if b == 0:
        return a, 1, 0
    g, x1, y1 = egcd(b, a % b)
    return g, y1, x1 - (a // b) * y1


def crt_general(a1, m1, a2, m2):
    """
    解:
      x ≡ a1 (mod m1)
      x ≡ a2 (mod m2)
    返回 (x0, lcm) 其中 x ≡ x0 (mod lcm)
    若无解抛异常
    """
    a1 %= m1
    a2 %= m2
    g, s, t = egcd(m1, m2)
    if (a2 - a1) % g != 0:
        raise ValueError("CRT: inconsistent congruences")

    lcm = m1 // g * m2
    # x = a1 + m1 * k
    # m1*k ≡ (a2-a1) (mod m2)
    k = ((a2 - a1) // g * s) % (m2 // g)
    x = (a1 + m1 * k) % lcm
    return x, lcm


def lift_k_with_crt(congs):
    r, M = congs[0]
    for r2, m2 in congs[1:]:
        r, M = crt_general(r, M, r2, m2)
    return r, M


# ---------- 找 1000-bit prime 的 k 并解密 ----------
def find_1000bit_prime_candidates(r, M):
    lo = 1 << 999
    hi = 1 << 1000

    t0 = (lo - r + M - 1) // M
    cands = []
    for t in range(max(0, t0 - 3), t0 + 20):
        k = r + t * M
        if lo <= k < hi and sp.isprime(k):
            cands.append(k)
    return cands


def decrypt_flag(k):
    key = hashlib.md5(long_to_bytes(k)).digest()
    ct = base64.b64decode(CIPH_B64)
    pt = AES.new(key, AES.MODE_ECB).decrypt(ct)
    try:
        return unpad(pt, 16)
    except ValueError:
        return pt


def main():
    p = int(P_STR)
    q = int(Q_STR)

    nums = extract_ints_from_sobj(DATA_PATH)
    n, a, b, det_a, det_b = parse_n_a_b(nums)

    print("[+] n bitlen =", n.bit_length())
    print("[+] det_a bitlen =", det_a.bit_length())
    print("[+] det_b bitlen =", det_b.bit_length())
    print("[+] check p*q == n ?", (p * q == n))

    print("[*] solving discrete log mod p...")
    kp, mp = recover_k_mod_prime(p, det_a, det_b)
    print("    k ≡", kp, "(mod", mp, ")")

    print("[*] solving discrete log mod q...")
    kq, mq = recover_k_mod_prime(q, det_a, det_b)
    print("    k ≡", kq, "(mod", mq, ")")

    r, M = lift_k_with_crt([(kp, mp), (kq, mq)])
    print("[+] combined: k ≡ r (mod M)")
    print("    M bitlen =", M.bit_length())

    cands = find_1000bit_prime_candidates(r, M)
    print("[+] prime candidates:", len(cands))

    for i, k in enumerate(cands):
        flag = decrypt_flag(k)
        print(f"[+] cand {i}: k bitlen={k.bit_length()}  decrypted={flag}")
        if isinstance(flag, (bytes, bytearray)) and (b"{" in flag or b"flag" in flag or b"HGAME" in flag):
            break


if __name__ == "__main__":
    main()

```

```
[+] n bitlen = 1074
[+] det_a bitlen = 1071
[+] det_b bitlen = 1072
[+] check p*q == n ? True
[*] solving discrete log mod p...
    [mod prime] ord(det_a) bitlen = 536
    k ≡ 52667753106966975782716551178346612993779763057471591956442663755590760938250730438530201096693603009616300385149850720497921006714509073486101967205417901945848 (mod 141482261250355126498261430160564494443474647621882803301307422231746642271073962281784081547196295225469770460114499384202950337951344689261149678611877308847971 )
[*] solving discrete log mod q...
    [mod prime] ord(det_a) bitlen = 538
    k ≡ 97793690266943406431658643072078654035411321038962116230462569216011685651545408039832085776884476346748323733709768043043618444157526539743259646621167459948583 (mod 511405127645157121220046316928395473344738559750412727565053675377154964183416414295066240070803421575018695355362581643466329860038567115911393279779768674224502 )
[+] combined: k ≡ r (mod M)
    M bitlen = 1073
[+] prime candidates: 1
[+] cand 0: k bitlen=1000  decrypted=b'hgame{1s_m@trix_d1p_rEal1y_sImpLe??}'
```

## Decision

### 题目分析

题目脚本（task.py）的核心逻辑是：

- 先把 flag 变成整数，再转成二进制串并补齐到 `25*8=200` 位：

  ```
  flagbin = bin(int.from_bytes(flag,'little'))[2:].rjust(25*8,"0")
  ```

- 对每一位 bit 生成一个 block，block 内有 `m=15` 条“样本”：

  - 若 bit=1：输出真实的 LWE 样本 `(a,b)`
  - 若 bit=0：输出完全均匀随机的 26 维向量（前 25 维 + 最后一维）

因此 output.txt 是一个长度 200 的列表，每项是 15 个长度 26 的 tuple。

**关键点：**两种情况下 `a` 都是均匀随机，差别只在 `b`：

- LWE：`b = <a,s> + e (mod q)`，其中噪声 `e` 很小（离散高斯，σ=2^16）
- Random：`b` 均匀随机，且与 `a` 独立

这明显是“区分 LWE 与均匀随机”的题。

### 为什么不能单独判一个 block

每个 block 只有 15 条样本，而维度 `n=25`。

要做 dual distinguisher 需要找非零向量 `u` 使得：

uTA≡0(modq)u^T A \equiv 0 \pmod quTA≡0(modq)

其中 `A` 是样本里的 `a` 组成的矩阵（行数 = 样本数）。

但单个 block：`A` 是 15×25，通常满秩，**不存在非零左核向量**，所以无法直接做 dual。

### 核心思路：拼两个 block 做 dual distinguisher

把两个 block 拼在一起：

- 样本数变成 30（>25），`A` 是 30×25
- 这时必然存在非零 `u ∈ Z^30` 满足 `u^T A = 0 (mod q)`

对同样拼起来的 `b` 向量，有：

- 若两个 block 都是 LWE（bit=1）：

  uTb≡uTe(modq)u^T b \equiv u^T e \pmod quTb≡uTe(modq)

  右侧是噪声的线性组合，中心化后 **非常接近 0**。

- 只要混入任意随机 block（bit=0）：
  `b` 对 `u` 近似均匀随机，`u^T b (mod q)` 中心化后通常在 **q/2 量级**。

因此我们可以定义一个 `score(i,j)`：

- 把第 i、j 两个 block 拼起来算一个短 `u`
- 计算 `t = center(u^T b mod q)` 的绝对值
- `|t|` 小 → 更像 LWE-LWE
- `|t|` 大 → 更像 random 混入

### 怎么找到 “LWE anchors”

问题变成：200 个 block 里哪些是 bit=1（LWE）？

我们先用 `score(i,j)` 去找“可靠的 LWE 块”当锚点（anchors）：

1. 随机抽大量 pair (i,j) 计算 score
2. 选一个阈值 TH，把 `score < TH` 的 pair 看作图的一条边
3. 在这个图中：
   - LWE 块之间更容易连边（因为 LWE-LWE 的 score 小）
   - 随机块很难连边
4. 度数高的点大概率是 LWE，取若干度数最高且与 anchor1 也“相互小 score” 的点作为 anchors

### 用 anchors 判 200 位

对每个 block k：

- 计算它与多个 anchors 的 `score(anchor, k)`
- 统计“有多少个 anchor 认为它像 LWE”（即 score < TH）
- 票数足够多 → 判 bit=1，否则 bit=0

为了减少偶然性（multiple testing），不直接取最小 score，而是用 **多个短 u 候选的中位数**做最终 score（更稳）。

### 解题脚本

```
#!/usr/bin/env sage
# solve.sage  (robust, no kmeans, no division-by-zero)
# run: sage solve.sage

import ast
import math
import random as pyrandom
from collections import Counter
from itertools import combinations

from fpylll import IntegerMatrix, LLL

# ===== fixed params from task.py =====
n, m = 25, 15
q = 256708627612544299823733222331047933697  # comment in task.py

# ===== utilities =====
def center_mod(x: int) -> int:
    x %= q
    if x > q // 2:
        x -= q
    return x

def inv_mod(a: int) -> int:
    return pow(a % q, -1, q)

def median_int(xs):
    xs = sorted(xs)
    k = len(xs)
    return xs[k // 2]

def right_kernel_basis_modq(B):
    """
    B: list of rows over GF(q), shape (nrows x ncols)
    Return basis vectors of right-kernel: B * v = 0 over GF(q).
    """
    rows = [row[:] for row in B]
    r = 0
    nrows = len(rows)
    ncols = len(rows[0])
    pivots = [-1] * nrows

    for c in range(ncols):
        piv = None
        for i in range(r, nrows):
            if rows[i][c] % q != 0:
                piv = i
                break
        if piv is None:
            continue

        rows[r], rows[piv] = rows[piv], rows[r]
        invp = inv_mod(rows[r][c])

        for j in range(c, ncols):
            rows[r][j] = (rows[r][j] * invp) % q

        for i in range(nrows):
            if i == r:
                continue
            factor = rows[i][c] % q
            if factor:
                for j in range(c, ncols):
                    rows[i][j] = (rows[i][j] - factor * rows[r][j]) % q

        pivots[r] = c
        r += 1
        if r == nrows:
            break

    pivset = set(p for p in pivots if p != -1)
    free_cols = [c for c in range(ncols) if c not in pivset]

    basis = []
    for fc in free_cols:
        v = [0] * ncols
        v[fc] = 1
        for i in range(r - 1, -1, -1):
            pc = pivots[i]
            if pc == -1:
                continue
            s = 0
            for j in range(pc + 1, ncols):
                if rows[i][j]:
                    s = (s + rows[i][j] * v[j]) % q
            v[pc] = (-s) % q
        basis.append(v)
    return basis

def lll_candidates_from_kernel(kernel_basis, take=6):
    """
    kernel_basis: k vectors length M, entries in [0,q).
    Lattice basis rows: [q I_M ; lift(kernel_basis)].
    Return up to 'take' short nontrivial vectors u.
    """
    k = len(kernel_basis)
    M = len(kernel_basis[0])
    mat = IntegerMatrix(M + k, M)

    for i in range(M):
        mat[i, i] = q

    for r, v in enumerate(kernel_basis):
        for c, x in enumerate(v):
            xi = x
            if xi > q // 2:
                xi -= q
            mat[M + r, c] = int(xi)

    LLL.reduction(mat)

    cand = []
    for i in range(min(M + k, take * 5)):
        u = [int(mat[i, j]) for j in range(M)]
        # ignore trivial multiples of q
        if all((x % q) == 0 for x in u):
            continue
        cand.append(u)
        if len(cand) >= take:
            break
    return cand

# ===== load data =====
print("[*] loading output.txt ...", flush=True)
enc = ast.literal_eval(open("output.txt", "r").read())
if len(enc) != 200:
    print(f"[!] warning: expected 200 blocks, got {len(enc)}", flush=True)
print("[*] loaded blocks =", len(enc), flush=True)

A_blocks, b_blocks = [], []
for blk in enc:
    A, b = [], []
    for row in blk:
        A.append([int(x) % q for x in row[:n]])
        b.append(int(row[n]) % q)
    A_blocks.append(A)  # 15 x 25
    b_blocks.append(b)  # 15

# ===== pairwise dual score (30 samples) =====
_pair_cache = {}

def pair_score(i, j, cand_take=6):
    """
    Score for blocks i,j:
      build A (30x25), find short u with u^T A = 0 mod q,
      compute several |center(u^T b)|, return MEDIAN (robust).
    """
    if i > j:
        i, j = j, i
    key = (i, j, cand_take)
    if key in _pair_cache:
        return _pair_cache[key]

    A = A_blocks[i] + A_blocks[j]  # 30x25
    b = b_blocks[i] + b_blocks[j]  # 30
    M = 30

    # B = A^T (25 x 30)
    B = [[A[r][c] for r in range(M)] for c in range(n)]
    ker = right_kernel_basis_modq(B)
    if not ker:
        _pair_cache[key] = None
        return None

    cands = lll_candidates_from_kernel(ker, take=cand_take)
    if not cands:
        _pair_cache[key] = None
        return None

    vals = []
    for u in cands:
        t = 0
        for ui, bi in zip(u, b):
            t = (t + (ui % q) * bi) % q
        vals.append(abs(center_mod(t)))

    sc = median_int(vals)  # IMPORTANT: median, not min
    _pair_cache[key] = sc
    return sc

# ===== find anchors via graph (scores of pairs) =====
pyrandom.seed(int(0x1337))

NP = 12000
print(f"[*] sampling {NP} pairs for anchor mining ...", flush=True)

pairs = []
for t in range(NP):
    i, j = pyrandom.sample(range(200), 2)
    sc = pair_score(i, j, cand_take=3)  # faster for mining
    if sc is None or sc == 0:
        continue
    pairs.append((sc, i, j))
    if (t + 1) % 2000 == 0:
        print(f"[*] sampled {t+1}/{NP}", flush=True)

pairs.sort(key=lambda x: x[0])
print(f"[*] usable mined pairs: {len(pairs)}", flush=True)
if len(pairs) < 3000:
    raise RuntimeError("Too few usable pairs; check parsing/output.txt format.")

# choose cutoff index by maximizing degree separation under reasonable density
deg = [0] * 200
edges = 0
best_idx = None
best_metric = -1.0

CHECK_EVERY = 200
for idx, (sc, i, j) in enumerate(pairs, start=1):
    deg[i] += 1
    deg[j] += 1
    edges += 1

    if idx % CHECK_EVERY:
        continue

    avgdeg = (2.0 * edges) / 200.0
    if not (6.0 <= avgdeg <= 100.0):
        continue

    sd = sorted(deg)
    mx = sd[-1]
    p90 = sd[int(0.90 * 199)]
    metric = (mx - p90) / (avgdeg + 1e-9)
    if metric > best_metric:
        best_metric = metric
        best_idx = idx

if best_idx is None:
    best_idx = max(800, len(pairs) // 12)

TH_pair = pairs[best_idx - 1][0]
print(f"[+] pair cutoff={best_idx}, TH_pair bitlen={TH_pair.bit_length()}", flush=True)

deg = [0] * 200
adj = [[] for _ in range(200)]
for sc, i, j in pairs[:best_idx]:
    if sc <= TH_pair:
        deg[i] += 1
        deg[j] += 1
        adj[i].append(j)
        adj[j].append(i)

a1 = max(range(200), key=lambda x: deg[x])
print("[+] anchor1 =", a1, "deg=", deg[a1], flush=True)

# pick anchors strongly linked to a1 and high degree
anchors = [a1]
for x in sorted(range(200), key=lambda z: deg[z], reverse=True):
    if x == a1:
        continue
    sc = pair_score(a1, x, cand_take=3)
    if sc is not None and sc <= TH_pair:
        anchors.append(x)
    if len(anchors) >= 10:
        break

print("[+] anchors:", anchors, flush=True)
if len(anchors) < 6:
    print("[!] few anchors; still proceeding, but you can increase NP if needed.", flush=True)

# ===== score each block against multiple anchors =====
USE_ANCHORS = anchors[:8] if len(anchors) >= 8 else anchors[:]  # up to 8 anchors
print("[*] scoring each block vs anchors:", USE_ANCHORS, flush=True)

metrics = [0.0] * 200
perblock_scores = [[] for _ in range(200)]

for k in range(200):
    scs = []
    for a in USE_ANCHORS:
        if a == k:
            continue
        sc = pair_score(a, k, cand_take=6)  # robust scoring for classification
        if sc is None or sc == 0:
            sc = q // 2
        scs.append(sc)
    perblock_scores[k] = scs
    logs = [math.log2(s) for s in scs]
    logs.sort()
    metrics[k] = logs[len(logs)//2]  # median log2
    if (k + 1) % 20 == 0:
        print(f"[*] block metrics {k+1}/200", flush=True)

# ===== 1D optimal split by minimizing within-class SSE =====
# sort by metric
order = sorted(range(200), key=lambda i: metrics[i])
xs = [metrics[i] for i in order]

# prefix sums
pref1 = [0.0]
pref2 = [0.0]
for v in xs:
    pref1.append(pref1[-1] + v)
    pref2.append(pref2[-1] + v*v)

def sse(l, r):  # [l, r)
    n_ = r - l
    if n_ <= 0:
        return float("inf")
    s1 = pref1[r] - pref1[l]
    s2 = pref2[r] - pref2[l]
    mu = s1 / n_
    return s2 - 2*mu*s1 + n_*(mu*mu)

best_cut = None
best_cost = float("inf")
for cut in range(1, 200):
    cost = sse(0, cut) + sse(cut, 200)
    if cost < best_cost:
        best_cost = cost
        best_cut = cut

left = order[:best_cut]
right = order[best_cut:]
mu_left = sum(metrics[i] for i in left) / len(left)
mu_right = sum(metrics[i] for i in right) / len(right)

# smaller metric => more likely LWE => bit=1
lwe_side_left = (mu_left < mu_right)
thr = (xs[best_cut-1] + xs[best_cut]) / 2.0

print(f"[+] split cut={best_cut}, thr≈{thr:.4f}, mu_left={mu_left:.4f}, mu_right={mu_right:.4f}", flush=True)

bits = [0]*200
for i in range(200):
    in_left = metrics[i] <= thr
    bits[i] = 1 if (in_left == lwe_side_left) else 0

def bits_to_int(bitlist):
    bitstr = "".join(str(b) for b in bitlist)
    return int(bitstr, 2)

def payload_from_int(x):
    return x.to_bytes(25, "little")

def payload_score(payload: bytes) -> int:
    # heuristic: prefer printable / typical CTF charset
    good = 0
    allowed = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_@-."
    for c in payload:
        if 32 <= c <= 126:
            good += 3
        else:
            good -= 12
        if c in allowed:
            good += 2
        if c in (0x7f, ord('{'), ord('}')):
            good -= 6
    return good

x0 = bits_to_int(bits)
p0 = payload_from_int(x0)
flag0 = b"hgame{" + p0 + b"}"
print("[+] candidate:", flag0, flush=True)

# ===== local correction: flip low-confidence bits (if needed) =====
# confidence = distance to threshold (smaller => more uncertain)
conf = [(abs(metrics[i] - thr), i) for i in range(200)]
conf.sort()

def improve_by_flips(x_base: int, max_flip=5, pool=30):
    pool_idx = [i for _, i in conf[:pool]]
    masks = [(1 << (199 - i)) for i in pool_idx]  # bit i is MSB-first

    best_x = x_base
    best_p = payload_from_int(best_x)
    best_s = payload_score(best_p)

    # include base
    best = (best_s, best_x, best_p)

    # try combos
    for r in range(1, max_flip + 1):
        for comb in combinations(range(pool), r):
            x = x_base
            for t in comb:
                x ^= masks[t]
            p = payload_from_int(x)
            s = payload_score(p)
            if s > best[0]:
                best = (s, x, p)
        # small early-exit if already very printable
        if best[0] >= 25 * 4:  # near-perfect
            break

    return best

# decide whether to run search (trigger if too many nonprintables)
printable_cnt = sum(1 for c in p0 if 32 <= c <= 126)
if printable_cnt < 25:
    print(f"[*] printable {printable_cnt}/25 => running local flip search ...", flush=True)
    best_s, best_x, best_p = improve_by_flips(x0, max_flip=5, pool=30)
    best_flag = b"hgame{" + best_p + b"}"
    print(f"[+] best_score={best_s}", flush=True)
    print("[FINAL]", best_flag, flush=True)
else:
    print("[FINAL]", flag0, flush=True)

```

```
[*] loading output.txt ...
[*] loaded blocks = 200
[*] sampling 12000 pairs for anchor mining ...
[*] sampled 2000/12000
[*] sampled 4000/12000
[*] sampled 6000/12000
[*] sampled 8000/12000
[*] sampled 10000/12000
[*] sampled 12000/12000
[*] usable mined pairs: 12000
[+] pair cutoff=600, TH_pair bitlen=122
[+] anchor1 = 46 deg= 21
[+] anchors: [46, 22, 154, 177, 3, 45, 70, 71, 81, 155]
[*] scoring each block vs anchors: [46, 22, 154, 177, 3, 45, 70, 71]
[*] block metrics 20/200
[*] block metrics 40/200
[*] block metrics 60/200
[*] block metrics 80/200
[*] block metrics 100/200
[*] block metrics 120/200
[*] block metrics 140/200
[*] block metrics 160/200
[*] block metrics 180/200
[*] block metrics 200/200
[+] split cut=112, thr≈124.3969, mu_left=122.8592, mu_right=125.8599
[+] candidate: b'hgame{w1sh_you_4_h@ppy_new_y3ar}'
[FINAL] b'hgame{w1sh_you_4_h@ppy_new_y3ar}'
```

## **eezzDLP**

### 1. 题目给了什么

`main2.py` 的核心逻辑是：main2

- 生成素数 p，令 n = p*p
- 在 Zmod(n) 上随机 2x2 矩阵 A
- 生成 660-bit 素数 k：k = getPrime(660) main2
- 计算 B = A^k
- key = MD5(long_to_bytes(k))，AES-ECB 加密 flag main2
- 保存 (n, A, B) 到 data2.sobj，并给出 base64 密文

目标：恢复 k，然后解密。

------

### 2. 数据特点（data2.sobj）

这是 Sage 的 `.sobj`，实际是：

- zlib 压缩的 pickle
- Sage Integer 会序列化成 base32 字符串

所以无需 Sage：用 `pickletools.genops` 把所有 `BINUNICODE/SHORT_BINUNICODE` 抠出来，筛 base32 字符串，再 `int(s, 32)` 就能还原大整数。

n 是完全平方数，直接：

- p = isqrt(n)
- 验证 p*p == n 且 p 为素数

这是本题最重要入口：**不需要分解 n**。

解析出矩阵后会发现：

- det(A) mod n == 1
- det(B) mod n == 1

所以不能像上一题那样用 det(B) = det(A)^k 变成标量离散对数。

------

### 3. 解法总览

本题核心思路分两段：

1. 利用 n = p*p 的“线性化”性质，直接求出 `k mod p`（这一步给你约 612 bits 信息量）。
2. 因为 k 是 660-bit，写成 `k = kp + p*t`，则 t 只有大约 48 bits。
   再从 `A mod p` 的一个特征值构造标量方程 `lambda^t == rhs (mod p)`，用 **Pollard Kangaroo（有界 DLP）** 在区间内求 t。

最后得到完整 k，验证 `A^k == B (mod p^2)`，然后 AES 解密。

------

### 4. 第一步：求 k mod p（p^2 线性化）

#### 4.1 关键事实：如果 X == I (mod p)，则 (I + p*M)^k 可线性化

在模 p^2 下有：

- 若 X == I (mod p)，则可写 X == I + p*M (mod p^2)
- 因为 (p*M)^2 == 0 (mod p^2)，所以：
  (I + p*M)^k == I + p*k*M  (mod p^2)

这是本题的“核心漏洞”。

#### 4.2 构造 C = A^(p-1)，让它在 mod p 下变成单位阵

在有限域 F_p 上，很多 2x2 矩阵满足：

- pow(A mod p, p-1) == I  (mod p)

脚本做法是：尝试几个常见指数 e：

- e = p-1
- e = p+1
- e = 2*(p-1)
- e = 2*(p+1)

找到一个 e 使得：

- pow(A mod p, e) == I  (mod p)

你这题里用到的是 e = p-1。

然后令：

- C = pow(A, e)  (mod p^2)
- D = pow(B, e)  (mod p^2)

因为 B = A^k，所以：

- D = pow(B, e) = pow(A^k, e) = pow(A, k*e) = pow(C, k)  (mod p^2)

又因为 C == I (mod p)，写成：

- C == I + p*X  (mod p^2)

则：

- D == C^k == (I + p*X)^k == I + p*k*X  (mod p^2)

#### 4.3 直接解出 k mod p

把矩阵等式改写成“除以 p”的形式：

- X' = (C - I)/p  (mod p)
- Y' = (D - I)/p  (mod p)

则有：

- Y' == k * X'  (mod p)

取任意一个位置 (i,j) 满足 X'[i][j] != 0 (mod p)，即可：

- k == Y'[i][j] * inv(X'[i][j])  (mod p)

这一步就得到 `kp = k mod p`（612-bit 信息量）。

------

### 5. 第二步：把剩余未知压成 48-bit，并做有界 DLP

#### 5.1 写成 k = kp + p*t

因为你已经知道 kp = k mod p，所以令：

- k = kp + p*t

题目规定 k 是 660-bit 素数 main2，而 p 是 612-bit，所以 t 的大小大概是：

- 660 - 612 = 48 bits

也就是说：剩下只是一个约 2^48 规模的未知量。

#### 5.2 在 F_p 上用特征值把矩阵幂转成标量幂

把 A 降到 mod p：

- A_p = A mod p
- B_p = B mod p

因为 det(A) == 1 (mod p)，其特征多项式可写成：

- x^2 - tr(A_p)*x + 1

判别式：

- D = tr(A_p)^2 - 4  (mod p)

用 Tonelli-Shanks 求 sqrt(D)，得到一个特征值：

- lambda = (tr(A_p) + sqrt(D)) * inv(2)  (mod p)

取对应特征向量 v，使：

- A_p * v == lambda * v  (mod p)

因为 B_p = A_p^k，所以：

- B_p * v == lambda^k * v  (mod p)

因此可以从比例得到：

- mu == lambda^k  (mod p)

（具体实现：算 Bv，然后用 v 的某个非零坐标做除法求 mu。）

#### 5.3 把指数 k 变成 t（有界 DLP 方程）

在 F_p 中有 lambda^p == lambda，因此：

- lambda^(p*t) == lambda^t  (mod p)

代入 k = kp + p*t：

- mu == lambda^k == lambda^(kp + p*t) == lambda^kp * lambda^t  (mod p)

所以：

- lambda^t == mu * lambda^(-kp)  (mod p)

令：

- g = lambda
- y = mu * pow(lambda, -kp)  (mod p)

我们要解：

- g^t == y  (mod p)

并且 t 的范围由 660-bit 限制确定：

- k in [2^659, 2^660)
- t_min = ceil((2^659 - kp)/p)
- t_max = floor((2^660 - 1 - kp)/p)

这就是标准的“区间内离散对数”。

#### 5.4 Pollard Kangaroo（Lambda method）求 t

普通 DLP 在 612-bit 群里不可行，但有界 DLP 可用 Pollard Kangaroo：

- 期望复杂度约 O(sqrt(t_max - t_min)) ~ O(2^24)

你实际跑出来大约 1800 万步，属于正常量级：

- 找到 t
- k = kp + p*t
- 验证 pow(A, k) == B  (mod p^2)

验证通过后就确定 k 正确。

### 解题脚本

```
# solve2_kangaroo.py
# Python 3.8+
import zlib, pickletools, math, hashlib, base64, random, time
import sympy as sp
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Util.number import long_to_bytes

DATA_PATH = "data2.sobj"
CIPH_B64  = "Q3UBa1pz1fi35L94peaFbPvpQe4UyXOUif3CKS/CmZdXOiV7bA5NNNjJ1KeUiAFE"

ALPH32 = set("0123456789abcdefghijklmnopqrstuv")

# -------------------- parse sobj (zlib + pickle base32 ints) --------------------
def extract_base32_ints(path):
    raw = open(path, "rb").read()
    try:
        dec = zlib.decompress(raw)
    except zlib.error:
        dec = raw

    vals = []
    for op, arg, pos in pickletools.genops(dec):
        if op.name in ("BINUNICODE", "SHORT_BINUNICODE", "UNICODE"):
            if isinstance(arg, str) and len(arg) > 10 and set(arg) <= ALPH32:
                vals.append(int(arg, 32))
    return vals

def parse_n_a_b(vals):
    # observed layout in pickle: [n, n, -trA, a00,a01,a10,a11, -trB, b00,b01,b10,b11]
    n = max(vals, key=lambda x: x.bit_length())
    idxs = [i for i, x in enumerate(vals) if x == n]
    if len(idxs) < 2:
        raise ValueError("cannot find repeated n in sobj")
    i0 = idxs[0]

    A = [vals[i0+3] % n, vals[i0+4] % n, vals[i0+5] % n, vals[i0+6] % n]
    B = [vals[i0+8] % n, vals[i0+9] % n, vals[i0+10] % n, vals[i0+11] % n]
    a = [[A[0], A[1]], [A[2], A[3]]]
    b = [[B[0], B[1]], [B[2], B[3]]]
    return n, a, b

# -------------------- 2x2 matrix ops mod m --------------------
def mat_mul(X, Y, mod):
    return [
        [(X[0][0]*Y[0][0] + X[0][1]*Y[1][0]) % mod,
         (X[0][0]*Y[0][1] + X[0][1]*Y[1][1]) % mod],
        [(X[1][0]*Y[0][0] + X[1][1]*Y[1][0]) % mod,
         (X[1][0]*Y[0][1] + X[1][1]*Y[1][1]) % mod],
    ]

def mat_pow(M, e, mod):
    R = [[1 % mod, 0], [0, 1 % mod]]
    A = [row[:] for row in M]
    while e > 0:
        if e & 1:
            R = mat_mul(R, A, mod)
        A = mat_mul(A, A, mod)
        e >>= 1
    return R

# -------------------- Step1: recover k mod p via (I+pX)^k linearization --------------------
def recover_k_mod_p(a, b, p):
    n = p * p
    ap = [[a[0][0] % p, a[0][1] % p],
          [a[1][0] % p, a[1][1] % p]]
    I_p = [[1 % p, 0], [0, 1 % p]]
    I_n = [[1, 0], [0, 1]]

    for e in [p - 1, p + 1, 2*(p - 1), 2*(p + 1)]:
        if mat_pow(ap, e, p) == I_p:
            C = mat_pow(a, e, n)
            D = mat_pow(b, e, n)
            X = [[((C[i][j] - I_n[i][j]) // p) % p for j in range(2)] for i in range(2)]
            Y = [[((D[i][j] - I_n[i][j]) // p) % p for j in range(2)] for i in range(2)]

            for i in range(2):
                for j in range(2):
                    if X[i][j] % p != 0:
                        kp = (Y[i][j] * pow(int(X[i][j]), -1, p)) % p
                        # sanity check on other nonzero entries
                        ok = True
                        for ii in range(2):
                            for jj in range(2):
                                if X[ii][jj] % p != 0 and (kp*X[ii][jj] - Y[ii][jj]) % p != 0:
                                    ok = False
                        if ok:
                            return int(kp), int(e)

    raise ValueError("failed to recover k mod p")

# -------------------- eigenvalue lambda and mu = lambda^k using eigenvector --------------------
def eigen_lambda_and_mu(ap, bp, p):
    tr = (ap[0][0] + ap[1][1]) % p
    D  = (tr*tr - 4) % p
    s  = int(sp.sqrt_mod(D, p, all_roots=False))
    inv2 = pow(2, -1, p)
    lam = int((tr + s) * inv2 % p)

    # eigenvector v for lam
    v0 = ap[0][1] % p
    v1 = (lam - ap[0][0]) % p
    if v0 == 0 and v1 == 0:
        v0 = (lam - ap[1][1]) % p
        v1 = ap[1][0] % p
    if v0 == 0 and v1 == 0:
        raise ValueError("failed to build eigenvector")

    # compute Bv = mu v
    Bv0 = (bp[0][0]*v0 + bp[0][1]*v1) % p
    Bv1 = (bp[1][0]*v0 + bp[1][1]*v1) % p
    if v0 != 0:
        mu = int(Bv0 * pow(int(v0), -1, p) % p)
    else:
        mu = int(Bv1 * pow(int(v1), -1, p) % p)

    return lam, mu

# -------------------- Pollard lambda (kangaroo) for bounded DLP in F_p* --------------------
def kangaroo_dlp(g, y, p, a, b,
                 m=32, dp_bits=16,
                 seed=2026,
                 max_steps=None,
                 progress_every=2_000_000):
    """
    Solve g^x = y (mod p), x in [a,b] using Pollard lambda (kangaroo).
    Returns x.
    """
    if a > b:
        raise ValueError("empty interval")

    # shift interval to [0, N]
    N = b - a
    inv_g = pow(g, -1, p)
    y = (y * pow(inv_g, a, p)) % p  # y = g^(x-a)

    # step sizes around sqrt(N)
    sqrtN = int(math.isqrt(N) + 1)
    rng = random.Random(seed)
    # random steps in [1, 2*sqrtN] (mean ~ sqrtN)
    steps = [rng.randrange(1, 2*sqrtN) for _ in range(m)]
    gsteps = [pow(g, s, p) for s in steps]

    mask = (1 << dp_bits) - 1
    def is_dp(v): return (v & mask) == 0
    def idx(v): return v & (m - 1)

    # expected total steps ~ O(sqrtN)
    if max_steps is None:
        max_steps = 3 * sqrtN  # safe upper bound

    # tame kangaroo: start at g^N
    T = pow(g, N, p)
    dT = 0
    table = {}

    t0 = time.time()
    for i in range(max_steps):
        if is_dp(T):
            # store the distance from g^N
            table[T] = dT
        j = idx(T)
        T = (T * gsteps[j]) % p
        dT += steps[j]
        if progress_every and (i+1) % progress_every == 0:
            print(f"[kangaroo] tame steps={i+1} stored={len(table)} elapsed={time.time()-t0:.1f}s")

    # wild kangaroo: start at y
    W = y
    dW = 0
    for i in range(max_steps * 2):
        hit = table.get(W)
        if hit is not None:
            x0 = N + hit - dW  # x0 in [0, N]
            if 0 <= x0 <= N:
                return x0 + a
        j = idx(W)
        W = (W * gsteps[j]) % p
        dW += steps[j]
        if progress_every and (i+1) % progress_every == 0:
            print(f"[kangaroo] wild steps={i+1} elapsed={time.time()-t0:.1f}s")

    raise ValueError("kangaroo failed: try increasing max_steps or tweaking dp_bits/m")

# -------------------- full solve --------------------
def main():
    vals = extract_base32_ints(DATA_PATH)
    n, a, b = parse_n_a_b(vals)
    p = int(math.isqrt(n))
    if p * p != n or not sp.isprime(p):
        raise ValueError("n is not p^2 with prime p")

    print("[+] p bitlen =", p.bit_length())

    # Step1: k mod p
    kp, e_used = recover_k_mod_p(a, b, p)
    print("[+] k ≡", kp, "(mod p)")
    print("[*] used exponent e =", "p-1" if e_used == p-1 else str(e_used))

    # Work in F_p
    ap = [[a[0][0] % p, a[0][1] % p], [a[1][0] % p, a[1][1] % p]]
    bp = [[b[0][0] % p, b[0][1] % p], [b[1][0] % p, b[1][1] % p]]

    # lambda and mu=lambda^k
    lam, mu = eigen_lambda_and_mu(ap, bp, p)

    # k = kp + p*t, and in F_p : lam^k = lam^{kp} * lam^t
    rhs = mu * pow(pow(lam, -1, p), kp, p) % p  # mu * lam^{-kp}

    # t interval from 660-bit constraint: k in [2^659, 2^660)
    lo = 1 << 659
    hi = (1 << 660) - 1
    t_min = (lo - kp + p - 1) // p
    t_max = (hi - kp) // p

    print("[+] t in [t_min, t_max], bitlen ~", t_max.bit_length())
    print("[*] solving bounded DLP: lam^t = rhs (mod p) ...")

    t = kangaroo_dlp(lam, rhs, p, int(t_min), int(t_max),
                     m=32, dp_bits=16, seed=2026,
                     max_steps=None, progress_every=2_000_000)
    print("[+] found t =", t)

    k = kp + p * t
    print("[+] recovered k bitlen =", k.bit_length(), " prime?", sp.isprime(k))

    # verify b == a^k mod n
    if mat_pow(a, k, n) != [[b[0][0] % n, b[0][1] % n], [b[1][0] % n, b[1][1] % n]]:
        raise RuntimeError("verification failed: wrong k (try other sqrt root / tweak kangaroo params)")
    print("[+] verified a^k == b (mod p^2)")

    # decrypt: key = md5(long_to_bytes(k)), AES-ECB  :contentReference[oaicite:4]{index=4}
    key = hashlib.md5(long_to_bytes(k)).digest()
    ct = base64.b64decode(CIPH_B64)
    pt = AES.new(key, AES.MODE_ECB).decrypt(ct)
    print("[+] flag =", unpad(pt, 16))

if __name__ == "__main__":
    main()

```

```
[+] p bitlen = 612
[+] k ≡ 874301246660326636505513899663599973889693807215778679835042497199743298293584492761781492878191716365676814326799530063414690708410762051147268687901533725057513275491624031068194116 (mod p)
[*] used exponent e = p-1
[+] t in [t_min, t_max], bitlen ~ 49
[*] solving bounded DLP: lam^t = rhs (mod p) ...
[kangaroo] tame steps=2000000 stored=28 elapsed=4.3s
[kangaroo] tame steps=4000000 stored=50 elapsed=8.9s
[kangaroo] tame steps=6000000 stored=84 elapsed=13.2s
[kangaroo] tame steps=8000000 stored=109 elapsed=17.6s
[kangaroo] tame steps=10000000 stored=150 elapsed=21.9s
[kangaroo] tame steps=12000000 stored=189 elapsed=26.1s
[kangaroo] tame steps=14000000 stored=220 elapsed=30.4s
[kangaroo] tame steps=16000000 stored=243 elapsed=34.6s
[kangaroo] tame steps=18000000 stored=276 elapsed=38.7s
[kangaroo] tame steps=20000000 stored=302 elapsed=43.0s
[kangaroo] tame steps=22000000 stored=332 elapsed=47.1s
[kangaroo] tame steps=24000000 stored=363 elapsed=51.3s
[kangaroo] tame steps=26000000 stored=390 elapsed=55.5s
[kangaroo] tame steps=28000000 stored=414 elapsed=59.6s
[kangaroo] tame steps=30000000 stored=438 elapsed=63.8s
[kangaroo] tame steps=32000000 stored=458 elapsed=68.1s
[kangaroo] tame steps=34000000 stored=491 elapsed=72.2s
[kangaroo] tame steps=36000000 stored=520 elapsed=76.5s
[kangaroo] tame steps=38000000 stored=557 elapsed=80.9s
[kangaroo] wild steps=2000000 elapsed=87.1s
[kangaroo] wild steps=4000000 elapsed=91.3s
[kangaroo] wild steps=6000000 elapsed=95.0s
[kangaroo] wild steps=8000000 elapsed=99.1s
[kangaroo] wild steps=10000000 elapsed=103.3s
[kangaroo] wild steps=12000000 elapsed=107.6s
[kangaroo] wild steps=14000000 elapsed=112.0s
[kangaroo] wild steps=16000000 elapsed=116.0s
[kangaroo] wild steps=18000000 elapsed=120.3s
[+] found t = 297202975974859
[+] recovered k bitlen = 660  prime? True
[+] verified a^k == b (mod p^2)
[+] flag = b'hgame{M@trix-d1p_iz_rea1ly_1z!1!111!}'
```

