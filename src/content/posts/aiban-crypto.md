---
title: banai-crypto
published: 1145-01-14
description: "记录一些本人实际操作过程中ai没法想/难想出来的题目或者知识点"
tags: ["CTF","banai"]
draft: false







---

## 

## HGAME2026----**babyRSA** 

### 题目特点（rsa，特点是m>n , 提示用LLL后gpt直出)

这题的“坑点”不在分解 n（你甚至已经拿到了 p,q），而在于**明文 m 比模数 n 大**：

加密做的是： c ≡ m^e (mod n)

解密只能得到： r = c^d mod n = m mod n

真正的明文满足 m = r + t * n，但 t 的范围巨大，不能爆破。

### 关键数据特征（为什么 LLL 能做）

**flag 结构强：** m = "VIDAR{" + u_0 u_1 ... u_{k-1} + "}"

其中 k ∈ [30,40]，每个 u_i 来自 64 个字符集（digits + letters + `_` + `@`），对应 ASCII 值大约在 [48, 122] 之间，系数很小。

### 写成“模 n 的线性同余”（这是 LLL 入口）

设总长度 L = k + 7。把字节按大端展开，未知段满足： Σ (u_i * 256^(k-i)) ≡ R (mod n)

其中常数项 R 为： R ≡ r - bytes_to_long("VIDAR{") * 256^(k+1) - ord("}") (mod n)

令未知系数的基底为： a_i ≡ 256^(k-i) (mod n)

就得到了典型的“模 n 的小系数线性组合”： Σ (u_i * a_i) - R = t * n

### 为了让 LLL 更稳：把 u_i 平移到 0 附近

选一个中心值（比如 base = 85），令 u_i = v_i + base，则 v_i 大概在 [-40, 40] 的范围内： Σ (v_i * a_i) ≡ R - base * Σ a_i (mod n)

### LLL 格子怎么构造（核心）

构造维度为 k+2 的格，基向量（按“行”给出）：

- b_0 = (n, 0, 0, ..., 0, 0)
- b_{i+1} = (a_i, 0, ..., 1, ..., 0, 0)  [注：第 i+1 个位置是 1]
- b_{k+1} = (R', 0, 0, ..., 0, 1)  [注：embedding 向量，此处的 R' 即为上方平移后的常数项]

那么若存在解 (v_i, t)，其线性组合构成的向量： t*b_0 + Σ (v_i \* b_{i+1}) - 1*b_{k+1} = (0, v_0, ..., v_{k-1}, -1)

这个向量会非常短（因为 v_i 很小且最后一维固定为 ±1），LLL 算法很容易把它“吐出来”。最后把 u_i = v_i + base 还原成字节并校验字符集，再加上 RSA 复验即可。



## HGAME2026----**ezCurve**

###  题目特点（椭圆曲线，不进行任何提示ai会往**Coppersmith** 想，实际操作时多次未出，提示是椭圆曲线上的HNP问题后gemini直出）

HNP参考文章https://hasegawaazusa.github.io/hidden-number-problem.html

或者本地保存的





## 感觉挺有用的一些提示词

`分析数据特点`

`联网搜索一下`