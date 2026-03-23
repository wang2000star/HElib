# 比特数组 BGV 加密模板 (BGV Bit-Array Encryption Templates)

本目录提供四种对比特数组进行 BGV 同态加密的完整模板代码，涵盖从逐比特加密到
基于 GF(2^d) 有限域的 SIMD 打包加密。注释使用中英文结合。

This directory provides four complete BGV homomorphic encryption templates for
bit arrays, from per-bit encryption to GF(2^d) SIMD packed encryption.
Comments are in Chinese and English.

---

## 参数背景 (Parameter Background)

| 符号 | 含义 |
|------|------|
| `m`  | 分圆多项式指数（Cyclotomic index），phi(m) 为其 Euler 函数值 |
| `p`  | 明文模数（Plaintext modulus），本方案使用 `p=2`（GF(2) 比特运算）|
| `d`  | `ord_p(m)`：p 对 m 的乘法阶（p=2 时即 `ord_2(m)`）|
| `L`  | SIMD 槽数：`L = phi(m)/d`（每个槽是 GF(p^d) 的元素）|
| `r`  | Hensel 提升参数（BGV 默认 `r=1`）|
| `bits` | 模链比特数（越大支持越深的同态计算）|

满足关系：`2^d ≡ 1 (mod m)`（2 与 m 互素，d = ord_2(m)）

---

## 密钥类型 (Key Types)

| 密钥 | 说明 | 生成方式 |
|------|------|---------|
| 加解密密钥（SecKey/PubKey） | 必须；加密和解密 | `secret_key.GenSecKey()` |
| 重线性化密钥（Relinearization Key） | 乘法后降次所需；由 GenSecKey 隐含生成 | 自动 |
| 自举密钥（Bootstrapping Key） | 可选；用于降低密文噪声恢复计算深度 | `secret_key.genRecryptData()` |
| 旋转/伽罗瓦密钥（Rotation/Galois Key） | 可选；SIMD 槽间数据移动（旋转、移位）| `helib::addSome1DMatrices(sk)` 或 `helib::addAllMatrices(sk)` |

---

## 四种加密方案 (Four Encryption Methods)

### 方案一：逐比特加密 (`method1_per_bit.cpp`)

**描述**：对比特数组 `a[0..h-1]` 中的每个比特 `a_i` 单独加密成一个 BGV 密文。

**填充模式**：
- **模式 A（零填充）**：槽向量 `[a_i, 0, 0, ..., 0]`，仅第 0 槽存 `a_i`
- **模式 B（重复填充）**：槽向量 `[a_i, a_i, ..., a_i]`，所有 `nslots` 个槽均为 `a_i`

**适用场景**：
- 直接进行二进制算术运算（使用 `helib/binaryArith.h`）
- 每个比特需要独立操作

**密钥需求**：加解密密钥；自举密钥可选；无需旋转密钥

```
密文数量: h 个密文（每个比特一个）
每个密文: nslots = phi(m)/d 个槽
```

---

### 方案二：非 SIMD 打包加密 (`method2_nonsimd_packed.cpp`)

**描述**：将 `h` 个比特打包到一个 BGV 密文中，使用多项式系数空间（非 SIMD 槽结构）。
明文空间为 `Z_2[X] / Phi_m(X)`，有 `phi(m)` 个系数，每系数存一个比特。

**填充模式**：
- **模式 A（零填充）**：前 `h` 个系数为 `a[0..h-1]`，其余系数为 0；要求 `h ≤ phi(m)`
- **模式 B（重复填充）**：循环重复 `phi(m)/h` 次；要求 `h | phi(m)`

**实现方式**：直接使用 `NTL::ZZX` 多项式设置系数，调用 `public_key.Encrypt(ctxt, poly)` 加密

**密钥需求**：加解密密钥；自举密钥可选；无需旋转密钥

```
密文数量: 1 个密文
每个密文: phi(m) 个多项式系数 = phi(m) 个比特
```

---

### 方案三：SIMD 打包加密 (`method3_simd_packed.cpp`)

**描述**：利用 BGV 的 SIMD 结构，将 `h` 个比特（`h ≤ L`）分放入 `L` 个槽中打包加密。
每个槽是 `GF(2^d)` 的一个元素，但在 `d=1` 时退化为单比特槽。

**填充模式**：
- **模式 A（零填充）**：前 `h` 个槽存比特，剩余槽为 0；要求 `h ≤ L`
- **模式 B（重复填充）**：循环重复 `L/h` 次；要求 `h | L`

**额外功能**：
- 生成旋转密钥后可执行 SIMD 旋转（`ea.rotate(ctxt, k)`）、移位（`ea.shift(ctxt, k)`）等操作

**密钥需求**：加解密密钥；自举密钥可选；旋转密钥可选（`addSome1DMatrices`）

```
密文数量: 1 个密文
每个密文: L = phi(m)/d 个槽，每槽存 1 个比特
```

---

### 方案四：GF(2^d) 有限域 SIMD 打包加密 (`method4_gf2d_simd.cpp`)

**描述**：当 `8 | d` 时，每个槽是 `GF(2^d)` 的元素。利用 `GF(2^8) ⊂ GF(2^d)` 的包含关系，
将 8 个比特（一个字节）嵌入为 `GF(2^d)` 中的多项式 `b_0 + b_1*X + ... + b_7*X^7`，
放入一个槽中，总共 `L` 个槽存放 `L` 个字节（`8L` 个比特）。

**要求**：`8 | d`（8 整除 d）；`num_bytes ≤ L`

**关于 AES**：
- AES 的 `GF(2^8)` 使用不可约多项式 `P(X) = X^8 + X^4 + X^3 + X + 1`（0x11B）
- HElib 使用 Phi_m 的不可约因子 `G(X)`（度数为 `d`），不一定与 AES 多项式相同
- 字节的嵌入方式（系数表示）在 `d ≥ 8` 时是通用的，不受 `G` 影响
- 若需精确的 AES 域乘法，需要将 AES 运算映射到 HElib 的 `GF(2^d)` 结构

**同态操作**：
- 槽加法 `ctxt += ctxt2` 对应 `GF(2^8)` 加法（= XOR）
- 槽乘法 `ctxt.multiplyBy(ctxt2)` 对应 `GF(2^d)` 乘法

**密钥需求**：加解密密钥；自举密钥可选；旋转密钥可选

```
密文数量: 1 个密文
每个密文: L = phi(m)/d 个槽，每槽存 1 个字节（8 比特）
总容量: L * 8 个比特
```

---

## 方案对比表 (Comparison Table)

| 特性 | 方案一 | 方案二 | 方案三 | 方案四 |
|------|--------|--------|--------|--------|
| 密文数量 | `h` 个 | 1 个 | 1 个 | 1 个 |
| 每密文容量 | 1 比特 | `phi(m)` 比特 | `L` 比特 | `L*8` 比特 |
| SIMD 并行 | 否 | 否 | 是 | 是 |
| 需要旋转密钥 | 否 | 否 | 可选 | 可选 |
| 条件 | — | `h ≤ phi(m)` | `h ≤ L` | `8|d`, `num_bytes ≤ L` |
| 明文空间 | `GF(2)` 槽 | 系数空间 | `GF(2^d)` 槽 | `GF(2^d)` 槽 |

---

## 编译方法 (Building)

```bash
# 在 HElib 根目录下
mkdir build && cd build
cmake -Dhelib_DIR=<installed-helib>/share/cmake/helib ../examples/BGV_bit_encryption
# 或者在 examples/ 目录下（已包含 add_subdirectory）
cmake ..
make method1_per_bit method2_nonsimd_packed method3_simd_packed method4_gf2d_simd
```

---

## 参数选择建议 (Parameter Selection Guide)

```cpp
// 方案一/二/三示例参数（p=2, GF(2) SIMD）
// m=4369 = 17*257, phi(m)=4096, d=ord_2(4369)=16, L=256 slots
long m = 4369, p = 2, r = 1, bits = 300, c = 2;

// 方案四示例参数（8|d 要求）
// m=4369: d=16, 8|16 ✓, L=256 slots; 每个密文存 256 个字节
long m = 4369; // d=16, L=256, 可存 256 字节

// 较小测试参数
// m=17: phi(17)=16, d=ord_2(17)=8, L=2 slots（仅用于快速测试）
long m = 17; // d=8, L=2, 仅适用于小规模测试

// 查询参数
long d = context.getOrdP();  // ord_2(m)
long L = context.getNSlots(); // phi(m)/d
long phiM = context.getPhiM(); // phi(m)
```

---

## 参考资料 (References)

- [HElib GitHub](https://github.com/homenc/HElib)
- [HElib Design Document](https://eprint.iacr.org/2012/099)
- [BGV Binary Arithmetic Example](../BGV_binary_arithmetic/BGV_binary_arithmetic.cpp)
- [BGV Packed Arithmetic Example](../BGV_packed_arithmetic/BGV_packed_arithmetic.cpp)
