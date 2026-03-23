/* Copyright (C) 2019-2021 IBM Corp.
 * This program is Licensed under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *   http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License. See accompanying LICENSE file.
 */

/**
 * @file method4_gf2d_simd.cpp
 * @brief 方案四：基于 GF(2^d) 有限域的 SIMD 打包加密
 *        (GF(2^d) Finite Field SIMD Packed BGV Encryption)
 *
 * 功能说明：
 *   当 8 整除 d（其中 d = ord_2(m)）时，每个 SIMD 槽是 GF(2^d) 的一个元素。
 *   由于 GF(2^8) ⊂ GF(2^d)（域扩张包含关系），可以将 8 个比特嵌入到一个槽中，
 *   表示为 GF(2^8) 的一个元素，再放入 GF(2^d) 槽中进行 SIMD 打包加密。
 *
 *   在 HElib 中，每个槽是 GF(2^d) = GF(2)[X]/G(X)，其中 G 是 Phi_m(X) 在
 *   GF(2) 上的一个不可约因式，度数为 d。
 *   将 8 位字节值 b 嵌入槽中：将 b 的 8 个比特作为多项式的系数：
 *     b = b_0 + b_1*X + b_2*X^2 + ... + b_7*X^7 (in GF(2^d), d>=8)
 *
 *   关于 AES 的 GF(2^8) 模多项式：
 *     AES 使用的不可约多项式为 P(X) = X^8 + X^4 + X^3 + X + 1（十六进制 0x11B）。
 *     但 HElib 的槽使用自身选取的不可约多项式 G（Phi_m 的因子），不一定与 AES 相同。
 *     若需要精确的 AES 域运算，需要将 AES 的域运算映射到 HElib 的域结构（本模板
 *     仅演示嵌入方法，不执行 AES 的域乘法）。
 *
 * 参数要求：
 *   - p = 2（GF(2) 基础域）
 *   - d = ord_2(m) 必须能被 8 整除（8 | d）
 *   - L = phi(m)/d 个 SIMD 槽，每槽容纳 8 位字节值
 *
 * 密钥选项：
 *   - 加解密密钥（SecKey/PubKey）：必须生成
 *   - 重线性化密钥（Relinearization Key）：GenSecKey 隐含生成
 *   - 自举密钥（Bootstrapping Key）：可选
 *   - 旋转密钥（Galois/Rotation Key）：可选；用于 SIMD 槽间数据移动
 *
 * Method 4: GF(2^d) SIMD packed encryption.
 *   Requires 8 | d where d = ord_2(m).
 *   Each slot is GF(2^d); embed 8-bit bytes into slots via GF(2^8) ⊂ GF(2^d).
 *   An 8-bit byte b is encoded as a polynomial: b_0 + b_1*X + ... + b_7*X^7.
 *   Note on AES: AES GF(2^8) uses P(X) = X^8+X^4+X^3+X+1 (0x11B), but
 *   HElib uses its own G polynomial; direct AES field arithmetic requires
 *   additional mapping (not shown here).
 */

#include <iostream>
#include <vector>
#include <cstdint>

#include <NTL/ZZX.h>
#include <helib/helib.h>

int main(int argc, char* argv[])
{
  std::cout << "===================================================\n";
  std::cout << "  方案四：GF(2^d) 有限域 SIMD 打包加密\n";
  std::cout << "  (GF(2^d) SIMD Packed BGV Encryption)\n";
  std::cout << "===================================================\n\n";

  // -----------------------------------------------------------------------
  // 1. 参数设置 (Parameter Setup)
  // -----------------------------------------------------------------------

  // 明文模数 p=2（GF(2) 上的运算）
  long p = 2;

  // 选择 m 使得 d = ord_2(m) 能被 8 整除
  // Choose m such that d = ord_2(m) is divisible by 8
  //
  // m=4369 = 17 * 257:
  //   phi(4369) = phi(17)*phi(257) = 16*256 = 4096
  //   ord_2(17)  = 8  (因为 2^8=256≡1 mod 17)
  //   ord_2(257) = 16 (因为 2^8=256≡-1 mod 257, 2^16≡1 mod 257)
  //   ord_2(4369) = lcm(8,16) = 16
  //   d=16, 8|16 ✓, L=4096/16=256 槽
  long m = 4369;

  long r    = 1;    // Hensel 提升参数
  long bits = 300;  // 模链比特数
  long c    = 2;    // 密钥切换矩阵列数

  // 是否启用自举
  bool enable_bootstrapping = false;

  // 是否生成旋转密钥
  bool enable_rotation_keys = true;

  // 待加密的字节数组（每个元素是 8 位，取值 0-255）
  // Byte array to encrypt (each element is an 8-bit value, 0-255)
  // 此示例使用 16 个字节（可对应 AES 的一个 128 位块）
  // 16 bytes = one AES 128-bit block
  std::vector<uint8_t> bytes_array = {
    0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89,
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
  };
  long num_bytes = static_cast<long>(bytes_array.size());

  // -----------------------------------------------------------------------
  // 2. 初始化上下文 (Context Initialization)
  // -----------------------------------------------------------------------
  std::cout << "正在初始化 BGV 上下文... (Initializing BGV context...)\n";

  helib::ContextBuilder<helib::BGV> cb;
  cb.m(m).p(p).r(r).bits(bits).c(c);

  if (enable_bootstrapping) {
    std::vector<long> mvec = {7, 5, 9, 13};
    std::vector<long> gens = {2341, 3277, 911};
    std::vector<long> ords = {6, 4, 6};
    cb.bootstrappable(true).mvec(mvec).gens(gens).ords(ords);
    std::cout << "已启用自举（bootstrapping enabled）\n";
  }

  helib::Context context = cb.build();
  context.printout();

  long phiM = context.getPhiM();  // phi(m)
  long d    = context.getOrdP();  // d = ord_2(m)，每个槽是 GF(2^d)
  long L    = context.getNSlots(); // L = phi(m)/d，SIMD 槽数

  std::cout << "\nphi(m)=" << phiM
            << "  d=ord_2(m)=" << d << " (每槽 GF(2^" << d << ") 的度数)"
            << "  L=phi(m)/d=" << L << " (SIMD 槽数)\n";
  std::cout << "安全级别: " << context.securityLevel() << "\n\n";

  // 验证 8 | d
  if (d % 8 != 0) {
    std::cerr << "错误：d=" << d << " 不能被 8 整除！"
              << "方案四要求 8 | d 以嵌入 GF(2^8) 元素。\n"
              << "请选择合适的 m（如 m=4369, d=16）。\n";
    return 1;
  }
  std::cout << "满足条件：8 | d=" << d << " ✓（可嵌入 GF(2^8) 到 GF(2^" << d << ")）\n\n";

  if (num_bytes > L) {
    std::cerr << "错误：字节数 " << num_bytes << " 超过槽数 L=" << L << "\n";
    return 1;
  }

  // -----------------------------------------------------------------------
  // 3. 密钥生成 (Key Generation)
  // -----------------------------------------------------------------------
  std::cout << "正在生成密钥... (Generating keys...)\n";

  helib::SecKey secret_key(context);
  secret_key.GenSecKey();
  std::cout << "  - 加解密密钥 已生成\n";
  std::cout << "  - 重线性化密钥 已隐含生成\n";

  if (enable_bootstrapping) {
    secret_key.genRecryptData();
    std::cout << "  - 自举密钥 已生成\n";
  }

  if (enable_rotation_keys) {
    // 生成旋转密钥，用于 SIMD 槽间操作
    helib::addSome1DMatrices(secret_key);
    std::cout << "  - 旋转密钥 (Galois/Rotation keys) 已生成\n";
  } else {
    std::cout << "  - 旋转密钥 未生成\n";
  }

  const helib::PubKey& public_key = secret_key;
  const helib::EncryptedArray& ea = context.getEA();
  std::cout << "\n";

  // -----------------------------------------------------------------------
  // 4. 编码：将 8 位字节嵌入 GF(2^d) 槽
  //    Encoding: embed 8-bit bytes into GF(2^d) slots
  //
  //    表示方法：字节 b = b_0*2^0 + b_1*2^1 + ... + b_7*2^7
  //    嵌入为多项式：f(X) = b_0 + b_1*X + b_2*X^2 + ... + b_7*X^7
  //    放入 GF(2^d)[X] 中（系数在 GF(2) 上，度数 < 8 <= d）
  //
  //    Embedding: byte b = b_0 + b_1*X + ... + b_7*X^7 as element of GF(2^d)
  //    (the polynomial has degree < 8 <= d, so no reduction by G needed)
  //
  //    关于 AES 模多项式（参考）：
  //    AES uses GF(2^8) with P(X) = X^8 + X^4 + X^3 + X + 1 (0x11B).
  //    When 8|d, the embedding of GF(2^8) into GF(2^d) via the polynomial
  //    representation is natural: any polynomial of degree < 8 over GF(2)
  //    is also a valid element of GF(2^d) (modulo G which has degree d >= 8).
  // -----------------------------------------------------------------------
  std::cout << "---------------------------------------------------\n";
  std::cout << "  将 " << num_bytes << " 个字节嵌入 " << num_bytes
            << " 个 GF(2^" << d << ") 槽并加密\n";
  std::cout << "  Embedding " << num_bytes << " bytes into "
            << num_bytes << " GF(2^" << d << ") slots and encrypting\n";
  std::cout << "---------------------------------------------------\n";

  // 构建 Ptxt<BGV>，每个槽是一个 GF(2^d) 元素
  helib::Ptxt<helib::BGV> ptxt(context);

  for (long i = 0; i < num_bytes; ++i) {
    uint8_t b = bytes_array[i];

    // 将字节 b 转换为 GF(2) 系数多项式
    // Convert byte b to GF(2) coefficient polynomial: b = sum_{j=0}^{7} b_j * X^j
    NTL::ZZX byte_poly;
    byte_poly.SetLength(8);
    for (int bit = 0; bit < 8; ++bit) {
      NTL::SetCoeff(byte_poly, bit, (b >> bit) & 1);
    }

    // 将多项式设为第 i 个槽的值（PolyMod 会自动 mod G(X)，但度<8<=d 无需规约）
    // Set as the i-th slot value (PolyMod reduces mod G(X), but deg < 8 <= d)
    ptxt[i] = byte_poly;
  }
  // 剩余槽（i = num_bytes .. L-1）自动为 0（零填充）
  // Remaining slots (i >= num_bytes) are implicitly 0 (zero-padding)

  // 打印待加密的字节（十六进制）
  std::cout << "待加密字节（十六进制）:\n  ";
  for (long i = 0; i < num_bytes; ++i) {
    std::cout << std::hex << std::uppercase
              << "0x" << static_cast<int>(bytes_array[i]);
    if (i + 1 < num_bytes) std::cout << " ";
  }
  std::cout << std::dec << "\n\n";

  // 加密
  helib::Ctxt ctxt(public_key);
  public_key.Encrypt(ctxt, ptxt);
  std::cout << "加密完成！(Encryption done!)\n\n";

  // -----------------------------------------------------------------------
  // 5. 解密并提取字节
  //    Decrypt and extract bytes
  // -----------------------------------------------------------------------
  std::cout << "---------------------------------------------------\n";
  std::cout << "  解密验证 (Decryption Verification)\n";
  std::cout << "---------------------------------------------------\n";

  helib::Ptxt<helib::BGV> result(context);
  secret_key.Decrypt(result, ctxt);

  // 从 PolyMod 槽中恢复字节
  // Recover bytes from PolyMod slots
  std::cout << "解密字节（十六进制）:\n  ";
  bool all_ok = true;
  for (long i = 0; i < num_bytes; ++i) {
    // 将 PolyMod 转换为 NTL::ZZX 多项式
    // Cast PolyMod to NTL::ZZX polynomial
    NTL::ZZX slot_poly = static_cast<NTL::ZZX>(result[i]);

    // 从多项式系数恢复字节（低 8 位）
    // Recover byte from polynomial coefficients (low 8 bits)
    uint8_t recovered_byte = 0;
    for (int bit = 0; bit < 8; ++bit) {
      long coeff = NTL::to_long(NTL::coeff(slot_poly, bit));
      recovered_byte |= static_cast<uint8_t>((coeff & 1) << bit);
    }

    std::cout << std::hex << std::uppercase
              << "0x" << static_cast<int>(recovered_byte);
    if (i + 1 < num_bytes) std::cout << " ";

    if (recovered_byte != bytes_array[i]) all_ok = false;
  }
  std::cout << std::dec << "\n";
  std::cout << (all_ok ? "解密验证通过！✓\n" : "解密验证失败！✗\n");

  // -----------------------------------------------------------------------
  // 6. 演示：GF(2^d) 槽上的同态加法（对应 GF(2^8) 的 XOR）
  //    Demo: Homomorphic addition on GF(2^d) slots (= XOR on GF(2^8))
  //    在 GF(2) 上，加法等于 XOR；同态加法保持 GF(2^d) 的域结构
  // -----------------------------------------------------------------------
  std::cout << "\n---------------------------------------------------\n";
  std::cout << "  演示：同态 GF(2^d) 加法（= XOR over GF(2^8)）\n";
  std::cout << "  Demo: Homomorphic GF(2^d) addition (= XOR over GF(2^8))\n";
  std::cout << "---------------------------------------------------\n";

  // 构建另一个明文（用相同字节数组的位取反作为掩码）
  // Build another plaintext (byte-inverted version as mask)
  std::vector<uint8_t> mask_bytes = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
    0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01
  };

  helib::Ptxt<helib::BGV> ptxt_mask(context);
  for (long i = 0; i < num_bytes; ++i) {
    uint8_t b = mask_bytes[i];
    NTL::ZZX poly;
    poly.SetLength(8);
    for (int bit = 0; bit < 8; ++bit) {
      NTL::SetCoeff(poly, bit, (b >> bit) & 1);
    }
    ptxt_mask[i] = poly;
  }

  helib::Ctxt ctxt_mask(public_key);
  public_key.Encrypt(ctxt_mask, ptxt_mask);

  // 同态加法（GF(2^d) 加法 = XOR）
  // Homomorphic addition (= XOR in GF(2^d))
  helib::Ctxt ctxt_xor = ctxt;
  ctxt_xor += ctxt_mask;

  // 解密结果
  helib::Ptxt<helib::BGV> result_xor(context);
  secret_key.Decrypt(result_xor, ctxt_xor);

  std::cout << "XOR 结果（解密后，十六进制）:\n  ";
  bool xor_ok = true;
  for (long i = 0; i < num_bytes; ++i) {
    NTL::ZZX slot_poly = static_cast<NTL::ZZX>(result_xor[i]);
    uint8_t recovered_byte = 0;
    for (int bit = 0; bit < 8; ++bit) {
      long coeff = NTL::to_long(NTL::coeff(slot_poly, bit));
      recovered_byte |= static_cast<uint8_t>((coeff & 1) << bit);
    }
    uint8_t expected = bytes_array[i] ^ mask_bytes[i]; // 明文 XOR
    std::cout << std::hex << std::uppercase
              << "0x" << static_cast<int>(recovered_byte);
    if (i + 1 < num_bytes) std::cout << " ";
    if (recovered_byte != expected) xor_ok = false;
  }
  std::cout << std::dec << "\n";
  std::cout << (xor_ok ? "XOR 验证通过！✓\n" : "XOR 验证失败！✗\n");

  // -----------------------------------------------------------------------
  // 7. SIMD 旋转演示（若已生成旋转密钥）
  // -----------------------------------------------------------------------
  if (enable_rotation_keys) {
    std::cout << "\n---------------------------------------------------\n";
    std::cout << "  SIMD 旋转演示 (SIMD Rotation Demo)\n";
    std::cout << "---------------------------------------------------\n";

    helib::Ctxt ctxt_rot = ctxt;
    // 槽向量循环左旋 1 位
    ea.rotate(ctxt_rot, 1);

    helib::Ptxt<helib::BGV> result_rot(context);
    secret_key.Decrypt(result_rot, ctxt_rot);

    NTL::ZZX slot0_before = static_cast<NTL::ZZX>(result[0]);
    NTL::ZZX slot0_after  = static_cast<NTL::ZZX>(result_rot[0]);

    uint8_t byte0_before = 0, byte0_after = 0;
    for (int bit = 0; bit < 8; ++bit) {
      byte0_before |= static_cast<uint8_t>(
          (NTL::to_long(NTL::coeff(slot0_before, bit)) & 1) << bit);
      byte0_after  |= static_cast<uint8_t>(
          (NTL::to_long(NTL::coeff(slot0_after,  bit)) & 1) << bit);
    }

    std::cout << std::hex << std::uppercase;
    std::cout << "旋转前 槽[0]=0x" << static_cast<int>(byte0_before) << "\n";
    std::cout << "左旋1位后 槽[0]=0x" << static_cast<int>(byte0_after)
              << "（应等于原槽[1]=0x" << static_cast<int>(bytes_array[1]) << "）\n";
    std::cout << std::dec;
  }

  // -----------------------------------------------------------------------
  // 8. 自举演示（若已启用）
  // -----------------------------------------------------------------------
  if (enable_bootstrapping) {
    std::cout << "\n---------------------------------------------------\n";
    std::cout << "  自举演示 (Bootstrapping Demo)\n";
    std::cout << "---------------------------------------------------\n";
    std::cout << "自举前 noiseBound: " << ctxt.getNoiseBound() << "\n";
    public_key.reCrypt(ctxt);
    std::cout << "自举后 noiseBound: " << ctxt.getNoiseBound() << "\n";

    helib::Ptxt<helib::BGV> result_boot(context);
    secret_key.Decrypt(result_boot, ctxt);
    bool boot_ok = true;
    for (long i = 0; i < num_bytes; ++i) {
      NTL::ZZX slot_poly = static_cast<NTL::ZZX>(result_boot[i]);
      uint8_t recovered_byte = 0;
      for (int bit = 0; bit < 8; ++bit) {
        long coeff = NTL::to_long(NTL::coeff(slot_poly, bit));
        recovered_byte |= static_cast<uint8_t>((coeff & 1) << bit);
      }
      if (recovered_byte != bytes_array[i]) boot_ok = false;
    }
    std::cout << (boot_ok ? "自举后解密验证通过！✓\n" : "自举后解密验证失败！✗\n");
  }

  std::cout << "\n方案四完成。(Method 4 complete.)\n";
  return 0;
}
