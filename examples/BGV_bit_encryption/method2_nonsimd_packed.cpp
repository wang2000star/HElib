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
 * @file method2_nonsimd_packed.cpp
 * @brief 方案二：非 SIMD 打包加密（Non-SIMD Packed BGV Encryption）
 *
 * 功能说明：
 *   将 h 个比特打包到一个 BGV 密文中，使用多项式的系数表示（非 SIMD 槽结构）。
 *   在 BGV 方案中，明文空间为 Z_2[X] / Phi_m(X)，该多项式有 phi(m) 个系数，
 *   每个系数可以存储一个 GF(2) 元素（即一个比特）。
 *   因此，一个密文可以"非打包"地存储最多 phi(m) 个比特。
 *
 *   提供两种填充方式（h < phi(m)）：
 *     - 模式 A（零填充）：前 h 个系数为 a_0,...,a_{h-1}，其余系数为 0。
 *       要求：h < phi(m)
 *     - 模式 B（重复填充）：将 h 个比特循环重复填满 phi(m) 个系数。
 *       要求：h 整除 phi(m)
 *
 * 与方案三的区别：
 *   - 方案二（本文件）：使用 NTL::ZZX 多项式系数空间，共 phi(m) 个系数/比特
 *   - 方案三：使用 SIMD 槽结构，共 L = phi(m)/d 个槽，每槽存 1 个 GF(2) 元素
 *
 * 密钥选项：
 *   - 加解密密钥（SecKey/PubKey）：必须生成
 *   - 重线性化密钥（Relinearization Key）：乘法降次需要，GenSecKey 隐含生成
 *   - 自举密钥（Bootstrapping Key）：可选
 *   - 旋转密钥（Rotation/Galois Key）：本方案不需要
 *
 * Method 2: Non-SIMD packed encryption.
 *   h bits are packed into the polynomial coefficient space (Z_2[X]/Phi_m(X))
 *   of a single BGV ciphertext, with phi(m) coefficients total.
 *   Padding mode A: [a_0,...,a_{h-1}, 0,...,0]   (zero-pad, requires h < phi(m))
 *   Padding mode B: [a_0,...,a_{h-1}, a_0,...] (repeat-pad, requires h | phi(m))
 */

#include <iostream>
#include <vector>

#include <NTL/ZZX.h>
#include <helib/helib.h>

int main(int argc, char* argv[])
{
  std::cout << "===================================================\n";
  std::cout << "  方案二：非 SIMD 打包加密\n";
  std::cout << "  (Non-SIMD Packed BGV Encryption)\n";
  std::cout << "===================================================\n\n";

  // -----------------------------------------------------------------------
  // 1. 参数设置 (Parameter Setup)
  // -----------------------------------------------------------------------

  // 明文模数 p=2（GF(2) 上的比特运算）
  long p = 2;

  // 分圆多项式指数 m：phi(m) 决定多项式系数空间维度
  // m=4369: phi(4369)=4096, ord_2(4369)=16, nslots=256
  long m = 4369;

  // Hensel 提升参数
  long r = 1;

  // 模链比特数
  long bits = 300;

  // 密钥切换矩阵列数
  long c = 2;

  // 是否启用自举
  bool enable_bootstrapping = false;

  // 待加密的比特数组
  // Bit array to encrypt
  // 注意：h 必须 <= phi(m)（模式 A）或 h 整除 phi(m)（模式 B）
  // Note: h <= phi(m) for mode A, or h | phi(m) for mode B
  std::vector<long> bits_array = {1, 0, 1, 1, 0, 1, 0, 1,
                                   0, 1, 1, 0, 1, 0, 0, 1};
  long h = static_cast<long>(bits_array.size());

  // -----------------------------------------------------------------------
  // 2. 初始化上下文 (Context Initialization)
  // -----------------------------------------------------------------------
  std::cout << "正在初始化 BGV 上下文... (Initializing BGV context...)\n";

  helib::ContextBuilder<helib::BGV> cb;
  cb.m(m).p(p).r(r).bits(bits).c(c);

  if (enable_bootstrapping) {
    // 自举需要指定 mvec、gens 和 ords（依赖具体的 m 值）
    // Bootstrapping requires mvec, gens, ords (depend on specific m)
    std::vector<long> mvec = {7, 5, 9, 13};
    std::vector<long> gens = {2341, 3277, 911};
    std::vector<long> ords = {6, 4, 6};
    cb.bootstrappable(true).mvec(mvec).gens(gens).ords(ords);
    std::cout << "已启用自举（bootstrapping enabled）\n";
  }

  helib::Context context = cb.build();
  context.printout();

  long phiM = context.getPhiM(); // phi(m) = 多项式系数个数
  long d    = context.getOrdP(); // d = ord_2(m)
  long L    = context.getNSlots(); // L = phi(m)/d = 槽数

  std::cout << "\nphi(m)=" << phiM
            << "  d=ord_2(m)=" << d
            << "  L=phi(m)/d=" << L << "\n";
  std::cout << "安全级别: " << context.securityLevel() << "\n\n";

  // 验证参数合法性 (Validate parameters)
  if (h > phiM) {
    std::cerr << "错误：h=" << h << " 超过 phi(m)=" << phiM
              << "，无法进行非 SIMD 打包加密！\n";
    return 1;
  }
  if (phiM % h != 0) {
    std::cout << "警告：phi(m)=" << phiM << " 不能被 h=" << h
              << " 整除，模式 B（重复填充）将不可用。\n";
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

  // 本方案不需要旋转密钥（无 SIMD 旋转操作）
  // No rotation keys needed (no SIMD rotation)

  const helib::PubKey& public_key = secret_key;

  const helib::EncryptedArray& ea = context.getEA();
  std::cout << "\n";

  // -----------------------------------------------------------------------
  // 4. 模式 A：零填充加密
  //    Mode A: Zero-padding encryption
  //    明文多项式: a_0 + a_1*X + ... + a_{h-1}*X^{h-1} + 0*X^h + ...
  // -----------------------------------------------------------------------
  std::cout << "---------------------------------------------------\n";
  std::cout << "  模式 A（零填充）: phi(m) 个系数，前 h 个为比特，其余为 0\n";
  std::cout << "  Mode A (zero-padding): first h coefficients = bits, rest = 0\n";
  std::cout << "  条件：h < phi(m) = " << phiM << "\n";
  std::cout << "---------------------------------------------------\n";

  // 构造明文多项式（系数空间）
  // Build plaintext polynomial in coefficient space
  NTL::ZZX ptxt_poly_A;
  ptxt_poly_A.SetLength(h);
  for (long i = 0; i < h; ++i) {
    NTL::SetCoeff(ptxt_poly_A, i, bits_array[i]);
  }
  // 高次系数隐含为 0（零填充到 phi(m) 个系数）
  // Higher-degree coefficients are implicitly 0 (zero-padded)

  // 加密（使用 NTL::ZZX 直接加密，明文空间为 Z_2[X]/Phi_m(X)）
  // Encrypt using NTL::ZZX directly (plaintext in Z_2[X]/Phi_m(X))
  helib::Ctxt ctxt_A(public_key);
  public_key.Encrypt(ctxt_A, ptxt_poly_A);
  std::cout << "模式 A 加密完成，明文多项式系数（前 " << h << " 个）:\n  ";
  for (long i = 0; i < h; ++i) {
    std::cout << bits_array[i];
    if (i + 1 < h) std::cout << ", ";
  }
  std::cout << ", 0, 0, ... (共 " << phiM << " 个系数)\n\n";

  // -----------------------------------------------------------------------
  // 5. 模式 B：重复填充加密
  //    Mode B: Repeat-padding encryption
  //    明文多项式: [a_0,...,a_{h-1}, a_0,...,a_{h-1}, ...] 重复 phi(m)/h 次
  //    要求：h 整除 phi(m)
  // -----------------------------------------------------------------------
  std::cout << "---------------------------------------------------\n";
  std::cout << "  模式 B（重复填充）: 将 h 个比特循环重复至 phi(m) 个系数\n";
  std::cout << "  Mode B (repeat-padding): h bits repeated phi(m)/h times\n";
  std::cout << "  条件：h | phi(m)，即 " << phiM << " % " << h << " = "
            << (phiM % h) << "\n";
  std::cout << "---------------------------------------------------\n";

  helib::Ctxt ctxt_B(public_key);

  if (phiM % h == 0) {
    long repeat = phiM / h; // 重复次数

    NTL::ZZX ptxt_poly_B;
    ptxt_poly_B.SetLength(phiM);
    for (long rep = 0; rep < repeat; ++rep) {
      for (long i = 0; i < h; ++i) {
        NTL::SetCoeff(ptxt_poly_B, rep * h + i, bits_array[i]);
      }
    }

    public_key.Encrypt(ctxt_B, ptxt_poly_B);
    std::cout << "模式 B 加密完成，重复 " << repeat << " 次，共 "
              << phiM << " 个系数\n\n";
  } else {
    std::cout << "模式 B 跳过：phi(m)=" << phiM << " 不能被 h="
              << h << " 整除\n\n";
  }

  // -----------------------------------------------------------------------
  // 6. 解密验证 (Decryption & Verification)
  // -----------------------------------------------------------------------
  std::cout << "---------------------------------------------------\n";
  std::cout << "  解密验证 (Decryption Verification)\n";
  std::cout << "---------------------------------------------------\n";

  // 解密模式 A
  // Decrypt Mode A: recover ZZX polynomial
  NTL::ZZX decrypted_poly_A;
  secret_key.Decrypt(decrypted_poly_A, ctxt_A);

  std::cout << "模式 A 解密 - 前 " << h << " 个系数:\n  ";
  bool modeA_ok = true;
  for (long i = 0; i < h; ++i) {
    long coeff = NTL::to_long(NTL::coeff(decrypted_poly_A, i));
    std::cout << coeff;
    if (i + 1 < h) std::cout << ", ";
    if (coeff != bits_array[i]) modeA_ok = false;
  }
  std::cout << "\n";
  std::cout << (modeA_ok ? "模式 A 验证通过！✓\n" : "模式 A 验证失败！✗\n");
  std::cout << "\n";

  // 解密模式 B（若已加密）
  if (phiM % h == 0) {
    NTL::ZZX decrypted_poly_B;
    secret_key.Decrypt(decrypted_poly_B, ctxt_B);

    std::cout << "模式 B 解密 - 前 " << h << " 个系数（第一轮）:\n  ";
    bool modeB_ok = true;
    for (long i = 0; i < h; ++i) {
      long coeff = NTL::to_long(NTL::coeff(decrypted_poly_B, i));
      std::cout << coeff;
      if (i + 1 < h) std::cout << ", ";
      if (coeff != bits_array[i]) modeB_ok = false;
    }
    std::cout << "\n";
    // 验证第二轮（若 phi(m)/h >= 2）
    if (phiM / h >= 2) {
      std::cout << "模式 B 解密 - 第 " << h << " 到 " << (2*h-1)
                << " 个系数（第二轮）:\n  ";
      for (long i = 0; i < h; ++i) {
        long coeff = NTL::to_long(NTL::coeff(decrypted_poly_B, h + i));
        std::cout << coeff;
        if (i + 1 < h) std::cout << ", ";
        if (coeff != bits_array[i]) modeB_ok = false;
      }
      std::cout << "\n";
    }
    std::cout << (modeB_ok ? "模式 B 验证通过！✓\n" : "模式 B 验证失败！✗\n");
  }

  // -----------------------------------------------------------------------
  // 7. 自举演示（若已启用）
  // -----------------------------------------------------------------------
  if (enable_bootstrapping) {
    std::cout << "\n---------------------------------------------------\n";
    std::cout << "  自举演示 (Bootstrapping Demo) - 对模式 A 密文执行自举\n";
    std::cout << "---------------------------------------------------\n";
    std::cout << "自举前 noiseBound: " << ctxt_A.getNoiseBound() << "\n";
    public_key.reCrypt(ctxt_A);
    std::cout << "自举后 noiseBound: " << ctxt_A.getNoiseBound() << "\n";

    NTL::ZZX dec_boot;
    secret_key.Decrypt(dec_boot, ctxt_A);
    bool boot_ok = true;
    for (long i = 0; i < h; ++i) {
      if (NTL::to_long(NTL::coeff(dec_boot, i)) != bits_array[i])
        boot_ok = false;
    }
    std::cout << (boot_ok ? "自举后解密验证通过！✓\n" : "自举后解密验证失败！✗\n");
  }

  std::cout << "\n方案二完成。(Method 2 complete.)\n";
  return 0;
}
