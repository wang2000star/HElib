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
 * @file method3_simd_packed.cpp
 * @brief 方案三：SIMD 打包加密（SIMD Packed BGV Encryption）
 *
 * 功能说明：
 *   利用 BGV 方案的 SIMD（单指令多数据）结构，将 L 个比特分别放入 L 个槽中打包加密。
 *
 *   参数背景：
 *     - d = ord_2(m)：2 对 m 的乘法阶（multiplicative order of 2 mod m）
 *     - 满足 2^d ≡ 1 (mod m)（即 p=2 时的槽分解条件）
 *     - L = phi(m)/d：SIMD 槽数（每个槽是 GF(2^d) 的一个元素）
 *
 *   提供两种填充方式（h 个比特，h <= L）：
 *     - 模式 A（零填充）：前 h 个槽存比特，剩余槽为 0。要求 h <= L。
 *     - 模式 B（重复填充）：将 h 个比特循环填满 L 个槽。要求 h 整除 L。
 *
 * 密钥选项：
 *   - 加解密密钥（SecKey/PubKey）：必须生成
 *   - 重线性化密钥（Relinearization Key）：GenSecKey 隐含生成
 *   - 自举密钥（Bootstrapping Key）：可选，通过 genRecryptData() 生成
 *   - 旋转密钥（Galois/Rotation Key）：可选；SIMD 旋转操作所需
 *     * addSome1DMatrices: 生成部分旋转密钥（高效，推荐）
 *     * addAllMatrices: 生成所有旋转密钥（更全面，内存开销大）
 *
 * Method 3: SIMD packed encryption.
 *   L = phi(m)/d bits packed into L slots (each slot is GF(2^d)).
 *   d = ord_2(m) = multiplicative order of 2 modulo m (2^d ≡ 1 mod m).
 *   Padding mode A: [a_0,...,a_{h-1}, 0,...,0]   (zero-pad, h <= L)
 *   Padding mode B: [a_0,...,a_{h-1}, a_0,...] (repeat-pad, h | L)
 */

#include <iostream>
#include <vector>

#include <helib/helib.h>

int main(int argc, char* argv[])
{
  std::cout << "===================================================\n";
  std::cout << "  方案三：SIMD 打包加密\n";
  std::cout << "  (SIMD Packed BGV Encryption)\n";
  std::cout << "===================================================\n\n";

  // -----------------------------------------------------------------------
  // 1. 参数设置 (Parameter Setup)
  // -----------------------------------------------------------------------

  // 明文模数 p=2（GF(2) 上的比特运算）
  long p = 2;

  // 分圆多项式指数 m
  // 需要满足 2^d ≡ 1 (mod m)，即 ord_2(m) = d，槽数 L = phi(m)/d
  // m=4369: phi(4369)=4096, d=ord_2(4369)=16, L=256 slots
  long m = 4369;

  long r    = 1;    // Hensel 提升参数
  long bits = 300;  // 模链比特数
  long c    = 2;    // 密钥切换矩阵列数

  // 是否启用自举
  bool enable_bootstrapping = false;

  // 是否生成旋转密钥（Galois/Rotation Keys）
  // Whether to generate rotation (Galois) keys for SIMD data movement
  bool enable_rotation_keys = true;

  // 待加密的比特数组（长度 h <= L）
  // Bit array to encrypt (h must be <= L for mode A, or h | L for mode B)
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
    // 自举参数（依赖 m 的具体值）
    std::vector<long> mvec = {7, 5, 9, 13};
    std::vector<long> gens = {2341, 3277, 911};
    std::vector<long> ords = {6, 4, 6};
    cb.bootstrappable(true).mvec(mvec).gens(gens).ords(ords);
    std::cout << "已启用自举（bootstrapping enabled）\n";
  }

  helib::Context context = cb.build();
  context.printout();

  long phiM = context.getPhiM(); // phi(m)
  long d    = context.getOrdP(); // d = ord_2(m)（每槽 GF(2^d) 的度数）
  long L    = context.getNSlots(); // L = phi(m)/d（SIMD 槽数）

  std::cout << "\nphi(m)=" << phiM
            << "  d=ord_2(m)=" << d
            << "  L=phi(m)/d=" << L << " (SIMD 槽数)\n";
  std::cout << "安全级别: " << context.securityLevel() << "\n\n";

  // 验证参数合法性
  if (h > L) {
    std::cerr << "错误：h=" << h << " 超过槽数 L=" << L
              << "，无法进行 SIMD 打包加密！\n";
    return 1;
  }
  if (L % h != 0) {
    std::cout << "警告：L=" << L << " 不能被 h=" << h
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

  if (enable_rotation_keys) {
    // 生成旋转（Galois）密钥，用于 SIMD 槽间数据移动（旋转、移位等）
    // Generate rotation (Galois) keys for SIMD data movement (rotate, shift)
    //
    // addSome1DMatrices：生成"婴儿步-巨人步"策略所需的部分旋转密钥（推荐）
    // addSome1DMatrices: generates rotation keys for baby-step/giant-step strategy
    helib::addSome1DMatrices(secret_key);
    std::cout << "  - 旋转密钥 (Galois/Rotation keys) 已生成 (addSome1DMatrices)\n";

    // 若需要所有旋转密钥（内存开销更大）：
    // For ALL rotation keys (higher memory cost):
    // helib::addAllMatrices(secret_key);
  } else {
    std::cout << "  - 旋转密钥 未生成（SIMD 旋转操作不可用）\n";
  }

  const helib::PubKey& public_key = secret_key;
  const helib::EncryptedArray& ea = context.getEA();
  std::cout << "\n";

  // -----------------------------------------------------------------------
  // 4. 模式 A：零填充 SIMD 加密
  //    Mode A: Zero-padding SIMD encryption
  //    槽向量: [a_0, a_1, ..., a_{h-1}, 0, 0, ..., 0]（共 L 个槽）
  // -----------------------------------------------------------------------
  std::cout << "---------------------------------------------------\n";
  std::cout << "  模式 A（零填充）: [a_0,...,a_{h-1}, 0,...,0]（共 L="
            << L << " 槽）\n";
  std::cout << "  Mode A (zero-padding): [bits..., 0,...,0] (L=" << L << " slots)\n";
  std::cout << "---------------------------------------------------\n";

  // 构建槽向量：前 h 个槽为比特值，其余为 0
  // Build slot vector: first h slots = bits, rest = 0
  std::vector<long> slots_A(L, 0L);
  for (long i = 0; i < h; ++i) {
    slots_A[i] = bits_array[i];
  }

  // 使用 Ptxt<BGV> 进行 SIMD 编码并加密
  // Construct Ptxt<BGV> from slot vector, then encrypt
  helib::Ptxt<helib::BGV> ptxt_A(context, slots_A);

  helib::Ctxt ctxt_A(public_key);
  public_key.Encrypt(ctxt_A, ptxt_A);

  std::cout << "模式 A 加密完成，槽向量（前 " << h << " 个）: [";
  for (long i = 0; i < h; ++i) {
    std::cout << slots_A[i];
    if (i + 1 < h) std::cout << ", ";
  }
  std::cout << ", 0, ...]\n\n";

  // -----------------------------------------------------------------------
  // 5. 模式 B：重复填充 SIMD 加密
  //    Mode B: Repeat-padding SIMD encryption
  //    槽向量: [a_0,...,a_{h-1}, a_0,...,a_{h-1}, ...] 重复 L/h 次
  //    要求：h 整除 L
  // -----------------------------------------------------------------------
  std::cout << "---------------------------------------------------\n";
  std::cout << "  模式 B（重复填充）: 将 h=" << h << " 个比特重复填满 L="
            << L << " 个槽\n";
  std::cout << "  Mode B (repeat-padding): h bits repeated L/h times\n";
  std::cout << "  条件：h | L，即 " << L << " % " << h << " = "
            << (L % h) << "\n";
  std::cout << "---------------------------------------------------\n";

  helib::Ctxt ctxt_B(public_key);

  if (L % h == 0) {
    long repeat = L / h;

    std::vector<long> slots_B(L, 0L);
    for (long rep = 0; rep < repeat; ++rep) {
      for (long i = 0; i < h; ++i) {
        slots_B[rep * h + i] = bits_array[i];
      }
    }

    helib::Ptxt<helib::BGV> ptxt_B(context, slots_B);

    public_key.Encrypt(ctxt_B, ptxt_B);
    std::cout << "模式 B 加密完成，重复 " << repeat << " 次，共 " << L << " 个槽\n\n";
  } else {
    std::cout << "模式 B 跳过：L=" << L << " 不能被 h=" << h << " 整除\n\n";
  }

  // -----------------------------------------------------------------------
  // 6. SIMD 旋转演示（若已生成旋转密钥）
  //    SIMD Rotation Demo (if rotation keys were generated)
  // -----------------------------------------------------------------------
  if (enable_rotation_keys) {
    std::cout << "---------------------------------------------------\n";
    std::cout << "  SIMD 旋转演示 (SIMD Rotation Demo)\n";
    std::cout << "---------------------------------------------------\n";

    helib::Ctxt ctxt_rotated = ctxt_A;

    // 将槽向量向左旋转 1 位（即槽[0]移到末尾，槽[1]移到槽[0]）
    // Rotate slots left by 1 (slot[0] moves to end, slot[1] -> slot[0])
    ea.rotate(ctxt_rotated, 1);

    helib::Ptxt<helib::BGV> result_rot(context);
    secret_key.Decrypt(result_rot, ctxt_rotated);

    long slot0_after = static_cast<long>(result_rot[0]);
    std::cout << "旋转前槽[0]=" << slots_A[0] << "，槽[1]=" << slots_A[1] << "\n";
    std::cout << "左旋 1 位后槽[0]=" << slot0_after
              << "（原槽[1]=" << slots_A[1] << "）\n\n";
  }

  // -----------------------------------------------------------------------
  // 7. 解密验证 (Decryption & Verification)
  // -----------------------------------------------------------------------
  std::cout << "---------------------------------------------------\n";
  std::cout << "  解密验证 (Decryption Verification)\n";
  std::cout << "---------------------------------------------------\n";

  // 解密模式 A
  helib::Ptxt<helib::BGV> result_A(context);
  secret_key.Decrypt(result_A, ctxt_A);

  std::cout << "模式 A 解密 - 前 " << h << " 个槽:\n  ";
  bool modeA_ok = true;
  for (long i = 0; i < h; ++i) {
    long val = static_cast<long>(result_A[i]);
    std::cout << val;
    if (i + 1 < h) std::cout << ", ";
    if (val != bits_array[i]) modeA_ok = false;
  }
  std::cout << "\n";
  std::cout << (modeA_ok ? "模式 A 验证通过！✓\n" : "模式 A 验证失败！✗\n");
  std::cout << "\n";

  // 解密模式 B（若已加密）
  if (L % h == 0) {
    helib::Ptxt<helib::BGV> result_B(context);
    secret_key.Decrypt(result_B, ctxt_B);

    std::cout << "模式 B 解密 - 前 " << h << " 个槽（第一轮）:\n  ";
    bool modeB_ok = true;
    for (long i = 0; i < h; ++i) {
      long val = static_cast<long>(result_B[i]);
      std::cout << val;
      if (i + 1 < h) std::cout << ", ";
      if (val != bits_array[i]) modeB_ok = false;
    }
    std::cout << "\n";
    if (L / h >= 2) {
      std::cout << "模式 B 解密 - 槽 " << h << " 到 " << (2*h-1)
                << "（第二轮）:\n  ";
      for (long i = 0; i < h; ++i) {
        long val = static_cast<long>(result_B[h + i]);
        std::cout << val;
        if (i + 1 < h) std::cout << ", ";
        if (val != bits_array[i]) modeB_ok = false;
      }
      std::cout << "\n";
    }
    std::cout << (modeB_ok ? "模式 B 验证通过！✓\n" : "模式 B 验证失败！✗\n");
  }

  // -----------------------------------------------------------------------
  // 8. 自举演示（若已启用）
  // -----------------------------------------------------------------------
  if (enable_bootstrapping) {
    std::cout << "\n---------------------------------------------------\n";
    std::cout << "  自举演示 (Bootstrapping Demo) - 对模式 A 密文执行自举\n";
    std::cout << "---------------------------------------------------\n";
    std::cout << "自举前 noiseBound: " << ctxt_A.getNoiseBound() << "\n";
    public_key.reCrypt(ctxt_A);
    std::cout << "自举后 noiseBound: " << ctxt_A.getNoiseBound() << "\n";

    helib::Ptxt<helib::BGV> result_boot(context);
    secret_key.Decrypt(result_boot, ctxt_A);
    bool boot_ok = true;
    for (long i = 0; i < h; ++i) {
      if (static_cast<long>(result_boot[i]) != bits_array[i]) boot_ok = false;
    }
    std::cout << (boot_ok ? "自举后解密验证通过！✓\n" : "自举后解密验证失败！✗\n");
  }

  std::cout << "\n方案三完成。(Method 3 complete.)\n";
  return 0;
}
