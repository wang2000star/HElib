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
 * @file method1_per_bit.cpp
 * @brief 方案一：逐比特加密（Per-Bit BGV Encryption）
 *
 * 功能说明：
 *   对比特数组 a[0..h-1] 中的每个比特 a_i，单独加密成一个 BGV 密文。
 *   提供两种槽填充（Padding）方式：
 *     - 模式 A（零填充）：明文槽向量为 [a_i, 0, 0, ..., 0]，仅第 0 槽存放 a_i。
 *     - 模式 B（重复填充）：明文槽向量为 [a_i, a_i, ..., a_i]，所有槽均复制 a_i。
 *
 * 密钥选项：
 *   - 加解密密钥（SecKey/PubKey）：必须生成
 *   - 重线性化密钥（Relinearization Key）：乘法后降次所需，由 GenSecKey 隐含生成
 *   - 自举密钥（Bootstrapping Key）：可选；通过 genRecryptData() 生成
 *
 * 注意：
 *   - p=2 表示基于 GF(2) 的 BGV 方案（比特运算）
 *   - 本示例中未生成旋转密钥（Galois/Rotation Key），因逐比特加密无需 SIMD 旋转
 *   - 参数仅用于演示，不代表生产级安全参数
 *
 * Method 1: Each bit a_i is encrypted into a separate BGV ciphertext.
 *   Padding mode A: [a_i, 0, 0, ..., 0]
 *   Padding mode B: [a_i, a_i, ..., a_i]
 */

#include <iostream>
#include <vector>

#include <helib/helib.h>

int main(int argc, char* argv[])
{
  std::cout << "===================================================\n";
  std::cout << "  方案一：逐比特加密 (Per-Bit BGV Encryption)\n";
  std::cout << "===================================================\n\n";

  // -----------------------------------------------------------------------
  // 1. 参数设置 (Parameter Setup)
  // -----------------------------------------------------------------------

  // 明文模数 p=2，基于 GF(2) 的 BGV 方案（比特运算）
  // Plaintext modulus p=2 (binary BGV scheme)
  long p = 2;

  // 分圆多项式指数 m，phi(m) 决定槽数上限
  // Cyclotomic index m; phi(m) determines the number of available slots
  long m = 4369; // phi(4369) = 4096, ord_2(4369) = 16, nslots = 256

  // Hensel 提升参数（BGV 默认为 1）
  // Hensel lifting parameter (default 1 for BGV)
  long r = 1;

  // 模链比特数（越大可支持越深的同态计算）
  // Number of bits in the modulus chain (more bits = deeper computation)
  long bits = 300;

  // 密钥切换矩阵列数（通常 2 或 3）
  // Number of columns in key-switching matrix (typically 2 or 3)
  long c = 2;

  // 是否启用自举（Bootstrapping）
  // Whether to enable bootstrapping
  bool enable_bootstrapping = false;

  // 待加密的比特数组（示例：8 个比特）
  // Bit array to encrypt (example: 8 bits)
  std::vector<long> bits_array = {1, 0, 1, 1, 0, 1, 0, 1};
  long h = static_cast<long>(bits_array.size());

  // -----------------------------------------------------------------------
  // 2. 初始化上下文 (Context Initialization)
  // -----------------------------------------------------------------------
  std::cout << "正在初始化 BGV 上下文... (Initializing BGV context...)\n";

  helib::ContextBuilder<helib::BGV> cb;
  cb.m(m).p(p).r(r).bits(bits).c(c);

  if (enable_bootstrapping) {
    // 自举需要指定 mvec（m 的因式分解）、gens 和 ords
    // Bootstrapping requires mvec (factorization of m), gens and ords
    // 下面参数仅适用于 m=4095；使用其他 m 时须相应调整
    // Below params are only valid for m=4095; adjust accordingly for other m
    std::vector<long> mvec = {7, 5, 9, 13};
    std::vector<long> gens = {2341, 3277, 911};
    std::vector<long> ords = {6, 4, 6};
    cb.bootstrappable(true).mvec(mvec).gens(gens).ords(ords);
    std::cout << "已启用自举（bootstrapping enabled）\n";
  }

  helib::Context context = cb.build();

  context.printout();
  std::cout << "\n安全级别 (Security level): "
            << context.securityLevel() << "\n";

  // 获取 EncryptedArray（包含槽信息）
  // Get EncryptedArray (contains slot information)
  const helib::EncryptedArray& ea = context.getEA();
  long nslots = ea.size(); // 槽总数 = phi(m)/d
  std::cout << "槽总数 nslots (= phi(m)/ord_p(m)): " << nslots << "\n";
  std::cout << "ord_2(m) = d: " << context.getOrdP() << "\n\n";

  // -----------------------------------------------------------------------
  // 3. 密钥生成 (Key Generation)
  // -----------------------------------------------------------------------
  std::cout << "正在生成密钥... (Generating keys...)\n";

  // 创建并生成私钥（同时隐含生成公钥和重线性化密钥）
  // Create and generate secret key (also implicitly creates public key
  // and relinearization key)
  helib::SecKey secret_key(context);
  secret_key.GenSecKey();
  std::cout << "  - 加解密密钥 (Enc/Dec key) 已生成\n";
  std::cout << "  - 重线性化密钥 (Relinearization key) 已隐含生成\n";

  if (enable_bootstrapping) {
    // 生成自举密钥（用于降低密文噪声、恢复计算深度）
    // Generate bootstrapping key (reduces noise, restores computation depth)
    secret_key.genRecryptData();
    std::cout << "  - 自举密钥 (Bootstrapping key) 已生成\n";
  }

  // 公钥引用（SecKey 是 PubKey 的子类）
  // Public key reference (SecKey is a subclass of PubKey)
  const helib::PubKey& public_key = secret_key;

  // 注意：本方案不需要旋转密钥（Galois key），因为不做 SIMD 旋转操作
  // Note: No rotation (Galois) keys needed since we don't perform SIMD rotations
  std::cout << "\n";

  // -----------------------------------------------------------------------
  // 4. 加密（两种填充模式）
  // Encryption with two padding modes
  // -----------------------------------------------------------------------
  std::cout << "---------------------------------------------------\n";
  std::cout << "  模式 A（零填充）: [a_i, 0, 0, ..., 0]\n";
  std::cout << "  Mode A (zero-padding): [a_i, 0, 0, ..., 0]\n";
  std::cout << "---------------------------------------------------\n";

  // 每个比特对应一个密文，共 h 个密文
  std::vector<helib::Ctxt> encrypted_A;
  encrypted_A.reserve(h);

  for (long i = 0; i < h; ++i) {
    // 构建槽向量：仅第 0 槽为 a_i，其余为 0
    // Build slot vector: only slot 0 = a_i, rest = 0
    std::vector<long> slot_vec(nslots, 0L);
    slot_vec[0] = bits_array[i];

    // 使用 Ptxt<BGV> 进行编码并加密
    // Construct Ptxt<BGV> from slot vector, then encrypt
    helib::Ptxt<helib::BGV> ptxt(context, slot_vec);

    helib::Ctxt ctxt(public_key);
    public_key.Encrypt(ctxt, ptxt);
    encrypted_A.push_back(std::move(ctxt));
  }
  std::cout << "已加密 " << h << " 个比特（模式 A），每个密文槽向量为"
            << " [a_i, 0, ..., 0]\n\n";

  std::cout << "---------------------------------------------------\n";
  std::cout << "  模式 B（重复填充）: [a_i, a_i, ..., a_i]\n";
  std::cout << "  Mode B (replication): [a_i, a_i, ..., a_i]\n";
  std::cout << "---------------------------------------------------\n";

  std::vector<helib::Ctxt> encrypted_B;
  encrypted_B.reserve(h);

  for (long i = 0; i < h; ++i) {
    // 构建槽向量：所有槽均为 a_i
    // Build slot vector: all slots = a_i
    std::vector<long> slot_vec(nslots, bits_array[i]);

    helib::Ptxt<helib::BGV> ptxt(context, slot_vec);

    helib::Ctxt ctxt(public_key);
    public_key.Encrypt(ctxt, ptxt);
    encrypted_B.push_back(std::move(ctxt));
  }
  std::cout << "已加密 " << h << " 个比特（模式 B），每个密文槽向量为"
            << " [a_i, ..., a_i]\n\n";

  // -----------------------------------------------------------------------
  // 5. 解密验证 (Decryption & Verification)
  // -----------------------------------------------------------------------
  std::cout << "---------------------------------------------------\n";
  std::cout << "  解密验证 (Decryption Verification)\n";
  std::cout << "---------------------------------------------------\n";

  bool all_correct = true;

  for (long i = 0; i < h; ++i) {
    helib::Ptxt<helib::BGV> result_A(context);
    secret_key.Decrypt(result_A, encrypted_A[i]);

    // 提取第 0 槽的比特值（模式 A：仅槽[0]为 a_i）
    // Extract bit from slot 0 (Mode A: only slot[0] = a_i)
    long decrypted_bit_A = static_cast<long>(result_A[0]);

    if (decrypted_bit_A != bits_array[i]) {
      std::cerr << "[模式A] 比特 " << i << " 解密错误！期望 "
                << bits_array[i] << " 实际 " << decrypted_bit_A << "\n";
      all_correct = false;
    }

    helib::Ptxt<helib::BGV> result_B(context);
    secret_key.Decrypt(result_B, encrypted_B[i]);

    // 模式 B 中所有槽应相同，取槽[0]验证
    // Mode B: all slots should be the same; check slot[0]
    long decrypted_bit_B = static_cast<long>(result_B[0]);

    if (decrypted_bit_B != bits_array[i]) {
      std::cerr << "[模式B] 比特 " << i << " 解密错误！期望 "
                << bits_array[i] << " 实际 " << decrypted_bit_B << "\n";
      all_correct = false;
    }
  }

  if (all_correct) {
    std::cout << "所有比特解密验证通过！(All bits decrypted correctly!)\n";
  }

  // -----------------------------------------------------------------------
  // 6. 自举演示（若已启用）
  // Bootstrapping demo (if enabled)
  // -----------------------------------------------------------------------
  if (enable_bootstrapping) {
    std::cout << "\n---------------------------------------------------\n";
    std::cout << "  自举演示 (Bootstrapping Demo)\n";
    std::cout << "---------------------------------------------------\n";
    std::cout << "对第 0 个比特密文（模式 B）执行自举以降低噪声...\n";
    std::cout << "Bootstrapping the first ciphertext (Mode B) to reduce noise...\n";

    // 自举前噪声级别
    std::cout << "自举前 noiseBound: " << encrypted_B[0].getNoiseBound() << "\n";

    // 执行自举（reCrypt）
    public_key.reCrypt(encrypted_B[0]);

    std::cout << "自举后 noiseBound: " << encrypted_B[0].getNoiseBound() << "\n";

    // 解密验证自举后结果
    helib::Ptxt<helib::BGV> result_boot(context);
    secret_key.Decrypt(result_boot, encrypted_B[0]);
    long dec_boot_bit = static_cast<long>(result_boot[0]);
    std::cout << "自举后解密第 0 槽: " << dec_boot_bit
              << "  (期望 " << bits_array[0] << ")\n";
  }

  std::cout << "\n方案一完成。(Method 1 complete.)\n";
  return 0;
}
