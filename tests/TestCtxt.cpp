/* Copyright (C) 2020-2021 IBM Corp.
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

// This test file does not fully cover Ctxt, and is intended as a starting
// point for testing new functionality of Ctxt going forward.
// The older tests with more extensive coverage can be found in the files
// with names matching "GTest*".

#include <helib/helib.h>
#include <helib/debugging.h>

#include "test_common.h"
#include "gtest/gtest.h"

namespace {

struct BGVParameters
{
  BGVParameters(unsigned m,
                unsigned p,
                unsigned r,
                unsigned bits,
                const std::vector<long>& gens = {},
                const std::vector<long>& ords = {}) :
      m(m), p(p), r(r), bits(bits), gens(gens), ords(ords){};

  const unsigned m;
  const unsigned p;
  const unsigned r;
  const unsigned bits;
  const std::vector<long> gens;
  const std::vector<long> ords;

  friend std::ostream& operator<<(std::ostream& os, const BGVParameters& params)
  {
    return os << "{"
              << "m = " << params.m << ", "
              << "p = " << params.p << ", "
              << "r = " << params.r << ", "
              << "gens = " << helib::vecToStr(params.gens) << ", "
              << "ords = " << helib::vecToStr(params.ords) << ", "
              << "bits = " << params.bits << "}";
  }
};

class TestCtxt : public ::testing::TestWithParam<BGVParameters>
{
protected:
  const unsigned long m;
  const unsigned long p;
  const unsigned long r;
  const unsigned long bits;
  helib::Context context;
  helib::SecKey secretKey;
  helib::PubKey publicKey;
  const helib::EncryptedArray& ea;

  TestCtxt() :
      m(GetParam().m),
      p(GetParam().p),
      r(GetParam().r),
      bits(GetParam().bits),
      context(helib::ContextBuilder<helib::BGV>()
                  .m(m)
                  .p(p)
                  .r(r)
                  .bits(bits)
                  .build()),
      secretKey(context),
      publicKey((secretKey.GenSecKey(),
                 addFrbMatrices(secretKey),
                 addSome1DMatrices(secretKey),
                 secretKey)),
      ea(context.getEA())
  {}

  virtual void SetUp() override
  {
    helib::setupDebugGlobals(&secretKey, context.shareEA());
  };

  virtual void TearDown() override { helib::cleanupDebugGlobals(); }

  virtual ~TestCtxt() = default;
};

class TestCtxtWithBadDimensions : public TestCtxt
{
protected:
  TestCtxtWithBadDimensions() : TestCtxt()
  {
    for (long i = 0; i < context.getZMStar().numOfGens(); ++i) {
      if (!ea.nativeDimension(i)) {
        return;
      }
    }
    throw std::logic_error("Algebra provided does not have a bad dimension");
  }
};

TEST_P(TestCtxt, timesEqualsWithLongWorks)
{
  helib::Ptxt<helib::BGV> ptxt(context, std::vector<long>(ea.size(), 5));
  helib::Ctxt ctxt(publicKey);
  publicKey.Encrypt(ctxt, ptxt);
  ctxt *= 2l;

  helib::Ptxt<helib::BGV> expected_result(context,
                                          std::vector<long>(ea.size(), 10));
  helib::Ptxt<helib::BGV> decrypted_result(context);
  secretKey.Decrypt(decrypted_result, ctxt);

  EXPECT_EQ(decrypted_result, expected_result);
}

TEST_P(TestCtxt, timesEqualsWithEncodedPtxtWorks)
{
  helib::Ptxt<helib::BGV> ptxt(context, std::vector<long>(ea.size(), 5));
  helib::Ctxt ctxt(publicKey);
  publicKey.Encrypt(ctxt, ptxt);

  helib::PtxtArray pa(context, NTL::ZZX(2l));
  helib::EncodedPtxt eptxt; // Container for holding a polynomial i.e. NTL::ZZX
  pa.encode(eptxt);
  ctxt *= eptxt; // Same as the deprecated function ctxt *= NTL::ZZX(2l);

  helib::Ptxt<helib::BGV> expected_result(context,
                                          std::vector<long>(ea.size(), 10));
  helib::Ptxt<helib::BGV> decrypted_result(context);
  secretKey.Decrypt(decrypted_result, ctxt);

  EXPECT_EQ(decrypted_result, expected_result);
}

TEST_P(TestCtxt, mapTo01WorksCorrectlyForConstantInputs)
{
  std::vector<long> data(ea.size());
  std::iota(data.begin(), data.end(), 0);
  for (auto& num : data)
    num %= p;
  helib::Ptxt<helib::BGV> ptxt(context, data);
  helib::Ctxt ctxt(publicKey);
  publicKey.Encrypt(ctxt, ptxt);
  mapTo01(ea, ctxt);
  mapTo01(ea, ptxt);

  std::vector<long> expected(data);
  for (auto& num : expected)
    num = num ? 1 : 0;

  helib::Ptxt<helib::BGV> expected_result(context, expected);
  helib::Ptxt<helib::BGV> result(context);
  secretKey.Decrypt(result, ctxt);

  EXPECT_EQ(expected_result, ptxt);
  EXPECT_EQ(expected_result, result);
  EXPECT_EQ(ptxt, result);
}

TEST_P(TestCtxt, mapTo01WorksCorrectlyForNonConstantInputs)
{
  NTL::ZZX poly;
  NTL::SetCoeff(poly, 0, 1001);
  NTL::SetCoeff(poly, 1, 1001);

  helib::Ptxt<helib::BGV> ptxt(context, std::vector<NTL::ZZX>(ea.size(), poly));
  helib::Ctxt ctxt(publicKey);
  publicKey.Encrypt(ctxt, ptxt);
  mapTo01(ea, ctxt);
  mapTo01(ea, ptxt);

  helib::Ptxt<helib::BGV> expected_result(context,
                                          std::vector<long>(ea.size(), 1));
  helib::Ptxt<helib::BGV> result(context);
  secretKey.Decrypt(result, ctxt);

  EXPECT_EQ(expected_result, ptxt);
  EXPECT_EQ(expected_result, result);
  EXPECT_EQ(ptxt, result);
}

TEST_P(TestCtxtWithBadDimensions,
       frobeniusAutomorphWorksCorrectlyWithBadDimensions)
{
  std::vector<long> data(ea.size());
  std::iota(data.begin(), data.end(), 0);
  helib::Ptxt<helib::BGV> ptxt(context, data);
  helib::Ctxt ctxt(publicKey);
  publicKey.Encrypt(ctxt, ptxt);
  helib::Ptxt<helib::BGV> expected_result(ptxt);
  for (long i = 0; i <= ea.getDegree(); ++i) {
    ctxt.frobeniusAutomorph(i);
    for (long j = 0; j < i; ++j) {
      expected_result.power(p);
    }

    helib::Ptxt<helib::BGV> result(context);
    secretKey.Decrypt(result, ctxt);

    EXPECT_EQ(expected_result, result)
        << "Frobenius automorph failed with i=" << i << std::endl;
  }
}

TEST_P(TestCtxt, frobeniusAutomorphWorksCorrectly)
{
  std::vector<long> data(ea.size());
  std::iota(data.begin(), data.end(), 0);
  helib::Ptxt<helib::BGV> ptxt(context, data);
  helib::Ctxt ctxt(publicKey);
  publicKey.Encrypt(ctxt, ptxt);
  helib::Ptxt<helib::BGV> expected_result(ptxt);
  for (long i = 0; i <= ea.getDegree(); ++i) {
    ctxt.frobeniusAutomorph(i);
    for (long j = 0; j < i; ++j) {
      expected_result.power(p);
    }

    helib::Ptxt<helib::BGV> result(context);
    secretKey.Decrypt(result, ctxt);

    EXPECT_EQ(ptxt, result)
        << "Frobenius automorph failed with i=" << i << std::endl;
  }
}

TEST_P(TestCtxtWithBadDimensions, rotate1DRotatesCorrectlyWithBadDimensions)
{
  std::vector<long> data(ea.size());
  std::iota(data.begin(), data.end(), 0);
  helib::Ptxt<helib::BGV> ptxt(context, data);
  helib::Ctxt ctxt(publicKey);
  publicKey.Encrypt(ctxt, ptxt);

  for (long i = 0; i < context.getZMStar().numOfGens(); ++i) {
    helib::Ctxt tmp(ctxt);
    ea.rotate1D(tmp, i, 3);
    helib::Ptxt<helib::BGV> expected_result(ptxt);
    expected_result.rotate1D(i, 3);
    helib::Ptxt<helib::BGV> result(context);
    secretKey.Decrypt(result, tmp);

    EXPECT_EQ(expected_result, result);
  }
}

TEST_P(TestCtxt, mulAddWithDelayedRelinGivesSameResultAsTwoSeparateRelins)
{
  // Encrypt four distinct plaintext vectors: [1,2,...], [2,3,...], [3,4,...], [4,5,...]
  std::vector<long> data0(ea.size()), data1(ea.size()), data2(ea.size()),
      data3(ea.size());
  std::iota(data0.begin(), data0.end(), 1);
  std::iota(data1.begin(), data1.end(), 2);
  std::iota(data2.begin(), data2.end(), 3);
  std::iota(data3.begin(), data3.end(), 4);

  helib::Ptxt<helib::BGV> ptxt0(context, data0);
  helib::Ptxt<helib::BGV> ptxt1(context, data1);
  helib::Ptxt<helib::BGV> ptxt2(context, data2);
  helib::Ptxt<helib::BGV> ptxt3(context, data3);

  helib::Ctxt c0(publicKey), c1(publicKey), c2(publicKey), c3(publicKey);
  publicKey.Encrypt(c0, ptxt0);
  publicKey.Encrypt(c1, ptxt1);
  publicKey.Encrypt(c2, ptxt2);
  publicKey.Encrypt(c3, ptxt3);

  // Reference: relin(c0*c1) + relin(c2*c3) using two separate multiplications
  helib::Ctxt ref(c0);
  ref.multiplyBy(c1);
  helib::Ctxt ref_tmp(c2);
  ref_tmp.multiplyBy(c3);
  ref += ref_tmp;

  // Delayed-relin version: relin(c0*c1 + c2*c3) using one relinearization
  helib::Ctxt result = helib::mulAddWithDelayedRelin(c0, c1, c2, c3);

  // Both should decrypt to the same plaintext: ptxt0*ptxt1 + ptxt2*ptxt3
  helib::Ptxt<helib::BGV> decRef(context), decResult(context);
  secretKey.Decrypt(decRef, ref);
  secretKey.Decrypt(decResult, result);

  EXPECT_EQ(decRef, decResult)
      << "mulAddWithDelayedRelin should give the same plaintext result as "
         "two separate multiplications followed by addition";
}

TEST_P(TestCtxt, totalSumOfVectorGivesSameResultAsSequentialAddition)
{
  // Encrypt five distinct plaintext vectors and verify that totalSum gives
  // the same result as sequential += operations.
  const long nCtxts = 5;
  std::vector<helib::Ptxt<helib::BGV>> ptxts;
  std::vector<helib::Ctxt> ctxts;
  ptxts.reserve(nCtxts);
  ctxts.reserve(nCtxts);
  for (long k = 0; k < nCtxts; ++k) {
    std::vector<long> data(ea.size());
    std::iota(data.begin(), data.end(), k + 1);
    ptxts.emplace_back(context, data);
    ctxts.emplace_back(publicKey);
    publicKey.Encrypt(ctxts.back(), ptxts.back());
  }

  // Reference: sequential addition
  helib::Ctxt ref(ctxts[0]);
  for (long k = 1; k < nCtxts; ++k)
    ref += ctxts[k];

  // totalSum (void version)
  helib::Ctxt out(publicKey);
  helib::totalSum(out, ctxts);

  helib::Ptxt<helib::BGV> decRef(context), decOut(context);
  secretKey.Decrypt(decRef, ref);
  secretKey.Decrypt(decOut, out);

  EXPECT_EQ(decRef, decOut)
      << "totalSum (void) should give the same plaintext result as sequential "
         "addition";

  // totalSum (value-returning version)
  helib::Ctxt outVal = helib::totalSum(ctxts);
  helib::Ptxt<helib::BGV> decOutVal(context);
  secretKey.Decrypt(decOutVal, outVal);

  EXPECT_EQ(decRef, decOutVal)
      << "totalSum (value-returning) should give the same plaintext result as "
         "sequential addition";
}

TEST_P(TestCtxt, totalSumOfSingleCiphertextReturnsThatCiphertext)
{
  std::vector<long> data(ea.size());
  std::iota(data.begin(), data.end(), 1);
  helib::Ptxt<helib::BGV> ptxt(context, data);
  helib::Ctxt ctxt(publicKey);
  publicKey.Encrypt(ctxt, ptxt);

  helib::Ctxt out(publicKey);
  helib::totalSum(out, {ctxt});

  helib::Ptxt<helib::BGV> decOut(context);
  secretKey.Decrypt(decOut, out);

  EXPECT_EQ(ptxt, decOut)
      << "totalSum of a single ciphertext should decrypt to the original "
         "plaintext";
}

TEST_P(TestCtxt, totalSumOfEmptyVectorClearsCiphertext)
{
  std::vector<long> data(ea.size(), 42);
  helib::Ptxt<helib::BGV> ptxt(context, data);
  helib::Ctxt out(publicKey);
  publicKey.Encrypt(out, ptxt); // start with a non-empty ciphertext

  const std::vector<helib::Ctxt> empty;
  helib::totalSum(out, empty);

  EXPECT_TRUE(out.isEmpty())
      << "totalSum of an empty vector should clear the output ciphertext";
}

// Use this when thoroughly exploring an (m, p) grid of parameters.
// std::vector<BGVParameters> getParameters(bool good)
// {
//   std::vector<BGVParameters> parameterSets;
//
//   const long r = 1;
//   const long bits = 500;
//   const long min_p = 257;
//   const long max_p = 2003;
//   const long min_m = 100;
//   const long max_m = 3000;
//
//   std::vector<BGVParameters> params;
//   auto getParamFunc = good ? helib_test::getGoodDimensionParams
//                            : helib_test::getBadDimensionParams;
//   auto m_p_pairs = getParamFunc(min_m, max_m, min_p, max_p, 10, 10);
//   std::transform(m_p_pairs.begin(),
//                  m_p_pairs.end(),
//                  std::back_inserter(params),
//                  [](const auto& pair) {
//                    return BGVParameters(pair.first, pair.second, r, bits);
//                  });
//   return params;
// }

// INSTANTIATE_TEST_SUITE_P(variousParameters, TestCtxt,
// ::testing::ValuesIn(getParameters(true)));
// INSTANTIATE_TEST_SUITE_P(variousParameters, TestCtxtWithBadDimensions,
// ::testing::ValuesIn(getParameters(false)));

INSTANTIATE_TEST_SUITE_P(
    variousParameters,
    TestCtxt,
    ::testing::Values(BGVParameters(2049, 2, 1, 300),
                      BGVParameters(45, 1009, 1, 500),
                      BGVParameters(45, 317, 1, 500),
                      BGVParameters(45, 353, 1, 500),
                      BGVParameters(45, 367, 1, 500),
                      BGVParameters(45, 397, 1, 500),
                      BGVParameters(45, 419, 1, 500),
                      BGVParameters(45, 443, 1, 500),
                      BGVParameters(45, 971, 1, 500, {11}, {12}),
                      // This is here to test an algebra with 3 good dimensions
                      // BGVParameters(10005, 37, 1, 500),
                      BGVParameters(45, 19, 1, 300)));

INSTANTIATE_TEST_SUITE_P(variousParameters,
                         TestCtxtWithBadDimensions,
                         ::testing::Values(BGVParameters(45, 1009, 1, 500),
                                           BGVParameters(45, 349, 1, 300),
                                           BGVParameters(45, 379, 1, 300),
                                           BGVParameters(45, 499, 1, 300),
                                           BGVParameters(45, 619, 1, 300),
                                           BGVParameters(45, 709, 1, 300),
                                           BGVParameters(45, 769, 1, 300),
                                           BGVParameters(45, 829, 1, 300),
                                           BGVParameters(45, 919, 1, 300),
                                           BGVParameters(45, 19, 1, 300)));

} // namespace
