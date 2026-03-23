# Copyright (C) 2019-2021 IBM Corp.
# This program is Licensed under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance
# with the License. You may obtain a copy of the License at
#   http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License. See accompanying LICENSE file.

add_executable(method1_per_bit method1_per_bit.cpp)
target_link_libraries(method1_per_bit helib)

add_executable(method2_nonsimd_packed method2_nonsimd_packed.cpp)
target_link_libraries(method2_nonsimd_packed helib)

add_executable(method3_simd_packed method3_simd_packed.cpp)
target_link_libraries(method3_simd_packed helib)

add_executable(method4_gf2d_simd method4_gf2d_simd.cpp)
target_link_libraries(method4_gf2d_simd helib)
