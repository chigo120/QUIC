#pragma once
#include "fec-codec.h"
#include "fec-vdm.h"
#include <cstring>
#include <unordered_map>

namespace ns3 {

/**
 * Vandermonde Reed-Solomon 抹除碼。
 *
 * 使用 Luigi Rizzo 的 fec.c（1997-98，BSD 授權）。
 * 矩陣採 Vandermonde 結構，與 cm256 的 Cauchy 矩陣不同，
 * 兩者都是 MDS 碼（任意 K of K+P 可還原），但數學基底有別。
 *
 * 限制：K + P ≤ 256（GF(2^8) 大小）。
 */
class VandermondeRsCodec : public FecCodec
{
public:
  std::string Name () const override
  {
    return "Vandermonde-RS-GF256 (Luigi Rizzo fec.c)";
  }

  bool Encode (uint32_t K, uint32_t P, uint32_t B,
               const std::vector<std::vector<uint8_t>>& src,
               std::vector<std::vector<uint8_t>>& repair) override
  {
    if (src.size () != K || K + P > 256) return false;

    uint32_t N = K + P;
    void *code = fec_new ((int)K, (int)N);
    if (!code) return false;

    // fec API 需要 non-const void* 指標陣列；複製一份 source 資料
    std::vector<std::vector<uint8_t>> srcCopy = src;
    std::vector<void *> srcPtrs (K);
    for (uint32_t i = 0; i < K; i++)
      srcPtrs[i] = srcCopy[i].data ();

    repair.resize (P);
    for (uint32_t p = 0; p < P; p++)
      {
        repair[p].resize (B, 0);
        fec_encode (code, srcPtrs.data (), repair[p].data (), (int)(K + p), (int)B);
      }

    fec_free (code);
    return true;
  }

  bool Decode (uint32_t K, uint32_t P, uint32_t B,
               std::vector<std::vector<uint8_t>>& data,
               std::vector<uint8_t>& indices) override
  {
    if (data.size () != K || indices.size () != K || K + P > 256) return false;

    uint32_t N = K + P;
    void *code = fec_new ((int)K, (int)N);
    if (!code) return false;

    // 把每個 symbol 複製進獨立的 flat buffer，讓 fec_decode shuffle 用
    std::vector<std::vector<uint8_t>> bufs (K, std::vector<uint8_t> (B));
    std::vector<void *> pkts (K);
    std::vector<int>    idx  (K);

    for (uint32_t i = 0; i < K; i++)
      {
        std::copy (data[i].begin (), data[i].end (), bufs[i].begin ());
        pkts[i] = bufs[i].data ();
        idx[i]  = (int)indices[i];
      }

    int ret = fec_decode (code, pkts.data (), idx.data (), (int)B);
    fec_free (code);
    if (ret != 0) return false;

    // fec_decode 後：pkts[i] 指向某個 bufs[j]，其內容為 source symbol i
    // 建立 pointer → buf 索引對映，再把結果寫回 data / indices
    std::unordered_map<void *, uint32_t> ptrMap;
    for (uint32_t i = 0; i < K; i++) ptrMap[bufs[i].data ()] = i;

    for (uint32_t i = 0; i < K; i++)
      {
        uint32_t bufIdx = ptrMap.at (pkts[i]);
        data[i]    = bufs[bufIdx];
        indices[i] = static_cast<uint8_t> (i); // 解碼後 position i = source i
      }

    return true;
  }
};

} // namespace ns3
