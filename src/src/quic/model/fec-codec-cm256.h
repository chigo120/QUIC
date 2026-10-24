#pragma once
#include "fec-codec.h"
#include "cm256.h"

namespace ns3 {

/**
 * Cauchy MDS GF(256) 抹除碼，使用 cm256 函式庫
 * （Christopher A. Taylor, https://github.com/catid/cm256）。
 *
 * 數學性質：與 Reed-Solomon 相同的 MDS 特性，
 * 任意 K 個已收 symbol（source 或 repair 皆可）即可還原全部 K 個 source。
 * 矩陣採 Cauchy 矩陣而非 Vandermonde 矩陣，任意子矩陣保證可逆。
 */
class Cm256Codec : public FecCodec
{
  bool m_initialized = false;

  bool Init ()
  {
    if (m_initialized) return true;
    m_initialized = (cm256_init () == 0);
    return m_initialized;
  }

public:
  std::string Name () const override
  {
    return "Cauchy-MDS-GF256 (cm256)";
  }

  bool Encode (uint32_t K, uint32_t P, uint32_t B,
               const std::vector<std::vector<uint8_t>>& src,
               std::vector<std::vector<uint8_t>>& repair) override
  {
    if (!Init () || src.size () != K) return false;

    cm256_encoder_params params;
    params.OriginalCount = static_cast<int> (K);
    params.RecoveryCount = static_cast<int> (P);
    params.BlockBytes    = static_cast<int> (B);

    // cm256 API 需要 void* (non-const)；複製一份以符合介面
    std::vector<std::vector<uint8_t>> srcCopy = src;
    std::vector<cm256_block> originals (K);
    for (uint32_t i = 0; i < K; i++)
      {
        originals[i].Block = srcCopy[i].data ();
        originals[i].Index = static_cast<uint8_t> (i);
      }

    std::vector<uint8_t> repairBuf (P * B);
    if (cm256_encode (params, originals.data (), repairBuf.data ()) != 0)
      return false;

    repair.resize (P);
    for (uint32_t i = 0; i < P; i++)
      repair[i].assign (repairBuf.data () + i * B,
                        repairBuf.data () + (i + 1) * B);
    return true;
  }

  bool Decode (uint32_t K, uint32_t P, uint32_t B,
               std::vector<std::vector<uint8_t>>& data,
               std::vector<uint8_t>& indices) override
  {
    if (!Init () || data.size () != K || indices.size () != K) return false;

    cm256_encoder_params params;
    params.OriginalCount = static_cast<int> (K);
    params.RecoveryCount = static_cast<int> (P);
    params.BlockBytes    = static_cast<int> (B);

    std::vector<cm256_block> blocks (K);
    for (uint32_t i = 0; i < K; i++)
      {
        blocks[i].Block = data[i].data ();
        blocks[i].Index = indices[i];
      }

    if (cm256_decode (params, blocks.data ()) != 0) return false;

    // cm256_decode 將 repair 位置原地改寫為還原的 source 資料，並更新 Index
    for (uint32_t i = 0; i < K; i++)
      indices[i] = blocks[i].Index;

    return true;
  }
};

} // namespace ns3
