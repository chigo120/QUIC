#pragma once
#include <vector>
#include <cstdint>
#include <string>

namespace ns3 {

/**
 * FEC 編解碼器抽象介面（Strategy Pattern）。
 *
 * 傳輸邏輯只依賴此介面，切換演算法只需換實作類別，
 * 不需動 quic-socket-base 的 encode/decode 路徑。
 *
 * 新增演算法步驟：
 *   1. 繼承 FecCodec 並實作 Encode / Decode / Name
 *   2. 在模擬腳本或 socket setup 呼叫 SetFecCodec(new YourCodec())
 */
class FecCodec
{
public:
  virtual ~FecCodec () = default;

  virtual std::string Name () const = 0;

  /**
   * 編碼：K 個 source symbol → P 個 repair symbol。
   *
   * @param K      source symbol 數量
   * @param P      repair symbol 數量
   * @param B      每個 symbol 的位元組數（所有 symbol 等長）
   * @param src    src[i] 為第 i 個 source symbol，長度恰為 B
   * @param repair 輸出：P 個 vector，每個長度 B
   * @return       成功回傳 true
   */
  virtual bool Encode (uint32_t K, uint32_t P, uint32_t B,
                       const std::vector<std::vector<uint8_t>>& src,
                       std::vector<std::vector<uint8_t>>& repair) = 0;

  /**
   * 解碼：給定任意 K 個已收到的 symbol（source 或 repair 混合），
   * 還原所有丟失的 source symbol。
   *
   * @param K       原始 source symbol 數量
   * @param P       編碼時使用的 repair 數量
   * @param B       每個 symbol 的位元組數
   * @param data    輸入/輸出：data[i] 為 symbol 資料（B bytes）；
   *                decode 成功後，repair 位置會被覆寫為還原的 source 資料
   * @param indices 輸入/輸出：indices[i] 為 symbol 的索引號
   *                  0 .. K-1   → source symbol
   *                  K .. K+P-1 → repair symbol
   *                decode 成功後，原 repair 位置的索引更新為還原的 source 索引
   * @return        成功回傳 true
   */
  virtual bool Decode (uint32_t K, uint32_t P, uint32_t B,
                       std::vector<std::vector<uint8_t>>& data,
                       std::vector<uint8_t>& indices) = 0;
};

} // namespace ns3
