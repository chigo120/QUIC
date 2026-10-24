#ifndef FEC_RECOVERY_MODEL_H
#define FEC_RECOVERY_MODEL_H

#include <stdint.h>

namespace ns3 {

class FecRecoveryModel {
public:
    // 定義支援的 FEC 演算法
    enum FecScheme {
        RAPTOR_Q,      // 使用 RaptorQ 公式
        RAPTOR_CODES,  // 使用 Raptor Codes 公式
        REED_SOLOMON
    };

    /**
     * @brief 判斷是否成功修復 (模擬)
     * * @param n 當前 Block 接收到的總封包數 (Source + Repair)
     * @param k 該 Block 設定的原始封包數 (Source Symbols)
     * @param scheme 使用的 FEC 演算法
     * @return true 代表解碼成功 (Recovered), false 代表失敗
     */
    static bool IsRecovered (uint32_t n, uint32_t k, FecScheme scheme);
};

} // namespace ns3

#endif /* FEC_RECOVERY_MODEL_H */
