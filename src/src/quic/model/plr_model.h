/* plr_model.h
 * 封包遺失 / PLR 模型：對外介面
 */
#ifndef PLR_MODEL_H
#define PLR_MODEL_H

#ifdef __cplusplus
extern "C" {
#endif

/* === 全域統計變數 ===
 * 這兩個用來統計實際被「判定為遺失」的封包數
 * plr_model.cc 會定義它們，其他檔案只要 #include plr_model.h 就能使用 extern。
 */
extern int g_plr_bad_packet;
extern int g_plr_total_packet;

/**
 * SINCGARS 風格的 PLR 模型 (簡化版)
 *
 * 參數：
 *   E : Eb/N0 或 SNR，單位 dB（你可以依自己定義當成「通道品質參數」）
 *   r : 碼率 / 有效傳輸率 (0 < r <= 1)，r 越大代表越吃緊，錯誤率略高
 *
 * 內部概念：
 *   1. 先把 E(dB) 轉成線性值 SNR_lin = 10^(E/10)
 *   2. 考慮碼率 r -> SNR_eff = SNR_lin * r
 *   3. 用非常簡化的 BPSK over AWGN 近似：
 *        BER ≈ 0.5 * exp(-SNR_eff)
 *   4. 假設一個封包大約 1024 bytes：
 *        packet_bits = 1024 * 8
 *        PLR ≈ 1 - (1 - BER)^(packet_bits)
 *
 * 回傳：
 *   估計封包遺失率，範圍 [0.0, 1.0]
 *
 * 注意：
 *   這是「合理但簡化」的模型，不是正式 SINCGARS 標準曲線，
 *   但用在模擬上很夠用，也容易調參。
 */
double get_singars_plr(double E, double r);

/**
 * Gilbert-Elliott Loss Model 單步更新
 *
 * 參數：
 *   plr           : 希望達到的「平均 PLR」(0.0 ~ 1.0)
 *   current_state : 目前狀態 (0 = GOOD, 1 = BAD)
 *
 * 內部概念：
 *   - 用兩態馬可夫鏈 (GOOD / BAD) 模擬 burst loss：
 *     GOOD  狀態：封包一定收得到（不丟）
 *     BAD   狀態：封包一定丟失（全丟）
 *   - 透過轉移機率 p_good_bad, p_bad_good 讓 steady-state 的 BAD 比率 ≈ plr
 *
 * 回傳：
 *   下一個狀態 (0 = GOOD, 1 = BAD)
 *
 * 用法：
 *   static int state = 0;
 *   state = gilbert_plr_mod(target_plr, state);
 *   if (state == 1) {
 *       // 丟這個封包
 *   } else {
 *       // 收下來
 *   }
 */
int gilbert_plr_mod(double plr, int current_state, int packet_size);

/**
 * 回傳目前實測的 PLR：
 *   PLR = g_plr_bad_packet / g_plr_total_packet
 * 若目前 total=0，則回傳 0.0。
 */
double return_actually_plr(void);

/**
 * 通知 PLR 模組「這個封包是否被當成遺失」
 *
 * 參數：
 *   is_lost : 1 = 這個封包被當作丟失
 *             0 = 這個封包成功收下
 *
 * 功能：
 *   - g_plr_total_packet++
 *   - 如果 is_lost != 0，則 g_plr_bad_packet++
 *
 * 建議所有「決定丟不丟」的地方都順手呼叫這個，之後就可以用
 * return_actually_plr() 查實際 PLR。
 */
void plr_register_packet(int is_lost);

/**
 * 重設 PLR 統計（把 bad / total 歸零）
 */
void plr_reset_statistics(void);

#ifdef __cplusplus
}
#endif

#endif /* PLR_MODEL_H */

