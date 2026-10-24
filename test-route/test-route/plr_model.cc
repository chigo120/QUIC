// plr_model.cc
// 封包遺失 / PLR 模型實作

#include "plr_model.h"
#include <time.h>
#include <math.h>   // pow, exp
#include <stdlib.h> // rand, RAND_MAX

int g_plr_bad_packet   = 0;
int g_plr_total_packet = 0;

time_t rx_sock_startTime;

/* -------------------------------------------------------
 * 1. SINCGARS-style PLR (簡化版)
 * ----------------------------------------------------- */
double get_singars_plr(double E, double r)
{
    // 安全檢查：避免怪值
    if (r <= 0.0) {
        r = 1.0;
    }
    if (E < -20.0) {
        E = -20.0;
    }
    if (E > 40.0) {
        E = 40.0;
    }

    // 1) dB -> 線性
    double snr_lin = pow(10.0, E / 10.0);

    // 2) 考慮碼率，簡單乘上 r 當有效 SNR
    double snr_eff = snr_lin * r;

    // 3) 非常簡化的 BPSK BER 近似：BER ≈ 0.5 * exp(-snr_eff)
    //    (原始公式會用 Q-function，這裡為了簡單用 exp() 逼近)
    double ber = 0.5 * exp(-snr_eff);

    if (ber < 1e-12) {
        ber = 1e-12;
    }
    if (ber > 0.5) {
        ber = 0.5;
    }

    // 4) 假設封包 1024 bytes
    const int packet_bits = 1024 * 8;

    //    PLR = 1 - (1 - BER)^(packet_bits)
    double plr = 1.0 - pow(1.0 - ber, (double)packet_bits);

    // 5) 夾在 [0, 1] 之間
    if (plr < 0.0) plr = 0.0;
    if (plr > 1.0) plr = 1.0;

    return plr;
}

/* -------------------------------------------------------
 * 2. Gilbert-Elliott Loss Model
 *
 * 參數說明：
 *   plr          - 目標封包遺失率 (0.0 ~ 1.0)
 *   current_state - 當前狀態 (1 = Good, 0 = Bad)
 *   packet_size  - 封包大小 (bytes)，支援 512 / 1024 / 1400
 *                  其他值會 fallback 到最近的支援大小
 *
 * p / q 來源：依據 GE Model Statistical Characteristics 表格
 *   q = 1 / ABL
 *   p = (PLR * q) / (1 - PLR)
 * ----------------------------------------------------- */
int gilbert_plr_mod(double plr, int current_state, int packet_size)
{
    double p_good_bad;  /* p: Good -> Bad */
    double p_bad_good;  /* q: Bad  -> Good */

    /* --------------------------------------------------
     * 根據 packet_size 選擇對應的參數表
     * -------------------------------------------------- */

    /* 512 byte packet 參數表 */
    static const double tbl_512[12][2] = {
        /* { p_good_bad, p_bad_good } */
        { 0.00116, 0.11507 },   /* PLR =  1% */
        { 0.00585, 0.11124 },   /* PLR =  5% */
        { 0.01151, 0.10363 },   /* PLR = 10% */
        { 0.02330, 0.09320 },   /* PLR = 20% */
        { 0.03554, 0.08292 },   /* PLR = 30% */
        { 0.05047, 0.07570 },   /* PLR = 40% */
        { 0.06604, 0.06604 },   /* PLR = 50% */
        { 0.08921, 0.05947 },   /* PLR = 60% */
        { 0.12443, 0.05333 },   /* PLR = 70% */  // <-- 新增
        { 0.19181, 0.04795 },   /* PLR = 80% */  // <-- 新增
        { 0.38790, 0.04310 },   /* PLR = 90% */  // <-- 新增
        { 1.00000, 0.00000 },   /* PLR = 100% */ // <-- 新增
    };

    /* 1024 byte packet 參數表 */
    static const double tbl_1024[12][2] = {
        { 0.00232, 0.22989 },   /* PLR =  1% */
        { 0.01172, 0.22272 },   /* PLR =  5% */
        { 0.02310, 0.20790 },   /* PLR = 10% */
        { 0.04664, 0.18657 },   /* PLR = 20% */
        { 0.07119, 0.16611 },   /* PLR = 30% */
        { 0.10117, 0.15175 },   /* PLR = 40% */
        { 0.13193, 0.13193 },   /* PLR = 50% */
        { 0.17789, 0.11860 },   /* PLR = 60% */
        { 0.24755, 0.10609 },   /* PLR = 70% */  // <-- 新增
        { 0.38071, 0.09518 },   /* PLR = 80% */  // <-- 新增
        { 0.77040, 0.08560 },   /* PLR = 90% */  // <-- 新增
        { 1.00000, 0.00000 },   /* PLR = 100% */ // <-- 新增
    };

    /* 1400 byte packet 參數表 */
    static const double tbl_1400[12][2] = {
        { 0.00319, 0.31546 },   /* PLR =  1% */
        { 0.01600, 0.30395 },   /* PLR =  5% */
        { 0.03139, 0.28249 },   /* PLR = 10% */
        { 0.06427, 0.25707 },   /* PLR = 20% */
        { 0.09718, 0.22676 },   /* PLR = 30% */
        { 0.13803, 0.20704 },   /* PLR = 40% */
        { 0.17986, 0.17986 },   /* PLR = 50% */
        { 0.24197, 0.16131 },   /* PLR = 60% */
        { 0.33602, 0.14401 },   /* PLR = 70% */  // <-- 新增
        { 0.51567, 0.12892 },   /* PLR = 80% */  // <-- 新增
        { 1.00000, 0.11111 },   /* PLR = 90% */  // <-- 新增
        { 1.00000, 0.00000 },   /* PLR = 100% */ // <-- 新增
    };

    /* 選擇參數表 */
    const double (*tbl)[2];
    if (packet_size <= 768) {           /* 512 byte */
        tbl = tbl_512;
    } else if (packet_size <= 1212) {   /* 1024 byte */
        tbl = tbl_1024;
    } else {                            /* 1400 byte */
        tbl = tbl_1400;
    }

    /* --------------------------------------------------
     * 查表：將 PLR 轉為整數百分比後直接對應參數
     * -------------------------------------------------- */
    int p_loss = (int)(plr * 100.0);

    // ★ 新增防呆機制：如果傳入大於 1.0 的值，強制壓回 100
    if (p_loss > 100) {
        p_loss = 100;
    }

    int idx;
    switch (p_loss) {
        case  1:  idx = 0; break;
        case  5:  idx = 1; break;
        case 10:  idx = 2; break;
        case 20:  idx = 3; break;
        case 30:  idx = 4; break;
        case 40:  idx = 5; break;
        case 50:  idx = 6; break;
        case 60:  idx = 7; break;
        case 70:  idx = 8; break;  // <-- 新增
        case 80:  idx = 9; break;  // <-- 新增
        case 90:  idx = 10; break; // <-- 新增 90% 的索引
        case 100: idx = 11; break; // <-- 新增 100% 的索引
        default:  idx = 2; break;   /* fallback: 10% */
    }

    p_good_bad = tbl[idx][0];
    p_bad_good = tbl[idx][1];

    /* --------------------------------------------------
     * 狀態轉移
     * -------------------------------------------------- */
    int random     = rand();
    double random_num = (double)random / RAND_MAX;

    if (current_state) {    /* 目前 Good state */
        if (random_num < p_good_bad) {
            current_state = 0;  /* 轉移到 Bad */
        } else {
            current_state = 1;  /* 留在 Good */
        }
    } else {                /* 目前 Bad state */
        if (random_num < p_bad_good) {
            current_state = 1;  /* 轉移到 Good */
        } else {
            current_state = 0;  /* 留在 Bad */
        }
    }

    return current_state;
}

/* -------------------------------------------------------
 * 3. 實測 PLR
 * ----------------------------------------------------- */
double return_actually_plr(void)
{
    if (g_plr_total_packet <= 0) {
        return 0.0;
    }
    return (double)g_plr_bad_packet / (double)g_plr_total_packet;
}

/* -------------------------------------------------------
 * 4. 統計輔助
 * ----------------------------------------------------- */
void plr_register_packet(int is_lost)
{
    g_plr_total_packet++;
    if (is_lost) {
        g_plr_bad_packet++;
    }
}

void plr_reset_statistics(void)
{
    g_plr_total_packet = 0;
    g_plr_bad_packet   = 0;
}
