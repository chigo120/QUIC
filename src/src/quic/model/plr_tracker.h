// 封包遺失順序追蹤模組（動態擴展版）
#ifndef PLR_TRACKER_H
#define PLR_TRACKER_H

#include <cstdio>
#include <iomanip>

// 封包狀態
typedef enum {
    PKT_OK = 0,      // 成功
    PKT_LOST = 1     // 掉包
} PacketStatus;

// 追蹤器結構（動態擴展）
typedef struct {
    PacketStatus *history;   // 封包狀態歷史記錄
    int count;               // 當前記錄數量
    int capacity;            // 當前容量
    int consecutive_loss;    // 當前連續掉包數
    int max_consecutive_loss;// 最大連續掉包數
    int loss_bursts;         // 掉包爆發次數
} PLRTracker;

// 初始化追蹤器（不需指定大小，會自動擴展）
void plr_tracker_init(PLRTracker *tracker);

// 釋放追蹤器
void plr_tracker_free(PLRTracker *tracker);

// 記錄一個封包狀態（自動擴展空間）
void plr_tracker_record(PLRTracker *tracker, int is_lost);

// 印出統計資訊
void plr_tracker_print_stats(PLRTracker *tracker);

// 印出視覺化的掉包模式（最近N個封包）
void plr_tracker_print_pattern(PLRTracker *tracker, int last_n);

// 將完整記錄儲存到檔案
void plr_tracker_save_to_file(PLRTracker *tracker, const char *filename);

// 產生視覺化圖表到檔案（折線圖，以 FEC Block 為單位）
void plr_tracker_generate_chart(PLRTracker *tracker, const char *filename, int width);

// 清空記錄但保留記憶體
void plr_tracker_clear(PLRTracker *tracker);

#endif // PLR_TRACKER_H
