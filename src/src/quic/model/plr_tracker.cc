#include "plr_tracker.h"
#include <cstdlib>
#include <cstring>
#include <iostream>

#define INITIAL_CAPACITY 1024  // 初始容量
#define GROWTH_FACTOR 2        // 每次擴展為原來的2倍

void plr_tracker_init(PLRTracker *tracker)
{
    tracker->history = (PacketStatus *)malloc(INITIAL_CAPACITY * sizeof(PacketStatus));
    tracker->count = 0;
    tracker->capacity = INITIAL_CAPACITY;
    tracker->consecutive_loss = 0;
    tracker->max_consecutive_loss = 0;
    tracker->loss_bursts = 0;
}

void plr_tracker_free(PLRTracker *tracker)
{
    if (tracker->history) {
        free(tracker->history);
        tracker->history = NULL;
    }
    tracker->count = 0;
    tracker->capacity = 0;
}

// 動態擴展容量
static void plr_tracker_expand(PLRTracker *tracker)
{
    int new_capacity = tracker->capacity * GROWTH_FACTOR;
    PacketStatus *new_history = (PacketStatus *)realloc(
        tracker->history, 
        new_capacity * sizeof(PacketStatus)
    );
    
    if (new_history) {
        tracker->history = new_history;
        tracker->capacity = new_capacity;
        std::cout << "[追蹤器] 擴展容量至 " << new_capacity << " 個封包" << std::endl;
    } else {
        std::cout << "[追蹤器警告] 記憶體擴展失敗！" << std::endl;
    }
}

void plr_tracker_record(PLRTracker *tracker, int is_lost)
{
    if (!tracker || !tracker->history) return;
    
    // 如果空間不足，自動擴展
    if (tracker->count >= tracker->capacity) {
        plr_tracker_expand(tracker);
        // 如果擴展失敗，就不記錄了
        if (tracker->count >= tracker->capacity) {
            return;
        }
    }
    
    PacketStatus status = is_lost ? PKT_LOST : PKT_OK;
    tracker->history[tracker->count++] = status;
    
    // 更新連續掉包統計
    if (is_lost) {
        tracker->consecutive_loss++;
        if (tracker->consecutive_loss > tracker->max_consecutive_loss) {
            tracker->max_consecutive_loss = tracker->consecutive_loss;
        }
    } else {
        if (tracker->consecutive_loss > 0) {
            tracker->loss_bursts++;  // 結束一次掉包爆發
        }
        tracker->consecutive_loss = 0;
    }
}

void plr_tracker_print_stats(PLRTracker *tracker)
{
    if (!tracker || tracker->count == 0) {
        std::cout << "無封包記錄" << std::endl;
        return;
    }
    
    int total_loss = 0;
    for (int i = 0; i < tracker->count; i++) {
        if (tracker->history[i] == PKT_LOST) {
            total_loss++;
        }
    }
    
    double loss_rate = (double)total_loss / tracker->count * 100.0;
    double avg_burst = (tracker->loss_bursts > 0) ? 
                       (double)total_loss / tracker->loss_bursts : 0.0;
    
    std::cout << "\n========== 掉包統計 ==========" << std::endl;
    std::cout << "總封包數:         " << tracker->count << std::endl;
    std::cout << "掉包數:           " << total_loss << std::endl;
    std::cout << "掉包率:           " << std::fixed << std::setprecision(2) 
              << loss_rate << "%" << std::endl;
    std::cout << "最大連續掉包:     " << tracker->max_consecutive_loss << std::endl;
    std::cout << "掉包爆發次數:     " << tracker->loss_bursts << std::endl;
    if (tracker->loss_bursts > 0) {
        std::cout << "平均每次爆發:     " << std::setprecision(1) 
                  << avg_burst << " 個封包" << std::endl;
    }
    std::cout << "記憶體使用:       " << tracker->count << " / " 
              << tracker->capacity << std::endl;
    std::cout << "==============================\n" << std::endl;
}

void plr_tracker_print_pattern(PLRTracker *tracker, int last_n)
{
    if (!tracker || tracker->count == 0) {
        std::cout << "無封包記錄" << std::endl;
        return;
    }
    
    int start = (tracker->count > last_n) ? (tracker->count - last_n) : 0;
    int display_count = tracker->count - start;
    
    std::cout << "\n最近 " << display_count << " 個封包狀態:" << std::endl;
    std::cout << "(O=成功, X=掉包)\n" << std::endl;
    
    // 每行顯示 50 個封包
    int per_line = 50;
    for (int i = start; i < tracker->count; i++) {
        if ((i - start) % per_line == 0 && i != start) {
            std::cout << " [" << i << "]" << std::endl;
        }
        std::cout << (tracker->history[i] == PKT_OK ? 'O' : 'X');
    }
    std::cout << " [" << tracker->count << "]\n" << std::endl;
}

void plr_tracker_save_to_file(PLRTracker *tracker, const char *filename)
{
    if (!tracker || !filename) return;
    
    FILE *fp = fopen(filename, "w");
    if (!fp) {
        std::cout << "無法開啟檔案: " << filename << std::endl;
        return;
    }
    
    fprintf(fp, "# 封包遺失記錄\n");
    fprintf(fp, "# 格式: 序號,狀態(0=成功,1=掉包)\n");
    fprintf(fp, "# 總封包數: %d\n\n", tracker->count);
    
    for (int i = 0; i < tracker->count; i++) {
        fprintf(fp, "%d,%d\n", i+1, tracker->history[i]);
    }
    
    fclose(fp);
    std::cout << "已儲存 " << tracker->count << " 筆記錄到: " 
              << filename << std::endl;
}

void plr_tracker_generate_chart(PLRTracker *tracker, const char *filename, int width)//, int fec_block_size
{
    if (!tracker || !filename || width <= 0) return;
    
    FILE *fp = fopen(filename, "w");
    if (!fp) {
        std::cout << "無法開啟檔案: " << filename << std::endl;
        return;
    }
    
    fprintf(fp, "連續掉包數線性圖表\n");
    fprintf(fp, "==========================================\n");
    fprintf(fp, "總封包數: %d\n", tracker->count);
    fprintf(fp, "X軸: 封包序號\n");
    fprintf(fp, "Y軸: 連續掉包數\n");
    fprintf(fp, "==========================================\n\n");
    
    // 計算每個位置的連續掉包數
    int *burst_values = new int[tracker->count];
    int current_burst = 0;
    
    for (int i = 0; i < tracker->count; i++) {
        if (tracker->history[i] == PKT_LOST) {
            current_burst++;
            burst_values[i] = current_burst;
        } else {
            current_burst = 0;
            burst_values[i] = 0;
        }
    }
    
    // 找出最大連續掉包數（Y軸最大值）
    int max_burst = 0;
    for (int i = 0; i < tracker->count; i++) {
        if (burst_values[i] > max_burst) {
            max_burst = burst_values[i];
        }
    }
    
    if (max_burst == 0) {
        fprintf(fp, "無掉包記錄\n");
        delete[] burst_values;
        fclose(fp);
        return;
    }
    
    // 設定圖表高度（Y軸刻度數）
    int chart_height = (max_burst > 20) ? 20 : max_burst;
    int samples = (tracker->count > width) ? width : tracker->count;
    int step = (tracker->count + samples - 1) / samples;
    
    // 對封包進行採樣（X軸壓縮）
    int *sampled_bursts = new int[samples];
    for (int i = 0; i < samples; i++) {
        int idx = i * step;
        if (idx >= tracker->count) idx = tracker->count - 1;
        
        // 取該區間的最大連續掉包數
        int max_in_range = 0;
        for (int j = idx; j < idx + step && j < tracker->count; j++) {
            if (burst_values[j] > max_in_range) {
                max_in_range = burst_values[j];
            }
        }
        sampled_bursts[i] = max_in_range;
    }
    
    // 繪製圖表（從上到下）
    for (int y = chart_height; y > 0; y--) {
        // Y軸標籤
        fprintf(fp, "%3d |", y);
        
        // 繪製數據點
        for (int x = 0; x < samples; x++) {
            int scaled_value = (int)((double)sampled_bursts[x] * chart_height / max_burst);
            
            if (scaled_value >= y) {
                fprintf(fp, "*");  // 有數據
            } else {
                fprintf(fp, " ");  // 無數據
            }
        }
        fprintf(fp, "\n");
    }
    
    // X軸
    fprintf(fp, "    +");
    for (int i = 0; i < samples; i++) {
        fprintf(fp, "-");
    }
    fprintf(fp, "\n");
    
    // X軸標籤（顯示封包號）
    fprintf(fp, "     ");
    int label_interval = samples / 10;  // 顯示10個標籤
    if (label_interval < 1) label_interval = 1;
    
    for (int i = 0; i < samples; i++) {
        if (i % label_interval == 0) {
            int pkt_num = i * step;
            fprintf(fp, "%d", pkt_num % 10);  // 只顯示個位數
        } else {
            fprintf(fp, " ");
        }
    }
    fprintf(fp, "\n");
    
    // 圖表說明
    fprintf(fp, "\n說明:\n");
    fprintf(fp, "  * = 連續掉包事件\n");
    fprintf(fp, "  最大連續掉包數: %d\n", max_burst);
    fprintf(fp, "  X軸範圍: 0 - %d (封包號)\n", tracker->count - 1);
    if (step > 1) {
        fprintf(fp, "  註: 每個字元代表 %d 個封包，顯示該區間最大值\n", step);
    }
    
    delete[] burst_values;
    delete[] sampled_bursts;
    fclose(fp);
    std::cout << "已產生視覺化圖表: " << filename << std::endl;
}

void plr_tracker_clear(PLRTracker *tracker)
{
    if (!tracker) return;
    
    tracker->count = 0;
    tracker->consecutive_loss = 0;
    tracker->max_consecutive_loss = 0;
    tracker->loss_bursts = 0;
    // 保留 history 記憶體和 capacity
}

