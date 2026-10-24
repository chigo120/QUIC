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
 * ----------------------------------------------------- */
int gilbert_plr_mod(double plr, int current_state)
{
	double p_good_bad;		
	double p_bad_good;		
	
	int p_loss_thousandth = (int)(plr * 10000); 
	
	if (p_loss_thousandth == 337) {  // 3.37%
		p_good_bad = 0.0088;
		p_bad_good = 0.25;
	}
	else if (p_loss_thousandth == 345) {  // 3.45%
		p_good_bad = 0.0090;
		p_bad_good = 0.25;
	}
	else{
	
		int p_loss;

		p_loss = plr * 100;
		switch (p_loss)
		{
		case 0:
			p_good_bad = 0.0001;
			p_bad_good = 0.25;
			break;
			
		case 1:
			p_good_bad = 0.0025;
			p_bad_good = 0.25;
			break;

		case 5:
			p_good_bad = 0.0132;
			p_bad_good = 0.25;
			break;	
		
		case 10:
			p_good_bad = 0.0278;
			p_bad_good = 0.25;
			break;
		
		case 20:
			p_good_bad = 0.0625;
			p_bad_good = 0.25;
			break;
		
		case 30:
			p_good_bad = 0.1071;
			p_bad_good = 0.25;
			break;
		
		case 40:
			p_good_bad = 0.1667;
			p_bad_good = 0.25;
			break;
		
		case 50:
			p_good_bad = 0.24779;
			p_bad_good = 0.25;
			break;

		case 60:
			p_good_bad = 0.31;
			p_bad_good = 0.25;
			break;

		case 70:
			p_good_bad = 0.385;
			p_bad_good = 0.25;
			break;

		case 80:
			p_good_bad = 0.43;
			p_bad_good = 0.22;
			break;

		case 90:
			p_good_bad = 0.52;
			p_bad_good = 0.2;
			break;

		default:
			p_good_bad = 0.02777;
			p_bad_good = 0.25;
			break;
		}
	}
	
	double random_num = (double)rand() / RAND_MAX;
	int random = rand();
	random_num = (double)random / RAND_MAX;
	if (current_state) {
		//printf("good to bad p = %f\n", p_good_bad);
		if (random_num < p_good_bad) {
			current_state = 0;
		}
		else {
			current_state = 1;
		}
	}
	else {
		//printf("bad to good p = %f\n", p_bad_good);
		if (random_num < p_bad_good) {
			current_state = 1;
		}
		else {
			current_state = 0;
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

