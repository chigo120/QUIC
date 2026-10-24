#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/applications-module.h"
#include "route-helper.h"
#include "ns3/error-model.h"
#include <iostream>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("TestRouteMain");

int
main (int argc, char *argv[])
{
  
  LogComponentEnable ("RouteReceiver", LOG_LEVEL_INFO);
  LogComponentEnable ("RouteSender",   LOG_LEVEL_INFO);
  LogComponentEnable ("RouteHelper",   LOG_LEVEL_INFO);
  LogComponentEnable ("TestRouteMain", LOG_LEVEL_INFO);

  // ===== 參數 =====
  uint32_t seed = 1;
  uint32_t run  = 1;
  uint32_t chunk          = 1400;
  double   gePlr          = 0.0345;
  double   geSnr          = -1.0;
  double   geDir          = -1.0;
  int      geGilbert      = 1;
  bool     isVideo        = true;
  double   videoRateKbps  = 17449.0;
  bool     useFec         = true;
  std::string fecType = "RaptorQ";
  // ★★★ 新增：FEC 參數，預設值保持原樣，但允許修改 ★★★
  int fecK = 1024;
  int fecR = 52;
  double simTime = 35.0;

  CommandLine cmd;
  cmd.AddValue ("seed", "Random seed", seed);
  cmd.AddValue ("run",  "Random run number", run);
  cmd.AddValue ("chunk",     "Payload chunk bytes", chunk);
  cmd.AddValue ("gePlr",     "Average packet loss rate", gePlr);
  cmd.AddValue ("isVideo",   "1: video traffic, 0: file", isVideo);
  cmd.AddValue ("videoRate", "Video bitrate (kbps)", videoRateKbps);
  cmd.AddValue ("useFec",    "enable AL-FEC", useFec);
  cmd.AddValue ("fecType", "FEC Algorithm: RaptorQ or Raptor", fecType);
  // ★★★ 新增命令行參數 ★★★
  cmd.AddValue ("fecK", "Source Block Size (K)", fecK);
  cmd.AddValue ("fecR", "Repair Symbols (R)", fecR);
  cmd.AddValue ("simTime", "Simulation duration in seconds", simTime);
  cmd.Parse (argc, argv);

  RngSeedManager::SetSeed (seed);
  RngSeedManager::SetRun  (run);
  NS_LOG_UNCOND ("Using Seed=" << seed << " Run=" << run);

  // ... (保留 PLR 檢查程式碼，不更動) ...
  int p_loss_percent = static_cast<int>(std::round(gePlr * 100.0));
  int p_loss_thousandth = static_cast<int>(std::round(gePlr * 10000.0));
  bool isValidPlr = false;
  if (p_loss_thousandth == 337 || p_loss_thousandth == 345) {
      isValidPlr = true;
  }
  else {
      switch (p_loss_percent) {
          case 0: case 1: case 5: case 10: case 20: case 30:
          case 40: case 50: case 60: case 70: case 80: case 90:
              isValidPlr = true;
              break;
          default:
              isValidPlr = false;
              break;
      }
  }

  if (!isValidPlr) {
      // ... (保留錯誤訊息) ...
      return 1;
  }
  
  NS_LOG_UNCOND("[CONFIG] Check Pass. gePlr=" << gePlr 
                << " (Use Gilbert Model? " << geGilbert << ")");

  NodeContainer nodes;
  nodes.Create (2);

  PointToPointHelper p2p;
  p2p.SetDeviceAttribute  ("DataRate", StringValue ("1Gbps"));
  p2p.SetChannelAttribute ("Delay",    StringValue ("2ms"));
  NetDeviceContainer devs = p2p.Install (nodes);
  p2p.EnablePcapAll ("route", true);

  InternetStackHelper stack;
  stack.Install (nodes);

  Ipv4AddressHelper ip;
  ip.SetBase ("10.1.1.0", "255.255.255.0");
  Ipv4InterfaceContainer ifs = ip.Assign (devs);
  uint16_t port = 5004;

  // ===== Receiver =====
  RouteReceiverHelper rx (InetSocketAddress (Ipv4Address::GetAny (), port));
  rx.SetUseFec (useFec);
  rx.SetFecType (fecType);
  rx.SetGeParams (gePlr, geSnr, geDir, geGilbert != 0);
  // ★★★ 設定 K 與 R ★★★
  rx.SetFecParams ((uint16_t)fecK, (uint16_t)fecR);

  ApplicationContainer rxApps = rx.Install (NodeContainer (nodes.Get (1)));
  rxApps.Start (Seconds (1.0));
  rxApps.Stop (Seconds (1.0 + simTime + 0.5));

  // ===== Sender =====
  const uint64_t MAX_TRANSPORT = 500ull * 1024ull * 1024ull;

  RouteSenderHelper tx (InetSocketAddress (ifs.GetAddress (1), port),
                        100, 33,              
                        1,                    
                        MAX_TRANSPORT,        
                        6,                    
                        "media$TOI%05d$.m4s", 
                        chunk,
                        CP_MEDIA_FILE);
  tx.SetUseFec (useFec);
  
  // ★★★ 設定 K 與 R ★★★
  tx.SetFecParams ((uint16_t)fecK, (uint16_t)fecR);

  if (isVideo)
    {
      // ★★★ 終極精確提速修正：根據實際封包總數計算發送頻率 ★★★
      
      // 1. 計算一個 GoP 實際有多少 byte
      uint64_t gopBytes = static_cast<uint64_t>(videoRateKbps * 1000.0 * 1.0 / 8.0);
      
      // 2. 計算 Source Packets (無條件進位)
      uint32_t srcPkts = (gopBytes + chunk - 1) / chunk;
      
      // 3. 計算會被切成幾個 Block (無條件進位)
      uint32_t blocks = (srcPkts + fecK - 1) / fecK;
      
      // 4. 計算每個 Block 都有 fecR 個修復封包，算出總修復封包
      uint32_t repairPkts = 0;
      if (useFec && fecK > 0) {
          repairPkts = blocks * fecR;
      }
      
      // 5. 這個 1 秒鐘的 GoP "真正" 需要送出的總封包數
      uint32_t totalPkts = srcPkts + repairPkts;
      
      // 6. 既然 1 個 GoP 規定要 1 秒傳完，每秒該送的精確頻率就是 totalPkts
      double pktPerSec    = static_cast<double>(totalPkts);
      double sendInterval = 1.0 / pktPerSec;  

      tx.SetNominalRateKbps (videoRateKbps);
      tx.SetSendInterval    (sendInterval);
      
      NS_LOG_UNCOND ("[VIDEO] 1秒GoP實際總封包=" << totalPkts 
                     << " (Src:" << srcPkts << " + Rep:" << repairPkts 
                     << ") -> 精確發送間隔=" << sendInterval << " 秒");
    }
  else
    {
      tx.SetNominalRateKbps (0.0);
      tx.SetSendInterval    (0.005);
    }

  ApplicationContainer txApps = tx.Install (NodeContainer (nodes.Get (0)));
  txApps.Start (Seconds (1.5));
  txApps.Stop (Seconds (1.5 + simTime));

  Simulator::Run ();
  Simulator::Destroy ();
  return 0;
  
}
