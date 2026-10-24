/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * FEC + 模擬影片串流流量測試
 *
 * 測試目的：
 *   quic-fec-verify.cc 資料量太小（無法壓測 buffer），
 *   quic-fec-bulksend-verify.cc 會撞到跟 FEC 無關的 BulkSendApplication
 *   / SendPendingData 無限迴圈舊 bug（見專案記憶）。
 *   這支測試改用「自己排程送資料」的方式模擬影片串流的真實流量特徵：
 *     - 固定 FPS，每個 Frame Interval 送一個 Frame
 *     - GOP 模式：每隔 gopSize 個 Frame 出現一個較大的 I-frame，
 *       其餘是較小的 P-frame（貼近真實視訊編碼的資料量分布）
 *     - 不透過 BulkSendApplication，而是像 quic-echo-client 一樣
 *       用 Simulator::Schedule 排程呼叫 Socket::Send()，天然受
 *       Frame Interval 節流，不會觸發「同一時間點無限要更多資料」
 *       的舊 bug
 *     - 單向串流（Source -> Sink），不需要 echo
 *
 * 觀察重點：
 *   - Source 排程送出的總 bytes 數 vs Sink 實際收到的總 bytes 數
 *   - 發送端 tx buffer 是否被塞滿（"Rejected. Not enough room to
 *     buffer packet." 警告）
 *   - 模擬是否能在預期時間內正常結束（而非卡死或 abort）
 *
 * 執行方式：
 *   ./waf --run "quic-fec-video-verify --durationSec=20 --lossRate=0.10"
 */

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/quic-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/applications-module.h"
#include <iostream>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("QuicFecVideoVerify");

// ── 影片串流參數與狀態（排程用的全域變數，跟 quic-echo-client 手法一致）──
static Ptr<Socket> g_videoSocket;
static uint32_t    g_frameRate     = 30;     // fps
static uint32_t    g_gopSize       = 30;     // 每 gopSize 個 frame 一個 I-frame
static uint32_t    g_pFrameBytes   = 800;    // P-frame 大小
static uint32_t    g_iFrameBytes   = 4000;   // I-frame 大小
static uint32_t    g_totalFrames   = 0;
static uint32_t    g_framesSent    = 0;
static uint64_t    g_totalBytesQueued = 0;   // 排程端「要求送出」的總 bytes

static Address g_serverAddress;
static uint16_t g_serverPort;
static Ptr<Node> g_sourceNode;

static void
StartVideoConnection ()
{
  // 一定要透過 Simulator::Schedule 呼叫（而非在 main() 裡、
  // Simulator::Run() 之前直接呼叫），否則 Connect() 送出的 INITIAL
  // 封包不會真的進入事件佇列處理，握手會卡在 CONNECTING_CLT 永遠出不來
  // （這是實測發現的行為，quic-echo-client 之所以正常，是因為它的
  //  Connect() 是在 StartApplication() 裡執行，而 StartApplication
  //  本身就是透過 ApplicationContainer::Start() 排程觸發的）。
  TypeId tid = TypeId::LookupByName ("ns3::QuicSocketFactory");
  g_videoSocket = Socket::CreateSocket (g_sourceNode, tid);
  g_videoSocket->Bind ();
  g_videoSocket->Connect (g_serverAddress);
}

static void
SendVideoFrame ()
{
  if (g_framesSent >= g_totalFrames)
    {
      return;
    }

  bool isIFrame = (g_framesSent % g_gopSize == 0);
  uint32_t frameSize = isIFrame ? g_iFrameBytes : g_pFrameBytes;

  Ptr<Packet> p = Create<Packet> (frameSize);
  // 用 Send(p, streamId) 明確指定固定跑在 stream 1 上，
  // 避免預設 Send(p)（flags=0）把資料分散送到所有已存在的 stream
  // （DisgregateSend 的 fan-out 邏輯，搭配 stream 層逐塊 dequeue，
  //  在多 stream 情境下會產生大量細碎 Socket Tx Buffer Add()，
  //  屬於跟 FEC 無關的既有問題，用單一 stream 直接繞開）。
  // 也更貼近真實影片串流「一個 QUIC stream 傳到底」的語意。
  int sent = g_videoSocket->Send (p, 1);
  if (sent > 0)
    {
      g_totalBytesQueued += sent;
    }
  else
    {
      NS_LOG_WARN ("[Video] Frame " << g_framesSent << " (" << frameSize
                   << " bytes) 送出失敗，Send() 回傳 " << sent
                   << "（很可能是發送端 tx buffer 滿了）");
    }

  g_framesSent++;
  if (g_framesSent < g_totalFrames)
    {
      Simulator::Schedule (MilliSeconds (1000.0 / g_frameRate), &SendVideoFrame);
    }
}

int
main (int argc, char *argv[])
{
  // ── 可調參數 ──────────────────────────────────────────────────
  uint32_t frameRate    = 30;      // fps
  uint32_t gopSize      = 30;      // GOP 長度（frame 數）
  uint32_t pFrameBytes  = 800;     // P-frame 大小
  uint32_t iFrameBytes  = 4000;    // I-frame 大小
  double   durationSec  = 20.0;    // 影片長度（秒）
  uint32_t fecK         = 10;
  uint32_t fecP         = 4;
  double   lossRate     = 0.10;
  bool     enableFec    = true;
  bool     disableRetx  = true;
  uint32_t sndBufSize   = 131072;  // 發送端 buffer（預設 128KB）

  CommandLine cmd;
  cmd.AddValue ("frameRate", "影片幀率 (fps)", frameRate);
  cmd.AddValue ("gopSize", "GOP 長度（每幾個 frame 一個 I-frame）", gopSize);
  cmd.AddValue ("pFrameBytes", "P-frame 大小 (bytes)", pFrameBytes);
  cmd.AddValue ("iFrameBytes", "I-frame 大小 (bytes)", iFrameBytes);
  cmd.AddValue ("durationSec", "模擬影片長度（秒）", durationSec);
  cmd.AddValue ("fecK", "FEC 來源符號數 K", fecK);
  cmd.AddValue ("fecP", "FEC 修復符號數 P", fecP);
  cmd.AddValue ("lossRate", "封包遺失率 (0.0-1.0)", lossRate);
  cmd.AddValue ("enableFec", "是否啟用 FEC", enableFec);
  cmd.AddValue ("disableRetx", "是否關閉 TCP 式重傳", disableRetx);
  cmd.AddValue ("sndBufSize", "發送端 buffer 大小（bytes）", sndBufSize);
  cmd.Parse (argc, argv);

  g_frameRate   = frameRate;
  g_gopSize     = gopSize;
  g_pFrameBytes = pFrameBytes;
  g_iFrameBytes = iFrameBytes;
  g_totalFrames = static_cast<uint32_t> (durationSec * frameRate);

  Config::SetDefault ("ns3::QuicSocketBase::EnableFec", BooleanValue (enableFec));
  Config::SetDefault ("ns3::QuicSocketBase::FecK", UintegerValue (fecK));
  Config::SetDefault ("ns3::QuicSocketBase::FecP", UintegerValue (fecP));
  Config::SetDefault ("ns3::QuicSocketBase::DisableRetransmission", BooleanValue (disableRetx));
  Config::SetDefault ("ns3::QuicSocketBase::SocketSndBufSize", UintegerValue (sndBufSize));

  Time::SetResolution (Time::NS);
  LogComponentEnableAll (LOG_PREFIX_TIME);
  LogComponentEnableAll (LOG_PREFIX_NODE);
  LogComponentEnable ("QuicSocketBase", LOG_LEVEL_INFO);
  LogComponentEnable ("QuicFecVideoVerify", LOG_LEVEL_INFO);

  NodeContainer nodes;
  nodes.Create (2);
  auto n1 = nodes.Get (0);   // video source
  auto n2 = nodes.Get (1);   // video sink

  PointToPointHelper p2p;
  p2p.SetDeviceAttribute  ("DataRate", StringValue ("5Mbps"));
  p2p.SetChannelAttribute ("Delay",    StringValue ("2ms"));
  NetDeviceContainer devices = p2p.Install (nodes);

  // 封包遺失只套在 source -> sink 方向（sink 的接收端）
  Ptr<RateErrorModel> em = CreateObject<RateErrorModel> ();
  em->SetAttribute ("ErrorRate", DoubleValue (lossRate));
  em->SetAttribute ("ErrorUnit", StringValue ("ERROR_UNIT_PACKET"));
  devices.Get (1)->SetAttribute ("ReceiveErrorModel", PointerValue (em));

  QuicHelper stack;
  stack.InstallQuic (nodes);

  Ipv4AddressHelper address;
  address.SetBase ("10.1.1.0", "255.255.255.0");
  Ipv4InterfaceContainer interfaces = address.Assign (devices);

  uint16_t port = 9;
  double simDuration = durationSec + 10.0;   // 多留 10 秒讓收尾/FEC 復原跑完

  // ── Sink（接收端，只負責收資料計數）──────────────────────────
  Address sinkLocalAddress (InetSocketAddress (Ipv4Address::GetAny (), port));
  PacketSinkHelper sinkHelper ("ns3::QuicSocketFactory", sinkLocalAddress);
  ApplicationContainer sinkApps = sinkHelper.Install (n2);
  sinkApps.Start (Seconds (1.0));
  sinkApps.Stop  (Seconds (simDuration));

  // ── Source（影片串流端）──────────────────────────────────────
  // 不透過 BulkSendApplication，直接用底層 socket + Simulator::Schedule
  // 排程送出，跟 quic-echo-client 的作法一致，天然受 frame interval 節流
  g_sourceNode    = n1;
  g_serverAddress = InetSocketAddress (interfaces.GetAddress (1), port);
  g_serverPort    = port;

  // Sink 要到 t=1.0s 才開始監聽（見 sinkApps.Start 上面），Connect()
  // 一定要晚於這個時間點才有人接，否則 INITIAL 封包送到時沒人在聽，
  // 加上 DisableRetransmission 不會重試，握手就永久卡在 CONNECTING_CLT
  Simulator::Schedule (Seconds (1.5), &StartVideoConnection);
  Simulator::Schedule (Seconds (2.5), &SendVideoFrame);

  uint64_t expectedTotalBytes =
    (uint64_t) (g_totalFrames / gopSize) * iFrameBytes +
    (uint64_t) (g_totalFrames - g_totalFrames / gopSize) * pFrameBytes;

  std::cout << "\n"
            << "╔══════════════════════════════════════════╗\n"
            << "║     QUIC FEC 模擬影片串流測試              ║\n"
            << "╚══════════════════════════════════════════╝\n"
            << "  影片長度  : " << durationSec << " 秒 @ " << frameRate << " fps ("
            << g_totalFrames << " frames)\n"
            << "  GOP       : 每 " << gopSize << " frame 一個 I-frame ("
            << iFrameBytes << " bytes)，其餘 P-frame (" << pFrameBytes << " bytes)\n"
            << "  預期總資料量: " << expectedTotalBytes << " bytes\n"
            << "  發送端 Buffer: " << sndBufSize << " bytes\n"
            << "  FEC 狀態  : " << (enableFec ? "啟用" : "關閉")
            << " (K=" << fecK << " P=" << fecP << ")\n"
            << "  封包遺失率: " << (lossRate * 100) << "%\n"
            << "  重傳機制  : " << (disableRetx ? "關閉" : "啟用") << "\n\n";

  Simulator::Stop (Seconds (simDuration + 5.0));
  Simulator::Run ();

  Ptr<PacketSink> sink = DynamicCast<PacketSink> (sinkApps.Get (0));
  uint64_t totalRx = sink->GetTotalRx ();

  std::cout << "\n"
            << "══════════════ 執行結束 ══════════════\n"
            << "  預期送出   : " << expectedTotalBytes << " bytes\n"
            << "  實際排程送出: " << g_totalBytesQueued << " bytes（Send() 成功回傳的量）\n"
            << "  Sink 實際收到: " << totalRx << " bytes\n"
            << "  送達率     : " << (100.0 * totalRx / expectedTotalBytes) << "%\n";
  if (g_framesSent < g_totalFrames)
    {
      std::cout << "  === 注意：只送出 " << g_framesSent << "/" << g_totalFrames
                << " frames，可能提早卡住 ===\n";
    }
  if (totalRx >= expectedTotalBytes)
    {
      std::cout << "  === RESULT: PASS（影片資料完整送達）===\n\n";
    }
  else
    {
      std::cout << "  === RESULT: INCOMPLETE ===\n\n";
    }

  Simulator::Destroy ();
  return 0;
}
