/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * FEC + 發送端 Buffer 壓力測試
 *
 * 測試目的：
 *   quic-fec-verify.cc 用的是小訊息 echo（總資料量遠小於 128KB 的
 *   SocketSndBufSize），不可能重現「發送端 buffer 滿」的情境。
 *   這支測試改用 BulkSendHelper 持續灌資料（預設 300KB，大於預設
 *   128KB 的發送端 buffer），搭配 FEC + 封包遺失，觀察：
 *     1. 發送端 tx buffer 是否真的被塞滿（QuicSocketTxBuffer::Add
 *        會印出 "Rejected. Not enough room to buffer packet."）
 *     2. 最終 Sink 收到的位元組數是否等於 Source 送出的位元組數
 *     3. 模擬是否能正常結束，還是卡死/abort
 *
 * 執行方式：
 *   ./waf --run "quic-fec-bulksend-verify --maxBytes=300000 --lossRate=0.10"
 */

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/quic-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/applications-module.h"
#include <iostream>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("QuicFecBulksendVerify");

int
main (int argc, char *argv[])
{
  // ── 可調參數 ──────────────────────────────────────────────────
  uint64_t maxBytes   = 300000;   // 要傳送的總位元組數（> 128KB 預設 buffer）
  uint32_t fecK       = 10;
  uint32_t fecP       = 4;
  double   lossRate   = 0.10;
  bool     enableFec  = true;
  bool     disableRetx = true;
  double   simDuration = 60.0;
  uint32_t sndBufSize  = 131072;  // 預設 128KB，可調大以對照驗證

  CommandLine cmd;
  cmd.AddValue ("maxBytes", "要傳送的總位元組數", maxBytes);
  cmd.AddValue ("fecK", "FEC 來源符號數 K", fecK);
  cmd.AddValue ("fecP", "FEC 修復符號數 P", fecP);
  cmd.AddValue ("lossRate", "封包遺失率 (0.0-1.0)", lossRate);
  cmd.AddValue ("enableFec", "是否啟用 FEC", enableFec);
  cmd.AddValue ("disableRetx", "是否關閉 TCP 式重傳", disableRetx);
  cmd.AddValue ("simDuration", "模擬總時長（秒）", simDuration);
  cmd.AddValue ("sndBufSize", "發送端 buffer 大小（bytes）", sndBufSize);
  cmd.Parse (argc, argv);

  Config::SetDefault ("ns3::QuicSocketBase::EnableFec", BooleanValue (enableFec));
  Config::SetDefault ("ns3::QuicSocketBase::FecK", UintegerValue (fecK));
  Config::SetDefault ("ns3::QuicSocketBase::FecP", UintegerValue (fecP));
  Config::SetDefault ("ns3::QuicSocketBase::DisableRetransmission", BooleanValue (disableRetx));
  Config::SetDefault ("ns3::QuicSocketBase::SocketSndBufSize", UintegerValue (sndBufSize));

  Time::SetResolution (Time::NS);
  LogComponentEnableAll (LOG_PREFIX_TIME);
  LogComponentEnableAll (LOG_PREFIX_NODE);
  LogComponentEnable ("QuicSocketBase", LOG_LEVEL_INFO);
  LogComponentEnable ("QuicSocketTxBuffer", LOG_LEVEL_WARN);

  NodeContainer nodes;
  nodes.Create (2);
  auto n1 = nodes.Get (0);   // source
  auto n2 = nodes.Get (1);   // sink

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

  // ── Sink（接收端） ───────────────────────────────────────────
  Address sinkLocalAddress (InetSocketAddress (Ipv4Address::GetAny (), port));
  PacketSinkHelper sinkHelper ("ns3::QuicSocketFactory", sinkLocalAddress);
  ApplicationContainer sinkApps = sinkHelper.Install (n2);
  sinkApps.Start (Seconds (1.0));
  sinkApps.Stop  (Seconds (simDuration));

  // ── Source（發送端，持續灌資料）───────────────────────────────
  BulkSendHelper bulkSend ("ns3::QuicSocketFactory",
                            InetSocketAddress (interfaces.GetAddress (1), port));
  bulkSend.SetAttribute ("MaxBytes", UintegerValue (maxBytes));
  bulkSend.SetAttribute ("SendSize", UintegerValue (1400));
  ApplicationContainer sourceApps = bulkSend.Install (n1);
  sourceApps.Start (Seconds (2.0));
  sourceApps.Stop  (Seconds (simDuration));

  std::cout << "\n"
            << "╔══════════════════════════════════════════╗\n"
            << "║     QUIC FEC 發送端 Buffer 壓力測試        ║\n"
            << "╚══════════════════════════════════════════╝\n"
            << "  傳送總量  : " << maxBytes << " bytes\n"
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
            << "  Source 應送出: " << maxBytes << " bytes\n"
            << "  Sink 實際收到: " << totalRx   << " bytes\n"
            << "  完整度       : " << (100.0 * totalRx / maxBytes) << "%\n";
  if (totalRx >= maxBytes)
    {
      std::cout << "  === RESULT: PASS（資料完整送達）===\n\n";
    }
  else
    {
      std::cout << "  === RESULT: INCOMPLETE（資料未完整送達，可能卡住）===\n\n";
    }

  Simulator::Destroy ();
  return 0;
}
