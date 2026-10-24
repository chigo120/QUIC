#include "route-receiver.h"
#include "ns3/udp-socket-factory.h"
#include "ns3/packet.h"
#include "ns3/log.h"
#include "ns3/simulator.h"
#include "ns3/inet-socket-address.h"
#include <algorithm>
#include <cstdlib>
#include <cmath>
#include "plr_model.h"

static double s_geTargetPlr   = 0.0;
static double s_geSnrParam    = 0.0;
static double s_geDirParam    = 0.0;
static int    s_geUseGilbert  = 0;
static int    s_geState       = 1;

static void GeModelInitForNs3(double packetLossRate, double signalNoiseRate,
                              double dirDiffRate, int useGilbert)
{
  s_geTargetPlr  = packetLossRate;
  s_geSnrParam   = signalNoiseRate;
  s_geDirParam   = dirDiffRate;
  s_geUseGilbert = useGilbert ? 1 : 0;
  s_geState      = 0;
  if (s_geTargetPlr < 0.0) s_geTargetPlr = 0.0;
  if (s_geTargetPlr > 1.0) s_geTargetPlr = 1.0;
  plr_reset_statistics();
}

static int GeModelShouldDrop(int packet_size)
{
  int lost = 0;
  if (s_geUseGilbert) {
    s_geState = gilbert_plr_mod(s_geTargetPlr, s_geState, packet_size);
    lost = (s_geState == 0);
  } else {
    double u = static_cast<double>(std::rand()) / static_cast<double>(RAND_MAX);
    lost = (u < s_geTargetPlr);
  }
  plr_register_packet(lost);
  return lost;
}

namespace ns3 {

NS_LOG_COMPONENT_DEFINE("RouteReceiver");
NS_OBJECT_ENSURE_REGISTERED(RouteReceiver);

TypeId RouteReceiver::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::RouteReceiver")
    .SetParent<Application> ()
    .SetGroupName ("Applications")
    .AddConstructor<RouteReceiver> ();
  return tid;
}

RouteReceiver::RouteReceiver () : m_useFec(true) {
  m_rng = CreateObject<UniformRandomVariable>();
  // 初始化預設值
  m_K = DEFAULT_RAPTORQ_K;
  m_R = DEFAULT_RAPTORQ_R;
}

RouteReceiver::~RouteReceiver () {}

void RouteReceiver::Configure (Address local) { m_local = local; }

void RouteReceiver::SetGeParams (double packetLossRate, double signalNoiseRate,
                                 double dirDiffRate, bool useGilbert)
{
  m_gePacketLossRate = packetLossRate;
  m_geSnr            = signalNoiseRate;
  m_geDir            = dirDiffRate;
  m_geUseGilbert     = useGilbert;
}

void RouteReceiver::StartApplication ()
{
  if (!m_socket)
  {
    m_socket = Socket::CreateSocket (GetNode (), UdpSocketFactory::GetTypeId ());
    m_socket->Bind (m_local);
    m_socket->SetRecvCallback (MakeCallback (&RouteReceiver::HandleRead, this));
  }
  m_totalBlocks         = 0;
  m_failedBlocks        = 0;
  m_totalSourceSymbols  = 0;
  m_failedSourceSymbols = 0;
  GeModelInitForNs3(m_gePacketLossRate, m_geSnr, m_geDir, m_geUseGilbert ? 1 : 0);
}

void RouteReceiver::StopApplication ()
{
  if (m_socket) {
    m_socket->Close ();
    m_socket = nullptr;
  }
  if (m_objects.empty()) {
    NS_LOG_UNCOND("[RESULT] 沒有接收到任何 ROUTE 物件。");
    NS_LOG_UNCOND("[METRIC] before AL-FEC = " << return_actually_plr());
    return;
  }
  
  uint64_t totalRecoveredBytes = 0;
  uint32_t totalFiles = m_objects.size();
  uint32_t failedFiles = 0;

  for (auto &kv : m_objects)
  {
    const ObjectStats &obj = kv.second;
    bool objOk = true;

    // ★ 保持防呆機制
    if (obj.blocks.empty() || obj.objLen == 0) {
        objOk = false;
    }
    
    if (!m_useFec) {
        uint64_t recvSymbols = 0;
        for (auto &bk : obj.blocks) recvSymbols += bk.second.sourceCount;
        uint64_t expectedSymbols = (m_chunkGuess > 0 && obj.objLen > 0) ?
            (obj.objLen + m_chunkGuess - 1) / m_chunkGuess : 0;
        if (recvSymbols < expectedSymbols) objOk = false;
    } 
    else 
    {
        uint64_t blockSizeBytes = static_cast<uint64_t>(m_K) * m_chunkGuess;
        int32_t maxSbn = -1;

        if (obj.objLen > 0 && blockSizeBytes > 0) 
        {
            maxSbn = static_cast<int32_t>((obj.objLen + blockSizeBytes - 1) / blockSizeBytes) - 1;
        }

        for (int32_t sbn = 0; sbn <= maxSbn; ++sbn)
        {
            uint32_t expectedSourceSymbols = m_K;
            uint64_t blockStartOffset = static_cast<uint64_t>(sbn) * blockSizeBytes;
            
            if (blockStartOffset < obj.objLen) {
                uint64_t symbolsLeft = (obj.objLen - blockStartOffset + m_chunkGuess - 1) / m_chunkGuess;
                if (symbolsLeft < m_K) expectedSourceSymbols = static_cast<uint32_t>(symbolsLeft);
            }
            uint32_t real_K = (expectedSourceSymbols == 0) ? 1 : expectedSourceSymbols;

            auto it = obj.blocks.find(sbn);
            m_totalBlocks++; 
            m_totalSourceSymbols += real_K;

            if (it == obj.blocks.end()) { 
                m_failedBlocks++;
                m_failedSourceSymbols += real_K;
                objOk = false;
                continue;
            }

            const BlockStats &bs = it->second;
            uint32_t N = bs.sourceCount + bs.repairCount;

            if (N < real_K) {
                m_failedBlocks++;
                uint32_t lost = (real_K > bs.sourceCount) ? (real_K - bs.sourceCount) : 0;
                m_failedSourceSymbols += lost;
                objOk = false;
            } else {
                bool systematicComplete = (bs.sourceCount >= real_K);
                double ps = systematicComplete ? 1.0 : 
                           ((m_fecType == "Raptor") ? RaptorSuccessProb(N, real_K) : RaptorQSuccessProb(N, real_K));
                
                if (m_rng->GetValue(0.0, 1.0) > ps) {
                    m_failedBlocks++;
                    uint32_t lost = (real_K > bs.sourceCount) ? (real_K - bs.sourceCount) : 0;
                    m_failedSourceSymbols += lost;
                    objOk = false;
                }
            }
        }
    }

    if (objOk) {
        totalRecoveredBytes += obj.objLen;
    } else {
        failedFiles++;
    }
  }

  double duration = 35.0;
  double actPlr = return_actually_plr();
  uint64_t lostPkts = static_cast<uint64_t>(std::round(actPlr * g_plr_total_packet));
  NS_LOG_UNCOND("[METRIC] 總傳輸封包數 = " << g_plr_total_packet);
  NS_LOG_UNCOND("[METRIC] 實際丟棄封包數 = " << lostPkts);
  
  double effectiveBytes = static_cast<double>(totalRecoveredBytes);
  double goodputKbps = (effectiveBytes * 8.0) / (duration * 1000.0);
  double networkThroughputKbps = (g_plr_total_packet * (m_chunkGuess + 97) * 8.0) / (duration * 1000.0);
  double efficiency = (networkThroughputKbps > 0) ? (goodputKbps / networkThroughputKbps) : 0.0;
  NS_LOG_UNCOND("[METRIC] 有效吞吐量 = " << goodputKbps << " kbps");
  NS_LOG_UNCOND("[METRIC] 實際網路吞吐量 = " << networkThroughputKbps << " kbps");
  NS_LOG_UNCOND("[METRIC] 效率 = " << efficiency);
  NS_LOG_UNCOND("[METRIC] before AL-FEC = " << actPlr);
  if (m_useFec && m_totalSourceSymbols > 0) {
      double plrAfter = static_cast<double>(m_failedSourceSymbols) / static_cast<double>(m_totalSourceSymbols);
      double fecOverhead = static_cast<double>(m_R) / static_cast<double>(m_K);
      NS_LOG_UNCOND("[METRIC] after AL-FEC = " << plrAfter);
      NS_LOG_UNCOND("[METRIC] fec_overhead = " << fecOverhead);
      
      uint32_t successBlocks = 0;
      double blockSuccessRate = 1.0;
      if (m_totalBlocks > 0) {
          successBlocks = m_totalBlocks - m_failedBlocks;
          blockSuccessRate = static_cast<double>(successBlocks) / static_cast<double>(m_totalBlocks);
      }
      NS_LOG_UNCOND("[METRIC] 區塊成功率 = " << blockSuccessRate);
      NS_LOG_UNCOND("[METRIC] 成功接收區塊數 = " << successBlocks);
      NS_LOG_UNCOND("[METRIC] 總區塊數 = " << m_totalBlocks);
      
  } else {
      NS_LOG_UNCOND("[METRIC] after AL-FEC = " << actPlr);
      NS_LOG_UNCOND("[METRIC] fec_overhead = 0");
      NS_LOG_UNCOND("[METRIC] 區塊成功率 = 0");
      NS_LOG_UNCOND("[METRIC] 成功接收區塊數 = 0");
      NS_LOG_UNCOND("[METRIC] 總區塊數 = 0");
  }
  
  uint32_t successFiles = totalFiles > failedFiles ? (totalFiles - failedFiles) : 0;
  NS_LOG_UNCOND("[METRIC] 成功還原GoP數 = " << successFiles);
}

void RouteReceiver::HandleRead (Ptr<Socket> socket)
{
  if (m_firstRxTimeSec < 0.0) {
      m_firstRxTimeSec = Simulator::Now().GetSeconds();
  }
  Address from;
  Ptr<Packet> pkt;
  while ((pkt = socket->RecvFrom(from)))
  {
    uint32_t pktSize = pkt->GetSize() + 42;
    
    // ★ 移除 PeekHeader 與 LogRouteRxEv 邏輯，恢復單純丟包判定
    if (GeModelShouldDrop(pktSize)) {
      continue;
    }

    RouteLctFecHeader hdr;
    pkt->RemoveHeader(hdr);
    
    // ★★★ 加上這三行：動態捕捉真實的封包大小 (Chunk Size) ★★★
    if (pkt->GetSize() > m_chunkGuess) {
        m_chunkGuess = pkt->GetSize();
    }
    // ★★★ ============================================ ★★★
    
    const LctHeader &h = hdr.h;
    const SourceFecPayloadId &fec = hdr.fec;
    const FecFrameHeader &ff = hdr.ff;
    ObjectStats &obj = m_objects[h.TOI];
    if (obj.toi == 0) {
      obj.toi = h.TOI;
      obj.objLen = h.extTolPresent ? h.transferLength : 0;
    }
    BlockStats &bs = obj.blocks[ff.sbn];
    if (bs.receivedEsis.find(ff.esi) == bs.receivedEsis.end()) {
        bs.receivedEsis.insert(ff.esi);
        if (ff.symbolType == SYMBOL_SOURCE) bs.sourceCount++;
        else bs.repairCount++;
    }
    if (ff.symbolType == SYMBOL_SOURCE) {
          uint32_t offset = fec.startOffset;
          if (offset < m_objLen) {
            uint32_t remain = static_cast<uint32_t>(m_objLen - offset);
            uint32_t payloadLen = std::min(remain, pkt->GetSize());
            for (uint32_t k = 0; k < payloadLen; ++k) {
              if (!m_received[offset + k]) {
                m_received[offset + k] = true;
                m_receivedCount++;
              }
            }
            if (!m_completed && m_receivedCount >= m_objLen) {
                m_completed = true;
            }
          }
        }
  }
}
}
