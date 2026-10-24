#include "route-sender.h"
#include "ns3/log.h"
#include "ns3/simulator.h"
#include "ns3/udp-socket-factory.h"
#include "ns3/packet.h"
#include "ns3/inet-socket-address.h"
#include "ns3/core-module.h"
#include "route-common.h"
#include <algorithm>

namespace ns3 {
NS_LOG_COMPONENT_DEFINE("RouteSender");
NS_OBJECT_ENSURE_REGISTERED(RouteSender);

TypeId RouteSender::GetTypeId (void) {
  static TypeId tid = TypeId ("ns3::RouteSender")
    .SetParent<Application> ()
    .SetGroupName ("Applications")
    .AddConstructor<RouteSender> ();
  return tid;
}

RouteSender::RouteSender() 
{
  m_totalSentBytes   = 0;
  m_totalSourceBytes = 0;
  m_totalRepairBytes = 0;
  m_firstSendTime    = Seconds(0.0);
  m_lastSendTime     = Seconds(0.0);
  // 建構子中使用預設值
  m_K = DEFAULT_RAPTORQ_K;
  m_R = DEFAULT_RAPTORQ_R;
}
RouteSender::~RouteSender() {}

void RouteSender::Configure(Address dst, uint32_t tsi, uint32_t toi,
                            uint32_t efdtVersion, uint64_t maxTransportSize,
                            uint32_t maxExpiresDeltaSec, std::string fileTemplate,
                            uint32_t chunkSize, RouteCodepoint cp)
{
  m_peer = dst;
  m_lct.TSI = tsi;
  m_baseToi = toi;
  m_lct.TOI = toi;
  m_efdtVersion = efdtVersion;
  m_maxTransportSize = maxTransportSize;
  m_maxExpiresDeltaSec = maxExpiresDeltaSec;
  m_fileTemplate = fileTemplate;
  m_chunkSize = chunkSize;
  m_cp = cp;
  m_lct.CP = cp;

  m_objectSizeList.clear();
  if (m_nominalRateKbps > 0.0)
    {
      const double gopDurationSec = 1.0; 
      uint64_t objSize64 = static_cast<uint64_t>(m_nominalRateKbps * 1000.0 * gopDurationSec / 8.0);
      if (objSize64 == 0) objSize64 = m_chunkSize;

      uint32_t objSize32 = static_cast<uint32_t>(objSize64);
      
      m_objectSizeList.clear();
      m_objectSizeList.push_back(objSize32);
      m_numObjects = m_objectSizeList.size();

      NS_LOG_UNCOND("[CONFIG][VIDEO] bitrate=" << m_nominalRateKbps
                     << " kbps, GoP=" << gopDurationSec
                     << " s, GoP Size=" << objSize32 << " bytes (啟動無限串流模式)");
    }
  else
    {
      const uint32_t LARGE_FILE = 64u * 1024u;
      const uint32_t SMALL_FILE = 12u * 1024u; 
      m_objectSizeList.push_back(LARGE_FILE);
      m_objectSizeList.push_back(SMALL_FILE);
    }

  m_numObjects   = m_objectSizeList.size();
  m_currObjIndex = 0;
  m_objectSize = m_objectSizeList[m_currObjIndex];
  m_lct.extTolPresent  = true;
  m_lct.transferLength = m_objectSize;
}

void RouteSender::StartApplication() {
  if (!m_socket) {
    m_socket = Socket::CreateSocket (GetNode (), UdpSocketFactory::GetTypeId ());
    m_socket->Connect (m_peer);
  }
  
  m_currObjIndex = 0;
  m_lct.TOI      = m_baseToi + m_currObjIndex;
  m_objectSize   = m_objectSizeList[m_currObjIndex];
  m_lct.transferLength = m_objectSize;
  m_sentOffset = 0;
  m_seq = 1;

  EmitEfdtOnce();
  m_lct.extTimePresent = true;
  m_lct.ERTseconds = m_maxExpiresDeltaSec;

  if (!m_useFec) m_R = 0;
  
  m_totalSentBytes = 0;
  m_totalSourceBytes = 0;  
  m_totalRepairBytes = 0;
  m_firstSendTime  = Seconds (0.0);
  m_lastSendTime   = Seconds (0.0);

  m_currSbn = 0;
  m_nextEsi = 0;
  m_sentInBlock = 0;
  m_repairsSentInBlock = 0;
  m_sendingRepairs = false;
  m_sendEvent = Simulator::Schedule (Seconds(m_sendIntervalSec),
                                   &RouteSender::SendNextChunk, this);
}

void RouteSender::StopApplication ()
{
  if (m_socket) {
      m_socket->Close ();
      m_socket = nullptr;
  }
  Simulator::Cancel (m_sendEvent);

  if (m_totalSentBytes > 0 && m_lastSendTime > m_firstSendTime)
    {
      double duration = (m_lastSendTime - m_firstSendTime).GetSeconds ();
      double actualRateBps = static_cast<double>(m_totalSentBytes) * 8.0 / duration;

      NS_LOG_UNCOND("[SENDER] totalBytes=" << m_totalSentBytes
                     << " duration=" << duration << " s"
                     << " actualRate=" << actualRateBps << " bps");
  }
}

void RouteSender::EmitEfdtOnce() {
  if (m_efdtEmitted) return;
  uint64_t now = static_cast<uint64_t>(Simulator::Now().GetSeconds());
  uint64_t expires = now + m_maxExpiresDeltaSec;
  std::string efdt = MakeEfdtXml(m_efdtVersion,
                                 m_maxTransportSize ? m_maxTransportSize : m_objectSize,
                                 m_fileTemplate,
                                 expires);
  NS_LOG_INFO("[EFDT]\n" << efdt);
  m_efdtEmitted = true;
}

void RouteSender::SendNextChunk()
{
  if (!m_socket) return;
  while (m_sentOffset >= m_objectSize && !m_sendingRepairs && m_sentInBlock == 0)
    {
      if (m_nominalRateKbps > 0.0 || m_currObjIndex + 1 < m_numObjects)
        {
          m_currObjIndex++;
          m_lct.TOI = m_baseToi + m_currObjIndex;
          
          m_objectSize = (m_nominalRateKbps > 0.0) ? m_objectSizeList[0] : m_objectSizeList[m_currObjIndex];
          
          m_lct.transferLength = m_objectSize;
          m_sentOffset         = 0;
          m_seq                = 1;
          m_currSbn            = 0;
          m_nextEsi            = 0;
          m_sentInBlock        = 0;
          m_repairsSentInBlock = 0;
          m_sendingRepairs     = false;
        }
      else
        {
          NS_LOG_INFO ("ROUTE all objects complete (last TOI=" << m_lct.TOI << ")");
          return;
        }
    }

  bool     isRepair   = m_sendingRepairs;
  uint32_t payloadLen = 0;

  if (!isRepair)
    {
      if (m_sentOffset >= m_objectSize)
        {
          if (m_useFec && m_sentInBlock > 0 && m_repairsSentInBlock < m_R)
            {
              isRepair       = true;
              m_sendingRepairs = true;
              payloadLen     = m_chunkSize;
            }
          else
            {
              m_sentInBlock = 0;
              m_sendEvent = Simulator::Schedule (Seconds (m_sendIntervalSec),
                                                 &RouteSender::SendNextChunk, this);
              return;
            }
        }
      else
        {
          uint32_t remain = m_objectSize - m_sentOffset;
          payloadLen = std::min (m_chunkSize, remain);
        }
    }

  if (isRepair) payloadLen = m_chunkSize;

  RouteLctFecHeader hdr;
  hdr.h = m_lct;
  if (isRepair) {
      hdr.fec.startOffset = m_objectSize;
      hdr.ff.startOffset  = m_objectSize;
  } else {
      hdr.fec.startOffset = m_sentOffset;
      hdr.ff.startOffset  = m_sentOffset;
  }

  hdr.ff.fecEncodingId = m_fecEncodingId;
  hdr.ff.instanceId    = m_fecInstanceId;
  hdr.ff.sbn           = m_currSbn;
  hdr.ff.esi           = m_nextEsi++;
  hdr.ff.symbolType    = isRepair ? SYMBOL_REPAIR : SYMBOL_SOURCE;

  Ptr<Packet> p = Create<Packet> (payloadLen);
  p->AddHeader (hdr);
  m_socket->Send (p);
  
  Time now = Simulator::Now ();

  if (m_totalSentBytes == 0) m_firstSendTime = now;
  uint32_t pktBytes = p->GetSize();
  m_totalSentBytes += pktBytes;
  m_lastSendTime = now;
  if (isRepair) m_totalRepairBytes += pktBytes;
  else m_totalSourceBytes += pktBytes;

  ++m_seq;
  if (!isRepair)
    {
      m_sentOffset += payloadLen;
      m_sentInBlock++;
      if (m_useFec && m_sentInBlock >= m_K)
        {
          m_sendingRepairs     = true;
          m_repairsSentInBlock = 0;
        }
    }
  else
    {
      m_repairsSentInBlock++;
      if (m_repairsSentInBlock >= m_R)
        {
          m_sendingRepairs     = false;
          m_sentInBlock        = 0;
          m_repairsSentInBlock = 0;
          m_currSbn++;
          m_nextEsi = 0;
        }
    }
  if (m_lct.extTimePresent && m_lct.ERTseconds > 0) m_lct.ERTseconds -= 1;
  m_sendEvent = Simulator::Schedule (Seconds (m_sendIntervalSec),
                                     &RouteSender::SendNextChunk, this);
}
}