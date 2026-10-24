#ifndef ROUTE_SENDER_H
#define ROUTE_SENDER_H

#include "ns3/application.h"
#include "ns3/address.h"
#include "ns3/ptr.h"
#include "ns3/socket.h"
#include "ns3/event-id.h"
#include "ns3/type-id.h"
#include "route-common.h"
#include <vector>
#include "ns3/nstime.h"  

namespace ns3 {

class RouteSender : public Application {
public:
  static TypeId GetTypeId (void);
  RouteSender ();
  ~RouteSender () override;

  void Configure (Address dst, uint32_t tsi, uint32_t toi,
                  uint32_t efdtVersion, uint64_t maxTransportSize,
                  uint32_t maxExpiresDeltaSec, std::string fileTemplate,
                  uint32_t chunkSize, RouteCodepoint cp = CP_MEDIA_FILE);
  
  void SetUseFec (bool useFec) { m_useFec = useFec; }
  void SetSendInterval (double sec) { m_sendIntervalSec = sec; }
  void SetNominalRateKbps (double r) { m_nominalRateKbps = r; }

  // ★★★ 新增：允許設定 FEC 參數 (K, R) ★★★
  void SetFecParams(uint16_t k, uint16_t r) {
      m_K = k;
      m_R = r;
  }

protected:
  void StartApplication (void) override;
  void StopApplication (void) override;

private:
  void SendNextChunk ();
  void EmitEfdtOnce ();

  Ptr<Socket> m_socket;
  Address     m_peer;

  LctHeader   m_lct;
  SourceFecPayloadId m_fec;
  
  uint32_t m_chunkSize = 1200;
  uint32_t m_objectSize = 12800;
  uint32_t m_sentOffset = 0;
  uint32_t m_seq = 1;
  std::vector<uint32_t> m_objectSizeList;
  uint32_t              m_currObjIndex = 0;
  uint32_t              m_numObjects   = 1;
  uint32_t              m_baseToi      = 0;

  bool      m_efdtEmitted = false;
  uint32_t  m_efdtVersion = 1;
  uint64_t  m_maxTransportSize = 0;
  uint32_t  m_maxExpiresDeltaSec = 6;
  std::string m_fileTemplate = "media$TOI%05d$.m4s";

  EventId   m_sendEvent;
  RouteCodepoint m_cp = CP_MEDIA_FILE;

  uint8_t  m_fecEncodingId = 130; 
  uint8_t  m_fecInstanceId = 0;
  
  // ★★★ 修正：使用變數而非 const ★★★
  uint16_t m_K = DEFAULT_RAPTORQ_K;
  uint16_t m_R = DEFAULT_RAPTORQ_R;

  uint16_t m_currSbn           = 0;
  uint32_t m_nextEsi           = 0;
  uint16_t m_sentInBlock       = 0;
  bool     m_sendingRepairs    = false;
  uint16_t m_repairsSentInBlock= 0;

  bool     m_useFec = true;
  double   m_sendIntervalSec = 0.005;

  uint64_t m_totalSentBytes = 0;
  uint64_t m_totalSourceBytes;
  uint64_t m_totalRepairBytes;
  Time     m_firstSendTime;
  Time     m_lastSendTime;       
  double   m_nominalRateKbps = 0.0;
};

} // namespace ns3

#endif