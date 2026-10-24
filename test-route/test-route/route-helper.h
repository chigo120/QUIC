#ifndef ROUTE_HELPER_H
#define ROUTE_HELPER_H

#include <string>
#include "ns3/ptr.h" 
#include "ns3/application.h"
#include "ns3/application-container.h"
#include "ns3/node-container.h"
#include "ns3/address.h"
#include "route-common.h"

namespace ns3 {

class RouteSenderHelper {
public:
  RouteSenderHelper (Address dst, uint32_t tsi, uint32_t toi,
                     uint32_t efdtVersion, uint64_t maxTransportSize,
                     uint32_t maxExpiresDeltaSec, std::string fileTemplate,
                     uint32_t chunkSize, RouteCodepoint cp = CP_MEDIA_FILE);
  ApplicationContainer Install (NodeContainer c);

  void SetNominalRateKbps (double kbps) { m_nominalRateKbps = kbps; }
  void SetUseFec          (bool useFec) { m_useFec          = useFec; }
  void SetSendInterval    (double sec)  { m_sendIntervalSec = sec; }
  
  // ★★★ 新增：Helper 設定函式 ★★★
  void SetFecParams (uint16_t k, uint16_t r) { m_K = k; m_R = r; }

private:
  Ptr<Application> InstallPriv (Ptr<Node> node);

  Address       m_dst;
  uint32_t      m_tsi;
  uint32_t      m_toi;
  uint32_t      m_efdtVersion;
  uint64_t      m_maxTransportSize;
  uint32_t      m_maxExpiresDeltaSec;
  std::string   m_fileTemplate;
  uint32_t      m_chunk;
  RouteCodepoint m_cp;
  double        m_nominalRateKbps;
  bool          m_useFec;
  double        m_sendIntervalSec;
  
  // ★★★ 新增 ★★★
  uint16_t m_K = DEFAULT_RAPTORQ_K;
  uint16_t m_R = DEFAULT_RAPTORQ_R;
};

class RouteReceiverHelper {
public:
  explicit RouteReceiverHelper (Address local);
  void SetGeParams (double packetLossRate,
                    double signalNoiseRate,
                    double dirDiffRate,
                    bool   useGilbert);
  void SetUseFec (bool useFec); 
  void SetFecType (std::string type);
  void SetNominalRateKbps (double r) { m_nominalRateKbps = r; }
  
  // ★★★ 新增 ★★★
  void SetFecParams (uint16_t k, uint16_t r) { m_K = k; m_R = r; }

  ApplicationContainer Install (NodeContainer c);
  
private:
  Ptr<Application> InstallPriv (Ptr<Node> node);
  Address m_local;
  RouteCodepoint m_cp;
  double m_gePacketLossRate;
  double m_geSnr;
  double m_geDir;
  bool   m_geUseGilbert;
  bool   m_useFec;
  std::string m_fecType = "RaptorQ";
  double m_nominalRateKbps = 0.0;

  // ★★★ 新增 ★★★
  uint16_t m_K = DEFAULT_RAPTORQ_K;
  uint16_t m_R = DEFAULT_RAPTORQ_R;
};

} // namespace ns3
#endif