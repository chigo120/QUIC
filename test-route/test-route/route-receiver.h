#ifndef ROUTE_RECEIVER_H
#define ROUTE_RECEIVER_H
#include "ns3/application.h"
#include "ns3/ptr.h"
#include "ns3/socket.h"
#include "ns3/address.h"
#include "ns3/type-id.h"
#include "route-common.h"
#include <vector>
#include <unordered_map>
#include "ns3/random-variable-stream.h"
#include "plr_model.h"
#include <set> // 修正 missing include

namespace ns3 {

class RouteReceiver : public Application {
public:
  static TypeId GetTypeId (void);
  RouteReceiver ();
  ~RouteReceiver () override;

  void Configure (Address local);

  void SetGeParams (double packetLossRate,
                    double signalNoiseRate,
                    double dirDiffRate,
                    bool   useGilbert);
  
  void SetUseFec (bool useFec) { m_useFec = useFec; }
  void SetFecType (std::string type) {m_fecType = type;}

  // ★★★ 新增：設定 FEC K, R ★★★
  void SetFecParams(uint16_t k, uint16_t r) {
      m_K = k;
      m_R = r;
  }

protected:
  void StartApplication (void) override;
  void StopApplication (void) override;

private:
  std::string m_fecType = "RaptorQ";
  void HandleRead (Ptr<Socket> socket);

  Ptr<Socket> m_socket;
  Address     m_local;
  
  uint32_t m_tsi = 0;
  uint32_t m_toi = 0;
  uint64_t m_objLen = 0;
  std::vector<bool> m_received;
  uint64_t m_receivedCount = 0;
  bool     m_completed = false;
  uint32_t m_chunkGuess = 0;
  uint64_t m_firstPktWallClock = 0;
  uint64_t m_expires = 0;

  std::unordered_map<uint16_t, uint32_t> m_lastEsiPerSbn;
  
  struct BlockStats {
    uint32_t sourceCount = 0;
    uint32_t repairCount = 0;
    std::set<uint32_t> receivedEsis;
  };

  struct ObjectStats {
    uint32_t toi = 0;
    uint64_t objLen = 0;
    std::unordered_map<uint16_t, BlockStats> blocks;
  };

  std::unordered_map<uint32_t, ObjectStats> m_objects; 
  Ptr<UniformRandomVariable> m_rng;

  double m_gePacketLossRate = 0.0;
  double m_geSnr            = 0.0;
  double m_geDir            = 0.0;
  double m_firstRxTimeSec = -1.0;
  bool   m_geUseGilbert     = false;
  
  bool   m_useFec;
  
  // ★★★ 新增：使用變數記錄 K/R，不再依賴全域常數 ★★★
  uint16_t m_K = DEFAULT_RAPTORQ_K;
  uint16_t m_R = DEFAULT_RAPTORQ_R;

  uint32_t m_totalBlocks = 0;
  uint32_t m_failedBlocks = 0;
  uint64_t m_totalSourceSymbols = 0;
  uint64_t m_failedSourceSymbols = 0;
};

} // namespace ns3
#endif