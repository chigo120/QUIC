// route-helper.cc
#include "route-helper.h"
#include "route-sender.h"
#include "route-receiver.h"
#include "ns3/log.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE("RouteHelper");

// ===== RouteSenderHelper =====

RouteSenderHelper::RouteSenderHelper (Address dst,
                                      uint32_t tsi,
                                      uint32_t toi,
                                      uint32_t efdtVersion,
                                      uint64_t maxTransportSize,
                                      uint32_t maxExpiresDeltaSec,
                                      std::string fileTemplate,
                                      uint32_t chunkSize,
                                      RouteCodepoint cp)
  : m_dst (dst),
    m_tsi (tsi),
    m_toi (toi),
    m_efdtVersion (efdtVersion),
    m_maxTransportSize (maxTransportSize),
    m_maxExpiresDeltaSec (maxExpiresDeltaSec),
    m_fileTemplate (fileTemplate),
    m_chunk (chunkSize),
    m_cp (cp),
    m_nominalRateKbps (0.0),
    m_useFec (true),
    m_sendIntervalSec (0.005)
{
}

ApplicationContainer
RouteSenderHelper::Install (NodeContainer c)
{
  ApplicationContainer apps;
  for (NodeContainer::Iterator i = c.Begin (); i != c.End (); ++i)
    {
      apps.Add (InstallPriv (*i));
    }
  return apps;
}

Ptr<Application>
RouteSenderHelper::InstallPriv (Ptr<Node> node)
{
  Ptr<RouteSender> app = CreateObject<RouteSender> ();
  app->SetNominalRateKbps (m_nominalRateKbps);
  app->Configure (m_dst,
                  m_tsi,
                  m_toi,
                  m_efdtVersion,
                  m_maxTransportSize,
                  m_maxExpiresDeltaSec,
                  m_fileTemplate,
                  m_chunk,
                  m_cp);
  app->SetUseFec (m_useFec);
  app->SetSendInterval (m_sendIntervalSec);
  // ★★★ 傳遞參數 ★★★
  app->SetFecParams (m_K, m_R);

  node->AddApplication (app);
  return app;
}

// ===== RouteReceiverHelper =====

RouteReceiverHelper::RouteReceiverHelper (Address local)
  : m_local (local),
    m_cp (CP_MEDIA_FILE),
    m_gePacketLossRate (0.0),
    m_geSnr (-1.0),
    m_geDir (-1.0),
    m_geUseGilbert (false),
    m_useFec (true),
    m_nominalRateKbps (0.0)
{
}

void
RouteReceiverHelper::SetGeParams (double packetLossRate,
                                  double signalNoiseRate,
                                  double dirDiffRate,
                                  bool   useGilbert)
{
  m_gePacketLossRate = packetLossRate;
  m_geSnr            = signalNoiseRate;
  m_geDir            = dirDiffRate;
  m_geUseGilbert     = useGilbert;
}

void
RouteReceiverHelper::SetUseFec (bool useFec)
{
  m_useFec = useFec;
}

ApplicationContainer
RouteReceiverHelper::Install (NodeContainer c)
{
  ApplicationContainer apps;
  for (NodeContainer::Iterator i = c.Begin (); i != c.End (); ++i)
    {
      apps.Add (InstallPriv (*i));
    }
  return apps;
}

void
RouteReceiverHelper::SetFecType (std::string type)
{
  m_fecType = type;
}

Ptr<Application>
RouteReceiverHelper::InstallPriv (Ptr<Node> node)
{
  Ptr<RouteReceiver> app = CreateObject<RouteReceiver> ();
  app->Configure (m_local);
  app->SetGeParams (m_gePacketLossRate,
                    m_geSnr,
                    m_geDir,
                    m_geUseGilbert);
  app->SetFecType (m_fecType);
  app->SetUseFec (m_useFec);
  // ★★★ 傳遞參數 ★★★
  app->SetFecParams (m_K, m_R);
  node->AddApplication (app);
  return app;
}

} // namespace ns3
