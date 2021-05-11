//
// This file is a part of UERANSIM open source project.
// Copyright (c) 2021 ALİ GÜNGÖR.
//
// The software and all associated files are licensed under GPL-3.0
// and subject to the terms and conditions defined in LICENSE file.
//

#include "sm.hpp"
#include <algorithm>
#include <nas/proto_conf.hpp>
#include <nas/utils.hpp>
#include <ue/app/task.hpp>
#include <ue/mm/mm.hpp>

#include <utils/common.hpp> // JK


namespace nr::ue
{

static nas::IE5gSmCapability MakeSmCapability()
{
    nas::IE5gSmCapability cap{};
    cap.rqos = nas::EReflectiveQoS::NOT_SUPPORTED;
    cap.mh6pdu = nas::EMultiHomedIPv6PduSession::NOT_SUPPORTED;
    return cap;
}

static nas::IEIntegrityProtectionMaximumDataRate MakeIntegrityMaxRate(const IntegrityMaxDataRateConfig &config)
{
    nas::IEIntegrityProtectionMaximumDataRate res{};
    res.maxRateDownlink = nas::EMaximumDataRatePerUeForUserPlaneIntegrityProtectionForDownlink::SIXTY_FOUR_KBPS;
    res.maxRateUplink = nas::EMaximumDataRatePerUeForUserPlaneIntegrityProtectionForUplink::SIXTY_FOUR_KBPS;
    if (config.downlinkFull)
        res.maxRateDownlink = nas::EMaximumDataRatePerUeForUserPlaneIntegrityProtectionForDownlink::FULL_DATA_RATE;
    if (config.uplinkFull)
        res.maxRateUplink = nas::EMaximumDataRatePerUeForUserPlaneIntegrityProtectionForUplink::FULL_DATA_RATE;
    return res;
}

void NasSm::sendEstablishmentRequest(const SessionConfig &config)
{
    m_logger->debug("Sending PDU session establishment request");
    m_logger->info("JK### sendPDUSessionEstablishmentRequest @ue IMSI: %s START: %.3f",
                m_base->config->supi->value.c_str(),
                (double)utils::CurrentTimeMicros()/1000);

    /* Control the protocol state */
    if (!m_mm->isRegistered())
    {
        m_logger->err("UE is not registered");
        return;
    }

    /* Control the received config */
    if (config.type != nas::EPduSessionType::IPV4)
    {
        m_logger->err("PDU session type [%s] is not supported", nas::utils::EnumToString(config.type));
        return;
    }
    if (m_mm->isRegisteredForEmergency() && !config.isEmergency)
    {
        m_logger->err("Non-emergency PDU session cannot be requested, UE is registered for emergency only");
        return;
    }
    if (config.isEmergency && anyEmergencySession())
    {
        m_logger->err(
            "Emergency PDU session cannot be requested, another emergency session already established or establishing");
        return;
    }

    /* Allocate PSI */
    int psi = allocatePduSessionId(config);
    if (psi == 0)
        return;

    /* Allocate PTI */
    int pti = allocateProcedureTransactionId();
    if (pti == 0)
    {
        freePduSessionId(psi);
        return;
    }

    /* Set relevant fields of the PS description */
    auto &ps = m_pduSessions[psi];
    ps->psState = EPsState::ACTIVE_PENDING;
    ps->sessionType = config.type;
    ps->apn = config.apn;
    ps->sNssai = config.sNssai;
    ps->isEmergency = config.isEmergency;
    ps->authorizedQoSRules = {};
    ps->sessionAmbr = {};
    ps->authorizedQoSFlowDescriptions = {};
    ps->pduAddress = {};

    /* Make PCO */
    nas::ProtocolConfigurationOptions opt{};
    opt.additionalParams.push_back(std::make_unique<nas::ProtocolConfigurationItem>(
        nas::EProtocolConfigId::CONT_ID_UP_IP_ADDRESS_ALLOCATION_VIA_NAS_SIGNALLING, true, OctetString::Empty()));
    opt.additionalParams.push_back(std::make_unique<nas::ProtocolConfigurationItem>(
        nas::EProtocolConfigId::CONT_ID_DOWN_DNS_SERVER_IPV4_ADDRESS, true, OctetString::Empty()));

    nas::IEExtendedProtocolConfigurationOptions iePco{};
    iePco.configurationProtocol = nas::EConfigurationProtocol::PPP;
    iePco.extension = true;
    iePco.options = opt.encode();

    /* Prepare the establishment request message */
    auto req = std::make_unique<nas::PduSessionEstablishmentRequest>();
    req->pti = pti;
    req->pduSessionId = psi;
    req->integrityProtectionMaximumDataRate = MakeIntegrityMaxRate(m_base->config->integrityMaxRate);
    req->pduSessionType = nas::IEPduSessionType{};
    req->pduSessionType->pduSessionType = nas::EPduSessionType::IPV4;
    req->sscMode = nas::IESscMode{};
    req->sscMode->sscMode = nas::ESscMode::SSC_MODE_1;
    req->extendedProtocolConfigurationOptions = std::move(iePco);
    req->smCapability = MakeSmCapability();

    /* Set relevant fields of the PT, and start T3580 */
    auto &pt = m_procedureTransactions[pti];
    pt.state = EPtState::PENDING;
    pt.timer = newTransactionTimer(3580);
    pt.message = std::move(req);
    pt.psi = psi;

    /* Send SM message */
    sendSmMessage(psi, *pt.message);

    m_logger->info("JK### sendPDUSessionEstablishmentRequest @ue IMSI: %s END: %.3f",
                m_base->config->supi->value.c_str(),
                (double)utils::CurrentTimeMicros()/1000);

    // TO MODIFY: send ==> receive
//     m_logger->info("JK### sendPDUSessionResourceSetupRequest @ue IMSI: %s END: %.3f",
//                     m_base->config->supi->value.c_str(),
//                     (double)utils::CurrentTimeMicros()/1000);
//     m_logger->info("JK### receivePDUSessionResourceSetupResponse @ue IMSI: %s START: %.3f",
//                     m_base->config->supi->value.c_str(),
//                     (double)utils::CurrentTimeMicros()/1000);

    // MERGED TO receivePDUSessionResourceSetupRequest
    // m_logger->info("JK### receivesendPDUSessionEstablishmentAccept @ue IMSI: %s START: %.3f",
    //                 m_base->config->supi->value.c_str(),
    //                 (double)utils::CurrentTimeMicros()/1000);
    m_logger->info("JK### receivePDUSessionResourceSetupRequest(+EstablishmentAccept) @ue IMSI: %s START: %.3f",
                    m_base->config->supi->value.c_str(),
                    (double)utils::CurrentTimeMicros()/1000);
}


void NasSm::receivePduSessionEstablishmentAccept(const nas::PduSessionEstablishmentAccept &msg)
{
    m_logger->debug("PDU Session Establishment Accept received");

    // TO MODIFY recv ==> send and Locations Req ==> Res
    // m_logger->info("JK### receivePDUSessionResourceSetupResponse @ue IMSI: %s END: %.3f",
    //                 m_base->config->supi->value.c_str(),
    //                 (double)utils::CurrentTimeMicros()/1000);

    // MERGED with receivePDUSessionResourceSetupRequest
    // m_logger->info("JK### receivesendPDUSessionEstablishmentAccept @ue IMSI: %s END: %.3f",
    // m_logger->info("JK### receivePDUSessionResourceSetupRequest(+EstablishmentAccept) @ue IMSI: %s END: %.3f",
    //                 m_base->config->supi->value.c_str(),
    //                 (double)utils::CurrentTimeMicros()/1000);


    if (msg.smCause.has_value())
    {
        m_logger->warn("SM cause received in PduSessionEstablishmentAccept [%s]",
                       nas::utils::EnumToString(msg.smCause->value));
    }

    if (msg.pti < ProcedureTransaction::MIN_ID || msg.pti > ProcedureTransaction::MAX_ID)
    {
        // PTI is required for PDU session establishment request
        m_logger->err("Received PTI [%d] value is invalid", msg.pti);
        sendSmCause(nas::ESmCause::INVALID_PTI_VALUE, msg.pduSessionId);
        return;
    }

    if (m_procedureTransactions[msg.pti].psi != msg.pduSessionId)
    {
        m_logger->err("Received PSI value [%d] is invalid, expected was [%d]", msg.pduSessionId,
                      m_procedureTransactions[msg.pti].psi);
        sendSmCause(nas::ESmCause::INVALID_PTI_VALUE, msg.pduSessionId);
        return;
    }

    freeProcedureTransactionId(msg.pti);

    auto& pduSession = m_pduSessions[msg.pduSessionId];
    if (pduSession->psState != EPsState::ACTIVE_PENDING)
    {
        m_logger->err("PS establishment accept received without requested");
        sendSmCause(nas::ESmCause::MESSAGE_TYPE_NOT_COMPATIBLE_WITH_THE_PROTOCOL_STATE, pduSession->psi);
        return;
    }

    pduSession->psState = EPsState::ACTIVE;
    pduSession->authorizedQoSRules = nas::utils::DeepCopyIe(msg.authorizedQoSRules);
    pduSession->sessionAmbr = nas::utils::DeepCopyIe(msg.sessionAmbr);
    pduSession->sessionType = msg.selectedPduSessionType.pduSessionType;

    if (msg.authorizedQoSFlowDescriptions.has_value())
        pduSession->authorizedQoSFlowDescriptions = nas::utils::DeepCopyIe(*msg.authorizedQoSFlowDescriptions);
    else
        pduSession->authorizedQoSFlowDescriptions = {};

    if (msg.pduAddress.has_value())
        pduSession->pduAddress = nas::utils::DeepCopyIe(*msg.pduAddress);
    else
        pduSession->pduAddress = {};

    auto *statusUpdate = new NwUeStatusUpdate(NwUeStatusUpdate::SESSION_ESTABLISHMENT);
    statusUpdate->pduSession = pduSession;
    m_base->appTask->push(statusUpdate);

    m_logger->info("PDU Session establishment is successful PSI[%d]", pduSession->psi);
}

void NasSm::receivePduSessionEstablishmentReject(const nas::PduSessionEstablishmentReject &msg)
{
    m_logger->err("PDU Session Establishment Reject received [%s]", nas::utils::EnumToString(msg.smCause.value));
    // TODO
}

void NasSm::abortEstablishmentRequest(int pti)
{
    int psi = m_procedureTransactions[pti].psi;

    m_logger->debug("PDU Session Establishment Procedure aborted for PTI[%d], PSI[%d]", pti, psi);

    freeProcedureTransactionId(pti);
    freePduSessionId(psi);
}

} // namespace nr::ue