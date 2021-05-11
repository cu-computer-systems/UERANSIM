//
// This file is a part of UERANSIM open source project.
// Copyright (c) 2021 ALİ GÜNGÖR.
//
// The software and all associated files are licensed under GPL-3.0
// and subject to the terms and conditions defined in LICENSE file.
//

#include "mm.hpp"
#include <asn/rrc/ASN_RRC_EstablishmentCause.h>
#include <nas/utils.hpp>
#include <ue/nas/enc.hpp>
#include <ue/rrc/task.hpp>
#include <ue/sm/sm.hpp>

//JK 
#include <utils/common.hpp>


namespace nr::ue
{

void NasMm::sendNasMessage(const nas::PlainMmMessage &msg)
{
    // TODO trigger on send

    OctetString pdu{};
    if (m_usim->m_currentNsCtx &&
        (m_usim->m_currentNsCtx->integrity != nas::ETypeOfIntegrityProtectionAlgorithm::IA0 ||
         m_usim->m_currentNsCtx->ciphering != nas::ETypeOfCipheringAlgorithm::EA0))
    {
        auto secured = nas_enc::Encrypt(*m_usim->m_currentNsCtx, msg);
        nas::EncodeNasMessage(*secured, pdu);
    }
    else
    {
        nas::EncodeNasMessage(msg, pdu);
    }

    if (m_cmState == ECmState::CM_IDLE)
    {
        auto *nw = new NwUeNasToRrc(NwUeNasToRrc::INITIAL_NAS_DELIVERY);
        nw->nasPdu = std::move(pdu);
        nw->rrcEstablishmentCause = ASN_RRC_EstablishmentCause_mo_Data;
        m_base->rrcTask->push(nw);
    }
    else
    {
        auto *nw = new NwUeNasToRrc(NwUeNasToRrc::UPLINK_NAS_DELIVERY);
        nw->nasPdu = std::move(pdu);
        m_base->rrcTask->push(nw);
    }
}

void NasMm::receiveNasMessage(const nas::NasMessage &msg)
{
    if (msg.epd == nas::EExtendedProtocolDiscriminator::SESSION_MANAGEMENT_MESSAGES)
    {
        m_logger->warn("Bad constructed message received (SM)");
        sendMmStatus(nas::EMmCause::MESSAGE_TYPE_NOT_COMPATIBLE_WITH_PROTOCOL_STATE);
        return;
    }

    auto &mmMsg = (const nas::MmMessage &)msg;

    if (mmMsg.sht == nas::ESecurityHeaderType::NOT_PROTECTED)
    {
        //  If any NAS signalling message is received as not integrity protected even though the secure exchange of NAS
        //  messages has been established by the network, then the NAS shall discard this message
        if (m_usim->m_currentNsCtx)
        {
            m_logger->err(
                "Not integrity protected NAS message received after security establishment. Ignoring received "
                "NAS message");
            return;
        }

        receiveMmMessage((const nas::PlainMmMessage &)mmMsg);
        return;
    }

    auto &securedMm = (const nas::SecuredMmMessage &)mmMsg;

    if (mmMsg.sht == nas::ESecurityHeaderType::INTEGRITY_PROTECTED_WITH_NEW_SECURITY_CONTEXT)
    {
        auto smcMsg = nas::DecodeNasMessage(OctetView{securedMm.plainNasMessage});

        if (smcMsg->epd != nas::EExtendedProtocolDiscriminator::MOBILITY_MANAGEMENT_MESSAGES ||
            (((const nas::MmMessage &)(*smcMsg)).sht != nas::ESecurityHeaderType::NOT_PROTECTED) ||
            (((const nas::PlainMmMessage &)(*smcMsg)).messageType != nas::EMessageType::SECURITY_MODE_COMMAND))
        {
            m_logger->warn("A valid Security Mode Command expected for given SHT. Ignoring received NAS message");
            sendMmStatus(nas::EMmCause::UNSPECIFIED_PROTOCOL_ERROR);
            return;
        }

        receiveMmMessage((const nas::PlainMmMessage &)(*smcMsg));
        return;
    }

    if (mmMsg.sht == nas::ESecurityHeaderType::INTEGRITY_PROTECTED_AND_CIPHERED_WITH_NEW_SECURITY_CONTEXT)
    {
        m_logger->warn("Bad constructed message received (SHT)");
        sendMmStatus(nas::EMmCause::UNSPECIFIED_PROTOCOL_ERROR);
        return;
    }

    if (!m_usim->m_currentNsCtx)
    {
        m_logger->warn("Secured NAS message received while no security context");
        sendMmStatus(nas::EMmCause::MESSAGE_NOT_COMPATIBLE_WITH_PROTOCOL_STATE);
        return;
    }

    auto decrypted = nas_enc::Decrypt(*m_usim->m_currentNsCtx, securedMm);
    if (decrypted == nullptr)
    {
        m_logger->err("MAC mismatch in NAS encryption. Ignoring received NAS Message.");
        sendMmStatus(nas::EMmCause::MAC_FAILURE);
        return;
    }

    auto &innerMsg = *decrypted;
    if (innerMsg.epd == nas::EExtendedProtocolDiscriminator::MOBILITY_MANAGEMENT_MESSAGES)
    {
        auto &innerMm = (const nas::MmMessage &)innerMsg;
        if (innerMm.sht == nas::ESecurityHeaderType::NOT_PROTECTED)
            receiveMmMessage((const nas::PlainMmMessage &)innerMm);
        else
        {
            m_logger->warn("Nested protected NAS messages detected");
            receiveNasMessage(innerMsg);
        }
    }
    else if (innerMsg.epd == nas::EExtendedProtocolDiscriminator::SESSION_MANAGEMENT_MESSAGES)
    {
        m_sm->receiveSmMessage((const nas::SmMessage &)(innerMsg));
    }
    else
    {
        m_logger->warn("Bad constructed message received (EPD)");
        sendMmStatus(nas::EMmCause::MESSAGE_TYPE_NON_EXISTENT_OR_NOT_IMPLEMENTED);
    }
}

void NasMm::receiveMmMessage(const nas::PlainMmMessage &msg)
{
    // TODO: trigger on receive

    switch (msg.messageType)
    {
    case nas::EMessageType::REGISTRATION_ACCEPT:
        m_logger->info("JK*** receiveMmMessage REGISTRATION_ACCEPT IMSI: %s START: %.3f",
                    m_base->config->supi->value.c_str(),
                    (double)utils::CurrentTimeMicros()/1000);
        receiveRegistrationAccept((const nas::RegistrationAccept &)msg);
        m_logger->info("JK*** receiveMmMessage REGISTRATION_ACCEPT IMSI: %s END: %.3f",
                    m_base->config->supi->value.c_str(),
                    (double)utils::CurrentTimeMicros()/1000);
        break;
    case nas::EMessageType::REGISTRATION_REJECT:
        m_logger->info("JK*** receiveMmMessage REGISTRATION_REJECT IMSI: %s START: %.3f",
                    m_base->config->supi->value.c_str(),
                    (double)utils::CurrentTimeMicros()/1000);
        receiveRegistrationReject((const nas::RegistrationReject &)msg);
        m_logger->info("JK*** receiveMmMessage REGISTRATION_REJECT IMSI: %s END: %.3f",
                    m_base->config->supi->value.c_str(),
                    (double)utils::CurrentTimeMicros()/1000);
                    
        break;
    case nas::EMessageType::DEREGISTRATION_ACCEPT_UE_ORIGINATING:
        m_logger->info("JK*** receiveMmMessage DEREGISTRATION_ACCEPT_UE_ORIGINATING IMSI: %s START: %.3f",
                    m_base->config->supi->value.c_str(),
                    (double)utils::CurrentTimeMicros()/1000);
        receiveDeregistrationAccept((const nas::DeRegistrationAcceptUeOriginating &)msg);
        m_logger->info("JK*** receiveMmMessage DEREGISTRATION_ACCEPT_UE_ORIGINATING IMSI: %s END: %.3f",
                    m_base->config->supi->value.c_str(),
                    (double)utils::CurrentTimeMicros()/1000);
                
        
        break;
    case nas::EMessageType::DEREGISTRATION_REQUEST_UE_TERMINATED:
        m_logger->info("JK*** receiveMmMessage DEREGISTRATION_REQUEST_UE_TERMINATED IMSI: %s START: %.3f",
                    m_base->config->supi->value.c_str(),
                    (double)utils::CurrentTimeMicros()/1000);
        receiveDeregistrationRequest((const nas::DeRegistrationRequestUeTerminated &)msg);
        m_logger->info("JK*** receiveMmMessage DEREGISTRATION_REQUEST_UE_TERMINATED IMSI: %s END: %.3f",
                    m_base->config->supi->value.c_str(),
                    (double)utils::CurrentTimeMicros()/1000);
        
        break;
    case nas::EMessageType::SERVICE_REJECT:
        m_logger->info("JK*** receiveMmMessage SERVICE_REJECT IMSI: %s START: %.3f",
                    m_base->config->supi->value.c_str(),
                    (double)utils::CurrentTimeMicros()/1000);
        receiveServiceReject((const nas::ServiceReject &)msg);
        m_logger->info("JK*** receiveMmMessage SERVICE_REJECT IMSI: %s END: %.3f",
                    m_base->config->supi->value.c_str(),
                    (double)utils::CurrentTimeMicros()/1000);
        
        
        break;
    case nas::EMessageType::SERVICE_ACCEPT:
        m_logger->info("JK*** receiveMmMessage SERVICE_ACCEPT IMSI: %s START: %.3f",
                    m_base->config->supi->value.c_str(),
                    (double)utils::CurrentTimeMicros()/1000);
        receiveServiceAccept((const nas::ServiceAccept &)msg);
        m_logger->info("JK*** receiveMmMessage SERVICE_ACCEPT IMSI: %s END: %.3f",
                    m_base->config->supi->value.c_str(),
                    (double)utils::CurrentTimeMicros()/1000);
        
        
        break;
    case nas::EMessageType::CONFIGURATION_UPDATE_COMMAND:
        m_logger->info("JK*** receiveMmMessage receiveConfigurationUpdate @ue IMSI: %s START: %.3f",
                    m_base->config->supi->value.c_str(),
                    (double)utils::CurrentTimeMicros()/1000);
        m_logger->info("JK### receiveConfigurationUpdateCommand @ue IMSI: %s START: %.3f",
                    m_base->config->supi->value.c_str(),
                    (double)utils::CurrentTimeMicros()/1000);
        receiveConfigurationUpdate((const nas::ConfigurationUpdateCommand &)msg);
        m_logger->info("JK*** receiveMmMessage receiveConfigurationUpdate @ue IMSI: %s END: %.3f",
                    m_base->config->supi->value.c_str(),
                    (double)utils::CurrentTimeMicros()/1000);
        // m_logger->info("JK### receiveConfigurationUpdateCommand @ue IMSI: %s END: %.3f",
        //             m_base->config->supi->value.c_str(),
        //             (double)utils::CurrentTimeMicros()/1000);        
        break;
    case nas::EMessageType::AUTHENTICATION_REQUEST:
        m_logger->info("JK*** receiveMmMessage AUTHENTICATION_REQUEST IMSI: %s START: %.3f",
                    m_base->config->supi->value.c_str(),
                    (double)utils::CurrentTimeMicros()/1000);
        receiveAuthenticationRequest((const nas::AuthenticationRequest &)msg);
        m_logger->info("JK*** receiveMmMessage AUTHENTICATION_REQUEST IMSI: %s END: %.3f",
                    m_base->config->supi->value.c_str(),
                    (double)utils::CurrentTimeMicros()/1000);  
        break;
    case nas::EMessageType::AUTHENTICATION_RESPONSE:
        m_logger->info("JK*** receiveMmMessage AUTHENTICATION_RESPONSE IMSI: %s START: %.3f",
                    m_base->config->supi->value.c_str(),
                    (double)utils::CurrentTimeMicros()/1000);
        receiveAuthenticationResponse((const nas::AuthenticationResponse &)msg);
        m_logger->info("JK*** receiveMmMessage AUTHENTICATION_RESPONSE IMSI: %s END: %.3f",
                    m_base->config->supi->value.c_str(),
                    (double)utils::CurrentTimeMicros()/1000);  
        
        break;
    case nas::EMessageType::AUTHENTICATION_REJECT:
        m_logger->info("JK*** receiveMmMessage AUTHENTICATION_REJECT IMSI: %s START: %.3f",
                    m_base->config->supi->value.c_str(),
                    (double)utils::CurrentTimeMicros()/1000);
        receiveAuthenticationReject((const nas::AuthenticationReject &)msg);
        m_logger->info("JK*** receiveMmMessage AUTHENTICATION_REJECT IMSI: %s END: %.3f",
                    m_base->config->supi->value.c_str(),
                    (double)utils::CurrentTimeMicros()/1000);  
        
        break;
    case nas::EMessageType::AUTHENTICATION_RESULT:
        m_logger->info("JK*** receiveMmMessage AUTHENTICATION_RESULT IMSI: %s START: %.3f",
                    m_base->config->supi->value.c_str(),
                    (double)utils::CurrentTimeMicros()/1000);
        receiveAuthenticationResult((const nas::AuthenticationResult &)msg);
        m_logger->info("JK*** receiveMmMessage AUTHENTICATION_RESULT IMSI: %s END: %.3f",
                    m_base->config->supi->value.c_str(),
                    (double)utils::CurrentTimeMicros()/1000);  
        
        break;
    case nas::EMessageType::IDENTITY_REQUEST:
        m_logger->info("JK*** receiveMmMessage IDENTITY_REQUEST IMSI: %s START: %.3f",
                    m_base->config->supi->value.c_str(),
                    (double)utils::CurrentTimeMicros()/1000);
        receiveIdentityRequest((const nas::IdentityRequest &)msg);
        m_logger->info("JK*** receiveMmMessage IDENTITY_REQUEST IMSI: %s END: %.3f",
                    m_base->config->supi->value.c_str(),
                    (double)utils::CurrentTimeMicros()/1000);  
        break;
    case nas::EMessageType::SECURITY_MODE_COMMAND:
        m_logger->info("JK*** receiveMmMessage SECURITY_MODE_COMMAND IMSI: %s START: %.3f",
                    m_base->config->supi->value.c_str(),
                    (double)utils::CurrentTimeMicros()/1000);
        receiveSecurityModeCommand((const nas::SecurityModeCommand &)msg);
        m_logger->info("JK*** receiveMmMessage SECURITY_MODE_COMMAND IMSI: %s END: %.3f",
                    m_base->config->supi->value.c_str(),
                    (double)utils::CurrentTimeMicros()/1000); 
        
        break;
    case nas::EMessageType::FIVEG_MM_STATUS:
        m_logger->info("JK*** receiveMmMessage FIVEG_MM_STATUS IMSI: %s START: %.3f",
                    m_base->config->supi->value.c_str(),
                    (double)utils::CurrentTimeMicros()/1000);
        receiveMmStatus((const nas::FiveGMmStatus &)msg);
        m_logger->info("JK*** receiveMmMessage FIVEG_MM_STATUS IMSI: %s END: %.3f",
                    m_base->config->supi->value.c_str(),
                    (double)utils::CurrentTimeMicros()/1000); 
        
        break;
    case nas::EMessageType::DL_NAS_TRANSPORT:
        m_logger->info("JK*** receiveMmMessage DL_NAS_TRANSPORT IMSI: %s START: %.3f",
                    m_base->config->supi->value.c_str(),
                    (double)utils::CurrentTimeMicros()/1000);
        receiveDlNasTransport((const nas::DlNasTransport &)msg);
        m_logger->info("JK*** receiveMmMessage DL_NAS_TRANSPORT IMSI: %s END: %.3f",
                    m_base->config->supi->value.c_str(),
                    (double)utils::CurrentTimeMicros()/1000); 
        
        
        break;
    default:
        m_logger->err("Unhandled NAS MM message received: %d", (int)msg.messageType);
        break;
    }
}

void NasMm::receiveDlNasTransport(const nas::DlNasTransport &msg)
{
    if (msg.payloadContainerType.payloadContainerType != nas::EPayloadContainerType::N1_SM_INFORMATION)
    {
        m_logger->err("Unhandled DL NAS Transport type: %d", (int)msg.payloadContainerType.payloadContainerType);
        return;
    }

    OctetView buff{msg.payloadContainer.data.data(), static_cast<size_t>(msg.payloadContainer.data.length())};
    auto sm = nas::DecodeNasMessage(buff);
    if (sm->epd != nas::EExtendedProtocolDiscriminator::SESSION_MANAGEMENT_MESSAGES)
    {
        m_logger->err("Bad payload container in DL NAS Transport");
        return;
    }

    m_sm->receiveSmMessage((const nas::SmMessage &)(*sm));
}

void NasMm::sendMmStatus(nas::EMmCause cause)
{
    m_logger->warn("Sending MM Status with cause %s", nas::utils::EnumToString(cause));

    nas::FiveGMmStatus m;
    m.mmCause.value = cause;
    sendNasMessage(m);
}

void NasMm::receiveMmStatus(const nas::FiveGMmStatus &msg)
{
    receiveMmCause(msg.mmCause);
}

void NasMm::receiveMmCause(const nas::IE5gMmCause &msg)
{
    m_logger->err("MM cause received: %s", nas::utils::EnumToString(msg.value));
}

} // namespace nr::ue
