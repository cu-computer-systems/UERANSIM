//
// This file is a part of UERANSIM open source project.
// Copyright (c) 2021 ALİ GÜNGÖR.
//
// The software and all associated files are licensed under GPL-3.0
// and subject to the terms and conditions defined in LICENSE file.
//

#include "task.hpp"
#include "utils.hpp"

#include <gnb/gtp/task.hpp>
#include <gnb/rrc/task.hpp>

#include <asn/ngap/ASN_NGAP_AMF-UE-NGAP-ID.h>
#include <asn/ngap/ASN_NGAP_InitialContextSetupRequest.h>
#include <asn/ngap/ASN_NGAP_InitialContextSetupResponse.h>
#include <asn/ngap/ASN_NGAP_NGAP-PDU.h>
#include <asn/ngap/ASN_NGAP_ProtocolIE-Field.h>
#include <asn/ngap/ASN_NGAP_SuccessfulOutcome.h>
#include <asn/ngap/ASN_NGAP_UE-NGAP-ID-pair.h>
#include <asn/ngap/ASN_NGAP_UE-NGAP-IDs.h>
#include <asn/ngap/ASN_NGAP_UEAggregateMaximumBitRate.h>
#include <asn/ngap/ASN_NGAP_UEContextModificationRequest.h>
#include <asn/ngap/ASN_NGAP_UEContextModificationResponse.h>
#include <asn/ngap/ASN_NGAP_UEContextReleaseCommand.h>
#include <asn/ngap/ASN_NGAP_UEContextReleaseComplete.h>
#include <asn/ngap/ASN_NGAP_UEContextReleaseRequest.h>
#include <asn/ngap/ASN_NGAP_UESecurityCapabilities.h>

namespace nr::gnb
{

void NgapTask::receiveInitialContextSetup(int amfId, ASN_NGAP_InitialContextSetupRequest *msg)
{
    // m_logger->debug("Initial Context Setup Request received");
    // JK
    m_logger->debug("Initial Context Setup Request received, amfId: %d", amfId);

    
    auto *ue = findUeByNgapIdPair(amfId, ngap_utils::FindNgapIdPair(msg));
    if (ue == nullptr)
        return;

    // MERGED WITH receiveRegistrationAccept @ue
    // m_logger->info("JK### receiveInitialContextSetupRequest @gNB ueId: %d END: %.3f", ue->ctxId, (double)utils::CurrentTimeMicros()/1000);
    m_logger->info("JK### receiveInitialContextSetupRequest(+RegistrationAccept) @gNB ueId: %d END: %.3f", 
                ue->ctxId, (double)utils::CurrentTimeMicros()/1000);

    m_logger->info("JK### sendInitialContextSetupResponse @gNB ueId: %d START: %.3f", 
                ue->ctxId, (double)utils::CurrentTimeMicros()/1000);


    auto *ie = asn::ngap::GetProtocolIe(msg, ASN_NGAP_ProtocolIE_ID_id_UEAggregateMaximumBitRate);
    if (ie)
    {
        ue->ueAmbr.dlAmbr = asn::GetUnsigned64(ie->UEAggregateMaximumBitRate.uEAggregateMaximumBitRateDL) / 8ull;
        ue->ueAmbr.ulAmbr = asn::GetUnsigned64(ie->UEAggregateMaximumBitRate.uEAggregateMaximumBitRateUL) / 8ull;
    }

    auto *response = asn::ngap::NewMessagePdu<ASN_NGAP_InitialContextSetupResponse>({});
    sendNgapUeAssociated(ue->ctxId, response);

    m_logger->info("JK### sendInitialContextSetupResponse @gNB ueId: %d END: %.3f", ue->ctxId, (double)utils::CurrentTimeMicros()/1000);
    // TO DELETE: recv PDU resource ==> send PUD Est. Request
    // m_logger->info("JK### receivePDUSessionResourceSetupRequest @gNB ueId: %d START: %.3f", ue->ctxId, (double)utils::CurrentTimeMicros()/1000);

    // Other possible following steps
    // Send registration complete
    // Recv Configuration Update command
    // Send PDU Session Establish Request

    ie = asn::ngap::GetProtocolIe(msg, ASN_NGAP_ProtocolIE_ID_id_NAS_PDU);
    if (ie)
        deliverDownlinkNas(ue->ctxId, asn::GetOctetString(ie->NAS_PDU));

    auto *w = new NwGnbNgapToGtp(NwGnbNgapToGtp::UE_CONTEXT_UPDATE);
    w->update = std::make_unique<GtpUeContextUpdate>(true, ue->ctxId, ue->ueAmbr);
    m_base->gtpTask->push(w);
}

void NgapTask::receiveContextRelease(int amfId, ASN_NGAP_UEContextReleaseCommand *msg)
{
    auto *ue = findUeByNgapIdPair(amfId, ngap_utils::FindNgapIdPairFromUeNgapIds(msg));

    m_logger->debug("UE Context Release Command received");
    m_logger->info("JK### receiveContextReleaseCommand @gNB ueId: %d END: %.3f", ue->ctxId, (double)utils::CurrentTimeMicros()/1000);
    m_logger->info("JK### sendContextReleaseComplete @gNB ueId: %d START: %.3f", ue->ctxId, (double)utils::CurrentTimeMicros()/1000);

    if (ue == nullptr)
        return;

    // Notify RRC task
    auto *w1 = new NwGnbNgapToRrc(NwGnbNgapToRrc::AN_RELEASE);
    w1->ueId = ue->ctxId;
    m_base->rrcTask->push(w1);

    // Notify GTP task
    auto *w2 = new NwGnbNgapToGtp(NwGnbNgapToGtp::UE_CONTEXT_RELEASE);
    w2->ueId = ue->ctxId;
    m_base->gtpTask->push(w2);

    auto *response = asn::ngap::NewMessagePdu<ASN_NGAP_UEContextReleaseComplete>({});
    sendNgapUeAssociated(ue->ctxId, response);

    m_logger->info("JK### sendContextReleaseComplete @gNB ueId: %d END: %.3f", ue->ctxId, (double)utils::CurrentTimeMicros()/1000);

    deleteUeContext(ue->ctxId);
}

void NgapTask::receiveContextModification(int amfId, ASN_NGAP_UEContextModificationRequest *msg)
{
    m_logger->debug("UE Context Modification Request received");

    auto *ue = findUeByNgapIdPair(amfId, ngap_utils::FindNgapIdPair(msg));
    if (ue == nullptr)
        return;

    auto *ie = asn::ngap::GetProtocolIe(msg, ASN_NGAP_ProtocolIE_ID_id_UEAggregateMaximumBitRate);
    if (ie)
    {
        ue->ueAmbr.dlAmbr = asn::GetUnsigned64(ie->UEAggregateMaximumBitRate.uEAggregateMaximumBitRateDL);
        ue->ueAmbr.ulAmbr = asn::GetUnsigned64(ie->UEAggregateMaximumBitRate.uEAggregateMaximumBitRateUL);
    }

    ie = asn::ngap::GetProtocolIe(msg, ASN_NGAP_ProtocolIE_ID_id_NewAMF_UE_NGAP_ID);
    if (ie)
    {
        int64_t old = ue->amfUeNgapId;
        ue->amfUeNgapId = asn::GetSigned64(ie->AMF_UE_NGAP_ID_1);
        m_logger->debug("AMF-UE-NGAP-ID changed from %ld to %ld", old, ue->amfUeNgapId);
    }

    auto *response = asn::ngap::NewMessagePdu<ASN_NGAP_UEContextModificationResponse>({});
    sendNgapUeAssociated(ue->ctxId, response);

    auto *w = new NwGnbNgapToGtp(NwGnbNgapToGtp::UE_CONTEXT_UPDATE);
    w->update = std::make_unique<GtpUeContextUpdate>(false, ue->ctxId, ue->ueAmbr);
    m_base->gtpTask->push(w);
}

void NgapTask::sendContextRelease(int ueId, NgapCause cause)
{
    m_logger->info("JK### sendContextReleaseRequest @gNB ueId: %d START: %.3f", ueId, (double)utils::CurrentTimeMicros()/1000);
    m_logger->debug("Sending UE Context release request (NG-RAN node initiated)");

    auto *ieCause = asn::New<ASN_NGAP_UEContextReleaseRequest_IEs>();
    ieCause->id = ASN_NGAP_ProtocolIE_ID_id_Cause;
    ieCause->criticality = ASN_NGAP_Criticality_ignore;
    ieCause->value.present = ASN_NGAP_UEContextReleaseRequest_IEs__value_PR_Cause;
    ngap_utils::ToCauseAsn_Ref(cause, ieCause->value.choice.Cause);

    auto *pdu = asn::ngap::NewMessagePdu<ASN_NGAP_UEContextReleaseRequest>({ieCause});
    sendNgapUeAssociated(ueId, pdu);
    m_logger->info("JK### sendContextReleaseRequest @gNB ueId: %d END: %.3f", ueId, (double)utils::CurrentTimeMicros()/1000);
    m_logger->info("JK### receiveContextReleaseCommand @gNB ueId: %d START: %.3f", ueId, (double)utils::CurrentTimeMicros()/1000);
}

} // namespace nr::gnb