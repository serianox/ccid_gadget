/*
 * Copyright (C) 2009 Frank Morgner
 *
 * This file is part of ccid.
 *
 * ccid is free software: you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later
 * version.
 *
 * ccid is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * ccid.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <asm/byteorder.h>
#include <libopensc/errors.h>
#include <libopensc/log.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ccid.h"

// TODO
//#define sc_debug(level, format, args...) fprintf(stderr, format, ## args)
#define bin_log(level, format, args...) fprintf(stderr, format, ## args)
//#define SC_FUNC_RETURN(level, r) do { return r; } while(0)
// TODO maybe include pcsc?
#define SC_PROTO_T0		0x00000001
#define SC_PROTO_T1		0x00000002
/* reader flags */
#define SC_READER_CARD_PRESENT		0x00000001
#define SC_READER_CARD_CHANGED		0x00000002
#define SC_READER_CARD_INUSE		0x00000004
#define SC_READER_CARD_EXCLUSIVE	0x00000008
#define SC_READER_HAS_WAITING_AREA	0x00000010
#define SC_READER_REMOVED			0x00000020
#define SC_READER_ENABLE_ESCAPE		0x00000040

/* reader capabilities */
#define SC_READER_CAP_DISPLAY	0x00000001
#define SC_READER_CAP_PIN_PAD	0x00000002
#define SC_READER_CAP_PACE_EID             0x00000004
#define SC_READER_CAP_PACE_ESIGN           0x00000008
#define SC_READER_CAP_PACE_DESTROY_CHANNEL 0x00000010
#define SC_READER_CAP_PACE_GENERIC         0x00000020

static int
perform_PC_to_RDR_GetSlotStatus(const __u8 *in, size_t inlen, __u8 **out, size_t *outlen);
static int
perform_PC_to_RDR_IccPowerOn(const __u8 *in, size_t inlen, __u8 **out, size_t *outlen);
static int
perform_PC_to_RDR_IccPowerOff(const __u8 *in, size_t inlen, __u8 **out, size_t *outlen);
static int
perform_pseudo_apdu(const __u8 *in, size_t inlen, __u8 **out, size_t *outlen);
static int
perform_PC_to_RDR_XfrBlock(const __u8 *in, size_t inlen, __u8** out, size_t *outlen);
static int
perform_PC_to_RDR_GetParamters(const __u8 *in, size_t inlen, __u8** out, size_t *outlen);
static int
perform_unknown(const __u8 *in, size_t inlen, __u8 **out, size_t *outlen);

struct ccid_class_descriptor
ccid_desc = {
    .bLength                = sizeof ccid_desc,
    .bDescriptorType        = 0x21,
    .bcdCCID                = __constant_cpu_to_le16(0x0110),
    .bMaxSlotIndex          = 0,
    .bVoltageSupport        = 0x01,  // 5.0V
    .dwProtocols            = __constant_cpu_to_le32(
                              0x01|  // T=0
                              0x02), // T=1
    .dwDefaultClock         = __constant_cpu_to_le32(0xDFC),
    .dwMaximumClock         = __constant_cpu_to_le32(0xDFC),
    .bNumClockSupport       = 1,
    .dwDataRate             = __constant_cpu_to_le32(0x2580),
    .dwMaxDataRate          = __constant_cpu_to_le32(0x2580),
    .bNumDataRatesSupported = 1,
    .dwMaxIFSD              = __constant_cpu_to_le32(0xFF), // IFSD is handled by the real reader driver
    .dwSynchProtocols       = __constant_cpu_to_le32(0),
    .dwMechanical           = __constant_cpu_to_le32(0),
    .dwFeatures             = __constant_cpu_to_le32(
                              0x00000002|  // Automatic parameter configuration based on ATR data
                              0x00000004|  // Automatic activation of ICC on inserting
                              0x00000008|  // Automatic ICC voltage selection
                              0x00000010|  // Automatic ICC clock frequency change
                              0x00000020|  // Automatic baud rate change
                              0x00000040|  // Automatic parameters negotiation
                              0x00000080|  // Automatic PPS   
                              0x00000400|  // Automatic IFSD exchange as first exchange
                              0x00040000|  // Short and Extended APDU level exchange with CCID
                              0x00100000), // USB Wake up signaling supported
    .dwMaxCCIDMessageLength = __constant_cpu_to_le32(CCID_EXT_APDU_MAX),
    .bClassGetResponse      = 0xFF,
    .bclassEnvelope         = 0xFF,
    .wLcdLayout             = __constant_cpu_to_le16(
                              0x0000|   // Number of lines for the LCD display
                              0x0000),  // Number of characters per line
    .bPINSupport            = 0,
    .bMaxCCIDBusySlots      = 0x01,
};

#define debug_sc_result(sc_result) \
{ \
    if (sc_result < 0) \
        sc_debug(SC_LOG_DEBUG_VERBOSE, sc_strerror(sc_result)); \
    else \
        sc_debug(SC_LOG_DEBUG_NORMAL, sc_strerror(sc_result)); \
}

int ccid_initialize(int reader_id, int verbose)
{
    return SC_SUCCESS;
}

void ccid_shutdown(void)
{
    return;
}

static int get_rapdu(const __u8 *in, size_t inlen, __u8** out, size_t *outlen)
{
    int sc_result;

    if (!out || !outlen || !in) {
        sc_result = SC_ERROR_INVALID_ARGUMENTS;
        goto err;
    }

    if (0) { // check CLA 0xFF
        sc_result = perform_pseudo_apdu(NULL, 0, NULL, NULL);
    } else {
        sc_result = SC_SUCCESS;
        //sc_result = sc_transmit_apdu(card, apdu);
    }
    if (sc_result < 0) {
        goto err;
    }

    // check SW1 is valid (0x6Y or 0x9Y)

    sc_result = SC_SUCCESS;

err:
    return sc_result;
}

static __u8 get_bError(int sc_result)
{
    if (sc_result < 0) {
        switch (sc_result) {
            case SC_ERROR_KEYPAD_TIMEOUT:
                return CCID_BERROR_PIN_TIMEOUT;

            case SC_ERROR_KEYPAD_CANCELLED:
                return CCID_BERROR_PIN_CANCELLED;

            case SC_ERROR_EVENT_TIMEOUT:
            case SC_ERROR_CARD_UNRESPONSIVE:
                return CCID_BERROR_ICC_MUTE;

            default:
                return CCID_BERROR_HW_ERROR;
        }
    } else
        return CCID_BERROR_OK;
}

static __u8 get_bStatus(int sc_result)
{
    int flags;
    __u8 bstatus = 0;

    if (flags >= 0) {
        if (sc_result < 0) {
            if (flags & SC_READER_CARD_PRESENT) {
                if (flags & SC_READER_CARD_CHANGED) {
                    sc_debug(SC_LOG_DEBUG_NORMAL, "error inactive");
                    bstatus = CCID_BSTATUS_ERROR_INACTIVE;
                } else {
                    sc_debug(SC_LOG_DEBUG_NORMAL, "error active");
                    bstatus = CCID_BSTATUS_ERROR_ACTIVE;
                }
            } else {
                sc_debug(SC_LOG_DEBUG_NORMAL, "error no icc");
                bstatus = CCID_BSTATUS_ERROR_NOICC;
            }
        } else {
            if (flags & SC_READER_CARD_PRESENT) {
                if (flags & SC_READER_CARD_CHANGED) {
                    sc_debug(SC_LOG_DEBUG_NORMAL, "ok inactive");
                    bstatus = CCID_BSTATUS_OK_INACTIVE;
                } else {
                    sc_debug(SC_LOG_DEBUG_NORMAL, "ok active");
                    bstatus = CCID_BSTATUS_OK_ACTIVE;
                }
            } else {
                sc_debug(SC_LOG_DEBUG_NORMAL, "ok no icc");
                bstatus = CCID_BSTATUS_OK_NOICC;
            }
        }
    } else {
        debug_sc_result(flags);
        sc_debug(SC_LOG_DEBUG_VERBOSE, "Could not detect card presence."
                " Falling back to default (bStatus=0x%02X).", bstatus);
    }

    return bstatus;
}

static int
get_RDR_to_PC_SlotStatus(__u8 bSeq, int sc_result, __u8 **outbuf, size_t *outlen,
        const __u8 *abProtocolDataStructure, size_t abProtocolDataStructureLen)
{
    if (!outbuf)
        return SC_ERROR_INVALID_ARGUMENTS;
    if (abProtocolDataStructureLen > 0xffff) {
        sc_debug(SC_LOG_DEBUG_VERBOSE, "abProtocolDataStructure %u bytes too long",
                abProtocolDataStructureLen-0xffff);
        return SC_ERROR_INVALID_DATA;
    }

    RDR_to_PC_SlotStatus_t *status = realloc(*outbuf, sizeof(*status) + abProtocolDataStructureLen);
    if (!status)
        return SC_ERROR_OUT_OF_MEMORY;
    *outbuf = (__u8 *) status;
    *outlen = sizeof(*status) + abProtocolDataStructureLen;

    status->bMessageType = 0x81;
    status->dwLength     = __constant_cpu_to_le32(abProtocolDataStructureLen);
    status->bSlot        = 0;
    status->bSeq         = bSeq;
    status->bStatus      = get_bStatus(sc_result);
    status->bError       = get_bError(sc_result);
    status->bClockStatus = 0;

    /* Flawfinder: ignore */
    memcpy((*outbuf) + sizeof(*status), abProtocolDataStructure, abProtocolDataStructureLen);

    return SC_SUCCESS;
}

static int
get_RDR_to_PC_DataBlock(__u8 bSeq, int sc_result, __u8 **outbuf,
        size_t *outlen, const __u8 *abData, size_t abDataLen)
{
    if (!outbuf)
        return SC_ERROR_INVALID_ARGUMENTS;
    if (abDataLen > 0xffff) {
        sc_debug(SC_LOG_DEBUG_VERBOSE, "abProtocolDataStructure %u bytes too long",
                abDataLen-0xffff);
        return SC_ERROR_INVALID_DATA;
    }

    RDR_to_PC_DataBlock_t *data = realloc(*outbuf, sizeof(*data) + abDataLen);
    if (!data)
        return SC_ERROR_OUT_OF_MEMORY;
    *outbuf = (__u8 *) data;
    *outlen = sizeof(*data) + abDataLen;

    data->bMessageType    = 0x80;
    data->dwLength        = __constant_cpu_to_le32(abDataLen);
    data->bSlot           = 0;
    data->bSeq            = bSeq;
    data->bStatus         = get_bStatus(sc_result);
    data->bError          = get_bError(sc_result);
    data->bChainParameter = 0;

    /* Flawfinder: ignore */
    memcpy((*outbuf) + sizeof(*data), abData, abDataLen);

    return SC_SUCCESS;
}

static int
perform_PC_to_RDR_GetSlotStatus(const __u8 *in, size_t inlen, __u8 **out, size_t *outlen)
{
    const PC_to_RDR_GetSlotStatus_t *request = (PC_to_RDR_GetSlotStatus_t *) in;

    if (!out || !outlen || !in)
        return SC_ERROR_INVALID_ARGUMENTS;

    if (inlen < sizeof *request)
        SC_FUNC_RETURN(SC_LOG_DEBUG_VERBOSE, SC_ERROR_INVALID_DATA);

    *outlen = sizeof(RDR_to_PC_SlotStatus_t);

    if (request->bMessageType != 0x65
            || request->dwLength != __constant_cpu_to_le32(0)
            || request->bSlot != 0
            || request->abRFU1 != 0
            || request->abRFU2 != 0)
        sc_debug(SC_LOG_DEBUG_NORMAL, "warning: malformed PC_to_RDR_GetSlotStatus");

    return get_RDR_to_PC_SlotStatus(request->bSeq, SC_SUCCESS,
            out, outlen, NULL, 0);
}

static int
perform_PC_to_RDR_IccPowerOn(const __u8 *in, size_t inlen, __u8 **out, size_t *outlen)
{
    const PC_to_RDR_IccPowerOn_t *request = (PC_to_RDR_IccPowerOn_t *) in;
    int sc_result;

    if (!out || !outlen || !in)
        return SC_ERROR_INVALID_ARGUMENTS;

    if (inlen < sizeof *request)
        SC_FUNC_RETURN(SC_LOG_DEBUG_VERBOSE, SC_ERROR_INVALID_DATA);

    if (request->bMessageType != 0x62
            || request->dwLength != __constant_cpu_to_le32(0)
            || request->bSlot != 0
            || !( request->bPowerSelect == 0
                || request->bPowerSelect & ccid_desc.bVoltageSupport)
            || request->abRFU != 0)
        sc_debug(SC_LOG_DEBUG_NORMAL, "warning: malformed PC_to_RDR_IccPowerOn");

    sc_debug(SC_LOG_DEBUG_NORMAL, "Card is already powered on.");

    if (sc_result >= 0) {
        return get_RDR_to_PC_SlotStatus(request->bSeq,
                // TODO return ATR
                //sc_result, out, outlen, card->atr.value, card->atr.len);
                sc_result, out, outlen, NULL, 0);
    } else {
        sc_debug(SC_LOG_DEBUG_VERBOSE, "Returning default status package.");
        return get_RDR_to_PC_SlotStatus(request->bSeq,
                sc_result, out, outlen, NULL, 0);
    }
}

static int
perform_PC_to_RDR_IccPowerOff(const __u8 *in, size_t inlen, __u8 **out, size_t *outlen)
{
    const PC_to_RDR_IccPowerOff_t *request = (PC_to_RDR_IccPowerOff_t *) in;
    int sc_result = SC_SUCCESS;

    if (!in || !out || !outlen)
        return SC_ERROR_INVALID_ARGUMENTS;

    if (inlen < sizeof *request)
        SC_FUNC_RETURN(SC_LOG_DEBUG_VERBOSE, SC_ERROR_INVALID_DATA);

    if (request->bMessageType != 0x63
            || request->dwLength != __constant_cpu_to_le32(0)
            || request->bSlot != 0
            || request->abRFU1 != 0
            || request->abRFU2 != 0)
        sc_debug(SC_LOG_DEBUG_NORMAL, "warning: malformed PC_to_RDR_IccPowerOff");

    //sc_reset(card, 1);
    //sc_result = sc_disconnect_card(card);

    return get_RDR_to_PC_SlotStatus(request->bSeq, sc_result,
                out, outlen, NULL, 0);
}

struct sw {
    unsigned char sw1;
    unsigned char sw2;
};
static const struct sw iso_sw_ok = { 0x90, 0x00};
static const struct sw iso_sw_incorrect_p1_p2 = { 0x6A, 0x86};
static const struct sw iso_sw_ref_data_not_found = {0x6A, 0x88};
static const struct sw iso_sw_inconsistent_data = {0x6A, 0x87};
static const struct sw iso_sw_func_not_supported = {0x6A, 0x81};
static const struct sw iso_sw_ins_not_supported = {0x6D, 0x00};

#define min(a,b) (a<b?a:b)
static int
perform_pseudo_apdu(const __u8 *in, size_t inlen, __u8 **out, size_t *outlen)
{
    if (!in || !out || !outlen)
        return SC_ERROR_INVALID_ARGUMENTS;

	// switch (apdu->ins) {
	// 	case 0x9A:

    //         switch (apdu->p1) {
    //             case 0x01:
    //                 /* GetReaderInfo */
    //                 if (apdu->datalen != 0) {
    //                     apdu->sw1 = iso_sw_incorrect_p1_p2.sw1;
    //                     apdu->sw2 = iso_sw_incorrect_p1_p2.sw2;
    //                     goto err;
    //                 }
    //                 /* TODO Merge this with STRINGID_MFGR, STRINGID_PRODUCT in usb.c */
    //                 /* Copied from olsc/AusweisApp/Data/siqTerminalsInfo.cfg */
    //                 char *Herstellername = "REINER SCT";
    //                 char *Produktname = "cyberJack RFID komfort";
    //                 char *Firmwareversion = "1.0";
    //                 char *Treiberversion = "3.99.5";
    //                 switch (apdu->p2) {
    //                     case 0x01:
    //                         apdu->resplen = min(apdu->resplen, strlen(Herstellername));
    //                         memcpy(apdu->resp, Herstellername, apdu->resplen);
    //                         break;
    //                     case 0x03:
    //                         apdu->resplen = min(apdu->resplen, strlen(Produktname));
    //                         memcpy(apdu->resp, Produktname, apdu->resplen);
    //                         break;
    //                     case 0x06:
    //                         apdu->resplen = min(apdu->resplen, strlen(Firmwareversion));
    //                         memcpy(apdu->resp, Firmwareversion, apdu->resplen);
    //                         break;
    //                     case 0x07:
    //                         apdu->resplen = min(apdu->resplen, strlen(Treiberversion));
    //                         memcpy(apdu->resp, Treiberversion, apdu->resplen);
    //                         break;
    //                     default:
    //                         apdu->sw1 = iso_sw_ref_data_not_found.sw1;
    //                         apdu->sw2 = iso_sw_ref_data_not_found.sw2;
    //                         goto err;
    //                 }
    //                 break;

    //             case 0x04:
    //                 switch (apdu->p2) {
    //                     default:
    //                         apdu->sw1 = iso_sw_func_not_supported.sw1;
    //                         apdu->sw2 = iso_sw_func_not_supported.sw2;
    //                         goto err;
    //                 }
    //                 break;

    //             default:
    //                 apdu->sw1 = iso_sw_func_not_supported.sw1;
    //                 apdu->sw2 = iso_sw_func_not_supported.sw2;
    //                 goto err;
    //         }
    //         break;

	// 	default:
    //         apdu->sw1 = iso_sw_ins_not_supported.sw1;
    //         apdu->sw2 = iso_sw_ins_not_supported.sw2;
    //         goto err;
	// }

err:
    return SC_SUCCESS;
}

static int
perform_PC_to_RDR_XfrBlock(const __u8 *in, size_t inlen, __u8** out, size_t *outlen)
{
    const PC_to_RDR_XfrBlock_t *request = (PC_to_RDR_XfrBlock_t *) in;
    const __u8 *abDataIn = in + sizeof *request;
    int sc_result;
    size_t abDataOutLen = 0, apdulen;
    __u8 *abDataOut = NULL;

    if (!in || !out || !outlen)
        return SC_ERROR_INVALID_ARGUMENTS;

    if (inlen < sizeof *request)
        SC_FUNC_RETURN(SC_LOG_DEBUG_VERBOSE, SC_ERROR_INVALID_DATA);

    if (request->bMessageType != 0x6F
            || request->bSlot != 0
            || request->bBWI  != 0)
        sc_debug(SC_LOG_DEBUG_NORMAL, "malformed PC_to_RDR_XfrBlock, will continue anyway");

	apdulen = __le32_to_cpu(request->dwLength);
	if (inlen < apdulen+sizeof *request) {
        sc_debug(SC_LOG_DEBUG_VERBOSE, "Not enough Data for APDU");
        SC_FUNC_RETURN(SC_LOG_DEBUG_VERBOSE, SC_ERROR_INVALID_DATA);
	}

    sc_result = SC_SUCCESS; //TODO check malformed APDU sc_bytes2apdu(abDataIn, apdulen, &apdu);
    if (sc_result >= 0)
        sc_result = get_rapdu(abDataIn, apdulen, out, outlen);
    else
        bin_log(SC_LOG_DEBUG_VERBOSE, "Invalid APDU", abDataIn,
                __le32_to_cpu(request->dwLength));

    sc_result = get_RDR_to_PC_DataBlock(request->bSeq, sc_result,
            out, outlen, abDataOut, abDataOutLen);

    free(abDataOut);

    return sc_result;
}

static int
perform_PC_to_RDR_GetParamters(const __u8 *in, size_t inlen, __u8** out, size_t *outlen)
{
    const PC_to_RDR_GetParameters_t *request = (PC_to_RDR_GetParameters_t *) in;
    RDR_to_PC_Parameters_t *result;
    abProtocolDataStructure_T1_t *t1;
    abProtocolDataStructure_T0_t *t0;
    int sc_result;

    if (!in || !out || !outlen)
        return SC_ERROR_INVALID_ARGUMENTS;

    if (inlen < sizeof *request)
        SC_FUNC_RETURN(SC_LOG_DEBUG_VERBOSE, SC_ERROR_INVALID_DATA);

    if (request->bMessageType != 0x6C
            || request->dwLength != __constant_cpu_to_le32(0)
            || request->bSlot != 0)
        sc_debug(SC_LOG_DEBUG_NORMAL, "warning: malformed PC_to_RDR_GetParamters");

    switch (SC_PROTO_T0) {
        case SC_PROTO_T0:
            result = realloc(*out, sizeof *result + sizeof *t0);
            if (!result)
                return SC_ERROR_OUT_OF_MEMORY;
            *out = (__u8 *) result;

            result->bProtocolNum = 0;
            result->dwLength = __constant_cpu_to_le32(sizeof *t0);

            t0 = (abProtocolDataStructure_T0_t *) result + sizeof *result;
            /* values taken from ISO 7816-3 defaults
             * FIXME analyze ATR to get values */
            t0->bmFindexDindex    =
                1<<4|   // index to table 7 ISO 7816-3 (Fi)
                1;      // index to table 8 ISO 7816-3 (Di)
            t0->bmTCCKST0         = 0<<1;   // convention (direct)
            t0->bGuardTimeT0      = 0xFF;
            t0->bWaitingIntegerT0 = 0x10;
            t0->bClockStop        = 0;      // (not allowed)

            sc_result = SC_SUCCESS;
            break;

        case SC_PROTO_T1:
            result = realloc(*out, sizeof *result + sizeof *t1);
            if (!result)
                return SC_ERROR_OUT_OF_MEMORY;
            *out = (__u8 *) result;

            result->bProtocolNum = 1;
            result->dwLength = __constant_cpu_to_le32(sizeof *t1);

            t1 = (abProtocolDataStructure_T1_t *) (result + sizeof *result);
            /* values taken from OpenPGP-card
             * FIXME analyze ATR to get values */
            t1->bmFindexDindex     =
                1<<4|   // index to table 7 ISO 7816-3 (Fi)
                3;      // index to table 8 ISO 7816-3 (Di)
            t1->bmTCCKST1          =
                0|      // checksum type (CRC)
                0<<1|   // convention (direct)
                0x10;
            t1->bGuardTimeT1       = 0xFF;
            t1->bWaitingIntegersT1 =
                4<<4|   // BWI
                5;      // CWI
            t1->bClockStop         = 0;      // (not allowed)
            t1->bIFSC              = 0x80;
            t1->bNadValue          = 0;      // see 7816-3 9.4.2.1 (only default value)

            sc_result = SC_SUCCESS;
            break;

        default:
            sc_result = SC_ERROR_INVALID_DATA;
            break;
    }

    result = realloc(*out, sizeof *result);
    if (!result)
        return SC_ERROR_OUT_OF_MEMORY;
    *out = (__u8 *) result;

    result->bMessageType = 0x82;
    result->bSlot = 0;
    result->bSeq = request->bSeq;
    result->bStatus = get_bStatus(sc_result);
    result->bError  = get_bError(sc_result);

    if (sc_result < 0)
        debug_sc_result(sc_result);

    return SC_SUCCESS;
}

/* XXX calling sc_wait_for_event blocks all other threads, thats why it
 * can't be used here... */
static int
get_RDR_to_PC_NotifySlotChange(RDR_to_PC_NotifySlotChange_t **out)
{
    int sc_result;
    uint8_t oldmask;
    uint8_t changed [] = {
            CCID_SLOT1_CHANGED,
            CCID_SLOT2_CHANGED,
            CCID_SLOT3_CHANGED,
            CCID_SLOT4_CHANGED,
    };
    uint8_t present [] = {
            CCID_SLOT1_CARD_PRESENT,
            CCID_SLOT2_CARD_PRESENT,
            CCID_SLOT3_CARD_PRESENT,
            CCID_SLOT4_CARD_PRESENT,
    };

    if (!out)
        return SC_ERROR_INVALID_ARGUMENTS;

    RDR_to_PC_NotifySlotChange_t *result = realloc(*out, sizeof *result);
    if (!result)
        return SC_ERROR_OUT_OF_MEMORY;
    *out = result;

    result->bMessageType = 0x50;
    result->bmSlotICCState = CCID_SLOTS_UNCHANGED;
    oldmask = CCID_SLOTS_UNCHANGED;

    sc_result = 0; // TODO
    if (sc_result < 0) {
        sc_debug(SC_LOG_DEBUG_VERBOSE, "Could not detect card presence.");
        debug_sc_result(sc_result);
    }

    if (sc_result & SC_READER_CARD_PRESENT)
        result->bmSlotICCState |= present[0];
    if (sc_result & SC_READER_CARD_CHANGED) {
        sc_debug(SC_LOG_DEBUG_NORMAL, "Card status changed.");
        result->bmSlotICCState |= changed[0];
    }

    if ((oldmask & present[0]) != (result->bmSlotICCState & present[0])) {
        sc_debug(SC_LOG_DEBUG_NORMAL, "Card status changed.");
        result->bmSlotICCState |= changed[0];
    }

    return SC_SUCCESS;
}

static int
perform_unknown(const __u8 *in, size_t inlen, __u8 **out, size_t *outlen)
{
    const PC_to_RDR_GetSlotStatus_t *request = (PC_to_RDR_GetSlotStatus_t *) in;
    RDR_to_PC_SlotStatus_t *result;

    if (!in || !out || !outlen)
        return SC_ERROR_INVALID_ARGUMENTS;

    if (inlen < sizeof *request)
        SC_FUNC_RETURN(SC_LOG_DEBUG_VERBOSE, SC_ERROR_INVALID_DATA);

    result = realloc(*out, sizeof *result);
    if (!result)
        return SC_ERROR_OUT_OF_MEMORY;
    *out = (__u8 *) result;

    switch (request->bMessageType) {
        case 0x62:
        case 0x6F:
        case 0x69:
            result->bMessageType = 0x80;
            break;
        case 0x63:
        case 0x65:
        case 0x6E:
        case 0x6A:
        case 0x71:
        case 0x72:
            result->bMessageType = 0x81;
            break;
        case 0x61:
        case 0x6C:
        case 0x6D:
            result->bMessageType = 0x82;
            break;
        case 0x6B:
            result->bMessageType = 0x83;
            break;
        case 0x73:
            result->bMessageType = 0x84;
            break;
        default:
            sc_debug(SC_LOG_DEBUG_NORMAL, "Unknown message type in request (0x%02x). "
                    "Using bMessageType=0x%02x for output.",
                    request->bMessageType, 0);
            result->bMessageType = 0;
    }
    result->dwLength     = __constant_cpu_to_le32(0);
    result->bSlot        = 0,
    result->bSeq         = request->bSeq;
    result->bStatus      = get_bStatus(SC_ERROR_UNKNOWN_DATA_RECEIVED);
    result->bError       = 0;
    result->bClockStatus = 0;

    *outlen = sizeof *result;

    return SC_SUCCESS;
}

int ccid_parse_bulkout(const __u8* inbuf, size_t inlen, __u8** outbuf)
{
    int sc_result;
    size_t outlen;

    if (!inbuf)
        return 0;

	bin_log(SC_LOG_DEBUG_VERBOSE, "CCID input", inbuf, inlen);

    switch (*inbuf) {
        case 0x62: 
                sc_debug(SC_LOG_DEBUG_NORMAL,  "PC_to_RDR_IccPowerOn");
                sc_result = perform_PC_to_RDR_IccPowerOn(inbuf, inlen, outbuf, &outlen);
                break;

        case 0x63:
                sc_debug(SC_LOG_DEBUG_NORMAL,  "PC_to_RDR_IccPowerOff");
                sc_result = perform_PC_to_RDR_IccPowerOff(inbuf, inlen, outbuf, &outlen);
                break;

        case 0x65:
                sc_debug(SC_LOG_DEBUG_NORMAL,  "PC_to_RDR_GetSlotStatus");
                sc_result = perform_PC_to_RDR_GetSlotStatus(inbuf, inlen, outbuf, &outlen);
                break;

        case 0x6F:
                sc_debug(SC_LOG_DEBUG_NORMAL,  "PC_to_RDR_XfrBlock");
                sc_result = perform_PC_to_RDR_XfrBlock(inbuf, inlen, outbuf, &outlen);
                break;

        case 0x6C:
                sc_debug(SC_LOG_DEBUG_NORMAL,  "PC_to_RDR_GetParameters");
                sc_result = perform_PC_to_RDR_GetParamters(inbuf, inlen, outbuf, &outlen);
                break;

        default:
                sc_debug(SC_LOG_DEBUG_VERBOSE, "Unknown ccid bulk-in message. "
                        "Starting default handler...");
                sc_result = perform_unknown(inbuf, inlen, outbuf, &outlen);
    }

    if (sc_result < 0) {
        debug_sc_result(sc_result);
        return -1;
    }

    return outlen;
}

int ccid_parse_control(struct usb_ctrlrequest *setup, __u8 **outbuf)
{
    int r;
    __u16 value, index, length;
    __u8 *tmp;

    if (!setup || !outbuf)
        return -1;

    value = __le16_to_cpu(setup->wValue);
    index = __le16_to_cpu(setup->wIndex);
    length = __le16_to_cpu(setup->wLength);

    if (setup->bRequestType == USB_REQ_CCID) {
        switch(setup->bRequest) {
            case CCID_CONTROL_ABORT:
                sc_debug(SC_LOG_DEBUG_NORMAL, "ABORT");
                if (length != 0x00) {
                    sc_debug(SC_LOG_DEBUG_NORMAL, "warning: malformed ABORT");
                }

                r = 0;
                break;

            case CCID_CONTROL_GET_CLOCK_FREQUENCIES:
                sc_debug(SC_LOG_DEBUG_NORMAL, "GET_CLOCK_FREQUENCIES");
                if (value != 0x00) {
                    sc_debug(SC_LOG_DEBUG_NORMAL, "warning: malformed GET_CLOCK_FREQUENCIES");
                }

                r = sizeof(__le32);
                tmp = realloc(*outbuf, r);
                if (!tmp) {
                    r = SC_ERROR_OUT_OF_MEMORY;
                    break;
                }
                *outbuf = tmp;
                __le32 clock  = ccid_desc.dwDefaultClock;
                /* Flawfinder: ignore */
                memcpy(*outbuf, &clock,  sizeof (__le32));
                break;

            case CCID_CONTROL_GET_DATA_RATES:
                sc_debug(SC_LOG_DEBUG_NORMAL, "GET_DATA_RATES");
                if (value != 0x00) {
                    sc_debug(SC_LOG_DEBUG_NORMAL, "warning: malformed GET_DATA_RATES");
                }

                r = sizeof (__le32);
                tmp = realloc(*outbuf, r);
                if (tmp == NULL) {
                    r = -1;
                    break;
                }
                *outbuf = tmp;
                __le32 drate  = ccid_desc.dwDataRate;
                /* Flawfinder: ignore */
                memcpy(*outbuf, &drate,  sizeof (__le32));
                break;

            default:
                sc_debug(SC_LOG_DEBUG_VERBOSE, "Unknown ccid control command.");

                r = SC_ERROR_NOT_SUPPORTED;
        }
    } else {
        r = SC_ERROR_INVALID_ARGUMENTS;
    }

    if (r < 0)
        debug_sc_result(r);

    return r;
}

int ccid_state_changed(RDR_to_PC_NotifySlotChange_t **slotchange, int timeout)
{
    int sc_result;

    if (!slotchange)
        return 0;

    sc_result = get_RDR_to_PC_NotifySlotChange(slotchange);

    if (sc_result < 0) {
        debug_sc_result(sc_result);
    }

    if ((*slotchange)->bmSlotICCState)
        return 1;

    return 0;
}
