/*
 *
 *  oFono - Open Source Telephony
 *
 *  Copyright (C) 2008-2011  Intel Corporation. All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include <glib.h>
#include <ell/ell.h>

#include <ofono/log.h>
#include <ofono/modem.h>
#include <ofono/sms.h>
#include "smsutil.h"
#include "util.h"

#include "gatchat.h"
#include "gatresult.h"

#include "motorolamodem.h"


static const char *csca_prefix[] = { "+CSCA:", NULL };
static const char *cgsms_prefix[] = { "+CGSMS:", NULL };
static const char *csms_prefix[] = { "+CSMS:", NULL };
static const char *cmgf_prefix[] = { "+CMGF:", NULL };
static const char *cpms_prefix[] = { "+CPMS:", NULL };
static const char *cmgs_prefix[] = { "+CMGS:", NULL };
static const char *cmgl_prefix[] = { "+CMGL:", NULL };
static const char *none_prefix[] = { NULL };

#if 0
static gboolean set_cmgf(gpointer user_data);
static gboolean set_cpms(gpointer user_data);
static void motorola_cmgl_set_cpms(struct ofono_sms *sms, int store);

#define MAX_CMGF_RETRIES 10
#define MAX_CPMS_RETRIES 10

static const char *storages[] = {
	"SM",
	"ME",
	"MT",
	"SR",
	"BM",
};
#endif

struct sms_data {
	int store;
	int incoming;
	int retries;
	gboolean expect_sr;
	gboolean cnma_enabled;
	char *cnma_ack_pdu;
	int cnma_ack_pdu_len;
	guint timeout_source;
	GAtChat *chat;
	unsigned int vendor;
};

#if 0
struct cpms_request {
	struct ofono_sms *sms;
	int store;
	int index;
	gboolean expect_sr;
};

static void motorola_csca_set_cb(gboolean ok, GAtResult *result, gpointer user_data)
{
	struct cb_data *cbd = user_data;
	ofono_sms_sca_set_cb_t cb = cbd->cb;
	struct ofono_error error;

	decode_at_error(&error, g_at_result_final_response(result));

	cb(&error, cbd->data);
}

static void motorola_csca_set(struct ofono_sms *sms,
			const struct ofono_phone_number *sca,
			ofono_sms_sca_set_cb_t cb, void *user_data)
{
	struct sms_data *data = ofono_sms_get_data(sms);
	struct cb_data *cbd = cb_data_new(cb, user_data);
	char buf[128];

	snprintf(buf, sizeof(buf), "AT+CSCA=\"%s\",%d", sca->number, sca->type);

	if (g_at_chat_send(data->chat, buf, csca_prefix,
				at_csca_set_cb, cbd, g_free) > 0)
		return;

	g_free(cbd);

	CALLBACK_WITH_FAILURE(cb, user_data);
}

static void at_csca_query_cb(gboolean ok, GAtResult *result, gpointer user_data)
{
	struct cb_data *cbd = user_data;
	GAtResultIter iter;
	ofono_sms_sca_query_cb_t cb = cbd->cb;
	struct ofono_error error;
	struct ofono_phone_number sca;
	const char *number;

	decode_at_error(&error, g_at_result_final_response(result));

	if (!ok) {
		cb(&error, NULL, cbd->data);
		return;
	}

	g_at_result_iter_init(&iter, result);

	if (!g_at_result_iter_next(&iter, "+CSCA:"))
		goto err;

	if (!g_at_result_iter_next_string(&iter, &number))
		goto err;

	if (number[0] == '+') {
		number = number + 1;
		sca.type = 145;
	} else {
		sca.type = 129;
	}

	strncpy(sca.number, number, OFONO_MAX_PHONE_NUMBER_LENGTH);
	sca.number[OFONO_MAX_PHONE_NUMBER_LENGTH] = '\0';

	g_at_result_iter_next_number(&iter, &sca.type);

	DBG("csca_query_cb: %s, %d", sca.number, sca.type);

	cb(&error, &sca, cbd->data);

	return;

err:
	CALLBACK_WITH_FAILURE(cb, NULL, cbd->data);
}

static void motorola_csca_query(struct ofono_sms *sms, ofono_sms_sca_query_cb_t cb,
					void *user_data)
{
	struct sms_data *data = ofono_sms_get_data(sms);
	struct cb_data *cbd = cb_data_new(cb, user_data);

	if (g_at_chat_send(data->chat, "AT+CSCA?", csca_prefix,
				motorola_csca_query_cb, cbd, g_free) > 0)
		return;

	g_free(cbd);

	CALLBACK_WITH_FAILURE(cb, NULL, user_data);
}

static void motorola_cmgs_cb(gboolean ok, GAtResult *result, gpointer user_data)
{
	struct cb_data *cbd = user_data;
	GAtResultIter iter;
	ofono_sms_submit_cb_t cb = cbd->cb;
	struct ofono_error error;
	int mr;

	decode_at_error(&error, g_at_result_final_response(result));

	if (!ok) {
		cb(&error, -1, cbd->data);
		return;
	}

	g_at_result_iter_init(&iter, result);

	if (!g_at_result_iter_next(&iter, "+CMGS:"))
		goto err;

	if (!g_at_result_iter_next_number(&iter, &mr))
		goto err;

	DBG("Got MR: %d", mr);

	cb(&error, mr, cbd->data);
	return;

err:
	CALLBACK_WITH_FAILURE(cb, -1, cbd->data);
}

static void motorola_cmgs(struct ofono_sms *sms, const unsigned char *pdu,
			int pdu_len, int tpdu_len, int mms,
			ofono_sms_submit_cb_t cb, void *user_data)
{
	struct sms_data *data = ofono_sms_get_data(sms);
	struct cb_data *cbd = cb_data_new(cb, user_data);
	char buf[512];
	int len;

	if (mms) {
		switch (data->vendor) {
		case OFONO_VENDOR_GEMALTO:
			/* no mms support */
			break;
		default:
			snprintf(buf, sizeof(buf), "AT+CMMS=%d", mms);
			g_at_chat_send(data->chat, buf, none_prefix,
					NULL, NULL, NULL);
			break;
		}
	}

	len = snprintf(buf, sizeof(buf), "AT+CMGS=%d\r", tpdu_len);
	encode_hex_own_buf(pdu, pdu_len, 0, buf+len);

	if (g_at_chat_send(data->chat, buf, cmgs_prefix,
				motorola_cmgs_cb, cbd, g_free) > 0)
		return;

	g_free(cbd);

	CALLBACK_WITH_FAILURE(cb, -1, user_data);
}

static void motorola_cgsms_set_cb(gboolean ok, GAtResult *result, gpointer user_data)
{
	struct cb_data *cbd = user_data;
	ofono_sms_sca_set_cb_t cb = cbd->cb;
	struct ofono_error error;

	decode_at_error(&error, g_at_result_final_response(result));

	cb(&error, cbd->data);
}

static void motorola_cgsms_set(struct ofono_sms *sms, int bearer,
			ofono_sms_bearer_set_cb_t cb, void *user_data)
{
	struct sms_data *data = ofono_sms_get_data(sms);
	struct cb_data *cbd = cb_data_new(cb, user_data);
	char buf[64];

	snprintf(buf, sizeof(buf), "AT+CGSMS=%d", bearer);

	if (g_at_chat_send(data->chat, buf, none_prefix,
				motorola_cgsms_set_cb, cbd, g_free) > 0)
		return;

	g_free(cbd);

	CALLBACK_WITH_FAILURE(cb, user_data);
}

static void motorola_cgsms_query_cb(gboolean ok, GAtResult *result,
				gpointer user_data)
{
	struct cb_data *cbd = user_data;
	ofono_sms_bearer_query_cb_t cb = cbd->cb;
	struct ofono_error error;
	GAtResultIter iter;
	int bearer;

	decode_at_error(&error, g_at_result_final_response(result));

	if (!ok) {
		cb(&error, -1, cbd->data);
		return;
	}

	g_at_result_iter_init(&iter, result);

	if (!g_at_result_iter_next(&iter, "+CGSMS:"))
		goto err;

	g_at_result_iter_next_number(&iter, &bearer);

	cb(&error, bearer, cbd->data);

	return;

err:
	CALLBACK_WITH_FAILURE(cb, -1, cbd->data);
}

static void motorola_cgsms_query(struct ofono_sms *sms,
				ofono_sms_bearer_query_cb_t cb, void *user_data)
{
	struct sms_data *data = ofono_sms_get_data(sms);
	struct cb_data *cbd = cb_data_new(cb, user_data);

	if (g_at_chat_send(data->chat, "AT+CGSMS?", cgsms_prefix,
				motorola_cgsms_query_cb, cbd, g_free) > 0)
		return;

	g_free(cbd);

	CALLBACK_WITH_FAILURE(cb, -1, user_data);
}

static void motorola_cnma_cb(gboolean ok, GAtResult *result, gpointer user_data)
{
	if (!ok)
		ofono_error("CNMA acknowledgement failed: "
				"Further SMS reception is not guaranteed");
}

static inline void motorola_ack_delivery(struct ofono_sms *sms)
{
	struct sms_data *data = ofono_sms_get_data(sms);
	char buf[256];

	DBG("");

	/* We must acknowledge the PDU using CNMA */
	if (data->cnma_ack_pdu) {
		switch (data->vendor) {
		case OFONO_VENDOR_GEMALTO:
			snprintf(buf, sizeof(buf), "AT+CNMA=1");
			break;
		default:
			snprintf(buf, sizeof(buf), "AT+CNMA=1,%d\r%s",
					data->cnma_ack_pdu_len,
					data->cnma_ack_pdu);
			break;
		}
	} else {
		/* Should be a safe fallback */
		snprintf(buf, sizeof(buf), "AT+CNMA=0");
	}

	g_at_chat_send(data->chat, buf, none_prefix, at_cnma_cb, NULL, NULL);
}

static void motorola_cds_notify(GAtResult *result, gpointer user_data)
{
	struct ofono_sms *sms = user_data;
	struct sms_data *data = ofono_sms_get_data(sms);
	long pdu_len;
	int tpdu_len;
	const char *hexpdu;
	unsigned char pdu[176];
	GAtResultIter iter;

	g_at_result_iter_init(&iter, result);

	if (!g_at_result_iter_next(&iter, "+CDS:"))
		goto err;

	/*
	 * Quirk for ZTE firmware which is not compliant with 27.005
	 * The +CDS syntax used by ZTE is including a comma before the length
	 * +CDS: ,<length><CR><LF><pdu>
	 * As a result, we need to skip this omitted subparameter
	 */
	if (data->vendor == OFONO_VENDOR_ZTE)
		g_at_result_iter_skip_next(&iter);

	if (!g_at_result_iter_next_number(&iter, &tpdu_len))
		goto err;

	hexpdu = g_at_result_pdu(result);

	if (strlen(hexpdu) > sizeof(pdu) * 2) {
		ofono_error("Bad PDU length in CDS notification");
		return;
	}

	DBG("Got new Status-Report PDU via CDS: %s, %d", hexpdu, tpdu_len);

	/* Decode pdu and notify about new SMS status report */
	decode_hex_own_buf(hexpdu, -1, &pdu_len, 0, pdu);
	ofono_sms_status_notify(sms, pdu, pdu_len, tpdu_len);

	if (data->cnma_enabled)
		motorola_ack_delivery(sms);

	return;

err:
	ofono_error("Unable to parse CDS notification");
}

static void motorola_cmt_notify(GAtResult *result, gpointer user_data)
{
	struct ofono_sms *sms = user_data;
	struct sms_data *data = ofono_sms_get_data(sms);
	GAtResultIter iter;
	const char *hexpdu;
	unsigned char pdu[176];
	long pdu_len;
	int tpdu_len;

	g_at_result_iter_init(&iter, result);

	if (!g_at_result_iter_next(&iter, "+CMT:"))
		goto err;

	switch (data->vendor) {
	case OFONO_VENDOR_GEMALTO:
		if (!g_at_result_iter_next_number(&iter, &tpdu_len)) {
			/*
			 * Some Gemalto modems (ALS3,PLS8...), act in
			 * accordance with 3GPP 27.005.  So we need to skip
			 * the first (<alpha>) field
			 *  \r\n+CMT: ,23\r\nCAFECAFECAFE... ...\r\n
			 *             ^------- PDU length
			 */
			DBG("Retrying to find the PDU length");

			if (!g_at_result_iter_skip_next(&iter))
				goto err;

			/* Next attempt at finding the PDU length. */
			if (!g_at_result_iter_next_number(&iter, &tpdu_len))
				goto err;
		}

		break;
	default:
		if (!g_at_result_iter_skip_next(&iter))
			goto err;

		if (!g_at_result_iter_next_number(&iter, &tpdu_len))
			goto err;

		break;
	}

	hexpdu = g_at_result_pdu(result);

	if (strlen(hexpdu) > sizeof(pdu) * 2) {
		ofono_error("Bad PDU length in CMT notification");
		return;
	}

	DBG("Got new SMS Deliver PDU via CMT: %s, %d", hexpdu, tpdu_len);

	decode_hex_own_buf(hexpdu, -1, &pdu_len, 0, pdu);
	ofono_sms_deliver_notify(sms, pdu, pdu_len, tpdu_len);

	if (data->vendor != OFONO_VENDOR_SIMCOM)
		motorola_ack_delivery(sms);
	return;

err:
	ofono_error("Unable to parse CMT notification");
}

static void motorola_cmgr_notify(GAtResult *result, gpointer user_data)
{
	struct ofono_sms *sms = user_data;
	struct sms_data *data = ofono_sms_get_data(sms);
	GAtResultIter iter;
	const char *hexpdu;
	unsigned char pdu[176];
	long pdu_len;
	int tpdu_len;

	DBG("");

	g_at_result_iter_init(&iter, result);

	if (!g_at_result_iter_next(&iter, "+CMGR:"))
		goto err;

	if (!g_at_result_iter_skip_next(&iter))
		goto err;

	if (!g_at_result_iter_skip_next(&iter))
		goto err;

	if (!g_at_result_iter_next_number(&iter, &tpdu_len))
		goto err;

	hexpdu = g_at_result_pdu(result);

	if (strlen(hexpdu) > sizeof(pdu) * 2)
		goto err;

	DBG("Got PDU: %s, with len: %d", hexpdu, tpdu_len);

	decode_hex_own_buf(hexpdu, -1, &pdu_len, 0, pdu);

	if (data->expect_sr)
		ofono_sms_status_notify(sms, pdu, pdu_len, tpdu_len);
	else
		ofono_sms_deliver_notify(sms, pdu, pdu_len, tpdu_len);
	return;

err:
	ofono_error("Unable to parse CMGR response");
}

static void motorola_cmgr_cb(gboolean ok, GAtResult *result, gpointer user_data)
{
	if (!ok)
		ofono_error("Received a CMTI indication but CMGR failed!");
}

static void motorola_cmgd_cb(gboolean ok, GAtResult *result, gpointer user_data)
{
	if (!ok)
		ofono_error("Unable to delete received SMS");
}

static void motorola_cmgr_cpms_cb(gboolean ok, GAtResult *result, gpointer user_data)
{
	struct cpms_request *req = user_data;
	struct ofono_sms *sms = req->sms;
	struct sms_data *data = ofono_sms_get_data(sms);
	char buf[128];

	if (!ok) {
		ofono_error("Received CMTI/CDSI, but CPMS request failed");
		return;
	}

	data->store = req->store;
	data->expect_sr = req->expect_sr;

	snprintf(buf, sizeof(buf), "AT+CMGR=%d", req->index);
	g_at_chat_send(data->chat, buf, none_prefix, motorola_cmgr_cb, NULL, NULL);

	/* We don't buffer SMS on the SIM/ME, send along a CMGD as well */
	snprintf(buf, sizeof(buf), "AT+CMGD=%d", req->index);
	g_at_chat_send(data->chat, buf, none_prefix, motorola_cmgd_cb, NULL, NULL);
}

static void motorola_send_cmgr_cpms(struct ofono_sms *sms, int store, int index,
				gboolean expect_sr)
{
	struct sms_data *data = ofono_sms_get_data(sms);

	if (store == data->store) {
		struct cpms_request req;

		req.sms = sms;
		req.store = store;
		req.index = index;
		req.expect_sr = expect_sr;

		motorola_cmgr_cpms_cb(TRUE, NULL, &req);
	} else {
		char buf[128];
		const char *incoming = storages[data->incoming];
		struct cpms_request *req = g_new(struct cpms_request, 1);

		req->sms = sms;
		req->store = store;
		req->index = index;
		req->expect_sr = expect_sr;

		snprintf(buf, sizeof(buf), "AT+CPMS=\"%s\",\"%s\",\"%s\"",
				storages[store], storages[store], incoming);

		g_motorola_chat_send(data->chat, buf, cpms_prefix, motorola_cmgr_cpms_cb,
				req, g_free);
	}
}

static void at_cmti_notify(GAtResult *result, gpointer user_data)
{
	struct ofono_sms *sms = user_data;
	enum at_util_sms_store store;
	int index;

	if (at_util_parse_sms_index_delivery(result, "+CMTI:",
						&store, &index) == FALSE)
		goto error;

	if (store != AT_UTIL_SMS_STORE_SM && store != AT_UTIL_SMS_STORE_ME)
		goto error;

	DBG("Got a CMTI indication at %s, index: %d", storages[store], index);
	motorola_send_cmgr_cpms(sms, store, index, FALSE);
	return;

error:
	ofono_error("Unable to parse CMTI notification");
}

static void motorola_cdsi_notify(GAtResult *result, gpointer user_data)
{
	struct ofono_sms *sms = user_data;
	enum at_util_sms_store store;
	int index;

	if (motorola_util_parse_sms_index_delivery(result, "+CDSI:",
						&store, &index) == FALSE)
		goto error;

	/* Some modems actually store status reports in SM, and not SR */
	if (store != AT_UTIL_SMS_STORE_SR && store != AT_UTIL_SMS_STORE_SM &&
			store != AT_UTIL_SMS_STORE_ME)
		goto error;

	DBG("Got a CDSI indication at %s, index: %d", storages[store], index);
	motorola_send_cmgr_cpms(sms, store, index, TRUE);
	return;

error:
	ofono_error("Unable to parse CDSI notification");
}

static void motorola_cmgl_done(struct ofono_sms *sms)
{
	struct sms_data *data = ofono_sms_get_data(sms);

	DBG("");

	if (data->incoming == AT_UTIL_SMS_STORE_MT &&
			data->store == AT_UTIL_SMS_STORE_ME) {
		at_cmgl_set_cpms(sms, AT_UTIL_SMS_STORE_SM);
		return;
	}

	g_at_chat_register(data->chat, "+CMTI:", at_cmti_notify, FALSE,
				sms, NULL);
	g_at_chat_register(data->chat, "+CMT:", at_cmt_notify, TRUE,
				sms, NULL);
	g_at_chat_register(data->chat, "+CDS:", motorola_cds_notify, TRUE,
				sms, NULL);
	g_at_chat_register(data->chat, "+CDSI:", motorola_cdsi_notify, FALSE,
				sms, NULL);

	/* We treat CMGR just like a notification */
	g_at_chat_register(data->chat, "+CMGR:", motorola_cmgr_notify, TRUE,
				sms, NULL);
}

static void motorola_cmgl_notify(GAtResult *result, gpointer user_data)
{
	struct ofono_sms *sms = user_data;
	struct sms_data *data = ofono_sms_get_data(sms);
	GAtResultIter iter;
	const char *hexpdu;
	unsigned char pdu[176];
	long pdu_len;
	int tpdu_len;
	int index;
	int status;
	char buf[16];

	DBG("");

	g_at_result_iter_init(&iter, result);

	while (g_at_result_iter_next(&iter, "+CMGL:")) {
		if (!g_at_result_iter_next_number(&iter, &index))
			goto err;

		if (!g_at_result_iter_next_number(&iter, &status))
			goto err;

		if (!g_at_result_iter_skip_next(&iter))
			goto err;

		if (!g_at_result_iter_next_number(&iter, &tpdu_len))
			goto err;

		/* Only MT messages */
		if (status != 0 && status != 1)
			continue;

		hexpdu = g_at_result_pdu(result);

		DBG("Found an old SMS PDU: %s, with len: %d",
				hexpdu, tpdu_len);

		if (strlen(hexpdu) > sizeof(pdu) * 2)
			continue;

		decode_hex_own_buf(hexpdu, -1, &pdu_len, 0, pdu);
		ofono_sms_deliver_notify(sms, pdu, pdu_len, tpdu_len);

		/* We don't buffer SMS on the SIM/ME, send along a CMGD */
		snprintf(buf, sizeof(buf), "AT+CMGD=%d", index);
		g_at_chat_send(data->chat, buf, none_prefix,
				motorola_cmgd_cb, NULL, NULL);
	}
	return;

err:
	ofono_error("Unable to parse CMGL response");
}

static void motorola_cmgl_cb(gboolean ok, GAtResult *result, gpointer user_data)
{
	struct ofono_sms *sms = user_data;

	if (!ok)
		DBG("Initial listing SMS storage failed!");

	motorola_cmgl_done(sms);
}

static void motorola_cmgl_cpms_cb(gboolean ok, GAtResult *result, gpointer user_data)
{
	struct cpms_request *req = user_data;
	struct ofono_sms *sms = req->sms;
	struct sms_data *data = ofono_sms_get_data(sms);

	if (!ok) {
		ofono_error("Initial CPMS request failed");
		motorola_cmgl_done(sms);
		return;
	}

	data->store = req->store;

	g_at_chat_send_pdu_listing(data->chat, "AT+CMGL=4", cmgl_prefix,
					motorola_cmgl_notify, motorola_cmgl_cb, sms, NULL);
}

static void motorola_cmgl_set_cpms(struct ofono_sms *sms, int store)
{
	struct sms_data *data = ofono_sms_get_data(sms);

	if (store == data->store) {
		struct cpms_request req;

		req.sms = sms;
		req.store = store;

		motorola_cmgl_cpms_cb(TRUE, NULL, &req);
	} else {
		char buf[128];
		const char *readwrite = storages[store];
		const char *incoming = storages[data->incoming];
		struct cpms_request *req = g_new(struct cpms_request, 1);

		req->sms = sms;
		req->store = store;

		snprintf(buf, sizeof(buf), "AT+CPMS=\"%s\",\"%s\",\"%s\"",
				readwrite, readwrite, incoming);

		g_at_chat_send(data->chat, buf, cpms_prefix, motorola_cmgl_cpms_cb,
				req, g_free);
	}
}

static void motorola_sms_initialized(struct ofono_sms *sms)
{
	struct sms_data *data = ofono_sms_get_data(sms);

	/* Inspect and free the incoming SMS storage */
	if (data->incoming == AT_UTIL_SMS_STORE_MT)
		motorola_cmgl_set_cpms(sms, AT_UTIL_SMS_STORE_ME);
	else
		motorola_cmgl_set_cpms(sms, data->incoming);

}
#endif

static void motorola_sms_not_supported(struct ofono_sms *sms)
{
	ofono_error("SMS not supported by this modem.  If this is an error"
			" please submit patches to support this hardware");

	ofono_sms_remove(sms);
}

#if 0

static void construct_ack_pdu(struct sms_data *d)
{
	struct sms ackpdu;
	unsigned char pdu[164];
	int len;
	int tpdu_len;

	DBG("");

	memset(&ackpdu, 0, sizeof(ackpdu));

	ackpdu.type = SMS_TYPE_DELIVER_REPORT_ACK;

	if (!sms_encode(&ackpdu, &len, &tpdu_len, pdu))
		goto err;

	/* Constructing an <ackpdu> according to 27.005 Section 4.6 */
	if (len != tpdu_len)
		goto err;

	d->cnma_ack_pdu = l_util_hexstring(pdu, tpdu_len);
	if (d->cnma_ack_pdu == NULL)
		goto err;

	d->cnma_ack_pdu_len = tpdu_len;
	return;

err:
	ofono_error("Unable to construct Deliver ACK PDU");
}


static void motorola_cpms_set_cb(gboolean ok, GAtResult *result, gpointer user_data)
{
	struct ofono_sms *sms = user_data;
	struct sms_data *data = ofono_sms_get_data(sms);

	if (ok)
		return motorola_query_cnmi(sms);

	data->retries += 1;

	if (data->retries == MAX_CPMS_RETRIES) {
		ofono_error("Unable to set preferred storage");
		return motorola_sms_not_supported(sms);
	}

	data->timeout_source = g_timeout_add_seconds(1, set_cpms, sms);
}

static gboolean set_cpms(gpointer user_data)
{
	struct ofono_sms *sms = user_data;
	struct sms_data *data = ofono_sms_get_data(sms);
	const char *store = storages[data->store];
	const char *incoming = storages[data->incoming];
	char buf[128];

	if (data->vendor == OFONO_VENDOR_WAVECOM_Q2XXX)
		snprintf(buf, sizeof(buf), "AT+CPMS=\"%s\"", store);
	else
		snprintf(buf, sizeof(buf), "AT+CPMS=\"%s\",\"%s\",\"%s\"",
				store, store, incoming);

	g_at_chat_send(data->chat, buf, cpms_prefix,
			motorola_cpms_set_cb, sms, NULL);

	data->timeout_source = 0;

	return FALSE;
}

static void motorola_cmgf_set_cb(gboolean ok, GAtResult *result, gpointer user_data)
{
	struct ofono_sms *sms = user_data;
	struct sms_data *data = ofono_sms_get_data(sms);

	if (ok) {
		data->retries = 0;
		set_cpms(sms);
		return;
	}

	data->retries += 1;

	if (data->retries == MAX_CMGF_RETRIES) {
		DBG("Unable to enter PDU mode");
		return motorola_sms_not_supported(sms);
	}

	data->timeout_source = g_timeout_add_seconds(1, set_cmgf, sms);
}

static gboolean set_cmgf(gpointer user_data)
{
	struct ofono_sms *sms = user_data;
	struct sms_data *data = ofono_sms_get_data(sms);

	g_at_chat_send(data->chat, "AT+CMGF=0", cmgf_prefix,
			motorola_cmgf_set_cb, sms, NULL);

	data->timeout_source = 0;

	return FALSE;
}

static void motorola_cpms_query_cb(gboolean ok, GAtResult *result,
				gpointer user_data)
{
	struct ofono_sms *sms = user_data;
	struct sms_data *data = ofono_sms_get_data(sms);
	gboolean supported = FALSE;

	if (ok) {
		int mem = 0, mem_max;
		GAtResultIter iter;
		const char *store;
		gboolean me_supported[3];
		gboolean sm_supported[3];
		gboolean mt_supported[3];

		memset(me_supported, 0, sizeof(me_supported));
		memset(sm_supported, 0, sizeof(sm_supported));
		memset(mt_supported, 0, sizeof(mt_supported));

		g_at_result_iter_init(&iter, result);

		if (!g_at_result_iter_next(&iter, "+CPMS:"))
			goto out;

		if (data->vendor == OFONO_VENDOR_WAVECOM_Q2XXX) {
			/* skip initial `(' */
			if (!g_at_result_iter_open_list(&iter))
				goto out;

			/*
			 * Wavecom Q2 replies: +CPMS: (("SM","BM","SR"),("SM"))
			 * This reply is broken according to 3GPP TS 07.05.
			 */
			mem_max = 2;
		} else
			mem_max = 3;

		for (mem = 0; mem < mem_max; mem++) {
			if (!g_at_result_iter_open_list(&iter))
				goto out;

			while (g_at_result_iter_next_string(&iter, &store)) {
				if (!strcmp(store, "ME"))
					me_supported[mem] = TRUE;
				else if (!strcmp(store, "SM"))
					sm_supported[mem] = TRUE;
				else if (!strcmp(store, "MT"))
					mt_supported[mem] = TRUE;
			}

			if (!g_at_result_iter_close_list(&iter))
				goto out;
		}

		if (data->vendor != OFONO_VENDOR_WAVECOM_Q2XXX &&
				!sm_supported[2] && !me_supported[2]
				&& !mt_supported[2])
			goto out;

		if (sm_supported[0] && sm_supported[1]) {
			supported = TRUE;
			data->store = AT_UTIL_SMS_STORE_SM;
		}

		if (me_supported[0] && me_supported[1]) {
			supported = TRUE;
			data->store = AT_UTIL_SMS_STORE_ME;
		}

		/* This seems to be a special case, where the modem will
		 * pick & route the SMS to any of the storages supported by
		 * mem1
		 */
		if (mt_supported[2] && (sm_supported[0] || me_supported[0]))
			data->incoming = AT_UTIL_SMS_STORE_MT;

		if (sm_supported[2])
			data->incoming = AT_UTIL_SMS_STORE_SM;

		if (me_supported[2])
			data->incoming = AT_UTIL_SMS_STORE_ME;
	}
out:
	if (!supported)
		return motorola_sms_not_supported(sms);

	set_cmgf(sms);
}

static void motorola_cmgf_query_cb(gboolean ok, GAtResult *result,
				gpointer user_data)
{
	struct ofono_sms *sms = user_data;
	struct sms_data *data = ofono_sms_get_data(sms);
	gboolean supported = FALSE;

	if (ok) {
		GAtResultIter iter;
		int mode;

		g_at_result_iter_init(&iter, result);

		if (!g_at_result_iter_next(&iter, "+CMGF:"))
			goto out;

		if (!g_at_result_iter_open_list(&iter))
			goto out;

		/* Look for mode 0 (PDU mode) */
		while (g_at_result_iter_next_number(&iter, &mode))
			if (mode == 0)
				supported = TRUE;
	}

out:
	if (!supported)
		return motorola_sms_not_supported(sms);

	g_at_chat_send(data->chat, "AT+CPMS=?", cpms_prefix,
			motorola_cpms_query_cb, sms, NULL);
}

static void motorola_csms_status_cb(gboolean ok, GAtResult *result,
				gpointer user_data)
{
	struct ofono_sms *sms = user_data;
	struct sms_data *data = ofono_sms_get_data(sms);
	gboolean supported = FALSE;

	if (ok) {
		GAtResultIter iter;
		int service;
		int mt;
		int mo;

		g_at_result_iter_init(&iter, result);

		if (!g_at_result_iter_next(&iter, "+CSMS:"))
			goto out;


		switch (data->vendor) {
		case OFONO_VENDOR_HUAWEI:
		case OFONO_VENDOR_NOVATEL:
			g_at_result_iter_skip_next(&iter);
			service = 0;
			break;
		default:
			if (!g_at_result_iter_next_number(&iter, &service))
				goto out;
			break;
		}

		if (!g_at_result_iter_next_number(&iter, &mt))
			goto out;

		if (!g_at_result_iter_next_number(&iter, &mo))
			goto out;

		if (service == 1)
			data->cnma_enabled = TRUE;

		if (mt == 1 && mo == 1)
			supported = TRUE;
	}

out:
	if (!supported)
		return motorola_sms_not_supported(sms);

	/* Now query supported text format */
	g_at_chat_send(data->chat, "AT+CMGF=?", cmgf_prefix,
			motorola_cmgf_query_cb, sms, NULL);
}

static void motorola_csms_set_cb(gboolean ok, GAtResult *result,
				gpointer user_data)
{
	struct ofono_sms *sms = user_data;
	struct sms_data *data = ofono_sms_get_data(sms);

	g_at_chat_send(data->chat, "AT+CSMS?", csms_prefix,
			motorola_csms_status_cb, sms, NULL);
}
#endif

static void motorola_csms_query_cb(gboolean ok, GAtResult *result,
				gpointer user_data)
{
	struct ofono_sms *sms = user_data;
	struct sms_data *data = ofono_sms_get_data(sms);
	gboolean cnma_supported = FALSE;
	GAtResultIter iter;
	int status_min, status_max;
	char buf[128];

	DBG("");

	if (ok) {
	  DBG("we expect failure");
		return motorola_sms_not_supported(sms);
	}

	DBG("Ok, should have error?");

	g_at_result_iter_init(&iter, result);

	if (!g_at_result_iter_next(&iter, "+CSMS:"))
		goto out;

	if (!g_at_result_iter_open_list(&iter))
		goto out;

	while (g_at_result_iter_next_range(&iter, &status_min, &status_max))
		if (status_min <= 1 && 1 <= status_max)
			cnma_supported = TRUE;

	DBG("CSMS query parsed successfully");

out:
	DBG("");
}

/*  */

static void got_hex_pdu(struct ofono_sms *sms, const char *hexpdu)
{
	long pdu_len;
	int tpdu_len;
  	unsigned char pdu[176];

	if (strlen(hexpdu) > sizeof(pdu) * 2) {
		ofono_error("Bad PDU length in CDS notification");
		return;
	}

	/*	for (tpdu_len = 0; tpdu_len < 159; tpdu_len++) */
	  {
	  printf("tpdu_len: %d\n", tpdu_len);
	/* Decode pdu and notify about new SMS status report */
	  decode_hex_own_buf(hexpdu, -1, &pdu_len, 0, pdu);
	  tpdu_len = pdu_len - 8; /* FIXME: this is not correct */
	DBG("Got new Status-Report PDU via CDS: %s, %d", hexpdu, tpdu_len);
	  ofono_sms_deliver_notify(sms, pdu, pdu_len, tpdu_len);
	}

	if (0)
		motorola_ack_delivery(sms);
}

static int registered;

static void insms_notify(GAtResult *result, gpointer user_data)
{
	struct ofono_sms *sms = user_data;

	GAtResultIter iter;
	const char *stat;
	int enabled;
	char *line;

	g_at_result_iter_init(&iter, result);
	/* g_at_result_iter_next_hexstring ? */
	if (!g_at_result_iter_next(&iter, ""))
		return;

	line = g_at_result_iter_raw_line(&iter);
	DBG("insms notify: %s\n", line);

	got_hex_pdu(sms, line);
#if 0
	if (!g_at_result_iter_next(&iter, "~+RSSI="))
		return;

	for (int i = 0; i < 7; i++) {
	/* 7 numbers */
	  if (!g_at_result_iter_next_number(&iter, &enabled))
	    return;
	  //DBG("signal changes %d %d\n", i, enabled);
	}
#endif
}

void motorola_sms_finish_probe(struct ofono_sms *sms)
{
	ofono_sms_register(sms);
}

static int motorola_sms_probe(struct ofono_sms *sms, unsigned int vendor,
				void *user)
{
	GAtChat *chat = user;
	struct sms_data *data;

	DBG("");

	data = g_new0(struct sms_data, 1);
	data->chat = g_at_chat_clone(chat);
	data->vendor = vendor;

	ofono_sms_set_data(sms, data);

	g_at_chat_register(data->chat, "", insms_notify, FALSE, sms, NULL);
#if 0
	g_at_chat_send(data->chat, "AT", csms_prefix,
			motorola_csms_query_cb, sms, NULL);
#endif

#if 0
	/*	~+GCMT=318\r
                          07912470338016000404B933330011911010122402409BC4B7589E0791CB6E16686E2F83D0E539FB0D72A7D7EF761DE42ECFC965765D4D2FB340613A08FD06B9D36BF21BE42EB7EBFA3248EF2ED7F569BA0B640DCFCB207479CE7E83D620B83C8D6687E765771A447E839A6F719AED1AEB41EA32E8169BD968305018046787E969105CFE068DD373F61B749BD5723498EC367381ACE139A8F916A7D9AEB11E */
	got_hex_pdu(sms, "07912470338016000404B933330011911010127042409BC4B7589E0791CB6E16686E2F83D0E539FB0D72A7D7EF761DE42ECFC965765D4D2FB340613A08FD06B9D36BF21BE42EB7EBFA3248EF2ED7F569BA0B640DCFCB207479CE7E83D620B83C8D6687E765771A447E839A6F719AED1AEB41EA326846C3E564315018046787E969105CFE068DD373F61B749BD5723498EC367381ACE139A8F916A7D9AEB11E");
#endif	
	return 0;
}

static void motorola_sms_remove(struct ofono_sms *sms)
{
	struct sms_data *data = ofono_sms_get_data(sms);

	l_free(data->cnma_ack_pdu);

	if (data->timeout_source > 0)
		g_source_remove(data->timeout_source);

	g_at_chat_unref(data->chat);
	g_free(data);

	ofono_sms_set_data(sms, NULL);
}

static const struct ofono_sms_driver driver = {
	.name		= "motorolamodem",
	.probe		= motorola_sms_probe,
	.remove		= motorola_sms_remove,
#if 0
	.sca_query	= motorola_csca_query,
	.sca_set	= motorola_csca_set,
	.submit		= motorola_cmgs,
	.bearer_query	= motorola_cgsms_query,
	.bearer_set	= motorola_cgsms_set,
#endif
};

void motorola_sms_init(void)
{
	ofono_sms_driver_register(&driver);
}

void motorola_sms_exit(void)
{
	ofono_sms_driver_unregister(&driver);
}
