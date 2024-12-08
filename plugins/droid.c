/*
 * oFono - Open Source Telephony
 * Copyright (C) 2008-2011  Intel Corporation
 * Copyright (C) 2009  Collabora Ltd
 * Copyright (C) 2020  Pavel Machek
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#define OFONO_API_SUBJECT_TO_CHANGE
#include <ofono/plugin.h>
#include <ofono/log.h>
#include <ofono/modem.h>
#include <ofono/call-barring.h>
#include <ofono/call-forwarding.h>
#include <ofono/call-meter.h>
#include <ofono/call-settings.h>
#include <ofono/devinfo.h>
#include <ofono/gprs.h>
#include <ofono/gprs-context.h>
#include <ofono/location-reporting.h>
#include <ofono/message-waiting.h>
#include <ofono/netmon.h>
#include <ofono/netreg.h>
#include <ofono/phonebook.h>
#include <ofono/radio-settings.h>
#include <ofono/sim.h>
#include <ofono/stk.h>
#include <ofono/sms.h>
#include <ofono/ussd.h>
#include <ofono/voicecall.h>

#include <drivers/qmimodem/qmi.h>
#include <drivers/qmimodem/dms.h>
#include <drivers/qmimodem/wda.h>
#include <drivers/qmimodem/wms.h>
#include <drivers/qmimodem/util.h>

struct service_request {
	struct qmi_service **member;
	uint32_t service_type;
};

struct droid_data {
	struct qmi_qmux_device *qmux;
	struct qmi_service *dms;
	struct qmi_service *uim;
	struct qmi_service *voice;
	struct qmi_service *pds;
	struct qmi_service *wms;
	struct qmi_service *nas;
	struct qmi_service *wds;
	struct qmi_service *wds_ip4;
	struct qmi_service *wds_ip6;
	unsigned long features;
	uint8_t oper_mode;
	struct l_queue *service_requests;
};

static void droid_debug(const char *str, void *user_data)
{
	const char *prefix = user_data;

	ofono_info("%s%s", prefix, str);
}

static void droid_io_debug(const char *str, void *user_data)
{
	const char *prefix = user_data;

	ofono_debug("%s%s", prefix, str);
}

static int droid_probe(struct ofono_modem *modem)
{
	struct droid_data *data;

	DBG("%p", modem);

	data = l_new(struct droid_data, 1);
	if (!data)
		return -ENOMEM;

	ofono_modem_set_data(modem, data);

	return 0;
}

static void cleanup_services(struct droid_data *data)
{
	if (data->service_requests) {
		l_queue_destroy(data->service_requests, l_free);
		data->service_requests = NULL;
	}

	qmi_service_free(data->wds_ip4);
	data->wds_ip4 = NULL;
	qmi_service_free(data->wds_ip6);
	data->wds_ip6 = NULL;
	qmi_service_free(data->wds);
	data->wds = NULL;
	qmi_service_free(data->nas);
	data->nas = NULL;
	qmi_service_free(data->wms);
	data->wms = NULL;
	qmi_service_free(data->pds);
	data->pds = NULL;
	qmi_service_free(data->voice);
	data->voice = NULL;
	qmi_service_free(data->uim);
	data->uim = NULL;
	qmi_service_free(data->dms);
	data->dms = NULL;
}

static void droid_remove(struct ofono_modem *modem)
{
	struct droid_data *data = ofono_modem_get_data(modem);

	DBG("%p", modem);

	cleanup_services(data);
	ofono_modem_set_data(modem, NULL);
	qmi_qmux_device_free(data->qmux);

	l_free(data);
}

static void shutdown_cb(void *user_data)
{
	struct ofono_modem *modem = user_data;
	struct droid_data *data = ofono_modem_get_data(modem);

	DBG("");

	qmi_qmux_device_free(data->qmux);
	data->qmux = NULL;

	ofono_modem_set_powered(modem, FALSE);
}

static void shutdown_device(struct ofono_modem *modem)
{
	struct droid_data *data = ofono_modem_get_data(modem);

	DBG("%p", modem);

	cleanup_services(data);

	qmi_qmux_device_shutdown(data->qmux, shutdown_cb, modem, NULL);
}

static void power_reset_cb(struct qmi_result *result, void *user_data)
{
	struct ofono_modem *modem = user_data;

	DBG("");

	if (qmi_result_set_error(result, NULL)) {
		shutdown_device(modem);
		return;
	}

	ofono_modem_set_powered(modem, TRUE);
}

static void get_oper_mode_cb(struct qmi_result *result, void *user_data)
{
	struct ofono_modem *modem = user_data;
	struct droid_data *data = ofono_modem_get_data(modem);
	struct qmi_param *param;
	uint8_t mode;

	DBG("");

	if (qmi_result_set_error(result, NULL)) {
		shutdown_device(modem);
		return;
	}

	if (!qmi_result_get_uint8(result, QMI_DMS_RESULT_OPER_MODE, &mode)) {
		shutdown_device(modem);
		return;
	}

	data->oper_mode = mode;

	switch (data->oper_mode) {
	case QMI_DMS_OPER_MODE_ONLINE:
		param = qmi_param_new_uint8(QMI_DMS_PARAM_OPER_MODE,
					QMI_DMS_OPER_MODE_PERSIST_LOW_POWER);
		if (!param) {
			shutdown_device(modem);
			return;
		}

		if (qmi_service_send(data->dms, QMI_DMS_SET_OPER_MODE, param,
					power_reset_cb, modem, NULL) > 0)
			return;

		shutdown_device(modem);
		break;
	default:
		ofono_modem_set_powered(modem, TRUE);
		break;
	}
}

static void get_caps_cb(struct qmi_result *result, void *user_data)
{
	struct ofono_modem *modem = user_data;
	struct droid_data *data = ofono_modem_get_data(modem);
	const struct qmi_dms_device_caps *caps;
	uint16_t len;
	uint8_t i;

	DBG("");

	if (qmi_result_set_error(result, NULL))
		goto error;

	caps = qmi_result_get(result, QMI_DMS_RESULT_DEVICE_CAPS, &len);
	if (!caps)
		goto error;

	DBG("service capabilities %d", caps->data_capa);
	DBG("sim supported %d", caps->sim_supported);

	for (i = 0; i < caps->radio_if_count; i++)
		DBG("radio = %d", caps->radio_if[i]);

	if (qmi_service_send(data->dms, QMI_DMS_GET_OPER_MODE, NULL,
				get_oper_mode_cb, modem, NULL) > 0)
		return;

error:
	shutdown_device(modem);
}

static void create_service_cb(struct qmi_service *service, void *user_data)
{
	struct ofono_modem *modem = user_data;
	struct droid_data *data = ofono_modem_get_data(modem);
	struct service_request *request = NULL;

	DBG("");

	if (!service)
		goto error;

	request = l_queue_pop_head(data->service_requests);
	*request->member = service;
	l_free(request);
	request = l_queue_peek_head(data->service_requests);

	if (!request) {
		l_queue_destroy(data->service_requests, NULL);
		data->service_requests = NULL;

		if (qmi_service_send(data->dms, QMI_DMS_GET_CAPS, NULL,
					get_caps_cb, modem, NULL) <= 0)
			goto error;

		return;
	}

	if (qmi_qmux_device_create_client(data->qmux, request->service_type,
						create_service_cb, modem, NULL))
		return;

error:
	shutdown_device(modem);
}

static void create_dms_cb(struct qmi_service *service, void *user_data)
{
	struct ofono_modem *modem = user_data;
	struct droid_data *data = ofono_modem_get_data(modem);
	struct service_request *request = NULL;

	DBG("");

	if (!service)
		goto error;

	data->dms = service;
	request = l_queue_peek_head(data->service_requests);

	if (qmi_qmux_device_create_client(data->qmux, request->service_type,
						create_service_cb, modem, NULL))
		return;

error:
	shutdown_device(modem);
}

static struct service_request *new_service_request(
			struct qmi_service **member, uint32_t service_type)
{
	struct service_request *request = l_new(struct service_request, 1);

	request->member = member;
	request->service_type = service_type;

	return request;
}

static void discover_cb(void *user_data)
{
	struct ofono_modem *modem = user_data;
	struct droid_data *data = ofono_modem_get_data(modem);

	DBG("");

	data->service_requests = l_queue_new();

	l_queue_push_tail(data->service_requests,
			new_service_request(&data->uim, QMI_SERVICE_UIM));
	l_queue_push_tail(data->service_requests,
			new_service_request(&data->voice, QMI_SERVICE_VOICE));
	l_queue_push_tail(data->service_requests,
			new_service_request(&data->pds, QMI_SERVICE_PDS));
	l_queue_push_tail(data->service_requests,
			new_service_request(&data->wms, QMI_SERVICE_WMS));
	l_queue_push_tail(data->service_requests,
			new_service_request(&data->nas, QMI_SERVICE_NAS));
	l_queue_push_tail(data->service_requests,
			new_service_request(&data->wds, QMI_SERVICE_WDS));
	l_queue_push_tail(data->service_requests,
			new_service_request(&data->wds_ip4, QMI_SERVICE_WDS));
	l_queue_push_tail(data->service_requests,
			new_service_request(&data->wds_ip6, QMI_SERVICE_WDS));

	if (qmi_qmux_device_create_client(data->qmux, QMI_SERVICE_DMS,
					create_dms_cb, modem, NULL))
		return;

	shutdown_device(modem);
}

static int droid_enable(struct ofono_modem *modem)
{
	struct droid_data *data = ofono_modem_get_data(modem);
	const char *device;

	DBG("%p", modem);

	device = ofono_modem_get_string(modem, "Device");
	if (!device)
		return -EINVAL;

	data->qmux = qmi_qmux_device_new(device);
	if (!data->qmux)
		return -ENOMEM;

	if (getenv("OFONO_QMI_DEBUG"))
		qmi_qmux_device_set_debug(data->qmux, droid_debug, "QMI: ");

	if (getenv("OFONO_QMI_IO_DEBUG"))
		qmi_qmux_device_set_io_debug(data->qmux,
						droid_io_debug, "QMI: ");

	qmi_qmux_device_discover(data->qmux, discover_cb, modem, NULL);

	return -EINPROGRESS;
}

static void power_disable_cb(struct qmi_result *result, void *user_data)
{
	struct ofono_modem *modem = user_data;

	DBG("");

	shutdown_device(modem);
}

static int droid_disable(struct ofono_modem *modem)
{
	struct droid_data *data = ofono_modem_get_data(modem);
	struct qmi_param *param;

	DBG("%p", modem);

	param = qmi_param_new_uint8(QMI_DMS_PARAM_OPER_MODE,
				QMI_DMS_OPER_MODE_PERSIST_LOW_POWER);
	if (!param)
		return -ENOMEM;

	if (qmi_service_send(data->dms, QMI_DMS_SET_OPER_MODE, param,
				power_disable_cb, modem, NULL) > 0)
		return -EINPROGRESS;

	shutdown_device(modem);

	return -EINPROGRESS;
}

static void set_online_cb(struct qmi_result *result, void *user_data)
{
	struct cb_data *cbd = user_data;
	ofono_modem_online_cb_t cb = cbd->cb;

	DBG("");

	if (qmi_result_set_error(result, NULL))
		CALLBACK_WITH_FAILURE(cb, cbd->data);
	else
		CALLBACK_WITH_SUCCESS(cb, cbd->data);
}

static void droid_set_online(struct ofono_modem *modem, ofono_bool_t online,
				ofono_modem_online_cb_t cb, void *user_data)
{
	struct droid_data *data = ofono_modem_get_data(modem);
	struct cb_data *cbd = cb_data_new(cb, user_data);
	struct qmi_param *param;
	uint8_t mode;

	DBG("%p %s", modem, online ? "online" : "offline");

	if (online)
		mode = QMI_DMS_OPER_MODE_ONLINE;
	else
		mode = QMI_DMS_OPER_MODE_LOW_POWER;

	param = qmi_param_new_uint8(QMI_DMS_PARAM_OPER_MODE, mode);
	if (!param)
		goto error;

	if (qmi_service_send(data->dms, QMI_DMS_SET_OPER_MODE, param,
				set_online_cb, cbd, l_free) > 0)
		return;

	qmi_param_free(param);

error:
	CALLBACK_WITH_FAILURE(cb, cbd->data);

	l_free(cbd);
}

/* Only some QMI features are usable, voicecall and sms are custom */
static void droid_pre_sim(struct ofono_modem *modem)
{
	struct droid_data *data = ofono_modem_get_data(modem);

	DBG("%p", modem);

	ofono_devinfo_create(modem, 0, "qmimodem",
				qmi_service_clone(data->dms));
	ofono_sim_create(modem, 0, "qmimodem",
				qmi_service_clone(data->dms),
				qmi_service_clone(data->uim));
	ofono_voicecall_create(modem, 0, "qmimodem",
				qmi_service_clone(data->voice));
	ofono_location_reporting_create(modem, 0, "qmimodem",
					l_steal_ptr(data->pds));
}

static void droid_post_sim(struct ofono_modem *modem)
{
	struct droid_data *data = ofono_modem_get_data(modem);
	struct ofono_message_waiting *mw;
	struct ofono_gprs *gprs;
	struct ofono_gprs_context *gc;
	const char *interface;

	DBG("%p", modem);

/*	ofono_phonebook_create(modem, 0, "qmimodem", data->qmux);*/
	ofono_radio_settings_create(modem, 0, "qmimodem",
					qmi_service_clone(data->dms),
					qmi_service_clone(data->nas));

	ofono_sms_create(modem, 0, "qmimodem",
				qmi_service_clone(data->wms));

	mw = ofono_message_waiting_create(modem);
	if (mw)
		ofono_message_waiting_register(mw);

	gprs = ofono_gprs_create(modem, 0, "qmimodem",
					qmi_service_clone(data->wds),
					qmi_service_clone(data->nas));
	if (!gprs) {
		ofono_warn("Unable to create gprs for: %s",
				ofono_modem_get_path(modem));
		return;
	}

	gc = ofono_gprs_context_create(modem, 0, "qmimodem", -1,
					qmi_service_clone(data->wds_ip4),
					qmi_service_clone(data->wds_ip6));
	if (!gc) {
		ofono_warn("Unable to create gprs-context for: %s",
				ofono_modem_get_path(modem));
		return;
	}

	ofono_gprs_add_context(gprs, gc);
	interface = ofono_modem_get_string(modem, "NetworkInterface");
	ofono_gprs_context_set_interface(gc, interface);
}

static void droid_post_online(struct ofono_modem *modem)
{
	struct droid_data *data = ofono_modem_get_data(modem);

	DBG("%p", modem);

	ofono_netreg_create(modem, 0, "qmimodem",
					qmi_service_clone(data->nas));
	ofono_netmon_create(modem, 0, "qmimodem",
					qmi_service_clone(data->nas));

	ofono_ussd_create(modem, 0, "qmimodem",
					qmi_service_clone(data->voice));
	ofono_call_settings_create(modem, 0, "qmimodem",
					qmi_service_clone(data->voice));
	ofono_call_barring_create(modem, 0, "qmimodem",
					qmi_service_clone(data->voice));
	ofono_call_forwarding_create(modem, 0, "qmimodem",
					qmi_service_clone(data->voice));
}

static struct ofono_modem_driver droid_driver = {
	.probe		= droid_probe,
	.remove		= droid_remove,
	.enable		= droid_enable,
	.disable	= droid_disable,
	.set_online	= droid_set_online,
	.pre_sim	= droid_pre_sim,
	.post_sim	= droid_post_sim,
	.post_online	= droid_post_online,
};

OFONO_MODEM_DRIVER_BUILTIN(droid, &droid_driver)
