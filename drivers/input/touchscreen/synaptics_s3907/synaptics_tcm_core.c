/*
 * Synaptics TCM touchscreen driver
 *
 * Copyright (C) 2017-2018 Synaptics Incorporated. All rights reserved.
 *
 * Copyright (C) 2017-2018 Scott Lin <scott.lin@tw.synaptics.com>
 * Copyright (C) 2018-2019 Ian Su <ian.su@tw.synaptics.com>
 * Copyright (C) 2018-2019 Joey Zhou <joey.zhou@synaptics.com>
 * Copyright (C) 2018-2019 Yuehao Qiu <yuehao.qiu@synaptics.com>
 * Copyright (C) 2018-2019 Aaron Chen <aaron.chen@tw.synaptics.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * INFORMATION CONTAINED IN THIS DOCUMENT IS PROVIDED "AS-IS, " AND SYNAPTICS
 * EXPRESSLY DISCLAIMS ALL EXPRESS AND IMPLIED WARRANTIES, INCLUDING ANY
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE,
 * AND ANY WARRANTIES OF NON-INFRINGEMENT OF ANY INTELLECTUAL PROPERTY RIGHTS.
 * IN NO EVENT SHALL SYNAPTICS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, PUNITIVE, OR CONSEQUENTIAL DAMAGES ARISING OUT OF OR IN CONNECTION
 * WITH THE USE OF THE INFORMATION CONTAINED IN THIS DOCUMENT, HOWEVER CAUSED
 * AND BASED ON ANY THEORY OF LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, AND EVEN IF SYNAPTICS WAS ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE. IF A TRIBUNAL OF COMPETENT JURISDICTION DOES
 * NOT PERMIT THE DISCLAIMER OF DIRECT DAMAGES OR ANY OTHER DAMAGES, SYNAPTICS'
 * TOTAL CUMULATIVE LIABILITY TO ANY PARTY SHALL NOT EXCEED ONE HUNDRED U.S.
 * DOLLARS.
 */

#include <linux/debugfs.h>
#include <linux/gpio.h>
#include <linux/kthread.h>
#include <linux/interrupt.h>
#include <linux/regulator/consumer.h>
#include <linux/power_supply.h>
#include "synaptics_tcm_core.h"

/* #define RESET_ON_RESUME */

/* #define RESUME_EARLY_UNBLANK */

#define RESET_ON_RESUME_DELAY_MS 50

#define PREDICTIVE_READING

#define MIN_READ_LENGTH 9

/* #define FORCE_RUN_APPLICATION_FIRMWARE */

#define NOTIFIER_PRIORITY 2

#define RESPONSE_TIMEOUT_MS 3000

#define APP_STATUS_POLL_TIMEOUT_MS 1000

#define APP_STATUS_POLL_MS 100

#define ENABLE_IRQ_DELAY_MS 20

#define FALL_BACK_ON_POLLING

#define POLLING_DELAY_MS 5

#define MODE_SWITCH_DELAY_MS 100

#define READ_RETRY_US_MIN 5000

#define READ_RETRY_US_MAX 10000

#define WRITE_DELAY_US_MIN 500

#define WRITE_DELAY_US_MAX 1000

#define DYNAMIC_CONFIG_SYSFS_DIR_NAME "dynamic_config"

#define ROMBOOT_DOWNLOAD_UNIT 16

#define PDT_END_ADDR 0x00ee

#define RMI_UBL_FN_NUMBER 0x35

#define FLAG_FOD_DISABLE 0
#define FLAG_FOD_ENABLE 1

/*#define GRIP_MODE_DEBUG*/

#define SYNA_GAME_MODE_ARRAY "synaptics,game-mode-array"
#define SYNA_ACTIVE_MODE_ARRAY "synaptics,active-mode-array"
#define SYNA_UP_THRESHOLD_ARRAY "synaptics,up-threshold-array"
#define SYNA_TOLERANCE_ARRAY "synaptics,tolerance-array"
#define SYNA_EDGE_FILTER_ARRAY "synaptics,edge-filter-array"
#define SYNA_PANEL_ORIEN_ARRAY "synaptics,panel-orien-array"
#define SYNA_REPORT_RATE_ARRAY "synaptics,report-rate-array"
#define SYNA_CORNER_FILTER_AREA_STEP_ARRAY                                     \
	"synaptics,cornerfilter-area-step-array"
#define SYNA_CORNER_ZONE_FILTER_HOR1_ARRAY                                     \
	"synaptics,cornerzone-filter-hor1-array"
#define SYNA_CORNER_ZONE_FILTER_HOR2_ARRAY                                     \
	"synaptics,cornerzone-filter-hor2-array"
#define SYNA_CORNER_ZONE_FILTER_VER_ARRAY                                      \
	"synaptics,cornerzone-filter-ver-array"
#define SYNA_DEAD_ZONE_FILTER_HOR_ARRAY "synaptics,deadzone-filter-hor-array"
#define SYNA_DEAD_ZONE_FILTER_VER_ARRAY "synaptics,deadzone-filter-ver-array"
#define SYNA_EDGE_ZONE_FILTER_HOR_ARRAY "synaptics,edgezone-filter-hor-array"
#define SYNA_EDGE_ZONE_FILTER_VER_ARRAY "synaptics,edgezone-filter-ver-array"
#define SYNA_DISPLAY_RESOLUTION_ARRAY "synaptics,panel-display-resolution"

enum syna_dts_index {
	SYNA_DTS_GET_MAX_INDEX = 0,
	SYNA_DTS_GET_MIN_INDEX,
	SYNA_DTS_GET_DEF_INDEX,
	SYNA_DTS_SET_CUR_INDEX,
	SYNA_DTS_GET_CUR_INDEX,
};

static struct syna_tcm_hcd *gloab_tcm_hcd;
static bool tp_probe_success;

struct drm_panel *active_panel;

#if (USE_KOBJ_SYSFS)

#define dynamic_config_sysfs(c_name, id)                                       \
	static ssize_t syna_tcm_sysfs_##c_name##_show(                         \
		struct kobject *kobj, struct kobj_attribute *attr, char *buf)  \
	{                                                                      \
		int retval;                                                    \
		unsigned short value;                                          \
		struct device *p_dev;                                          \
		struct kobject *p_kobj;                                        \
		struct syna_tcm_hcd *tcm_hcd;                                  \
                                                                               \
		p_kobj = sysfs_dir->parent;                                    \
		p_dev = container_of(p_kobj, struct device, kobj);             \
		tcm_hcd = dev_get_drvdata(p_dev);                              \
                                                                               \
		mutex_lock(&tcm_hcd->extif_mutex);                             \
                                                                               \
		retval = tcm_hcd->get_dynamic_config(tcm_hcd, id, &value);     \
		if (retval < 0) {                                              \
			LOGE(tcm_hcd->pdev->dev.parent,                        \
			     "Failed to get dynamic config, retval=%d\n",      \
			     retval);                                          \
			goto exit;                                             \
		}                                                              \
                                                                               \
		retval = snprintf(buf, PAGE_SIZE, "%u\n", value);              \
                                                                               \
	exit:                                                                  \
		mutex_unlock(&tcm_hcd->extif_mutex);                           \
                                                                               \
		return retval;                                                 \
	}                                                                      \
                                                                               \
	static ssize_t syna_tcm_sysfs_##c_name##_store(                        \
		struct kobject *kobj, struct kobj_attribute *attr,             \
		const char *buf, size_t count)                                 \
	{                                                                      \
		int retval;                                                    \
		unsigned int input;                                            \
		struct device *p_dev;                                          \
		struct kobject *p_kobj;                                        \
		struct syna_tcm_hcd *tcm_hcd;                                  \
                                                                               \
		p_kobj = sysfs_dir->parent;                                    \
		p_dev = container_of(p_kobj, struct device, kobj);             \
		tcm_hcd = dev_get_drvdata(p_dev);                              \
                                                                               \
		if (sscanf(buf, "%u", &input) != 1)                            \
			return -EINVAL;                                        \
                                                                               \
		mutex_lock(&tcm_hcd->extif_mutex);                             \
                                                                               \
		retval = tcm_hcd->set_dynamic_config(tcm_hcd, id, input);      \
		if (retval < 0) {                                              \
			LOGE(tcm_hcd->pdev->dev.parent,                        \
			     "Failed to set dynamic config, retval=%d\n",      \
			     retval);                                          \
			goto exit;                                             \
		}                                                              \
                                                                               \
		retval = count;                                                \
                                                                               \
	exit:                                                                  \
		mutex_unlock(&tcm_hcd->extif_mutex);                           \
                                                                               \
		return retval;                                                 \
	}

#else

#define dynamic_config_sysfs(c_name, id)                                       \
	static ssize_t syna_tcm_sysfs_##c_name##_show(                         \
		struct device *dev, struct device_attribute *attr, char *buf)  \
	{                                                                      \
		int retval;                                                    \
		unsigned short value;                                          \
		struct device *p_dev;                                          \
		struct kobject *p_kobj;                                        \
		struct syna_tcm_hcd *tcm_hcd;                                  \
                                                                               \
		p_kobj = sysfs_dir->parent;                                    \
		p_dev = container_of(p_kobj, struct device, kobj);             \
		tcm_hcd = dev_get_drvdata(p_dev);                              \
                                                                               \
		mutex_lock(&tcm_hcd->extif_mutex);                             \
                                                                               \
		retval = tcm_hcd->get_dynamic_config(tcm_hcd, id, &value);     \
		if (retval < 0) {                                              \
			LOGE(tcm_hcd->pdev->dev.parent,                        \
			     "Failed to get dynamic config, retval=%d\n",      \
			     retval);                                          \
			goto exit;                                             \
		}                                                              \
                                                                               \
		retval = snprintf(buf, PAGE_SIZE, "%u\n", value);              \
                                                                               \
	exit:                                                                  \
		mutex_unlock(&tcm_hcd->extif_mutex);                           \
                                                                               \
		return retval;                                                 \
	}                                                                      \
                                                                               \
	static ssize_t syna_tcm_sysfs_##c_name##_store(                        \
		struct device *dev, struct device_attribute *attr,             \
		const char *buf, size_t count)                                 \
	{                                                                      \
		int retval;                                                    \
		unsigned int input;                                            \
		struct device *p_dev;                                          \
		struct kobject *p_kobj;                                        \
		struct syna_tcm_hcd *tcm_hcd;                                  \
                                                                               \
		p_kobj = sysfs_dir->parent;                                    \
		p_dev = container_of(p_kobj, struct device, kobj);             \
		tcm_hcd = dev_get_drvdata(p_dev);                              \
                                                                               \
		if (sscanf(buf, "%u", &input) != 1)                            \
			return -EINVAL;                                        \
                                                                               \
		mutex_lock(&tcm_hcd->extif_mutex);                             \
                                                                               \
		retval = tcm_hcd->set_dynamic_config(tcm_hcd, id, input);      \
		if (retval < 0) {                                              \
			LOGE(tcm_hcd->pdev->dev.parent,                        \
			     "Failed to set dynamic config, retval=%d\n",      \
			     retval);                                          \
			goto exit;                                             \
		}                                                              \
                                                                               \
		retval = count;                                                \
                                                                               \
	exit:                                                                  \
		mutex_unlock(&tcm_hcd->extif_mutex);                           \
                                                                               \
		return retval;                                                 \
	}
#endif

DECLARE_COMPLETION(response_complete);

static struct kobject *sysfs_dir;

static struct syna_tcm_module_pool mod_pool;

#if (USE_KOBJ_SYSFS)
KOBJ_SHOW_PROTOTYPE(syna_tcm, info)
KOBJ_SHOW_PROTOTYPE(syna_tcm, info_appfw)
KOBJ_STORE_PROTOTYPE(syna_tcm, irq_en)
KOBJ_STORE_PROTOTYPE(syna_tcm, reset)
KOBJ_STORE_PROTOTYPE(syna_tcm, cb_debug)
KOBJ_STORE_PROTOTYPE(syna_tcm, misc_debug)
#ifdef WATCHDOG_SW
KOBJ_STORE_PROTOTYPE(syna_tcm, watchdog)
#endif
KOBJ_SHOW_STORE_PROTOTYPE(syna_tcm, no_doze)
KOBJ_SHOW_STORE_PROTOTYPE(syna_tcm, disable_noise_mitigation)
KOBJ_SHOW_STORE_PROTOTYPE(syna_tcm, inhibit_frequency_shift)
KOBJ_SHOW_STORE_PROTOTYPE(syna_tcm, requested_frequency)
KOBJ_SHOW_STORE_PROTOTYPE(syna_tcm, disable_hsync)
KOBJ_SHOW_STORE_PROTOTYPE(syna_tcm, rezero_on_exit_deep_sleep)
KOBJ_SHOW_STORE_PROTOTYPE(syna_tcm, charger_connected)
KOBJ_SHOW_STORE_PROTOTYPE(syna_tcm, no_baseline_relaxation)
KOBJ_SHOW_STORE_PROTOTYPE(syna_tcm, in_wakeup_gesture_mode)
KOBJ_SHOW_STORE_PROTOTYPE(syna_tcm, stimulus_fingers)
KOBJ_SHOW_STORE_PROTOTYPE(syna_tcm, grip_suppression_enabled)
KOBJ_SHOW_STORE_PROTOTYPE(syna_tcm, enable_thick_glove)
KOBJ_SHOW_STORE_PROTOTYPE(syna_tcm, enable_glove)
KOBJ_SHOW_STORE_PROTOTYPE(syna_tcm, enable_touch_and_hold)
KOBJ_SHOW_STORE_PROTOTYPE(syna_tcm, game_mode_ctrl)
KOBJ_SHOW_STORE_PROTOTYPE(syna_tcm, set_report_rate)
KOBJ_SHOW_STORE_PROTOTYPE(syna_tcm, enable_gesture_type)

static struct kobj_attribute *attrs[] = {
	KOBJ_ATTRIFY(info),	KOBJ_ATTRIFY(info_appfw),
	KOBJ_ATTRIFY(irq_en),	KOBJ_ATTRIFY(reset),
	KOBJ_ATTRIFY(cb_debug), KOBJ_ATTRIFY(misc_debug),
#ifdef WATCHDOG_SW
	KOBJ_ATTRIFY(watchdog),
#endif
};

static struct kobj_attribute *dynamic_config_attrs[] = {
	KOBJ_ATTRIFY(no_doze),
	KOBJ_ATTRIFY(disable_noise_mitigation),
	KOBJ_ATTRIFY(inhibit_frequency_shift),
	KOBJ_ATTRIFY(requested_frequency),
	KOBJ_ATTRIFY(disable_hsync),
	KOBJ_ATTRIFY(rezero_on_exit_deep_sleep),
	KOBJ_ATTRIFY(charger_connected),
	KOBJ_ATTRIFY(no_baseline_relaxation),
	KOBJ_ATTRIFY(in_wakeup_gesture_mode),
	KOBJ_ATTRIFY(stimulus_fingers),
	KOBJ_ATTRIFY(grip_suppression_enabled),
	KOBJ_ATTRIFY(enable_thick_glove),
	KOBJ_ATTRIFY(enable_glove),
	KOBJ_ATTRIFY(enable_touch_and_hold),
	KOBJ_ATTRIFY(game_mode_ctrl),
	KOBJ_ATTRIFY(set_report_rate),
	KOBJ_ATTRIFY(enable_gesture_type),
};

#else /* apply device attribute declarations */

SHOW_PROTOTYPE(syna_tcm, info)
SHOW_PROTOTYPE(syna_tcm, info_appfw)
STORE_PROTOTYPE(syna_tcm, irq_en)
STORE_PROTOTYPE(syna_tcm, reset)
#ifdef WATCHDOG_SW
STORE_PROTOTYPE(syna_tcm, watchdog)
#endif
SHOW_STORE_PROTOTYPE(syna_tcm, no_doze)
SHOW_STORE_PROTOTYPE(syna_tcm, disable_noise_mitigation)
SHOW_STORE_PROTOTYPE(syna_tcm, inhibit_frequency_shift)
SHOW_STORE_PROTOTYPE(syna_tcm, requested_frequency)
SHOW_STORE_PROTOTYPE(syna_tcm, disable_hsync)
SHOW_STORE_PROTOTYPE(syna_tcm, rezero_on_exit_deep_sleep)
SHOW_STORE_PROTOTYPE(syna_tcm, charger_connected)
SHOW_STORE_PROTOTYPE(syna_tcm, no_baseline_relaxation)
SHOW_STORE_PROTOTYPE(syna_tcm, in_wakeup_gesture_mode)
SHOW_STORE_PROTOTYPE(syna_tcm, stimulus_fingers)
SHOW_STORE_PROTOTYPE(syna_tcm, grip_suppression_enabled)
SHOW_STORE_PROTOTYPE(syna_tcm, enable_thick_glove)
SHOW_STORE_PROTOTYPE(syna_tcm, enable_glove)
SHOW_STORE_PROTOTYPE(syna_tcm, enable_touch_and_hold)
SHOW_STORE_PROTOTYPE(syna_tcm, game_mode_ctrl)
SHOW_STORE_PROTOTYPE(syna_tcm, set_report_rate)
SHOW_STORE_PROTOTYPE(syna_tcm, enable_gesture_type)

static struct device_attribute *attrs[] = {
	ATTRIFY(info),	   ATTRIFY(info_appfw), ATTRIFY(irq_en), ATTRIFY(reset),
#ifdef WATCHDOG_SW
	ATTRIFY(watchdog),
#endif
};

static struct device_attribute *dynamic_config_attrs[] = {
	ATTRIFY(no_doze),
	ATTRIFY(disable_noise_mitigation),
	ATTRIFY(inhibit_frequency_shift),
	ATTRIFY(requested_frequency),
	ATTRIFY(disable_hsync),
	ATTRIFY(rezero_on_exit_deep_sleep),
	ATTRIFY(charger_connected),
	ATTRIFY(no_baseline_relaxation),
	ATTRIFY(in_wakeup_gesture_mode),
	ATTRIFY(stimulus_fingers),
	ATTRIFY(grip_suppression_enabled),
	ATTRIFY(enable_thick_glove),
	ATTRIFY(enable_glove),
	ATTRIFY(enable_touch_and_hold),
	ATTRIFY(game_mode_ctrl),
	ATTRIFY(set_report_rate),
	ATTRIFY(enable_gesture_type),
};
#endif /* END of #if USE_KOBJ_SYSFS*/

static int syna_tcm_get_app_info(struct syna_tcm_hcd *tcm_hcd);
static int syna_tcm_sensor_detection(struct syna_tcm_hcd *tcm_hcd);
static void syna_tcm_check_hdl(struct syna_tcm_hcd *tcm_hcd, unsigned char id);

#if (USE_KOBJ_SYSFS)
static ssize_t syna_tcm_sysfs_info_show(struct kobject *kobj,
					struct kobj_attribute *attr, char *buf)
#else
static ssize_t syna_tcm_sysfs_info_show(struct device *dev,
					struct device_attribute *attr,
					char *buf)
#endif
{
	int retval;
	unsigned int count;
	struct device *p_dev;
	struct kobject *p_kobj;
	struct syna_tcm_hcd *tcm_hcd;

	p_kobj = sysfs_dir->parent;
	p_dev = container_of(p_kobj, struct device, kobj);
	tcm_hcd = dev_get_drvdata(p_dev);

	LOGE(tcm_hcd->pdev->dev.parent, "PAGE_SIZE = 0x%lx\n", PAGE_SIZE);

	mutex_lock(&tcm_hcd->extif_mutex);

	retval = tcm_hcd->identify(tcm_hcd, true);
	if (retval < 0) {
		LOGE(tcm_hcd->pdev->dev.parent,
		     "Failed to do identification, retval=%d\n", retval);
		goto exit;
	}

	count = 0;
	retval = snprintf(buf, PAGE_SIZE - count, "TouchComm version:  %d\n",
			  tcm_hcd->id_info.version);
	if (retval < 0)
		goto exit;

	buf += retval;
	count += retval;

	if (SYNAPTICS_TCM_ID_SUBVERSION == 0) {
		retval =
			snprintf(buf, PAGE_SIZE - count,
				 "Driver version:     %d.%d\n",
				 (unsigned char)(SYNAPTICS_TCM_ID_VERSION >> 8),
				 (unsigned char)SYNAPTICS_TCM_ID_VERSION);
	} else {
		retval =
			snprintf(buf, PAGE_SIZE - count,
				 "Driver version:     %d.%d.%d\n",
				 (unsigned char)(SYNAPTICS_TCM_ID_VERSION >> 8),
				 (unsigned char)SYNAPTICS_TCM_ID_VERSION,
				 SYNAPTICS_TCM_ID_SUBVERSION);
	}
	if (retval < 0)
		goto exit;

	buf += retval;
	count += retval;

	switch (tcm_hcd->id_info.mode) {
	case MODE_APPLICATION_FIRMWARE:
		retval = snprintf(buf, PAGE_SIZE - count,
				  "Firmware mode:      Application Firmware\n");
		if (retval < 0)
			goto exit;
		break;
	case MODE_HOSTDOWNLOAD_FIRMWARE:
		retval = snprintf(
			buf, PAGE_SIZE - count,
			"Firmware mode:      Host Download Firmware\n");
		if (retval < 0)
			goto exit;
		break;
	case MODE_BOOTLOADER:
		retval = snprintf(buf, PAGE_SIZE - count,
				  "Firmware mode:      Bootloader\n");
		if (retval < 0)
			goto exit;
		break;
	case MODE_TDDI_BOOTLOADER:
		retval = snprintf(buf, PAGE_SIZE - count,
				  "Firmware mode:      TDDI Bootloader\n");
		if (retval < 0)
			goto exit;
		break;
	case MODE_TDDI_HOSTDOWNLOAD_BOOTLOADER:
		retval = snprintf(
			buf, PAGE_SIZE - count,
			"Firmware mode:      TDDI Host Download Bootloader\n");
		if (retval < 0)
			goto exit;
		break;
	case MODE_ROMBOOTLOADER:
		retval = snprintf(buf, PAGE_SIZE - count,
				  "Firmware mode:      Rom Bootloader\n");
		if (retval < 0)
			goto exit;
		break;
	default:
		retval = snprintf(buf, PAGE_SIZE - count,
				  "Firmware mode:      Unknown (%d)\n",
				  tcm_hcd->id_info.mode);
		if (retval < 0)
			goto exit;
		break;
	}
	buf += retval;
	count += retval;

	retval = snprintf(buf, PAGE_SIZE - count, "Part number:        ");
	if (retval < 0)
		goto exit;

	buf += retval;
	count += retval;

	retval = secure_memcpy(buf, PAGE_SIZE - count,
			       tcm_hcd->id_info.part_number,
			       sizeof(tcm_hcd->id_info.part_number),
			       sizeof(tcm_hcd->id_info.part_number));
	if (retval < 0) {
		LOGE(tcm_hcd->pdev->dev.parent,
		     "Failed to copy part number string, retval=%d\n", retval);
		goto exit;
	}
	buf += sizeof(tcm_hcd->id_info.part_number);
	count += sizeof(tcm_hcd->id_info.part_number);

	retval = snprintf(buf, PAGE_SIZE - count, "\n");
	if (retval < 0)
		goto exit;

	buf += retval;
	count += retval;

	retval = snprintf(buf, PAGE_SIZE - count, "Packrat number:     %d\n",
			  tcm_hcd->packrat_number);
	if (retval < 0)
		goto exit;

	count += retval;

	retval = count;

exit:
	mutex_unlock(&tcm_hcd->extif_mutex);

	return retval;
}

#if (USE_KOBJ_SYSFS)
static ssize_t syna_tcm_sysfs_info_appfw_show(struct kobject *kobj,
					      struct kobj_attribute *attr,
					      char *buf)
#else
static ssize_t syna_tcm_sysfs_info_appfw_show(struct device *dev,
					      struct device_attribute *attr,
					      char *buf)
#endif
{
	int retval;
	unsigned int count;
	struct device *p_dev;
	struct kobject *p_kobj;
	struct syna_tcm_hcd *tcm_hcd;
	int i;

	p_kobj = sysfs_dir->parent;
	p_dev = container_of(p_kobj, struct device, kobj);
	tcm_hcd = dev_get_drvdata(p_dev);

	mutex_lock(&tcm_hcd->extif_mutex);

	retval = syna_tcm_get_app_info(tcm_hcd);
	if (retval < 0) {
		LOGE(tcm_hcd->pdev->dev.parent,
		     "Failed to get app info, retval=%d\n", retval);
		goto exit;
	}

	count = 0;

	retval = snprintf(buf, PAGE_SIZE - count, "app info version:  %d\n",
			  le2_to_uint(tcm_hcd->app_info.version));
	if (retval < 0)
		goto exit;

	buf += retval;
	count += retval;

	retval = snprintf(buf, PAGE_SIZE - count, "app info status:  %d\n",
			  le2_to_uint(tcm_hcd->app_info.status));
	if (retval < 0)
		goto exit;

	buf += retval;
	count += retval;

	retval = snprintf(buf, PAGE_SIZE - count, "static config size:  %d\n",
			  le2_to_uint(tcm_hcd->app_info.static_config_size));
	if (retval < 0)
		goto exit;

	buf += retval;
	count += retval;

	retval = snprintf(buf, PAGE_SIZE - count, "dynamic config size:  %d\n",
			  le2_to_uint(tcm_hcd->app_info.dynamic_config_size));
	if (retval < 0)
		goto exit;

	buf += retval;
	count += retval;

	retval = snprintf(
		buf, PAGE_SIZE - count, "app config block:  %d\n",
		le2_to_uint(tcm_hcd->app_info.app_config_start_write_block));
	if (retval < 0)
		goto exit;

	buf += retval;
	count += retval;

	retval = snprintf(buf, PAGE_SIZE - count, "app config size:  %d\n",
			  le2_to_uint(tcm_hcd->app_info.app_config_size));
	if (retval < 0)
		goto exit;

	buf += retval;
	count += retval;

	retval = snprintf(
		buf, PAGE_SIZE - count, "touch report config max size:  %d\n",
		le2_to_uint(tcm_hcd->app_info.max_touch_report_config_size));
	if (retval < 0)
		goto exit;

	buf += retval;
	count += retval;

	retval = snprintf(
		buf, PAGE_SIZE - count, "touch report payload max size:  %d\n",
		le2_to_uint(tcm_hcd->app_info.max_touch_report_payload_size));
	if (retval < 0)
		goto exit;

	buf += retval;
	count += retval;

	retval = snprintf(buf, PAGE_SIZE - count, "config id:  ");
	if (retval < 0)
		goto exit;

	buf += retval;
	count += retval;

	for (i = 0; i < sizeof(tcm_hcd->app_info.customer_config_id); i++) {
		retval = snprintf(buf, PAGE_SIZE - count, "0x%2x ",
				  tcm_hcd->app_info.customer_config_id[i]);
		buf += retval;
		count += retval;
	}

	retval = snprintf(buf, PAGE_SIZE - count, "\n");
	if (retval < 0)
		goto exit;

	buf += retval;
	count += retval;

	retval = snprintf(buf, PAGE_SIZE - count, "max x:  %d\n",
			  le2_to_uint(tcm_hcd->app_info.max_x));
	if (retval < 0)
		goto exit;

	buf += retval;
	count += retval;

	retval = snprintf(buf, PAGE_SIZE - count, "max y:  %d\n",
			  le2_to_uint(tcm_hcd->app_info.max_y));
	if (retval < 0)
		goto exit;

	buf += retval;
	count += retval;

	retval = snprintf(buf, PAGE_SIZE - count, "max objects:  %d\n",
			  le2_to_uint(tcm_hcd->app_info.max_objects));
	if (retval < 0)
		goto exit;

	buf += retval;
	count += retval;

	retval = snprintf(buf, PAGE_SIZE - count, "num cols:  %d\n",
			  le2_to_uint(tcm_hcd->app_info.num_of_image_cols));
	if (retval < 0)
		goto exit;

	buf += retval;
	count += retval;

	retval = snprintf(buf, PAGE_SIZE - count, "num rows:  %d\n",
			  le2_to_uint(tcm_hcd->app_info.num_of_image_rows));
	if (retval < 0)
		goto exit;

	buf += retval;
	count += retval;

	retval = snprintf(buf, PAGE_SIZE - count, "num buttons:  %d\n",
			  le2_to_uint(tcm_hcd->app_info.num_of_buttons));
	if (retval < 0)
		goto exit;

	buf += retval;
	count += retval;

	retval = snprintf(buf, PAGE_SIZE - count, "has profile:  %d\n",
			  le2_to_uint(tcm_hcd->app_info.has_hybrid_data));
	if (retval < 0)
		goto exit;

	buf += retval;
	count += retval;

	retval = snprintf(buf, PAGE_SIZE - count, "num force electrodes:  %d\n",
			  le2_to_uint(tcm_hcd->app_info.num_of_force_elecs));
	if (retval < 0)
		goto exit;

	count += retval;

	retval = count;

exit:
	mutex_unlock(&tcm_hcd->extif_mutex);

	return retval;
}

#if (USE_KOBJ_SYSFS)
static ssize_t syna_tcm_sysfs_irq_en_store(struct kobject *kobj,
					   struct kobj_attribute *attr,
					   const char *buf, size_t count)
#else
static ssize_t syna_tcm_sysfs_irq_en_store(struct device *dev,
					   struct device_attribute *attr,
					   const char *buf, size_t count)
#endif
{
	int retval;
	unsigned int input;
	struct device *p_dev;
	struct kobject *p_kobj;
	struct syna_tcm_hcd *tcm_hcd;

	p_kobj = sysfs_dir->parent;
	p_dev = container_of(p_kobj, struct device, kobj);
	tcm_hcd = dev_get_drvdata(p_dev);

	if (sscanf(buf, "%u", &input) != 1)
		return -EINVAL;

	mutex_lock(&tcm_hcd->extif_mutex);

	if (input == 0) {
		retval = tcm_hcd->enable_irq(tcm_hcd, false, true);
		if (retval < 0) {
			LOGE(tcm_hcd->pdev->dev.parent,
			     "Failed to disable interrupt, retval=%d\n",
			     retval);
			goto exit;
		}
	} else if (input == 1) {
		retval = tcm_hcd->enable_irq(tcm_hcd, true, NULL);
		if (retval < 0) {
			LOGE(tcm_hcd->pdev->dev.parent,
			     "Failed to enable interrupt, retval=%d\n", retval);
			goto exit;
		}
	} else {
		retval = -EINVAL;
		goto exit;
	}

	retval = count;

exit:
	mutex_unlock(&tcm_hcd->extif_mutex);

	return retval;
}

#if (USE_KOBJ_SYSFS)
static ssize_t syna_tcm_sysfs_reset_store(struct kobject *kobj,
					  struct kobj_attribute *attr,
					  const char *buf, size_t count)
#else
static ssize_t syna_tcm_sysfs_reset_store(struct device *dev,
					  struct device_attribute *attr,
					  const char *buf, size_t count)
#endif
{
	int retval;
	bool hw_reset;
	unsigned int input;
	struct device *p_dev;
	struct kobject *p_kobj;
	struct syna_tcm_hcd *tcm_hcd;

	p_kobj = sysfs_dir->parent;
	p_dev = container_of(p_kobj, struct device, kobj);
	tcm_hcd = dev_get_drvdata(p_dev);

	if (sscanf(buf, "%u", &input) != 1)
		return -EINVAL;

	if (input == 1)
		hw_reset = false;
	else if (input == 2)
		hw_reset = true;
	else
		return -EINVAL;

	mutex_lock(&tcm_hcd->extif_mutex);

	retval = tcm_hcd->reset_n_reinit(tcm_hcd, hw_reset, true);
	if (retval < 0) {
		LOGE(tcm_hcd->pdev->dev.parent,
		     "Failed to do reset and reinit, retval=%d\n", retval);
		goto exit;
	}

	retval = count;

exit:
	mutex_unlock(&tcm_hcd->extif_mutex);

	return retval;
}

/*
Debug
"echo 1 > cb_debug" : call "queue_work(tcm_hcd->event_wq, &tcm_hcd->early_suspend_work);
"echo 2 > cb_debug" : call "queue_work(tcm_hcd->event_wq, &tcm_hcd->suspend_work);
"echo 3 > cb_debug" : call "queue_work(tcm_hcd->event_wq, &tcm_hcd->resume_work);"
*/

// static int syna_tcm_set_cur_value(int mode, int val);
static void syna_tcm_esd_recovery(struct syna_tcm_hcd *tcm_hcd);

#if (USE_KOBJ_SYSFS)
static ssize_t syna_tcm_sysfs_cb_debug_store(struct kobject *kobj,
					     struct kobj_attribute *attr,
					     const char *buf, size_t count)
#else
static ssize_t syna_tcm_sysfs_cb_debug_store(struct device *dev,
					     struct device_attribute *attr,
					     const char *buf, size_t count)
#endif
{
	int retval;
	unsigned int input;
	struct device *p_dev;
	struct kobject *p_kobj;
	struct syna_tcm_hcd *tcm_hcd;
	unsigned int mode, val;

	p_kobj = sysfs_dir->parent;
	p_dev = container_of(p_kobj, struct device, kobj);
	tcm_hcd = dev_get_drvdata(p_dev);

	if (sscanf(buf, "%u", &input) != 1)
		return -EINVAL;

	mutex_lock(&tcm_hcd->extif_mutex);

	LOGN(tcm_hcd->pdev->dev.parent, "debug get data 0x%02x\n", input);

	mode = input & 0xFF;
	val = (input >> 8) & 0xFF;
	// syna_tcm_set_cur_value(mode, val);

	retval = count;

	mutex_unlock(&tcm_hcd->extif_mutex);

	return retval;
}

#if (USE_KOBJ_SYSFS)
static ssize_t syna_tcm_sysfs_misc_debug_store(struct kobject *kobj,
					       struct kobj_attribute *attr,
					       const char *buf, size_t count)
#else
static ssize_t syna_tcm_sysfs_misc_debug_store(struct device *dev,
					       struct device_attribute *attr,
					       const char *buf, size_t count)
#endif
{
	int retval;
	unsigned int input;
	struct device *p_dev;
	struct kobject *p_kobj;
	struct syna_tcm_hcd *tcm_hcd;

	p_kobj = sysfs_dir->parent;
	p_dev = container_of(p_kobj, struct device, kobj);
	tcm_hcd = dev_get_drvdata(p_dev);

	if (sscanf(buf, "%u", &input) != 1)
		return -EINVAL;

	mutex_lock(&tcm_hcd->extif_mutex);

	LOGN(tcm_hcd->pdev->dev.parent, "misc debug get data 0x%02x\n", input);

	/* 1 -- esd recovery */
	if (input == 1)
		syna_tcm_esd_recovery(tcm_hcd);

	retval = count;

	mutex_unlock(&tcm_hcd->extif_mutex);

	return retval;
}

static ssize_t syna_tcm_sysfs_test_store(struct device *dev,
					 struct device_attribute *attr,
					 const char *buf, size_t count)
{
	int value = 0;

	LOGI(gloab_tcm_hcd->pdev->dev.parent, "%s, buf: %s, count: %zu\n",
	     __func__, buf, count);
	sscanf(buf, "%u", &value);
	touch_fod_test(value);
	return count;
}
static DEVICE_ATTR(fod_test, (S_IRUGO | S_IWUSR | S_IWGRP), NULL,
		   syna_tcm_sysfs_test_store);

#ifdef WATCHDOG_SW
#if (USE_KOBJ_SYSFS)
static ssize_t syna_tcm_sysfs_watchdog_store(struct kobject *kobj,
					     struct kobj_attribute *attr,
					     const char *buf, size_t count)
#else
static ssize_t syna_tcm_sysfs_watchdog_store(struct device *dev,
					     struct device_attribute *attr,
					     const char *buf, size_t count)
#endif
{
	unsigned int input;
	struct device *p_dev;
	struct kobject *p_kobj;
	struct syna_tcm_hcd *tcm_hcd;

	p_kobj = sysfs_dir->parent;
	p_dev = container_of(p_kobj, struct device, kobj);
	tcm_hcd = dev_get_drvdata(p_dev);

	if (sscanf(buf, "%u", &input) != 1)
		return -EINVAL;

	if (input != 0 && input != 1)
		return -EINVAL;

	mutex_lock(&tcm_hcd->extif_mutex);

	tcm_hcd->watchdog.run = input;
	tcm_hcd->update_watchdog(tcm_hcd, input);

	mutex_unlock(&tcm_hcd->extif_mutex);

	return count;
}
#endif

dynamic_config_sysfs(no_doze, DC_NO_DOZE)

	dynamic_config_sysfs(disable_noise_mitigation,
			     DC_DISABLE_NOISE_MITIGATION)

		dynamic_config_sysfs(inhibit_frequency_shift,
				     DC_INHIBIT_FREQUENCY_SHIFT)

			dynamic_config_sysfs(requested_frequency,
					     DC_REQUESTED_FREQUENCY)

				dynamic_config_sysfs(disable_hsync,
						     DC_DISABLE_HSYNC)

					dynamic_config_sysfs(
						rezero_on_exit_deep_sleep,
						DC_REZERO_ON_EXIT_DEEP_SLEEP)

						dynamic_config_sysfs(
							charger_connected,
							DC_CHARGER_CONNECTED)

							dynamic_config_sysfs(
								no_baseline_relaxation,
								DC_NO_BASELINE_RELAXATION)

								dynamic_config_sysfs(
									in_wakeup_gesture_mode,
									DC_IN_WAKEUP_GESTURE_MODE)

									dynamic_config_sysfs(
										stimulus_fingers,
										DC_STIMULUS_FINGERS)

										dynamic_config_sysfs(
											grip_suppression_enabled,
											DC_GRIP_SUPPRESSION_ENABLED)

											dynamic_config_sysfs(
												enable_thick_glove,
												DC_ENABLE_THICK_GLOVE)

												dynamic_config_sysfs(
													enable_glove,
													DC_ENABLE_GLOVE)

													dynamic_config_sysfs(
														enable_touch_and_hold,
														DC_ENABLE_TOUCH_AND_HOLD);

dynamic_config_sysfs(game_mode_ctrl, DC_GAME_MODE_CTRL);

dynamic_config_sysfs(set_report_rate, DC_SET_REPORT_RATE);

dynamic_config_sysfs(enable_gesture_type, DC_GESTURE_TYPE_ENABLE);

int syna_tcm_add_module(struct syna_tcm_module_cb *mod_cb, bool insert)
{
	struct syna_tcm_module_handler *mod_handler;
	unsigned int waitTimeMs = 0;
#define WAIT_MOD_INITIALIZED_MS (5)
#define WAIT_MOD_INITIALIZED_MAX_MS (500)
	static unsigned int mod_pool_wait_cnt = 0;
	while (!mod_pool.initialized) {
		if (mod_pool_wait_cnt > 0) {
			pr_err("%s: mod_pool.initialized is not ready, and waint cnt(%d) > 0, give up this module(type:%d, instsert:%s)\n",
			       __func__, mod_pool_wait_cnt, mod_cb->type,
			       (insert) ? "true" : "false");
			return -EINVAL;
		}
		msleep(WAIT_MOD_INITIALIZED_MS);
		waitTimeMs += WAIT_MOD_INITIALIZED_MS;
		if (waitTimeMs > WAIT_MOD_INITIALIZED_MAX_MS) {
			pr_err("%s: mod_pool.initialized is not ready, and wait timeout, give up this module(type:%d, instsert:%s)\n",
			       __func__, mod_cb->type,
			       (insert) ? "true" : "false");
			return -EINVAL;
		}
	}
	if (waitTimeMs > 0) {
		mod_pool_wait_cnt++;
		pr_err("%s: wait time %d ms for module(type:%d, instsert:%s)\n",
		       __func__, waitTimeMs, mod_cb->type,
		       (insert) ? "true" : "false");
	}

#if 0
	if (!mod_pool.initialized) {
		pr_err("%s: mod_pool.initialized is not ready, give up this module(type:%d, instsert:%s)\n",
			__func__, mod_cb->type, (insert) ? "true" : "false");
		return -EINVAL;
       }


	if (!mod_pool.initialized) {
		mutex_init(&mod_pool.mutex);
		INIT_LIST_HEAD(&mod_pool.list);
		mod_pool.initialized = true;
	}
#endif

	mutex_lock(&mod_pool.mutex);

	if (insert) {
		mod_handler = kzalloc(sizeof(*mod_handler), GFP_KERNEL);
		if (!mod_handler) {
			pr_err("%s: Failed to allocate memory for mod_handler\n",
			       __func__);
			mutex_unlock(&mod_pool.mutex);
			return -ENOMEM;
		}
		mod_handler->mod_cb = mod_cb;
		mod_handler->insert = true;
		mod_handler->detach = false;
		list_add_tail(&mod_handler->link, &mod_pool.list);
	} else if (!list_empty(&mod_pool.list)) {
		list_for_each_entry (mod_handler, &mod_pool.list, link) {
			if (mod_handler->mod_cb->type == mod_cb->type) {
				mod_handler->insert = false;
				mod_handler->detach = true;
				goto exit;
			}
		}
	}

exit:
	mutex_unlock(&mod_pool.mutex);

	if (mod_pool.queue_work)
		queue_work(mod_pool.workqueue, &mod_pool.work);

	return 0;
}
EXPORT_SYMBOL(syna_tcm_add_module);

static void syna_tcm_module_work(struct work_struct *work)
{
	struct syna_tcm_module_handler *mod_handler;
	struct syna_tcm_module_handler *tmp_handler;
	struct syna_tcm_hcd *tcm_hcd = mod_pool.tcm_hcd;

	mutex_lock(&mod_pool.mutex);

	if (!list_empty(&mod_pool.list)) {
		list_for_each_entry_safe (mod_handler, tmp_handler,
					  &mod_pool.list, link) {
			if (mod_handler->insert) {
				if (mod_handler->mod_cb->init)
					mod_handler->mod_cb->init(tcm_hcd);
				mod_handler->insert = false;
			}
			if (mod_handler->detach) {
				if (mod_handler->mod_cb->remove)
					mod_handler->mod_cb->remove(tcm_hcd);
				list_del(&mod_handler->link);
				kfree(mod_handler);
			}
		}
	}

	mutex_unlock(&mod_pool.mutex);

	return;
}

#ifdef REPORT_NOTIFIER
/**
 * syna_tcm_report_notifier() - notify occurrence of report received from device
 *
 * @data: handle of core module
 *
 * The occurrence of the report generated by the device is forwarded to the
 * asynchronous inbox of each registered application module.
 */
static int syna_tcm_report_notifier(void *data)
{
	struct sched_param param = { .sched_priority = NOTIFIER_PRIORITY };
	struct syna_tcm_module_handler *mod_handler;
	struct syna_tcm_hcd *tcm_hcd = data;

	sched_setscheduler(current, SCHED_RR, &param);

	set_current_state(TASK_INTERRUPTIBLE);

	while (!kthread_should_stop()) {
		schedule();

		if (kthread_should_stop())
			break;

		set_current_state(TASK_RUNNING);

		mutex_lock(&mod_pool.mutex);

		if (!list_empty(&mod_pool.list)) {
			list_for_each_entry (mod_handler, &mod_pool.list,
					     link) {
				if (!mod_handler->insert &&
				    !mod_handler->detach &&
				    (mod_handler->mod_cb->asyncbox))
					mod_handler->mod_cb->asyncbox(tcm_hcd);
			}
		}

		mutex_unlock(&mod_pool.mutex);

		set_current_state(TASK_INTERRUPTIBLE);
	};

	return 0;
}
#endif

/**
 * syna_tcm_dispatch_report() - dispatch report received from device
 *
 * @tcm_hcd: handle of core module
 *
 * The report generated by the device is forwarded to the synchronous inbox of
 * each registered application module for further processing. In addition, the
 * report notifier thread is woken up for asynchronous notification of the
 * report occurrence.
 */
static void syna_tcm_dispatch_report(struct syna_tcm_hcd *tcm_hcd)
{
	struct syna_tcm_module_handler *mod_handler;

	LOCK_BUFFER(tcm_hcd->in);
	LOCK_BUFFER(tcm_hcd->report.buffer);

	tcm_hcd->report.buffer.buf = &tcm_hcd->in.buf[MESSAGE_HEADER_SIZE];

	tcm_hcd->report.buffer.buf_size = tcm_hcd->in.buf_size;
	tcm_hcd->report.buffer.buf_size -= MESSAGE_HEADER_SIZE;

	tcm_hcd->report.buffer.data_length = tcm_hcd->payload_length;

	tcm_hcd->report.id = tcm_hcd->status_report_code;

	/* report directly if touch report is received */
	if (tcm_hcd->report.id == REPORT_TOUCH) {
		if (tcm_hcd->report_touch)
			tcm_hcd->report_touch();

	} else {
		/* once an identify report is received, */
		/* reinitialize touch in case any changes */
		if ((tcm_hcd->report.id == REPORT_IDENTIFY) &&
		    IS_FW_MODE(tcm_hcd->id_info.mode)) {
			if (atomic_read(&tcm_hcd->helper.task) == HELP_NONE) {
				atomic_set(&tcm_hcd->helper.task,
					   HELP_TOUCH_REINIT);
				queue_work(tcm_hcd->helper.workqueue,
					   &tcm_hcd->helper.work);
			}
		}

		/* dispatch received report to the other modules */
		mutex_lock(&mod_pool.mutex);

		if (!list_empty(&mod_pool.list)) {
			list_for_each_entry (mod_handler, &mod_pool.list,
					     link) {
				if (!mod_handler->insert &&
				    !mod_handler->detach &&
				    (mod_handler->mod_cb->syncbox))
					mod_handler->mod_cb->syncbox(tcm_hcd);
			}
		}

		tcm_hcd->async_report_id = tcm_hcd->status_report_code;

		mutex_unlock(&mod_pool.mutex);
	}

	UNLOCK_BUFFER(tcm_hcd->report.buffer);
	UNLOCK_BUFFER(tcm_hcd->in);

#ifdef REPORT_NOTIFIER
	wake_up_process(tcm_hcd->notifier_thread);
#endif

	return;
}

/**
 * syna_tcm_dispatch_response() - dispatch response received from device
 *
 * @tcm_hcd: handle of core module
 *
 * The response to a command is forwarded to the sender of the command.
 */
static void syna_tcm_dispatch_response(struct syna_tcm_hcd *tcm_hcd)
{
	int retval;

	if (atomic_read(&tcm_hcd->command_status) != CMD_BUSY)
		return;

	tcm_hcd->response_code = tcm_hcd->status_report_code;

	if (tcm_hcd->payload_length == 0) {
		atomic_set(&tcm_hcd->command_status, CMD_IDLE);
		goto exit;
	}

	LOCK_BUFFER(tcm_hcd->resp);

	retval = syna_tcm_alloc_mem(tcm_hcd, &tcm_hcd->resp,
				    tcm_hcd->payload_length);
	if (retval < 0) {
		LOGE(tcm_hcd->pdev->dev.parent,
		     "Failed to allocate memory for tcm_hcd->resp.buf, retval=%d\n",
		     retval);
		UNLOCK_BUFFER(tcm_hcd->resp);
		atomic_set(&tcm_hcd->command_status, CMD_ERROR);
		goto exit;
	}

	LOCK_BUFFER(tcm_hcd->in);

	retval = secure_memcpy(tcm_hcd->resp.buf, tcm_hcd->resp.buf_size,
			       &tcm_hcd->in.buf[MESSAGE_HEADER_SIZE],
			       tcm_hcd->in.buf_size - MESSAGE_HEADER_SIZE,
			       tcm_hcd->payload_length);
	if (retval < 0) {
		LOGE(tcm_hcd->pdev->dev.parent, "Failed to copy payload\n");
		UNLOCK_BUFFER(tcm_hcd->in);
		UNLOCK_BUFFER(tcm_hcd->resp);
		atomic_set(&tcm_hcd->command_status, CMD_ERROR);
		goto exit;
	}

	tcm_hcd->resp.data_length = tcm_hcd->payload_length;

	UNLOCK_BUFFER(tcm_hcd->in);
	UNLOCK_BUFFER(tcm_hcd->resp);

	atomic_set(&tcm_hcd->command_status, CMD_IDLE);

exit:
	complete(&response_complete);

	return;
}

/**
 * syna_tcm_dispatch_message() - dispatch message received from device
 *
 * @tcm_hcd: handle of core module
 *
 * The information received in the message read in from the device is dispatched
 * to the appropriate destination based on whether the information represents a
 * report or a response to a command.
 */
static void syna_tcm_dispatch_message(struct syna_tcm_hcd *tcm_hcd)
{
	int retval;
	unsigned char *build_id;
	unsigned int payload_length;
	unsigned int max_write_size;

	if (tcm_hcd->status_report_code == REPORT_IDENTIFY) {
		payload_length = tcm_hcd->payload_length;

		LOCK_BUFFER(tcm_hcd->in);

		retval = secure_memcpy(
			(unsigned char *)&tcm_hcd->id_info,
			sizeof(tcm_hcd->id_info),
			&tcm_hcd->in.buf[MESSAGE_HEADER_SIZE],
			tcm_hcd->in.buf_size - MESSAGE_HEADER_SIZE,
			MIN(sizeof(tcm_hcd->id_info), payload_length));
		if (retval < 0) {
			LOGE(tcm_hcd->pdev->dev.parent,
			     "Failed to copy identification info, retval=%d\n",
			     retval);
			UNLOCK_BUFFER(tcm_hcd->in);
			return;
		}

		UNLOCK_BUFFER(tcm_hcd->in);

		build_id = tcm_hcd->id_info.build_id;
		tcm_hcd->packrat_number = le4_to_uint(build_id);

		max_write_size = le2_to_uint(tcm_hcd->id_info.max_write_size);
		tcm_hcd->wr_chunk_size = MIN(max_write_size, WR_CHUNK_SIZE);
		if (tcm_hcd->wr_chunk_size == 0)
			tcm_hcd->wr_chunk_size = max_write_size;

		LOGN(tcm_hcd->pdev->dev.parent,
		     "Received identify report (firmware mode = 0x%02x)\n",
		     tcm_hcd->id_info.mode);

		if (atomic_read(&tcm_hcd->command_status) == CMD_BUSY) {
			switch (tcm_hcd->command) {
			case CMD_RESET:
			case CMD_RUN_BOOTLOADER_FIRMWARE:
			case CMD_RUN_APPLICATION_FIRMWARE:
			case CMD_ENTER_PRODUCTION_TEST_MODE:
			case CMD_ROMBOOT_RUN_BOOTLOADER_FIRMWARE:
				tcm_hcd->response_code = STATUS_OK;
				atomic_set(&tcm_hcd->command_status, CMD_IDLE);
				complete(&response_complete);
				break;
			default:
				LOGN(tcm_hcd->pdev->dev.parent,
				     "Device has been reset\n");
				atomic_set(&tcm_hcd->command_status, CMD_ERROR);
				complete(&response_complete);
				break;
			}
		} else {
			if ((tcm_hcd->id_info.mode == MODE_ROMBOOTLOADER) &&
			    tcm_hcd->in_hdl_mode) {
				if (atomic_read(&tcm_hcd->helper.task) ==
				    HELP_NONE) {
					atomic_set(&tcm_hcd->helper.task,
						   HELP_SEND_ROMBOOT_HDL);
					queue_work(tcm_hcd->helper.workqueue,
						   &tcm_hcd->helper.work);
				} else {
					LOGN(tcm_hcd->pdev->dev.parent,
					     "Helper thread is busy\n");
				}
				return;
			}
		}

#ifdef FORCE_RUN_APPLICATION_FIRMWARE
		if (IS_NOT_FW_MODE(tcm_hcd->id_info.mode) &&
		    !mutex_is_locked(&tcm_hcd->reset_mutex)) {
			if (atomic_read(&tcm_hcd->helper.task) == HELP_NONE) {
				atomic_set(&tcm_hcd->helper.task,
					   HELP_RUN_APPLICATION_FIRMWARE);
				queue_work(tcm_hcd->helper.workqueue,
					   &tcm_hcd->helper.work);
				return;
			}
		}
#endif

		/* To avoid the identify report dispatching during the HDL. */
		if (atomic_read(&tcm_hcd->host_downloading)) {
			LOGN(tcm_hcd->pdev->dev.parent,
			     "Switched to TCM mode and going to download the configs\n");
			return;
		}
	}

	if (tcm_hcd->status_report_code >= REPORT_IDENTIFY)
		syna_tcm_dispatch_report(tcm_hcd);
	else
		syna_tcm_dispatch_response(tcm_hcd);

	return;
}

/**
 * syna_tcm_continued_read() - retrieve entire payload from device
 *
 * @tcm_hcd: handle of core module
 *
 * Read transactions are carried out until the entire payload is retrieved from
 * the device and stored in the handle of the core module.
 */
static int syna_tcm_continued_read(struct syna_tcm_hcd *tcm_hcd)
{
	int retval;
	unsigned char marker;
	unsigned char code;
	unsigned int idx;
	unsigned int offset;
	unsigned int chunks;
	unsigned int chunk_space;
	unsigned int xfer_length;
	unsigned int total_length;
	unsigned int remaining_length;

	total_length = MESSAGE_HEADER_SIZE + tcm_hcd->payload_length + 1;

	remaining_length = total_length - tcm_hcd->read_length;

	LOCK_BUFFER(tcm_hcd->in);

	retval = syna_tcm_realloc_mem(tcm_hcd, &tcm_hcd->in, total_length + 1);
	if (retval < 0) {
		LOGE(tcm_hcd->pdev->dev.parent,
		     "Failed to reallocate memory for tcm_hcd->in.buf, retval=%d\n",
		     retval);
		UNLOCK_BUFFER(tcm_hcd->in);
		return retval;
	}

	/* available chunk space for payload = total chunk size minus header
	 * marker byte and header code byte */
	if (tcm_hcd->rd_chunk_size == 0)
		chunk_space = remaining_length;
	else
		chunk_space = tcm_hcd->rd_chunk_size - 2;

	chunks = ceil_div(remaining_length, chunk_space);

	chunks = chunks == 0 ? 1 : chunks;

	offset = tcm_hcd->read_length;

	LOCK_BUFFER(tcm_hcd->temp);

	for (idx = 0; idx < chunks; idx++) {
		if (remaining_length > chunk_space)
			xfer_length = chunk_space;
		else
			xfer_length = remaining_length;

		if (xfer_length == 1) {
			tcm_hcd->in.buf[offset] = MESSAGE_PADDING;
			offset += xfer_length;
			remaining_length -= xfer_length;
			continue;
		}

		retval = syna_tcm_alloc_mem(tcm_hcd, &tcm_hcd->temp,
					    xfer_length + 2);
		if (retval < 0) {
			LOGE(tcm_hcd->pdev->dev.parent,
			     "Failed to allocate memory for tcm_hcd->temp.buf, retval=%d\n",
			     retval);
			UNLOCK_BUFFER(tcm_hcd->temp);
			UNLOCK_BUFFER(tcm_hcd->in);
			return retval;
		}

		retval = syna_tcm_read(tcm_hcd, tcm_hcd->temp.buf,
				       xfer_length + 2);
		if (retval < 0) {
			LOGE(tcm_hcd->pdev->dev.parent,
			     "Failed to read from device, retval=%d\n", retval);
			UNLOCK_BUFFER(tcm_hcd->temp);
			UNLOCK_BUFFER(tcm_hcd->in);
			return retval;
		}

		marker = tcm_hcd->temp.buf[0];
		code = tcm_hcd->temp.buf[1];

		if (marker != MESSAGE_MARKER) {
			LOGE(tcm_hcd->pdev->dev.parent,
			     "Incorrect header marker (0x%02x)\n", marker);
			UNLOCK_BUFFER(tcm_hcd->temp);
			UNLOCK_BUFFER(tcm_hcd->in);
			return -EIO;
		}

		if (code != STATUS_CONTINUED_READ) {
			LOGE(tcm_hcd->pdev->dev.parent,
			     "Incorrect header code (0x%02x)\n", code);
			UNLOCK_BUFFER(tcm_hcd->temp);
			UNLOCK_BUFFER(tcm_hcd->in);
			return -EIO;
		}

		retval = secure_memcpy(&tcm_hcd->in.buf[offset],
				       tcm_hcd->in.buf_size - offset,
				       &tcm_hcd->temp.buf[2],
				       tcm_hcd->temp.buf_size - 2, xfer_length);
		if (retval < 0) {
			LOGE(tcm_hcd->pdev->dev.parent,
			     "Failed to copy payload, retval=%d\n", retval);
			UNLOCK_BUFFER(tcm_hcd->temp);
			UNLOCK_BUFFER(tcm_hcd->in);
			return retval;
		}

		offset += xfer_length;

		remaining_length -= xfer_length;
	}

	UNLOCK_BUFFER(tcm_hcd->temp);
	UNLOCK_BUFFER(tcm_hcd->in);

	return 0;
}

/**
 * syna_tcm_raw_read() - retrieve specific number of data bytes from device
 *
 * @tcm_hcd: handle of core module
 * @in_buf: buffer for storing data retrieved from device
 * @length: number of bytes to retrieve from device
 *
 * Read transactions are carried out until the specific number of data bytes are
 * retrieved from the device and stored in in_buf.
 */
static int syna_tcm_raw_read(struct syna_tcm_hcd *tcm_hcd,
			     unsigned char *in_buf, unsigned int length)
{
	int retval;
	unsigned char code;
	unsigned int idx;
	unsigned int offset;
	unsigned int chunks;
	unsigned int chunk_space;
	unsigned int xfer_length;
	unsigned int remaining_length;

	LOGN(tcm_hcd->pdev->dev.parent, "-----enter-----length:%d\n", length);

	if (length < 2) {
		LOGE(tcm_hcd->pdev->dev.parent, "Invalid length information\n");
		return -EINVAL;
	}

	/* minus header marker byte and header code byte */
	remaining_length = length - 2;

	/* available chunk space for data = total chunk size minus header marker
	 * byte and header code byte */
	if (tcm_hcd->rd_chunk_size == 0)
		chunk_space = remaining_length;
	else
		chunk_space = tcm_hcd->rd_chunk_size - 2;

	chunks = ceil_div(remaining_length, chunk_space);

	chunks = chunks == 0 ? 1 : chunks;

	offset = 0;

	LOCK_BUFFER(tcm_hcd->temp);

	for (idx = 0; idx < chunks; idx++) {
		if (remaining_length > chunk_space)
			xfer_length = chunk_space;
		else
			xfer_length = remaining_length;

		if (xfer_length == 1) {
			in_buf[offset] = MESSAGE_PADDING;
			offset += xfer_length;
			remaining_length -= xfer_length;
			continue;
		}

		retval = syna_tcm_alloc_mem(tcm_hcd, &tcm_hcd->temp,
					    xfer_length + 2);
		if (retval < 0) {
			LOGE(tcm_hcd->pdev->dev.parent,
			     "Failed to allocate memory for tcm_hcd->temp.buf, retval=%d\n",
			     retval);
			UNLOCK_BUFFER(tcm_hcd->temp);
			return retval;
		}

		retval = syna_tcm_read(tcm_hcd, tcm_hcd->temp.buf,
				       xfer_length + 2);
		if (retval < 0) {
			LOGE(tcm_hcd->pdev->dev.parent,
			     "Failed to read from device, retval=%d\n", retval);
			UNLOCK_BUFFER(tcm_hcd->temp);
			return retval;
		}

		code = tcm_hcd->temp.buf[1];

		if (idx == 0) {
			retval = secure_memcpy(&in_buf[0], length,
					       &tcm_hcd->temp.buf[0],
					       tcm_hcd->temp.buf_size,
					       xfer_length + 2);
		} else {
			if (code != STATUS_CONTINUED_READ) {
				LOGE(tcm_hcd->pdev->dev.parent,
				     "Incorrect header code (0x%02x)\n", code);
				UNLOCK_BUFFER(tcm_hcd->temp);
				return -EIO;
			}

			retval = secure_memcpy(&in_buf[offset], length - offset,
					       &tcm_hcd->temp.buf[2],
					       tcm_hcd->temp.buf_size - 2,
					       xfer_length);
		}
		if (retval < 0) {
			LOGE(tcm_hcd->pdev->dev.parent,
			     "Failed to copy data, retval=%d\n", retval);
			UNLOCK_BUFFER(tcm_hcd->temp);
			return retval;
		}

		if (idx == 0)
			offset += (xfer_length + 2);
		else
			offset += xfer_length;

		remaining_length -= xfer_length;
	}

	UNLOCK_BUFFER(tcm_hcd->temp);

	return 0;
}

/**
 * syna_tcm_raw_write() - write command/data to device without receiving
 * response
 *
 * @tcm_hcd: handle of core module
 * @command: command to send to device
 * @data: data to send to device
 * @length: length of data in bytes
 *
 * A command and its data, if any, are sent to the device.
 */
static int syna_tcm_raw_write(struct syna_tcm_hcd *tcm_hcd,
			      unsigned char command, unsigned char *data,
			      unsigned int length)
{
	int retval;
	unsigned int idx;
	unsigned int chunks;
	unsigned int chunk_space;
	unsigned int xfer_length;
	unsigned int remaining_length;

	remaining_length = length;

	/* available chunk space for data = total chunk size minus command
	 * byte */
	if (tcm_hcd->wr_chunk_size == 0)
		chunk_space = remaining_length;
	else
		chunk_space = tcm_hcd->wr_chunk_size - 1;

	chunks = ceil_div(remaining_length, chunk_space);

	chunks = chunks == 0 ? 1 : chunks;

	LOCK_BUFFER(tcm_hcd->out);

	for (idx = 0; idx < chunks; idx++) {
		if (remaining_length > chunk_space)
			xfer_length = chunk_space;
		else
			xfer_length = remaining_length;

		retval = syna_tcm_alloc_mem(tcm_hcd, &tcm_hcd->out,
					    xfer_length + 1);
		if (retval < 0) {
			LOGE(tcm_hcd->pdev->dev.parent,
			     "Failed to allocate memory for tcm_hcd->out.buf, retval=%d\n",
			     retval);
			UNLOCK_BUFFER(tcm_hcd->out);
			return retval;
		}

		if (idx == 0)
			tcm_hcd->out.buf[0] = command;
		else
			tcm_hcd->out.buf[0] = CMD_CONTINUE_WRITE;

		if (xfer_length) {
			retval = secure_memcpy(&tcm_hcd->out.buf[1],
					       tcm_hcd->out.buf_size - 1,
					       &data[idx * chunk_space],
					       remaining_length, xfer_length);
			if (retval < 0) {
				LOGE(tcm_hcd->pdev->dev.parent,
				     "Failed to copy data, retval=%d\n",
				     retval);
				UNLOCK_BUFFER(tcm_hcd->out);
				return retval;
			}
		}

		retval = syna_tcm_write(tcm_hcd, tcm_hcd->out.buf,
					xfer_length + 1);
		if (retval < 0) {
			LOGE(tcm_hcd->pdev->dev.parent,
			     "Failed to write to device, retval=%d\n", retval);
			UNLOCK_BUFFER(tcm_hcd->out);
			return retval;
		}

		remaining_length -= xfer_length;
	}

	UNLOCK_BUFFER(tcm_hcd->out);

	return 0;
}

/**
 * syna_tcm_read_message() - read message from device
 *
 * @tcm_hcd: handle of core module
 * @in_buf: buffer for storing data in raw read mode
 * @length: length of data in bytes in raw read mode
 *
 * If in_buf is not NULL, raw read mode is used and syna_tcm_raw_read() is
 * called. Otherwise, a message including its entire payload is retrieved from
 * the device and dispatched to the appropriate destination.
 */
static int syna_tcm_read_message(struct syna_tcm_hcd *tcm_hcd,
				 unsigned char *in_buf, unsigned int length)
{
	int retval;
	bool retry;
	unsigned int total_length;
	struct syna_tcm_message_header *header;
	int retry_cnt = 0;

	mutex_lock(&tcm_hcd->rw_ctrl_mutex);

	if (in_buf != NULL) {
		retval = syna_tcm_raw_read(tcm_hcd, in_buf, length);
		goto exit;
	}

	retry = true;

retry:
	LOCK_BUFFER(tcm_hcd->in);

	retval = syna_tcm_read(tcm_hcd, tcm_hcd->in.buf, tcm_hcd->read_length);
	if (retval < 0) {
		LOGE(tcm_hcd->pdev->dev.parent,
		     "Failed to read from device, retval=%d\n", retval);
		UNLOCK_BUFFER(tcm_hcd->in);
		if (retry) {
			usleep_range(READ_RETRY_US_MIN, READ_RETRY_US_MAX);
			retry = false;
			goto retry;
		}
		goto exit;
	}

	header = (struct syna_tcm_message_header *)tcm_hcd->in.buf;

	if (header->marker != MESSAGE_MARKER) {
		LOGE(tcm_hcd->pdev->dev.parent,
		     "Incorrect header marker (0x%02x)\n", header->marker);
		UNLOCK_BUFFER(tcm_hcd->in);
		retval = -ENXIO;
		if (retry) {
			usleep_range(READ_RETRY_US_MIN, READ_RETRY_US_MAX);
			//retry = false;
			if (retry_cnt < 20) {
				retry_cnt++;
			} else {
				retry_cnt = 0;
				retry = false;
			}
			goto retry;
		}
		goto exit;
	}

	tcm_hcd->status_report_code = header->code;

	tcm_hcd->payload_length = le2_to_uint(header->length);

	LOGD(tcm_hcd->pdev->dev.parent, "Status report code = 0x%02x\n",
	     tcm_hcd->status_report_code);

	LOGD(tcm_hcd->pdev->dev.parent, "Payload length = %d\n",
	     tcm_hcd->payload_length);

	if (tcm_hcd->status_report_code <= STATUS_ERROR ||
	    tcm_hcd->status_report_code == STATUS_INVALID) {
		switch (tcm_hcd->status_report_code) {
		case STATUS_OK:
			break;
		case STATUS_CONTINUED_READ:
			LOGD(tcm_hcd->pdev->dev.parent,
			     "Out-of-sync continued read\n");
		case STATUS_IDLE:
		case STATUS_BUSY:
			tcm_hcd->payload_length = 0;
			UNLOCK_BUFFER(tcm_hcd->in);
			retval = 0;
			goto exit;
		default:
			LOGE(tcm_hcd->pdev->dev.parent,
			     "Incorrect Status code (0x%02x)\n",
			     tcm_hcd->status_report_code);
			if (tcm_hcd->status_report_code == STATUS_INVALID) {
				if (retry) {
					usleep_range(READ_RETRY_US_MIN,
						     READ_RETRY_US_MAX);
					retry = false;
					goto retry;
				} else {
					tcm_hcd->payload_length = 0;
				}
			}
		}
	}

	total_length = MESSAGE_HEADER_SIZE + tcm_hcd->payload_length + 1;

#ifdef PREDICTIVE_READING
	if (total_length <= tcm_hcd->read_length) {
		goto check_padding;
	} else if (total_length - 1 == tcm_hcd->read_length) {
		tcm_hcd->in.buf[total_length - 1] = MESSAGE_PADDING;
		goto check_padding;
	}
#else
	if (tcm_hcd->payload_length == 0) {
		tcm_hcd->in.buf[total_length - 1] = MESSAGE_PADDING;
		goto check_padding;
	}
#endif

	UNLOCK_BUFFER(tcm_hcd->in);

	retval = syna_tcm_continued_read(tcm_hcd);
	if (retval < 0) {
		LOGE(tcm_hcd->pdev->dev.parent,
		     "Failed to do continued read, retval=%d\n", retval);
		goto exit;
	};

	LOCK_BUFFER(tcm_hcd->in);

	tcm_hcd->in.buf[0] = MESSAGE_MARKER;
	tcm_hcd->in.buf[1] = tcm_hcd->status_report_code;
	tcm_hcd->in.buf[2] = (unsigned char)tcm_hcd->payload_length;
	tcm_hcd->in.buf[3] = (unsigned char)(tcm_hcd->payload_length >> 8);

check_padding:
	if (tcm_hcd->in.buf[total_length - 1] != MESSAGE_PADDING) {
		LOGE(tcm_hcd->pdev->dev.parent,
		     "Incorrect message padding byte (0x%02x)\n",
		     tcm_hcd->in.buf[total_length - 1]);
		UNLOCK_BUFFER(tcm_hcd->in);
		retval = -EIO;
		goto exit;
	}

	UNLOCK_BUFFER(tcm_hcd->in);

#ifdef PREDICTIVE_READING
	total_length = MAX(total_length, MIN_READ_LENGTH);
	tcm_hcd->read_length = MIN(total_length, tcm_hcd->rd_chunk_size);
	if (tcm_hcd->rd_chunk_size == 0)
		tcm_hcd->read_length = total_length;
#endif
	if (tcm_hcd->is_detected)
		syna_tcm_dispatch_message(tcm_hcd);

	retval = 0;

exit:
	if (retval < 0) {
		if (atomic_read(&tcm_hcd->command_status) == CMD_BUSY) {
			atomic_set(&tcm_hcd->command_status, CMD_ERROR);
			complete(&response_complete);
		}
	}

	mutex_unlock(&tcm_hcd->rw_ctrl_mutex);

	return retval;
}

/**
 * syna_tcm_write_message() - write message to device and receive response
 *
 * @tcm_hcd: handle of core module
 * @command: command to send to device
 * @payload: payload of command
 * @length: length of payload in bytes
 * @resp_buf: buffer for storing command response
 * @resp_buf_size: size of response buffer in bytes
 * @resp_length: length of command response in bytes
 * @response_code: status code returned in command response
 * @polling_delay_ms: delay time after sending command before resuming polling
 *
 * If resp_buf is NULL, raw write mode is used and syna_tcm_raw_write() is
 * called. Otherwise, a command and its payload, if any, are sent to the device
 * and the response to the command generated by the device is read in.
 */
static int syna_tcm_write_message(struct syna_tcm_hcd *tcm_hcd,
				  unsigned char command, unsigned char *payload,
				  unsigned int length, unsigned char **resp_buf,
				  unsigned int *resp_buf_size,
				  unsigned int *resp_length,
				  unsigned char *response_code,
				  unsigned int polling_delay_ms)
{
	int retval;
	unsigned int idx;
	unsigned int chunks;
	unsigned int chunk_space;
	unsigned int xfer_length;
	unsigned int remaining_length;
	unsigned int command_status;
	bool is_romboot_hdl = (command == CMD_ROMBOOT_DOWNLOAD) ? true : false;
	bool is_hdl_reset = (command == CMD_RESET) && (tcm_hcd->in_hdl_mode);

	if (response_code != NULL)
		*response_code = STATUS_INVALID;

	if (!tcm_hcd->do_polling && current->pid == tcm_hcd->isr_pid) {
		LOGE(tcm_hcd->pdev->dev.parent, "Invalid execution context\n");
		return -EINVAL;
	}

	mutex_lock(&tcm_hcd->command_mutex);

	mutex_lock(&tcm_hcd->rw_ctrl_mutex);

	if (resp_buf == NULL) {
		retval = syna_tcm_raw_write(tcm_hcd, command, payload, length);
		mutex_unlock(&tcm_hcd->rw_ctrl_mutex);
		goto exit;
	}

	if (tcm_hcd->do_polling && polling_delay_ms) {
		cancel_delayed_work_sync(&tcm_hcd->polling_work);
		flush_workqueue(tcm_hcd->polling_workqueue);
	}

	atomic_set(&tcm_hcd->command_status, CMD_BUSY);

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0))
	reinit_completion(&response_complete);
#else
	INIT_COMPLETION(response_complete);
#endif

	tcm_hcd->command = command;

	LOCK_BUFFER(tcm_hcd->resp);

	tcm_hcd->resp.buf = *resp_buf;
	tcm_hcd->resp.buf_size = *resp_buf_size;
	tcm_hcd->resp.data_length = 0;

	UNLOCK_BUFFER(tcm_hcd->resp);

	/* adding two length bytes as part of payload */
	remaining_length = length + 2;

	/* available chunk space for payload = total chunk size minus command
	 * byte */
	if (tcm_hcd->wr_chunk_size == 0)
		chunk_space = remaining_length;
	else
		chunk_space = tcm_hcd->wr_chunk_size - 1;

	if (is_romboot_hdl) {
		if (WR_CHUNK_SIZE) {
			chunk_space = WR_CHUNK_SIZE - 1;
			chunk_space = chunk_space -
				      (chunk_space % ROMBOOT_DOWNLOAD_UNIT);
		} else {
			chunk_space = remaining_length;
		}
	}

	chunks = ceil_div(remaining_length, chunk_space);

	chunks = chunks == 0 ? 1 : chunks;

	LOGD(tcm_hcd->pdev->dev.parent, "Command = 0x%02x\n", command);

	LOCK_BUFFER(tcm_hcd->out);

	for (idx = 0; idx < chunks; idx++) {
		if (remaining_length > chunk_space)
			xfer_length = chunk_space;
		else
			xfer_length = remaining_length;

		retval = syna_tcm_alloc_mem(tcm_hcd, &tcm_hcd->out,
					    xfer_length + 1);
		if (retval < 0) {
			LOGE(tcm_hcd->pdev->dev.parent,
			     "Failed to allocate memory for tcm_hcd->out.buf, retval=%d\n",
			     retval);
			UNLOCK_BUFFER(tcm_hcd->out);
			mutex_unlock(&tcm_hcd->rw_ctrl_mutex);
			goto exit;
		}

		if (idx == 0) {
			tcm_hcd->out.buf[0] = command;
			tcm_hcd->out.buf[1] = (unsigned char)length;
			tcm_hcd->out.buf[2] = (unsigned char)(length >> 8);

			if (xfer_length > 2) {
				retval = secure_memcpy(
					&tcm_hcd->out.buf[3],
					tcm_hcd->out.buf_size - 3, payload,
					remaining_length - 2, xfer_length - 2);
				if (retval < 0) {
					LOGE(tcm_hcd->pdev->dev.parent,
					     "Failed to copy payload, retval=%d\n",
					     retval);
					UNLOCK_BUFFER(tcm_hcd->out);
					mutex_unlock(&tcm_hcd->rw_ctrl_mutex);
					goto exit;
				}
			}
		} else {
			tcm_hcd->out.buf[0] = CMD_CONTINUE_WRITE;

			retval = secure_memcpy(&tcm_hcd->out.buf[1],
					       tcm_hcd->out.buf_size - 1,
					       &payload[idx * chunk_space - 2],
					       remaining_length, xfer_length);
			if (retval < 0) {
				LOGE(tcm_hcd->pdev->dev.parent,
				     "Failed to copy payload, retval=%d\n",
				     retval);
				UNLOCK_BUFFER(tcm_hcd->out);
				mutex_unlock(&tcm_hcd->rw_ctrl_mutex);
				goto exit;
			}
		}

		/* 		LOGE(tcm_hcd->pdev->dev.parent,
					"Before cmd = 0x%02x\n", command); */
		retval = syna_tcm_write(tcm_hcd, tcm_hcd->out.buf,
					xfer_length + 1);
		if (retval < 0) {
			LOGE(tcm_hcd->pdev->dev.parent,
			     "Failed to write to device, retval=%d\n", retval);
			UNLOCK_BUFFER(tcm_hcd->out);
			mutex_unlock(&tcm_hcd->rw_ctrl_mutex);
			goto exit;
		}
		/* 		LOGE(tcm_hcd->pdev->dev.parent,
					"After cmd = 0x%02x\n", command); */
		remaining_length -= xfer_length;

		if (chunks > 1)
			usleep_range(WRITE_DELAY_US_MIN, WRITE_DELAY_US_MAX);
	}

	UNLOCK_BUFFER(tcm_hcd->out);

	mutex_unlock(&tcm_hcd->rw_ctrl_mutex);

	if (is_hdl_reset)
		goto exit;

	if (tcm_hcd->do_polling && polling_delay_ms) {
		queue_delayed_work(tcm_hcd->polling_workqueue,
				   &tcm_hcd->polling_work,
				   msecs_to_jiffies(polling_delay_ms));
	}

	retval = wait_for_completion_timeout(
		&response_complete, msecs_to_jiffies(RESPONSE_TIMEOUT_MS));
	if (retval == 0) {
		LOGE(tcm_hcd->pdev->dev.parent,
		     "Timed out waiting for response (command 0x%02x), irq: %s, ATTN: %d\n",
		     tcm_hcd->command,
		     (tcm_hcd->irq_enabled) ? STR(TRUE) : STR(FALSE),
		     gpio_get_value(tcm_hcd->hw_if->bdata->irq_gpio));
		retval = -ETIME;
		goto exit;
	}

	command_status = atomic_read(&tcm_hcd->command_status);
	if (command_status != CMD_IDLE) {
		LOGE(tcm_hcd->pdev->dev.parent,
		     "Failed to get valid response (command 0x%02x)\n",
		     tcm_hcd->command);
		retval = -EIO;
		goto exit;
	}

	LOCK_BUFFER(tcm_hcd->resp);

	if (tcm_hcd->response_code != STATUS_OK) {
		if (tcm_hcd->resp.data_length) {
			LOGE(tcm_hcd->pdev->dev.parent,
			     "Error code = 0x%02x (command 0x%02x)\n",
			     tcm_hcd->resp.buf[0], tcm_hcd->command);
		}
		retval = -EIO;
	} else {
		retval = 0;
	}

	*resp_buf = tcm_hcd->resp.buf;
	*resp_buf_size = tcm_hcd->resp.buf_size;
	*resp_length = tcm_hcd->resp.data_length;

	if (response_code != NULL)
		*response_code = tcm_hcd->response_code;

	UNLOCK_BUFFER(tcm_hcd->resp);

exit:
	tcm_hcd->command = CMD_NONE;

	atomic_set(&tcm_hcd->command_status, CMD_IDLE);

	mutex_unlock(&tcm_hcd->command_mutex);

	return retval;
}

static int syna_tcm_wait_hdl(struct syna_tcm_hcd *tcm_hcd)
{
	int retval;

	msleep(HOST_DOWNLOAD_WAIT_MS);

	if (!atomic_read(&tcm_hcd->host_downloading))
		return 0;

	retval = wait_event_interruptible_timeout(
		tcm_hcd->hdl_wq, !atomic_read(&tcm_hcd->host_downloading),
		msecs_to_jiffies(HOST_DOWNLOAD_TIMEOUT_MS));
	if (retval == 0) {
		LOGE(tcm_hcd->pdev->dev.parent,
		     "Timed out waiting for completion of host download\n");
		atomic_set(&tcm_hcd->host_downloading, 0);
		retval = -EIO;
	} else {
		retval = 0;
	}

	return retval;
}

static void syna_tcm_check_hdl(struct syna_tcm_hcd *tcm_hcd, unsigned char id)
{
	struct syna_tcm_module_handler *mod_handler;

	LOCK_BUFFER(tcm_hcd->report.buffer);

	tcm_hcd->report.buffer.buf = NULL;
	tcm_hcd->report.buffer.buf_size = 0;
	tcm_hcd->report.buffer.data_length = 0;
	tcm_hcd->report.id = id;

	UNLOCK_BUFFER(tcm_hcd->report.buffer);

	mutex_lock(&mod_pool.mutex);

	if (!list_empty(&mod_pool.list)) {
		list_for_each_entry (mod_handler, &mod_pool.list, link) {
			if (!mod_handler->insert && !mod_handler->detach &&
			    (mod_handler->mod_cb->syncbox))
				mod_handler->mod_cb->syncbox(tcm_hcd);
		}
	}

	mutex_unlock(&mod_pool.mutex);

	return;
}

#ifdef WATCHDOG_SW
static void syna_tcm_update_watchdog(struct syna_tcm_hcd *tcm_hcd, bool en)
{
	cancel_delayed_work_sync(&tcm_hcd->watchdog.work);
	flush_workqueue(tcm_hcd->watchdog.workqueue);

	if (!tcm_hcd->watchdog.run) {
		tcm_hcd->watchdog.count = 0;
		return;
	}

	if (en) {
		queue_delayed_work(tcm_hcd->watchdog.workqueue,
				   &tcm_hcd->watchdog.work,
				   msecs_to_jiffies(WATCHDOG_DELAY_MS));
	} else {
		tcm_hcd->watchdog.count = 0;
	}

	return;
}

static void syna_tcm_watchdog_work(struct work_struct *work)
{
	int retval;
	unsigned char marker;
	struct delayed_work *delayed_work =
		container_of(work, struct delayed_work, work);
	struct syna_tcm_watchdog *watchdog =
		container_of(delayed_work, struct syna_tcm_watchdog, work);
	struct syna_tcm_hcd *tcm_hcd =
		container_of(watchdog, struct syna_tcm_hcd, watchdog);

	if (mutex_is_locked(&tcm_hcd->rw_ctrl_mutex))
		goto exit;

	mutex_lock(&tcm_hcd->rw_ctrl_mutex);

	retval = syna_tcm_read(tcm_hcd, &marker, 1);

	mutex_unlock(&tcm_hcd->rw_ctrl_mutex);

	if (retval < 0 || marker != MESSAGE_MARKER) {
		LOGE(tcm_hcd->pdev->dev.parent,
		     "Failed to read from device, retval=%d\n", retval);

		tcm_hcd->watchdog.count++;

		if (tcm_hcd->watchdog.count >= WATCHDOG_TRIGGER_COUNT) {
			retval = tcm_hcd->reset_n_reinit(tcm_hcd, true, false);
			if (retval < 0) {
				LOGE(tcm_hcd->pdev->dev.parent,
				     "Failed to do reset and reinit, retval=%d\n",
				     retval);
			}
			tcm_hcd->watchdog.count = 0;
		}
	}

exit:
	queue_delayed_work(tcm_hcd->watchdog.workqueue, &tcm_hcd->watchdog.work,
			   msecs_to_jiffies(WATCHDOG_DELAY_MS));

	return;
}
#endif

static void syna_tcm_polling_work(struct work_struct *work)
{
	int retval;
	struct delayed_work *delayed_work =
		container_of(work, struct delayed_work, work);
	struct syna_tcm_hcd *tcm_hcd =
		container_of(delayed_work, struct syna_tcm_hcd, polling_work);

	if (!tcm_hcd->do_polling)
		return;

	retval = tcm_hcd->read_message(tcm_hcd, NULL, 0);
	if (retval < 0) {
		LOGE(tcm_hcd->pdev->dev.parent,
		     "Failed to read message, retval=%d\n", retval);
		if (retval == -ENXIO && tcm_hcd->hw_if->bus_io->type == BUS_SPI)
			syna_tcm_check_hdl(tcm_hcd, REPORT_HDL_F35);
	}

	if (!(tcm_hcd->in_suspend && retval < 0)) {
		queue_delayed_work(tcm_hcd->polling_workqueue,
				   &tcm_hcd->polling_work,
				   msecs_to_jiffies(POLLING_DELAY_MS));
	}

	return;
}

static irqreturn_t syna_tcm_isr(int irq, void *data)
{
	int retval;
	struct syna_tcm_hcd *tcm_hcd = data;
	const struct syna_tcm_board_data *bdata = tcm_hcd->hw_if->bdata;

	if (unlikely(gpio_get_value(bdata->irq_gpio) != bdata->irq_on_state))
		goto exit;

	tcm_hcd->isr_pid = current->pid;

	retval = tcm_hcd->read_message(tcm_hcd, NULL, 0);
	if (retval < 0) {
		if (tcm_hcd->sensor_type == TYPE_F35)
			syna_tcm_check_hdl(tcm_hcd, REPORT_HDL_F35);
		else
			LOGE(tcm_hcd->pdev->dev.parent,
			     "Failed to read message, retval=%d\n", retval);
	}

exit:
	return IRQ_HANDLED;
}

static int syna_tcm_enable_irq(struct syna_tcm_hcd *tcm_hcd, bool en, bool ns)
{
	int retval;
	const struct syna_tcm_board_data *bdata = tcm_hcd->hw_if->bdata;
	static bool irq_freed = true;

	mutex_lock(&tcm_hcd->irq_en_mutex);

	if (en) {
		if (tcm_hcd->irq_enabled) {
			LOGD(tcm_hcd->pdev->dev.parent,
			     "Interrupt already enabled\n");
			retval = 0;
			goto exit;
		}

		if (bdata->irq_gpio < 0) {
			LOGE(tcm_hcd->pdev->dev.parent, "Invalid IRQ GPIO\n");
			retval = -EINVAL;
			goto queue_polling_work;
		}

		if (irq_freed) {
			retval = request_threaded_irq(tcm_hcd->irq, NULL,
						      syna_tcm_isr,
						      bdata->irq_flags,
						      PLATFORM_DRIVER_NAME,
						      tcm_hcd);
			if (retval < 0) {
				LOGE(tcm_hcd->pdev->dev.parent,
				     "Failed to create interrupt thread, retval=%d\n",
				     retval);
			}
		} else {
			enable_irq(tcm_hcd->irq);
			retval = 0;
		}

	queue_polling_work:
		if (retval < 0) {
#ifdef FALL_BACK_ON_POLLING
			queue_delayed_work(tcm_hcd->polling_workqueue,
					   &tcm_hcd->polling_work,
					   msecs_to_jiffies(POLLING_DELAY_MS));
			tcm_hcd->do_polling = true;
			retval = 0;
#endif
		}

		if (retval < 0)
			goto exit;
		else
			msleep(ENABLE_IRQ_DELAY_MS);
	} else {
		if (!tcm_hcd->irq_enabled) {
			LOGD(tcm_hcd->pdev->dev.parent,
			     "Interrupt already disabled\n");
			retval = 0;
			goto exit;
		}

		if (bdata->irq_gpio >= 0) {
			if (ns) {
				disable_irq_nosync(tcm_hcd->irq);
			} else {
				disable_irq(tcm_hcd->irq);
				free_irq(tcm_hcd->irq, tcm_hcd);
			}
			irq_freed = !ns;
		}

		if (ns) {
			cancel_delayed_work(&tcm_hcd->polling_work);
		} else {
			cancel_delayed_work_sync(&tcm_hcd->polling_work);
			flush_workqueue(tcm_hcd->polling_workqueue);
		}

		tcm_hcd->do_polling = false;
	}

	retval = 0;

exit:
	if (retval == 0)
		tcm_hcd->irq_enabled = en;

	mutex_unlock(&tcm_hcd->irq_en_mutex);

	return retval;
}

/**
 * syna_tcm_set_gpio() - request system gpio and set gpio config O/I
 * 
 * gpio_request --- request system gpio
 * gpio_direction_input  --- input gpio
 * gpio_direction_output --- output gpio
 */
static int syna_tcm_set_gpio(struct syna_tcm_hcd *tcm_hcd, int gpio,
			     bool config, int dir, int state)
{
	int retval;
	char label[16];

	if (config) {
		retval = snprintf(label, 16, "tcm_gpio_%d\n", gpio);
		if (retval < 0) {
			LOGE(tcm_hcd->pdev->dev.parent,
			     "Failed to set GPIO label, retval=%d\n", retval);
			return retval;
		}

		retval = gpio_request(gpio, label);
		if (retval < 0) {
			LOGE(tcm_hcd->pdev->dev.parent,
			     "Failed to request GPIO %d, retval=%d\n", gpio,
			     retval);
			return retval;
		}

		if (dir == 0)
			retval = gpio_direction_input(gpio);
		else
			retval = gpio_direction_output(gpio, state);
		if (retval < 0) {
			LOGE(tcm_hcd->pdev->dev.parent,
			     "Failed to set GPIO %d direction, retval=%d\n",
			     gpio, retval);
			return retval;
		}
	} else {
		gpio_free(gpio);
	}

	return 0;
}

/**
 * syna_tcm_config_gpio() - set gpio config
 * 
 */
static int syna_tcm_config_gpio(struct syna_tcm_hcd *tcm_hcd)
{
	int retval;
	const struct syna_tcm_board_data *bdata = tcm_hcd->hw_if->bdata;

	LOGE(tcm_hcd->pdev->dev.parent, "config gpio\n");
	if (bdata->power_gpio >= 0) {
		retval = syna_tcm_set_gpio(tcm_hcd, bdata->power_gpio, true, 1,
					   !bdata->power_on_state);
		LOGI(tcm_hcd->pdev->dev.parent, "set power_gpio %d:\n",
		     bdata->power_gpio);
		if (retval < 0) {
			LOGE(tcm_hcd->pdev->dev.parent,
			     "Failed to configure power GPIO, retval=%d\n",
			     retval);
			goto err_set_gpio_power;
		}
	}

	if (bdata->reset_gpio >= 0) {
		retval = syna_tcm_set_gpio(tcm_hcd, bdata->reset_gpio, true, 1,
					   !bdata->reset_on_state);
		LOGI(tcm_hcd->pdev->dev.parent, "set reset_gpio %d:\n",
		     bdata->reset_gpio);
		if (retval < 0) {
			LOGE(tcm_hcd->pdev->dev.parent,
			     "Failed to configure reset GPIO, retval=%d\n",
			     retval);
			goto err_set_gpio_reset;
		}
	}

	if (bdata->power_gpio >= 0) {
		LOGE(tcm_hcd->pdev->dev.parent, "%s set power_delay_ms:%d \n",
		     __func__, bdata->power_delay_ms);
		gpio_set_value(bdata->power_gpio, bdata->power_on_state);
		msleep(bdata->power_delay_ms);
	}

	if (bdata->reset_gpio >= 0) {
		LOGE(tcm_hcd->pdev->dev.parent,
		     "%s set reset_active_ms:%d reset_delay_ms:%d \n", __func__,
		     bdata->reset_active_ms, bdata->reset_delay_ms);
		gpio_set_value(bdata->reset_gpio, bdata->reset_on_state);
		msleep(bdata->reset_active_ms);
		gpio_set_value(bdata->reset_gpio, !bdata->reset_on_state);
		msleep(bdata->reset_delay_ms);
	}

	if (bdata->irq_gpio >= 0) {
		retval =
			syna_tcm_set_gpio(tcm_hcd, bdata->irq_gpio, true, 0, 0);
		LOGI(tcm_hcd->pdev->dev.parent, "set irq_gpio %d:\n",
		     bdata->irq_gpio);
		if (retval < 0) {
			LOGE(tcm_hcd->pdev->dev.parent,
			     "Failed to configure interrupt GPIO, retval=%d\n",
			     retval);
			goto err_set_gpio_irq;
		}
	}

	return 0;

err_set_gpio_irq:
err_set_gpio_reset:
	if (bdata->power_gpio >= 0)
		syna_tcm_set_gpio(tcm_hcd, bdata->power_gpio, false, 0, 0);

err_set_gpio_power:
	if (bdata->irq_gpio >= 0)
		syna_tcm_set_gpio(tcm_hcd, bdata->irq_gpio, false, 0, 0);

	return retval;
}

static int syna_tcm_enable_regulator(struct syna_tcm_hcd *tcm_hcd, bool on)
{
	int ret = 0;
	LOGE(tcm_hcd->pdev->dev.parent, "syna_tcm_enable_regulator\n");

	if (on) {
		ret = regulator_enable(tcm_hcd->avdd);
		if (ret) {
			LOGE(tcm_hcd->pdev->dev.parent,
			     "Failed to enable avdd:%d", ret);
			return ret;
		}
		usleep_range(3000, 3100);
		ret = regulator_enable(tcm_hcd->iovdd);
		if (ret) {
			regulator_disable(tcm_hcd->avdd);
			LOGE(tcm_hcd->pdev->dev.parent,
			     "Failed to enable iovdd:%d", ret);
			return ret;
		}

		return 0;
	}

	/*power off process */
	ret = regulator_disable(tcm_hcd->iovdd);
	if (ret)
		LOGE(tcm_hcd->pdev->dev.parent, "Failed to disable iovdd:%d",
		     ret);

	ret = regulator_disable(tcm_hcd->avdd);
	if (!ret)
		LOGE(tcm_hcd->pdev->dev.parent, "regulator disable SUCCESS");
	else
		LOGE(tcm_hcd->pdev->dev.parent,
		     "Failed to disable analog power:%d", ret);

	return ret;
}

static int syna_tcm_regulator_init(struct syna_tcm_hcd *tcm_hcd)
{
	const struct syna_tcm_board_data *bdata = tcm_hcd->hw_if->bdata;

	struct device *dev = tcm_hcd->pdev->dev.parent;
	int ret = 0;

	LOGN(tcm_hcd->pdev->dev.parent, "Power init");
	if (strlen(bdata->avdd_name)) {
		tcm_hcd->avdd = devm_regulator_get(dev, bdata->avdd_name);
		if (IS_ERR_OR_NULL(tcm_hcd->avdd)) {
			ret = PTR_ERR(tcm_hcd->avdd);
			LOGE(tcm_hcd->pdev->dev.parent,
			     "Failed to get regulator avdd:%d", ret);
			tcm_hcd->avdd = NULL;
			return ret;
		}
	} else {
		LOGE(tcm_hcd->pdev->dev.parent, "Avdd name is NULL");
	}
	ret = regulator_set_voltage(tcm_hcd->avdd, 3300000, 3300000);
	if (ret) {
		LOGE(tcm_hcd->pdev->dev.parent,
		     "regulator_set_voltage failed %d\n", ret);
		return ret;
	}

	if (strlen(bdata->iovdd_name)) {
		tcm_hcd->iovdd = devm_regulator_get(dev, bdata->iovdd_name);
		if (IS_ERR_OR_NULL(tcm_hcd->iovdd)) {
			ret = PTR_ERR(tcm_hcd->iovdd);
			LOGE(tcm_hcd->pdev->dev.parent,
			     "Failed to get regulator iovdd:%d", ret);
			tcm_hcd->iovdd = NULL;
		}
	} else {
		LOGE(tcm_hcd->pdev->dev.parent, "iovdd name is NULL");
	}
	ret = regulator_set_voltage(tcm_hcd->iovdd, 1800000, 1800000);
	if (ret) {
		LOGE(tcm_hcd->pdev->dev.parent,
		     "regulator_set_voltage failed %d\n", ret);
		return ret;
	}

	return ret;
}

static void syna_tcm_esd_recovery(struct syna_tcm_hcd *tcm_hcd)
{
	int retval;

	LOGI(tcm_hcd->pdev->dev.parent, "syna_tcm_esd_recovery enter!\n");

	mutex_lock(&tcm_hcd->esd_recovery_mutex);

	/* power down */
	syna_tcm_enable_regulator(tcm_hcd, false);

	/* power up */
	retval = syna_tcm_enable_regulator(tcm_hcd, true);
	if (retval < 0) {
		LOGE(tcm_hcd->pdev->dev.parent,
		     "Failed to enable regulators, retval = %d\n", retval);
	}

	/* hardware reset */
	retval = tcm_hcd->reset_n_reinit(tcm_hcd, true, true);
	if (retval < 0) {
		LOGE(tcm_hcd->pdev->dev.parent,
		     "Failed to do reset and reinit, retval = %d\n", retval);
	}

	mutex_unlock(&tcm_hcd->esd_recovery_mutex);
	return;
}

static int syna_tcm_get_app_info(struct syna_tcm_hcd *tcm_hcd)
{
	int retval;
	unsigned char *resp_buf;
	unsigned int resp_buf_size;
	unsigned int resp_length;
	unsigned int timeout;

	timeout = APP_STATUS_POLL_TIMEOUT_MS;

	resp_buf = NULL;
	resp_buf_size = 0;

get_app_info:
	retval = tcm_hcd->write_message(tcm_hcd, CMD_GET_APPLICATION_INFO, NULL,
					0, &resp_buf, &resp_buf_size,
					&resp_length, NULL, 0);
	if (retval < 0) {
		LOGE(tcm_hcd->pdev->dev.parent,
		     "Failed to write command %s, retval=%d\n",
		     STR(CMD_GET_APPLICATION_INFO), retval);
		goto exit;
	}

	retval = secure_memcpy((unsigned char *)&tcm_hcd->app_info,
			       sizeof(tcm_hcd->app_info), resp_buf,
			       resp_buf_size,
			       MIN(sizeof(tcm_hcd->app_info), resp_length));
	if (retval < 0) {
		LOGE(tcm_hcd->pdev->dev.parent,
		     "Failed to copy application info, retval=%d\n", retval);
		goto exit;
	}

	tcm_hcd->app_status = le2_to_uint(tcm_hcd->app_info.status);

	if (tcm_hcd->app_status == APP_STATUS_BOOTING ||
	    tcm_hcd->app_status == APP_STATUS_UPDATING) {
		if (timeout > 0) {
			msleep(APP_STATUS_POLL_MS);
			timeout -= APP_STATUS_POLL_MS;
			goto get_app_info;
		}
	}

	retval = 0;

exit:
	kfree(resp_buf);

	return retval;
}

static int syna_tcm_get_boot_info(struct syna_tcm_hcd *tcm_hcd)
{
	int retval;
	unsigned char *resp_buf;
	unsigned int resp_buf_size;
	unsigned int resp_length;

	resp_buf = NULL;
	resp_buf_size = 0;

	retval = tcm_hcd->write_message(tcm_hcd, CMD_GET_BOOT_INFO, NULL, 0,
					&resp_buf, &resp_buf_size, &resp_length,
					NULL, 0);
	if (retval < 0) {
		LOGE(tcm_hcd->pdev->dev.parent,
		     "Failed to write command %s, retval=%d\n",
		     STR(CMD_GET_BOOT_INFO), retval);
		goto exit;
	}

	retval = secure_memcpy((unsigned char *)&tcm_hcd->boot_info,
			       sizeof(tcm_hcd->boot_info), resp_buf,
			       resp_buf_size,
			       MIN(sizeof(tcm_hcd->boot_info), resp_length));
	if (retval < 0) {
		LOGE(tcm_hcd->pdev->dev.parent,
		     "Failed to copy boot info, retval=%d\n", retval);
		goto exit;
	}

	retval = 0;

exit:
	kfree(resp_buf);

	return retval;
}

static int syna_tcm_get_romboot_info(struct syna_tcm_hcd *tcm_hcd)
{
	int retval;
	unsigned char *resp_buf;
	unsigned int resp_buf_size;
	unsigned int resp_length;

	resp_buf = NULL;
	resp_buf_size = 0;

	retval = tcm_hcd->write_message(tcm_hcd, CMD_GET_ROMBOOT_INFO, NULL, 0,
					&resp_buf, &resp_buf_size, &resp_length,
					NULL, 0);
	if (retval < 0) {
		LOGE(tcm_hcd->pdev->dev.parent,
		     "Failed to write command %s, retval=%d\n",
		     STR(CMD_GET_ROMBOOT_INFO), retval);
		goto exit;
	}

	retval = secure_memcpy((unsigned char *)&tcm_hcd->romboot_info,
			       sizeof(tcm_hcd->romboot_info), resp_buf,
			       resp_buf_size,
			       MIN(sizeof(tcm_hcd->romboot_info), resp_length));
	if (retval < 0) {
		LOGE(tcm_hcd->pdev->dev.parent,
		     "Failed to copy boot info, retval=%d\n", retval);
		goto exit;
	}

	LOGD(tcm_hcd->pdev->dev.parent, "version = %d\n",
	     tcm_hcd->romboot_info.version);

	LOGD(tcm_hcd->pdev->dev.parent, "status = 0x%02x\n",
	     tcm_hcd->romboot_info.status);

	LOGD(tcm_hcd->pdev->dev.parent, "version = 0x%02x 0x%02x\n",
	     tcm_hcd->romboot_info.asic_id[0],
	     tcm_hcd->romboot_info.asic_id[1]);

	LOGD(tcm_hcd->pdev->dev.parent, "write_block_size_words = %d\n",
	     tcm_hcd->romboot_info.write_block_size_words);

	LOGD(tcm_hcd->pdev->dev.parent, "max_write_payload_size = %d\n",
	     tcm_hcd->romboot_info.max_write_payload_size[0] |
		     tcm_hcd->romboot_info.max_write_payload_size[1] << 8);

	LOGD(tcm_hcd->pdev->dev.parent, "last_reset_reason = 0x%02x\n",
	     tcm_hcd->romboot_info.last_reset_reason);

	retval = 0;

exit:
	kfree(resp_buf);

	return retval;
}

static int syna_tcm_identify(struct syna_tcm_hcd *tcm_hcd, bool id)
{
	int retval;
	unsigned char *resp_buf;
	unsigned int resp_buf_size;
	unsigned int resp_length;
	unsigned int max_write_size;

	resp_buf = NULL;
	resp_buf_size = 0;

	mutex_lock(&tcm_hcd->identify_mutex);

	if (!id)
		goto get_info;

	retval = tcm_hcd->write_message(tcm_hcd, CMD_IDENTIFY, NULL, 0,
					&resp_buf, &resp_buf_size, &resp_length,
					NULL, 0);
	if (retval < 0) {
		LOGE(tcm_hcd->pdev->dev.parent,
		     "Failed to write command %s, retval=%d\n",
		     STR(CMD_IDENTIFY), retval);
		goto exit;
	}

	retval =
		secure_memcpy((unsigned char *)&tcm_hcd->id_info,
			      sizeof(tcm_hcd->id_info), resp_buf, resp_buf_size,
			      MIN(sizeof(tcm_hcd->id_info), resp_length));
	if (retval < 0) {
		LOGE(tcm_hcd->pdev->dev.parent,
		     "Failed to copy identification info, retval=%d\n", retval);
		goto exit;
	}

	tcm_hcd->packrat_number = le4_to_uint(tcm_hcd->id_info.build_id);

	max_write_size = le2_to_uint(tcm_hcd->id_info.max_write_size);
	tcm_hcd->wr_chunk_size = MIN(max_write_size, WR_CHUNK_SIZE);
	if (tcm_hcd->wr_chunk_size == 0)
		tcm_hcd->wr_chunk_size = max_write_size;

	LOGN(tcm_hcd->pdev->dev.parent, "Firmware build id = %d\n",
	     tcm_hcd->packrat_number);

get_info:
	LOGI(tcm_hcd->pdev->dev.parent, "id_info.mode = %d\n",
	     tcm_hcd->id_info.mode);
	switch (tcm_hcd->id_info.mode) {
	case MODE_APPLICATION_FIRMWARE:
	case MODE_HOSTDOWNLOAD_FIRMWARE:

		retval = syna_tcm_get_app_info(tcm_hcd);
		if (retval < 0) {
			LOGE(tcm_hcd->pdev->dev.parent,
			     "Failed to get application info, retval=%d\n",
			     retval);
			goto exit;
		}
		break;
	case MODE_BOOTLOADER:
	case MODE_TDDI_BOOTLOADER:

		LOGD(tcm_hcd->pdev->dev.parent, "In bootloader mode\n");

		retval = syna_tcm_get_boot_info(tcm_hcd);
		if (retval < 0) {
			LOGE(tcm_hcd->pdev->dev.parent,
			     "Failed to get boot info, retval=%d\n", retval);
			goto exit;
		}
		break;
	case MODE_ROMBOOTLOADER:

		LOGD(tcm_hcd->pdev->dev.parent, "In rombootloader mode\n");

		retval = syna_tcm_get_romboot_info(tcm_hcd);
		if (retval < 0) {
			LOGE(tcm_hcd->pdev->dev.parent,
			     "Failed to get application info, retval=%d\n",
			     retval);
			goto exit;
		}
		break;
	default:
		break;
	}

	retval = 0;

exit:
	mutex_unlock(&tcm_hcd->identify_mutex);

	kfree(resp_buf);

	return retval;
}

static int syna_tcm_run_production_test_firmware(struct syna_tcm_hcd *tcm_hcd)
{
	int retval;
	bool retry;
	unsigned char *resp_buf;
	unsigned int resp_buf_size;
	unsigned int resp_length;

	retry = true;

	resp_buf = NULL;
	resp_buf_size = 0;

retry:
	retval = tcm_hcd->write_message(tcm_hcd, CMD_ENTER_PRODUCTION_TEST_MODE,
					NULL, 0, &resp_buf, &resp_buf_size,
					&resp_length, NULL,
					MODE_SWITCH_DELAY_MS);
	if (retval < 0) {
		LOGE(tcm_hcd->pdev->dev.parent,
		     "Failed to write command %s, retval=%d\n",
		     STR(CMD_ENTER_PRODUCTION_TEST_MODE), retval);
		goto exit;
	}

	if (tcm_hcd->id_info.mode != MODE_PRODUCTIONTEST_FIRMWARE) {
		LOGE(tcm_hcd->pdev->dev.parent,
		     "Failed to run production test firmware\n");
		if (retry) {
			retry = false;
			goto retry;
		}
		retval = -EINVAL;
		goto exit;
	} else if (tcm_hcd->app_status != APP_STATUS_OK) {
		LOGE(tcm_hcd->pdev->dev.parent, "Application status = 0x%02x\n",
		     tcm_hcd->app_status);
	}

	retval = 0;

exit:
	kfree(resp_buf);

	return retval;
}

static int syna_tcm_run_application_firmware(struct syna_tcm_hcd *tcm_hcd)
{
	int retval;
	bool retry;
	unsigned char *resp_buf;
	unsigned int resp_buf_size;
	unsigned int resp_length;

	retry = true;

	resp_buf = NULL;
	resp_buf_size = 0;

retry:
	retval = tcm_hcd->write_message(tcm_hcd, CMD_RUN_APPLICATION_FIRMWARE,
					NULL, 0, &resp_buf, &resp_buf_size,
					&resp_length, NULL,
					MODE_SWITCH_DELAY_MS);
	if (retval < 0) {
		LOGE(tcm_hcd->pdev->dev.parent,
		     "Failed to write command %s, retval=%d\n",
		     STR(CMD_RUN_APPLICATION_FIRMWARE), retval);
		goto exit;
	}

	retval = tcm_hcd->identify(tcm_hcd, false);
	if (retval < 0) {
		LOGE(tcm_hcd->pdev->dev.parent,
		     "Failed to do identification, retval=%d\n", retval);
		goto exit;
	}

	if (IS_NOT_FW_MODE(tcm_hcd->id_info.mode)) {
		LOGE(tcm_hcd->pdev->dev.parent,
		     "Failed to run application firmware (boot status = 0x%02x)\n",
		     tcm_hcd->boot_info.status);
		if (retry) {
			retry = false;
			goto retry;
		}
		retval = -EINVAL;
		goto exit;
	} else if (tcm_hcd->app_status != APP_STATUS_OK) {
		LOGE(tcm_hcd->pdev->dev.parent, "Application status = 0x%02x\n",
		     tcm_hcd->app_status);
	}

	retval = 0;

exit:
	kfree(resp_buf);

	return retval;
}

static int syna_tcm_run_bootloader_firmware(struct syna_tcm_hcd *tcm_hcd)
{
	int retval;
	unsigned char *resp_buf;
	unsigned int resp_buf_size;
	unsigned int resp_length;
	unsigned char command;

	resp_buf = NULL;
	resp_buf_size = 0;
	command = (tcm_hcd->id_info.mode == MODE_ROMBOOTLOADER) ?
			  CMD_ROMBOOT_RUN_BOOTLOADER_FIRMWARE :
			  CMD_RUN_BOOTLOADER_FIRMWARE;

	retval = tcm_hcd->write_message(tcm_hcd, command, NULL, 0, &resp_buf,
					&resp_buf_size, &resp_length, NULL,
					MODE_SWITCH_DELAY_MS);
	if (retval < 0) {
		if (tcm_hcd->id_info.mode == MODE_ROMBOOTLOADER) {
			LOGE(tcm_hcd->pdev->dev.parent,
			     "Failed to write command %s, retval=%d\n",
			     STR(CMD_ROMBOOT_RUN_BOOTLOADER_FIRMWARE), retval);
		} else {
			LOGE(tcm_hcd->pdev->dev.parent,
			     "Failed to write command %s, retval=%d\n",
			     STR(CMD_RUN_BOOTLOADER_FIRMWARE), retval);
		}
		goto exit;
	}

	if (command != CMD_ROMBOOT_RUN_BOOTLOADER_FIRMWARE) {
		retval = tcm_hcd->identify(tcm_hcd, false);
		if (retval < 0) {
			LOGE(tcm_hcd->pdev->dev.parent,
			     "Failed to do identification, retval=%d\n",
			     retval);
			goto exit;
		}

		if (IS_FW_MODE(tcm_hcd->id_info.mode)) {
			LOGE(tcm_hcd->pdev->dev.parent,
			     "Failed to enter bootloader mode\n");
			retval = -EINVAL;
			goto exit;
		}
	}

	retval = 0;

exit:
	kfree(resp_buf);

	return retval;
}

static int syna_tcm_switch_mode(struct syna_tcm_hcd *tcm_hcd,
				enum firmware_mode mode)
{
	int retval;

	mutex_lock(&tcm_hcd->reset_mutex);

#ifdef WATCHDOG_SW
	tcm_hcd->update_watchdog(tcm_hcd, false);
#endif

	switch (mode) {
	case FW_MODE_BOOTLOADER:
		retval = syna_tcm_run_bootloader_firmware(tcm_hcd);
		if (retval < 0) {
			LOGE(tcm_hcd->pdev->dev.parent,
			     "Failed to switch to bootloader mode, retval=%d\n",
			     retval);
			goto exit;
		}
		break;
	case FW_MODE_APPLICATION:
		retval = syna_tcm_run_application_firmware(tcm_hcd);
		if (retval < 0) {
			LOGE(tcm_hcd->pdev->dev.parent,
			     "Failed to switch to application mode, retval=%d\n",
			     retval);
			goto exit;
		}
		break;
	case FW_MODE_PRODUCTION_TEST:
		retval = syna_tcm_run_production_test_firmware(tcm_hcd);
		if (retval < 0) {
			LOGE(tcm_hcd->pdev->dev.parent,
			     "Failed to switch to production test mode, retval=%d\n",
			     retval);
			goto exit;
		}
		break;
	default:
		LOGE(tcm_hcd->pdev->dev.parent, "Invalid firmware mode\n");
		retval = -EINVAL;
		goto exit;
	}

	retval = 0;

exit:
#ifdef WATCHDOG_SW
	tcm_hcd->update_watchdog(tcm_hcd, true);
#endif

	mutex_unlock(&tcm_hcd->reset_mutex);

	return retval;
}

static int syna_tcm_get_dynamic_config(struct syna_tcm_hcd *tcm_hcd,
				       enum dynamic_config_id id,
				       unsigned short *value)
{
	int retval;
	unsigned char out_buf;
	unsigned char *resp_buf;
	unsigned int resp_buf_size;
	unsigned int resp_length;

	resp_buf = NULL;
	resp_buf_size = 0;

	out_buf = (unsigned char)id;

	retval = tcm_hcd->write_message(tcm_hcd, CMD_GET_DYNAMIC_CONFIG,
					&out_buf, sizeof(out_buf), &resp_buf,
					&resp_buf_size, &resp_length, NULL, 0);
	if (retval < 0) {
		LOGE(tcm_hcd->pdev->dev.parent,
		     "Failed to write command %s, id = %d, retval=%d\n",
		     STR(CMD_GET_DYNAMIC_CONFIG), id, retval);
		goto exit;
	}

	if (resp_length < 2) {
		LOGE(tcm_hcd->pdev->dev.parent, "Invalid data length\n");
		retval = -EINVAL;
		goto exit;
	}

	*value = (unsigned short)le2_to_uint(resp_buf);

	retval = 0;

exit:
	kfree(resp_buf);

	return retval;
}

static int syna_tcm_set_dynamic_config(struct syna_tcm_hcd *tcm_hcd,
				       enum dynamic_config_id id,
				       unsigned short value)
{
	int retval;
	unsigned char out_buf[3];
	unsigned char *resp_buf;
	unsigned int resp_buf_size;
	unsigned int resp_length;

	resp_buf = NULL;
	resp_buf_size = 0;

	out_buf[0] = (unsigned char)id;
	out_buf[1] = (unsigned char)value;
	out_buf[2] = (unsigned char)(value >> 8);

	retval = tcm_hcd->write_message(tcm_hcd, CMD_SET_DYNAMIC_CONFIG,
					out_buf, sizeof(out_buf), &resp_buf,
					&resp_buf_size, &resp_length, NULL, 0);
	if (retval < 0) {
		LOGE(tcm_hcd->pdev->dev.parent,
		     "Failed to write command %s, retval=%d\n",
		     STR(CMD_SET_DYNAMIC_CONFIG), retval);
		goto exit;
	}

	retval = 0;

exit:
	kfree(resp_buf);

	return retval;
}

static void syna_tcm_set_charge_status(void)
{
	int retval = 0;
	unsigned short val = 0;
	struct syna_tcm_hcd *tcm_hcd = gloab_tcm_hcd;

	val = tcm_hcd->charger_connected &
	      0x01; /* Default Value: 0, disconnected: 1, connected */
	if (tcm_hcd->in_sleep) {
		LOGI(tcm_hcd->pdev->dev.parent,
		     "in sleep, don't set charge bit [%d]\n", val);
		goto exit;
	}

	/* set dynamic config */
	LOGI(tcm_hcd->pdev->dev.parent,
	     "set charger_connected, value = 0x%02x\n", val);
	retval =
		tcm_hcd->set_dynamic_config(tcm_hcd, DC_CHARGER_CONNECTED, val);
	if (retval < 0) {
		LOGE(tcm_hcd->pdev->dev.parent,
		     "set charger_connected failed, retval=%d\n", retval);
	}

exit:
	return;
}

static int syna_tcm_get_data_location(struct syna_tcm_hcd *tcm_hcd,
				      enum flash_area area, unsigned int *addr,
				      unsigned int *length)
{
	int retval;
	unsigned char out_buf;
	unsigned char *resp_buf;
	unsigned int resp_buf_size;
	unsigned int resp_length;

	switch (area) {
	case CUSTOM_LCM:
		out_buf = LCM_DATA;
		break;
	case CUSTOM_OEM:
		out_buf = OEM_DATA;
		break;
	case PPDT:
		out_buf = PPDT_DATA;
		break;
	default:
		LOGE(tcm_hcd->pdev->dev.parent, "Invalid flash area\n");
		return -EINVAL;
	}

	resp_buf = NULL;
	resp_buf_size = 0;

	retval = tcm_hcd->write_message(tcm_hcd, CMD_GET_DATA_LOCATION,
					&out_buf, sizeof(out_buf), &resp_buf,
					&resp_buf_size, &resp_length, NULL, 0);
	if (retval < 0) {
		LOGE(tcm_hcd->pdev->dev.parent,
		     "Failed to write command %s, retval=%d\n",
		     STR(CMD_GET_DATA_LOCATION), retval);
		goto exit;
	}

	if (resp_length != 4) {
		LOGE(tcm_hcd->pdev->dev.parent, "Invalid data length\n");
		retval = -EINVAL;
		goto exit;
	}

	*addr = le2_to_uint(&resp_buf[0]);
	*length = le2_to_uint(&resp_buf[2]);

	retval = 0;

exit:
	kfree(resp_buf);

	return retval;
}

static int syna_tcm_sleep(struct syna_tcm_hcd *tcm_hcd, bool en)
{
	int retval;
	unsigned char command;
	unsigned char *resp_buf;
	unsigned int resp_buf_size;
	unsigned int resp_length;

	command = en ? CMD_ENTER_DEEP_SLEEP : CMD_EXIT_DEEP_SLEEP;

	resp_buf = NULL;
	resp_buf_size = 0;

	retval = tcm_hcd->write_message(tcm_hcd, command, NULL, 0, &resp_buf,
					&resp_buf_size, &resp_length, NULL, 0);
	if (retval < 0) {
		LOGE(tcm_hcd->pdev->dev.parent,
		     "Failed to write command %s, retval=%d\n",
		     en ? STR(CMD_ENTER_DEEP_SLEEP) : STR(CMD_EXIT_DEEP_SLEEP),
		     retval);
		goto exit;
	}

	retval = 0;

exit:
	kfree(resp_buf);

	return retval;
}

static int syna_tcm_reset(struct syna_tcm_hcd *tcm_hcd)
{
	int retval;
	unsigned char *resp_buf;
	unsigned int resp_buf_size;
	unsigned int resp_length;
	const struct syna_tcm_board_data *bdata = tcm_hcd->hw_if->bdata;

	retval = tcm_hcd->write_message(tcm_hcd, CMD_RESET, NULL, 0, &resp_buf,
					&resp_buf_size, &resp_length, NULL,
					bdata->reset_delay_ms);
	if (retval < 0) {
		LOGE(tcm_hcd->pdev->dev.parent,
		     "Failed to write command %s, retval=%d\n", STR(CMD_RESET),
		     retval);
	}

	return retval;
}

static int syna_tcm_reset_and_reinit(struct syna_tcm_hcd *tcm_hcd, bool hw,
				     bool update_wd)
{
	int retval;
	unsigned char *resp_buf;
	unsigned int resp_buf_size;
	unsigned int resp_length;
	struct syna_tcm_module_handler *mod_handler;
	const struct syna_tcm_board_data *bdata = tcm_hcd->hw_if->bdata;

	resp_buf = NULL;
	resp_buf_size = 0;

	mutex_lock(&tcm_hcd->reset_mutex);

#ifdef WATCHDOG_SW
	if (update_wd)
		tcm_hcd->update_watchdog(tcm_hcd, false);
#endif

	if (hw) {
		if (bdata->reset_gpio < 0) {
			LOGE(tcm_hcd->pdev->dev.parent,
			     "Hardware reset unavailable\n");
			retval = -EINVAL;
			goto exit;
		}
		gpio_set_value(bdata->reset_gpio, bdata->reset_on_state);
		msleep(bdata->reset_active_ms);
		gpio_set_value(bdata->reset_gpio, !bdata->reset_on_state);
	} else {
		retval = syna_tcm_reset(tcm_hcd);
		if (retval < 0) {
			LOGE(tcm_hcd->pdev->dev.parent,
			     "Failed to do reset, retval=%d\n", retval);
			goto exit;
		}
	}

	/* for hdl, the remaining re-init process will be done */
	/* in the helper thread, so wait for the completion here */
	if (tcm_hcd->in_hdl_mode) {
		mutex_unlock(&tcm_hcd->reset_mutex);
		kfree(resp_buf);

		retval = syna_tcm_wait_hdl(tcm_hcd);
		if (retval < 0) {
			LOGE(tcm_hcd->pdev->dev.parent,
			     "Failed to wait for completion of host download, retval=%d\n",
			     retval);
			return retval;
		}

#ifdef WATCHDOG_SW
		if (update_wd)
			tcm_hcd->update_watchdog(tcm_hcd, true);
#endif
		return 0;
	}

	msleep(bdata->reset_delay_ms);

	retval = tcm_hcd->identify(tcm_hcd, false);
	if (retval < 0) {
		LOGE(tcm_hcd->pdev->dev.parent,
		     "Failed to do identification, retval=%d\n", retval);
		goto exit;
	}

	if (IS_FW_MODE(tcm_hcd->id_info.mode))
		goto get_features;

	retval = tcm_hcd->write_message(tcm_hcd, CMD_RUN_APPLICATION_FIRMWARE,
					NULL, 0, &resp_buf, &resp_buf_size,
					&resp_length, NULL,
					MODE_SWITCH_DELAY_MS);
	if (retval < 0) {
		LOGN(tcm_hcd->pdev->dev.parent, "Failed to write command %s\n",
		     STR(CMD_RUN_APPLICATION_FIRMWARE));
	}

	retval = tcm_hcd->identify(tcm_hcd, false);
	if (retval < 0) {
		LOGE(tcm_hcd->pdev->dev.parent,
		     "Failed to do identification, retval=%d\n", retval);
		goto exit;
	}

get_features:
	LOGN(tcm_hcd->pdev->dev.parent, "Firmware mode = 0x%02x\n",
	     tcm_hcd->id_info.mode);

	if (IS_NOT_FW_MODE(tcm_hcd->id_info.mode)) {
		LOGN(tcm_hcd->pdev->dev.parent, "Boot status = 0x%02x\n",
		     tcm_hcd->boot_info.status);
	} else if (tcm_hcd->app_status != APP_STATUS_OK) {
		LOGN(tcm_hcd->pdev->dev.parent, "Application status = 0x%02x\n",
		     tcm_hcd->app_status);
	}

	if (IS_NOT_FW_MODE(tcm_hcd->id_info.mode))
		goto dispatch_reinit;

	retval = tcm_hcd->write_message(tcm_hcd, CMD_GET_FEATURES, NULL, 0,
					&resp_buf, &resp_buf_size, &resp_length,
					NULL, 0);
	if (retval < 0) {
		LOGN(tcm_hcd->pdev->dev.parent, "Failed to write command %s\n",
		     STR(CMD_GET_FEATURES));
	} else {
		retval = secure_memcpy(
			(unsigned char *)&tcm_hcd->features,
			sizeof(tcm_hcd->features), resp_buf, resp_buf_size,
			MIN(sizeof(tcm_hcd->features), resp_length));
		if (retval < 0) {
			LOGE(tcm_hcd->pdev->dev.parent,
			     "Failed to copy feature description, retval=%d\n",
			     retval);
		}
	}

dispatch_reinit:
	mutex_lock(&mod_pool.mutex);

	if (!list_empty(&mod_pool.list)) {
		list_for_each_entry (mod_handler, &mod_pool.list, link) {
			if (!mod_handler->insert && !mod_handler->detach &&
			    (mod_handler->mod_cb->reinit))
				mod_handler->mod_cb->reinit(tcm_hcd);
		}
	}

	mutex_unlock(&mod_pool.mutex);

	retval = 0;

exit:
#ifdef WATCHDOG_SW
	if (update_wd)
		tcm_hcd->update_watchdog(tcm_hcd, true);
#endif

	mutex_unlock(&tcm_hcd->reset_mutex);

	kfree(resp_buf);

	return retval;
}

static int syna_tcm_rezero(struct syna_tcm_hcd *tcm_hcd)
{
	int retval;
	unsigned char *resp_buf;
	unsigned int resp_buf_size;
	unsigned int resp_length;

	resp_buf = NULL;
	resp_buf_size = 0;

	retval = tcm_hcd->write_message(tcm_hcd, CMD_REZERO, NULL, 0, &resp_buf,
					&resp_buf_size, &resp_length, NULL, 0);
	if (retval < 0) {
		LOGE(tcm_hcd->pdev->dev.parent,
		     "Failed to write command %s, retval=%d\n", STR(CMD_REZERO),
		     retval);
		goto exit;
	}

	retval = 0;

exit:
	kfree(resp_buf);

	return retval;
}

static void syna_tcm_helper_work(struct work_struct *work)
{
	int retval;
	unsigned char task;
	struct syna_tcm_module_handler *mod_handler;
	struct syna_tcm_helper *helper =
		container_of(work, struct syna_tcm_helper, work);
	struct syna_tcm_hcd *tcm_hcd =
		container_of(helper, struct syna_tcm_hcd, helper);

	task = atomic_read(&helper->task);

	switch (task) {
	/* this helper can help to run the application firmware */
	case HELP_RUN_APPLICATION_FIRMWARE:
		mutex_lock(&tcm_hcd->reset_mutex);

#ifdef WATCHDOG_SW
		tcm_hcd->update_watchdog(tcm_hcd, false);
#endif
		retval = syna_tcm_run_application_firmware(tcm_hcd);
		if (retval < 0) {
			LOGE(tcm_hcd->pdev->dev.parent,
			     "Failed to switch to application mode, retval=%d\n",
			     retval);
		}
#ifdef WATCHDOG_SW
		tcm_hcd->update_watchdog(tcm_hcd, true);
#endif
		mutex_unlock(&tcm_hcd->reset_mutex);
		break;

	/* the reinit helper is used to notify all installed modules to */
	/* do the re-initialization process, since the HDL is completed */
	case HELP_SEND_REINIT_NOTIFICATION:
		mutex_lock(&tcm_hcd->reset_mutex);

		/* do identify to ensure application firmware is running */
		retval = tcm_hcd->identify(tcm_hcd, true);
		if (retval < 0) {
			LOGE(tcm_hcd->pdev->dev.parent,
			     "Application firmware is not running, retval=%d\n",
			     retval);
			mutex_unlock(&tcm_hcd->reset_mutex);
			break;
		}

		/* init the touch reporting here */
		/* since the HDL is completed */
		retval = touch_reinit(tcm_hcd);
		if (retval < 0) {
			LOGE(tcm_hcd->pdev->dev.parent,
			     "Failed to initialze touch reporting, retval=%d\n",
			     retval);
			break;
		}

		mutex_lock(&mod_pool.mutex);
		if (!list_empty(&mod_pool.list)) {
			list_for_each_entry (mod_handler, &mod_pool.list,
					     link) {
				if (!mod_handler->insert &&
				    !mod_handler->detach &&
				    (mod_handler->mod_cb->reinit))
					mod_handler->mod_cb->reinit(tcm_hcd);
			}
		}
		mutex_unlock(&mod_pool.mutex);
		mutex_unlock(&tcm_hcd->reset_mutex);
		wake_up_interruptible(&tcm_hcd->hdl_wq);
		break;

	/* this helper is used to reinit the touch reporting */
	case HELP_TOUCH_REINIT:
		retval = touch_reinit(tcm_hcd);
		if (retval < 0) {
			LOGE(tcm_hcd->pdev->dev.parent,
			     "Failed to re-initialze touch reporting, retval=%d\n",
			     retval);
		}
#ifdef CONFIG_FACTORY_BUILD
		// syna_tcm_set_cur_value(Touch_Fod_Enable,
		// 		       FOD_STATUS_AUTHENTICATION);
#endif
		/* resend the charger bit after reset */
		syna_tcm_set_charge_status();
		break;

	/* this helper is used to trigger a romboot hdl */
	case HELP_SEND_ROMBOOT_HDL:
		syna_tcm_check_hdl(tcm_hcd, REPORT_HDL_ROMBOOT);
		break;
	default:
		break;
	}

	atomic_set(&helper->task, HELP_NONE);

	return;
}

#if defined(CONFIG_PM) || defined(CONFIG_FB)
static int syna_tcm_pm_resume(struct device *dev)
{
	int i, retval;
	struct syna_tcm_module_handler *mod_handler;
	struct syna_tcm_hcd *tcm_hcd = dev_get_drvdata(dev);

	LOGN(tcm_hcd->pdev->dev.parent, "-----enter-----%s\n", __func__);

	if (!tcm_hcd->in_suspend) {
		LOGN(tcm_hcd->pdev->dev.parent,
		     "tp is in resume state,-----exit-----%s\n", __func__);
		return 0;
	}

	tcm_hcd->in_suspending = false;

	if (tcm_hcd->in_hdl_mode) {
		if (!tcm_hcd->wakeup_gesture_enabled) {
			tcm_hcd->enable_irq(tcm_hcd, true, NULL);
			retval = syna_tcm_wait_hdl(tcm_hcd);
			if (retval < 0) {
				LOGE(tcm_hcd->pdev->dev.parent,
				     "Failed to wait for completion of host download, retval=%d\n",
				     retval);
				goto exit;
			}
			goto mod_resume;
		}
	} else {
		if (!tcm_hcd->wakeup_gesture_enabled || tcm_hcd->in_sleep)
			tcm_hcd->enable_irq(tcm_hcd, true, NULL);

#ifdef RESET_ON_RESUME
		msleep(RESET_ON_RESUME_DELAY_MS);
		goto do_reset;
#endif
	}

	if (IS_NOT_FW_MODE(tcm_hcd->id_info.mode) ||
	    tcm_hcd->app_status != APP_STATUS_OK) {
		LOGN(tcm_hcd->pdev->dev.parent, "Identifying mode = 0x%02x\n",
		     tcm_hcd->id_info.mode);
		goto do_reset;
	}

	retval = tcm_hcd->sleep(tcm_hcd, false);
	if (retval < 0) {
		for (i = 0; i < 5; i++) {
			msleep(5);
			retval = tcm_hcd->sleep(tcm_hcd, false);
			if (retval < 0) {
				LOGE(tcm_hcd->pdev->dev.parent,
				     "Failed to exit sleep for the %d time , retval=%d\n",
				     i + 2, retval);
			} else {
				LOGN(tcm_hcd->pdev->dev.parent,
				     "exit deep sleep :%d, retval=%d\n", i + 2,
				     retval);
				goto success;
			}
		}
		LOGE(tcm_hcd->pdev->dev.parent,
		     "Failed to exit sleep resulting in frozen screen \n");
		goto exit;
	} else {
		LOGN(tcm_hcd->pdev->dev.parent,
		     " one exit deep sleep success retval=%d\n", retval);
	}

success:
	if ((tcm_hcd->fod_enabled) && (tcm_hcd->fod_finger))
		goto mod_resume;

	retval = syna_tcm_rezero(tcm_hcd);
	if (retval < 0) {
		LOGE(tcm_hcd->pdev->dev.parent, "Failed to rezero, retval=%d\n",
		     retval);
		goto exit;
	}

	goto mod_resume;

do_reset:
	retval = tcm_hcd->reset_n_reinit(tcm_hcd, false, true);
	if (retval < 0) {
		LOGE(tcm_hcd->pdev->dev.parent,
		     "Failed to do reset and reinit, retval=%d\n", retval);
		goto exit;
	}

	if (IS_NOT_FW_MODE(tcm_hcd->id_info.mode) ||
	    tcm_hcd->app_status != APP_STATUS_OK) {
		LOGN(tcm_hcd->pdev->dev.parent, "Identifying mode = 0x%02x\n",
		     tcm_hcd->id_info.mode);
		retval = 0;
		goto exit;
	}

mod_resume:
	touch_resume(tcm_hcd);

#ifdef WATCHDOG_SW
	tcm_hcd->update_watchdog(tcm_hcd, true);
#endif

	mutex_lock(&mod_pool.mutex);

	if (!list_empty(&mod_pool.list)) {
		list_for_each_entry (mod_handler, &mod_pool.list, link) {
			if (!mod_handler->insert && !mod_handler->detach &&
			    (mod_handler->mod_cb->resume))
				mod_handler->mod_cb->resume(tcm_hcd);
		}
	}

	mutex_unlock(&mod_pool.mutex);

	retval = 0;

exit:
	tcm_hcd->in_sleep = false;
	tcm_hcd->in_suspend = false;

	return retval;
}

static int syna_tcm_pm_suspend(struct device *dev)
{
	struct syna_tcm_module_handler *mod_handler;
	struct syna_tcm_hcd *tcm_hcd = dev_get_drvdata(dev);

	LOGN(tcm_hcd->pdev->dev.parent, "-----enter-----%s\n", __func__);
	if (tcm_hcd->in_suspend) {
		LOGN(tcm_hcd->pdev->dev.parent,
		     "tp is in suspend state-----exit-----%s\n", __func__);
		return 0;
	}

	touch_suspend(tcm_hcd);

	mutex_lock(&mod_pool.mutex);

	if (!list_empty(&mod_pool.list)) {
		list_for_each_entry (mod_handler, &mod_pool.list, link) {
			if (!mod_handler->insert && !mod_handler->detach &&
			    (mod_handler->mod_cb->suspend))
				mod_handler->mod_cb->suspend(tcm_hcd);
		}
	}

	mutex_unlock(&mod_pool.mutex);

	if (!tcm_hcd->wakeup_gesture_enabled)
		tcm_hcd->enable_irq(tcm_hcd, false, true);

	tcm_hcd->in_suspend = true;
	touch_free_objects(tcm_hcd);
	tcm_hcd->in_suspending = false;
	touch_update_fod_enable_value(tcm_hcd);

	return 0;
}
#endif

static int syna_tcm_early_suspend(struct device *dev)
{
	int retval;
	struct syna_tcm_module_handler *mod_handler;
	struct syna_tcm_hcd *tcm_hcd = dev_get_drvdata(dev);

	LOGN(tcm_hcd->pdev->dev.parent, "-----enter-----%s\n", __func__);
	if (tcm_hcd->in_suspend) {
		LOGE(tcm_hcd->pdev->dev.parent,
		     "enter:syna_tcm_early_suspend------1\n");
		return 0;
	}

	tcm_hcd->in_suspending = true;

	LOGN(tcm_hcd->pdev->dev.parent,
	     "fod_enabled:%d aod_enable:%d doubletap_enable:%d finger_unlock_status:%d\n",
	     tcm_hcd->fod_enabled, tcm_hcd->aod_enable,
	     tcm_hcd->doubletap_enable, tcm_hcd->finger_unlock_status);

#ifdef WATCHDOG_SW
	tcm_hcd->update_watchdog(tcm_hcd, false);
#endif

	if (IS_NOT_FW_MODE(tcm_hcd->id_info.mode) ||
	    tcm_hcd->app_status != APP_STATUS_OK) {
		LOGN(tcm_hcd->pdev->dev.parent, "Identifying mode = 0x%02x\n",
		     tcm_hcd->id_info.mode);
		return 0;
	}

	if (tcm_hcd->fod_enabled == true || tcm_hcd->aod_enable == true ||
	    tcm_hcd->doubletap_enable == true ||
	    tcm_hcd->finger_unlock_status > 0) {
		tcm_hcd->wakeup_gesture_enabled = WAKEUP_GESTURE;
	} else
		tcm_hcd->wakeup_gesture_enabled = false;

#ifdef CONFIG_FACTORY_BUILD
	tcm_hcd->wakeup_gesture_enabled = false;
#endif

	if (tcm_hcd->wakeup_gesture_enabled &&
	    tcm_hcd->finger_unlock_status > 0) {
		LOGI(tcm_hcd->pdev->dev.parent,
		     "finger_unlock_status[%d] set fod_enabled to enable\n",
		     tcm_hcd->finger_unlock_status);
		tcm_hcd->fod_enabled = FLAG_FOD_ENABLE;
		queue_work(tcm_hcd->event_wq, &tcm_hcd->fod_work);
	}

	if (!tcm_hcd->wakeup_gesture_enabled || tcm_hcd->nonui_status == 2) {
		if (!tcm_hcd->in_sleep) {
			LOGE(tcm_hcd->pdev->dev.parent, "set fw sleep\n");
			retval = tcm_hcd->sleep(tcm_hcd, true);
			if (retval < 0) {
				tcm_hcd->in_sleep = false;
				LOGE(tcm_hcd->pdev->dev.parent,
				     "Failed to enter deep sleep, retval=%d\n",
				     retval);
				return retval;
			}
			tcm_hcd->in_sleep = true;
		}
	} else
		LOGN(tcm_hcd->pdev->dev.parent,
		     "skip set fw sleep for wakeup_gesture_enabled:%d nonui_status:%d \n",
		     tcm_hcd->wakeup_gesture_enabled, tcm_hcd->nonui_status);

	touch_early_suspend(tcm_hcd);

	mutex_lock(&mod_pool.mutex);

	if (!list_empty(&mod_pool.list)) {
		list_for_each_entry (mod_handler, &mod_pool.list, link) {
			if (!mod_handler->insert && !mod_handler->detach &&
			    (mod_handler->mod_cb->early_suspend)) {
				LOGE(tcm_hcd->pdev->dev.parent,
				     "enter:syna_tcm_early_suspend------3\n");
				mod_handler->mod_cb->early_suspend(tcm_hcd);
			}
		}
	}

	mutex_unlock(&mod_pool.mutex);
	LOGN(tcm_hcd->pdev->dev.parent, "-----exit-----%s\n", __func__);
	return 0;
}

static void syna_tcm_resume_work(struct work_struct *work)
{
	int retval;
	struct syna_tcm_hcd *tcm_hcd =
		container_of(work, struct syna_tcm_hcd, resume_work);

	LOGN(tcm_hcd->pdev->dev.parent, "-----enter-----%s\n", __func__);
	tcm_hcd->flag_sleep = false;
	retval = syna_tcm_pm_resume(&tcm_hcd->pdev->dev);
	tcm_hcd->fb_ready++;

	/* resend the charger bit after resume */
	syna_tcm_set_charge_status();

	LOGN(tcm_hcd->pdev->dev.parent, "-----exit-----%s\n", __func__);

	return;
}

static void syna_tcm_early_suspend_work(struct work_struct *work)
{
	int retval;
	struct syna_tcm_hcd *tcm_hcd =
		container_of(work, struct syna_tcm_hcd, early_suspend_work);

	LOGN(tcm_hcd->pdev->dev.parent, "-----enter-----%s\n", __func__);
	tcm_hcd->flag_sleep = true;

	retval = syna_tcm_early_suspend(&tcm_hcd->pdev->dev);

	LOGN(tcm_hcd->pdev->dev.parent, "-----exit-----%s\n", __func__);

	return;
}

static void syna_tcm_suspend_work(struct work_struct *work)
{
	int retval;
	struct syna_tcm_hcd *tcm_hcd =
		container_of(work, struct syna_tcm_hcd, suspend_work);

	LOGN(tcm_hcd->pdev->dev.parent, "-----enter-----%s\n", __func__);

	retval = syna_tcm_pm_suspend(&tcm_hcd->pdev->dev);
	tcm_hcd->fb_ready = 0;

	LOGN(tcm_hcd->pdev->dev.parent, "-----exit-----%s\n", __func__);

	return;
}

#if defined(CONFIG_DRM)
static void syna_tcm_drm_state_notifier_callback(
	enum panel_event_notifier_tag notifier_tag,
	struct panel_event_notification *notification, void *client_data)
{
	int retval = 0;
	struct syna_tcm_hcd *tcm_hcd = client_data;

	if (!notification) {
		LOGE(tcm_hcd->pdev->dev.parent, "Invalid notification\n");
		return;
	}

	switch (notification->notif_type) {
	case DRM_PANEL_EVENT_UNBLANK:
		LOGN(tcm_hcd->pdev->dev.parent, "touch resume\n");
		queue_work(tcm_hcd->event_wq, &tcm_hcd->resume_work);
		break;
	case DRM_PANEL_EVENT_BLANK:
	case DRM_PANEL_EVENT_BLANK_LP:
		if (atomic_read(&tcm_hcd->firmware_flashing)) {
			retval = wait_event_interruptible_timeout(
				tcm_hcd->reflash_wq,
				!atomic_read(&tcm_hcd->firmware_flashing),
				msecs_to_jiffies(RESPONSE_TIMEOUT_MS));
			if (retval == 0) {
				LOGE(tcm_hcd->pdev->dev.parent,
				     "Timed out waiting for completion of flashing firmware\n");
				atomic_set(&tcm_hcd->firmware_flashing, 0);
				return;
			}
		}

		if (notification->notif_data.early_trigger) {
			LOGN(tcm_hcd->pdev->dev.parent,
			     "touch early suspend\n");
			queue_work(tcm_hcd->event_wq,
				   &tcm_hcd->early_suspend_work);
		} else {
			LOGN(tcm_hcd->pdev->dev.parent, "touch suspend\n");
			queue_work(tcm_hcd->event_wq, &tcm_hcd->suspend_work);
		}
		break;
	default:
		LOGE(tcm_hcd->pdev->dev.parent, "notification serviced: %d\n",
		     notification->notif_type);
		break;
	}
}
#endif

#ifdef SYNA_TCM_XIAOMI_TOUCHFEATURE
static int syna_tcm_set_cur_value(void *private, enum touch_mode mode, int value)
{
	int retval;
	struct syna_tcm_hcd *tcm_hcd = private;

	LOGE(tcm_hcd->pdev->dev.parent, "set mode: %d, value: %d", mode, value);

	switch (mode) {
	case TOUCH_MODE_DOUBLETAP_GESTURE:
		tcm_hcd->doubletap_enable = value > 0 ? true : false;
		break;
	case TOUCH_MODE_FOD_PRESS_GESTURE:
		tcm_hcd->finger_unlock_status = FOD_STATUS_INPUT_FINGERPRINT;
		tcm_hcd->fod_enabled = FLAG_FOD_ENABLE;
	case TOUCH_MODE_SINGLETAP_GESTURE:
		tcm_hcd->aod_enable = value > 0 ? true : false;
		break;
	case TOUCH_MODE_NONUI_MODE:
		tcm_hcd->nonui_status = value;
		if (tcm_hcd->flag_sleep) {
			switch (tcm_hcd->nonui_status) {
			case 0:
				if (tcm_hcd->in_sleep) {
					LOGI(tcm_hcd->pdev->dev.parent,
					     "Exit sleep mode!\n");
					/* enable irq */
					tcm_hcd->enable_irq(tcm_hcd, true,
							    NULL);
					retval = tcm_hcd->sleep(tcm_hcd, false);
					if (retval < 0) {
						tcm_hcd->in_sleep = true;
						LOGE(tcm_hcd->pdev->dev.parent,
						     "Failed to exit deep sleep, retval=%d\n",
						     retval);
						goto exit;
					}
					tcm_hcd->in_sleep = false;
				}

				if (tcm_hcd->fod_icon_status ||
				    tcm_hcd->aod_enable) {
					LOGI(tcm_hcd->pdev->dev.parent,
					     "Enable single tap!\n");
					tcm_hcd->gesture_type |= (0x0001 << 13);
					retval = tcm_hcd->set_dynamic_config(
						tcm_hcd, DC_GESTURE_TYPE_ENABLE,
						tcm_hcd->gesture_type);
					if (retval < 0) {
						LOGE(tcm_hcd->pdev->dev.parent,
						     "Failed to enable gesture type, retval=%d\n",
						     retval);
						goto exit;
					}
				}
				break;
			case 1:
				if (tcm_hcd->fod_icon_status &&
				    !tcm_hcd->aod_enable &&
				    tcm_hcd->in_suspend) {
					LOGI(tcm_hcd->pdev->dev.parent,
					     "Disable single tap!\n");
					tcm_hcd->gesture_type &=
						~(0x0001 << 13);
					retval = tcm_hcd->set_dynamic_config(
						tcm_hcd, DC_GESTURE_TYPE_ENABLE,
						tcm_hcd->gesture_type);
					if (retval < 0) {
						LOGE(tcm_hcd->pdev->dev.parent,
						     "Failed to disable single tap, retval=%d\n",
						     retval);
						goto exit;
					}
				}
				break;
			case 2:
				if (!tcm_hcd->in_sleep &&
				    tcm_hcd->wakeup_gesture_enabled &&
				    tcm_hcd->in_suspend) {
					LOGI(tcm_hcd->pdev->dev.parent,
					     "Enter sleep mode!\n");
					retval = tcm_hcd->sleep(tcm_hcd, true);
					if (retval < 0) {
						tcm_hcd->in_sleep = false;
						LOGE(tcm_hcd->pdev->dev.parent,
						     "Failed to enter deep sleep, retval=%d\n",
						     retval);
						goto exit;
					}
					/* disable irq */
					tcm_hcd->enable_irq(tcm_hcd, false,
							    true);
					tcm_hcd->in_sleep = true;
				}
				break;
			}
		}
		break;
	default:
		LOGE(tcm_hcd->pdev->dev.parent, "handler got mode %d with value %d, not implemented",
		       mode, value);
		return -EINVAL;
	}

exit:
	return 0;
}

static int syna_tcm_get_mode_value(void *private, enum touch_mode mode)
{
	struct syna_tcm_hcd *tcm_hcd = private;

	LOGE(tcm_hcd->pdev->dev.parent, "get mode: %d", mode);
	switch (mode) {
	case TOUCH_MODE_DOUBLETAP_GESTURE:
		return tcm_hcd->doubletap_enable;
	case TOUCH_MODE_SINGLETAP_GESTURE:
		return tcm_hcd->aod_enable;
	case TOUCH_MODE_FOD_PRESS_GESTURE:
		return tcm_hcd->fod_enabled;
	case TOUCH_MODE_NONUI_MODE:
		return tcm_hcd->nonui_status;
	default:
		LOGE(tcm_hcd->pdev->dev.parent, "handler got mode %d, not implemented", mode);
		return -EINVAL;
	}
	return 0;
}
#endif

static int syna_tcm_check_f35(struct syna_tcm_hcd *tcm_hcd)
{
	int retval;
	unsigned char fn_number;
	int retry = 0;
	const int retry_max = 10;

F35_BOOT_RECHECK:
	retval = syna_tcm_rmi_read(tcm_hcd, PDT_END_ADDR, &fn_number,
				   sizeof(fn_number));
	if (retval < 0) {
		LOGE(tcm_hcd->pdev->dev.parent,
		     "Failed to read F35 function number, retval=%d\n", retval);
		tcm_hcd->is_detected = false;
		return -ENODEV;
	}

	LOGD(tcm_hcd->pdev->dev.parent, "Found F$%02x\n", fn_number);

	if (fn_number != RMI_UBL_FN_NUMBER) {
		LOGE(tcm_hcd->pdev->dev.parent,
		     "Failed to find F$35, try_times = %d\n", retry);
		if (retry < retry_max) {
			msleep(100);
			retry++;
			goto F35_BOOT_RECHECK;
		}
		tcm_hcd->is_detected = false;
		return -ENODEV;
	}
	return 0;
}

static int syna_tcm_sensor_detection(struct syna_tcm_hcd *tcm_hcd)
{
	int retval;
	unsigned char *build_id;
	unsigned int payload_length;
	unsigned int max_write_size;

	tcm_hcd->in_hdl_mode = false;
	tcm_hcd->sensor_type = TYPE_UNKNOWN;

	/* read sensor info for identification */
	retval = tcm_hcd->read_message(tcm_hcd, NULL, 0);

	/* once the tcm communication interface is not ready, */
	/* check whether the device is in F35 mode        */
	if (retval < 0) {
		if (retval == -ENXIO &&
		    tcm_hcd->hw_if->bus_io->type == BUS_SPI) {
			retval = syna_tcm_check_f35(tcm_hcd);
			if (retval < 0) {
				LOGE(tcm_hcd->pdev->dev.parent,
				     "Failed to read TCM message, retval=%d\n",
				     retval);
				return retval;
			}
			tcm_hcd->in_hdl_mode = true;
			tcm_hcd->sensor_type = TYPE_F35;
			tcm_hcd->is_detected = true;
			tcm_hcd->rd_chunk_size = HDL_RD_CHUNK_SIZE;
			tcm_hcd->wr_chunk_size = HDL_WR_CHUNK_SIZE;

			LOGN(tcm_hcd->pdev->dev.parent, "F35 mode\n");
			return retval;
		} else {
			LOGE(tcm_hcd->pdev->dev.parent,
			     "Failed to read TCM message, retval=%d\n", retval);
			return retval;
		}
	}

	/* expect to get an identify report after powering on */

	if (tcm_hcd->status_report_code != REPORT_IDENTIFY) {
		LOGE(tcm_hcd->pdev->dev.parent,
		     "Unexpected report code (0x%02x)\n",
		     tcm_hcd->status_report_code);

		return -ENODEV;
	}

	tcm_hcd->is_detected = true;
	payload_length = tcm_hcd->payload_length;

	LOCK_BUFFER(tcm_hcd->in);

	retval = secure_memcpy((unsigned char *)&tcm_hcd->id_info,
			       sizeof(tcm_hcd->id_info),
			       &tcm_hcd->in.buf[MESSAGE_HEADER_SIZE],
			       tcm_hcd->in.buf_size - MESSAGE_HEADER_SIZE,
			       MIN(sizeof(tcm_hcd->id_info), payload_length));
	if (retval < 0) {
		LOGE(tcm_hcd->pdev->dev.parent,
		     "Failed to copy identification info, retval=%d\n", retval);
		UNLOCK_BUFFER(tcm_hcd->in);
		return retval;
	}

	UNLOCK_BUFFER(tcm_hcd->in);

	build_id = tcm_hcd->id_info.build_id;
	tcm_hcd->packrat_number = le4_to_uint(build_id);

	max_write_size = le2_to_uint(tcm_hcd->id_info.max_write_size);
	tcm_hcd->wr_chunk_size = MIN(max_write_size, WR_CHUNK_SIZE);
	if (tcm_hcd->wr_chunk_size == 0)
		tcm_hcd->wr_chunk_size = max_write_size;

	if (tcm_hcd->id_info.mode == MODE_ROMBOOTLOADER) {
		tcm_hcd->in_hdl_mode = true;
		tcm_hcd->sensor_type = TYPE_ROMBOOT;
		tcm_hcd->rd_chunk_size = HDL_RD_CHUNK_SIZE;
		tcm_hcd->wr_chunk_size = HDL_WR_CHUNK_SIZE;
		LOGN(tcm_hcd->pdev->dev.parent, "RomBoot mode\n");
	} else if (tcm_hcd->id_info.mode == MODE_APPLICATION_FIRMWARE) {
		tcm_hcd->sensor_type = TYPE_FLASH;
		LOGN(tcm_hcd->pdev->dev.parent,
		     "Application mode (build id = %d)\n",
		     tcm_hcd->packrat_number);
	} else {
		LOGW(tcm_hcd->pdev->dev.parent,
		     "TCM is detected, but mode is 0x%02x\n",
		     tcm_hcd->id_info.mode);
	}

	return 0;
}

/*static ssize_t tp_irq_debug_write(struct file *file, const char __user *buf,
				size_t count, loff_t *pos)
{
	int retval = 0;
	char tmp[1];
	int ret;

	if (copy_from_user(tmp, buf, 1)) {
		pr_err("%s: copy_from_user data fail\n", __func__);
		retval = -EFAULT;
	}
	ret = (int)tmp[0];
	pr_err("%s: ret = %d\n", __func__, ret);
	if (ret)
		disable_irq(gloab_tcm_hcd->irq);
	else
		enable_irq(gloab_tcm_hcd->irq);

	return retval;

}

static const struct proc_ops tp_irq_debug_ops = {
	.proc_write = tp_irq_debug_write,
};*/

#ifdef SYNAPTICS_DEBUGFS_ENABLE
static void syna_tcm_dbg_suspend(struct syna_tcm_hcd *tcm_hcd, bool enable)
{
	if (enable) {
		queue_work(tcm_hcd->event_wq, &tcm_hcd->early_suspend_work);
		queue_work(tcm_hcd->event_wq, &tcm_hcd->suspend_work);
	} else
		queue_work(tcm_hcd->event_wq, &tcm_hcd->resume_work);
}

static int syna_tcm_dbg_open(struct inode *inode, struct file *file)
{
	file->private_data = inode->i_private;

	return 0;
}

static ssize_t syna_tcm_dbg_read(struct file *file, char __user *buf,
				 size_t size, loff_t *ppos)
{
	const char *str = "cmd support as below:\n \
	\necho \"irq-disable\" or \"irq-enable\" to ctrl irq\n \
	\necho \"tp-suspend-en\" or \"tp-suspend-off\" to ctrl panel in or off suspend status\n \
	\necho \"tp-sd-en\" or \"tp-sd-off\" to ctrl panel in or off sleep status\n";

	loff_t pos = *ppos;
	int len = strlen(str);

	if (pos < 0)
		return -EINVAL;
	if (pos >= len)
		return 0;

	if (copy_to_user(buf, str, len))
		return -EFAULT;

	*ppos = pos + len;

	return len;
}

static ssize_t syna_tcm_dbg_write(struct file *file, const char __user *buf,
				  size_t size, loff_t *ppos)
{
	char *cmd = kzalloc(size + 1, GFP_KERNEL);
	int ret = size;

	if (!cmd)
		return -ENOMEM;

	if (copy_from_user(cmd, buf, size)) {
		ret = -EFAULT;
		goto out;
	}

	cmd[size] = '\0';

	if (!strncmp(cmd, "irq-disable", 11)) {
		LOGI(gloab_tcm_hcd->pdev->dev.parent,
		     "%s touch irq is disabled!\n", __func__);
		gloab_tcm_hcd->enable_irq(gloab_tcm_hcd, false, true);
	} else if (!strncmp(cmd, "irq-enable", 10)) {
		LOGI(gloab_tcm_hcd->pdev->dev.parent,
		     "%s touch irq is enabled!\n", __func__);
		gloab_tcm_hcd->enable_irq(gloab_tcm_hcd, true, NULL);
	} else if (!strncmp(cmd, "tp-sd-en", 8))
		syna_tcm_dbg_suspend(gloab_tcm_hcd, true);
	else if (!strncmp(cmd, "tp-sd-off", 9))
		syna_tcm_dbg_suspend(gloab_tcm_hcd, false);
	else if (!strncmp(cmd, "tp-suspend-en", 13))
		syna_tcm_dbg_suspend(gloab_tcm_hcd, true);
	else if (!strncmp(cmd, "tp-suspend-off", 14))
		syna_tcm_dbg_suspend(gloab_tcm_hcd, false);
out:
	kfree(cmd);

	return ret;
}

static int syna_tcm_dbg_release(struct inode *inode, struct file *file)
{
	file->private_data = NULL;

	return 0;
}

static void syna_tcm_debugfs_exit(void)
{
	debugfs_remove_recursive(gloab_tcm_hcd->debugfs);
}

static const struct file_operations tpdbg_operations = {
	.owner = THIS_MODULE,
	.open = syna_tcm_dbg_open,
	.read = syna_tcm_dbg_read,
	.write = syna_tcm_dbg_write,
	.release = syna_tcm_dbg_release,
};
#endif

#ifdef SYNAPTICS_POWERSUPPLY_CB
static int syna_tcm_get_charging_status(void)
{
	struct power_supply *usb_psy;
	union power_supply_propval val;
	int is_charging = 0;
	int rc = 0;
	is_charging = !!power_supply_is_system_supplied();

	if (!is_charging)
		return NOT_CHARGING;

	usb_psy = power_supply_get_by_name("usb");
	if (usb_psy) {
		rc = power_supply_get_property(usb_psy,
					       POWER_SUPPLY_PROP_ONLINE, &val);
		if (rc < 0)
			LOGE(gloab_tcm_hcd->pdev->dev.parent,
			     "%s Couldn't get usb online status, rc=%d\n",
			     __func__, rc);
		else if (val.intval == 1)
			return WIRED_CHARGING;
	} else {
		LOGE(gloab_tcm_hcd->pdev->dev.parent, "%s not found usb psy\n",
		     __func__);
	}
	return NOT_CHARGING;
}

static void syna_tcm_power_supply_work(struct work_struct *work)
{
	int charging_status;

	LOGD(gloab_tcm_hcd->pdev->dev.parent, "%s enter!\n", __func__);
	if (!gloab_tcm_hcd || !tp_probe_success) {
		LOGE(gloab_tcm_hcd->pdev->dev.parent,
		     "%s touch is not inited\n", __func__);
		return;
	}

	charging_status = syna_tcm_get_charging_status();

	if (charging_status != gloab_tcm_hcd->charging_status ||
	    gloab_tcm_hcd->charging_status < 0) {
		gloab_tcm_hcd->charging_status = charging_status;
		gloab_tcm_hcd->charger_connected =
			(charging_status == WIRED_CHARGING) ? 1 : 0;
		if (gloab_tcm_hcd->in_suspend) {
			LOGI(gloab_tcm_hcd->pdev->dev.parent,
			     "%s Can't write charge status\n", __func__);
			return;
		}
		syna_tcm_set_charge_status();
	}
}

static int syna_tcm_power_supply_event(struct notifier_block *nb,
				       unsigned long event, void *ptr)
{
	if (!gloab_tcm_hcd)
		return 0;

	schedule_delayed_work(&gloab_tcm_hcd->power_supply_work,
			      msecs_to_jiffies(500));
	return 0;
}
#endif

#if defined(CONFIG_DRM)
/*
 * pointer active_panel initlized function, used to checkout panel(config)from devices
 * tree , later will be passed to drm_notifyXXX function.
 * @param device node contains the panel
 * @return pointer to that panel if panel truely  exists, otherwise negative number
 */
static int ts_check_panel(struct device_node *np)
{
	int i;
	int count;
	struct device_node *node;
	struct drm_panel *panel;

	count = of_count_phandle_with_args(np, "panel", NULL);
	if (count <= 0)
		return -ENODEV;

	for (i = 0; i < count; i++) {
		node = of_parse_phandle(np, "panel", i);
		panel = of_drm_find_panel(node);
		of_node_put(node);
		if (!IS_ERR(panel)) {
			active_panel = panel;
			return 0;
		} else {
			active_panel = NULL;
		}
	}

	return PTR_ERR(panel);
}

static void ts_register_panel_notifier_work(struct work_struct *work)
{
	struct syna_tcm_hcd *tcm_hcd = container_of(
		work, struct syna_tcm_hcd, panel_notifier_register_work.work);
	int error;
	static int check_count = 0;
	struct spi_device *spi;
	struct device_node *dp;

	spi = to_spi_device(tcm_hcd->pdev->dev.parent);
	dp = spi->dev.of_node;
	LOGE(tcm_hcd->pdev->dev.parent, "Start register panel notifier\n");

	error = ts_check_panel(dp);

	if (!dp || !active_panel) {
		LOGE(tcm_hcd->pdev->dev.parent,
		     "Failed to register panel notifier, try again\n");
		if (check_count++ < 5) {
			schedule_delayed_work(
				&tcm_hcd->panel_notifier_register_work,
				msecs_to_jiffies(5000));
		} else {
			LOGE(tcm_hcd->pdev->dev.parent,
			     "Failed to register panel notifier, not trying again\n");
		}
		return;
	}

	if (active_panel) {
		tcm_hcd->notifier_cookie = panel_event_notifier_register(
			PANEL_EVENT_NOTIFICATION_PRIMARY,
			PANEL_EVENT_NOTIFIER_CLIENT_PRIMARY_TOUCH, active_panel,
			&syna_tcm_drm_state_notifier_callback, (void *)tcm_hcd);
		if (!tcm_hcd->notifier_cookie) {
			LOGE(tcm_hcd->pdev->dev.parent,
			     "Failed to register for panel events\n");
		}
	}
}
#endif

static int syna_tcm_probe(struct platform_device *pdev)
{
	int retval;
	int idx;
	struct syna_tcm_hcd *tcm_hcd;
	const struct syna_tcm_board_data *bdata;
	const struct syna_tcm_hw_interface *hw_if;
	struct spi_device *spi;
	// struct device_node *dp;

	LOGE(&pdev->dev, "-----enter-----%s\n", __func__);
	hw_if = pdev->dev.platform_data;
	if (!hw_if) {
		LOGE(&pdev->dev, "Hardware interface not found\n");
		return -ENODEV;
	}

	bdata = hw_if->bdata;
	if (!bdata) {
		LOGE(&pdev->dev, "Board data not found\n");
		return -ENODEV;
	}

	tcm_hcd = kzalloc(sizeof(*tcm_hcd), GFP_KERNEL);
	if (!tcm_hcd) {
		LOGE(&pdev->dev, "Failed to allocate memory for tcm_hcd\n");
		return -ENOMEM;
	}

	platform_set_drvdata(pdev, tcm_hcd);
	gloab_tcm_hcd = tcm_hcd;

	tcm_hcd->pdev = pdev;
	tcm_hcd->hw_if = hw_if;
	tcm_hcd->reset = syna_tcm_reset;
	tcm_hcd->reset_n_reinit = syna_tcm_reset_and_reinit;
	tcm_hcd->sleep = syna_tcm_sleep;
	tcm_hcd->identify = syna_tcm_identify;
	tcm_hcd->enable_irq = syna_tcm_enable_irq;
	tcm_hcd->switch_mode = syna_tcm_switch_mode;
	tcm_hcd->read_message = syna_tcm_read_message;
	tcm_hcd->write_message = syna_tcm_write_message;
	tcm_hcd->get_dynamic_config = syna_tcm_get_dynamic_config;
	tcm_hcd->set_dynamic_config = syna_tcm_set_dynamic_config;
	tcm_hcd->get_data_location = syna_tcm_get_data_location;

	tcm_hcd->rd_chunk_size = RD_CHUNK_SIZE;
	tcm_hcd->wr_chunk_size = WR_CHUNK_SIZE;
	tcm_hcd->is_detected = false;
	tcm_hcd->wakeup_gesture_enabled = WAKEUP_GESTURE;
	tcm_hcd->fod_enabled = false;
	tcm_hcd->fod_finger = false;
	tcm_hcd->in_suspending = false;
	tcm_hcd->lockdown_info_ready = false;
	tcm_hcd->flag_sleep = false;
#ifdef PREDICTIVE_READING
	tcm_hcd->read_length = MIN_READ_LENGTH;
#else
	tcm_hcd->read_length = MESSAGE_HEADER_SIZE;
#endif

#ifdef WATCHDOG_SW
	tcm_hcd->watchdog.run = RUN_WATCHDOG;
	tcm_hcd->update_watchdog = syna_tcm_update_watchdog;
#endif

	if (bdata->irq_gpio >= 0)
		tcm_hcd->irq = gpio_to_irq(bdata->irq_gpio);
	else
		tcm_hcd->irq = bdata->irq_gpio;

	mutex_init(&tcm_hcd->extif_mutex);
	mutex_init(&tcm_hcd->reset_mutex);
	mutex_init(&tcm_hcd->irq_en_mutex);
	mutex_init(&tcm_hcd->io_ctrl_mutex);
	mutex_init(&tcm_hcd->rw_ctrl_mutex);
	mutex_init(&tcm_hcd->command_mutex);
	mutex_init(&tcm_hcd->identify_mutex);
	mutex_init(&tcm_hcd->esd_recovery_mutex);

	INIT_BUFFER(tcm_hcd->in, false);
	INIT_BUFFER(tcm_hcd->out, false);
	INIT_BUFFER(tcm_hcd->resp, true);
	INIT_BUFFER(tcm_hcd->temp, false);
	INIT_BUFFER(tcm_hcd->config, false);
	INIT_BUFFER(tcm_hcd->report.buffer, true);

	LOCK_BUFFER(tcm_hcd->in);

	retval = syna_tcm_alloc_mem(tcm_hcd, &tcm_hcd->in,
				    tcm_hcd->read_length + 1);
	if (retval < 0) {
		LOGE(&pdev->dev,
		     "Failed to allocate memory for tcm_hcd->in.buf, retval=%d\n",
		     retval);
		UNLOCK_BUFFER(tcm_hcd->in);
		goto err_alloc_mem;
	}

	UNLOCK_BUFFER(tcm_hcd->in);

	atomic_set(&tcm_hcd->command_status, CMD_IDLE);

	atomic_set(&tcm_hcd->helper.task, HELP_NONE);

	device_init_wakeup(&pdev->dev, 1);

	init_waitqueue_head(&tcm_hcd->hdl_wq);

	init_waitqueue_head(&tcm_hcd->reflash_wq);
	atomic_set(&tcm_hcd->firmware_flashing, 0);

	if (!mod_pool.initialized) {
		mutex_init(&mod_pool.mutex);
		INIT_LIST_HEAD(&mod_pool.list);
		mod_pool.initialized = true;
	}

	spi = to_spi_device(tcm_hcd->pdev->dev.parent);
	/*
	dp = spi->dev.of_node;
	retval = ts_check_panel(dp);
	if (retval < 0) {
		LOGE(&pdev->dev, "please add the panel name at dts config, retval=%d\n", retval);
	}
*/
	tcm_hcd->pinctrl = devm_pinctrl_get(&spi->dev);
	if (IS_ERR(tcm_hcd->pinctrl)) {
		LOGE(&pdev->dev, "Cannot find default pinctrl, ret = %d!\n",
		     PTR_ERR(tcm_hcd->pinctrl));
	} else {
		tcm_hcd->pins_default =
			pinctrl_lookup_state(tcm_hcd->pinctrl, "default");
		if (IS_ERR(tcm_hcd->pins_default))
			LOGE(&pdev->dev, "Cannot find pinctrl default %d!\n",
			     PTR_ERR(tcm_hcd->pins_default));
		else
			pinctrl_select_state(tcm_hcd->pinctrl,
					     tcm_hcd->pins_default);
	}

	retval = syna_tcm_regulator_init(tcm_hcd);
	if (retval < 0) {
		LOGE(tcm_hcd->pdev->dev.parent,
		     "Failed to get regulators, retval=%d\n", retval);
		goto err_regulator_init;
	}

	retval = syna_tcm_enable_regulator(tcm_hcd, true);
	if (retval < 0) {
		LOGE(tcm_hcd->pdev->dev.parent,
		     "Failed to enable regulators, retval=%d\n", retval);
		goto err_enable_regulator;
	}

	retval = syna_tcm_config_gpio(tcm_hcd);
	if (retval < 0) {
		LOGE(tcm_hcd->pdev->dev.parent,
		     "Failed to configure GPIO's, retval=%d\n", retval);
		goto err_config_gpio;
	}

	/* detect the type of touch controller */
	retval = syna_tcm_sensor_detection(tcm_hcd);
	if (retval < 0) {
		LOGE(tcm_hcd->pdev->dev.parent,
		     "Failed to detect the sensor, retval=%d\n", retval);
		goto err_sysfs_create_dir;
	}

	sysfs_dir =
		kobject_create_and_add(PLATFORM_DRIVER_NAME, &pdev->dev.kobj);
	if (!sysfs_dir) {
		LOGE(tcm_hcd->pdev->dev.parent,
		     "Failed to create sysfs directory, retval=%d\n", retval);
		retval = -EINVAL;
		goto err_sysfs_create_dir;
	}

	tcm_hcd->sysfs_dir = sysfs_dir;

	for (idx = 0; idx < ARRAY_SIZE(attrs); idx++) {
		retval = sysfs_create_file(tcm_hcd->sysfs_dir,
					   &(*attrs[idx]).attr);
		if (retval < 0) {
			LOGE(tcm_hcd->pdev->dev.parent,
			     "Failed to create sysfs file, retval=%d\n",
			     retval);
			goto err_sysfs_create_file;
		}
	}

	tcm_hcd->dynamnic_config_sysfs_dir = kobject_create_and_add(
		DYNAMIC_CONFIG_SYSFS_DIR_NAME, tcm_hcd->sysfs_dir);
	if (!tcm_hcd->dynamnic_config_sysfs_dir) {
		LOGE(tcm_hcd->pdev->dev.parent,
		     "Failed to create dynamic config sysfs directory\n");
		retval = -EINVAL;
		goto err_sysfs_create_dynamic_config_dir;
	}

	for (idx = 0; idx < ARRAY_SIZE(dynamic_config_attrs); idx++) {
		retval = sysfs_create_file(tcm_hcd->dynamnic_config_sysfs_dir,
					   &(*dynamic_config_attrs[idx]).attr);
		if (retval < 0) {
			LOGE(tcm_hcd->pdev->dev.parent,
			     "Failed to create dynamic config sysfs file, retval=%d\n",
			     retval);
			goto err_sysfs_create_dynamic_config_file;
		}
	}

	/* tcm_hcd->tp_irq_debug =
		proc_create("tp_irq_debug", 0664, NULL, &tp_irq_debug_ops);*/

#ifdef REPORT_NOTIFIER
	tcm_hcd->notifier_thread = kthread_run(
		syna_tcm_report_notifier, tcm_hcd, "syna_tcm_report_notifier");
	if (IS_ERR(tcm_hcd->notifier_thread)) {
		retval = PTR_ERR(tcm_hcd->notifier_thread);
		LOGE(tcm_hcd->pdev->dev.parent,
		     "Failed to create and run tcm_hcd->notifier_thread, retval=%d\n",
		     retval);
		goto err_create_run_kthread;
	}
#endif

	tcm_hcd->helper.workqueue =
		create_singlethread_workqueue("syna_tcm_helper");

	INIT_WORK(&tcm_hcd->helper.work, syna_tcm_helper_work);

#ifdef WATCHDOG_SW
	tcm_hcd->watchdog.workqueue =
		create_singlethread_workqueue("syna_tcm_watchdog");
	INIT_DELAYED_WORK(&tcm_hcd->watchdog.work, syna_tcm_watchdog_work);
#endif

	tcm_hcd->polling_workqueue =
		create_singlethread_workqueue("syna_tcm_polling");
	INIT_DELAYED_WORK(&tcm_hcd->polling_work, syna_tcm_polling_work);

	tcm_hcd->event_wq =
		alloc_workqueue("syna_tcm_event_queue",
				WQ_UNBOUND | WQ_HIGHPRI | WQ_CPU_INTENSIVE, 1);
	if (!tcm_hcd->event_wq) {
		LOGE(tcm_hcd->pdev->dev.parent, "Failed to create event_wq\n");
		retval = -ENOMEM;
		goto err_pm_event_wq;
	}
	INIT_WORK(&tcm_hcd->resume_work, syna_tcm_resume_work);
	INIT_WORK(&tcm_hcd->early_suspend_work, syna_tcm_early_suspend_work);
	INIT_WORK(&tcm_hcd->suspend_work, syna_tcm_suspend_work);

#if defined(CONFIG_DRM)
	INIT_DELAYED_WORK(&tcm_hcd->panel_notifier_register_work,
			  ts_register_panel_notifier_work);
	schedule_delayed_work(&tcm_hcd->panel_notifier_register_work,
			      msecs_to_jiffies(5000));
#endif

#ifdef SYNA_TCM_XIAOMI_TOUCHFEATURE
	tcm_hcd->xiaomi_touch.set_mode_value = syna_tcm_set_cur_value;
	tcm_hcd->xiaomi_touch.get_mode_value = syna_tcm_get_mode_value;
	tcm_hcd->xiaomi_touch.private = tcm_hcd;
	register_xiaomi_touch_client(TOUCH_ID_PRIMARY, &tcm_hcd->xiaomi_touch);
#endif
	tcm_hcd->syna_tcm_class = class_create(THIS_MODULE, "touch-syna_tcm");

	tcm_hcd->syna_tcm_dev =
		device_create(tcm_hcd->syna_tcm_class, NULL,
			      tcm_hcd->tp_dev_num, tcm_hcd, "tp_dev");
	if (IS_ERR(tcm_hcd->syna_tcm_dev)) {
		LOGE(tcm_hcd->pdev->dev.parent,
		     "Failed to create device for the sysfs!\n");
	}
	dev_set_drvdata(tcm_hcd->syna_tcm_dev, tcm_hcd);

	retval = sysfs_create_file(&tcm_hcd->syna_tcm_dev->kobj,
				   &dev_attr_fod_test.attr);
	if (retval) {
		LOGE(tcm_hcd->pdev->dev.parent,
		     "Failed to create fod_test sysfs group!, retval=%d\n",
		     retval);
	}

#ifdef SYNAPTICS_POWERSUPPLY_CB
	INIT_DELAYED_WORK(&tcm_hcd->power_supply_work,
			  syna_tcm_power_supply_work);
	tcm_hcd->charging_status = -1;
	tcm_hcd->power_supply_notifier.notifier_call =
		syna_tcm_power_supply_event;
	retval = power_supply_reg_notifier(&tcm_hcd->power_supply_notifier);
	if (retval < 0) {
		LOGE(tcm_hcd->pdev->dev.parent,
		     "usb online notifier registration error, retval=%d\n",
		     retval);
	}
#endif

#ifdef SYNAPTICS_DEBUGFS_ENABLE
	tcm_hcd->debugfs = debugfs_create_dir("tp_debug", NULL);
	if (tcm_hcd->debugfs) {
		debugfs_create_file("switch_state", 0660, tcm_hcd->debugfs,
				    tcm_hcd, &tpdbg_operations);
	}
#endif

	init_completion(&tcm_hcd->pm_resume_completion);

	/* since the fw is not ready for hdl devices */
	if (tcm_hcd->in_hdl_mode)
		goto prepare_modules;

	/* register and enable the interrupt in probe */
	/* if this is not the hdl device */
	retval = tcm_hcd->enable_irq(tcm_hcd, true, NULL);
	if (retval < 0) {
		LOGE(tcm_hcd->pdev->dev.parent,
		     "Failed to enable interrupt, retval=%d\n", retval);
		goto err_enable_irq;
	}
	LOGI(tcm_hcd->pdev->dev.parent, "Interrupt is registered\n");

	/* ensure the app firmware is running */
	retval = syna_tcm_identify(tcm_hcd, false);
	if (retval < 0) {
		LOGE(tcm_hcd->pdev->dev.parent,
		     "Application firmware is not running, retval=%d\n",
		     retval);
		goto err_do_identify;
	}

	/* initialize the touch reporting */
	retval = touch_init(tcm_hcd);
	if (retval < 0) {
		LOGE(tcm_hcd->pdev->dev.parent,
		     "Failed to initialze touch reporting, retval=%d\n",
		     retval);
		goto err_do_identify;
	}

prepare_modules:
	/* prepare to add other modules */
	mod_pool.workqueue = create_singlethread_workqueue("syna_tcm_module");
	INIT_WORK(&mod_pool.work, syna_tcm_module_work);
	mod_pool.tcm_hcd = tcm_hcd;
	mod_pool.queue_work = true;
	queue_work(mod_pool.workqueue, &mod_pool.work);

	tp_probe_success = true;
	return 0;

err_do_identify:
	tcm_hcd->enable_irq(tcm_hcd, false, true);

err_enable_irq:
	cancel_delayed_work_sync(&tcm_hcd->power_supply_work);
	power_supply_unreg_notifier(&tcm_hcd->power_supply_notifier);

	cancel_delayed_work_sync(&tcm_hcd->polling_work);
	flush_workqueue(tcm_hcd->polling_workqueue);
	destroy_workqueue(tcm_hcd->polling_workqueue);

#ifdef WATCHDOG_SW
	cancel_delayed_work_sync(&tcm_hcd->watchdog.work);
	flush_workqueue(tcm_hcd->watchdog.workqueue);
	destroy_workqueue(tcm_hcd->watchdog.workqueue);
#endif

	cancel_work_sync(&tcm_hcd->helper.work);
	flush_workqueue(tcm_hcd->helper.workqueue);
	destroy_workqueue(tcm_hcd->helper.workqueue);

#ifdef SYNA_TCM_XIAOMI_TOUCHFEATURE
	unregister_xiaomi_touch_client(TOUCH_ID_PRIMARY);
#endif

	if (tcm_hcd->tp_lockdown_info_proc)
		remove_proc_entry("tp_lockdown_info", NULL);
	if (tcm_hcd->tp_fw_version_proc)
		remove_proc_entry("tp_fw_version", NULL);
	if (tcm_hcd->tp_data_dump_proc)
		remove_proc_entry("tp_data_dump", NULL);
	if (tcm_hcd->tp_selftest_proc)
		remove_proc_entry("tp_selftest", NULL);
	tcm_hcd->tp_lockdown_info_proc = NULL;
	tcm_hcd->tp_fw_version_proc = NULL;
	tcm_hcd->tp_data_dump_proc = NULL;
	tcm_hcd->tp_selftest_proc = NULL;

#ifdef SYNAPTICS_DEBUGFS_ENABLE
	syna_tcm_debugfs_exit();
#endif

#if defined(CONFIG_DRM)
	cancel_delayed_work_sync(&tcm_hcd->panel_notifier_register_work);
	if (active_panel && tcm_hcd->notifier_cookie)
		panel_event_notifier_unregister(tcm_hcd->notifier_cookie);
#endif

err_pm_event_wq:
	/* cancel_work_sync(&tcm_hcd->early_suspend_work);
	cancel_work_sync(&tcm_hcd->suspend_work);
	cancel_work_sync(&tcm_hcd->resume_work);
	flush_workqueue(tcm_hcd->event_wq); */
	destroy_workqueue(tcm_hcd->event_wq);

#ifdef REPORT_NOTIFIER
	kthread_stop(tcm_hcd->notifier_thread);
err_create_run_kthread:
#endif

	if (tcm_hcd->tp_lockdown_info_proc)
		remove_proc_entry("tp_lockdown_info", NULL);
	if (tcm_hcd->tp_fw_version_proc)
		remove_proc_entry("tp_fw_version", NULL);
	tcm_hcd->tp_lockdown_info_proc = NULL;
	tcm_hcd->tp_fw_version_proc = NULL;

err_sysfs_create_dynamic_config_file:
	for (idx--; idx >= 0; idx--) {
		sysfs_remove_file(tcm_hcd->dynamnic_config_sysfs_dir,
				  &(*dynamic_config_attrs[idx]).attr);
	}

	kobject_put(tcm_hcd->dynamnic_config_sysfs_dir);

	idx = ARRAY_SIZE(attrs);

err_sysfs_create_dynamic_config_dir:
err_sysfs_create_file:
	for (idx--; idx >= 0; idx--)
		sysfs_remove_file(tcm_hcd->sysfs_dir, &(*attrs[idx]).attr);

	kobject_put(tcm_hcd->sysfs_dir);

err_sysfs_create_dir:
	if (bdata->irq_gpio >= 0)
		syna_tcm_set_gpio(tcm_hcd, bdata->irq_gpio, false, 0, 0);

	if (bdata->power_gpio >= 0)
		syna_tcm_set_gpio(tcm_hcd, bdata->power_gpio, false, 0, 0);

	if (bdata->reset_gpio >= 0)
		syna_tcm_set_gpio(tcm_hcd, bdata->reset_gpio, false, 0, 0);

err_config_gpio:
err_enable_regulator:
	if (!tcm_hcd->avdd || !tcm_hcd->iovdd)
		LOGE(tcm_hcd->pdev->dev.parent,
		     "There is NULL for avdd or iovdd\n");
	devm_regulator_put(tcm_hcd->avdd);
	devm_regulator_put(tcm_hcd->iovdd);
	tcm_hcd->avdd = NULL;
	tcm_hcd->iovdd = NULL;

err_regulator_init:
	device_init_wakeup(&pdev->dev, 0);

err_alloc_mem:
	RELEASE_BUFFER(tcm_hcd->report.buffer);
	RELEASE_BUFFER(tcm_hcd->config);
	RELEASE_BUFFER(tcm_hcd->temp);
	RELEASE_BUFFER(tcm_hcd->resp);
	RELEASE_BUFFER(tcm_hcd->out);
	RELEASE_BUFFER(tcm_hcd->in);
	kfree(tcm_hcd);
	tcm_hcd = NULL;
	gloab_tcm_hcd = NULL;

	return retval;
}

static int syna_tcm_remove(struct platform_device *pdev)
{
	int idx;
	struct syna_tcm_module_handler *mod_handler;
	struct syna_tcm_module_handler *tmp_handler;
	struct syna_tcm_hcd *tcm_hcd = platform_get_drvdata(pdev);
	const struct syna_tcm_board_data *bdata = tcm_hcd->hw_if->bdata;

	LOGE(tcm_hcd->pdev->dev.parent, "syna_tcm_remove enter!\n");

#if 0
	/* there is one issue on k9e, it will crash the system, but not found the rootcause.
	 * Here is just copy the workaround and disable it.
	 * Please contact with K9E driver engineer to learn more infomation.
	 */
	int retval;
	if (atomic_read(&tcm_hcd->firmware_flashing)) {

        retval = wait_event_interruptible_timeout(
            tcm_hcd->reflash_wq,
            !atomic_read(&tcm_hcd->firmware_flashing),
            msecs_to_jiffies(3000)
            );
            if (retval == 0) {
                LOGE(tcm_hcd->pdev->dev.parent,
                        "Timed out waiting for completion of flashing firmware\n");
            } else {
                       retval = 0;
            }
    }
#endif

	tp_probe_success = false;
	touch_remove(tcm_hcd);

	mutex_lock(&mod_pool.mutex);

	if (!list_empty(&mod_pool.list)) {
		list_for_each_entry_safe (mod_handler, tmp_handler,
					  &mod_pool.list, link) {
			if (mod_handler->mod_cb->remove)
				mod_handler->mod_cb->remove(tcm_hcd);
			list_del(&mod_handler->link);
			kfree(mod_handler);
		}
	}

	mod_pool.queue_work = false;
	cancel_work_sync(&mod_pool.work);
	flush_workqueue(mod_pool.workqueue);
	destroy_workqueue(mod_pool.workqueue);

	mutex_unlock(&mod_pool.mutex);

	cancel_delayed_work_sync(&tcm_hcd->power_supply_work);
	power_supply_unreg_notifier(&tcm_hcd->power_supply_notifier);

	if (tcm_hcd->irq_enabled && bdata->irq_gpio >= 0) {
		disable_irq(tcm_hcd->irq);
		free_irq(tcm_hcd->irq, tcm_hcd);
	}

	cancel_delayed_work_sync(&tcm_hcd->polling_work);
	flush_workqueue(tcm_hcd->polling_workqueue);
	destroy_workqueue(tcm_hcd->polling_workqueue);

#ifdef WATCHDOG_SW
	cancel_delayed_work_sync(&tcm_hcd->watchdog.work);
	flush_workqueue(tcm_hcd->watchdog.workqueue);
	destroy_workqueue(tcm_hcd->watchdog.workqueue);
#endif

#if defined(CONFIG_DRM)
	cancel_delayed_work_sync(&tcm_hcd->panel_notifier_register_work);
	if (active_panel && tcm_hcd->notifier_cookie)
		panel_event_notifier_unregister(tcm_hcd->notifier_cookie);
#endif

	cancel_work_sync(&tcm_hcd->helper.work);
	flush_workqueue(tcm_hcd->helper.workqueue);
	destroy_workqueue(tcm_hcd->helper.workqueue);

	cancel_work_sync(&tcm_hcd->early_suspend_work);
	cancel_work_sync(&tcm_hcd->suspend_work);
	cancel_work_sync(&tcm_hcd->resume_work);
	cancel_work_sync(&tcm_hcd->set_report_rate_work);
	flush_workqueue(tcm_hcd->event_wq);
	destroy_workqueue(tcm_hcd->event_wq);

#ifdef SYNA_TCM_XIAOMI_TOUCHFEATURE
	unregister_xiaomi_touch_client(TOUCH_ID_PRIMARY);
#endif

#ifdef REPORT_NOTIFIER
	kthread_stop(tcm_hcd->notifier_thread);
#endif

	for (idx = 0; idx < ARRAY_SIZE(dynamic_config_attrs); idx++) {
		sysfs_remove_file(tcm_hcd->dynamnic_config_sysfs_dir,
				  &(*dynamic_config_attrs[idx]).attr);
	}

	kobject_put(tcm_hcd->dynamnic_config_sysfs_dir);

	for (idx = 0; idx < ARRAY_SIZE(attrs); idx++)
		sysfs_remove_file(tcm_hcd->sysfs_dir, &(*attrs[idx]).attr);

	kobject_put(tcm_hcd->sysfs_dir);

	if (bdata->irq_gpio >= 0)
		syna_tcm_set_gpio(tcm_hcd, bdata->irq_gpio, false, 0, 0);

	if (bdata->power_gpio >= 0)
		syna_tcm_set_gpio(tcm_hcd, bdata->power_gpio, false, 0, 0);

	if (bdata->reset_gpio >= 0)
		syna_tcm_set_gpio(tcm_hcd, bdata->reset_gpio, false, 0, 0);

	syna_tcm_enable_regulator(tcm_hcd, false);

	device_init_wakeup(&pdev->dev, 0);

	RELEASE_BUFFER(tcm_hcd->report.buffer);
	RELEASE_BUFFER(tcm_hcd->config);
	RELEASE_BUFFER(tcm_hcd->temp);
	RELEASE_BUFFER(tcm_hcd->resp);
	RELEASE_BUFFER(tcm_hcd->out);
	RELEASE_BUFFER(tcm_hcd->in);

	kfree(tcm_hcd);
	tcm_hcd = NULL;
	gloab_tcm_hcd = NULL;

	return 0;
}

static void syna_tcm_shutdown(struct platform_device *pdev)
{
	int retval;

	retval = syna_tcm_remove(pdev);
}

#ifdef CONFIG_PM
static int syna_pm_suspend(struct device *dev)
{
	struct syna_tcm_hcd *tcm_hcd = dev_get_drvdata(dev);
	LOGN(tcm_hcd->pdev->dev.parent, "%s enter!\n", __func__);

	if (!tcm_hcd) {
		LOGE(tcm_hcd->pdev->dev.parent,
		     "Failed to enter syna_pm_suspend!\n");
		return -1;
	}
	tcm_hcd->tp_pm_suspend = true;
	reinit_completion(&tcm_hcd->pm_resume_completion);

	return 0;
}

static int syna_pm_resume(struct device *dev)
{
	struct syna_tcm_hcd *tcm_hcd = dev_get_drvdata(dev);
	LOGN(tcm_hcd->pdev->dev.parent, "%s enter!\n", __func__);

	if (!tcm_hcd) {
		LOGE(tcm_hcd->pdev->dev.parent,
		     "Failed to enter syna_pm_resume!\n");
		return -1;
	}

	tcm_hcd->tp_pm_suspend = false;
	complete(&tcm_hcd->pm_resume_completion);

	return 0;
}

static const struct dev_pm_ops syna_tcm_dev_pm_ops = {
	.suspend = syna_pm_suspend,
	.resume = syna_pm_resume,
};
#endif

static struct platform_driver syna_tcm_driver = {
	.driver = {
		.name = PLATFORM_DRIVER_NAME,
		.owner = THIS_MODULE,
#ifdef CONFIG_PM
		.pm = &syna_tcm_dev_pm_ops,
#endif
	},
	.probe = syna_tcm_probe,
	.remove = syna_tcm_remove,
	.shutdown = syna_tcm_shutdown,
};

static int __init syna_tcm_module_init(void)
{
	int retval;

	retval = syna_tcm_bus_init();
	if (retval < 0)
		return retval;

	return platform_driver_register(&syna_tcm_driver);
}

static void __exit syna_tcm_module_exit(void)
{
	platform_driver_unregister(&syna_tcm_driver);

	syna_tcm_bus_exit();

	return;
}

module_init(syna_tcm_module_init);
module_exit(syna_tcm_module_exit);

MODULE_AUTHOR("Synaptics, Inc.");
MODULE_DESCRIPTION("Synaptics TCM Touch Driver");
MODULE_LICENSE("GPL v2");
