/*
 * Goodix Gesture Module
 *
 * Copyright (C) 2019 - 2020 Goodix, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be a reference
 * to you, when you are integrating the GOODiX's CTP IC into your system,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 */
#include <linux/spinlock.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/input.h>
#include <linux/platform_device.h>
#include <linux/version.h>
#include <linux/delay.h>
#include <linux/atomic.h>
#include <linux/input/mt.h>
#include "goodix_ts_core.h"

#define QUERYBIT(longlong, bit) (!!(longlong[bit / 8] & (1 << bit % 8)))

#define GSX_GESTURE_TYPE_LEN 32
#define TYPE_B_PROTOCOL

/*
 * struct gesture_module - gesture module data
 * @registered: module register state
 * @sysfs_node_created: sysfs node state
 * @gesture_type: valid gesture type, each bit represent one gesture type
 * @gesture_data: store latest gesture code get from irq event
 * @gesture_ts_cmd: gesture command data
 */
struct gesture_module {
	atomic_t registered;
	rwlock_t rwlock;
	u8 gesture_type[GSX_GESTURE_TYPE_LEN];
	u8 gesture_data;
	struct goodix_ext_module module;
};

static struct gesture_module *gsx_gesture; /*allocated in gesture init module*/
static bool module_initialized;

int goodix_gesture_enable(int enable)
{
	int ret = 0;

	if (!module_initialized)
		return 0;

	ts_info("enable is %d", enable);
	if (enable) {
		if (atomic_read(&gsx_gesture->registered))
			ts_info("gesture module has been already registered");
		else
			ret = goodix_register_ext_module_no_wait(
				&gsx_gesture->module);
	} else {
		if (!atomic_read(&gsx_gesture->registered))
			ts_info("gesture module has been already unregistered");
		else
			ret = goodix_unregister_ext_module(
				&gsx_gesture->module);
	}

	return ret;
}

/**
 * gsx_gesture_type_show - show valid gesture type
 *
 * @module: pointer to goodix_ext_module struct
 * @buf: pointer to output buffer
 * Returns >=0 - succeed,< 0 - failed
 */
// static ssize_t gsx_gesture_type_show(struct goodix_ext_module *module,
// 				char *buf)
// {
// 	int count = 0, i, ret = 0;
// 	unsigned char *type;

// 	type = kzalloc(PAGE_SIZE, GFP_KERNEL);
// 	if (!type)
// 		return -ENOMEM;
// 	read_lock(&gsx_gesture->rwlock);
// 	for (i = 0; i < 256; i++) {
// 		if (QUERYBIT(gsx_gesture->gesture_type, i)) {
// 			count += scnprintf(type + count,
// 					   PAGE_SIZE, "%02x,", i);
// 		}
// 	}
// 	if (count > 0)
// 		ret = scnprintf(buf, PAGE_SIZE, "%s\n", type);
// 	read_unlock(&gsx_gesture->rwlock);

// 	kfree(type);
// 	return ret;
// }

/**
 * gsx_gesture_type_store - set vailed gesture
 *
 * @module: pointer to goodix_ext_module struct
 * @buf: pointer to valid gesture type
 * @count: length of buf
 * Returns >0 - valid gestures, < 0 - failed
 */
// static ssize_t gsx_gesture_type_store(struct goodix_ext_module *module,
// 		const char *buf, size_t count)
// {
// 	int i;

// 	if (count <= 0 || count > 256 || buf == NULL) {
// 		ts_err("Parameter error");
// 		return -EINVAL;
// 	}

// 	write_lock(&gsx_gesture->rwlock);
// 	memset(gsx_gesture->gesture_type, 0, GSX_GESTURE_TYPE_LEN);
// 	for (i = 0; i < count; i++)
// 		gsx_gesture->gesture_type[buf[i]/8] |= (0x1 << buf[i]%8);
// 	write_unlock(&gsx_gesture->rwlock);

// 	return count;
// }

// static ssize_t gsx_gesture_enable_show(struct goodix_ext_module *module,
// 		char *buf)
// {
// 	return scnprintf(buf, PAGE_SIZE, "%d\n",
// 			 atomic_read(&gsx_gesture->registered));
// }

// static ssize_t gsx_gesture_enable_store(struct goodix_ext_module *module,
// 		const char *buf, size_t count)
// {
// 	bool val;
// 	int ret;

// 	ret = strtobool(buf, &val);
// 	if (ret < 0)
// 		return ret;

// 	if (val) {
// 		ret = goodix_gesture_enable(1);
// 		return ret ? ret : count;
// 	} else {
// 		ret = goodix_gesture_enable(0);
// 		return ret ? ret : count;
// 	}
// }

// static ssize_t gsx_gesture_data_show(struct goodix_ext_module *module,
// 				char *buf)
// {
// 	ssize_t count;

// 	read_lock(&gsx_gesture->rwlock);
// 	count = scnprintf(buf, PAGE_SIZE, "gesture type code:0x%x\n",
// 			  gsx_gesture->gesture_data);
// 	read_unlock(&gsx_gesture->rwlock);

// 	return count;
// }

// const struct goodix_ext_attribute gesture_attrs[] = {
// 	__EXTMOD_ATTR(type, 0666, gsx_gesture_type_show,
// 		gsx_gesture_type_store),
// 	__EXTMOD_ATTR(enable, 0666, gsx_gesture_enable_show,
// 		gsx_gesture_enable_store),
// 	__EXTMOD_ATTR(data, 0444, gsx_gesture_data_show, NULL)
// };

// static int gsx_gesture_init(struct goodix_ts_core *cd,
// 		struct goodix_ext_module *module)
// {
// 	if (!cd || !cd->hw_ops->gesture) {
// 		ts_err("gesture unsupported");
// 		return -EINVAL;
// 	}

// 	ts_info("gesture switch: ON");
// 	ts_debug("enable all gesture type");
// 	/* set all bit to 1 to enable all gesture wakeup */
// 	memset(gsx_gesture->gesture_type, 0xff, GSX_GESTURE_TYPE_LEN);
// 	atomic_set(&gsx_gesture->registered, 1);

// 	return 0;
// }

// static int gsx_gesture_exit(struct goodix_ts_core *cd,
// 		struct goodix_ext_module *module)
// {
// 	if (!cd || !cd->hw_ops->gesture) {
// 		ts_err("gesture unsupported");
// 		return -EINVAL;
// 	}

// 	ts_info("gesture switch: OFF");
// 	ts_debug("disable all gesture type");
// 	memset(gsx_gesture->gesture_type, 0x00, GSX_GESTURE_TYPE_LEN);
// 	atomic_set(&gsx_gesture->registered, 0);

// 	return 0;
// }

typedef unsigned char undefined;
typedef unsigned char byte;
struct event_head {
	int event_status;
	u8 event_type;
	u8 request_code;
	u8 gesture_type;
	undefined field4_0x7;
	u16 fodx;
	u16 fody;
	u8 overlay_area;
	undefined field8_0xd;
	undefined field9_0xe;
	undefined field10_0xf;
	undefined field11_0x10;
	u8 fod_id;
	undefined field13_0x12;
	undefined field14_0x13;
	undefined field15_0x14;
	undefined field16_0x15;
	undefined field17_0x16;
	undefined field18_0x17;
	undefined field19_0x18;
	undefined field20_0x19;
	undefined field21_0x1a;
	undefined field22_0x1b;
	undefined field23_0x1c;
	undefined field24_0x1d;
	undefined field25_0x1e;
	undefined field26_0x1f;
};

/**
 * gsx_gesture_ist - Gesture Irq handle
 * This functions is excuted when interrupt happended and
 * ic in doze mode.
 *
 * @cd: pointer to touch core data
 * return: 0 goon execute, EVT_CANCEL_IRQEVT  stop execute
 */
int goodix_gesture_ist(struct goodix_ts_core *cd)
{
	// TODO: the decompiled code in ghidra doesn't make much sense to me. Check it later.
	struct goodix_ts_hw_ops *hw_ops = cd->hw_ops;
	struct event_head gesture_data = { 0 };
	int ret;
	unsigned int overlay_area;
	u8 event_status;
	enum ts_event_type event_type;

	if (atomic_read(&cd->suspended) == 0)
		return EVT_CONTINUE;

	mutex_lock(&cd->report_mutex);

	ret = hw_ops->read(cd, cd->ic_info.misc.touch_data_addr,
			   (u8 *)&gesture_data, 0x12);

	if (ret != 0) {
		ts_err("failed get gesture event head data");
		goto error_out;
	}
	event_status = gesture_data.event_status;
	event_type = gesture_data.event_type;
	overlay_area = gesture_data.overlay_area;
	if (0 != (ret = checksum_cmp((const u8 *)&gesture_data, 8, 0))) {
		ts_err("touch head checksum err");
		ts_err("touch_head %*ph", 8, gesture_data);
		if (gesture_data.event_type != 'U' || event_status != '\0')
			goto error_out;
		ts_info("warning: fod up checksum err");
	}
	ts_debug("event_status = 0x%x", event_status);
	ts_debug("touch_head %*ph", 8, gesture_data);

	if (((event_status & 0x20) | ret) == 0) {
		event_type = EVENT_INVALID;
	}

	if (cd->unknown_uint == 2) {
		hw_ops->after_event_handler(cd);
	}

	// if (ret) {
	// 	ts_err("failed get gesture data");
	// 	goto re_send_ges_cmd;
	// }

	if ((ret == 0) && ((event_status >> 5 & 1) == 0)) {
		event_type = cd->ts_event.event_type;
		ts_err("invalid event type: 0x%x", event_type);
		goto success_out;
	}

	// if (!(gs_event.event_type & EVENT_GESTURE)) {
	// 	ts_err("invalid event type: 0x%x",
	// 		cd->ts_event.event_type);
	// 	goto re_send_ges_cmd;
	// }

	if (event_type == 0x55) {
		cd->fod_down_before_suspend = false;
		// TODO: WTF is this?
		if (((*(byte *)&cd->gesture_enabled >> 2 & 1) != 0) ||
		    (cd->nonui_status == 2)) {
			if (cd->fod_finger != false) {
				ts_info("gesture fod up, overlay_area: %d");
				cd->fod_finger = false;
				input_event(cd->input_dev, 1, 0x152, 0);
				input_event(cd->input_dev, 3, 0x32, 0);
				input_event(cd->input_dev, 3, 0x33, 0);
				input_event(cd->input_dev, 0, 0, 0);
				input_event(cd->input_dev, 3, 0x2f,
					    gesture_data.fod_id);
				input_mt_report_slot_state(cd->input_dev, 0, 0);
				input_event(cd->input_dev, 1, 0x14a, 0);
				input_event(cd->input_dev, 1, 0x145, 0);
				input_event(cd->input_dev, 0, 0, 0);
				update_fod_press_status(0);
			}
			goto final_exit;
		}
		ts_info("not enable FOD Up");
	} else if (event_type == 0xcc) {
		if ((*(byte *)&cd->gesture_enabled >> 1 & 1) != 0) {
			ts_info("GTP gesture report double tap");
			input_event(cd->input_dev, 1, 0x8f, 1);
			input_event(cd->input_dev, 0, 0, 0);
			input_event(cd->input_dev, 1, 0x8f, 0);
			input_event(cd->input_dev, 0, 0, 0);
			goto success_out;
		}
		ts_debug("not enable DOUBLE-TAP");
		goto success_out;
	} else if (event_type == 0x4c) {
		if ((*(byte *)&cd->gesture_enabled & 1) == 0) {
			ts_debug("not enable SINGLE-TAP");
		} else {
			ts_info("GTP gesture report single tap");
			input_event(cd->input_dev, 1, 0x162, 1);
			input_event(cd->input_dev, 0, 0, 0);
			input_event(cd->input_dev, 1, 0x162, 0);
			input_event(cd->input_dev, 0, 0, 0);
		}
		goto success_out;
	} else if (event_type == 0x46) {
		if ((*(byte *)&cd->gesture_enabled >> 2 & 1) == 0) {
			ts_info("not enable FOD Down");
			if (cd->fod_finger != false)
				goto final_exit;
			goto success_out;
		}
		if (cd->fod_down_before_suspend != false) {
			ts_debug("fod down before suspend, no need report");
			goto final_exit;
		}
	} else {
		ts_info("unsupported gesture: %x", event_type);
		goto success_out;
	}
	ts_debug(
		"gesture coordinate fodx: %d, fody: %d, fod_id: %d, overlay_area: %d",
		gesture_data.fodx, gesture_data.fody, gesture_data.fod_id,
		gesture_data.overlay_area);
	input_event(cd->input_dev, 1, 0x152, 1);
	input_event(cd->input_dev, 0, 0, 0);
	input_event(cd->input_dev, 3, 0x2f, gesture_data.fod_id);
	input_mt_report_slot_state(cd->input_dev, 0, 1);
	input_event(cd->input_dev, 1, 0x14a, 1);
	input_event(cd->input_dev, 1, 0x145, 1);
	input_event(cd->input_dev, 3, 0x35, gesture_data.fodx);
	input_event(cd->input_dev, 3, 0x36, gesture_data.fody);
	input_event(cd->input_dev, 3, 0x32, overlay_area);
	input_event(cd->input_dev, 3, 0x33, overlay_area);
	input_event(cd->input_dev, 0, 0, 0);
	if (cd->fod_finger == false) {
		ts_info("gesture fod down, overlay_area: %d", overlay_area);
	}
	cd->fod_finger = true;
	update_fod_press_status(1);
	goto final_exit;
	// 	if ((gesture_data[0] & 0x08)  != 0)
	// 		FP_Event_Gesture = 1;
	// #ifdef GOODIX_FOD_AREA_REPORT
	// 	if (cd->fod_status && (FP_Event_Gesture == 1) &&
	// 		(gs_event.gesture_type== 0x46) &&
	// 		(cd->nonui_status != 2)) {
	// 		fodx = gesture_data[8] | (gesture_data[9] << 8);
	// 		fody = gesture_data[10] | (gesture_data[11] << 8);
	// 		overlay_area=gesture_data[12];
	// 		ts_debug("gesture coordinate 0x%x,0x%x,0x%x",
	//                             fodx,fody,overlay_area);
	// 			input_report_key(cd->input_dev, BTN_INFO, 1);
	// 			input_sync(cd->input_dev);
	// #ifdef TYPE_B_PROTOCOL
	// 			input_mt_slot(cd->input_dev, 0);
	// 			input_mt_report_slot_state(cd->input_dev,
	// 					MT_TOOL_FINGER, 1);
	// #endif
	// 			input_report_key(cd->input_dev, BTN_TOUCH, 1);
	// 			input_report_key(cd->input_dev, BTN_TOOL_FINGER, 1);
	// 			input_report_abs(cd->input_dev,ABS_MT_POSITION_X,fodx);
	// 			input_report_abs(cd->input_dev,ABS_MT_POSITION_Y,fody);
	// 			input_report_abs(cd->input_dev, ABS_MT_WIDTH_MAJOR,overlay_area);
	// 			input_report_abs(cd->input_dev, ABS_MT_WIDTH_MINOR,overlay_area);
	// 			input_sync(cd->input_dev);
	// 			update_fod_press_status(1);
	// 			//mi_disp_lhbm_fod_set_finger_event(0, 1, true);
	// 			cd->fod_finger = true;
	// 			FP_Event_Gesture = 0;
	// 			goto re_send_ges_cmd;
	// 	}
	// 	if  ( (FP_Event_Gesture == 1) && (gs_event.gesture_type== 0x55)){
	// 		if (cd->fod_finger) {
	// 			ts_info("fod finger is %d",cd->fod_finger);
	// 			cd->fod_finger = false;
	// 			input_report_key(cd->input_dev, BTN_INFO, 0);
	// 			input_report_abs(cd->input_dev, ABS_MT_WIDTH_MAJOR, 0);
	// 			input_report_abs(cd->input_dev, ABS_MT_WIDTH_MINOR, 0);
	// 			input_sync(cd->input_dev);
	// #ifdef TYPE_B_PROTOCOL
	// 			input_mt_slot(cd->input_dev, 0);
	// 			input_mt_report_slot_state(cd->input_dev,
	// 					MT_TOOL_FINGER, 0);
	// #endif
	// 			input_report_key(cd->input_dev, BTN_TOUCH, 0);
	// 			input_report_key(cd->input_dev, BTN_TOOL_FINGER, 0);
	// 			input_sync(cd->input_dev);
	// 			update_fod_press_status(0);
	// 			//mi_disp_lhbm_fod_set_finger_event(0, 0, true);
	// 		}
	// 		goto re_send_ges_cmd;
	// 	}
	// #endif
	// 	if (QUERYBIT(gsx_gesture->gesture_type, gs_event.gesture_type)) {
	// 		gsx_gesture->gesture_data = gs_event.gesture_type;
	// 		/* do resume routine */
	// 		ts_info("GTP got valid gesture type 0x%x", gs_event.gesture_type);
	// 		if (cd->double_wakeup && gs_event.gesture_type == 0xcc) {
	// 			ts_info("GTP gesture report double tap");
	// 			key_value = KEY_WAKEUP;
	// 		}
	// 		if ((cd->fod_icon_status || cd->aod_status) &&
	// 				cd->nonui_status == 0 &&
	// 				gs_event.gesture_type == 0x4c ) {
	// 			ts_info("GTP gesture report single tap");
	// 			key_value = KEY_GOTO;
	// 		}
	// 		input_report_key(cd->input_dev, key_value, 1);
	// 		input_sync(cd->input_dev);
	// 		input_report_key(cd->input_dev, key_value, 0);
	// 		input_sync(cd->input_dev);
	// 		goto re_send_ges_cmd;
	// 	} else {
	// 		ts_info("unsupported gesture:%x", gs_event.gesture_type);
	// 	}

error_out:
	ts_err("failed get gesture data");
success_out:
	if (0 != hw_ops->gesture(cd, cd->gesture_enabled)) {
		ts_info("warning: failed re_send gesture cmd");
	}
final_exit:
	mutex_unlock(&cd->report_mutex);

	return EVT_CANCEL_IRQEVT;
}

/**
 * gsx_gesture_before_suspend - execute gesture suspend routine
 * This functions is excuted to set ic into doze mode
 *
 * @cd: pointer to touch core data
 * @module: pointer to goodix_ext_module struct
 * return: 0 goon execute, EVT_IRQCANCLED  stop execute
 */
int gsx_gesture_before_suspend(struct goodix_ts_core *cd,
			       struct goodix_ext_module *module)
{
	int ret;
	const struct goodix_ts_hw_ops *hw_ops = cd->hw_ops;

	ret = hw_ops->gesture(cd, cd->gesture_enabled);
	if (ret)
		ts_err("failed enter gesture mode");
	else
		ts_info("enter gesture mode");

	cd->work_status = 1;
	hw_ops->irq_enable(cd, true);
	enable_irq_wake(cd->irq);

	return EVT_CANCEL_SUSPEND;
}

int gsx_gesture_before_resume(struct goodix_ts_core *cd,
			      struct goodix_ext_module *module)
{
	const struct goodix_ts_hw_ops *hw_ops = cd->hw_ops;

	hw_ops->irq_enable(cd, false);
	disable_irq_wake(cd->irq);
	hw_ops->reset(cd, GOODIX_NORMAL_RESET_DELAY_MS);

	return EVT_CANCEL_RESUME;
}

int gesture_module_init(void)
{
	module_initialized = true;
	ts_info("gesture module init success");
	return 0;
}

void gesture_module_exit(void)
{
	ts_info("gesture module exit");
	if (!module_initialized)
		module_initialized = false;

	return;
}
