/*
  * fts.c
  *
  * FTS Capacitive touch screen controller (FingerTipS)
  *
  * Copyright (C) 2016, STMicroelectronics Limited.
  * Authors: AMG(Analog Mems Group)
  *
  * This program is free software; you can redistribute it and/or modify
  * it under the terms of the GNU General Public License version 2 as
  * published by the Free Software Foundation.
  *
  * THE PRESENT SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES
  * OR CONDITIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED, FOR THE SOLE
  * PURPOSE TO SUPPORT YOUR APPLICATION DEVELOPMENT.
  * AS A RESULT, STMICROELECTRONICS SHALL NOT BE HELD LIABLE FOR ANY DIRECT,
  * INDIRECT OR CONSEQUENTIAL DAMAGES WITH RESPECT TO ANY CLAIMS ARISING FROM
  * THE
  * CONTENT OF SUCH SOFTWARE AND/OR THE USE MADE BY CUSTOMERS OF THE CODING
  * INFORMATION CONTAINED HEREIN IN CONNECTION WITH THEIR PRODUCTS.
  *
  * THIS SOFTWARE IS SPECIFICALLY DESIGNED FOR EXCLUSIVE USE WITH ST PARTS.
  */


/*!
  * \file fts.c
  * \brief It is the main file which contains all the most important functions
  * generally used by a device driver the driver
  */

#include <linux/device.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/hrtimer.h>
#include <linux/delay.h>
#include <linux/firmware.h>
#include <linux/i2c.h>
#include <linux/i2c-dev.h>
#include <linux/gpio.h>
#include <linux/of_gpio.h>
#include <linux/regulator/consumer.h>
#include <linux/input.h>
#include <linux/input/mt.h>
#include <linux/interrupt.h>
#include <linux/notifier.h>
#include <linux/fb.h>
#include <linux/spi/spi.h>
#include <linux/backlight.h>
#if defined(CONFIG_DRM)
#include <linux/soc/qcom/panel_event_notifier.h>
#include <drm/drm_panel.h>
#endif

#include "fts.h"
#include "fts_lib/fts_flash.h"
#include "fts_lib/fts_test.h"
#include "fts_lib/fts_error.h"

#ifdef FTS_XIAOMI_TOUCHFEATURE
#include "../xiaomi/xiaomi_touch.h"
#endif

struct fts_ts_info *fts_info;
spinlock_t fts_int;
static int system_reseted_up;
static int system_reseted_down;
static int disable_irq_count = 1;

char fts_ts_phys[64];
extern struct test_to_do tests;

#if defined(CONFIG_DRM)
static struct drm_panel *active_panel;
#endif

#define event_id(_e)		(EVT_ID_##_e >> 4)
#define handler_name(_h)	fts_##_h##_event_handler
#define install_handler(_i, _evt, _hnd) \
		(_i->event_dispatch_table[event_id(_evt)] = handler_name(_hnd))


#ifdef KERNEL_ABOVE_2_6_38
#define TYPE_B_PROTOCOL
#endif

/**
  * Set the value of system_reseted_up flag
  * @param val value to write in the flag
  */
void set_system_reseted_up(int val)
{
	system_reseted_up = val;
}

/**
  * Return the value of system_resetted_down.
  * @return the flag value: 0 if not set, 1 if set
  */
int is_system_resetted_down(void)
{
	return system_reseted_down;
}

/**
  * Return the value of system_resetted_up.
  * @return the flag value: 0 if not set, 1 if set
  */
int is_system_resetted_up(void)
{
	return system_reseted_up;
}

/**
  * Set the value of system_reseted_down flag
  * @param val value to write in the flag
  */
void set_system_reseted_down(int val)
{
	system_reseted_down = val;
}

/**
  * Enable the host side interrupt
  */
static void fts_interrupt_enable(struct fts_ts_info *info)
{
	enable_irq(info->client->irq);
}

/**
  * Disable the interrupt so the ISR of the driver can not be called
  * @return OK if success or an error code which specify the type of error
  */
int fts_disable_interrupt(void)
{
	unsigned long flag;

	if (get_client() != NULL) {
		spin_lock_irqsave(&fts_int, flag);
		log_info(1, "%s: Number of disable = %d\n", __func__,
			disable_irq_count);
		if (disable_irq_count == 0) {
			log_info(1, "%s Executing Disable...\n", __func__);
			disable_irq(get_client()->irq);
			disable_irq_count++;
		}
		/* disable_irq is re-entrant so it is required to keep track
		  * of the number of calls of this when reenabling */
		  spin_unlock_irqrestore(&fts_int, flag);
		log_info(1, "%s: Interrupt Disabled!\n", __func__);
		return OK;
	}
	log_info(1, "%s: Impossible get client irq... ERROR %08X\n",
		__func__, ERROR_OP_NOT_ALLOW);
	return ERROR_OP_NOT_ALLOW;
}

/**
  * Reset the disable_irq count
  * @return OK
  */
int fts_reset_disable_irq_count(void)
{
	disable_irq_count = 0;
	return OK;
}

/**
  * Enable the interrupt so the ISR of the driver can be called
  * @return OK if success or an error code which specify the type of error
  */
int fts_enable_interrupt(void)
{
	unsigned long flag;

	if (get_client() != NULL) {
		spin_lock_irqsave(&fts_int, flag);
		log_info(1, "%s: Number of re-enable = %d\n", __func__,
			 disable_irq_count);
		while (disable_irq_count > 0) {
			/* loop N times according on the pending number of
			 * disable_irq to truly re-enable the int */
			log_info(1, "%s: Executing Enable...\n", __func__);
			enable_irq(get_client()->irq);
			disable_irq_count--;
		}

		spin_unlock_irqrestore(&fts_int, flag);
		log_info(1, "%s: Interrupt Enabled!\n", __func__);
		return OK;
	}
	log_info(1, "%s: Impossible get client irq... ERROR %08X\n",
		 __func__, ERROR_OP_NOT_ALLOW);
	return ERROR_OP_NOT_ALLOW;
}

/**
  * Release all the touches in the linux input subsystem
  * @param info pointer to fts_ts_info which contains info about the device and
  * its hw setup
  */
void release_all_touches(struct fts_ts_info *info)
{
	unsigned int type = MT_TOOL_FINGER;
	int i;

	for (i = 0; i < TOUCH_ID_MAX; i++) {
		input_mt_slot(info->input_dev, i);
		input_report_abs(info->input_dev, ABS_MT_PRESSURE, 0);
		input_mt_report_slot_state(info->input_dev, type, 0);
		input_report_abs(info->input_dev, ABS_MT_TRACKING_ID, -1);
	}
	input_report_key(info->input_dev, BTN_TOUCH, 0);
	input_sync(info->input_dev);
	info->touch_id = 0;
}


/**
  * The function handle the switching of the mode in the IC enabling/disabling
  * the sensing and the features set from the host
  * @param info pointer to fts_ts_info which contains info about the device and
  * its hw setup
  * @param force if 1, the enabling/disabling command will be send even
  * if the feature was already enabled/disabled otherwise it will judge if
  * the feature changed status or the IC had a system reset
  * @return OK if success or an error code which specify the type of error
  *encountered
  */
static int fts_mode_handler(struct fts_ts_info *info, int force)
{
	int res = OK;
	u8 data = 0;
	u8 gesture_cmd[4] = { 0x20, 0x00, 0x00, 0x00 };

	/* disable irq wake because resuming from gesture mode */
	if ((info->mode == SCAN_MODE_LOW_POWER) && (info->resume_bit == 1))
		disable_irq_wake(info->client->irq);

	info->mode = SCAN_MODE_HIBERNATE;
	log_info(1, "%s: Mode Handler starting...\n", __func__);
	switch (info->resume_bit) {
	case 0:	/* screen down */
		if (!info->gesture_enabled) {
			log_info(1, "%s: Screen OFF... Enter sense off\n", __func__);
			/* do sense off in order to avoid the flooding of the fifo with
			 * touch events if someone is touching the panel during suspend
			 */
			data = SCAN_MODE_HIBERNATE;
			res = fts_write_fw_reg(SCAN_MODE_ADDR, &data, 1);
			if (res == OK)
				info->mode = SCAN_MODE_HIBERNATE;
		} else {
			log_info(1, "%s: Screen OFF... Enter lp mode\n", __func__);
			data = SCAN_MODE_LOW_POWER;
			res = fts_write_fw_reg(SCAN_MODE_ADDR, &data, 1);
			if (res == OK)
				info->mode = SCAN_MODE_LOW_POWER;
			msleep(20);
			res = fts_write_fw_reg(GESTURE_ENABLE_ADDR, gesture_cmd, 4);
			if (res == OK)
				log_info(1, "doubletap enabled\n");
		}
		set_system_reseted_down(0);
		break;

	case 1:	/* screen up */
		log_info(1, "%s: Screen ON...\n", __func__);
		data = SCAN_MODE_ACTIVE;
		res = fts_write_fw_reg(SCAN_MODE_ADDR, &data, 1);
		if (res == OK)
			info->mode = SCAN_MODE_ACTIVE;
		set_system_reseted_up(0);
		break;

	default:
		log_info(1,
			 "%s: invalid resume_bit value = %d! ERROR %08X\n",
			 __func__, info->resume_bit, ERROR_OP_NOT_ALLOW);
		res = ERROR_OP_NOT_ALLOW;
	}
	/*TODO : For all the gesture related modes */

	log_info(1, "%s: Mode Handler finished! res = %08X mode = %08X\n",
		 __func__, res, info->mode);
	return res;
}

/**
 * Report to the linux input system the pressure and release of a button handling concurrency
 * @param info pointer to fts_ts_info which contains info about the device and its hw setup
 * @param key_code	button value
 */
void fts_input_report_key(struct fts_ts_info *info, int key_code)
{
	mutex_lock(&info->input_report_mutex);
	input_report_key(info->input_dev, key_code, 1);
	input_sync(info->input_dev);
	input_report_key(info->input_dev, key_code, 0);
	input_sync(info->input_dev);
	mutex_unlock(&info->input_report_mutex);
}

/**
 * Event handler for user report events (EVT_ID_USER_REPORT)
 * Handle user events reported by the FW due to some interaction triggered by an external user (press keys, perform gestures, etc.)
 */
static void fts_user_report_event_handler(struct fts_ts_info *info,
					  unsigned char *event)
{
	switch (event[1]) {
	case EVT_TYPE_USER_GESTURE:
		switch (event[2]) {
		case GEST_ID_DBLTAP:
			if (!info->gesture_enabled)
				return;
			fts_input_report_key(info, KEY_WAKEUP);
			break;

		default:
			log_info(0, "%s: Invalid gesture ID: %d\n", __func__, event[2]);
		}

		break;

	default:
		log_info(
			1,
			"%s Received unhandled user report event = %02X %02X %02X %02X %02X %02X %02X %02X\n",
			__func__, event[0], event[1], event[2], event[3],
			event[4], event[5], event[6], event[7]);
	}
}

/**
  * Bottom Half Interrupt Handler function
  * This handler is called each time there is at least one new event in the FIFO
  * and the interrupt pin of the IC goes low. It will read all the events from
  * the FIFO and dispatch them to the proper event handler according the event
  * ID
  */
static void fts_event_handler(struct work_struct *work)
{
	struct fts_ts_info *info;
	int error = 0, count = 0;
	unsigned char data[FIFO_EVENT_SIZE] = { 0 };
	unsigned char event_id;

	event_dispatch_handler_t event_handler;

	info = container_of(work, struct fts_ts_info, work);
	pm_wakeup_event(info->dev, jiffies_to_msecs(HZ));
	for (count = 0; count < MAX_FIFO_EVENT; count++) {
		error = fts_read_fw_reg(FIFO_READ_ADDR, data, 8);
		if (error == OK && data[0] != EVT_ID_NOEVENT)
			event_id = data[0] >> 4;
		else
			break;

		if (event_id < NUM_EVT_ID) {
			event_handler = info->event_dispatch_table[event_id];
			event_handler(info, (data));
		}
	}
	input_sync(info->input_dev);
	fts_interrupt_enable(info);
}


/**
  * Top half Interrupt handler function
  * Respond to the interrupt and schedule the bottom half interrupt handler
  * in its work queue
  * @see fts_event_handler()
  */
static irqreturn_t fts_interrupt_handler(int irq, void *handle)
{
	struct fts_ts_info *info = handle;

	disable_irq_nosync(info->client->irq);
	queue_work(info->event_wq, &info->work);
	return IRQ_HANDLED;
}

/**
  * Event Handler for no events (EVT_ID_NOEVENT)
  */
static void fts_nop_event_handler(struct fts_ts_info *info,
					unsigned char *event)
{
	log_info(1,
		 "%s: Doing nothing for event = %02X %02X %02X %02X %02X %02X %02X %02X\n",
		 __func__, event[0], event[1], event[2], event[3],
		 event[4], event[5], event[6], event[7]);
}

/**
  * Event handler for enter and motion events (EVT_ID_ENTER_POINT,
  * EVT_ID_MOTION_POINT )
  * report to the linux input system touches with their coordinated and
  * additional informations
  */
static void fts_enter_pointer_event_handler(struct fts_ts_info *info, unsigned
					    char *event)
{
	unsigned char touch_id;
	unsigned int touch_condition = 1, tool = MT_TOOL_FINGER;
	int x, y, z, distance, major, minor;
	u8 touch_type;

	if (!info->resume_bit)
		goto no_report;

	touch_type = event[1] & 0x0F;
	touch_id = (event[1] & 0xF0) >> 4;

	x = (((int)event[3]) << 8) | (event[2]);
	y = (((int)event[5]) << 8) | (event[4]);
	z = (int)(event[5]);
	distance = 0;	/* if the tool is touching the display the distance
			 * should be 0 */
	major = (int)(event[6]);
	minor = (int)(event[7]);

	if (x >= info->board->x_max)
		x = info->board->x_max;

	if (y >= info->board->y_max)
		y = info->board->y_max;
	input_mt_slot(info->input_dev, touch_id);
	switch (touch_type) {
	/* TODO: customer can implement a different strategy for each kind of
	 * touch */
	case TOUCH_TYPE_FINGER:
	case TOUCH_TYPE_GLOVE:
	case TOUCH_TYPE_LARGE:
		tool = MT_TOOL_FINGER;
		touch_condition = 1;
		__set_bit(touch_id, &info->touch_id);
		break;


	case TOUCH_TYPE_FINGER_HOVER:
		tool = MT_TOOL_FINGER;
		touch_condition = 0;	/* need to hover */
		z = 0;	/* no pressure */
		__set_bit(touch_id, &info->touch_id);
		distance = DISTANCE_MAX;	/* check with fw report the
						 * hovering distance */
		break;

	default:
		log_info(1, "%s: Invalid touch type = %d ! No Report...\n",
			  __func__, touch_type);
		goto no_report;
	}

	input_report_key(info->input_dev, BTN_TOUCH, touch_condition);
	input_mt_report_slot_state(info->input_dev, tool, 1);
	input_report_abs(info->input_dev, ABS_MT_POSITION_X, x);
	input_report_abs(info->input_dev, ABS_MT_POSITION_Y, y);
	input_report_abs(info->input_dev, ABS_MT_TOUCH_MAJOR, major);
	input_report_abs(info->input_dev, ABS_MT_TOUCH_MINOR, minor);
	input_report_abs(info->input_dev, ABS_MT_PRESSURE, z);
	input_report_abs(info->input_dev, ABS_MT_DISTANCE, distance);

no_report:
	return;
}

/**
  * Event handler for leave event (EVT_ID_LEAVE_POINT )
  * Report to the linux input system that one touch left the display
  */
static void fts_leave_pointer_event_handler(struct fts_ts_info *info, unsigned
					    char *event)
{
	unsigned char touch_id;
	unsigned int tool = MT_TOOL_FINGER;
	u8 touch_type;

	touch_type = event[1] & 0x0F;
	touch_id = (event[1] & 0xF0) >> 4;


	input_mt_slot(info->input_dev, touch_id);
	switch (touch_type) {
	case TOUCH_TYPE_FINGER:
	case TOUCH_TYPE_GLOVE:
	case TOUCH_TYPE_LARGE:
	case TOUCH_TYPE_FINGER_HOVER:
		tool = MT_TOOL_FINGER;
		__clear_bit(touch_id, &info->touch_id);
		break;
	default:
		log_info(1, "%s: Invalid touch type = %d ! No Report...\n",
			 __func__, touch_type);
		return;
	}

	input_report_abs(info->input_dev, ABS_MT_PRESSURE, 0);
	input_mt_report_slot_state(info->input_dev, tool, 0);
	input_report_abs(info->input_dev, ABS_MT_TRACKING_ID, -1);
}

#define fts_motion_pointer_event_handler fts_enter_pointer_event_handler
/*!< remap the motion event handler to the same function which handle the enter
 * event */
/**
  * Event handler for error events (EVT_ID_ERROR)
  * Handle unexpected error events implementing recovery strategy and
  * restoring the sensing status that the IC had before the error occured
  */
static void fts_error_event_handler(struct fts_ts_info *info, unsigned
				    char *event)
{
	int error = 0;

	log_info(1,
		 "%s: Received event %02X %02X %02X %02X %02X %02X %02X %02X\n",
		 __func__, event[0], event[1], event[2], event[3], event[4],
		 event[5],
		 event[6], event[7]);

	switch (event[1]) {
	case EVT_TYPE_ERROR_HARD_FAULT:
	case EVT_TYPE_ERROR_WATCHDOG:
	{
		/* before reset clear all slots */
		release_all_touches(info);
		fts_disable_interrupt();
		error = fts_system_reset(1);
		error |= fts_mode_handler(info, 0);
		error |= fts_enable_interrupt();
		if (error < OK)
			log_info(1,
				 "%s: Cannot reset the device ERROR %08X\n",
				 __func__, error);
	}
	break;
	}
}

/**
  * Event handler for controller ready event (EVT_ID_CONTROLLER_READY)
  * Handle controller events received after unexpected reset of the IC updating
  * the resets flag and restoring the proper sensing status
  */
static void fts_controller_ready_event_handler(struct fts_ts_info *info,
					       unsigned char *event)
{
	int error;

	log_info(1,
		"%s: controller event %02X %02X %02X %02X %02X %02X %02X %02X\n",
		 __func__, event[0], event[1], event[2], event[3], event[4],
		 event[5],
		 event[6], event[7]);
	release_all_touches(info);
	set_system_reseted_up(1);
	set_system_reseted_down(1);
	error = fts_mode_handler(info, 0);
	if (error < OK)
		log_info(1,
			 "%s: Cannot restore the device status ERROR %08X\n",
			 __func__, error);
}

/**
  * Initialize the dispatch table with the event handlers for any possible event
  * ID
  * Set IRQ pin behavior (level triggered low)
  * Register top half interrupt handler function.
  * @see fts_interrupt_handler()
  */
static int fts_interrupt_install(struct fts_ts_info *info)
{
	int i, error = 0;

	info->event_dispatch_table = kzalloc(sizeof(event_dispatch_handler_t) *
					     NUM_EVT_ID, GFP_KERNEL);
	if (!info->event_dispatch_table) {
		log_info(1, "%s: OOM allocating event dispatch table\n",
			__func__);
		return -ENOMEM;
	}

	for (i = 0; i < NUM_EVT_ID; i++)
		info->event_dispatch_table[i] = fts_nop_event_handler;

	install_handler(info, ENTER_POINT, enter_pointer);
	install_handler(info, LEAVE_POINT, leave_pointer);
	install_handler(info, MOTION_POINT, motion_pointer);
	install_handler(info, ERROR, error);
	install_handler(info, CONTROLLER_READY, controller_ready);
	install_handler(info, USER_REPORT, user_report);

	error = fts_disable_interrupt();

	log_info(1, "%s: Interrupt Mode\n", __func__);
	if (request_irq(info->client->irq, fts_interrupt_handler,
			IRQF_TRIGGER_LOW, FTS_TS_DRV_NAME, info)) {
		log_info(1, "%s: Request irq failed\n", __func__);
		kfree(info->event_dispatch_table);
		error = -EBUSY;
	}

	return error;
}

/**
  *	Clean the dispatch table and the free the IRQ.
  *	This function is called when the driver need to be removed
  */
static void fts_interrupt_uninstall(struct fts_ts_info *info)
{
	fts_disable_interrupt();
	kfree(info->event_dispatch_table);
	free_irq(info->client->irq, info);
}

/**
  * Resume work function which perform a system reset, clean all the touches
  *from the linux input system and prepare the ground for enabling the sensing
  */
static void fts_resume_work(struct work_struct *work)
{
	struct fts_ts_info *info;

	info = container_of(work, struct fts_ts_info, resume_work);
	pm_wakeup_event(info->dev, jiffies_to_msecs(HZ));
	info->resume_bit = 1;
	fts_disable_interrupt();
	fts_system_reset(1);
	release_all_touches(info);
	fts_mode_handler(info, 0);
	info->sensor_sleep = false;
	fts_enable_interrupt();
	xiaomi_touch_set_suspend_state(XIAOMI_TOUCH_RESUME);
}

/**
  * Suspend work function which clean all the touches from Linux input system
  *and prepare the ground to disabling the sensing or enter in gesture mode
  */
static void fts_suspend_work(struct work_struct *work)
{
	struct fts_ts_info *info;

	info = container_of(work, struct fts_ts_info, suspend_work);
	pm_wakeup_event(info->dev, jiffies_to_msecs(HZ));
	info->resume_bit = 0;
	fts_mode_handler(info, 0);
	release_all_touches(info);
	info->sensor_sleep = true;
	fts_enable_interrupt();
	xiaomi_touch_set_suspend_state(XIAOMI_TOUCH_SUSPEND);
}


#if defined(CONFIG_DRM)
static void
fts_drm_panel_notifier_callback(enum panel_event_notifier_tag notifier_tag,
				struct panel_event_notification *notification,
				void *client_data)
{
	struct fts_ts_info *info = client_data;

	if (!notification) {
		log_info(1, "%s: Invalid notification\n", __func__);
		return;
	}

	log_info(1, "%s: Notification type:%d, early_trigger:%d",
		 __func__, notification->notif_type,
		 notification->notif_data.early_trigger);

	switch (notification->notif_type) {
	case DRM_PANEL_EVENT_UNBLANK:
		log_info(1, "%s: FB_BLANK_UNBLANK before sensor_sleep\n", __func__);
		flush_workqueue(info->event_wq);
		if (!info->sensor_sleep)
			return;
		log_info(1, "%s: FB_BLANK_UNBLANK\n", __func__);
		queue_work(info->event_wq, &info->resume_work);
		break;
	case DRM_PANEL_EVENT_BLANK:
	case DRM_PANEL_EVENT_BLANK_LP:
		if (notification->notif_data.early_trigger == 0) {
			flush_workqueue(info->event_wq);
			if (info->sensor_sleep)
				return;
			log_info(1, "%s: FB_BLANK %s\n", __func__,
				 notification->notif_type ==
						 DRM_PANEL_EVENT_BLANK_LP ?
					 "POWER DOWN" :
					 "LP");
			queue_work(info->event_wq, &info->suspend_work);
		}
		break;
	default:
		log_info(1, "%s: notification serviced :%d\n", __func__,
			 notification->notif_type);
		break;
	}
}

/**
 * pointer active_panel initlized function, used to checkout panel(config)from devices
 * tree ,later will be passed to drm_notifyXXX function.
 * @param device node contains the panel
 * @return pointer to that panel if panel truely  exists, otherwise negative number
 */

static int fts_ts_check_panel(struct device_node *np)
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

static void fts_register_panel_notifier_work(struct work_struct *work)
{
	struct fts_ts_info *info = container_of(
		work, struct fts_ts_info, panel_notifier_register_work.work);
	struct device_node *dp = info->client->dev.of_node;
	int error;
	static int check_count = 0;

	log_info(1, "Start register panel notifier\n");

	error = fts_ts_check_panel(dp);

	if (!dp || !active_panel) {
		log_info(1, "Failed to register panel notifier, try again\n");
		if (check_count++ < 5)
			schedule_delayed_work(
				&info->panel_notifier_register_work,
				msecs_to_jiffies(5000));
		else {
			log_info(
				1,
				"Failed to register panel notifier, not try\n");
		}
		return;
	}

	if (active_panel) {
		info->notifier_cookie = panel_event_notifier_register(
			PANEL_EVENT_NOTIFICATION_PRIMARY,
			PANEL_EVENT_NOTIFIER_CLIENT_PRIMARY_TOUCH, active_panel,
			&fts_drm_panel_notifier_callback, (void *)info);
		if (!info->notifier_cookie)
			log_info(1, "Failed to register for panel events\n");
	}
}
#endif

#ifdef FTS_XIAOMI_TOUCHFEATURE
static struct xiaomi_touch_interface xiaomi_touch_interfaces;

static int fts_set_cur_value(int mode, int value)
{
	log_info(1, "%s: mode: %d, value: %d\n", __func__, mode, value);

	if (mode == Touch_Doubletap_Mode && fts_info && value >= 0) {
		fts_info->gesture_enabled = value;
		return 0;
	}

	log_info(1, "%s: unhandled mode %d\n", __func__, mode);

	return 0;
}

static int fts_get_cur_value(int mode, int value_type)
{
	log_info(1, "%s: mode: %d, value type: %d\n", __func__, mode, value_type);

	if (mode == Touch_Doubletap_Mode && fts_info) {
		return fts_info->gesture_enabled;
	}

	log_info(1, "%s: unsupported mode %d with value type %d\n", __func__, mode, value_type);
	return -1;
}
#endif

/**
  * Complete the boot up process, initializing the sensing of the IC according
  * to the current setting chosen by the host
  * Register the notifier for the suspend/resume actions and the event handler
  * @return OK if success or an error code which specify the type of error
  */
static int fts_init_sensing(struct fts_ts_info *info)
{
	int error = 0;

	error |= fts_interrupt_install(info);
	log_info(1, "%s: Sensing on..\n", __func__);
	error |= fts_mode_handler(info, 0);
	error |= fts_reset_disable_irq_count();

	if (error < OK)
		log_info(1, "%s: Init error (ERROR = %08X)\n",
			 __func__, error);


	return error;
}

/**
  *	Implement the fw update and initialization flow of the IC that should be
  *executed at every boot up.
  *	The function perform a fw update of the IC in case of crc error or a new
  *fw version and then understand if the IC need to be re-initialized again.
  *	@return  OK if success or an error code which specify the type of error
  *	encountered
  */

static int fts_chip_init(struct fts_ts_info *info)
{
	int res = OK;
	int i = 0;
	struct force_update_flag force_burn;

	force_burn.code_update = 0;
	force_burn.panel_init = 0;
	for (; i < FLASH_MAX_SECTIONS; i++)
		force_burn.section_update[i] = 0;
	log_info(1, "%s: [1]: FW UPDATE..\n", __func__, res);
	res = flash_update(&force_burn);
	if (res != OK) {
		log_info(1, "%s: [1]: FW UPDATE FAILED..\n", __func__, res);
		//return res;
	}
	if (force_burn.panel_init) {
		log_info(1, "%s: [2]: MP TEST..\n", __func__, res);
		res = fts_production_test_main(LIMITS_FILE, &tests, 0);
		if (res != OK)
			log_info(1, "%s: [2]: MP TEST FAILED..\n",
				__func__, res);
	}

	log_info(1, "%s: [3]: TOUCH INIT..\n", __func__, res);
	res = fts_init_sensing(info);
	if (res != OK) {
		log_info(1, "%s: [3]: TOUCH INIT FAILED..\n",
				__func__, res);
		return res;
	}
	return res;
}

#ifndef FW_UPDATE_ON_PROBE
/**
  *	Function called by the delayed workthread executed after the probe in
  * order to perform the fw update flow
  *	@see  fts_chip_init()
  */
static void flash_update_auto(struct work_struct *work)
{
	struct delayed_work *fwu_work = container_of(work, struct delayed_work,
						     work);
	struct fts_ts_info *info = container_of(fwu_work, struct fts_ts_info,
						fwu_work);
	fts_chip_init(info);
}
#endif

/**
  * This function try to attempt to communicate with the IC for the first time
  * during the boot up process in order to read the necessary info for the
  * following stages.
  * The function execute a system reset, read fundamental info (system info)
  * @return OK if success or an error code which specify the type of error
  */
static int fts_init(struct fts_ts_info *info)
{
	int res = 0;
	u8 data[3] = { 0 };
	u16 chip_id = 0;

	open_channel(info->client);
	set_reset_gpio(info->board->reset_gpio);
	init_test_to_do();
#ifndef I2C_INTERFACE
#ifdef SPI4_WIRE
	log_info(1, "%s: Configuring SPI4..\n", __func__);
	res = configure_spi4();
	if (res < OK) {
		log_info(1, "%s: Error configuring IC in spi4 mode: %08X\n",
			__func__, res);
		return res;
	}
#endif
#endif
	res = fts_write_read_u8ux(FTS_CMD_HW_REG_R, HW_ADDR_SIZE,
				CHIP_ID_ADDRESS, data, 2, DUMMY_BYTE);
	if (res < OK) {
		log_info(1, "%s: Bus Connection issue: %08X\n", __func__, res);
		return res;
	}
	chip_id = (u16)((data[0] << 8) + data[1]);
	log_info(1, "%s: Chip id: 0x%04X\n", __func__, chip_id);
	if (chip_id != CHIP_ID) {
		log_info(1,
			"%s: Wrong Chip detected.. Expected|Detected: 0x%04X|0x%04X\n",
			__func__, CHIP_ID, chip_id);
		return ERROR_WRONG_CHIP_ID;
	}
	res = fts_system_reset(1);
	if (res < OK) {
		if (res == ERROR_BUS_W) {
			log_info(1, "%s: Bus Connection issue\n", __func__);
			return res;
		}
		/*other errors are because of no FW,
		so we continue to flash*/
	}
	res = read_sys_info();
	if (res < 0)
		log_info(1, "%s: Couldnot read sys info.. No FW..\n",
			 __func__);
	return OK;
}

/**
  * From the name of the power regulator get/put the actual regulator structs
  * (copying their references into fts_ts_info variable)
  * @param info pointer to fts_ts_info which contains info about the device and
  * its hw setup
  * @param get if 1, the regulators are get otherwise they are put (released)
  * back to the system
  * @return OK if success or an error code which specify the type of error
  */
static int fts_get_reg(struct fts_ts_info *info, bool get)
{
	int ret_val;
	const struct fts_hw_platform_data *bdata = info->board;

	if (!get) {
		ret_val = 0;
		goto regulator_put;
	}

	if ((bdata->vdd_reg_name != NULL) && (*bdata->vdd_reg_name != 0)) {
		info->vdd_reg = regulator_get(info->dev, bdata->vdd_reg_name);
		if (IS_ERR(info->vdd_reg)) {
			log_info(1, "%s: Failed to get power regulator\n",
				 __func__);
			ret_val = PTR_ERR(info->vdd_reg);
			goto regulator_put;
		}
	}

	if ((bdata->avdd_reg_name != NULL) && (*bdata->avdd_reg_name != 0)) {
		info->avdd_reg = regulator_get(info->dev, bdata->avdd_reg_name);
		if (IS_ERR(info->avdd_reg)) {
			log_info(1,
				 "%s: Failed to get bus pullup regulator\n",
				 __func__);
			ret_val = PTR_ERR(info->avdd_reg);
			goto regulator_put;
		}
	}

	return OK;

regulator_put:
	if (info->vdd_reg) {
		regulator_put(info->vdd_reg);
		info->vdd_reg = NULL;
	}

	if (info->avdd_reg) {
		regulator_put(info->avdd_reg);
		info->avdd_reg = NULL;
	}

	return ret_val;
}

/**
  * Enable or disable the power regulators
  * @param info pointer to fts_ts_info which contains info about the device and
  * its hw setup
  * @param enable if 1, the power regulators are turned on otherwise they are
  * turned off
  * @return OK if success or an error code which specify the type of error
  */
static int fts_enable_reg(struct fts_ts_info *info, bool enable)
{
	int ret_val;

	if (!enable) {
		ret_val = 0;
		goto disable_pwr_reg;
	}

	if (info->vdd_reg) {
		ret_val = regulator_enable(info->vdd_reg);
		if (ret_val < 0) {
			log_info(1, "%s: Failed to enable bus regulator\n",
				 __func__);
			goto exit;
		}
	}

	if (info->avdd_reg) {
		ret_val = regulator_enable(info->avdd_reg);
		if (ret_val < 0) {
			log_info(1, "%s: Failed to enable power regulator\n",
				 __func__);
			goto disable_bus_reg;
		}
	}

	return OK;

disable_pwr_reg:
	if (info->avdd_reg)
		regulator_disable(info->avdd_reg);

disable_bus_reg:
	if (info->vdd_reg)
		regulator_disable(info->vdd_reg);

exit:
	return ret_val;
}

/**
  * Configure a GPIO according to the parameters
  * @param gpio gpio number
  * @param config if true, the gpio is set up otherwise it is free
  * @param dir direction of the gpio, 0 = in, 1 = out
  * @param state initial value (if the direction is in, this parameter is
  * ignored)
  * return error code
  */

static int fts_gpio_setup(int gpio, bool config, int dir, int state)
{
	int ret_val = 0;
	unsigned char buf[16];

	if (config) {
		snprintf(buf, 16, "fts_gpio_%u\n", gpio);

		ret_val = gpio_request(gpio, buf);
		if (ret_val) {
			log_info(1, "%s %s: Failed to get gpio %d (code: %d)",
				 __func__, gpio, ret_val);
			return ret_val;
		}

		if (dir == 0)
			ret_val = gpio_direction_input(gpio);
		else
			ret_val = gpio_direction_output(gpio, state);
		if (ret_val) {
			log_info(1, "%s %s: Failed to set gpio %d direction",
				 __func__, gpio);
			return ret_val;
		}
	} else
		gpio_free(gpio);

	return ret_val;
}

/**
  * Setup the IRQ and RESET (if present) gpios.
  * If the Reset Gpio is present it will perform a cycle HIGH-LOW-HIGH in order
  *to assure that the IC has been reset properly
  */
static int fts_set_gpio(struct fts_ts_info *info)
{
	int ret_val;
	struct fts_hw_platform_data *bdata =
		info->board;

	ret_val = fts_gpio_setup(bdata->irq_gpio, true, 0, 0);
	if (ret_val < 0) {
		log_info(1, "%s %s: Failed to configure irq GPIO\n",
			 __func__);
		goto err_gpio_irq;
	}

	if (bdata->reset_gpio >= 0) {
		ret_val = fts_gpio_setup(bdata->reset_gpio, true, 1, 0);
		if (ret_val < 0) {
			log_info(1, "%s %s: Failed to configure reset GPIO\n",
				 __func__);
			goto err_gpio_reset;
		}
	}
	if (bdata->reset_gpio >= 0) {
		gpio_set_value(bdata->reset_gpio, 0);
		msleep(20);
		gpio_set_value(bdata->reset_gpio, 1);
	}

	return OK;

err_gpio_reset:
	fts_gpio_setup(bdata->irq_gpio, false, 0, 0);
	bdata->reset_gpio = GPIO_NOT_DEFINED;
err_gpio_irq:
	return ret_val;
}

static int fts_pinctrl_init(struct fts_ts_info *info)
{
	int retval = 0;
	/* Get pinctrl if target uses pinctrl */
	info->ts_pinctrl = devm_pinctrl_get(info->dev);

	if (IS_ERR_OR_NULL(info->ts_pinctrl)) {
		retval = PTR_ERR(info->ts_pinctrl);
		dev_err(info->dev, "Target does not use pinctrl %d\n", retval);
		goto err_pinctrl_get;
	}

	info->pinctrl_state_active =
		pinctrl_lookup_state(info->ts_pinctrl, PINCTRL_STATE_ACTIVE);

	if (IS_ERR_OR_NULL(info->pinctrl_state_active)) {
		retval = PTR_ERR(info->pinctrl_state_active);
		dev_err(info->dev, "Can not lookup %s pinstate %d\n",
			PINCTRL_STATE_ACTIVE, retval);
		goto err_pinctrl_lookup;
	}

	info->pinctrl_state_suspend =
		pinctrl_lookup_state(info->ts_pinctrl, PINCTRL_STATE_SUSPEND);

	if (IS_ERR_OR_NULL(info->pinctrl_state_suspend)) {
		retval = PTR_ERR(info->pinctrl_state_suspend);
		dev_dbg(info->dev, "Can not lookup %s pinstate %d\n",
			PINCTRL_STATE_SUSPEND, retval);
		goto err_pinctrl_lookup;
	}

	return 0;
err_pinctrl_lookup:
	devm_pinctrl_put(info->ts_pinctrl);
err_pinctrl_get:
	info->ts_pinctrl = NULL;
	return retval;
}

/**
  * Retrieve and parse the hw information from the device tree node defined in
  * the system.
  * the most important information to obtain are: IRQ and RESET gpio numbers,
  * power regulator names
  * In the device file node is possible to define additional optional
  *information that can be parsed here.
  */
static int parse_dt(struct device *dev, struct fts_hw_platform_data *bdata)
{
	int ret_val;
	const char *name;
	struct device_node *np = dev->of_node;
	u32 temp_val;

	bdata->irq_gpio = of_get_named_gpio_flags(np, "fts,irq-gpio", 0, NULL);

	log_info(1, "%s: irq_gpio = %d\n", __func__, bdata->irq_gpio);

	ret_val = of_property_read_string(np, "fts,regulator_dvdd", &name);
	if (ret_val == -EINVAL)
		bdata->vdd_reg_name = NULL;
	else if (ret_val < 0)
		return ret_val;
	else {
		bdata->vdd_reg_name = name;
		log_info(1, "%s: pwr_reg_name = %s\n", __func__, name);
	}

	ret_val = of_property_read_string(np, "fts,regulator_avdd", &name);
	if (ret_val == -EINVAL)
		bdata->avdd_reg_name = NULL;
	else if (ret_val < 0)
		return ret_val;
	else {
		bdata->avdd_reg_name = name;
		log_info(1, "%s: bus_reg_name = %s\n", __func__, name);
	}

	if (of_property_read_bool(np, "fts,reset-gpio")) {
		bdata->reset_gpio = of_get_named_gpio_flags(np,
				"fts,reset-gpio", 0, NULL);
		log_info(1, "%s: reset_gpio =%d\n",
			__func__, bdata->reset_gpio);
	} else
		bdata->reset_gpio = GPIO_NOT_DEFINED;

	ret_val = of_property_read_u32(np, "fts,x-max", &temp_val);
	if (ret_val < 0)
		bdata->x_max = X_AXIS_MAX;
	else
		bdata->x_max = temp_val;

	ret_val = of_property_read_u32(np, "fts,y-max", &temp_val);
	if (ret_val < 0)
		bdata->y_max = Y_AXIS_MAX;
	else
		bdata->y_max = temp_val;

	return OK;
}

/**
  * Probe function, called when the driver it is matched with a device with the
  *same name compatible name
  * This function allocate, initialize and define all the most important
  *function and flow that are used by the driver to operate with the IC.
  * It allocates device variables, initialize queues and schedule works,
  *registers the IRQ handler, suspend/resume callbacks, registers the device to
  *the linux input subsystem etc.
  */
#ifdef I2C_INTERFACE
static int fts_probe(struct i2c_client *client, const struct i2c_device_id
						*idp)
{
#else
static int fts_probe(struct spi_device *client)
{
#endif

	struct fts_ts_info *info = NULL;
	int error = 0;
	struct device_node *dp = client->dev.of_node;
	int ret_val;
	u16 bus_type;
	u8 input_dev_free_flag = 0;

	log_info(1, "%s: driver probe begin!\n", __func__);
	log_info(1, "%s: driver ver. %s\n", __func__, FTS_TS_DRV_VERSION);


	log_info(1, "%s: SET Bus Functionality :\n", __func__);
#ifdef I2C_INTERFACE
	log_info(1, "%s: I2C interface...\n", __func__);
	if (!i2c_check_functionality(client->adapter, I2C_FUNC_I2C)) {
		log_info(1, "%s: Unsupported I2C functionality\n", __func__);
		error = -EIO;
		goto probe_error_exit_0;
	}

	log_info(1, "%s: I2C address: %x\n", __func__, client->addr);
	bus_type = BUS_I2C;
#else
	log_info(1, "%s: SPI interface...\n", __func__);
	client->mode = SPI_MODE_0;
#ifndef SPI4_WIRE
	client->mode |= SPI_3WIRE;
#endif
	client->max_speed_hz = SPI_CLOCK_FREQ;
	client->bits_per_word = 8;
	if (spi_setup(client) < 0) {
		log_info(1, "%s: Unsupported SPI functionality\n", __func__);
		error = -EIO;
		goto probe_error_exit_0;
	}
	bus_type = BUS_SPI;
#endif

	log_info(1, "%s SET Device driver INFO:\n", __func__);
	info = kzalloc(sizeof(struct fts_ts_info), GFP_KERNEL);
	if (!info) {
		log_info(1,
			 "%s: Out of memory... Impossible to allocate struct info!\n",
			 __func__);
		error = -ENOMEM;
		goto probe_error_exit_0;
	}

	fts_info = info;
	info->client = client;
	info->dev = &info->client->dev;

	dev_set_drvdata(info->dev, info);

	if (dp) {
		info->board = devm_kzalloc(&client->dev,
					   sizeof(struct fts_hw_platform_data),
					   GFP_KERNEL);
		if (!info->board) {
			log_info(1, "%s: ERROR:info.board kzalloc failed\n",
				 __func__);
			goto probe_error_exit_1;
		}
		parse_dt(&client->dev, info->board);
	}

#if defined(CONFIG_DRM)
	INIT_DELAYED_WORK(&info->panel_notifier_register_work,
			  fts_register_panel_notifier_work);
	error = fts_ts_check_panel(dp);
	if (!active_panel) {
		log_info(1, "Can't find panel\n");
		schedule_delayed_work(&info->panel_notifier_register_work,
				      msecs_to_jiffies(5000));
	} else {
		info->notifier_cookie = panel_event_notifier_register(
			PANEL_EVENT_NOTIFICATION_PRIMARY,
			PANEL_EVENT_NOTIFIER_CLIENT_PRIMARY_TOUCH, active_panel,
			&fts_drm_panel_notifier_callback, (void *)info);
		if (!info->notifier_cookie) {
			log_info(1, "Failed to register for panel events\n");
		}
	}
#endif

	ret_val = fts_pinctrl_init(info);

	if (!ret_val && info->ts_pinctrl) {
		error = pinctrl_select_state(info->ts_pinctrl,
					     info->pinctrl_state_active);

		if (error < 0) {
			dev_err(&client->dev,
				"%s: Failed to select %s pinstate %d\n",
				__func__, PINCTRL_STATE_ACTIVE, error);
		}
	} else {
		dev_err(&client->dev, "%s: Failed to init pinctrl\n", __func__);
		goto probe_error_exit_2;
	}

	log_info(1, "%s: SET Regulators:\n", __func__);
	ret_val = fts_get_reg(info, true);
	if (ret_val < 0) {
		log_info(1, "%s: ERROR:Failed to get regulators\n",
			 __func__);
		goto probe_error_exit_2;
	}

	ret_val = fts_enable_reg(info, true);
	if (ret_val < 0) {
		log_info(1, "%s: ERROR Failed to enable regulators\n",
			 __func__);
		goto probe_error_exit_3;
	}

	log_info(1, "%s: SET GPIOS:\n", __func__);
	ret_val = fts_set_gpio(info);
	if (ret_val < 0) {
		log_info(1, "%s: ERROR Failed to set up GPIO's\n",
			 __func__);
		goto probe_error_exit_3;
	}
	info->client->irq = gpio_to_irq(info->board->irq_gpio);
	info->dev = &info->client->dev;

	log_info(1, "%s: SET Event Handler:\n", __func__);
	info->event_wq = alloc_workqueue("fts-event-queue", WQ_UNBOUND |
					 WQ_HIGHPRI | WQ_CPU_INTENSIVE, 1);
	if (!info->event_wq) {
		log_info(1, "%s: ERROR: Cannot create work thread\n", __func__);
		error = -ENOMEM;
		goto probe_error_exit_3;
	}

	INIT_WORK(&info->work, fts_event_handler);
	INIT_WORK(&info->resume_work, fts_resume_work);
	INIT_WORK(&info->suspend_work, fts_suspend_work);

	log_info(1, "%s: SET Input Device Property:\n", __func__);
	info->input_dev = input_allocate_device();
	if (!info->input_dev) {
		log_info(1, "%s: ERROR: No such input device defined!\n",
			__func__);
		error = -ENODEV;
		goto probe_error_exit_4;
	}
	info->input_dev->dev.parent = &client->dev;
	info->input_dev->name = FTS_TS_DRV_NAME;
	snprintf(fts_ts_phys, sizeof(fts_ts_phys), "%s/input0",
		 info->input_dev->name);
	info->input_dev->phys = fts_ts_phys;
	info->input_dev->id.bustype = bus_type;
	info->input_dev->id.vendor = 0x0001;
	info->input_dev->id.product = 0x0002;
	info->input_dev->id.version = 0x0100;

	__set_bit(EV_SYN, info->input_dev->evbit);
	__set_bit(EV_KEY, info->input_dev->evbit);
	__set_bit(EV_ABS, info->input_dev->evbit);
	__set_bit(BTN_TOUCH, info->input_dev->keybit);

	input_mt_init_slots(info->input_dev, TOUCH_ID_MAX, INPUT_MT_DIRECT);
	input_set_abs_params(info->input_dev, ABS_MT_POSITION_X, X_AXIS_MIN,
						info->board->x_max - 1, 0, 0);
	input_set_abs_params(info->input_dev, ABS_MT_POSITION_Y, Y_AXIS_MIN,
						info->board->y_max - 1, 0, 0);
	input_set_abs_params(info->input_dev, ABS_MT_TOUCH_MAJOR, AREA_MIN,
						info->board->x_max, 0, 0);
	input_set_abs_params(info->input_dev, ABS_MT_TOUCH_MINOR, AREA_MIN,
						info->board->y_max, 0, 0);
	input_set_abs_params(info->input_dev, ABS_MT_PRESSURE, PRESSURE_MIN,
						PRESSURE_MAX, 0, 0);
	input_set_abs_params(info->input_dev, ABS_MT_DISTANCE, DISTANCE_MIN,
						DISTANCE_MAX, 0, 0);
	input_set_capability(info->input_dev, EV_KEY, KEY_WAKEUP);
	mutex_init(&(info->input_report_mutex));
	spin_lock_init(&fts_int);
	error = input_register_device(info->input_dev);
	if (error) {
		log_info(1, "%s: ERROR: No such input device\n", __func__);
		error = -ENODEV;
		goto probe_error_exit_5;
	}
	input_dev_free_flag = 1;

	info->resume_bit = 1;
	ret_val = fts_init(info);
	if (ret_val < OK) {
		log_info(1, "%s: Initialization fails.. exiting..\n",
			__func__);
		goto probe_error_exit_6;
	}

	ret_val = fts_proc_init();
	if (ret_val < OK)
		log_info(1, "%s: Cannot create /proc filenode..\n", __func__);

#if defined(FW_UPDATE_ON_PROBE) && defined(FW_H_FILE)
	ret_val = fts_chip_init(info);
	if (ret_val < OK) {
		log_info(1, "%s: Flashing FW/Production Test/Touch Init Failed..\n",
			 __func__);
		goto probe_error_exit_6;
	}
#else
	log_info(1, "%s: SET Auto Fw Update:\n", __func__);
	info->fwu_workqueue = alloc_workqueue("fts-fwu-queue", WQ_UNBOUND |
					      WQ_HIGHPRI | WQ_CPU_INTENSIVE, 1);
	if (!info->fwu_workqueue) {
		log_info(1, "%s ERROR: Cannot create fwu work thread\n",
			__func__);
		goto probe_error_exit_6;
	}
	INIT_DELAYED_WORK(&info->fwu_work, flash_update_auto);
#endif
#ifndef FW_UPDATE_ON_PROBE
	queue_delayed_work(info->fwu_workqueue, &info->fwu_work,
			   msecs_to_jiffies(1000));
#endif

	if (info->fts_tp_class == NULL)
#ifdef FTS_XIAOMI_TOUCHFEATURE
		info->fts_tp_class = get_xiaomi_touch_class();
#else
		info->fts_tp_class = class_create(THIS_MODULE, "touch");
#endif
	info->fts_touch_dev = device_create(info->fts_tp_class, NULL,
										CHIP_ID, info, "tp_dev");

	if (IS_ERR(info->fts_touch_dev)) {
		log_info(1, "ERROR: Failed to create device for sysfs!\n");
		goto probe_error_exit_7;
	}

#ifdef FTS_XIAOMI_TOUCHFEATURE
	memset(&xiaomi_touch_interfaces, 0x00,
		   sizeof(struct xiaomi_touch_interface));
	xiaomi_touch_interfaces.setModeValue = fts_set_cur_value;
	xiaomi_touch_interfaces.getModeValue = fts_get_cur_value;
	xiaomitouch_register_modedata(0, &xiaomi_touch_interfaces);
#endif

	log_info(1, "%s: Probe Finished!\n", __func__);
	return OK;

probe_error_exit_7:
	device_destroy(info->fts_tp_class, CHIP_ID);

probe_error_exit_6:
	input_unregister_device(info->input_dev);

probe_error_exit_5:
	if (!input_dev_free_flag)
		input_free_device(info->input_dev);

probe_error_exit_4:
	destroy_workqueue(info->event_wq);

probe_error_exit_3:
	fts_enable_reg(info, false);
	fts_get_reg(info, false);

probe_error_exit_2:
#if defined(CONFIG_DRM)
	cancel_delayed_work_sync(&info->panel_notifier_register_work);
	if (active_panel && info->notifier_cookie)
		panel_event_notifier_unregister(info->notifier_cookie);
#endif

	if (info->ts_pinctrl)
		devm_pinctrl_put(info->ts_pinctrl);

probe_error_exit_1:
	fts_info = NULL;
	kfree(info);

probe_error_exit_0:
	log_info(1, "%s: Probe Failed!\n", __func__);

	return error;
}

/**
  * Clear and free all the resources associated to the driver.
  * This function is called when the driver need to be removed.
  */
#ifdef I2C_INTERFACE
static int fts_remove(struct i2c_client *client)
{
#else
static int fts_remove(struct spi_device *client)
{
#endif
	struct fts_ts_info *info = dev_get_drvdata(&(client->dev));

	fts_proc_remove();
	fts_interrupt_uninstall(info);
#if defined(CONFIG_DRM)
	if (active_panel && info->notifier_cookie)
		panel_event_notifier_unregister(info->notifier_cookie);
#endif
	input_unregister_device(info->input_dev);
	destroy_workqueue(info->event_wq);
#ifndef FW_UPDATE_ON_PROBE
	destroy_workqueue(info->fwu_workqueue);
#endif
	device_destroy(info->fts_tp_class, CHIP_ID);
	fts_enable_reg(info, false);
	fts_get_reg(info, false);
	fts_info = NULL;
	kfree(info);
	return OK;
}

static struct of_device_id fts_of_match_table[] = {
	{
		.compatible = "st,spi-pri",
	},
	{},
};

#ifdef I2C_INTERFACE
static const struct i2c_device_id fts_device_id[] = {
	{ FTS_TS_DRV_NAME, 0 },
	{}
};

static struct i2c_driver fts_i2c_driver = {
	.driver			= {
		.name		= FTS_TS_DRV_NAME,
		.of_match_table = fts_of_match_table,
	},
	.probe			= fts_probe,
	.remove			= fts_remove,
	.id_table		= fts_device_id,
};
#else
static struct spi_driver fts_spi_driver = {
	.driver			= {
		.name		= FTS_TS_DRV_NAME,
		.of_match_table = fts_of_match_table,
		.owner		= THIS_MODULE,
	},
	.probe			= fts_probe,
	.remove			= fts_remove,
};

#endif




static int __init fts_driver_init(void)
{
#ifdef I2C_INTERFACE
	return i2c_add_driver(&fts_i2c_driver);
#else
	return spi_register_driver(&fts_spi_driver);
#endif
}

static void __exit fts_driver_exit(void)
{
#ifdef I2C_INTERFACE
		i2c_del_driver(&fts_i2c_driver);
#else
		spi_unregister_driver(&fts_spi_driver);
#endif
}


MODULE_DESCRIPTION("STMicroelectronics MultiTouch IC Driver");
MODULE_AUTHOR("STMicroelectronics");
MODULE_LICENSE("GPL");

late_initcall(fts_driver_init);
module_exit(fts_driver_exit);
