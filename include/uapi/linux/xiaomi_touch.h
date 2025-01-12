/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */

#ifndef __UAPI__XIAOMI__TOUCH_H
#define __UAPI__XIAOMI__TOUCH_H

#include <linux/ioctl.h>
#include <linux/types.h>

/**
 * enum touch_mode: - Defines various modes supported by the touchscreen driver.
 * @TOUCH_MODE_SINGLETAP_GESTURE: Enables or disables the single-tap gesture.
 * @TOUCH_MODE_DOUBLETAP_GESTURE: Enables or disables the double-tap gesture.
 * @TOUCH_MODE_FOD_PRESS_GESTURE: Enables or disabled the fingerprint-on-display press gesture.
 * @TOUCH_MODE_FOD_FINGER_STATE: Sysfs node that just reports what it gets told from userspace.
 * @TOUCH_MODE_NONUI_MODE: Disables or enables currently enabled gestures.
 * @TOUCH_MODE_REPORT_RATE: Configures the touchscreen sampling rate.
 * @TOUCH_MODE_FOLD_STATUS: Informs the xiaomi touch driver about current fold status.
 * @TOUCH_MODE_NUM: Represents the total number of supported modes.
 *
 * This enumeration is used to identify modes when configuring or querying
 * the touchscreen driver via IOCTL commands.
 */
enum touch_mode {
	TOUCH_MODE_SINGLETAP_GESTURE,
	TOUCH_MODE_DOUBLETAP_GESTURE,
	TOUCH_MODE_FOD_PRESS_GESTURE,
	TOUCH_MODE_FOD_FINGER_STATE,
	TOUCH_MODE_NONUI_MODE,
	TOUCH_MODE_REPORT_RATE,
	TOUCH_MODE_FOLD_STATUS,
	TOUCH_MODE_NUM,
};

/**
 * enum touch_mode_cmd: - Defines commands for interacting with touchscreen modes.
 * @TOUCH_MODE_SET: Sets the current value for the specified mode.
 * @TOUCH_MODE_GET: Retrieves the current value of the specified mode.
 *
 * These commands are used with the IOCTL interface to configure or query
 * touchscreen driver modes.
 */
enum touch_mode_cmd {
	TOUCH_MODE_SET,
	TOUCH_MODE_GET,
};

/**
 * struct touch_mode_request: - Represents a request to set or get a mode value.
 * @mode: The mode to configure or query (see enum touch_mode).
 * @value: The value to set or retrieve for the mode.
 *
 * This structure is passed between user space and kernel space through
 * IOCTL commands for touchscreen mode configuration.
 */
struct touch_mode_request {
	enum touch_mode mode;
	int value;
};

/**
 * enum touch_fold_status: - Represents the fold status.
 * @TOUCH_FOLD_STATUS_UNFOLDED: Fold status where the primary touchscreen is active.
 * @TOUCH_FOLD_STATUS_FOLDED: Fold status where the secondary touchscreen is active.
 *
 * These are the supported values for TOUCH_MODE_FOLD_STATUS requests.
 */
enum touch_fold_status {
	TOUCH_FOLD_STATUS_UNFOLDED,
	TOUCH_FOLD_STATUS_FOLDED,
	TOUCH_FOLD_STATUS_NUM,
};

/*
 * IOCTL definitions for touchscreen configuration.
 * Used by user space applications to communicate with the kernel driver.
 */

/**
 * TOUCH_IOC_SET_CUR_VALUE: - IOCTL command to set the value of a mode.
 * Expects a struct touch_mode_request containing the mode and value.
 */
#define TOUCH_IOC_SET_CUR_VALUE                                                \
	_IOW('T', TOUCH_MODE_SET, struct touch_mode_request)

/**
 * TOUCH_IOC_GET_CUR_VALUE: - IOCTL command to get the value of a mode.
 * Expects a struct touch_mode_request and fills its value field with the
 * current mode value.
 */
#define TOUCH_IOC_GET_CUR_VALUE                                                \
	_IOR('T', TOUCH_MODE_GET, struct touch_mode_request)

#endif /* __UAPI__XIAOMI__TOUCH_H */
