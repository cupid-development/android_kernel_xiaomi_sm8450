#ifndef __LINUX__XIAOMI__TOUCH_H
#define __LINUX__XIAOMI__TOUCH_H

#include <linux/types.h>
#include <asm/ioctl.h>

#define MAX_BUF_SIZE 256
#define MAX_TOUCH_ID 10
#define THP_CMD_BASE 1000

enum MODE_CMD {
	SET_CUR_VALUE = 0,
	GET_CUR_VALUE,
	GET_DEF_VALUE,
	GET_MIN_VALUE,
	GET_MAX_VALUE,
	GET_MODE_VALUE,
	RESET_MODE,
	SET_LONG_VALUE,
};

enum MODE_TYPE {
	Touch_Game_Mode = 0,
	Touch_Active_MODE = 1,
	Touch_UP_THRESHOLD = 2,
	Touch_Tolerance = 3,
	Touch_Aim_Sensitivity = 4,
	Touch_Tap_Stability = 5,
	Touch_Expert_Mode = 6,
	Touch_Edge_Filter = 7,
	Touch_Panel_Orientation = 8,
	Touch_Report_Rate = 9,
	Touch_Fod_Enable = 10,
	Touch_Aod_Enable = 11,
	Touch_Resist_RF = 12,
	Touch_Idle_Time = 13,
	Touch_Doubletap_Mode = 14,
	Touch_Grip_Mode = 15,
	Touch_FodIcon_Enable = 16,
	Touch_Nonui_Mode = 17,
	Touch_Debug_Level = 18,
	Touch_Power_Status = 19,
	Touch_Fod_Longpress_Gesture,
	Touch_Singletap_Gesture,
	Touch_Mode_NUM,
	THP_LOCK_SCAN_MODE = THP_CMD_BASE + 0,
	THP_FOD_DOWNUP_CTL = THP_CMD_BASE + 1,
	THP_SELF_CAP_SCAN = THP_CMD_BASE + 2,
	THP_REPORT_POINT_SWITCH = THP_CMD_BASE + 3,
	THP_HAL_INIT_READY = THP_CMD_BASE + 4,
	THP_HAL_VSYNC_MODE = THP_CMD_BASE + 9,
	THP_HAL_CHARGING_STATUS = THP_CMD_BASE + 10,
	THP_HAL_REPORT_RATE = THP_CMD_BASE + 11,
	THP_HAL_DISPLAY_FPS = THP_CMD_BASE + 12,
	THP_KNOCK_FRAME_COUNT = THP_CMD_BASE + 13,
	THP_HAL_TOUCH_SENSOR = THP_CMD_BASE + 15,
	THP_NORMALIZE_FREQ_SCAN = THP_CMD_BASE + 68,
	THP_NORMALIZE_K_REQUEST = THP_CMD_BASE + 69,
	THP_NORMALIZE_B_REQUEST = THP_CMD_BASE + 70,
	THP_IDLE_BASALINE_UPDATE = THP_CMD_BASE + 71,
};

#define TOUCH_MAGIC 'T'
#define TOUCH_IOC_SET_CUR_VALUE _IO(TOUCH_MAGIC, SET_CUR_VALUE)
#define TOUCH_IOC_GET_CUR_VALUE _IO(TOUCH_MAGIC, GET_CUR_VALUE)

#endif
