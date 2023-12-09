/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2014-2020, The Linux Foundation. All rights reserved.
 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM touch
#if !defined(_TRACE_H_) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_H_
#include <linux/stringify.h>
#include <linux/types.h>
#include <linux/tracepoint.h>
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE touch_trace
TRACE_EVENT(tracing_mark_write,
	    TP_PROTO(char trace_type, const struct task_struct *task,
		     int thp_cnt, int ic_frame_no),
	    TP_ARGS(trace_type, task, thp_cnt, ic_frame_no),
	    TP_STRUCT__entry(__field(char, trace_type) __field(int, pid)
				     __field(int, thp_cnt)
					     __field(int, ic_frame_no)),
	    TP_fast_assign(__entry->trace_type = trace_type;
			   __entry->pid = task ? task->tgid : 0;
			   __entry->thp_cnt = thp_cnt;
			   __entry->ic_frame_no = ic_frame_no;),
	    TP_printk("%c|%d|Read Thp Frame (frm_cnt:%llu, icframe_cnt:%d)",
		      __entry->trace_type, __entry->pid, __entry->thp_cnt,
		      __entry->ic_frame_no))
#define TOUCH_TRACE_FRAME_CNT_BEGIN(thp_cnt, ic_frame_no)                      \
	trace_tracing_mark_write('B', current, thp_cnt, ic_frame_no)
#define TOUCH_TRACE_FRAME_CNT_END() trace_tracing_mark_write('E', current, 0, 0)
#endif /* _TRACE_H_ */
#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH                                                     \
	../../../../ vendor / xiaomi / proprietary / touch / touchfeature_v2 / \
		touch_driver / m11 / goodix_9916r /
/* This part must be outside protection */
#include <trace/define_trace.h>