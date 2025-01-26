// SPDX-License-Identifier: GPL-2.0
/*
 * Xiaomi touch - a common interface to user space for touchscreen
 * related features, used to abstract different touchscreen drivers.
 *
 * Copyright (C) 2024 The LineageOS Project
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "xiaomi_touch.h"

#include <linux/fs.h>
#include <linux/device.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/soc/qcom/panel_event_notifier.h>
#include <linux/uaccess.h>
#include <linux/workqueue.h>

struct class *touch_class;
struct device *touch_dev;

static struct xiaomi_touch_interface *interfaces[TOUCH_ID_NUM];

static struct workqueue_struct *register_panel_wq;
static struct delayed_work register_panel_work;

struct oneshot_sensor_attribute {
	struct device_attribute dev_attr;
	enum oneshot_sensor_type type;
};

/**
 * struct oneshot_sensor: - Internal representation of a oneshot sensor.
 * @enabled_name: Sysfs node name for enabling/disabling the sensor.
 * @status_name: Sysfs node name for reporting the sensor's status.
 * @enabled_attr: Sysfs attributes for enabled node.
 * @status_attr: Sysfs attributes for status node.
 * @mode: Specifies the mode associated with this oneshot sensor, used to retrieve the
 *        corresponding value from the touch driver.
 * @pending_event: Stores the event value (> 0 if an event is pending, 0 if cleared).
 * @mutex: Synchronizes access to the sensor's state.
 *
 * A oneshot sensor is not a continuous-reading sensor.
 * Instead, it fires discrete events, such as a gesture occurrence.
 * The pending event value is cleared after the event is read
 * by user space.
 */
struct oneshot_sensor {
	char *enabled_name;
	char *status_name;
	struct oneshot_sensor_attribute enabled_attr;
	struct oneshot_sensor_attribute status_attr;
	enum touch_mode mode;
	atomic_t pending_event;
	struct mutex mutex;
};

/*
 * Maps a oneshot sensor to it's required attributes.
 * Used in generic methods to provide sensor specific options.
 */
static struct oneshot_sensor *oneshot_sensor_map[ONESHOT_SENSOR_TYPE_NUM];

/*
 * Stores the state of requested and actually configured gesture enabled
 * states. They diverge when we defer enabling/disabling gestures while
 * resumed. The actually enabled state is stored individually for primary
 * and secondary touch.
 */
static atomic_t oneshot_sensor_enabled_requested[ONESHOT_SENSOR_TYPE_NUM];
static atomic_t oneshot_sensor_enabled[TOUCH_ID_NUM][ONESHOT_SENSOR_TYPE_NUM];

static atomic_t suspended = ATOMIC_INIT(0);

static struct workqueue_struct *oneshot_sensor_enable_wq;
static struct delayed_work oneshot_sensor_enable_work;

/*
 * Stores the last fod state reported by userspace.
 * This can be used by userspace software to poll whether fod is
 * currently shown and ready.
 */
static atomic_t fod_finger_state = ATOMIC_INIT(0);

/*
 * Stores the active touch id, as reported by userspace via
 * TOUCH_MODE_FOLD_STATUS. Used to enable gestures on
 * only one panel on foldable devices.
 */
static enum touch_id active_touch_id = TOUCH_ID_PRIMARY;

/*
 * Controls whether gestures are reported up to userspace.
 * Userspace can set this using the TOUCH_MODE_NONUI_MODE
 * command to enable/disable this mode.
 */
static atomic_t pocket_disable_gestures = ATOMIC_INIT(0);

struct touch_mode_attribute {
	struct device_attribute dev_attr;
	enum touch_mode touch_mode;
};

int register_xiaomi_touch_client(enum touch_id touch_id,
				 struct xiaomi_touch_interface *interface)
{
	if (touch_id >= TOUCH_ID_NUM || interfaces[touch_id])
		return -EINVAL;
	interfaces[touch_id] = interface;

	return 0;
}
EXPORT_SYMBOL_GPL(register_xiaomi_touch_client);

int unregister_xiaomi_touch_client(enum touch_id touch_id)
{
	if (touch_id >= TOUCH_ID_NUM)
		return -EINVAL;
	interfaces[touch_id] = NULL;

	return 0;
}
EXPORT_SYMBOL_GPL(unregister_xiaomi_touch_client);

int notify_oneshot_sensor(enum oneshot_sensor_type sensor_type, int value)
{
	struct oneshot_sensor *sensor;

	if (sensor_type >= ONESHOT_SENSOR_TYPE_NUM ||
	    !oneshot_sensor_map[sensor_type]) {
		pr_err("tried to notify for invalid oneshot sensor %d\n",
		       sensor_type);
		return -EINVAL;
	}
	if (atomic_read(&pocket_disable_gestures)) {
		pr_info("gesture of type %d with value %d ignored due to pocket/nonui mode\n",
			sensor_type, value);
	} else {
		sensor = oneshot_sensor_map[sensor_type];
		atomic_set(&sensor->pending_event, value);
		sysfs_notify(&touch_dev->kobj, NULL, sensor->status_name);
	}

	return 0;
}
EXPORT_SYMBOL_GPL(notify_oneshot_sensor);

/**
 * oneshot_sensor_update_driver: - Enable/disable the touchscreen drivers gestures
 *                                 related to the the oneshot sensors.
 * @touch_id: The identifier of the touchscreen driver to update.
 * @enabled: Whether the gestures should be enabled or disabled.
 * @requested_state: Array of length ONESHOT_SENSOR_TYPE_NUM containing the
 *                   requested state for each oneshot sensor. Can be NULL if
 *                   @enabled is false.
 */
static void oneshot_sensor_update_driver(enum touch_id touch_id, bool enabled,
					 atomic_t requested_state[])
{
	int i;
	struct xiaomi_touch_interface *interface;

	interface = interfaces[touch_id];
	if (!interface || !interface->get_mode_value ||
	    !interface->set_mode_value)
		return;

	for (i = 0; i < ONESHOT_SENSOR_TYPE_NUM; i++) {
		int requested_value =
			enabled ? atomic_read(&requested_state[i]) : 0;
		if (atomic_xchg(&oneshot_sensor_enabled[touch_id][i], requested_value) !=
		    requested_value) {
			pr_info("setting mode %d to %d!\n", i, requested_value);
			interface->set_mode_value(interface->private,
						  oneshot_sensor_map[i]->mode,
						  requested_value);
		}
	}
}

static void oneshot_sensor_enable_handler(struct work_struct *work)
{
	if (atomic_read(&suspended))
		oneshot_sensor_update_driver(active_touch_id, true,
					     oneshot_sensor_enabled_requested);
}

static ssize_t oneshot_sensor_status_show(struct device *dev,
					  struct device_attribute *attr,
					  char *buf)
{
	struct oneshot_sensor_attribute *sensor_attribute =
		container_of(attr, struct oneshot_sensor_attribute, dev_attr);

	// reading the status resets it to 0
	return snprintf(
		buf, PAGE_SIZE, "%d\n",
		atomic_cmpxchg(&oneshot_sensor_map[sensor_attribute->type]
					->pending_event,
			       1, 0));
}

static ssize_t oneshot_sensor_enabled_show(struct device *dev,
					   struct device_attribute *attr,
					   char *buf)
{
	struct oneshot_sensor_attribute *sensor_attribute =
		container_of(attr, struct oneshot_sensor_attribute, dev_attr);

	return snprintf(
		buf, PAGE_SIZE, "%d\n",
		atomic_read(&oneshot_sensor_enabled_requested[sensor_attribute
								      ->type]));
}

static ssize_t oneshot_sensor_enabled_store(struct device *dev,
					    struct device_attribute *attr,
					    const char *arg, size_t count)
{
	struct oneshot_sensor_attribute *sensor_attribute =
		container_of(attr, struct oneshot_sensor_attribute, dev_attr);
	unsigned int enable;

	if (kstrtouint(arg, 10, &enable))
		return -EINVAL;

	// only boolean input is allowed
	if (enable < 0 || enable > 1)
		return -EINVAL;

	if (atomic_xchg(
		    &oneshot_sensor_enabled_requested[sensor_attribute->type],
		    enable) != enable) {
		cancel_delayed_work_sync(&oneshot_sensor_enable_work);
		queue_delayed_work(oneshot_sensor_enable_wq,
				   &oneshot_sensor_enable_work,
				   msecs_to_jiffies(300));
		sysfs_notify(&dev->kobj, NULL, attr->attr.name);
	}

	return count;
}

/**
 * ONESHOT_SENSOR: - Declares a oneshot sensor including related sysfs attributes.
 * @_varname: A struct oneshot_sensor with this name is declared.
 * @_enabled: enabled_name of struct oneshot_sensor.
 * @_status: status_name of struct oneshot_sensor.
 * @_type: enum oneshot_sensor_type used to find oneshot_sensors in sensors_map.
 * @_mode: enum touch_mode for communication with the touchscreen driver.
 */
#define ONESHOT_SENSOR(_varname, _enabled, _status, _type, _mode)              \
	struct oneshot_sensor _varname = {                                     \
		.enabled_name = #_enabled,                                     \
		.status_name = #_status,                                       \
		.enabled_attr = { __ATTR(_enabled, 0644,                       \
					 oneshot_sensor_enabled_show,          \
					 oneshot_sensor_enabled_store),        \
				  _type },                                     \
		.status_attr = { __ATTR(_status, 0444,                         \
					oneshot_sensor_status_show, NULL),     \
				 _type },                                      \
		.mode = _mode,                                                 \
		.pending_event = ATOMIC_INIT(0),                               \
		.mutex = __MUTEX_INITIALIZER(_varname.mutex),                  \
	}

/**
 * ONESHOT_SENSOR_ATTRS: - Generates sysfs attribute pointers for a oneshot sensor.
 * @_sensor: The name of the struct oneshot_sensor instance.
 */
#define ONESHOT_SENSOR_ATTRS(_sensor)                                          \
	&_sensor.enabled_attr.dev_attr.attr, &_sensor.status_attr.dev_attr.attr

static ONESHOT_SENSOR(single_tap_sensor, gesture_single_tap_enabled,
		      gesture_single_tap_state, ONESHOT_SENSOR_SINGLE_TAP,
		      TOUCH_MODE_SINGLETAP_GESTURE);
static ONESHOT_SENSOR(double_tap_sensor, gesture_double_tap_enabled,
		      gesture_double_tap_state, ONESHOT_SENSOR_DOUBLE_TAP,
		      TOUCH_MODE_DOUBLETAP_GESTURE);
static ONESHOT_SENSOR(fod_press_sensor, fod_longpress_gesture_enabled,
		      fod_press_status, ONESHOT_SENSOR_FOD_PRESS,
		      TOUCH_MODE_FOD_PRESS_GESTURE);

static struct attribute *oneshot_sensor_attrs[] = {
	ONESHOT_SENSOR_ATTRS(single_tap_sensor),
	ONESHOT_SENSOR_ATTRS(double_tap_sensor),
	ONESHOT_SENSOR_ATTRS(fod_press_sensor),
	NULL,
};

static const struct attribute_group oneshot_sensor_group = {
	// name defaults to NULL (device name will be used)
	.attrs = oneshot_sensor_attrs,
};

static int touch_mode_get(enum touch_mode mode)
{
	struct xiaomi_touch_interface *interface;

	// The following modes are not passed down to the touch driver
	switch (mode) {
	case TOUCH_MODE_FOD_FINGER_STATE:
		return atomic_read(&fod_finger_state);
	case TOUCH_MODE_NONUI_MODE:
		return atomic_read(&pocket_disable_gestures);
	case TOUCH_MODE_FOLD_STATUS:
		switch (active_touch_id) {
		case TOUCH_ID_PRIMARY:
			return TOUCH_FOLD_STATUS_UNFOLDED;
		case TOUCH_ID_SECONDARY:
			return TOUCH_FOLD_STATUS_FOLDED;
		default:
			return -EINVAL;
		}
	default:
		break;
	}

	interface = interfaces[active_touch_id];
	if (!interface || !interface->get_mode_value)
		return -EFAULT;

	return interface->get_mode_value(interface->private, mode);
}

static int touch_mode_set(enum touch_mode mode, int value)
{
	struct xiaomi_touch_interface *interface;
	enum touch_id requested_touch_id;

	// The following modes are not passed down to the touch driver
	switch (mode) {
	case TOUCH_MODE_FOD_FINGER_STATE:
		atomic_set(&fod_finger_state, value);
		sysfs_notify(&touch_dev->kobj, NULL, "fod_finger_state");
		return 0;
	case TOUCH_MODE_NONUI_MODE:
		atomic_set(&pocket_disable_gestures, value);
		return 0;
	case TOUCH_MODE_FOLD_STATUS:
		switch (value) {
		case TOUCH_FOLD_STATUS_UNFOLDED:
			requested_touch_id = TOUCH_ID_PRIMARY;
			return 0;
		case TOUCH_FOLD_STATUS_FOLDED:
			requested_touch_id = TOUCH_ID_SECONDARY;
			return 0;
		default:
			return -EINVAL;
		}

		if (active_touch_id != requested_touch_id) {
			oneshot_sensor_update_driver(
				requested_touch_id, true,
				oneshot_sensor_enabled[active_touch_id]);
			oneshot_sensor_update_driver(active_touch_id, false,
						     NULL);
			active_touch_id = requested_touch_id;
		}
		return 0;
	default:
		break;
	}

	interface = interfaces[active_touch_id];
	if (!interface || !interface->set_mode_value)
		return -EFAULT;

	interface->set_mode_value(interface->private, mode, value);

	return 0;
}

static ssize_t touch_mode_show(struct device *dev,
			       struct device_attribute *attr, char *buf)
{
	struct touch_mode_attribute *mode_attribute =
		container_of(attr, struct touch_mode_attribute, dev_attr);
	int value;

	value = touch_mode_get(mode_attribute->touch_mode);
	if (value < 0)
		return value;

	return snprintf(buf, PAGE_SIZE, "%d\n", value);
}

static ssize_t touch_mode_store(struct device *dev,
				struct device_attribute *attr, const char *arg,
				size_t count)
{
	struct touch_mode_attribute *mode_attribute =
		container_of(attr, struct touch_mode_attribute, dev_attr);
	unsigned int value;
	int set_success;

	if (kstrtouint(arg, 10, &value))
		return -EINVAL;

	set_success = touch_mode_set(mode_attribute->touch_mode, value);
	if (set_success < 0)
		return set_success;

	return count;
}

/**
 * TOUCH_MODE_ATTR_RW - Define a read-write touch mode attribute.
 * @_name: Attribute name.
 * @_mode: Value of enum touch_mode corresponding to this attribute.
 *
 * Convenience macro for defining a struct touch_mode_attribute
 */
#define TOUCH_MODE_ATTR_RW(_name, _mode)                                       \
	struct touch_mode_attribute touch_mode_attr_##_name = {                \
		.dev_attr = __ATTR(_name, 0644, touch_mode_show,               \
				   touch_mode_store),                          \
		.touch_mode = _mode,                                           \
	}

TOUCH_MODE_ATTR_RW(bump_sample_rate, TOUCH_MODE_REPORT_RATE);
TOUCH_MODE_ATTR_RW(fod_finger_state, TOUCH_MODE_FOD_FINGER_STATE);

static struct attribute *touch_mode_attrs[] = {
	&touch_mode_attr_bump_sample_rate.dev_attr.attr,
	&touch_mode_attr_fod_finger_state.dev_attr.attr,
	NULL,
};

static const struct attribute_group touch_mode_group = {
	// name defaults to NULL (device name will be used)
	.attrs = touch_mode_attrs,
};

const struct attribute_group *touch_attr_groups[] = {
	&oneshot_sensor_group,
	&touch_mode_group,
	NULL,
};

static long xiaomi_touch_dev_ioctl(struct file *file, unsigned int cmd,
				   unsigned long arg)
{
	struct touch_mode_request request;
	int retval = 0;

	if (copy_from_user(&request, (int __user *)arg, sizeof(request)))
		return -EFAULT;

	pr_info("cmd: %d, mode: %d, value: %d\n", _IOC_NR(cmd), request.mode,
		request.value);

	switch (_IOC_NR(cmd)) {
	case TOUCH_MODE_SET:
		retval = touch_mode_set(request.mode, request.value);
		break;
	case TOUCH_MODE_GET:
		request.value = touch_mode_get(request.mode);
		if (request.value < 0)
			retval = -EINVAL;
		else
			retval = copy_to_user((int __user *)arg, &request,
					      sizeof(request));
		break;
	default:
		retval = -EINVAL;
	}

	return retval;
}

static const struct file_operations xiaomitouch_dev_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = xiaomi_touch_dev_ioctl,
};

static void
touch_panel_event_callback(enum panel_event_notifier_tag tag,
			   struct panel_event_notification *notification,
			   void *client_data)
{
	if (!notification)
		return;

	switch (notification->notif_type) {
	case DRM_PANEL_EVENT_BLANK:
	case DRM_PANEL_EVENT_BLANK_LP:
		/*
		 * Apply the settings which were done while the display was
		 * resumed. Delay it to avoid unnecessary touchscreen
		 * notifications when the changes are being reverted when
		 * the screen turns off.
		 */
		if (!notification->notif_data.early_trigger) {
			atomic_set(&suspended, 1);
			queue_delayed_work(oneshot_sensor_enable_wq,
					   &oneshot_sensor_enable_work,
					   msecs_to_jiffies(300));
		}
		break;
	case DRM_PANEL_EVENT_UNBLANK:
		/*
		 * Store the suspended state and cancel the delayed work to
		 * avoid unnecessary touchscreen notifications. If the mode is
		 * actually changed, the touchscreen will be notified on the
		 * next suspend.
		 */
		if (notification->notif_data.early_trigger) {
			atomic_set(&suspended, 0);
			cancel_delayed_work_sync(&oneshot_sensor_enable_work);
		}
		break;
	default:
		break;
	}
}

static bool touch_register_panel_event_notifier(
	struct device_node *np, const char *property_name,
	enum panel_event_notifier_tag tag,
	enum panel_event_notifier_client client, void **cookie)
{
	int count, i;
	struct device_node *node;
	struct drm_panel *panel;

	if (*cookie)
		return true;
	count = of_count_phandle_with_args(np, property_name, NULL);
	if (count <= 0)
		return true;
	for (i = 0; i < count; i++) {
		node = of_parse_phandle(np, property_name, i);
		panel = of_drm_find_panel(node);
		of_node_put(node);
		if (!IS_ERR(panel))
			break;
	}
	if (IS_ERR(panel))
		return false;

	*cookie = panel_event_notifier_register(
		tag, client, panel, touch_panel_event_callback, NULL);

	return !IS_ERR(*cookie);
}

static void *panel_cookie_primary, *panel_cookie_secondary;

static void register_panel_handler(struct work_struct *work)
{
	struct device_node *node;
	bool primary, secondary;

	node = of_find_node_by_name(NULL, "xiaomi-touch");
	primary = touch_register_panel_event_notifier(
		node, "panel-primary", PANEL_EVENT_NOTIFICATION_PRIMARY,
		PANEL_EVENT_NOTIFIER_CLIENT_XIAOMI_TOUCH_PRIMARY,
		&panel_cookie_primary);
	secondary = touch_register_panel_event_notifier(
		node, "panel-secondary", PANEL_EVENT_NOTIFICATION_SECONDARY,
		PANEL_EVENT_NOTIFIER_CLIENT_XIAOMI_TOUCH_SECONDARY,
		&panel_cookie_secondary);
	if (!primary || !secondary) {
		pr_info("Failed to register panel event notifier, trying again in 5 seconds!\n");
		queue_delayed_work(register_panel_wq, &register_panel_work,
				   5 * HZ);
	}
}

static struct miscdevice misc_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "xiaomi-touch",
	.fops = &xiaomitouch_dev_fops,
};

static int __init xiaomi_touch_init(void)
{
	int ret = 0;

	oneshot_sensor_map[ONESHOT_SENSOR_SINGLE_TAP] = &single_tap_sensor;
	oneshot_sensor_map[ONESHOT_SENSOR_DOUBLE_TAP] = &double_tap_sensor;
	oneshot_sensor_map[ONESHOT_SENSOR_FOD_PRESS] = &fod_press_sensor;

	oneshot_sensor_enable_wq =
		create_singlethread_workqueue("oneshot_sensor_enable_wq");
	if (IS_ERR(oneshot_sensor_enable_wq)) {
		pr_err("failed to create workqueue for oneshot sensor enabling\n");
		goto create_oneshot_workqueue_err;
	}
	INIT_DELAYED_WORK(&oneshot_sensor_enable_work,
			  oneshot_sensor_enable_handler);

	ret = misc_register(&misc_dev);
	if (ret) {
		pr_err("failed to register misc device, err :%d\n", ret);
		goto misc_register_err;
	}

	touch_class = class_create(THIS_MODULE, "touch");
	if (IS_ERR(touch_class)) {
		pr_err("failed to create class\n");
		goto class_create_err;
	}

	touch_dev =
		device_create_with_groups(touch_class, NULL, MKDEV(0, 0), NULL,
					  touch_attr_groups, "touch_dev");
	if (IS_ERR(touch_dev)) {
		pr_err("failed to create device with sysfs group\n");
		goto device_create_err;
	}

	register_panel_wq =
		create_singlethread_workqueue("touch_register_panel_wq");
	if (IS_ERR(register_panel_wq)) {
		pr_err("failed to create workqueue for panel work\n");
		goto create_workqueue_err;
	}
	INIT_DELAYED_WORK(&register_panel_work, register_panel_handler);
	queue_delayed_work(register_panel_wq, &register_panel_work, 0);

	return ret;

create_workqueue_err:
	device_unregister(touch_dev);
device_create_err:
	class_destroy(touch_class);
class_create_err:
	misc_deregister(&misc_dev);
misc_register_err:
	destroy_workqueue(oneshot_sensor_enable_wq);
create_oneshot_workqueue_err:
	return ret;
}

static void __exit xiaomi_touch_exit(void)
{
	cancel_delayed_work_sync(&register_panel_work);
	destroy_workqueue(register_panel_wq);
	if (!IS_ERR(panel_cookie_primary))
		panel_event_notifier_unregister(panel_cookie_primary);
	if (!IS_ERR(panel_cookie_secondary))
		panel_event_notifier_unregister(panel_cookie_secondary);
	device_unregister(touch_dev);
	class_destroy(touch_class);
	misc_deregister(&misc_dev);
	cancel_delayed_work_sync(&oneshot_sensor_enable_work);
	destroy_workqueue(oneshot_sensor_enable_wq);
}

module_init(xiaomi_touch_init);
module_exit(xiaomi_touch_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("The LineageOS Project");
MODULE_DESCRIPTION("User space interface for touch screen features");
