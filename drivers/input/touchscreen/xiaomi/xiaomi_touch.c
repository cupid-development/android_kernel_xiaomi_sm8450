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
#include <linux/uaccess.h>

struct class *touch_class;
struct device *touch_dev;

static struct xiaomi_touch_interface *interfaces[TOUCH_ID_NUM];

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
	sensor = oneshot_sensor_map[sensor_type];
	atomic_set(&sensor->pending_event, value);
	sysfs_notify(&touch_dev->kobj, NULL, sensor->status_name);

	return 0;
}
EXPORT_SYMBOL_GPL(notify_oneshot_sensor);

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
	struct xiaomi_touch_interface *interface;
	struct oneshot_sensor_attribute *sensor_attribute =
		container_of(attr, struct oneshot_sensor_attribute, dev_attr);

	interface = interfaces[TOUCH_ID_PRIMARY];
	if (!interface || !interface->get_mode_value)
		return -EFAULT;

	return snprintf(
		buf, PAGE_SIZE, "%d\n",
		interface->get_mode_value(
			interface->private,
			oneshot_sensor_map[sensor_attribute->type]->mode));
}

static ssize_t oneshot_sensor_enabled_store(struct device *dev,
					    struct device_attribute *attr,
					    const char *arg, size_t count)
{
	struct xiaomi_touch_interface *interface;
	struct oneshot_sensor_attribute *sensor_attribute =
		container_of(attr, struct oneshot_sensor_attribute, dev_attr);
	unsigned int enable;

	interface = interfaces[TOUCH_ID_PRIMARY];
	if (!interface || !interface->get_mode_value ||
	    !interface->set_mode_value)
		return -EFAULT;

	if (kstrtouint(arg, 10, &enable))
		return -EINVAL;

	// only boolean input is allowed
	if (enable < 0 || enable > 1)
		return -EINVAL;

	if (interface->get_mode_value(
		    interface->private,
		    oneshot_sensor_map[sensor_attribute->type]->mode) !=
	    enable) {
		interface->set_mode_value(
			interface->private,
			oneshot_sensor_map[sensor_attribute->type]->mode,
			enable);
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

static struct attribute_group oneshot_sensor_attr_group = {
	// name defaults to NULL (device name will be used)
	.attrs = oneshot_sensor_attrs,
};

const struct attribute_group *touch_attr_groups[] = {
	&oneshot_sensor_attr_group,
	NULL,
};

static long xiaomi_touch_dev_ioctl(struct file *file, unsigned int cmd,
				   unsigned long arg)
{
	struct xiaomi_touch_interface *interface;
	struct touch_mode_request request;

	if (copy_from_user(&request, (int __user *)arg, sizeof(request)))
		return -EFAULT;

	pr_info("cmd: %d, mode: %d, value: %d\n", _IOC_NR(cmd), request.mode,
		request.value);

	interface = interfaces[TOUCH_ID_PRIMARY];
	if (!interface || !interface->get_mode_value ||
	    !interface->set_mode_value)
		return -EFAULT;

	switch (_IOC_NR(cmd)) {
	case TOUCH_MODE_SET:
		interface->set_mode_value(interface->private, request.mode,
					  request.value);
		break;
	case TOUCH_MODE_GET:
		request.value = interface->get_mode_value(interface->private,
							  request.mode);
		break;
	default:
		return -EINVAL;
	}

	return copy_to_user((int __user *)arg, &request, sizeof(request));
}

static const struct file_operations xiaomitouch_dev_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = xiaomi_touch_dev_ioctl,
};

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

	return ret;

device_create_err:
	class_destroy(touch_class);
class_create_err:
	misc_deregister(&misc_dev);
misc_register_err:
	return ret;
}

static void __exit xiaomi_touch_exit(void)
{
	device_unregister(touch_dev);
	class_destroy(touch_class);
	misc_deregister(&misc_dev);
}

module_init(xiaomi_touch_init);
module_exit(xiaomi_touch_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("The LineageOS Project");
MODULE_DESCRIPTION("User space interface for touch screen features");
