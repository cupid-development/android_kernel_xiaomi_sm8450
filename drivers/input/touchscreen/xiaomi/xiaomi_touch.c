#include "xiaomi_touch.h"

static struct xiaomi_touch_pdata *touch_pdata;
static struct xiaomi_touch *xiaomi_touch_device;
static knock_data_t knock_data;
static struct file_operations xiaomi_knock_fops = {
	.owner = THIS_MODULE,
	.read = knock_data_read,
	.write = knock_data_write,
	.poll = knock_data_poll,
	.unlocked_ioctl = knock_data_ioctl,
	.mmap = knock_data_mmap,
};

#define RAW_SIZE (PAGE_SIZE * 12)

int knock_node_init(void)
{
	int rc;

	pr_info("%s\n", __func__);
	init_waitqueue_head(&knock_data.wait_data_complete_queue_head);
	if (knock_data.vaddr == NULL) {
		knock_data.vaddr = kzalloc(0x1000, (gfp_t)0xdc0);
		if (knock_data.vaddr != 0) {
			knock_data.paddr =
				(void *)virt_to_phys(knock_data.vaddr);
			pr_info("%s: raw data addr: %lld, phy addr: %lld\n",
				__func__, knock_data.vaddr, knock_data.paddr);
		} else {
			pr_err("%s: alloc memory for mmap failed\n", __func__);
			return -1;
		}
	}

	knock_data.device.minor = 0xff;
	knock_data.device.name = "xiaomi-touch-knock";
	knock_data.device.fops = &xiaomi_knock_fops;
	knock_data.device.parent = NULL;

	rc = misc_register(&knock_data.device);
	if (rc == 0) {
		pr_info("%s: complete!\n", __func__);
		return 0;
	}

	pr_err("%s: register %s node failed\n", __func__, "xiaomi-touch-knock");
	if (knock_data.vaddr != NULL) {
		kfree(knock_data.vaddr);
		knock_data.vaddr = NULL;
	}
	pr_err("%s: failed\n", __func__);
	return rc;
}

void knock_node_release(void)
{
	if (knock_data.vaddr != NULL) {
		kfree(knock_data.vaddr);
		knock_data.vaddr = NULL;
	}
	misc_deregister(&knock_data.device);
	return;
}

void knock_data_notify(void)
{
	wake_up_interruptible(&knock_data.wait_data_complete_queue_head);
	return;
}

long knock_data_ioctl(struct file *intf, unsigned int code, unsigned long buf)
{
	if (code != 0) {
		return 0;
	}
	knock_data.is_data_ready = true;
	wake_up_interruptible(&knock_data.wait_data_complete_queue_head);
	return 0;
}

int knock_data_mmap(struct file *file, struct vm_area_struct *vma)
{
	long size;
	ulong pfn;

	if (knock_data.vaddr == NULL) {
		pr_err("%s: invalid memory\n", __func__);
		return -ENOMEM;
	}

	size = vma->vm_end - vma->vm_start;
	pfn = (ulong)((long)knock_data.paddr + vma->vm_pgoff * 0x1000) >> 0xc;
	if (0 == remap_pfn_range(vma, vma->vm_start, pfn, size,
				 __pgprot(0x68000000000fc3))) {
		pr_info("%s: remap_pfn_range %u, size:%ld, success\n", __func__,
			(unsigned int)pfn, size);
	} else {
		return -EAGAIN;
	}
	return 0;
}

void update_knock_data(u8 *buf, int size, int frame_id)
{
	memcpy(knock_data.vaddr, buf, (long)size);
	knock_data.is_data_ready = true;
	knock_data.size = size;
	pr_info("%s: frame id %d, size is %d\n", __func__, frame_id, size);
	return;
}

__poll_t knock_data_poll(struct file *file, poll_table *wait)
{
	poll_wait(file, &knock_data.wait_data_complete_queue_head, wait);
	if (knock_data.is_data_ready) {
		knock_data.is_data_ready = false;
		return EPOLLRDNORM | EPOLLIN;
	}
	return 0;
}

ssize_t knock_data_read(struct file *dev, char __user *buf, size_t count,
			loff_t *pos)
{
	char local_buf[5] = { 0 };
	unsigned long not_copied = 0;
	if (*pos == 0) {
		int size =
			snprintf(local_buf, 5, "%d\n", knock_data.frame_count);
		if (size < 0) {
			return size;
		}
		not_copied = copy_to_user(buf, local_buf, size);
		if (not_copied == 0) {
			*pos = *pos + 1;
		} else {
			return -EFAULT;
		}
	}
	return 0;
}

extern ssize_t knock_data_write(struct file *dev, const char __user *buf,
				size_t count, loff_t *pos)
{
	uint frame_cnt;
	char local_buf[6] = { 0 };
	size_t capped_cnt = count >= 5 ? 5 : count;
	if (0 == copy_from_user(local_buf, buf, capped_cnt)) {
		local_buf[capped_cnt] = '\0';
		if (sscanf(local_buf, "%d", &frame_cnt) < 0) {
			pr_err("%s:  scanf knock frame count failed!\n",
			       __func__);
			frame_cnt = 0;
		}
	} else {
		pr_err("%s: copy_from_user failed!\n", __func__);
		frame_cnt = 0;
	}
	pr_info("%s: set knock frame count %d!\n", __func__, frame_cnt);
	if (knock_data.callback != NULL) {
		// cfi slow path: update_touch_irq_no.cfi_jt
		knock_data.callback(frame_cnt);
	}
	thp_send_cmd_to_hal(0x3f5, knock_data.frame_count);
	return count;
}

static int xiaomi_touch_dev_open(struct inode *inode, struct file *file)
{
	struct xiaomi_touch *dev = NULL;
	int i = MINOR(inode->i_rdev);
	struct xiaomi_touch_pdata *touch_pdata;

	pr_info("%s\n", __func__);
	dev = xiaomi_touch_dev_get(i);
	if (!dev) {
		pr_err("%s cant get dev\n", __func__);
		return -ENOMEM;
	}
	touch_pdata = dev_get_drvdata(dev->dev);

	file->private_data = touch_pdata;
	return 0;
}

static ssize_t xiaomi_touch_dev_read(struct file *file, char __user *buf,
				     size_t count, loff_t *pos)
{
	return 0;
}

static ssize_t xiaomi_touch_dev_write(struct file *file, const char __user *buf,
				      size_t count, loff_t *pos)
{
	return 0;
}

static unsigned int xiaomi_touch_dev_poll(struct file *file, poll_table *wait)
{
	return 0;
}

static long xiaomi_touch_dev_ioctl(struct file *file, unsigned int cmd,
				   unsigned long arg)
{
	int ret = -EINVAL;
	int buf[MAX_BUF_SIZE] = {
		0,
	};
	struct xiaomi_touch_pdata *pdata = file->private_data;
	void __user *argp = (void __user *)arg;
	struct xiaomi_touch_interface *touch_data = NULL;
	struct xiaomi_touch *dev = pdata->device;
	int user_cmd = _IOC_NR(cmd);

	mutex_lock(&dev->mutex);
	ret = copy_from_user(&buf, (int __user *)argp, sizeof(buf));
	if (buf[0] < 0 || buf[0] > 1) {
		pr_err("%s invalid param\n", __func__);
		mutex_unlock(&dev->mutex);
		return -EINVAL;
	}

	touch_data = pdata->touch_data[buf[0]];
	if (!pdata || !touch_data || !dev) {
		pr_err("%s invalid memory\n", __func__);
		mutex_unlock(&dev->mutex);
		return -ENOMEM;
	}

	pr_info("%s cmd:%d, touchId:%d, mode:%d, value:%d\n", __func__,
		user_cmd, buf[0], buf[1], buf[2]);

	switch (user_cmd) {
	case SET_CUR_VALUE:
		if (touch_data->setModeValue)
			buf[0] = touch_data->setModeValue(buf[1], buf[2]);
		break;
	case GET_CUR_VALUE:
	case GET_DEF_VALUE:
	case GET_MIN_VALUE:
	case GET_MAX_VALUE:
		if (touch_data->getModeValue)
			buf[0] = touch_data->getModeValue(buf[1], user_cmd);
		break;
	case RESET_MODE:
		if (touch_data->resetMode)
			buf[0] = touch_data->resetMode(buf[1]);
		break;
	case GET_MODE_VALUE:
		if (touch_data->getModeValue)
			ret = touch_data->getModeAll(buf[1], buf);
		break;
	case SET_LONG_VALUE:
		if (touch_data->setModeLongValue && buf[2] <= MAX_BUF_SIZE)
			ret = touch_data->setModeLongValue(buf[1], buf[2],
							   &buf[3]);
		break;
	default:
		pr_err("%s don't support mode\n", __func__);
		ret = -EINVAL;
		break;
	}

	if (buf[1] >= THP_CMD_BASE) {
		goto exit;
	}

	if (user_cmd == SET_CUR_VALUE) {
		touch_data->thp_cmd_buf[0] = user_cmd;
		touch_data->thp_cmd_buf[1] = buf[0];
		touch_data->thp_cmd_buf[2] = buf[1];
		touch_data->thp_cmd_buf[3] = buf[2];
		touch_data->thp_cmd_size = 4;
	} else if (user_cmd == SET_LONG_VALUE) {
		touch_data->thp_cmd_buf[0] = user_cmd;
		touch_data->thp_cmd_buf[1] = buf[0];
		touch_data->thp_cmd_buf[2] = buf[1];
		touch_data->thp_cmd_buf[3] = buf[2];
		memcpy(&(touch_data->thp_cmd_buf[4]), &buf[3],
		       sizeof(int) * buf[2]);
		touch_data->thp_cmd_size = 4 + buf[2];
	} else if (user_cmd == RESET_MODE) {
		touch_data->thp_cmd_buf[0] = user_cmd;
		touch_data->thp_cmd_buf[1] = buf[0];
		touch_data->thp_cmd_buf[2] = buf[1];
		touch_data->thp_cmd_size = 3;
	} else {
		goto exit;
	}

	touch_data->touch_event_status = 1;
	touch_data->touch_event_ready_status = 1;
	touch_data->thp_cmd_ready_size = touch_data->thp_cmd_size;

	memcpy(touch_data->thp_cmd_ready_buf, touch_data->thp_cmd_buf,
	       touch_data->thp_cmd_size * sizeof(int));
	sysfs_notify(&xiaomi_touch_device->dev->kobj, NULL,
		     "touch_thp_cmd_ready");
	if ((touch_pdata->param_head == touch_pdata->param_tail) &&
	    (touch_pdata->param_flag == 1)) {
		pr_err("[MITouch-ERR][%s:%d] %s param buffer is full!\n\n",
		       __func__, __LINE__, __func__);
		mutex_unlock(&dev->mutex);
		return -ENFILE;
	}
	spin_lock(&touch_pdata->param_lock);
	BUG_ON(touch_pdata->param_tail >= PARAM_BUF_NUM);
	touch_pdata->touch_cmd_data[touch_pdata->param_tail]->thp_cmd_size =
		touch_data->thp_cmd_size;
	memcpy(touch_pdata->touch_cmd_data[touch_pdata->param_tail]->param_buf,
	       touch_data->thp_cmd_buf, touch_data->thp_cmd_size * sizeof(int));
	if (touch_pdata->param_tail == PARAM_BUF_NUM - 1)
		touch_pdata->param_tail = 0;
	else
		touch_pdata->param_tail++;
	if (touch_pdata->param_tail == touch_pdata->param_head)
		touch_pdata->param_flag = 1;
	spin_unlock(&touch_pdata->param_lock);
	sysfs_notify(&xiaomi_touch_device->dev->kobj, NULL, "touch_thp_cmd");
exit:
	if (ret >= 0)
		ret = copy_to_user((int __user *)argp, &buf, sizeof(buf));
	else
		pr_err("%s can't get data from touch driver\n", __func__);

	mutex_unlock(&dev->mutex);

	return ret;
}

static int xiaomi_touch_dev_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct xiaomi_touch_pdata *pdata = file->private_data;
	unsigned long start = vma->vm_start;
	unsigned long size = vma->vm_end - vma->vm_start;
	unsigned long offset = vma->vm_pgoff << PAGE_SHIFT;
	unsigned long page;
	unsigned long pos;

	if (!pdata) {
		pr_err("%s invalid memory\n", __func__);
		return -ENOMEM;
	}

	/*
	tx_num = pdata->touch_data->get_touch_tx_num();
	rx_num = pdata->touch_data->get_touch_rx_num();
	*/

	pos = (unsigned long)pdata->phy_base + offset;
	page = pos >> PAGE_SHIFT;

	if (remap_pfn_range(vma, start, page, size, PAGE_SHARED)) {
		return -EAGAIN;
	} else {
		pr_info("%s remap_pfn_range %u, size:%ld, success\n", __func__,
			(unsigned int)page, size);
	}
	return 0;
}

static int xiaomi_touch_dev_release(struct inode *inode, struct file *file)
{
	return 0;
}

static const struct file_operations xiaomitouch_dev_fops = {
	.owner = THIS_MODULE,
	.open = xiaomi_touch_dev_open,
	.read = xiaomi_touch_dev_read,
	.write = xiaomi_touch_dev_write,
	.poll = xiaomi_touch_dev_poll,
	.mmap = xiaomi_touch_dev_mmap,
	.unlocked_ioctl = xiaomi_touch_dev_ioctl,
	.compat_ioctl = xiaomi_touch_dev_ioctl,
	.release = xiaomi_touch_dev_release,
	.llseek = no_llseek,
};

static struct xiaomi_touch xiaomi_touch_dev = {
	.misc_dev = {
		.minor = MISC_DYNAMIC_MINOR,
		.name = "xiaomi-touch",
		.fops = &xiaomitouch_dev_fops,
		.parent = NULL,
	},
	.mutex = __MUTEX_INITIALIZER(xiaomi_touch_dev.mutex),
	.palm_mutex = __MUTEX_INITIALIZER(xiaomi_touch_dev.palm_mutex),
	.prox_mutex = __MUTEX_INITIALIZER(xiaomi_touch_dev.prox_mutex),
	.wait_queue = __WAIT_QUEUE_HEAD_INITIALIZER(xiaomi_touch_dev.wait_queue),
	.fod_press_status_mutex = __MUTEX_INITIALIZER(xiaomi_touch_dev.fod_press_status_mutex),
	.gesture_single_tap_mutex = __MUTEX_INITIALIZER(xiaomi_touch_dev.gesture_single_tap_mutex),
	.abnormal_event_mutex = __MUTEX_INITIALIZER(xiaomi_touch_dev.abnormal_event_mutex),
};

struct xiaomi_touch *xiaomi_touch_dev_get(int minor)
{
	if (xiaomi_touch_dev.misc_dev.minor == minor)
		return &xiaomi_touch_dev;
	else
		return NULL;
}

struct class *get_xiaomi_touch_class(void)
{
	return xiaomi_touch_dev.class;
}
EXPORT_SYMBOL_GPL(get_xiaomi_touch_class);

struct device *get_xiaomi_touch_dev(void)
{
	return xiaomi_touch_dev.dev;
}
EXPORT_SYMBOL_GPL(get_xiaomi_touch_dev);

int xiaomitouch_register_modedata(int touchId,
				  struct xiaomi_touch_interface *data)
{
	int ret = 0;
	struct xiaomi_touch_interface *touch_data = NULL;

	if (!touch_pdata)
		ret = -ENOMEM;

	BUG_ON(touchId > 2);

	touch_data = touch_pdata->touch_data[touchId];
	pr_info("%s\n", __func__);

	mutex_lock(&xiaomi_touch_dev.mutex);

	if (data->setModeValue)
		touch_data->setModeValue = data->setModeValue;
	if (data->getModeValue)
		touch_data->getModeValue = data->getModeValue;
	if (data->resetMode)
		touch_data->resetMode = data->resetMode;
	if (data->getModeAll)
		touch_data->getModeAll = data->getModeAll;
	if (data->palm_sensor_read)
		touch_data->palm_sensor_read = data->palm_sensor_read;
	if (data->palm_sensor_write)
		touch_data->palm_sensor_write = data->palm_sensor_write;
	if (data->prox_sensor_read)
		touch_data->prox_sensor_read = data->prox_sensor_read;
	if (data->prox_sensor_write)
		touch_data->prox_sensor_write = data->prox_sensor_write;
	if (data->panel_vendor_read)
		touch_data->panel_vendor_read = data->panel_vendor_read;
	if (data->panel_color_read)
		touch_data->panel_color_read = data->panel_color_read;
	if (data->panel_display_read)
		touch_data->panel_display_read = data->panel_display_read;
	if (data->touch_vendor_read)
		touch_data->touch_vendor_read = data->touch_vendor_read;
	if (data->setModeLongValue)
		touch_data->setModeLongValue = data->setModeLongValue;
	if (data->get_touch_rx_num)
		touch_data->get_touch_rx_num = data->get_touch_rx_num;
	if (data->get_touch_tx_num)
		touch_data->get_touch_tx_num = data->get_touch_tx_num;
	if (data->get_touch_x_resolution)
		touch_data->get_touch_x_resolution =
			data->get_touch_x_resolution;
	if (data->get_touch_y_resolution)
		touch_data->get_touch_y_resolution =
			data->get_touch_y_resolution;
	if (data->enable_touch_raw)
		touch_data->enable_touch_raw = data->enable_touch_raw;
	if (data->enable_touch_delta)
		touch_data->enable_touch_delta = data->enable_touch_delta;
	if (data->enable_clicktouch_raw)
		touch_data->enable_clicktouch_raw = data->enable_clicktouch_raw;
	if (data->set_touch_reg_status)
		touch_data->set_touch_reg_status = data->set_touch_reg_status;
	if (data->get_touch_ic_buffer)
		touch_data->get_touch_ic_buffer = data->get_touch_ic_buffer;
	if (data->get_touch_super_resolution_factor)
		touch_data->get_touch_super_resolution_factor =
			data->get_touch_super_resolution_factor;

	mutex_unlock(&xiaomi_touch_dev.mutex);

	return ret;
}
EXPORT_SYMBOL_GPL(xiaomitouch_register_modedata);

int update_palm_sensor_value(int value)
{
	struct xiaomi_touch *dev = NULL;

	mutex_lock(&xiaomi_touch_dev.palm_mutex);

	if (!touch_pdata) {
		mutex_unlock(&xiaomi_touch_dev.palm_mutex);
		return -ENODEV;
	}

	dev = touch_pdata->device;

	if (value != touch_pdata->palm_value) {
		pr_info("%s value:%d\n", __func__, value);
		touch_pdata->palm_value = value;
		touch_pdata->palm_changed = true;
		sysfs_notify(&xiaomi_touch_dev.dev->kobj, NULL, "palm_sensor");
	}

	mutex_unlock(&xiaomi_touch_dev.palm_mutex);
	return 0;
}
EXPORT_SYMBOL_GPL(update_palm_sensor_value);

static ssize_t palm_sensor_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct xiaomi_touch_pdata *pdata = dev_get_drvdata(dev);

	pdata->palm_changed = false;

	return snprintf(buf, PAGE_SIZE, "%d\n", pdata->palm_value);
}

static ssize_t palm_sensor_store(struct device *dev,
				 struct device_attribute *attr, const char *buf,
				 size_t count)
{
	unsigned int input;
	struct xiaomi_touch_pdata *pdata = dev_get_drvdata(dev);

	if (sscanf(buf, "%d", &input) < 0)
		return -EINVAL;

	pdata->touch_data[0]->palm_sensor_onoff = input;
	if (pdata->touch_data[0]->palm_sensor_write)
		pdata->touch_data[0]->palm_sensor_write(!!input);
	else {
		pr_err("%s has not implement\n", __func__);
	}
	pr_info("%s value:%d\n", __func__, !!input);
	sysfs_notify(&xiaomi_touch_dev.dev->kobj, NULL, "palm_sensor_data");

	return count;
}

static ssize_t palm_sensor_data_show(struct device *dev,
				     struct device_attribute *attr, char *buf)
{
	struct xiaomi_touch_pdata *pdata = dev_get_drvdata(dev);

	pdata->palm_changed = false;

	return snprintf(buf, PAGE_SIZE, "%d\n",
			pdata->touch_data[0]->palm_sensor_onoff);
}

static ssize_t palm_sensor_data_store(struct device *dev,
				      struct device_attribute *attr,
				      const char *buf, size_t count)
{
	unsigned int input;
	struct xiaomi_touch_pdata *pdata = dev_get_drvdata(dev);

	mutex_lock(&xiaomi_touch_dev.palm_mutex);

	if (sscanf(buf, "%d", &input) < 0)
		return -EINVAL;

	if (input != pdata->palm_value) {
		pr_info("%s value:%d\n", __func__, input);
		pdata->palm_changed = true;
		pdata->palm_value = input;
		sysfs_notify(&xiaomi_touch_dev.dev->kobj, NULL, "palm_sensor");
	}

	mutex_unlock(&xiaomi_touch_dev.palm_mutex);

	return count;
}

int update_prox_sensor_value(int value)
{
	struct xiaomi_touch *dev = NULL;

	mutex_lock(&xiaomi_touch_dev.prox_mutex);

	if (!touch_pdata) {
		mutex_unlock(&xiaomi_touch_dev.prox_mutex);
		return -ENODEV;
	}

	dev = touch_pdata->device;

	if (value != touch_pdata->prox_value) {
		pr_info("%s value:%d\n", __func__, value);
		touch_pdata->prox_value = value;
		touch_pdata->prox_changed = true;
		sysfs_notify(&xiaomi_touch_dev.dev->kobj, NULL, "prox_sensor");
	}

	mutex_unlock(&xiaomi_touch_dev.prox_mutex);
	return 0;
}
EXPORT_SYMBOL_GPL(update_prox_sensor_value);

static ssize_t prox_sensor_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct xiaomi_touch_pdata *pdata = dev_get_drvdata(dev);

	pdata->prox_changed = false;

	return snprintf(buf, PAGE_SIZE, "%d\n", pdata->prox_changed);
}

static ssize_t prox_sensor_store(struct device *dev,
				 struct device_attribute *attr, const char *buf,
				 size_t count)
{
	unsigned int input;
	struct xiaomi_touch_pdata *pdata = dev_get_drvdata(dev);

	if (sscanf(buf, "%d", &input) < 0)
		return -EINVAL;

	if (pdata->touch_data[0]->prox_sensor_write)
		pdata->touch_data[0]->prox_sensor_write(!!input);
	else {
		pr_err("%s has not implement\n", __func__);
	}
	pr_info("%s value:%d\n", __func__, !!input);

	return count;
}

static ssize_t panel_vendor_show(struct device *dev,
				 struct device_attribute *attr, char *buf)
{
	struct xiaomi_touch_pdata *pdata = dev_get_drvdata(dev);

	if (pdata->touch_data[0]->panel_vendor_read)
		return snprintf(buf, PAGE_SIZE, "%c",
				pdata->touch_data[0]->panel_vendor_read());
	else
		return 0;
}

static ssize_t panel_color_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct xiaomi_touch_pdata *pdata = dev_get_drvdata(dev);

	if (pdata->touch_data[0]->panel_color_read)
		return snprintf(buf, PAGE_SIZE, "%c",
				pdata->touch_data[0]->panel_color_read());
	else
		return 0;
}

static ssize_t panel_display_show(struct device *dev,
				  struct device_attribute *attr, char *buf)
{
	struct xiaomi_touch_pdata *pdata = dev_get_drvdata(dev);

	if (pdata->touch_data[0]->panel_display_read)
		return snprintf(buf, PAGE_SIZE, "%c",
				pdata->touch_data[0]->panel_display_read());
	else
		return 0;
}

static ssize_t touch_vendor_show(struct device *dev,
				 struct device_attribute *attr, char *buf)
{
	struct xiaomi_touch_pdata *pdata = dev_get_drvdata(dev);

	if (pdata->touch_data[0]->touch_vendor_read)
		return snprintf(buf, PAGE_SIZE, "%c",
				pdata->touch_data[0]->touch_vendor_read());
	else
		return 0;
}

static ssize_t xiaomi_touch_tx_num_show(struct device *dev,
					struct device_attribute *attr,
					char *buf)
{
	struct xiaomi_touch_pdata *pdata = dev_get_drvdata(dev);

	if (pdata->touch_data[0]->get_touch_tx_num)
		return snprintf(buf, PAGE_SIZE, "%d\n",
				pdata->touch_data[0]->get_touch_tx_num());
	else
		return 0;
}

static ssize_t xiaomi_touch_rx_num_show(struct device *dev,
					struct device_attribute *attr,
					char *buf)
{
	struct xiaomi_touch_pdata *pdata = dev_get_drvdata(dev);

	if (pdata->touch_data[0]->get_touch_rx_num)
		return snprintf(buf, PAGE_SIZE, "%d\n",
				pdata->touch_data[0]->get_touch_rx_num());
	else
		return 0;
}

static ssize_t xiaomi_touch_x_resolution_show(struct device *dev,
					      struct device_attribute *attr,
					      char *buf)
{
	struct xiaomi_touch_pdata *pdata = dev_get_drvdata(dev);

	if (pdata->touch_data[0]->get_touch_x_resolution)
		return snprintf(buf, PAGE_SIZE, "%d\n",
				pdata->touch_data[0]->get_touch_x_resolution());
	else
		return 0;
}

static ssize_t xiaomi_touch_y_resolution_show(struct device *dev,
					      struct device_attribute *attr,
					      char *buf)
{
	struct xiaomi_touch_pdata *pdata = dev_get_drvdata(dev);

	if (pdata->touch_data[0]->get_touch_y_resolution)
		return snprintf(buf, PAGE_SIZE, "%d\n",
				pdata->touch_data[0]->get_touch_y_resolution());
	else
		return 0;
}

int copy_touch_rawdata(char *raw_base, int len)
{
	struct xiaomi_touch *dev = NULL;

	if (!touch_pdata) {
		return -ENODEV;
	}

	dev = touch_pdata->device;
	memcpy((unsigned char *)touch_pdata->raw_buf[touch_pdata->raw_tail],
	       (unsigned char *)raw_base, len);
	touch_pdata->raw_len = len;
	spin_lock(&touch_pdata->raw_lock);
	touch_pdata->raw_tail++;
	if (touch_pdata->raw_tail == RAW_BUF_NUM)
		touch_pdata->raw_tail = 0;
	spin_unlock(&touch_pdata->raw_lock);

	return 0;
}
EXPORT_SYMBOL_GPL(copy_touch_rawdata);

int update_touch_rawdata(void)
{
	sysfs_notify(&xiaomi_touch_dev.dev->kobj, NULL, "update_rawdata");

	return 0;
}
EXPORT_SYMBOL_GPL(update_touch_rawdata);

static ssize_t enable_touchraw_store(struct device *dev,
				     struct device_attribute *attr,
				     const char *buf, size_t count)
{
	struct xiaomi_touch_interface *touch_data = NULL;
	unsigned int input;

	if (!touch_pdata) {
		return -ENOMEM;
	}
	touch_data = touch_pdata->touch_data[0];

	if (sscanf(buf, "%d", &input) < 0)
		return -EINVAL;

	pr_info("%s,%d\n", __func__, input);
	if (touch_data->enable_touch_raw)
		touch_data->enable_touch_raw(!!input);

	touch_data->is_enable_touchraw = !!input;
	touch_pdata->raw_tail = 0;
	touch_pdata->raw_head = 0;

	return count;
}

static ssize_t enable_touchraw_show(struct device *dev,
				    struct device_attribute *attr, char *buf)
{
	struct xiaomi_touch_interface *touch_data = NULL;

	if (!touch_pdata) {
		return -ENOMEM;
	}
	touch_data = touch_pdata->touch_data[0];

	return snprintf(buf, PAGE_SIZE, "%d\n", touch_data->is_enable_touchraw);
}

static ssize_t enable_touchdelta_store(struct device *dev,
				       struct device_attribute *attr,
				       const char *buf, size_t count)
{
	struct xiaomi_touch_interface *touch_data = NULL;
	unsigned int input;

	if (!touch_pdata) {
		return -ENOMEM;
	}
	touch_data = touch_pdata->touch_data[0];

	if (sscanf(buf, "%d", &input) < 0)
		return -EINVAL;

	pr_info("%s,%d\n", __func__, input);
	if (touch_data->enable_touch_delta)
		touch_data->enable_touch_delta(!!input);

	touch_data->is_enable_touchdelta = !!input;
	return count;
}

static ssize_t enable_touchdelta_show(struct device *dev,
				      struct device_attribute *attr, char *buf)
{
	struct xiaomi_touch_interface *touch_data = NULL;

	if (!touch_pdata) {
		return -ENOMEM;
	}
	touch_data = touch_pdata->touch_data[0];

	return snprintf(buf, PAGE_SIZE, "%d\n",
			touch_data->is_enable_touchdelta);
}

static ssize_t thp_cmd_status_show(struct device *dev,
				   struct device_attribute *attr, char *buf)
{
	struct xiaomi_touch_interface *touch_data = NULL;
	mutex_lock(&dev->mutex);

	if (!touch_pdata) {
		mutex_unlock(&dev->mutex);
		return -ENOMEM;
	}

	touch_data = touch_pdata->touch_data[0];
	memcpy(buf, touch_data->thp_cmd_buf,
	       touch_data->thp_cmd_size * sizeof(int));
	if ((touch_pdata->param_head == touch_pdata->param_tail) &&
	    (touch_pdata->param_flag == 0)) {
		pr_err("[MITouch-ERR][%s:%d] %s param buffer is empty!\n",
		       __func__, __LINE__, __func__);
		mutex_unlock(&dev->mutex);
		return -EINVAL;
	}
	spin_lock(&touch_pdata->param_lock);
	BUG_ON(touch_pdata->param_head >= PARAM_BUF_NUM);
	memcpy(buf, touch_pdata->touch_cmd_data[touch_pdata->param_head],
	       touch_pdata->touch_cmd_data[touch_pdata->param_head]
			       ->thp_cmd_size *
		       sizeof(int));
	if (touch_pdata->param_head != PARAM_BUF_NUM - 1)
		touch_pdata->param_head++;
	if (touch_pdata->param_head == touch_pdata->param_tail)
		touch_pdata->param_flag = 0;
	spin_unlock(&touch_pdata->param_lock);
	// if(touch_pdata->param_head != touch_pdata->param_tail) {
	// TODO: the stock driver does this.
	//       But it is causing infinite events. Maybe I messed up something else?
	// 	dump_stack();
	// 	pr_info("%s: notify thp_cmd_status\n", __func__);
	// 	sysfs_notify(&xiaomi_touch_device->dev->kobj, NULL, "touch_thp_cmd");
	// }
	touch_data->touch_event_status = 0;
	__wake_up(&touch_data->wait_queue, 3, 0, 0);
	mutex_unlock(&dev->mutex);
	return touch_data->thp_cmd_size * sizeof(int);
}

static ssize_t thp_cmd_status_store(struct device *dev,
				    struct device_attribute *attr,
				    const char *buf, size_t count)
{
	struct xiaomi_touch_interface *touch_data = NULL;
	struct wait_queue_entry wait_entry = { 0 };
	unsigned int input[MAX_BUF_SIZE];
	const char *p = buf;
	bool new_data = false;
	int para_cnt = 0;
	int i = 0;
	long j = 0;
	long res = 0;

	if (!touch_pdata) {
		return -ENOMEM;
	}
	touch_data = touch_pdata->touch_data[0];

	memset(input, 0x00, sizeof(int) * MAX_BUF_SIZE);

	for (p = buf; *p != '\0'; p++) {
		if (*p >= '0' && *p <= '9') {
			input[i] = input[i] * 10 + (*p - '0');
			if (!new_data) {
				new_data = true;
				para_cnt++;
			}
		} else if (*p == ' ' || *p == ',') {
			if (new_data) {
				i++;
				new_data = false;
			}
		} else {
			break;
		}
	}

	pr_info("%s size:%d, cmd:%d, %d, %d, %d\n", __func__, para_cnt,
		input[0], input[1], input[2], input[3]);
	if (sizeof(int) * para_cnt < MAX_BUF_SIZE) {
		for (i = 0; i < para_cnt; i++) {
			touch_data->thp_cmd_buf[i] = input[i];
		}
		touch_data->thp_cmd_size = para_cnt;
		touch_data->touch_event_status = 1;
		if ((touch_pdata->param_head != touch_pdata->param_tail) ||
		    (touch_pdata->param_flag != 1)) {
			spin_lock(&touch_pdata->param_lock);
			BUG_ON(touch_pdata->param_tail >= PARAM_BUF_NUM);
			touch_pdata->touch_cmd_data[touch_pdata->param_tail]
				->thp_cmd_size = touch_data->thp_cmd_size;
			memcpy(touch_pdata
				       ->touch_cmd_data[touch_pdata->param_tail],
			       touch_data->thp_cmd_buf,
			       touch_data->thp_cmd_size * sizeof(int));
			if (touch_pdata->param_tail != PARAM_BUF_NUM - 1)
				touch_pdata->param_tail++;
			if (touch_pdata->param_tail == touch_pdata->param_head)
				touch_pdata->param_flag = 1;
			spin_unlock(&touch_pdata->param_lock);
			sysfs_notify(&xiaomi_touch_device->dev->kobj, NULL,
				     "touch_thp_cmd");
			if (touch_data->touch_event_status != 0) {
				init_wait_entry(&wait_entry, 0);
				res = prepare_to_wait_event(
					&touch_data->wait_queue, &wait_entry,
					1);
				if (touch_data->touch_event_status == 0) {
					j = 0x19;
				} else {
					j = 0x19;
					do {
						if (res != 0)
							goto wait_timeout;
						j = schedule_timeout(j);
						res = prepare_to_wait_event(
							&touch_data->wait_queue,
							&wait_entry, 1);
						if (touch_data->touch_event_status ==
							    0 &&
						    j == 0) {
							j = 1;
						}
					} while (
						(j != 0) &&
						(touch_data->touch_event_status !=
						 0));
				}
				res = j;
				finish_wait(&touch_data->wait_queue,
					    &wait_entry);
			wait_timeout:
				if (res < 1)
					pr_err("[MITouch-ERR][%s:%d] %s thp read timeout, skip this event, status:%d\n",
					       __func__, __LINE__, __func__);
			}
		}
	} else {
		pr_info("%s memory overlow\n", __func__);
	}
	return count;
}

static ssize_t thp_cmd_ready_status_show(struct device *dev,
					 struct device_attribute *attr,
					 char *buf)
{
	struct xiaomi_touch_interface *touch_data = NULL;
	mutex_lock(&dev->mutex);

	if (!touch_pdata) {
		mutex_unlock(&dev->mutex);
		return -ENOMEM;
	}
	touch_data = touch_pdata->touch_data[0];
	memcpy(buf, touch_data->thp_cmd_ready_buf,
	       touch_data->thp_cmd_ready_size * sizeof(int));
	mutex_unlock(&dev->mutex);
	return touch_data->thp_cmd_ready_size * sizeof(int);
}

static ssize_t thp_cmd_ready_status_store(struct device *dev,
					  struct device_attribute *attr,
					  const char *buf, size_t count)
{
	struct xiaomi_touch_interface *touch_data = NULL;
	unsigned int input[MAX_BUF_SIZE];
	const char *p = buf;
	bool new_data = false;
	int para_cnt = 0;
	int i = 0;

	if (!touch_pdata) {
		return -ENOMEM;
	}
	touch_data = touch_pdata->touch_data[0];

	memset(input, 0x00, sizeof(int) * MAX_BUF_SIZE);

	for (p = buf; *p != '\0'; p++) {
		if (*p >= '0' && *p <= '9') {
			input[i] = input[i] * 10 + (*p - '0');
			if (!new_data) {
				new_data = true;
				para_cnt++;
			}
		} else if (*p == ' ' || *p == ',') {
			if (new_data) {
				i++;
				new_data = false;
			}
		} else {
			break;
		}
	}

	pr_info("%s size:%d, cmd:%d, %d, %d, %d\n", __func__, para_cnt,
		input[0], input[1], input[2], input[3]);
	if (((long)para_cnt & 0x3fffffffffffffc0U) == 0) {
		for (i = 0; i < para_cnt; i++) {
			touch_data->thp_cmd_ready_buf[i] = input[i];
		}
		touch_data->thp_cmd_ready_size = para_cnt;
		touch_data->touch_event_ready_status = 1;
		sysfs_notify(&xiaomi_touch_device->dev->kobj, NULL,
			     "touch_thp_cmd_ready");
	} else {
		pr_info("%s memory overlow\n", __func__);
	}
	return count;
}

static ssize_t thp_cmd_data_show(struct device *dev,
				 struct device_attribute *attr, char *buf)
{
	struct xiaomi_touch_interface *touch_data = NULL;

	if (!touch_pdata)
		return -ENOMEM;

	touch_data = touch_pdata->touch_data[0];
	memcpy(buf, touch_data->thp_cmd_data_buf,
	       touch_data->thp_cmd_data_size);

	return touch_data->thp_cmd_ready_size;
}

static ssize_t thp_cmd_data_store(struct device *dev,
				  struct device_attribute *attr,
				  const char *buf, size_t count)
{
	struct xiaomi_touch_interface *touch_data = NULL;

	if (!touch_pdata)
		return -ENOMEM;

	touch_data = touch_pdata->touch_data[0];

	if (count > MAX_BUF_SIZE) {
		pr_info("%s memory out of range:%d\n", __func__, (int)count);
		return count;
	}
	pr_info("%s buf:%s, size:%d\n", __func__, buf, (int)count);
	memcpy(touch_data->thp_cmd_data_buf, buf, count);
	touch_data->thp_cmd_data_size = count;
	sysfs_notify(&xiaomi_touch_device->dev->kobj, NULL,
		     "touch_thp_cmd_data");

	return count;
}

void thp_send_cmd_to_hal(int cmd, int value)
{
	struct xiaomi_touch_interface *touch_data = NULL;
	struct wait_queue_entry wait_entry = { 0 };
	long j = 0;
	long res = 0;

	touch_data = touch_pdata->touch_data[0];

	if (!touch_data)
		return;
	mutex_lock(&xiaomi_touch_dev.mutex);
	touch_data->thp_cmd_buf[0] = SET_CUR_VALUE;
	touch_data->thp_cmd_buf[1] = 0;
	touch_data->thp_cmd_buf[2] = cmd;
	touch_data->thp_cmd_buf[3] = value;
	touch_data->thp_cmd_size = 4;
	touch_data->touch_event_status = 1;
	if ((touch_pdata->param_head == touch_pdata->param_tail) &&
	    (touch_pdata->param_flag == 1)) {
		pr_info("[MITouch-ERR][%s:%d] %s param buffer is full!\n",
			__func__, __LINE__, __func__);
		mutex_unlock(&xiaomi_touch_dev.mutex);
		return;
	}
	spin_lock(&touch_pdata->param_lock);

	BUG_ON(touch_pdata->param_tail >= PARAM_BUF_NUM);

	touch_pdata->touch_cmd_data[touch_pdata->param_tail]->thp_cmd_size =
		touch_data->thp_cmd_size;
	memcpy(touch_pdata->touch_cmd_data[touch_pdata->param_tail],
	       touch_data->thp_cmd_buf, touch_data->thp_cmd_size * sizeof(int));
	if (touch_pdata->param_tail != PARAM_BUF_NUM - 1)
		touch_pdata->param_tail++;
	if (touch_pdata->param_tail == touch_pdata->param_head)
		touch_pdata->param_flag = 1;
	spin_unlock(&touch_pdata->param_lock);

	// dump_stack();
	// pr_info("%s: notify touch_thp_cmd\n", __func__);

	sysfs_notify(&xiaomi_touch_device->dev->kobj, NULL, "touch_thp_cmd");
	if (touch_data->touch_event_status != 0) {
		init_wait_entry(&wait_entry, 0);
		res = prepare_to_wait_event(&touch_data->wait_queue,
					    &wait_entry, 1);
		if (touch_data->touch_event_status == 0) {
			j = 0x19;
		} else {
			j = 0x19;
			do {
				if (res != 0)
					goto wait_timeout;
				j = schedule_timeout(j);
				res = prepare_to_wait_event(
					&touch_data->wait_queue, &wait_entry,
					1);
				if (touch_data->touch_event_status == 0 &&
				    j == 0) {
					j = 1;
				}
			} while ((j != 0) &&
				 (touch_data->touch_event_status != 0));
		}
		res = j;
		finish_wait(&touch_data->wait_queue, &wait_entry);
	wait_timeout:
		if (res < 1)
			pr_err("[MITouch-ERR][%s:%d] %s thp read timeout, skip this event, status:%d\n",
			       __func__, __LINE__, __func__);
	}
	mutex_unlock(&xiaomi_touch_dev.mutex);
}
EXPORT_SYMBOL_GPL(thp_send_cmd_to_hal);

static ssize_t thp_downthreshold_show(struct device *dev,
				      struct device_attribute *attr, char *buf)
{
	struct xiaomi_touch_interface *touch_data = NULL;

	if (!touch_pdata) {
		return -ENOMEM;
	}
	touch_data = touch_pdata->touch_data[0];

	return snprintf(buf, PAGE_SIZE, "%d\n", touch_data->thp_downthreshold);
}

static ssize_t thp_downthreshold_store(struct device *dev,
				       struct device_attribute *attr,
				       const char *buf, size_t count)
{
	struct xiaomi_touch_interface *touch_data = NULL;
	unsigned int input;

	if (!touch_pdata) {
		return -ENOMEM;
	}
	touch_data = touch_pdata->touch_data[0];

	if (sscanf(buf, "%d", &input) < 0)
		return -EINVAL;

	pr_info("%s,%d\n", __func__, input);
	touch_data->thp_downthreshold = input;
	sysfs_notify(&xiaomi_touch_dev.dev->kobj, NULL, "touch_thp_downthd");

	return count;
}

static ssize_t thp_upthreshold_show(struct device *dev,
				    struct device_attribute *attr, char *buf)
{
	struct xiaomi_touch_interface *touch_data = NULL;

	if (!touch_pdata) {
		return -ENOMEM;
	}
	touch_data = touch_pdata->touch_data[0];

	return snprintf(buf, PAGE_SIZE, "%d\n", touch_data->thp_upthreshold);
}

static ssize_t thp_upthreshold_store(struct device *dev,
				     struct device_attribute *attr,
				     const char *buf, size_t count)
{
	struct xiaomi_touch_interface *touch_data = NULL;
	unsigned int input;

	if (!touch_pdata) {
		return -ENOMEM;
	}
	touch_data = touch_pdata->touch_data[0];

	if (sscanf(buf, "%d", &input) < 0)
		return -EINVAL;

	pr_info("%s,%d\n", __func__, input);
	touch_data->thp_upthreshold = input;
	sysfs_notify(&xiaomi_touch_dev.dev->kobj, NULL, "touch_thp_upthd");

	return count;
}

static ssize_t thp_movethreshold_store(struct device *dev,
				       struct device_attribute *attr,
				       const char *buf, size_t count)
{
	struct xiaomi_touch_interface *touch_data = NULL;
	unsigned int input;

	if (!touch_pdata) {
		return -ENOMEM;
	}
	touch_data = touch_pdata->touch_data[0];

	if (sscanf(buf, "%d", &input) < 0)
		return -EINVAL;

	pr_info("%s,%d\n", __func__, input);
	touch_data->thp_movethreshold = input;
	sysfs_notify(&xiaomi_touch_dev.dev->kobj, NULL, "touch_thp_movethd");

	return count;
}

static ssize_t thp_movethreshold_show(struct device *dev,
				      struct device_attribute *attr, char *buf)
{
	struct xiaomi_touch_interface *touch_data = NULL;

	if (!touch_pdata) {
		return -ENOMEM;
	}
	touch_data = touch_pdata->touch_data[0];

	return snprintf(buf, PAGE_SIZE, "%d\n", touch_data->thp_movethreshold);
}

static ssize_t thp_islandthreshold_store(struct device *dev,
					 struct device_attribute *attr,
					 const char *buf, size_t count)
{
	struct xiaomi_touch_interface *touch_data = NULL;
	unsigned int input;

	if (!touch_pdata) {
		return -ENOMEM;
	}
	touch_data = touch_pdata->touch_data[0];

	if (sscanf(buf, "%d", &input) < 0)
		return -EINVAL;

	pr_info("%s,%d\n", __func__, input);
	touch_data->thp_islandthreshold = input;
	sysfs_notify(&xiaomi_touch_dev.dev->kobj, NULL, "touch_thp_islandthd");

	return count;
}

static ssize_t thp_islandthreshold_show(struct device *dev,
					struct device_attribute *attr,
					char *buf)
{
	struct xiaomi_touch_interface *touch_data = NULL;

	if (!touch_pdata) {
		return -ENOMEM;
	}
	touch_data = touch_pdata->touch_data[0];

	return snprintf(buf, PAGE_SIZE, "%d\n",
			touch_data->thp_islandthreshold);
}

static ssize_t thp_noisefilter_store(struct device *dev,
				     struct device_attribute *attr,
				     const char *buf, size_t count)
{
	struct xiaomi_touch_interface *touch_data = NULL;
	unsigned int input;

	if (!touch_pdata) {
		return -ENOMEM;
	}
	touch_data = touch_pdata->touch_data[0];

	if (sscanf(buf, "%d", &input) < 0)
		return -EINVAL;

	pr_info("%s,%d\n", __func__, input);
	touch_data->thp_noisefilter = input;
	sysfs_notify(&xiaomi_touch_dev.dev->kobj, NULL,
		     "touch_thp_noisefilter");

	return count;
}

static ssize_t thp_noisefilter_show(struct device *dev,
				    struct device_attribute *attr, char *buf)
{
	struct xiaomi_touch_interface *touch_data = NULL;

	if (!touch_pdata) {
		return -ENOMEM;
	}
	touch_data = touch_pdata->touch_data[0];

	return snprintf(buf, PAGE_SIZE, "%d\n", touch_data->thp_noisefilter);
}

static ssize_t thp_smooth_store(struct device *dev,
				struct device_attribute *attr, const char *buf,
				size_t count)
{
	struct xiaomi_touch_interface *touch_data = NULL;
	unsigned int input;

	if (!touch_pdata) {
		return -ENOMEM;
	}
	touch_data = touch_pdata->touch_data[0];

	if (sscanf(buf, "%d", &input) < 0)
		return -EINVAL;

	pr_info("%s,%d\n", __func__, input);
	touch_data->thp_smooth = input;
	sysfs_notify(&xiaomi_touch_dev.dev->kobj, NULL, "touch_thp_smooth");

	return count;
}

static ssize_t thp_smooth_show(struct device *dev,
			       struct device_attribute *attr, char *buf)
{
	struct xiaomi_touch_interface *touch_data = NULL;

	if (!touch_pdata) {
		return -ENOMEM;
	}
	touch_data = touch_pdata->touch_data[0];

	return snprintf(buf, PAGE_SIZE, "%d\n", touch_data->thp_smooth);
}

static ssize_t thp_dump_frame_store(struct device *dev,
				    struct device_attribute *attr,
				    const char *buf, size_t count)
{
	struct xiaomi_touch_interface *touch_data = NULL;
	unsigned int input;

	if (!touch_pdata) {
		return -ENOMEM;
	}
	touch_data = touch_pdata->touch_data[0];

	if (sscanf(buf, "%d", &input) < 0)
		return -EINVAL;

	pr_info("%s,%d\n", __func__, input);
	touch_data->thp_dump_raw = input;
	sysfs_notify(&xiaomi_touch_dev.dev->kobj, NULL, "touch_thp_dump");

	return count;
}

static ssize_t thp_dump_frame_show(struct device *dev,
				   struct device_attribute *attr, char *buf)
{
	struct xiaomi_touch_interface *touch_data = NULL;

	if (!touch_pdata) {
		return -ENOMEM;
	}
	touch_data = touch_pdata->touch_data[0];

	return snprintf(buf, PAGE_SIZE, "%d\n", touch_data->thp_dump_raw);
}

static ssize_t update_rawdata_show(struct device *dev,
				   struct device_attribute *attr, char *buf)
{
	int remaining = 0;

	if (!touch_pdata->raw_data)
		return -ENOMEM;

	if (touch_pdata->raw_head == touch_pdata->raw_tail)
		return snprintf(buf, PAGE_SIZE, "%s\n", "0");
	else {
		if (touch_pdata->raw_head < touch_pdata->raw_tail)
			remaining =
				touch_pdata->raw_tail - touch_pdata->raw_head;
		else
			remaining = RAW_BUF_NUM - touch_pdata->raw_head +
				    touch_pdata->raw_tail;
		memcpy((unsigned char *)touch_pdata->raw_data,
		       (unsigned char *)
			       touch_pdata->raw_buf[touch_pdata->raw_head],
		       touch_pdata->raw_len);
		spin_lock(&touch_pdata->raw_lock);
		touch_pdata->raw_head++;
		if (touch_pdata->raw_head == RAW_BUF_NUM)
			touch_pdata->raw_head = 0;
		spin_unlock(&touch_pdata->raw_lock);
	}
	return snprintf(buf, PAGE_SIZE, "%d\n", remaining);
}

static ssize_t update_rawdata_store(struct device *dev,
				    struct device_attribute *attr,
				    const char *buf, size_t count)
{
	if (!touch_pdata->raw_data)
		return -ENOMEM;

	if (touch_pdata->raw_head != touch_pdata->raw_tail)
		sysfs_notify(&xiaomi_touch_dev.dev->kobj, NULL,
			     "update_rawdata");

	pr_info("%s notify buf\n", __func__);

	return count;
}

static ssize_t enable_clicktouch_store(struct device *dev,
				       struct device_attribute *attr,
				       const char *buf, size_t count)
{
	struct xiaomi_touch_interface *touch_data = NULL;
	unsigned int input;

	if (!touch_pdata) {
		return -ENOMEM;
	}
	touch_data = touch_pdata->touch_data[0];

	if (sscanf(buf, "%d", &input) < 0)
		return -EINVAL;

	pr_info("%s,%d\n", __func__, input);
	if (touch_data->enable_clicktouch_raw)
		touch_data->enable_clicktouch_raw(input);

	return count;
}

static ssize_t enable_clicktouch_show(struct device *dev,
				      struct device_attribute *attr, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%s\n", "1");
}

int update_clicktouch_raw(void)
{
	sysfs_notify(&xiaomi_touch_dev.dev->kobj, NULL, "clicktouch_raw");

	return 0;
}
EXPORT_SYMBOL_GPL(update_clicktouch_raw);

int xiaomi_touch_set_suspend_state(int state)
{
	if (!touch_pdata) {
		return -ENODEV;
	}
	touch_pdata->suspend_state = state;

	sysfs_notify(&xiaomi_touch_dev.dev->kobj, NULL, "suspend_state");

	return 0;
}
EXPORT_SYMBOL_GPL(xiaomi_touch_set_suspend_state);

static ssize_t xiaomi_touch_suspend_state(struct device *dev,
					  struct device_attribute *attr,
					  char *buf)
{
	if (!touch_pdata) {
		return -ENODEV;
	}
	return snprintf(buf, PAGE_SIZE, "%d\n", touch_pdata->suspend_state);
}

void update_active_status(bool status)
{
	struct xiaomi_touch_interface *touch_data = NULL;

	if (!touch_pdata) {
		return;
	}

	touch_data = touch_pdata->touch_data[0];

	if (status != touch_data->active_status) {
		touch_data->active_status = status;
		sysfs_notify(&xiaomi_touch_dev.dev->kobj, NULL,
			     "touch_active_status");
	}
}
EXPORT_SYMBOL_GPL(update_active_status);

static ssize_t touch_active_status_show(struct device *dev,
					struct device_attribute *attr,
					char *buf)
{
	struct xiaomi_touch_pdata *pdata = dev_get_drvdata(dev);

	return snprintf(buf, PAGE_SIZE, "%d\n",
			pdata->touch_data[0]->active_status);
}

static ssize_t touch_finger_status_store(struct device *dev,
					 struct device_attribute *attr,
					 const char *buf, size_t count)
{
	struct xiaomi_touch_interface *touch_data = NULL;
	unsigned int input;

	if (!touch_pdata) {
		return -ENOMEM;
	}
	touch_data = touch_pdata->touch_data[0];

	if (sscanf(buf, "%d", &input) < 0)
		return -EINVAL;

	if (input != touch_data->finger_status) {
		touch_data->finger_status = input;
		sysfs_notify(&xiaomi_touch_dev.dev->kobj, NULL,
			     "touch_finger_status");
		if (input != 0 && input != touch_data->active_status) {
			touch_data->active_status = true;
			sysfs_notify(&xiaomi_touch_dev.dev->kobj, NULL,
				     "touch_active_status");
		}
	}

	return count;
}

static ssize_t touch_finger_status_show(struct device *dev,
					struct device_attribute *attr,
					char *buf)
{
	struct xiaomi_touch_interface *touch_data = NULL;

	if (!touch_pdata) {
		return -ENOMEM;
	}
	touch_data = touch_pdata->touch_data[0];

	return snprintf(buf, PAGE_SIZE, "%d\n", touch_data->finger_status);
}

void update_touch_irq_no(int irq_no)
{
	if (!touch_pdata) {
		return;
	}

	touch_pdata->touch_data[0]->irq_no = irq_no;
	sysfs_notify(&xiaomi_touch_dev.dev->kobj, NULL, "touch_irq_no");
}
EXPORT_SYMBOL_GPL(update_touch_irq_no);

static ssize_t touch_irq_no_show(struct device *dev,
				 struct device_attribute *attr, char *buf)
{
	struct xiaomi_touch_pdata *pdata = dev_get_drvdata(dev);

	return snprintf(buf, PAGE_SIZE, "%d\n", pdata->touch_data[0]->irq_no);
}

int update_fod_press_status(int value)
{
	struct xiaomi_touch *dev = NULL;

	mutex_lock(&xiaomi_touch_dev.fod_press_status_mutex);

	if (!touch_pdata) {
		mutex_unlock(&xiaomi_touch_dev.fod_press_status_mutex);
		return -ENODEV;
	}

	dev = touch_pdata->device;

	if (value != touch_pdata->fod_press_status_value) {
		pr_info("%s: value:%d\n", __func__, value);
		touch_pdata->fod_press_status_value = value;
		sysfs_notify(&xiaomi_touch_dev.dev->kobj, NULL,
			     "fod_press_status");
	}

	mutex_unlock(&xiaomi_touch_dev.fod_press_status_mutex);
	return 0;
}
EXPORT_SYMBOL_GPL(update_fod_press_status);

int notify_gesture_single_tap(void)
{
	mutex_lock(&xiaomi_touch_dev.gesture_single_tap_mutex);
	sysfs_notify(&xiaomi_touch_dev.dev->kobj, NULL,
		     "gesture_single_tap_state");
	mutex_unlock(&xiaomi_touch_dev.gesture_single_tap_mutex);
	return 0;
}
EXPORT_SYMBOL_GPL(notify_gesture_single_tap);

static ssize_t gesture_single_tap_value_show(struct device *dev,
					     struct device_attribute *attr,
					     char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%d\n", 1);
}

static ssize_t fod_press_status_show(struct device *dev,
				     struct device_attribute *attr, char *buf)
{
	struct xiaomi_touch_pdata *pdata = dev_get_drvdata(dev);

	return snprintf(buf, PAGE_SIZE, "%d\n", pdata->fod_press_status_value);
}

static ssize_t resolution_factor_show(struct device *dev,
				      struct device_attribute *attr, char *buf)
{
	int factor = 1;

	if (!touch_pdata) {
		return -ENODEV;
	}
	if (touch_pdata->touch_data[0]->get_touch_super_resolution_factor) {
		factor = touch_pdata->touch_data[0]
				 ->get_touch_super_resolution_factor();
	}
	return snprintf(buf, PAGE_SIZE, "%d", factor);
}

static ssize_t touch_sensor_show(struct device *dev,
				 struct device_attribute *attr, char *buf)

{
	return snprintf(buf, PAGE_SIZE, "%d\n", 1);
}

static ssize_t touch_sensor_store(struct device *dev,
				  struct device_attribute *attr,
				  const char *buf, size_t count)
{
	struct xiaomi_touch_pdata *pdata = dev_get_drvdata(dev);
	unsigned int input;

	if (!pdata) {
		return -ENODEV;
	}

	if (sscanf(buf, "%d", &input) < 0) {
		return -EINVAL;
	}

	if (input >= 0) {
		thp_send_cmd_to_hal(THP_HAL_TOUCH_SENSOR, input);
		if (input == 0) {
			if (touch_pdata->touch_data[0]->set_up_interrupt_mode) {
				touch_pdata->touch_data[0]
					->set_up_interrupt_mode(0);
			}
		}
	}

	pr_info("%s value:%d\n", __func__, input);

	return count;
}

static ssize_t touch_preset_point_show(struct device *dev,
				       struct device_attribute *attr, char *buf)

{
	struct xiaomi_touch_pdata *pdata = dev_get_drvdata(dev);

	if (!pdata) {
		return -ENODEV;
	}

	return snprintf(buf, PAGE_SIZE, "%d\n",
			pdata->touch_data[0]->thp_preset_point);
}

static ssize_t touch_preset_point_store(struct device *dev,
					struct device_attribute *attr,
					const char *buf, size_t count)
{
	struct xiaomi_touch_pdata *pdata = dev_get_drvdata(dev);
	unsigned int input = 0;

	if (!pdata) {
		return -ENODEV;
	}

	if (sscanf(buf, "%d", &input) < 0) {
		return -EINVAL;
	}

	pdata->touch_data[0]->thp_preset_point = input;
	sysfs_notify(&xiaomi_touch_dev.dev->kobj, NULL,
		     "touch_thp_preset_point");
	pr_info("[MITouch-INF][%s:%d] %s value:%d\n", __func__, __LINE__,
		__func__, input);

	return count;
}

static ssize_t touch_testresult_show(struct device *dev,
				     struct device_attribute *attr, char *buf)

{
	struct xiaomi_touch_pdata *pdata = dev_get_drvdata(dev);

	if (!pdata) {
		return -ENODEV;
	}

	return snprintf(buf, PAGE_SIZE, "%d\n",
			pdata->touch_data[0]->thp_test_result);
}

static ssize_t touch_testresult_store(struct device *dev,
				      struct device_attribute *attr,
				      const char *buf, size_t count)
{
	struct xiaomi_touch_pdata *pdata = dev_get_drvdata(dev);
	unsigned int input = 0;

	if (!pdata) {
		return -ENODEV;
	}

	if (sscanf(buf, "%d", &input) < 0) {
		return -EINVAL;
	}

	pdata->touch_data[0]->thp_test_result = input;
	sysfs_notify(&xiaomi_touch_dev.dev->kobj, NULL, "touch_thp_testresult");
	pr_info("[MITouch-INF][%s:%d] %s value:%d\n", __func__, __LINE__,
		__func__, input);

	return count;
}

static ssize_t touch_testmode_show(struct device *dev,
				   struct device_attribute *attr, char *buf)

{
	struct xiaomi_touch_pdata *pdata = dev_get_drvdata(dev);

	if (!pdata) {
		return -ENODEV;
	}

	return snprintf(buf, PAGE_SIZE, "%d\n",
			pdata->touch_data[0]->thp_test_mode);
}

static ssize_t touch_testmode_store(struct device *dev,
				    struct device_attribute *attr,
				    const char *buf, size_t count)
{
	struct xiaomi_touch_pdata *pdata = dev_get_drvdata(dev);
	unsigned int input = 0;

	if (!pdata) {
		return -ENODEV;
	}

	if (sscanf(buf, "%d", &input) < 0) {
		return -EINVAL;
	}

	pdata->touch_data[0]->thp_test_mode = input;
	sysfs_notify(&xiaomi_touch_dev.dev->kobj, NULL, "touch_thp_testmode");
	pr_info("[MITouch-INF][%s:%d] %s value:%d\n", __func__, __LINE__,
		__func__, input);

	return count;
}

static ssize_t touch_sensor_ctrl_show(struct device *dev,
				      struct device_attribute *attr, char *buf)

{
	struct xiaomi_touch_pdata *pdata = dev_get_drvdata(dev);

	if (!pdata) {
		return -ENODEV;
	}

	return snprintf(buf, PAGE_SIZE, "%d\n",
			pdata->touch_data[0]->touch_sensor_ctrl_value);
}

static ssize_t touch_sensor_ctrl_store(struct device *dev,
				       struct device_attribute *attr,
				       const char *buf, size_t count)
{
	struct xiaomi_touch_pdata *pdata = dev_get_drvdata(dev);
	unsigned int input = 0;

	if (!pdata) {
		return -ENODEV;
	}

	if (sscanf(buf, "%d", &input) < 0) {
		pr_err("[MITouch-INF][%s:%d] %s get input error\n", __func__,
		       __LINE__, __func__);
		return -EINVAL;
	}

	pdata->touch_data[0]->touch_sensor_ctrl_value = input;
	pr_info("[MITouch-INF][%s:%d] %s touch sensor ctrl %d\n\n", __func__,
		__LINE__, __func__, input);
	sysfs_notify(&xiaomi_touch_dev.dev->kobj, NULL, "touch_sensor_ctrl");

	return count;
}

static ssize_t touch_thp_mem_notify_show(struct device *dev,
					 struct device_attribute *attr,
					 char *buf)

{
	return snprintf(buf, PAGE_SIZE, "%d", 1);
}

static ssize_t touch_thp_mem_notify_store(struct device *dev,
					  struct device_attribute *attr,
					  const char *buf, size_t count)
{
	unsigned int input;

	if (sscanf(buf, "%d", &input) < 0) {
		return -EINVAL;
	}

	if (input == 1) {
		sysfs_notify(&xiaomi_touch_dev.dev->kobj, NULL,
			     "touch_thp_mem_notify");
	}

	return count;
}

static ssize_t abnormal_event_show(struct device *dev,
				   struct device_attribute *attr, char *buf)

{
	ssize_t rc = ABNORMAL_EVENT_SIZE;
	struct xiaomi_touch_interface *touch_data = NULL;
	struct xiaomi_touch_pdata *pdata = dev_get_drvdata(dev);

	if (!pdata) {
		return -ENODEV;
	}

	mutex_lock(&pdata->device->abnormal_event_mutex);

	touch_data = pdata->touch_data[0];

	if (pdata->abnormal_event_head == pdata->abnormal_event_tail &&
	    pdata->abnormal_event_flag == false) {
		rc = -1;
		pr_err("[MITouch-ERR][%s:%d] %s buf is empty\n", __func__,
		       __LINE__, __func__);
	} else {
		BUG_ON(pdata->abnormal_event_head > 10);
		memcpy(buf,
		       pdata->abnormal_event_buf[pdata->abnormal_event_head],
		       ABNORMAL_EVENT_SIZE);
		++pdata->abnormal_event_head;
		if (pdata->abnormal_event_head > ABNORMAL_EVENT_NUM - 1) {
			pdata->abnormal_event_head = 0;
			pdata->abnormal_event_flag = false;
		}
		if ((pdata->abnormal_event_head < pdata->abnormal_event_tail) ||
		    (pdata->abnormal_event_flag != false)) {
			sysfs_notify(&xiaomi_touch_dev.dev->kobj, NULL,
				     "abnormal_event");
		}
	}

	mutex_unlock(&pdata->device->abnormal_event_mutex);

	return rc;
}

static ssize_t abnormal_event_store(struct device *dev,
				    struct device_attribute *attr,
				    const char *buf, size_t count)
{
	struct xiaomi_touch_interface *touch_data = NULL;
	struct xiaomi_touch_pdata *pdata = dev_get_drvdata(dev);

	if (!pdata || count != ABNORMAL_EVENT_SIZE) {
		pr_err("[MITouch-ERR][%s:%d] %s fail! pdata = %ld, size = %d, %d\n",
		       __func__, __LINE__, __func__, (long)pdata, count,
		       ABNORMAL_EVENT_SIZE);
		return -ENODEV;
	}

	touch_data = pdata->touch_data[0];

	mutex_lock(&pdata->device->abnormal_event_mutex);

	memcpy(pdata->abnormal_event_buf[pdata->abnormal_event_tail], buf,
	       ABNORMAL_EVENT_SIZE);
	++pdata->abnormal_event_tail;
	if (pdata->abnormal_event_tail >= ABNORMAL_EVENT_NUM - 1) {
		pdata->abnormal_event_tail = 0;
		pdata->abnormal_event_flag = true;
	}

	mutex_unlock(&pdata->device->abnormal_event_mutex);

	sysfs_notify(&xiaomi_touch_dev.dev->kobj, NULL, "abnormal_event");

	return count;
}

static ssize_t touch_doze_analysis_show(struct device *dev,
					struct device_attribute *attr,
					char *buf)

{
	struct xiaomi_touch_interface *touch_data = NULL;
	struct xiaomi_touch_pdata *pdata = dev_get_drvdata(dev);

	if (!pdata) {
		return -ENODEV;
	}

	touch_data = pdata->touch_data[0];

	if (touch_data->touch_doze_analysis) {
		return snprintf(buf, PAGE_SIZE, "%d\n",
				touch_data->touch_doze_analysis(5));
	}

	return 0;
}

static ssize_t touch_doze_analysis_store(struct device *dev,
					 struct device_attribute *attr,
					 const char *buf, size_t count)
{
	struct xiaomi_touch_interface *touch_data = NULL;
	struct xiaomi_touch_pdata *pdata = dev_get_drvdata(dev);
	unsigned int input;

	if (!pdata) {
		return -ENODEV;
	}

	if (sscanf(buf, "%d", &input) < 0) {
		return -EINVAL;
	}

	touch_data = pdata->touch_data[0];

	if (touch_data->touch_doze_analysis) {
		touch_data->touch_doze_analysis(input);
	} else {
		pr_err("[MITouch-ERR][%s:%d] %s has not implement\n\n",
		       __func__, __LINE__, __func__);
	}

	pr_info("%s value:%d\n", __func__, input);

	return count;
}

static ssize_t touch_ic_buffer_show(struct device *dev,
				    struct device_attribute *attr, char *buf)

{
	struct xiaomi_touch_interface *touch_data = NULL;
	struct xiaomi_touch_pdata *pdata = dev_get_drvdata(dev);
	unsigned int rc = 0;
	char *local_buf;

	if (!pdata) {
		return -ENODEV;
	}

	touch_data = pdata->touch_data[0];

	if (touch_data->get_touch_ic_buffer) {
		local_buf = touch_data->get_touch_ic_buffer();
		rc = snprintf(buf, PAGE_SIZE, "%s", local_buf);
		if (local_buf)
			vfree(local_buf);

	} else {
		pr_info("[MITouch-INF][%s:%d] %s get touch ic buffer wrong\n",
			__func__, __LINE__, __func__);
	}

	return rc;
}

static DEVICE_ATTR(abnormal_event, (S_IRUGO | S_IWUSR | S_IWGRP),
		   abnormal_event_show, abnormal_event_store);

static DEVICE_ATTR(touch_sensor, (S_IRUGO | S_IWUSR | S_IWGRP),
		   touch_sensor_show, touch_sensor_store);

static DEVICE_ATTR(touch_sensor_ctrl, (S_IRUGO | S_IWUSR | S_IWGRP),
		   touch_sensor_ctrl_show, touch_sensor_ctrl_store);

static DEVICE_ATTR(touch_thp_testmode, (S_IRUGO | S_IWUSR | S_IWGRP),
		   touch_testmode_show, touch_testmode_store);

static DEVICE_ATTR(touch_thp_testresult, (S_IRUGO | S_IWUSR | S_IWGRP),
		   touch_testresult_show, touch_testresult_store);

static DEVICE_ATTR(touch_thp_preset_point, (S_IRUGO | S_IWUSR | S_IWGRP),
		   touch_preset_point_show, touch_preset_point_store);

static DEVICE_ATTR(touch_doze_analysis, (S_IRUGO | S_IWUSR | S_IWGRP),
		   touch_doze_analysis_show, touch_doze_analysis_store);

static DEVICE_ATTR(touch_ic_buffer, (S_IRUGO | S_IWUSR | S_IWGRP),
		   touch_ic_buffer_show, NULL);

static DEVICE_ATTR(touch_thp_cmd_ready, (S_IRUGO | S_IWUSR | S_IWGRP),
		   thp_cmd_ready_status_show, thp_cmd_ready_status_store);

static DEVICE_ATTR(touch_thp_cmd_data, (S_IRUGO | S_IWUSR | S_IWGRP),
		   thp_cmd_data_show, thp_cmd_data_store);

static DEVICE_ATTR(touch_thp_cmd, (S_IRUGO | S_IWUSR | S_IWGRP),
		   thp_cmd_status_show, thp_cmd_status_store);

static DEVICE_ATTR(touch_thp_islandthd, (S_IRUGO | S_IWUSR | S_IWGRP),
		   thp_islandthreshold_show, thp_islandthreshold_store);

static DEVICE_ATTR(touch_thp_downthd, (S_IRUGO | S_IWUSR | S_IWGRP),
		   thp_downthreshold_show, thp_downthreshold_store);

static DEVICE_ATTR(touch_thp_upthd, (S_IRUGO | S_IWUSR | S_IWGRP),
		   thp_upthreshold_show, thp_upthreshold_store);

static DEVICE_ATTR(touch_thp_movethd, (S_IRUGO | S_IWUSR | S_IWGRP),
		   thp_movethreshold_show, thp_movethreshold_store);

static DEVICE_ATTR(touch_thp_smooth, (S_IRUGO | S_IWUSR | S_IWGRP),
		   thp_smooth_show, thp_smooth_store);

static DEVICE_ATTR(touch_thp_dump, (S_IRUGO | S_IWUSR | S_IWGRP),
		   thp_dump_frame_show, thp_dump_frame_store);

static DEVICE_ATTR(touch_thp_noisefilter, (S_IRUGO | S_IWUSR | S_IWGRP),
		   thp_noisefilter_show, thp_noisefilter_store);

static DEVICE_ATTR(touch_thp_mem_notify, (S_IRUGO | S_IWUSR | S_IWGRP),
		   touch_thp_mem_notify_show, touch_thp_mem_notify_store);

static DEVICE_ATTR(enable_touch_raw, (S_IRUGO | S_IWUSR | S_IWGRP),
		   enable_touchraw_show, enable_touchraw_store);

static DEVICE_ATTR(enable_touch_delta, (S_IRUGO | S_IWUSR | S_IWGRP),
		   enable_touchdelta_show, enable_touchdelta_store);

static DEVICE_ATTR(palm_sensor, (S_IRUGO | S_IWUSR | S_IWGRP), palm_sensor_show,
		   palm_sensor_store);

static DEVICE_ATTR(palm_sensor_data, (S_IRUGO | S_IWUSR | S_IWGRP),
		   palm_sensor_data_show, palm_sensor_data_store);

static DEVICE_ATTR(prox_sensor, (S_IRUGO | S_IWUSR | S_IWGRP), prox_sensor_show,
		   prox_sensor_store);

static DEVICE_ATTR(clicktouch_raw, (S_IRUGO | S_IWUSR | S_IWGRP),
		   enable_clicktouch_show, enable_clicktouch_store);

static DEVICE_ATTR(panel_vendor, (S_IRUGO), panel_vendor_show, NULL);

static DEVICE_ATTR(panel_color, (S_IRUGO), panel_color_show, NULL);

static DEVICE_ATTR(panel_display, (S_IRUGO), panel_display_show, NULL);

static DEVICE_ATTR(touch_vendor, (S_IRUGO), touch_vendor_show, NULL);

static DEVICE_ATTR(touch_thp_tx_num, (S_IRUGO), xiaomi_touch_tx_num_show, NULL);

static DEVICE_ATTR(touch_thp_rx_num, (S_IRUGO), xiaomi_touch_rx_num_show, NULL);

static DEVICE_ATTR(touch_thp_x_resolution, (S_IRUGO),
		   xiaomi_touch_x_resolution_show, NULL);

static DEVICE_ATTR(touch_thp_y_resolution, (S_IRUGO),
		   xiaomi_touch_y_resolution_show, NULL);

static DEVICE_ATTR(suspend_state, 0644, xiaomi_touch_suspend_state, NULL);

static DEVICE_ATTR(update_rawdata, (S_IRUGO | S_IWUSR | S_IWGRP),
		   update_rawdata_show, update_rawdata_store);
static DEVICE_ATTR(fod_press_status, (0664), fod_press_status_show, NULL);

static DEVICE_ATTR(gesture_single_tap_state, (0664),
		   gesture_single_tap_value_show, NULL);

static DEVICE_ATTR(resolution_factor, 0644, resolution_factor_show, NULL);

static DEVICE_ATTR(touch_active_status, (0664), touch_active_status_show, NULL);

static DEVICE_ATTR(touch_finger_status, (0664), touch_finger_status_show,
		   touch_finger_status_store);

static DEVICE_ATTR(touch_irq_no, (0664), touch_irq_no_show, NULL);

static struct attribute *touch_attr_group[] = {
	&dev_attr_abnormal_event.attr,
	&dev_attr_enable_touch_raw.attr,
	&dev_attr_enable_touch_delta.attr,
	&dev_attr_touch_thp_cmd.attr,
	&dev_attr_touch_thp_cmd_data.attr,
	&dev_attr_clicktouch_raw.attr,
	&dev_attr_touch_thp_tx_num.attr,
	&dev_attr_touch_thp_rx_num.attr,
	&dev_attr_touch_thp_x_resolution.attr,
	&dev_attr_touch_thp_y_resolution.attr,
	&dev_attr_touch_thp_downthd.attr,
	&dev_attr_touch_thp_upthd.attr,
	&dev_attr_touch_thp_movethd.attr,
	&dev_attr_touch_thp_islandthd.attr,
	&dev_attr_touch_thp_smooth.attr,
	&dev_attr_touch_thp_dump.attr,
	&dev_attr_touch_thp_noisefilter.attr,
	&dev_attr_touch_thp_mem_notify.attr,
	&dev_attr_palm_sensor.attr,
	&dev_attr_palm_sensor_data.attr,
	&dev_attr_prox_sensor.attr,
	&dev_attr_panel_vendor.attr,
	&dev_attr_panel_color.attr,
	&dev_attr_panel_display.attr,
	&dev_attr_touch_vendor.attr,
	&dev_attr_update_rawdata.attr,
	&dev_attr_suspend_state.attr,
	&dev_attr_fod_press_status.attr,
	&dev_attr_gesture_single_tap_state.attr,
	&dev_attr_resolution_factor.attr,
	&dev_attr_touch_active_status.attr,
	&dev_attr_touch_finger_status.attr,
	&dev_attr_touch_irq_no.attr,
	&dev_attr_touch_sensor.attr,
	&dev_attr_touch_sensor_ctrl.attr,
	&dev_attr_touch_thp_testmode.attr,
	&dev_attr_touch_thp_testresult.attr,
	&dev_attr_touch_thp_preset_point.attr,
	&dev_attr_touch_doze_analysis.attr,
	&dev_attr_touch_ic_buffer.attr,
	&dev_attr_touch_thp_cmd_ready.attr,
	NULL,
};

static void *event_start(struct seq_file *m, loff_t *p)
{
	int pos = 0;
	struct last_touch_event *event;
	if (!touch_pdata || !touch_pdata->last_touch_events)
		return NULL;
	event = touch_pdata->last_touch_events;
	if (*p >= LAST_TOUCH_EVENTS_MAX)
		return NULL;

	pos = (event->head + *p) & (LAST_TOUCH_EVENTS_MAX - 1);
	return event->touch_event_buf + pos;
}

static void *event_next(struct seq_file *m, void *v, loff_t *p)
{
	int pos = 0;
	struct last_touch_event *event;
	if (!touch_pdata || !touch_pdata->last_touch_events)
		return NULL;
	event = touch_pdata->last_touch_events;
	if (++*p >= LAST_TOUCH_EVENTS_MAX)
		return NULL;
	pos = (event->head + *p) & (LAST_TOUCH_EVENTS_MAX - 1);
	return event->touch_event_buf + pos;
}

static int32_t event_show(struct seq_file *m, void *v)
{
	struct touch_event *event_info;
	struct rtc_time tm;
	event_info = (struct touch_event *)v;

	if (event_info->state == EVENT_INIT)
		return 0;
	rtc_time64_to_tm(event_info->touch_time.tv_sec, &tm);
	seq_printf(m, "%d-%02d-%02d %02d:%02d:%02d.%09lu UTC Finger (%2d) %s\n",
		   tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour,
		   tm.tm_min, tm.tm_sec, event_info->touch_time.tv_nsec,
		   event_info->slot,
		   event_info->state == EVENT_DOWN ? "P" : "R");
	return 0;
}

static void event_stop(struct seq_file *m, void *v)
{
	return;
}

const struct seq_operations last_touch_events_seq_ops = {
	.start = event_start,
	.next = event_next,
	.stop = event_stop,
	.show = event_show,
};

static ssize_t tp_hal_version_read(struct file *file, char __user *buf,
				   size_t count, loff_t *pos)
{
	struct xiaomi_touch_interface *touch_data = NULL;
	int ret;

	if (!touch_pdata) {
		return -ENOMEM;
	}
	touch_data = touch_pdata->touch_data[0];

	if (*pos != 0) {
		return 0;
	}

	count = strlen(touch_data->tp_hal_version);
	ret = copy_to_user(buf, &touch_data->tp_hal_version, count);
	if (ret == 0) {
		*pos += count;
	} else {
		return -EFAULT;
	}

	return count;
}

static ssize_t tp_hal_version_write(struct file *file, const char __user *buf,
				    size_t count, loff_t *pos)
{
	struct xiaomi_touch_interface *touch_data = NULL;
	int ret;

	if (!touch_pdata) {
		return -ENOMEM;
	}
	touch_data = touch_pdata->touch_data[0];

	// touch_data->thp_downthreshold = 0;
	// touch_data->thp_upthreshold = 0;
	// touch_data->thp_movethreshold = 0;
	// touch_data->thp_noisefilter = 0;
	// touch_data->thp_islandthreshold = 0;
	// touch_data->thp_smooth = 0;
	// touch_data->thp_dump_raw = 0;

	memset(&touch_data->tp_hal_version, 0, TP_VERSION_SIZE);

	if (count < TP_VERSION_SIZE) {
		ret = copy_from_user(&touch_data->tp_hal_version, buf, count);
		if (ret != 0) {
			return -EFAULT;
		}
	}

	return count;
}

static const struct proc_ops tp_hal_version_ops = {
	.proc_read = tp_hal_version_read,
	.proc_write = tp_hal_version_write,
};

/*
static int32_t last_touch_events_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &last_touch_events_seq_ops);
}
*/
void last_touch_events_collect(int slot, int state)
{
	struct touch_event *event_info;
	struct last_touch_event *event;
	static int event_state[MAX_TOUCH_ID] = { 0 };

	if (!touch_pdata || !touch_pdata->last_touch_events ||
	    slot >= MAX_TOUCH_ID || event_state[slot] == state)
		return;
	event_state[slot] = state;
	event = touch_pdata->last_touch_events;

	event_info = &event->touch_event_buf[event->head];
	event_info->state = !!state ? EVENT_DOWN : EVENT_UP;
	event_info->slot = slot;
	ktime_get_real_ts64(&event_info->touch_time);
	event->head++;
	event->head &= LAST_TOUCH_EVENTS_MAX - 1;
}
EXPORT_SYMBOL_GPL(last_touch_events_collect);
/*
struct file_operations last_touch_events_ops = {
	.owner = THIS_MODULE,
	.open = last_touch_events_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release,
};
*/
static const struct of_device_id xiaomi_touch_of_match[] = {
	{
		.compatible = "xiaomi-touch",
	},
	{},
};

static int xiaomi_touch_parse_dt(struct device *dev,
				 struct xiaomi_touch_pdata *data)
{
	int ret;
	struct device_node *np;

	np = dev->of_node;
	if (!np)
		return -ENODEV;

	ret = of_property_read_string(np, "touch,name", &data->name);
	if (ret)
		return ret;

	pr_info("%s touch,name:%s\n", __func__, data->name);

	return 0;
}

static int xiaomi_touch_probe(struct platform_device *pdev)
{
	int ret = 0;
	int i = 0;
	struct device *dev = &pdev->dev;
	struct xiaomi_touch_pdata *pdata = NULL;

	pr_info("%s enter\n", __func__);

	ret = knock_node_init();

	if (ret != 0)
		goto sys_group_err;

	pdata = devm_kzalloc(dev, sizeof(struct xiaomi_touch_pdata),
			     GFP_KERNEL);
	if (!pdata)
		return -ENOMEM;

	pdata->raw_data = (unsigned int *)kzalloc(RAW_SIZE, GFP_KERNEL);
	if (!pdata->raw_data) {
		ret = -ENOMEM;
		pr_err("%s alloc mem for raw data\n", __func__);
		goto parse_dt_err;
	}

	for (i = 0; i < PARAM_BUF_NUM; i++) {
		pdata->touch_cmd_data[i] =
			kzalloc(sizeof(struct touch_cmd_info), GFP_KERNEL);
		if (!pdata->touch_cmd_data[i]) {
			ret = -ENOMEM;
			pr_err("%s alloc mem for param buf data\n", __func__);
			goto parse_dt_err;
		}
	}

	pdata->param_head = 0;
	pdata->param_tail = 0;
	pdata->param_flag = 0;

	for (i = 0; i < RAW_BUF_NUM; i++) {
		pdata->raw_buf[i] =
			(unsigned int *)kzalloc(RAW_SIZE, GFP_KERNEL);
		if (!pdata->raw_buf[i]) {
			ret = -ENOMEM;
			pr_err("%s alloc mem for raw buf data\n", __func__);
			goto parse_dt_err;
		}
	}
	pdata->raw_head = 0;
	pdata->raw_tail = 0;
	pdata->phy_base = virt_to_phys(pdata->raw_data);
	pr_info("%s: kernel base:%lld, phy base:%lld\n", __func__,
		(unsigned long)pdata->raw_data, (unsigned long)pdata->phy_base);
	spin_lock_init(&pdata->raw_lock);
	ret = xiaomi_touch_parse_dt(dev, pdata);
	if (ret < 0) {
		pr_err("%s parse dt error:%d\n", __func__, ret);
		goto parse_dt_err;
	}

	ret = misc_register(&xiaomi_touch_dev.misc_dev);
	if (ret) {
		pr_err("%s create misc device err:%d\n", __func__, ret);
		goto parse_dt_err;
	}
	xiaomi_touch_device = &xiaomi_touch_dev;
	if (!xiaomi_touch_dev.class)
		xiaomi_touch_dev.class = class_create(THIS_MODULE, "touch");

	if (!xiaomi_touch_dev.class) {
		pr_err("%s create device class err\n", __func__);
		goto class_create_err;
	}

	xiaomi_touch_dev.dev = device_create(xiaomi_touch_dev.class, NULL, 'T',
					     NULL, "touch_dev");
	if (!xiaomi_touch_dev.dev) {
		pr_err("%s create device dev err\n", __func__);
		goto device_create_err;
	}

	pdata->touch_data[0] = (struct xiaomi_touch_interface *)kzalloc(
		sizeof(struct xiaomi_touch_interface), GFP_KERNEL);
	if (pdata->touch_data[0] == NULL) {
		ret = -ENOMEM;
		pr_err("%s alloc mem for touch_data\n", __func__);
		goto data_mem_err;
	}
	pdata->touch_data[1] = (struct xiaomi_touch_interface *)kzalloc(
		sizeof(struct xiaomi_touch_interface), GFP_KERNEL);
	if (pdata->touch_data[1] == NULL) {
		ret = -ENOMEM;
		pr_err("%s alloc mem for touch_data\n", __func__);
		goto sys_group_err;
	}

	pdata->last_touch_events = (struct last_touch_event *)kzalloc(
		sizeof(struct last_touch_event), GFP_KERNEL);
	if (pdata->last_touch_events == NULL) {
		ret = -ENOMEM;
		pr_err("%s: alloc mem for last touch evnets\n", __func__);
		goto sys_group_err;
	}
	pdata->device = &xiaomi_touch_dev;
	dev_set_drvdata(xiaomi_touch_dev.dev, pdata);

	init_waitqueue_head(&pdata->touch_data[0]->wait_queue);
	init_waitqueue_head(&pdata->touch_data[1]->wait_queue);
	init_waitqueue_head(&pdata->touch_data[0]->wait_queue_ready);
	init_waitqueue_head(&pdata->touch_data[1]->wait_queue_ready);

	touch_pdata = pdata;

	xiaomi_touch_dev.attrs.attrs = touch_attr_group;
	ret = sysfs_create_group(&xiaomi_touch_dev.dev->kobj,
				 &xiaomi_touch_dev.attrs);
	if (ret) {
		pr_err("%s ERROR: Cannot create sysfs structure!:%d\n",
		       __func__, ret);
		ret = -ENODEV;
		goto sys_group_err;
	}
	pdata->last_touch_events_proc = proc_create_seq(
		"last_touch_events", 0644, NULL, &last_touch_events_seq_ops);

	pdata->tp_hal_version_proc =
		proc_create("tp_hal_version", 0644, NULL, &tp_hal_version_ops);

	pr_info("%s over\n", __func__);

	return ret;

sys_group_err:
	if (pdata->touch_data[0]) {
		kfree(pdata->touch_data[0]);
		pdata->touch_data[0] = NULL;
	}
	if (pdata->touch_data[1]) {
		kfree(pdata->touch_data[1]);
		pdata->touch_data[1] = NULL;
	}
	if (pdata->last_touch_events) {
		kfree(pdata->last_touch_events);
		pdata->last_touch_events = NULL;
	}
data_mem_err:
	device_destroy(xiaomi_touch_dev.class, 'T');
device_create_err:
	class_destroy(xiaomi_touch_dev.class);
	xiaomi_touch_dev.class = NULL;
class_create_err:
	misc_deregister(&xiaomi_touch_dev.misc_dev);
parse_dt_err:
	if (pdata->raw_data) {
		kfree(pdata->raw_data);
		pdata->raw_data = NULL;
	}
	for (i = 0; i < RAW_BUF_NUM; i++) {
		if (pdata->raw_buf[i]) {
			kfree(pdata->raw_buf[i]);
			pdata->raw_buf[i] = NULL;
		}
	}

	for (i = 0; i < PARAM_BUF_NUM; i++) {
		if (pdata->touch_cmd_data[i]) {
			kfree(pdata->touch_cmd_data[i]);
			pdata->touch_cmd_data[i] = NULL;
		}
	}
	pr_err("%s fail!\n", __func__);
	return ret;
}

static int xiaomi_touch_remove(struct platform_device *pdev)
{
	int i;

	sysfs_remove_group(&xiaomi_touch_dev.dev->kobj,
			   &xiaomi_touch_dev.attrs);
	device_destroy(xiaomi_touch_dev.class, 'T');
	class_destroy(xiaomi_touch_dev.class);
	xiaomi_touch_dev.class = NULL;
	misc_deregister(&xiaomi_touch_dev.misc_dev);
	if (touch_pdata->raw_data) {
		kfree(touch_pdata->raw_data);
		touch_pdata->raw_data = NULL;
	}

	for (i = 0; i < RAW_BUF_NUM; i++) {
		if (touch_pdata->raw_buf[i]) {
			kfree(touch_pdata->raw_buf[i]);
			touch_pdata->raw_buf[i] = NULL;
		}
	}

	if (touch_pdata->last_touch_events) {
		kfree(touch_pdata->last_touch_events);
		touch_pdata->last_touch_events = NULL;
	}
	if (touch_pdata->last_touch_events_proc != NULL) {
		remove_proc_entry("last_touch_events", NULL);
		touch_pdata->last_touch_events_proc = NULL;
	}

	if (touch_pdata->tp_hal_version_proc != NULL) {
		remove_proc_entry("tp_hal_version", NULL);
		touch_pdata->tp_hal_version_proc = NULL;
	}

	if (touch_pdata->touch_data[0]) {
		kfree(touch_pdata->touch_data[0]);
		touch_pdata->touch_data[0] = NULL;
	}
	if (touch_pdata->touch_data[1]) {
		kfree(touch_pdata->touch_data[1]);
		touch_pdata->touch_data[1] = NULL;
	}

	knock_node_release();

	return 0;
}

static struct platform_driver
	xiaomi_touch_device_driver = { .probe = xiaomi_touch_probe,
				       .remove = xiaomi_touch_remove,
				       .driver = {
					       .name = "xiaomi-touch",
					       .of_match_table = of_match_ptr(
						       xiaomi_touch_of_match),
				       } };

static int __init xiaomi_touch_init(void)
{
	return platform_driver_register(&xiaomi_touch_device_driver);
}

static void __exit xiaomi_touch_exit(void)
{
	platform_driver_unregister(&xiaomi_touch_device_driver);
}

MODULE_LICENSE("GPL");

module_init(xiaomi_touch_init);
module_exit(xiaomi_touch_exit);
