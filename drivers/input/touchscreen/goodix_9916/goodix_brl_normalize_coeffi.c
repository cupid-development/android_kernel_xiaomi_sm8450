#include "goodix_ts_core.h"
#include "goodix_brl_normalize_coeffi.h"

void goto_next_line(char **ptr);

unsigned char panel_lockdown[8] = { 0x53, 0x42, 0x32, 0x03,
				    0x4d, 0x31, 0x32, 0x01 };

struct normalize_k_param normalize_k_array[20];

#define next_token()                                                           \
	token = strsep(&ptr, ",");                                             \
	if (token == NULL || kstrtoint(token, 10, &tmp) != 0)                  \
	goto parse_err

int goodix_normalize_coeffi_update(struct goodix_ts_core *cd)
{
	const struct firmware *fw = NULL;
	int rc, i, tmp, j, k;
	unsigned char buf[8] = { 0 };
	u64 unknown;
	char *csv_file;
	char *csv_buf;
	char target_name[6];
	char *ptr, *token;
	char *buf0 = NULL, *buf1 = NULL;

	if (cd == NULL) {
		return -1;
	}

	rc = cd->hw_ops->read(cd, TS_LOCKDOWN_REG, buf, sizeof(buf));
	if (rc != 0) {
		ts_err("read lockdown info failed! cnt: %d", 1);
		rc = cd->hw_ops->read(cd, TS_LOCKDOWN_REG, buf, sizeof(buf));
		if (rc != 0) {
			ts_err("read lockdown info failed! cnt: %d", 2);
			return -1;
		}
	}

	if (memcmp(buf, panel_lockdown, sizeof(buf)) == 0) {
		ts_info("use glass ceramic normalize file");
		unknown = 0x7673632e315f;
		csv_file = "goodix_normalize_1.csv";
	} else {
		ts_info("use glass normal normalize file");
		unknown = 0x7673632e;
		csv_file = "goodix_normalize.csv";
	}

	ts_info("k_file_name:%s", csv_file);
	rc = request_firmware(&fw, csv_file, &cd->pdev->dev);
	if (rc < 0) {
		ts_err("normalize k file [%s] not available", csv_file);
		return -EINVAL;
	}

	if (fw->size < 100) {
		ts_err("request_firmware, normalize param length error,len:%zu",
		       fw->size);
		return -EINVAL;
	}

	csv_buf = kzalloc(fw->size + 1, GFP_KERNEL);
	if (csv_buf == NULL) {
		ts_err("kzalloc failed");
		return -ENOMEM;
	}

	if (cd->ic_info.parm.mutual_freq_num != 0) {
		for (i = 0; i < cd->ic_info.parm.mutual_freq_num; i++) {
			sprintf(target_name, "freq%d", i);
			memcpy(csv_buf, fw->data, fw->size);
			if (fw->size == 0) {
				rc = -ENXIO;
				continue;
			}
			normalize_k_array[i] =
				(const struct normalize_k_param){ 0 };
			ptr = strstr(csv_buf, target_name);
			if (ptr == NULL) {
			parse_err:
				ts_err("load %s failed 1, maybe not this item",
				       target_name);
				rc = -4;
			other_err:
				ts_err("get target[%s] fail", target_name);
				continue;
			}
			strsep(&ptr, ",");
			next_token();
			normalize_k_array[i].head.smp_point_num = tmp;
			next_token();
			normalize_k_array[i].head.freq_factor = tmp;
			next_token();
			normalize_k_array[i].head.gain_c = tmp;
			next_token();
			normalize_k_array[i].head.dump_ssl = tmp;
			next_token();
			normalize_k_array[i].head.rx_num = tmp;
			next_token();
			normalize_k_array[i].head.tx_num = tmp;
			next_token();
			normalize_k_array[i].head.version = tmp;
			next_token();
			normalize_k_array[i].head.freq_scan_state = tmp;
			next_token();
			normalize_k_array[i].head.flash_write_time = tmp;
			normalize_k_array[i].size =
				normalize_k_array[i].head.tx_num *
				normalize_k_array[i].head.rx_num;
			normalize_k_array[i].data =
				kmalloc(normalize_k_array[i].size * sizeof(u16),
					GFP_KERNEL);
			if (normalize_k_array[i].data == NULL) {
				goto other_err;
			}
			goto_next_line(&ptr);
			if (ptr == NULL || *ptr == '\0') {
				rc = -5;
				if (normalize_k_array[i].data != NULL) {
					kfree(normalize_k_array[i].data);
					normalize_k_array[i].data = 0;
				}
				normalize_k_array[i].size = 0;
				goto other_err;
			}
			if (normalize_k_array[i].size > 0) {
				for (j = 0;
				     j < normalize_k_array[i].head.tx_num;
				     j++) {
					for (k = 0;
					     k <
					     normalize_k_array[i].head.rx_num;
					     k++) {
						token = strsep(&ptr, ",");
						if (token == NULL ||
						    kstrtoint(token, 10,
							      &tmp) != 0) {
							rc = -4;

							if (normalize_k_array[i]
								    .data !=
							    NULL) {
								kfree(normalize_k_array[i]
									      .data);
								normalize_k_array[i]
									.data =
									0;
							}
							normalize_k_array[i]
								.size = 0;
							goto other_err;
						}
						normalize_k_array[i].data
							[j * normalize_k_array[i]
									 .head
									 .rx_num +
							 k] = tmp;
					}
					goto_next_line(&ptr);
					if (ptr == NULL || *ptr == '\0') {
						rc = -5;
						if (normalize_k_array[i].data !=
						    NULL) {
							kfree(normalize_k_array[i]
								      .data);
							normalize_k_array[i]
								.data = 0;
						}
						normalize_k_array[i].size = 0;
						goto other_err;
					}
				}
			}
			ts_info("get target[%s] ok", target_name);
			rc = 0;

			// read rx x tx num data
		}
	}
	kfree(csv_buf);
	if (fw != NULL) {
		release_firmware(fw);
	}

	if (rc < 0) {
		ts_err("parse normalize k file failed");
	} else if ((normalize_k_array[0].size == 0) ||
		   (normalize_k_array[0].data == NULL)) {
		ts_err("can't find valid normalize param, skip update normalize coeffi");
		rc = 0;
	} else {
		if (cd->ic_info.other.normalize_k_version == 0xffff) {
			ts_info("current normalize K version 0x%x, need update",
				0xffff);
		} else {
			if (normalize_k_array[0].head.version ==
			    cd->ic_info.other.normalize_k_version) {
				ts_info("no need update normalize coeffi, k version: %d\n",
					normalize_k_array[0].head.version);
				rc = 0;
				goto clean_up;
			}
			ts_info("K version unequal need update 0x%x != 0x%x",
				normalize_k_array[0].head.version,
				cd->ic_info.other.normalize_k_version);
		}

		buf0 = kzalloc(0x4000, GFP_KERNEL);
		buf1 = kzalloc(0x4000, GFP_KERNEL);
		if (buf0 == NULL || buf1 == NULL) {
			ts_err("kzalloc failed");
			rc = -1;
			goto clean_up_more;
		}

		// TODO
	}

clean_up_more:
	if (buf0 != NULL) {
		kfree(buf0);
	}
	if (buf1 != NULL) {
		kfree(buf1);
	}
	return rc;

clean_up:
	for (i = 0; i < 10; i++) {
		kfree(normalize_k_array[i].data);
		normalize_k_array[i].data = NULL;
	}
	return rc;
}