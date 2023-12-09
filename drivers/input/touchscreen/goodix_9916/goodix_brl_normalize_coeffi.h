typedef struct __attribute__((packed)) {
	u16 smp_point_num;
	u16 freq_factor;
	u8 gain_c;
	u8 dump_ssl;
	u8 rx_num;
	u8 tx_num;
	u16 version;
	u16 freq_scan_state;
	u16 flash_write_time;
	u16 config_checksum;
} normalize_k_head_t;

struct normalize_k_param {
	normalize_k_head_t head;
	int size;
	u16 *data;
};
