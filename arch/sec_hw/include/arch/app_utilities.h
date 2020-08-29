#ifndef SRC_OCTOPOS_ARCH_INCLUDE_ARCH_APP_UTILITIES_H_
#define SRC_OCTOPOS_ARCH_INCLUDE_ARCH_APP_UTILITIES_H_


#define secure_printf(fmt, args...) do								\
	{char output_buf[64];									\
	memset(output_buf, 0x0, 64); sprintf(output_buf, fmt, ##args);				\
					 api->write_to_secure_serial_out(output_buf);}while(0)	\

#define insecure_printf(fmt, ...)								\
	do {char output_buf[64];								\
	int num_chars = 0;									\
	memset(output_buf, 0x0, 64);  						 		\
	num_chars = snprintf(output_buf, 61, fmt "\r\n", ##__VA_ARGS__);			\
	if (num_chars > 61) num_chars = 61;							\
	api->write_to_shell(output_buf, num_chars);} while(0)


#endif /* SRC_OCTOPOS_ARCH_INCLUDE_ARCH_APP_UTILITIES_H_ */
