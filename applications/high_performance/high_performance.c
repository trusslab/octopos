#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <pthread.h>
#include <sys/stat.h>
#include <octopos/runtime.h>

char output_buf[64];
int num_chars = 0;
//pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
#define secure_printf(fmt, args...) {memset(output_buf, 0x0, 64); sprintf(output_buf, fmt, ##args);	\
					 ((struct runtime_api *)api)->write_to_secure_serial_out(output_buf);}

#define insecure_printf(fmt, args...) {memset(output_buf, 0x0, 64); num_chars = sprintf(output_buf, fmt, ##args);\
					 ((struct runtime_api *)api)->write_to_shell(output_buf, num_chars);}

void *sendThread(void *api)
{
	char line[1024];
	int size;
	uint8_t target_qid = 17;
  int ret;

//  pthread_mutex_lock(&mutex);
	uint8_t own_qid = ((struct runtime_api *)api)->get_runtime_queue_id();
//
//	/* send message */
//	insecure_printf("%c", own_qid);
//
//	/* receive response */
//	int ret = ((struct runtime_api *)api)->read_from_shell(line, &size);
//	if (ret || size == 0) {
//		printf("%s: Didn't receive a valid response\n", __func__);
//		return NULL;
//	}
//
//	target_qid = line[0];
//	printf("%s: Received response: target_qid = %d (size = %d)\n",
//         __func__, target_qid, size);
	/* secure IPC */
	ret = ((struct runtime_api *)api)->request_secure_ipc(target_qid, 200, 100, NULL);
	if (ret) {
		printf("%s: Couldn't establish secure IPC (ret = %d)\n",
           __func__, ret);
		return NULL;
	}
//  pthread_mutex_unlock(&mutex);

  char secure_msg[64] = "secure msg 1";
	int secure_msg_size = sizeof("secure msg 1");
  ((struct runtime_api *)api)->send_msg_on_secure_ipc(secure_msg, secure_msg_size);

  ((struct runtime_api *)api)->recv_msg_on_secure_ipc(secure_msg, &secure_msg_size);
	printf("%s: Received secure msg: %s (size = %d)\n",
         __func__, secure_msg, secure_msg_size);

  ((struct runtime_api *)api)->yield_secure_ipc();

  return NULL;
}

void *receiveThread(void *api)
{
  char line[1024];
  int size;
  uint8_t target_qid = 17;
  uint8_t own_qid = ((struct runtime_api *)api)->get_runtime_queue_id();
  int ret;

//  /* receive message */
//  int ret = ((struct runtime_api *)api)->read_from_shell(line, &size);
//  if (ret || size == 0) {
//    printf("%s: Didn't receive a valid response\n", __func__);
//    return NULL;
//  }
//
//  target_qid = line[0];
//  printf("%s: Received response: target_qid = %d (size = %d)\n",
//         __func__, target_qid, size);
//
//  /* send response */
//  insecure_printf("%c", own_qid);

  /* secure IPC */
  ret = ((struct runtime_api *)api)->request_secure_ipc(target_qid, 200, 100, NULL);
  if (ret) {
    printf("%s: Couldn't establish secure IPC (ret = %d)\n",
           __func__, ret);
    return NULL;
  }

  char secure_msg[64];
  int secure_msg_size;

  ((struct runtime_api *)api)->recv_msg_on_secure_ipc(secure_msg, &secure_msg_size);
  printf("%s: Received secure msg: %s (size = %d)\n",
         __func__, secure_msg, secure_msg_size);

  strcpy(secure_msg, "secure msg 2");
  secure_msg_size = sizeof("secure msg 2");
  ((struct runtime_api *)api)->send_msg_on_secure_ipc(secure_msg, secure_msg_size);
  ((struct runtime_api *)api)->yield_secure_ipc();

  return NULL;
}

extern "C" __attribute__ ((visibility ("default")))
void app_main(struct runtime_api *api)
{
	pthread_t sender_thread, receiver_thread;
	pthread_create(&sender_thread, NULL, sendThread, api);
  pthread_create(&receiver_thread, NULL, receiveThread, api);

  pthread_join(sender_thread, NULL);
  pthread_join(receiver_thread, NULL);

	pthread_exit(NULL);
}
