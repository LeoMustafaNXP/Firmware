/**
 * @file d2xsign.cpp
 * TODO Description
 *
 * @author Leutrim Mustafa <leo.mustafa@nxp.com>
 * @author Jannik Beyerstedt <jannik.beyerstedt@nxp.com>
 */

#include <poll.h>
#include <px4_config.h>
#include <px4_posix.h>
#include <px4_tasks.h>
#include <unistd.h>

// includes for uORB and mavlink communication
#include <uORB/uORB.h>
#include <uORB/topics/debug_key_value.h>
#include <uORB/topics/heartbeatsign.h>
#include <uORB/topics/nfc_rx.h>
#include <uORB/topics/nfc_test.h>
#include <uORB/topics/nfc_tx.h>
#include <uORB/topics/sensor_combined.h>
#include <uORB/topics/vehicle_attitude.h>
#include <uORB/topics/vehicle_status.h>
#include <uORB/topics/led_control.h> // uORB for led_control

// includes for mbedtls
#if !defined(MBEDTLS_CONFIG_FILE)
#include <mbedtls/config.h>
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/entropy.h>
#include <mbedtls/pk.h>
#include <mbedtls/sha256.h>
#include <mbedtls/x509.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/x509_csr.h>

#if defined(MBEDTLS_PLATFORM_C)
#include <mbedtls/platform.h>
#else
#include <cstdio>
#include <cstdlib>
#define mbedtls_printf          printf
#define MBEDTLS_EXIT_SUCCESS    EXIT_SUCCESS
#define MBEDTLS_EXIT_FAILURE    EXIT_FAILURE
#endif /* MBEDTLS_PLATFORM_C */

#if !defined(MBEDTLS_ECDSA_C) || !defined(MBEDTLS_SHA256_C) || \
    !defined(MBEDTLS_ENTROPY_C) || !defined(MBEDTLS_CTR_DRBG_C)
#error MBEDTLS_ECDSA_C and/or MBEDTLS_SHA256_C and/or MBEDTLS_ENTROPY_C and/or MBEDTLS_CTR_DRBG_C not defined
#endif

#include <cmath>
#include <cstdio>
#include <cstring>



/* GLOBAL DEFINITIONS AND TYPES */
#define UID_LEN_BYTE        18      // byte of secure element unique ID

// set crypto algorithms and drone information
#define ECC_CURVE       MBEDTLS_ECP_DP_SECP256R1
#define HASH_TYPE       MBEDTLS_MD_SHA256
#define HASH_LEN        32          // byte for hash buffer

#define CSR_SUBJECT         "C=DE,O=NXP,CN=UAV2,serialNumber="
#define CSR_SUBJECT_MAX     70 // 25 + len(O) + len(CN) + 2*UID_LEN_BYTE
#define SERIAL_NUMBER       "112233445566778899aabbccddeeff112233"  // TODO: get from security module
#define CSR_MD_ALG          HASH_TYPE

// local keystore (TODO: integrate hardware security module)
#define PRIVKEY_FILE        "/fs/microsd/keystore/UavPrivKey.key"
#define PRIVKEY_FILESIZE    300     // byte for buffer of PEM encoded file
#define CSR_FILE            "/fs/microsd/keystore/UavCsr.csr"
#define CSR_FILESIZE        800     // byte for buffer of PEM encoded file
#define CERT_FILE           "/fs/microsd/keystore/UavCrt.crt"
#define ROOTCA_FILE         "/fs/microsd/keystore/rootca.crt"
#define INTERMCA_FILE       "/fs/microsd/keystore/intermca.crt"
#define CERTS_FILESIZE      800     // byte for buffer of PEM encoded file

// NFC commands and companion controller communication
#define DATAID_ACK      0
#define DATAID_ROOTCA   1
#define DATAID_CSR      2
#define DATAID_CERT     3

#define MAXMSGP                             10
#define MAVLINK_MSG_NFC_FIELD_NFC_ID_LEN    8
#define MAVLINK_MSG_NFC_FIELD_DATA_LEN      200

//#define WAITTIME        5 // in sec
#define WAITTIMEACK     5 // in sec

// command handling state machine
enum MainStates {
	state_init,
	state_wait,
	state_recvRootCA,
	state_recvDroneCert,
	state_generateCsr,
	state_sendDataCsr,
	state_sendDataRootCa,
	state_sendSignMsg,
	state_stop
};

enum NfcCommands {
	nfcCmd_Ack      = DATAID_ACK,
	nfcCmd_Rootca   = DATAID_ROOTCA,
	nfcCmd_Csr      = DATAID_CSR,
	nfcCmd_Cert     = DATAID_CERT,
	nfcCmd_NULL     = 255
};


/* GLOBAL VARIABLES AND BUFFERS */

// state machine
bool run{false};
MainStates currentState{state_init};
bool event_nfcCmd{false};                      // triggers state transition from state_wait
NfcCommands event_nfcCmd_type{nfcCmd_NULL};    // NFC command type

// generic buffer
uint8_t ioBuffer[1024];

// NFC companion controller communication
struct nfc_rx_s nfc_rx;
int nfc_rx_sub_fd;
int nfc_rx_sub_fdACK;
//int nfc_tx_sub_fd;
uint8_t BufRxNfcData[MAXMSGP][MAVLINK_MSG_NFC_FIELD_DATA_LEN];
uint8_t RxNfcID_s[MAVLINK_MSG_NFC_FIELD_NFC_ID_LEN] = {0};
int8_t recvACK = 0;

// TODO: move to main function's stack and give to functions (by reference)!!!
time_t t;
struct timespec _ts;
long start_time = 0;
long end_time = 0;
long start_timeACK = 0;
long end_timeACK = 0;

// Led control
struct led_control_s led_control;	// structur with led_control paramters


/* FUNCTION DECLARATIONS */
void nfcCom_send(const uint8_t *buf, size_t dataLen, nfc_rx_s nfc_rx_data, uint8_t dataId);
void nfcCom_waitAck();
void nfcCom_sendAck();
int read_file_to_buffer(uint8_t *buf, size_t buflen, const char *input_file);
int write_file_from_buffer(const uint8_t *buf, size_t buflen, const char *output_file);

// crypto
int generate_keypair(mbedtls_pk_context *pk_ctx);
static int write_uav_key(mbedtls_pk_context *key, const char *output_file);
int load_uav_key(mbedtls_pk_context *key, const char *input_file);
int generate_and_save_csr(mbedtls_pk_context *key, const char *output_file);
int load_cert(mbedtls_x509_crt *cert, const char *input_file);

// debug helpers
static void dump_pubkey(const char *title, mbedtls_ecdsa_context *key);
static void dump_privkey(const char *title, mbedtls_ecdsa_context *key);
static void dump_buf(const char *title, const unsigned char *buf, size_t len);

extern "C" __EXPORT int d2xsign_main(int argc, char *argv[]);


/*
 * MAIN APPLICATION
 */
int d2xsign_main(__attribute__((unused))int argc, __attribute__((unused))char *argv[])
{
	PX4_INFO("Hello UAVsign!");
	currentState = state_init;
	run = true;

	// uORB topic subscription
	nfc_rx_sub_fd = orb_subscribe(ORB_ID(nfc_rx));
	px4_pollfd_struct_t fds[] = {{}}; // possibility to wait for multiple topics, but using one here
	fds[0].fd = nfc_rx_sub_fd;
	fds[0].events = POLLIN;

	// uORB Led Control
	memset(&led_control, 0, sizeof(led_control));                                    // fill the structure with 0
	orb_advert_t led_control_pub = orb_advertise(ORB_ID(led_control), &led_control); // advertise structure for ORB_ID

	// mbedtls contexts (already init them here, because of error exit tidy up)
	mbedtls_pk_context pk_ctx;
	mbedtls_pk_init(&pk_ctx);

	mbedtls_x509_crt uav_cert;
	mbedtls_x509_crt_init(&uav_cert);

	mbedtls_x509_crt rootca_cert;
	mbedtls_x509_crt_init(&rootca_cert);
	mbedtls_x509_crt intermca_cert;
	mbedtls_x509_crt_init(&intermca_cert);

	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_ctr_drbg_init(&ctr_drbg);

	// other shared variables
	int ret;    // misc function return codes


	while (run) {
		/* poll NFC commands from uORB */
		px4_poll(fds, 1, 5);

		//event_nfcCmd = false;
		if ((fds[0].revents & POLLIN) != 0) {
			orb_copy(ORB_ID(nfc_rx), nfc_rx_sub_fd, &nfc_rx);
			recvACK = 0;

			switch (nfc_rx.data_id) {
			case (DATAID_ACK):
				event_nfcCmd_type = nfcCmd_Ack;
				break;

			case (DATAID_ROOTCA):
				event_nfcCmd_type = nfcCmd_Rootca;
				break;

			case (DATAID_CSR):
				event_nfcCmd_type = nfcCmd_Csr;
				break;

			case (DATAID_CERT):
				event_nfcCmd_type = nfcCmd_Cert;
				break;

			default:
				event_nfcCmd_type = nfcCmd_NULL;
			}

			if (nfc_rx.data_id != DATAID_ACK) {
				event_nfcCmd = true;

				printf("Recieve Mavlink Message: \n");
				printf("NFC_ID:		");

				for (uint8_t i = 0; i < sizeof(nfc_rx.nfc_id); i++) {
					printf("%02X", nfc_rx.nfc_id[i]);
					sprintf(reinterpret_cast<char *>(&RxNfcID_s[i * 2]), "%02X", nfc_rx.nfc_id[i]);
				}

				printf("\n");

				printf("NFC_ID_s:	%s \n", RxNfcID_s);
				printf("NFC_Data_ID:	%i\n", nfc_rx.data_id);
				printf("NFC_Data_Len:	%i\n", nfc_rx.data_len);
				printf("NFC_Data_nr:	%i\n", nfc_rx.data_nr);



				printf("NFC_Data:	");

				for (uint8_t i = 0; i < sizeof(nfc_rx.data); i++) {
					printf("%c", nfc_rx.data[i]);
					BufRxNfcData[nfc_rx.data_nr][i] = nfc_rx.data[i];
				}

				printf("\n\n");

				nfcCom_sendAck();

			} else {
				printf("Recieve ACK \n");
				recvACK = 1;
			}
		}

		/* evaluate main state machine */
		switch (currentState) {
		case state_init:

			/* [THIS STATE: DO ACTIONS] */
			PX4_INFO("loading private key from file...");

			ret = load_uav_key(&pk_ctx, PRIVKEY_FILE);

			if (MBEDTLS_ERR_PK_FILE_IO_ERROR == ret) {
				// no private key file: so probably first startup -> generate new keypair
				PX4_INFO("generating an new ECC key pair...");

				if ((ret = generate_keypair(&pk_ctx)) != 0) {
					usleep(100 * 1000); // wait for printf output
					PX4_ERR("generate_keypair ERROR -0x%04X", -ret);
				}

				PX4_INFO("writing private key to file...");

				if ((ret = write_uav_key(&pk_ctx, PRIVKEY_FILE)) != 0) {
					usleep(100 * 1000); // wait for printf output
					PX4_ERR("write_uav_key ERROR -0x%04X", -ret);
				}

			} else if (0 != ret) {
				usleep(100 * 1000); // wait for printf output
				PX4_ERR("load_uav_key ERROR -0x%04X", -ret);

				/* [STATE TRANSITION] */
				currentState = state_stop;
				/* [THIS STATE: EXIT ACTIONS] */
				// none
				/* [NEXT STATE: ENTRY ACTIONS] */
				PX4_INFO("----- ENTRY state_stop -----");

				break;
			}

			dump_pubkey(" + Pub:  ", mbedtls_pk_ec(pk_ctx));            // debug
			dump_privkey(" + Priv: ", mbedtls_pk_ec(pk_ctx));           // debug

			PX4_INFO("loading root CA certificate from file...");

			if ((ret = load_cert(&rootca_cert, ROOTCA_FILE)) != 0) {
				PX4_ERR("load_cert ERROR -0x%04X", -ret);
				PX4_ERR("TODO: unhandled error, see previous messages");
			}

			PX4_INFO("loading intermediate CA certificate from file...");

			if ((ret = load_cert(&intermca_cert, INTERMCA_FILE)) != 0) {
				PX4_ERR("load_cert ERROR -0x%04X", -ret);
				PX4_ERR("TODO: unhandled error, see previous messages");
			}

			// set led to RED FAST BLINKING
			//led_control.num_blinks = 10;                     // bkinks
			led_control.priority = led_control_s::MAX_PRIORITY; // priority
			led_control.mode = led_control_s::MODE_BLINK_NORMAL;  // led mode
			led_control.led_mask = 0xff;                     // select leds - 0xff for all
			led_control.color = led_control_s::COLOR_RED;     // color

			orb_publish(ORB_ID(led_control), led_control_pub, &led_control); // publish the message to uORB service

			/* [STATE TRANSITION] */
			currentState = state_wait;
			/* [THIS STATE: EXIT ACTIONS] */
			// none
			/* [NEXT STATE: ENTRY ACTIONS] */
			PX4_INFO("----- ENTRY state_wait -----");
			break;

		case state_wait:

			/* [THIS STATE: DO ACTIONS] */
			// none

			if (event_nfcCmd) {
				event_nfcCmd = false; // reset the flag

				if (nfc_rx.data_nr == nfc_rx.data_len) {
					switch (event_nfcCmd_type) {
					case nfcCmd_Ack:
						PX4_INFO("incoming NFC command: ACK");

						/* [STATE TRANSITION] */
						currentState = state_wait; // self-transition
						//* [THIS STATE: EXIT ACTIONS] */
						// none
						/* [NEXT STATE: ENTRY ACTIONS] */
						PX4_INFO("----- ENTRY state_wait -----");
						break;

					case nfcCmd_Rootca:
						PX4_INFO("incoming NFC command: ROOTCA");

						/* [STATE TRANSITION] */
						currentState = state_recvRootCA;
						//* [THIS STATE: EXIT ACTIONS] */
						// none
						/* [NEXT STATE: ENTRY ACTIONS] */
						PX4_INFO("----- ENTRY state_recvRootCA -----");

						// set LED AMBER NORMAL BLINKING
						//led_control.num_blinks = 10;                     // bkinks
						led_control.priority = led_control_s::MAX_PRIORITY; // priority
						led_control.mode = led_control_s::MODE_BLINK_NORMAL;  // led mode
						led_control.led_mask = 0xff;                     // select leds - 0xff for all
						led_control.color = led_control_s::COLOR_AMBER;     // color

						orb_publish(ORB_ID(led_control), led_control_pub, &led_control); // publish the message to uORB service
						break;

					case nfcCmd_Csr:
						PX4_INFO("incoming NFC command: CSR");

						/* [STATE TRANSITION] */
						currentState = state_wait; // self-transition
						//* [THIS STATE: EXIT ACTIONS] */
						// none
						/* [NEXT STATE: ENTRY ACTIONS] */
						PX4_INFO("----- ENTRY state_wait -----");
						break;

					case nfcCmd_Cert:
						PX4_INFO("incoming NFC command: CERT");

						/* [STATE TRANSITION] */
						currentState = state_recvDroneCert;
						//* [THIS STATE: EXIT ACTIONS] */
						// none
						/* [NEXT STATE: ENTRY ACTIONS] */
						PX4_INFO("----- ENTRY state_recvDroneCert -----");
						break;

					default:
						PX4_ERR("ERROR: incoming NFC command unknown");
					}
				}
			}

			break;

		case state_recvRootCA:

			/* [THIS STATE: DO ACTIONS] */
			memset(ioBuffer, 0x00, sizeof(ioBuffer));

			if (nfc_rx.data_nr == nfc_rx.data_len) {
				PX4_INFO("Recieve RootCA!");

				for (int a = 1; a <= nfc_rx.data_len; a++) {
					for (int b = 0; b < MAVLINK_MSG_NFC_FIELD_DATA_LEN; b++) {
						printf("%c", BufRxNfcData[a][b]);               // debug
						ioBuffer[(MAVLINK_MSG_NFC_FIELD_DATA_LEN * (a - 1) + b)] = BufRxNfcData[a][b];
					}
				}

				printf("\n");

				PX4_INFO("received data len: %i", (nfc_rx.data_len * MAVLINK_MSG_NFC_FIELD_DATA_LEN));

				// save the reveived certificate data to file
				if (write_file_from_buffer(ioBuffer, strlen(reinterpret_cast<const char *>(ioBuffer)), ROOTCA_FILE) != 0) {
					PX4_ERR("TODO: unhandled error, see previous messages");
				}

				// load the root CA certificate
				if (load_cert(&rootca_cert, ROOTCA_FILE) != 0) {
					PX4_ERR("TODO: unhandled error, see previous messages");
				}
			}

			/* [STATE TRANSITION] */
			currentState = state_generateCsr;
			//* [THIS STATE: EXIT ACTIONS] */
			// none
			/* [NEXT STATE: ENTRY ACTIONS] */
			PX4_INFO("----- ENTRY state_generateCsr -----");
			break;

		case state_recvDroneCert:

			/* [THIS STATE: DO ACTIONS] */
			memset(ioBuffer, 0x00, sizeof(ioBuffer));

			if (nfc_rx.data_nr == nfc_rx.data_len) {
				PX4_INFO("Recieve Cert!");

				for (int a = 1; a <= nfc_rx.data_len; a++) {
					for (int b = 0; b < MAVLINK_MSG_NFC_FIELD_DATA_LEN; b++) {
						printf("%c", BufRxNfcData[a][b]);
						ioBuffer[(MAVLINK_MSG_NFC_FIELD_DATA_LEN * (a - 1) + b)] = BufRxNfcData[a][b];
					}
				}

				printf("\n");

				PX4_INFO("received data len: %i", (nfc_rx.data_len * MAVLINK_MSG_NFC_FIELD_DATA_LEN));

				// save the reveived certificate data to file
				if (write_file_from_buffer(ioBuffer, (nfc_rx.data_len * MAVLINK_MSG_NFC_FIELD_DATA_LEN), CERT_FILE) != 0) {
					PX4_ERR("TODO: unhandled error, see previous messages");
				}

				// load (and verify) own certificate
				if (load_cert(&uav_cert, CERT_FILE) != 0) {
					PX4_ERR("TODO: unhandled error, see previous messages");
				}

				// verify certificate chain of own certificate
				// TODO: not only root CA is needed, but also intermediate CA!
				uint32_t flags;

				if ((mbedtls_x509_crt_verify(&uav_cert, &rootca_cert, nullptr, nullptr, &flags, nullptr, nullptr)) == 0) {
					PX4_INFO("UAV certificate OK!");

				} else {
					// TODO: replace tempbuf with global buffer
					char tempbuf[1024];
					mbedtls_x509_crt_verify_info(tempbuf, sizeof(tempbuf), "ver: ", flags);
					puts(tempbuf);
					PX4_ERR("UAV certificate not ok!");
				}
			}

			/* [STATE TRANSITION] */
			currentState = state_sendDataRootCa;
			//* [THIS STATE: EXIT ACTIONS] */
			// none
			/* [NEXT STATE: ENTRY ACTIONS] */
			PX4_INFO("----- ENTRY state_sendDataRootCa -----");
			break;

		case state_generateCsr:
			/* [THIS STATE: DO ACTIONS] */
			PX4_INFO("generating an new ECC key pair...");

			if ((ret = generate_keypair(&pk_ctx)) != 0) {
				usleep(100 * 1000); // wait for printf output
				PX4_ERR("generate_keypair ERROR -0x%04X", -ret);
			}

			dump_pubkey(" + Pub:  ", mbedtls_pk_ec(pk_ctx));        // debug
			dump_privkey(" + Priv: ", mbedtls_pk_ec(pk_ctx));       // debug

			PX4_INFO("writing private key to file...");

			if ((ret = write_uav_key(&pk_ctx, PRIVKEY_FILE)) != 0) {
				usleep(100 * 1000); // wait for printf output
				PX4_ERR("write_uav_key ERROR -0x%04X", -ret);
			}

			usleep(100 * 1000); // wait for printf output
			PX4_INFO("generating CSR...");

			// generate CSR
			if ((ret = generate_and_save_csr(&pk_ctx, CSR_FILE)) != 0) {
				usleep(100 * 1000); // wait for printf output
				PX4_ERR("generate_and_save_csr ERROR -0x%04X", -ret);
			}

			/* [STATE TRANSITION] */
			currentState = state_sendDataCsr;
			//* [THIS STATE: EXIT ACTIONS] */
			// none
			/* [NEXT STATE: ENTRY ACTIONS] */
			PX4_INFO("----- ENTRY state_sendDataCsr -----");
			break;

		case state_sendDataCsr:
			/* [THIS STATE: DO ACTIONS] */
			sleep(1);
			memset(ioBuffer, 0x00, sizeof(ioBuffer));

			// read CSR from file to buffer
			ret = read_file_to_buffer(ioBuffer, sizeof(ioBuffer), CSR_FILE);

			if (ret <= 0) {
				PX4_ERR("TODO: unhandled error, see previous messages");
			}

			// send CSR file to NFC companion board
			nfcCom_send(ioBuffer, ret, nfc_rx, DATAID_CSR);

			/* [STATE TRANSITION] */
			currentState = state_wait;
			//* [THIS STATE: EXIT ACTIONS] */
			// none
			/* [NEXT STATE: ENTRY ACTIONS] */
			PX4_INFO("----- ENTRY state_wait -----");

			// set LED RED NORMAL BLINKING
			//led_control.num_blinks = 10;                     // bkinks
			led_control.priority = led_control_s::MAX_PRIORITY; // priority
			led_control.mode = led_control_s::MODE_BLINK_NORMAL;  // led mode
			led_control.led_mask = 0xff;                     // select leds - 0xff for all
			led_control.color = led_control_s::COLOR_RED;     // color

			orb_publish(ORB_ID(led_control), led_control_pub, &led_control); // publish the message to uORB service
			break;

		case state_sendDataRootCa:
			/* [THIS STATE: DO ACTIONS] */
			sleep(1);
			memset(ioBuffer, 0x00, sizeof(ioBuffer));

			// read CSR from file to buffer
			ret = read_file_to_buffer(ioBuffer, sizeof(ioBuffer), ROOTCA_FILE);

			if (ret <= 0) {
				PX4_ERR("TODO: unhandled error, see previous messages");
			}

			// send root CA file to NFC companion board
			nfcCom_send(ioBuffer, ret, nfc_rx, DATAID_ROOTCA);

			/* [STATE TRANSITION] */
			currentState = state_sendSignMsg;
			//* [THIS STATE: EXIT ACTIONS] */
			// none
			/* [NEXT STATE: ENTRY ACTIONS] */
			PX4_INFO("----- ENTRY state_sendSignMsg -----");
			break;

		case state_sendSignMsg: {
				/* [THIS STATE: DO ACTIONS] */
				uint8_t dataToSign[6] = {0};
				uint8_t txHash[64] = {0};
				uint8_t txSignature[64] = {0};
				size_t txSignature_len;

				struct heartbeatsign_s heartbeatsign_st  = {0};
				orb_advert_t heartbeatsign_pub_fd = orb_advertise(ORB_ID(heartbeatsign), &heartbeatsign_st);

				// create message, which should be signed
				heartbeatsign_st.basemode = 82;
				heartbeatsign_st.custommode = 67305985;
				heartbeatsign_st.systemstatus = 4;

				// copy data to sign to a continous buffer
				uint32_t bufccustommode = heartbeatsign_st.custommode;

				dataToSign[0] = heartbeatsign_st.basemode;
				dataToSign[4] = static_cast<uint8_t>(bufccustommode);
				dataToSign[3] = static_cast<uint8_t>(bufccustommode >> 8);
				dataToSign[2] = static_cast<uint8_t>(bufccustommode >> 16);
				dataToSign[1] = static_cast<uint8_t>(bufccustommode >> 24);
				dataToSign[5] = heartbeatsign_st.systemstatus;

				// compute signature
				PX4_INFO("computing message hash...");

				if ((ret = mbedtls_sha256_ret(dataToSign, sizeof(dataToSign), txHash, 0)) != 0) {
					usleep(100 * 1000); // wait for printf output
					PX4_ERR("mbedtls_sha256_ret ERROR -0x%04X", -ret);
					PX4_ERR("TODO: unhandled error, see previous messages");
				}

				dump_buf(" + Hash: ", txHash, sizeof(txHash));              // debug

				usleep(100 * 1000); // wait for printf output
				PX4_INFO("signing message...");

				if ((ret = mbedtls_pk_sign(&pk_ctx, HASH_TYPE, txHash, sizeof(txHash), txSignature, &txSignature_len,
							   mbedtls_ctr_drbg_random, &ctr_drbg)) != 0) {
					usleep(100 * 1000); // wait for printf output
					PX4_ERR("mbedtls_pk_sign ERROR -0x%04X", -ret);
					PX4_ERR("TODO: unhandled error, see previous messages");
				}

				dump_buf(" + Sign: ", txSignature, txSignature_len);        // debug

				// copy signature to message and send it out
				heartbeatsign_st.signlen = txSignature_len;
				memcpy(heartbeatsign_st.signature, txSignature, sizeof(heartbeatsign_st.signature));

				orb_publish(ORB_ID(heartbeatsign), heartbeatsign_pub_fd, &heartbeatsign_st);
			}


			/* [STATE TRANSITION] */
			currentState = state_wait;
			//* [THIS STATE: EXIT ACTIONS] */
			// none
			/* [NEXT STATE: ENTRY ACTIONS] */
			PX4_INFO("----- ENTRY state_wait -----");
			break;

		case state_stop:
			run = false;
			break;
		}

	} /* end while(run) */

	/* tidy up */
	mbedtls_pk_free(&pk_ctx);
	mbedtls_x509_crt_free(&uav_cert);
	mbedtls_x509_crt_free(&rootca_cert);
	mbedtls_x509_crt_free(&intermca_cert);
	mbedtls_ctr_drbg_free(&ctr_drbg);

	PX4_INFO("all tasks finished");
	return 0;
}


/*
 * HELPER FUNCTIONS
 */

/**
* Send data to NFC companion controller via Mavlink
* @param buf Binary data buffer
* @param dataLen Size of buffer (Bytes)
* @param nfc_rx_data RX data struct (to copy the nfc_id from)
* @param dataId NFC communication data ID (nfc_tx_s::data_id)
*/
void nfcCom_send(const uint8_t *buf, size_t dataLen, nfc_rx_s nfc_rx_data, uint8_t dataId)
{
	struct nfc_tx_s nfc_tx = {0};
	orb_advert_t nfc_tx_pub_fd;
	int nfcrest;

	nfc_tx_pub_fd = orb_advertise(ORB_ID(nfc_tx), &nfc_tx);

	memcpy(nfc_tx.nfc_id, nfc_rx_data.nfc_id, sizeof(nfc_tx.nfc_id));
	nfc_tx.data_id = dataId;

	nfc_tx.data_len = dataLen / sizeof(nfc_tx.data) + 1;
	nfcrest = dataLen - (sizeof(nfc_tx.data) * (nfc_tx.data_len - 1));

	printf("nfcCom_send: data len:      %zu\n", dataLen);               // debug
	printf("nfcCom_send: packetCounter: %i\n", nfc_tx.data_len);        // debug
	printf("nfcCom_send: nfcrest:       %i\n", nfcrest);                // debug

	for (uint8_t j = 0; j <  nfc_tx.data_len; j++) {
		nfc_tx.data_nr = j + 1;
		printf("TxNfcDataNr:	%i\n", nfc_tx.data_nr);                 // debug

		printf("TxNfcData:\n");                                         // debug

		if ((nfc_tx.data_nr == nfc_tx.data_len) && (nfcrest != 0)) {
			for (uint8_t i = 0; i < nfcrest; i++) {
				nfc_tx.data[i] = buf[i + (j * (sizeof(nfc_tx.data)))];
				printf("%c", nfc_tx.data[i]);                           // debug
			}

			for (uint8_t i = nfcrest; i < sizeof(nfc_tx.data); i++) {
				nfc_tx.data[i] = '\0';
				printf("%c", nfc_tx.data[i]);                           // debug
			}

		} else {
			for (uint8_t i = 0; i < sizeof(nfc_tx.data); i++) {
				nfc_tx.data[i] = buf[i + (j * (sizeof(nfc_tx.data)))];
				printf("%c", nfc_tx.data[i]);                           // debug
			}
		}

		printf("\n");                                                   // debug

		PX4_INFO("Sending Data to NFC!");
		orb_publish(ORB_ID(nfc_tx), nfc_tx_pub_fd, &nfc_tx);

		nfcCom_waitAck();
		recvACK = 0;
	}
}

void nfcCom_waitAck()
{
	clock_gettime(CLOCK_REALTIME, &_ts);
	start_timeACK = _ts.tv_sec;
	recvACK = 0;

	nfc_rx_sub_fdACK = orb_subscribe(ORB_ID(nfc_rx));

	px4_pollfd_struct_t fdsACK[] = {{}}; // possibility to wait for multiple topics, but using one here
	fdsACK[0].fd = nfc_rx_sub_fdACK;
	fdsACK[0].events = POLLIN;

	while (recvACK == 0) {
		clock_gettime(CLOCK_REALTIME, &_ts);
		end_timeACK = _ts.tv_sec;

		if (end_timeACK > (start_timeACK + WAITTIMEACK)) {
			printf("BREAK\n");
			recvACK = -1;
			break;
		}

		px4_poll(fdsACK, 1, 1000);

		//event_nfcCmd = false;
		if ((fdsACK[0].revents & POLLIN) != 0) {
			orb_copy(ORB_ID(nfc_rx), nfc_rx_sub_fdACK, &nfc_rx);
			event_nfcCmd = true;

			if (nfc_rx.data_id == DATAID_ACK) {
				printf("Recieve ACK \n");
				sleep(2);
				recvACK = 1;
			}
		}
	}
}

void nfcCom_sendAck()
{
	struct nfc_tx_s nfc_tx_st = {0};
	memset(&nfc_tx_st, 0, sizeof(nfc_tx_st));
	orb_advert_t nfc_tx_pub_fd = orb_advertise(ORB_ID(nfc_tx), &nfc_tx_st);

	memcpy(nfc_tx_st.nfc_id, nfc_rx.nfc_id, sizeof(nfc_tx_st.nfc_id));
	nfc_tx_st.data_id = DATAID_ACK;
	nfc_tx_st.data_len = 1;
	nfc_tx_st.data_nr = 1;
	memset(nfc_tx_st.data, 0, sizeof(nfc_tx_st.data));

	PX4_INFO("Sending ACK!");
	orb_publish(ORB_ID(nfc_tx), nfc_tx_pub_fd, &nfc_tx_st);
}

/**
* Read file to buffer e.g. for transferring the content
* @param buffer Binary data buffer to write the file content to
* @param buflen Size of buffer (Bytes)
* @param input_file File path to read
* @return number of read bytes on success, negative error code on failure
*/
int read_file_to_buffer(uint8_t *buf, size_t buflen, const char *input_file)
{
	FILE *f;            // TODO: use ofstream because of RAII
	long filesize = 0;

	if ((f = fopen(input_file, "rb")) == nullptr) {
		PX4_ERR("error opening file to read");
		return -1;
	}

	fseek(f, 0, SEEK_END);
	filesize = ftell(f);
	fseek(f, 0, SEEK_SET);

	if (filesize > static_cast<long>(buflen)) {
		PX4_ERR("file too big for the given buffer");
		fclose(f);
		return -2;
	}

	if (fread(buf, filesize, 1, f) < static_cast<size_t>(filesize)) {
		//PX4_ERR("file not read completely");		// TODO: check why file not read completely
		//fclose(f);
		//return -3;
	}

	fclose(f);
	return filesize;
}

/**
* Write file from buffer e.g. when receiving content
* @param buffer Binary data buffer to write to file
* @param buflen Length of data to write (Bytes)
* @param output_file File path to write to
* @return 0 on success, negative error code on failure
*/
int write_file_from_buffer(const uint8_t *buf, size_t buflen, const char *output_file)
{
	FILE *f;            // TODO: use ifstream because of RAII

	if ((f = fopen(output_file, "wb")) == nullptr) {
		PX4_ERR("error opening file to write");
		return -1;
	}

	if (fwrite(buf, 1, buflen, f) != buflen) {
		PX4_ERR("error writing to file");
		fclose(f);
		return -2;
	}

	fclose(f);
	return 0;
}



/*
 * CRYPTO FUNCTIONS
 */
/**
* Generate a new ECC key pair using the curve in ECC_CURVE
* @param pk_ctx private key context to initialize and fill with new key
* @return 0 on success, -1 on failure
*/
int generate_keypair(mbedtls_pk_context *pk_ctx)
{
	int ret;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	const char *pers = "ecdsa";         // personal PRNG seed

	mbedtls_pk_init(pk_ctx);
	mbedtls_ctr_drbg_init(&ctr_drbg);

	PX4_INFO(". Seeding the random number generator...");
	mbedtls_entropy_init(&entropy);

	if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, reinterpret_cast<const uint8_t *>(pers),
					 strlen(pers))) != 0) {
		PX4_ERR("! ERROR mbedtls_ctr_drbg_seed returned -0x%04X", -ret);
		return -1;
	}

	PX4_INFO(". Generating key pair...");
	mbedtls_pk_setup(pk_ctx, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));

	if ((ret = mbedtls_ecdsa_genkey(mbedtls_pk_ec(*pk_ctx), ECC_CURVE, mbedtls_ctr_drbg_random,
					&ctr_drbg)) != 0) {
		PX4_ERR("! ERROR mbedtls_ecdsa_genkey returned -0x%04X", -ret);
		return -1;
	}

	PX4_INFO(". OK (key size: %d bits)", static_cast<int>(mbedtls_pk_ec(*pk_ctx)->grp.pbits));

	return 0;
}

/**
* Write the UAV's ECC private key to a file using PEM encoding
* @param key private Key context to persist
* @param output_file File path to write to. Directories must already exist!
* @return 0 on success, negative error code on failure
*/
static int write_uav_key(mbedtls_pk_context *key, const char *output_file)
{
	int ret;
	FILE *f;
	uint8_t output_buf[PRIVKEY_FILESIZE];
	size_t len;

	// write PEM ECC private key
	if ((ret = mbedtls_pk_write_key_pem(key, output_buf, sizeof(output_buf))) != 0) {
		PX4_ERR("mbedtls_pk_write_key_pem ERROR -0x%04X", -ret);
		return ret;
	}

	len = strlen(reinterpret_cast<char *>(output_buf));

	if ((f = fopen(output_file, "wb")) == nullptr) {
		PX4_ERR("error opening file to write");
		return -1;
	}

	if (fwrite(&output_buf, 1, len, f) != len) {
		PX4_ERR("error writing to file");
		fclose(f);
		return -2;
	}

	fclose(f);
	return 0;
}

/**
* Load the UAV's ECC private key from a file with PEM encoding
* @param key Private key context to write the key to
* @param input_file File path to read
* @return 0 on success, negative error code on failure
*/
int load_uav_key(mbedtls_pk_context *key, const char *input_file)
{
	int ret;

	mbedtls_pk_init(key);

	if ((ret = mbedtls_pk_parse_keyfile(key, input_file, nullptr)) != 0) {
		if (MBEDTLS_ERR_PK_FILE_IO_ERROR == ret) {
			PX4_ERR("mbedtls_pk_parse_keyfile ERROR opening/ reading file");

		} else {
			PX4_ERR("mbedtls_pk_parse_keyfile ERROR -0x%04X", -ret);
		}

		return ret;
	}

	return 0;
}

/**
* Generate a CSR from a given keypair and save to file with PEM encoding
* @param key ECDSA key pair (e.g. from generate_keypair())
* @param output_file File path to write to. Directories must already exist!
* @return 0 on success, negative error code on failure
*/
int generate_and_save_csr(mbedtls_pk_context *key, const char *output_file)
{
	int ret;
	FILE *f;
	unsigned char output_buf[CSR_FILESIZE] = {0};
	size_t len = 0;
	char subject[CSR_SUBJECT_MAX] = {0};
	mbedtls_x509write_csr csr;

	mbedtls_x509write_csr_init(&csr);

	/*
	 * prepare CSR
	 */
	mbedtls_x509write_csr_set_md_alg(&csr, CSR_MD_ALG);

	strncat(subject, CSR_SUBJECT, (CSR_SUBJECT_MAX - (2 * UID_LEN_BYTE)));
	strncat(subject, SERIAL_NUMBER, (2 * UID_LEN_BYTE));
	PX4_INFO(". Subject: %s", subject);

	if ((ret = mbedtls_x509write_csr_set_subject_name(&csr, subject)) != 0) {
		PX4_ERR("mbedtls_x509write_csr_set_subject_name ERROR -0x%04X", -ret);
		return ret;
	}

	PX4_INFO(". Transferring key to CSR");
	mbedtls_x509write_csr_set_key(&csr, key);

	/*
	 * save CSR to file
	 */
	mbedtls_ctr_drbg_context ctr_drbg;  // TODO: why does a signature need a RNG?
	mbedtls_ctr_drbg_init(&ctr_drbg);

	// memset(output_buf, 0, CSR_FILESIZE); // only needed, if global buffer is used

	PX4_INFO(". Converting CSR to PEM");

	if ((ret = mbedtls_x509write_csr_pem(&csr, output_buf, CSR_FILESIZE, mbedtls_ctr_drbg_random, &ctr_drbg)) < 0) {
		PX4_ERR("mbedtls_x509write_csr_pem ERROR -0x%04X", -ret);
		return ret;
	}

	len = strlen(reinterpret_cast<char *>(output_buf));

	PX4_INFO(". Saving CSR to file");

	if ((f = fopen(output_file, "w")) == nullptr) {
		PX4_ERR("error opening file to write");
		return -1;
	}

	if (fwrite(&output_buf, 1, len, f) != len) {
		PX4_ERR("error writing to file");
		fclose(f);
		return -2;
	}

	fclose(f);
	return 0;
}

/**
* Load x509 certificate file
* @param cert Certificate structure to write to
* @param input_file File path to read
* @return 0 on success, negative error code on failure
*/
int load_cert(mbedtls_x509_crt *cert, const char *input_file)
{
	int ret;

	mbedtls_x509_crt_init(cert);

	if ((ret = mbedtls_x509_crt_parse_file(cert, input_file)) < 0) {
		if (MBEDTLS_ERR_PK_FILE_IO_ERROR == ret) {
			PX4_ERR("mbedtls_pk_parse_keyfile ERROR opening/ reading file");

		} else {
			PX4_ERR("mbedtls_x509_crt_parse_file ERROR -0x%04X", -ret);
		}

		return ret;
	}

	return 0;
}


/*
 * DEBUG HELPERS
 */
static void dump_pubkey(const char *title, mbedtls_ecdsa_context *key)
{
	unsigned char buf[300];
	size_t len;

	if (mbedtls_ecp_point_write_binary(&key->grp, &key->Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &len, buf, sizeof buf) != 0) {
		mbedtls_printf("internal error\n");
		return;
	}

	dump_buf(title, buf, len);
}

static void dump_privkey(const char *title, mbedtls_ecdsa_context *key)
{
	unsigned char buf[300] = {0};
	size_t len = key->d.n * sizeof(mbedtls_mpi_uint);

	for (uint16_t i = 0; i < len; i++) {
		buf[i] = (reinterpret_cast<uint8_t *>(key->d.p))[i];
	}

	dump_buf(title, buf, len);
}

static void dump_buf(const char *title, const unsigned char *buf, size_t len)
{
	mbedtls_printf("%s", title);

	for (size_t i = 0; i < len; i++) {
		mbedtls_printf("%c%c", "0123456789ABCDEF" [buf[i] / 16], "0123456789ABCDEF" [buf[i] % 16]);
	}

	mbedtls_printf("\n");
}
