/****************************************************************************
 *
 *   Copyright (c) 2012-2016 PX4 Development Team. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name PX4 nor the names of its contributors may be
 *    used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 ****************************************************************************/

/**
 * @file px4_simple_app.c
 * Minimal application example for PX4 autopilot
 *
 * @author Example User <mail@example.com>
 */
 
#include <px4_config.h>
#include <px4_tasks.h>
#include <px4_posix.h>
#include <unistd.h>
#include <stdio.h>
#include <poll.h>
#include <string.h>
#include <math.h>
#include <errno.h>
#include <float.h>
#include <stdlib.h>
#include <time.h>


#include <uORB/uORB.h>
#include <uORB/topics/sensor_combined.h>
#include <uORB/topics/vehicle_attitude.h>
#include <uORB/topics/vehicle_status.h>
#include <uORB/topics/debug_key_value.h>
#include <uORB/topics/nfc_test.h>
#include <uORB/topics/nfc_tx.h>
#include <uORB/topics/nfc_rx.h>
#include <uORB/topics/heartbeatsign.h>

//#include <mavlink/inlcude/mavlink/v2.0/common/mavlink_msg_nfc.h>

//#include <uORB/topics/nfc_data.h>

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_printf     printf
#endif


#include "mbedtls/mbedtls/entropy.h"
#include "mbedtls/mbedtls/ctr_drbg.h"
#include "mbedtls/mbedtls/bignum.h"
#include "mbedtls/mbedtls/x509.h"
#include "mbedtls/mbedtls/x509_csr.h"
#include "mbedtls/mbedtls/rsa.h"
#include "mbedtls/mbedtls/x509_crt.h"
#include "mbedtls/mbedtls/havege.h"
#include "mbedtls/mbedtls/pk.h"
#include "mbedtls/mbedtls/md5.h"

#include <stdio.h>
#include <string.h>


#include "mbedtls/mbedtls/error.h"
#include "mbedtls/mbedtls/pk.h"
#include "mbedtls/mbedtls/ecdsa.h"



#define KEY_SIZE 1024
#define EXPONENT 65537

#if defined(MBEDTLS_ECP_C)
#define DFL_EC_CURVE            MBEDTLS_ECP_DP_SECP192K1  //mbedtls_ecp_curve_list()->grp_id
#else
#define DFL_EC_CURVE            0
#endif

#if !defined(_WIN32) && defined(MBEDTLS_FS_IO)
#define USAGE_DEV_RANDOM \
    "    use_dev_random=0|1    default: 0\n"
#else
#define USAGE_DEV_RANDOM ""
#endif /* !_WIN32 && MBEDTLS_FS_IO */

#define FORMAT_PEM              0
#define FORMAT_DER              1

#define DFL_TYPE                MBEDTLS_PK_ECKEY // MBEDTLS_PK_RSA
//#define DFL_TYPE                MBEDTLS_PK_RSA // MBEDTLS_PK_ECKEY
#define DFL_RSA_KEYSIZE         2048
#define PRIVKEYFILE            "/fs/microsd/keystore/UavPrivKey.key"
#define DFL_FORMAT              FORMAT_PEM
#define DFL_USE_DEV_RANDOM      0

//CSR Gen
//#define PRIVKEYFILE            "keyfile.key"
#define DFL_DEBUG_LEVEL         0
#define CSRFILE     "/fs/microsd/keystore/UAVcsr.csr"
#define DFL_SUBJECT_NAME        "CN=NFCID310115,O=NXP,C=DE, serialNumber=010203"
#define DFL_KEY_USAGE           0
#define DFL_NS_CERT_TYPE        0

#define ROOTCAFILE "/fs/microsd/keystore/CaCert.crt"
#define CERTFILE "/fs/microsd/keystore/UAVCrt.crt"

#define DATAID_ACK 0
#define DATAID_ROOTCA 1
#define DATAID_CSR 2
#define DATAID_CERT 3

#define MAXMSGP 10
#define MAVLINK_MSG_NFC_FIELD_NFC_ID_LEN 8
#define MAVLINK_MSG_NFC_FIELD_DATA_LEN 200

#define WAITTIME 5 //in sek
#define WAITTIMEACK 5 //in sek

enum states{
	init,
	waitForData,
	sendDataCSR,
	sendDataCA,
	genKeys,
	sendSignMsg,
	checkSignMsg,
	error,
	stop,
	debug
}currentstate;

char csrsubjectname[128];

mbedtls_pk_context UAVkey;
uint8_t output_bufCSR[4096];
uint8_t output_bufCA[1024];
//unsigned char *output_bufCSR;

uint8_t UAV_ID[8] = "11061993"; //{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
struct nfc_rx_s nfc_rx;
int nfc_rx_sub_fd;
int nfc_rx_sub_fdACK;
int nfc_tx_sub_fd;

int vehicle_status_sub_fd;

uint8_t getNFCmsg = 0; 
uint8_t getRootCA = 0; 
uint8_t getCert = 0; 
int8_t UTMrootCA[1024];
int8_t UAVCertBuf[1024];

uint8_t BufRxNfcData[MAXMSGP][MAVLINK_MSG_NFC_FIELD_DATA_LEN];
uint8_t RxNfcID_s[MAVLINK_MSG_NFC_FIELD_NFC_ID_LEN] = {0};

__EXPORT int uavsignapp_main(int argc, char *argv[]);

int generatePirvateKey(void);
int generateCSR(void);
int write_certificate_request( mbedtls_x509write_csr *req, const char *output_file,
                               int (*f_rng)(void *, unsigned char *, size_t),
                               void *p_rng );
void evalEvents(void);
void evalStates(void);
void sendACK(void);
void waitForACK(void);
void loadCA(void);
void loadCSR(void);
void loadPrivateKey(void); 
int writeCertToFile(void);
int writeRootCaToFile(void);
void loadCert(void);
void loadCAFromFile(void);

uint8_t run = 0; 
uint8_t i = 0; 
uint8_t j = 0; 

time_t t;
struct timespec _ts;
uint8_t temp = 0;

long start_time = 0;
long end_time = 0;
long start_timeACK = 0;
long end_timeACK = 0;

uint8_t len_outputbuf = 0;
size_t lenCSR = 0;
size_t lenCA = 0;
int8_t recvACK = 0; 

long lSize;
char * buffer;
long result;
int UAVCertSize;
int lenCert;
//MavlinkStreamNFC msNFC;

mbedtls_havege_state hs;												//Struktur für Random Generator
mbedtls_pk_context privateKey;
mbedtls_x509_crt publicKey;
mbedtls_x509_crt publicKeyRx;
mbedtls_x509_crt rootCA;
mbedtls_x509_crt UAVCert;

struct optionsPrivKey
{
    int type;                   /* the type of key to generate          */
    int rsa_keysize;            /* length of key in bits                */
    int ec_curve;               /* curve identifier for EC keys         */
    const char *filename;       /* filename of the key file             */
    int format;                 /* the output format to use             */
    int use_dev_random;         /* use /dev/random as entropy source    */
} opt_keygen;

static int write_private_key( mbedtls_pk_context *key, const char *output_file )
{
    int ret;
    FILE *f;
    //unsigned char output_buf[16000]; 
    
    unsigned char *output_buf;
    output_buf = malloc(16000*sizeof(unsigned char));
       
    unsigned char *c = output_buf;
    size_t len = 0;

    memset(output_buf, 0, 16000);
    if( opt_keygen.format == FORMAT_PEM )
    {
        if( ( ret = mbedtls_pk_write_key_pem( key, output_buf, 16000 ) ) != 0 )
            return( ret );

        len = strlen( (char *) output_buf );
    }
    else
    {
        if( ( ret = mbedtls_pk_write_key_der( key, output_buf, 16000 ) ) < 0 )
            return( ret );

        len = ret;
        c = output_buf + sizeof(output_buf) - len;
    }

    if( ( f = fopen( output_file, "wb" ) ) == NULL )
        return( -1 );

    if( fwrite( c, 1, len, f ) != len )
    {
        fclose( f );
        return( -1 );
    }

    fclose( f );
    free(output_buf);

    return( 0 );
}

int generatePirvateKey(void){
	
	int ret = 0;
    
    char buf[1024];
    //int i;
    //char *p, *q;
    mbedtls_mpi N, P, Q, D, E, DP, DQ, QP;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "gen_key";

    /*
     * Set to sane values
     */

    mbedtls_mpi_init( &N ); mbedtls_mpi_init( &P ); mbedtls_mpi_init( &Q );
    mbedtls_mpi_init( &D ); mbedtls_mpi_init( &E ); mbedtls_mpi_init( &DP );
    mbedtls_mpi_init( &DQ ); mbedtls_mpi_init( &QP );

    mbedtls_pk_init( &UAVkey );
    mbedtls_ctr_drbg_init( &ctr_drbg );
    memset( buf, 0, sizeof( buf ) );

    opt_keygen.type                = DFL_TYPE;
    opt_keygen.rsa_keysize         = DFL_RSA_KEYSIZE;
    opt_keygen.ec_curve            = DFL_EC_CURVE;
    opt_keygen.filename            = PRIVKEYFILE;
    opt_keygen.format              = DFL_FORMAT;
    opt_keygen.use_dev_random      = DFL_USE_DEV_RANDOM;

    mbedtls_printf( "\n  . Seeding the random number generator..." );
    fflush( stdout );

    mbedtls_entropy_init( &entropy );
    
   
    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *) pers,
                               strlen( pers ) ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ctr_drbg_seed returned -0x%04x\n", -ret );
        goto exit;
    }
    

    /*
     * 1.1. Generate the key
     */
    mbedtls_printf( "\n  . Generating the private key ..." );
    fflush( stdout );

    if( ( ret = mbedtls_pk_setup( &UAVkey, mbedtls_pk_info_from_type( opt_keygen.type ) ) ) != 0 )
    {
        mbedtls_printf( " failed\n  !  mbedtls_pk_setup returned -0x%04x", -ret );
        goto exit;
    }

#if defined(MBEDTLS_RSA_C) && defined(MBEDTLS_GENPRIME)
    if( opt_keygen.type == MBEDTLS_PK_RSA )
    {
        ret = mbedtls_rsa_gen_key( mbedtls_pk_rsa( UAVkey ), mbedtls_ctr_drbg_random, &ctr_drbg,
                                   opt_keygen.rsa_keysize, 65537 );
        if( ret != 0 )
        {
            mbedtls_printf( " failed\n  !  mbedtls_rsa_gen_key returned -0x%04x", -ret );
            goto exit;
        }
    }
    else
#endif /* MBEDTLS_RSA_C */
#if defined(MBEDTLS_ECP_C)
    if( opt_keygen.type == MBEDTLS_PK_ECKEY )
    {
        ret = mbedtls_ecp_gen_key( opt_keygen.ec_curve, mbedtls_pk_ec( UAVkey ),
                                   mbedtls_ctr_drbg_random, &ctr_drbg );
        if( ret != 0 )
        {
            mbedtls_printf( " failed\n  !  mbedtls_ecp_gen_key returned -0x%04x", -ret );
            goto exit;
        }
    }
    else
#endif /* MBEDTLS_ECP_C */
    {
        mbedtls_printf( " failed\n  !  key type not supported\n" );
        goto exit;
    }

    /*
     * 1.2 Print the key
     */
    mbedtls_printf( " ok\n  . Key information:\n" );

#if defined(MBEDTLS_RSA_C)
    if( mbedtls_pk_get_type( &UAVkey ) == MBEDTLS_PK_RSA )
    {
        mbedtls_rsa_context *rsa = mbedtls_pk_rsa( UAVkey );

        if( ( ret = mbedtls_rsa_export    ( rsa, &N, &P, &Q, &D, &E ) ) != 0 ||
            ( ret = mbedtls_rsa_export_crt( rsa, &DP, &DQ, &QP ) )      != 0 )
        {
            mbedtls_printf( " failed\n  ! could not export RSA parameters\n\n" );
            goto exit;
        }

        mbedtls_mpi_write_file( "N:  ",  &N,  16, NULL );
        mbedtls_mpi_write_file( "E:  ",  &E,  16, NULL );
        mbedtls_mpi_write_file( "D:  ",  &D,  16, NULL );
        mbedtls_mpi_write_file( "P:  ",  &P,  16, NULL );
        mbedtls_mpi_write_file( "Q:  ",  &Q,  16, NULL );
        mbedtls_mpi_write_file( "DP: ",  &DP, 16, NULL );
        mbedtls_mpi_write_file( "DQ:  ", &DQ, 16, NULL );
        mbedtls_mpi_write_file( "QP:  ", &QP, 16, NULL );
    }
    else
#endif
#if defined(MBEDTLS_ECP_C)
    if( mbedtls_pk_get_type( &UAVkey ) == MBEDTLS_PK_ECKEY )
    {
        mbedtls_ecp_keypair *ecp = mbedtls_pk_ec( UAVkey );
        mbedtls_printf( "curve: %s\n",
                mbedtls_ecp_curve_info_from_grp_id( ecp->grp.id )->name );
        mbedtls_mpi_write_file( "X_Q:   ", &ecp->Q.X, 16, NULL );
        mbedtls_mpi_write_file( "Y_Q:   ", &ecp->Q.Y, 16, NULL );
        mbedtls_mpi_write_file( "D:     ", &ecp->d  , 16, NULL );
    }
    else
#endif
        mbedtls_printf("  ! key type not supported\n");

    /*
     * 1.3 Export key
     */
    mbedtls_printf( "  . Writing key to file..." );

    if( ( ret = write_private_key( &UAVkey, opt_keygen.filename ) ) != 0 )
    {
        mbedtls_printf( " failed\n" );
        goto exit;
    }

    mbedtls_printf( " ok\n" );

exit:

    if( ret != 0 && ret != 1)
    {
#ifdef MBEDTLS_ERROR_C
        mbedtls_strerror( ret, buf, sizeof( buf ) );
        mbedtls_printf( " - %s\n", buf );
#else
        mbedtls_printf("\n");
#endif
    }

    mbedtls_mpi_free( &N ); mbedtls_mpi_free( &P ); mbedtls_mpi_free( &Q );
    mbedtls_mpi_free( &D ); mbedtls_mpi_free( &E ); mbedtls_mpi_free( &DP );
    mbedtls_mpi_free( &DQ ); mbedtls_mpi_free( &QP );

    //mbedtls_pk_free( &UAVkey );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );


    return( ret );
	
}

int writeCertToFile(void){

    FILE *f;
    
    lenCert = UAVCertSize;//sizeof(UAVCertBuf);
    printf("LenCert: %i\n", lenCert); 

    if( ( f = fopen( CERTFILE, "wb" ) ) == NULL )
        return( -1 );

    // if( fwrite( UAVCertBuf, 1, lenCert, f ) != lenCert )
    // {
    //     fclose( f );
    //     return( -1 );
    // }

	fwrite( UAVCertBuf, 1, lenCert, f );

    fclose( f );
    
    return( 0 );
}

int writeRootCaToFile(void){

    FILE *f;
    
    lenCert = 1024;//sizeof(UTMrootCA);
    printf("LenCert: %i\n", lenCert); 

    if( ( f = fopen( ROOTCAFILE, "wb" ) ) == NULL )
        return( -1 );

    // if( fwrite( UTMrootCA, 1, lenCert, f ) != lenCert )
    // {
    //     fclose( f );
    //     return( -1 );
    // }

	fwrite( UTMrootCA, 1, lenCert, f );

    fclose( f );
    
    return( 0 );
}

struct optionsCSR
{
    const char *filename;       /* filename of the key file             */
    int debug_level;            /* level of debugging                   */
    const char *output_file;    /* where to store the constructed key file  */
    const char *subject_name;   /* subject name for certificate request */
    unsigned char key_usage;    /* key usage flags                      */
    unsigned char ns_cert_type; /* NS cert type                         */
} opt_csrgen;

int write_certificate_request( mbedtls_x509write_csr *req, const char *output_file,
                               int (*f_rng)(void *, unsigned char *, size_t),
                               void *p_rng )
{
    int ret;
    FILE *f;
    unsigned char output_buf[4096];
	//output_buf = malloc(4096*sizeof(unsigned char));
	
    //output_bufCSR = malloc(4096*sizeof(unsigned char));
    

    //memset( output_bufCSR, 0, 4096 );
    if( ( ret = mbedtls_x509write_csr_pem( req, output_buf, 4096, f_rng, p_rng ) ) < 0 )
        return( ret );

    lenCSR = strlen( (char *) output_buf );
    //printf("\nstrlen: %i\n", lenCSR); 

    if( ( f = fopen( output_file, "w" ) ) == NULL )
        return( -1 );

    if( fwrite( output_buf, 1, lenCSR, f ) != lenCSR )
    {
        fclose( f );
        return( -1 );
    }

    fclose( f );
    
    memcpy(output_bufCSR, output_buf, 4096);
    //free(output_buf);

    return( 0 );
}

int generateCSR(void){
	
	 int ret = 0;
    mbedtls_pk_context key;
    char buf[1024];
    //int i;
    //char *p, *q, *r;
    mbedtls_x509write_csr req;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "csr example app";

    /*
     * Set to sane values
     */
    mbedtls_x509write_csr_init( &req );
    mbedtls_x509write_csr_set_md_alg( &req, MBEDTLS_MD_SHA256 );
    mbedtls_pk_init( &key );
    mbedtls_ctr_drbg_init( &ctr_drbg );
    memset( buf, 0, sizeof( buf ) );
	
	//strcpy(csrsubjectname, "CN=NFCID");
	//strcat(csrsubjectname, RxNfcID_s); 
	strcpy(csrsubjectname, "CN=UAV");
	//strcat(csrsubjectname, UAV_ID);
	strcat(csrsubjectname, "1");
	//for(i = 0; i < sizeof(nfc_rx.nfc_id); i++){
		//printf("%c", nfc_rx.nfc_id[i]);
	//	csrsubjectname[i + strlen("CN=NFCID")] = nfc_rx.nfc_id[i];
	//}
	
	strcat(csrsubjectname,",O=NXP,C=DE,");
	strcat(csrsubjectname,"serialNumber=");
	strcat(csrsubjectname,"11061993");
	
	printf("CSRSubjectName:	");
	for(i=0; i < sizeof(csrsubjectname); i++){
		printf("%c", csrsubjectname[i]);
	} 
	printf("\n");

    opt_csrgen.filename            = PRIVKEYFILE;
    opt_csrgen.debug_level         = DFL_DEBUG_LEVEL;
    opt_csrgen.output_file         = CSRFILE;
    opt_csrgen.subject_name        = csrsubjectname;
    opt_csrgen.key_usage           = DFL_KEY_USAGE;
    opt_csrgen.ns_cert_type        = DFL_NS_CERT_TYPE;


    if( opt_csrgen.key_usage )
        mbedtls_x509write_csr_set_key_usage( &req, opt_csrgen.key_usage );

    if( opt_csrgen.ns_cert_type )
        mbedtls_x509write_csr_set_ns_cert_type( &req, opt_csrgen.ns_cert_type );

    /*
     * 0. Seed the PRNG
     */
    mbedtls_printf( "  . Seeding the random number generator..." );
    fflush( stdout );

    mbedtls_entropy_init( &entropy );
    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *) pers,
                               strlen( pers ) ) ) != 0 )
    {
        mbedtls_printf( " failed\n  !  mbedtls_ctr_drbg_seed returned %d", ret );
        goto exit;
    }

    mbedtls_printf( " ok\n" );

    /*
     * 1.0. Check the subject name for validity
     */
    mbedtls_printf( "  . Checking subject name..." );
    fflush( stdout );

    if( ( ret = mbedtls_x509write_csr_set_subject_name( &req, opt_csrgen.subject_name ) ) != 0 )
    {
        mbedtls_printf( " failed\n  !  mbedtls_x509write_csr_set_subject_name returned %d", ret );
        goto exit;
    }

    mbedtls_printf( " ok\n" );

    /*
     * 1.1. Load the key
     */
    mbedtls_printf( "  . Loading the private key ..." );
    fflush( stdout );

    ret = mbedtls_pk_parse_keyfile( &key, opt_csrgen.filename, NULL );

    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  !  mbedtls_pk_parse_keyfile returned %d", ret );
        goto exit;
    }

    mbedtls_x509write_csr_set_key( &req, &key );

    mbedtls_printf( " ok\n" );

    /*
     * 1.2. Writing the request
     */
    mbedtls_printf( "  . Writing the certificate request ..." );
    fflush( stdout );

    if( ( ret = write_certificate_request( &req, opt_csrgen.output_file,
                                           mbedtls_ctr_drbg_random, &ctr_drbg ) ) != 0 )
    {
        mbedtls_printf( " failed\n  !  write_certifcate_request %d", ret );
        goto exit;
    }

    mbedtls_printf( " ok\n" );

exit:

    if( ret != 0 && ret != 1)
    {
#ifdef MBEDTLS_ERROR_C
        mbedtls_strerror( ret, buf, sizeof( buf ) );
        mbedtls_printf( " - %s\n", buf );
#else
        mbedtls_printf("\n");
#endif
    }

    mbedtls_x509write_csr_free( &req );
    mbedtls_pk_free( &key );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );

    return( ret );
}

void loadCert(void){
	printf("LoadCert\n");
	mbedtls_x509_crt_init(&UAVCert);
	mbedtls_x509_crt_parse_file(&UAVCert, CERTFILE);
}

void loadPrivateKey(void){
	printf("LoadPrivateKey\n");
	mbedtls_pk_init(&privateKey);
	mbedtls_pk_parse_keyfile(&privateKey, PRIVKEYFILE, NULL);
}

void loadCA(void){
	printf("LoadCA\n");
	mbedtls_x509_crt_init(&rootCA);
	mbedtls_x509_crt_parse_file(&rootCA, ROOTCAFILE);
}

void loadCSR(void){
	FILE *CSRFile;
	CSRFile = fopen ( CSRFILE, "rb" );
	if (CSRFile==NULL) {fputs ("File error",stderr); exit (1);}

	// obtain file size:
	fseek (CSRFile , 0 , SEEK_END);
	lSize = ftell (CSRFile);
	rewind (CSRFile);

	// allocate memory to contain the whole file:
	buffer = (char*) malloc (sizeof(char)*lSize);
	if (buffer == NULL) {fputs ("Memory error",stderr); exit (2);}

	// copy the file into the buffer:
	result = fread (buffer,1,lSize,CSRFile);
	if (result != lSize) {fputs ("Reading error",stderr); exit (3);}


	printf("CSR: \n");
	printf("%s",buffer);
	printf("\n");

	//printf("Size: ");
	//printf("%ld",lSize);
	//printf("\n");

	printf("Result: ");
	printf("%i",result);
	printf("\n");

	memcpy(output_bufCSR, buffer, result);
	lenCSR = result; 
}

void loadCAFromFile(void){
	FILE *CAFile;
	CAFile = fopen ( ROOTCAFILE, "rb" );
	if (CAFile==NULL) {fputs ("File error",stderr); exit (1);}

	// obtain file size:
	fseek (CAFile , 0 , SEEK_END);
	lSize = ftell (CAFile);
	rewind (CAFile);

	// allocate memory to contain the whole file:
	buffer = (char*) malloc (sizeof(char)*lSize);
	if (buffer == NULL) {fputs ("Memory error",stderr); exit (2);}

	// copy the file into the buffer:
	result = fread (buffer,1,lSize,CAFile);
	if (result != lSize) {fputs ("Reading error",stderr); exit (3);}


	printf("CA: \n");
	printf("%s",buffer);
	printf("\n");

	//printf("Size: ");
	//printf("%ld",lSize);
	//printf("\n");

	printf("Result: ");
	printf("%i",result);
	printf("\n");

	memcpy(output_bufCA, buffer, result);
	lenCA = result; 
}

void sendACK(void){
	struct nfc_tx_s nfc_tx_st;
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

void waitForACK(void){
	
	clock_gettime(CLOCK_REALTIME, &_ts);
	start_timeACK = _ts.tv_sec;
	recvACK == 0;
	
	nfc_rx_sub_fdACK = orb_subscribe(ORB_ID(nfc_rx));

	/* one could wait for multiple topics with this technique, just using one here */
	px4_pollfd_struct_t fdsACK[] = {
		{ .fd = nfc_rx_sub_fdACK,   .events = POLLIN },
	};
	//int l =0;
	while(recvACK == 0){
		//l++;
		clock_gettime(CLOCK_REALTIME, &_ts);
		end_timeACK = _ts.tv_sec;
		
		if(end_timeACK > (start_timeACK + WAITTIMEACK)){
			printf("BREAK\n");
			//j = j-1;
			recvACK = -1;
			break;
		}
		
		px4_poll(fdsACK, 1, 1000);
		//getNFCmsg = 0; 
		if (fdsACK[0].revents & POLLIN) {			
			orb_copy(ORB_ID(nfc_rx), nfc_rx_sub_fdACK, &nfc_rx);
			getNFCmsg = 1;
			 
			if(nfc_rx.data_id == DATAID_ACK){
				printf("Recieve ACK \n");
				recvACK = 1; 
			}
		}
		//if(l > 100000){
			//printf("BREAK\n");
			////j = j-1;
			//recvACK = -1;
			//break;
	 	//}
	}
}


void evalStates(void){

	switch(currentstate){
	
		case init:
		if(temp == 0){
			printf("----- INIT ----\n");
			temp = 1;
		}
				
		loadPrivateKey();
		
		mbedtls_x509_crt_init(&UAVCert);
		
		//loadCA();
		
		//loadCert();
	
		break;
		
		case waitForData:
		if(temp == 0){
			printf("----- waitForData ----\n");
			temp = 1;
		}

		if(getNFCmsg == 1){
		
			switch(nfc_rx.data_id){
				
				case DATAID_ACK:
				PX4_INFO("Recieve ACK!");
				break;
				
				case DATAID_ROOTCA:
				if(nfc_rx.data_nr == nfc_rx.data_len){
					PX4_INFO("Recieve RootCA!");
					
					int a = 0;
					int b = 0; 
			
					for(a = 1; a <= nfc_rx.data_len; a++){
						for(b = 0; b < MAVLINK_MSG_NFC_FIELD_DATA_LEN;b++){
							printf("%c", BufRxNfcData[a][b]);
							UTMrootCA[(MAVLINK_MSG_NFC_FIELD_DATA_LEN * (a-1) + b)] = BufRxNfcData[a][b];
						}
					}
					printf("\n");
										
					writeRootCaToFile();
					loadCA();
					getRootCA = 1; 
					
				}
				break;
				
				case DATAID_CSR:
				PX4_INFO("Recieve CSR!");
				break;
				
				case DATAID_CERT:
							
				if(nfc_rx.data_nr == nfc_rx.data_len){
					PX4_INFO("Recieve Cert!");
					
					int a = 0;
					int b = 0; 
			
					for(a = 1; a <= nfc_rx.data_len; a++){
						for(b = 0; b < MAVLINK_MSG_NFC_FIELD_DATA_LEN;b++){
							printf("%c", BufRxNfcData[a][b]);
							UAVCertBuf[(MAVLINK_MSG_NFC_FIELD_DATA_LEN * (a-1) + b)] = BufRxNfcData[a][b];
						}
					}
					printf("\n");
					
					UAVCertSize = MAVLINK_MSG_NFC_FIELD_DATA_LEN*nfc_rx.data_len;
					uint32_t flags;
					mbedtls_x509_crt_parse(&UAVCert, &UAVCertBuf, (UAVCertSize));
					 
					if ((mbedtls_x509_crt_verify(&UAVCert, &rootCA, NULL, NULL, &flags, NULL, NULL)) == 0){
						//checkCert = 1;
						printf("Cert is ok!\n");
						writeCertToFile(); 
						getCert = 1; 
						
					}else{
						char tempbuf[1024];
						mbedtls_x509_crt_verify_info(tempbuf, sizeof(tempbuf), "ver: ", flags);
						puts(tempbuf);
						//checkCert = 0;
						printf("Cert is not ok!\n");
					}
					
				}
					
				break;			
			
			}
			
		}

		
		break;
		
		case sendDataCSR:
		if(temp == 0){
			printf("----- sendDataCSR ----\n");
			temp = 1;
		}
		
		
		;
		sleep(1);
		struct nfc_tx_s nfc_tx_st;
		memset(&nfc_tx_st, 0, sizeof(nfc_tx_st));
		
		orb_advert_t nfc_tx_pub_fd = orb_advertise(ORB_ID(nfc_tx), &nfc_tx_st);
		
		memcpy(nfc_tx_st.nfc_id, nfc_rx.nfc_id, sizeof(nfc_tx_st.nfc_id));
		nfc_tx_st.data_id = DATAID_CSR;

		printf("len_output_bufCSR: %i\n",lenCSR);
		printf("output_bufCSR:\n %s\n", output_bufCSR);
		
		nfc_tx_st.data_len = lenCSR/sizeof(nfc_tx_st.data) + 1;
		printf("packetCounter: %i\n", nfc_tx_st.data_len);
		
		int nfcrest = lenCSR - ( sizeof(nfc_tx_st.data) * (nfc_tx_st.data_len-1));
		printf("nfcrest: %i\n", nfcrest);
		
		for(j = 0; j <  nfc_tx_st.data_len; j++){
		
			nfc_tx_st.data_nr = j + 1;
			printf("TxNfcDataNr:	%i\n", nfc_tx_st.data_nr);
			
			printf("TxNfcData:\n");
			
			if((nfc_tx_st.data_nr == nfc_tx_st.data_len)&&(nfcrest != 0)){
				for(i = 0; i < nfcrest; i++){
					nfc_tx_st.data[i] = output_bufCSR[i+(j*(sizeof(nfc_tx_st.data)))];
					printf("%c", nfc_tx_st.data[i]);
				}
				
				for(i = nfcrest; i < sizeof(nfc_tx_st.data); i++){
					nfc_tx_st.data[i] = '\0';
					printf("%c", nfc_tx_st.data[i]);
				}
				
			}else{
				for(i = 0; i < sizeof(nfc_tx_st.data); i++){
					nfc_tx_st.data[i] = output_bufCSR[i+(j*(sizeof(nfc_tx_st.data)))];
					printf("%c", nfc_tx_st.data[i]);
				}
			}
				printf("\n");
			
			PX4_INFO("Sending Data to NFC!");
			orb_publish(ORB_ID(nfc_tx), nfc_tx_pub_fd, &nfc_tx_st);
			
			waitForACK();
			recvACK = 0;  
			
			//free(output_bufCSR);
		}
		break;
		
		case sendDataCA:
		if(temp == 0){
			printf("----- sendDataCA ----\n");
			temp = 1;
		}
		
		sleep(1);
		struct nfc_tx_s nfc_tx_stc;
		memset(&nfc_tx_stc, 0, sizeof(nfc_tx_stc));
		
		orb_advert_t nfc_tx_pub_fdc = orb_advertise(ORB_ID(nfc_tx), &nfc_tx_stc);
		
		memcpy(nfc_tx_stc.nfc_id, nfc_rx.nfc_id, sizeof(nfc_tx_stc.nfc_id));
		nfc_tx_stc.data_id = DATAID_ROOTCA;
		
		loadCAFromFile();

		//printf("len_output_bufCA: %i\n",lenCA);
		//printf("output_bufCA:\n %s\n", output_bufCA);
		
		nfc_tx_stc.data_len = lenCA/sizeof(nfc_tx_stc.data) + 1;
		//printf("packetCounter: %i\n", nfc_tx_stc.data_len);
		
		int nfcrestc = lenCA - ( sizeof(nfc_tx_stc.data) * (nfc_tx_stc.data_len-1));
		//printf("nfcrest: %i\n", nfcrestc);
		
		for(j = 0; j <  nfc_tx_stc.data_len; j++){
		
			nfc_tx_stc.data_nr = j + 1;
			//printf("TxNfcDataNr:	%i\n", nfc_tx_stc.data_nr);
			
			//printf("TxNfcData:\n");
			
			if((nfc_tx_stc.data_nr == nfc_tx_stc.data_len)&&(nfcrestc != 0)){
				for(i = 0; i < nfcrestc; i++){
					nfc_tx_stc.data[i] = output_bufCA[i+(j*(sizeof(nfc_tx_stc.data)))];
					//printf("%c", nfc_tx_stc.data[i]);
				}
				
				for(i = nfcrestc; i < sizeof(nfc_tx_st.data); i++){
					nfc_tx_stc.data[i] = '\0';
					//printf("%c", nfc_tx_stc.data[i]);
				}
				
			}else{
				for(i = 0; i < sizeof(nfc_tx_st.data); i++){
					nfc_tx_stc.data[i] = output_bufCA[i+(j*(sizeof(nfc_tx_stc.data)))];
					//printf("%c", nfc_tx_stc.data[i]);
				}
			}
				//printf("\n");
			
			PX4_INFO("Sending Data to NFC!");
			orb_publish(ORB_ID(nfc_tx), nfc_tx_pub_fdc, &nfc_tx_stc);

			//sleep(1);  
			waitForACK();
			recvACK = 0;
			
			//free(output_bufCSR);
		}
		break;
		
		case genKeys:
		if(temp == 0){
			printf("----- genKeys ----\n");
			temp = 1;
		}
		
		generateCSR();

		
		break;
		
		case sendSignMsg:
		if(temp == 0){
			printf("----- sendSignMsg ----\n");
			temp = 1;
		}
			
			
			uint8_t TxResponseHash[64];	
			size_t hashlaenge;
			size_t sig_len;
			uint8_t SignResponse[64] = {0};
			uint8_t DataHash[6] = {0};
			uint16_t ret = 0;
			
			struct heartbeatsign_s heartbeatsign_st;
			memset(&heartbeatsign_st, 0, sizeof(heartbeatsign_st));
		
			orb_advert_t heartbeatsign_pub_fd = orb_advertise(ORB_ID(heartbeatsign), &heartbeatsign_st);
			
			
			heartbeatsign_st.basemode = 82;
			heartbeatsign_st.custommode = 67305985;
			heartbeatsign_st.systemstatus = 4;
			
			uint32_t bufccustommode = heartbeatsign_st.custommode;
			
			DataHash[0] = heartbeatsign_st.basemode;
			DataHash[4] = (uint8_t)(bufccustommode);
			DataHash[3] = (uint8_t)(bufccustommode>>8);
			DataHash[2] = (uint8_t)(bufccustommode>>16);
			DataHash[1] = (uint8_t)(bufccustommode>>24);
			DataHash[5] = heartbeatsign_st.systemstatus;
					
			
			mbedtls_entropy_context entropy;
			mbedtls_ctr_drbg_context ctr_drbg2;
			const char *pers = "csr example app";
			mbedtls_entropy_init( &entropy );
			if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg2, mbedtls_entropy_func, &entropy,
									   (const unsigned char *) pers,
									   strlen( pers ) ) ) != 0 )
			{
				mbedtls_printf( " failed\n  !  mbedtls_ctr_drbg_seed returned %d", ret );

			}

			mbedtls_printf( " ok\n" );
			
			printf("DataHash:			 ");
			for(i=0;sizeof(DataHash)>i;i++){
				printf("%i", DataHash[i]);
			}
			printf("\n");
			
			mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), DataHash, sizeof(DataHash), TxResponseHash );
			hashlaenge = mbedtls_md_get_size(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256));
			
			printf("Hashlaenge: %i\n", hashlaenge); 
			
			printf("TxResponseHash: 		");
			for(i=0;hashlaenge>i;i++){
				printf("%02x", TxResponseHash[i]);
				if((i+1)%16 == 0){
					printf("\n");
					printf("				");
				}
			}
			printf("\n");
			
			if( ( ret = mbedtls_pk_sign(&privateKey, MBEDTLS_MD_SHA256, TxResponseHash, hashlaenge, SignResponse, &sig_len, mbedtls_ctr_drbg_random, &ctr_drbg2)))
			{
				mbedtls_printf( " failed\n  ! mbedtls_rsa_pkcs1_sign returned -0x%0x\n\n", -ret );
				//currentState = Error;
			}
			
			printf("Siglen: %i\n", sig_len); 
			
				printf("Sig: 				");
			for(i=0;sig_len>i;i++){
				printf("%02x", SignResponse[i]);
				if((i+1)%16 == 0){
					printf("\n");
					printf("				");
				}
			}
			printf("\n");
			
			heartbeatsign_st.signlen = sig_len;
			memcpy(heartbeatsign_st.signature, SignResponse, sizeof(heartbeatsign_st.signature));
			
			orb_publish(ORB_ID(heartbeatsign), heartbeatsign_pub_fd, &heartbeatsign_st);
				
			//if( ( ret = mbedtls_pk_verify(&UAVCert.pk, MBEDTLS_MD_SHA256, TxResponseHash, hashlaenge, SignResponse, sig_len) != 0 ))
			//{
			//mbedtls_printf("Signature failed:		[X]\n");
			//mbedtls_printf( " failed\n  ! mbedtls_rsa_pkcs1_verify returned -0x%0x\n\n", -ret );
			////check = 0;
			//}else{
			//mbedtls_printf("Signature is valid:		[X]\n");
			////check = 1;
			//ret = 0;
			//}
			//printf("\n");
			
			
		break;
		
		case checkSignMsg:
		if(temp == 0){
			printf("----- checkSignMsg ----\n");
			temp = 1;
		}
		
		
		break;
		
		case error:
		if(temp == 0){
			printf("----- error ----\n");
			temp = 1;
		}
		
		
		break;
		
		case stop:
		if(temp == 0){
			printf("----- stop ----\n");
			temp = 1;
		}
		
		run = 0; 
		break;
		
		case debug:
		if(temp == 0){
			printf("----- debug ----\n");
			temp = 1;
		}
		
		
		break;
	
	}
	
}

void evalEvents(void){

	switch(currentstate){
	
		case init:
		currentstate = waitForData;
		
		//currentstate = sendSignMsg;
		
		//currentstate = sendDataCSR;
		temp = 0;
		break;
		
		case waitForData:
		if(getNFCmsg == 1){
			getNFCmsg = 0; 
			
			if(getRootCA == 1){
				getRootCA = 0; 
				currentstate = genKeys;
				temp = 0;
			}
			
			if(getCert == 1){
				getCert = 0; 
				currentstate = sendDataCA;
				temp = 0;
			}
			
			
		}
		break;
		
		case sendDataCSR:
		currentstate = waitForData; 
		temp = 0;
		break;
		
		case sendDataCA:
		currentstate = sendSignMsg; 
		temp = 0;
		break;
		
		case genKeys:
		currentstate = sendDataCSR;
		temp = 0;
		break;
		
		case sendSignMsg:
		currentstate = stop;
		temp = 0;
		break;
		
		case checkSignMsg:
		
		break;
		
		case error:
		
		break;
		
		case stop:
		
		break;
		
		case debug:
		
		break;
	
	}
}

int uavsignapp_main(int argc, char *argv[])
{
	PX4_INFO("Hello UAVsign!");
	
	currentstate = init;
	run = 1; 
	
	nfc_rx_sub_fd = orb_subscribe(ORB_ID(nfc_rx));

	/* one could wait for multiple topics with this technique, just using one here */
	px4_pollfd_struct_t fds[] = {
		{ .fd = nfc_rx_sub_fd,   .events = POLLIN },
	};
	

	while(run == 1){
		//PX4_INFO("poll now");
		px4_poll(fds, 1, 5);
		//getNFCmsg = 0; 
		if (fds[0].revents & POLLIN) {			
			orb_copy(ORB_ID(nfc_rx), nfc_rx_sub_fd, &nfc_rx);
			getNFCmsg = 1;
			recvACK = 0;
			
			if(nfc_rx.data_id != DATAID_ACK){
				 
				printf("Recieve Mavlink Message: \n");
				printf("NFC_ID:		");
				for(i = 0; i < sizeof(nfc_rx.nfc_id); i++){
					printf("%02X", nfc_rx.nfc_id[i]);
					sprintf(&RxNfcID_s[i*2], "%02X", nfc_rx.nfc_id[i]);
				}
				printf("\n");
				
				printf("NFC_ID_s:	%s \n", RxNfcID_s);
				
				printf("NFC_Data_ID:	%i\n", nfc_rx.data_id);
				printf("NFC_Data_Len:	%i\n", nfc_rx.data_len);
				printf("NFC_Data_nr:	%i\n", nfc_rx.data_nr);
				
				printf("NFC_Data:	");
				for(i = 0; i < sizeof(nfc_rx.data); i++){
					printf("%c", nfc_rx.data[i]);
					BufRxNfcData[nfc_rx.data_nr][i] = nfc_rx.data[i];
				}
				printf("\n");
				printf("\n");
				
				sendACK(); 
			}else{
				printf("Recieve ACK \n");
				recvACK = 1; 
			}
			
			
		}
			
		evalStates();
		evalEvents();
		
	}


	//struct nfc_test_s nfc_s_test;
	//memset(&nfc_s_test, 0, sizeof(nfc_s_test));
	
	//orb_advert_t nfc_test_pub_fd = orb_advertise(ORB_ID(nfc_test), &nfc_s_test);
	
	//nfc_s_test.nfc_id = 1;
	//nfc_s_test.nfc_seq = 2;
	//nfc_s_test.nfc_data = 5;
	
	//orb_publish(ORB_ID(nfc_test), nfc_test_pub_fd, &nfc_s_test);
		
	
	//while (true) {
	//int poll_ret = px4_poll(fds, 1, 1000);
	
    
	//}
	
	PX4_INFO("exiting");

	return 0;
}
