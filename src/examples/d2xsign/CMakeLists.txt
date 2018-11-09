############################################################################
# 
#   Copyright (c) 2018 Jannik Beyerstedt, Leo Mustafa
#                 NXP Semiconductors Germany GmbH
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in
#    the documentation and/or other materials provided with the
#    distribution.
# 3. Neither the name PX4 nor the names of its contributors may be
#    used to endorse or promote products derived from this software
#    without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
# OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
# AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
############################################################################
px4_add_module(
	MODULE examples__d2xsign
	MAIN d2xsign
	STACK_MAIN 20000
	COMPILE_FLAGS -DMBEDTLS_USER_CONFIG_FILE=<mbedtls_cfg.h>
	INCLUDES mbedtls/include ./
	SRCS
		d2xsign.cpp

		mbedtls/library/aes.c
		mbedtls/library/aesni.c
		mbedtls/library/arc4.c
		mbedtls/library/aria.c
		mbedtls/library/asn1parse.c
		mbedtls/library/asn1write.c
		mbedtls/library/base64.c
		mbedtls/library/bignum.c
		mbedtls/library/blowfish.c
		mbedtls/library/camellia.c
		mbedtls/library/ccm.c
		mbedtls/library/chacha20.c
		mbedtls/library/chachapoly.c
		mbedtls/library/cipher.c
		mbedtls/library/cipher_wrap.c
		mbedtls/library/cmac.c
		mbedtls/library/ctr_drbg.c
		mbedtls/library/des.c
		mbedtls/library/dhm.c
		mbedtls/library/ecdh.c
		mbedtls/library/ecdsa.c
		mbedtls/library/ecjpake.c
		mbedtls/library/ecp.c
		mbedtls/library/ecp_curves.c
		mbedtls/library/entropy.c
		mbedtls/library/entropy_poll.c
		mbedtls/library/error.c
		mbedtls/library/gcm.c
		mbedtls/library/havege.c
		#mbedtls/library/hkdf.c
		mbedtls/library/hmac_drbg.c
		mbedtls/library/md.c
		mbedtls/library/md2.c
		mbedtls/library/md4.c
		mbedtls/library/md5.c
		mbedtls/library/md_wrap.c
		mbedtls/library/memory_buffer_alloc.c
		#mbedtls/library/nist_kw.c
		mbedtls/library/oid.c
		mbedtls/library/padlock.c
		mbedtls/library/pem.c
		mbedtls/library/pk.c
		mbedtls/library/pkcs5.c
		mbedtls/library/pkcs12.c
		mbedtls/library/pkparse.c
		mbedtls/library/pk_wrap.c
		mbedtls/library/pkwrite.c
		mbedtls/library/platform.c
		mbedtls/library/platform_util.c
		mbedtls/library/poly1305.c
		mbedtls/library/ripemd160.c
		mbedtls/library/rsa.c
		mbedtls/library/rsa_internal.c
		mbedtls/library/sha1.c
		mbedtls/library/sha256.c
		mbedtls/library/sha512.c
		mbedtls/library/threading.c
		mbedtls/library/timing.c
		mbedtls/library/version.c
		mbedtls/library/version_features.c
		mbedtls/library/xtea.c

		mbedtls/library/certs.c
		mbedtls/library/pkcs11.c
		mbedtls/library/x509.c
		mbedtls/library/x509_create.c
		mbedtls/library/x509_crl.c
		mbedtls/library/x509_crt.c
		mbedtls/library/x509_csr.c
		mbedtls/library/x509write_crt.c
		mbedtls/library/x509write_csr.c

		mbedtls/library/debug.c
		#mbedtls/library/net_sockets.c
		mbedtls/library/ssl_cache.c
		mbedtls/library/ssl_ciphersuites.c
		mbedtls/library/ssl_cli.c
		mbedtls/library/ssl_cookie.c
		mbedtls/library/ssl_srv.c
		mbedtls/library/ssl_ticket.c
		mbedtls/library/ssl_tls.c

	DEPENDS
	)
