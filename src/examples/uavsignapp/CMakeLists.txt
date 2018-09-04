############################################################################
#
#   Copyright (c) 2015 PX4 Development Team. All rights reserved.
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
	MODULE examples__uavsignapp
	MAIN uavsignapp
	STACK_MAIN 20000
	SRCS
		uavsignapp.c
		mbedtls/aes.c
		mbedtls/aesni.c
		mbedtls/arc4.c
		mbedtls/asn1parse.c
		mbedtls/asn1write.c
		mbedtls/base64.c
		mbedtls/bignum.c
		mbedtls/blowfish.c
		mbedtls/camellia.c
		mbedtls/ccm.c
		mbedtls/certs.c
		mbedtls/cipher.c
		mbedtls/cipher_wrap.c
		mbedtls/cmac.c
		mbedtls/ctr_drbg.c
		mbedtls/debug.c
		mbedtls/des.c
		mbedtls/dhm.c
		mbedtls/ecdh.c
		mbedtls/ecdsa.c
		mbedtls/ecjpake.c
		mbedtls/ecp.c
		mbedtls/ecp_curves.c
		mbedtls/entropy.c
		mbedtls/entropy_poll.c
		mbedtls/error.c
		mbedtls/gcm.c
		mbedtls/havege.c
		mbedtls/hmac_drbg.c
		mbedtls/md.c
		mbedtls/md2.c
		mbedtls/md4.c
		mbedtls/md5.c
		mbedtls/md_wrap.c
		mbedtls/memory_buffer_alloc.c
		mbedtls/oid.c
		mbedtls/padlock.c
		mbedtls/pem.c
		mbedtls/pk.c
		mbedtls/pkcs5.c
		mbedtls/pkcs11.c
		mbedtls/pkcs12.c
		mbedtls/pkparse.c
		mbedtls/pk_wrap.c
		mbedtls/pkwrite.c
		mbedtls/platform.c
		mbedtls/platform_util.c
		mbedtls/ripemd160.c
		mbedtls/rsa.c
		mbedtls/rsa_internal.c
		mbedtls/sha1.c
		mbedtls/sha256.c
		mbedtls/sha512.c
		mbedtls/ssl_cache.c
		mbedtls/ssl_ciphersuites.c
		mbedtls/ssl_cli.c
		mbedtls/ssl_cookie.c
		mbedtls/ssl_srv.c
		mbedtls/ssl_ticket.c
		mbedtls/ssl_tls.c
		mbedtls/threading.c
		mbedtls/timing.c
		mbedtls/version.c
		mbedtls/version_features.c
		mbedtls/x509.c
		mbedtls/x509_create.c
		mbedtls/x509_crl.c
		mbedtls/x509_crt.c
		mbedtls/x509_csr.c
		mbedtls/x509write_crt.c
		mbedtls/x509write_csr.c
		mbedtls/xtea.c
		
	DEPENDS
	)
