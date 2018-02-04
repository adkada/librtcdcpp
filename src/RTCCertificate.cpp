/**
 * Copyright (c) 2017, Andrew Gault, Nick Chadwick and Guillaume Egles.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *    * Neither the name of the <organization> nor the
 *      names of its contributors may be used to endorse or promote products
 *      derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * Simple wrapper around GnuTLS or OpenSSL Certs.
 */

#include "rtcdcpp/RTCCertificate.hpp"

#include <cassert>
#include <ctime>

#ifdef USE_GNUTLS

#include <gnutls/crypto.h>

namespace rtcdcpp {

using namespace std;

static void check_gnutls(int ret, const std::string &message = "GnuTLS error") {
  if(ret != GNUTLS_E_SUCCESS)
    throw std::runtime_error(message + ": " + gnutls_strerror(ret));
}

static gnutls_certificate_credentials_t *create_creds() { 
  auto pcreds = new gnutls_certificate_credentials_t;
  check_gnutls(gnutls_certificate_allocate_credentials(pcreds));
  return pcreds;
}

static void delete_creds(gnutls_certificate_credentials_t *pcreds) {
  gnutls_certificate_free_credentials(*pcreds);
  delete pcreds;
}

static std::string GenerateFingerprint(gnutls_x509_crt_t crt) {
  const size_t bufSize = 32;
  unsigned char buf[bufSize];
  size_t len = bufSize;
  check_gnutls(gnutls_x509_crt_get_fingerprint(crt, GNUTLS_DIG_SHA256, buf, &len), "X509 fingerprint error");
  
  int offset = 0;
  char fp[SHA256_FINGERPRINT_SIZE];
  std::memset(fp, 0, SHA256_FINGERPRINT_SIZE);
  for (unsigned int i = 0; i < len; ++i) {
    snprintf(fp + offset, 4, "%02X:", buf[i]);
    offset += 3;
  }
  fp[offset - 1] = '\0';
  return std::string(fp);
}

RTCCertificate RTCCertificate::GenerateCertificate(std::string common_name, int days) {
  gnutls_x509_crt_t crt;
  gnutls_x509_privkey_t privkey;
  check_gnutls(gnutls_x509_crt_init(&crt)); 
  check_gnutls(gnutls_x509_privkey_init(&privkey)); 
  
  try {
    const unsigned int bits = gnutls_sec_param_to_pk_bits(GNUTLS_PK_RSA, GNUTLS_SEC_PARAM_HIGH);
    check_gnutls(gnutls_x509_privkey_generate(privkey, GNUTLS_PK_RSA, bits, 0), "Unable to generate key pair");
  
    gnutls_x509_crt_set_activation_time(crt, std::time(NULL) - 3600);
    gnutls_x509_crt_set_expiration_time(crt, std::time(NULL) + days*24*3600);
    gnutls_x509_crt_set_version(crt, 1);
    gnutls_x509_crt_set_key(crt, privkey);
    gnutls_x509_crt_set_dn_by_oid(crt, GNUTLS_OID_X520_COMMON_NAME, 0, common_name.data(), common_name.size());
  
    const size_t serialSize = 16;
    char serial[serialSize];
    gnutls_rnd(GNUTLS_RND_NONCE, serial, serialSize);
    gnutls_x509_crt_set_serial(crt, serial, serialSize);

    check_gnutls(gnutls_x509_crt_sign2(crt, crt, privkey, GNUTLS_DIG_SHA256, 0), "Unable to auto-sign certificate");

    return RTCCertificate(crt, privkey);
  }
  catch(...) {
    gnutls_x509_crt_deinit(crt);
    gnutls_x509_privkey_deinit(privkey);
    throw;
  }
}

RTCCertificate::RTCCertificate(std::string crt_pem, std::string key_pem) :
  creds_(create_creds(), delete_creds) {

  gnutls_datum_t crt_datum; crt_datum.data = (unsigned char*)crt_pem.data(); crt_datum.size = crt_pem.size();
  gnutls_datum_t key_datum; key_datum.data = (unsigned char*)key_pem.data(); key_datum.size = key_pem.size();
  check_gnutls(gnutls_certificate_set_x509_key_mem(*creds_, &crt_datum, &key_datum, GNUTLS_X509_FMT_PEM), "Unable to import PEM");

  gnutls_x509_crt_t *crt_list = NULL;
  unsigned int crt_list_size = 0;
  check_gnutls(gnutls_certificate_get_x509_crt(*creds_, 0, &crt_list, &crt_list_size));
  assert(crt_list_size == 1);
  try {
    fingerprint_ = GenerateFingerprint(crt_list[0]);
  }
  catch(...) {
    gnutls_x509_crt_deinit(crt_list[0]);
    gnutls_free(crt_list);
    throw;
  }
  gnutls_x509_crt_deinit(crt_list[0]);
  gnutls_free(crt_list);
}

RTCCertificate::RTCCertificate(gnutls_x509_crt_t crt, gnutls_x509_privkey_t privkey) : 
  creds_(create_creds(), delete_creds),
  fingerprint_(GenerateFingerprint(crt)) {

  check_gnutls(gnutls_certificate_set_x509_key(*creds_, &crt, 1, privkey), "Unable to set certificate and key pair in credentials");
  gnutls_x509_crt_deinit(crt);
  gnutls_x509_privkey_deinit(privkey);
}

}

#else

#include <openssl/pem.h>

namespace rtcdcpp {

using namespace std;

static std::shared_ptr<X509> GenerateX509(std::shared_ptr<EVP_PKEY> evp_pkey, const std::string &common_name, int days) {
  std::shared_ptr<X509> null_result;

  std::shared_ptr<X509> x509(X509_new(), X509_free);
  std::shared_ptr<BIGNUM> serial_number(BN_new(), BN_free);
  std::shared_ptr<X509_NAME> name(X509_NAME_new(), X509_NAME_free);

  if (!x509 || !serial_number || !name) {
    return null_result;
  }

  if (!X509_set_pubkey(x509.get(), evp_pkey.get())) {
    return null_result;
  }

  if (!BN_pseudo_rand(serial_number.get(), 64, 0, 0)) {
    return null_result;
  }

  ASN1_INTEGER *asn1_serial_number = X509_get_serialNumber(x509.get());
  if (!asn1_serial_number) {
    return null_result;
  }

  if (!BN_to_ASN1_INTEGER(serial_number.get(), asn1_serial_number)) {
    return null_result;
  }

  if (!X509_set_version(x509.get(), 0L)) {
    return null_result;
  }

  if (!X509_NAME_add_entry_by_NID(name.get(), NID_commonName, MBSTRING_UTF8, (unsigned char *)common_name.c_str(), -1, -1, 0)) {
    return null_result;
  }

  if (!X509_set_subject_name(x509.get(), name.get()) || !X509_set_issuer_name(x509.get(), name.get())) {
    return null_result;
  }

  if (!X509_gmtime_adj(X509_get_notBefore(x509.get()), 0) || !X509_gmtime_adj(X509_get_notAfter(x509.get()), days * 24 * 3600)) {
    return null_result;
  }

  if (!X509_sign(x509.get(), evp_pkey.get(), EVP_sha1())) {
    return null_result;
  }

  return x509;
}

static std::string GenerateFingerprint(std::shared_ptr<X509> x509) {
  unsigned int len;
  unsigned char buf[EVP_MAX_MD_SIZE] = {0};
  if (!X509_digest(x509.get(), EVP_sha256(), buf, &len)) {
    throw std::runtime_error("GenerateFingerprint(): X509_digest error");
  }

  if (len != 32) {
    throw std::runtime_error("GenerateFingerprint(): unexpected fingerprint size");
  }

  int offset = 0;
  char fp[SHA256_FINGERPRINT_SIZE];
  memset(fp, 0, SHA256_FINGERPRINT_SIZE);
  for (unsigned int i = 0; i < len; ++i) {
    snprintf(fp + offset, 4, "%02X:", buf[i]);
    offset += 3;
  }
  fp[offset - 1] = '\0';
  return std::string(fp);
}

RTCCertificate RTCCertificate::GenerateCertificate(std::string common_name, int days) {
  std::shared_ptr<EVP_PKEY> pkey(EVP_PKEY_new(), EVP_PKEY_free);
  RSA *rsa = RSA_new();

  std::shared_ptr<BIGNUM> exponent(BN_new(), BN_free);

  if (!pkey || !rsa || !exponent) {
    throw std::runtime_error("GenerateCertificate: !pkey || !rsa || !exponent");
  }

  if (!BN_set_word(exponent.get(), 0x10001) || !RSA_generate_key_ex(rsa, 2048, exponent.get(), NULL) || !EVP_PKEY_assign_RSA(pkey.get(), rsa)) {
    throw std::runtime_error("GenerateCertificate: Error generating key");
  }
  auto cert = GenerateX509(pkey, common_name, days);

  if (!cert) {
    throw std::runtime_error("GenerateCertificate: Error in GenerateX509");
  }
  return RTCCertificate(cert, pkey);
}

RTCCertificate::RTCCertificate(std::string crt_pem, std::string key_pem) {
  /* x509 */
  BIO *bio = BIO_new(BIO_s_mem());
  BIO_write(bio, crt_pem.c_str(), (int)crt_pem.length());

  x509_ = std::shared_ptr<X509>(PEM_read_bio_X509(bio, nullptr, 0, 0), X509_free);
  BIO_free(bio);
  if (!x509_) {
    throw std::invalid_argument("Could not read certificate PEM");
  }

  /* evp_pkey */
  bio = BIO_new(BIO_s_mem());
  BIO_write(bio, key_pem.c_str(), (int)key_pem.length());

  evp_pkey_ = std::shared_ptr<EVP_PKEY>(PEM_read_bio_PrivateKey(bio, nullptr, 0, 0), EVP_PKEY_free);
  BIO_free(bio);

  if (!evp_pkey_) {
    throw std::invalid_argument("Could not read key PEM");
  }

  fingerprint_ = GenerateFingerprint(x509_);
}

RTCCertificate::RTCCertificate(std::shared_ptr<X509> x509, std::shared_ptr<EVP_PKEY> evp_pkey)
    : x509_(x509), evp_pkey_(evp_pkey), fingerprint_(GenerateFingerprint(x509_)) {}
}

#endif

