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
 * Simple wrapper around GnuTLS or OpenSSL DTLS.
 */

#include "rtcdcpp/DTLSWrapper.hpp"
#include "rtcdcpp/RTCCertificate.hpp"

#include <iostream>
#include <cassert>

#ifdef USE_GNUTLS

#include <gnutls/dtls.h>

namespace rtcdcpp {

using namespace std;

static bool check_gnutls(int ret, const std::string &message = "GnuTLS error") {
  if(ret < 0) {
    if(!gnutls_error_is_fatal(ret)) return false;
    throw std::runtime_error(message + ": " + gnutls_strerror(ret));
  }
  return true;
}

DTLSWrapper::DTLSWrapper(PeerConnection *peer_connection) :
  peer_connection(peer_connection),
  certificate_(nullptr),
  handshake_complete(false),
  should_stop(false) {
  if (peer_connection->config().certificates.size() != 1) {
    throw std::runtime_error("At least one and only one certificate has to be set");
  }
  certificate_ = &peer_connection->config().certificates.front();
  this->decrypted_callback = [](ChunkPtr x) {};
  this->encrypted_callback = [](ChunkPtr x) {};
}

DTLSWrapper::~DTLSWrapper() {
  Stop();
}

bool DTLSWrapper::Initialize() {
  gnutls_certificate_set_verify_function(certificate_->creds(), CertificateCallback);
  return true;
}

void DTLSWrapper::Start() {
  unsigned int flags = GNUTLS_DATAGRAM;
  flags|= (peer_connection->role == peer_connection->Server ? GNUTLS_SERVER : GNUTLS_CLIENT);
  check_gnutls(gnutls_init(&this->session, flags));
  
  const char *priorities = "SECURE128:-VERS-SSL3.0:-VERS-TLS1.0:-ARCFOUR-128";
  const char *err_pos = NULL;
  check_gnutls(gnutls_priority_set_direct(this->session, priorities, &err_pos), "Unable to set TLS priorities");
  
  gnutls_session_set_ptr(this->session, this);
  gnutls_transport_set_ptr(this->session, this);
  gnutls_transport_set_push_function(this->session, WriteCallback);
  gnutls_transport_set_pull_function(this->session, ReadCallback);
  gnutls_transport_set_pull_timeout_function(this->session, TimeoutCallback);

  check_gnutls(gnutls_credentials_set(this->session, GNUTLS_CRD_CERTIFICATE, certificate_->creds()));
  
  this->decrypt_thread = std::thread([this]() {
    SPDLOG_TRACE(logger, "Start(): Starting handshake - {}", std::this_thread::get_id());
    while(!check_gnutls(gnutls_handshake(this->session), "TLS handshake failed")) {}
    peer_connection->OnDTLSHandshakeDone();
    
    this->encrypt_thread = std::thread(&DTLSWrapper::RunEncrypt, this);
    this->RunDecrypt();
  });
}

void DTLSWrapper::Stop() {
  this->should_stop = true;
  gnutls_bye(this->session, GNUTLS_SHUT_RDWR);

  encrypt_queue.Stop();
  if (this->encrypt_thread.joinable()) {
    this->encrypt_thread.join();
  }
  decrypt_queue.Stop();
  if (this->decrypt_thread.joinable()) {
    this->decrypt_thread.join();
  }

  gnutls_deinit(this->session);
}

void DTLSWrapper::SetEncryptedCallback(std::function<void(ChunkPtr chunk)> encrypted_callback) { this->encrypted_callback = encrypted_callback; }

void DTLSWrapper::SetDecryptedCallback(std::function<void(ChunkPtr chunk)> decrypted_callback) { this->decrypted_callback = decrypted_callback; }

void DTLSWrapper::DecryptData(ChunkPtr chunk) { this->decrypt_queue.push(chunk); }

void DTLSWrapper::RunDecrypt() {
  SPDLOG_TRACE(logger, "RunDecrypt()");

  while (!this->should_stop) {
    const unsigned int bufSize = 2048;
    char buf[bufSize] = {0};
    ssize_t ret = gnutls_record_recv(this->session, buf, bufSize);
    if(!check_gnutls(ret)) continue;
    if(ret == 0) break;
    this->decrypted_callback(std::make_shared<Chunk>(buf, ret));
  }
}

void DTLSWrapper::EncryptData(ChunkPtr chunk) { this->encrypt_queue.push(chunk); }

void DTLSWrapper::RunEncrypt() {
  SPDLOG_TRACE(logger, "RunEncrypt()");
  while (!this->should_stop) {
    ChunkPtr chunk = this->encrypt_queue.wait_and_pop();
    if (!chunk) break;
    while (!should_stop) {
      ssize_t ret = gnutls_record_send(this->session, chunk->Data(), chunk->Length());
      if(!check_gnutls(ret)) continue;
      break;
    }
  }
}

int DTLSWrapper::CertificateCallback(gnutls_session_t session) {
  DTLSWrapper *w = static_cast<DTLSWrapper*>(gnutls_session_get_ptr(session));
  
  if(gnutls_certificate_type_get(session) != GNUTLS_CRT_X509) {
    return GNUTLS_E_CERTIFICATE_ERROR;
  }

  // Get peer's certificate
  unsigned int count = 0;
  const gnutls_datum_t *array = gnutls_certificate_get_peers(session, &count);
  if(!array || count == 0) {
    return GNUTLS_E_CERTIFICATE_ERROR;
  }
  
  gnutls_x509_crt_t crt;
  check_gnutls(gnutls_x509_crt_init(&crt));
  int ret = gnutls_x509_crt_import(crt, &array[0], GNUTLS_X509_FMT_DER);
  if(ret != GNUTLS_E_SUCCESS) {
    gnutls_x509_crt_deinit(crt);
    return GNUTLS_E_CERTIFICATE_ERROR;
  }
  
  std::string fingerprint = RTCCertificate::GenerateFingerprint(crt);
  gnutls_x509_crt_deinit(crt);
  
  return fingerprint == w->peer_connection->remoteFingerprint() ? GNUTLS_E_SUCCESS : GNUTLS_E_CERTIFICATE_ERROR;
}

ssize_t DTLSWrapper::WriteCallback(gnutls_transport_ptr_t ptr, const void* data, size_t len) {
  DTLSWrapper *w = static_cast<DTLSWrapper*>(ptr);
  if (len > 0) {
    w->encrypted_callback(std::make_shared<Chunk>(data, len));
  }
  return ssize_t(len);
}

ssize_t DTLSWrapper::ReadCallback(gnutls_transport_ptr_t ptr, void* data, size_t maxlen) {
  DTLSWrapper *w = static_cast<DTLSWrapper*>(ptr);
  while (!w->should_stop) {
    ChunkPtr chunk = w->decrypt_queue.wait_and_pop();
    if (!chunk) return 0;
    ssize_t len = std::min(maxlen, chunk->Size());
    std::memcpy(data, chunk->Data(), len);
    return len;
  }
  return -1;
}

int DTLSWrapper::TimeoutCallback(gnutls_transport_ptr_t ptr, unsigned int ms)
{
  // So ReadCallback is called
  return 1;
}

}

#else

#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/ssl.h>

namespace rtcdcpp {

using namespace std;

int DTLSWrapper::wrapper_ex_idx = -1;

DTLSWrapper::DTLSWrapper(PeerConnection *peer_connection)
    : peer_connection(peer_connection), certificate_(nullptr), handshake_complete(false), should_stop(false) {
  if (peer_connection->config().certificates.size() != 1) {
    throw std::runtime_error("At least one and only one certificate has to be set");
  }
  certificate_ = &peer_connection->config().certificates.front();
  this->decrypted_callback = [](ChunkPtr x) { ; };
  this->encrypted_callback = [](ChunkPtr x) { ; };
}

DTLSWrapper::~DTLSWrapper() {
  Stop();

  // NOTE: We intentionally do NOT free the BIO's manually

  if (ssl) {
    if (SSL_shutdown(ssl) == 0) {
      SSL_shutdown(ssl);
    }
    SSL_free(ssl);
    ssl = nullptr;
  }
  if (ctx) {
    SSL_CTX_free(ctx);
    ctx = nullptr;
  }
}

bool DTLSWrapper::Initialize() {
  ctx = SSL_CTX_new(DTLSv1_method());
  if (!ctx) {
    return false;
  }
  if (SSL_CTX_set_cipher_list(ctx, "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH") != 1) {
    return false;
  }

  SSL_CTX_set_read_ahead(ctx, 1);
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, CertificateCallback);
  SSL_CTX_set_verify_depth(ctx, 1);
  SSL_CTX_use_PrivateKey(ctx, certificate_->evp_pkey());
  SSL_CTX_use_certificate(ctx, certificate_->x509());

  if (SSL_CTX_check_private_key(ctx) != 1) {
    return false;
  }

  ssl = SSL_new(ctx);
  if (!ssl) {
    return false;
  }

  in_bio = BIO_new(BIO_s_mem());
  if (!in_bio) {
    return false;
  }
  BIO_set_mem_eof_return(in_bio, -1);

  out_bio = BIO_new(BIO_s_mem());
  if (!out_bio) {
    return false;
  }
  BIO_set_mem_eof_return(out_bio, -1);

  SSL_set_bio(ssl, in_bio, out_bio);

  std::shared_ptr<EC_KEY> ecdh = std::shared_ptr<EC_KEY>(EC_KEY_new_by_curve_name(NID_X9_62_prime256v1), EC_KEY_free);
  SSL_set_options(ssl, SSL_OP_SINGLE_ECDH_USE);
  SSL_set_tmp_ecdh(ssl, ecdh.get());

  if(wrapper_ex_idx == -1) {
    wrapper_ex_idx = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
  }
  SSL_set_ex_data(ssl, wrapper_ex_idx, this);
  
  return true;
}

void DTLSWrapper::Start() {
  SPDLOG_TRACE(logger, "Start(): Starting handshake - {}", std::this_thread::get_id());
  if (peer_connection->role == peer_connection->Server) {
    SSL_set_accept_state(ssl); // This is for role server.
  } else {
    SSL_set_connect_state(ssl);
  }
  uint8_t buf[4192];
  SSL_do_handshake(ssl);
  while (BIO_ctrl_pending(out_bio) > 0) {
    // XXX: This is not actually valid (buf + offset send after)
    int nbytes = BIO_read(out_bio, buf, sizeof(buf));
    if (nbytes > 0) {
      SPDLOG_TRACE(logger, "Start(): Sending handshake bytes {}", nbytes);
      this->encrypted_callback(std::make_shared<Chunk>(buf, nbytes));
    }
  }

  this->encrypt_thread = std::thread(&DTLSWrapper::RunEncrypt, this);
  this->decrypt_thread = std::thread(&DTLSWrapper::RunDecrypt, this);
}

void DTLSWrapper::Stop() {
  this->should_stop = true;

  encrypt_queue.Stop();
  if (this->encrypt_thread.joinable()) {
    this->encrypt_thread.join();
  }

  decrypt_queue.Stop();
  if (this->decrypt_thread.joinable()) {
    this->decrypt_thread.join();
  }
}

void DTLSWrapper::SetEncryptedCallback(std::function<void(ChunkPtr chunk)> encrypted_callback) { this->encrypted_callback = encrypted_callback; }

void DTLSWrapper::SetDecryptedCallback(std::function<void(ChunkPtr chunk)> decrypted_callback) { this->decrypted_callback = decrypted_callback; }

void DTLSWrapper::DecryptData(ChunkPtr chunk) { this->decrypt_queue.push(chunk); }

void DTLSWrapper::RunDecrypt() {
  SPDLOG_TRACE(logger, "RunDecrypt()");

  bool should_notify = false;
  while (!should_stop) {
    int read_bytes = 0;
    uint8_t buf[2048] = {0};
    ChunkPtr chunk = this->decrypt_queue.wait_and_pop();
    if (!chunk) return;
    size_t cur_len = chunk->Length();

    {
      std::lock_guard<std::mutex> lock(this->ssl_mutex);
      BIO_write(in_bio, chunk->Data(), (int)chunk->Length());
      read_bytes = SSL_read(ssl, buf, sizeof(buf));

      if (!handshake_complete) {
        if (BIO_ctrl_pending(out_bio)) {
          uint8_t out_buf[2048];
          int send_bytes = 0;
          while (BIO_ctrl_pending(out_bio) > 0) {
            send_bytes += BIO_read(out_bio, out_buf + send_bytes, sizeof(out_buf) - send_bytes);
          }
          if (send_bytes > 0) {
            this->encrypted_callback(std::make_shared<Chunk>(out_buf, send_bytes));
          }
        }

        if (SSL_is_init_finished(ssl)) {
          handshake_complete = true;
          should_notify = true;
        }
      }
    }

    if (read_bytes > 0) {
      this->decrypted_callback(std::make_shared<Chunk>(buf, read_bytes));
    } else {
      // TODO: SSL error checking
    }

    if (should_notify) {
      should_notify = false;
      peer_connection->OnDTLSHandshakeDone();
    }
  }
}

void DTLSWrapper::EncryptData(ChunkPtr chunk) { this->encrypt_queue.push(chunk); }

void DTLSWrapper::RunEncrypt() {
  SPDLOG_TRACE(logger, "RunEncrypt()");
  while (!this->should_stop) {
    ChunkPtr chunk = this->encrypt_queue.wait_and_pop();
    if (!chunk) return;

    {
      std::lock_guard<std::mutex> lock(this->ssl_mutex);
      uint8_t buf[2048] = {0};
      if (SSL_write(ssl, chunk->Data(), (int)chunk->Length()) <= 0) {
        // TODO: Error handling
      }

      int nbytes = 0;
      while (BIO_ctrl_pending(out_bio) > 0) {
        nbytes += BIO_read(out_bio, buf + nbytes, 2048 - nbytes);
      }

      if (nbytes > 0) {
        this->encrypted_callback(std::make_shared<Chunk>(buf, nbytes));
      }
    }
  }
}

int DTLSWrapper::CertificateCallback(int preverify_ok, X509_STORE_CTX *ctx) {
  SSL *ssl = static_cast<SSL*>(X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx()));
  DTLSWrapper *w = static_cast<DTLSWrapper*>(SSL_get_ex_data(ssl, DTLSWrapper::wrapper_ex_idx));
  
  X509 *crt = X509_STORE_CTX_get_current_cert(ctx);
  std::string fingerprint = RTCCertificate::GenerateFingerprint(crt);
  
  return fingerprint == w->peer_connection->remoteFingerprint() ? 1 : 0;
}

}

#endif

