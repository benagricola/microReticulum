/*
 * Copyright (c) 2023 Chad Attermann
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 */

#include "Token.h"

#include "HMAC.h"
#include "PKCS7.h"
#include "AES.h"
#include "../Log.h"

#include <stdexcept>
#include <time.h>

#include <mbedtls/aes.h>
#if defined(ARDUINO_ARCH_ESP32) || defined(ESP32)
#include <esp_heap_caps.h>
#endif

using namespace RNS;
using namespace RNS::Cryptography;
using namespace RNS::Type::Cryptography::Token;

namespace {
	// Shared process-wide AES staging scratch. Lazily allocated by
	// Token::init_shared_scratch() from the firmware setup() before
	// BLE/WiFi initialise. See the header for the rationale (it's
	// our runtime equivalent of CONFIG_SPIRAM_MALLOC_RESERVE_INTERNAL).
	//
	// Access is serialised by the firmware's rns_lock; tests are
	// single-threaded.
	uint8_t* g_aes_scratch_in   = nullptr;
	uint8_t* g_aes_scratch_out  = nullptr;
	size_t   g_aes_scratch_size = 0;

	// Stage an AES-CBC operation through the internal-SRAM scratch
	// buffers in chunks of g_aes_scratch_size. mbedtls_aes_crypt_cbc
	// updates iv[] to the last ciphertext block on each call, so CBC
	// chaining across chunks is preserved without any intervention.
	//
	// Requires g_aes_scratch_size > 0 — caller MUST check this.
	int aes_crypt_cbc_staged(mbedtls_aes_context* ctx, int mode,
	                         size_t length,
	                         unsigned char* iv,
	                         const unsigned char* input,
	                         unsigned char* output) {
		size_t offset = 0;
		while (offset < length) {
			size_t this_chunk = length - offset;
			if (this_chunk > g_aes_scratch_size) this_chunk = g_aes_scratch_size;
			memcpy(g_aes_scratch_in, input + offset, this_chunk);
			const int rc = mbedtls_aes_crypt_cbc(
				ctx, mode, this_chunk, iv,
				g_aes_scratch_in, g_aes_scratch_out);
			if (rc != 0) return rc;
			memcpy(output + offset, g_aes_scratch_out, this_chunk);
			offset += this_chunk;
		}
		return 0;
	}
}

bool Token::init_shared_scratch(size_t bytes_per_buffer) {
	if (g_aes_scratch_in && g_aes_scratch_out && g_aes_scratch_size > 0) {
		return true;
	}
	if (bytes_per_buffer == 0 || (bytes_per_buffer % 16) != 0) {
		ERRORF("Token::init_shared_scratch: bytes_per_buffer must be a "
		       "non-zero multiple of 16 (got %u)",
		       (unsigned)bytes_per_buffer);
		return false;
	}
#if defined(ARDUINO_ARCH_ESP32) || defined(ESP32)
	g_aes_scratch_in = (uint8_t*)heap_caps_malloc(
		bytes_per_buffer, MALLOC_CAP_DMA | MALLOC_CAP_INTERNAL);
	g_aes_scratch_out = (uint8_t*)heap_caps_malloc(
		bytes_per_buffer, MALLOC_CAP_DMA | MALLOC_CAP_INTERNAL);
#else
	g_aes_scratch_in  = (uint8_t*)malloc(bytes_per_buffer);
	g_aes_scratch_out = (uint8_t*)malloc(bytes_per_buffer);
#endif
	if (!g_aes_scratch_in || !g_aes_scratch_out) {
		if (g_aes_scratch_in)  { free(g_aes_scratch_in);  g_aes_scratch_in  = nullptr; }
		if (g_aes_scratch_out) { free(g_aes_scratch_out); g_aes_scratch_out = nullptr; }
		ERRORF("Token::init_shared_scratch: failed to allocate 2 x %u "
		       "bytes of DMA-cap internal SRAM",
		       (unsigned)bytes_per_buffer);
		return false;
	}
	g_aes_scratch_size = bytes_per_buffer;
#if defined(ARDUINO_ARCH_ESP32) || defined(ESP32)
	INFOF("Token: AES scratch reservation %u + %u bytes (in=%p out=%p) "
	      "dma_free_after=%u",
	      (unsigned)bytes_per_buffer, (unsigned)bytes_per_buffer,
	      g_aes_scratch_in, g_aes_scratch_out,
	      (unsigned)heap_caps_get_free_size(MALLOC_CAP_DMA));
#endif
	return true;
}

Token::Token(const Bytes& key, token_mode mode /*= AES*/) {

	if (!key) {
		throw std::invalid_argument("Token key cannot be None");
	}

	if (mode == MODE_AES) {
		if (key.size() == 32) {
			_mode = MODE_AES_128_CBC;
			//p self._signing_key = key[:16]
			_signing_key = key.left(16);
			//p self._encryption_key = key[16:]
			_encryption_key = key.mid(16);
		}
		else if (key.size() == 64) {
			_mode = MODE_AES_256_CBC;
			//p self._signing_key = key[:32]
			_signing_key = key.left(32);
			//p self._encryption_key = key[32:]
			_encryption_key = key.mid(32);
		}
		else {
			throw std::invalid_argument("Token key must be 128 or 256 bits, not " + std::to_string(key.size()*8));
		}
	}
	else {
		throw std::invalid_argument("Invalid token mode: " + std::to_string(mode));
	}

	// Set up the AES engine contexts ONCE here. The key schedule (the
	// expensive part of AES setup) is computed by mbedtls_aes_setkey_*
	// and lives in the mbedtls_aes_context for the Token's lifetime;
	// per-call encrypt/decrypt only needs to reset the IV + run the
	// cipher. Saves the per-packet esp_aes_setkey call that the old
	// CBC<AES128> wrapper made (and which contributed to internal-SRAM
	// fragmentation under sustained Resource transfer).
	mbedtls_aes_init(&_aes_enc);
	mbedtls_aes_init(&_aes_dec);
	const unsigned int keybits =
		(_mode == MODE_AES_128_CBC) ? 128 : 256;
	int rc_e = mbedtls_aes_setkey_enc(&_aes_enc, _encryption_key.data(), keybits);
	int rc_d = mbedtls_aes_setkey_dec(&_aes_dec, _encryption_key.data(), keybits);
	if (rc_e != 0 || rc_d != 0) {
		// setkey failure here is unrecoverable; the Token is constructed
		// in a non-functional state but won't crash subsequent calls
		// (encrypt/decrypt will detect _aes_ready=false and throw).
		mbedtls_aes_free(&_aes_enc);
		mbedtls_aes_free(&_aes_dec);
		ERRORF("Token: mbedtls_aes_setkey_{enc,dec} failed (rc_e=%d rc_d=%d)",
		       rc_e, rc_d);
		throw aes_resource_exhausted("setkey", rc_e != 0 ? rc_e : rc_d);
	}
	_aes_ready = true;

	MEM("Token object created");
}

Token::~Token() {
	if (_aes_ready) {
		mbedtls_aes_free(&_aes_enc);
		mbedtls_aes_free(&_aes_dec);
		_aes_ready = false;
	}
	MEM("Token object destroyed");
}

bool Token::verify_hmac(const Bytes& token) {

	if (token.size() <= 32) {
		throw std::invalid_argument("Cannot verify HMAC on token of only " + std::to_string(token.size()) + " bytes");
	}

	//received_hmac = token[-32:]
	Bytes received_hmac = token.right(32);
	DEBUGF("Token::verify_hmac: received_hmac: %s", received_hmac.toHex().c_str());
	//expected_hmac = HMAC.new(self._signing_key, token[:-32]).digest()
	Bytes expected_hmac = HMAC::generate(_signing_key, token.left(token.size()-32))->digest();
	DEBUGF("Token::verify_hmac: expected_hmac: %s", expected_hmac.toHex().c_str());

	return (received_hmac == expected_hmac);
}

const Bytes Token::encrypt(const Bytes& data) {

	if (!_aes_ready) {
		throw std::runtime_error("Token::encrypt: AES engine not initialised");
	}

	// Per-encrypt heap trace. Investigation-only; fires three NOTICEF log
	// lines per ciphertext on the hot path, so compiled out unless the
	// firmware build defines RNS_VERBOSE_DIAG.
#if defined(RNS_VERBOSE_DIAG) && (defined(ARDUINO_ARCH_ESP32) || defined(ESP32))
	NOTICEF("AES enc[ENTER] len=%u dma_free=%u dma_largest=%u sram_free=%u",
	       (unsigned)data.size(),
	       (unsigned)heap_caps_get_free_size(MALLOC_CAP_DMA),
	       (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_DMA),
	       (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL));
#endif
	DEBUGF("Token::encrypt: plaintext length: %lu", data.size());
	Bytes iv = random(16);
	TRACEF("Token::encrypt: iv:         %s", iv.toHex().c_str());
	TRACEF("Token::encrypt: plaintext:  %s", data.toHex().c_str());

	Bytes padded = PKCS7::pad(data);

	uint8_t iv_buf[16];
	memcpy(iv_buf, iv.data(), 16);

	Bytes ciphertext;
	uint8_t* out = ciphertext.writable(padded.size());
	if (!out) {
		throw std::runtime_error("Token::encrypt: failed to allocate ciphertext buffer");
	}

	const int rc = (g_aes_scratch_size > 0)
		? aes_crypt_cbc_staged(&_aes_enc, MBEDTLS_AES_ENCRYPT,
		                       padded.size(), iv_buf,
		                       padded.data(), out)
		: mbedtls_aes_crypt_cbc(&_aes_enc, MBEDTLS_AES_ENCRYPT,
		                        padded.size(), iv_buf,
		                        padded.data(), out);
	if (rc != 0) {
		throw aes_resource_exhausted("encrypt", rc);
	}

#if defined(RNS_VERBOSE_DIAG) && (defined(ARDUINO_ARCH_ESP32) || defined(ESP32))
	NOTICEF("AES enc[POST-CBC] len=%u dma_free=%u dma_largest=%u sram_free=%u",
	       (unsigned)padded.size(),
	       (unsigned)heap_caps_get_free_size(MALLOC_CAP_DMA),
	       (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_DMA),
	       (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL));
#endif

	DEBUGF("Token::encrypt: padded ciphertext length: %lu", ciphertext.size());
	TRACEF("Token::encrypt: ciphertext: %s", ciphertext.toHex().c_str());

	Bytes signed_parts = iv + ciphertext;
	Bytes sig(HMAC::generate(_signing_key, signed_parts)->digest());
	TRACEF("Token::encrypt: sig:        %s", sig.toHex().c_str());
	Bytes token(signed_parts + sig);
	DEBUGF("Token::encrypt: token length: %lu", token.size());
#if defined(RNS_VERBOSE_DIAG) && (defined(ARDUINO_ARCH_ESP32) || defined(ESP32))
	NOTICEF("AES enc[EXIT] token_len=%u dma_free=%u dma_largest=%u sram_free=%u",
	       (unsigned)token.size(),
	       (unsigned)heap_caps_get_free_size(MALLOC_CAP_DMA),
	       (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_DMA),
	       (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL));
#endif
	return token;
}


const Bytes Token::decrypt(const Bytes& token) {

	if (!_aes_ready) {
		throw std::runtime_error("Token::decrypt: AES engine not initialised");
	}

	DEBUGF("Token::decrypt: token length: %lu", token.size());
	if (token.size() < 48) {
		throw std::invalid_argument("Cannot decrypt token of only " + std::to_string(token.size()) + " bytes");
	}

	if (!verify_hmac(token)) {
		throw std::invalid_argument("Token token HMAC was invalid");
	}

	//iv = token[:16]
	Bytes iv = token.left(16);
	TRACEF("Token::decrypt: iv:         %s", iv.toHex().c_str());

	//ciphertext = token[16:-32]
	Bytes ciphertext = token.mid(16, token.size()-48);
	TRACEF("Token::decrypt: ciphertext: %s", ciphertext.toHex().c_str());

	// mbedtls_aes_crypt_cbc mutates the IV; copy it to a writable buf.
	uint8_t iv_buf[16];
	memcpy(iv_buf, iv.data(), 16);

	Bytes plaintext;
	uint8_t* out = plaintext.writable(ciphertext.size());
	if (!out) {
		throw std::runtime_error("Token::decrypt: failed to allocate plaintext buffer");
	}

	const int rc = (g_aes_scratch_size > 0)
		? aes_crypt_cbc_staged(&_aes_dec, MBEDTLS_AES_DECRYPT,
		                       ciphertext.size(), iv_buf,
		                       ciphertext.data(), out)
		: mbedtls_aes_crypt_cbc(&_aes_dec, MBEDTLS_AES_DECRYPT,
		                        ciphertext.size(), iv_buf,
		                        ciphertext.data(), out);
	if (rc != 0) {
		throw aes_resource_exhausted("decrypt", rc);
	}

	try {
		PKCS7::inplace_unpad(plaintext);
	}
	catch (const std::exception& e) {
		// HMAC verified but PKCS7 padding is invalid — this should be
		// impossible if both peers' keys and IVs match and AES didn't
		// silently corrupt output. Surface as "Could not decrypt Token
		// token" (the historical message) so existing callers keep
		// their behaviour.
		WARNING("Could not decrypt Token token");
		throw std::runtime_error("Could not decrypt Token token");
	}

	DEBUGF("Token::decrypt: plaintext length: %lu", plaintext.size());
	TRACEF("Token::decrypt: plaintext:  %s", plaintext.toHex().c_str());
	return plaintext;
}