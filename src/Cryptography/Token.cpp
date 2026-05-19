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

using namespace RNS;
using namespace RNS::Cryptography;
using namespace RNS::Type::Cryptography::Token;

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

	DEBUGF("Token::encrypt: plaintext length: %lu", data.size());
	Bytes iv = random(16);
	TRACEF("Token::encrypt: iv:         %s", iv.toHex().c_str());
	TRACEF("Token::encrypt: plaintext:  %s", data.toHex().c_str());

	// PKCS7 pad the plaintext to a 16-byte boundary.
	Bytes padded = PKCS7::pad(data);

	// mbedtls_aes_crypt_cbc MUTATES the IV buffer (advances it to the
	// last ciphertext block). We must pass a writable copy so the
	// caller's iv stays intact.
	uint8_t iv_buf[16];
	memcpy(iv_buf, iv.data(), 16);

	Bytes ciphertext;
	uint8_t* out = ciphertext.writable(padded.size());
	if (!out) {
		throw std::runtime_error("Token::encrypt: failed to allocate ciphertext buffer");
	}

	const int rc = mbedtls_aes_crypt_cbc(
		&_aes_enc,
		MBEDTLS_AES_ENCRYPT,
		padded.size(),
		iv_buf,
		padded.data(),
		out);
	if (rc != 0) {
		// Most likely path: esp-aes returned ESP_ERR_NO_MEM because the
		// internal DMA buffer alloc failed under SRAM fragmentation.
		// Propagate as a typed exception so the caller can treat it as
		// transient (retry next packet) rather than as a protocol-level
		// decrypt-fail.
		throw aes_resource_exhausted("encrypt", rc);
	}

	DEBUGF("Token::encrypt: padded ciphertext length: %lu", ciphertext.size());
	TRACEF("Token::encrypt: ciphertext: %s", ciphertext.toHex().c_str());

	Bytes signed_parts = iv + ciphertext;

	Bytes sig(HMAC::generate(_signing_key, signed_parts)->digest());
	TRACEF("Token::encrypt: sig:        %s", sig.toHex().c_str());
	Bytes token(signed_parts + sig);
	DEBUGF("Token::encrypt: token length: %lu", token.size());
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

	const int rc = mbedtls_aes_crypt_cbc(
		&_aes_dec,
		MBEDTLS_AES_DECRYPT,
		ciphertext.size(),
		iv_buf,
		ciphertext.data(),
		out);
	if (rc != 0) {
		// Same transient-resource path as encrypt. Propagate as typed
		// exception — distinct from genuine "Could not decrypt Token
		// token" (which used to swallow this case and mask the real
		// cause).
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