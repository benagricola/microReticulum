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

#pragma once

#include "Random.h"
#include "../Bytes.h"
#include "../Type.h"

#include <stdint.h>
#include <stdexcept>

#include <mbedtls/aes.h>

namespace RNS { namespace Cryptography {

    /*
    This class provides a slightly modified implementation of the Fernet spec
    found at: https://github.com/fernet/spec/blob/master/Spec.md

    According to the spec, a Fernet token includes a one byte VERSION and
    eight byte TIMESTAMP field at the start of each token. These fields are
    not relevant to Reticulum. They are therefore stripped from this
    implementation, since they incur overhead and leak initiator metadata.
    */

	// Thrown when the underlying AES driver fails to satisfy a crypt
	// operation due to resource exhaustion (e.g. esp-aes DMA buffer alloc
	// fail under internal-SRAM pressure). Caller (Link::decrypt /
	// Link::encrypt) catches this distinctly from "Could not decrypt
	// Token token" so the failure-counter and circuit breaker only fire
	// for genuine protocol-corruption signals — transient AES resource
	// failures don't tear down an otherwise-healthy link.
	class aes_resource_exhausted : public std::runtime_error {
	public:
		aes_resource_exhausted(const char* op, int rc)
			: std::runtime_error(std::string("AES ") + op +
			                     " out of resources (mbedtls rc=" +
			                     std::to_string(rc) + ")"),
			  _rc(rc) {}
		int rc() const { return _rc; }
	private:
		int _rc;
	};

	class Token {

	public:
		using Ptr = std::shared_ptr<Token>;

	public:
		static inline const Bytes generate_key(RNS::Type::Cryptography::Token::token_mode mode = RNS::Type::Cryptography::Token::MODE_AES_256_CBC) {
			if (mode == RNS::Type::Cryptography::Token::MODE_AES_128_CBC) return random(32);
			else if (mode == RNS::Type::Cryptography::Token::MODE_AES_256_CBC) return random(64);
			else throw new std::invalid_argument("Invalid token mode: " + std::to_string(mode));
		}

	public:
		Token(const Bytes& key, RNS::Type::Cryptography::Token::token_mode mode = RNS::Type::Cryptography::Token::MODE_AES);
		~Token();

		// mbedtls_aes_context is non-trivially copyable — disable copy
		// to keep the cached engine state consistent with the key.
		Token(const Token&) = delete;
		Token& operator=(const Token&) = delete;

		// Allocate process-wide internal-SRAM DMA-capable scratch buffers
		// used by Token::encrypt/decrypt to stage their AES input/output
		// when scratch is initialised. The firmware should call this
		// EARLY in setup() — before BLE/WiFi init — so the allocation
		// happens against a fresh DMA-cap heap and is large enough to
		// matter. Once allocated, the buffers are pinned for the device
		// lifetime: they double as a CONFIG_SPIRAM_MALLOC_RESERVE_INTERNAL
		// equivalent (preventing WiFi/lwIP from monopolising the DMA-cap
		// pool) and as the staging area for chunked AES-CBC.
		//
		// bytes_per_buffer is the size of EACH of the two buffers (in,
		// out). Total reservation = 2 * bytes_per_buffer. Returns true
		// on success, false on alloc failure (in which case Token falls
		// back to direct mbedtls_aes_crypt_cbc calls with no staging —
		// works for small messages, prone to esp-aes alloc failure
		// for big Resource transfers).
		//
		// Idempotent: subsequent calls return true if scratch already
		// allocated, regardless of the requested size.
		static bool init_shared_scratch(size_t bytes_per_buffer);

	public:
		bool verify_hmac(const Bytes& token);
		const Bytes encrypt(const Bytes& data);
		const Bytes decrypt(const Bytes& token);

	private:
		RNS::Type::Cryptography::Token::token_mode _mode = RNS::Type::Cryptography::Token::MODE_AES_256_CBC;
		Bytes _signing_key;
		Bytes _encryption_key;

		// AES engine state, set up once in the ctor (mbedtls_aes_setkey_*
		// runs the key schedule expansion which is the expensive step).
		// Per-call encrypt/decrypt just resets IV + runs the cipher.
		// Previously every Token::encrypt/decrypt stack-constructed a
		// fresh CBC<AES128> and called setKey() — that meant every
		// Resource part on a Link re-expanded the round-key schedule and
		// allocated a fresh esp-aes DMA buffer, which is what was failing
		// under fragmented internal-SRAM and silently corrupting output.
		mbedtls_aes_context _aes_enc;
		mbedtls_aes_context _aes_dec;
		bool _aes_ready = false;
	};

} }
