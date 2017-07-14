/*
 *  Copyright (c) 2004 Apple Computer, Inc. All Rights Reserved.
 *
 *  @APPLE_LICENSE_HEADER_START@
 *
 *  This file contains Original Code and/or Modifications of Original Code
 *  as defined in and that are subject to the Apple Public Source License
 *  Version 2.0 (the 'License'). You may not use this file except in
 *  compliance with the License. Please obtain a copy of the License at
 *  http://www.opensource.apple.com/apsl/ and read it before using this
 *  file.
 *
 *  The Original Code and all software distributed under the License are
 *  distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 *  EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 *  INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 *  Please see the License for the specific language governing rights and
 *  limitations under the License.
 *
 *  @APPLE_LICENSE_HEADER_END@
 */

#include "OpenSCKeyHandle.h"

#include "OpenSCRecord.h"
#include "OpenSCToken.h"

#include <security_utilities/debugging.h>
#include <security_utilities/utilities.h>
#include <security_cdsa_utilities/cssmerrors.h>
#include <Security/cssmerr.h>

#include "libopensc/log.h"
/************************** OpenSCKeyHandle ************************/

OpenSCKeyHandle::OpenSCKeyHandle(OpenSCToken &OpenSCToken,
const Tokend::MetaRecord &metaRecord, OpenSCKeyRecord &cacKey) :
Tokend::KeyHandle(metaRecord, &cacKey),
mToken(OpenSCToken), mKey(cacKey)
{
	sc_debug(mToken.mScCtx, SC_LOG_DEBUG_NORMAL, "In OpenSCKeyHandle:: OpenSCKeyHandle()\n");
}


OpenSCKeyHandle::~OpenSCKeyHandle()
{
}


void OpenSCKeyHandle::getKeySize(CSSM_KEY_SIZE &keySize)
{
	sc_debug(mToken.mScCtx, SC_LOG_DEBUG_NORMAL, "In OpenSCKeyHandle::getKeySize()\n", keySize);
	secdebug("crypto", "getKeySize");
	CssmError::throwMe(CSSM_ERRCODE_FUNCTION_NOT_IMPLEMENTED);
}


uint32 OpenSCKeyHandle::getOutputSize(const Context &context,
uint32 inputSize, bool encrypting)
{
	sc_debug(mToken.mScCtx, SC_LOG_DEBUG_NORMAL, "In OpenSCKeyHandle::geOutputSize()\n");
	secdebug("crypto", "getOutputSize");
	CssmError::throwMe(CSSM_ERRCODE_FUNCTION_NOT_IMPLEMENTED);
	return 0;
}


void OpenSCKeyHandle::generateSignature(const Context &context,
CSSM_ALGORITHMS signOnly, const CssmData &input, CssmData &signature)
{
	// for sc_pkcs15_compute_signature()
	unsigned int flags = 0;

	sc_debug(mToken.mScCtx, SC_LOG_DEBUG_NORMAL, "In OpenSCKeyHandle::generateSignature()\n");

	if (context.type() == CSSM_ALGCLASS_SIGNATURE) {
		sc_debug(mToken.mScCtx, SC_LOG_DEBUG_NORMAL, "  type == CSSM_ALGCLASS_SIGNATURE\n");
	}
	else {
		sc_debug(mToken.mScCtx, SC_LOG_DEBUG_NORMAL, "  Unknown type: 0x%0x, exiting\n", context.type());
		CssmError::throwMe(CSSMERR_CSP_INVALID_CONTEXT);
	}

	if (context.algorithm() == CSSM_ALGID_RSA) {
		sc_debug(mToken.mScCtx, SC_LOG_DEBUG_NORMAL, "  algorithm == CSSM_ALGID_RSA\n");
	}
	else {
		sc_debug(mToken.mScCtx, SC_LOG_DEBUG_NORMAL, "  Unknown algorithm: 0x%0x, exiting\n", context.algorithm());
		CssmError::throwMe(CSSMERR_CSP_INVALID_ALGORITHM);
	}

	if (signOnly == CSSM_ALGID_SHA1) {

		if (input.Length != 20)
			CssmError::throwMe(CSSMERR_CSP_BLOCK_SIZE_MISMATCH);
		flags |= SC_ALGORITHM_RSA_HASH_SHA1;
		sc_debug(mToken.mScCtx, SC_LOG_DEBUG_NORMAL, "  Using SHA1, length is 20\n");
	}
	else if (signOnly == CSSM_ALGID_SHA256) {
		if (input.Length != 32)
			CssmError::throwMe(CSSMERR_CSP_BLOCK_SIZE_MISMATCH);
		flags |= SC_ALGORITHM_RSA_HASH_SHA256;
		sc_debug(mToken.mScCtx, SC_LOG_DEBUG_NORMAL, "  Using SHA256, length is 32\n");
	}
	else if (signOnly == CSSM_ALGID_SHA384) {
		if (input.Length != 48)
			CssmError::throwMe(CSSMERR_CSP_BLOCK_SIZE_MISMATCH);
		flags |= SC_ALGORITHM_RSA_HASH_SHA384;
		sc_debug(mToken.mScCtx, SC_LOG_DEBUG_NORMAL, "  Using SHA384, length is 48\n");
	}
	else if (signOnly == CSSM_ALGID_SHA512) {
		if (input.Length != 64)
			CssmError::throwMe(CSSMERR_CSP_BLOCK_SIZE_MISMATCH);
		flags |= SC_ALGORITHM_RSA_HASH_SHA512;
		sc_debug(mToken.mScCtx, SC_LOG_DEBUG_NORMAL, "  Using SHA512, length is 64\n");
	}
	else if (signOnly == CSSM_ALGID_MD5) {
		if (input.Length != 16)
			CssmError::throwMe(CSSMERR_CSP_BLOCK_SIZE_MISMATCH);
		flags |= SC_ALGORITHM_RSA_HASH_MD5;
		sc_debug(mToken.mScCtx, SC_LOG_DEBUG_NORMAL, "  Using MD5, length is 16\n");

	}
	else if (signOnly == CSSM_ALGID_NONE) {
		sc_debug(mToken.mScCtx, SC_LOG_DEBUG_NORMAL, "  NO digest (perhaps for SSL authentication)\n");
		flags |= SC_ALGORITHM_RSA_HASH_NONE;
	}
	else {
		sc_debug(mToken.mScCtx, SC_LOG_DEBUG_NORMAL, "  Unknown signOnly value: 0x%0x, exiting\n", signOnly);
		CssmError::throwMe(CSSMERR_CSP_INVALID_DIGEST_ALGORITHM);
	}

	// Get padding, but default to pkcs1 style padding
	uint32 padding = CSSM_PADDING_PKCS1;
	context.getInt(CSSM_ATTRIBUTE_PADDING, padding);

	if (padding == CSSM_PADDING_PKCS1) {
		sc_debug(mToken.mScCtx, SC_LOG_DEBUG_NORMAL, "  PKCS#1 padding\n");
		flags |= SC_ALGORITHM_RSA_PAD_PKCS1;
	}
	else if (padding == CSSM_PADDING_NONE) {
		sc_debug(mToken.mScCtx, SC_LOG_DEBUG_NORMAL, "  NO padding\n");
	}
	else {
		sc_debug(mToken.mScCtx, SC_LOG_DEBUG_NORMAL, "  Unknown padding 0x%0x, exiting\n", padding);
		CssmError::throwMe(CSSMERR_CSP_INVALID_ATTR_PADDING);
	}

	size_t keyLength = (mKey.sizeInBits() + 7) / 8;
	// @@@ Switch to using tokend allocators
	unsigned char *outputData =
		reinterpret_cast<unsigned char *>(malloc(keyLength));
	if (outputData == NULL)
		CssmError::throwMe(CSSMERR_CSP_MEMORY_ERROR);

	sc_debug(mToken.mScCtx, SC_LOG_DEBUG_NORMAL, "  Signing buffers: inlen=%d, outlen=%d\n",input.Length, keyLength);
	// Call OpenSC to do the actual signing
	int rv = sc_pkcs15_compute_signature(mToken.mScP15Card,
		mKey.signKey(), flags, input.Data, input.Length, outputData, keyLength);
	sc_debug(mToken.mScCtx, SC_LOG_DEBUG_NORMAL, "  sc_pkcs15_compute_signature(): rv = %d\n", rv);
	if (rv < 0) {
		free(outputData);
		CssmError::throwMe(CSSMERR_CSP_FUNCTION_FAILED);
	}
	signature.Data = outputData;
	signature.Length = rv;
}


void OpenSCKeyHandle::verifySignature(const Context &context,
CSSM_ALGORITHMS signOnly, const CssmData &input, const CssmData &signature)
{
	secdebug("crypto", "verifySignature");
	CssmError::throwMe(CSSM_ERRCODE_FUNCTION_NOT_IMPLEMENTED);
}


void OpenSCKeyHandle::generateMac(const Context &context,
const CssmData &input, CssmData &output)
{
	secdebug("crypto", "generateMac");
	CssmError::throwMe(CSSM_ERRCODE_FUNCTION_NOT_IMPLEMENTED);
}


void OpenSCKeyHandle::verifyMac(const Context &context,
const CssmData &input, const CssmData &compare)
{
	secdebug("crypto", "verifyMac");
	CssmError::throwMe(CSSM_ERRCODE_FUNCTION_NOT_IMPLEMENTED);
}


void OpenSCKeyHandle::encrypt(const Context &context,
const CssmData &clear, CssmData &cipher)
{
	secdebug("crypto", "encrypt");
	CssmError::throwMe(CSSM_ERRCODE_FUNCTION_NOT_IMPLEMENTED);
}


void OpenSCKeyHandle::decrypt(const Context &context,
const CssmData &cipher, CssmData &clear)
{
	secdebug("crypto", "decrypt alg: %lu", (long unsigned int) context.algorithm());
	sc_debug(mToken.mScCtx, SC_LOG_DEBUG_NORMAL, "In OpenSCKeyHandle::decrypt(ciphertext length = %d)\n", cipher.Length);

	if (context.type() != CSSM_ALGCLASS_ASYMMETRIC)
		CssmError::throwMe(CSSMERR_CSP_INVALID_CONTEXT);

	if (context.algorithm() != CSSM_ALGID_RSA)
		CssmError::throwMe(CSSMERR_CSP_INVALID_ALGORITHM);

	// @@@ Switch to using tokend allocators
	unsigned char *outputData =
		reinterpret_cast<unsigned char *>(malloc(cipher.Length));
	if (outputData == NULL)
		CssmError::throwMe(CSSMERR_CSP_MEMORY_ERROR);

	// Call OpenSC to do the actual decryption
	int rv = sc_pkcs15_decipher(mToken.mScP15Card,
		mKey.decryptKey(), SC_ALGORITHM_RSA_PAD_PKCS1,
		cipher.Data, cipher.Length, outputData, cipher.Length);
	sc_debug(mToken.mScCtx, SC_LOG_DEBUG_NORMAL, "  sc_pkcs15_decipher(): rv = %d\n", rv);
	if (rv < 0) {
		free(outputData);
		CssmError::throwMe(CSSMERR_CSP_FUNCTION_FAILED);
	}
	clear.Data = outputData;
	clear.Length = rv;

	sc_debug(mToken.mScCtx, SC_LOG_DEBUG_NORMAL, "  decrypt(): returning with %d decrypted bytes%d\n", clear.Length);
}


void OpenSCKeyHandle::exportKey(const Context &context,
const AccessCredentials *cred, CssmKey &wrappedKey)
{
	sc_debug(mToken.mScCtx, SC_LOG_DEBUG_NORMAL, "exportKey");
	CssmError::throwMe(CSSM_ERRCODE_FUNCTION_NOT_IMPLEMENTED);
}


/********************** OpenSCKeyHandleFactory *********************/

OpenSCKeyHandleFactory::~OpenSCKeyHandleFactory()
{
}


Tokend::KeyHandle *OpenSCKeyHandleFactory::keyHandle(
Tokend::TokenContext *tokenContext, const Tokend::MetaRecord &metaRecord,
Tokend::Record &record) const
{
	OpenSCKeyRecord &key = dynamic_cast<OpenSCKeyRecord &>(record);
	OpenSCToken &openSCToken = static_cast<OpenSCToken &>(*tokenContext);
	return new OpenSCKeyHandle(openSCToken, metaRecord, key);
}
