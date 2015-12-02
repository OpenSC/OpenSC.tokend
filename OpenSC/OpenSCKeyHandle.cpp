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
#include <Security/cssmapple.h>

#include "libopensc/log.h"
#include "libopensc/asn1.h"
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


void OpenSCKeyHandle::generateRsaSignature(const Context &context,
CSSM_ALGORITHMS signOnly, const CssmData &input, CssmData &signature)
{
	unsigned int flags = 0;

	if (mKey.signKey()->type != SC_PKCS15_TYPE_PRKEY_RSA)
		CssmError::throwMe(CSSMERR_CSP_INVALID_ALGORITHM);

	// default to pkcs1 style padding
	switch(context.getInt(CSSM_ATTRIBUTE_PADDING, CSSM_PADDING_PKCS1)) {
		case CSSM_PADDING_NONE:
			flags |= SC_ALGORITHM_RSA_PAD_NONE;
			break;
		case CSSM_PADDING_PKCS1:
			flags |= SC_ALGORITHM_RSA_PAD_PKCS1;
			break;
		default:
			CssmError::throwMe(CSSMERR_CSP_INVALID_ATTR_PADDING);
	}

	switch (signOnly) {
		case CSSM_ALGID_MD5:
			if (input.Length != 16)
				CssmError::throwMe(CSSMERR_CSP_BLOCK_SIZE_MISMATCH);
			flags |= SC_ALGORITHM_RSA_HASH_MD5;
			break;
		case CSSM_ALGID_SHA1:
			if (input.Length != 20)
				CssmError::throwMe(CSSMERR_CSP_BLOCK_SIZE_MISMATCH);
			flags |= SC_ALGORITHM_RSA_HASH_SHA1;
			break;
		case CSSM_ALGID_SHA256:
			if (input.Length != 32)
				CssmError::throwMe(CSSMERR_CSP_BLOCK_SIZE_MISMATCH);
			flags |= SC_ALGORITHM_RSA_HASH_SHA256;
			break;
		case CSSM_ALGID_SHA384:
			if (input.Length != 48)
				CssmError::throwMe(CSSMERR_CSP_BLOCK_SIZE_MISMATCH);
			flags |= SC_ALGORITHM_RSA_HASH_SHA384;
			break;
		case CSSM_ALGID_SHA512:
			if (input.Length != 64)
				CssmError::throwMe(CSSMERR_CSP_BLOCK_SIZE_MISMATCH);
			flags |= SC_ALGORITHM_RSA_HASH_SHA512;
			break;
		case CSSM_ALGID_NONE:
			sc_debug(mToken.mScCtx, SC_LOG_DEBUG_NORMAL, "  NO digest (perhaps for SSL authentication)\n");
			flags |= SC_ALGORITHM_RSA_HASH_NONE;
			break;
		default:
			sc_debug(mToken.mScCtx, SC_LOG_DEBUG_NORMAL, "  Unknown signOnly value: 0x%0x, exiting\n", signOnly);
			CssmError::throwMe(CSSMERR_CSP_INVALID_DIGEST_ALGORITHM);
	}

	// Modulus size in bits
	size_t sig_len = (mKey.sizeInBits() + 7) / 8;
	unsigned char *outputData = reinterpret_cast<unsigned char *>(malloc(sig_len));
	if (outputData == NULL)
		CssmError::throwMe(CSSMERR_CSP_MEMORY_ERROR);

	// Call OpenSC to do the actual signing
	if (0 > sc_pkcs15_compute_signature(mToken.mScP15Card, mKey.signKey(),
			flags, input.Data, input.Length, outputData, sig_len)) {
		free(outputData);
		CssmError::throwMe(CSSMERR_CSP_FUNCTION_FAILED);
	}

	signature.Data = outputData;
	signature.Length = sig_len;
}


void OpenSCKeyHandle::generateEcdsaSignature(const Context &context,
CSSM_ALGORITHMS signOnly, const CssmData &input, CssmData &signature)
{
	unsigned int flags = 0;

	if (mKey.signKey()->type != SC_PKCS15_TYPE_PRKEY_EC)
		CssmError::throwMe(CSSMERR_CSP_INVALID_ALGORITHM);

	if (CSSM_PADDING_NONE != context.getInt(CSSM_ATTRIBUTE_PADDING,
				CSSM_PADDING_NONE))
		CssmError::throwMe(CSSMERR_CSP_INVALID_ATTR_PADDING);

	switch (signOnly) {
		case CSSM_ALGID_SHA1:
			if (input.Length != 20)
				CssmError::throwMe(CSSMERR_CSP_BLOCK_SIZE_MISMATCH);
			flags |= SC_ALGORITHM_ECDSA_HASH_SHA1;
			break;
		case CSSM_ALGID_SHA256:
			if (input.Length != 32)
				CssmError::throwMe(CSSMERR_CSP_BLOCK_SIZE_MISMATCH);
			flags |= SC_ALGORITHM_ECDSA_HASH_SHA256;
			break;
		case CSSM_ALGID_SHA384:
			if (input.Length != 48)
				CssmError::throwMe(CSSMERR_CSP_BLOCK_SIZE_MISMATCH);
			flags |= SC_ALGORITHM_ECDSA_HASH_SHA384;
			break;
		case CSSM_ALGID_SHA512:
			if (input.Length != 64)
				CssmError::throwMe(CSSMERR_CSP_BLOCK_SIZE_MISMATCH);
			flags |= SC_ALGORITHM_ECDSA_HASH_SHA512;
			break;
		case CSSM_ALGID_NONE:
			sc_debug(mToken.mScCtx, SC_LOG_DEBUG_NORMAL, "  NO digest (perhaps for SSL authentication)\n");
			flags |= SC_ALGORITHM_ECDSA_HASH_NONE;
			break;
		default:
			CssmError::throwMe(CSSMERR_CSP_INVALID_DIGEST_ALGORITHM);
			sc_debug(mToken.mScCtx, SC_LOG_DEBUG_NORMAL, "  Unknown signOnly value: 0x%0x, exiting\n", signOnly);
	}

	// double of field size in bytes
	size_t sig_len = 2*((mKey.sizeInBits() + 7) / 8);
	unsigned char *outputData = reinterpret_cast<unsigned char *>(malloc(sig_len));
	if (outputData == NULL)
		CssmError::throwMe(CSSMERR_CSP_MEMORY_ERROR);

	if (0 > sc_pkcs15_compute_signature(mToken.mScP15Card, mKey.signKey(),
				flags, input.Data, input.Length, outputData, sig_len)) {
		free(outputData);
		CssmError::throwMe(CSSMERR_CSP_FUNCTION_FAILED);
	}

	// Wrap the result of compute_signature() as ASN.1 SEQUENCE
	unsigned char *seq = NULL;
	size_t seqlen = 0;
	if (sc_asn1_sig_value_rs_to_sequence(mToken.mScCtx, outputData, sig_len, &seq, &seqlen))   {
		sc_debug(mToken.mScCtx, SC_LOG_DEBUG_NORMAL,
				"Failed to convert signature to ASN1 sequence format.\n");
		free(outputData);
		CssmError::throwMe(CSSMERR_CSP_INVALID_OUTPUT_VECTOR);
	}
	free(outputData);

	signature.Data = seq;
	signature.Length = seqlen;
}


void OpenSCKeyHandle::generateSignature(const Context &context,
CSSM_ALGORITHMS signOnly, const CssmData &input, CssmData &signature)
{
	sc_debug(mToken.mScCtx, SC_LOG_DEBUG_NORMAL, "In OpenSCKeyHandle::generateSignature()\n");

	if (context.type() != CSSM_ALGCLASS_SIGNATURE) {
		sc_debug(mToken.mScCtx, SC_LOG_DEBUG_NORMAL, "  ALGCLASS_SIGNATURE Unknown type: 0x%0x, exiting\n", context.type());
		CssmError::throwMe(CSSMERR_CSP_INVALID_CONTEXT);
	}

	switch (context.algorithm()) {
		case CSSM_ALGID_RSA:
			generateRsaSignature(context, signOnly, input, signature);
			break;
		case CSSM_ALGID_ECDSA:
			generateEcdsaSignature(context, signOnly, input, signature);
			break;
		default:
			CssmError::throwMe(CSSMERR_CSP_INVALID_ALGORITHM);
	}
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
