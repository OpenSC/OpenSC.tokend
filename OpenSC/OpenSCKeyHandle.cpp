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
#include "OpenSCLog.h"

#include <security_utilities/debugging.h>
#include <security_utilities/utilities.h>
#include <security_cdsa_utilities/cssmerrors.h>
#include <Security/cssmerr.h>

/************************** OpenSCKeyHandle ************************/

OpenSCKeyHandle::OpenSCKeyHandle(OpenSCToken &OpenSCToken,
const Tokend::MetaRecord &metaRecord, OpenSCKeyRecord &cacKey) :
Tokend::KeyHandle(metaRecord, &cacKey),
mToken(OpenSCToken), mKey(cacKey)
{
    otdLog("In OpenSCKeyHandle:: OpenSCKeyHandle()\n");
}


OpenSCKeyHandle::~OpenSCKeyHandle()
{
}


void OpenSCKeyHandle::getKeySize(CSSM_KEY_SIZE &keySize)
{
    otdLog("In OpenSCKeyHandle::getKeySize()\n", keySize);
    secdebug("crypto", "getKeySize");
    CssmError::throwMe(CSSM_ERRCODE_FUNCTION_NOT_IMPLEMENTED);
}


uint32 OpenSCKeyHandle::getOutputSize(const Context &context,
uint32 inputSize, bool encrypting)
{
    otdLog("In OpenSCKeyHandle::getKeySize()\n");
    secdebug("crypto", "getOutputSize");
    CssmError::throwMe(CSSM_ERRCODE_FUNCTION_NOT_IMPLEMENTED);
    return 0;
}


void OpenSCKeyHandle::generateSignature(const Context &context,
CSSM_ALGORITHMS signOnly, const CssmData &input, CssmData &signature)
{
    // for sc_pkcs15_compute_signature()
    unsigned int flags = 0;

    otdLog("In OpenSCKeyHandle::generateSignature()\n");

    if (context.type() == CSSM_ALGCLASS_SIGNATURE)
    {
        otdLog("  type == CSSM_ALGCLASS_SIGNATURE\n");
    }
    else
    {
        otdLog("  Unknown type: 0x%0x, exiting\n", context.type());
        CssmError::throwMe(CSSMERR_CSP_INVALID_CONTEXT);
    }

    if (context.algorithm() == CSSM_ALGID_RSA)
    {
        otdLog("  algorithm == CSSM_ALGID_RSA\n");
    }
    else
    {
        otdLog("  Unknown algorithm: 0x%0x, exiting\n", context.algorithm());
        CssmError::throwMe(CSSMERR_CSP_INVALID_ALGORITHM);
    }

    if (signOnly == CSSM_ALGID_SHA1)
    {

        if (input.Length != 20)
            CssmError::throwMe(CSSMERR_CSP_BLOCK_SIZE_MISMATCH);
        flags |= SC_ALGORITHM_RSA_HASH_SHA1;
        otdLog("  Using SHA1, length is 20\n");
    }
    else if (signOnly == CSSM_ALGID_MD5)
    {
        if (input.Length != 16)
            CssmError::throwMe(CSSMERR_CSP_BLOCK_SIZE_MISMATCH);
        flags |= SC_ALGORITHM_RSA_HASH_MD5;
        otdLog("  Using MD5, length is 16\n");

    }
    else if (signOnly == CSSM_ALGID_NONE)
    {
        otdLog("  NO digest (perhaps for SSL authentication)\n");
        flags |= SC_ALGORITHM_RSA_HASH_NONE;
    }
    else
    {
        otdLog("  Unknown signOnly value: 0x%0x, exiting\n", signOnly);
        CssmError::throwMe(CSSMERR_CSP_INVALID_DIGEST_ALGORITHM);
    }

    // Get padding, but default to pkcs1 style padding
    uint32 padding = CSSM_PADDING_PKCS1;
    context.getInt(CSSM_ATTRIBUTE_PADDING, padding);

    if (padding == CSSM_PADDING_PKCS1)
    {
        otdLog("  PKCS#1 padding\n");
        flags |= SC_ALGORITHM_RSA_PAD_PKCS1;
    }
    else if (padding == CSSM_PADDING_NONE)
    {
        otdLog("  NO padding\n");
    }
    else
    {
        otdLog("  Unknown padding 0x%0x, exiting\n", padding);
        CssmError::throwMe(CSSMERR_CSP_INVALID_ATTR_PADDING);
    }

    size_t keyLength = (mKey.sizeInBits() + 7) / 8;
    // @@@ Switch to using tokend allocators
    unsigned char *outputData =
        reinterpret_cast<unsigned char *>(malloc(keyLength));
    if (outputData == NULL)
        CssmError::throwMe(CSSMERR_CSP_MEMORY_ERROR);

    // Call OpenSC to do the actual signing
    int rv = sc_pkcs15_compute_signature(mToken.mScP15Card,
        mKey.object(), flags, input.Data, input.Length, outputData, keyLength);
    otdLog("  sc_pkcs15_compute_signature(): rv = %d\n", rv);
    if (rv < 0)
    {
        free(outputData);
        CssmError::throwMe(CSSMERR_CSP_FUNCTION_FAILED);
    }
    signature.Data = outputData;
    signature.Length = rv;

    otdLogHex("  generateSignature(): signature, sig:",
        signature.Data, signature.Length);
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
    secdebug("crypto", "decrypt alg: %lu", context.algorithm());
    otdLog("In OpenSCKeyHandle::decrypt(ciphertext length = %d)\n", cipher.Length);

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
        mKey.object(), SC_ALGORITHM_RSA_PAD_PKCS1,
        cipher.Data, cipher.Length, outputData, cipher.Length);
    otdLog("  sc_pkcs15_decipher(): rv = %d\n", rv);
    if (rv < 0)
    {
        free(outputData);
        CssmError::throwMe(CSSMERR_CSP_FUNCTION_FAILED);
    }
    clear.Data = outputData;
    clear.Length = rv;

    otdLog("  decrypt(): returning with %d decrypted bytes%d\n", clear.Length);
}


void OpenSCKeyHandle::exportKey(const Context &context,
const AccessCredentials *cred, CssmKey &wrappedKey)
{
    otdLog("exportKey");
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
