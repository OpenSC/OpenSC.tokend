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

/*
 *  OpenSCKeyHandle.h
 *  TokendMuscle
 */

/*
 * This code is based on the BELPIC tokend distributed by Apple with Tiger.   Adapted for use with
 * an Aladdin eToken Pro populated with OpenSC (PKCS#15) by Ron DiNapoli, Cornell University (rd29@cornell.edu)
 *
 * This code only works if you have a driver which allows your token to interface with the PCSC daemon
 */

#ifndef _OpenSCKEYHANDLE_H_
#define _OpenSCKEYHANDLE_H_

#include "KeyHandle.h"

class OpenSCToken;
class OpenSCKeyRecord;

class OpenSCKeyHandle: public Tokend::KeyHandle
{
	NOCOPY(OpenSCKeyHandle)
	public:
		OpenSCKeyHandle(OpenSCToken &OpenSCToken,
			const Tokend::MetaRecord &metaRecord, OpenSCKeyRecord &cacKey);
		~OpenSCKeyHandle();

		virtual void getKeySize(CSSM_KEY_SIZE &keySize);
		virtual uint32 getOutputSize(const Context &context, uint32 inputSize,
			bool encrypting);
		virtual void generateSignature(const Context &context,
			CSSM_ALGORITHMS signOnly, const CssmData &input, CssmData &signature);
		virtual void verifySignature(const Context &context,
			CSSM_ALGORITHMS signOnly, const CssmData &input,
			const CssmData &signature);
		virtual void generateMac(const Context &context, const CssmData &input, CssmData &output);
		virtual void verifyMac(const Context &context, const CssmData &input, const CssmData &compare);
		virtual void encrypt(const Context &context, const CssmData &clear, CssmData &cipher);
		virtual void decrypt(const Context &context, const CssmData &cipher, CssmData &clear);

		virtual void exportKey(const Context &context, const AccessCredentials *cred, CssmKey &wrappedKey);

	protected:
		virtual void generateRsaSignature(const Context &context,
			CSSM_ALGORITHMS signOnly, const CssmData &input, CssmData &signature);
		virtual void generateEcdsaSignature(const Context &context,
			CSSM_ALGORITHMS signOnly, const CssmData &input, CssmData &signature);

	private:
		OpenSCToken &mToken;
		OpenSCKeyRecord &mKey;
};

//
// A factory that creates OpenSCKeyHandle objects.
//
class OpenSCKeyHandleFactory : public Tokend::KeyHandleFactory
{
	NOCOPY(OpenSCKeyHandleFactory)
		public:
		OpenSCKeyHandleFactory() {}
		virtual ~OpenSCKeyHandleFactory();

		virtual Tokend::KeyHandle *keyHandle(Tokend::TokenContext *tokenContext,
			const Tokend::MetaRecord &metaRecord, Tokend::Record &record) const;
};
/* !_OpenSCKEYHANDLE_H_ */
#endif
