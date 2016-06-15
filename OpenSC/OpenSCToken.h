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
 *  OpenSCToken.h
 *  TokendOpenSC
 */

#ifndef _OpenSCTOKEN_H_
#define _OpenSCTOKEN_H_

#include <Token.h>
#include "TokenContext.h"

#include "libopensc/opensc.h"
#include "libopensc/pkcs15.h"
#include "libopensc/errors.h"

#include <security_utilities/pcsc++.h>

class OpenSCSchema;

//
// "The" token
//
class OpenSCToken : public Tokend::Token, public TokenContext
{
	NOCOPY(OpenSCToken)
		public:
		OpenSCToken();
		~OpenSCToken();

		virtual void didDisconnect();
		virtual void didEnd();

		virtual uint32 probe(SecTokendProbeFlags flags, char tokenUid[TOKEND_MAX_UID]);
		virtual void establish(const CSSM_GUID *guid, uint32 subserviceId,
			SecTokendEstablishFlags flags, const char *cacheDirectory,
			const char *workDirectory, char mdsDirectory[PATH_MAX],
			char printName[PATH_MAX]);
		virtual void getOwner(AclOwnerPrototype &owner);
		virtual void getAcl(const char *tag, uint32 &count, AclEntryInfo *&acls);

		virtual void changePIN(int pinNum,
			const unsigned char *oldPin, size_t oldPinLength,
			const unsigned char *newPin, size_t newPinLength);
		virtual uint32_t pinStatus(int pinNum);
		virtual void verifyPIN(int pinNum, const unsigned char *pin, size_t pinLength);
		virtual void unverifyPIN(int pinNum);

		virtual bool isLocked();
		//virtual void authenticate(CSSM_DB_ACCESS_TYPE mode, const AccessCredentials *cred);
		bool _verifyPIN(int pinNum, const unsigned char *pin, size_t pinLength);

		bool _changePIN( int pinNum,
			const unsigned char *oldPin, size_t oldPinLength,
			const unsigned char *newPin, size_t newPinLength );
	
#if 0
		bool checkPIN( int pinNum);
#endif
        
		// To manipulate mPinMap
		void addToPinMap(const sc_pkcs15_id_t *id);
		int getRefFromPinMap(const sc_pkcs15_id_t *id);
		const sc_pkcs15_id_t * getIdFromPinMap(int pinNum);

		// Workaround for the multiple PIN slots issue
		void setCurrentPIN(int pinNum) { mCurrentPIN = pinNum; }
	public:
		sc_context_t *mScCtx;
		sc_card_t *mScCard;
		sc_pkcs15_card_t *mScP15Card;

	private:
		void populate();
		// temporary ACL cache hack - to be removed
		AutoAclOwnerPrototype mAclOwner;
		AutoAclEntryInfoList mAclEntries;
		bool mLocked;
		// temporary workaround for multiple PINs - to be removed
		int mCurrentPIN;

		map<int, const sc_pkcs15_id_t *> mPinMap;
		int mPinCount;
};

/* !_OpenSCTOKEN_H_ */
#endif
