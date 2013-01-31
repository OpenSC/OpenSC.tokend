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

#include "OpenSCRecord.h"

#include "OpenSCToken.h"
#include "Attribute.h"
#include "MetaAttribute.h"
#include "MetaRecord.h"
#include <security_cdsa_client/aclclient.h>
#include <Security/SecKey.h>
#include "libopensc/log.h"

/**************************** OpenSCRecord *******************************/

OpenSCRecord::OpenSCRecord(OpenSCToken *openSCToken, const sc_pkcs15_object_t *object) : mObject(object), mToken(openSCToken)
{
	mDescription = object->label;
}


/********************** OpenSCCertificateRecord **************************/

OpenSCCertificateRecord::OpenSCCertificateRecord(OpenSCToken *openSCToken, const sc_pkcs15_object_t *object) :
OpenSCRecord(openSCToken, object)
{
	mCertInfo = (sc_pkcs15_cert_info_t *) object->data;
}


Tokend::Attribute *OpenSCCertificateRecord::getDataAttribute(
Tokend::TokenContext *tokenContext)
{
	CssmData data;
	OpenSCToken &openSCToken = static_cast<OpenSCToken &>(*tokenContext);

	// is it cached already?
	if (openSCToken.cachedObject(0, mDescription, data)) {
		Tokend::Attribute *attribute = new Tokend::Attribute(data.Data, data.Length);
		delete[] data.Data;
		return attribute;
	}

	sc_pkcs15_cert_t *cert;

	int r = sc_pkcs15_read_certificate(openSCToken.mScP15Card, mCertInfo, &cert);

	sc_debug(mToken->mScCtx, SC_LOG_DEBUG_NORMAL, "OpenSCCertificateRecord::getDataAttribute(): sc_pkcs15_read_certificate(): %d\n", r);
	Tokend::Attribute *attrib = NULL;
	// if we found it, cache it!
	if (r==0) {
		data.Data = new u8[cert->data.len];
		memcpy(data.Data, cert->data.value, cert->data.len);
		data.Length = cert->data.len;
		openSCToken.cacheObject(0, mDescription, data);
		attrib = new Tokend::Attribute(data.Data, data.Length);
		sc_pkcs15_free_certificate(cert);
	}
	return attrib;
}


void OpenSCCertificateRecord::getAcl(const char *tag, uint32 &count, AclEntryInfo *&acls)
{
	sc_debug(mToken->mScCtx, SC_LOG_DEBUG_NORMAL, "In OpenSCCertificateRecord::getAcl, tag is: %s\n", tag);
	if (!mAclEntries) {
		mAclEntries.allocator(Allocator::standard());
		// certificates are for public inspection
		mAclEntries.add(CssmClient::AclFactory::AnySubject(
			mAclEntries.allocator()),
			AclAuthorizationSet(CSSM_ACL_AUTHORIZATION_DB_READ, 0));
	}
	count = mAclEntries.size();
	acls = mAclEntries.entries();
	sc_debug(mToken->mScCtx, SC_LOG_DEBUG_NORMAL, "  returned %d ACL entries\n", count);
}

size_t OpenSCKeyRecord::sizeInBits() const
{
	sc_pkcs15_prkey_info *prkey = (sc_pkcs15_prkey_info *)mPrKeyObj->data;
	return prkey->modulus_length;
}

/************************** OpenSCKeyRecord *****************************/

OpenSCKeyRecord::OpenSCKeyRecord(OpenSCToken *openSCToken, const sc_pkcs15_object_t *object,
const Tokend::MetaRecord &metaRecord) :
OpenSCRecord(openSCToken, object)
{
	// find out key attributes!
	attributeAtIndex(metaRecord.metaAttribute(kSecKeyDecrypt).attributeIndex(),
		new Tokend::Attribute(true));
	attributeAtIndex(metaRecord.metaAttribute(kSecKeyUnwrap).attributeIndex(),
		new Tokend::Attribute(true));
	attributeAtIndex(metaRecord.metaAttribute(kSecKeySign).attributeIndex(),
		new Tokend::Attribute(true));
	mToken = openSCToken;
	mPrKeyObj = mPrKeySign = mPrKeyDecrypt = object;
}

OpenSCKeyRecord::OpenSCKeyRecord(OpenSCToken *openSCToken,
								 const sc_pkcs15_object_t *objectOne,
								 const sc_pkcs15_object_t *objectTwo,
								 const Tokend::MetaRecord &metaRecord) :
OpenSCRecord(openSCToken, objectOne)
{
	int decryptFlags	= SC_PKCS15_PRKEY_USAGE_DECRYPT
						| SC_PKCS15_PRKEY_USAGE_UNWRAP;
	
	int signFlags		= SC_PKCS15_PRKEY_USAGE_SIGN
						| SC_PKCS15_PRKEY_USAGE_SIGNRECOVER
						| SC_PKCS15_PRKEY_USAGE_NONREPUDIATION;
	
	sc_pkcs15_prkey_info_t	*kOne = (sc_pkcs15_prkey_info_t *) objectOne->data;
	sc_pkcs15_prkey_info_t	*kTwo = (sc_pkcs15_prkey_info_t *) objectTwo->data;
	
	// find out key attributes!
	attributeAtIndex(metaRecord.metaAttribute(kSecKeyDecrypt).attributeIndex(),
					 new Tokend::Attribute(true));
	attributeAtIndex(metaRecord.metaAttribute(kSecKeyUnwrap).attributeIndex(),
					 new Tokend::Attribute(true));
	attributeAtIndex(metaRecord.metaAttribute(kSecKeySign).attributeIndex(),
					 new Tokend::Attribute(true));
	mToken = openSCToken;
	if ((kOne->usage & signFlags) && (kTwo->usage & decryptFlags)) {
		mPrKeySign = objectOne;
		mPrKeyDecrypt = objectTwo;
	} else if ((kOne->usage & decryptFlags) && (kTwo->usage & signFlags)) {
		mPrKeySign = objectTwo;
		mPrKeyDecrypt = objectOne;
	} else
		PCSC::Error::throwMe(CSSM_ERRCODE_INTERNAL_ERROR);
	mPrKeyObj = objectOne; // Could be objectTwo also, since both keys share the same attributes
}

void OpenSCKeyRecord::getOwner(AclOwnerPrototype &owner)
{
	sc_debug(mToken->mScCtx, SC_LOG_DEBUG_NORMAL, "In OpenSCKeyRecord::getOwner()\n");
	// we claim we're owned by PIN #1
	if (!mAclOwner) {
		mAclOwner.allocator(Allocator::standard());
		mAclOwner = CssmClient::AclFactory::PinSubject(Allocator::standard(), 1);
	}
	owner = mAclOwner;
}


void OpenSCKeyRecord::getAcl(const char *tag, uint32 &count, AclEntryInfo *&acls)
{
	sc_debug(mToken->mScCtx, SC_LOG_DEBUG_NORMAL, "In OpenSCKeyRecord::getAcl, tag is: %s\n", tag);
	if (!mAclEntries) {
		mAclEntries.allocator(Allocator::standard());
		// Anyone can read the DB record for this key (which is a reference CSSM_KEY)
		sc_debug(mToken->mScCtx, SC_LOG_DEBUG_NORMAL, "DB read for a reference key object is always OK\n");
		// Anyone can read the DB record for this key (which is a reference
		// CSSM_KEY)
		mAclEntries.add(CssmClient::AclFactory::AnySubject(
			mAclEntries.allocator()),
			AclAuthorizationSet(CSSM_ACL_AUTHORIZATION_DB_READ, 0));

		// The pinNum uniquely identifies the AuthID of the PIN needed to use this key,
		// so when OpenSCToken::verifyPIN() is called with this pinNum, we know which
		// PIN we have to verify
		int pinNum = mToken->getRefFromPinMap(&mPrKeyObj->auth_id);
		sc_debug(mToken->mScCtx, SC_LOG_DEBUG_NORMAL, "  auth_id for PIN: %s, pinNum = %d\n",
			sc_pkcs15_print_id(&mPrKeyObj->auth_id), pinNum);
		if (pinNum != -1) {
			char tmptag[20];
			
			// This is hardcoded for now.
			// Apparently, more than one PIN slot is not supported.
			snprintf(tmptag, sizeof(tmptag), "PIN%d", 1);
			
			if(mObject->user_consent) {
				// PIN for this key must be entered every time
				// This will be used for user consent keys like the non repudiation keys
				// from national eID cards)
				AclAuthorizationSet aclAuthSet = AclAuthorizationSet(CSSM_ACL_AUTHORIZATION_SIGN, 0);
				
				CssmData prompt;
				mAclEntries.add(CssmClient::AclFactory::PromptPWSubject(mAclEntries.allocator(), prompt),
								AclAuthorizationSet(CSSM_ACL_AUTHORIZATION_SIGN,
													0), tmptag);

			} else if (pinNum == 1) {
				// PIN needs to be entered only once if this key is associated with PIN #1
				// and doesn't have the user consent bit set
				mAclEntries.add(CssmClient::AclFactory::PinSubject(mAclEntries.allocator(), pinNum),
								AclAuthorizationSet(CSSM_ACL_AUTHORIZATION_ENCRYPT,
													CSSM_ACL_AUTHORIZATION_DECRYPT,
													CSSM_ACL_AUTHORIZATION_SIGN,
													CSSM_ACL_AUTHORIZATION_MAC,
													CSSM_ACL_AUTHORIZATION_DERIVE,
													0), tmptag);
			} else {
				// All other keys without the user consent bit set.
				// This is just a temporary workaround, until proper PIN slots are supported.
				CssmData prompt;
				mAclEntries.add(CssmClient::AclFactory::PromptPWSubject(mAclEntries.allocator(), prompt),
								AclAuthorizationSet(CSSM_ACL_AUTHORIZATION_ENCRYPT,
													CSSM_ACL_AUTHORIZATION_DECRYPT,
													CSSM_ACL_AUTHORIZATION_SIGN,
													CSSM_ACL_AUTHORIZATION_MAC,
													CSSM_ACL_AUTHORIZATION_DERIVE,
													0), tmptag);
			}
		}
	}
	count = mAclEntries.size();
	acls = mAclEntries.entries();
	// Notify the tokend object with the PIN it should verify
	mToken->setCurrentPIN(mToken->getRefFromPinMap(&mPrKeyObj->auth_id));
	sc_debug(mToken->mScCtx, SC_LOG_DEBUG_NORMAL, "  retuning %d ACL entries\n", count);
}
