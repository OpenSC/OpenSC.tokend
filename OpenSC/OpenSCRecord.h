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

#ifndef _OpenSCRECORD_H_
#define _OpenSCRECORD_H_

#include "Record.h"
#include "OpenSCToken.h"
#include "libopensc/opensc.h"
#include "libopensc/pkcs15.h"
#include <security_cdsa_utilities/cssmcred.h>

class OpenSCToken;

class OpenSCRecord : public Tokend::Record
{
	NOCOPY(OpenSCRecord)
		public:
		OpenSCRecord(OpenSCToken *openSCToken, const sc_pkcs15_object_t *object);
		~OpenSCRecord() {}

		virtual const char *description() { return mDescription; }
		const sc_pkcs15_object_t * object() { return mObject; }
	protected:
		const char *mDescription;
		const sc_pkcs15_object_t *mObject;
		OpenSCToken *mToken;
};

class OpenSCCertificateRecord : public OpenSCRecord
{
	NOCOPY(OpenSCCertificateRecord)
		public:
		OpenSCCertificateRecord(OpenSCToken *openSCToken, const sc_pkcs15_object_t *object);
		~OpenSCCertificateRecord() {}
		virtual Tokend::Attribute *getDataAttribute(Tokend::TokenContext *tokenContext);
		virtual void getAcl(const char *tag, uint32 &count, AclEntryInfo *&acls);

	private:
		const sc_pkcs15_cert_info_t *mCertInfo;
		AutoAclEntryInfoList mAclEntries;
};

class OpenSCKeyRecord : public OpenSCRecord
{
	NOCOPY(OpenSCKeyRecord)
		public:
		OpenSCKeyRecord(OpenSCToken *openSCToken, const sc_pkcs15_object_t *object,
			const Tokend::MetaRecord &metaRecord);
		OpenSCKeyRecord(OpenSCToken *openSCToken,
			const sc_pkcs15_object_t *objectOne,
			const sc_pkcs15_object_t *objectTwo,
			const Tokend::MetaRecord &metaRecord);
		~OpenSCKeyRecord() {}

		size_t sizeInBits() const;

		const sc_pkcs15_object_t * signKey() { return mPrKeySign; }
		const sc_pkcs15_object_t * decryptKey() { return mPrKeyDecrypt; }
		virtual void getOwner(AclOwnerPrototype &owner);
		virtual void getAcl(const char *tag, uint32 &count, AclEntryInfo *&acls);

	private:
		const sc_pkcs15_object_t *mPrKeyObj, *mPrKeySign, *mPrKeyDecrypt;
		AutoAclOwnerPrototype mAclOwner;
		AutoAclEntryInfoList mAclEntries;
};
/* !_OpenSCRECORD_H_ */
#endif
