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

#include "OpenSCError.h"
#include "OpenSCToken.h"
#include "OpenSCLog.h"
#include "Attribute.h"
#include "MetaAttribute.h"
#include "MetaRecord.h"
#include <security_cdsa_client/aclclient.h>
#include <Security/SecKey.h>

/**************************** OpenSCRecord *******************************/

OpenSCRecord::OpenSCRecord(const sc_pkcs15_object_t *object) : mObject(object)
{
    mDescription = object->label;
}


/********************** OpenSCCertificateRecord **************************/

OpenSCCertificateRecord::OpenSCCertificateRecord(const sc_pkcs15_object_t *object) :
OpenSCRecord(object)
{
    mCertInfo = (sc_pkcs15_cert_info_t *) object->data;
}


Tokend::Attribute *OpenSCCertificateRecord::getDataAttribute(
Tokend::TokenContext *tokenContext)
{
    CssmData data;
    OpenSCToken &openSCToken = static_cast<OpenSCToken &>(*tokenContext);

    // is it cached already?
    if (openSCToken.cachedObject(0, mDescription, data))
    {
        Tokend::Attribute *attribute = new Tokend::Attribute(data.Data, data.Length);
        free(data.Data);
        return attribute;
    }

    sc_pkcs15_cert_t *cert;

    int r = sc_pkcs15_read_certificate(openSCToken.mScP15Card, mCertInfo, &cert);

    otdLog("OpenSCCertificateRecord::getDataAttribute(): sc_pkcs15_read_certificate(): %d\n", r);
    Tokend::Attribute *attrib = NULL;
    // if we found it, cache it!
    if (r==0)
    {
        data.Data = cert->data;
        data.Length = cert->data_len;
        openSCToken.cacheObject(0, mDescription, data);
        attrib = new Tokend::Attribute(data.Data, data.Length);
        sc_pkcs15_free_certificate(cert);
    }
    return attrib;
}


void OpenSCCertificateRecord::getAcl(const char *tag, uint32 &count, AclEntryInfo *&acls)
{
    otdLog("In OpenSCCertificateRecord::getAcl, tag is: %s\n", tag);
    if (!mAclEntries)
    {
        mAclEntries.allocator(Allocator::standard());
        // certificates are for public inspection
        mAclEntries.add(CssmClient::AclFactory::AnySubject(
            mAclEntries.allocator()),
            AclAuthorizationSet(CSSM_ACL_AUTHORIZATION_DB_READ, 0));
    }
    count = mAclEntries.size();
    acls = mAclEntries.entries();
    otdLog("  returned %d ACL entries\n", count);
}


/************************** OpenSCKeyRecord *****************************/

OpenSCKeyRecord::OpenSCKeyRecord(OpenSCToken *openSCToken, const sc_pkcs15_object_t *object,
const Tokend::MetaRecord &metaRecord) :
OpenSCRecord(object)
{
    // find out key attributes!
    attributeAtIndex(metaRecord.metaAttribute(kSecKeyDecrypt).attributeIndex(),
        new Tokend::Attribute(true));
    attributeAtIndex(metaRecord.metaAttribute(kSecKeyUnwrap).attributeIndex(),
        new Tokend::Attribute(true));
    attributeAtIndex(metaRecord.metaAttribute(kSecKeySign).attributeIndex(),
        new Tokend::Attribute(true));
    mToken = openSCToken;
    mPrKeyObj = object;
}


void OpenSCKeyRecord::getOwner(AclOwnerPrototype &owner)
{
    otdLog("In OpenSCKeyRecord::getOwner()\n");
    // we claim we're owned by PIN #1
    if (!mAclOwner)
    {
        mAclOwner.allocator(Allocator::standard());
        mAclOwner = CssmClient::AclFactory::PinSubject(Allocator::standard(), 1);
    }
    owner = mAclOwner;
}


void OpenSCKeyRecord::getAcl(const char *tag, uint32 &count, AclEntryInfo *&acls)
{
    otdLog("In OpenSCKeyRecord::getAcl, tag is: %s\n", tag);
    if (!mAclEntries)
    {
        mAclEntries.allocator(Allocator::standard());
        // Anyone can read the DB record for this key (which is a reference CSSM_KEY)
        otdLog("DB read for a reference key object is always OK\n");
        // Anyone can read the DB record for this key (which is a reference
        // CSSM_KEY)
        mAclEntries.add(CssmClient::AclFactory::AnySubject(
            mAclEntries.allocator()),
            AclAuthorizationSet(CSSM_ACL_AUTHORIZATION_DB_READ, 0));

        // The pinNum uniquely identifies the AuthID of the PIN needed to use this key,
        // so when OpenSCToken::verifyPIN() is called with this pinNum, we know which
        // PIN we have to verify
        int pinNum = mToken->getRefFromPinMap(&mPrKeyObj->auth_id);
        otdLog("  auth_id for PIN: %s, pinNum = %d\n",
            sc_pkcs15_print_id(&mPrKeyObj->auth_id), pinNum);
        if (pinNum != -1)
        {
            char tmptag[20];
            snprintf(tmptag, sizeof(tmptag), "PIN%d", pinNum);
            mAclEntries.add(CssmClient::AclFactory::PinSubject(
                mAclEntries.allocator(), pinNum),
                AclAuthorizationSet(CSSM_ACL_AUTHORIZATION_ENCRYPT,
                CSSM_ACL_AUTHORIZATION_DECRYPT,
                CSSM_ACL_AUTHORIZATION_SIGN,
                CSSM_ACL_AUTHORIZATION_MAC,
                CSSM_ACL_AUTHORIZATION_DERIVE,
                0), tmptag);
        }
    }
    count = mAclEntries.size();
    acls = mAclEntries.entries();
    otdLog("  retuning %d ACL entries\n", count);
}
