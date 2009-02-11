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

#include "OpenSCToken.h"

#include "Adornment.h"
#include "AttributeCoder.h"

#include <opensc/opensc.h>
#include <opensc/scconf.h>
#include "OpenSCError.h"
#include "OpenSCRecord.h"
#include "OpenSCSchema.h"
#include "OpenSCLog.h"
#include <security_cdsa_client/aclclient.h>
#include <map>
#include <vector>

using CssmClient::AclFactory;

OpenSCToken::OpenSCToken() : mLocked(false)
{
    otdEnableLogging(true);
    mTokenContext = this;
    mScCtx = NULL;
    mScCard = NULL;
    mSession.open();
    mPinCount = 1;
}


OpenSCToken::~OpenSCToken()
{
    delete mSchema;

// Clean pin cache
    map<sc_pkcs15_pin_info_t *, pin_t>::iterator it;
    for (it = mPinCache.begin(); it != mPinCache.end(); it++)
        memset(it->second.value, 0, SC_MAX_PIN_SIZE);
}


void OpenSCToken::didDisconnect()
{
    otdLog("In OpenSCToken::didDisconnect()\n");
    PCSC::Card::didDisconnect();
}


void OpenSCToken::didEnd()
{
    return;
    otdLog("In OpenSCToken::didEnd()\n");
    PCSC::Card::didEnd();
}


void OpenSCToken::changePIN(int pinNum,
const unsigned char *oldPin, size_t oldPinLength,
const unsigned char *newPin, size_t newPinLength)
{
    otdLog("In OpenSCToken::changePIN(%d)\n", pinNum);
    if (pinNum != 1)
        CssmError::throwMe(CSSM_ERRCODE_SAMPLE_VALUE_NOT_SUPPORTED);

    if( _changePIN( pinNum, oldPin, oldPinLength, newPin, newPinLength ) )
    {
        mLocked = false;
    }
    else
    {
        CssmError::throwMe(CSSM_ERRCODE_OPERATION_AUTH_DENIED);
    }

}


bool OpenSCToken:: _changePIN( int pinNum,
const unsigned char *oldPin, size_t oldPinLength,
const unsigned char *newPin, size_t newPinLength )
{
    otdLog("In OpenSCToken::_changePIN(), PIN num is: %d\n", pinNum);

    int r, i, rv;
    struct sc_pkcs15_object *objs[32];

// pinNum -> AuthID
    const sc_pkcs15_id_t *auth_id = getIdFromPinMap(pinNum);
    if (auth_id == NULL)
    {
        otdLog("  ERR: getIdFromPinMap(): no AuthID found for pinNum %d\n", pinNum);
        CssmError::throwMe(CSSM_ERRCODE_INVALID_DATA);
    }

// AuthID -> pin object  +  change pin
    r = sc_pkcs15_get_objects(mScP15Card, SC_PKCS15_TYPE_AUTH_PIN, objs, 32);
    otdLog("  sc_pkcs15_get_objects(pin_id=%s): %d\n", sc_pkcs15_print_id(auth_id),  r);
    if (r >= 0)
    {
        for (i = 0; i < r; i++)
        {
            sc_pkcs15_pin_info_t *pin_info = (sc_pkcs15_pin_info_t *) objs[i]->data;
            if (sc_pkcs15_compare_id(auth_id, &pin_info->auth_id))
            {

                rv = sc_pkcs15_change_pin( mScP15Card, pin_info, oldPin, oldPinLength, newPin, newPinLength );
                otdLog("  In OpenSCToken::sc_pkcs15_change_pin returned %d for pin %d\n", rv, pinNum );
                if (rv==0)
                {
                    cachePIN(pin_info, newPin, newPinLength);
                    return true;
                }
                else
                    return false;
            }
        }
    }
    return false;
}


uint32_t OpenSCToken::pinStatus(int pinNum)
{
    otdLog("In OpenSCToken::pinStatus for pinNum (%d)\n", pinNum);

    CssmError::throwMe(CSSM_ERRCODE_FUNCTION_NOT_IMPLEMENTED);
}


// does the token look as 'locked' for keychain ?
bool OpenSCToken::isLocked()
{
    otdLog("In OpenSCToken::isLocked()\n");
    return mLocked;
}


void OpenSCToken::verifyPIN(int pinNum, const uint8_t *pin, size_t pinLength)
{
    otdLog("In OpenSCToken::verifyPIN(%d)\n", pinNum);
    if (_verifyPIN(pinNum, pin, pinLength))
    {
        otdLog("  About to call BEGIN()\n");
        mLocked = false;
    }
    else
    {
        CssmError::throwMe(CSSM_ERRCODE_OPERATION_AUTH_DENIED);
    }

// Start a new transaction which we never get rid of until someone calls
// unverifyPIN()
}


bool OpenSCToken::_verifyPIN(int pinNum, const uint8_t *pin, size_t pinLength)
{
    otdLog("In OpenSCToken::_verifyPIN(), PIN num is: %d\n", pinNum);

    int r, i, rv;
    struct sc_pkcs15_object *objs[32];

// pinNum -> AuthID
    const sc_pkcs15_id_t *auth_id = getIdFromPinMap(pinNum);
    if (auth_id == NULL)
    {
        otdLog("  ERR: getIdFromPinMap(): no AuthID found for pinNum %d\n", pinNum);
        CssmError::throwMe(CSSM_ERRCODE_INVALID_DATA);
    }

// AuthID -> pin object  +  verify pin
    r = sc_pkcs15_get_objects(mScP15Card, SC_PKCS15_TYPE_AUTH_PIN, objs, 32);
    otdLog("  sc_pkcs15_get_objects(pin_id=%s): %d\n", sc_pkcs15_print_id(auth_id),  r);
    if (r >= 0)
    {
        for (i = 0; i < r; i++)
        {
            sc_pkcs15_pin_info_t *pin_info = (sc_pkcs15_pin_info_t *) objs[i]->data;
            if (sc_pkcs15_compare_id(auth_id, &pin_info->auth_id))
            {
                rv = sc_pkcs15_verify_pin(mScP15Card, pin_info, pin,pinLength);
                otdLog("  In OpenSCToken::verify returned %d for pin %d\n", rv, pinNum);
                if (rv==0)
                {
                    cachePIN(pin_info, pin, pinLength);
                    return true;
                }
                else
                    return false;
            }
        }
    }
    return false;
}


int OpenSCToken::verifyCachedPIN(const sc_pkcs15_id *authID)
{
    map<sc_pkcs15_pin_info_t *, pin_t>::iterator it;

// Look up the cached PIN + verify
    for (it = mPinCache.begin(); it != mPinCache.end(); it++)
    {
        if (sc_pkcs15_compare_id(authID, &it->first->auth_id))
        {
            const pin_t *pinval = &it->second;
            int rv = sc_pkcs15_verify_pin(mScP15Card, it->first,
                pinval->value, pinval->len);
            otdLog("  OpenSCToken::verifyCachedPin(): r = %d\n", rv);
            return rv;
        }
    }

    otdLog("  OpenSCToken::verifyCachedPin(): pin with ID \"%s\" not found\n",
        sc_pkcs15_print_id(authID));
    return SC_ERROR_SECURITY_STATUS_NOT_SATISFIED;
}


void OpenSCToken::cachePIN(sc_pkcs15_pin_info_t *pin_info,
const unsigned char *pin, size_t pinLength)
{
    map<sc_pkcs15_pin_info_t *, pin_t>::iterator it;
    pin_t pinval;

    strncpy((char *) pinval.value, (const char *) pin, SC_MAX_PIN_SIZE);
    pinval.len = pinLength < SC_MAX_PIN_SIZE ? pinLength : SC_MAX_PIN_SIZE;

    for (it = mPinCache.begin(); it != mPinCache.end(); it++)
    {
        if (sc_pkcs15_compare_id(&pin_info->auth_id, &it->first->auth_id))
        {
            it->second = pinval;
        }
    }

// Pin not yet cached -> make a new entry
    mPinCache.insert(make_pair(pin_info, pinval));
}


void OpenSCToken::unverifyPIN(int pinNum)
{
    otdLog("In OpenSCToken::unverifyPIN(%d)\n", pinNum);

    if (pinNum != -1)
        CssmError::throwMe(CSSM_ERRCODE_SAMPLE_VALUE_NOT_SUPPORTED);

    mLocked = true;
}


// We must recognize the token and create a (machine readable UID) if we can.
// A score of 0 means we can't handle the card; if multiple tokends can handle
//  the card then the one that returns the highest score is returned.
uint32 OpenSCToken::probe(SecTokendProbeFlags flags,
char tokenUid[TOKEND_MAX_UID])
{
    otdLog("\nIn OpenSCToken::probe()\n");

    uint32 score = Tokend::ISO7816Token::probe(flags, tokenUid);

// FIXME bool doDisconnect = true; /*!(flags & kSecTokendProbeKeepToken); */

// Init OpenSC
    int r = sc_establish_context(&mScCtx, "tokend");
    otdLog("  tokend_establish_context(): %d\n", r);
    if (r == 0)
    {
// Which reader to use
        unsigned int idx;
        sc_reader_t *reader = NULL;

        const SCARD_READERSTATE &readerState = *(*startupReaderInfo)();
        for (idx = 0; idx < sc_ctx_get_reader_count(mScCtx); idx++)
        {

            reader = sc_ctx_get_reader(mScCtx, idx);
            if (!reader)
                return 0;

            if (strcmp(readerState.szReader, reader->name) == 0)
                break;
        }

// Connect to the card
        if (idx < sc_ctx_get_reader_count(mScCtx))
        {
            r = sc_connect_card(reader, 0, &mScCard);
            otdLog("  sc_connect_card(): %d\n", r);
            if (r < 0)
            {
                sc_release_context(mScCtx);
                mScCtx = NULL;
            }
            else
            {
                otdLog("  card: %s\n", mScCard->name);
                r = sc_pkcs15_bind(mScCard, &mScP15Card);
                otdLog("  sc_pkcs15_bind(): %d\n", r);
                if (r == 0)
                {
// get the score
                    scconf_block *conf_block = NULL;
                    conf_block = sc_get_conf_block(mScCtx, "framework", "tokend", 1);
                    score = 50;
                    if (conf_block != NULL)
                    {
                        score = scconf_get_int(conf_block, "score", score);
                        otdLog("  Get Score from config file: %d\n", score);
                    }

// Create a tokenUid
                    if (mScP15Card->label != NULL)
                        strlcpy(tokenUid, mScP15Card->label, TOKEND_MAX_UID);
                    if (mScP15Card->serial_number != NULL)
                        strlcpy(tokenUid + strlen(tokenUid), mScP15Card->serial_number,
                            TOKEND_MAX_UID - strlen(tokenUid));

                    otdLog("    score = %d, tokenUid = \"%s\"\n", score, tokenUid);
                }
            }
        }
        else
            otdLog("  err: reader \"%s\" not found by OpenSC\n", readerState.szReader);
    }

    return score;
}


void OpenSCToken::establish(const CSSM_GUID *guid, uint32 subserviceId,
SecTokendEstablishFlags flags, const char *cacheDirectory,
const char *workDirectory, char mdsDirectory[PATH_MAX],
char printName[PATH_MAX])
{
    otdLog("In OpenSCToken::establish() -> we had the highest score\n");

    if (mScP15Card == NULL)
        PCSC::Error::throwMe(CSSM_ERRCODE_INTERNAL_ERROR);

    Tokend::ISO7816Token::establish(guid, subserviceId, flags,
        cacheDirectory, workDirectory, mdsDirectory, printName);

    otdLog("  About to create schema\n");
    mSchema = new OpenSCSchema();
    mSchema->create();

    otdLog("  Schema created, about to call populate()\n");

    populate();

    if (mScP15Card->label)
        strcpy(printName, mScP15Card->label);
    else
        strcpy(printName,"OpenSC Token");

    otdLog("  returning from OpenSCToken::establish()\n");
}


//
// Database-level ACLs
//
void OpenSCToken::getOwner(AclOwnerPrototype &owner)
{
    otdLog("In OpenSCToken::getOwner()\n");
// we don't really know (right now), so claim we're owned by PIN #1
    if (!mAclOwner)
    {
        mAclOwner.allocator(Allocator::standard());
        mAclOwner = AclFactory::PinSubject(Allocator::standard(), 1);
    }
    owner = mAclOwner;
}


void OpenSCToken::getAcl(const char *tag, uint32 &count, AclEntryInfo *&acls)
{
    otdLog("In OpenSCToken::getAcl()\n");

// get pin list, then for each pin in the future
    if (!mAclEntries)
    {
        mAclEntries.allocator(Allocator::standard());
// Anyone can read the attributes and data of any record on this token
// (it's further limited by the object itself).
        mAclEntries.add(CssmClient::AclFactory::AnySubject(
            mAclEntries.allocator()),
            AclAuthorizationSet(CSSM_ACL_AUTHORIZATION_DB_READ, 0));

//mAclEntries.addPin(AclFactory::PWSubject(mAclEntries.allocator()), 1);
//mAclEntries.addPin(AclFactory::PromptPWSubject(mAclEntries.allocator(), CssmData()), 1);
// We support PIN1 with either a passed in password
// subject or a prompted password subject.
        mAclEntries.addPin(AclFactory::PWSubject(mAclEntries.allocator()), 1);
//mAclEntries.addPin(AclFactory::PWSubject(mAclEntries.allocator()), 2);
        mAclEntries.addPin(AclFactory::PromptPWSubject(mAclEntries.allocator(), CssmData()), 1);
        mAclEntries.addPin(AclFactory::PinSubject(mAclEntries.allocator(), CssmData()), 1);
    }
    count = mAclEntries.size();
    acls = mAclEntries.entries();
}


void  OpenSCToken::addToPinMap(const sc_pkcs15_id_t *id)
{
    if (getRefFromPinMap(id) != -1)
        return;                                   // already added

    mPinMap.insert(make_pair(mPinCount++, id));
}


int OpenSCToken::getRefFromPinMap(const sc_pkcs15_id_t *id)
{
    map<int, const sc_pkcs15_id_t *>::const_iterator it;

    for (it = mPinMap.begin(); it != mPinMap.end(); it++)
    {
        if (sc_pkcs15_compare_id(id, it->second))
            return it->first;
    }
    return -1;                                    // id not found
}


const sc_pkcs15_id_t * OpenSCToken::getIdFromPinMap(int pinNum)
{
    map<int, const sc_pkcs15_id_t *>::const_iterator it;

    for (it = mPinMap.begin(); it != mPinMap.end(); it++)
    {
        if (pinNum == it->first)
            return it->second;
    }
    return NULL;                                  // pinNum not found
}


#pragma mark ---------------- OpenSC Specific --------------

void OpenSCToken::populate()
{
    otdLog("In OpenSCToken::populate()\n");

// We work with certificates and private keys only
    Tokend::Relation &certRelation = mSchema->findRelation(CSSM_DL_DB_RECORD_X509_CERTIFICATE);
    Tokend::Relation &privateKeyRelation = mSchema->findRelation(CSSM_DL_DB_RECORD_PRIVATE_KEY);
//Tokend::Relation &dataRelation = mSchema->findRelation(CSSM_DL_DB_RECORD_GENERIC);

    int r, i;
    struct sc_pkcs15_object *objs[32];

// Map from ID to certs.
    typedef std::map<sc_pkcs15_id_t *, RefPointer<Tokend::Record> > IdRecordMap;
    IdRecordMap mCertificates;

// Locate certificates
                                                  //FIXME - max objects constant ?
    r = sc_pkcs15_get_objects(mScP15Card, SC_PKCS15_TYPE_CERT_X509, objs, 32);
    otdLog("  sc_pkcs15_get_objects(TYPE_CERT_X509): %d\n", r);
    if (r >= 0)
    {
        for (i = 0; i < r; i++)
        {
            struct sc_pkcs15_cert_info *cert_info = (struct sc_pkcs15_cert_info *) objs[i]->data;
//  get the actual record
            RefPointer<Tokend::Record> record(new OpenSCCertificateRecord(objs[i]));
// put it into certificates map
            otdLog("    - %s (ID=%s)\n", objs[i]->label, sc_pkcs15_print_id(&cert_info->id));
// put into map
            mCertificates.insert(std::pair<sc_pkcs15_id_t *, RefPointer<Tokend::Record> >(&cert_info->id, record));
// mark as certificate
            certRelation.insertRecord(record);
        }
    }

// Locate private keys
    r = sc_pkcs15_get_objects(mScP15Card, SC_PKCS15_TYPE_PRKEY_RSA, objs, 32);
    otdLog("  sc_pkcs15_get_objects(TYPE_PRKEY_RSA): %d\n", r);
    if (r >= 0)
    {
        for (i = 0; i < r; i++)
        {
            sc_pkcs15_prkey_info_t *prkey_info = (sc_pkcs15_prkey_info_t *) objs[i]->data;
            RefPointer<Tokend::Record> record(
                new OpenSCKeyRecord(this, objs[i], privateKeyRelation.metaRecord()));
// put it into prkey map
            otdLog("    - %s (ID=%s)\n", objs[i]->label, sc_pkcs15_print_id(&prkey_info->id));
            privateKeyRelation.insertRecord(record);

// do the bind between the key and a cert
            IdRecordMap::const_iterator it;
            for (it = mCertificates.begin(); it != mCertificates.end(); it++)
            {
                if (sc_pkcs15_compare_id(it->first, &prkey_info->id))
                    break;
            }
            if (it == mCertificates.end())
                otdLog("        no certificate found for this key\n");
            else
            {
                otdLog("        linked this key to cert \"%s\"\n", it->second->description());
                record->setAdornment(mSchema->publicKeyHashCoder().certificateKey(),
                    new Tokend::LinkedRecordAdornment(it->second));
            }

        }
    }

// Get the PIN(s) and put their ID in the mPinMap. This way we get
// a unique int as a reference to each PIN (ID), this has to be
// returned in the OpenSCKeyRecord::getAcl() method.
    r = sc_pkcs15_get_objects(mScP15Card, SC_PKCS15_TYPE_AUTH_PIN, objs, 32);
    otdLog("  sc_pkcs15_get_objects(TYPE_AUTH_PIN): %d\n", r);
    for (i = 0; i < r; i++)
    {
        sc_pkcs15_pin_info *pin_info = (sc_pkcs15_pin_info *) objs[i]->data;
        if ((pin_info->flags & SC_PKCS15_PIN_FLAG_SO_PIN) ||
            (pin_info->flags & SC_PKCS15_PIN_FLAG_UNBLOCKING_PIN))
        {
            otdLog("    ignored non-user pin with ID=%s\n",
                sc_pkcs15_print_id(&pin_info->auth_id));
            continue;
        }
        addToPinMap(&pin_info->auth_id);
        otdLog("    added pin with ID=%s to the pinmap\n",
            sc_pkcs15_print_id(&pin_info->auth_id));
    }

    otdLog("  returning from OpenSCToken::populate()\n");
}
