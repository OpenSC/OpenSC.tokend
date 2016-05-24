/*
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
 *  OpenSCAttributeCoder.cpp
 *  Tokend
 *
 *  Created by Hugh Cole-Baker on 4/12/09.
 *
 */

#include "OpenSCAttributeCoder.h"
#include "OpenSCToken.h"
#include "OpenSCRecord.h"
#include "MetaAttribute.h"
#include "MetaRecord.h"
#include "Attribute.h"
#include "libopensc/pkcs15.h"
#include "libopensc/log.h"
#include <Security/SecKey.h>

using namespace Tokend;

OpenSCKeyAttributeCoder::OpenSCKeyAttributeCoder()
{

}


OpenSCKeyAttributeCoder::~OpenSCKeyAttributeCoder()
{

}


void OpenSCKeyAttributeCoder::decode(Tokend::TokenContext *tokenContext,
const Tokend::MetaAttribute &metaAttribute,
Tokend::Record &record)
{
	OpenSCToken &token_obj = dynamic_cast<OpenSCToken &>(*tokenContext);
	OpenSCKeyRecord &keyRec = dynamic_cast<OpenSCKeyRecord &>(record);
	const sc_pkcs15_object *keyObj = keyRec.object();

	if(!keyObj)
		return;

	uint32 attrId = metaAttribute.attributeId();

	unsigned long value = 0;

	switch (attrId) {
		case kSecKeyEffectiveKeySize:
		case kSecKeyKeySizeInBits:
			if(keyObj->type & SC_PKCS15_TYPE_PRKEY) {
				sc_pkcs15_prkey_info *prkey = (sc_pkcs15_prkey_info *)keyObj->data;
				if (keyObj->type == SC_PKCS15_TYPE_PRKEY_EC)
					value = prkey->field_length; /* EC field length in bits */
				else
					value = prkey->modulus_length; /* RSA modulus length in bits */
				// FIXME - need to address DSA keys too
			}
			else if(keyObj->type & SC_PKCS15_TYPE_PUBKEY) {
				sc_pkcs15_pubkey_info *pubkey = (sc_pkcs15_pubkey_info *)keyObj->data;
				if (keyObj->type == SC_PKCS15_TYPE_PRKEY_EC)
					value = pubkey->field_length; /* EC field length in bits */
				else
					value = pubkey->modulus_length; /* RSA modulus length in bits */
				// FIXME - need to address DSA keys too
			}
			else if(keyObj->type & SC_PKCS15_TYPE_PUBKEY) {
				sc_pkcs15_pubkey_info *pubkey = (sc_pkcs15_pubkey_info *)keyObj->data;
				if (keyObj->type == SC_PKCS15_TYPE_PRKEY_EC) {
				  sc_debug(token_obj.mScCtx, SC_LOG_DEBUG_NORMAL, "keyObj type EC (%d)\n", keyObj->type);
					value = pubkey->field_length; /* EC field length in bits */
				} else {
				  sc_debug(token_obj.mScCtx, SC_LOG_DEBUG_NORMAL, "keyObj type RSA (%d)\n", keyObj->type);
					value = pubkey->modulus_length; /* RSA modulus length in bits */
				}
				// FIXME - need to address DSA keys too
			else {
				sc_debug(token_obj.mScCtx, SC_LOG_DEBUG_NORMAL, "Unknown keyObj type: %d\n", keyObj->type);
			}
			record.attributeAtIndex(metaAttribute.attributeIndex(), new Attribute((uint32)value));
			break;

		default:
			sc_debug(token_obj.mScCtx, SC_LOG_DEBUG_NORMAL, "Unknown AttributeID: %d\n",attrId);
			break;
	}
}
