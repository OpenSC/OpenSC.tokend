/*
 *  Copyright (c) 2004 Apple Computer, Inc. All Rights Reserved.
 *
 *  @APPLE_LICENSE_HEADER_OpenSCSTART@
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
 *  OpenSCSchema.h
 *  TokendMuscle
 */

/*
 * This code is based on the BELPIC tokend distributed by Apple with Tiger.   Adapted for use with
 * an Aladdin eToken Pro populated with OpenSC (PKCS#15) by Ron DiNapoli, Cornell University (rd29@cornell.edu)
 *
 * This code only works if you have a driver which allows your token to interface with the PCSC daemon
 */

#ifndef _OpenSCSCHEMA_H_
#define _OpenSCSCHEMA_H_

#include "Schema.h"
#include "OpenSCKeyHandle.h"
#include "OpenSCAttributeCoder.h"

namespace Tokend
{
	class Relation;
	class MetaRecord;
	class AttributeCoder;
}


class OpenSCSchema : public Tokend::Schema
{
	NOCOPY(OpenSCSchema)
		public:
		OpenSCSchema();
		virtual ~OpenSCSchema();

		virtual void create();

	protected:
		Tokend::Relation *createKeyRelation(CSSM_DB_RECORDTYPE keyType);

	private:
		Tokend::ConstAttributeCoder mKeyAlgorithmCoder;
		OpenSCKeyAttributeCoder mKeyAttributeCoder;

		OpenSCKeyHandleFactory mOpenSCKeyHandleFactory;
};
/* !_OpenSCSCHEMA_H_ */
#endif
