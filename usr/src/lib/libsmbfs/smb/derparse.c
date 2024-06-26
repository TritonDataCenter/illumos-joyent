// Copyright 2012 Nexenta Systems, Inc.  All rights reserved.
// Copyright (C) 2002 Microsoft Corporation
// All rights reserved.
//
// THIS CODE AND INFORMATION IS PROVIDED "AS IS"
// WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED
// OR IMPLIED, INCLUDING BUT NOT LIMITED
// TO THE IMPLIED WARRANTIES OF MERCHANTIBILITY
// AND/OR FITNESS FOR A PARTICULAR PURPOSE.
//
// Date    - 10/08/2002
// Author  - Sanj Surati


/////////////////////////////////////////////////////////////
//
// DERPARSE.C
//
// SPNEGO Token Handler Source File
//
// Contains implementation of ASN.1 DER read/write functions
// as defined in DERPARSE.H.
//
/////////////////////////////////////////////////////////////

#include <stdlib.h>
#include <stdio.h>
#include <memory.h>
#include <sys/byteorder.h>
#include "spnego.h"
#include "derparse.h"

//
// The GSS Mechanism OID enumeration values (SPNEGO_MECH_OID) control which offset in
// the array below, that a mechanism can be found.
//

#pragma error_messages (off,E_INITIALIZATION_TYPE_MISMATCH)
MECH_OID g_stcMechOIDList [] =
{
        {(unsigned char *)"\x06\x09\x2a\x86\x48\x82\xf7\x12\x01\x02\x02",
         11,  9, spnego_mech_oid_Kerberos_V5_Legacy},	// 1.2.840.48018.1.2.2
	{(unsigned char *)"\x06\x09\x2a\x86\x48\x86\xf7\x12\x01\x02\x02",
         11,  9, spnego_mech_oid_Kerberos_V5}, // 1.2.840.113554.1.2.2
	{(unsigned char *)"\x06\x06\x2b\x06\x01\x05\x05\x02",
         8,  6, spnego_mech_oid_Spnego}, // 1.3.6.1.5.5.2
	{(unsigned char *)"\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a",
         12, 10, spnego_mech_oid_NTLMSSP}, // 1.3.6.1.4.1.311.2.2.10
	{(unsigned char *)"", 0,  0, spnego_mech_oid_NotUsed  // Placeholder
        }
};
#pragma error_messages (default,E_INITIALIZATION_TYPE_MISMATCH)

/////////////////////////////////////////////////////////////////////////////
//
// Function:
//    ASNDerGetLength
//
// Parameters:
//    [in]  pbLengthData      -  DER Length Data
//    [in]  nBoundaryLength   -  Length that value must not exceed.
//    [out] pnLength          -  Filled out with length value
//    [out] pnNumLengthBytes  -  Filled out with number of bytes
//                               consumed by DER length.
//
// Returns:
//    int   Success - SPNEGO_E_SUCCESS
//          Failure - SPNEGO API Error code
//
// Comments :
//    Interprets the data at pbLengthData as a DER length.  The length must
//    fit within the bounds of nBoundary length.  We do not currently
//    process lengths that take more than 4 bytes.
//
////////////////////////////////////////////////////////////////////////////

int ASNDerGetLength( unsigned char* pbLengthData, long nBoundaryLength, long* pnLength,
                     long* pnNumLengthBytes )
{
   int   nReturn = SPNEGO_E_INVALID_LENGTH;
   int   nNumLengthBytes = 0;

   // First check if the extended length bit is set

   if ( *pbLengthData & LEN_XTND )
   {
      // Lower 7 bits contain the number of trailing bytes that describe the length
      nNumLengthBytes = *pbLengthData & LEN_MASK;

      // Check that the number of bytes we are about to read is within our boundary
      // constraints

      if ( nNumLengthBytes <= nBoundaryLength - 1 )
      {

         // For now, our handler won't deal with lengths greater than 4 bytes
         if ( nNumLengthBytes >= 1 && nNumLengthBytes <= 4 )
         {
            // 0 out the initial length
            *pnLength = 0L;

            // Bump by 1 byte
            pbLengthData++;

   #ifdef _LITTLE_ENDIAN

            // There may be a cleaner way to do this, but for now, this seems to be
            // an easy way to do the transformation
            switch ( nNumLengthBytes )
            {
               case 1:
               {
                  *( ( (unsigned char*) pnLength ) ) = *pbLengthData;
                  break;
               }

               case 2:
               {
                  *( ( (unsigned char*) pnLength ) ) = *(pbLengthData + 1);
                  *( ( (unsigned char*) pnLength ) + 1 ) = *(pbLengthData);

                  break;
               }

               case 3:
               {
                  *( ( (unsigned char*) pnLength ) ) = *(pbLengthData + 2);
                  *( ( (unsigned char*) pnLength ) + 2 ) = *(pbLengthData + 1);
                  *( ( (unsigned char*) pnLength ) + 3 ) = *(pbLengthData);
                  break;
               }

               case 4:
               {
                  *( ( (unsigned char*) pnLength ) ) = *(pbLengthData + 3);
                  *( ( (unsigned char*) pnLength ) + 1 ) = *(pbLengthData + 2);
                  *( ( (unsigned char*) pnLength ) + 2 ) = *(pbLengthData + 1);
                  *( ( (unsigned char*) pnLength ) + 3 ) = *(pbLengthData);
                  break;
               }

            }  // SWITCH ( nNumLengthBytes )

   #else
            // We are Big-Endian, so the length can be copied in from the source
            // as is.  Ensure that we adjust for the number of bytes we actually
            // copy.

            memcpy( ( (unsigned char *) pnLength ) + ( 4 - nNumLengthBytes ),
                     pbLengthData, nNumLengthBytes );
   #endif

            // Account for the initial length byte
            *pnNumLengthBytes = nNumLengthBytes + 1;
            nReturn = SPNEGO_E_SUCCESS;

         }  // IF Valid Length

      }  // IF num bytes to read is within the boundary length

   }  // IF xtended length
   else
   {

      // Extended bit is not set, so the length is in the value and the one
      // byte describes the length
      *pnLength = *pbLengthData & LEN_MASK;
      *pnNumLengthBytes = 1;
      nReturn = SPNEGO_E_SUCCESS;

   }

   return nReturn;
}


/////////////////////////////////////////////////////////////////////////////
//
// Function:
//    ASNDerCheckToken
//
// Parameters:
//    [in]  pbTokenData       -  Token Data
//    [in]  nToken            -  Token identifier to check for
//    [in]  nLengthWithToken  -  Expected token length (with data)
//    [in]  nBoundaryLength   -  Length that value must not exceed.
//    [out] pnLength          -  Filled out with data length
//    [out] pnTokenLength     -  Filled out with number of bytes
//                               consumed by token identifier and length.
//
// Returns:
//    int   Success - SPNEGO_E_SUCCESS
//          Failure - SPNEGO API Error code
//
// Comments :
//    Checks the data pointed to by pbTokenData for the specified token
//    identifier and the length that immediately follows.  If
//    nLengthWithToken is > 0, the calculated length must match.  The
//    length must also not exceed the specified boundary length .
//
////////////////////////////////////////////////////////////////////////////

int ASNDerCheckToken( unsigned char* pbTokenData, unsigned char nToken,
                        long nLengthWithToken, long nBoundaryLength,
                        long* pnLength, long* pnTokenLength )
{

   int   nReturn = SPNEGO_E_INVALID_LENGTH;
   long  nNumLengthBytes = 0L;

   // Make sure that we've at least got 2 bytes of room to work with

   if ( nBoundaryLength >= 2 )
   {
      // The first byte of the token data MUST match the specified token
      if ( *pbTokenData == nToken )
      {
         // Next byte indicates the length
         pbTokenData++;

         // Get the length described by the token
         if ( ( nReturn = ASNDerGetLength( pbTokenData, nBoundaryLength, pnLength,
                                             &nNumLengthBytes )  ) == SPNEGO_E_SUCCESS )
         {
            // Verify that the length is LESS THAN the boundary length
            // (this should prevent us walking out of our buffer)
            if ( ( nBoundaryLength - ( nNumLengthBytes + 1 ) < *pnLength ) )
            {

               nReturn = SPNEGO_E_INVALID_LENGTH;

            }

            // If we were passed a length to check, do so now
            if ( nLengthWithToken > 0L )
            {

               // Check that the expected length matches
               if ( ( nLengthWithToken - ( nNumLengthBytes + 1 ) ) != *pnLength )
               {

                  nReturn = SPNEGO_E_INVALID_LENGTH;

               }

            }  // IF need to validate length

            if ( SPNEGO_E_SUCCESS == nReturn )
            {
               *pnTokenLength = nNumLengthBytes + 1;
            }

         }  // IF ASNDerGetLength

      }  // IF token matches
      else
      {
         nReturn = SPNEGO_E_TOKEN_NOT_FOUND;
      }

   }  // IF Boundary Length is at least 2 bytes

   return nReturn;
}

/////////////////////////////////////////////////////////////////////////////
//
// Function:
//    ASNDerCheckOID
//
// Parameters:
//    [in]  pbTokenData       -  Token Data
//    [in]  nMechOID          -  OID we are looking for
//    [in]  nBoundaryLength   -  Length that value must not exceed.
//    [out] pnTokenLength     -  Filled out with number of bytes
//                               consumed by token and data.
//
// Returns:
//    int   Success - SPNEGO_E_SUCCESS
//          Failure - SPNEGO API Error code
//
// Comments :
//    Checks the data pointed to by pbTokenData for the specified OID.
//
////////////////////////////////////////////////////////////////////////////

int ASNDerCheckOID( unsigned char* pbTokenData, SPNEGO_MECH_OID nMechOID, long nBoundaryLength,
                     long* pnTokenLength )
{
   int   nReturn = 0L;
   long  nLength = 0L;

   // Verify that we have an OID token
   if ( ( nReturn = ASNDerCheckToken( pbTokenData, OID, 0L, nBoundaryLength,
                                       &nLength, pnTokenLength ) ) == SPNEGO_E_SUCCESS )
   {
      // Add the data length to the Token Length
      *pnTokenLength += nLength;

      // Token Lengths plus the actual length must match the length in our OID list element.
      // If it doesn't, we're done
      if ( *pnTokenLength == g_stcMechOIDList[nMechOID].iLen )
      {
         // Memcompare the token and the expected field
         if ( memcmp( pbTokenData, g_stcMechOIDList[nMechOID].ucOid, *pnTokenLength ) != 0 )
         {
            nReturn = SPNEGO_E_UNEXPECTED_OID;
         }
      }
      else
      {
         nReturn = SPNEGO_E_UNEXPECTED_OID;
      }

   }  // IF OID Token CHecks

   return nReturn;
}

/////////////////////////////////////////////////////////////////////////////
//
// Function:
//    ASNDerCalcNumLengthBytes
//
// Parameters:
//    [in]  nLength           -  Length to calculate length bytes for.
//
// Returns:
//    int   Number of bytes necessary to represent length
//
// Comments :
//    Helper function to calculate the number of length bytes necessary to
//    represent a length value.  For our purposes, a 32-bit value should be
//    enough to describea length.
//
////////////////////////////////////////////////////////////////////////////

int ASNDerCalcNumLengthBytes( long nLength )
{
      if ( nLength <= 0x7F )
      {
         // A single byte will be sufficient for describing this length.
         // The byte will simply contain the length
         return 1;
      }
      else if ( nLength <= 0xFF )
      {
         // Two bytes are necessary, one to say how many following bytes
         // describe the length, and one to give the length
         return 2;
      }
      else if ( nLength <= 0xFFFF )
      {
         // Three bytes are necessary, one to say how many following bytes
         // describe the length, and two to give the length
         return 3;
      }
      else if ( nLength <= 0xFFFFFF )
      {
         // Four bytes are necessary, one to say how many following bytes
         // describe the length, and three to give the length
         return 4;
      }
      else
      {
         // Five bytes are necessary, one to say how many following bytes
         // describe the length, and four to give the length
         return 5;
      }
}


/////////////////////////////////////////////////////////////////////////////
//
// Function:
//    ASNDerCalcTokenLength
//
// Parameters:
//    [in]  nLength           -  Length to calculate length bytes for.
//    [in]  nDataLength       -  Actual Data length value.
//
// Returns:
//    long  Number of bytes necessary to represent a token, length and data
//
// Comments :
//    Helper function to calculate a token and value size, based on a
//    supplied length value, and any binary data that will need to be
//    written out.
//
////////////////////////////////////////////////////////////////////////////

long ASNDerCalcTokenLength( long nLength, long nDataLength )
{
   // Add a byte to the length size to account for a single byte to
   // hold the token type.
   long  nTotalLength = ASNDerCalcNumLengthBytes( nLength ) + 1;

   return nTotalLength + nDataLength;
}


/////////////////////////////////////////////////////////////////////////////
//
// Function:
//    ASNDerCalcElementLength
//
// Parameters:
//    [in]  nDataLength       -  Length of data.
//    [out] pnInternalLength  -  Filled out with length of element
//                               without sequence info.
//
// Returns:
//    long  Number of bytes necessary to represent an element
//
// Comments :
//    Helper function to calculate an element length.  An element consists
//    of a sequence token, a type token and then the data.
//
////////////////////////////////////////////////////////////////////////////

long ASNDerCalcElementLength( long nDataLength, long* pnInternalLength )
{
   // First the type token and the actual data
   long  nTotalLength = ASNDerCalcTokenLength( nDataLength, nDataLength );

   // Internal length is the length without the element sequence token
   if ( NULL != pnInternalLength )
   {
      *pnInternalLength = nTotalLength;
   }

   // Next add in the element's sequence token (remember that its
   // length is the total length of the type token and data)
   nTotalLength += ASNDerCalcTokenLength( nTotalLength, 0L );

   return nTotalLength;
}

/////////////////////////////////////////////////////////////////////////////
//
// Function:
//    ASNDerCalcMechListLength
//
// Parameters:
//    [in]  mechoid           -  Mech OID to put in list.
//    [out] pnInternalLength  -  Filled out with length of element
//                               without the primary sequence token.
//
// Returns:
//    long  Number of bytes necessary to represent a mechList
//
// Comments :
//    Helper function to calculate a MechList length.  A mechlist consists
//    of a NegTokenInit sequence token, a sequence token for the MechList
//    and finally a list of OIDs.
//
////////////////////////////////////////////////////////////////////////////

long ASNDerCalcMechListLength( SPNEGO_MECH_OID *mechOidLst, int mechOidCnt,
   long* pnInternalLength )
{
	// First the OID
	SPNEGO_MECH_OID oid_idx;
	long  nTotalLength;
	int i;

	nTotalLength = 0;
	for (i = 0; i < mechOidCnt; i++) {
		oid_idx = mechOidLst[i];
		nTotalLength += g_stcMechOIDList[oid_idx].iLen;
	}

	// Next add in a sequence token
	nTotalLength += ASNDerCalcTokenLength( nTotalLength, 0L );

	// Internal length is the length without the element sequence token
	if ( NULL != pnInternalLength )
	{
		*pnInternalLength = nTotalLength;
	}

	// Finally add in the element's sequence token
	nTotalLength += ASNDerCalcTokenLength( nTotalLength, 0L );

	return nTotalLength;
}


/////////////////////////////////////////////////////////////////////////////
//
// Function:
//    ASNDerWriteLength
//
// Parameters:
//    [out] pbData            -  Buffer to write into.
//    [in]  nLength           -  Length to write out.
//
// Returns:
//    int   Number of bytes written out
//
// Comments :
//    Helper function to write out a length value following DER rules .
//
////////////////////////////////////////////////////////////////////////////

int ASNDerWriteLength( unsigned char* pbData, long nLength )
{
   int   nNumBytesRequired = ASNDerCalcNumLengthBytes( nLength );
   int   nNumLengthBytes = nNumBytesRequired - 1;


   if ( nNumBytesRequired > 1 )
   {

      // Write out the number of bytes following which will be used
      *pbData = (unsigned char ) ( LEN_XTND | nNumLengthBytes );

      // Point to where we'll actually write the length
      pbData++;

#ifdef  _LITTLE_ENDIAN

      // There may be a cleaner way to do this, but for now, this seems to be
      // an easy way to do the transformation
      switch ( nNumLengthBytes )
      {
         case 1:
         {
            // Cast the length to a single byte, since we know that it
            // is 0x7F or less (or we wouldn't only need a single byte).

            *pbData = (unsigned char) nLength;
            break;
         }

         case 2:
         {
            *pbData = *( ( (unsigned char*) &nLength ) + 1 );
            *( pbData + 1) = *( ( (unsigned char*) &nLength ) );
            break;
         }

         case 3:
         {
            *pbData = *( ( (unsigned char*) &nLength ) + 3 );
            *( pbData + 1) = *( ( (unsigned char*) &nLength ) + 2 );
            *( pbData + 2) = *( ( (unsigned char*) &nLength ) );
            break;
         }

         case 4:
         {
            *pbData = *( ( (unsigned char*) &nLength ) + 3 );
            *( pbData + 1) = *( ( (unsigned char*) &nLength ) + 2 );
            *( pbData + 2) = *( ( (unsigned char*) &nLength ) + 1 );
            *( pbData + 3) = *( ( (unsigned char*) &nLength ) );
            break;
         }

      }  // SWITCH ( nNumLengthBytes )

#else
      // We are Big-Endian, so the length can be copied in from the source
      // as is.  Ensure that we adjust for the number of bytes we actually
      // copy.

      memcpy( pbData,
               ( (unsigned char *) &nLength ) + ( 4 - nNumLengthBytes ), nNumLengthBytes );
#endif

   }  // IF > 1 byte for length
   else
   {
      // Cast the length to a single byte, since we know that it
      // is 0x7F or less (or we wouldn't only need a single byte).

      *pbData = (unsigned char) nLength;
   }

   return nNumBytesRequired;
}

/////////////////////////////////////////////////////////////////////////////
//
// Function:
//    ASNDerWriteToken
//
// Parameters:
//    [out] pbData            -  Buffer to write into.
//    [in]  ucType            -  Token Type
//    [in]  pbTokenValue      -  Actual Value
//    [in]  nLength           -  Length of Data.
//
// Returns:
//    int   Number of bytes written out
//
// Comments :
//    Helper function to write out a token and any associated data.  If
//    pbTokenValue is non-NULL, then it is written out in addition to the
//    token identifier and the length bytes.
//
////////////////////////////////////////////////////////////////////////////

int ASNDerWriteToken( unsigned char* pbData, unsigned char ucType,
                     unsigned char* pbTokenValue, long nLength )
{
   int   nTotalBytesWrittenOut = 0L;
   int   nNumLengthBytesWritten = 0L;

   // Write out the type
   *pbData = ucType;

   // Wrote 1 byte, and move data pointer
   nTotalBytesWrittenOut++;
   pbData++;

   // Now write out the length and adjust the number of bytes written out
   nNumLengthBytesWritten = ASNDerWriteLength( pbData, nLength );

   nTotalBytesWrittenOut += nNumLengthBytesWritten;
   pbData += nNumLengthBytesWritten;

   // Write out the token value if we got one.  The assumption is that the
   // nLength value indicates how many bytes are in pbTokenValue.

   if ( NULL != pbTokenValue )
   {
      memcpy( pbData, pbTokenValue, nLength );
      nTotalBytesWrittenOut += nLength;
   }

   return nTotalBytesWrittenOut;
}


/////////////////////////////////////////////////////////////////////////////
//
// Function:
//    ASNDerWriteOID
//
// Parameters:
//    [out] pbData            -  Buffer to write into.
//    [in]  eMechOID          -  OID to write out.
//
// Returns:
//    int   Number of bytes written out
//
// Comments :
//    Helper function to write out an OID.  For these we have the raw bytes
//    listed in a global structure.  The caller simply indicates which OID
//    should be written and we will splat out the data.
//
////////////////////////////////////////////////////////////////////////////

int ASNDerWriteOID( unsigned char* pbData, SPNEGO_MECH_OID eMechOID )
{

	if (pbData != NULL) {
		memcpy( pbData, g_stcMechOIDList[eMechOID].ucOid,
		    g_stcMechOIDList[eMechOID].iLen );
	}

	return g_stcMechOIDList[eMechOID].iLen;
}


/////////////////////////////////////////////////////////////////////////////
//
// Function:
//    ASNDerWriteMechList
//
// Parameters:
//    [out] pbData            -  Buffer to write into.
//    [in]  eMechOID          -  OID to put in MechList.
//
// Returns:
//    int   Number of bytes written out
//
// Comments :
//    Helper function to write out a MechList.  A MechList consists of the
//    Init Token Sequence, a sequence token and then the list of OIDs.  In
//    our case the OID is from a global array of known OIDs.
//
////////////////////////////////////////////////////////////////////////////

long ASNDerWriteMechList( unsigned char* pbData, SPNEGO_MECH_OID *mechOidLst, int mechOidCnt )
{
	// First get the length
	long  nInternalLength = 0L;
	long  nMechListLength;
	long  nTempLength = 0L;
	int   i;

	nMechListLength = ASNDerCalcMechListLength(mechOidLst, mechOidCnt, &nInternalLength);
	nTempLength = ASNDerWriteToken( pbData, SPNEGO_NEGINIT_ELEMENT_MECHTYPES,
                                    NULL, nInternalLength );

	// Adjust the data pointer
	pbData += nTempLength;
	nInternalLength	-= nTempLength;

	// Now write the Sequence token and the OID (the OID is a BLOB in the global
	// structure.

	nTempLength = ASNDerWriteToken( pbData, SPNEGO_CONSTRUCTED_SEQUENCE,
					NULL, nInternalLength);
	pbData += nTempLength;

	for (i = 0; i < mechOidCnt; i++) {
		nTempLength = ASNDerWriteOID( pbData, mechOidLst[i] );
		pbData += nTempLength;
	}

	return nMechListLength;
}


/////////////////////////////////////////////////////////////////////////////
//
// Function:
//    ASNDerWriteElement
//
// Parameters:
//    [out] pbData            -  Buffer to write into.
//    [in]  ucElementSequence -  Sequence Token
//    [in]  ucType            -  Token Type
//    [in]  pbTokenValue      -  Actual Value
//    [in]  nLength           -  Length of Data.
//
// Returns:
//    int   Number of bytes written out
//
// Comments :
//    Helper function to write out a SPNEGO Token element.  An element
//    consists of a sequence token, a type token and the associated data.
//
////////////////////////////////////////////////////////////////////////////

int ASNDerWriteElement( unsigned char* pbData, unsigned char ucElementSequence,
                        unsigned char ucType, unsigned char* pbTokenValue, long nLength )
{
   // First get the length
   long  nInternalLength = 0L;
   long  nElementLength = ASNDerCalcElementLength( nLength, &nInternalLength );
   long  nTempLength = 0L;

   // Write out the sequence byte and the length of the type and data
   nTempLength = ASNDerWriteToken( pbData, ucElementSequence, NULL, nInternalLength );

   // Adjust the data pointer
   pbData += nTempLength;

   // Now write the type and the data.
   nTempLength = ASNDerWriteToken( pbData, ucType, pbTokenValue, nLength );

   return nElementLength;
}
