/********************************************************************************/
/*										*/
/*			 Ultravisor Support Interface  				*/
/*										*/
/* (c) Copyright IBM Corporation 2019						*/
/*										*/
/* All rights reserved.								*/
/* 										*/
/* Redistribution and use in source and binary forms, with or without		*/
/* modification, are permitted provided that the following conditions are	*/
/* met:										*/
/* 										*/
/* Redistributions of source code must retain the above copyright notice,	*/
/* this list of conditions and the following disclaimer.			*/
/* 										*/
/* Redistributions in binary form must reproduce the above copyright		*/
/* notice, this list of conditions and the following disclaimer in the		*/
/* documentation and/or other materials provided with the distribution.		*/
/* 										*/
/* Neither the names of the IBM Corporation nor the names of its		*/
/* contributors may be used to endorse or promote products derived from		*/
/* this software without specific prior written permission.			*/
/* 										*/
/* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS		*/
/* "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT		*/
/* LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR	*/
/* A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT		*/
/* HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,	*/
/* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT		*/
/* LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,	*/
/* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY	*/
/* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT		*/
/* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE	*/
/* OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.		*/
/********************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <ibmtss/tss.h>
#include <ibmtss/tssfile.h>
#include <ibmtss/tssmarshal.h>
#include <ibmtss/tssresponsecode.h>
#include <ibmtss/Startup_fp.h>
#include "tssproperties.h"

#include "tssuv.h"

// /* TPM2B Types */
//  typedef struct {
//    UINT16          size;
//    BYTE            buffer[1];
//  } TPM2B, *P2B;

///* Table 71 - Definition of TPM2B_DIGEST Structure */
//
//  typedef struct {
//      UINT16    size;
//      BYTE      buffer[sizeof(TPMU_HA)];
//  } DIGEST_2B;
//
//  typedef union {
//      DIGEST_2B    t;
//      TPM2B        b;
//  } TPM2B_DIGEST;

//
// typedef struct {
//      UINT32              count;          /* number of digests in the list, mini  mum is two for TPM2_PolicyOR(). */
//     TPM2B_DIGEST        digests[8];     /* a list of digests */
// } TPML_DIGEST;
//

TPML_DIGEST uv_tss_tpml_hashlist;

static void traceError(const char *command, TPM_RC rc)
{
    const char *msg;
    const char *submsg;
    const char *num;
    printf("%s: failed, rc %08x\n", command, rc);
    TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
    printf("%s%s%s\n", msg, submsg, num);
}

/**
 * @brief readpublic fills the TSS context object slot with the
 *        wrapping key public part. The Name is required for
 *        the HMAC calculation.
 *
 */
static TPM_RC UV_TSS_ReadPublic(TSS_CONTEXT *tssContext,
				const TPMI_DH_OBJECT keyHandle,
				const size_t pubLength,
				const uint8_t *pubBuffer)
{
	TPM_RC		rc;
	ReadPublic_In	*readPublicIn;
	ReadPublic_Out	*readPublicOut;
	TPM2B_NAME *publicName;

	readPublicIn = NULL;
	readPublicOut = NULL;

	rc = TSS_Malloc((unsigned char **)&readPublicIn,
			sizeof(*readPublicIn));
	if (rc) {
	    traceError("readPublicIn malloc", rc);
	    goto out;
	}

	rc = TSS_Malloc((unsigned char **)&readPublicOut,
			sizeof(*readPublicOut));
	if (rc) {
	    traceError("readPublicOut malloc", rc);
	    goto readpublic_free;
	}

	readPublicIn->objectHandle = keyHandle;

	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)readPublicOut,
			 (COMMAND_PARAMETERS *)readPublicIn,
			 NULL,
			 TPM_CC_ReadPublic,
			 TPM_RH_NULL, NULL, 0);
	if (rc) {
	    goto readpublic_free;
	}

	publicName = &readPublicOut->name;

	rc = memcmp(&publicName->t.name[0], pubBuffer, pubLength);

	if (rc) {
		traceError("memcmp of publicName", rc);
	}

readpublic_free:
	free(readPublicOut);
	free(readPublicIn);
out:
	return rc;
}

static void UV_TSS_Init_Decrypt_Hashlist(TPML_DIGEST *hashlist,
					 const size_t polALength,
					 const uint8_t *polABuffer,
					 const size_t polBLength,
					 const uint8_t *polBBuffer)
{
	TPM2B *tpm2b;
	uint16_t targetSize;

	hashlist->count = 2;

	/* PEF policy a */
	tpm2b = &hashlist->digests[0].b;
	targetSize = sizeof(hashlist->digests[0].t.buffer);
	TSS_TPM2B_Create(tpm2b, polABuffer, (uint16_t)polALength, targetSize);

	/* PEF policy b */
	tpm2b = &hashlist->digests[1].b;
	targetSize = sizeof(hashlist->digests[1].t.buffer);
	TSS_TPM2B_Create(tpm2b, polBBuffer, (uint16_t)polBLength, targetSize);
}

static TPM_RC UV_TSS_Policy_AuthValue_In(TSS_CONTEXT *tssContext,
		TPMI_SH_AUTH_SESSION sessionHandle)
{
	TPM_RC			rc;
	PolicyAuthValue_In 	policyAuthValueIn;

	policyAuthValueIn.policySession = sessionHandle;
	rc = TSS_Execute(tssContext,
			 NULL,
			 (COMMAND_PARAMETERS *)&policyAuthValueIn,
			 NULL,
			 TPM_CC_PolicyAuthValue,
			 TPM_RH_NULL, NULL, 0);

	return rc;
}

static TPM_RC
UV_TSS_Policy_Or_In(TSS_CONTEXT *tssContext, TPMI_SH_AUTH_SESSION sessionHandle,
		    const size_t polALength, const uint8_t *polABuffer,
		    const size_t polBLength, const uint8_t *polBBuffer)
{
	TPM_RC			rc;
	TPML_DIGEST		*pHashList = &uv_tss_tpml_hashlist;
	PolicyOR_In 		*policyORIn;

	UV_TSS_Init_Decrypt_Hashlist(pHashList, polALength, polABuffer,
				     polBLength, polBBuffer);

	policyORIn = NULL;

	rc = TSS_Malloc((unsigned char **)&policyORIn, sizeof(*policyORIn));
	if (rc) {
	    traceError("policyORIn malloc", rc);
	    goto out;
	}

	policyORIn->policySession = sessionHandle;
	policyORIn->pHashList = *pHashList;
	rc = TSS_Execute(tssContext,
			 NULL,
			 (COMMAND_PARAMETERS *)policyORIn,
			 NULL,
			 TPM_CC_PolicyOR,
			 TPM_RH_NULL, NULL, 0);

	free(policyORIn);

out:
	return rc;
}

static TPM_RC UV_TSS_Policy_RSA_Decrypt(TSS_CONTEXT *tssContext,
		TPMI_SH_AUTH_SESSION sessionHandle)
{
	TPM_RC			rc;
	PolicyCommandCode_In 	policyCommandCodeIn;

	policyCommandCodeIn.policySession = sessionHandle;
	policyCommandCodeIn.code = TPM_CC_RSA_Decrypt;
	rc = TSS_Execute(tssContext,
			 NULL,
			 (COMMAND_PARAMETERS *)&policyCommandCodeIn,
			 NULL,
			 TPM_CC_PolicyCommandCode,
			 TPM_RH_NULL, NULL, 0);

	return rc;
}

static TPM_RC UV_TSS_Start_Auth_Session(TSS_CONTEXT *tssContext,
		TPMI_SH_AUTH_SESSION *sessionHandle)
{
	TPM_RC			rc;
	StartAuthSession_In 	*startAuthSessionIn;
	StartAuthSession_Out 	*startAuthSessionOut;
	StartAuthSession_Extra	*startAuthSessionExtra;

	startAuthSessionIn = NULL;
	startAuthSessionOut = NULL;
	startAuthSessionExtra = NULL;

	rc = TSS_Malloc((unsigned char **)&startAuthSessionIn, sizeof(*startAuthSessionIn));
	if (rc) {
	    traceError("startAuthSessionIn malloc", rc);
	    goto out;
	}

	rc = TSS_Malloc((unsigned char **)&startAuthSessionOut, sizeof(*startAuthSessionOut));
	if (rc) {
	    traceError("startAuthSessionOut malloc", rc);
	    goto auth_session_free;
	}

	rc = TSS_Malloc((unsigned char **)&startAuthSessionExtra, sizeof(*startAuthSessionExtra));
	if (rc) {
	    traceError("startAuthSessionExtra malloc", rc);
	    goto auth_session_free;
	}

	startAuthSessionIn->sessionType = TPM_SE_POLICY;
	startAuthSessionIn->tpmKey = TPM_RH_NULL;
	startAuthSessionIn->bind = TPM_RH_NULL;
	startAuthSessionIn->encryptedSalt.b.size = 0;	/* (not required) */
	startAuthSessionIn->nonceCaller.t.size = 0;	/* (not required) */
	startAuthSessionIn->symmetric.algorithm = TPM_ALG_AES;
	startAuthSessionIn->authHash = TPM_ALG_SHA256;
	startAuthSessionIn->symmetric.keyBits.aes = 128;
	startAuthSessionIn->symmetric.mode.aes = TPM_ALG_CFB;
	startAuthSessionExtra->bindPassword = NULL;	/* (not required) */
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)startAuthSessionOut,
			 (COMMAND_PARAMETERS *)startAuthSessionIn,
			 (EXTRA_PARAMETERS *)startAuthSessionExtra,
			 TPM_CC_StartAuthSession,
			 TPM_RH_NULL, NULL, 0);
	if (rc) {
	    goto auth_session_free;
	}

	*sessionHandle = startAuthSessionOut->sessionHandle;

auth_session_free:
	free(startAuthSessionIn);
	free(startAuthSessionOut);
	free(startAuthSessionExtra);
out:
	return rc;
}

static TPM_RC flushContext(TSS_CONTEXT *tssContext, TPM_HANDLE handle)
{
	TPM_RC		rc;
	FlushContext_In	*flushCtx;

	flushCtx = malloc(sizeof(*flushCtx));
	if (flushCtx == NULL)
		return TPM_RC_MEMORY;

	flushCtx->flushHandle = handle;
	rc = TSS_Execute(tssContext,
			NULL,
			(COMMAND_PARAMETERS *)flushCtx,
			NULL,
			TPM_CC_FlushContext,
			TPM_RH_NULL, NULL, 0);

	free(flushCtx);

	return rc;
}

/*
  UV_TSS_Decrypt()

  The policies contain 3 terms:

  Policy A should be a constant
  Policy B should be a constant based on the NV index attributes

  @ uvContext	input, uv context
  @ keyPassword	input, pointer to nul terminated string password
  @ decLength	output, pointer to decrypted data length
  @ decBuffer	output, pointer to decrypted data
  @ encLength	input, encrypted data length
  @ encBuffer	input, encrypted data
  @ wrapKeyHandle input, Wrapping key handle 
  @ pubLength	input, public area length
  @ pubBuffer	input, public area
  @ polALength	inout, policy A buffer
  @ polABuffer	inout, policy A buffer
  @ polBLength	inout, policy B buffer
  @ polBBuffer	inout, policy B buffer
*/

TPM_RC UV_TSS_Decrypt(void *uvContext, const char *keyPassword,
		      uint16_t *decLength, uint8_t *decBuffer,
		      uint16_t encLength, const uint8_t *encBuffer,
		      const uint32_t wrapKeyHandle,
		      const size_t pubLength, const uint8_t *pubBuffer,
		      const size_t polALength, const uint8_t *polABuffer,
		      const size_t polBLength, const uint8_t *polBBuffer)
{
	TPM_RC			rc, ret;
	TSS_CONTEXT		*tssContext;
	TPMI_SH_AUTH_SESSION	sessionHandle;
	TPMI_DH_OBJECT		keyHandle = wrapKeyHandle;
	RSA_Decrypt_In 		*rsa_DecryptIn;
	RSA_Decrypt_Out 	*rsa_DecryptOut;

	/* Start a TSS context */
	rc = TSS_Create(&tssContext);
	if (rc) {
		return rc;
	}

	/* Set uv_ctx and interface type*/
	tssContext->uv_ctx = uvContext;
	tssContext->tssInterfaceType = "uv";

	rc = UV_TSS_ReadPublic(tssContext, keyHandle, pubLength, pubBuffer);
	if (rc) {
	    traceError("readpublic", rc);
	    goto out;
	}

	/* start the policy session */
	rc = UV_TSS_Start_Auth_Session(tssContext, &sessionHandle);
	if (rc) {
	    traceError("startauthsession", rc);
	    goto out;
	}

	/* Policy Command Code RSA Decrypt */
	rc = UV_TSS_Policy_RSA_Decrypt(tssContext, sessionHandle);
	if (rc) {
	    traceError("policycommandcode", rc);
	    goto flush_session;
	}

	/* policy authvalue */
	rc = UV_TSS_Policy_AuthValue_In(tssContext, sessionHandle);
	if (rc) {
	    traceError("policyAuthValueIn", rc);
	    goto flush_session;
	}

	/* policy or */
	rc = UV_TSS_Policy_Or_In(tssContext, sessionHandle, polALength,
				 polABuffer, polBLength, polBBuffer);
	if (rc) {
	    traceError("policyor", rc);
	    goto flush_session;
	}

	/* decrypt the encrypted secret */
	rsa_DecryptIn = NULL;
	rsa_DecryptOut = NULL;

	rc = TSS_Malloc((unsigned char **)&rsa_DecryptIn, sizeof(*rsa_DecryptIn));
	if (rc) {
	    traceError("rsa_DecryptIn malloc", rc);
	    goto flush_session;
	}

	rc = TSS_Malloc((unsigned char **)&rsa_DecryptOut, sizeof(*rsa_DecryptOut));
	if (rc) {
	    traceError("rsa_DecryptOut malloc", rc);
	    goto rsa_decrypt_in_free;
	}

	rsa_DecryptIn->keyHandle = keyHandle;
	rsa_DecryptIn->cipherText.t.size = (uint16_t)encLength;	/* cast safe, range tested above */
	memcpy(rsa_DecryptIn->cipherText.t.buffer, encBuffer, encLength);
	rsa_DecryptIn->inScheme.scheme = TPM_ALG_NULL;
	rsa_DecryptIn->label.t.size = 0;
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)rsa_DecryptOut,
			 (COMMAND_PARAMETERS *)rsa_DecryptIn,
			 NULL,
			 TPM_CC_RSA_Decrypt,
			 sessionHandle, keyPassword,
			 TPMA_SESSION_ENCRYPT|TPMA_SESSION_CONTINUESESSION,
			 TPM_RH_NULL, NULL, 0);
	if (rc) {
	    traceError("rsa_decrypt", rc);
	    goto rsa_decrypt_out_free;
	}

	/* Open code TSS_Structure_Marshal as malloc not needed on pre-allocated buffer */
	/* marshal once to calculates the byte length */
	*decLength = 0;
	rc = TSS_TPM2B_PUBLIC_KEY_RSA_Marshal(&rsa_DecryptOut->message,
			decLength, NULL, NULL);
	if (rc == 0) {
	  uint8_t *buffer1 = decBuffer;        /* for marshaling, moves pointer */
          *decLength = 0;
	  rc = TSS_TPM2B_PUBLIC_KEY_RSA_Marshal(&rsa_DecryptOut->message,
			  decLength, &buffer1, NULL);
	  /* Adjust for return data containing length information */
	  buffer1 = decBuffer + sizeof(uint16_t);
          *decLength = *decLength - sizeof(uint16_t);
	  memmove(decBuffer, buffer1, *decLength);
	}

rsa_decrypt_out_free:
	free(rsa_DecryptOut);

rsa_decrypt_in_free:
	free(rsa_DecryptIn);

flush_session:
	ret = flushContext(tssContext, sessionHandle);
	if (rc == 0)
		rc = ret;

out:
	ret = TSS_Delete(tssContext);
	if (rc == 0)
		rc = ret;

	return rc;
}
