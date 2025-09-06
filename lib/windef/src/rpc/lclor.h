

/* this ALWAYS GENERATED file contains the definitions for the interfaces */


 /* File created by MIDL compiler version 8.01.0628 */
/* at Tue Jan 19 06:14:07 2038
 */
/* Compiler settings for C:/Users/Admin/Desktop/BB_original/BreakingBat/src/rpc/lclor.idl:
    Oicf, W1, Zp8, env=Win64 (32b run), target_arch=AMD64 8.01.0628 
    protocol : dce , ms_ext, c_ext, robust
    error checks: allocation ref bounds_check enum stub_data 
    VC __declspec() decoration level: 
         __declspec(uuid()), __declspec(selectany), __declspec(novtable)
         DECLSPEC_UUID(), MIDL_INTERFACE()
*/
/* @@MIDL_FILE_HEADING(  ) */



/* verify that the <rpcndr.h> version is high enough to compile this file*/
#ifndef __REQUIRED_RPCNDR_H_VERSION__
#define __REQUIRED_RPCNDR_H_VERSION__ 500
#endif

#include "rpc.h"
#include "rpcndr.h"

#ifndef __RPCNDR_H_VERSION__
#error this stub requires an updated version of <rpcndr.h>
#endif /* __RPCNDR_H_VERSION__ */


#ifndef __lclor_h__
#define __lclor_h__

#if defined(_MSC_VER) && (_MSC_VER >= 1020)
#pragma once
#endif

#ifndef DECLSPEC_XFGVIRT
#if defined(_CONTROL_FLOW_GUARD_XFG)
#define DECLSPEC_XFGVIRT(base, func) __declspec(xfg_virtual(base, func))
#else
#define DECLSPEC_XFGVIRT(base, func)
#endif
#endif

/* Forward Declarations */ 

/* header files for imported files */
#include "wtypes.h"
#include "hstring.h"

#ifdef __cplusplus
extern "C"{
#endif 


#ifndef __ILocalObjectExporter_INTERFACE_DEFINED__
#define __ILocalObjectExporter_INTERFACE_DEFINED__

/* interface ILocalObjectExporter */
/* [version][uuid] */ 

typedef MIDL_uhyper ID;

typedef ID MID;

typedef ID OXID;

typedef ID OID;

typedef GUID IPID;

typedef REFGUID REFIPID;

#if 0
// Declare the LOCAL_HSTRING handle as wire_marshal for midl only
typedef /* [unique][wire_marshal] */ HSTRING *LOCAL_HSTRING;

#endif

// Declare the LOCAL_HSTRING handle for C/C++
typedef __RPC_unique_pointer HSTRING* LOCAL_HSTRING;

typedef /* [context_handle] */ void *PHPROCESS;

#define	PROXY_DECODE_MAX_STRUCT_SIZE	( 300 )

typedef /* [public][public] */ struct __MIDL_ILocalObjectExporter_0001
    {
    DWORD offsetofChannelPtrFromProxyPtr;
    DWORD64 addressofOIDListHead;
    /* [range] */ DWORD sizeofIPIDEntry;
    DWORD offsetofNextIPIDPointerInIPIDEntry;
    DWORD offsetofFlagsInIPIDEntry;
    DWORD offsetofIPIDInIPIDEntry;
    DWORD offsetofServerAddressInIPIDEntry;
    DWORD offsetofOIDFLinkInIPIDEntry;
    DWORD serverIPIDEntryFlag;
    DWORD invalidIPIDEntryFlags;
    /* [range] */ DWORD sizeofOxidEntry;
    DWORD offsetofPidInOxidEntry;
    DWORD offsetofTidInOxidEntry;
    /* [range] */ DWORD sizeofCClientChannel;
    DWORD offsetofCanonicalIRpcChannelBufferInCClientChannel;
    DWORD offsetofIPIDEntryInCClientChannel;
    DWORD offsetofOxidEntryInCClientChannel;
    DWORD offsetofSignatureInCClientChannel;
    GUID guidSignatureofCClientChannel;
    } 	PROXY_DECODE_INFO;

typedef /* [public][public] */ struct __MIDL_ILocalObjectExporter_0002
    {
    /* [unique][string] */ WCHAR *pName;
    WORD wId;
    } 	SECPKG;

typedef struct tagDUALSTRINGARRAY
    {
    WORD wNumEntries;
    WORD wSecurityOffset;
    /* [size_is] */ WORD aStringArray[ 1 ];
    } 	DUALSTRINGARRAY;

typedef /* [public][public][public][public] */ 
enum __MIDL_ILocalObjectExporter_0003
    {
        OR_OXID_CLIENT_DEPENDENCY_NONE	= 0,
        OR_OXID_CLIENT_DEPENDENCY_UNIDIRECTIONAL	= 1,
        OR_OXID_CLIENT_DEPENDENCY_BIDIRECTIONAL	= 2
    } 	ClientDependencyBehavior;

typedef /* [public][public][public][public] */ struct __MIDL_ILocalObjectExporter_0004
    {
    WORD MajorVersion;
    WORD MinorVersion;
    } 	COMVERSION;

typedef /* [public][public][public][public][public] */ struct __MIDL_ILocalObjectExporter_0005
    {
    DWORD id;
    DWORD version;
    DWORD size;
    /* [size_is] */ BYTE data[ 1 ];
    } 	CONTAINER_EXTENT;

typedef /* [public][public][public][public][public] */ struct __MIDL_ILocalObjectExporter_0006
    {
    DWORD size;
    DWORD reserved;
    /* [ref][size_is] */ CONTAINER_EXTENT **extent;
    } 	CONTAINER_EXTENT_ARRAY;

typedef /* [public][public][public][public] */ struct __MIDL_ILocalObjectExporter_0007
    {
    DWORD version;
    DWORD64 capabilityFlags;
    CONTAINER_EXTENT_ARRAY *extensions;
    } 	CONTAINERVERSION;

typedef /* [public][public][public] */ struct __MIDL_ILocalObjectExporter_0008
    {
    DWORD dwTid;
    DWORD dwPid;
    DWORD dwAuthnHint;
    COMVERSION version;
    CONTAINERVERSION containerVersion;
    IPID ipidRemUnknown;
    DWORD dwFlags;
    DUALSTRINGARRAY *psa;
    GUID guidProcessIdentifier;
    DWORD64 processHostId;
    ClientDependencyBehavior clientDependencyBehavior;
    LOCAL_HSTRING packageFullName;
    LOCAL_HSTRING userSid;
    LOCAL_HSTRING appcontainerSid;
    OXID primaryOxid;
    GUID primaryIpidRemUnknown;
    } 	INTERNAL_OXID_INFO;

typedef /* [public][public] */ struct __MIDL_ILocalObjectExporter_0009
    {
    MID mid;
    OXID oxid;
    DWORD refs;
    } 	OXID_REF;

typedef /* [public][public] */ struct __MIDL_ILocalObjectExporter_0010
    {
    MID mid;
    OID oid;
    } 	OID_MID_PAIR;

typedef /* [public][public] */ struct __MIDL_ILocalObjectExporter_0011
    {
    MID mid;
    OXID oxid;
    OID oid;
    } 	OXID_OID_PAIR;

typedef /* [public][public] */ struct __MIDL_ILocalObjectExporter_0012
    {
    MID mid;
    OID oid;
    DWORD unmarshalCount;
    } 	POTENTIAL_PROXY_OID;

#define	CONNECT_DISABLEDCOM	( 0x1 )

#define	CONNECT_ENABLE_CONTAINER_DCOM	( 0x2 )

#define	CONNECT_MUTUALAUTH	( 0x4 )

#define	CONNECT_SECUREREF	( 0x8 )

#define	CONNECT_CATCH_SERVER_EXCEPTIONS	( 0x10 )

#define	CONNECT_BREAK_ON_SILENCED_SERVER_EXCEPTIONS	( 0x20 )

#define	CONNECT_DISABLE_CALL_FAILURE_LOGGING	( 0x40 )

#define	CONNECT_DISABLE_INVALID_SD_LOGGING	( 0x80 )

#define	CONNECT_ENABLE_OLD_MODAL_LOOP	( 0x100 )

#define	CONNECT_ACCESS_RESTRICTIONS_VIA_POLICY	( 0x200 )

#define	MAX_IDS	( 0x20000 )

#define	MAX_OIDS	( 0x100000 )

error_status_t Connect( 
    /* [in] */ handle_t hServer,
    /* [unique][string][in] */ WCHAR *pwszWinstaDesktop,
    /* [unique][string][in] */ WCHAR *pwszExePath,
    /* [unique][in] */ PROXY_DECODE_INFO *pProxyDecodeInfo,
    /* [in] */ DWORD dwProcessFlags,
    /* [in] */ WORD dwProcessArchitecture,
    /* [out] */ PHPROCESS *pProcess,
    /* [out] */ DWORD *pdwTimeoutInSeconds,
    /* [out] */ DUALSTRINGARRAY **ppdsaOrBindings,
    /* [out] */ MID *pLocalMid,
    /* [range][in] */ DWORD cIdsToReserve,
    /* [size_is][out] */ ID aIdsReserved[  ],
    /* [out] */ DWORD *pcIdsReserved,
    /* [out] */ DWORD *pfConnectFlags,
    /* [out] */ DWORD *pIncomingContainerAuthnSvc,
    /* [out] */ DWORD *pOutgoingContainerAuthnSvc,
    /* [string][out] */ WCHAR **pLegacySecurity,
    /* [out] */ DWORD *pAuthnLevel,
    /* [out] */ DWORD *pImpLevel,
    /* [out] */ DWORD *pcServerSvc,
    /* [size_is][size_is][out] */ WORD **aServerSvc,
    /* [out] */ DWORD *pcClientSvc,
    /* [size_is][size_is][out] */ SECPKG **aClientSvc,
    /* [out] */ LONG *pcChannelHook,
    /* [size_is][size_is][out] */ GUID **aChannelHook,
    /* [out] */ DWORD *pProcessID,
    /* [out] */ DWORD *pScmProcessID,
    /* [out] */ DWORD64 *pSignature,
    /* [out] */ GUID *pguidRPCSSProcessIdentifier,
    /* [out] */ DWORD dwSDSizes[ 5 ],
    /* [out] */ DWORD *pdwSDBlob,
    /* [size_is][size_is][out] */ BYTE **pSDBlob);

error_status_t SetAppID( 
    /* [in] */ handle_t hServer,
    /* [in] */ PHPROCESS phProcess,
    /* [in] */ GUID guidAppID);

error_status_t GetDefaultSecurityPermissions( 
    /* [in] */ handle_t hServer,
    /* [out] */ DWORD dwSDSizes[ 4 ],
    /* [out] */ DWORD *pdwSDBlob,
    /* [size_is][size_is][out] */ BYTE **pSDBlob);

error_status_t AllocateReservedIds( 
    /* [in] */ handle_t hServer,
    /* [in] */ PHPROCESS phProcess,
    /* [range][in] */ unsigned long cIdsToAlloc,
    /* [size_is][out] */ ID aIdsAllocated[  ],
    /* [out] */ DWORD *pcIdsAllocated);

error_status_t BulkUpdateOIDs( 
    /* [in] */ handle_t hServer,
    /* [in] */ PHPROCESS phProcess,
    /* [range][in] */ DWORD cOidsToBeAdded,
    /* [size_is][in] */ OXID_OID_PAIR aOidsToBeAdded[  ],
    /* [size_is][out] */ DWORD aStatusOfAdds[  ],
    /* [range][in] */ DWORD cOidsToBeRemoved,
    /* [size_is][in] */ OID_MID_PAIR aOidsToBeRemoved[  ],
    /* [range][in] */ DWORD cServerOidsToFree,
    /* [size_is][in] */ OID aServerOids[  ],
    /* [range][in] */ DWORD cServerOidsToUnPin,
    /* [size_is][in] */ OID aServerOidsToUnPin[  ],
    /* [range][in] */ DWORD cOxidsToFree,
    /* [size_is][in] */ OXID_REF aOxidsToFree[  ],
    /* [range][in] */ DWORD cUnmarshaledPotentialProxyOids,
    /* [size_is][in] */ POTENTIAL_PROXY_OID aUnmarshaledPotentialProxyOids[  ]);

error_status_t ClientResolveOXID( 
    /* [in] */ handle_t hServer,
    /* [in] */ PHPROCESS phProcess,
    /* [ref][in] */ OXID *poxidServer,
    /* [unique][in] */ DUALSTRINGARRAY *pssaServerObjectResolverBindings,
    /* [ref][out] */ INTERNAL_OXID_INFO *poxidInfo,
    /* [out] */ MID *pLocalMidOfRemote,
    /* [out] */ DWORD *pulMarshaledTargetInfoLength,
    /* [size_is][size_is][out] */ BYTE **pucMarshaledTargetInfo,
    /* [out] */ WORD *pAuthnSvc);

error_status_t ServerAllocateOXIDAndOIDs( 
    /* [in] */ handle_t hServer,
    /* [in] */ PHPROCESS phProcess,
    /* [ref][out] */ OXID *poxidServer,
    /* [in] */ DWORD fApartment,
    /* [range][in] */ unsigned long cOids,
    /* [length_is][size_is][out] */ OID aOid[  ],
    /* [out] */ DWORD *pcOidsAllocated,
    /* [ref][in] */ INTERNAL_OXID_INFO *poxidInfo,
    /* [unique][in] */ DUALSTRINGARRAY *pdsaStringBindings,
    /* [unique][in] */ DUALSTRINGARRAY *pdsaSecurityBindings,
    /* [out] */ DWORD64 *pdwOrBindingsID,
    /* [out] */ DUALSTRINGARRAY **ppdsaOrBindings);

error_status_t ServerAllocateOIDs( 
    /* [in] */ handle_t hServer,
    /* [in] */ PHPROCESS phProcess,
    /* [ref][in] */ OXID *poxidServer,
    /* [range][in] */ DWORD cOidsReturn,
    /* [size_is][in] */ OID aOidsReturn[  ],
    /* [range][in] */ DWORD cOidsAlloc,
    /* [size_is][out] */ OID aOidsAlloc[  ],
    /* [out] */ DWORD *pcOidsAllocated);

error_status_t ServerFreeOXIDAndOIDs( 
    /* [in] */ handle_t hServer,
    /* [in] */ PHPROCESS phProcess,
    /* [in] */ OXID oxidServer,
    /* [range][in] */ unsigned long cOids,
    /* [size_is][in] */ OID aOids[  ]);

error_status_t SetServerOIDFlags( 
    /* [in] */ handle_t hServer,
    /* [in] */ PHPROCESS phProcess,
    /* [in] */ OID oid,
    /* [in] */ DWORD dwFlags);

error_status_t Disconnect( 
    /* [in] */ handle_t hClient,
    /* [out][in] */ PHPROCESS *pphProcess,
    /* [in] */ BOOL fQueueFastRundownWorkItem);

error_status_t GetUpdatedResolverBindings( 
    /* [in] */ handle_t hRpc,
    /* [in] */ PHPROCESS phProcess,
    /* [out] */ DUALSTRINGARRAY **ppdsaOrBindings,
    /* [out] */ DWORD64 *pdwBindingsID);



extern RPC_IF_HANDLE ILocalObjectExporter_v2_0_c_ifspec;
extern RPC_IF_HANDLE ILocalObjectExporter_v2_0_s_ifspec;
#endif /* __ILocalObjectExporter_INTERFACE_DEFINED__ */

/* Additional Prototypes for ALL interfaces */

void __RPC_USER PHPROCESS_rundown( PHPROCESS );

unsigned long             __RPC_USER  LOCAL_HSTRING_UserSize(     unsigned long *, unsigned long            , LOCAL_HSTRING * ); 
unsigned char * __RPC_USER  LOCAL_HSTRING_UserMarshal(  unsigned long *, unsigned char *, LOCAL_HSTRING * ); 
unsigned char * __RPC_USER  LOCAL_HSTRING_UserUnmarshal(unsigned long *, unsigned char *, LOCAL_HSTRING * ); 
void                      __RPC_USER  LOCAL_HSTRING_UserFree(     unsigned long *, LOCAL_HSTRING * ); 

unsigned long             __RPC_USER  LOCAL_HSTRING_UserSize64(     unsigned long *, unsigned long            , LOCAL_HSTRING * ); 
unsigned char * __RPC_USER  LOCAL_HSTRING_UserMarshal64(  unsigned long *, unsigned char *, LOCAL_HSTRING * ); 
unsigned char * __RPC_USER  LOCAL_HSTRING_UserUnmarshal64(unsigned long *, unsigned char *, LOCAL_HSTRING * ); 
void                      __RPC_USER  LOCAL_HSTRING_UserFree64(     unsigned long *, LOCAL_HSTRING * ); 

/* end of Additional Prototypes */

#ifdef __cplusplus
}
#endif

#endif


