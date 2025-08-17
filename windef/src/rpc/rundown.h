

/* this ALWAYS GENERATED file contains the definitions for the interfaces */


 /* File created by MIDL compiler version 8.01.0628 */
/* at Tue Jan 19 06:14:07 2038
 */
/* Compiler settings for C:/Users/Admin/Desktop/BB_original/BreakingBat/src/rpc/rundown.idl:
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

#ifndef COM_NO_WINDOWS_H
#include "windows.h"
#include "ole2.h"
#endif /*COM_NO_WINDOWS_H*/

#ifndef __rundown_h__
#define __rundown_h__

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

#ifndef __IRemUnknown_FWD_DEFINED__
#define __IRemUnknown_FWD_DEFINED__
typedef interface IRemUnknown IRemUnknown;

#endif 	/* __IRemUnknown_FWD_DEFINED__ */


#ifndef __AsyncIRemUnknown_FWD_DEFINED__
#define __AsyncIRemUnknown_FWD_DEFINED__
typedef interface AsyncIRemUnknown AsyncIRemUnknown;

#endif 	/* __AsyncIRemUnknown_FWD_DEFINED__ */


#ifndef __IRemUnknown2_FWD_DEFINED__
#define __IRemUnknown2_FWD_DEFINED__
typedef interface IRemUnknown2 IRemUnknown2;

#endif 	/* __IRemUnknown2_FWD_DEFINED__ */


#ifndef __AsyncIRemUnknown2_FWD_DEFINED__
#define __AsyncIRemUnknown2_FWD_DEFINED__
typedef interface AsyncIRemUnknown2 AsyncIRemUnknown2;

#endif 	/* __AsyncIRemUnknown2_FWD_DEFINED__ */


#ifndef __IRemUnknownN_FWD_DEFINED__
#define __IRemUnknownN_FWD_DEFINED__
typedef interface IRemUnknownN IRemUnknownN;

#endif 	/* __IRemUnknownN_FWD_DEFINED__ */


#ifndef __AsyncIRemUnknownN_FWD_DEFINED__
#define __AsyncIRemUnknownN_FWD_DEFINED__
typedef interface AsyncIRemUnknownN AsyncIRemUnknownN;

#endif 	/* __AsyncIRemUnknownN_FWD_DEFINED__ */


#ifndef __IRundown_FWD_DEFINED__
#define __IRundown_FWD_DEFINED__
typedef interface IRundown IRundown;

#endif 	/* __IRundown_FWD_DEFINED__ */


#ifndef __AsyncIRundown_FWD_DEFINED__
#define __AsyncIRundown_FWD_DEFINED__
typedef interface AsyncIRundown AsyncIRundown;

#endif 	/* __AsyncIRundown_FWD_DEFINED__ */


/* header files for imported files */
#include "unknwn.h"
#include "lclor.h"

#ifdef __cplusplus
extern "C"{
#endif 


#ifndef __ObjectRpcBaseTypes_INTERFACE_DEFINED__
#define __ObjectRpcBaseTypes_INTERFACE_DEFINED__

/* interface ObjectRpcBaseTypes */


#define	OBJREF_SIGNATURE	( 0x574f454d )

#define	SORF_NULL	( 0 )

#define	OBJREF_STANDARD	( 0x1 )

#define	OBJREF_HANDLER	( 0x2 )

#define	OBJREF_CUSTOM	( 0x4 )

#define	OBJREF_EXTENDED	( 0x8 )

typedef struct tagSTDOBJREF
    {
    DWORD flags;
    DWORD cPublicRefs;
    OXID oxid;
    OID oid;
    IPID ipid;
    } 	STDOBJREF;

typedef struct tagDATAELEMENT
    {
    GUID dataID;
    DWORD cbSize;
    DWORD cbRounded;
    /* [size_is] */ BYTE Data[ 1 ];
    } 	DATAELEMENT;

typedef struct tagOBJREFDATA
    {
    DWORD nElms;
    /* [unique][size_is][size_is] */ DATAELEMENT **ppElmArray;
    } 	OBJREFDATA;

typedef struct tagOBJREF
    {
    DWORD signature;
    DWORD flags;
    GUID iid;
    /* [switch_type][switch_is] */ union 
        {
        /* [case()] */ struct 
            {
            STDOBJREF std;
            DUALSTRINGARRAY saResAddr;
            } 	u_standard;
        /* [case()] */ struct 
            {
            STDOBJREF std;
            CLSID clsid;
            DUALSTRINGARRAY saResAddr;
            } 	u_handler;
        /* [case()] */ struct 
            {
            CLSID clsid;
            DWORD cbExtension;
            DWORD size;
            /* [ref][size_is] */ BYTE *pData;
            } 	u_custom;
        /* [case()] */ struct 
            {
            STDOBJREF std;
            /* [unique] */ OBJREFDATA *pORData;
            DUALSTRINGARRAY saResAddr;
            } 	u_extended;
        } 	u_objref;
    } 	OBJREF;

typedef struct tagMInterfacePointer
    {
    DWORD ulCntData;
    /* [size_is] */ BYTE abData[ 1 ];
    } 	MInterfacePointer;

typedef /* [unique] */ MInterfacePointer *PMInterfacePointer;

typedef /* [disable_consistency_check] */ MInterfacePointer *PMInterfacePointerInternal;



extern RPC_IF_HANDLE ObjectRpcBaseTypes_v0_0_c_ifspec;
extern RPC_IF_HANDLE ObjectRpcBaseTypes_v0_0_s_ifspec;
#endif /* __ObjectRpcBaseTypes_INTERFACE_DEFINED__ */

#ifndef __IRemUnknown_INTERFACE_DEFINED__
#define __IRemUnknown_INTERFACE_DEFINED__

/* interface IRemUnknown */
/* [async_uuid][uuid][object] */ 

#define	MAX_REQUESTED_INTERFACES	( 0x8000 )

typedef struct tagREMQIRESULT
    {
    HRESULT hResult;
    STDOBJREF std;
    } 	REMQIRESULT;

typedef struct tagREMINTERFACEREF
    {
    IPID ipid;
    DWORD cPublicRefs;
    DWORD cPrivateRefs;
    } 	REMINTERFACEREF;

typedef /* [disable_consistency_check] */ REMQIRESULT *PREMQIRESULT;


EXTERN_C const IID IID_IRemUnknown;

#if defined(__cplusplus) && !defined(CINTERFACE)
    
    MIDL_INTERFACE("00000131-0000-0000-C000-000000000046")
    IRemUnknown : public IUnknown
    {
    public:
        virtual HRESULT STDMETHODCALLTYPE RemQueryInterface( 
            /* [in] */ REFIPID ripid,
            /* [in] */ DWORD cRefs,
            /* [range][in] */ WORD cIids,
            /* [size_is][in] */ IID *iids,
            /* [size_is][size_is][out] */ PREMQIRESULT *ppQIResults) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE RemAddRef( 
            /* [in] */ WORD cInterfaceRefs,
            /* [size_is][in] */ REMINTERFACEREF InterfaceRefs[  ],
            /* [size_is][out] */ HRESULT *pResults) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE RemRelease( 
            /* [in] */ WORD cInterfaceRefs,
            /* [size_is][in] */ REMINTERFACEREF InterfaceRefs[  ]) = 0;
        
    };
    
    
#else 	/* C style interface */

    typedef struct IRemUnknownVtbl
    {
        BEGIN_INTERFACE
        
        DECLSPEC_XFGVIRT(IUnknown, QueryInterface)
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            IRemUnknown * This,
            /* [in] */ REFIID riid,
            /* [annotation][iid_is][out] */ 
            _COM_Outptr_  void **ppvObject);
        
        DECLSPEC_XFGVIRT(IUnknown, AddRef)
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            IRemUnknown * This);
        
        DECLSPEC_XFGVIRT(IUnknown, Release)
        ULONG ( STDMETHODCALLTYPE *Release )( 
            IRemUnknown * This);
        
        DECLSPEC_XFGVIRT(IRemUnknown, RemQueryInterface)
        HRESULT ( STDMETHODCALLTYPE *RemQueryInterface )( 
            IRemUnknown * This,
            /* [in] */ REFIPID ripid,
            /* [in] */ DWORD cRefs,
            /* [range][in] */ WORD cIids,
            /* [size_is][in] */ IID *iids,
            /* [size_is][size_is][out] */ PREMQIRESULT *ppQIResults);
        
        DECLSPEC_XFGVIRT(IRemUnknown, RemAddRef)
        HRESULT ( STDMETHODCALLTYPE *RemAddRef )( 
            IRemUnknown * This,
            /* [in] */ WORD cInterfaceRefs,
            /* [size_is][in] */ REMINTERFACEREF InterfaceRefs[  ],
            /* [size_is][out] */ HRESULT *pResults);
        
        DECLSPEC_XFGVIRT(IRemUnknown, RemRelease)
        HRESULT ( STDMETHODCALLTYPE *RemRelease )( 
            IRemUnknown * This,
            /* [in] */ WORD cInterfaceRefs,
            /* [size_is][in] */ REMINTERFACEREF InterfaceRefs[  ]);
        
        END_INTERFACE
    } IRemUnknownVtbl;

    interface IRemUnknown
    {
        CONST_VTBL struct IRemUnknownVtbl *lpVtbl;
    };

    

#ifdef COBJMACROS


#define IRemUnknown_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define IRemUnknown_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define IRemUnknown_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define IRemUnknown_RemQueryInterface(This,ripid,cRefs,cIids,iids,ppQIResults)	\
    ( (This)->lpVtbl -> RemQueryInterface(This,ripid,cRefs,cIids,iids,ppQIResults) ) 

#define IRemUnknown_RemAddRef(This,cInterfaceRefs,InterfaceRefs,pResults)	\
    ( (This)->lpVtbl -> RemAddRef(This,cInterfaceRefs,InterfaceRefs,pResults) ) 

#define IRemUnknown_RemRelease(This,cInterfaceRefs,InterfaceRefs)	\
    ( (This)->lpVtbl -> RemRelease(This,cInterfaceRefs,InterfaceRefs) ) 

#endif /* COBJMACROS */


#endif 	/* C style interface */




#endif 	/* __IRemUnknown_INTERFACE_DEFINED__ */


#ifndef __AsyncIRemUnknown_INTERFACE_DEFINED__
#define __AsyncIRemUnknown_INTERFACE_DEFINED__

/* interface AsyncIRemUnknown */
/* [uuid][object] */ 


EXTERN_C const IID IID_AsyncIRemUnknown;

#if defined(__cplusplus) && !defined(CINTERFACE)
    
    MIDL_INTERFACE("000e0131-0000-0000-C000-000000000046")
    AsyncIRemUnknown : public IUnknown
    {
    public:
        virtual HRESULT STDMETHODCALLTYPE Begin_RemQueryInterface( 
            /* [in] */ REFIPID ripid,
            /* [in] */ DWORD cRefs,
            /* [range][in] */ WORD cIids,
            /* [size_is][in] */ IID *iids) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE Finish_RemQueryInterface( 
            /* [size_is][size_is][out] */ PREMQIRESULT *ppQIResults) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE Begin_RemAddRef( 
            /* [in] */ WORD cInterfaceRefs,
            /* [size_is][in] */ REMINTERFACEREF InterfaceRefs[  ]) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE Finish_RemAddRef( 
            /* [size_is][out] */ HRESULT *pResults) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE Begin_RemRelease( 
            /* [in] */ WORD cInterfaceRefs,
            /* [size_is][in] */ REMINTERFACEREF InterfaceRefs[  ]) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE Finish_RemRelease( void) = 0;
        
    };
    
    
#else 	/* C style interface */

    typedef struct AsyncIRemUnknownVtbl
    {
        BEGIN_INTERFACE
        
        DECLSPEC_XFGVIRT(IUnknown, QueryInterface)
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            AsyncIRemUnknown * This,
            /* [in] */ REFIID riid,
            /* [annotation][iid_is][out] */ 
            _COM_Outptr_  void **ppvObject);
        
        DECLSPEC_XFGVIRT(IUnknown, AddRef)
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            AsyncIRemUnknown * This);
        
        DECLSPEC_XFGVIRT(IUnknown, Release)
        ULONG ( STDMETHODCALLTYPE *Release )( 
            AsyncIRemUnknown * This);
        
        DECLSPEC_XFGVIRT(AsyncIRemUnknown, Begin_RemQueryInterface)
        HRESULT ( STDMETHODCALLTYPE *Begin_RemQueryInterface )( 
            AsyncIRemUnknown * This,
            /* [in] */ REFIPID ripid,
            /* [in] */ DWORD cRefs,
            /* [range][in] */ WORD cIids,
            /* [size_is][in] */ IID *iids);
        
        DECLSPEC_XFGVIRT(AsyncIRemUnknown, Finish_RemQueryInterface)
        HRESULT ( STDMETHODCALLTYPE *Finish_RemQueryInterface )( 
            AsyncIRemUnknown * This,
            /* [size_is][size_is][out] */ PREMQIRESULT *ppQIResults);
        
        DECLSPEC_XFGVIRT(AsyncIRemUnknown, Begin_RemAddRef)
        HRESULT ( STDMETHODCALLTYPE *Begin_RemAddRef )( 
            AsyncIRemUnknown * This,
            /* [in] */ WORD cInterfaceRefs,
            /* [size_is][in] */ REMINTERFACEREF InterfaceRefs[  ]);
        
        DECLSPEC_XFGVIRT(AsyncIRemUnknown, Finish_RemAddRef)
        HRESULT ( STDMETHODCALLTYPE *Finish_RemAddRef )( 
            AsyncIRemUnknown * This,
            /* [size_is][out] */ HRESULT *pResults);
        
        DECLSPEC_XFGVIRT(AsyncIRemUnknown, Begin_RemRelease)
        HRESULT ( STDMETHODCALLTYPE *Begin_RemRelease )( 
            AsyncIRemUnknown * This,
            /* [in] */ WORD cInterfaceRefs,
            /* [size_is][in] */ REMINTERFACEREF InterfaceRefs[  ]);
        
        DECLSPEC_XFGVIRT(AsyncIRemUnknown, Finish_RemRelease)
        HRESULT ( STDMETHODCALLTYPE *Finish_RemRelease )( 
            AsyncIRemUnknown * This);
        
        END_INTERFACE
    } AsyncIRemUnknownVtbl;

    interface AsyncIRemUnknown
    {
        CONST_VTBL struct AsyncIRemUnknownVtbl *lpVtbl;
    };

    

#ifdef COBJMACROS


#define AsyncIRemUnknown_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define AsyncIRemUnknown_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define AsyncIRemUnknown_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define AsyncIRemUnknown_Begin_RemQueryInterface(This,ripid,cRefs,cIids,iids)	\
    ( (This)->lpVtbl -> Begin_RemQueryInterface(This,ripid,cRefs,cIids,iids) ) 

#define AsyncIRemUnknown_Finish_RemQueryInterface(This,ppQIResults)	\
    ( (This)->lpVtbl -> Finish_RemQueryInterface(This,ppQIResults) ) 

#define AsyncIRemUnknown_Begin_RemAddRef(This,cInterfaceRefs,InterfaceRefs)	\
    ( (This)->lpVtbl -> Begin_RemAddRef(This,cInterfaceRefs,InterfaceRefs) ) 

#define AsyncIRemUnknown_Finish_RemAddRef(This,pResults)	\
    ( (This)->lpVtbl -> Finish_RemAddRef(This,pResults) ) 

#define AsyncIRemUnknown_Begin_RemRelease(This,cInterfaceRefs,InterfaceRefs)	\
    ( (This)->lpVtbl -> Begin_RemRelease(This,cInterfaceRefs,InterfaceRefs) ) 

#define AsyncIRemUnknown_Finish_RemRelease(This)	\
    ( (This)->lpVtbl -> Finish_RemRelease(This) ) 

#endif /* COBJMACROS */


#endif 	/* C style interface */




#endif 	/* __AsyncIRemUnknown_INTERFACE_DEFINED__ */


#ifndef __IRemUnknown2_INTERFACE_DEFINED__
#define __IRemUnknown2_INTERFACE_DEFINED__

/* interface IRemUnknown2 */
/* [async_uuid][uuid][object] */ 


EXTERN_C const IID IID_IRemUnknown2;

#if defined(__cplusplus) && !defined(CINTERFACE)
    
    MIDL_INTERFACE("00000143-0000-0000-C000-000000000046")
    IRemUnknown2 : public IRemUnknown
    {
    public:
        virtual HRESULT STDMETHODCALLTYPE RemQueryInterface2( 
            /* [in] */ REFIPID ripid,
            /* [range][in] */ WORD cIids,
            /* [size_is][in] */ IID *iids,
            /* [size_is][out] */ HRESULT *phr,
            /* [size_is][out] */ PMInterfacePointerInternal *ppMIF) = 0;
        
    };
    
    
#else 	/* C style interface */

    typedef struct IRemUnknown2Vtbl
    {
        BEGIN_INTERFACE
        
        DECLSPEC_XFGVIRT(IUnknown, QueryInterface)
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            IRemUnknown2 * This,
            /* [in] */ REFIID riid,
            /* [annotation][iid_is][out] */ 
            _COM_Outptr_  void **ppvObject);
        
        DECLSPEC_XFGVIRT(IUnknown, AddRef)
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            IRemUnknown2 * This);
        
        DECLSPEC_XFGVIRT(IUnknown, Release)
        ULONG ( STDMETHODCALLTYPE *Release )( 
            IRemUnknown2 * This);
        
        DECLSPEC_XFGVIRT(IRemUnknown, RemQueryInterface)
        HRESULT ( STDMETHODCALLTYPE *RemQueryInterface )( 
            IRemUnknown2 * This,
            /* [in] */ REFIPID ripid,
            /* [in] */ DWORD cRefs,
            /* [range][in] */ WORD cIids,
            /* [size_is][in] */ IID *iids,
            /* [size_is][size_is][out] */ PREMQIRESULT *ppQIResults);
        
        DECLSPEC_XFGVIRT(IRemUnknown, RemAddRef)
        HRESULT ( STDMETHODCALLTYPE *RemAddRef )( 
            IRemUnknown2 * This,
            /* [in] */ WORD cInterfaceRefs,
            /* [size_is][in] */ REMINTERFACEREF InterfaceRefs[  ],
            /* [size_is][out] */ HRESULT *pResults);
        
        DECLSPEC_XFGVIRT(IRemUnknown, RemRelease)
        HRESULT ( STDMETHODCALLTYPE *RemRelease )( 
            IRemUnknown2 * This,
            /* [in] */ WORD cInterfaceRefs,
            /* [size_is][in] */ REMINTERFACEREF InterfaceRefs[  ]);
        
        DECLSPEC_XFGVIRT(IRemUnknown2, RemQueryInterface2)
        HRESULT ( STDMETHODCALLTYPE *RemQueryInterface2 )( 
            IRemUnknown2 * This,
            /* [in] */ REFIPID ripid,
            /* [range][in] */ WORD cIids,
            /* [size_is][in] */ IID *iids,
            /* [size_is][out] */ HRESULT *phr,
            /* [size_is][out] */ PMInterfacePointerInternal *ppMIF);
        
        END_INTERFACE
    } IRemUnknown2Vtbl;

    interface IRemUnknown2
    {
        CONST_VTBL struct IRemUnknown2Vtbl *lpVtbl;
    };

    

#ifdef COBJMACROS


#define IRemUnknown2_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define IRemUnknown2_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define IRemUnknown2_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define IRemUnknown2_RemQueryInterface(This,ripid,cRefs,cIids,iids,ppQIResults)	\
    ( (This)->lpVtbl -> RemQueryInterface(This,ripid,cRefs,cIids,iids,ppQIResults) ) 

#define IRemUnknown2_RemAddRef(This,cInterfaceRefs,InterfaceRefs,pResults)	\
    ( (This)->lpVtbl -> RemAddRef(This,cInterfaceRefs,InterfaceRefs,pResults) ) 

#define IRemUnknown2_RemRelease(This,cInterfaceRefs,InterfaceRefs)	\
    ( (This)->lpVtbl -> RemRelease(This,cInterfaceRefs,InterfaceRefs) ) 


#define IRemUnknown2_RemQueryInterface2(This,ripid,cIids,iids,phr,ppMIF)	\
    ( (This)->lpVtbl -> RemQueryInterface2(This,ripid,cIids,iids,phr,ppMIF) ) 

#endif /* COBJMACROS */


#endif 	/* C style interface */




#endif 	/* __IRemUnknown2_INTERFACE_DEFINED__ */


#ifndef __AsyncIRemUnknown2_INTERFACE_DEFINED__
#define __AsyncIRemUnknown2_INTERFACE_DEFINED__

/* interface AsyncIRemUnknown2 */
/* [uuid][object] */ 


EXTERN_C const IID IID_AsyncIRemUnknown2;

#if defined(__cplusplus) && !defined(CINTERFACE)
    
    MIDL_INTERFACE("000e0143-0000-0000-C000-000000000046")
    AsyncIRemUnknown2 : public AsyncIRemUnknown
    {
    public:
        virtual HRESULT STDMETHODCALLTYPE Begin_RemQueryInterface2( 
            /* [in] */ REFIPID ripid,
            /* [range][in] */ WORD cIids,
            /* [size_is][in] */ IID *iids) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE Finish_RemQueryInterface2( 
            /* [size_is][out] */ HRESULT *phr,
            /* [size_is][out] */ PMInterfacePointerInternal *ppMIF) = 0;
        
    };
    
    
#else 	/* C style interface */

    typedef struct AsyncIRemUnknown2Vtbl
    {
        BEGIN_INTERFACE
        
        DECLSPEC_XFGVIRT(IUnknown, QueryInterface)
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            AsyncIRemUnknown2 * This,
            /* [in] */ REFIID riid,
            /* [annotation][iid_is][out] */ 
            _COM_Outptr_  void **ppvObject);
        
        DECLSPEC_XFGVIRT(IUnknown, AddRef)
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            AsyncIRemUnknown2 * This);
        
        DECLSPEC_XFGVIRT(IUnknown, Release)
        ULONG ( STDMETHODCALLTYPE *Release )( 
            AsyncIRemUnknown2 * This);
        
        DECLSPEC_XFGVIRT(AsyncIRemUnknown, Begin_RemQueryInterface)
        HRESULT ( STDMETHODCALLTYPE *Begin_RemQueryInterface )( 
            AsyncIRemUnknown2 * This,
            /* [in] */ REFIPID ripid,
            /* [in] */ DWORD cRefs,
            /* [range][in] */ WORD cIids,
            /* [size_is][in] */ IID *iids);
        
        DECLSPEC_XFGVIRT(AsyncIRemUnknown, Finish_RemQueryInterface)
        HRESULT ( STDMETHODCALLTYPE *Finish_RemQueryInterface )( 
            AsyncIRemUnknown2 * This,
            /* [size_is][size_is][out] */ PREMQIRESULT *ppQIResults);
        
        DECLSPEC_XFGVIRT(AsyncIRemUnknown, Begin_RemAddRef)
        HRESULT ( STDMETHODCALLTYPE *Begin_RemAddRef )( 
            AsyncIRemUnknown2 * This,
            /* [in] */ WORD cInterfaceRefs,
            /* [size_is][in] */ REMINTERFACEREF InterfaceRefs[  ]);
        
        DECLSPEC_XFGVIRT(AsyncIRemUnknown, Finish_RemAddRef)
        HRESULT ( STDMETHODCALLTYPE *Finish_RemAddRef )( 
            AsyncIRemUnknown2 * This,
            /* [size_is][out] */ HRESULT *pResults);
        
        DECLSPEC_XFGVIRT(AsyncIRemUnknown, Begin_RemRelease)
        HRESULT ( STDMETHODCALLTYPE *Begin_RemRelease )( 
            AsyncIRemUnknown2 * This,
            /* [in] */ WORD cInterfaceRefs,
            /* [size_is][in] */ REMINTERFACEREF InterfaceRefs[  ]);
        
        DECLSPEC_XFGVIRT(AsyncIRemUnknown, Finish_RemRelease)
        HRESULT ( STDMETHODCALLTYPE *Finish_RemRelease )( 
            AsyncIRemUnknown2 * This);
        
        DECLSPEC_XFGVIRT(AsyncIRemUnknown2, Begin_RemQueryInterface2)
        HRESULT ( STDMETHODCALLTYPE *Begin_RemQueryInterface2 )( 
            AsyncIRemUnknown2 * This,
            /* [in] */ REFIPID ripid,
            /* [range][in] */ WORD cIids,
            /* [size_is][in] */ IID *iids);
        
        DECLSPEC_XFGVIRT(AsyncIRemUnknown2, Finish_RemQueryInterface2)
        HRESULT ( STDMETHODCALLTYPE *Finish_RemQueryInterface2 )( 
            AsyncIRemUnknown2 * This,
            /* [size_is][out] */ HRESULT *phr,
            /* [size_is][out] */ PMInterfacePointerInternal *ppMIF);
        
        END_INTERFACE
    } AsyncIRemUnknown2Vtbl;

    interface AsyncIRemUnknown2
    {
        CONST_VTBL struct AsyncIRemUnknown2Vtbl *lpVtbl;
    };

    

#ifdef COBJMACROS


#define AsyncIRemUnknown2_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define AsyncIRemUnknown2_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define AsyncIRemUnknown2_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define AsyncIRemUnknown2_Begin_RemQueryInterface(This,ripid,cRefs,cIids,iids)	\
    ( (This)->lpVtbl -> Begin_RemQueryInterface(This,ripid,cRefs,cIids,iids) ) 

#define AsyncIRemUnknown2_Finish_RemQueryInterface(This,ppQIResults)	\
    ( (This)->lpVtbl -> Finish_RemQueryInterface(This,ppQIResults) ) 

#define AsyncIRemUnknown2_Begin_RemAddRef(This,cInterfaceRefs,InterfaceRefs)	\
    ( (This)->lpVtbl -> Begin_RemAddRef(This,cInterfaceRefs,InterfaceRefs) ) 

#define AsyncIRemUnknown2_Finish_RemAddRef(This,pResults)	\
    ( (This)->lpVtbl -> Finish_RemAddRef(This,pResults) ) 

#define AsyncIRemUnknown2_Begin_RemRelease(This,cInterfaceRefs,InterfaceRefs)	\
    ( (This)->lpVtbl -> Begin_RemRelease(This,cInterfaceRefs,InterfaceRefs) ) 

#define AsyncIRemUnknown2_Finish_RemRelease(This)	\
    ( (This)->lpVtbl -> Finish_RemRelease(This) ) 


#define AsyncIRemUnknown2_Begin_RemQueryInterface2(This,ripid,cIids,iids)	\
    ( (This)->lpVtbl -> Begin_RemQueryInterface2(This,ripid,cIids,iids) ) 

#define AsyncIRemUnknown2_Finish_RemQueryInterface2(This,phr,ppMIF)	\
    ( (This)->lpVtbl -> Finish_RemQueryInterface2(This,phr,ppMIF) ) 

#endif /* COBJMACROS */


#endif 	/* C style interface */




#endif 	/* __AsyncIRemUnknown2_INTERFACE_DEFINED__ */


#ifndef __IRemUnknownN_INTERFACE_DEFINED__
#define __IRemUnknownN_INTERFACE_DEFINED__

/* interface IRemUnknownN */
/* [async_uuid][uuid][object] */ 

#define	IRUF_CONVERTTOWEAK	( 0x1 )

#define	IRUF_CONVERTTOSTRONG	( 0x2 )

#define	IRUF_DISCONNECTIFLASTSTRONG	( 0x4 )

typedef struct tagXAptCallback
    {
    DWORD64 pfnCallback;
    DWORD64 pParam;
    DWORD64 pServerCtx;
    DWORD64 pUnk;
    GUID iid;
    INT iMethod;
    GUID guidProcessSecret;
    } 	XAptCallback;


EXTERN_C const IID IID_IRemUnknownN;

#if defined(__cplusplus) && !defined(CINTERFACE)
    
    MIDL_INTERFACE("0000013C-0000-0000-C000-000000000046")
    IRemUnknownN : public IRemUnknown2
    {
    public:
        virtual HRESULT STDMETHODCALLTYPE AcknowledgeMarshalingSets( 
            /* [in] */ WORD cMarshalingSets,
            /* [size_is][in] */ DWORD64 *pMarshalingSets) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE RemChangeRef( 
            /* [in] */ DWORD flags,
            /* [in] */ WORD cInterfaceRefs,
            /* [size_is][in] */ REMINTERFACEREF InterfaceRefs[  ]) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE DoCallback( 
            /* [in] */ XAptCallback *pCallbackData) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE DoNonreentrantCallback( 
            /* [in] */ XAptCallback *pCallbackData) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetInterfaceNameFromIPID( 
            /* [in] */ REFIPID ripid,
            /* [out] */ HSTRING *interfaceName) = 0;
        
    };
    
    
#else 	/* C style interface */

    typedef struct IRemUnknownNVtbl
    {
        BEGIN_INTERFACE
        
        DECLSPEC_XFGVIRT(IUnknown, QueryInterface)
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            IRemUnknownN * This,
            /* [in] */ REFIID riid,
            /* [annotation][iid_is][out] */ 
            _COM_Outptr_  void **ppvObject);
        
        DECLSPEC_XFGVIRT(IUnknown, AddRef)
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            IRemUnknownN * This);
        
        DECLSPEC_XFGVIRT(IUnknown, Release)
        ULONG ( STDMETHODCALLTYPE *Release )( 
            IRemUnknownN * This);
        
        DECLSPEC_XFGVIRT(IRemUnknown, RemQueryInterface)
        HRESULT ( STDMETHODCALLTYPE *RemQueryInterface )( 
            IRemUnknownN * This,
            /* [in] */ REFIPID ripid,
            /* [in] */ DWORD cRefs,
            /* [range][in] */ WORD cIids,
            /* [size_is][in] */ IID *iids,
            /* [size_is][size_is][out] */ PREMQIRESULT *ppQIResults);
        
        DECLSPEC_XFGVIRT(IRemUnknown, RemAddRef)
        HRESULT ( STDMETHODCALLTYPE *RemAddRef )( 
            IRemUnknownN * This,
            /* [in] */ WORD cInterfaceRefs,
            /* [size_is][in] */ REMINTERFACEREF InterfaceRefs[  ],
            /* [size_is][out] */ HRESULT *pResults);
        
        DECLSPEC_XFGVIRT(IRemUnknown, RemRelease)
        HRESULT ( STDMETHODCALLTYPE *RemRelease )( 
            IRemUnknownN * This,
            /* [in] */ WORD cInterfaceRefs,
            /* [size_is][in] */ REMINTERFACEREF InterfaceRefs[  ]);
        
        DECLSPEC_XFGVIRT(IRemUnknown2, RemQueryInterface2)
        HRESULT ( STDMETHODCALLTYPE *RemQueryInterface2 )( 
            IRemUnknownN * This,
            /* [in] */ REFIPID ripid,
            /* [range][in] */ WORD cIids,
            /* [size_is][in] */ IID *iids,
            /* [size_is][out] */ HRESULT *phr,
            /* [size_is][out] */ PMInterfacePointerInternal *ppMIF);
        
        DECLSPEC_XFGVIRT(IRemUnknownN, AcknowledgeMarshalingSets)
        HRESULT ( STDMETHODCALLTYPE *AcknowledgeMarshalingSets )( 
            IRemUnknownN * This,
            /* [in] */ WORD cMarshalingSets,
            /* [size_is][in] */ DWORD64 *pMarshalingSets);
        
        DECLSPEC_XFGVIRT(IRemUnknownN, RemChangeRef)
        HRESULT ( STDMETHODCALLTYPE *RemChangeRef )( 
            IRemUnknownN * This,
            /* [in] */ DWORD flags,
            /* [in] */ WORD cInterfaceRefs,
            /* [size_is][in] */ REMINTERFACEREF InterfaceRefs[  ]);
        
        DECLSPEC_XFGVIRT(IRemUnknownN, DoCallback)
        HRESULT ( STDMETHODCALLTYPE *DoCallback )( 
            IRemUnknownN * This,
            /* [in] */ XAptCallback *pCallbackData);
        
        DECLSPEC_XFGVIRT(IRemUnknownN, DoNonreentrantCallback)
        HRESULT ( STDMETHODCALLTYPE *DoNonreentrantCallback )( 
            IRemUnknownN * This,
            /* [in] */ XAptCallback *pCallbackData);
        
        DECLSPEC_XFGVIRT(IRemUnknownN, GetInterfaceNameFromIPID)
        HRESULT ( STDMETHODCALLTYPE *GetInterfaceNameFromIPID )( 
            IRemUnknownN * This,
            /* [in] */ REFIPID ripid,
            /* [out] */ HSTRING *interfaceName);
        
        END_INTERFACE
    } IRemUnknownNVtbl;

    interface IRemUnknownN
    {
        CONST_VTBL struct IRemUnknownNVtbl *lpVtbl;
    };

    

#ifdef COBJMACROS


#define IRemUnknownN_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define IRemUnknownN_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define IRemUnknownN_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define IRemUnknownN_RemQueryInterface(This,ripid,cRefs,cIids,iids,ppQIResults)	\
    ( (This)->lpVtbl -> RemQueryInterface(This,ripid,cRefs,cIids,iids,ppQIResults) ) 

#define IRemUnknownN_RemAddRef(This,cInterfaceRefs,InterfaceRefs,pResults)	\
    ( (This)->lpVtbl -> RemAddRef(This,cInterfaceRefs,InterfaceRefs,pResults) ) 

#define IRemUnknownN_RemRelease(This,cInterfaceRefs,InterfaceRefs)	\
    ( (This)->lpVtbl -> RemRelease(This,cInterfaceRefs,InterfaceRefs) ) 


#define IRemUnknownN_RemQueryInterface2(This,ripid,cIids,iids,phr,ppMIF)	\
    ( (This)->lpVtbl -> RemQueryInterface2(This,ripid,cIids,iids,phr,ppMIF) ) 


#define IRemUnknownN_AcknowledgeMarshalingSets(This,cMarshalingSets,pMarshalingSets)	\
    ( (This)->lpVtbl -> AcknowledgeMarshalingSets(This,cMarshalingSets,pMarshalingSets) ) 

#define IRemUnknownN_RemChangeRef(This,flags,cInterfaceRefs,InterfaceRefs)	\
    ( (This)->lpVtbl -> RemChangeRef(This,flags,cInterfaceRefs,InterfaceRefs) ) 

#define IRemUnknownN_DoCallback(This,pCallbackData)	\
    ( (This)->lpVtbl -> DoCallback(This,pCallbackData) ) 

#define IRemUnknownN_DoNonreentrantCallback(This,pCallbackData)	\
    ( (This)->lpVtbl -> DoNonreentrantCallback(This,pCallbackData) ) 

#define IRemUnknownN_GetInterfaceNameFromIPID(This,ripid,interfaceName)	\
    ( (This)->lpVtbl -> GetInterfaceNameFromIPID(This,ripid,interfaceName) ) 

#endif /* COBJMACROS */


#endif 	/* C style interface */




#endif 	/* __IRemUnknownN_INTERFACE_DEFINED__ */


#ifndef __AsyncIRemUnknownN_INTERFACE_DEFINED__
#define __AsyncIRemUnknownN_INTERFACE_DEFINED__

/* interface AsyncIRemUnknownN */
/* [uuid][object] */ 


EXTERN_C const IID IID_AsyncIRemUnknownN;

#if defined(__cplusplus) && !defined(CINTERFACE)
    
    MIDL_INTERFACE("000B013C-0000-0000-C000-000000000046")
    AsyncIRemUnknownN : public AsyncIRemUnknown2
    {
    public:
        virtual HRESULT STDMETHODCALLTYPE Begin_AcknowledgeMarshalingSets( 
            /* [in] */ WORD cMarshalingSets,
            /* [size_is][in] */ DWORD64 *pMarshalingSets) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE Finish_AcknowledgeMarshalingSets( void) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE Begin_RemChangeRef( 
            /* [in] */ DWORD flags,
            /* [in] */ WORD cInterfaceRefs,
            /* [size_is][in] */ REMINTERFACEREF InterfaceRefs[  ]) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE Finish_RemChangeRef( void) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE Begin_DoCallback( 
            /* [in] */ XAptCallback *pCallbackData) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE Finish_DoCallback( void) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE Begin_DoNonreentrantCallback( 
            /* [in] */ XAptCallback *pCallbackData) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE Finish_DoNonreentrantCallback( void) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE Begin_GetInterfaceNameFromIPID( 
            /* [in] */ REFIPID ripid) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE Finish_GetInterfaceNameFromIPID( 
            /* [out] */ HSTRING *interfaceName) = 0;
        
    };
    
    
#else 	/* C style interface */

    typedef struct AsyncIRemUnknownNVtbl
    {
        BEGIN_INTERFACE
        
        DECLSPEC_XFGVIRT(IUnknown, QueryInterface)
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            AsyncIRemUnknownN * This,
            /* [in] */ REFIID riid,
            /* [annotation][iid_is][out] */ 
            _COM_Outptr_  void **ppvObject);
        
        DECLSPEC_XFGVIRT(IUnknown, AddRef)
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            AsyncIRemUnknownN * This);
        
        DECLSPEC_XFGVIRT(IUnknown, Release)
        ULONG ( STDMETHODCALLTYPE *Release )( 
            AsyncIRemUnknownN * This);
        
        DECLSPEC_XFGVIRT(AsyncIRemUnknown, Begin_RemQueryInterface)
        HRESULT ( STDMETHODCALLTYPE *Begin_RemQueryInterface )( 
            AsyncIRemUnknownN * This,
            /* [in] */ REFIPID ripid,
            /* [in] */ DWORD cRefs,
            /* [range][in] */ WORD cIids,
            /* [size_is][in] */ IID *iids);
        
        DECLSPEC_XFGVIRT(AsyncIRemUnknown, Finish_RemQueryInterface)
        HRESULT ( STDMETHODCALLTYPE *Finish_RemQueryInterface )( 
            AsyncIRemUnknownN * This,
            /* [size_is][size_is][out] */ PREMQIRESULT *ppQIResults);
        
        DECLSPEC_XFGVIRT(AsyncIRemUnknown, Begin_RemAddRef)
        HRESULT ( STDMETHODCALLTYPE *Begin_RemAddRef )( 
            AsyncIRemUnknownN * This,
            /* [in] */ WORD cInterfaceRefs,
            /* [size_is][in] */ REMINTERFACEREF InterfaceRefs[  ]);
        
        DECLSPEC_XFGVIRT(AsyncIRemUnknown, Finish_RemAddRef)
        HRESULT ( STDMETHODCALLTYPE *Finish_RemAddRef )( 
            AsyncIRemUnknownN * This,
            /* [size_is][out] */ HRESULT *pResults);
        
        DECLSPEC_XFGVIRT(AsyncIRemUnknown, Begin_RemRelease)
        HRESULT ( STDMETHODCALLTYPE *Begin_RemRelease )( 
            AsyncIRemUnknownN * This,
            /* [in] */ WORD cInterfaceRefs,
            /* [size_is][in] */ REMINTERFACEREF InterfaceRefs[  ]);
        
        DECLSPEC_XFGVIRT(AsyncIRemUnknown, Finish_RemRelease)
        HRESULT ( STDMETHODCALLTYPE *Finish_RemRelease )( 
            AsyncIRemUnknownN * This);
        
        DECLSPEC_XFGVIRT(AsyncIRemUnknown2, Begin_RemQueryInterface2)
        HRESULT ( STDMETHODCALLTYPE *Begin_RemQueryInterface2 )( 
            AsyncIRemUnknownN * This,
            /* [in] */ REFIPID ripid,
            /* [range][in] */ WORD cIids,
            /* [size_is][in] */ IID *iids);
        
        DECLSPEC_XFGVIRT(AsyncIRemUnknown2, Finish_RemQueryInterface2)
        HRESULT ( STDMETHODCALLTYPE *Finish_RemQueryInterface2 )( 
            AsyncIRemUnknownN * This,
            /* [size_is][out] */ HRESULT *phr,
            /* [size_is][out] */ PMInterfacePointerInternal *ppMIF);
        
        DECLSPEC_XFGVIRT(AsyncIRemUnknownN, Begin_AcknowledgeMarshalingSets)
        HRESULT ( STDMETHODCALLTYPE *Begin_AcknowledgeMarshalingSets )( 
            AsyncIRemUnknownN * This,
            /* [in] */ WORD cMarshalingSets,
            /* [size_is][in] */ DWORD64 *pMarshalingSets);
        
        DECLSPEC_XFGVIRT(AsyncIRemUnknownN, Finish_AcknowledgeMarshalingSets)
        HRESULT ( STDMETHODCALLTYPE *Finish_AcknowledgeMarshalingSets )( 
            AsyncIRemUnknownN * This);
        
        DECLSPEC_XFGVIRT(AsyncIRemUnknownN, Begin_RemChangeRef)
        HRESULT ( STDMETHODCALLTYPE *Begin_RemChangeRef )( 
            AsyncIRemUnknownN * This,
            /* [in] */ DWORD flags,
            /* [in] */ WORD cInterfaceRefs,
            /* [size_is][in] */ REMINTERFACEREF InterfaceRefs[  ]);
        
        DECLSPEC_XFGVIRT(AsyncIRemUnknownN, Finish_RemChangeRef)
        HRESULT ( STDMETHODCALLTYPE *Finish_RemChangeRef )( 
            AsyncIRemUnknownN * This);
        
        DECLSPEC_XFGVIRT(AsyncIRemUnknownN, Begin_DoCallback)
        HRESULT ( STDMETHODCALLTYPE *Begin_DoCallback )( 
            AsyncIRemUnknownN * This,
            /* [in] */ XAptCallback *pCallbackData);
        
        DECLSPEC_XFGVIRT(AsyncIRemUnknownN, Finish_DoCallback)
        HRESULT ( STDMETHODCALLTYPE *Finish_DoCallback )( 
            AsyncIRemUnknownN * This);
        
        DECLSPEC_XFGVIRT(AsyncIRemUnknownN, Begin_DoNonreentrantCallback)
        HRESULT ( STDMETHODCALLTYPE *Begin_DoNonreentrantCallback )( 
            AsyncIRemUnknownN * This,
            /* [in] */ XAptCallback *pCallbackData);
        
        DECLSPEC_XFGVIRT(AsyncIRemUnknownN, Finish_DoNonreentrantCallback)
        HRESULT ( STDMETHODCALLTYPE *Finish_DoNonreentrantCallback )( 
            AsyncIRemUnknownN * This);
        
        DECLSPEC_XFGVIRT(AsyncIRemUnknownN, Begin_GetInterfaceNameFromIPID)
        HRESULT ( STDMETHODCALLTYPE *Begin_GetInterfaceNameFromIPID )( 
            AsyncIRemUnknownN * This,
            /* [in] */ REFIPID ripid);
        
        DECLSPEC_XFGVIRT(AsyncIRemUnknownN, Finish_GetInterfaceNameFromIPID)
        HRESULT ( STDMETHODCALLTYPE *Finish_GetInterfaceNameFromIPID )( 
            AsyncIRemUnknownN * This,
            /* [out] */ HSTRING *interfaceName);
        
        END_INTERFACE
    } AsyncIRemUnknownNVtbl;

    interface AsyncIRemUnknownN
    {
        CONST_VTBL struct AsyncIRemUnknownNVtbl *lpVtbl;
    };

    

#ifdef COBJMACROS


#define AsyncIRemUnknownN_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define AsyncIRemUnknownN_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define AsyncIRemUnknownN_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define AsyncIRemUnknownN_Begin_RemQueryInterface(This,ripid,cRefs,cIids,iids)	\
    ( (This)->lpVtbl -> Begin_RemQueryInterface(This,ripid,cRefs,cIids,iids) ) 

#define AsyncIRemUnknownN_Finish_RemQueryInterface(This,ppQIResults)	\
    ( (This)->lpVtbl -> Finish_RemQueryInterface(This,ppQIResults) ) 

#define AsyncIRemUnknownN_Begin_RemAddRef(This,cInterfaceRefs,InterfaceRefs)	\
    ( (This)->lpVtbl -> Begin_RemAddRef(This,cInterfaceRefs,InterfaceRefs) ) 

#define AsyncIRemUnknownN_Finish_RemAddRef(This,pResults)	\
    ( (This)->lpVtbl -> Finish_RemAddRef(This,pResults) ) 

#define AsyncIRemUnknownN_Begin_RemRelease(This,cInterfaceRefs,InterfaceRefs)	\
    ( (This)->lpVtbl -> Begin_RemRelease(This,cInterfaceRefs,InterfaceRefs) ) 

#define AsyncIRemUnknownN_Finish_RemRelease(This)	\
    ( (This)->lpVtbl -> Finish_RemRelease(This) ) 


#define AsyncIRemUnknownN_Begin_RemQueryInterface2(This,ripid,cIids,iids)	\
    ( (This)->lpVtbl -> Begin_RemQueryInterface2(This,ripid,cIids,iids) ) 

#define AsyncIRemUnknownN_Finish_RemQueryInterface2(This,phr,ppMIF)	\
    ( (This)->lpVtbl -> Finish_RemQueryInterface2(This,phr,ppMIF) ) 


#define AsyncIRemUnknownN_Begin_AcknowledgeMarshalingSets(This,cMarshalingSets,pMarshalingSets)	\
    ( (This)->lpVtbl -> Begin_AcknowledgeMarshalingSets(This,cMarshalingSets,pMarshalingSets) ) 

#define AsyncIRemUnknownN_Finish_AcknowledgeMarshalingSets(This)	\
    ( (This)->lpVtbl -> Finish_AcknowledgeMarshalingSets(This) ) 

#define AsyncIRemUnknownN_Begin_RemChangeRef(This,flags,cInterfaceRefs,InterfaceRefs)	\
    ( (This)->lpVtbl -> Begin_RemChangeRef(This,flags,cInterfaceRefs,InterfaceRefs) ) 

#define AsyncIRemUnknownN_Finish_RemChangeRef(This)	\
    ( (This)->lpVtbl -> Finish_RemChangeRef(This) ) 

#define AsyncIRemUnknownN_Begin_DoCallback(This,pCallbackData)	\
    ( (This)->lpVtbl -> Begin_DoCallback(This,pCallbackData) ) 

#define AsyncIRemUnknownN_Finish_DoCallback(This)	\
    ( (This)->lpVtbl -> Finish_DoCallback(This) ) 

#define AsyncIRemUnknownN_Begin_DoNonreentrantCallback(This,pCallbackData)	\
    ( (This)->lpVtbl -> Begin_DoNonreentrantCallback(This,pCallbackData) ) 

#define AsyncIRemUnknownN_Finish_DoNonreentrantCallback(This)	\
    ( (This)->lpVtbl -> Finish_DoNonreentrantCallback(This) ) 

#define AsyncIRemUnknownN_Begin_GetInterfaceNameFromIPID(This,ripid)	\
    ( (This)->lpVtbl -> Begin_GetInterfaceNameFromIPID(This,ripid) ) 

#define AsyncIRemUnknownN_Finish_GetInterfaceNameFromIPID(This,interfaceName)	\
    ( (This)->lpVtbl -> Finish_GetInterfaceNameFromIPID(This,interfaceName) ) 

#endif /* COBJMACROS */


#endif 	/* C style interface */




#endif 	/* __AsyncIRemUnknownN_INTERFACE_DEFINED__ */


#ifndef __IRundown_INTERFACE_DEFINED__
#define __IRundown_INTERFACE_DEFINED__

/* interface IRundown */
/* [async_uuid][uuid][object] */ 

#define	MAX_OID_RUNDOWNS_PER_CALL	( 100 )


EXTERN_C const IID IID_IRundown;

#if defined(__cplusplus) && !defined(CINTERFACE)
    
    MIDL_INTERFACE("00000134-0000-0000-C000-000000000046")
    IRundown : public IRemUnknownN
    {
    public:
        virtual HRESULT STDMETHODCALLTYPE RundownOid( 
            /* [range][in] */ DWORD cOid,
            /* [size_is][in] */ OID aOid[  ],
            /* [size_is][out] */ BYTE aRundownStatus[  ]) = 0;
        
    };
    
    
#else 	/* C style interface */

    typedef struct IRundownVtbl
    {
        BEGIN_INTERFACE
        
        DECLSPEC_XFGVIRT(IUnknown, QueryInterface)
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            IRundown * This,
            /* [in] */ REFIID riid,
            /* [annotation][iid_is][out] */ 
            _COM_Outptr_  void **ppvObject);
        
        DECLSPEC_XFGVIRT(IUnknown, AddRef)
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            IRundown * This);
        
        DECLSPEC_XFGVIRT(IUnknown, Release)
        ULONG ( STDMETHODCALLTYPE *Release )( 
            IRundown * This);
        
        DECLSPEC_XFGVIRT(IRemUnknown, RemQueryInterface)
        HRESULT ( STDMETHODCALLTYPE *RemQueryInterface )( 
            IRundown * This,
            /* [in] */ REFIPID ripid,
            /* [in] */ DWORD cRefs,
            /* [range][in] */ WORD cIids,
            /* [size_is][in] */ IID *iids,
            /* [size_is][size_is][out] */ PREMQIRESULT *ppQIResults);
        
        DECLSPEC_XFGVIRT(IRemUnknown, RemAddRef)
        HRESULT ( STDMETHODCALLTYPE *RemAddRef )( 
            IRundown * This,
            /* [in] */ WORD cInterfaceRefs,
            /* [size_is][in] */ REMINTERFACEREF InterfaceRefs[  ],
            /* [size_is][out] */ HRESULT *pResults);
        
        DECLSPEC_XFGVIRT(IRemUnknown, RemRelease)
        HRESULT ( STDMETHODCALLTYPE *RemRelease )( 
            IRundown * This,
            /* [in] */ WORD cInterfaceRefs,
            /* [size_is][in] */ REMINTERFACEREF InterfaceRefs[  ]);
        
        DECLSPEC_XFGVIRT(IRemUnknown2, RemQueryInterface2)
        HRESULT ( STDMETHODCALLTYPE *RemQueryInterface2 )( 
            IRundown * This,
            /* [in] */ REFIPID ripid,
            /* [range][in] */ WORD cIids,
            /* [size_is][in] */ IID *iids,
            /* [size_is][out] */ HRESULT *phr,
            /* [size_is][out] */ PMInterfacePointerInternal *ppMIF);
        
        DECLSPEC_XFGVIRT(IRemUnknownN, AcknowledgeMarshalingSets)
        HRESULT ( STDMETHODCALLTYPE *AcknowledgeMarshalingSets )( 
            IRundown * This,
            /* [in] */ WORD cMarshalingSets,
            /* [size_is][in] */ DWORD64 *pMarshalingSets);
        
        DECLSPEC_XFGVIRT(IRemUnknownN, RemChangeRef)
        HRESULT ( STDMETHODCALLTYPE *RemChangeRef )( 
            IRundown * This,
            /* [in] */ DWORD flags,
            /* [in] */ WORD cInterfaceRefs,
            /* [size_is][in] */ REMINTERFACEREF InterfaceRefs[  ]);
        
        DECLSPEC_XFGVIRT(IRemUnknownN, DoCallback)
        HRESULT ( STDMETHODCALLTYPE *DoCallback )( 
            IRundown * This,
            /* [in] */ XAptCallback *pCallbackData);
        
        DECLSPEC_XFGVIRT(IRemUnknownN, DoNonreentrantCallback)
        HRESULT ( STDMETHODCALLTYPE *DoNonreentrantCallback )( 
            IRundown * This,
            /* [in] */ XAptCallback *pCallbackData);
        
        DECLSPEC_XFGVIRT(IRemUnknownN, GetInterfaceNameFromIPID)
        HRESULT ( STDMETHODCALLTYPE *GetInterfaceNameFromIPID )( 
            IRundown * This,
            /* [in] */ REFIPID ripid,
            /* [out] */ HSTRING *interfaceName);
        
        DECLSPEC_XFGVIRT(IRundown, RundownOid)
        HRESULT ( STDMETHODCALLTYPE *RundownOid )( 
            IRundown * This,
            /* [range][in] */ DWORD cOid,
            /* [size_is][in] */ OID aOid[  ],
            /* [size_is][out] */ BYTE aRundownStatus[  ]);
        
        END_INTERFACE
    } IRundownVtbl;

    interface IRundown
    {
        CONST_VTBL struct IRundownVtbl *lpVtbl;
    };

    

#ifdef COBJMACROS


#define IRundown_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define IRundown_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define IRundown_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define IRundown_RemQueryInterface(This,ripid,cRefs,cIids,iids,ppQIResults)	\
    ( (This)->lpVtbl -> RemQueryInterface(This,ripid,cRefs,cIids,iids,ppQIResults) ) 

#define IRundown_RemAddRef(This,cInterfaceRefs,InterfaceRefs,pResults)	\
    ( (This)->lpVtbl -> RemAddRef(This,cInterfaceRefs,InterfaceRefs,pResults) ) 

#define IRundown_RemRelease(This,cInterfaceRefs,InterfaceRefs)	\
    ( (This)->lpVtbl -> RemRelease(This,cInterfaceRefs,InterfaceRefs) ) 


#define IRundown_RemQueryInterface2(This,ripid,cIids,iids,phr,ppMIF)	\
    ( (This)->lpVtbl -> RemQueryInterface2(This,ripid,cIids,iids,phr,ppMIF) ) 


#define IRundown_AcknowledgeMarshalingSets(This,cMarshalingSets,pMarshalingSets)	\
    ( (This)->lpVtbl -> AcknowledgeMarshalingSets(This,cMarshalingSets,pMarshalingSets) ) 

#define IRundown_RemChangeRef(This,flags,cInterfaceRefs,InterfaceRefs)	\
    ( (This)->lpVtbl -> RemChangeRef(This,flags,cInterfaceRefs,InterfaceRefs) ) 

#define IRundown_DoCallback(This,pCallbackData)	\
    ( (This)->lpVtbl -> DoCallback(This,pCallbackData) ) 

#define IRundown_DoNonreentrantCallback(This,pCallbackData)	\
    ( (This)->lpVtbl -> DoNonreentrantCallback(This,pCallbackData) ) 

#define IRundown_GetInterfaceNameFromIPID(This,ripid,interfaceName)	\
    ( (This)->lpVtbl -> GetInterfaceNameFromIPID(This,ripid,interfaceName) ) 


#define IRundown_RundownOid(This,cOid,aOid,aRundownStatus)	\
    ( (This)->lpVtbl -> RundownOid(This,cOid,aOid,aRundownStatus) ) 

#endif /* COBJMACROS */


#endif 	/* C style interface */




#endif 	/* __IRundown_INTERFACE_DEFINED__ */


#ifndef __AsyncIRundown_INTERFACE_DEFINED__
#define __AsyncIRundown_INTERFACE_DEFINED__

/* interface AsyncIRundown */
/* [uuid][object] */ 


EXTERN_C const IID IID_AsyncIRundown;

#if defined(__cplusplus) && !defined(CINTERFACE)
    
    MIDL_INTERFACE("000e0134-0000-0000-C000-000000000046")
    AsyncIRundown : public AsyncIRemUnknownN
    {
    public:
        virtual HRESULT STDMETHODCALLTYPE Begin_RundownOid( 
            /* [range][in] */ DWORD cOid,
            /* [size_is][in] */ OID aOid[  ]) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE Finish_RundownOid( 
            /* [size_is][out] */ BYTE aRundownStatus[  ]) = 0;
        
    };
    
    
#else 	/* C style interface */

    typedef struct AsyncIRundownVtbl
    {
        BEGIN_INTERFACE
        
        DECLSPEC_XFGVIRT(IUnknown, QueryInterface)
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            AsyncIRundown * This,
            /* [in] */ REFIID riid,
            /* [annotation][iid_is][out] */ 
            _COM_Outptr_  void **ppvObject);
        
        DECLSPEC_XFGVIRT(IUnknown, AddRef)
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            AsyncIRundown * This);
        
        DECLSPEC_XFGVIRT(IUnknown, Release)
        ULONG ( STDMETHODCALLTYPE *Release )( 
            AsyncIRundown * This);
        
        DECLSPEC_XFGVIRT(AsyncIRemUnknown, Begin_RemQueryInterface)
        HRESULT ( STDMETHODCALLTYPE *Begin_RemQueryInterface )( 
            AsyncIRundown * This,
            /* [in] */ REFIPID ripid,
            /* [in] */ DWORD cRefs,
            /* [range][in] */ WORD cIids,
            /* [size_is][in] */ IID *iids);
        
        DECLSPEC_XFGVIRT(AsyncIRemUnknown, Finish_RemQueryInterface)
        HRESULT ( STDMETHODCALLTYPE *Finish_RemQueryInterface )( 
            AsyncIRundown * This,
            /* [size_is][size_is][out] */ PREMQIRESULT *ppQIResults);
        
        DECLSPEC_XFGVIRT(AsyncIRemUnknown, Begin_RemAddRef)
        HRESULT ( STDMETHODCALLTYPE *Begin_RemAddRef )( 
            AsyncIRundown * This,
            /* [in] */ WORD cInterfaceRefs,
            /* [size_is][in] */ REMINTERFACEREF InterfaceRefs[  ]);
        
        DECLSPEC_XFGVIRT(AsyncIRemUnknown, Finish_RemAddRef)
        HRESULT ( STDMETHODCALLTYPE *Finish_RemAddRef )( 
            AsyncIRundown * This,
            /* [size_is][out] */ HRESULT *pResults);
        
        DECLSPEC_XFGVIRT(AsyncIRemUnknown, Begin_RemRelease)
        HRESULT ( STDMETHODCALLTYPE *Begin_RemRelease )( 
            AsyncIRundown * This,
            /* [in] */ WORD cInterfaceRefs,
            /* [size_is][in] */ REMINTERFACEREF InterfaceRefs[  ]);
        
        DECLSPEC_XFGVIRT(AsyncIRemUnknown, Finish_RemRelease)
        HRESULT ( STDMETHODCALLTYPE *Finish_RemRelease )( 
            AsyncIRundown * This);
        
        DECLSPEC_XFGVIRT(AsyncIRemUnknown2, Begin_RemQueryInterface2)
        HRESULT ( STDMETHODCALLTYPE *Begin_RemQueryInterface2 )( 
            AsyncIRundown * This,
            /* [in] */ REFIPID ripid,
            /* [range][in] */ WORD cIids,
            /* [size_is][in] */ IID *iids);
        
        DECLSPEC_XFGVIRT(AsyncIRemUnknown2, Finish_RemQueryInterface2)
        HRESULT ( STDMETHODCALLTYPE *Finish_RemQueryInterface2 )( 
            AsyncIRundown * This,
            /* [size_is][out] */ HRESULT *phr,
            /* [size_is][out] */ PMInterfacePointerInternal *ppMIF);
        
        DECLSPEC_XFGVIRT(AsyncIRemUnknownN, Begin_AcknowledgeMarshalingSets)
        HRESULT ( STDMETHODCALLTYPE *Begin_AcknowledgeMarshalingSets )( 
            AsyncIRundown * This,
            /* [in] */ WORD cMarshalingSets,
            /* [size_is][in] */ DWORD64 *pMarshalingSets);
        
        DECLSPEC_XFGVIRT(AsyncIRemUnknownN, Finish_AcknowledgeMarshalingSets)
        HRESULT ( STDMETHODCALLTYPE *Finish_AcknowledgeMarshalingSets )( 
            AsyncIRundown * This);
        
        DECLSPEC_XFGVIRT(AsyncIRemUnknownN, Begin_RemChangeRef)
        HRESULT ( STDMETHODCALLTYPE *Begin_RemChangeRef )( 
            AsyncIRundown * This,
            /* [in] */ DWORD flags,
            /* [in] */ WORD cInterfaceRefs,
            /* [size_is][in] */ REMINTERFACEREF InterfaceRefs[  ]);
        
        DECLSPEC_XFGVIRT(AsyncIRemUnknownN, Finish_RemChangeRef)
        HRESULT ( STDMETHODCALLTYPE *Finish_RemChangeRef )( 
            AsyncIRundown * This);
        
        DECLSPEC_XFGVIRT(AsyncIRemUnknownN, Begin_DoCallback)
        HRESULT ( STDMETHODCALLTYPE *Begin_DoCallback )( 
            AsyncIRundown * This,
            /* [in] */ XAptCallback *pCallbackData);
        
        DECLSPEC_XFGVIRT(AsyncIRemUnknownN, Finish_DoCallback)
        HRESULT ( STDMETHODCALLTYPE *Finish_DoCallback )( 
            AsyncIRundown * This);
        
        DECLSPEC_XFGVIRT(AsyncIRemUnknownN, Begin_DoNonreentrantCallback)
        HRESULT ( STDMETHODCALLTYPE *Begin_DoNonreentrantCallback )( 
            AsyncIRundown * This,
            /* [in] */ XAptCallback *pCallbackData);
        
        DECLSPEC_XFGVIRT(AsyncIRemUnknownN, Finish_DoNonreentrantCallback)
        HRESULT ( STDMETHODCALLTYPE *Finish_DoNonreentrantCallback )( 
            AsyncIRundown * This);
        
        DECLSPEC_XFGVIRT(AsyncIRemUnknownN, Begin_GetInterfaceNameFromIPID)
        HRESULT ( STDMETHODCALLTYPE *Begin_GetInterfaceNameFromIPID )( 
            AsyncIRundown * This,
            /* [in] */ REFIPID ripid);
        
        DECLSPEC_XFGVIRT(AsyncIRemUnknownN, Finish_GetInterfaceNameFromIPID)
        HRESULT ( STDMETHODCALLTYPE *Finish_GetInterfaceNameFromIPID )( 
            AsyncIRundown * This,
            /* [out] */ HSTRING *interfaceName);
        
        DECLSPEC_XFGVIRT(AsyncIRundown, Begin_RundownOid)
        HRESULT ( STDMETHODCALLTYPE *Begin_RundownOid )( 
            AsyncIRundown * This,
            /* [range][in] */ DWORD cOid,
            /* [size_is][in] */ OID aOid[  ]);
        
        DECLSPEC_XFGVIRT(AsyncIRundown, Finish_RundownOid)
        HRESULT ( STDMETHODCALLTYPE *Finish_RundownOid )( 
            AsyncIRundown * This,
            /* [size_is][out] */ BYTE aRundownStatus[  ]);
        
        END_INTERFACE
    } AsyncIRundownVtbl;

    interface AsyncIRundown
    {
        CONST_VTBL struct AsyncIRundownVtbl *lpVtbl;
    };

    

#ifdef COBJMACROS


#define AsyncIRundown_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define AsyncIRundown_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define AsyncIRundown_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define AsyncIRundown_Begin_RemQueryInterface(This,ripid,cRefs,cIids,iids)	\
    ( (This)->lpVtbl -> Begin_RemQueryInterface(This,ripid,cRefs,cIids,iids) ) 

#define AsyncIRundown_Finish_RemQueryInterface(This,ppQIResults)	\
    ( (This)->lpVtbl -> Finish_RemQueryInterface(This,ppQIResults) ) 

#define AsyncIRundown_Begin_RemAddRef(This,cInterfaceRefs,InterfaceRefs)	\
    ( (This)->lpVtbl -> Begin_RemAddRef(This,cInterfaceRefs,InterfaceRefs) ) 

#define AsyncIRundown_Finish_RemAddRef(This,pResults)	\
    ( (This)->lpVtbl -> Finish_RemAddRef(This,pResults) ) 

#define AsyncIRundown_Begin_RemRelease(This,cInterfaceRefs,InterfaceRefs)	\
    ( (This)->lpVtbl -> Begin_RemRelease(This,cInterfaceRefs,InterfaceRefs) ) 

#define AsyncIRundown_Finish_RemRelease(This)	\
    ( (This)->lpVtbl -> Finish_RemRelease(This) ) 


#define AsyncIRundown_Begin_RemQueryInterface2(This,ripid,cIids,iids)	\
    ( (This)->lpVtbl -> Begin_RemQueryInterface2(This,ripid,cIids,iids) ) 

#define AsyncIRundown_Finish_RemQueryInterface2(This,phr,ppMIF)	\
    ( (This)->lpVtbl -> Finish_RemQueryInterface2(This,phr,ppMIF) ) 


#define AsyncIRundown_Begin_AcknowledgeMarshalingSets(This,cMarshalingSets,pMarshalingSets)	\
    ( (This)->lpVtbl -> Begin_AcknowledgeMarshalingSets(This,cMarshalingSets,pMarshalingSets) ) 

#define AsyncIRundown_Finish_AcknowledgeMarshalingSets(This)	\
    ( (This)->lpVtbl -> Finish_AcknowledgeMarshalingSets(This) ) 

#define AsyncIRundown_Begin_RemChangeRef(This,flags,cInterfaceRefs,InterfaceRefs)	\
    ( (This)->lpVtbl -> Begin_RemChangeRef(This,flags,cInterfaceRefs,InterfaceRefs) ) 

#define AsyncIRundown_Finish_RemChangeRef(This)	\
    ( (This)->lpVtbl -> Finish_RemChangeRef(This) ) 

#define AsyncIRundown_Begin_DoCallback(This,pCallbackData)	\
    ( (This)->lpVtbl -> Begin_DoCallback(This,pCallbackData) ) 

#define AsyncIRundown_Finish_DoCallback(This)	\
    ( (This)->lpVtbl -> Finish_DoCallback(This) ) 

#define AsyncIRundown_Begin_DoNonreentrantCallback(This,pCallbackData)	\
    ( (This)->lpVtbl -> Begin_DoNonreentrantCallback(This,pCallbackData) ) 

#define AsyncIRundown_Finish_DoNonreentrantCallback(This)	\
    ( (This)->lpVtbl -> Finish_DoNonreentrantCallback(This) ) 

#define AsyncIRundown_Begin_GetInterfaceNameFromIPID(This,ripid)	\
    ( (This)->lpVtbl -> Begin_GetInterfaceNameFromIPID(This,ripid) ) 

#define AsyncIRundown_Finish_GetInterfaceNameFromIPID(This,interfaceName)	\
    ( (This)->lpVtbl -> Finish_GetInterfaceNameFromIPID(This,interfaceName) ) 


#define AsyncIRundown_Begin_RundownOid(This,cOid,aOid)	\
    ( (This)->lpVtbl -> Begin_RundownOid(This,cOid,aOid) ) 

#define AsyncIRundown_Finish_RundownOid(This,aRundownStatus)	\
    ( (This)->lpVtbl -> Finish_RundownOid(This,aRundownStatus) ) 

#endif /* COBJMACROS */


#endif 	/* C style interface */




#endif 	/* __AsyncIRundown_INTERFACE_DEFINED__ */


/* Additional Prototypes for ALL interfaces */

unsigned long             __RPC_USER  HSTRING_UserSize(     unsigned long *, unsigned long            , HSTRING * ); 
unsigned char * __RPC_USER  HSTRING_UserMarshal(  unsigned long *, unsigned char *, HSTRING * ); 
unsigned char * __RPC_USER  HSTRING_UserUnmarshal(unsigned long *, unsigned char *, HSTRING * ); 
void                      __RPC_USER  HSTRING_UserFree(     unsigned long *, HSTRING * ); 

unsigned long             __RPC_USER  HSTRING_UserSize64(     unsigned long *, unsigned long            , HSTRING * ); 
unsigned char * __RPC_USER  HSTRING_UserMarshal64(  unsigned long *, unsigned char *, HSTRING * ); 
unsigned char * __RPC_USER  HSTRING_UserUnmarshal64(unsigned long *, unsigned char *, HSTRING * ); 
void                      __RPC_USER  HSTRING_UserFree64(     unsigned long *, HSTRING * ); 

/* end of Additional Prototypes */

#ifdef __cplusplus
}
#endif

#endif


