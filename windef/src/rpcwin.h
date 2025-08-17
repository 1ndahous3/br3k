#ifndef _RPCWIN_
#define _RPCWIN_

#ifdef __cplusplus
extern "C" {
#endif

// COM IRundown stuff

struct tagPageEntry {
    struct tagPageEntry *pNext;
    unsigned int dwFlag;
};

struct CInternalPageAllocator {
    SIZE_T _cPages;
    struct tagPageEntry **_pPageListStart;
    struct tagPageEntry **_pPageListEnd;
    UINT _dwFlags;
    struct tagPageEntry _ListHead;
    UINT _cEntries;
    SIZE_T _cbPerEntry;
    USHORT _cEntriesPerPage;
    void *_pLock;
};

// CPageAllocator CIPIDTable::_palloc structure in COM DLL
struct CPageAllocator {
    struct CInternalPageAllocator _pgalloc;
    PVOID _hHeap;
    SIZE_T _cbPerEntry;
    INT _lNumEntries;
};

enum IPIDFlags {
    IPIDF_CONNECTING = 0x1,
    IPIDF_DISCONNECTED = 0x2,
    IPIDF_SERVERENTRY = 0x4,
    IPIDF_NOPING = 0x8,
    IPIDF_COPY = 0x10,
    IPIDF_VACANT = 0x80,
    IPIDF_NONNDRSTUB = 0x100,
    IPIDF_NONNDRPROXY = 0x200,
    IPIDF_NOTIFYACT = 0x400,
    IPIDF_TRIED_ASYNC = 0x800,
    IPIDF_ASYNC_SERVER = 0x1000,
    IPIDF_DEACTIVATED = 0x2000,
    IPIDF_WEAKREFCACHE = 0x4000,
    IPIDF_STRONGREFCACHE = 0x8000,
    IPIDF_UNSECURECALLSALLOWED = 0x10000
};

typedef struct tagIPIDEntry {
    struct tagIPIDEntry *pNextIPID; // next IPIDEntry for same object
    DWORD dwFlags;                  // flags (see IPIDFLAGS)
    ULONG cStrongRefs;              // strong reference count
    ULONG cWeakRefs;                // weak reference count
    ULONG cPrivateRefs;             // private reference count
    void *pv;                       // real interface pointer
    /*IUnknown*/ void *pStub;       // proxy or stub pointer
    void *pOXIDEntry;               // ptr to OXIDEntry in OXID Table
    GUID ipid;                      // interface pointer identifier
    GUID iid;                       // interface iid
    void *pChnl;                    // channel pointer
    void *pIRCEntry;                // reference cache line
    HSTRING *pInterfaceName;
    struct tagIPIDEntry *pOIDFLink; // In use OID list
    struct tagIPIDEntry *pOIDBLink;
} IPIDEntry;

// IPID in IDL has GUID typedef
struct IPID_VALUES {
    WORD offset; // These are reversed because of little-endian
    WORD page;   // These are reversed because of little-endian
    WORD pid;
    WORD tid;
    BYTE seq[8];
};

typedef struct tagSOleTlsData {
    /* 0x0000 */ void *pvThreadBase;
    /* 0x0008 */ void *pSmAllocator;
    /* 0x0010 */ ULONG dwApartmentID;
    /* 0x0014 */ ULONG dwFlags;
    /* 0x0018 */ LONG TlsMapIndex;
    /* 0x0020 */ void **ppTlsSlot;
    /* 0x0028 */ ULONG cComInits;
    /* 0x002c */ ULONG cOleInits;
    /* 0x0030 */ ULONG cCalls;
    /* 0x0038 */ void *pServerCall;
    /* 0x0040 */ void *pCallObjectCache;
    /* 0x0048 */ void *pContextStack;
    /* 0x0050 */ void *pObjServer;
    /* 0x0058 */ ULONG dwTIDCaller;
    /* 0x0060 */ void *pCurrentCtxForNefariousReaders;
    /* 0x0068 */ void *pCurrentContext;
} SOleTlsData;

#ifdef __cplusplus
}
#endif

#endif /* _RPCWIN_ */
