#ifndef _NTWIN_
#define _NTWIN_

#ifdef __cplusplus
extern "C" {
#endif

union ULARGE_INTEGER {
    struct {
        DWORD LowPart;
        DWORD HighPart;
    };
    struct {
        DWORD LowPart;
        DWORD HighPart;
    } u;
    ULONGLONG QuadPart;
};

typedef union LARGE_INTEGER {
    struct {
        DWORD LowPart;
        LONG HighPart;
    };
    struct {
        DWORD LowPart;
        LONG HighPart;
    } u;
    LONGLONG QuadPart;
};

struct RTL_CRITICAL_SECTION_DEBUG {
    WORD   Type;
    WORD   CreatorBackTraceIndex;
    struct RTL_CRITICAL_SECTION *CriticalSection;
    LIST_ENTRY ProcessLocksList;
    DWORD EntryCount;
    DWORD ContentionCount;
    DWORD Flags;
    WORD   CreatorBackTraceIndexHigh;
    WORD   Identifier;
};

#pragma pack(push, 8)

struct RTL_CRITICAL_SECTION {
    PRTL_CRITICAL_SECTION_DEBUG DebugInfo;

    //
    //  The following three fields control entering and exiting the critical
    //  section for the resource
    //

    LONG LockCount;
    LONG RecursionCount;
    HANDLE OwningThread;        // from the thread's ClientId->UniqueThread
    HANDLE LockSemaphore;
    ULONG_PTR SpinCount;        // force size on 64-bit systems when packed
};

#pragma pack(pop)

struct RTL_SRWLOCK {
    PVOID Ptr;
};

struct RTL_CONDITION_VARIABLE {
    PVOID Ptr;
};

struct RTL_BARRIER {
    DWORD Reserved1;
    DWORD Reserved2;
    ULONG_PTR Reserved3[2];
    DWORD Reserved4;
    DWORD Reserved5;
};

typedef struct _TPP_PH_LINKS TPP_PH_LINKS, *PTPP_PH_LINKS;
typedef struct _TPP_ITE_WAITER TPP_ITE_WAITER, *PTPP_ITE_WAITER;
typedef struct _TPP_QUEUE TPP_QUEUE, *PTPP_QUEUE;
typedef struct _TPP_NUMA_NODE TPP_NUMA_NODE, *PTPP_NUMA_NODE;
typedef struct _FULL_TP_POOL FULL_TP_POOL, *PFULL_TP_POOL;

typedef struct _TP_TASK_CALLBACKS {
    PVOID ExecuteCallback;
    PVOID Unposted;
} TP_TASK_CALLBACKS, *PTP_TASK_CALLBACKS;

typedef struct _TP_TASK {
    PTP_TASK_CALLBACKS Callbacks;
    ULONG NumaNode;
    UCHAR IdealProcessor;
    UCHAR Padding_242[3];
    LIST_ENTRY ListEntry;
} TP_TASK, *PTP_TASK;

typedef struct _TPP_REFCOUNT {
    LONG Refcount;
} TPP_REFCOUNT, *PTPP_REFCOUNT;

typedef struct _TPP_CALLER {
    PVOID ReturnAddress;
} TPP_CALLER, *PTPP_CALLER;

typedef struct _TPP_PH {
    PTPP_PH_LINKS Root;
} TPP_PH, *PTPP_PH;

typedef struct _TP_DIRECT {
    TP_TASK Task;
    ULONGLONG Lock;
    LIST_ENTRY IoCompletionInformationList;
    PVOID Callback;
    ULONG NumaNode;
    UCHAR IdealProcessor;
    UCHAR Padding[3];
} TP_DIRECT, *PTP_DIRECT;

typedef struct _TPP_TIMER_SUBQUEUE {
    LONGLONG Expiration;
    TPP_PH WindowStart;
    TPP_PH WindowEnd;
    PVOID Timer;
    PVOID TimerPkt;
    TP_DIRECT Direct;
    ULONG ExpirationWindow;
    LONG Padding[1];
} TPP_TIMER_SUBQUEUE, *PTPP_TIMER_SUBQUEUE;

typedef struct _TPP_TIMER_QUEUE {
    RTL_SRWLOCK Lock;
    TPP_TIMER_SUBQUEUE AbsoluteQueue;
    TPP_TIMER_SUBQUEUE RelativeQueue;
    LONG AllocatedTimerCount;
    LONG Padding[1];
} TPP_TIMER_QUEUE, *PTPP_TIMER_QUEUE;

typedef struct _TPP_NUMA_NODE {
    LONG WorkerCount;
} TPP_NUMA_NODE, *PTPP_NUMA_NODE;

typedef struct _TPP_POOL_QUEUE_STATE {
    LONGLONG Exchange;
} TPP_POOL_QUEUE_STATE, *PTPP_POOL_QUEUE_STATE;

struct _TPP_QUEUE {
    LIST_ENTRY Queue;
    RTL_SRWLOCK Lock;
};

struct _FULL_TP_POOL {
    TPP_REFCOUNT Refcount;
    LONG Padding_239;
    TPP_POOL_QUEUE_STATE QueueState;
    PTPP_QUEUE TaskQueue[3];
    PTPP_NUMA_NODE NumaNode;
    PVOID ProximityInfo;
    HANDLE WorkerFactory;
    HANDLE CompletionPort;
    RTL_SRWLOCK Lock;
    LIST_ENTRY PoolObjectList;
    LIST_ENTRY WorkerList;
    TPP_TIMER_QUEUE TimerQueue;
};

typedef struct _TPP_WORK_STATE {
    LONG Exchange;
} TPP_WORK_STATE, *PTPP_WORK_STATE;

struct _TPP_ITE_WAITER {
    PTPP_ITE_WAITER Next;
    PVOID ThreadId;
};

struct _TPP_PH_LINKS {
    LIST_ENTRY Siblings;
    LIST_ENTRY Children;
    LONGLONG Key;
};

typedef struct _TPP_ITE {
    PTPP_ITE_WAITER First;
} TPP_ITE, *PTPP_ITE;

typedef struct _TPP_FLAGS_COUNT {
    LONGLONG Data;
} TPP_FLAGS_COUNT, *PTPP_FLAGS_COUNT;

typedef struct _TPP_BARRIER {
    TPP_FLAGS_COUNT Ptr;
    RTL_SRWLOCK WaitLock;
    TPP_ITE WaitList;
} TPP_BARRIER, *PTPP_BARRIER;

typedef struct _TPP_CLEANUP_GROUP_MEMBER {
    TPP_REFCOUNT Refcount;
    LONG Padding_233;
    PVOID VFuncs;
    PVOID CleanupGroup;
    PVOID CleanupGroupCancelCallback;
    PVOID FinalizationCallback;
    LIST_ENTRY CleanupGroupMemberLinks;
    TPP_BARRIER CallbackBarrier;
    PVOID Callback;
    PVOID Context;
    PVOID ActivationContext;
    PVOID SubProcessTag;
    GUID ActivityId;
    ALPC_WORK_ON_BEHALF_TICKET WorkOnBehalfTicket;
    PVOID RaceDll;
    PFULL_TP_POOL Pool;
    LIST_ENTRY PoolObjectLinks;
    ULONG Flags;
    LONG Padding_234;
    TPP_CALLER AllocCaller;
    TPP_CALLER ReleaseCaller;
    LONG CallbackPriority;
    LONG Padding[1];
} TPP_CLEANUP_GROUP_MEMBER, *PTPP_CLEANUP_GROUP_MEMBER;

typedef struct _FULL_TP_WORK {
    TPP_CLEANUP_GROUP_MEMBER CleanupGroupMember;
    TP_TASK Task;
    TPP_WORK_STATE WorkState;
    LONG Padding[1];
} FULL_TP_WORK, *PFULL_TP_WORK;

typedef struct _FULL_TP_TIMER {
    FULL_TP_WORK Work;
    RTL_SRWLOCK Lock;
    TPP_PH_LINKS WindowEndLinks;
    TPP_PH_LINKS WindowStartLinks;
    LONGLONG DueTime;
    TPP_ITE Ite;
    ULONG Window;
    ULONG Period;
    UCHAR Inserted;
    UCHAR WaitTimer;
    UCHAR TimerStatus;
    UCHAR BlockInsert;
    LONG Padding[1];
} FULL_TP_TIMER, *PFULL_TP_TIMER;

typedef struct _FULL_TP_WAIT {
    FULL_TP_TIMER Timer;
    HANDLE Handle;
    HANDLE WaitPkt;
    HANDLE NextWaitHandle;
    LARGE_INTEGER NextWaitTimeout;
    TP_DIRECT Direct;
    UCHAR WaitFlags;
    UCHAR Padding[7];
} FULL_TP_WAIT, *PFULL_TP_WAIT;

typedef struct _FULL_TP_IO {
    TPP_CLEANUP_GROUP_MEMBER CleanupGroupMember;
    TP_DIRECT Direct;
    HANDLE File;
    LONG PendingIrpCount;
    LONG Padding[1];
} FULL_TP_IO, *PFULL_TP_IO;

typedef struct _FULL_TP_ALPC {
    TP_DIRECT Direct;
    TPP_CLEANUP_GROUP_MEMBER CleanupGroupMember;
    HANDLE AlpcPort;
    LONG DeferredSendCount;
    LONG LastConcurrencyCount;
    ULONG Flags;
    LONG Padding[1];
} FULL_TP_ALPC, *PFULL_TP_ALPC;

typedef struct _FULL_TP_JOB {
    TP_DIRECT Direct;
    TPP_CLEANUP_GROUP_MEMBER CleanupGroupMember;
    HANDLE JobHandle;
    LONGLONG CompletionState;
    RTL_SRWLOCK RundownLock;
} FULL_TP_JOB, *PFULL_TP_JOB;

typedef union RTL_RUN_ONCE {
    PVOID Ptr;
};

struct BASE_RELOCATION_BLOCK {
    DWORD PageAddress;
    DWORD BlockSize;
} BASE_RELOCATION_BLOCK, *PBASE_RELOCATION_BLOCK;

struct BASE_RELOCATION_ENTRY {
    USHORT Offset : 12;
    USHORT Type : 4;
} BASE_RELOCATION_ENTRY, *PBASE_RELOCATION_ENTRY;

NTSYSCALLAPI
HANDLE
NTAPI
NtUserGetWindowProcessHandle(
    _In_ HWND hWnd,
    _In_ ACCESS_MASK DesiredAccess
);

#ifdef __cplusplus
}
#endif

#endif /* _NTWIN_ */
