//Copyright (c) 2007-2008, Marton Anka
//
//Permission is hereby granted, free of charge, to any person obtaining a 
//copy of this software and associated documentation files (the "Software"), 
//to deal in the Software without restriction, including without limitation 
//the rights to use, copy, modify, merge, publish, distribute, sublicense, 
//and/or sell copies of the Software, and to permit persons to whom the 
//Software is furnished to do so, subject to the following conditions:
//
//The above copyright notice and this permission notice shall be included 
//in all copies or substantial portions of the Software.
//
//THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS 
//OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
//FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL 
//THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
//LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING 
//FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS 
//IN THE SOFTWARE.

// Copyright © 2015 Hansoft AB 
// Distributed under the MIT license, see license text in LICENSE.Malterlib

#include <Mib/Core/Core>
#include <Mib/Container/Regions>

namespace NMib::NInstrumentation
{
	class CMHook
	{
		enum
		{
			EMaxCodeBytes = 32
			, EMaxRips = 4
			, EJmpSize = 5
		};

		class CAllocatorIgnore : public NMib::NMemory::CAllocator_NonTrackedHeap
		{
		public:
			using CAutoDestroy = NMemory::TCAllocator_AutoDestroyStatic<CAllocatorIgnore>;

			only_parameters_aliased malloc_like static void *f_AllocWithSizeDebug(mint &_Size, const ch8 *_pFile, aint _Line, EHeapDebugFlag _Flags = EHeapDebugFlag_None, EAllocationFlag _AllocFlags = EAllocationFlag_None, ENumaNode _NumaNode = ENumaNode_Default)
			{
				return CAllocator_NonTrackedHeap::f_AllocWithSizeDebug(_Size, _pFile, _Line, _Flags | EHeapDebugFlag_Ignore, _AllocFlags, _NumaNode);
			}
			only_parameters_aliased malloc_like static void *f_AllocDebug(mint _Size, const ch8 *_pFile, aint _Line, EHeapDebugFlag _Flags = EHeapDebugFlag_None, EAllocationFlag _AllocFlags = EAllocationFlag_None, ENumaNode _NumaNode = ENumaNode_Default)
			{
				return CAllocator_NonTrackedHeap::f_AllocDebug(_Size, _pFile, _Line, _Flags | EHeapDebugFlag_Ignore, _AllocFlags, _NumaNode);
			}
			only_parameters_aliased malloc_like static void *f_AllocAlignedWithSizeDebug(mint &_Size, mint _Alignment, const ch8 *_pFile, aint _Line, EHeapDebugFlag _Flags = EHeapDebugFlag_None, EAllocationFlag _AllocFlags = EAllocationFlag_None, ENumaNode _NumaNode = ENumaNode_Default)
			{
				return CAllocator_NonTrackedHeap::f_AllocAlignedWithSizeDebug(_Size, _Alignment, _pFile, _Line, _Flags | EHeapDebugFlag_Ignore, _AllocFlags, _NumaNode);
			}
			only_parameters_aliased malloc_like static void *f_AllocAlignedDebug(mint _Size, mint _Alignment, const ch8 *_pFile, aint _Line, EHeapDebugFlag _Flags = EHeapDebugFlag_None, EAllocationFlag _AllocFlags = EAllocationFlag_None, ENumaNode _NumaNode = ENumaNode_Default)
			{
				return CAllocator_NonTrackedHeap::f_AllocAlignedDebug(_Size, _Alignment, _pFile, _Line, _Flags | EHeapDebugFlag_Ignore, _AllocFlags, _NumaNode);
			}
			only_parameters_aliased malloc_like static void *f_AllocWithSize(mint &_Size, EAllocationFlag _AllocFlags = EAllocationFlag_None, ENumaNode _NumaNode = ENumaNode_Default)
			{
				return CAllocator_NonTrackedHeap::f_AllocWithSizeDebug(_Size, DMibPFile, DMibPLine, EHeapDebugFlag_Ignore, _AllocFlags, _NumaNode);
			}
			only_parameters_aliased malloc_like static void *f_Alloc(mint _Size, EAllocationFlag _AllocFlags = EAllocationFlag_None, ENumaNode _NumaNode = ENumaNode_Default)
			{
				return CAllocator_NonTrackedHeap::f_AllocDebug(_Size, DMibPFile, DMibPLine, EHeapDebugFlag_Ignore, _AllocFlags, _NumaNode);
			}
			only_parameters_aliased malloc_like static void *f_AllocAlignedWithSize(mint &_Size, mint _Alignment, EAllocationFlag _AllocFlags = EAllocationFlag_None, ENumaNode _NumaNode = ENumaNode_Default)
			{
				return CAllocator_NonTrackedHeap::f_AllocAlignedWithSizeDebug(_Size, _Alignment, DMibPFile, DMibPLine, EHeapDebugFlag_Ignore, _AllocFlags, _NumaNode);
			}
			only_parameters_aliased malloc_like static void *f_AllocAligned(mint _Size, mint _Alignment, EAllocationFlag _AllocFlags = EAllocationFlag_None, ENumaNode _NumaNode = ENumaNode_Default)
			{
				return CAllocator_NonTrackedHeap::f_AllocAlignedDebug(_Size, _Alignment, DMibPFile, DMibPLine, EHeapDebugFlag_Ignore, _AllocFlags, _NumaNode);
			}
			only_parameters_aliased static CAutoDestroy f_AllocSafeWithSize(mint &_Size, mint _Alignment, EAllocationFlag _AllocFlags = EAllocationFlag_None, ENumaNode _NumaNode = ENumaNode_Default)
			{
				CAutoDestroy AutoDestroy;
				AutoDestroy.m_pMemory = f_AllocAlignedWithSize(_Size, _Alignment, _AllocFlags, _NumaNode);
				AutoDestroy.m_Size = _Size;

				return fg_Move(AutoDestroy);
			}
			only_parameters_aliased static CAutoDestroy f_AllocSafe(mint _Size, mint _Alignment, EAllocationFlag _AllocFlags = EAllocationFlag_None, ENumaNode _NumaNode = ENumaNode_Default)
			{
				CAutoDestroy AutoDestroy;
				AutoDestroy.m_pMemory = f_AllocAligned(_Size, _Alignment, _AllocFlags, _NumaNode);
				AutoDestroy.m_Size = _Size;

				return fg_Move(AutoDestroy);
			}
		};

#			if DMibConfig_MalterlibMemoryManager_Debug
			using CAllocator = CAllocatorIgnore;
#			else
			using CAllocator = NMib::NMemory::CAllocator_NonTrackedHeap;
#			endif

		//=========================================================================
		// The trampoline structure - stores every bit of info about a hook

		struct CFreeTrampoline
		{
			DMibListLinkDS_Link(CFreeTrampoline, m_Link);
		};

		struct CTrampolinePool;
		struct CTrampoline
		{
			CTrampolinePool *m_pPool;
			uint8 *pSystemFunction;							// the original system function
			uint32 cbOverwrittenCode;						// number of bytes overwritten by the jump
			uint8 *pHookFunction;							// the hook function that we provide
			uint8 codeJumpToHookFunction[EMaxCodeBytes];	// placeholder for code that jumps to the hook function
			uint8 codeTrampoline[EMaxCodeBytes];			// placeholder for code that holds the first few
															//   bytes from the system function and a jump to the remainder
															//   in the original location
			uint8 codeUntouched[EMaxCodeBytes];				// placeholder for unmodified original code
															//   (we patch IP-relative addressing)
		};

		struct CTrampolinePool
		{
			DMibListLinkDS_List(CFreeTrampoline, m_Link) m_FreeTrampolines;
			zmint m_nUsed;
			mint m_Size;
			CTrampolinePool(void *_pMemory, mint _MemorySize);
			~CTrampolinePool();

			void f_Unprotect();
			void f_Protect();
		};

		NMib::NContainer::TCMap<uint8 *, CTrampolinePool, NMib::CSort_Default, CAllocator> m_TrampolinePools;

		struct CModuleCache
		{
			mint m_Size;
			bool m_bImage;
		};
		NMib::NContainer::TCMap<mint, CModuleCache, NMib::CSort_Default, CAllocator> m_ModulesCache;

		NMib::NContainer::TCRegions<uint8 *, NMib::CVoidTag, CAllocator> m_Unprotected;

		//=========================================================================
		// The patch data structures - store info about rip-relative instructions
		// during hook placement
		struct CRipInfo
		{
			uint32 dwOffset;
			int64 nDisplacement;
		};

		struct CPatchData
		{
			int64 nLimitUp;
			int64 nLimitDown;
			uint32 nRipCnt;
			CRipInfo rips[EMaxRips];
		};

		//=========================================================================
		// Global vars
		NMib::NThread::CMutual m_Lock;

		NMib::NContainer::TCMap<void *, CTrampoline *, NMib::CSort_Default, CAllocator> m_Hooks;
		zmint m_IsSuspended;

		bool fp_Unprotect(uint8 *_pMem, mint _Size);
		uint8 *fp_SkipJumps(uint8 *pbCode);
		uint8 *fp_EmitJump(uint8 *pbCode, uint8 *pbJumpTo);
		CTrampoline *fp_TrampolineAlloc(uint8 *pSystemFunction, int64 nLimitUp, int64 nLimitDown);
		CTrampoline *fp_TrampolineGet(uint8 *pHookedFunction);
		void fp_TrampolineFree(CTrampoline *pTrampoline, bool bNeverUsed);
		void fp_FixupIPRelativeAddressing(uint8 *pbNew, uint8 *pbOriginal, CPatchData* pdata);
		uint32 fp_DisassembleAndSkip(void * pFunction, uint32 dwMinLen, CPatchData* pdata);

		void fp_Suspend();
		void fp_Resume();
	public:
		CMHook();
		bool f_SetHook(void ** ppSystemFunction, void * pHookFunction);
		bool f_Unhook(void ** ppHookedFunction);
		void f_Suspend();
		void f_Resume();
	};
}
