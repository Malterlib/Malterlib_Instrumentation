// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

/*
This code is derived from mhook with the following copyright:
SPDX-License-Identifier: MIT

Copyright (c) 2007-2008, Marton Anka

Permission is hereby granted, free of charge, to any person obtaining a
copy of this software and associated documentation files (the "Software"),
to deal in the Software without restriction, including without limitation
the rights to use, copy, modify, merge, publish, distribute, sublicense,
and/or sell copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included
in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
IN THE SOFTWARE.
*/

#pragma once

#include <Mib/Core/Core>
#include <Mib/Container/Regions>

namespace NMib::NInstrumentation
{
	struct CMHook
	{
		CMHook();
		bool f_SetHook(void **o_pSystemFunction, void *_pHookFunction);
		bool f_Unhook(void **o_pHookedFunction);
		void f_Suspend();
		void f_Resume();

	private:
		static constexpr uint32 mcp_MaxCodeBytes = 32;
		static constexpr uint32 mcp_MaxRips = 4;
		static constexpr uint32 mcp_JumpSize = 5;

		struct CAllocatorIgnore : public NMib::NMemory::CAllocator_NonTrackedHeap
		{
			using CAutoDestroy = NMemory::TCAllocator_AutoDestroyStatic<CAllocatorIgnore>;

			DMibNamedAsMemberFunction only_parameters_aliased malloc_like static auto f_AllocWithSizeDebug
				(
					umint &_Size
					, ch8 const *_pFile
					, aint _Line
					, EHeapDebugFlag _Flags = EHeapDebugFlag_None
					, EAllocationFlag _AllocFlags = EAllocationFlag_None
					, ENumaNode _NumaNode = ENumaNode_Default
				)
				-> void *
			;
			DMibNamedAsMemberFunction only_parameters_aliased malloc_like static auto f_AllocDebug
				(
					umint _Size
					, ch8 const *_pFile
					, aint _Line
					, EHeapDebugFlag _Flags = EHeapDebugFlag_None
					, EAllocationFlag _AllocFlags = EAllocationFlag_None
					, ENumaNode _NumaNode = ENumaNode_Default
				)
				-> void *
			;
			DMibNamedAsMemberFunction only_parameters_aliased malloc_like static auto f_AllocAlignedWithSizeDebug
				(
					umint &_Size
					, umint _Alignment
					, ch8 const *_pFile
					, aint _Line
					, EHeapDebugFlag _Flags = EHeapDebugFlag_None
					, EAllocationFlag _AllocFlags = EAllocationFlag_None
					, ENumaNode _NumaNode = ENumaNode_Default
				)
				-> void *
			;
			DMibNamedAsMemberFunction only_parameters_aliased malloc_like static auto f_AllocAlignedDebug
				(
					umint _Size
					, umint _Alignment
					, ch8 const *_pFile
					, aint _Line
					, EHeapDebugFlag _Flags = EHeapDebugFlag_None
					, EAllocationFlag _AllocFlags = EAllocationFlag_None
					, ENumaNode _NumaNode = ENumaNode_Default
				)
				-> void *
			;
			DMibNamedAsMemberFunction only_parameters_aliased malloc_like static void *f_AllocWithSize
				(
					umint &_Size
					, EAllocationFlag _AllocFlags = EAllocationFlag_None
					, ENumaNode _NumaNode = ENumaNode_Default
				)
			;
			DMibNamedAsMemberFunction only_parameters_aliased malloc_like static void *f_Alloc
				(
					umint _Size
					, EAllocationFlag _AllocFlags = EAllocationFlag_None
					, ENumaNode _NumaNode = ENumaNode_Default
				)
			;
			DMibNamedAsMemberFunction only_parameters_aliased malloc_like static auto f_AllocAlignedWithSize
				(
					umint &_Size
					, umint _Alignment
					, EAllocationFlag _AllocFlags = EAllocationFlag_None
					, ENumaNode _NumaNode = ENumaNode_Default
				)
				-> void *
			;
			DMibNamedAsMemberFunction only_parameters_aliased malloc_like static auto f_AllocAligned
				(
					umint _Size
					, umint _Alignment
					, EAllocationFlag _AllocFlags = EAllocationFlag_None
					, ENumaNode _NumaNode = ENumaNode_Default
				)
				-> void *
			;
			DMibNamedAsMemberFunction only_parameters_aliased static auto f_AllocSafeWithSize
				(
					umint &_Size
					, umint _Alignment
					, EAllocationFlag _AllocFlags = EAllocationFlag_None
					, ENumaNode _NumaNode = ENumaNode_Default
				)
				-> CAutoDestroy
			;
			DMibNamedAsMemberFunction only_parameters_aliased static auto f_AllocSafe
				(
					umint _Size
					, umint _Alignment
					, EAllocationFlag _AllocFlags = EAllocationFlag_None
					, ENumaNode _NumaNode = ENumaNode_Default
				)
				-> CAutoDestroy
			;
		};

#if DMibConfig_MalterlibMemoryManager_Debug
		using CAllocator = CAllocatorIgnore;
#else
		using CAllocator = NMib::NMemory::CAllocator_NonTrackedHeap;
#endif

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
			uint8 *m_pSystemFunction;                         // the original system function
			uint32 m_nOverwrittenBytes;                       // number of bytes overwritten by the jump
			uint8 *m_pHookFunction;                           // the hook function that we provide
			uint8 m_CodeJumpToHookFunction[mcp_MaxCodeBytes]; // placeholder for code that jumps to the hook function
			// placeholder for code that holds the first few bytes from the system function and a jump to the remainder in the original location
			uint8 m_CodeTrampoline[mcp_MaxCodeBytes];
			uint8 m_CodeUntouched[mcp_MaxCodeBytes]; // placeholder for unmodified original code (we patch IP-relative addressing)
		};

		struct CTrampolinePool
		{
			DMibListLinkDS_List(CFreeTrampoline, m_Link) m_FreeTrampolines;
			zmint m_nUsed;
			umint m_Size;
			CTrampolinePool(void *_pMemory, umint _MemorySize);
			~CTrampolinePool();

			void f_Unprotect();
			void f_Protect();
		};

		NMib::NContainer::TCMap<uint8 *, CTrampolinePool, NMib::CSort_Default, CAllocator> mp_TrampolinePools;

		struct CModuleCache
		{
			umint m_Size;
			bool m_bImage;
		};

		NMib::NContainer::TCMap<umint, CModuleCache, NMib::CSort_Default, CAllocator> mp_ModulesCache;

		NMib::NContainer::TCRegions<uint8 *, NMib::CVoidTag, CAllocator> mp_Unprotected;

		//=========================================================================
		// The patch data structures - store info about rip-relative instructions
		// during hook placement
		struct CRipInfo
		{
			uint32 m_Offset;
			int64 m_Displacement;
		};

		struct CPatchData
		{
			int64 m_LimitUp;
			int64 m_LimitDown;
			uint32 m_nRips;
			CRipInfo m_Rips[mcp_MaxRips];
		};

		//=========================================================================
		// Global vars
		NMib::NThread::CMutual mp_Lock;

		NMib::NContainer::TCMap<void *, CTrampoline *, NMib::CSort_Default, CAllocator> mp_Hooks;
		zmint mp_IsSuspended;

		bool fp_Unprotect(uint8 *_pMem, umint _Size);
		uint8 *fp_SkipJumps(uint8 *_pCode);
		uint8 *fp_EmitJump(uint8 *_pCode, uint8 *_pJumpTo);
		CTrampoline *fp_TrampolineAlloc(uint8 *_pSystemFunction, int64 _LimitUp, int64 _LimitDown);
		CTrampoline *fp_TrampolineGet(uint8 *_pHookedFunction);
		void fp_TrampolineFree(CTrampoline *_pTrampoline, bool _bNeverUsed);
		void fp_FixupIPRelativeAddressing(uint8 *_pNew, uint8 *_pOriginal, CPatchData *_pData);
		uint32 fp_DisassembleAndSkip(void *_pFunction, uint32 _MinLength, CPatchData *o_pData);

		void fp_Suspend();
		void fp_Resume();
	};
}
