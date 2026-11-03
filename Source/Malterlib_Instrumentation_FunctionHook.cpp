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

#ifndef DPlatformFamily_Windows

#include "Malterlib_Instrumentation_FunctionHook.h"
#include "../../../External/mhook/disasm-lib/disasm.h"

namespace NMib::NInstrumentation
{
#if 0
#	define DMHookTrace DMibTraceSafe
#else
#	define DMHookTrace(d_Format, d_Args) (void)0
#endif

	only_parameters_aliased malloc_like auto CMHook::CAllocatorIgnore::f_AllocWithSizeDebug
		(
			umint &_Size
			, ch8 const *_pFile
			, aint _Line
			, EHeapDebugFlag _Flags
			, EAllocationFlag _AllocFlags
			, ENumaNode _NumaNode
		)
		-> void *
	{
		return CAllocator_NonTrackedHeap::f_AllocWithSizeDebug(_Size, _pFile, _Line, _Flags | EHeapDebugFlag_Ignore, _AllocFlags, _NumaNode);
	}

	only_parameters_aliased malloc_like auto CMHook::CAllocatorIgnore::f_AllocDebug
		(
			umint _Size
			, ch8 const *_pFile
			, aint _Line
			, EHeapDebugFlag _Flags
			, EAllocationFlag _AllocFlags
			, ENumaNode _NumaNode
		)
		-> void *
	{
		return CAllocator_NonTrackedHeap::f_AllocDebug(_Size, _pFile, _Line, _Flags | EHeapDebugFlag_Ignore, _AllocFlags, _NumaNode);
	}

	only_parameters_aliased malloc_like auto CMHook::CAllocatorIgnore::f_AllocAlignedWithSizeDebug
		(
			umint &_Size
			, umint _Alignment
			, ch8 const *_pFile
			, aint _Line
			, EHeapDebugFlag _Flags
			, EAllocationFlag _AllocFlags
			, ENumaNode _NumaNode
		)
		-> void *
	{
		return CAllocator_NonTrackedHeap::f_AllocAlignedWithSizeDebug(_Size, _Alignment, _pFile, _Line, _Flags | EHeapDebugFlag_Ignore, _AllocFlags, _NumaNode);
	}

	only_parameters_aliased malloc_like auto CMHook::CAllocatorIgnore::f_AllocAlignedDebug
		(
			umint _Size
			, umint _Alignment
			, ch8 const *_pFile
			, aint _Line
			, EHeapDebugFlag _Flags
			, EAllocationFlag _AllocFlags
			, ENumaNode _NumaNode
		)
		-> void *
	{
		return CAllocator_NonTrackedHeap::f_AllocAlignedDebug(_Size, _Alignment, _pFile, _Line, _Flags | EHeapDebugFlag_Ignore, _AllocFlags, _NumaNode);
	}

	only_parameters_aliased malloc_like void *CMHook::CAllocatorIgnore::f_AllocWithSize(umint &_Size, EAllocationFlag _AllocFlags, ENumaNode _NumaNode)
	{
		return CAllocator_NonTrackedHeap::f_AllocWithSizeDebug(_Size, DMibPFile, DMibPLine, EHeapDebugFlag_Ignore, _AllocFlags, _NumaNode);
	}

	only_parameters_aliased malloc_like void *CMHook::CAllocatorIgnore::f_Alloc(umint _Size, EAllocationFlag _AllocFlags, ENumaNode _NumaNode)
	{
		return CAllocator_NonTrackedHeap::f_AllocDebug(_Size, DMibPFile, DMibPLine, EHeapDebugFlag_Ignore, _AllocFlags, _NumaNode);
	}

	only_parameters_aliased malloc_like auto CMHook::CAllocatorIgnore::f_AllocAlignedWithSize(umint &_Size, umint _Alignment, EAllocationFlag _AllocFlags, ENumaNode _NumaNode) -> void *
	{
		return CAllocator_NonTrackedHeap::f_AllocAlignedWithSizeDebug(_Size, _Alignment, DMibPFile, DMibPLine, EHeapDebugFlag_Ignore, _AllocFlags, _NumaNode);
	}

	only_parameters_aliased malloc_like auto CMHook::CAllocatorIgnore::f_AllocAligned(umint _Size, umint _Alignment, EAllocationFlag _AllocFlags, ENumaNode _NumaNode) -> void *
	{
		return CAllocator_NonTrackedHeap::f_AllocAlignedDebug(_Size, _Alignment, DMibPFile, DMibPLine, EHeapDebugFlag_Ignore, _AllocFlags, _NumaNode);
	}

	only_parameters_aliased auto CMHook::CAllocatorIgnore::f_AllocSafeWithSize(umint &_Size, umint _Alignment, EAllocationFlag _AllocFlags, ENumaNode _NumaNode) -> CAutoDestroy
	{
		CAutoDestroy AutoDestroy;
		AutoDestroy.m_pMemory = f_AllocAlignedWithSize(_Size, _Alignment, _AllocFlags, _NumaNode);
		AutoDestroy.m_Size = _Size;

		return fg_Move(AutoDestroy);
	}

	only_parameters_aliased auto CMHook::CAllocatorIgnore::f_AllocSafe(umint _Size, umint _Alignment, EAllocationFlag _AllocFlags, ENumaNode _NumaNode) -> CAutoDestroy
	{
		CAutoDestroy AutoDestroy;
		AutoDestroy.m_pMemory = f_AllocAligned(_Size, _Alignment, _AllocFlags, _NumaNode);
		AutoDestroy.m_Size = _Size;

		return fg_Move(AutoDestroy);
	}

	//=========================================================================
	// Internal function:
	//
	// Skip over jumps that lead to the real function. Gets around import
	// jump tables, etc.
	//=========================================================================
	uint8 *CMHook::fp_SkipJumps(uint8 *_pCode)
	{
		if (this->mp_Hooks.f_FindEqual((void *)_pCode))
			return nullptr; // Already mapped
#if defined(DArchitecture_x86) || defined(DArchitecture_x64)

#	if defined DArchitecture_x64
		if ((_pCode[0] & 0xF0) == 0x40 && _pCode[1] == 0xff && _pCode[2] == 0x25)
		{
			// REX PREFIX, just skip it
			++_pCode;
		}
#	endif

		if (_pCode[0] == 0xff && _pCode[1] == 0x25)
		{
#	ifdef DArchitecture_x86
			// on x86 we have an absolute pointer...
			uint8 *pTarget = *(uint8 **)&_pCode[2];
			// ... that shows us an absolute pointer.
			return fp_SkipJumps(*(uint8 **)pTarget);
#	elif defined DArchitecture_x64
			// on x64 we have a 32-bit offset...
			int32 Offset = *(int32 *)&_pCode[2];
			// ... that shows us an absolute pointer
			return fp_SkipJumps(*(uint8 **)(_pCode + 6 + Offset));
#	endif
		}
		else if (_pCode[0] == 0xe9)
		{
			// here the behavior is identical, we have...
			// ...a 32-bit offset to the destination.
			return fp_SkipJumps(_pCode + 5 + *(int32 *)&_pCode[1]);
		}
		else if (_pCode[0] == 0xeb)
		{
			// and finally an 8-bit offset to the destination
			return fp_SkipJumps(_pCode + 2 + *(int8 *)&_pCode[1]);
		}
#else
#	error unsupported platform
#endif
		return _pCode;
	}

	//=========================================================================
	// Internal function:
	//
	// Writes code at _pCode that jumps to _pJumpTo. Will attempt to do this
	// in as few bytes as possible. Important on x64 where the long jump
	// (0xff 0x25 ....) can take up 14 bytes.
	//=========================================================================
	uint8 *CMHook::fp_EmitJump(uint8 *_pCode, uint8 *_pJumpTo)
	{
#if defined(DArchitecture_x86) || defined(DArchitecture_x64)
		uint8 *pJumpFrom = _pCode + 5;
		umint nDistanceBytes = pJumpFrom > _pJumpTo ? pJumpFrom - _pJumpTo : _pJumpTo - pJumpFrom;
		DMHookTrace("mhooks: fp_EmitJump: Jumping from {} to {}, diff is {}{\n}", pJumpFrom, _pJumpTo, nDistanceBytes);
		if (nDistanceBytes <= 0x7fff0000)
		{
			_pCode[0] = 0xe9;
			_pCode += 1;
			*((uint32 *)_pCode) = (uint32)(umint)(_pJumpTo - pJumpFrom);
			_pCode += sizeof(uint32);
		}
		else
		{
			// movabs x, eax/rax
#	ifdef DArchitecture_x64
			*_pCode = 0x48;
			++_pCode;
#	endif
			*_pCode = 0xb8;
			++_pCode;
			*((umint *)_pCode) = (umint)(_pJumpTo);
			_pCode += sizeof(umint);
			// jmp eax/rax
			_pCode[0] = 0xff;
			_pCode[1] = 0xe0;
			_pCode += 2;
		}
#else
#	error unsupported platform
#endif
		return _pCode;
	}

	//=========================================================================
	// Internal function:
	//
	// Will try to allocate the trampoline structure within 2 gigabytes of
	// the target function.
	//=========================================================================

	CMHook::CTrampolinePool::CTrampolinePool(void *_pMemory, umint _MemorySize)
	{
		umint nTrampolines = _MemorySize / sizeof(CTrampoline);
		m_Size = nTrampolines * sizeof(CTrampoline);

		CTrampoline *pTrampolines = (CTrampoline *)_pMemory;

		for (umint i = 0; i < nTrampolines; ++i)
		{
			auto pData = &pTrampolines[i];

			CFreeTrampoline *pFree = new(pData) CFreeTrampoline();

			m_FreeTrampolines.f_InsertLast(pFree);
		}
	}

	void CMHook::CTrampolinePool::f_Unprotect()
	{
		uint8 *pStart = NContainer::TCMap<uint8 *, CTrampolinePool>::fs_GetKey(*this);
		NSys::fg_Mem_VirtualProtect(pStart, m_Size, EProtect_Read | EProtect_Write | EProtect_Exec);
	}

	void CMHook::CTrampolinePool::f_Protect()
	{
		uint8 *pStart = NContainer::TCMap<uint8 *, CTrampolinePool>::fs_GetKey(*this);
		NSys::fg_Mem_VirtualProtect(pStart, m_Size, EProtect_Read | EProtect_Exec);
	}

	CMHook::CTrampolinePool::~CTrampolinePool()
	{
		DMibFastCheck(m_nUsed == 0);

		uint8 *pStart = NContainer::TCMap<uint8 *, CTrampolinePool>::fs_GetKey(*this);

		m_FreeTrampolines.f_Clear();

		umint Size = NMemory::CAllocator_VirtualNoTracking::f_SizePadded(sizeof(CTrampoline));
		NMemory::CAllocator_VirtualNoTracking::f_Free(pStart, Size);
	}

	CMHook::CTrampoline *CMHook::fp_TrampolineAlloc(uint8 *_pSystemFunction, int64 _LimitUp, int64 _LimitDown)
	{
		uint8 *pLower = _pSystemFunction + _LimitUp;
		pLower = pLower < (uint8 *)(umint)0x0000000080000000 ? (uint8 *)(0x1) : (uint8 *)(pLower - (uint8 *)0x7fff0000);
		uint8 *pUpper = _pSystemFunction + _LimitDown;
		pUpper = pUpper < (uint8 *)(umint)0xffffffff80000000 ? (uint8 *)(pUpper + (umint)0x7ff80000) : (uint8 *)(umint)0xfffffffffff80000;

		for (auto iPool = mp_TrampolinePools.f_GetIterator_SmallestGreaterThanEqual(pLower); iPool; ++iPool)
		{
			uint8 *pStart = iPool.f_GetKey();
			auto pPool = &*iPool;
			uint8 *pEnd = pStart + iPool->m_Size;
			if (pStart >= pLower && pEnd <= pUpper)
			{
				auto *pFreeTrampoline = pPool->m_FreeTrampolines.f_GetFirst();
				if (pFreeTrampoline)
				{
					pFreeTrampoline->m_Link.f_Unlink();
					CTrampoline *pTrampoline = (CTrampoline *)pFreeTrampoline;
					NMemory::fg_MemClear(*pTrampoline);
					pTrampoline->m_pPool = pPool;
					mp_Hooks[pTrampoline->m_CodeTrampoline] = pTrampoline;
					++pPool->m_nUsed;
					return pTrampoline;
				}
			}
			else if (pStart > pUpper)
				break;
		}

		uint8 *pMemory = NULL;

		// do we have room to store this guy?
		{
			// determine lower and upper bounds for the allocation locations.
			// in the basic scenario this is +/- 2GB but IP-relative instructions
			// found in the original code may require a smaller window.
			DMHookTrace("mhooks: fp_TrampolineAlloc: Allocating for {} between {} and {}{\n}", _pSystemFunction, pLower, pUpper);

			umint Size = NMemory::CAllocator_VirtualNoTracking::f_SizePadded(sizeof(CTrampoline));
			pMemory = (uint8 *)NSys::fg_Mem_VirtualAllocInRange(Size, pLower, pUpper, EAllocationFlag_WillFreeWithSize);

			// found and allocated a trampoline?
			if (pMemory)
			{
				auto Mapped = mp_TrampolinePools(pMemory, pMemory, Size);

				auto *pPool = &*Mapped;

				auto *pFreeTrampoline = pPool->m_FreeTrampolines.f_GetFirst();
				if (pFreeTrampoline)
				{
					pFreeTrampoline->m_Link.f_Unlink();
					CTrampoline *pTrampoline = (CTrampoline *)pFreeTrampoline;
					NMemory::fg_MemClear(*pTrampoline);
					pTrampoline->m_pPool = pPool;
					mp_Hooks[pTrampoline->m_CodeTrampoline] = pTrampoline;
					++pPool->m_nUsed;
					return pTrampoline;
				}
			}
		}

		return nullptr;
	}

	//=========================================================================
	// Internal function:
	//
	// Return the internal trampoline structure that belongs to a hooked function.
	//=========================================================================

	CMHook::CTrampoline *CMHook::fp_TrampolineGet(uint8 *_pHookedFunction)
	{
		auto iFind = mp_Hooks.f_FindEqual(_pHookedFunction);
		if (iFind)
			return *iFind;
		return nullptr;
	}

	//=========================================================================
	// Internal function:
	//
	// Free a trampoline structure.
	//=========================================================================
	void CMHook::fp_TrampolineFree(CTrampoline *_pTrampoline, bool _bNeverUsed)
	{
		mp_Hooks.f_Remove(_pTrampoline->m_CodeTrampoline);
		auto pPool = _pTrampoline->m_pPool;

		CFreeTrampoline *pFree = new(_pTrampoline) CFreeTrampoline();
		pPool->m_FreeTrampolines.f_InsertLast(pFree);

		if ((--pPool->m_nUsed) == 0)
			mp_TrampolinePools.f_Remove(pPool);
	}

	CMHook::CMHook()
	{
	}

	//=========================================================================
	// if IP-relative addressing has been detected, fix up the code so the
	// offset points to the original location
	void CMHook::fp_FixupIPRelativeAddressing(uint8 *_pNew, uint8 *_pOriginal, CPatchData *_pData)
	{
#if defined DArchitecture_x64
		int64 Difference = _pNew - _pOriginal;
		for (uint32 i = 0; i < _pData->m_nRips; i++)
		{
			uint32 NewDisplacement = (uint32)(_pData->m_Rips[i].m_Displacement - Difference);
			DMHookTrace
				(
					"mhooks: fixing up RIP instruction operand for code at 0x{}: "
					"old displacement: 0x{nfh,sj8,sf0}, new displacement: 0x{nfh,sj8,sf0}{\n}"
					, (_pNew + _pData->m_Rips[i].m_Offset) << _pData->m_Rips[i].m_Displacement << NewDisplacement
				)
			;
			*(uint32 *)(_pNew + _pData->m_Rips[i].m_Offset) = NewDisplacement;
		}
#endif
	}

	//=========================================================================
	// Examine the machine code at the target function's entry point, and
	// skip bytes in a way that we'll always end on an instruction boundary.
	// We also detect branches and subroutine calls (as well as returns)
	// at which point disassembly must stop.
	// Finally, detect and collect information on IP-relative instructions
	// that we can patch.
	uint32 CMHook::fp_DisassembleAndSkip(void *_pFunction, uint32 _MinLength, CPatchData *o_pData)
	{
		uint32 SkippedLength = 0;
		o_pData->m_LimitDown = 0;
		o_pData->m_LimitUp = 0;
		o_pData->m_nRips = 0;
#ifdef DArchitecture_x86
		ARCHITECTURE_TYPE Architecture = ARCH_X86;
#elif defined DArchitecture_x64
		ARCHITECTURE_TYPE Architecture = ARCH_X64;
#else
#	error unsupported platform
#endif
		DISASSEMBLER Disassembler;
		if (InitDisassembler(&Disassembler, Architecture))
		{
			INSTRUCTION *pInstruction = NULL;
			U8 *pLoc = (U8 *)_pFunction;
			uint32 Flags = DISASM_DECODE | DISASM_ALIGNOUTPUT | DISASM_SUPPRESSERRORS; // DISASM_DISASSEMBLE |
#ifdef DMibDebug
			// Flags |= DISASM_DISASSEMBLE;
#endif

			DMHookTrace("mhooks:	: Disassembling {}{\n}", pLoc);
			while ((SkippedLength < _MinLength) && (pInstruction = GetInstruction(&Disassembler, (ULONG_PTR)pLoc, pLoc, Flags)))
			{
				DMHookTrace("mhooks: fp_DisassembleAndSkip: {}: {}{\n}", pLoc, pInstruction->String);
				if (pInstruction->Type == ITYPE_RET)
					break;
				if (pInstruction->Type == ITYPE_BRANCH)
					break;
				if (pInstruction->Type == ITYPE_BRANCHCC)
					break;
				if (pInstruction->Type == ITYPE_CALL)
					break;
				if (pInstruction->Type == ITYPE_CALLCC)
					break;

#if defined DArchitecture_x64
				bool bProcessRip = false;
				// mov or lea to/from register to/from rip+imm32
				if
				(
					(pInstruction->Type == ITYPE_MOV || pInstruction->Type == ITYPE_LEA)
					&& (pInstruction->X86.Relative)
					&& (pInstruction->OperandCount == 2)
					&&
					(
						((pInstruction->Operands[0].Flags & OP_IPREL) && (pInstruction->Operands[0].Register == AMD64_REG_RIP || pInstruction->Operands[0].Register == X86_REG_EIP))
						|| ((pInstruction->Operands[1].Flags & OP_IPREL) && (pInstruction->Operands[1].Register == AMD64_REG_RIP || pInstruction->Operands[1].Register == X86_REG_EIP))
					)
				)
				{
					// rip-addressing "mov reg, [rip+imm32]"
					// rip-addressing "mov [rip+imm32], reg"
					DMHookTrace
						(
							"mhooks: fp_DisassembleAndSkip: found OP_IPREL on operand {} with displacement 0x{nfh,sj8,sf0} (in memory: {}){\n}"
							, 1
							, pInstruction->X86.Displacement
							, *(int32 *)(pLoc + (pInstruction->Length - 4))
						)
					;
					bProcessRip = true;
				}
				else if ((pInstruction->OperandCount >= 1) && (pInstruction->Operands[0].Flags & OP_IPREL))
				{
					// unsupported rip-addressing
					DMHookTrace("mhooks: fp_DisassembleAndSkip: found unsupported OP_IPREL on operand {} at {}{\n}", 0, pLoc);
					// dump instruction bytes to the debug output
					for (uint32 i = 0; i < pInstruction->Length; i++)
						DMHookTrace("mhooks: fp_DisassembleAndSkip: instr byte {sj2,sf0}: 0x{nfh,sj2,sf0}{\n}", i, pLoc[i]);
					break;
				}
				else if ((pInstruction->OperandCount >= 2) && (pInstruction->Operands[1].Flags & OP_IPREL))
				{
					// unsupported rip-addressing
					DMHookTrace("mhooks: fp_DisassembleAndSkip: found unsupported OP_IPREL on operand {} at {}{\n}", 1, pLoc);
					// dump instruction bytes to the debug output
					for (uint32 i = 0; i < pInstruction->Length; i++)
						DMHookTrace("mhooks: fp_DisassembleAndSkip: instr byte {sj2,sf0}: 0x{nfh,sj2,sf0}{\n}", i, pLoc[i]);
					break;
				}
				else if ((pInstruction->OperandCount >= 3) && (pInstruction->Operands[2].Flags & OP_IPREL))
				{
					// unsupported rip-addressing
					DMHookTrace("mhooks: fp_DisassembleAndSkip: found unsupported OP_IPREL on operand {} at {}{\n}", 2, pLoc);
					// dump instruction bytes to the debug output
					for (uint32 i = 0; i < pInstruction->Length; i++)
						DMHookTrace("mhooks: fp_DisassembleAndSkip: instr byte {sj2,sf0}: 0x{nfh,sj2,sf0}{\n}", i, pLoc[i]);
					break;
				}
				// follow through with RIP-processing if needed
				if (bProcessRip)
				{
					// calculate displacement relative to function start
					int64 nAdjustedDisplacement = pInstruction->X86.Displacement + (pLoc - (U8 *)_pFunction);
					// store displacement values furthest from zero (both positive and negative)
					if (nAdjustedDisplacement < o_pData->m_LimitDown)
						o_pData->m_LimitDown = nAdjustedDisplacement;
					if (nAdjustedDisplacement > o_pData->m_LimitUp)
						o_pData->m_LimitUp = nAdjustedDisplacement;
					// store patch info
					if (o_pData->m_nRips < mcp_MaxRips)
					{
						o_pData->m_Rips[o_pData->m_nRips].m_Offset = SkippedLength + (pInstruction->Length - 4);
						o_pData->m_Rips[o_pData->m_nRips].m_Displacement = pInstruction->X86.Displacement;
						o_pData->m_nRips++;
					}
					else
					{
						// no room for patch info, stop disassembly
						break;
					}
				}
#endif

				SkippedLength += pInstruction->Length;
				pLoc += pInstruction->Length;
			}

			CloseDisassembler(&Disassembler);
		}

		return SkippedLength;
	}

	bool CMHook::fp_Unprotect(uint8 *_pMem, umint _Size)
	{
		uint8 *pStart = fg_AlignDown(_pMem, 4096);
		uint8 *pEnd = fg_AlignUp(_pMem + _Size, 4096);

		NContainer::TCRegions<uint8 *, zbool, NMemory::CAllocator_NonTrackedHeap> ToAdd;
		ToAdd.f_MakeRegion(pStart, pEnd);

		for (auto iRegion = mp_Unprotected.f_GetIterator(pStart); iRegion; ++iRegion)
		{
			if (iRegion->f_End() < pStart)
				continue;
			if (iRegion->f_Start() >= pEnd)
				break;

			auto Start = fg_Max(pStart, iRegion->f_Start());
			auto End = fg_Min(pEnd, iRegion->f_End());
			if (Start != End)
			{
				ToAdd.f_MakeRegion
					(
						Start
						, End
						, [&](zbool &_Region)
						{
							_Region = true;
						}
					)
				;
			}
		}

		bool bSuccess = true;
		for (auto iRegion = ToAdd.f_GetIterator(); iRegion; ++iRegion)
		{
			if (!iRegion->f_Data())
			{
				uint8 *pStart = iRegion->f_Start();
				umint Size = iRegion->f_End() - iRegion->f_Start();
				try
				{
					NSys::fg_Mem_VirtualProtect(pStart, Size, EProtect_Exec | EProtect_Read | EProtect_Write);
					mp_Unprotected.f_MakeRegion(iRegion->f_Start(), iRegion->f_End());
				}
				catch (NException::CException const &_Exception)
				{
					(void)_Exception;
					DMibDTrace("Protect failed {}{\n}", _Exception.f_GetErrorStr());
					bSuccess = false;
				}
			}
		}

		return bSuccess;
	}

	//=========================================================================
	bool CMHook::f_SetHook(void **o_pSystemFunction, void *_pHookFunction)
	{
		CTrampoline *pTrampoline = NULL;
		void *pSystemFunction = *o_pSystemFunction;
		// ensure thread-safety
		DMibLock(mp_Lock);
		DMHookTrace("mhooks: Mhook_SetHook: Started on the job: {} / {}{\n}", pSystemFunction, _pHookFunction);
		// find the real functions (jump over jump tables, if any)
		pSystemFunction = fp_SkipJumps((uint8 *)pSystemFunction);
		_pHookFunction = fp_SkipJumps((uint8 *)_pHookFunction);
		if (!pSystemFunction || !_pHookFunction)
			return false;
		DMHookTrace("mhooks: Mhook_SetHook: Started on the job: {} / {}{\n}", pSystemFunction, _pHookFunction);
		// figure out the length of the overwrite zone
		CPatchData PatchData = {0};
		uint32 InstructionLength = fp_DisassembleAndSkip(pSystemFunction, mcp_JumpSize, &PatchData);
		if (InstructionLength >= mcp_JumpSize)
		{
			DMHookTrace("mhooks: Mhook_SetHook: disassembly signals {} bytes{\n}", InstructionLength);
			// suspend every other thread in this process, and make sure their IP
			// is not in the code we're about to overwrite.
			bool bSuspend = !mp_IsSuspended;
			if (bSuspend)
				fp_Suspend();
			// allocate a trampoline structure (TODO: it is pretty wasteful to get
			// VirtualAlloc to grab chunks of memory smaller than 100 bytes)
			pTrampoline = fp_TrampolineAlloc((uint8 *)pSystemFunction, PatchData.m_LimitUp, PatchData.m_LimitDown);
			if (pTrampoline)
			{
				DMHookTrace("mhooks: Mhook_SetHook: allocated structure at {}{\n}", pTrampoline);
				// set the system function to PAGE_EXECUTE_READWRITE
				if (fp_Unprotect((uint8 *)pSystemFunction, InstructionLength))
				{
					DMHookTrace("mhooks: Mhook_SetHook: readwrite set on system function{\n}", 0);
					// mark our trampoline buffer to PAGE_EXECUTE_READWRITE
					// create our trampoline function
					uint8 *pCode = pTrampoline->m_CodeTrampoline;
					// save original code..
					for (uint32 i = 0; i < InstructionLength; i++)
						pTrampoline->m_CodeUntouched[i] = pCode[i] = ((uint8 *)pSystemFunction)[i];
					pCode += InstructionLength;
					// plus a jump to the continuation in the original location
					pCode = fp_EmitJump(pCode, ((uint8 *)pSystemFunction) + InstructionLength);
					DMHookTrace("mhooks: Mhook_SetHook: updated the trampoline{\n}", 0);

					DMibFastCheck(pCode <= pTrampoline->m_CodeTrampoline + mcp_MaxCodeBytes);

					// fix up any IP-relative addressing in the code
					fp_FixupIPRelativeAddressing(pTrampoline->m_CodeTrampoline, (uint8 *)pSystemFunction, &PatchData);

					umint Distance
						= (uint8 *)_pHookFunction < (uint8 *)pSystemFunction ? (uint8 *)pSystemFunction - (uint8 *)_pHookFunction : (uint8 *)_pHookFunction - (uint8 *)pSystemFunction
					;
					if (Distance > 0x7fff0000)
					{
						// create a stub that jumps to the replacement function.
						// we need this because jumping from the API to the hook directly
						// will be a long jump, which is 14 bytes on x64, and we want to
						// avoid that - the API may or may not have room for such stuff.
						// (remember, we only have 5 bytes guaranteed in the API.)
						// on the other hand we do have room, and the trampoline will always be
						// within +/- 2GB of the API, so we do the long jump in there.
						// the API will jump to the "reverse trampoline" which
						// will jump to the user's hook code.
						pCode = pTrampoline->m_CodeJumpToHookFunction;
						pCode = fp_EmitJump(pCode, (uint8 *)_pHookFunction);
						DMibFastCheck(pCode <= pTrampoline->m_CodeJumpToHookFunction + mcp_MaxCodeBytes);

						DMHookTrace("mhooks: Mhook_SetHook: created reverse trampoline{\n}", 0);
						NSys::fg_Mem_VirtualFlushInstructionCache(pTrampoline->m_CodeJumpToHookFunction, pCode - pTrampoline->m_CodeJumpToHookFunction);

						// update the API itself
						pCode = (uint8 *)pSystemFunction;
						pCode = fp_EmitJump(pCode, pTrampoline->m_CodeJumpToHookFunction);
						DMibFastCheck(pCode <= (uint8 *)pSystemFunction + mcp_JumpSize);
					}
					else
					{
						// the jump will be at most 5 bytes so we can do it directly
						// update the API itself
						pCode = (uint8 *)pSystemFunction;
						pCode = fp_EmitJump(pCode, (uint8 *)_pHookFunction);
						DMibFastCheck(pCode <= (uint8 *)pSystemFunction + mcp_JumpSize);
					}

					// update data members
					pTrampoline->m_nOverwrittenBytes = InstructionLength;
					pTrampoline->m_pSystemFunction = (uint8 *)pSystemFunction;
					pTrampoline->m_pHookFunction = (uint8 *)_pHookFunction;

					// flush instruction cache
					NSys::fg_Mem_VirtualFlushInstructionCache(pTrampoline->m_CodeTrampoline, InstructionLength);
					// flush instruction cache and restore original protection
					NSys::fg_Mem_VirtualFlushInstructionCache(pSystemFunction, InstructionLength);
				}
				else
					DMHookTrace("mhooks: Mhook_SetHook: failed VirtualProtectEx 1: {}{\n}", 0);
				if (pTrampoline->m_pSystemFunction)
				{
					// this is what the application will use as the entry point
					// to the "original" unhooked function.
					*o_pSystemFunction = pTrampoline->m_CodeTrampoline;
					DMHookTrace("mhooks: Mhook_SetHook: Hooked the function!{\n}", 0);
				}
				else
				{
					// if we failed discard the trampoline (forcing VirtualFree)
					fp_TrampolineFree(pTrampoline, true);
					pTrampoline = NULL;
				}
			}
			if (bSuspend)
				fp_Resume();
		}
		else
			DMHookTrace("mhooks: disassembly signals {} bytes (unacceptable){\n}", InstructionLength);
		return (pTrampoline != NULL);
	}

	//=========================================================================
	bool CMHook::f_Unhook(void **o_pHookedFunction)
	{
		DMHookTrace("mhooks: Mhook_Unhook: {}{\n}", *o_pHookedFunction);
		bool bReturn = false;
		DMibLock(mp_Lock);
		// get the trampoline structure that corresponds to our function
		CTrampoline *pTrampoline = fp_TrampolineGet((uint8 *)*o_pHookedFunction);
		if (pTrampoline)
		{
			bool bSuspend = !mp_IsSuspended;
			if (bSuspend)
				fp_Suspend();
			DMHookTrace("mhooks: Mhook_Unhook: found struct at {}{\n}", pTrampoline);
			// make memory writable
			if (fp_Unprotect((uint8 *)pTrampoline->m_pSystemFunction, pTrampoline->m_nOverwrittenBytes))
			{
				DMHookTrace("mhooks: Mhook_Unhook: readwrite set on system function{\n}", 0);
				uint8 *pCode = (uint8 *)pTrampoline->m_pSystemFunction;
				for (uint32 i = 0; i < pTrampoline->m_nOverwrittenBytes; i++)
					pCode[i] = pTrampoline->m_CodeUntouched[i];
				// flush instruction cache and make memory unwritable
				NSys::fg_Mem_VirtualFlushInstructionCache(pTrampoline->m_pSystemFunction, pTrampoline->m_nOverwrittenBytes);
				// return the original function pointer
				*o_pHookedFunction = pTrampoline->m_pSystemFunction;
				bReturn = true;
				DMHookTrace("mhooks: Mhook_Unhook: sysfunc: {}{\n}", *o_pHookedFunction);
				fp_TrampolineFree(pTrampoline, false);
				DMHookTrace("mhooks: Mhook_Unhook: unhook successful{\n}", 0);
			}
			else
				DMHookTrace("mhooks: Mhook_Unhook: failed VirtualProtectEx 1: {}{\n}", 0);
			if (bSuspend)
				fp_Resume();
		}
		else
			DMHookTrace("mhooks: No such trapoline{\n}", 0);
		return bReturn;
	}

	void CMHook::f_Suspend()
	{
		mp_Lock.f_Lock();
		fp_Suspend();
	}

	void CMHook::f_Resume()
	{
		fp_Resume();
		mp_Lock.f_Unlock();
	}

	void CMHook::fp_Suspend()
	{
		DMibFastCheck(mp_IsSuspended == 0);
		++mp_IsSuspended;

		for (auto iPool = mp_TrampolinePools.f_GetIterator(); iPool; ++iPool)
			iPool->f_Unprotect();
	}

	void CMHook::fp_Resume()
	{
		--mp_IsSuspended;
		// Protect data
		for (auto iPool = mp_TrampolinePools.f_GetIterator(); iPool; ++iPool)
			iPool->f_Protect();
	}
}

#endif
