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

#ifndef DPlatformFamily_Windows

#include "Malterlib_Instrumentation_FunctionHook.h"
#include "../../SDK/mhook/disasm-lib/disasm.h"

namespace NMib
{
	namespace NInstrumentation
	{
		#if 0
		#	define DMHookTrace DMibTraceSafe
		#else
		#	define DMHookTrace(_Format, _Args) (void)0
		#endif

		//=========================================================================
		// Internal function:
		// 
		// Skip over jumps that lead to the real function. Gets around import
		// jump tables, etc.
		//=========================================================================
		uint8 *CMHook::fp_SkipJumps(uint8 *pbCode) 
		{
			if (this->m_Hooks.f_FindEqual((void *)pbCode))
				return nullptr; // Already mapped
		#if defined(DArchitecture_x86) || defined(DArchitecture_x64)

		#if defined DArchitecture_x64
			if ((pbCode[0] & 0xF0) == 0x40 && pbCode[1] == 0xff && pbCode[2] == 0x25)
			{
				// REX PREFIX, just skip it
				++pbCode;
			}
		#endif

			if (pbCode[0] == 0xff && pbCode[1] == 0x25)
			{
		#ifdef DArchitecture_x86
				// on x86 we have an absolute pointer...
				uint8 *pbTarget = *(uint8 **)&pbCode[2];
				// ... that shows us an absolute pointer.
				return fp_SkipJumps(*(uint8 **)pbTarget);
		#elif defined DArchitecture_x64
				// on x64 we have a 32-bit offset...
				int32 lOffset = *(int32 *)&pbCode[2];
				// ... that shows us an absolute pointer
				return fp_SkipJumps(*(uint8 **)(pbCode + 6 + lOffset));
		#endif
			} 
			else if (pbCode[0] == 0xe9)
			{
				// here the behavior is identical, we have...
				// ...a 32-bit offset to the destination.
				return fp_SkipJumps(pbCode + 5 + *(int32 *)&pbCode[1]);
			} 
			else if (pbCode[0] == 0xeb)
			{
				// and finally an 8-bit offset to the destination
				return fp_SkipJumps(pbCode + 2 + *(int8 *)&pbCode[1]);
			}
		#else
		#	error unsupported platform
		#endif
			return pbCode;
		}

		//=========================================================================
		// Internal function:
		//
		// Writes code at pbCode that jumps to pbJumpTo. Will attempt to do this
		// in as few bytes as possible. Important on x64 where the long jump
		// (0xff 0x25 ....) can take up 14 bytes.
		//=========================================================================
		uint8 *CMHook::fp_EmitJump(uint8 *pbCode, uint8 *pbJumpTo)
		{
		#if defined(DArchitecture_x86) || defined(DArchitecture_x64)
			uint8 *pbJumpFrom = pbCode + 5;
			mint cbDiff = pbJumpFrom > pbJumpTo ? pbJumpFrom - pbJumpTo : pbJumpTo - pbJumpFrom;
			DMHookTrace("mhooks: fp_EmitJump: Jumping from {} to {}, diff is {}{\n}", pbJumpFrom << pbJumpTo << cbDiff);
			if (cbDiff <= 0x7fff0000) {
				pbCode[0] = 0xe9;
				pbCode += 1;
				*((uint32 *)pbCode) = (uint32)(mint)(pbJumpTo - pbJumpFrom);
				pbCode += sizeof(uint32);
			} else {
				// movabs x, eax/rax
		#ifdef DArchitecture_x64
				*pbCode = 0x48;
				++pbCode;
		#endif
				*pbCode = 0xb8;
				++pbCode;
				*((mint *)pbCode) = (mint)(pbJumpTo);
				pbCode += sizeof(mint);
				// jmp eax/rax
				pbCode[0] = 0xff;
				pbCode[1] = 0xe0;
				pbCode += 2;

			}
		#else 
		#	error unsupported platform
		#endif
			return pbCode;
		}

		//=========================================================================
		// Internal function:
		//
		// Will try to allocate the trampoline structure within 2 gigabytes of
		// the target function. 
		//=========================================================================

		CMHook::CTrampolinePool::CTrampolinePool(void *_pMemory, mint _MemorySize)
		{
			mint nTrampoline = _MemorySize / sizeof(CTrampoline);
			m_Size = nTrampoline * sizeof(CTrampoline);

			CTrampoline *pTrampolines = (CTrampoline *)_pMemory;

			for (mint i = 0; i < nTrampoline; ++i)
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

			mint Size = NMem::CAllocator_VirtualNoTracking::f_SizePadded(1);
			NMem::CAllocator_VirtualNoTracking::f_Free(pStart, Size);
		}

		CMHook::CTrampoline *CMHook::fp_TrampolineAlloc(uint8 *pSystemFunction, int64 nLimitUp, int64 nLimitDown) 
		{
			uint8 *pLower = pSystemFunction + nLimitUp;
			pLower = pLower < (uint8 *)(mint)0x0000000080000000 ? (uint8 *)(0x1) : (uint8 *)(pLower - (uint8 *)0x7fff0000);
			uint8 *pUpper = pSystemFunction + nLimitDown;
			pUpper = pUpper < (uint8 *)(mint)0xffffffff80000000 ? (uint8 *)(pUpper + (mint)0x7ff80000) : (uint8 *)(mint)0xfffffffffff80000;

			for (auto iPool = m_TrampolinePools.f_GetIterator_SmallestGreaterThanEqual(pLower); iPool; ++iPool)
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
						NMem::fg_MemClear(*pTrampoline);
						pTrampoline->m_pPool = pPool;
						m_Hooks[pTrampoline->codeTrampoline] = pTrampoline;
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
				DMHookTrace("mhooks: fp_TrampolineAlloc: Allocating for {} between {} and {}{\n}", pSystemFunction << pLower << pUpper);

				mint Size = NMem::CAllocator_VirtualNoTracking::f_SizePadded(sizeof(CTrampoline));
				pMemory = (uint8 *)NSys::fg_Mem_VirtualAllocInRange(Size, pLower, pUpper, EAllocationFlag_WillFreeWithSize);

				// found and allocated a trampoline?
				if (pMemory) 
				{
					auto Mapped = m_TrampolinePools(pMemory, pMemory, Size);

					auto *pPool = &*Mapped;
					
					auto *pFreeTrampoline = pPool->m_FreeTrampolines.f_GetFirst();
					if (pFreeTrampoline)
					{
						pFreeTrampoline->m_Link.f_Unlink();
						CTrampoline *pTrampoline = (CTrampoline *)pFreeTrampoline;
						NMem::fg_MemClear(*pTrampoline);
						pTrampoline->m_pPool = pPool;
						m_Hooks[pTrampoline->codeTrampoline] = pTrampoline;
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

		CMHook::CTrampoline *CMHook::fp_TrampolineGet(uint8 *pHookedFunction) 
		{

			auto iFind = m_Hooks.f_FindEqual(pHookedFunction);
			if (iFind)
				return *iFind;
			return nullptr;
		}

		//=========================================================================
		// Internal function:
		//
		// Free a trampoline structure.
		//=========================================================================
		void CMHook::fp_TrampolineFree(CTrampoline *pTrampoline, bool bNeverUsed) 
		{
			m_Hooks.f_Remove(pTrampoline->codeTrampoline);
			auto pPool = pTrampoline->m_pPool;

			CFreeTrampoline *pFree = new(pTrampoline) CFreeTrampoline();
			pPool->m_FreeTrampolines.f_InsertLast(pFree);

			if ((--pPool->m_nUsed) == 0)
				m_TrampolinePools.f_Remove(pPool);
		}

		CMHook::CMHook()
		{
		}

		//=========================================================================
		// if IP-relative addressing has been detected, fix up the code so the
		// offset points to the original location
		void CMHook::fp_FixupIPRelativeAddressing(uint8 *pbNew, uint8 *pbOriginal, CPatchData* pdata)
		{
		#if defined DArchitecture_x64
			int64 diff = pbNew - pbOriginal;
			for (uint32 i = 0; i < pdata->nRipCnt; i++) {
				uint32 dwNewDisplacement = (uint32)(pdata->rips[i].nDisplacement - diff);
				DMHookTrace("mhooks: fixing up RIP instruction operand for code at 0x{}: "
					"old displacement: 0x{nfh,sj8,sf0}, new displacement: 0x{nfh,sj8,sf0}{\n}", 
					(pbNew + pdata->rips[i].dwOffset)
					<< pdata->rips[i].nDisplacement
					<< dwNewDisplacement);
				*(uint32 *)(pbNew + pdata->rips[i].dwOffset) = dwNewDisplacement;
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
		uint32 CMHook::fp_DisassembleAndSkip(void * pFunction, uint32 dwMinLen, CPatchData* pdata)
		{
			uint32 dwRet = 0;
			pdata->nLimitDown = 0;
			pdata->nLimitUp = 0;
			pdata->nRipCnt = 0;
		#ifdef DArchitecture_x86
			ARCHITECTURE_TYPE arch = ARCH_X86;
		#elif defined DArchitecture_x64
			ARCHITECTURE_TYPE arch = ARCH_X64;
		#else
			#error unsupported platform
		#endif
			DISASSEMBLER dis;
			if (InitDisassembler(&dis, arch)) 
			{
				INSTRUCTION* pins = NULL;
				U8* pLoc = (U8*)pFunction;
				uint32 dwFlags = DISASM_DECODE | DISASM_ALIGNOUTPUT | DISASM_SUPPRESSERRORS; // DISASM_DISASSEMBLE | 
		#ifdef DMibDebug
		//		dwFlags |= DISASM_DISASSEMBLE;
		#endif

				DMHookTrace("mhooks:	: Disassembling {}{\n}", pLoc);
				while ( (dwRet < dwMinLen) && (pins = GetInstruction(&dis, (ULONG_PTR)pLoc, pLoc, dwFlags)) ) {
					DMHookTrace("mhooks: fp_DisassembleAndSkip: {}: {}{\n}", pLoc << pins->String);
					if (pins->Type == ITYPE_RET		) break;
					if (pins->Type == ITYPE_BRANCH	) break;
					if (pins->Type == ITYPE_BRANCHCC) break;
					if (pins->Type == ITYPE_CALL	) break;
					if (pins->Type == ITYPE_CALLCC	) break;

					#if defined DArchitecture_x64
						bool bProcessRip = false;
						// mov or lea to/from register to/from rip+imm32
						if 
							(
								(pins->Type == ITYPE_MOV || pins->Type == ITYPE_LEA) 
								&& (pins->X86.Relative) 
								&& (pins->OperandCount == 2)
								&&
								(
									(
										(pins->Operands[0].Flags & OP_IPREL) 
										&& 
										(
											pins->Operands[0].Register == AMD64_REG_RIP
											|| pins->Operands[0].Register == X86_REG_EIP
										)
									)
									||
									(
										(pins->Operands[1].Flags & OP_IPREL) 
										&& 
										(
											pins->Operands[1].Register == AMD64_REG_RIP
											|| pins->Operands[1].Register == X86_REG_EIP
										)
									)
								)
							)
						{
							// rip-addressing "mov reg, [rip+imm32]"
							// rip-addressing "mov [rip+imm32], reg"
							DMHookTrace("mhooks: fp_DisassembleAndSkip: found OP_IPREL on operand {} with displacement 0x{nfh,sj8,sf0} (in memory: {}){\n}", 1 << pins->X86.Displacement << *(int32 *)(pLoc+(pins->Length - 4)));
							bProcessRip = true;
						}
						else if ( (pins->OperandCount >= 1) && (pins->Operands[0].Flags & OP_IPREL) )
						{
							// unsupported rip-addressing
							DMHookTrace("mhooks: fp_DisassembleAndSkip: found unsupported OP_IPREL on operand {} at {}{\n}", 0 << pLoc);
							// dump instruction bytes to the debug output
							for (uint32 i=0; i<pins->Length; i++) {
								DMHookTrace("mhooks: fp_DisassembleAndSkip: instr byte {sj2,sf0}: 0x{nfh,sj2,sf0}{\n}", i << pLoc[i]);
							}
							break;
						}
						else if ( (pins->OperandCount >= 2) && (pins->Operands[1].Flags & OP_IPREL) )
						{
							// unsupported rip-addressing
							DMHookTrace("mhooks: fp_DisassembleAndSkip: found unsupported OP_IPREL on operand {} at {}{\n}", 1 << pLoc);
							// dump instruction bytes to the debug output
							for (uint32 i=0; i<pins->Length; i++) {
								DMHookTrace("mhooks: fp_DisassembleAndSkip: instr byte {sj2,sf0}: 0x{nfh,sj2,sf0}{\n}", i << pLoc[i]);
							}
							break;
						}
						else if ( (pins->OperandCount >= 3) && (pins->Operands[2].Flags & OP_IPREL) )
						{
							// unsupported rip-addressing
							DMHookTrace("mhooks: fp_DisassembleAndSkip: found unsupported OP_IPREL on operand {} at {}{\n}", 2 << pLoc);
							// dump instruction bytes to the debug output
							for (uint32 i=0; i<pins->Length; i++) {
								DMHookTrace("mhooks: fp_DisassembleAndSkip: instr byte {sj2,sf0}: 0x{nfh,sj2,sf0}{\n}", i << pLoc[i]);
							}
							break;
						}
						// follow through with RIP-processing if needed
						if (bProcessRip) {
							// calculate displacement relative to function start
							int64 nAdjustedDisplacement = pins->X86.Displacement + (pLoc - (U8*)pFunction);
							// store displacement values furthest from zero (both positive and negative)
							if (nAdjustedDisplacement < pdata->nLimitDown)
								pdata->nLimitDown = nAdjustedDisplacement;
							if (nAdjustedDisplacement > pdata->nLimitUp)
								pdata->nLimitUp = nAdjustedDisplacement;
							// store patch info
							if (pdata->nRipCnt < EMaxRips) {
								pdata->rips[pdata->nRipCnt].dwOffset = dwRet + (pins->Length - 4);
								pdata->rips[pdata->nRipCnt].nDisplacement = pins->X86.Displacement;
								pdata->nRipCnt++;
							} else {
								// no room for patch info, stop disassembly
								break;
							}
						}
					#endif

					dwRet += pins->Length;
					pLoc  += pins->Length;
				}

				CloseDisassembler(&dis);
			}

			return dwRet;
		}

		bool CMHook::fp_Unprotect(uint8 *_pMem, mint _Size)
		{
			uint8 *pStart = fg_AlignDown(_pMem, 4096);
			uint8 *pEnd = fg_AlignUp(_pMem + _Size, 4096);

			NContainer::TCRegions<uint8 *, zbool, NMem::CAllocator_NonTrackedHeap> ToAdd;
			ToAdd.f_MakeRegion(pStart, pEnd);

			for (auto iRegion = m_Unprotected.f_GetIterator(pStart); iRegion; ++iRegion)
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
					mint Size = iRegion->f_End() - iRegion->f_Start();
					try
					{
						NSys::fg_Mem_VirtualProtect(pStart, Size, EProtect_Exec | EProtect_Read | EProtect_Write);
						m_Unprotected.f_MakeRegion(iRegion->f_Start(), iRegion->f_End());
					}
					catch (NException::CException const& _Exception)
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
		bool CMHook::f_SetHook(void * *ppSystemFunction, void * pHookFunction) 
		{
			CTrampoline *pTrampoline = NULL;
			void * pSystemFunction = *ppSystemFunction;
			// ensure thread-safety
			DMibLock(m_Lock);
			DMHookTrace("mhooks: Mhook_SetHook: Started on the job: {} / {}{\n}", pSystemFunction << pHookFunction);
			// find the real functions (jump over jump tables, if any)
			pSystemFunction = fp_SkipJumps((uint8 *)pSystemFunction);
			pHookFunction   = fp_SkipJumps((uint8 *)pHookFunction);
			if (!pSystemFunction || !pHookFunction)
				return false;
			DMHookTrace("mhooks: Mhook_SetHook: Started on the job: {} / {}{\n}", pSystemFunction << pHookFunction);
			// figure out the length of the overwrite zone
			CPatchData patchdata = {0};
			uint32 dwInstructionLength = fp_DisassembleAndSkip(pSystemFunction, EJmpSize, &patchdata);
			if (dwInstructionLength >= EJmpSize) {
				DMHookTrace("mhooks: Mhook_SetHook: disassembly signals {} bytes{\n}", dwInstructionLength);
				// suspend every other thread in this process, and make sure their IP 
				// is not in the code we're about to overwrite.
				bool bSuspend = !m_IsSuspended;
				if (bSuspend)
					fp_Suspend();
				// allocate a trampoline structure (TODO: it is pretty wasteful to get
				// VirtualAlloc to grab chunks of memory smaller than 100 bytes)
				pTrampoline = fp_TrampolineAlloc((uint8 *)pSystemFunction, patchdata.nLimitUp, patchdata.nLimitDown);
				if (pTrampoline) {
					DMHookTrace("mhooks: Mhook_SetHook: allocated structure at {}{\n}", pTrampoline);
					// set the system function to PAGE_EXECUTE_READWRITE
					if (fp_Unprotect((uint8 *)pSystemFunction, dwInstructionLength)) {
						DMHookTrace("mhooks: Mhook_SetHook: readwrite set on system function{\n}", 0);
						// mark our trampoline buffer to PAGE_EXECUTE_READWRITE
						// create our trampoline function
						uint8 *pbCode = pTrampoline->codeTrampoline;
						// save original code..
						for (uint32 i = 0; i<dwInstructionLength; i++) {
							pTrampoline->codeUntouched[i] = pbCode[i] = ((uint8 *)pSystemFunction)[i];
						}
						pbCode += dwInstructionLength;
						// plus a jump to the continuation in the original location
						pbCode = fp_EmitJump(pbCode, ((uint8 *)pSystemFunction) + dwInstructionLength);
						DMHookTrace("mhooks: Mhook_SetHook: updated the trampoline{\n}", 0);

						DMibFastCheck(pbCode <= pTrampoline->codeTrampoline + EMaxCodeBytes);

						// fix up any IP-relative addressing in the code
						fp_FixupIPRelativeAddressing(pTrampoline->codeTrampoline, (uint8 *)pSystemFunction, &patchdata);

						mint dwDistance = (uint8 *)pHookFunction < (uint8 *)pSystemFunction ? 
							(uint8 *)pSystemFunction - (uint8 *)pHookFunction : (uint8 *)pHookFunction - (uint8 *)pSystemFunction;
						if (dwDistance > 0x7fff0000) {
							// create a stub that jumps to the replacement function.
							// we need this because jumping from the API to the hook directly 
							// will be a long jump, which is 14 bytes on x64, and we want to 
							// avoid that - the API may or may not have room for such stuff. 
							// (remember, we only have 5 bytes guaranteed in the API.)
							// on the other hand we do have room, and the trampoline will always be
							// within +/- 2GB of the API, so we do the long jump in there. 
							// the API will jump to the "reverse trampoline" which
							// will jump to the user's hook code.
							pbCode = pTrampoline->codeJumpToHookFunction;
							pbCode = fp_EmitJump(pbCode, (uint8 *)pHookFunction);
							DMibFastCheck(pbCode <= pTrampoline->codeJumpToHookFunction + EMaxCodeBytes);

							DMHookTrace("mhooks: Mhook_SetHook: created reverse trampoline{\n}", 0);
							NSys::fg_Mem_VirtualFlushInstructionCache(pTrampoline->codeJumpToHookFunction, pbCode - pTrampoline->codeJumpToHookFunction);

							// update the API itself
							pbCode = (uint8 *)pSystemFunction;
							pbCode = fp_EmitJump(pbCode, pTrampoline->codeJumpToHookFunction);
							DMibFastCheck(pbCode <= (uint8 *)pSystemFunction + EJmpSize);
						} else {
							// the jump will be at most 5 bytes so we can do it directly
							// update the API itself
							pbCode = (uint8 *)pSystemFunction;
							pbCode = fp_EmitJump(pbCode, (uint8 *)pHookFunction);
							DMibFastCheck(pbCode <= (uint8 *)pSystemFunction + EJmpSize);
						}

						// update data members
						pTrampoline->cbOverwrittenCode = dwInstructionLength;
						pTrampoline->pSystemFunction = (uint8 *)pSystemFunction;
						pTrampoline->pHookFunction = (uint8 *)pHookFunction;

						// flush instruction cache
						NSys::fg_Mem_VirtualFlushInstructionCache(pTrampoline->codeTrampoline, dwInstructionLength);
						// flush instruction cache and restore original protection
						NSys::fg_Mem_VirtualFlushInstructionCache(pSystemFunction, dwInstructionLength);
					} else {
						DMHookTrace("mhooks: Mhook_SetHook: failed VirtualProtectEx 1: {}{\n}", 0);
					}
					if (pTrampoline->pSystemFunction) {
						// this is what the application will use as the entry point
						// to the "original" unhooked function.
						*ppSystemFunction = pTrampoline->codeTrampoline;
						DMHookTrace("mhooks: Mhook_SetHook: Hooked the function!{\n}", 0);
					} else {
						// if we failed discard the trampoline (forcing VirtualFree)
						fp_TrampolineFree(pTrampoline, true);
						pTrampoline = NULL;
					}
				}
				if (bSuspend)
					fp_Resume();
			} else {
				DMHookTrace("mhooks: disassembly signals {} bytes (unacceptable){\n}", dwInstructionLength);
			}
			return (pTrampoline != NULL);
		}

		//=========================================================================
		bool CMHook::f_Unhook(void * *ppHookedFunction)
		{
			DMHookTrace("mhooks: Mhook_Unhook: {}{\n}", *ppHookedFunction);
			bool bRet = false;
			DMibLock(m_Lock);
			// get the trampoline structure that corresponds to our function
			CTrampoline *pTrampoline = fp_TrampolineGet((uint8 *)*ppHookedFunction);
			if (pTrampoline) {
				bool bSuspend = !m_IsSuspended;
				if (bSuspend)
					fp_Suspend();
				DMHookTrace("mhooks: Mhook_Unhook: found struct at {}{\n}", pTrampoline);
				// make memory writable
				if (fp_Unprotect((uint8 *)pTrampoline->pSystemFunction, pTrampoline->cbOverwrittenCode)) 
				{
					DMHookTrace("mhooks: Mhook_Unhook: readwrite set on system function{\n}", 0);
					uint8 *pbCode = (uint8 *)pTrampoline->pSystemFunction;
					for (uint32 i = 0; i<pTrampoline->cbOverwrittenCode; i++) {
						pbCode[i] = pTrampoline->codeUntouched[i];
					}
					// flush instruction cache and make memory unwritable
					NSys::fg_Mem_VirtualFlushInstructionCache(pTrampoline->pSystemFunction, pTrampoline->cbOverwrittenCode);
					// return the original function pointer
					*ppHookedFunction = pTrampoline->pSystemFunction;
					bRet = true;
					DMHookTrace("mhooks: Mhook_Unhook: sysfunc: {}{\n}", *ppHookedFunction);
					fp_TrampolineFree(pTrampoline, false);
					DMHookTrace("mhooks: Mhook_Unhook: unhook successful{\n}", 0);
				} 
				else 
				{
					DMHookTrace("mhooks: Mhook_Unhook: failed VirtualProtectEx 1: {}{\n}", 0);
				}
				if (bSuspend)
					fp_Resume();
			}
			else
			{
				DMHookTrace("mhooks: No such trapoline{\n}", 0);
			}
			return bRet;
		}

		void CMHook::f_Suspend()
		{
			m_Lock.f_Lock();
			fp_Suspend();
		}
		void CMHook::f_Resume()
		{
			fp_Resume();
			m_Lock.f_Unlock();
		}

		void CMHook::fp_Suspend() 
		{
			DMibFastCheck(m_IsSuspended == 0);
			++m_IsSuspended;

			for (auto iPool = m_TrampolinePools.f_GetIterator(); iPool; ++iPool)
				iPool->f_Unprotect();
		}

		void CMHook::fp_Resume() 
		{
			--m_IsSuspended;
			// Protect data
			for (auto iPool = m_TrampolinePools.f_GetIterator(); iPool; ++iPool)
				iPool->f_Protect();
		}
	}
}

#endif
