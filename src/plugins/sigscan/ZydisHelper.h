/*
 * MacroQuest: The extension platform for EverQuest
 * Copyright (C) 2002-present MacroQuest Authors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2, as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#pragma once

#include <Zydis/Zydis.h>

#include <cstdint>
#include <vector>
#include <string>

namespace sigscan {

struct InstructionInfo
{
	size_t offset;       // offset from start of buffer
	size_t length;       // instruction length in bytes
	bool hasRipRelative; // has a RIP-relative memory operand
	size_t ripDispOffset;  // offset of the RIP displacement within the instruction
	size_t ripDispSize;    // size of displacement (always 4 for x64)
	bool hasRel32;       // has a relative branch (E8 call, E9 jmp, 0F 8x Jcc)
	size_t rel32Offset;    // offset of the rel32 within the instruction
	bool hasLargeImm;    // has an immediate >= 0x1000 (likely an address or changeable constant)
	size_t immOffset;      // offset of the immediate within the instruction
	size_t immSize;        // size of the immediate
};

class ZydisHelper
{
public:
	ZydisHelper()
	{
		ZydisDecoderInit(&m_decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
	}

	// Decode instructions from a buffer, returning info about each
	std::vector<InstructionInfo> DecodeBuffer(const uint8_t* data, size_t length, uintptr_t runtimeAddress = 0) const
	{
		std::vector<InstructionInfo> results;
		size_t offset = 0;

		while (offset < length)
		{
			ZydisDecodedInstruction instruction;
			ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

			ZyanStatus status = ZydisDecoderDecodeFull(
				&m_decoder, data + offset, length - offset,
				&instruction, operands);

			if (!ZYAN_SUCCESS(status))
				break;

			InstructionInfo info = {};
			info.offset = offset;
			info.length = instruction.length;

			AnalyzeOperands(data + offset, instruction, operands, info);

			results.push_back(info);
			offset += instruction.length;
		}

		return results;
	}

private:
	void AnalyzeOperands(const uint8_t* instrBytes, const ZydisDecodedInstruction& insn,
		const ZydisDecodedOperand* operands, InstructionInfo& info) const
	{
		// Check for RIP-relative memory operands
		for (int i = 0; i < insn.operand_count; ++i)
		{
			const auto& op = operands[i];

			if (op.type == ZYDIS_OPERAND_TYPE_MEMORY &&
				op.mem.base == ZYDIS_REGISTER_RIP &&
				insn.raw.disp.size == 32)
			{
				info.hasRipRelative = true;
				info.ripDispOffset = insn.raw.disp.offset;
				info.ripDispSize = 4;
			}

			if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && op.imm.is_relative)
			{
				info.hasRel32 = true;
				info.rel32Offset = insn.raw.imm[0].offset;
			}

			if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && !op.imm.is_relative)
			{
				uint64_t immVal = op.imm.is_signed
					? static_cast<uint64_t>(static_cast<int64_t>(op.imm.value.s))
					: op.imm.value.u;

				if (immVal >= 0x1000 && insn.raw.imm[0].size >= 32)
				{
					info.hasLargeImm = true;
					info.immOffset = insn.raw.imm[0].offset;
					info.immSize = insn.raw.imm[0].size / 8;
				}
			}
		}
	}

	ZydisDecoder m_decoder;
};

} // namespace sigscan
