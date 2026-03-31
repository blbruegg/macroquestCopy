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

#include "SigGen.h"

#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cstring>

namespace sigscan {

SigGenerator::SigGenerator()
{
}

void SigGenerator::SetTextSection(uintptr_t baseAddress, size_t size)
{
	m_textBase = baseAddress;
	m_textSize = size;
}

int SigGenerator::CountMatches(const PatternData& pattern) const
{
	if (m_textBase == 0 || m_textSize == 0)
		return -1;

	int count = 0;
	const uint8_t* base = reinterpret_cast<const uint8_t*>(m_textBase);
	size_t patLen = pattern.bytes.size();

	if (patLen == 0 || patLen > m_textSize)
		return 0;

	for (size_t i = 0; i <= m_textSize - patLen; ++i)
	{
		bool match = true;
		for (size_t j = 0; j < patLen; ++j)
		{
			if (pattern.mask[j] == 'x' && base[i + j] != pattern.bytes[j])
			{
				match = false;
				break;
			}
		}
		if (match)
		{
			++count;
			if (count > 1)
				return count; // early exit, we only care about uniqueness
		}
	}

	return count;
}

PatternData SigGenerator::BuildFunctionSignature(const uint8_t* data, size_t maxLen)
{
	// Disassemble instructions to know what bytes to wildcard
	auto instructions = m_zydis.DecodeBuffer(data, maxLen);

	PatternData result;

	// Build pattern from decoded instructions, wildcarding relocatable parts
	for (const auto& insn : instructions)
	{
		for (size_t i = 0; i < insn.length; ++i)
		{
			size_t byteOffset = insn.offset + i;
			bool shouldWildcard = false;

			// Wildcard RIP-relative displacements
			if (insn.hasRipRelative &&
				i >= insn.ripDispOffset && i < insn.ripDispOffset + insn.ripDispSize)
			{
				shouldWildcard = true;
			}

			// Wildcard relative branch targets (E8/E9 rel32)
			if (insn.hasRel32 &&
				i >= insn.rel32Offset && i < insn.rel32Offset + 4)
			{
				shouldWildcard = true;
			}

			// Wildcard large immediates (likely addresses or changeable constants)
			if (insn.hasLargeImm &&
				i >= insn.immOffset && i < insn.immOffset + insn.immSize)
			{
				shouldWildcard = true;
			}

			result.bytes.push_back(data[byteOffset]);
			result.mask.push_back(shouldWildcard ? '?' : 'x');
		}

		// Try progressively longer signatures until unique
		if (result.bytes.size() >= 16)
		{
			int matches = CountMatches(result);
			if (matches == 1)
				return result;
		}

		// Cap at 128 bytes
		if (result.bytes.size() >= 128)
			break;
	}

	return result;
}

std::vector<SigGenerator::CodeReference> SigGenerator::FindReferencesTo(uintptr_t dataAddress) const
{
	std::vector<CodeReference> refs;

	if (m_textBase == 0 || m_textSize == 0)
		return refs;

	const uint8_t* base = reinterpret_cast<const uint8_t*>(m_textBase);

	// Scan for RIP-relative references: any instruction with a 4-byte displacement
	// that resolves to our target address. We look for the displacement value
	// at each position and verify it with Zydis.

	ZydisHelper zydis;

	for (size_t i = 0; i < m_textSize - 7; ++i)
	{
		// For each position, check if there's a 4-byte signed displacement
		// that could point to our target. RIP-relative addressing:
		// target = RIP + disp32, where RIP = instruction_end
		// We don't know instruction boundaries here, so try common patterns.

		// Check for common instruction patterns that use RIP-relative addressing:
		// MOV reg, [RIP+disp32]:  48 8B xx xx xx xx xx  (REX.W + opcode + modrm=xx05)
		// LEA reg, [RIP+disp32]:  48 8D xx xx xx xx xx
		// CMP [RIP+disp32], ...:  48 39 xx xx xx xx xx

		uint8_t byte0 = base[i];
		uint8_t byte1 = (i + 1 < m_textSize) ? base[i + 1] : 0;
		uint8_t byte2 = (i + 2 < m_textSize) ? base[i + 2] : 0;

		// Check if ModRM byte indicates RIP-relative (mod=00, rm=101 -> modrm & 0xC7 == 0x05)
		// We need to figure out where the ModRM byte is, which depends on prefixes and opcode.
		// Instead of guessing, let's use Zydis on a small window.

		// Quick pre-filter: look for the 4-byte displacement value we expect
		// For an instruction at address (m_textBase + i) with length L:
		//   target = (m_textBase + i + L) + disp32
		// So disp32 = target - (m_textBase + i + L)
		// L is typically 3-8 bytes for RIP-relative instructions.

		for (int instrLen = 3; instrLen <= 8; ++instrLen)
		{
			if (i + instrLen > m_textSize)
				break;

			int32_t expectedDisp = static_cast<int32_t>(
				static_cast<int64_t>(dataAddress) -
				static_cast<int64_t>(m_textBase + i + instrLen));

			// Check if the displacement appears in the instruction bytes
			// The displacement is typically at offset (instrLen - 4) for simple cases
			size_t dispPos = instrLen - 4;
			if (dispPos < 1 || i + dispPos + 4 > m_textSize)
				continue;

			int32_t actualDisp;
			std::memcpy(&actualDisp, &base[i + dispPos], 4);

			if (actualDisp != expectedDisp)
				continue;

			// Verify with Zydis that this is actually a valid instruction
			auto decoded = zydis.DecodeBuffer(base + i, std::min<size_t>(15, m_textSize - i));
			if (decoded.empty())
				continue;

			const auto& info = decoded[0];
			if (info.length != static_cast<size_t>(instrLen))
				continue;

			if (info.hasRipRelative && info.ripDispOffset == dispPos)
			{
				CodeReference ref;
				ref.instrAddress = m_textBase + i;
				ref.dispOffset = dispPos;
				ref.instrLength = instrLen;
				refs.push_back(ref);

				if (refs.size() >= 20) // cap to avoid excessive scanning
					return refs;

				break; // found valid decode for this position
			}
		}
	}

	return refs;
}

PatternData SigGenerator::BuildGlobalSignature(const CodeReference& ref, int& outOffsetAdjust, int& outDerefInsnLen)
{
	// Build a signature around the instruction that references the global.
	// Include context before and after for uniqueness.

	// Read bytes around the reference instruction
	const size_t contextBefore = 32;
	const size_t maxLen = 128;

	uintptr_t sigStart = (ref.instrAddress > m_textBase + contextBefore)
		? ref.instrAddress - contextBefore
		: m_textBase;

	size_t availLen = std::min<size_t>(maxLen, m_textBase + m_textSize - sigStart);
	const uint8_t* data = reinterpret_cast<const uint8_t*>(sigStart);

	// Disassemble to get proper instruction boundaries
	auto instructions = m_zydis.DecodeBuffer(data, availLen);

	PatternData result;
	size_t refInsnStart = ref.instrAddress - sigStart;

	for (const auto& insn : instructions)
	{
		for (size_t i = 0; i < insn.length; ++i)
		{
			size_t byteOffset = insn.offset + i;
			bool shouldWildcard = false;

			if (insn.hasRipRelative &&
				i >= insn.ripDispOffset && i < insn.ripDispOffset + insn.ripDispSize)
			{
				shouldWildcard = true;
			}

			if (insn.hasRel32 &&
				i >= insn.rel32Offset && i < insn.rel32Offset + 4)
			{
				shouldWildcard = true;
			}

			if (insn.hasLargeImm &&
				i >= insn.immOffset && i < insn.immOffset + insn.immSize)
			{
				shouldWildcard = true;
			}

			result.bytes.push_back(data[byteOffset]);
			result.mask.push_back(shouldWildcard ? '?' : 'x');
		}

		if (result.bytes.size() >= 16 && insn.offset >= refInsnStart)
		{
			int matches = CountMatches(result);
			if (matches == 1)
				break;
		}

		if (result.bytes.size() >= 128)
			break;
	}

	// offsetAdjust = bytes from pattern start to the displacement within the reference instruction
	outOffsetAdjust = static_cast<int>(refInsnStart + ref.dispOffset);
	outDerefInsnLen = static_cast<int>(ref.instrLength);

	return result;
}

SigGenResult SigGenerator::GenerateForFunction(const std::string& name, uintptr_t address)
{
	SigGenResult result;
	result.name = name;

	if (address < m_textBase || address >= m_textBase + m_textSize)
	{
		result.success = false;
		result.errorMessage = "Address outside .text section";
		return result;
	}

	size_t maxLen = std::min<size_t>(128, m_textBase + m_textSize - address);
	const uint8_t* data = reinterpret_cast<const uint8_t*>(address);

	PatternData pattern = BuildFunctionSignature(data, maxLen);

	if (pattern.bytes.empty())
	{
		result.success = false;
		result.errorMessage = "Failed to decode instructions at address";
		return result;
	}

	int matches = CountMatches(pattern);
	if (matches == 0)
	{
		result.success = false;
		result.errorMessage = "Pattern matches nothing (internal error)";
		return result;
	}

	if (matches > m_maxAcceptableMatches)
	{
		result.success = false;
		std::ostringstream oss;
		oss << "Pattern not unique: " << matches << " matches found";
		result.errorMessage = oss.str();
		return result;
	}

	result.success = true;
	result.entry.name = name;
	result.entry.pattern = PatternToString(pattern);
	result.entry.type = OffsetType::Function;
	result.entry.offsetAdjust = 0;
	result.entry.derefInsnLen = 0;

	if (matches > 1)
		result.lowConfidence = true;

	// Record previous address in preferred-base terms
	uintptr_t preferredAddr = address - m_actualBase + m_preferredBase;
	std::ostringstream addrStr;
	addrStr << "0x" << std::uppercase << std::hex << preferredAddr;
	result.entry.previousAddress = addrStr.str();

	return result;
}

SigGenResult SigGenerator::GenerateForGlobal(const std::string& name, uintptr_t address)
{
	SigGenResult result;
	result.name = name;

	// Find code references to this data address
	auto refs = FindReferencesTo(address);

	if (refs.empty())
	{
		result.success = false;
		result.errorMessage = "No code references found to global address";
		return result;
	}

	// Try each reference until we find one that produces a unique signature.
	// First pass: look for unique (1 match). Second pass: accept low-confidence.
	struct BestCandidate
	{
		PatternData pattern;
		int offsetAdjust = 0;
		int derefInsnLen = 0;
		int matchCount = 0;
	};
	BestCandidate bestLowConf;

	for (const auto& ref : refs)
	{
		int offsetAdjust = 0;
		int derefInsnLen = 0;
		PatternData pattern = BuildGlobalSignature(ref, offsetAdjust, derefInsnLen);

		if (pattern.bytes.empty())
			continue;

		int matches = CountMatches(pattern);
		if (matches == 1)
		{
			result.success = true;
			result.entry.name = name;
			result.entry.pattern = PatternToString(pattern);
			result.entry.type = OffsetType::GlobalRef;
			result.entry.offsetAdjust = offsetAdjust;
			result.entry.derefInsnLen = derefInsnLen;

			uintptr_t preferredAddr = address - m_actualBase + m_preferredBase;
			std::ostringstream addrStr;
			addrStr << "0x" << std::uppercase << std::hex << preferredAddr;
			result.entry.previousAddress = addrStr.str();

			return result;
		}

		// Track best low-confidence candidate (fewest matches)
		if (matches > 1 && matches <= m_maxAcceptableMatches &&
			(bestLowConf.matchCount == 0 || matches < bestLowConf.matchCount))
		{
			bestLowConf.pattern = pattern;
			bestLowConf.offsetAdjust = offsetAdjust;
			bestLowConf.derefInsnLen = derefInsnLen;
			bestLowConf.matchCount = matches;
		}
	}

	// Accept best low-confidence candidate if available
	if (bestLowConf.matchCount > 0)
	{
		result.success = true;
		result.lowConfidence = true;
		result.entry.name = name;
		result.entry.pattern = PatternToString(bestLowConf.pattern);
		result.entry.type = OffsetType::GlobalRef;
		result.entry.offsetAdjust = bestLowConf.offsetAdjust;
		result.entry.derefInsnLen = bestLowConf.derefInsnLen;

		uintptr_t preferredAddr = address - m_actualBase + m_preferredBase;
		std::ostringstream addrStr;
		addrStr << "0x" << std::uppercase << std::hex << preferredAddr;
		result.entry.previousAddress = addrStr.str();

		return result;
	}

	result.success = false;
	result.errorMessage = "Could not generate unique signature from any code reference";
	return result;
}

SigGenResult SigGenerator::Generate(const std::string& name, uintptr_t address)
{
	bool inText = (address >= m_textBase && address < m_textBase + m_textSize);

	// Determine if this looks like a global variable based on naming conventions.
	// Global variables: pinst*, inst*, DI8__*, __*Name (where name suggests data),
	// and anything with "_Table" in the name.
	// Functions: ClassName__MethodName pattern (capital letter + letters + __ + method)
	bool looksLikeGlobal = false;

	if (name.substr(0, 5) == "pinst" ||
		name.substr(0, 4) == "inst" ||
		name.substr(0, 3) == "DI8")
	{
		looksLikeGlobal = true;
	}
	else if (name.size() >= 3 && name[0] == '_' && name[1] == '_')
	{
		// Names starting with __ are globals unless they're in .text
		// (functions like __do_loot live in .text)
		looksLikeGlobal = !inText;
	}
	else if (name.find("_Table") != std::string::npos)
	{
		looksLikeGlobal = true;
	}
	else if (!inText)
	{
		// Address outside .text = definitely a data global
		looksLikeGlobal = true;
	}

	// Try primary strategy, then fallback
	if (looksLikeGlobal)
	{
		auto result = GenerateForGlobal(name, address);
		if (result.success)
			return result;

		// Fallback: maybe it's actually a function in a non-.text code section
		if (inText)
			return GenerateForFunction(name, address);

		return result;
	}
	else
	{
		auto result = GenerateForFunction(name, address);
		if (result.success)
			return result;

		// Fallback: try as global (maybe it's a data address with code refs)
		auto globalResult = GenerateForGlobal(name, address);
		if (globalResult.success)
			return globalResult;

		return result; // return original error
	}
}

} // namespace sigscan
