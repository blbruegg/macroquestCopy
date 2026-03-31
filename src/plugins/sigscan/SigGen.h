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

#include "PatternFormat.h"
#include "ZydisHelper.h"

#include <cstdint>
#include <string>
#include <vector>
#include <functional>

namespace sigscan {

// Describes the type of offset
enum class OffsetType
{
	Function,  // Offset points to start of a function
	GlobalRef, // Offset is a global variable (data address)
};

// A single signature entry
struct SignatureEntry
{
	std::string name;        // e.g. "CXWnd__IsType"
	std::string pattern;     // IDA-style hex pattern
	OffsetType type = OffsetType::Function;
	int offsetAdjust = 0;    // bytes from pattern match to displacement
	int derefInsnLen = 0;    // instruction length for RIP-relative resolution
	std::string previousAddress; // hex string of the address this was generated from
};

// Result of attempting to generate a signature for one offset
struct SigGenResult
{
	std::string name;
	bool success = false;
	bool lowConfidence = false; // true if multiple matches (scanner will disambiguate)
	std::string errorMessage;
	SignatureEntry entry;
};

// Callback for progress reporting
using ProgressCallback = std::function<void(const std::string& name, int current, int total)>;

class SigGenerator
{
public:
	SigGenerator();

	// Set the memory region to scan for uniqueness verification
	void SetTextSection(uintptr_t baseAddress, size_t size);

	// Generate a signature for a function offset
	SigGenResult GenerateForFunction(const std::string& name, uintptr_t address);

	// Generate a signature for a global variable offset
	SigGenResult GenerateForGlobal(const std::string& name, uintptr_t address);

	// Auto-detect type and generate signature
	SigGenResult Generate(const std::string& name, uintptr_t address);

	// Set preferred base for recording previous addresses
	void SetPreferredBase(uintptr_t preferred, uintptr_t actual)
	{
		m_preferredBase = preferred;
		m_actualBase = actual;
	}

private:
	// Check if a pattern is unique in the text section
	int CountMatches(const PatternData& pattern) const;

	// Try to build a unique signature starting from the given address
	PatternData BuildFunctionSignature(const uint8_t* data, size_t maxLen);

	// Find a code reference to a data address in the text section
	struct CodeReference
	{
		uintptr_t instrAddress;
		size_t dispOffset;     // offset of displacement within instruction
		size_t instrLength;    // total instruction length
	};
	std::vector<CodeReference> FindReferencesTo(uintptr_t dataAddress) const;

	// Build signature around a code reference to a global
	PatternData BuildGlobalSignature(const CodeReference& ref, int& outOffsetAdjust, int& outDerefInsnLen);

	ZydisHelper m_zydis;
	uintptr_t m_textBase = 0;
	size_t m_textSize = 0;
	uintptr_t m_preferredBase = 0;
	uintptr_t m_actualBase = 0;
	int m_maxAcceptableMatches = 3; // accept up to this many matches (scanner disambiguates)
};

} // namespace sigscan
