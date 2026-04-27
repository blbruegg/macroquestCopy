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

#include "SigGen.h"

#include <cstdint>
#include <string>
#include <vector>
#include <map>

namespace sigscan {

enum class ScanConfidence
{
	High,     // Exactly one match
	Low,      // Multiple matches, picked nearest to old address
	NotFound, // No matches
};

struct ScanResult
{
	std::string name;
	ScanConfidence confidence = ScanConfidence::NotFound;
	uintptr_t newAddress = 0;       // in preferred-base terms
	uintptr_t oldAddress = 0;       // from signature database
	int64_t delta = 0;              // newAddress - oldAddress
	int matchCount = 0;
	std::string errorMessage;
};

class SigScanner
{
public:
	SigScanner();

	// Set the memory region to scan
	void SetTextSection(uintptr_t baseAddress, size_t size);

	// Set base addresses for offset calculation
	void SetBaseAddresses(uintptr_t preferredBase, uintptr_t actualBase);

	// Scan for a single signature
	ScanResult Scan(const SignatureEntry& entry) const;

	// Scan all signatures
	std::vector<ScanResult> ScanAll(const std::vector<SignatureEntry>& entries) const;

	// Scan all signatures with delta-guided fallback for NOT_FOUND entries.
	// First does a normal scan, computes the median delta, then retries
	// NOT_FOUND globals/functions using the predicted address.
	std::vector<ScanResult> ScanAllWithFallback(const std::vector<SignatureEntry>& entries) const;

private:
	// Find all matches of a pattern in the text section
	std::vector<uintptr_t> FindAllMatches(const PatternData& pattern) const;

	// Resolve a global reference from a pattern match
	uintptr_t ResolveGlobalRef(uintptr_t matchAddr, int offsetAdjust, int derefInsnLen) const;

	// Delta-guided fallback: scan for RIP-relative references to a predicted global address
	ScanResult ScanGlobalByDelta(const SignatureEntry& entry, int64_t medianDelta) const;

	// Delta-guided fallback: check if predicted function address looks valid
	ScanResult ScanFunctionByDelta(const SignatureEntry& entry, int64_t medianDelta) const;

	// Find all RIP-relative references to a target address within a tolerance
	std::vector<uintptr_t> FindRIPReferencesTo(uintptr_t targetAddr, int64_t tolerance = 0x100) const;

	uintptr_t m_textBase = 0;
	size_t m_textSize = 0;
	uintptr_t m_preferredBase = 0;
	uintptr_t m_actualBase = 0;
};

// JSON serialization
std::string SignaturesToJson(const std::vector<SignatureEntry>& entries, const std::string& clientDate);
std::vector<SignatureEntry> SignaturesFromJson(const std::string& json, std::string* outClientDate = nullptr);
std::string ScanResultsToJson(const std::vector<ScanResult>& results);

} // namespace sigscan
