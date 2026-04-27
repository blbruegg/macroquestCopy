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

#include "SigScan.h"
#include "ZydisHelper.h"

#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cstring>
#include <cmath>
#include <map>
#include <numeric>
#include <set>

namespace sigscan {

SigScanner::SigScanner()
{
}

void SigScanner::SetTextSection(uintptr_t baseAddress, size_t size)
{
	m_textBase = baseAddress;
	m_textSize = size;
}

void SigScanner::SetBaseAddresses(uintptr_t preferredBase, uintptr_t actualBase)
{
	m_preferredBase = preferredBase;
	m_actualBase = actualBase;
}

std::vector<uintptr_t> SigScanner::FindAllMatches(const PatternData& pattern) const
{
	std::vector<uintptr_t> matches;

	if (m_textBase == 0 || m_textSize == 0 || pattern.bytes.empty())
		return matches;

	const uint8_t* base = reinterpret_cast<const uint8_t*>(m_textBase);
	size_t patLen = pattern.bytes.size();

	if (patLen > m_textSize)
		return matches;

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
			matches.push_back(m_textBase + i);
		}
	}

	return matches;
}

uintptr_t SigScanner::ResolveGlobalRef(uintptr_t matchAddr, int offsetAdjust, int derefInsnLen) const
{
	// Read the RIP-relative displacement
	uintptr_t dispAddr = matchAddr + offsetAdjust;
	int32_t disp;
	std::memcpy(&disp, reinterpret_cast<const void*>(dispAddr), 4);

	// RIP-relative: target = instruction_end + displacement
	// instruction_end = matchAddr + derefInsnLen (from start of the referencing instruction)
	// But offsetAdjust points to the disp within the pattern, and the instruction starts
	// at matchAddr + (offsetAdjust - dispOffsetWithinInsn). Since we stored offsetAdjust
	// as the offset from pattern start to the displacement, and derefInsnLen as the
	// instruction length, the instruction starts at (dispAddr - dispOffsetWithinInsn).
	// Actually: the instruction that contains the displacement starts at some offset,
	// and ends at instrStart + derefInsnLen. The displacement is at instrStart + dispOffsetInInsn.
	// We have: dispAddr = matchAddr + offsetAdjust = instrStart + dispOffsetInInsn
	// We need: instrEnd = instrStart + derefInsnLen
	// But we don't separately store dispOffsetInInsn vs instrStart offset.
	//
	// Simplification: For most RIP-relative instructions, the displacement is the last
	// 4 bytes of the instruction. So instrEnd = dispAddr + 4.
	// This is true for MOV, LEA, CMP, etc. with no immediate following the displacement.

	uintptr_t instrEnd = dispAddr + 4;
	uintptr_t target = instrEnd + static_cast<int64_t>(disp);

	return target;
}

ScanResult SigScanner::Scan(const SignatureEntry& entry) const
{
	ScanResult result;
	result.name = entry.name;

	// Parse old address
	if (!entry.previousAddress.empty())
	{
		result.oldAddress = std::stoull(entry.previousAddress, nullptr, 16);
	}

	PatternData pattern = PatternFromString(entry.pattern);
	auto matches = FindAllMatches(pattern);

	result.matchCount = static_cast<int>(matches.size());

	if (matches.empty())
	{
		result.confidence = ScanConfidence::NotFound;
		result.errorMessage = "No matches found";
		return result;
	}

	// Too many matches means the signature is too generic to be useful
	if (matches.size() > 10)
	{
		result.confidence = ScanConfidence::NotFound;
		std::ostringstream oss;
		oss << "Too many matches (" << matches.size() << "), signature too generic";
		result.errorMessage = oss.str();
		return result;
	}

	uintptr_t matchAddr;

	if (matches.size() == 1)
	{
		matchAddr = matches[0];
		result.confidence = ScanConfidence::High;
	}
	else
	{
		// Multiple matches - pick the one nearest to the old address (adjusted for base)
		uintptr_t oldActual = result.oldAddress - m_preferredBase + m_actualBase;
		matchAddr = matches[0];
		int64_t bestDist = std::abs(static_cast<int64_t>(matches[0]) - static_cast<int64_t>(oldActual));

		for (size_t i = 1; i < matches.size(); ++i)
		{
			int64_t dist = std::abs(static_cast<int64_t>(matches[i]) - static_cast<int64_t>(oldActual));
			if (dist < bestDist)
			{
				bestDist = dist;
				matchAddr = matches[i];
			}
		}

		result.confidence = ScanConfidence::Low;
		std::ostringstream oss;
		oss << matches.size() << " matches found, picked nearest to old address";
		result.errorMessage = oss.str();
	}

	// Resolve the actual address
	if (entry.type == OffsetType::Function)
	{
		// Pattern match IS the function address
		uintptr_t preferredAddr = matchAddr - m_actualBase + m_preferredBase;
		result.newAddress = preferredAddr;
	}
	else if (entry.type == OffsetType::GlobalRef)
	{
		// Need to dereference RIP-relative to get the actual global address
		uintptr_t actualAddr = ResolveGlobalRef(matchAddr, entry.offsetAdjust, entry.derefInsnLen);
		uintptr_t preferredAddr = actualAddr - m_actualBase + m_preferredBase;
		result.newAddress = preferredAddr;
	}

	result.delta = static_cast<int64_t>(result.newAddress) - static_cast<int64_t>(result.oldAddress);

	return result;
}

std::vector<ScanResult> SigScanner::ScanAll(const std::vector<SignatureEntry>& entries) const
{
	std::vector<ScanResult> results;
	results.reserve(entries.size());

	for (const auto& entry : entries)
	{
		results.push_back(Scan(entry));
	}

	return results;
}

std::vector<uintptr_t> SigScanner::FindRIPReferencesTo(uintptr_t targetAddr, int64_t tolerance) const
{
	std::vector<uintptr_t> results;

	if (m_textBase == 0 || m_textSize == 0)
		return results;

	const uint8_t* base = reinterpret_cast<const uint8_t*>(m_textBase);
	ZydisHelper zydis;

	// Displacement-value scanning: for each position, try common instruction lengths
	// and check if the 4-byte displacement at (instrLen - 4) points near our target.
	// This avoids the REX prefix filter that misses many RIP-relative instructions.
	for (size_t i = 0; i < m_textSize - 7; ++i)
	{
		for (int instrLen = 3; instrLen <= 8; ++instrLen)
		{
			if (i + instrLen > m_textSize)
				break;

			size_t dispPos = instrLen - 4;
			if (dispPos < 1 || i + dispPos + 4 > m_textSize)
				continue;

			int32_t disp;
			std::memcpy(&disp, &base[i + dispPos], 4);

			// RIP-relative: target = instrEnd + disp
			uintptr_t instrEnd = m_textBase + i + instrLen;
			uintptr_t refTarget = instrEnd + static_cast<int64_t>(disp);

			int64_t diff = static_cast<int64_t>(refTarget) - static_cast<int64_t>(targetAddr);
			if (diff < -tolerance || diff > tolerance)
				continue;

			// Verify with Zydis that this is actually a valid RIP-relative instruction
			auto decoded = zydis.DecodeBuffer(base + i, std::min<size_t>(15, m_textSize - i));
			if (decoded.empty())
				continue;

			const auto& info = decoded[0];
			if (info.length != static_cast<size_t>(instrLen))
				continue;

			if (info.hasRipRelative && info.ripDispOffset == dispPos)
			{
				results.push_back(refTarget);
				if (results.size() >= 100)
					return results;
				break; // found valid decode for this position
			}
		}
	}

	return results;
}

ScanResult SigScanner::ScanGlobalByDelta(const SignatureEntry& entry, int64_t medianDelta) const
{
	ScanResult result;
	result.name = entry.name;
	result.oldAddress = std::stoull(entry.previousAddress, nullptr, 16);

	// Predict where the global should be in the new binary
	uintptr_t predictedAddr = static_cast<uintptr_t>(
		static_cast<int64_t>(result.oldAddress) + medianDelta);

	// Convert to actual address space for searching
	uintptr_t predictedActual = predictedAddr - m_preferredBase + m_actualBase;

	// Search for RIP-relative references to addresses near the predicted location
	auto refs = FindRIPReferencesTo(predictedActual, 0x200);

	if (refs.empty())
	{
		result.confidence = ScanConfidence::NotFound;
		result.errorMessage = "No references found near predicted address (delta-guided)";
		return result;
	}

	// Count how many references point to each unique address
	std::map<uintptr_t, int> addrCounts;
	for (uintptr_t addr : refs)
		addrCounts[addr]++;

	// Too many unique targets = too noisy to be reliable
	if (addrCounts.size() > 20)
	{
		result.confidence = ScanConfidence::NotFound;
		std::ostringstream oss;
		oss << "Delta-guided: too many unique targets (" << addrCounts.size() << ") in search window";
		result.errorMessage = oss.str();
		return result;
	}

	// Pick the address closest to the predicted location (not most-referenced)
	uintptr_t bestAddr = 0;
	int64_t bestDist = INT64_MAX;
	int bestCount = 0;
	for (const auto& [addr, count] : addrCounts)
	{
		int64_t dist = std::abs(static_cast<int64_t>(addr) - static_cast<int64_t>(predictedActual));
		if (dist < bestDist)
		{
			bestDist = dist;
			bestAddr = addr;
			bestCount = count;
		}
	}

	// Convert back to preferred address space
	uintptr_t preferredAddr = bestAddr - m_actualBase + m_preferredBase;

	// Sanity check: the delta should be within a reasonable range of the median
	int64_t actualDelta = static_cast<int64_t>(preferredAddr) - static_cast<int64_t>(result.oldAddress);
	if (std::abs(actualDelta - medianDelta) > 0x10000)
	{
		result.confidence = ScanConfidence::NotFound;
		std::ostringstream oss;
		oss << "Delta-guided match at 0x" << std::hex << std::uppercase << preferredAddr
			<< " has unusual delta (0x" << actualDelta << " vs median 0x" << medianDelta << ")";
		result.errorMessage = oss.str();
		return result;
	}

	result.newAddress = preferredAddr;
	result.delta = actualDelta;
	result.matchCount = bestCount;
	result.confidence = ScanConfidence::Low;

	std::ostringstream oss;
	oss << "Delta-guided: " << bestCount << " references, closest of "
		<< addrCounts.size() << " unique targets";
	result.errorMessage = oss.str();

	return result;
}

ScanResult SigScanner::ScanFunctionByDelta(const SignatureEntry& entry, int64_t medianDelta) const
{
	ScanResult result;
	result.name = entry.name;
	result.oldAddress = std::stoull(entry.previousAddress, nullptr, 16);

	// Predict where the function should be in the new binary
	uintptr_t predictedPreferred = static_cast<uintptr_t>(
		static_cast<int64_t>(result.oldAddress) + medianDelta);
	uintptr_t predictedActual = predictedPreferred - m_preferredBase + m_actualBase;

	// Check if the predicted address is within our scan region
	if (predictedActual < m_textBase || predictedActual >= m_textBase + m_textSize)
	{
		result.confidence = ScanConfidence::NotFound;
		result.errorMessage = "Predicted address outside code sections (delta-guided)";
		return result;
	}

	// Search for relative call/jump references to addresses near the predicted location.
	// Functions are typically called via E8 (call rel32). Scan for E8 instructions
	// whose target is near the predicted address.
	const uint8_t* base = reinterpret_cast<const uint8_t*>(m_textBase);
	std::map<uintptr_t, int> targetCounts;
	int64_t tolerance = 0x200;

	for (size_t i = 0; i < m_textSize - 5; ++i)
	{
		if (base[i] != 0xE8) // CALL rel32
			continue;

		int32_t rel;
		std::memcpy(&rel, base + i + 1, 4);
		uintptr_t callTarget = m_textBase + i + 5 + static_cast<int64_t>(rel);

		int64_t diff = static_cast<int64_t>(callTarget) - static_cast<int64_t>(predictedActual);
		if (diff >= -tolerance && diff <= tolerance)
		{
			targetCounts[callTarget]++;
		}
	}

	if (targetCounts.empty())
	{
		result.confidence = ScanConfidence::NotFound;
		result.errorMessage = "No call references found near predicted address (delta-guided)";
		return result;
	}

	// Too many unique targets = too noisy
	if (targetCounts.size() > 30)
	{
		result.confidence = ScanConfidence::NotFound;
		std::ostringstream oss;
		oss << "Delta-guided: too many unique call targets (" << targetCounts.size() << ")";
		result.errorMessage = oss.str();
		return result;
	}

	// Filter to plausible function starts: the byte before a function is typically
	// 0xCC (INT3 padding), 0xC3 (RET), or the address is 16-byte aligned.
	// Also require at least 2 callers to reduce false positives.
	std::map<uintptr_t, int> validTargets;
	for (const auto& [addr, count] : targetCounts)
	{
		if (addr <= m_textBase || addr >= m_textBase + m_textSize)
			continue;

		size_t offset = addr - m_textBase;
		uint8_t prevByte = base[offset - 1];
		bool aligned16 = (addr % 16 == 0);
		bool afterPadding = (prevByte == 0xCC || prevByte == 0xC3 || prevByte == 0xCB);

		if (aligned16 || afterPadding || count >= 3)
			validTargets[addr] = count;
	}

	// Fall back to all targets if no valid ones found
	const auto& candidates = validTargets.empty() ? targetCounts : validTargets;

	// Pick the target closest to predicted address
	uintptr_t bestAddr = 0;
	int64_t bestDist = INT64_MAX;
	int bestCount = 0;
	for (const auto& [addr, count] : candidates)
	{
		int64_t dist = std::abs(static_cast<int64_t>(addr) - static_cast<int64_t>(predictedActual));
		if (dist < bestDist)
		{
			bestDist = dist;
			bestAddr = addr;
			bestCount = count;
		}
	}

	uintptr_t preferredAddr = bestAddr - m_actualBase + m_preferredBase;
	int64_t actualDelta = static_cast<int64_t>(preferredAddr) - static_cast<int64_t>(result.oldAddress);

	if (std::abs(actualDelta - medianDelta) > 0x10000)
	{
		result.confidence = ScanConfidence::NotFound;
		result.errorMessage = "Delta-guided function match has unusual delta";
		return result;
	}

	result.newAddress = preferredAddr;
	result.delta = actualDelta;
	result.matchCount = bestCount;
	result.confidence = ScanConfidence::Low;

	std::ostringstream oss;
	oss << "Delta-guided: " << bestCount << " call refs, closest of "
		<< targetCounts.size() << " unique targets";
	result.errorMessage = oss.str();

	return result;
}

std::vector<ScanResult> SigScanner::ScanAllWithFallback(const std::vector<SignatureEntry>& entries) const
{
	// First pass: normal signature scan
	auto results = ScanAll(entries);

	// Compute median delta from successful results
	std::vector<int64_t> deltas;
	for (const auto& r : results)
	{
		if (r.confidence == ScanConfidence::High && r.delta != 0)
			deltas.push_back(r.delta);
	}

	if (deltas.size() < 10)
		return results; // not enough data for delta-guided fallback

	std::sort(deltas.begin(), deltas.end());
	int64_t medianDelta = deltas[deltas.size() / 2];

	// Collect addresses already claimed by first-pass results
	std::set<uintptr_t> claimedAddresses;
	for (const auto& r : results)
	{
		if (r.confidence != ScanConfidence::NotFound && r.newAddress != 0)
			claimedAddresses.insert(r.newAddress);
	}

	// Second pass: delta-guided fallback for NOT_FOUND entries
	int recovered = 0;
	for (size_t i = 0; i < results.size(); ++i)
	{
		if (results[i].confidence != ScanConfidence::NotFound)
			continue;

		const auto& entry = entries[i];
		ScanResult fallback;

		if (entry.type == OffsetType::GlobalRef)
			fallback = ScanGlobalByDelta(entry, medianDelta);
		else
			fallback = ScanFunctionByDelta(entry, medianDelta);

		if (fallback.confidence != ScanConfidence::NotFound)
		{
			// Skip if this address was already claimed by another offset
			if (claimedAddresses.count(fallback.newAddress))
			{
				results[i].errorMessage = "Delta-guided: address already claimed by another offset";
				continue;
			}

			results[i] = fallback;
			claimedAddresses.insert(fallback.newAddress);
			++recovered;
		}
	}

	return results;
}

// --- JSON Serialization ---
// Using simple manual JSON generation to avoid adding a JSON library dependency.

static std::string EscapeJson(const std::string& s)
{
	std::string result;
	result.reserve(s.size());
	for (char c : s)
	{
		switch (c)
		{
		case '"':  result += "\\\""; break;
		case '\\': result += "\\\\"; break;
		case '\n': result += "\\n"; break;
		case '\r': result += "\\r"; break;
		case '\t': result += "\\t"; break;
		default:   result += c; break;
		}
	}
	return result;
}

std::string SignaturesToJson(const std::vector<SignatureEntry>& entries, const std::string& clientDate)
{
	std::ostringstream json;
	json << "{\n";
	json << "  \"version\": 1,\n";
	json << "  \"generated_from\": \"" << EscapeJson(clientDate) << "\",\n";
	json << "  \"signatures\": {\n";

	for (size_t i = 0; i < entries.size(); ++i)
	{
		const auto& e = entries[i];
		json << "    \"" << EscapeJson(e.name) << "\": {\n";
		json << "      \"pattern\": \"" << EscapeJson(e.pattern) << "\",\n";
		json << "      \"type\": \"" << (e.type == OffsetType::Function ? "function" : "global_ref") << "\",\n";
		json << "      \"offset_adjust\": " << e.offsetAdjust << ",\n";
		json << "      \"deref_insn_len\": " << e.derefInsnLen << ",\n";
		json << "      \"previous_address\": \"" << EscapeJson(e.previousAddress) << "\"\n";
		json << "    }";
		if (i + 1 < entries.size())
			json << ",";
		json << "\n";
	}

	json << "  }\n";
	json << "}\n";

	return json.str();
}

// Simple JSON parser for our specific format
static std::string ExtractJsonString(const std::string& json, const std::string& key)
{
	std::string searchKey = "\"" + key + "\"";
	size_t pos = json.find(searchKey);
	if (pos == std::string::npos) return "";

	pos = json.find(':', pos + searchKey.size());
	if (pos == std::string::npos) return "";

	pos = json.find('"', pos + 1);
	if (pos == std::string::npos) return "";

	size_t end = pos + 1;
	while (end < json.size() && json[end] != '"')
	{
		if (json[end] == '\\') end++; // skip escaped char
		end++;
	}

	return json.substr(pos + 1, end - pos - 1);
}

static int ExtractJsonInt(const std::string& json, const std::string& key)
{
	std::string searchKey = "\"" + key + "\"";
	size_t pos = json.find(searchKey);
	if (pos == std::string::npos) return 0;

	pos = json.find(':', pos + searchKey.size());
	if (pos == std::string::npos) return 0;

	pos++;
	while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t')) pos++;

	return std::atoi(json.c_str() + pos);
}

std::vector<SignatureEntry> SignaturesFromJson(const std::string& json, std::string* outClientDate)
{
	std::vector<SignatureEntry> entries;

	if (outClientDate)
		*outClientDate = ExtractJsonString(json, "generated_from");

	// Find "signatures" block
	size_t sigPos = json.find("\"signatures\"");
	if (sigPos == std::string::npos)
		return entries;

	// Find each entry by looking for pattern of "name": {
	size_t pos = json.find('{', sigPos + 12); // skip past "signatures":
	if (pos == std::string::npos)
		return entries;

	pos++; // skip opening brace of signatures object

	while (pos < json.size())
	{
		// Find next entry name
		size_t nameStart = json.find('"', pos);
		if (nameStart == std::string::npos)
			break;

		// Check if we've hit the closing brace
		size_t bracePos = json.find('}', pos);
		if (bracePos != std::string::npos && bracePos < nameStart)
			break;

		size_t nameEnd = json.find('"', nameStart + 1);
		if (nameEnd == std::string::npos)
			break;

		std::string name = json.substr(nameStart + 1, nameEnd - nameStart - 1);

		// Find the entry's object
		size_t objStart = json.find('{', nameEnd);
		if (objStart == std::string::npos)
			break;

		// Find matching closing brace (simple - no nested objects in entries)
		size_t objEnd = json.find('}', objStart);
		if (objEnd == std::string::npos)
			break;

		std::string entryJson = json.substr(objStart, objEnd - objStart + 1);

		SignatureEntry entry;
		entry.name = name;
		entry.pattern = ExtractJsonString(entryJson, "pattern");

		std::string typeStr = ExtractJsonString(entryJson, "type");
		entry.type = (typeStr == "global_ref") ? OffsetType::GlobalRef : OffsetType::Function;

		entry.offsetAdjust = ExtractJsonInt(entryJson, "offset_adjust");
		entry.derefInsnLen = ExtractJsonInt(entryJson, "deref_insn_len");
		entry.previousAddress = ExtractJsonString(entryJson, "previous_address");

		entries.push_back(entry);

		pos = objEnd + 1;
	}

	return entries;
}

std::string ScanResultsToJson(const std::vector<ScanResult>& results)
{
	std::ostringstream json;
	json << "{\n";
	json << "  \"results\": [\n";

	for (size_t i = 0; i < results.size(); ++i)
	{
		const auto& r = results[i];
		json << "    {\n";
		json << "      \"name\": \"" << EscapeJson(r.name) << "\",\n";

		const char* confStr = "not_found";
		if (r.confidence == ScanConfidence::High) confStr = "high";
		else if (r.confidence == ScanConfidence::Low) confStr = "low";

		json << "      \"confidence\": \"" << confStr << "\",\n";
		json << "      \"new_address\": \"0x" << std::uppercase << std::hex << r.newAddress << "\",\n";
		json << "      \"old_address\": \"0x" << std::uppercase << std::hex << r.oldAddress << "\",\n";
		json << std::dec;
		json << "      \"delta\": " << r.delta << ",\n";
		json << "      \"match_count\": " << r.matchCount;
		if (!r.errorMessage.empty())
			json << ",\n      \"error\": \"" << EscapeJson(r.errorMessage) << "\"";
		json << "\n    }";
		if (i + 1 < results.size())
			json << ",";
		json << "\n";
	}

	json << "  ]\n";
	json << "}\n";

	return json.str();
}

} // namespace sigscan
