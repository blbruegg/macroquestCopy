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

#include "SigScan.h"

#include <string>
#include <vector>

namespace sigscan {

struct ScanReport
{
	int totalOffsets = 0;
	int found = 0;
	int notFound = 0;
	int ambiguous = 0;
	int64_t medianDelta = 0;
	int outlierCount = 0; // offsets whose delta differs from median by > 0x10000

	std::vector<ScanResult> notFoundEntries;
	std::vector<ScanResult> ambiguousEntries;
	std::vector<ScanResult> outlierEntries;
};

// Generate a report from scan results
ScanReport GenerateReport(const std::vector<ScanResult>& results);

// Format report as a human-readable string
std::string FormatReport(const ScanReport& report);

// Format a short summary suitable for chat output
std::string FormatSummary(const ScanReport& report);

} // namespace sigscan
