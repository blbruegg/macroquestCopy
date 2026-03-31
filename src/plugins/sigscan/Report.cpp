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

#include "Report.h"

#include <algorithm>
#include <sstream>
#include <iomanip>
#include <cmath>

namespace sigscan {

ScanReport GenerateReport(const std::vector<ScanResult>& results)
{
	ScanReport report;
	report.totalOffsets = static_cast<int>(results.size());

	std::vector<int64_t> deltas;

	for (const auto& r : results)
	{
		switch (r.confidence)
		{
		case ScanConfidence::High:
			report.found++;
			deltas.push_back(r.delta);
			break;
		case ScanConfidence::Low:
			report.ambiguous++;
			report.ambiguousEntries.push_back(r);
			deltas.push_back(r.delta);
			break;
		case ScanConfidence::NotFound:
			report.notFound++;
			report.notFoundEntries.push_back(r);
			break;
		}
	}

	// Calculate median delta
	if (!deltas.empty())
	{
		std::sort(deltas.begin(), deltas.end());
		report.medianDelta = deltas[deltas.size() / 2];

		// Find outliers
		for (const auto& r : results)
		{
			if (r.confidence == ScanConfidence::NotFound)
				continue;

			if (std::abs(r.delta - report.medianDelta) > 0x10000)
			{
				report.outlierCount++;
				report.outlierEntries.push_back(r);
			}
		}
	}

	return report;
}

std::string FormatReport(const ScanReport& report)
{
	std::ostringstream out;

	out << "Offset Update Report\n";
	out << "====================\n\n";

	double foundPct = report.totalOffsets > 0
		? 100.0 * report.found / report.totalOffsets : 0;
	double notFoundPct = report.totalOffsets > 0
		? 100.0 * report.notFound / report.totalOffsets : 0;
	double ambigPct = report.totalOffsets > 0
		? 100.0 * report.ambiguous / report.totalOffsets : 0;

	out << std::fixed << std::setprecision(1);
	out << "FOUND:     " << report.found << " / " << report.totalOffsets
		<< "  (" << foundPct << "%)\n";
	out << "NOT_FOUND: " << report.notFound << " / " << report.totalOffsets
		<< "  (" << notFoundPct << "%)\n";
	out << "AMBIGUOUS: " << report.ambiguous << " / " << report.totalOffsets
		<< "  (" << ambigPct << "%)\n\n";

	out << "Median delta: 0x" << std::hex << std::uppercase << report.medianDelta << std::dec << "\n";
	out << "Outliers (delta differs by >0x10000 from median): " << report.outlierCount << "\n\n";

	if (!report.notFoundEntries.empty())
	{
		out << "--- NOT FOUND ---\n";
		for (const auto& r : report.notFoundEntries)
		{
			out << "  " << r.name << "  (old: " << std::hex << "0x" << r.oldAddress << std::dec << ")\n";
		}
		out << "\n";
	}

	if (!report.ambiguousEntries.empty())
	{
		out << "--- AMBIGUOUS (manual review needed) ---\n";
		for (const auto& r : report.ambiguousEntries)
		{
			out << "  " << r.name << "  (old: 0x" << std::hex << r.oldAddress
				<< " -> new: 0x" << r.newAddress << ", " << std::dec
				<< r.matchCount << " matches)\n";
		}
		out << "\n";
	}

	if (!report.outlierEntries.empty())
	{
		out << "--- OUTLIERS (unusual shift) ---\n";
		for (const auto& r : report.outlierEntries)
		{
			out << "  " << r.name << "  delta: 0x" << std::hex << r.delta
				<< " vs median 0x" << report.medianDelta << std::dec << "\n";
		}
		out << "\n";
	}

	return out.str();
}

std::string FormatSummary(const ScanReport& report)
{
	std::ostringstream out;
	out << "SigScan: " << report.found << "/" << report.totalOffsets << " found";
	if (report.ambiguous > 0)
		out << ", " << report.ambiguous << " ambiguous";
	if (report.notFound > 0)
		out << ", " << report.notFound << " not found";
	return out.str();
}

} // namespace sigscan
