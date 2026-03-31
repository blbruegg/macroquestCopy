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

// Standalone PE-based signature scanner and generator.
// Reads EQ executables from disk and generates/scans signatures without needing
// to inject into a running process.
//
// Usage:
//   SigScanCLI.exe generate <executable> <offsets_header.h> [--output signatures.json]
//   SigScanCLI.exe scan <signatures.json> <executable> [--output results.json]
//   SigScanCLI.exe report <scan_results.json>

#include "PEParser.h"
#include "../SigGen.h"
#include "../SigScan.h"
#include "../Report.h"
#include "../PatternFormat.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <filesystem>
#include <regex>

namespace fs = std::filesystem;

static std::string ReadFile(const std::string& path)
{
	std::ifstream file(path);
	if (!file.is_open())
	{
		std::cerr << "Error: Cannot open file: " << path << std::endl;
		return "";
	}
	std::ostringstream ss;
	ss << file.rdbuf();
	return ss.str();
}

// Parse offset definitions from a header file.
// Looks for: #define NAME_x 0xADDRESS
struct OffsetDef
{
	std::string name;       // without the _x suffix
	uintptr_t address;      // the hex value
};

static std::vector<OffsetDef> ParseOffsetsFromHeader(const std::string& headerPath)
{
	std::vector<OffsetDef> offsets;
	std::ifstream file(headerPath);
	if (!file.is_open())
	{
		std::cerr << "Error: Cannot open header: " << headerPath << std::endl;
		return offsets;
	}

	std::regex pattern(R"(#define\s+(\w+)_x\s+(0x[0-9A-Fa-f]+))");
	std::string line;

	while (std::getline(file, line))
	{
		std::smatch match;
		if (std::regex_search(line, match, pattern))
		{
			OffsetDef def;
			def.name = match[1].str();
			def.address = std::stoull(match[2].str(), nullptr, 16);
			offsets.push_back(def);
		}
	}

	return offsets;
}

// Extract __ClientDate from header
static std::string ParseClientDate(const std::string& headerPath)
{
	std::ifstream file(headerPath);
	if (!file.is_open())
		return "";

	std::regex pattern(R"(#define\s+__ClientDate\s+(\d+)u?)");
	std::string line;

	while (std::getline(file, line))
	{
		std::smatch match;
		if (std::regex_search(line, match, pattern))
			return match[1].str();
	}

	return "";
}

static void PrintUsage()
{
	std::cout << "SigScanCLI - Standalone offset signature scanner\n\n"
		<< "Usage:\n"
		<< "  SigScanCLI generate <executable> <offsets_header.h> [--output signatures.json]\n"
		<< "  SigScanCLI scan <signatures.json> <executable> [--output results.json]\n"
		<< "  SigScanCLI report <scan_results.json>\n\n"
		<< "Commands:\n"
		<< "  generate  Generate signatures from an executable and its offset header\n"
		<< "  scan      Scan an executable using a signature database\n"
		<< "  report    Display a report from scan results\n\n"
		<< "Examples:\n"
		<< "  Generate signatures from current binary:\n"
		<< "    SigScanCLI generate eqgame.exe eqgame.h --output signatures_eqgame.json\n\n"
		<< "  Scan a patched binary:\n"
		<< "    SigScanCLI scan signatures_eqgame.json eqgame_new.exe --output results.json\n\n"
		<< "  Update headers from results:\n"
		<< "    python update_headers.py results.json\n";
}

static int DoGenerate(int argc, char* argv[])
{
	if (argc < 4)
	{
		std::cerr << "Error: generate requires <executable> and <offsets_header.h>\n"
			<< "  SigScanCLI generate <executable> <offsets_header.h> [--output signatures.json]\n";
		return 1;
	}

	std::string exePath = argv[2];
	std::string headerPath = argv[3];
	std::string outputPath;

	for (int i = 4; i < argc; ++i)
	{
		if (std::string(argv[i]) == "--output" && i + 1 < argc)
			outputPath = argv[++i];
	}

	// Parse offsets from header
	auto offsets = ParseOffsetsFromHeader(headerPath);
	if (offsets.empty())
	{
		std::cerr << "Error: No offsets found in " << headerPath << std::endl;
		return 1;
	}

	std::string clientDate = ParseClientDate(headerPath);
	std::cout << "Parsed " << offsets.size() << " offsets from " << headerPath;
	if (!clientDate.empty())
		std::cout << " (client date: " << clientDate << ")";
	std::cout << "\n";

	// Load PE file
	std::wstring wExePath(exePath.begin(), exePath.end());
	sigscan::PEFile pe;
	if (!pe.Load(wExePath))
	{
		std::cerr << "Error: Cannot load PE file: " << exePath << std::endl;
		return 1;
	}

	std::cout << "Loaded " << exePath << " (preferred base: 0x"
		<< std::hex << pe.GetPreferredBase() << std::dec << ")\n";

	// Build a contiguous code buffer that maps all executable sections
	// by virtual address, filling gaps with INT3 (0xCC) to prevent false matches.
	uint32_t codeRVA, codeSize;
	auto codeBuffer = pe.BuildCodeBuffer(codeRVA, codeSize);
	if (codeBuffer.empty())
	{
		std::cerr << "Error: No executable sections found\n";
		return 1;
	}

	std::cout << "Code sections: RVA 0x" << std::hex << codeRVA
		<< ", size 0x" << codeSize << std::dec << "\n\n";

	// Set up generator.
	// fakeActualBase maps so that (fakeActualBase + RVA) = buffer address of that RVA.
	uintptr_t preferredBase = pe.GetPreferredBase();
	const uint8_t* codeData = codeBuffer.data();
	uintptr_t fakeActualBase = reinterpret_cast<uintptr_t>(codeData) - codeRVA;
	uintptr_t codeAddr = reinterpret_cast<uintptr_t>(codeData);

	sigscan::SigGenerator generator;
	generator.SetTextSection(codeAddr, codeSize);
	generator.SetPreferredBase(preferredBase, fakeActualBase);

	// Generate signatures
	std::vector<sigscan::SignatureEntry> entries;
	int highConf = 0, lowConf = 0, failed = 0;
	std::vector<std::string> failures;
	std::vector<std::string> warnings;

	for (size_t i = 0; i < offsets.size(); ++i)
	{
		const auto& off = offsets[i];

		// Convert preferred address to actual mapped address
		uintptr_t actualAddr = off.address - preferredBase + fakeActualBase;

		if ((i + 1) % 50 == 0 || i + 1 == offsets.size())
		{
			std::cout << "\rGenerating signatures... " << (i + 1) << "/" << offsets.size() << std::flush;
		}

		auto result = generator.Generate(off.name, actualAddr);

		if (result.success)
		{
			entries.push_back(result.entry);
			if (result.lowConfidence)
			{
				++lowConf;
				warnings.push_back(off.name + " (multiple matches, will disambiguate by proximity)");
			}
			else
			{
				++highConf;
			}
		}
		else
		{
			++failed;
			failures.push_back(off.name + ": " + result.errorMessage);
		}
	}

	std::cout << "\n\nGeneration complete:\n"
		<< "  High confidence: " << highConf << "\n"
		<< "  Low confidence:  " << lowConf << "\n"
		<< "  Failed:          " << failed << "\n"
		<< "  Total:           " << offsets.size() << "\n";

	if (!warnings.empty())
	{
		std::cout << "\nLow confidence (scanner will pick nearest match):\n";
		for (const auto& w : warnings)
			std::cout << "  " << w << "\n";
	}

	if (!failures.empty())
	{
		std::cout << "\nFailed offsets:\n";
		for (const auto& f : failures)
			std::cout << "  " << f << "\n";
	}

	if (entries.empty())
	{
		std::cerr << "Error: No signatures generated\n";
		return 1;
	}

	// Write signatures JSON
	if (outputPath.empty())
	{
		fs::path hp(headerPath);
		outputPath = "signatures_" + hp.stem().string() + ".json";
	}

	std::string json = sigscan::SignaturesToJson(entries, clientDate);
	std::ofstream outFile(outputPath);
	if (outFile.is_open())
	{
		outFile << json;
		outFile.close();
		std::cout << "\nSignatures written to " << outputPath << std::endl;
	}
	else
	{
		std::cerr << "Error: Cannot write to " << outputPath << std::endl;
		return 1;
	}

	return 0;
}

static int DoScan(int argc, char* argv[])
{
	if (argc < 4)
	{
		std::cerr << "Error: scan requires <signatures.json> and <executable>\n";
		return 1;
	}

	std::string sigPath = argv[2];
	std::string exePath = argv[3];
	std::string outputPath;

	for (int i = 4; i < argc; ++i)
	{
		if (std::string(argv[i]) == "--output" && i + 1 < argc)
			outputPath = argv[++i];
	}

	// Load signatures
	std::string sigJson = ReadFile(sigPath);
	if (sigJson.empty())
		return 1;

	std::string clientDate;
	auto entries = sigscan::SignaturesFromJson(sigJson, &clientDate);
	if (entries.empty())
	{
		std::cerr << "Error: No signatures found in " << sigPath << std::endl;
		return 1;
	}

	std::cout << "Loaded " << entries.size() << " signatures (from client date: " << clientDate << ")\n";

	// Load PE file
	std::wstring wExePath(exePath.begin(), exePath.end());
	sigscan::PEFile pe;
	if (!pe.Load(wExePath))
	{
		std::cerr << "Error: Cannot load PE file: " << exePath << std::endl;
		return 1;
	}

	std::cout << "Loaded " << exePath << " (preferred base: 0x"
		<< std::hex << pe.GetPreferredBase() << std::dec << ")\n";

	uint32_t codeRVA, codeSize;
	auto codeBuffer = pe.BuildCodeBuffer(codeRVA, codeSize);
	if (codeBuffer.empty())
	{
		std::cerr << "Error: No executable sections found\n";
		return 1;
	}

	std::cout << "Scanning code sections: RVA 0x" << std::hex << codeRVA
		<< ", size 0x" << codeSize << std::dec << "\n\n";

	const uint8_t* codeData = codeBuffer.data();
	uintptr_t fakeActualBase = reinterpret_cast<uintptr_t>(codeData) - codeRVA;
	uintptr_t codeAddr = reinterpret_cast<uintptr_t>(codeData);

	sigscan::SigScanner scanner;
	scanner.SetTextSection(codeAddr, codeSize);
	scanner.SetBaseAddresses(pe.GetPreferredBase(), fakeActualBase);

	auto results = scanner.ScanAllWithFallback(entries);

	// Generate and display report
	auto report = sigscan::GenerateReport(results);
	std::string reportStr = sigscan::FormatReport(report);
	std::cout << reportStr;

	// Write results
	if (outputPath.empty())
		outputPath = "scan_results.json";

	std::string resultsJson = sigscan::ScanResultsToJson(results);
	std::ofstream outFile(outputPath);
	if (outFile.is_open())
	{
		outFile << resultsJson;
		outFile.close();
		std::cout << "\nResults written to " << outputPath << std::endl;
	}
	else
	{
		std::cerr << "Error: Cannot write to " << outputPath << std::endl;
		return 1;
	}

	return 0;
}

static int DoReport(int argc, char* argv[])
{
	if (argc < 3)
	{
		std::cerr << "Error: report requires <scan_results.json>\n";
		return 1;
	}

	std::string resultsPath = argv[2];
	std::string json = ReadFile(resultsPath);
	if (json.empty())
		return 1;

	// Parse results from JSON (simplified - just display the file)
	std::cout << json << std::endl;
	return 0;
}

int main(int argc, char* argv[])
{
	if (argc < 2)
	{
		PrintUsage();
		return 1;
	}

	std::string command = argv[1];

	if (command == "generate")
		return DoGenerate(argc, argv);
	else if (command == "scan")
		return DoScan(argc, argv);
	else if (command == "report")
		return DoReport(argc, argv);
	else if (command == "--help" || command == "-h")
	{
		PrintUsage();
		return 0;
	}
	else
	{
		std::cerr << "Unknown command: " << command << std::endl;
		PrintUsage();
		return 1;
	}
}
