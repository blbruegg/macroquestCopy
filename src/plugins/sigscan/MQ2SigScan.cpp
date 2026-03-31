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

#include <mq/Plugin.h>
#include <Windows.h>

#include "OffsetTable.h"
#include "SigGen.h"
#include "SigScan.h"
#include "Report.h"

#include <fstream>
#include <sstream>
#include <filesystem>

PreSetup("MQ2SigScan");

namespace fs = std::filesystem;

namespace {

// Get the .text section bounds of a loaded module
bool GetTextSection(HMODULE hModule, uintptr_t& outBase, size_t& outSize)
{
	auto* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(hModule);
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return false;

	auto* ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(
		reinterpret_cast<uint8_t*>(hModule) + dosHeader->e_lfanew);
	if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
		return false;

	auto* section = IMAGE_FIRST_SECTION(ntHeaders);
	for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i, ++section)
	{
		if (std::strncmp(reinterpret_cast<const char*>(section->Name), ".text", 5) == 0)
		{
			outBase = reinterpret_cast<uintptr_t>(hModule) + section->VirtualAddress;
			outSize = section->Misc.VirtualSize;
			return true;
		}
	}

	return false;
}

// Get the output directory for signature files
fs::path GetOutputDir()
{
	// Use the MQ resource path or fallback to plugin directory
	char mqPath[MAX_PATH] = {};
	GetModuleFileNameA(nullptr, mqPath, MAX_PATH);
	fs::path exeDir = fs::path(mqPath).parent_path();

	// Try to use a "signatures" subfolder next to the plugin
	fs::path sigDir = exeDir / "signatures";
	if (!fs::exists(sigDir))
	{
		std::error_code ec;
		fs::create_directories(sigDir, ec);
	}
	return sigDir;
}

uintptr_t GetPreferredBase(sigscan::OffsetModule mod)
{
	switch (mod)
	{
	case sigscan::OffsetModule::EQGame:
		return eqlib::EQGamePreferredAddress;
	case sigscan::OffsetModule::EQMain:
	case sigscan::OffsetModule::EQGraphics:
		return eqlib::EQLibraryPreferredAddress;
	}
	return 0;
}

uintptr_t GetActualBase(sigscan::OffsetModule mod)
{
	switch (mod)
	{
	case sigscan::OffsetModule::EQGame:
		return reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
	case sigscan::OffsetModule::EQMain:
		return eqlib::EQMainBaseAddress;
	case sigscan::OffsetModule::EQGraphics:
		return eqlib::EQGraphicsBaseAddress;
	}
	return 0;
}

uintptr_t FixOffset(const sigscan::OffsetInfo& info)
{
	uintptr_t preferred = GetPreferredBase(info.module);
	uintptr_t actual = GetActualBase(info.module);
	return info.preferredAddress - preferred + actual;
}

const char* ModuleName(sigscan::OffsetModule mod)
{
	switch (mod)
	{
	case sigscan::OffsetModule::EQGame: return "eqgame";
	case sigscan::OffsetModule::EQMain: return "eqmain";
	case sigscan::OffsetModule::EQGraphics: return "eqgraphics";
	}
	return "unknown";
}

void CommandGenerate(PlayerClient* pChar, const char* szLine)
{
	WriteChatf("\ag[SigScan]\ax Starting signature generation...");

	auto table = sigscan::GetOffsetTable();

	// Group by module
	std::map<sigscan::OffsetModule, std::vector<sigscan::OffsetInfo>> byModule;
	for (const auto& info : table)
		byModule[info.module].push_back(info);

	fs::path outDir = GetOutputDir();

	for (auto& [mod, offsets] : byModule)
	{
		HMODULE hMod = nullptr;
		switch (mod)
		{
		case sigscan::OffsetModule::EQGame:
			hMod = GetModuleHandleW(nullptr);
			break;
		case sigscan::OffsetModule::EQMain:
			hMod = GetModuleHandleW(eqlib::EQMainModuleName);
			break;
		case sigscan::OffsetModule::EQGraphics:
			hMod = GetModuleHandleW(eqlib::EQGraphicsModuleName);
			break;
		}

		if (!hMod)
		{
			WriteChatf("\ar[SigScan]\ax Module %s not loaded, skipping", ModuleName(mod));
			continue;
		}

		uintptr_t textBase = 0;
		size_t textSize = 0;
		if (!GetTextSection(hMod, textBase, textSize))
		{
			WriteChatf("\ar[SigScan]\ax Could not find .text section for %s", ModuleName(mod));
			continue;
		}

		sigscan::SigGenerator gen;
		gen.SetTextSection(textBase, textSize);
		gen.SetPreferredBase(GetPreferredBase(mod), GetActualBase(mod));

		std::vector<sigscan::SignatureEntry> entries;
		int success = 0, fail = 0;

		for (const auto& info : offsets)
		{
			uintptr_t runtimeAddr = FixOffset(info);
			auto result = gen.Generate(info.name, runtimeAddr);

			if (result.success)
			{
				entries.push_back(result.entry);
				success++;
			}
			else
			{
				fail++;
				WriteChatf("\ay[SigScan]\ax Failed: %s - %s", info.name.c_str(), result.errorMessage.c_str());
			}
		}

		// Build client date string
		std::ostringstream dateStr;
		dateStr << __ClientDate;

		std::string json = sigscan::SignaturesToJson(entries, dateStr.str());

		fs::path outFile = outDir / (std::string("signatures_") + ModuleName(mod) + ".json");
		std::ofstream file(outFile);
		if (file.is_open())
		{
			file << json;
			file.close();
			WriteChatf("\ag[SigScan]\ax Wrote %s: %d/%d signatures (%d failed)",
				outFile.string().c_str(), success, static_cast<int>(offsets.size()), fail);
		}
		else
		{
			WriteChatf("\ar[SigScan]\ax Failed to write %s", outFile.string().c_str());
		}
	}

	WriteChatf("\ag[SigScan]\ax Generation complete.");
}

void CommandScan(PlayerClient* pChar, const char* szLine)
{
	WriteChatf("\ag[SigScan]\ax Starting signature scan...");

	fs::path sigDir = GetOutputDir();
	std::vector<sigscan::ScanResult> allResults;

	struct ModuleConfig
	{
		sigscan::OffsetModule mod;
		const char* filename;
		HMODULE hMod;
	};

	std::vector<ModuleConfig> modules = {
		{ sigscan::OffsetModule::EQGame, "signatures_eqgame.json", GetModuleHandleW(nullptr) },
		{ sigscan::OffsetModule::EQMain, "signatures_eqmain.json", GetModuleHandleW(eqlib::EQMainModuleName) },
		{ sigscan::OffsetModule::EQGraphics, "signatures_eqgraphics.json", GetModuleHandleW(eqlib::EQGraphicsModuleName) },
	};

	for (const auto& config : modules)
	{
		fs::path sigFile = sigDir / config.filename;
		if (!fs::exists(sigFile))
		{
			WriteChatf("\ay[SigScan]\ax Signature file not found: %s", sigFile.string().c_str());
			continue;
		}

		if (!config.hMod)
		{
			WriteChatf("\ay[SigScan]\ax Module not loaded for %s", config.filename);
			continue;
		}

		// Read signature file
		std::ifstream file(sigFile);
		std::string json((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
		file.close();

		std::string clientDate;
		auto entries = sigscan::SignaturesFromJson(json, &clientDate);

		if (entries.empty())
		{
			WriteChatf("\ay[SigScan]\ax No signatures found in %s", config.filename);
			continue;
		}

		uintptr_t textBase = 0;
		size_t textSize = 0;
		if (!GetTextSection(config.hMod, textBase, textSize))
		{
			WriteChatf("\ar[SigScan]\ax Could not find .text section for %s", config.filename);
			continue;
		}

		sigscan::SigScanner scanner;
		scanner.SetTextSection(textBase, textSize);
		scanner.SetBaseAddresses(GetPreferredBase(config.mod), GetActualBase(config.mod));

		auto results = scanner.ScanAll(entries);
		allResults.insert(allResults.end(), results.begin(), results.end());

		WriteChatf("\ag[SigScan]\ax Scanned %s: %d entries", config.filename, static_cast<int>(results.size()));
	}

	if (allResults.empty())
	{
		WriteChatf("\ar[SigScan]\ax No results to report.");
		return;
	}

	// Generate report
	auto report = sigscan::GenerateReport(allResults);
	std::string summary = sigscan::FormatSummary(report);
	WriteChatf("\ag[SigScan]\ax %s", summary.c_str());

	// Write results JSON
	std::string resultsJson = sigscan::ScanResultsToJson(allResults);
	fs::path resultsFile = sigDir / "scan_results.json";
	std::ofstream outFile(resultsFile);
	if (outFile.is_open())
	{
		outFile << resultsJson;
		outFile.close();
		WriteChatf("\ag[SigScan]\ax Results written to %s", resultsFile.string().c_str());
	}

	// Write full report
	std::string fullReport = sigscan::FormatReport(report);
	fs::path reportFile = sigDir / "scan_report.txt";
	std::ofstream repFile(reportFile);
	if (repFile.is_open())
	{
		repFile << fullReport;
		repFile.close();
		WriteChatf("\ag[SigScan]\ax Report written to %s", reportFile.string().c_str());
	}
}

void CommandReport(PlayerClient* pChar, const char* szLine)
{
	fs::path sigDir = GetOutputDir();
	fs::path reportFile = sigDir / "scan_report.txt";

	if (!fs::exists(reportFile))
	{
		WriteChatf("\ar[SigScan]\ax No report file found. Run /sigscan scan first.");
		return;
	}

	std::ifstream file(reportFile);
	std::string line;
	while (std::getline(file, line))
	{
		WriteChatf("[SigScan] %s", line.c_str());
	}
}

void CommandSigScan(PlayerClient* pChar, const char* szLine)
{
	char subCommand[256] = {};
	GetArg(subCommand, szLine, 1);

	if (_stricmp(subCommand, "generate") == 0 || _stricmp(subCommand, "gen") == 0)
	{
		CommandGenerate(pChar, GetNextArg(szLine));
	}
	else if (_stricmp(subCommand, "scan") == 0)
	{
		CommandScan(pChar, GetNextArg(szLine));
	}
	else if (_stricmp(subCommand, "report") == 0)
	{
		CommandReport(pChar, GetNextArg(szLine));
	}
	else
	{
		WriteChatf("\ag[SigScan]\ax Usage:");
		WriteChatf("  /sigscan generate - Generate signatures from current known-good offsets");
		WriteChatf("  /sigscan scan     - Scan current process using signature database");
		WriteChatf("  /sigscan report   - Display last scan report");
	}
}

} // anonymous namespace

PLUGIN_API void InitializePlugin()
{
	DebugSpewAlways("Initializing MQ2SigScan");
	AddCommand("/sigscan", CommandSigScan);
	WriteChatf("\ag[SigScan]\ax Loaded. Use /sigscan for help.");
}

PLUGIN_API void ShutdownPlugin()
{
	DebugSpewAlways("Shutting down MQ2SigScan");
	RemoveCommand("/sigscan");
}
