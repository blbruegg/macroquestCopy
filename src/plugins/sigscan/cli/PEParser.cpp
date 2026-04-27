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

#include "PEParser.h"
#include <algorithm>
#include <cstring>

namespace sigscan {

PEFile::~PEFile()
{
	Close();
}

bool PEFile::Load(const std::wstring& filePath)
{
	Close();

	m_fileHandle = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
		nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (m_fileHandle == INVALID_HANDLE_VALUE)
		return false;

	LARGE_INTEGER fileSize;
	if (!GetFileSizeEx(m_fileHandle, &fileSize))
	{
		Close();
		return false;
	}
	m_fileSize = static_cast<size_t>(fileSize.QuadPart);

	m_mappingHandle = CreateFileMappingW(m_fileHandle, nullptr, PAGE_READONLY, 0, 0, nullptr);
	if (!m_mappingHandle)
	{
		Close();
		return false;
	}

	m_mappedBase = static_cast<const uint8_t*>(MapViewOfFile(m_mappingHandle, FILE_MAP_READ, 0, 0, 0));
	if (!m_mappedBase)
	{
		Close();
		return false;
	}

	// Parse PE headers
	auto* dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(m_mappedBase);
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		Close();
		return false;
	}

	auto* ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS64*>(m_mappedBase + dosHeader->e_lfanew);
	if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
	{
		Close();
		return false;
	}

	m_preferredBase = ntHeaders->OptionalHeader.ImageBase;

	// Parse sections
	auto* section = IMAGE_FIRST_SECTION(ntHeaders);
	for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i, ++section)
	{
		PESection sec;
		sec.name = std::string(reinterpret_cast<const char*>(section->Name), 8);
		// Trim null bytes
		sec.name.erase(sec.name.find('\0'));
		sec.virtualAddress = section->VirtualAddress;
		sec.virtualSize = section->Misc.VirtualSize;
		sec.rawDataOffset = section->PointerToRawData;
		sec.rawDataSize = section->SizeOfRawData;
		sec.characteristics = section->Characteristics;
		m_sections.push_back(sec);
	}

	return true;
}

void PEFile::Close()
{
	if (m_mappedBase)
	{
		UnmapViewOfFile(m_mappedBase);
		m_mappedBase = nullptr;
	}
	if (m_mappingHandle)
	{
		CloseHandle(m_mappingHandle);
		m_mappingHandle = nullptr;
	}
	if (m_fileHandle != INVALID_HANDLE_VALUE)
	{
		CloseHandle(m_fileHandle);
		m_fileHandle = INVALID_HANDLE_VALUE;
	}
	m_sections.clear();
	m_fileSize = 0;
	m_preferredBase = 0;
}

bool PEFile::GetTextSection(uint32_t& outRVA, uint32_t& outSize) const
{
	for (const auto& sec : m_sections)
	{
		if (sec.name == ".text")
		{
			outRVA = sec.virtualAddress;
			outSize = sec.virtualSize;
			return true;
		}
	}
	return false;
}

bool PEFile::GetCodeBounds(uint32_t& outRVA, uint32_t& outSize) const
{
	uint32_t minRVA = UINT32_MAX;
	uint32_t maxEnd = 0;

	for (const auto& sec : m_sections)
	{
		if (sec.characteristics & IMAGE_SCN_CNT_CODE)
		{
			if (sec.virtualAddress < minRVA)
				minRVA = sec.virtualAddress;
			uint32_t end = sec.virtualAddress + sec.virtualSize;
			if (end > maxEnd)
				maxEnd = end;
		}
	}

	if (minRVA == UINT32_MAX)
		return false;

	outRVA = minRVA;
	outSize = maxEnd - minRVA;
	return true;
}

uint32_t PEFile::RVAToFileOffset(uint32_t rva) const
{
	for (const auto& sec : m_sections)
	{
		if (rva >= sec.virtualAddress && rva < sec.virtualAddress + sec.rawDataSize)
		{
			return sec.rawDataOffset + (rva - sec.virtualAddress);
		}
	}
	return 0;
}

const uint8_t* PEFile::GetDataAtRVA(uint32_t rva) const
{
	uint32_t fileOffset = RVAToFileOffset(rva);
	if (fileOffset == 0 || fileOffset >= m_fileSize)
		return nullptr;
	return m_mappedBase + fileOffset;
}

std::vector<uint8_t> PEFile::BuildCodeBuffer(uint32_t& outRVA, uint32_t& outSize) const
{
	// Find all code sections
	uint32_t minRVA = UINT32_MAX;
	uint32_t maxEnd = 0;

	for (const auto& sec : m_sections)
	{
		if (sec.characteristics & IMAGE_SCN_CNT_CODE)
		{
			if (sec.virtualAddress < minRVA)
				minRVA = sec.virtualAddress;
			uint32_t end = sec.virtualAddress + sec.virtualSize;
			if (end > maxEnd)
				maxEnd = end;
		}
	}

	if (minRVA == UINT32_MAX)
	{
		outRVA = 0;
		outSize = 0;
		return {};
	}

	uint32_t totalSize = maxEnd - minRVA;

	// Fill with INT3 (0xCC) so gaps between sections won't match any real pattern
	std::vector<uint8_t> buffer(totalSize, 0xCC);

	// Copy each code section into its correct virtual offset
	for (const auto& sec : m_sections)
	{
		if (!(sec.characteristics & IMAGE_SCN_CNT_CODE))
			continue;

		uint32_t offset = sec.virtualAddress - minRVA;
		uint32_t copySize = std::min(sec.rawDataSize, sec.virtualSize);

		if (sec.rawDataOffset + copySize <= m_fileSize)
		{
			std::memcpy(buffer.data() + offset, m_mappedBase + sec.rawDataOffset, copySize);
		}
	}

	outRVA = minRVA;
	outSize = totalSize;
	return buffer;
}

} // namespace sigscan
