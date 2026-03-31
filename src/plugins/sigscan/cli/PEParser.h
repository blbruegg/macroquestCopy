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

#include <Windows.h>
#include <cstdint>
#include <string>
#include <vector>

namespace sigscan {

struct PESection
{
	std::string name;
	uint32_t virtualAddress;
	uint32_t virtualSize;
	uint32_t rawDataOffset;
	uint32_t rawDataSize;
	uint32_t characteristics;
};

class PEFile
{
public:
	~PEFile();

	bool Load(const std::wstring& filePath);
	void Close();

	// Get the preferred image base from the PE headers
	uintptr_t GetPreferredBase() const { return m_preferredBase; }

	// Get the .text section info
	bool GetTextSection(uint32_t& outRVA, uint32_t& outSize) const;

	// Get combined bounds of all executable sections
	bool GetCodeBounds(uint32_t& outRVA, uint32_t& outSize) const;

	// Get a pointer to data at a given RVA
	const uint8_t* GetDataAtRVA(uint32_t rva) const;

	// Build a contiguous buffer mapping all code sections by virtual address.
	// Fills gaps between sections with 0xCC (INT3). Returns the buffer, and sets
	// outRVA/outSize to the base RVA and total size of the mapped region.
	std::vector<uint8_t> BuildCodeBuffer(uint32_t& outRVA, uint32_t& outSize) const;

	// Get all sections
	const std::vector<PESection>& GetSections() const { return m_sections; }

private:
	uint32_t RVAToFileOffset(uint32_t rva) const;

	HANDLE m_fileHandle = INVALID_HANDLE_VALUE;
	HANDLE m_mappingHandle = nullptr;
	const uint8_t* m_mappedBase = nullptr;
	size_t m_fileSize = 0;
	uintptr_t m_preferredBase = 0;
	std::vector<PESection> m_sections;
};

} // namespace sigscan
