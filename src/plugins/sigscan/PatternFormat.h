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

#include <cstdint>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <stdexcept>

namespace sigscan {

struct PatternData
{
	std::vector<uint8_t> bytes;
	std::string mask; // 'x' = match, '?' = wildcard
};

// Convert IDA-style pattern string ("48 89 5C 24 ?? 57") to bytes + mask
inline PatternData PatternFromString(const std::string& pattern)
{
	PatternData result;
	std::istringstream stream(pattern);
	std::string token;

	while (stream >> token)
	{
		if (token == "??" || token == "?")
		{
			result.bytes.push_back(0);
			result.mask.push_back('?');
		}
		else
		{
			unsigned long val = std::stoul(token, nullptr, 16);
			result.bytes.push_back(static_cast<uint8_t>(val));
			result.mask.push_back('x');
		}
	}

	return result;
}

// Convert bytes + mask to IDA-style pattern string
inline std::string PatternToString(const uint8_t* bytes, const char* mask, size_t length)
{
	std::ostringstream stream;

	for (size_t i = 0; i < length; ++i)
	{
		if (i > 0)
			stream << ' ';

		if (mask[i] == '?')
			stream << "??";
		else
			stream << std::uppercase << std::hex << std::setw(2) << std::setfill('0')
			       << static_cast<int>(bytes[i]);
	}

	return stream.str();
}

inline std::string PatternToString(const PatternData& data)
{
	return PatternToString(data.bytes.data(), data.mask.c_str(), data.bytes.size());
}

} // namespace sigscan
