local _M = {}

_M.version = "0.7.2"

local bit = require("bit")

local util = require("lib.util")

-- Shortcuts
local byte = string.byte
local find = string.find
local sub = string.sub

-- Returns whether the given ordinal is a decimal character
local function is_decimal_byte(ord)
	return ord ~= nil and ord >= 48 and ord <= 57
end

-- Converts a decimal ascii ordinal to its decimal value
local function ord2dec(ord)
	return ord-48
end

-- Returns whether the given ordinal is a hex character
local function is_hex_byte(ord)
	return ord ~= nil and ((ord >= 48 and ord <= 57) or (ord >= 65 and ord <= 70) or (ord >= 97 and ord <= 102))
end

-- Converts a hex ascii ordinal to its hex value
local function ord2hex(ord)
	if ord >= 97 and ord <= 97+15 then
		return ord-97+10
	elseif ord >= 65 and ord <= 65+15 then
		return ord-65+10
	else
		return ord-48
	end
end

-- Converts a hex character to the respective number
local function xsingle2c(c)
	return ord2hex(byte(c))
end

-- Converts a two-digit hex string to the respective number
local function x2c(s)
	return xsingle2c(s:sub(1, 1)) * 16 + xsingle2c(s:sub(2, 2))
end

function _M.base64_encode(waf, value)
	if value == nil or value:len() == 0 then
		return value, false
	end
	return ngx.encode_base64(value), true
end

function _M.base64_decode(waf, value)
	if value == nil or value:len() == 0 then
		return value, false
	end

	local transformed = ngx.decode_base64(value)
	if not transformed then
		return value, false
	end
	return transformed, true
end

function _M.length(waf, value)
	return value == nil and nil or tostring(value:len()), true
end

function _M.lowercase(waf, value)
	if value == nil then
		return nil, false
	end
	local low_value = string.lower(value)
	return low_value, value ~= low_value
end

function _M.sha1(waf, value)
	if value == nil then
		return nil, false
	end
	return ngx.sha1_bin(value), true
end

function _M.md5(waf, value)
	if value == nil then
		return nil, false
	end
	return ngx.md5_bin(value), true
end

function _M.hex_encode(waf, value)
	-- Empty values are considered transformed here
	-- TODO: Report and fix in ModSecurity.
	if value == nil then
		return value, false
	end

	return util.hex_encode(value), true
end

function _M.remove_nulls(waf, value)
	if value == nil then
		return nil, false
	end

	local len = value:len()
	local start = 1

	local toks = {}
	local idx = 1
	for i = 1, len do
		local c = byte(value, i)
		if c == 0 then
			toks[idx] = sub(value, start, i-1)
			idx = idx + 1
			ws = 2
			start = i+1
		end
	end

	if start > 1 then
		toks[idx] = sub(value, start)
	end

	if idx == 1 then
		return value, false
	else
		return table.concat(toks), true
	end
end

function _M.replace_nulls(waf, value)
	if value == nil or value:len() == 0 then
		return value, false
	end

	local p = find(value, "%z")
	if p == nil then
		return value, false
	end
	return string.gsub(value, "%z", " "), true
end

function _M.replace_comments(waf, value)
	if value == nil then
		return nil, false
	end

	local p = 1
	local start = 1
	local toks = {}
	local idx = 1

	local p = find(value, "/*", 1, true)
	while p ~= nil do
		toks[idx] = sub(value, start, p-1)
		idx = idx + 1

		local pp = find(value, "*/", p+1, true)
		if pp == nil then
			-- Ignore rest
			toks[idx] = ""
			start = 1
			break
		end

		start = pp + 2
		p = find(value, "/*", start, true)
	end

	if start > 1 then
		toks[idx] = sub(value, start)
		idx = idx + 1
	end

	if idx == 1 then
		return value, false
	else
		return table.concat(toks, " "), true
	end
end

function _M.compress_whitespace(waf, value)
	if value == nil then
		return nil, false
	end
	local len = value:len()
	local ws = 0
	local start = 1

	local toks = {}
	local idx = 1
	for i = 1, len do
		local c = byte(value, i)
		if c == 32 or c >= 9 and c <= 13 then
			if ws == 0 then
				ws = 1
			elseif ws == 1 then
				toks[idx] = sub(value, start, i-2)
				idx = idx + 1
				ws = 2
				start = i+1
			else
				start = i+1
			end
		else
			ws = 0
		end
	end

	if start > 1 then
		toks[idx] = sub(value, start)
	end

	if idx == 1 then
		return value, false
	else
		return table.concat(toks, " "), true
	end
end

function _M.remove_whitespace(waf, value)
	if value == nil then
		return nil, false
	end

	local len = value:len()
	local start = 1

	local toks = {}
	local idx = 1
	for i = 1, len do
		local c = byte(value, i)
		if c == 32 or c >= 9 and c <= 13 then
			toks[idx] = sub(value, start, i-1)
			idx = idx + 1
			ws = 2
			start = i+1
		end
	end

	if start > 1 then
		toks[idx] = sub(value, start)
	end

	if idx == 1 then
		return value, false
	else
		return table.concat(toks), true
	end
end

function _M.css_decode(waf, value)
	if value == nil then
		return nil, false
	end

	-- No need to do anything without any backslashes
	local p = find(value, "\\", 1, true)
	if p == nil then
		return value, false
	end

	local last = 1
	local toks = {}
	while p ~= nil do
		toks[#toks + 1] = sub(value, last, p-1)
		local to = p+1

		if p == #value then
			last = p + 1
			break
		end

		local hexmatch = string.match(sub(value, p+1), "^[a-fA-F0-9]+")
		if hexmatch then
			local hexlen = #hexmatch
			if hexlen > 6 then
				hexlen = 6
			end

			local fullcheck = false
			if hexlen == 1 then
				toks[#toks + 1] = string.char(xsingle2c(hexmatch))
				last = to + 1
			elseif hexlen == 2 then
				-- Use the last two from the end.
				toks[#toks + 1] = string.char(x2c(hexmatch))
				last = to + 2
			elseif hexlen == 3 then
				toks[#toks + 1] = string.char(x2c(sub(hexmatch, 2)))
				last = to + 3
			elseif hexlen == 4 then
				-- Use the last two from the end, but request a full width check.
				toks[#toks + 1] = string.char(x2c(sub(hexmatch, 3)))
				fullcheck = true
				last = to + 4
			elseif hexlen == 5 then
				-- Use the last two from the end, but request a full width check if the number is
				-- greater or equal to 0xFFFF.
				toks[#toks + 1] = string.char(x2c(sub(hexmatch, 4)))
				if sub(hexmatch, 1, 1) == "0" then
					fullcheck = true
				end
				last = to + 5
			else -- >= 6
				-- Use the last two from the end, but request a full width check if the number is
				-- greater or equal to 0xFFFF.
				toks[#toks + 1] = string.char(x2c(sub(hexmatch, 5)))
				if sub(hexmatch, 1, 2) == "00" then
					fullcheck = true
				end
				last = to + 6
			end

			-- Full width ASCII (0xff01 - 0xff5e) needs 0x20 added
			if fullcheck then
				assert(#(toks[#toks]) == 1)
				local c = byte(toks[#toks])
				if c > 0 and c < 0x5f and string.match(sub(hexmatch, hexlen-3, hexlen-2), "[fF][fF]") then
					toks[#toks] = string.char(c + 0x20)
				end
			end

			-- We must ignore a single whitespace after a hex escape
			if find(value, "%s", last) == last then
				last = last + 1
			end
		elseif sub(value, p+1, p+1) == "\n" then
			-- A newline character following backslash is ignored.
			last = to + 1
		else
			toks[#toks + 1] = sub(value, p+1, p+1)
			last = to + 1
		end

		p = find(value, "\\.?", last)
	end

	toks[#toks + 1] = sub(value, last)

	return table.concat(toks), true
end

local HTML_ENTITIES = {
	"amp", "&",
	"quot", "\"",
	"lt", "<",
	"gt", ">",
	"nbsp", string.char(160),
}
function _M.html_entity_decode(waf, value)
	if value == nil then
		return nil, false
	end

	local p = find(value, "&", 1, true)

	-- Shortcut: No & = no encoding
	if p == nil then
		return value, false
	end

	local last = 0
	local toks = {}
	while p ~= nil do
		toks[#toks + 1] = sub(value, last+1, p-1)

		-- Length of the current entity token (excluding the &)
		local toklen = 0
		-- Whether the token was decoded
		local token_decoded = false

		local next_char = byte(value, p+1)
		if next_char == 35 then -- "#"
			next_char = byte(value, p+2)

			-- Pattern replacement for #[xX][a-fA-F0-9]+
			if next_char == 120 or next_char == 88 then  -- x / X

				--[[
				This is clearly not standard behavior, but ModSecurity ignores characters > 0xFF
				by simply downcasting them to an unsigned byte.
				Thus, &#1000; becomes chr(1000 % 256) == chr(232).
				--]]
				local i = 0
				local hexval = 0
				local next_char = byte(value, p+3)
				while is_hex_byte(next_char) do
					hexval = bit.lshift(hexval, 4) + ord2hex(next_char)

					i = i + 1
					next_char = byte(value, p+3+i)
				end

				-- If we decoded at least one hex char, use it.
				if i >= 1 then
					toks[#toks + 1] = string.char(bit.band(hexval, 0xFF))
					toklen = 2 + i
					token_decoded = true
				end
			end

			if not token_decoded then

				local i = 2
				local decval = 0
				while is_decimal_byte(next_char) do
					decval = decval * 10 + ord2dec(next_char)
					i = i + 1
					next_char = byte(value, p+i)
				end

				-- If we decoded at least one digit, use it.
				if i >= 3 then
					toks[#toks + 1] = string.char(bit.band(decval, 0xFF))
					toklen = i-1
					token_decoded = true
				end
			end
		else
			local i = 1
			while HTML_ENTITIES[i] ~= nil do
				if find(value, HTML_ENTITIES[i], p+1, true) == p+1 then
					toks[#toks + 1] = HTML_ENTITIES[i+1]
					toklen = #HTML_ENTITIES[i]
					token_decoded = true
					break
				end
				i = i + 2
			end
		end

		-- Skip trailing semicolon (standard says it's required, but apparently not.)
		if byte(value, p + toklen + 1) == 59 then
			toklen = toklen + 1
		end

		-- If the entity wasn't decoded, copy it as-is
		if not token_decoded then
			toks[#toks + 1] = sub(value, p, p+toklen)
		end

		last = p + toklen
		p = find(value, "&", last + 1, true)
	end
	toks[#toks + 1] = sub(value, last + 1)
	return table.concat(toks), true
end

local MAGIC_JS_ESCAPES = {
	a="\a",
	b="\b",
	f="\f",
	n="\n",
	r="\r",
	t="\t",
	v="\v",
}
function _M.js_decode(waf, value)
	if value == nil then
		return nil, false
	end

	local p = find(value, "\\", 1, true)
	if p == nil then
		return value, false
	end

	local last = 0
	local toks = {}
	local ntoks = 0
	local changed = false
	local value_len = value:len()
	while p ~= nil do
		toks[ntoks + 1] = sub(value, last+1, p-1)
		ntoks = ntoks + 1

		-- Length of the current entity token (excluding the \\)
		local toklen = 0
		local token_decoded = false

		local next_char = byte(value, p+1)
		if p == value_len then
			-- \\ at end of string
			toks[ntoks + 1] = "\\"
			ntoks = ntoks + 1
		elseif next_char == 92 then -- "\"
			toks[ntoks + 1] = "\\"
			ntoks = ntoks + 1
			toklen = 1
			changed = true
		elseif next_char == 117 then
			-- uXXXX hex syntax
			-- Use only the lower byte, first two bytes only trigger an added offset if they're "FF"
			-- TODO: Fix this mess.
			local hc2 = byte(value, p+2)
			local hc3 = byte(value, p+3)
			local hc4 = byte(value, p+4)
			local hc5 = byte(value, p+5)
			if is_hex_byte(hc2) and is_hex_byte(hc3) and is_hex_byte(hc4) and is_hex_byte(hc5) then
				local hexval = bit.lshift(ord2hex(hc4), 4) + ord2hex(hc5)

				-- Full width ASCII (ff01 - ff5e) needs 0x20 added
				if hexval <= 0x5f and (hc2 == 70 or hc2 == 102) and (hc3 == 70 or hc3 == 102) then
					hexval = hexval + 0x20
				end

				toks[ntoks + 1] = string.char(hexval)
				ntoks = ntoks + 1
				toklen = 5
				changed = true
			else
				toks[ntoks + 1] = "u"
				ntoks = ntoks + 1
				toklen = 1
				changed = true
			end
		elseif next_char == 120 then
			-- xXX hex syntax
			local hc2 = byte(value, p+2)
			local hc3 = byte(value, p+3)
			if is_hex_byte(hc2) and is_hex_byte(hc3) then
				local hexval = bit.lshift(ord2hex(hc2), 4) + ord2hex(hc3)
				toks[ntoks + 1] = string.char(hexval)
				toklen = 3
			else
				toks[ntoks + 1] = "x"
				toklen = 1
			end
			ntoks = ntoks + 1
			changed = true
		elseif next_char >= 48 and next_char <= 55 then -- 0-7
			local c = string.match(value, "[0-7][0-7]?[0-7]?", p+1)
			local v = 0
			for i = 1, #c do
				v = v * 8 + xsingle2c(sub(c, i, i))
			end
			--  Do not use 3 characters if we will be > 1 byte
			if v > 255 then
				toks[ntoks + 1] = string.char(bit.rshift(v, 3))
				ntoks = ntoks + 1
				toklen = 2
			else
				toks[ntoks + 1] = string.char(v)
				ntoks = ntoks + 1
				toklen = #c
			end
			changed = true
		else
			toks[ntoks + 1] = MAGIC_JS_ESCAPES[string.char(next_char)] or string.char(next_char)
			ntoks = ntoks + 1
			toklen = 1
			changed = true
		end

		last = p + toklen
		p = find(value, "\\", last + 1, true)
	end
	toks[ntoks + 1] = sub(value, last + 1)
	return table.concat(toks), changed
end

function _M.normalise_path(waf, value)
	if value == nil then
		return nil, false
	end

	local toks = {}
	local last = 0

	-- Special case for leading /
	if sub(value, last+1, last+1) == "/" then
		toks[#toks + 1] = ""
		last = last+1
	end

	while true do
		local p = find(value, "/", last+1, true)

		local dir = sub(value, last+1, p and p-1 or value:len())
		last = p

		if dir == "" and p == nil then
			-- Trailing /
			toks[#toks + 1] = ""
		elseif dir == "" or dir == "." then
			-- Ignore~
		elseif dir == ".." then
			local prev = toks[#toks]
			if prev == "" then
				-- This is / -> just ignore the back reference
			elseif prev ~= nil and prev ~= ".." then
				-- foo/bar/.. -> foo
				toks[#toks] = nil
			else
				toks[#toks + 1] = dir
			end
		else
			toks[#toks + 1] = dir
		end

		if p == nil then
			break
		end
	end

	local transformed = table.concat(toks, "/")
	return transformed, transformed ~= value
end

function _M.cmd_line(waf, value)
	if value == nil then
		return nil, false
	end

	local transformed
	-- Delete stuff
	transformed = string.gsub(value, "[\"'%^\\]", "")
	-- Compress whitespace
	transformed = string.gsub(transformed, "[%s,;]+", " ")
	-- Remove space before / or (
	transformed = string.gsub(transformed, "%s([/%(])", "%1")

	transformed = string.lower(transformed)

	return transformed, transformed ~= value
end
_M.normalise_path_win = _M.normalise_path

function _M.url_decode(waf, value)
	if value == nil then
		return nil, false
	end

	local end_len = value:len() + 1
	local p = find(value, "%", 1, true) or end_len
	p = math.min(p, find(value, "+", 1, true) or end_len)
	if p == end_len then
		return value, false
	end

	local changed = false
	local last = 0
	local toks = {}
	while p ~= end_len do
		toks[#toks + 1] = sub(value, last+1, p-1)

		local c = byte(value, p)
		if c == 43 then  -- "+"
			last = p
			toks[#toks + 1] = " "
			changed = true
		else
			local hc1 = byte(value, p+1)
			local hc2 = byte(value, p+2)

			if is_hex_byte(hc1) and is_hex_byte(hc2) then
				last = p + 2
				toks[#toks + 1] = string.char(bit.lshift(ord2hex(hc1), 4) + ord2hex(hc2))
				changed = true
			else
				-- Skip over %
				last = p
				toks[#toks + 1] = "%"
			end
		end

		p = find(value, "%", last+1, true) or end_len
		p = math.min(p, find(value, "+", last+1, true) or end_len)
	end
	toks[#toks + 1] = sub(value, last + 1)

	return table.concat(toks), changed
end

-- Ignore the MS-specific escaping foo, we don't have IIS-based nginx anyway.
_M.url_decode_uni = _M.url_decode

return _M
