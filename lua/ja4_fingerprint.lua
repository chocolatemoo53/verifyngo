-- lua/ja4_fingerprint.lua
-- nginx Lua module that computes JA4/JA5 fingerprints from the TLS ClientHello
-- and passes them to verifyngo as headers.
--
-- Requires: OpenResty >= 1.29.2.1 with lua-resty-core >= 0.1.32
-- Install: opm get nemethhh/lua-resty-ja4
--
-- Usage in nginx.conf:
--
--   lua_package_path "/path/to/lua/?.lua;;";
--
--   server {
--       listen 443 ssl;
--
--       ssl_client_hello_by_lua_block {
--           require("ja4_fingerprint").compute()
--       }
--
--       location / {
--           proxy_pass http://127.0.0.1:8080;
--           # Headers are set automatically by the lua module
--       }
--   }
--

local _M = {}

-- JA5: ephemeral TLS extensions to exclude from the fingerprint hash.
-- These change between connections for the same client (session resumption,
-- padding heuristics) and break fingerprint stability.
-- Source: ntop JA5 spec (Sep 2026)
local JA5_EPHEMERAL_EXTENSIONS = {
    [0x0000] = true,  -- server_name (excluded from extension hash per JA4 spec)
    [0x0010] = true,  -- application_layer_protocol_negotiation (excluded per JA4 spec)
    [0x0015] = true,  -- padding
    [0x0023] = true,  -- session_ticket
    [0x002c] = true,  -- pre_shared_key
    [0x0031] = true,  -- early_data
    [0x0039] = true,  -- psk_key_exchange_modes
    [0xff01] = true,  -- renegotiation_info (often ephemeral)
}

-- GREASE values to filter out (RFC 8701)
local GREASE = {
    [0x0a0a] = true, [0x1a1a] = true, [0x2a2a] = true,
    [0x3a3a] = true, [0x4a4a] = true, [0x5a5a] = true,
    [0x6a6a] = true, [0x7a7a] = true, [0x8a8a] = true,
    [0x9a9a] = true, [0xaaaa] = true, [0xbaba] = true,
    [0xcaca] = true, [0xdada] = true, [0xeaea] = true,
    [0xfafa] = true,
}

local function is_grease(val)
    return GREASE[val] or false
end

local function sha256_truncate(data, len)
    local resty_sha256 = require "resty.sha256"
    local resty_str = require "resty.string"
    local sha = resty_sha256:new()
    sha:update(data)
    local digest = sha:final()
    return resty_str.to_hex(digest):sub(1, len)
end

local function sorted_hex_list(items)
    local hex = {}
    for _, v in ipairs(items) do
        hex[#hex + 1] = string.format("%04x", v)
    end
    table.sort(hex)
    return table.concat(hex, ",")
end

--- Compute JA4 fingerprint from ClientHello data.
-- @param sni string|nil Server Name Indication
-- @param ciphers table List of cipher suite IDs (GREASE already excluded by lua-resty-core)
-- @param extensions table List of extension type IDs
-- @param ext_data table Map of extension type -> raw bytes (optional, for JA5)
-- @return string JA4 fingerprint in format proto_ver_sni_cc_dd_alpn_ciphash_exthash
function _M.compute_ja4(sni, ciphers, extensions, ext_data)
    -- Protocol: always "t" for TLS (QUIC would be "q")
    local proto = "t"

    -- Version: from supported_versions extension
    local version = "00"
    if ext_data and ext_data[0x002b] then
        local sv = ext_data[0x002b]
        -- supported_versions is a list of 2-byte values, take the highest
        local max_ver = 0
        for i = 1, #sv - 1, 2 do
            local ver = (sv:byte(i) << 8) | sv:byte(i + 1)
            if ver > max_ver and not is_grease(ver) then
                max_ver = ver
            end
        end
        if max_ver > 0 then
            version = string.format("%02x", max_ver):sub(-2)
        end
    end

    -- SNI indicator
    local sni_char = "i"
    if sni and sni ~= "" then
        sni_char = "d"
    end

    -- Cipher count (GREASE excluded by lua-resty-core, but double-check)
    local cipher_count = 0
    for _, c in ipairs(ciphers) do
        if not is_grease(c) then
            cipher_count = cipher_count + 1
        end
    end
    if cipher_count > 99 then cipher_count = 99 end

    -- Extension count (exclude GREASE)
    local ext_count = 0
    for _, e in ipairs(extensions) do
        if not is_grease(e) then
            ext_count = ext_count + 1
        end
    end
    if ext_count > 99 then ext_count = 99 end

    -- ALPN: first + last char of first protocol
    local alpn = "00"
    if ext_data and ext_data[0x0010] then
        local alpn_raw = ext_data[0x0010]
        -- ALPN format: 2-byte length + protocols, each: 1-byte len + name
        if #alpn_raw >= 3 then
            local proto_len = alpn_raw:byte(3)
            if #alpn_raw >= 3 + proto_len then
                local first_proto = alpn_raw:sub(4, 2 + proto_len)
                alpn = first_proto:sub(1, 1) .. first_proto:sub(-1)
            end
        end
    end

    -- Cipher hash: SHA-256 of sorted cipher hex list, truncated to 12
    local sorted_ciphers = {}
    for _, c in ipairs(ciphers) do
        if not is_grease(c) then
            sorted_ciphers[#sorted_ciphers + 1] = c
        end
    end
    local ciph_hash = sha256_truncate(sorted_hex_list(sorted_ciphers), 12)

    -- Extension hash: SHA-256 of sorted extensions (excluding SNI and ALPN per JA4 spec)
    -- + signature_algorithms in original order
    local sorted_exts = {}
    local sig_algs = nil
    for _, e in ipairs(extensions) do
        if not is_grease(e) and e ~= 0x0000 and e ~= 0x0010 then
            sorted_exts[#sorted_exts + 1] = e
        end
        if e == 0x000d then
            sig_algs = true  -- signature_algorithms present
        end
    end
    local ext_hash_input = sorted_hex_list(sorted_exts)
    if sig_algs and ext_data and ext_data[0x000d] then
        -- Append signature_algorithms in original order (not sorted)
        local sig_hex = {}
        local sig_raw = ext_data[0x000d]
        for i = 1, #sig_raw - 1, 2 do
            sig_hex[#sig_hex + 1] = string.format("%04x", (sig_raw:byte(i) << 8) | sig_raw:byte(i + 1))
        end
        ext_hash_input = ext_hash_input .. "_" .. table.concat(sig_hex, ",")
    end
    local ext_hash = sha256_truncate(ext_hash_input, 12)

    return string.format("%s%s%s%02d%02d%s_%s_%s",
        proto, version, sni_char, cipher_count, ext_count, alpn,
        ciph_hash, ext_hash)
end

--- Compute JA5 fingerprint (JA4 + stable extensions + supported_groups).
-- Extends JA4 by filtering ephemeral extensions and adding a fourth field
-- from the supported_groups extension.
-- @param sni string|nil Server Name Indication
-- @param ciphers table List of cipher suite IDs
-- @param extensions table List of extension type IDs
-- @param ext_data table Map of extension type -> raw bytes
-- @return string JA5 fingerprint in format proto_ver_sni_cc_dd_alpn_ciphash_exthash_grouphash
function _M.compute_ja5(sni, ciphers, extensions, ext_data)
    -- Same as JA4 but with filtered extensions
    local proto = "t"

    local version = "00"
    if ext_data and ext_data[0x002b] then
        local sv = ext_data[0x002b]
        local max_ver = 0
        for i = 1, #sv - 1, 2 do
            local ver = (sv:byte(i) << 8) | sv:byte(i + 1)
            if ver > max_ver and not is_grease(ver) then
                max_ver = ver
            end
        end
        if max_ver > 0 then
            version = string.format("%02x", max_ver):sub(-2)
        end
    end

    local sni_char = "i"
    if sni and sni ~= "" then
        sni_char = "d"
    end

    -- Count extensions excluding GREASE AND ephemeral
    local cipher_count = 0
    for _, c in ipairs(ciphers) do
        if not is_grease(c) then
            cipher_count = cipher_count + 1
        end
    end
    if cipher_count > 99 then cipher_count = 99 end

    local ext_count = 0
    local stable_exts = {}
    for _, e in ipairs(extensions) do
        if not is_grease(e) and not JA5_EPHEMERAL_EXTENSIONS[e] then
            ext_count = ext_count + 1
            stable_exts[#stable_exts + 1] = e
        end
    end
    if ext_count > 99 then ext_count = 99 end

    local alpn = "00"
    if ext_data and ext_data[0x0010] then
        local alpn_raw = ext_data[0x0010]
        if #alpn_raw >= 3 then
            local proto_len = alpn_raw:byte(3)
            if #alpn_raw >= 3 + proto_len then
                local first_proto = alpn_raw:sub(4, 2 + proto_len)
                alpn = first_proto:sub(1, 1) .. first_proto:sub(-1)
            end
        end
    end

    local sorted_ciphers = {}
    for _, c in ipairs(ciphers) do
        if not is_grease(c) then
            sorted_ciphers[#sorted_ciphers + 1] = c
        end
    end
    local ciph_hash = sha256_truncate(sorted_hex_list(sorted_ciphers), 12)

    -- Extension hash uses STABLE extensions only (JA5 difference from JA4)
    local sorted_exts = {}
    local sig_algs = nil
    for _, e in ipairs(stable_exts) do
        if e ~= 0x000d then
            sorted_exts[#sorted_exts + 1] = e
        end
        if e == 0x000d then
            sig_algs = true
        end
    end
    local ext_hash_input = sorted_hex_list(sorted_exts)
    if sig_algs and ext_data and ext_data[0x000d] then
        local sig_hex = {}
        local sig_raw = ext_data[0x000d]
        for i = 1, #sig_raw - 1, 2 do
            sig_hex[#sig_hex + 1] = string.format("%04x", (sig_raw:byte(i) << 8) | sig_raw:byte(i + 1))
        end
        ext_hash_input = ext_hash_input .. "_" .. table.concat(sig_hex, ",")
    end
    local ext_hash = sha256_truncate(ext_hash_input, 12)

    -- JA5_d: supported_groups hash (GREASE-filtered, sorted)
    local group_hash = ""
    if ext_data and ext_data[0x000a] then
        local groups = {}
        local raw = ext_data[0x000a]
        for i = 1, #raw - 1, 2 do
            local g = (raw:byte(i) << 8) | raw:byte(i + 1)
            if not is_grease(g) then
                groups[#groups + 1] = g
            end
        end
        if #groups > 0 then
            group_hash = "_" .. sha256_truncate(sorted_hex_list(groups), 12)
        else
            group_hash = "_"
        end
    else
        group_hash = "_"
    end

    return string.format("%s%s%s%02d%02d%s_%s_%s%s",
        proto, version, sni_char, cipher_count, ext_count, alpn,
        ciph_hash, ext_hash, group_hash)
end

--- Main entry point: call from ssl_client_hello_by_lua_block.
-- Computes JA4 and JA5 fingerprints and sets them as request headers
-- for verifyngo to consume.
function _M.compute()
    local ssl = require "ngx.ssl.clienthello"

    local sni = ssl.get_client_hello_server_name()
    local ciphers = ssl.get_client_hello_ciphers()
    local extensions = ssl.get_client_hello_ext_present()

    -- Collect raw extension data for JA5 (supported_groups, signature_algorithms)
    local ext_data = {}
    for _, ext_type in ipairs(extensions) do
        local raw = ssl.get_client_hello_ext(ext_type)
        if raw then
            ext_data[ext_type] = raw
        end
    end

    local ja4 = _M.compute_ja4(sni, ciphers, extensions, ext_data)
    local ja5 = _M.compute_ja5(sni, ciphers, extensions, ext_data)

    -- Set headers for verifyngo to read
    ngx.req.set_header("X-JA4", ja4)
    ngx.req.set_header("X-JA5", ja5)

    -- Also log for debugging
    ngx.log(ngx.INFO, "JA4=", ja4, " JA5=", ja5)
end

return _M
