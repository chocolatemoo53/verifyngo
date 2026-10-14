local _M = {}

local EPHEMERAL_EXTENSIONS = {
    [0x0015] = true,
    [0x0023] = true,
    [0x0029] = true,
    [0x002a] = true,
    [0x002c] = true,
    [0x002d] = true,
}

local VERSIONS = {
    [0x0304] = "13",
    [0x0303] = "12",
    [0x0302] = "11",
    [0x0301] = "10",
    [0x0300] = "s3",
    [0xfeff] = "d1",
    [0xfefd] = "d2",
    [0xfefc] = "d3",
}

local EMPTY_HASH = "000000000000"

local function is_grease(v)
    return v % 16 == 10 and v % 256 == math.floor(v / 256)
end

local function u16_list(data, len_bytes)
    local out = {}
    if not data or #data < len_bytes then
        return out
    end
    local len = data:byte(1)
    if len_bytes == 2 then
        len = len * 256 + data:byte(2)
    end
    local last = math.min(#data, len_bytes + len)
    for i = len_bytes + 1, last - 1, 2 do
        local v = data:byte(i) * 256 + data:byte(i + 1)
        if not is_grease(v) then
            out[#out + 1] = v
        end
    end
    return out
end

local function hex_list(list)
    local out = {}
    for i, v in ipairs(list) do
        out[i] = string.format("%04x", v)
    end
    return table.concat(out, ",")
end

local function sorted(list)
    local copy = {}
    for i, v in ipairs(list) do
        copy[i] = v
    end
    table.sort(copy)
    return copy
end

local function hash12(s)
    local sha256 = require "resty.sha256"
    local to_hex = require("resty.string").to_hex
    local h = sha256:new()
    h:update(s)
    return to_hex(h:final()):sub(1, 12)
end

local function list_hash(list)
    if #list == 0 then
        return EMPTY_HASH
    end
    return hash12(hex_list(sorted(list)))
end

local function extension_hash(exts, sig_algs)
    if #exts == 0 then
        return EMPTY_HASH
    end
    local input = hex_list(sorted(exts))
    if #sig_algs > 0 then
        input = input .. "_" .. hex_list(sig_algs)
    end
    return hash12(input)
end

local function version_code(data)
    local best = 0
    for _, v in ipairs(u16_list(data, 1)) do
        if v > best then
            best = v
        end
    end
    return VERSIONS[best] or "00"
end

local function alpn_code(data)
    if not data or #data < 3 then
        return "00"
    end
    local n = data:byte(3)
    if n == 0 or #data < 3 + n then
        return "00"
    end
    local first, last = data:sub(4, 4), data:sub(3 + n, 3 + n)
    if first:match("^%w$") and last:match("^%w$") then
        return first .. last
    end
    return string.format("%02x", first:byte()):sub(1, 1) .. string.format("%02x", last:byte()):sub(2, 2)
end

local function count(n)
    return string.format("%02d", math.min(n, 99))
end

function _M.build(ciphers_raw, exts_raw, ext_data)
    local ciphers = {}
    for _, c in ipairs(ciphers_raw or {}) do
        if not is_grease(c) then
            ciphers[#ciphers + 1] = c
        end
    end

    local exts, has_sni = {}, false
    local ja4_hashed, tlsfp_hashed, tlsfp_count = {}, {}, 0
    for _, e in ipairs(exts_raw or {}) do
        if not is_grease(e) then
            exts[#exts + 1] = e
            local stable = not EPHEMERAL_EXTENSIONS[e]
            if stable then
                tlsfp_count = tlsfp_count + 1
            end
            if e == 0x0000 then
                has_sni = true
            elseif e ~= 0x0010 then
                ja4_hashed[#ja4_hashed + 1] = e
                if stable then
                    tlsfp_hashed[#tlsfp_hashed + 1] = e
                end
            end
        end
    end

    local prefix = "t" .. version_code(ext_data[0x002b]) .. (has_sni and "d" or "i") .. count(#ciphers)
    local alpn = alpn_code(ext_data[0x0010])
    local cipher_hash = list_hash(ciphers)
    local sig_algs = u16_list(ext_data[0x000d], 2)
    local groups = u16_list(ext_data[0x000a], 2)

    local ja4 = prefix .. count(#exts) .. alpn
        .. "_" .. cipher_hash
        .. "_" .. extension_hash(ja4_hashed, sig_algs)

    local tlsfp = prefix .. count(tlsfp_count) .. alpn:lower()
        .. "_" .. cipher_hash
        .. "_" .. extension_hash(tlsfp_hashed, sig_algs)
        .. "_" .. (#groups > 0 and list_hash(groups) or "")

    return ja4, tlsfp
end

local function from_handshake()
    local ssl_clt = require "ngx.ssl.clienthello"
    local ext_data = {}
    for _, t in ipairs({ 0x000a, 0x000d, 0x0010, 0x002b }) do
        ext_data[t] = ssl_clt.get_client_hello_ext(t)
    end
    return _M.build(ssl_clt.get_client_hello_ciphers(), ssl_clt.get_client_hello_ext_present(), ext_data)
end

function _M.compute()
    local ok, ja4, tlsfp = pcall(from_handshake)
    if ok then
        ngx.ctx.tls_fingerprints = { ja4 = ja4, tlsfp = tlsfp }
    else
        ngx.log(ngx.WARN, "tls fingerprint failed: ", ja4)
    end
end

function _M.set_headers()
    local fps = ngx.ctx.tls_fingerprints
    ngx.req.set_header("X-JA4", fps and fps.ja4)
    ngx.req.set_header("X-TLSFP", fps and fps.tlsfp)
end

return _M
