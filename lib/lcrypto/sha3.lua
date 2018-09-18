-- Copyright (C) by qlee


local ffi = require "ffi"
local ffi_new = ffi.new
local ffi_gc = ffi.gc
local ffi_str = ffi.string
local C = ffi.C
local setmetatable = setmetatable


local _M = { _VERSION = '1.0' }

local mt = { __index = _M }


ffi.cdef[[
typedef struct engine_st ENGINE;
typedef struct env_md_ctx_st EVP_MD_CTX;
typedef struct env_md_st EVP_MD;

const EVP_MD *EVP_sha3_224(void);
const EVP_MD *EVP_sha3_256(void);
const EVP_MD *EVP_sha3_384(void);
const EVP_MD *EVP_sha3_512(void);
const EVP_MD *EVP_shake128(void);
const EVP_MD *EVP_shake256(void);

EVP_MD_CTX *EVP_MD_CTX_new(void);
int EVP_MD_CTX_reset(EVP_MD_CTX *ctx);
void EVP_MD_CTX_free(EVP_MD_CTX *ctx);

int EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl);
int EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *d, size_t cnt);
int EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s);
]]


local hash
hash = {
    ["sha3-224"] = C.EVP_sha3_224(),
    ["sha3-256"] = C.EVP_sha3_256(),
    ["sha3-384"] = C.EVP_sha3_384(),
    ["sha3-512"] = C.EVP_sha3_512(),
    ["shake128"] = C.EVP_shake128(),
    ["shake256"] = C.EVP_shake256(),
}
_M.hash = hash

local max_digest_len = 64
local buf = ffi_new("char[?]", max_digest_len)
local outlen = ffi_new("unsigned int[1]")
local ctx_ptr_type = ffi.typeof("EVP_MD_CTX")


function _M.new(self, _hash)
    local method = hash[_hash]
    if not method then
        return nil
    end

    local ctx = C.EVP_MD_CTX_new()
    if ctx == nil then
        return nil
    end
    ffi_gc(ctx, C.EVP_MD_CTX_free)

    if C.EVP_DigestInit_ex(ctx, method, nil) == 0 then
        return nil
    end

    return setmetatable({ _ctx = ctx }, mt)
end


function _M.update(self, s)
    return C.EVP_DigestUpdate(self._ctx, s, #s)
end


function _M.final(self)
    if C.EVP_DigestFinal_ex(self._ctx, buf, outlen) == 0 then
        return nil
    end

    return ffi_str(buf, outlen[0])
end


function _M.reset(self)
    return C.EVP_MD_reset(self._ctx) == 1
end


return _M
