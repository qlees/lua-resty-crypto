-- Copyright (C) by qlee


local ffi = require "ffi"
local ffi_new = ffi.new
local ffi_gc = ffi.gc
local ffi_str = ffi.string
local ffi_copy = ffi.copy
local C = ffi.C
local setmetatable = setmetatable
local type = type


local _M = { _VERSION = '1.0' }

local mt = { __index = _M }


ffi.cdef[[
typedef struct engine_st ENGINE;

typedef struct evp_cipher_st EVP_CIPHER;
typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;

typedef struct env_md_ctx_st EVP_MD_CTX;
typedef struct env_md_st EVP_MD;

const EVP_MD *EVP_md5(void);
const EVP_MD *EVP_sha(void);
const EVP_MD *EVP_sha1(void);
const EVP_MD *EVP_sha224(void);
const EVP_MD *EVP_sha256(void);
const EVP_MD *EVP_sha384(void);
const EVP_MD *EVP_sha512(void);

const EVP_CIPHER *EVP_aes_128_ecb(void);
const EVP_CIPHER *EVP_aes_128_cbc(void);
const EVP_CIPHER *EVP_aes_128_cfb1(void);
const EVP_CIPHER *EVP_aes_128_cfb8(void);
const EVP_CIPHER *EVP_aes_128_cfb128(void);
const EVP_CIPHER *EVP_aes_128_ofb(void);
const EVP_CIPHER *EVP_aes_128_ctr(void);
const EVP_CIPHER *EVP_aes_192_ecb(void);
const EVP_CIPHER *EVP_aes_192_cbc(void);
const EVP_CIPHER *EVP_aes_192_cfb1(void);
const EVP_CIPHER *EVP_aes_192_cfb8(void);
const EVP_CIPHER *EVP_aes_192_cfb128(void);
const EVP_CIPHER *EVP_aes_192_ofb(void);
const EVP_CIPHER *EVP_aes_192_ctr(void);
const EVP_CIPHER *EVP_aes_256_ecb(void);
const EVP_CIPHER *EVP_aes_256_cbc(void);
const EVP_CIPHER *EVP_aes_256_cfb1(void);
const EVP_CIPHER *EVP_aes_256_cfb8(void);
const EVP_CIPHER *EVP_aes_256_cfb128(void);
const EVP_CIPHER *EVP_aes_256_ofb(void);

EVP_CIPHER_CTX *EVP_CIPHER_CTX_new();
void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *a);

int EVP_CipherInit_ex(EVP_CIPHER_CTX *ctx,const EVP_CIPHER *cipher,
        ENGINE *impl, unsigned char *key, const unsigned char *iv, int enc);

int EVP_CipherUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
        const unsigned char *in, int inl);

int EVP_CipherFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);

int EVP_BytesToKey(const EVP_CIPHER *type,const EVP_MD *md,
        const unsigned char *salt, const unsigned char *data, int datal,
        int count, unsigned char *key,unsigned char *iv);
]]

local hash
hash = {
    md5 = C.EVP_md5(),
    sha1 = C.EVP_sha1(),
    sha224 = C.EVP_sha224(),
    sha256 = C.EVP_sha256(),
    sha384 = C.EVP_sha384(),
    sha512 = C.EVP_sha512()
}
_M.hash = hash

local cipher
cipher = function (size, _cipher)
    local _size = size or 128
    local _cipher = _cipher or "cbc"
    local func = "EVP_aes_" .. _size .. "_" .. _cipher
    if C[func] then
        return { size=_size, cipher=_cipher, method=C[func]()}
    else
        return nil
    end
end
_M.cipher = cipher

function _M.new(self, enc, key, salt, _cipher, _hash, hash_rounds)
    local cipher_ctx = C.EVP_CIPHER_CTX_new()
    if cipher_ctx == nil then
        return nil, "no memory"
    end

    ffi_gc(cipher_ctx, C.EVP_CIPHER_CTX_free)

    local enc = enc or 0
    local _cipher = _cipher or cipher()
    local _hash = _hash or hash.md5
    local hash_rounds = hash_rounds or 1
    local _cipherLength = _cipher.size/8
    local gen_key = ffi_new("unsigned char[?]",_cipherLength)
    local gen_iv = ffi_new("unsigned char[?]",_cipherLength)

    if type(_hash) == "table" then
        if not _hash.iv or #_hash.iv ~= 16 then
          return nil, "bad iv"
        end

        if _hash.method then
            local tmp_key = _hash.method(key)

            if #tmp_key ~= _cipherLength then
                return nil, "bad key length"
            end

            ffi_copy(gen_key, tmp_key, _cipherLength)

        elseif #key ~= _cipherLength then
            return nil, "bad key length"

        else
            ffi_copy(gen_key, key, _cipherLength)
        end

        ffi_copy(gen_iv, _hash.iv, 16)

    else
        if salt and #salt ~= 8 then
            return nil, "salt must be 8 characters or nil"
        end

        if C.EVP_BytesToKey(_cipher.method, _hash, salt, key, #key,
                            hash_rounds, gen_key, gen_iv)
            ~= _cipherLength
        then
            return nil
        end
    end

    if C.EVP_CipherInit_ex(cipher_ctx, _cipher.method, nil,
      gen_key, gen_iv, enc) == 0 then
        return nil
    end

    return setmetatable({
      _cipher_ctx = cipher_ctx,
      _cipher = _cipher,
      _enc = enc
      }, mt)
end

function _M.Decrypter(self, key, salt, _cipher, _hash, hash_rounds)
    return self.new(self, 0, key, salt, _cipher, _hash, hash_rounds)
end

function _M.Encrypter(self, key, salt, _cipher, _hash, hash_rounds)
    return self.new(self, 1, key, salt, _cipher, _hash, hash_rounds)
end

function _M.update(self, s)
    local s_len = #s
    local buf = ffi_new("unsigned char[?]", s_len)
    local out_len = ffi_new("int[1]")
    local ctx = self._cipher_ctx

    if C.EVP_CipherUpdate(ctx, buf, out_len, s, s_len) == 0 then
      return nil
    end

    return ffi_str(buf, out_len[0])
end

function _M.final(self, s)
    local s_len = 0
    if s then
        s_len = #s
    end

    local buf = ffi_new("unsigned char[?]", s_len + self._cipher.size / 8)
    local out_len = ffi_new("int[1]")
    local tmp_len = ffi_new("int[1]")
    local ctx = self._cipher_ctx

    out_len[0] = 0
    if s and C.EVP_CipherUpdate(ctx, buf, out_len, s, s_len) == 0 then
        return nil
    end

    if C.EVP_CipherFinal_ex(ctx, buf + out_len[0], tmp_len) == 0 then
        return nil
    end

    return ffi_str(buf, out_len[0] + tmp_len[0])
end

return _M
