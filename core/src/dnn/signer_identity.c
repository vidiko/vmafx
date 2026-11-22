/**
 *  Copyright 2026 Lusoris
 *  SPDX-License-Identifier: EUPL-1.2
 *
 *  Signing-certificate checks for tiny-model Sigstore bundles. See
 *  signer_identity.h for the rationale (ADR-2985).
 *
 *  Every read is bounds-checked; a malformed bundle or certificate returns
 *  -EBADMSG. The DER walk descends a fixed number of levels (Certificate ->
 *  TBSCertificate -> [3] extensions -> Extension -> extnValue) and does not
 *  recurse. Only DER is accepted: one-byte tags, minimal definite lengths.
 */

#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "signer_identity.h"

/* NOLINTBEGIN(modernize-use-nullptr): C translation unit. The fork builds C as
 * C23, where clang-tidy also proposes the `nullptr` keyword, but this is a C
 * translation unit whose sources spell the null pointer constant `NULL` and
 * MSVC's documented /std:clatest C23 feature set does not include `nullptr`
 * while the required Windows build compiles this TU with cl.exe. ADR-1138. */

/* A Fulcio leaf certificate is 1.5 to 3 KiB of DER. */
#define SIGNER_MAX_CERT_DER 8192u
#define SIGNER_MAX_JSON_KEY 64u
#define SIGNER_MAX_JSON_DEPTH 16u
#define SIGNER_MAX_OBJECT_KEYS 16u
/* TBSCertificate has ten fields at most; a Fulcio certificate about twenty
 * extensions. Both bounds stop the walk on a crafted certificate. */
#define SIGNER_MAX_TBS_FIELDS 16u
#define SIGNER_MAX_EXTENSIONS 64u

enum {
    DER_BOOLEAN = 0x01,
    DER_BIT_STRING = 0x03,
    DER_OCTET_STRING = 0x04,
    DER_OID = 0x06,
    DER_UTF8_STRING = 0x0C,
    DER_SEQUENCE = 0x30,
    DER_URI = 0x86,        /* GeneralName uniformResourceIdentifier, [6] IMPLICIT */
    DER_EXTENSIONS = 0xA3, /* TBSCertificate extensions, [3] EXPLICIT */
};

/* 2.5.29.17, subjectAltName. */
static const unsigned char k_oid_san[] = {0x55, 0x1D, 0x11};
/* 1.3.6.1.4.1.57264.1.17, Fulcio's Source Repository Owner Identifier. */
static const unsigned char k_oid_owner_id[] = {0x2B, 0x06, 0x01, 0x04, 0x01,
                                               0x83, 0xBF, 0x30, 0x01, 0x11};

struct der_tlv {
    unsigned char tag;
    const unsigned char *val;
    size_t len;
};

struct signer_fields {
    struct der_tlv san;
    struct der_tlv owner;
    unsigned seen_san;
    unsigned seen_owner;
};

/* Read the length octets at buf[*off..len) into *out; DER minimal form, at
 * most three length bytes (16 MiB), which no certificate reaches. */
static int der_length(const unsigned char *buf, size_t len, size_t *off, size_t *out)
{
    size_t i = *off;
    if (i >= len)
        return -EBADMSG;
    size_t vlen = buf[i++];
    if ((vlen & 0x80u) != 0u) {
        const size_t nbytes = vlen & 0x7Fu;
        if (nbytes == 0u || nbytes > 3u || nbytes > len - i)
            return -EBADMSG;
        if (buf[i] == 0u)
            return -EBADMSG; /* leading zero: not minimal */
        vlen = 0u;
        for (size_t k = 0u; k < nbytes; k++)
            vlen = (vlen << 8u) | (size_t)buf[i + k];
        i += nbytes;
        if (vlen < 0x80u)
            return -EBADMSG; /* the short form would do: not minimal */
    }
    *off = i;
    *out = vlen;
    return 0;
}

/* Read the TLV at buf[*off..len) and advance *off past its value. */
static int der_next(const unsigned char *buf, size_t len, size_t *off, struct der_tlv *out)
{
    assert(buf != NULL);
    assert(off != NULL);
    assert(out != NULL);

    size_t i = *off;
    if (i >= len)
        return -EBADMSG;
    const unsigned char tag = buf[i++];
    if ((tag & 0x1Fu) == 0x1Fu)
        return -EBADMSG; /* multi-byte tag numbers do not occur in X.509 */
    size_t vlen = 0u;
    const int err = der_length(buf, len, &i, &vlen);
    if (err != 0)
        return err;
    if (vlen > len - i)
        return -EBADMSG;
    out->tag = tag;
    // SAFETY: i <= len after der_length and the value length check.
    out->val = buf + i;
    out->len = vlen;
    *off = i + vlen;
    return 0;
}

/* Read one TLV at buf[*off..len) and require tag @p tag. */
static int der_next_tagged(const unsigned char *buf, size_t len, size_t *off, unsigned char tag,
                           struct der_tlv *out)
{
    const int err = der_next(buf, len, off, out);
    if (err != 0)
        return err;
    return out->tag == tag ? 0 : -EBADMSG;
}

/* Read the only TLV inside @p outer, which must have tag @p tag. */
static int der_only(const struct der_tlv *outer, unsigned char tag, struct der_tlv *out)
{
    size_t off = 0u;
    const int err = der_next_tagged(outer->val, outer->len, &off, tag, out);
    if (err != 0)
        return err;
    return off == outer->len ? 0 : -EBADMSG;
}

static int tbs_extensions(const struct der_tlv *tbs, struct der_tlv *exts)
{
    size_t toff = 0u;
    for (unsigned n = 0u; n < SIGNER_MAX_TBS_FIELDS && toff < tbs->len; n++) {
        struct der_tlv field;
        const int err = der_next(tbs->val, tbs->len, &toff, &field);
        if (err != 0)
            return err;
        if (field.tag == DER_EXTENSIONS)
            return der_only(&field, DER_SEQUENCE, exts);
    }
    return -EBADMSG; /* no extensions: not a Fulcio certificate */
}

/* Find the extensions SEQUENCE of the DER certificate der[0..len). */
static int cert_extensions(const unsigned char *der, size_t len, struct der_tlv *exts)
{
    const struct der_tlv outer = {DER_SEQUENCE, der, len};
    struct der_tlv cert;
    int err = der_only(&outer, DER_SEQUENCE, &cert);
    if (err != 0)
        return err;

    size_t coff = 0u;
    struct der_tlv tbs;
    struct der_tlv alg;
    struct der_tlv sig;
    err = der_next_tagged(cert.val, cert.len, &coff, DER_SEQUENCE, &tbs);
    if (err == 0)
        err = der_next_tagged(cert.val, cert.len, &coff, DER_SEQUENCE, &alg);
    if (err == 0)
        err = der_next_tagged(cert.val, cert.len, &coff, DER_BIT_STRING, &sig);
    if (err != 0 || coff != cert.len)
        return -EBADMSG;
    return tbs_extensions(&tbs, exts);
}

/* Split one Extension into its OID and the contents of its extnValue. */
static int ext_split(const struct der_tlv *ext, struct der_tlv *oid, struct der_tlv *value)
{
    if (ext->tag != DER_SEQUENCE)
        return -EBADMSG;
    size_t off = 0u;
    int err = der_next(ext->val, ext->len, &off, oid);
    if (err != 0)
        return err;
    if (oid->tag != DER_OID)
        return -EBADMSG;
    err = der_next(ext->val, ext->len, &off, value);
    if (err == 0 && value->tag == DER_BOOLEAN)
        err = der_next(ext->val, ext->len, &off, value); /* skip `critical` */
    if (err != 0)
        return err;
    return (value->tag == DER_OCTET_STRING && off == ext->len) ? 0 : -EBADMSG;
}

static int oid_is(const struct der_tlv *oid, const unsigned char *want, size_t want_len)
{
    return oid->len == want_len && memcmp(oid->val, want, want_len) == 0;
}

/* Record the subject alternative name and the owner ID of @p ext. The name
 * must be one URI and the owner ID one UTF8String. */
static int collect_extension(const struct der_tlv *ext, struct signer_fields *f)
{
    struct der_tlv oid;
    struct der_tlv value;
    const int err = ext_split(ext, &oid, &value);
    if (err != 0)
        return err;
    if (oid_is(&oid, k_oid_san, sizeof(k_oid_san))) {
        struct der_tlv names;
        f->seen_san++;
        const int nerr = der_only(&value, DER_SEQUENCE, &names);
        return nerr != 0 ? nerr : der_only(&names, DER_URI, &f->san);
    }
    if (oid_is(&oid, k_oid_owner_id, sizeof(k_oid_owner_id))) {
        f->seen_owner++;
        return der_only(&value, DER_UTF8_STRING, &f->owner);
    }
    return 0;
}

static int is_ref_char(char c)
{
    return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '.' ||
           c == '+' || c == '-';
}

static int identity_tag_allowed(const char *ref, size_t rlen)
{
    static const char tag[] = "tags/v";
    const size_t tlen = sizeof(tag) - 1u;
    if (rlen <= tlen || memcmp(ref, tag, tlen) != 0 || ref[tlen] < '0' || ref[tlen] > '9')
        return 0;
    for (size_t i = tlen + 1u; i < rlen; i++) {
        if (!is_ref_char(ref[i]))
            return 0;
    }
    return 1;
}

int vmaf_dnn_signer_identity_allowed(const char *san, size_t len)
{
    static const char prefix[] =
        "https://github.com/vidiko/vmafx/.github/workflows/supply-chain.yml@refs/";
    static const char master[] = "heads/master";
    const size_t plen = sizeof(prefix) - 1u;

    if (san == NULL || len <= plen || memcmp(san, prefix, plen) != 0)
        return 0;
    // SAFETY: len > plen, so the reference starts within san[0..len).
    const char *ref = san + plen;
    const size_t rlen = len - plen;
    if (rlen == sizeof(master) - 1u && memcmp(ref, master, rlen) == 0)
        return 1;
    return identity_tag_allowed(ref, rlen);
}

static int collect_extensions(const struct der_tlv *exts, struct signer_fields *f)
{
    size_t off = 0u;
    for (unsigned n = 0u; n < SIGNER_MAX_EXTENSIONS && off < exts->len; n++) {
        struct der_tlv ext;
        int err = der_next(exts->val, exts->len, &off, &ext);
        if (err == 0)
            err = collect_extension(&ext, f);
        if (err != 0)
            return err;
    }
    if (off != exts->len)
        return -EBADMSG; /* more extensions than SIGNER_MAX_EXTENSIONS */
    return 0;
}

static int signer_fields_allowed(const struct signer_fields *f)
{
    if (f->seen_san != 1u || f->seen_owner != 1u)
        return -EPERM; /* missing or repeated: X.509 forbids repeats */

    const size_t id_len = sizeof(VMAF_DNN_SIGNER_OWNER_ID) - 1u;
    if (f->owner.len != id_len || memcmp(f->owner.val, VMAF_DNN_SIGNER_OWNER_ID, id_len) != 0)
        return -EPERM;
    if (!vmaf_dnn_signer_identity_allowed((const char *)f->san.val, f->san.len))
        return -EPERM;
    return 0;
}

int vmaf_dnn_signer_check_certificate(const unsigned char *der, size_t len)
{
    if (der == NULL || len == 0u || len > SIGNER_MAX_CERT_DER)
        return -EBADMSG;
    struct der_tlv exts;
    int err = cert_extensions(der, len, &exts);
    if (err != 0)
        return err;
    struct signer_fields f;
    (void)memset(&f, 0, sizeof(f));
    err = collect_extensions(&exts, &f);
    if (err != 0)
        return err;
    return signer_fields_allowed(&f);
}

struct json_span {
    const char *ptr;
    size_t len;
};

static int is_json_space(char c)
{
    return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

static size_t skip_json_space(const char *doc, size_t len, size_t i)
{
    for (; i < len && is_json_space(doc[i]); i++) {
    }
    return i;
}

/* Read an unescaped JSON string at doc[*off..len) into *out. */
static int json_read_plain(const char *doc, size_t len, size_t *off, struct json_span *out)
{
    size_t i = skip_json_space(doc, len, *off);
    if (i >= len || doc[i] != '"')
        return 0;
    const size_t start = i + 1u;
    for (i = start; i < len; i++) {
        const unsigned char c = (unsigned char)doc[i];
        if (c == '"') {
            // SAFETY: start <= i < len, so doc + start lies within doc[0..len).
            out->ptr = doc + start;
            out->len = i - start;
            *off = i + 1u;
            return 1;
        }
        if (c == '\\' || c < 0x20u)
            return 0;
    }
    return 0;
}

static int json_read_key(const char *doc, size_t len, size_t *off, struct json_span *key)
{
    if (!json_read_plain(doc, len, off, key))
        return 0;
    const size_t i = skip_json_space(doc, len, *off);
    if (i >= len || doc[i] != ':')
        return 0;
    *off = skip_json_space(doc, len, i + 1u);
    return *off < len;
}

static int json_skip_string(const char *doc, size_t len, size_t *off)
{
    size_t i = *off + 1u;
    while (i < len) {
        const unsigned char c = (unsigned char)doc[i];
        if (c == '"') {
            *off = i + 1u;
            return 1;
        }
        if (c < 0x20u)
            return 0;
        if (c == '\\') {
            const size_t esc = i + 1u;
            if (esc >= len || doc[esc] == 'u' || (unsigned char)doc[esc] < 0x20u)
                return 0;
            i = esc + 1u;
        } else {
            i++;
        }
    }
    return 0;
}

/* Update the nesting bitmask for one unquoted byte: 1 ok, -1 bad. */
static int json_bracket_step(char c, unsigned int *stack, size_t *depth)
{
    if (c == '{' || c == '[') {
        if (*depth >= SIGNER_MAX_JSON_DEPTH)
            return -1;
        if (c == '{') {
            *stack |= (1u << *depth);
        } else {
            *stack &= ~(1u << *depth);
        }
        (*depth)++;
        return 1;
    }
    if (c == '}' || c == ']') {
        if (*depth == 0u)
            return -1;
        (*depth)--;
        const char want = ((*stack & (1u << *depth)) != 0u) ? '}' : ']';
        if (c != want)
            return -1;
    }
    return 1;
}

static int json_skip_compound(const char *doc, size_t len, size_t *off)
{
    unsigned int stack = 0u;
    size_t depth = 0u;
    for (size_t i = *off; i < len;) {
        if (doc[i] == '"') {
            if (!json_skip_string(doc, len, &i))
                return 0;
            continue;
        }
        if (json_bracket_step(doc[i], &stack, &depth) < 0)
            return 0;
        i++;
        if (depth == 0u) {
            *off = i;
            return 1;
        }
    }
    return 0;
}

static int is_json_primitive_char(char c)
{
    return is_ref_char(c) || c == '_';
}

static int json_skip_value(const char *doc, size_t len, size_t *off)
{
    const size_t start = skip_json_space(doc, len, *off);
    if (start >= len)
        return 0;
    *off = start;
    if (doc[start] == '"')
        return json_skip_string(doc, len, off);
    if (doc[start] == '{' || doc[start] == '[')
        return json_skip_compound(doc, len, off);
    size_t i = start;
    for (; i < len && is_json_primitive_char(doc[i]); i++) {
    }
    *off = i;
    return i > start;
}

static int span_eq(const struct json_span *s, const char *lit)
{
    const size_t n = strnlen(lit, SIGNER_MAX_JSON_KEY);
    return s->len == n && memcmp(s->ptr, lit, n) == 0;
}

/* Match @p key against @p allowed[0..n_allowed) and mark it in *seen;
 * returns index >= 0, -1 on duplicate, -2 on unknown or case-variant key. */
static int json_allow_key(const struct json_span *key, const char *const *allowed, size_t n_allowed,
                          unsigned *seen)
{
    for (size_t k = 0u; k < n_allowed; k++) {
        if (span_eq(key, allowed[k])) {
            const unsigned bit = 1u << k;
            if ((*seen & bit) != 0u)
                return -1;
            *seen |= bit;
            return (int)k;
        }
    }
    return -2;
}

static int json_object_open(const char *doc, size_t len, size_t *off)
{
    const size_t i = skip_json_space(doc, len, *off);
    if (i >= len || doc[i] != '{')
        return 0;
    *off = skip_json_space(doc, len, i + 1u);
    return *off < len && doc[*off] != '}';
}

static int json_object_step(const char *doc, size_t len, size_t *off, int *done)
{
    const size_t i = skip_json_space(doc, len, *off);
    if (i >= len)
        return 0;
    if (doc[i] == ',') {
        *off = skip_json_space(doc, len, i + 1u);
        *done = 0;
        return *off < len && doc[*off] != '}';
    }
    if (doc[i] == '}') {
        *off = i + 1u;
        *done = 1;
        return 1;
    }
    return 0;
}

static int parse_certificate_object(const char *doc, size_t len, size_t *off,
                                    struct json_span *raw_b64)
{
    static const char *const allowed[] = {"rawBytes"};
    if (!json_object_open(doc, len, off))
        return 0;
    unsigned seen = 0u;
    struct json_span key;
    if (!json_read_key(doc, len, off, &key) || json_allow_key(&key, allowed, 1u, &seen) != 0 ||
        !json_read_plain(doc, len, off, raw_b64))
        return 0;
    int done = 0;
    return json_object_step(doc, len, off, &done) && done;
}

static int parse_verification_material(const char *doc, size_t len, size_t *off,
                                       struct json_span *raw_b64)
{
    static const char *const allowed[] = {
        "certificate",
        "tlogEntries",
        "timestampVerificationData",
    };
    if (!json_object_open(doc, len, off))
        return 0;
    unsigned seen = 0u;
    for (unsigned step = 0u; step < SIGNER_MAX_OBJECT_KEYS; step++) {
        struct json_span key;
        if (!json_read_key(doc, len, off, &key))
            return 0;
        const int idx = json_allow_key(&key, allowed, 3u, &seen);
        const int ok = (idx == 0) ? parse_certificate_object(doc, len, off, raw_b64) :
                                    (idx > 0 && json_skip_value(doc, len, off));
        int done = 0;
        if (!ok || !json_object_step(doc, len, off, &done))
            return 0;
        if (done)
            return (seen & 1u) != 0u;
    }
    return 0;
}

static int media_type_allowed(const char *doc, size_t len, size_t *off)
{
    struct json_span val;
    if (!json_read_plain(doc, len, off, &val))
        return 0;
    return span_eq(&val, "application/vnd.dev.sigstore.bundle.v0.3+json") ||
           span_eq(&val, "application/vnd.dev.sigstore.bundle+json;version=0.3");
}

static int parse_bundle_field(const char *doc, size_t len, size_t *off, int idx,
                              struct json_span *raw_b64)
{
    if (idx == 0)
        return media_type_allowed(doc, len, off);
    if (idx == 1)
        return parse_verification_material(doc, len, off, raw_b64);
    if (idx == 2 || idx == 3)
        return json_skip_value(doc, len, off);
    return 0;
}

static int parse_bundle_object(const char *doc, size_t len, struct json_span *raw_b64)
{
    static const char *const allowed[] = {
        "mediaType",
        "verificationMaterial",
        "messageSignature",
        "dsseEnvelope",
    };
    size_t off = 0u;
    if (!json_object_open(doc, len, &off))
        return 0;
    unsigned seen = 0u;
    for (unsigned step = 0u; step < SIGNER_MAX_OBJECT_KEYS; step++) {
        struct json_span key;
        if (!json_read_key(doc, len, &off, &key))
            return 0;
        const int idx = json_allow_key(&key, allowed, 4u, &seen);
        int done = 0;
        if (!parse_bundle_field(doc, len, &off, idx, raw_b64) ||
            !json_object_step(doc, len, &off, &done))
            return 0;
        if (done) {
            off = skip_json_space(doc, len, off);
            return off == len && (seen & 3u) == 3u && (seen & 12u) != 12u;
        }
    }
    return 0;
}

/* Locate the base64 text of the bundle's one certificate at
 * verificationMaterial.certificate.rawBytes. */
static int bundle_certificate_b64(const char *doc, size_t len, const char **b64, size_t *b64_len)
{
    if (memchr(doc, '\0', len) != NULL)
        return -EBADMSG;
    struct json_span raw_b64 = {NULL, 0u};
    if (!parse_bundle_object(doc, len, &raw_b64))
        return -EBADMSG;
    *b64 = raw_b64.ptr;
    *b64_len = raw_b64.len;
    return 0;
}

static int base64_value(unsigned char c)
{
    if (c >= 'A' && c <= 'Z')
        return c - 'A';
    if (c >= 'a' && c <= 'z')
        return c - 'a' + 26;
    if (c >= '0' && c <= '9')
        return c - '0' + 52;
    if (c == '+')
        return 62;
    return c == '/' ? 63 : -1;
}

/* Decode standard base64 with padding (RFC 4648 section 4) into out[0..cap). */
static int base64_decode(const char *in, size_t in_len, unsigned char *out, size_t cap,
                         size_t *out_len)
{
    if (in_len == 0u || in_len % 4u != 0u)
        return -EBADMSG;
    const size_t pad = (in[in_len - 1u] == '=') + (in[in_len - 2u] == '=');
    const size_t n = in_len / 4u * 3u - pad;
    if (n > cap)
        return -EBADMSG;
    const size_t data_len = in_len - pad;
    size_t o = 0u;
    for (size_t i = 0u; i < in_len; i += 4u) {
        unsigned long acc = 0u;
        for (size_t k = 0u; k < 4u; k++) {
            const int v = (i + k < data_len) ? base64_value((unsigned char)in[i + k]) : 0;
            if (v < 0)
                return -EBADMSG;
            acc = (acc << 6u) | (unsigned long)v;
        }
        for (size_t k = 0u; k < 3u && o < n; k++)
            out[o++] = (unsigned char)(acc >> (16u - 8u * k));
    }
    *out_len = n;
    return 0;
}

int vmaf_dnn_signer_check_bundle(const char *bundle, size_t len)
{
    if (bundle == NULL)
        return -EBADMSG;
    const char *b64 = NULL;
    size_t b64_len = 0u;
    int err = bundle_certificate_b64(bundle, len, &b64, &b64_len);
    if (err != 0)
        return err;
    uint8_t der[SIGNER_MAX_CERT_DER];
    size_t der_len = 0u;
    err = base64_decode(b64, b64_len, der, sizeof(der), &der_len);
    if (err != 0)
        return err;
    return vmaf_dnn_signer_check_certificate(der, der_len);
}

/* NOLINTEND(modernize-use-nullptr) */
