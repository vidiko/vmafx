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
 *  The JSON walk checks every nested value against the v0.3 bundle schema
 *  with an explicit stack of at most SIGNER_MAX_SCHEMA_DEPTH objects and
 *  does not recurse either.
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
/* The v0.3 schema nests at most three objects below a content or
 * verification-material field (tlogEntries[] -> inclusionProof -> checkpoint). */
#define SIGNER_MAX_SCHEMA_DEPTH 3u
#define SIGNER_MAX_SCHEMA_STEPS 4096u
/* At most 18 digits, so every accepted integer fits in an int64. */
#define SIGNER_MAX_INT_DIGITS 18u
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

/* Check standard base64 with padding (RFC 4648 section 4): a nonzero multiple
 * of four bytes, at most two trailing '=', every other byte in the alphabet. */
static int base64_shape(const char *in, size_t in_len, size_t *pad)
{
    if (in_len == 0u || in_len % 4u != 0u)
        return -EBADMSG;
    *pad = (size_t)(in[in_len - 1u] == '=') + (size_t)(in[in_len - 2u] == '=');
    const size_t data_len = in_len - *pad;
    for (size_t i = 0u; i < data_len; i++) {
        if (base64_value((unsigned char)in[i]) < 0)
            return -EBADMSG;
    }
    return 0;
}

/* The nested values of a v0.3 bundle (sigstore protobuf-specs, ProtoJSON
 * names). Each object lists its keys and the kind of each value; a key outside
 * the list, a repeated key, an empty object or a value of another kind is
 * refused. SK_STR: a JSON string of valid UTF-8 without \u escapes; SK_B64:
 * standard base64; SK_INT: an int64 as a number or a decimal string; SK_HASH:
 * a HashAlgorithm name; SK_B64S: an array of base64 strings; SK_OBJ: an
 * object; SK_OBJS: an array of objects. */
enum schema_kind { SK_STR, SK_B64, SK_INT, SK_HASH, SK_B64S, SK_OBJ, SK_OBJS };

enum schema_node_id {
    SN_MSGSIG,
    SN_DIGEST,
    SN_DSSE,
    SN_DSSE_SIG,
    SN_TLOG,
    SN_LOGID,
    SN_KINDVER,
    SN_PROMISE,
    SN_PROOF,
    SN_CHECKPOINT,
    SN_TSV,
    SN_RFC3161,
    SN_COUNT
};

struct schema_value {
    unsigned char kind;
    unsigned char child;
};

struct schema_node {
    const char *const *names;
    const struct schema_value *vals;
    size_t n;
};

static const char *const k_msgsig_names[] = {"messageDigest", "signature"};
static const struct schema_value k_msgsig_vals[] = {{SK_OBJ, SN_DIGEST}, {SK_B64, 0u}};
static const char *const k_digest_names[] = {"algorithm", "digest"};
static const struct schema_value k_digest_vals[] = {{SK_HASH, 0u}, {SK_B64, 0u}};
static const char *const k_dsse_names[] = {"payload", "payloadType", "signatures"};
static const struct schema_value k_dsse_vals[] = {
    {SK_B64, 0u}, {SK_STR, 0u}, {SK_OBJS, SN_DSSE_SIG}};
static const char *const k_dsse_sig_names[] = {"sig", "keyid"};
static const struct schema_value k_dsse_sig_vals[] = {{SK_B64, 0u}, {SK_STR, 0u}};
static const char *const k_tlog_names[] = {
    "logIndex",         "logId",          "kindVersion",       "integratedTime",
    "inclusionPromise", "inclusionProof", "canonicalizedBody",
};
static const struct schema_value k_tlog_vals[] = {
    {SK_INT, 0u},         {SK_OBJ, SN_LOGID}, {SK_OBJ, SN_KINDVER}, {SK_INT, 0u},
    {SK_OBJ, SN_PROMISE}, {SK_OBJ, SN_PROOF}, {SK_B64, 0u},
};
static const char *const k_logid_names[] = {"keyId"};
static const struct schema_value k_logid_vals[] = {{SK_B64, 0u}};
static const char *const k_kindver_names[] = {"kind", "version"};
static const struct schema_value k_kindver_vals[] = {{SK_STR, 0u}, {SK_STR, 0u}};
static const char *const k_promise_names[] = {"signedEntryTimestamp"};
static const struct schema_value k_promise_vals[] = {{SK_B64, 0u}};
static const char *const k_proof_names[] = {"logIndex", "rootHash", "treeSize", "hashes",
                                            "checkpoint"};
static const struct schema_value k_proof_vals[] = {
    {SK_INT, 0u}, {SK_B64, 0u}, {SK_INT, 0u}, {SK_B64S, 0u}, {SK_OBJ, SN_CHECKPOINT},
};
static const char *const k_checkpoint_names[] = {"envelope"};
static const struct schema_value k_checkpoint_vals[] = {{SK_STR, 0u}};
static const char *const k_tsv_names[] = {"rfc3161Timestamps"};
static const struct schema_value k_tsv_vals[] = {{SK_OBJS, SN_RFC3161}};
static const char *const k_rfc3161_names[] = {"signedTimestamp"};
static const struct schema_value k_rfc3161_vals[] = {{SK_B64, 0u}};

static const struct schema_node k_schema[SN_COUNT] = {
    [SN_MSGSIG] = {k_msgsig_names, k_msgsig_vals, 2u},
    [SN_DIGEST] = {k_digest_names, k_digest_vals, 2u},
    [SN_DSSE] = {k_dsse_names, k_dsse_vals, 3u},
    [SN_DSSE_SIG] = {k_dsse_sig_names, k_dsse_sig_vals, 2u},
    [SN_TLOG] = {k_tlog_names, k_tlog_vals, 7u},
    [SN_LOGID] = {k_logid_names, k_logid_vals, 1u},
    [SN_KINDVER] = {k_kindver_names, k_kindver_vals, 2u},
    [SN_PROMISE] = {k_promise_names, k_promise_vals, 1u},
    [SN_PROOF] = {k_proof_names, k_proof_vals, 5u},
    [SN_CHECKPOINT] = {k_checkpoint_names, k_checkpoint_vals, 1u},
    [SN_TSV] = {k_tsv_names, k_tsv_vals, 1u},
    [SN_RFC3161] = {k_rfc3161_names, k_rfc3161_vals, 1u},
};

static int schema_b64_ok(const char *doc, size_t len, size_t *off)
{
    struct json_span s;
    size_t pad = 0u;
    return json_read_plain(doc, len, off, &s) && base64_shape(s.ptr, s.len, &pad) == 0;
}

static int schema_hash_ok(const char *doc, size_t len, size_t *off)
{
    static const char *const names[] = {"SHA2_256", "SHA2_384", "SHA2_512", "SHA3_256", "SHA3_384"};
    struct json_span s;
    if (!json_read_plain(doc, len, off, &s))
        return 0;
    for (size_t k = 0u; k < sizeof(names) / sizeof(names[0]); k++) {
        if (span_eq(&s, names[k]))
            return 1;
    }
    return 0;
}

static int is_json_digit(char c)
{
    return c >= '0' && c <= '9';
}

/* Length of the optional '-' and the digits of an integer at doc[i..len):
 * 1 to SIGNER_MAX_INT_DIGITS digits without a leading zero; 0 when none. */
static size_t json_int_len(const char *doc, size_t len, size_t i)
{
    const size_t sign = (size_t)(i < len && doc[i] == '-');
    const size_t start = i + sign;
    const size_t stop =
        (len - start > SIGNER_MAX_INT_DIGITS + 1u) ? start + SIGNER_MAX_INT_DIGITS + 1u : len;
    size_t end = start;
    for (; end < stop && is_json_digit(doc[end]); end++) {
    }
    const size_t n = end - start;
    if (n == 0u || n > SIGNER_MAX_INT_DIGITS || (n > 1u && doc[start] == '0'))
        return 0u;
    return sign + n;
}

/* An int64 as ProtoJSON writes it (a decimal string) or as a JSON number. */
static int schema_int_ok(const char *doc, size_t len, size_t *off)
{
    size_t i = skip_json_space(doc, len, *off);
    const size_t quoted = (size_t)(i < len && doc[i] == '"');
    i += quoted;
    const size_t n = json_int_len(doc, len, i);
    if (n == 0u)
        return 0;
    i += n;
    if (quoted != 0u && (i >= len || doc[i] != '"'))
        return 0;
    *off = i + quoted;
    return 1;
}

/* Well-formed UTF-8 lead bytes (RFC 3629 section 4): the byte range, the
 * sequence length and the allowed range of the second byte. */
struct utf8_lead {
    unsigned char first;
    unsigned char last;
    unsigned char need;
    unsigned char lo;
    unsigned char hi;
};

static const struct utf8_lead k_utf8[] = {
    {0xC2u, 0xDFu, 2u, 0x80u, 0xBFu}, {0xE0u, 0xE0u, 3u, 0xA0u, 0xBFu},
    {0xE1u, 0xECu, 3u, 0x80u, 0xBFu}, {0xEDu, 0xEDu, 3u, 0x80u, 0x9Fu},
    {0xEEu, 0xEFu, 3u, 0x80u, 0xBFu}, {0xF0u, 0xF0u, 4u, 0x90u, 0xBFu},
    {0xF1u, 0xF3u, 4u, 0x80u, 0xBFu}, {0xF4u, 0xF4u, 4u, 0x80u, 0x8Fu},
};

static int utf8_tail_ok(const unsigned char *s, size_t need)
{
    for (size_t j = 2u; j < need; j++) {
        if (s[j] < 0x80u || s[j] > 0xBFu)
            return 0;
    }
    return 1;
}

/* Length of the UTF-8 sequence at s[0..n), n >= 1; 0 when it is not well
 * formed. */
static size_t utf8_seq_len(const unsigned char *s, size_t n)
{
    if (s[0] < 0x80u)
        return 1u;
    for (size_t k = 0u; k < sizeof(k_utf8) / sizeof(k_utf8[0]); k++) {
        const struct utf8_lead *r = &k_utf8[k];
        if (s[0] < r->first || s[0] > r->last)
            continue;
        if (n < r->need || s[1] < r->lo || s[1] > r->hi)
            return 0u;
        return utf8_tail_ok(s, r->need) ? r->need : 0u;
    }
    return 0u;
}

/* Length of one string character at s[0..n), n >= 1: a two-byte escape other
 * than \u, or a UTF-8 sequence that is not a control byte; 0 when refused. */
static size_t json_char_len(const unsigned char *s, size_t n)
{
    if (s[0] == '\\')
        return (n >= 2u && memchr("\"\\/bfnrt", s[1], 8u) != NULL) ? 2u : 0u;
    return s[0] >= 0x20u ? utf8_seq_len(s, n) : 0u;
}

static int schema_str_ok(const char *doc, size_t len, size_t *off)
{
    size_t i = skip_json_space(doc, len, *off);
    if (i >= len || doc[i] != '"')
        return 0;
    for (i++; i < len;) {
        if (doc[i] == '"') {
            *off = i + 1u;
            return 1;
        }
        // SAFETY: i < len, so doc + i and the len - i bytes after it lie within
        // doc[0..len).
        const size_t step = json_char_len((const unsigned char *)(doc + i), len - i);
        if (step == 0u)
            return 0;
        i += step;
    }
    return 0;
}

static int json_array_open(const char *doc, size_t len, size_t *off)
{
    const size_t i = skip_json_space(doc, len, *off);
    if (i >= len || doc[i] != '[')
        return 0;
    *off = skip_json_space(doc, len, i + 1u);
    return *off < len;
}

/* At a ']' just after '[' consume it: 1 empty array, 0 not empty. */
static int json_array_empty(const char *doc, size_t *off)
{
    if (doc[*off] != ']')
        return 0;
    (*off)++;
    return 1;
}

static int schema_b64_array_ok(const char *doc, size_t len, size_t *off)
{
    if (!json_array_open(doc, len, off))
        return 0;
    if (json_array_empty(doc, off))
        return 1;
    for (unsigned step = 0u; step < SIGNER_MAX_SCHEMA_STEPS; step++) {
        if (!schema_b64_ok(doc, len, off))
            return 0;
        const size_t i = skip_json_space(doc, len, *off);
        if (i >= len || (doc[i] != ',' && doc[i] != ']'))
            return 0;
        *off = i + 1u;
        if (doc[i] == ']')
            return 1;
    }
    return 0;
}

static int schema_scalar_ok(const char *doc, size_t len, size_t *off, unsigned char kind)
{
    switch (kind) {
    case SK_STR:
        return schema_str_ok(doc, len, off);
    case SK_B64:
        return schema_b64_ok(doc, len, off);
    case SK_INT:
        return schema_int_ok(doc, len, off);
    case SK_HASH:
        return schema_hash_ok(doc, len, off);
    case SK_B64S:
        return schema_b64_array_ok(doc, len, off);
    default:
        return 0;
    }
}

/* One open object of the walk: its schema node, whether it is an array
 * element, and the keys read so far. */
struct schema_frame {
    unsigned char node;
    unsigned char in_array;
    unsigned seen;
};

struct schema_walk {
    const char *doc;
    size_t len;
    size_t off;
    size_t depth;
    struct schema_frame stack[SIGNER_MAX_SCHEMA_DEPTH];
};

static int schema_push(struct schema_walk *w, unsigned char node, unsigned char in_array)
{
    if (w->depth >= SIGNER_MAX_SCHEMA_DEPTH || !json_object_open(w->doc, w->len, &w->off))
        return 0;
    struct schema_frame *f = &w->stack[w->depth];
    w->depth++;
    f->node = node;
    f->in_array = in_array;
    f->seen = 0u;
    return 1;
}

/* Open an object or an array of objects: 1 pushed, 2 empty array, 0 bad. */
static int schema_open(struct schema_walk *w, unsigned char kind, unsigned char node)
{
    if (kind != SK_OBJS)
        return schema_push(w, node, 0u);
    if (!json_array_open(w->doc, w->len, &w->off))
        return 0;
    if (json_array_empty(w->doc, &w->off))
        return 2;
    return schema_push(w, node, 1u);
}

/* After an array element: 1 pushed the next element, 0 array closed, -1 bad. */
static int schema_next_element(struct schema_walk *w, unsigned char node)
{
    const size_t i = skip_json_space(w->doc, w->len, w->off);
    if (i < w->len && w->doc[i] == ',') {
        w->off = i + 1u;
        return schema_push(w, node, 1u) ? 1 : -1;
    }
    if (i >= w->len || w->doc[i] != ']')
        return -1;
    w->off = i + 1u;
    return 0;
}

/* After a value: step the enclosing objects, closing each one that ends. */
static int schema_close(struct schema_walk *w)
{
    for (size_t level = 0u; level <= SIGNER_MAX_SCHEMA_DEPTH && w->depth > 0u; level++) {
        int done = 0;
        if (!json_object_step(w->doc, w->len, &w->off, &done))
            return 0;
        if (!done)
            return 1;
        w->depth--;
        const struct schema_frame *top = &w->stack[w->depth];
        if (top->in_array != 0u) {
            const int next = schema_next_element(w, top->node);
            if (next != 0)
                return next > 0;
        }
    }
    return w->depth == 0u;
}

/* Read one key of the innermost open object and its value. */
static int schema_step(struct schema_walk *w)
{
    struct schema_frame *top = &w->stack[w->depth - 1u];
    const struct schema_node *node = &k_schema[top->node];
    struct json_span key;
    if (!json_read_key(w->doc, w->len, &w->off, &key))
        return 0;
    const int idx = json_allow_key(&key, node->names, node->n, &top->seen);
    if (idx < 0)
        return 0;
    const struct schema_value v = node->vals[idx];
    if (v.kind == SK_OBJ || v.kind == SK_OBJS) {
        const int opened = schema_open(w, v.kind, v.child);
        return opened == 2 ? schema_close(w) : opened;
    }
    return schema_scalar_ok(w->doc, w->len, &w->off, v.kind) && schema_close(w);
}

/* Check the value at doc[*off..len) against schema node @p node, as one
 * object (SK_OBJ) or an array of them (SK_OBJS); on success *off ends it. */
static int schema_validate(const char *doc, size_t len, size_t *off, unsigned char kind,
                           unsigned char node)
{
    struct schema_walk w = {.doc = doc, .len = len, .off = *off, .depth = 0u};
    const int opened = schema_open(&w, kind, node);
    for (unsigned step = 0u; opened == 1 && step < SIGNER_MAX_SCHEMA_STEPS; step++) {
        if (!schema_step(&w))
            return 0;
        if (w.depth == 0u) {
            *off = w.off;
            return 1;
        }
    }
    if (opened == 2)
        *off = w.off;
    return opened == 2;
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

static int parse_material_field(const char *doc, size_t len, size_t *off, int idx,
                                struct json_span *raw_b64)
{
    if (idx == 0)
        return parse_certificate_object(doc, len, off, raw_b64);
    if (idx == 1)
        return schema_validate(doc, len, off, SK_OBJS, SN_TLOG);
    return idx == 2 && schema_validate(doc, len, off, SK_OBJ, SN_TSV);
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
        int done = 0;
        if (!parse_material_field(doc, len, off, idx, raw_b64) ||
            !json_object_step(doc, len, off, &done))
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
    if (idx == 2)
        return schema_validate(doc, len, off, SK_OBJ, SN_MSGSIG);
    if (idx == 3)
        return schema_validate(doc, len, off, SK_OBJ, SN_DSSE);
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

/* Decode standard base64 with padding (RFC 4648 section 4) into out[0..cap). */
static int base64_decode(const char *in, size_t in_len, unsigned char *out, size_t cap,
                         size_t *out_len)
{
    size_t pad = 0u;
    if (base64_shape(in, in_len, &pad) != 0)
        return -EBADMSG;
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
