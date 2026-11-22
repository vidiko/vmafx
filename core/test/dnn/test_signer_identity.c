/**
 *  Copyright 2026 Lusoris
 *  SPDX-License-Identifier: EUPL-1.2
 *
 *  ADR-2985: who may sign a tiny model. The signing certificate of a bundle
 *  must name the supply-chain workflow of vidiko/vmafx and carry the vidiko GitHub owner ID
 *  (Fulcio extension 1.3.6.1.4.1.57264.1.17); a name with a prefix or a
 *  suffix, another workflow, or the right name under another owner fails.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mu_table.h"
#include "signer_fixtures.h"
#include "signer_identity.h"
#include "test.h"

/* NOLINTBEGIN(modernize-use-nullptr): C translation unit (ADR-1138). */

#define TEST_MAX_SAN 1024u
#define TEST_MAX_BUNDLE 16384u
#define TEST_SHORT_BUNDLE 8192u
#define TEST_MAX_DER 4096u

static int san_allowed(const char *san)
{
    return vmaf_dnn_signer_identity_allowed(san, strnlen(san, TEST_MAX_SAN));
}

static int bundle_status(const char *bundle)
{
    return vmaf_dnn_signer_check_bundle(bundle, strnlen(bundle, TEST_MAX_BUNDLE));
}

static char *test_identity_accepts_release_and_master(void)
{
    mu_assert("release tag", san_allowed("https://github.com/vidiko/vmafx/.github/workflows/"
                                         "supply-chain.yml@refs/tags/v1.0.0-rc.3"));
    mu_assert("master (manual re-publication)",
              san_allowed("https://github.com/vidiko/vmafx/.github/workflows/"
                          "supply-chain.yml@refs/heads/master"));
    return NULL;
}

static char *test_identity_rejects_prefix_and_suffix(void)
{
    mu_assert("prefix", !san_allowed("https://evil.example/https://github.com/vidiko/vmafx/"
                                     ".github/workflows/supply-chain.yml@refs/tags/v1.0.0"));
    mu_assert("suffix after the ref", !san_allowed("https://github.com/vidiko/vmafx/.github/"
                                                   "workflows/supply-chain.yml@refs/heads/"
                                                   "master/evil"));
    mu_assert("suffix on the repository", !san_allowed("https://github.com/vidiko/vmafx-evil/"
                                                       ".github/workflows/supply-chain.yml"
                                                       "@refs/tags/v1.0.0"));
    mu_assert("tag with a path", !san_allowed("https://github.com/vidiko/vmafx/.github/"
                                              "workflows/supply-chain.yml@refs/tags/v1/x"));
    return NULL;
}

static char *test_identity_rejects_other_names(void)
{
    mu_assert("dot is not a wildcard", !san_allowed("https://githubXcom/vidiko/vmafx/.github/"
                                                    "workflows/supply-chain.yml@refs/tags/v1"));
    mu_assert("other workflow", !san_allowed("https://github.com/vidiko/vmafx/.github/"
                                             "workflows/evil.yml@refs/heads/master"));
    mu_assert("other branch", !san_allowed("https://github.com/vidiko/vmafx/.github/workflows/"
                                           "supply-chain.yml@refs/heads/evil"));
    mu_assert("tag without a digit", !san_allowed("https://github.com/vidiko/vmafx/.github/"
                                                  "workflows/supply-chain.yml@refs/tags/vx"));
    mu_assert("empty", !san_allowed(""));
    mu_assert("NULL", vmaf_dnn_signer_identity_allowed(NULL, 4) == 0);
    return NULL;
}

static char *test_bundle_tag_certificate_accepted(void)
{
    mu_assert("self-signed, release tag name and owner", bundle_status(k_bundle_tag) == 0);
    mu_assert("self-signed, right name and owner", bundle_status(k_bundle_master) == 0);
    return NULL;
}

/* The v1.0.0-rc.3 release was signed before the move: its real Fulcio
 * certificate names the workflow under the previous owner and carries the
 * previous owner ID, so it is refused, as is the right name with that ID. */
static char *test_bundle_previous_owner_rejected(void)
{
    mu_assert("v1.0.0-rc.3 release certificate", bundle_status(k_bundle_release) == -EPERM);
    mu_assert("right name, previous owner ID", bundle_status(k_bundle_previous_owner) == -EPERM);
    return NULL;
}

static char *test_bundle_wrong_owner_rejected(void)
{
    mu_assert("right name, other owner ID", bundle_status(k_bundle_wrong_owner) == -EPERM);
    mu_assert("no owner ID extension", bundle_status(k_bundle_no_owner) == -EPERM);
    return NULL;
}

static char *test_bundle_wrong_identity_rejected(void)
{
    mu_assert("prefix", bundle_status(k_bundle_prefix) == -EPERM);
    mu_assert("suffix", bundle_status(k_bundle_suffix) == -EPERM);
    mu_assert("dot wildcard", bundle_status(k_bundle_dot) == -EPERM);
    mu_assert("other workflow", bundle_status(k_bundle_other_workflow) == -EPERM);
    mu_assert("two names", bundle_status(k_bundle_two_names) == -EBADMSG);
    return NULL;
}

/* A bundle whose certificate field could be read two ways is refused: two
 * certificates, the proto field name (here), or a `\u` escape that spells a
 * key (next test). */
static char *test_bundle_ambiguous_certificate_rejected_with_buffer(char *doc)
{
    // SAFETY: k_bundle_tag is a nonempty NUL-terminated string starting with '{'.
    int n = snprintf(doc, TEST_MAX_BUNDLE, "{\"rawBytes\":\"AA==\",%s", k_bundle_tag + 1);
    mu_assert("snprintf two", n > 0 && (size_t)n < TEST_MAX_BUNDLE);
    mu_assert("two certificates", bundle_status(doc) == -EBADMSG);
    // SAFETY: k_bundle_tag is a nonempty NUL-terminated string starting with '{'.
    n = snprintf(doc, TEST_MAX_BUNDLE, "{\"raw_bytes\":\"AA==\",%s", k_bundle_tag + 1);
    mu_assert("snprintf proto", n > 0 && (size_t)n < TEST_MAX_BUNDLE);
    mu_assert("proto field name", bundle_status(doc) == -EBADMSG);
    return NULL;
}

static char *test_bundle_ambiguous_certificate_rejected(void)
{
    char *doc = calloc(TEST_MAX_BUNDLE, 1u);
    if (!doc)
        return "allocation failed";
    char *result = test_bundle_ambiguous_certificate_rejected_with_buffer(doc);
    free(doc);
    return result;
}

static char *test_bundle_escaped_or_missing_certificate_rejected_with_buffer(char *doc)
{
    // SAFETY: k_bundle_tag is a nonempty NUL-terminated string starting with '{'.
    const int n = snprintf(doc, TEST_MAX_BUNDLE, "{\"x\":\"\\u0041\",%s", k_bundle_tag + 1);
    mu_assert("snprintf escape", n > 0 && (size_t)n < TEST_MAX_BUNDLE);
    mu_assert("unicode escape", bundle_status(doc) == -EBADMSG);
    mu_assert("no certificate", bundle_status("{\"verificationMaterial\":{}}") == -EBADMSG);
    mu_assert("NULL", vmaf_dnn_signer_check_bundle(NULL, 0u) == -EBADMSG);
    return NULL;
}

static char *test_bundle_escaped_or_missing_certificate_rejected(void)
{
    char *doc = calloc(TEST_MAX_BUNDLE, 1u);
    if (!doc)
        return "allocation failed";
    char *result = test_bundle_escaped_or_missing_certificate_rejected_with_buffer(doc);
    free(doc);
    return result;
}

static char *test_bundle_malformed_rejected(void)
{
    mu_assert("not base64",
              bundle_status("{\"mediaType\":\"application/vnd.dev.sigstore.bundle.v0.3+json\","
                            "\"verificationMaterial\":{\"certificate\":"
                            "{\"rawBytes\":\"!!!!\"}}}") == -EBADMSG);
    mu_assert("bad length",
              bundle_status("{\"mediaType\":\"application/vnd.dev.sigstore.bundle.v0.3+json\","
                            "\"verificationMaterial\":{\"certificate\":"
                            "{\"rawBytes\":\"AAA\"}}}") == -EBADMSG);
    mu_assert("not DER",
              bundle_status("{\"mediaType\":\"application/vnd.dev.sigstore.bundle.v0.3+json\","
                            "\"verificationMaterial\":{\"certificate\":"
                            "{\"rawBytes\":\"AAAA\"}}}") == -EBADMSG);
    mu_assert("unterminated",
              bundle_status("{\"mediaType\":\"application/vnd.dev.sigstore.bundle.v0.3+json\","
                            "\"verificationMaterial\":{\"certificate\":"
                            "{\"rawBytes\":\"AAAA") == -EBADMSG);
    mu_assert("no colon",
              bundle_status("{\"mediaType\":\"application/vnd.dev.sigstore.bundle.v0.3+json\","
                            "\"verificationMaterial\":{\"certificate\":"
                            "{\"rawBytes\" \"AAAA\"}}}") == -EBADMSG);
    return NULL;
}

static int test_b64_val(unsigned char c)
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

static int fixture_raw_bytes_span(const char *bundle, const char **out_b64, size_t *out_len)
{
    static const char key[] = "\"rawBytes\":\"";
    const char *b64 = strstr(bundle, key);
    if (!b64)
        return 0;
    // SAFETY: b64 points to key inside bundle, so advancing by strlen(key) stays within bundle.
    b64 += sizeof(key) - 1u;
    const char *end = strchr(b64, '"');
    if (!end)
        return 0;
    *out_b64 = b64;
    // SAFETY: end was found by strchr starting at b64, so b64 <= end in the same string.
    *out_len = (size_t)(end - b64);
    return *out_len > 0u && *out_len % 4u == 0u;
}

static size_t decode_fixture_der(const char *bundle, unsigned char *der, size_t cap)
{
    const char *b64 = NULL;
    size_t in_len = 0u;
    if (!fixture_raw_bytes_span(bundle, &b64, &in_len))
        return 0u;
    const size_t pad = (b64[in_len - 1u] == '=') + (b64[in_len - 2u] == '=');
    const size_t out_len = in_len / 4u * 3u - pad;
    if (out_len > cap)
        return 0u;
    size_t o = 0u;
    for (size_t i = 0u; i < in_len; i += 4u) {
        unsigned long acc = 0u;
        for (size_t k = 0u; k < 4u; k++) {
            const int v = (i + k < in_len - pad) ? test_b64_val((unsigned char)b64[i + k]) : 0;
            if (v < 0)
                return 0u;
            acc = (acc << 6u) | (unsigned long)v;
        }
        for (size_t k = 0u; k < 3u && o < out_len; k++)
            der[o++] = (unsigned char)(acc >> (16u - 8u * k));
    }
    return out_len;
}

/* Every strict prefix of a valid DER certificate is malformed, never accepted:
 * the walk never reads past the bytes it was given. */
static char *test_certificate_truncations_rejected_with_buffer(unsigned char *der)
{
    const size_t full = decode_fixture_der(k_bundle_master, der, TEST_MAX_DER);
    mu_assert("fixture DER decoded", full > 0u && full <= TEST_MAX_DER);
    mu_assert("full DER certificate accepted", vmaf_dnn_signer_check_certificate(der, full) == 0);
    for (size_t cut = 0u; cut < full && cut < TEST_MAX_DER; cut++) {
        mu_assert("truncated DER certificate rejected",
                  vmaf_dnn_signer_check_certificate(der, cut) != 0);
    }
    return NULL;
}

static char *test_certificate_truncations_rejected(void)
{
    unsigned char *der = calloc(TEST_MAX_DER, 1u);
    if (!der)
        return "allocation failed";
    char *result = test_certificate_truncations_rejected_with_buffer(der);
    free(der);
    return result;
}

static int bundle_with_key_status_with_buffer(const char *key, char *doc)
{
    // SAFETY: k_bundle_tag is a nonempty NUL-terminated string starting with '{'.
    int n = snprintf(doc, TEST_MAX_BUNDLE, "{\"%s\":{},%s", key, k_bundle_tag + 1);
    if (n < 0 || (size_t)n >= TEST_MAX_BUNDLE)
        return 0;
    return bundle_status(doc);
}

static int bundle_with_key_status(const char *key)
{
    char *doc = calloc(TEST_MAX_BUNDLE, 1u);
    if (!doc)
        return 0;
    int result = bundle_with_key_status_with_buffer(key, doc);
    free(doc);
    return result;
}

static char *test_bundle_refuses_cert(void)
{
    mu_assert("alternate key refused", bundle_with_key_status("cert") == -EBADMSG);
    return NULL;
}

static char *test_bundle_refuses_base64_signature(void)
{
    mu_assert("alternate key refused", bundle_with_key_status("base64Signature") == -EBADMSG);
    return NULL;
}

static char *test_bundle_refuses_rekor_bundle(void)
{
    mu_assert("alternate key refused", bundle_with_key_status("rekorBundle") == -EBADMSG);
    return NULL;
}

static char *test_bundle_refuses_certificate_chain(void)
{
    mu_assert("alternate key refused", bundle_with_key_status("x509CertificateChain") == -EBADMSG);
    return NULL;
}

static char *test_bundle_refuses_public_key(void)
{
    mu_assert("alternate key refused", bundle_with_key_status("publicKey") == -EBADMSG);
    return NULL;
}

static char *test_bundle_requires_single_certificate_format_with_buffer(char *doc)
{
    // SAFETY: k_bundle_tag is a nonempty NUL-terminated string starting with '{'.
    int n = snprintf(doc, TEST_MAX_BUNDLE,
                     "{\"cert\":\"other\",\"base64Signature\":\"x\","
                     "\"rekorBundle\":{},%s",
                     k_bundle_tag + 1);
    mu_assert("fixture fits", n > 0 && (size_t)n < TEST_MAX_BUNDLE);
    mu_assert("only current certificate format", bundle_status(doc) == -EBADMSG);
    return NULL;
}

static char *test_bundle_requires_single_certificate_format(void)
{
    char *doc = calloc(TEST_MAX_BUNDLE, 1u);
    if (!doc)
        return "allocation failed";
    char *result = test_bundle_requires_single_certificate_format_with_buffer(doc);
    free(doc);
    return result;
}

static char *test_bundle_requires_media_type_with_buffer(char *doc)
{
    const char *rest = strstr(k_bundle_tag, ",\"verificationMaterial\"");
    mu_assert("fixture material", rest != NULL);
    // SAFETY: rest points to the leading comma of ",\"verificationMaterial\"" inside k_bundle_tag.
    int n = snprintf(doc, TEST_MAX_BUNDLE, "{%s", rest + 1);
    mu_assert("fixture fits", n > 0 && (size_t)n < TEST_MAX_BUNDLE);
    mu_assert("missing media type", bundle_status(doc) == -EBADMSG);
    return NULL;
}

static char *test_bundle_requires_media_type(void)
{
    char *doc = calloc(TEST_MAX_BUNDLE, 1u);
    if (!doc)
        return "allocation failed";
    char *result = test_bundle_requires_media_type_with_buffer(doc);
    free(doc);
    return result;
}

static char *test_bundle_requires_sigstore_media_type_with_buffer(char *doc)
{
    const char *rest = strstr(k_bundle_tag, ",\"verificationMaterial\"");
    mu_assert("fixture material", rest != NULL);
    int n = snprintf(doc, TEST_MAX_BUNDLE, "{\"mediaType\":\"application/json\"%s", rest);
    mu_assert("fixture fits", n > 0 && (size_t)n < TEST_MAX_BUNDLE);
    mu_assert("wrong media type", bundle_status(doc) == -EBADMSG);
    return NULL;
}

static char *test_bundle_requires_sigstore_media_type(void)
{
    char *doc = calloc(TEST_MAX_BUNDLE, 1u);
    if (!doc)
        return "allocation failed";
    char *result = test_bundle_requires_sigstore_media_type_with_buffer(doc);
    free(doc);
    return result;
}

static char *test_bundle_refuses_proto_x509_certificate_chain(void)
{
    mu_assert("x509_certificate_chain refused",
              bundle_with_key_status("x509_certificate_chain") == -EBADMSG);
    return NULL;
}

static char *test_bundle_refuses_proto_public_key(void)
{
    mu_assert("public_key refused", bundle_with_key_status("public_key") == -EBADMSG);
    return NULL;
}

static char *test_bundle_refuses_proto_base64_signature(void)
{
    mu_assert("base64_signature refused", bundle_with_key_status("base64_signature") == -EBADMSG);
    return NULL;
}

static char *test_bundle_refuses_proto_rekor_bundle(void)
{
    mu_assert("rekor_bundle refused", bundle_with_key_status("rekor_bundle") == -EBADMSG);
    return NULL;
}

static char *test_bundle_refuses_proto_media_type(void)
{
    mu_assert("media_type refused", bundle_with_key_status("media_type") == -EBADMSG);
    return NULL;
}

static char *test_bundle_refuses_proto_verification_material(void)
{
    mu_assert("verification_material refused",
              bundle_with_key_status("verification_material") == -EBADMSG);
    return NULL;
}

static char *test_bundle_refuses_proto_message_signature(void)
{
    mu_assert("message_signature refused", bundle_with_key_status("message_signature") == -EBADMSG);
    return NULL;
}

static char *test_bundle_refuses_proto_dsse_envelope(void)
{
    mu_assert("dsse_envelope refused", bundle_with_key_status("dsse_envelope") == -EBADMSG);
    return NULL;
}

static char *test_bundle_refuses_proto_tlog_entries(void)
{
    mu_assert("tlog_entries refused", bundle_with_key_status("tlog_entries") == -EBADMSG);
    return NULL;
}

static char *test_bundle_refuses_proto_timestamp_verification_data(void)
{
    mu_assert("timestamp_verification_data refused",
              bundle_with_key_status("timestamp_verification_data") == -EBADMSG);
    return NULL;
}

static int bundle_with_trailing_key_status_with_buffer(const char *key, char *doc)
{
    const size_t len = sizeof(k_bundle_tag) - 1u;
    int n = snprintf(doc, TEST_MAX_BUNDLE, "%.*s,\"%s\":{}}", (int)(len - 1u), k_bundle_tag, key);
    if (n < 0 || (size_t)n >= TEST_MAX_BUNDLE)
        return 0;
    return bundle_status(doc);
}

static int bundle_with_trailing_key_status(const char *key)
{
    char *doc = calloc(TEST_MAX_BUNDLE, 1u);
    if (!doc)
        return 0;
    int result = bundle_with_trailing_key_status_with_buffer(key, doc);
    free(doc);
    return result;
}

static char *test_bundle_requires_one_certificate(void)
{
    mu_assert("one certificate", bundle_with_trailing_key_status("certificate") == -EBADMSG);
    return NULL;
}

static char *test_bundle_requires_raw_bytes_first_with_buffer(char *doc)
{
    const char *raw = strstr(k_bundle_tag, "\"rawBytes\"");
    mu_assert("fixture rawBytes", raw != NULL);
    // SAFETY: raw was found by strstr in k_bundle_tag, so k_bundle_tag <= raw.
    int n = snprintf(doc, TEST_MAX_BUNDLE, "%.*s\"extra\":0,%s", (int)(raw - k_bundle_tag),
                     k_bundle_tag, raw);
    mu_assert("fixture fits", n > 0 && (size_t)n < TEST_MAX_BUNDLE);
    mu_assert("rawBytes first", bundle_status(doc) == -EBADMSG);
    return NULL;
}

static char *test_bundle_requires_raw_bytes_first(void)
{
    char *doc = calloc(TEST_MAX_BUNDLE, 1u);
    if (!doc)
        return "allocation failed";
    char *result = test_bundle_requires_raw_bytes_first_with_buffer(doc);
    free(doc);
    return result;
}

static char *test_bundle_requires_top_level_media_type_with_buffer(char *doc)
{
    const char *rest = strstr(k_bundle_tag, ",\"verificationMaterial\"");
    mu_assert("fixture material", rest != NULL);
    int n = snprintf(doc, TEST_MAX_BUNDLE,
                     "{\"nested\":{\"mediaType\":"
                     "\"application/vnd.dev.sigstore.bundle.v0.3+json\"}%s",
                     rest);
    mu_assert("fixture fits", n > 0 && (size_t)n < TEST_MAX_BUNDLE);
    mu_assert("top-level mediaType", bundle_status(doc) == -EBADMSG);
    return NULL;
}

static char *test_bundle_requires_top_level_media_type(void)
{
    char *doc = calloc(TEST_MAX_BUNDLE, 1u);
    if (!doc)
        return "allocation failed";
    char *result = test_bundle_requires_top_level_media_type_with_buffer(doc);
    free(doc);
    return result;
}

static char *test_bundle_requires_one_media_type(void)
{
    mu_assert("one mediaType", bundle_with_trailing_key_status("mediaType") == -EBADMSG);
    return NULL;
}

static char *test_bundle_full_shape_accepted(void)
{
    mu_assert("full release bundle shape", bundle_status(k_bundle_full_shape) == 0);
    return NULL;
}

static char *test_certificate_rejects_duplicate_owner(void)
{
    mu_assert("duplicate_owner", bundle_status(k_bundle_duplicate_owner) != 0);
    return NULL;
}

static char *test_certificate_rejects_duplicate_san(void)
{
    mu_assert("duplicate_san", bundle_status(k_bundle_duplicate_san) != 0);
    return NULL;
}

static char *test_certificate_rejects_owner_long(void)
{
    mu_assert("owner_long", bundle_status(k_bundle_owner_long) != 0);
    return NULL;
}

static char *test_certificate_rejects_owner_short(void)
{
    mu_assert("owner_short", bundle_status(k_bundle_owner_short) != 0);
    return NULL;
}

static char *test_certificate_rejects_owner_empty(void)
{
    mu_assert("owner_empty", bundle_status(k_bundle_owner_empty) != 0);
    return NULL;
}

static char *test_certificate_rejects_owner_space(void)
{
    mu_assert("owner_space", bundle_status(k_bundle_owner_space) != 0);
    return NULL;
}

static char *test_certificate_rejects_owner_tag(void)
{
    mu_assert("owner_tag", bundle_status(k_bundle_owner_tag) != 0);
    return NULL;
}

static char *test_certificate_rejects_san_email(void)
{
    mu_assert("san_email", bundle_status(k_bundle_san_email) != 0);
    return NULL;
}

static char *test_certificate_rejects_san_dns(void)
{
    mu_assert("san_dns", bundle_status(k_bundle_san_dns) != 0);
    return NULL;
}

static char *test_certificate_rejects_san_nul(void)
{
    mu_assert("san_nul", bundle_status(k_bundle_san_nul) != 0);
    return NULL;
}

static char *test_certificate_rejects_nonminimal_length(void)
{
    mu_assert("nonminimal_length", bundle_status(k_bundle_nonminimal_length) != 0);
    return NULL;
}

static char *test_certificate_rejects_trailing_bytes(void)
{
    mu_assert("trailing_bytes", bundle_status(k_bundle_trailing_bytes) != 0);
    return NULL;
}

static char *test_certificate_rejects_oversize(void)
{
    mu_assert("oversize", vmaf_dnn_signer_check_certificate(k_certificate_oversize,
                                                            sizeof(k_certificate_oversize)) != 0);
    return NULL;
}

static char *test_bundle_rejects_unknown_top_level_key(void)
{
    mu_assert("unknown top-level key refused",
              bundle_with_key_status("unknownTopLevel") == -EBADMSG);
    return NULL;
}

static char *test_bundle_rejects_case_variant_key_with_buffer(char *doc)
{
    const char *rest = strstr(k_bundle_tag, ",\"verificationMaterial\"");
    mu_assert("fixture material", rest != NULL);
    int n = snprintf(doc, TEST_MAX_BUNDLE,
                     "{\"MediaType\":\"application/vnd.dev.sigstore.bundle.v0.3+json\"%s", rest);
    mu_assert("fixture fits", n > 0 && (size_t)n < TEST_MAX_BUNDLE);
    mu_assert("case-variant MediaType refused", bundle_status(doc) == -EBADMSG);
    return NULL;
}

static char *test_bundle_rejects_case_variant_key(void)
{
    char *doc = calloc(TEST_MAX_BUNDLE, 1u);
    if (!doc)
        return "allocation failed";
    char *result = test_bundle_rejects_case_variant_key_with_buffer(doc);
    free(doc);
    return result;
}

static char *test_bundle_rejects_duplicate_key_with_buffer(char *doc)
{
    const size_t len = sizeof(k_bundle_tag) - 1u;
    int n = snprintf(doc, TEST_MAX_BUNDLE, "%.*s,\"certificate\":{\"rawBytes\":\"AA==\"}}}",
                     (int)(len - 2u), k_bundle_tag);
    mu_assert("fixture fits", n > 0 && (size_t)n < TEST_MAX_BUNDLE);
    mu_assert("duplicate verificationMaterial.certificate refused", bundle_status(doc) == -EBADMSG);
    return NULL;
}

static char *test_bundle_rejects_duplicate_key(void)
{
    char *doc = calloc(TEST_MAX_BUNDLE, 1u);
    if (!doc)
        return "allocation failed";
    char *result = test_bundle_rejects_duplicate_key_with_buffer(doc);
    free(doc);
    return result;
}

static char *test_bundle_rejects_top_level_certificate_without_material_with_buffer(char *doc)
{
    const char *cert = strstr(k_bundle_tag, "\"certificate\":");
    mu_assert("fixture certificate", cert != NULL);
    const size_t cert_len = strnlen(cert, TEST_MAX_BUNDLE);
    mu_assert("fixture closes", cert_len > 2u);
    int n = snprintf(doc, TEST_MAX_BUNDLE,
                     "{\"mediaType\":\"application/vnd.dev.sigstore.bundle.v0.3+json\",%.*s}",
                     (int)(cert_len - 2u), cert);
    mu_assert("fixture fits", n > 0 && (size_t)n < TEST_MAX_BUNDLE);
    mu_assert("top-level certificate without verificationMaterial refused",
              bundle_status(doc) == -EBADMSG);
    return NULL;
}

static char *test_bundle_rejects_top_level_certificate_without_material(void)
{
    char *doc = calloc(TEST_MAX_BUNDLE, 1u);
    if (!doc)
        return "allocation failed";
    char *result = test_bundle_rejects_top_level_certificate_without_material_with_buffer(doc);
    free(doc);
    return result;
}

static char *test_bundle_rejects_media_type_substring_v03_with_buffer(char *doc)
{
    const char *rest = strstr(k_bundle_tag, ",\"verificationMaterial\"");
    mu_assert("fixture material", rest != NULL);
    int n =
        snprintf(doc, TEST_MAX_BUNDLE,
                 "{\"mediaType\":\"application/vnd.dev.sigstore.bundle.v0.3+json.extra\"%s", rest);
    mu_assert("fixture fits", n > 0 && (size_t)n < TEST_MAX_BUNDLE);
    mu_assert("mediaType substring v0.3 refused", bundle_status(doc) == -EBADMSG);
    return NULL;
}

static char *test_bundle_rejects_media_type_substring_v03(void)
{
    char *doc = calloc(TEST_MAX_BUNDLE, 1u);
    if (!doc)
        return "allocation failed";
    char *result = test_bundle_rejects_media_type_substring_v03_with_buffer(doc);
    free(doc);
    return result;
}

static char *test_bundle_accepts_version_param_media_type_with_buffer(char *doc)
{
    const char *rest = strstr(k_bundle_tag, ",\"verificationMaterial\"");
    mu_assert("fixture material", rest != NULL);
    int n =
        snprintf(doc, TEST_MAX_BUNDLE,
                 "{\"mediaType\":\"application/vnd.dev.sigstore.bundle+json;version=0.3\"%s", rest);
    mu_assert("fixture fits", n > 0 && (size_t)n < TEST_MAX_BUNDLE);
    mu_assert("version=0.3 mediaType accepted", bundle_status(doc) == 0);
    return NULL;
}

static char *test_bundle_accepts_version_param_media_type(void)
{
    char *doc = calloc(TEST_MAX_BUNDLE, 1u);
    if (!doc)
        return "allocation failed";
    char *result = test_bundle_accepts_version_param_media_type_with_buffer(doc);
    free(doc);
    return result;
}

static char *test_certificate_rejects_tbs_only_outer_sequence_with_buffer(unsigned char *der)
{
    const size_t full = decode_fixture_der(k_bundle_master, der, TEST_MAX_DER);
    mu_assert("fixture DER decoded", full > 8u && full <= TEST_MAX_DER);
    mu_assert("outer and TBS use 2-byte DER length",
              der[0] == 0x30u && der[1] == 0x82u && der[4] == 0x30u && der[5] == 0x82u);
    const size_t tbs_tlv_len = 4u + (((size_t)der[6] << 8u) | (size_t)der[7]);
    mu_assert("TBS fits inside certificate", 4u + tbs_tlv_len < full);
    der[2] = (unsigned char)(tbs_tlv_len >> 8u);
    der[3] = (unsigned char)(tbs_tlv_len & 0xFFu);
    mu_assert("TBS-only outer SEQUENCE rejected",
              vmaf_dnn_signer_check_certificate(der, 4u + tbs_tlv_len) == -EBADMSG);
    return NULL;
}

static char *test_certificate_rejects_tbs_only_outer_sequence(void)
{
    unsigned char *der = calloc(TEST_MAX_DER, 1u);
    if (!der)
        return "allocation failed";
    char *result = test_certificate_rejects_tbs_only_outer_sequence_with_buffer(der);
    free(der);
    return result;
}

static char *test_certificate_rejects_trailing_bytes_in_outer_seq_with_buffer(unsigned char *der)
{
    const size_t full = decode_fixture_der(k_bundle_master, der, TEST_MAX_DER - 1u);
    mu_assert("fixture DER decoded", full > 4u && full < TEST_MAX_DER);
    mu_assert("outer uses 2-byte DER length", der[0] == 0x30u && der[1] == 0x82u);
    const size_t new_body_len = (full - 4u) + 1u;
    der[2] = (unsigned char)(new_body_len >> 8u);
    der[3] = (unsigned char)(new_body_len & 0xFFu);
    der[full] = 0x00u;
    mu_assert("trailing byte inside outer SEQUENCE rejected",
              vmaf_dnn_signer_check_certificate(der, full + 1u) == -EBADMSG);
    return NULL;
}

static char *test_certificate_rejects_trailing_bytes_inside_outer_sequence(void)
{
    unsigned char *der = calloc(TEST_MAX_DER, 1u);
    if (!der)
        return "allocation failed";
    char *result = test_certificate_rejects_trailing_bytes_in_outer_seq_with_buffer(der);
    free(der);
    return result;
}

static const MuTest tests[] = {
    MU_TEST(test_certificate_rejects_duplicate_owner),
    MU_TEST(test_certificate_rejects_duplicate_san),
    MU_TEST(test_certificate_rejects_owner_long),
    MU_TEST(test_certificate_rejects_owner_short),
    MU_TEST(test_certificate_rejects_owner_empty),
    MU_TEST(test_certificate_rejects_owner_space),
    MU_TEST(test_certificate_rejects_owner_tag),
    MU_TEST(test_certificate_rejects_san_email),
    MU_TEST(test_certificate_rejects_san_dns),
    MU_TEST(test_certificate_rejects_san_nul),
    MU_TEST(test_certificate_rejects_nonminimal_length),
    MU_TEST(test_certificate_rejects_trailing_bytes),
    MU_TEST(test_certificate_rejects_oversize),

    MU_TEST(test_identity_accepts_release_and_master),
    MU_TEST(test_identity_rejects_prefix_and_suffix),
    MU_TEST(test_identity_rejects_other_names),
    MU_TEST(test_bundle_tag_certificate_accepted),
    MU_TEST(test_bundle_previous_owner_rejected),
    MU_TEST(test_bundle_wrong_owner_rejected),
    MU_TEST(test_bundle_wrong_identity_rejected),
    MU_TEST(test_bundle_rejects_unknown_top_level_key),
    MU_TEST(test_bundle_ambiguous_certificate_rejected),
    MU_TEST(test_bundle_escaped_or_missing_certificate_rejected),
    MU_TEST(test_bundle_malformed_rejected),
    MU_TEST(test_certificate_truncations_rejected),
    MU_TEST(test_bundle_refuses_cert),
    MU_TEST(test_bundle_refuses_base64_signature),
    MU_TEST(test_bundle_refuses_rekor_bundle),
    MU_TEST(test_bundle_refuses_certificate_chain),
    MU_TEST(test_bundle_refuses_public_key),
    MU_TEST(test_bundle_requires_single_certificate_format),
    MU_TEST(test_bundle_requires_media_type),
    MU_TEST(test_bundle_requires_sigstore_media_type),
    MU_TEST(test_bundle_refuses_proto_x509_certificate_chain),
    MU_TEST(test_bundle_refuses_proto_public_key),
    MU_TEST(test_bundle_refuses_proto_base64_signature),
    MU_TEST(test_bundle_refuses_proto_rekor_bundle),
    MU_TEST(test_bundle_refuses_proto_media_type),
    MU_TEST(test_bundle_refuses_proto_verification_material),
    MU_TEST(test_bundle_refuses_proto_message_signature),
    MU_TEST(test_bundle_refuses_proto_dsse_envelope),
    MU_TEST(test_bundle_refuses_proto_tlog_entries),
    MU_TEST(test_bundle_refuses_proto_timestamp_verification_data),
    MU_TEST(test_bundle_requires_one_certificate),
    MU_TEST(test_bundle_requires_raw_bytes_first),
    MU_TEST(test_bundle_requires_top_level_media_type),
    MU_TEST(test_bundle_requires_one_media_type),
    MU_TEST(test_bundle_full_shape_accepted),
    MU_TEST(test_bundle_rejects_case_variant_key),
    MU_TEST(test_bundle_rejects_duplicate_key),
    MU_TEST(test_bundle_rejects_top_level_certificate_without_material),
    MU_TEST(test_bundle_rejects_media_type_substring_v03),
    MU_TEST(test_bundle_accepts_version_param_media_type),
    MU_TEST(test_certificate_rejects_tbs_only_outer_sequence),
    MU_TEST(test_certificate_rejects_trailing_bytes_inside_outer_sequence),
};

char *run_tests(void)
{
    return mu_run_table(tests, MU_TABLE_LEN(tests));
}

/* NOLINTEND(modernize-use-nullptr) */
