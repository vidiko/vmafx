/**
 *  Copyright 2026 Lusoris
 *  SPDX-License-Identifier: EUPL-1.2
 *
 *  T6-9 / ADR-0211 — exercise the failure modes of
 *  vmaf_dnn_verify_signature() without requiring `cosign` on the test
 *  host. The function fails closed, so every "missing X" path returns a
 *  negative errno and short-circuits before posix_spawnp is reached.
 */

#include <errno.h>

/* NOLINTBEGIN(concurrency-mt-unsafe): this test's subject is how the library
 * resolves paths from the process environment, so it has to set and unset
 * variables. Each test binary is its own single-threaded process, and nothing
 * else reads the environment while it runs (ADR-0141). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#include "compat/crt_portable.h"
#include "mu_table.h"
#include "test.h"

#include "dnn/model_loader.h"
#include "signer_fixtures.h"

/* NOLINTBEGIN(modernize-use-nullptr): C translation unit. The fork builds C as
 * C23, where clang-tidy also proposes the `nullptr` keyword, but MSVC's
 * documented /std:clatest C23 feature set does not include `nullptr` while the
 * required Windows build compiles this TU with cl.exe, and this file mirrors
 * the C spelling of the surface it exercises. ADR-1138. */

static char *test_verify_null_path(void)
{
    const int err = vmaf_dnn_verify_signature(NULL, NULL);
    mu_assert("NULL onnx path -> -EINVAL", err == -EINVAL);
    return NULL;
}

#ifndef _WIN32
#define TEST_BUFFER_256 256u
#define TEST_BUFFER_512 512u
#define TEST_BUFFER_4096 4096u

/* Helper: write a tiny scratch file + return its path inside `out_path`.
 *
 * Uses open(O_CREAT|O_WRONLY|O_TRUNC, 0600) instead of fopen("wb") so the
 * fixture creates the file with owner-only permissions. fopen() defers
 * mode to the umask (typically 0022, yielding 0644 — and 0666 in some
 * containerised CI environments), which CodeQL flags as
 * cpp/world-writable-file-creation. Tightening to 0600 keeps the test's
 * scratch output out of any other user's reach on shared CI hosts. */
static int write_tmp(const char *suffix, const char *body, char *out_path, size_t out_sz)
{
    const int n = snprintf(out_path, out_sz, "/tmp/vmaf_verify_test_%d_%s", (int)getpid(), suffix);
    if (n < 0 || (size_t)n >= out_sz)
        return -1;
    const int fd = open(out_path, O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR);
    if (fd < 0)
        return -1;
    FILE *f = fdopen(fd, "wb");
    if (!f) {
        /* POSIX leaves the descriptor open when fdopen() fails, so closing it here is
         * required.  cppcheck's posix.cfg lists fdopen as a deallocator of the fd
         * unconditionally, so 2.13 — the version CI installs from apt — reads this as a
         * second free.  2.21 no longer does. */
        /* cppcheck-suppress doubleFree ; see the note above */
        (void)close(fd);
        return -1;
    }
    if (body && fputs(body, f) < 0) {
        (void)fclose(f);
        return -1;
    }
    if (fclose(f) != 0)
        return -1;
    return 0;
}

static char *test_verify_missing_registry(void)
{
    /* No registry beside /tmp/foo.onnx — expect -ENOENT. */
    char onnx[256];
    const int wrc = write_tmp("missing_reg.onnx", "fake", onnx, sizeof(onnx));
    mu_assert("write_tmp succeeded", wrc == 0);
    const int err = vmaf_dnn_verify_signature(onnx, "/nonexistent/registry.json");
    mu_assert("missing registry -> -ENOENT", err == -ENOENT);
    (void)unlink(onnx);
    return NULL;
}

static char *test_verify_no_matching_entry(void)
{
    /* Registry exists but has no entry for `unknown.onnx`. */
    char reg_path[256];
    const int wrc = write_tmp(
        "reg.json", "{\"models\":[{\"id\":\"x\",\"onnx\":\"other.onnx\",\"sha256\":\"00\"}]}",
        reg_path, sizeof(reg_path));
    mu_assert("write_tmp reg succeeded", wrc == 0);
    const int err = vmaf_dnn_verify_signature("/tmp/unknown.onnx", reg_path);
    mu_assert("no entry -> -ENOENT", err == -ENOENT);
    (void)unlink(reg_path);
    return NULL;
}

static char *test_verify_missing_bundle(void)
{
    /* Registry has the entry, but the sigstore_bundle file does not exist. */
    char reg_path[256];
    const char *body = "{\"models\":[{\"id\":\"y\",\"onnx\":\"y.onnx\",\"sha256\":\"00\","
                       "\"sigstore_bundle\":\"y.onnx.sigstore.json\"}]}";
    const int wrc = write_tmp("reg2.json", body, reg_path, sizeof(reg_path));
    mu_assert("write_tmp reg2 succeeded", wrc == 0);
    const int err = vmaf_dnn_verify_signature("/tmp/y.onnx", reg_path);
    mu_assert("missing bundle -> -ENOENT", err == -ENOENT);
    (void)unlink(reg_path);
    return NULL;
}

static char *test_verify_entry_without_bundle(void)
{
    /* Entry exists but has no `sigstore_bundle` key — refuse to load
     * (unsigned model). */
    char reg_path[256];
    const char *body = "{\"models\":[{\"id\":\"z\",\"onnx\":\"z.onnx\",\"sha256\":\"00\"}]}";
    const int wrc = write_tmp("reg3.json", body, reg_path, sizeof(reg_path));
    mu_assert("write_tmp reg3 succeeded", wrc == 0);
    const int err = vmaf_dnn_verify_signature("/tmp/z.onnx", reg_path);
    mu_assert("no bundle key -> -ENOENT", err == -ENOENT);
    (void)unlink(reg_path);
    return NULL;
}

/* Helper: set up a per-test scratch directory under /tmp containing
 * registry.json + bundle file beside the model. Permissions are 0700 on
 * the directory and 0600 on the files (CodeQL fix for shared CI hosts).
 * Returns 0 on success, -1 on any setup failure. */
static int setup_scratch_dir(char *out_dir, size_t out_sz, const char *suffix)
{
    const int n = snprintf(out_dir, out_sz, "/tmp/vmaf_verify_dir_%d_%s", (int)getpid(), suffix);
    if (n < 0 || (size_t)n >= out_sz)
        return -1;
    /* Idempotent: clean up if a previous run left it behind. */
    (void)mkdir(out_dir, S_IRWXU);
    if (chmod(out_dir, S_IRWXU) != 0)
        return -1;
    return 0;
}

/* Write `body` into <dir>/<name> with mode 0600. */
static int write_in_dir(const char *dir, const char *name, const char *body)
{
    char path[512];
    const int n = snprintf(path, sizeof(path), "%s/%s", dir, name);
    if (n < 0 || (size_t)n >= (int)sizeof(path))
        return -1;
    const int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR);
    if (fd < 0)
        return -1;
    FILE *f = fdopen(fd, "wb");
    if (!f) {
        /* POSIX leaves the descriptor open when fdopen() fails, so closing it here is
         * required.  cppcheck's posix.cfg lists fdopen as a deallocator of the fd
         * unconditionally, so 2.13 — the version CI installs from apt — reads this as a
         * second free.  2.21 no longer does. */
        /* cppcheck-suppress doubleFree ; see the note above */
        (void)close(fd);
        return -1;
    }
    if (body && fputs(body, f) < 0) {
        (void)fclose(f);
        return -1;
    }
    if (fclose(f) != 0)
        return -1;
    return 0;
}

/* Best-effort cleanup of <dir>/<name>. Errors ignored — these are
 * scratch files inside a per-pid /tmp dir. */
static void cleanup_in_dir(const char *dir, const char *name)
{
    char path[512];
    const int n = snprintf(path, sizeof(path), "%s/%s", dir, name);
    if (n < 0 || (size_t)n >= (int)sizeof(path))
        return;
    (void)unlink(path);
}

static char *test_verify_default_registry_missing(void)
{
    /* registry_path = NULL forces the default-registry derivation:
     *   <dirname(onnx_path)>/registry.json
     * The onnx file lives in our scratch dir, but registry.json is
     * intentionally absent — exercises slurp_registry()'s fopen-fail
     * branch through the default-path lookup logic (lines 547-560). */
    char dir[256];
    mu_assert("setup scratch dir", setup_scratch_dir(dir, sizeof(dir), "defreg") == 0);
    mu_assert("write onnx", write_in_dir(dir, "model.onnx", "fake") == 0);

    char onnx_path[512];
    const int n = snprintf(onnx_path, sizeof(onnx_path), "%s/model.onnx", dir);
    mu_assert("snprintf onnx_path", n > 0 && (size_t)n < sizeof(onnx_path));

    const int err = vmaf_dnn_verify_signature(onnx_path, NULL);
    /* fopen() of the missing default registry returns -ENOENT. */
    mu_assert("default registry missing -> -ENOENT", err == -ENOENT);

    cleanup_in_dir(dir, "model.onnx");
    (void)rmdir(dir);
    return NULL;
}

static char *test_verify_default_registry_no_slash_in_onnx(void)
{
    /* onnx_path has no '/' separator -> falls through to the
     * model/tiny/registry.json default. That path won't exist in /tmp's
     * cwd, so we expect a slurp_registry() failure (-ENOENT). Exercises
     * lines 555-558 (the "no slash in onnx_path" branch). */
    const int err = vmaf_dnn_verify_signature("nonexistent.onnx", NULL);
    /* Whatever cwd resolves "model/tiny/registry.json" to, it must not
     * exist for an absolute-no-slash test argument run from the meson
     * test harness. Accept any negative errno that means "not found". */
    mu_assert("no-slash onnx + missing default reg -> negative", err < 0);
    return NULL;
}

static char *test_verify_registry_no_slash_in_path(void)
{
    /* registry_path has no '/' — exercises the bundle_abs `else` branch
     * (lines 601-607) where we just memcpy the relative bundle path. We
     * expect -ENOENT because the bundle won't exist in cwd. Use chdir to
     * a known scratch dir for a deterministic outcome. */
    char dir[256];
    mu_assert("setup scratch dir", setup_scratch_dir(dir, sizeof(dir), "noslash") == 0);
    const char *body = "{\"models\":[{\"id\":\"r\",\"onnx\":\"r.onnx\",\"sha256\":\"00\","
                       "\"sigstore_bundle\":\"r.onnx.sigstore.json\"}]}";
    mu_assert("write registry", write_in_dir(dir, "reg_noslash.json", body) == 0);

    /* Save + restore cwd so the test is hermetic. */
    char cwd_save[512];
    mu_assert("getcwd", getcwd(cwd_save, sizeof(cwd_save)) != NULL);
    mu_assert("chdir into scratch", chdir(dir) == 0);

    /* registry_path is a basename only — no '/'. */
    const int err = vmaf_dnn_verify_signature("/tmp/r.onnx", "reg_noslash.json");

    /* `chdir` is declared `warn_unused_result`, which a `(void)` cast does not
     * silence under GCC. Restoring the cwd is also load-bearing: every
     * assertion below, and every later test in this binary, runs relative to
     * it. Check it. */
    const int restored = chdir(cwd_save);
    mu_assert("restore cwd", restored == 0);
    mu_assert("no-slash registry + missing bundle -> -ENOENT", err == -ENOENT);

    cleanup_in_dir(dir, "reg_noslash.json");
    (void)rmdir(dir);
    return NULL;
}

/* Build a fake `cosign` shell script under <dir>/cosign that writes its
 * arguments, one per line, to <dir>/argv.txt and exits `exit_code`. Used to
 * exercise the posix_spawnp + waitpid paths without requiring the real
 * Sigstore toolchain. Mode 0700 (owner read/write/exec; CodeQL-clean). */
static int write_fake_cosign(const char *dir, int exit_code)
{
    char path[512];
    const int n = snprintf(path, sizeof(path), "%s/cosign", dir);
    if (n < 0 || (size_t)n >= (int)sizeof(path))
        return -1;
    const int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR | S_IXUSR);
    if (fd < 0)
        return -1;
    FILE *f = fdopen(fd, "w");
    if (!f) {
        /* POSIX leaves the descriptor open when fdopen() fails, so closing it here is
         * required.  cppcheck's posix.cfg lists fdopen as a deallocator of the fd
         * unconditionally, so 2.13 — the version CI installs from apt — reads this as a
         * second free.  2.21 no longer does. */
        /* cppcheck-suppress doubleFree ; see the note above */
        (void)close(fd);
        return -1;
    }
    /* Minimal shebang stub: record argv for the identity checks, then exit. */
    if (fprintf(
            f,
            "#!/bin/sh\nprintf '%%s\\n' \"$@\" > '%s/argv.txt'\n"
            "for arg in \"$@\"; do case \"$arg\" in --bundle=*) p=${arg#--bundle=};; esac; done\n"
            "d=$(/usr/bin/dirname \"$p\")\n"
            "(/usr/bin/stat -c '%%a' \"$d\" 2>/dev/null || "
            "/usr/bin/stat -f '%%Lp' \"$d\") > '%s/mode.txt'\n"
            "/usr/bin/cmp -s \"$p\" '%s/k.onnx.sigstore.json' && printf same > '%s/bytes.txt'\n"
            "exit %d\n",
            dir, dir, dir, dir, exit_code) < 0) {
        (void)fclose(f);
        return -1;
    }
    if (fclose(f) != 0)
        return -1;
    return 0;
}

/* Scratch directory, registry, bundle, ONNX model and fake cosign setup. */
static char *setup_fake_cosign_fixture(char *dir, size_t dir_sz, int exit_code, const char *bundle)
{
    mu_assert("setup scratch dir",
              setup_scratch_dir(dir, dir_sz, exit_code == 0 ? "cosign_ok" : "cosign_fail") == 0);
    /* Registry + bundle + onnx all under <dir>. The bundle's signing
     * certificate is checked before cosign runs (ADR-2985); the fake cosign
     * ignores the file. */
    const char *reg_body = "{\"models\":[{\"id\":\"k\",\"onnx\":\"k.onnx\",\"sha256\":\"00\","
                           "\"sigstore_bundle\":\"k.onnx.sigstore.json\"}]}";
    mu_assert("write registry", write_in_dir(dir, "registry.json", reg_body) == 0);
    mu_assert("write bundle", write_in_dir(dir, "k.onnx.sigstore.json", bundle) == 0);
    mu_assert("write onnx", write_in_dir(dir, "k.onnx", "fake") == 0);
    mu_assert("write fake cosign", write_fake_cosign(dir, exit_code) == 0);
    return NULL;
}

static FILE *open_read_stream(const char *path)
{
    int fd = openat(AT_FDCWD, path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return NULL;
    FILE *stream = fdopen(fd, "rb");
    if (!stream && close(fd) != 0)
        return NULL;
    return stream;
}

/* Read <dir>/argv.txt, the arguments the fake cosign received, into @p out
 * (empty when cosign never ran). */
static void read_recorded_argv_with_buffers(const char *dir, char *out, size_t out_sz, char *path)
{
    out[0] = '\0';
    const int n = snprintf(path, TEST_BUFFER_512, "%s/argv.txt", dir);
    if (n < 0 || (size_t)n >= TEST_BUFFER_512)
        return;
    FILE *f = open_read_stream(path);
    if (!f)
        return;
    const size_t r = fread(out, 1u, out_sz - 1u, f);
    out[r] = '\0';
    if (fclose(f) != 0)
        out[0] = '\0';
}

static void read_recorded_argv(const char *dir, char *out, size_t out_sz)
{
    char *path = calloc(TEST_BUFFER_512, 1u);
    if (!path) {
        free(path);
        out[0] = '\0';
        return;
    }
    read_recorded_argv_with_buffers(dir, out, out_sz, path);
    free(path);
}

static char *assert_copy_path_removed(char *copy_path)
{
    struct stat st;
    mu_assert("copy removed", stat(copy_path, &st) != 0);
    char *slash = strrchr(copy_path, '/');
    mu_assert("directory path", slash != NULL);
    *slash = '\0';
    mu_assert("directory removed", stat(copy_path, &st) != 0);
    return NULL;
}

static char *check_private_copy_removed_with_buffers(const char *dir, char *argv_seen, char *path)
{
    read_recorded_argv(dir, argv_seen, TEST_BUFFER_4096);
    const char *arg = strstr(argv_seen, "--bundle=");
    mu_assert("bundle argument recorded", arg != NULL);
    // SAFETY: arg points to the matched "--bundle=" literal in argv_seen.
    const char *copy = arg + (sizeof("--bundle=") - 1u);
    const char *end = strchr(copy, '\n');
    mu_assert("bundle argument ends", end != NULL);
    // SAFETY: end was found by strchr starting at copy, so copy <= end in argv_seen.
    int n = snprintf(path, TEST_BUFFER_512, "%.*s", (int)(end - copy), copy);
    mu_assert("copy path fits", n > 0 && (size_t)n < TEST_BUFFER_512);
    mu_assert("different bundle path", strstr(path, "k.onnx.sigstore.json") == NULL);
    return assert_copy_path_removed(path);
}

static char *check_private_copy_removed(const char *dir)
{
    char *argv_seen = calloc(TEST_BUFFER_4096, 1u);
    char *path = calloc(TEST_BUFFER_512, 1u);
    if (!argv_seen || !path) {
        free(argv_seen);
        free(path);
        return "allocation failed";
    }
    char *result = check_private_copy_removed_with_buffers(dir, argv_seen, path);
    free(argv_seen);
    free(path);
    return result;
}

static char *assert_bytes_observed(const char *dir, char *mode_path)
{
    int bn = snprintf(mode_path, TEST_BUFFER_512, "%s/bytes.txt", dir);
    mu_assert("bytes path fits", bn > 0 && (size_t)bn < TEST_BUFFER_512);
    struct stat st;
    mu_assert("checked bytes passed to cosign", fstatat(AT_FDCWD, mode_path, &st, 0) == 0);
    return NULL;
}

static char *check_copy_observation_with_buffers(const char *dir, int must_run, char *observation,
                                                 char *mode_path)
{
    int mn = snprintf(mode_path, TEST_BUFFER_512, "%s/mode.txt", dir);
    mu_assert("mode path fits", mn > 0 && (size_t)mn < TEST_BUFFER_512);
    FILE *mode_file = open_read_stream(mode_path);
    if (must_run)
        mu_assert("private directory observed", mode_file != NULL);
    if (mode_file) {
        const int got_line = fgets(observation, TEST_BUFFER_512, mode_file) != NULL;
        const int close_rc = fclose(mode_file);
        char *copy_msg = check_private_copy_removed(dir);
        if (copy_msg)
            return copy_msg;
        mu_assert("mode recorded", got_line);
        mu_assert("close mode", close_rc == 0);
        mu_assert("private directory mode", strcmp(observation, "700\n") == 0);
        return assert_bytes_observed(dir, mode_path);
    }
    return NULL;
}

static char *check_copy_observation(const char *dir, int must_run)
{
    char *observation = calloc(TEST_BUFFER_512, 1u);
    char *mode_path = calloc(TEST_BUFFER_512, 1u);
    if (!observation || !mode_path) {
        free(observation);
        free(mode_path);
        return "allocation failed";
    }
    char *result = check_copy_observation_with_buffers(dir, must_run, observation, mode_path);
    free(observation);
    free(mode_path);
    return result;
}

static int cleanup_fake_cosign_fixture(const char *dir)
{
    cleanup_in_dir(dir, "registry.json");
    cleanup_in_dir(dir, "k.onnx.sigstore.json");
    cleanup_in_dir(dir, "k.onnx");
    cleanup_in_dir(dir, "cosign");
    cleanup_in_dir(dir, "argv.txt");
    cleanup_in_dir(dir, "mode.txt");
    cleanup_in_dir(dir, "bytes.txt");
    return rmdir(dir);
}

static int save_env(const char *name, char **saved)
{
    const char *value = vmaf_getenv_portable(name);
    *saved = value ? VMAF_STRDUP(value) : NULL;
    return value && !*saved ? -ENOMEM : 0;
}

static int restore_env(const char *name, char *saved)
{
    const int rc = saved ? setenv(name, saved, 1) : unsetenv(name);
    free(saved);
    return rc;
}

static char *verify_with_fake_cosign(const char *dir, int *status)
{
    char onnx_path[512];
    const int n = snprintf(onnx_path, sizeof(onnx_path), "%s/k.onnx", dir);
    if (n <= 0 || (size_t)n >= sizeof(onnx_path))
        return "snprintf onnx_path";
    char reg_path[512];
    const int rn = snprintf(reg_path, sizeof(reg_path), "%s/registry.json", dir);
    if (rn <= 0 || (size_t)rn >= sizeof(reg_path))
        return "snprintf reg_path";

    /* Override PATH so locate_cosign() finds the stub. */
    char *path_save = NULL;
    if (save_env("PATH", &path_save) != 0)
        return "save PATH";
    if (setenv("PATH", dir, 1) != 0) {
        free(path_save);
        return "setenv PATH override";
    }
    *status = vmaf_dnn_verify_signature(onnx_path, reg_path);
    const int restored = restore_env("PATH", path_save);
    mu_assert("restore PATH", restored == 0);
    return NULL;
}

static char *run_with_fake_cosign_current_tmpdir(const char *bundle, int exit_code,
                                                 int expected_err, char *argv_out, size_t argv_sz)
{
    char dir[256];
    char *msg = setup_fake_cosign_fixture(dir, sizeof(dir), exit_code, bundle);
    if (msg)
        return msg;

    int err = 0;
    msg = verify_with_fake_cosign(dir, &err);
    if (!msg) {
        if (argv_out)
            read_recorded_argv(dir, argv_out, argv_sz);
        msg = check_copy_observation(dir, expected_err == 0 || exit_code != 0);
    }
    const int removed = cleanup_fake_cosign_fixture(dir);
    if (msg)
        return msg;
    mu_assert("remove fake cosign fixture", removed == 0);
    mu_assert("verify_signature returned expected status", err == expected_err);
    return NULL;
}

static char *run_with_fake_cosign(const char *bundle, int exit_code, int expected_err,
                                  char *argv_out, size_t argv_sz)
{
    char *tmpdir_save = NULL;
    mu_assert("save TMPDIR", save_env("TMPDIR", &tmpdir_save) == 0);
    /* Use the fixture's parent, which is also the loader's default. */
    if (setenv("TMPDIR", "/tmp", 1) != 0) {
        free(tmpdir_save);
        return "set TMPDIR";
    }
    char *msg =
        run_with_fake_cosign_current_tmpdir(bundle, exit_code, expected_err, argv_out, argv_sz);
    const int restored = restore_env("TMPDIR", tmpdir_save);
    mu_assert("restore TMPDIR", restored == 0);
    return msg;
}

static char *test_verify_copy_uses_private_directory(void)
{
    return run_with_fake_cosign(k_bundle_tag, 0, 0, NULL, 0u);
}

static char *test_verify_cosign_success(void)
{
    /* Fake cosign exits 0 -> verify_signature() returns 0. Exercises
     * locate_cosign() success (lines 513-534), posix_spawnp() success
     * (line 648), waitpid() (line 653), and the WIFEXITED+0 success
     * tail (lines 657-659). */
    return run_with_fake_cosign(k_bundle_tag, 0, 0, NULL, 0u);
}

static char *test_verify_cosign_nonzero_exit(void)
{
    /* Fake cosign exits 1 -> verify_signature() returns -EPROTO.
     * Exercises the same locate/spawn/wait path plus the failure tail
     * at line 657. */
    return run_with_fake_cosign(k_bundle_tag, 1, -EPROTO, NULL, 0u);
}

/* ADR-2985: the bundle's certificate must carry the vidiko owner ID and name
 * its supply-chain workflow exactly. A cosign that accepts everything (the
 * stub exits 0) must not make these pass. */
static char *test_verify_wrong_owner_rejected(void)
{
    return run_with_fake_cosign(k_bundle_wrong_owner, 0, -EPROTO, NULL, 0u);
}

/* The owner ID of the account that held the repository before the move. */
static char *test_verify_previous_owner_rejected(void)
{
    return run_with_fake_cosign(k_bundle_previous_owner, 0, -EPROTO, NULL, 0u);
}

static char *test_verify_prefix_identity_rejected(void)
{
    return run_with_fake_cosign(k_bundle_prefix, 0, -EPROTO, NULL, 0u);
}

static char *test_verify_suffix_identity_rejected(void)
{
    return run_with_fake_cosign(k_bundle_suffix, 0, -EPROTO, NULL, 0u);
}

/* cosign gets the anchored identity regexp and a private copy of the bundle
 * that was checked, which is gone once verification returns. */
static char *test_verify_cosign_gets_anchored_identity_with_buffers(char *argv_seen,
                                                                    char *copy_path)
{
    char *msg = run_with_fake_cosign(k_bundle_tag, 0, 0, argv_seen, TEST_BUFFER_4096);
    if (msg)
        return msg;
    mu_assert("anchored identity regexp",
              strstr(argv_seen, "\n^https://github\\.com/vidiko/vmafx/\\.github/workflows/"
                                "supply-chain\\.yml@refs/(heads/master|tags/"
                                "v[0-9][0-9A-Za-z.+-]*)$\n") != NULL);
    const char *bundle_arg = strstr(argv_seen, "--bundle=");
    mu_assert("cosign got --bundle", bundle_arg != NULL);
    // SAFETY: bundle_arg points to the matched "--bundle=" literal in argv_seen.
    const char *copy = bundle_arg + (sizeof("--bundle=") - 1u);
    const char *eol = strchr(copy, '\n');
    mu_assert("bundle argument ends", eol != NULL);
    // SAFETY: eol was found by strchr starting at copy, so copy <= eol in argv_seen.
    const int n = snprintf(copy_path, TEST_BUFFER_512, "%.*s", (int)(eol - copy), copy);
    mu_assert("snprintf copy path", n > 0 && (size_t)n < TEST_BUFFER_512);
    mu_assert("private copy, not the registry's bundle", strstr(copy_path, "vmafx-bundle-"));
    return assert_copy_path_removed(copy_path);
}

static char *test_verify_cosign_gets_anchored_identity(void)
{
    char *argv_seen = calloc(TEST_BUFFER_4096, 1u);
    char *copy_path = calloc(TEST_BUFFER_512, 1u);
    if (!argv_seen || !copy_path) {
        free(argv_seen);
        free(copy_path);
        return "allocation failed";
    }
    char *result = test_verify_cosign_gets_anchored_identity_with_buffers(argv_seen, copy_path);
    free(argv_seen);
    free(copy_path);
    return result;
}

static char *check_invalid_tmpdir_with_buffers(const char *value, int expected_err, char *saved,
                                               char *argv_seen)
{
    const char *old = vmaf_getenv_portable("TMPDIR");
    int had_old = old != NULL;
    int n = snprintf(saved, TEST_BUFFER_4096, "%s", old ? old : "");
    mu_assert("save TMPDIR", n >= 0 && (size_t)n < TEST_BUFFER_4096);
    mu_assert("set TMPDIR", setenv("TMPDIR", value, 1) == 0);
    char *msg = run_with_fake_cosign_current_tmpdir(k_bundle_tag, 0, expected_err, argv_seen,
                                                    TEST_BUFFER_4096);
    int restored = had_old ? setenv("TMPDIR", saved, 1) : unsetenv("TMPDIR");
    mu_assert("restore TMPDIR", restored == 0);
    if (msg)
        return msg;
    mu_assert("cosign not called", argv_seen[0] == '\0');
    return NULL;
}

static char *check_invalid_tmpdir(const char *value, int expected_err)
{
    char *saved = calloc(TEST_BUFFER_4096, 1u);
    char *argv_seen = calloc(TEST_BUFFER_4096, 1u);
    if (!saved || !argv_seen) {
        free(saved);
        free(argv_seen);
        return "allocation failed";
    }
    char *result = check_invalid_tmpdir_with_buffers(value, expected_err, saved, argv_seen);
    free(saved);
    free(argv_seen);
    return result;
}

static char *test_tmpdir_requires_absolute_path(void)
{
    return check_invalid_tmpdir(".", -EINVAL);
}

static char *test_tmpdir_requires_directory(void)
{
    return check_invalid_tmpdir("/dev/null", -EINVAL);
}

static int set_directory_mode(const char *dir, mode_t mode)
{
    int fd = openat(AT_FDCWD, dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    int result = fchmod(fd, mode);
    if (close(fd) != 0)
        return -1;
    return result;
}

static char *test_tmpdir_rejects_unprotected_shared_directory_with_buffer(char *dir)
{
    mu_assert("create temporary directory", setup_scratch_dir(dir, TEST_BUFFER_256, "shared") == 0);
    mu_assert("make shared", set_directory_mode(dir, 0777) == 0);
    char *msg = check_invalid_tmpdir(dir, -EACCES);
    int chmod_rc = set_directory_mode(dir, S_IRWXU);
    int remove_rc = rmdir(dir);
    mu_assert("restore permissions", chmod_rc == 0);
    mu_assert("remove test directory", remove_rc == 0);
    return msg;
}

static char *test_tmpdir_rejects_unprotected_shared_directory(void)
{
    char *dir = calloc(TEST_BUFFER_256, 1u);
    if (!dir)
        return "allocation failed";
    char *result = test_tmpdir_rejects_unprotected_shared_directory_with_buffer(dir);
    free(dir);
    return result;
}

static char *test_tmpdir_requires_writable_directory_with_buffer(char *dir)
{
    if (geteuid() == 0)
        return NULL;
    mu_assert("create temporary directory",
              setup_scratch_dir(dir, TEST_BUFFER_256, "unwritable") == 0);
    mu_assert("remove write permission", set_directory_mode(dir, S_IRUSR | S_IXUSR) == 0);
    char *msg = check_invalid_tmpdir(dir, -EACCES);
    int chmod_rc = set_directory_mode(dir, S_IRWXU);
    int remove_rc = rmdir(dir);
    mu_assert("restore permissions", chmod_rc == 0);
    mu_assert("remove test directory", remove_rc == 0);
    return msg;
}

static char *test_tmpdir_requires_writable_directory(void)
{
    if (geteuid() == 0)
        return NULL;
    char *dir = calloc(TEST_BUFFER_256, 1u);
    if (!dir)
        return "allocation failed";
    char *result = test_tmpdir_requires_writable_directory_with_buffer(dir);
    free(dir);
    return result;
}

static char *check_valid_tmpdir_with_buffer(const char *value, char *saved)
{
    const char *old = vmaf_getenv_portable("TMPDIR");
    const int had_old = old != NULL;
    const int n = snprintf(saved, TEST_BUFFER_4096, "%s", old ? old : "");
    mu_assert("save TMPDIR", n >= 0 && (size_t)n < TEST_BUFFER_4096);
    mu_assert("set TMPDIR", setenv("TMPDIR", value, 1) == 0);
    char *msg = run_with_fake_cosign_current_tmpdir(k_bundle_tag, 0, 0, NULL, 0u);
    const int restored = had_old ? setenv("TMPDIR", saved, 1) : unsetenv("TMPDIR");
    mu_assert("restore TMPDIR", restored == 0);
    return msg;
}

static char *check_valid_tmpdir(const char *value)
{
    char *saved = calloc(TEST_BUFFER_4096, 1u);
    if (!saved)
        return "allocation failed";
    char *result = check_valid_tmpdir_with_buffer(value, saved);
    free(saved);
    return result;
}

static char *test_tmpdir_accepts_sticky_shared_tmp(void)
{
    return check_valid_tmpdir("/tmp");
}

static char *test_tmpdir_accepts_private_under_0755_with_buffers(char *parent, char *child)
{
    mu_assert("create parent directory",
              setup_scratch_dir(parent, TEST_BUFFER_256, "parent0755") == 0);
    const mode_t mode_0755 =
        (mode_t)S_IRWXU | (mode_t)S_IRGRP | (mode_t)S_IXGRP | (mode_t)S_IROTH | (mode_t)S_IXOTH;
    mu_assert("set parent 0755", set_directory_mode(parent, mode_0755) == 0);
    const int cn = snprintf(child, TEST_BUFFER_512, "%s/private", parent);
    mu_assert("child path fits", cn > 0 && (size_t)cn < TEST_BUFFER_512);
    (void)mkdir(child, S_IRWXU);
    mu_assert("set child 0700", set_directory_mode(child, S_IRWXU) == 0);
    char *msg = check_valid_tmpdir(child);
    const int rm_child = rmdir(child);
    const int rm_parent = rmdir(parent);
    mu_assert("remove child directory", rm_child == 0);
    mu_assert("remove parent directory", rm_parent == 0);
    return msg;
}

static char *test_tmpdir_accepts_private_dir_under_0755_parent(void)
{
    char *parent = calloc(TEST_BUFFER_256, 1u);
    char *child = calloc(TEST_BUFFER_512, 1u);
    if (!parent || !child) {
        free(parent);
        free(child);
        return "allocation failed";
    }
    char *result = test_tmpdir_accepts_private_under_0755_with_buffers(parent, child);
    free(parent);
    free(child);
    return result;
}

static char *test_tmpdir_rejects_unprotected_shared_ancestor_with_buffers(char *parent, char *child)
{
    mu_assert("create parent directory",
              setup_scratch_dir(parent, TEST_BUFFER_256, "parent0777") == 0);
    const int cn = snprintf(child, TEST_BUFFER_512, "%s/private", parent);
    mu_assert("child path fits", cn > 0 && (size_t)cn < TEST_BUFFER_512);
    (void)mkdir(child, S_IRWXU);
    mu_assert("set child 0700", set_directory_mode(child, S_IRWXU) == 0);
    mu_assert("make parent 0777 without sticky", set_directory_mode(parent, 0777) == 0);
    char *msg = check_invalid_tmpdir(child, -EACCES);
    const int chmod_rc = set_directory_mode(parent, S_IRWXU);
    const int rm_child = rmdir(child);
    const int rm_parent = rmdir(parent);
    mu_assert("restore parent permissions", chmod_rc == 0);
    mu_assert("remove child directory", rm_child == 0);
    mu_assert("remove parent directory", rm_parent == 0);
    return msg;
}

static char *test_tmpdir_rejects_unprotected_shared_ancestor(void)
{
    char *parent = calloc(TEST_BUFFER_256, 1u);
    char *child = calloc(TEST_BUFFER_512, 1u);
    if (!parent || !child) {
        free(parent);
        free(child);
        return "allocation failed";
    }
    char *result = test_tmpdir_rejects_unprotected_shared_ancestor_with_buffers(parent, child);
    free(parent);
    free(child);
    return result;
}

static char *test_tmpdir_mode_rule(void)
{
    enum { me = 1000, other = 1001 };
    static const struct {
        uid_t owner;
        mode_t mode;
        uid_t euid;
        int private_only;
        int expected;
        char *message;
    } cases[] = {
        {0, 01777, me, 0, 0, "root sticky shared ok"},
        {me, 0755, me, 0, 0, "own 0755 ok"},
        {0, 0755, 0, 0, 0, "root euid ok"},
        {other, 0755, me, 0, -EACCES, "other owner refused"},
        {other, 01777, me, 0, -EACCES, "other owner sticky refused"},
        {0, 0777, me, 0, -EACCES, "root 0777 without sticky refused"},
        {me, 0770, me, 0, -EACCES, "own 0770 refused"},
        {me, 0700, me, 1, 0, "private 0700 ok"},
        {me, 0740, me, 1, -EACCES, "private group read refused"},
        {0, 0700, me, 1, -EACCES, "private root owner refused"},
    };
    for (size_t i = 0; i < MU_TABLE_LEN(cases); i++) {
        const int result = vmaf_dnn_temp_dir_mode_ok(cases[i].owner, cases[i].mode, cases[i].euid,
                                                     cases[i].private_only);
        mu_assert(cases[i].message, result == cases[i].expected);
    }
    return NULL;
}

struct symlink_tmpdir_paths {
    const char *parent;
    const char *child;
    const char *home;
    const char *link;
};

static char *setup_symlink_tmpdir(char *parent, char *child, char *home, char *link,
                                  struct symlink_tmpdir_paths *created)
{
    if (setup_scratch_dir(parent, TEST_BUFFER_256, "linkparent") != 0)
        return "create parent directory";
    created->parent = parent;
    int n = snprintf(child, TEST_BUFFER_512, "%s/private", parent);
    mu_assert("child path fits", n > 0 && (size_t)n < TEST_BUFFER_512);
    if (mkdir(child, S_IRWXU) != 0 && errno != EEXIST)
        return "create child directory";
    created->child = child;
    mu_assert("set child 0700", set_directory_mode(child, S_IRWXU) == 0);
    if (setup_scratch_dir(home, TEST_BUFFER_256, "linkhome") != 0)
        return "create link directory";
    created->home = home;
    n = snprintf(link, TEST_BUFFER_512, "%s/tmpdir", home);
    mu_assert("link path fits", n > 0 && (size_t)n < TEST_BUFFER_512);
    if (unlink(link) != 0 && errno != ENOENT)
        return "remove stale symlink";
    if (symlink(child, link) != 0)
        return "create symlink";
    created->link = link;
    mu_assert("make parent 0777 without sticky", set_directory_mode(parent, 0777) == 0);
    return NULL;
}

static char *cleanup_symlink_tmpdir(const struct symlink_tmpdir_paths *created)
{
    const int chmod_rc = created->parent ? set_directory_mode(created->parent, S_IRWXU) : 0;
    const int rm_link = created->link ? unlink(created->link) : 0;
    const int rm_home = created->home ? rmdir(created->home) : 0;
    const int rm_child = created->child ? rmdir(created->child) : 0;
    const int rm_parent = created->parent ? rmdir(created->parent) : 0;
    mu_assert("restore parent permissions", chmod_rc == 0);
    mu_assert("remove symlink", rm_link == 0);
    mu_assert("remove link directory", rm_home == 0);
    mu_assert("remove child directory", rm_child == 0);
    mu_assert("remove parent directory", rm_parent == 0);
    return NULL;
}

static char *test_tmpdir_rejects_symlink_into_shared_with_buffers(char *parent, char *child,
                                                                  char *home, char *link)
{
    struct symlink_tmpdir_paths created = {0};
    char *setup_msg = setup_symlink_tmpdir(parent, child, home, link, &created);
    char *msg = setup_msg ? NULL : check_invalid_tmpdir(link, -EACCES);
    char *cleanup_msg = cleanup_symlink_tmpdir(&created);
    if (setup_msg)
        return setup_msg;
    return cleanup_msg ? cleanup_msg : msg;
}

/* TMPDIR is a symlink, inside a private 0700 scratch directory, to a 0700
 * directory whose parent is 0777 without the sticky bit: the lexical path
 * passes, the resolved one must not (CodeRabbit 4658621520). */
static char *test_tmpdir_rejects_symlink_into_shared_parent(void)
{
    char *parent = calloc(TEST_BUFFER_256, 1u);
    char *child = calloc(TEST_BUFFER_512, 1u);
    char *home = calloc(TEST_BUFFER_256, 1u);
    char *link = calloc(TEST_BUFFER_512, 1u);
    char *result = "allocation failed";
    if (parent && child && home && link)
        result = test_tmpdir_rejects_symlink_into_shared_with_buffers(parent, child, home, link);
    free(parent);
    free(child);
    free(home);
    free(link);
    return result;
}

static char *test_tmpdir_rejects_other_owner_with_buffer(char *dir)
{
    mu_assert("create temporary directory",
              setup_scratch_dir(dir, TEST_BUFFER_256, "otherowner") == 0);
    const int dfd = openat(AT_FDCWD, dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    mu_assert("open temporary directory", dfd >= 0);
    const int chown_rc = fchown(dfd, (uid_t)65534, (gid_t)-1);
    const int close_rc = close(dfd);
    mu_assert("hand directory to another user", chown_rc == 0 && close_rc == 0);
    char *msg = check_invalid_tmpdir(dir, -EACCES);
    const int remove_rc = rmdir(dir);
    mu_assert("remove test directory", remove_rc == 0);
    return msg;
}

/* A 0700 TMPDIR owned by another user is refused (CodeRabbit 4658621513).
 * Only root can hand a directory to another user, so other users skip it;
 * test_tmpdir_mode_rule covers the rule for them. */
static char *test_tmpdir_rejects_other_owner(void)
{
    if (geteuid() != 0)
        return NULL;
    char *dir = calloc(TEST_BUFFER_256, 1u);
    if (!dir)
        return "allocation failed";
    char *result = test_tmpdir_rejects_other_owner_with_buffer(dir);
    free(dir);
    return result;
}

/* Scratch-dir + registry + bundle + onnx setup shared by
 * test_verify_cosign_not_on_path. Extracted for the branch-budget reason
 * noted on setup_fake_cosign_fixture above. */
static char *setup_cosign_not_on_path_fixture(char *dir, size_t dir_sz)
{
    mu_assert("setup scratch dir", setup_scratch_dir(dir, dir_sz, "nopath") == 0);
    const char *reg_body = "{\"models\":[{\"id\":\"q\",\"onnx\":\"q.onnx\",\"sha256\":\"00\","
                           "\"sigstore_bundle\":\"q.onnx.sigstore.json\"}]}";
    mu_assert("write registry", write_in_dir(dir, "registry.json", reg_body) == 0);
    mu_assert("write bundle", write_in_dir(dir, "q.onnx.sigstore.json", "{}") == 0);
    mu_assert("write onnx", write_in_dir(dir, "q.onnx", "fake") == 0);
    return NULL;
}

static char *test_verify_cosign_not_on_path(void)
{
    /* PATH set to an empty directory with no `cosign` binary. The
     * locate_cosign() walk completes without finding a match and
     * returns -EACCES, which propagates through verify_signature().
     * Exercises the locate_cosign() failure tail (line 534). */
    char dir[256];
    char *setup_msg = setup_cosign_not_on_path_fixture(dir, sizeof(dir));
    if (setup_msg)
        return setup_msg;

    char path_save[2048];
    const char *path_env = getenv("PATH");
    const int pn = snprintf(path_save, sizeof(path_save), "%s", path_env ? path_env : "");
    mu_assert("snprintf PATH save", pn >= 0 && (size_t)pn < sizeof(path_save));
    /* Point PATH at a directory we control that does NOT contain
     * cosign. (Using "" would tickle the empty-string short-circuit
     * at the top of locate_cosign — we want the full PATH walk to
     * exit without a hit.) */
    mu_assert("setenv PATH override", setenv("PATH", dir, 1) == 0);

    char onnx_path[512];
    const int n = snprintf(onnx_path, sizeof(onnx_path), "%s/q.onnx", dir);
    mu_assert("snprintf onnx_path", n > 0 && (size_t)n < (int)sizeof(onnx_path));
    char reg_path[512];
    const int rn = snprintf(reg_path, sizeof(reg_path), "%s/registry.json", dir);
    mu_assert("snprintf reg_path", rn > 0 && (size_t)rn < (int)sizeof(reg_path));

    const int err = vmaf_dnn_verify_signature(onnx_path, reg_path);

    (void)setenv("PATH", path_save, 1);
    cleanup_in_dir(dir, "registry.json");
    cleanup_in_dir(dir, "q.onnx.sigstore.json");
    cleanup_in_dir(dir, "q.onnx");
    (void)rmdir(dir);

    mu_assert("cosign not on PATH -> -EACCES", err == -EACCES);
    return NULL;
}

/* Scratch-dir + registry + bundle + onnx setup shared by
 * test_verify_cosign_path_empty_string. Extracted for the branch-budget
 * reason noted on setup_fake_cosign_fixture above. */
static char *setup_cosign_empty_path_fixture(char *dir, size_t dir_sz)
{
    mu_assert("setup scratch dir", setup_scratch_dir(dir, dir_sz, "emptypath") == 0);
    const char *reg_body = "{\"models\":[{\"id\":\"e\",\"onnx\":\"e.onnx\",\"sha256\":\"00\","
                           "\"sigstore_bundle\":\"e.onnx.sigstore.json\"}]}";
    mu_assert("write registry", write_in_dir(dir, "registry.json", reg_body) == 0);
    mu_assert("write bundle", write_in_dir(dir, "e.onnx.sigstore.json", "{}") == 0);
    mu_assert("write onnx", write_in_dir(dir, "e.onnx", "fake") == 0);
    return NULL;
}

static char *test_verify_cosign_path_empty_string(void)
{
    /* Empty PATH string short-circuits locate_cosign() at line 517 with
     * -EACCES before any directory walk. Distinct branch from the
     * "PATH set but cosign not present" case above. */
    char dir[256];
    char *setup_msg = setup_cosign_empty_path_fixture(dir, sizeof(dir));
    if (setup_msg)
        return setup_msg;

    char path_save[2048];
    const char *path_env = getenv("PATH");
    const int pn = snprintf(path_save, sizeof(path_save), "%s", path_env ? path_env : "");
    mu_assert("snprintf PATH save", pn >= 0 && (size_t)pn < sizeof(path_save));
    mu_assert("setenv PATH=''", setenv("PATH", "", 1) == 0);

    char onnx_path[512];
    const int n = snprintf(onnx_path, sizeof(onnx_path), "%s/e.onnx", dir);
    mu_assert("snprintf onnx_path", n > 0 && (size_t)n < (int)sizeof(onnx_path));
    char reg_path[512];
    const int rn = snprintf(reg_path, sizeof(reg_path), "%s/registry.json", dir);
    mu_assert("snprintf reg_path", rn > 0 && (size_t)rn < (int)sizeof(reg_path));

    const int err = vmaf_dnn_verify_signature(onnx_path, reg_path);

    (void)setenv("PATH", path_save, 1);
    cleanup_in_dir(dir, "registry.json");
    cleanup_in_dir(dir, "e.onnx.sigstore.json");
    cleanup_in_dir(dir, "e.onnx");
    (void)rmdir(dir);

    mu_assert("empty PATH -> -EACCES", err == -EACCES);
    return NULL;
}

static char *run_with_registry_body(const char *body, const char *onnx_path, int expected_err,
                                    const char *suffix)
{
    char reg_path[256];
    const int wrc = write_tmp(suffix, body, reg_path, sizeof(reg_path));
    mu_assert("write_tmp succeeded", wrc == 0);
    const int err = vmaf_dnn_verify_signature(onnx_path, reg_path);
    (void)unlink(reg_path);
    mu_assert("verify_signature returned expected status", err == expected_err);
    return NULL;
}

static char *test_verify_malformed_onnx_no_colon(void)
{
    /* `"onnx"` key with no ':' after it -> -ENOENT (line 402). */
    const char *body = "{\"onnx\" \"x.onnx\"}";
    return run_with_registry_body(body, "/tmp/x.onnx", -ENOENT, "mal_nocolon.json");
}

static char *test_verify_malformed_onnx_no_open_quote(void)
{
    /* `"onnx":` followed by a non-quoted token -> -EBADMSG (line 407). */
    const char *body = "{\"onnx\": x.onnx}";
    return run_with_registry_body(body, "/tmp/x.onnx", -EBADMSG, "mal_noopen.json");
}

static char *test_verify_malformed_onnx_no_close_quote(void)
{
    /* `"onnx": "value` with no closing quote -> -EBADMSG (line 411). */
    const char *body = "{\"onnx\": \"x.onnx";
    return run_with_registry_body(body, "/tmp/x.onnx", -EBADMSG, "mal_noclose.json");
}

static char *test_verify_malformed_bundle_no_colon(void)
{
    /* Matching entry but `"sigstore_bundle"` key has no ':' -> -EBADMSG
     * (line 424). Construct the value string carefully so that the
     * malformed-key fragment occurs *before* the next entry. */
    const char *body = "{\"models\":[{\"id\":\"x\",\"onnx\":\"m.onnx\",\"sigstore_bundle\""
                       " \"m.bundle\"}]}";
    return run_with_registry_body(body, "/tmp/m.onnx", -EBADMSG, "mal_bcolon.json");
}

static char *test_verify_malformed_bundle_no_open_quote(void)
{
    /* `"sigstore_bundle":` followed by a non-quoted token -> -EBADMSG
     * (line 429). */
    const char *body = "{\"models\":[{\"id\":\"x\",\"onnx\":\"m.onnx\",\"sigstore_bundle\":"
                       " m.bundle}]}";
    return run_with_registry_body(body, "/tmp/m.onnx", -EBADMSG, "mal_bopen.json");
}

static char *test_verify_malformed_bundle_no_close_quote(void)
{
    /* `"sigstore_bundle": "value` with no closing quote -> -EBADMSG
     * (line 433). The terminator file body is intentionally truncated. */
    const char *body = "{\"models\":[{\"id\":\"x\",\"onnx\":\"m.onnx\",\"sigstore_bundle\":"
                       " \"m.bundle";
    return run_with_registry_body(body, "/tmp/m.onnx", -EBADMSG, "mal_bclose.json");
}

static char *test_verify_bundle_is_directory(void)
{
    /* Bundle path resolves to a directory (not a regular file). Exercises
     * the !S_ISREG branch (line 616) — distinct from the stat-fails
     * branch already covered by test_verify_missing_bundle. */
    char dir[256];
    mu_assert("setup scratch dir", setup_scratch_dir(dir, sizeof(dir), "bundle_isdir") == 0);
    const char *reg_body = "{\"models\":[{\"id\":\"d\",\"onnx\":\"d.onnx\",\"sha256\":\"00\","
                           "\"sigstore_bundle\":\"bundle_dir\"}]}";
    mu_assert("write registry", write_in_dir(dir, "registry.json", reg_body) == 0);
    /* Make `bundle_dir` an actual directory inside <dir>. */
    char bundle_path[512];
    const int bn = snprintf(bundle_path, sizeof(bundle_path), "%s/bundle_dir", dir);
    mu_assert("snprintf bundle_path", bn > 0 && (size_t)bn < (int)sizeof(bundle_path));
    mu_assert("mkdir bundle_dir", mkdir(bundle_path, S_IRWXU) == 0);

    char reg_path[512];
    const int rn = snprintf(reg_path, sizeof(reg_path), "%s/registry.json", dir);
    mu_assert("snprintf reg_path", rn > 0 && (size_t)rn < (int)sizeof(reg_path));

    const int err = vmaf_dnn_verify_signature("/tmp/d.onnx", reg_path);
    mu_assert("bundle is directory -> -ENOENT", err == -ENOENT);

    (void)rmdir(bundle_path);
    cleanup_in_dir(dir, "registry.json");
    (void)rmdir(dir);
    return NULL;
}

static char *test_verify_bundle_rejects_parent_traversal_with_buffers(char *parent, char *sub,
                                                                      char *reg_path)
{
    mu_assert("setup parent dir", setup_scratch_dir(parent, TEST_BUFFER_256, "traverse") == 0);
    mu_assert("write outside bundle", write_in_dir(parent, "x.sigstore.json", k_bundle_tag) == 0);
    const int sn = snprintf(sub, TEST_BUFFER_512, "%s/sub", parent);
    mu_assert("sub path fits", sn > 0 && (size_t)sn < TEST_BUFFER_512);
    (void)mkdir(sub, S_IRWXU);
    mu_assert("chmod sub", set_directory_mode(sub, S_IRWXU) == 0);
    const char *body = "{\"models\":[{\"id\":\"m\",\"onnx\":\"m.onnx\",\"sha256\":\"00\","
                       "\"sigstore_bundle\":\"../x.sigstore.json\"}]}";
    mu_assert("write sub registry", write_in_dir(sub, "registry.json", body) == 0);
    const int rn = snprintf(reg_path, TEST_BUFFER_512, "%s/registry.json", sub);
    mu_assert("reg path fits", rn > 0 && (size_t)rn < TEST_BUFFER_512);
    const int err = vmaf_dnn_verify_signature("/tmp/m.onnx", reg_path);
    cleanup_in_dir(sub, "registry.json");
    (void)rmdir(sub);
    cleanup_in_dir(parent, "x.sigstore.json");
    (void)rmdir(parent);
    mu_assert("parent traversal bundle path -> -EINVAL", err == -EINVAL);
    return NULL;
}

static char *test_verify_bundle_rejects_parent_traversal(void)
{
    char *parent = calloc(TEST_BUFFER_256, 1u);
    char *sub = calloc(TEST_BUFFER_512, 1u);
    char *reg_path = calloc(TEST_BUFFER_512, 1u);
    if (!parent || !sub || !reg_path) {
        free(parent);
        free(sub);
        free(reg_path);
        return "allocation failed";
    }
    char *result = test_verify_bundle_rejects_parent_traversal_with_buffers(parent, sub, reg_path);
    free(parent);
    free(sub);
    free(reg_path);
    return result;
}

static char *test_verify_bundle_rejects_absolute_path(void)
{
    const char *body = "{\"models\":[{\"id\":\"m\",\"onnx\":\"m.onnx\",\"sha256\":\"00\","
                       "\"sigstore_bundle\":\"/tmp/m.onnx.sigstore.json\"}]}";
    return run_with_registry_body(body, "/tmp/m.onnx", -EINVAL, "abs_bundle.json");
}

static char *test_verify_bundle_path_at_length_limit_with_buffers(char *rel, char *body)
{
    /* "/tmp" is 4 bytes; with '/' (1 byte) and NUL (1 byte), a relative path of
     * TEST_BUFFER_4096 - 5 bytes (4091) makes dlen + 1 + blen + 1 == 4097 > PATH_MAX. */
    const size_t rel_len = TEST_BUFFER_4096 - 5u;
    for (size_t i = 0u; i < rel_len; i++)
        rel[i] = (i % 64u == 63u) ? '/' : 'a';
    rel[rel_len] = '\0';
    const int n = snprintf(body, (size_t)TEST_BUFFER_4096 * 2u,
                           "{\"models\":[{\"id\":\"m\",\"onnx\":\"m.onnx\",\"sha256\":\"00\","
                           "\"sigstore_bundle\":\"%s\"}]}",
                           rel);
    mu_assert("registry body fits", n > 0 && (size_t)n < (size_t)TEST_BUFFER_4096 * 2u);
    return run_with_registry_body(body, "/tmp/m.onnx", -ENAMETOOLONG, "long_bundle.json");
}

static char *test_verify_bundle_path_at_length_limit(void)
{
    char *rel = calloc(TEST_BUFFER_4096, 1u);
    char *body = calloc((size_t)TEST_BUFFER_4096 * 2u, 1u);
    if (!rel || !body) {
        free(rel);
        free(body);
        return "allocation failed";
    }
    char *result = test_verify_bundle_path_at_length_limit_with_buffers(rel, body);
    free(rel);
    free(body);
    return result;
}
#endif /* !_WIN32 */

#ifdef _WIN32
static char *test_verify_windows_returns_enosys(void)
{
    const int err = vmaf_dnn_verify_signature("C:\\fake.onnx", NULL);
    mu_assert("Windows path -> -ENOSYS", err == -ENOSYS);
    return NULL;
}
#endif

static const MuTest common_tests[] = {
    MU_TEST(test_verify_null_path),
};

#ifndef _WIN32
static const MuTest platform_tests[] = {
    MU_TEST(test_verify_missing_registry),
    MU_TEST(test_verify_no_matching_entry),
    MU_TEST(test_verify_missing_bundle),
    MU_TEST(test_verify_entry_without_bundle),
    MU_TEST(test_verify_default_registry_missing),
    MU_TEST(test_verify_default_registry_no_slash_in_onnx),
    MU_TEST(test_verify_registry_no_slash_in_path),
    MU_TEST(test_verify_bundle_is_directory),
    MU_TEST(test_verify_malformed_onnx_no_colon),
    MU_TEST(test_verify_malformed_onnx_no_open_quote),
    MU_TEST(test_verify_malformed_onnx_no_close_quote),
    MU_TEST(test_verify_malformed_bundle_no_colon),
    MU_TEST(test_verify_malformed_bundle_no_open_quote),
    MU_TEST(test_verify_malformed_bundle_no_close_quote),
    MU_TEST(test_verify_cosign_path_empty_string),
    MU_TEST(test_verify_cosign_not_on_path),
    MU_TEST(test_verify_copy_uses_private_directory),
    MU_TEST(test_verify_cosign_success),
    MU_TEST(test_verify_cosign_nonzero_exit),
    MU_TEST(test_verify_wrong_owner_rejected),
    MU_TEST(test_verify_previous_owner_rejected),
    MU_TEST(test_verify_prefix_identity_rejected),
    MU_TEST(test_verify_suffix_identity_rejected),
    MU_TEST(test_verify_cosign_gets_anchored_identity),
    MU_TEST(test_tmpdir_requires_absolute_path),
    MU_TEST(test_tmpdir_requires_directory),
    MU_TEST(test_tmpdir_requires_writable_directory),
    MU_TEST(test_tmpdir_rejects_unprotected_shared_directory),
    MU_TEST(test_tmpdir_accepts_sticky_shared_tmp),
    MU_TEST(test_tmpdir_accepts_private_dir_under_0755_parent),
    MU_TEST(test_tmpdir_rejects_unprotected_shared_ancestor),
    MU_TEST(test_tmpdir_mode_rule),
    MU_TEST(test_tmpdir_rejects_symlink_into_shared_parent),
    MU_TEST(test_tmpdir_rejects_other_owner),
    MU_TEST(test_verify_bundle_rejects_parent_traversal),
    MU_TEST(test_verify_bundle_rejects_absolute_path),
    MU_TEST(test_verify_bundle_path_at_length_limit),
};
#else
static const MuTest platform_tests[] = {
    MU_TEST(test_verify_windows_returns_enosys),
};
#endif

/* Run tiny model verification tests and return the first failure message, or NULL on success. */
char *run_tests(void)
{
    char *msg = mu_run_table(common_tests, MU_TABLE_LEN(common_tests));
    if (msg)
        return msg;
    return mu_run_table(platform_tests, MU_TABLE_LEN(platform_tests));
}

/* NOLINTEND(modernize-use-nullptr) */

/* NOLINTEND(concurrency-mt-unsafe) */
