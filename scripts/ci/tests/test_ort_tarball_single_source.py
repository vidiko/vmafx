# Copyright 2026 Lusoris
# SPDX-License-Identifier: EUPL-1.2
"""Check ONNX source restrictions and the ClangBuildAnalyzer guard."""

from __future__ import annotations

import json
import re
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

from scripts.ci import check_ort_tarball_pins as guard

ROOT = Path(__file__).resolve().parents[3]
SHAPE_FINDING = "container ort_nuget_install.py instruction violates canonical RUN shape"


class TestOrtDocumentation(unittest.TestCase):
    adr = ROOT / "docs/adr/3561-ort-nuget.md"
    notes = ROOT / "docs/development/ci-workflow-notes/tests-and-quality-gates.md"

    def test_index_tags_match_decision(self) -> None:
        header = self.adr.read_text(encoding="utf-8").partition("- **Tags**: ")[2].splitlines()[0]
        fragment = self.adr.parent / "_index_fragments" / self.adr.name
        tags = fragment.read_text(encoding="utf-8").strip().strip("|").rsplit("|", 1)[1]
        self.assertEqual(set(tags.strip().split(", ")), set(header.replace("`", "").split(", ")))

    def test_decision_cites_maintainer_request(self) -> None:
        references = self.adr.read_text(encoding="utf-8").partition("## References\n")[2]
        self.assertRegex(references, r"(?m)^- (?:req|Q\d+\.\d+) \(paraphrased")
        self.assertIn("NuGet", references)

    def coverage_notes(self) -> str:
        text = self.notes.read_text(encoding="utf-8").partition("## coverage\n")[2]
        return " ".join(text.partition("\n## ")[0].split())

    def test_coverage_documents_driverless_provider_limit(self) -> None:
        self.assertRegex(self.coverage_notes(), r"does not assert that the CUDA provider attaches")

    def test_coverage_documents_cache_repair_scope(self) -> None:
        notes = self.coverage_notes()
        self.assertIn("repairs the current run only", notes)
        self.assertIn("gh cache delete", notes)
        self.assertIn("pin catalog rotates the key", notes)


class TestOrtGuard(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

    def test_local_unittest_discovery_includes_all_guard_cases(self) -> None:
        source = Path(__file__).read_text(encoding="utf-8")
        expected = len(re.findall(r"^(?:    )?def test_\w+\(", source, re.MULTILINE))
        suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
        self.assertGreater(expected, 0)
        self.assertEqual(suite.countTestCases(), expected)

    def test_old_source_and_direct_nuget_refused(self) -> None:
        tmp_path = Path(self.temp.name)
        workflow = tmp_path / "test.yml"
        for source, message in (
            ("https://github.com/microsoft/onnxruntime/releases/download/v1/file", "old ONNX"),
            (
                "https://api.nuget.org/v3-flatcontainer/microsoft.ml.onnxruntime/file",
                "must use helper",
            ),
        ):
            workflow.write_text(f"run: curl {source}\n", encoding="utf-8")
            rc, findings = guard.check_tarball_pins(files=[workflow])
            assert rc == 1
            assert message in "\n".join(findings)

    def test_bad_pin_refused(self) -> None:
        tmp_path = Path(self.temp.name)
        pins = tmp_path / "scripts/ci/ort-nuget-pins.json"
        pins.parent.mkdir(parents=True)
        for bad_entry, message in (
            ({"sha256": "a" * 63, "size": 10}, "malformed sha256"),
            ({"sha256": "a" * 64, "size": 0}, "invalid size"),
            ({"sha256": "a" * 64, "size": -5}, "invalid size"),
        ):
            pins.write_text(
                json.dumps({"packages": {"cpu": {"versions": {"1.0": bad_entry}}}}),
                encoding="utf-8",
            )
            rc, findings = guard.check_tarball_pins(root=tmp_path)
            assert rc == 1
            assert message in "\n".join(findings)

    def test_workflow_helper_version_pin_positive_and_negative(self) -> None:
        tmp_path = Path(self.temp.name)
        workflow = tmp_path / "workflow.yml"
        workflow.write_text(
            "jobs:\n"
            "  build:\n"
            "    steps:\n"
            "      - name: Install CPU ORT\n"
            "        env:\n"
            '          ORT_VERSION: "1.29.0"\n'
            "        run: |\n"
            '          python3 scripts/ci/ort_nuget_install.py --version "${ORT_VERSION}" \\\n'
            "            --prefix /opt/onnxruntime\n"
            "      - name: Install GPU ORT\n"
            "        env:\n"
            '          ORT_VERSION: "1.22.0"\n'
            "        run: |\n"
            '          python3 scripts/ci/ort_nuget_install.py --package gpu --version "${ORT_VERSION}" \\\n'
            "            --prefix /opt/onnxruntime\n",
            encoding="utf-8",
        )
        rc, findings = guard.check_tarball_pins(files=[workflow])
        assert rc == 0, findings

        for pkg_arg, unpinned_ver, pkg_label in (
            ("", "1.99.0", "cpu"),
            ("--package gpu ", "1.29.0", "gpu"),
        ):
            workflow.write_text(
                "jobs:\n"
                "  build:\n"
                "    steps:\n"
                "      - name: Install ORT\n"
                "        env:\n"
                f'          ORT_VERSION: "{unpinned_ver}"\n'
                "        run: |\n"
                f'          python3 scripts/ci/ort_nuget_install.py {pkg_arg}--version "${{ORT_VERSION}}" \\\n'
                "            --prefix /opt/onnxruntime\n",
                encoding="utf-8",
            )
            rc, findings = guard.check_tarball_pins(files=[workflow])
            assert rc == 1
            assert f"unpinned ORT_VERSION '{unpinned_ver}' for package '{pkg_label}'" in "\n".join(
                findings
            )

    def test_multiple_helper_commands_use_their_own_arguments(self) -> None:
        workflow = Path(self.temp.name) / "commands.yml"
        packages: dict[str, dict[str, Any]] = {
            "cpu": {"versions": {"1.0": {}}},
            "gpu": {"versions": {"2.0": {}}},
        }
        first = "    python ort_nuget_install.py --package cpu --version 1.0\n"
        second = "    python ort_nuget_install.py --package gpu --version 2.0\n"
        workflow.write_text("- run: |\n" + first + second)
        self.assertEqual(guard.scan_file(workflow, packages)[0], [])
        workflow.write_text("- run: |\n" + first + second.replace("2.0", "1.0"))
        findings = guard.scan_file(workflow, packages)[0]
        self.assertEqual(len(findings), 1)
        self.assertIn(":3: unpinned ORT_VERSION '1.0' for package 'gpu'", findings[0])

    def test_cpu_and_gpu_calls_share_a_shell_line(self) -> None:
        workflow = Path(self.temp.name) / "commands.yml"
        packages: dict[str, dict[str, Any]] = {
            "cpu": {"versions": {"1.0": {}}},
            "gpu": {"versions": {"2.0": {}}},
        }
        cpu = 'python3 ort_nuget_install.py --prefix "a;b" --version 1.0'
        gpu = 'python3 ort_nuget_install.py --package "gpu" --version '
        for separator in ("; ", " && ", " || ", " | ", " && " + chr(92) + "\n    "):
            with self.subTest(separator=separator):
                command = "- run: |\n    " + cpu + separator + gpu
                workflow.write_text(command + "2.0\n", encoding="utf-8")
                self.assertEqual(guard.scan_file(workflow, packages)[0], [])
                workflow.write_text(command + "9.9\n", encoding="utf-8")
                line = 2 + separator.count("\n")
                self.assertEqual(
                    guard.scan_file(workflow, packages)[0],
                    [f"{workflow}:{line}: unpinned ORT_VERSION '9.9' for package 'gpu'"],
                )

    def test_helper_version_bindings(self) -> None:
        workflow = Path(self.temp.name) / "bindings.yml"
        packages: dict[str, dict[str, Any]] = {"cpu": {"versions": {"1.0": {}}}}
        prefix = '- name: install\n  env:\n    ORT_VERSION: "1.0"\n  run: |\n'
        call = '    python ort_nuget_install.py --version "$ORT_VERSION"\n'
        for assignment, expected in (
            ("", False),
            ("    ORT_VERSION=1.0\n", True),
            ("    ORT_VERSION=9.0\n", True),
            ('    ORT_VERSION="$NEXT_VERSION"\n', True),
            ('    ORT_VERSION="$(cat version)"\n', True),
            ('    ORT_VERSION="${NEXT_VERSION:-1.0}"\n', True),
            ("    # ORT_VERSION=9.0\n", False),
        ):
            with self.subTest(assignment=assignment):
                workflow.write_text(prefix + assignment + call)
                findings = guard.scan_file(workflow, packages)[0]
                self.assertEqual(bool(findings), expected, findings)
                if expected:
                    self.assertIn(":6: ambiguous ORT_VERSION in step", findings[0])

    def test_inline_nonliteral_helper_version(self) -> None:
        workflow = Path(self.temp.name) / "inline.yml"
        packages: dict[str, dict[str, Any]] = {"cpu": {"versions": {"1.0": {}}}}
        tail = 'python3 ort_nuget_install.py --version "$ORT_VERSION"\n'
        cases = (
            (
                f'- run: |\n    ORT_VERSION=1.0 && ORT_VERSION="$NEXT_VERSION" && {tail}',
                ":2: ambiguous ORT_VERSION in step",
            ),
            (
                '- name: install\n  env:\n    ORT_VERSION: "1.0"\n  run: |\n'
                f'    true && ORT_VERSION="$NEXT_VERSION" && {tail}',
                ":5: ambiguous ORT_VERSION in step",
            ),
            (
                f'- run: |\n    ORT_VERSION="1.0$NEXT_VERSION" {tail}',
                ":2: ambiguous ORT_VERSION in step",
            ),
            (
                f"- run: |\n    ORT_VERSION=1.0#$NEXT_VERSION {tail}",
                ":2: ambiguous ORT_VERSION in step",
            ),
            (
                f"- run: |\n    ORT_VERSION=1.0$(echo ORT_VERSION=1.0 ) {tail}",
                ":2: ambiguous ORT_VERSION in step",
            ),
            (
                f'- run: |\n    ORT_VERSION="--version 1.0" && {tail}',
                ":2: ambiguous ORT_VERSION in step",
            ),
            (
                f'- run: |\n    ORT_VERSION="1.0" {tail}',
                ":2: ambiguous ORT_VERSION in step",
            ),
        )
        for text, expected in cases[: guard.MAX_COMMAND_LINES]:
            with self.subTest(text=text):
                workflow.write_text(text, encoding="utf-8")
                findings = guard.scan_file(workflow, packages)[0]
                self.assertEqual(findings, [f"{workflow}{expected}"])

    def test_nuget_package_identity(self) -> None:
        workflow = Path(self.temp.name) / "downloads.yml"
        address = "https://api.nuget.org/v3-flatcontainer/"
        cases = (
            (f"curl {address}microsoft.ml.onnxruntime/file", "must use helper"),
            (
                f"ORT_PACKAGE: microsoft.ml.onnxruntime\n  run: curl {address}${{ORT_PACKAGE}}/file",
                "must use helper",
            ),
            (
                "- name: dl\n  env:\n    ORT: microsoft.ml.onnxruntime\n"
                f'  run: curl {address}"${{ORT}}"/file',
                "ONNX Runtime download must use helper",
            ),
            (
                "- name: dl\n  env:\n    ORT: microsoft.ml.onnxruntime\n"
                f'  run: curl {address}"$ORT"/file',
                "ONNX Runtime download must use helper",
            ),
            (
                f'- run: curl {address}"microsoft.ml".onnxruntime/file',
                "ONNX Runtime download must use helper",
            ),
            (
                f"- run: curl {address}'microsoft.ml'.onnxruntime/file",
                "ONNX Runtime download must use helper",
            ),
            (f'- run: curl {address}"$(cat pkg)"/file', "NuGet download with unresolved package"),
            (f"run: wget {address}$UNKNOWN/file", "NuGet download with unresolved package"),
            (f"run: curl {address}other.package/file", None),
            (f"# curl {address}${{UNKNOWN}}/file", None),
            (f"OTHER: unrelated\n  run: curl {address}$OTHER/file", None),
            (f'OTHER: unrelated\n  run: curl {address}"$OTHER"/file', None),
        )
        for text, expected in cases:
            with self.subTest(text=text):
                body = text if text.startswith("- ") else f"- name: download\n  {text}"
                workflow.write_text(f"{body}\n", encoding="utf-8")
                findings = guard.scan_file(workflow, {})[0]
                if expected:
                    self.assertIn(expected, "\n".join(findings))
                else:
                    self.assertEqual(findings, [])

    def test_download_checks_only_the_referenced_package_binding(self) -> None:
        workflow = Path(self.temp.name) / "packages.yml"
        step = (
            "- name: download\n  env:\n    ORT: microsoft.ml.onnxruntime\n"
            "    OTHER: unrelated.package\n  run: curl https://api.nuget.org/v3-flatcontainer/"
        )
        workflow.write_text(step + "${OTHER}/file\n", encoding="utf-8")
        self.assertEqual(guard.scan_file(workflow, {})[0], [])
        workflow.write_text(step + "${ORT}/file\n", encoding="utf-8")
        self.assertEqual(
            guard.scan_file(workflow, {})[0],
            [f"{workflow}:5: ONNX Runtime download must use helper"],
        )

        workflow.write_text(
            step + "${OTHER}/file https://api.nuget.org/v3-flatcontainer/$ORT/file\n"
        )
        self.assertEqual(
            guard.scan_file(workflow, {})[0],
            [f"{workflow}:5: ONNX Runtime download must use helper"],
        )
        workflow.write_text(step.replace("unrelated.package", "$SOURCE") + "${OTHER}/file\n")
        self.assertEqual(
            guard.scan_file(workflow, {})[0],
            [f"{workflow}:5: NuGet download with unresolved package"],
        )

    def test_container_sources_and_pins(self) -> None:
        container = Path(self.temp.name) / "Containerfile"
        for keyword in ("ARG", "ENV"):
            helper = (
                f"{keyword} ORT_VERSION={{version}}\n"
                "RUN python3 scripts/ci/ort_nuget_install.py --package cpu " + chr(92) + "\n"
                '    --version "${{ORT_VERSION}}" --prefix /usr/local\n'
            )
            container.write_text(helper.format(version="1.30.0"))
            self.assertEqual(guard.check_tarball_pins(files=[container]), (0, []))
            container.write_text(helper.format(version="1.99.0"))
            self.assertEqual(
                guard.check_tarball_pins(files=[container]),
                (1, [f"{container}:2: unpinned ORT_VERSION '1.99.0' for package 'cpu'"]),
            )
        for command in (
            "RUN curl https://github.com/microsoft/onnxruntime/releases/download/v1/file\n",
            "RUN curl https://github.com/microsoft/onnxruntime/releases/\\\n    download/v1/file\n",
            "RUN curl https://api.nuget.org/v3-flatcontainer/\\\n    microsoft.ml.onnxruntime/file\n",
        ):
            container.write_text(command)
            rc, findings = guard.check_tarball_pins(files=[container])
            self.assertEqual(rc, 1, findings)
            self.assertIn(f"{container}:1:", "\n".join(findings))

    def test_container_continuation_comment_helper_accepted(self) -> None:
        container = Path(self.temp.name) / "Containerfile"
        container.write_text(
            "ARG ORT_VERSION=1.30.0\n"
            "RUN set -eux \\\n"
            "    # comment\n"
            "    && python3 scripts/ci/ort_nuget_install.py --package cpu \\\n"
            "        # comment\n"
            '        --version "${ORT_VERSION}" --prefix /usr/local\n'
        )
        self.assertEqual(guard.check_tarball_pins(files=[container]), (0, []))

    def test_container_continuation_comment_split_release_refused(self) -> None:
        container = Path(self.temp.name) / "Containerfile"
        container.write_text(
            "RUN set -eux \\\n"
            "    # comment\n"
            "    && curl -fsSL https://github.com/microsoft/onnxruntime/releases/\\\n"
            "        download/v1.30.0/ort.tgz\n"
        )
        self.assertEqual(
            guard.check_tarball_pins(files=[container]),
            (1, [f"{container}:1: old ONNX Runtime release source forbidden"]),
        )

    def test_container_add_continuation_split_release_refused(self) -> None:
        container = Path(self.temp.name) / "Containerfile"
        container.write_text(
            "ADD https://github.com/microsoft/onnxruntime/releases/\\\n"
            "    # comment\n"
            "    download/v1.30.0/ort.tgz /tmp/ort.tgz\n"
        )
        self.assertEqual(
            guard.check_tarball_pins(files=[container]),
            (1, [f"{container}:1: old ONNX Runtime release source forbidden"]),
        )

    def test_container_inline_version_override_refused(self) -> None:
        container = Path(self.temp.name) / "Containerfile"
        container.write_text(
            "ARG ORT_VERSION=1.30.0\n"
            "RUN ORT_VERSION=1.99.0 python3 scripts/ci/ort_nuget_install.py"
            ' --package cpu --version "${ORT_VERSION}" --prefix /usr/local\n'
        )
        self.assertEqual(
            guard.check_tarball_pins(files=[container]),
            (1, [f"{container}:2: unpinned ORT_VERSION '1.99.0' for package 'cpu'"]),
        )

    def test_container_continued_inline_version_override_refused(self) -> None:
        container = Path(self.temp.name) / "Containerfile"
        cases = (
            (
                "ARG ORT_VERSION=1.30.0\n"
                "RUN ORT_VERSION=1.99.0 \\\n"
                '    python3 scripts/ci/ort_nuget_install.py --package cpu --version "${ORT_VERSION}" --prefix /usr/local\n',
                3,
            ),
            (
                "ARG ORT_VERSION=1.30.0\n"
                "RUN true \\\n"
                "    && ORT_VERSION=1.99.0 \\\n"
                '    python3 scripts/ci/ort_nuget_install.py --package cpu --version "${ORT_VERSION}" --prefix /usr/local\n',
                4,
            ),
        )
        for text, line_no in cases:
            with self.subTest(line_no=line_no):
                container.write_text(text)
                self.assertEqual(
                    guard.check_tarball_pins(files=[container]),
                    (
                        1,
                        [f"{container}:{line_no}: unpinned ORT_VERSION '1.99.0' for package 'cpu'"],
                    ),
                )

    def test_container_quoted_hash_before_split_release_refused(self) -> None:
        container = Path(self.temp.name) / "Containerfile"
        for step_arg in ('"step #1"', "'step #1'"):
            with self.subTest(step_arg=step_arg):
                container.write_text(
                    f"RUN echo {step_arg} \\\n"
                    "    && curl -fsSL https://github.com/microsoft/onnxruntime/releases/\\\n"
                    "        download/v1.30.0/ort.tgz\n"
                )
                self.assertEqual(
                    guard.check_tarball_pins(files=[container]),
                    (1, [f"{container}:1: old ONNX Runtime release source forbidden"]),
                )

    def test_container_continuation_blank_line_split_release_refused(self) -> None:
        container = Path(self.temp.name) / "Containerfile"
        container.write_text(
            "RUN set -eux \\\n"
            "\n"
            "    && curl -fsSL https://github.com/microsoft/onnxruntime/releases/\\\n"
            "        download/v1.30.0/ort.tgz\n"
        )
        self.assertEqual(
            guard.check_tarball_pins(files=[container]),
            (1, [f"{container}:1: old ONNX Runtime release source forbidden"]),
        )

    def test_container_accepted_comments_and_pinned_override(self) -> None:
        container = Path(self.temp.name) / "Containerfile"
        cases = (
            "ARG ORT_VERSION=1.30.0\n"
            "RUN python3 scripts/ci/ort_nuget_install.py \\\n"
            "    --package cpu \\\n"
            "    # comment between continued lines\n"
            '    --version "${ORT_VERSION}" --prefix /usr/local\n',
            "# https://github.com/microsoft/onnxruntime/releases/download/v1.30.0/ort.tgz\n"
            "ARG ORT_VERSION=1.30.0\n"
            'RUN python3 scripts/ci/ort_nuget_install.py --package cpu --version "${ORT_VERSION}" --prefix /usr/local\n',
            "ARG ORT_VERSION=1.30.0\n"
            "RUN ORT_VERSION=1.30.0 \\\n"
            '    python3 scripts/ci/ort_nuget_install.py --package cpu --version "${ORT_VERSION}" --prefix /usr/local\n',
            "ARG ORT_VERSION=1.99.0\n"
            "RUN ORT_VERSION=1.30.0 \\\n"
            '    python3 scripts/ci/ort_nuget_install.py --package cpu --version "${ORT_VERSION}" --prefix /usr/local\n',
        )
        for text in cases:
            with self.subTest(text=text):
                container.write_text(text)
                self.assertEqual(guard.check_tarball_pins(files=[container]), (0, []))

    def test_container_first_line_and_eof_without_newline_boundaries(self) -> None:
        container = Path(self.temp.name) / "Containerfile"
        container.write_text(
            "RUN python3 scripts/ci/ort_nuget_install.py --package cpu --version 1.30.0 --prefix /usr/local\n"
        )
        self.assertEqual(guard.check_tarball_pins(files=[container]), (0, []))
        container.write_text(
            "RUN python3 scripts/ci/ort_nuget_install.py --package cpu --version 1.99.0 --prefix /usr/local\n"
        )
        self.assertEqual(
            guard.check_tarball_pins(files=[container]),
            (1, [f"{container}:1: unpinned ORT_VERSION '1.99.0' for package 'cpu'"]),
        )
        container.write_text(
            "ARG ORT_VERSION=1.30.0\n"
            "RUN python3 scripts/ci/ort_nuget_install.py --package cpu \\\n"
            '    --version "${ORT_VERSION}" --prefix /usr/local'
        )
        self.assertEqual(guard.check_tarball_pins(files=[container]), (0, []))
        container.write_text(
            "ARG ORT_VERSION=1.30.0\n"
            "RUN ORT_VERSION=1.99.0 \\\n"
            '    python3 scripts/ci/ort_nuget_install.py --package cpu --version "${ORT_VERSION}" --prefix /usr/local'
        )
        self.assertEqual(
            guard.check_tarball_pins(files=[container]),
            (1, [f"{container}:3: unpinned ORT_VERSION '1.99.0' for package 'cpu'"]),
        )

    def test_container_continuation_line_limit_boundary(self) -> None:
        container = Path(self.temp.name) / "Containerfile"
        call = "    && python3 scripts/ci/ort_nuget_install.py --package cpu --version 1.30.0 --prefix /usr/local\n"
        at_limit = (
            "RUN echo start \\\n" + "    && echo step \\\n" * (guard.MAX_COMMAND_LINES - 2) + call
        )
        container.write_text(at_limit)
        self.assertEqual(guard.check_tarball_pins(files=[container]), (0, []))
        over_limit = (
            "RUN echo start \\\n" + "    && echo step \\\n" * (guard.MAX_COMMAND_LINES - 1) + call
        )
        container.write_text(over_limit)
        self.assertEqual(
            guard.check_tarball_pins(files=[container]),
            (1, [f"{container}:1: container command continuation exceeds limit"]),
        )

    def test_container_second_helper_call_unpinned_refused(self) -> None:
        container = Path(self.temp.name) / "Containerfile"
        two_lines = (
            "ARG ORT_VERSION=1.30.0\n"
            'RUN python3 scripts/ci/ort_nuget_install.py --package cpu --version "${ORT_VERSION}" --prefix /a \\\n'
            " && python3 scripts/ci/ort_nuget_install.py --package cpu --version 1.99.0 --prefix /b\n"
        )
        one_line = (
            "ARG ORT_VERSION=1.30.0\n"
            'RUN python3 scripts/ci/ort_nuget_install.py --package cpu --version "${ORT_VERSION}" --prefix /a'
            " && python3 scripts/ci/ort_nuget_install.py --package cpu --version 1.99.0 --prefix /b\n"
        )
        for text, line_no in ((two_lines, 3), (one_line, 2)):
            with self.subTest(line_no=line_no):
                container.write_text(text)
                self.assertEqual(
                    guard.check_tarball_pins(files=[container]),
                    (
                        1,
                        [f"{container}:{line_no}: unpinned ORT_VERSION '1.99.0' for package 'cpu'"],
                    ),
                )

    def test_container_first_helper_call_unpinned_second_pinned_refused(self) -> None:
        container = Path(self.temp.name) / "Containerfile"
        container.write_text(
            "ARG ORT_VERSION=1.30.0\n"
            "RUN python3 scripts/ci/ort_nuget_install.py --package cpu --version 1.99.0 --prefix /a \\\n"
            ' && python3 scripts/ci/ort_nuget_install.py --package cpu --version "${ORT_VERSION}" --prefix /b\n'
        )
        self.assertEqual(
            guard.check_tarball_pins(files=[container]),
            (1, [f"{container}:2: unpinned ORT_VERSION '1.99.0' for package 'cpu'"]),
        )

    def test_container_standalone_and_export_binding_refused(self) -> None:
        container = Path(self.temp.name) / "Containerfile"
        cases = (
            (
                "ARG ORT_VERSION=1.30.0\n"
                "RUN ORT_VERSION=1.99.0"
                ' && python3 scripts/ci/ort_nuget_install.py --package cpu --version "${ORT_VERSION}" --prefix /a\n',
                2,
            ),
            (
                "ARG ORT_VERSION=1.30.0\n"
                "RUN export ORT_VERSION=1.99.0"
                ' && python3 scripts/ci/ort_nuget_install.py --package cpu --version "${ORT_VERSION}" --prefix /a\n',
                2,
            ),
            (
                "RUN ORT_VERSION=1.99.0 \\\n"
                " && python3 scripts/ci/ort_nuget_install.py --package cpu --version 1.30.0 --prefix /a \\\n"
                ' && python3 scripts/ci/ort_nuget_install.py --package cpu --version "${ORT_VERSION}" --prefix /b\n',
                3,
            ),
            (
                "RUN export ORT_VERSION=1.99.0 \\\n"
                " && python3 scripts/ci/ort_nuget_install.py --package cpu --version 1.30.0 --prefix /a \\\n"
                ' && python3 scripts/ci/ort_nuget_install.py --package cpu --version "${ORT_VERSION}" --prefix /b\n',
                3,
            ),
        )
        for text, line_no in cases:
            with self.subTest(text=text):
                container.write_text(text)
                self.assertEqual(
                    guard.check_tarball_pins(files=[container]),
                    (
                        1,
                        [f"{container}:{line_no}: unpinned ORT_VERSION '1.99.0' for package 'cpu'"],
                    ),
                )

    def test_container_measured_bypass_shapes_refused(self) -> None:
        container = Path(self.temp.name) / "Containerfile"
        cases = (
            (
                "ARG ORT_VERSION=1.30.0\n"
                "RUN sh -c 'ORT_VERSION=1.99.0 python3 scripts/ci/ort_nuget_install.py"
                ' --package cpu --version "${ORT_VERSION}" --prefix /usr/local\'\n',
                2,
            ),
            (
                "ARG ORT_VERSION=1.30.0\n"
                "RUN sh -c 'ORT_VERSION=1.99.0 && python3 scripts/ci/ort_nuget_install.py"
                ' --package cpu --version "${ORT_VERSION}" --prefix /usr/local\'\n',
                2,
            ),
            (
                "ARG ORT_VERSION=1.30.0\n"
                "RUN (ORT_VERSION=1.99.0 && python3 scripts/ci/ort_nuget_install.py"
                ' --package cpu --version "${ORT_VERSION}" --prefix /usr/local)\n',
                2,
            ),
            (
                "ARG ORT_VERSION=1.30.0\n"
                "RUN --mount=type=cache,target=/tmp/cache ORT_VERSION=1.99.0 \\\n"
                "&& python3 scripts/ci/ort_nuget_install.py --package cpu"
                ' --version "${ORT_VERSION}" --prefix /usr/local\n',
                3,
            ),
            (
                "ARG ORT_VERSION=1.30.0\n"
                "RUN python3 scripts/ci/ort_nuget_install.py --package cpu"
                ' --version "${ORT_VERSION}" --prefix /a \\\n'
                "& python3 scripts/ci/ort_nuget_install.py --package cpu"
                " --version 1.99.0 --prefix /b\n",
                2,
            ),
            (
                "RUN python3 scripts/ci/ort_nuget_install.py --package cpu"
                " --version 1.30.0 --version 1.99.0 --prefix /usr/local\n",
                1,
            ),
        )
        for text, line_no in cases:
            with self.subTest(text=text):
                container.write_text(text)
                self.assertEqual(
                    guard.check_tarball_pins(files=[container]),
                    (1, [f"{container}:{line_no}: {SHAPE_FINDING}"]),
                )

    def test_container_non_canonical_shapes_refused(self) -> None:
        container = Path(self.temp.name) / "Containerfile"
        cmd = "python3 scripts/ci/ort_nuget_install.py --package cpu"
        cases = (
            (
                'RUN ["python3", "scripts/ci/ort_nuget_install.py", "--package", "cpu",'
                ' "--version", "1.30.0", "--prefix", "/usr/local"]\n',
                1,
            ),
            (f"RUN <<EOF\n{cmd} --version 1.30.0 --prefix /usr/local\nEOF\n", 2),
            (f"RUN <<EOF \\\n{cmd} --version 1.30.0 --prefix /usr/local\n", 2),
            (
                f'ARG ORT_VERSION=1.30.0\nRUN false || {cmd} --version "${{ORT_VERSION}}" --prefix /usr/local\n',
                2,
            ),
            (
                f'ARG ORT_VERSION=1.30.0\nRUN export ORT_VERSION=1.30.0; {cmd} --version "${{ORT_VERSION}}" --prefix /usr/local\n',
                2,
            ),
            (f"RUN {cmd} --version $(echo 1.30.0) --prefix /usr/local\n", 1),
            (
                f'ARG ORT_VERSION=1.30.0\nRUN env ORT_VERSION=1.99.0 {cmd} --version "${{ORT_VERSION}}" --prefix /usr/local\n',
                2,
            ),
            (
                f'RUN : ${{ORT_VERSION:=1.99.0}} && {cmd} --version "${{ORT_VERSION}}" --prefix /usr/local\n',
                1,
            ),
            (f"RUN unset ORT_VERSION && {cmd} --version 1.30.0 --prefix /usr/local\n", 1),
            (f"RUN eval true && {cmd} --version 1.30.0 --prefix /usr/local\n", 1),
            (f"RUN {cmd} --version 1.30.0 --prefix /usr/local --unknown-flag val\n", 1),
            (f"RUN {cmd} --package gpu --version 1.30.0 --prefix /usr/local\n", 1),
        )
        for text, line_no in cases:
            with self.subTest(text=text):
                container.write_text(text)
                self.assertEqual(
                    guard.check_tarball_pins(files=[container]),
                    (1, [f"{container}:{line_no}: {SHAPE_FINDING}"]),
                )

    def test_container_canonical_shapes_and_installer_flags_accepted(self) -> None:
        installer_src = (ROOT / "scripts/ci/ort_nuget_install.py").read_text(encoding="utf-8")
        installer_flags = set(re.findall(r'add_argument\("(--[a-z-]+)"', installer_src))
        self.assertEqual(installer_flags, getattr(guard, "HELPER_FLAGS", set()))
        sample_values = {
            "--package": "cpu",
            "--version": "1.30.0",
            "--prefix": "/usr/local",
            "--pkgconfig-dir": "/usr/local/lib/pkgconfig",
            "--cache-dir": "/var/cache/ort",
            "--print-pin": "1.30.0",
        }
        self.assertEqual(set(sample_values), installer_flags)
        all_flags = " ".join(f"{flag} {sample_values[flag]}" for flag in sorted(installer_flags))
        container = Path(self.temp.name) / "Containerfile"
        positives = (
            "ARG ORT_VERSION=1.30.0\n"
            'RUN python3 scripts/ci/ort_nuget_install.py --package cpu --version "${ORT_VERSION}" --prefix /usr/local\n',
            "ARG ORT_VERSION=1.30.0\n"
            "RUN python3 scripts/ci/ort_nuget_install.py --package cpu \\\n"
            '    --version "${ORT_VERSION}" --prefix /usr/local\n',
            "RUN python3 scripts/ci/ort_nuget_install.py --package cpu --version 1.30.0 --prefix /usr/local\n",
            "RUN python3 scripts/ci/ort_nuget_install.py --version 1.30.0 --package cpu --prefix /usr/local\n",
            "RUN ORT_VERSION=1.30.0"
            ' && python3 scripts/ci/ort_nuget_install.py --package cpu --version "${ORT_VERSION}" --prefix /usr/local\n',
            "RUN export ORT_VERSION=1.30.0"
            ' && python3 scripts/ci/ort_nuget_install.py --package cpu --version "${ORT_VERSION}" --prefix /usr/local\n',
            "ARG ORT_VERSION=1.30.0\n"
            'RUN python3 scripts/ci/ort_nuget_install.py --package cpu --version "${ORT_VERSION}" --prefix /a \\\n'
            " && python3 scripts/ci/ort_nuget_install.py --package gpu --version 1.22.0 --prefix /b\n",
            "ARG ORT_VERSION=1.30.0\n"
            "RUN python3 scripts/ci/ort_nuget_install.py --package cpu \\\n"
            "    # comment between continued lines\n"
            '    --version "${ORT_VERSION}" --prefix /usr/local\n',
            f"RUN python3 scripts/ci/ort_nuget_install.py {all_flags}\n",
        )
        for text in positives:
            with self.subTest(text=text):
                container.write_text(text)
                self.assertEqual(guard.check_tarball_pins(files=[container]), (0, []))

    def test_container_comment_with_helper_token_before_call(self) -> None:
        container = Path(self.temp.name) / "Containerfile"
        container.write_text(
            "ARG ORT_VERSION=1.30.0\n"
            "RUN set -eux \\\n"
            "    # ort_nuget_install.py comment between continued lines\n"
            '    && python3 scripts/ci/ort_nuget_install.py --package cpu --version "${ORT_VERSION}" --prefix /a\n'
        )
        self.assertEqual(guard.check_tarball_pins(files=[container]), (0, []))
        container.write_text(
            "ARG ORT_VERSION=1.30.0\n"
            'RUN python3 scripts/ci/ort_nuget_install.py --package cpu --version "${ORT_VERSION}" --prefix /a \\\n'
            "    # ort_nuget_install.py comment between continued lines\n"
            "    && python3 scripts/ci/ort_nuget_install.py --package cpu --version 1.99.0 --prefix /b\n"
        )
        self.assertEqual(
            guard.check_tarball_pins(files=[container]),
            (1, [f"{container}:4: unpinned ORT_VERSION '1.99.0' for package 'cpu'"]),
        )

    def test_container_inline_assignment_first_call_only_refused(self) -> None:
        container = Path(self.temp.name) / "Containerfile"
        container.write_text(
            "ARG ORT_VERSION=1.30.0\n"
            "RUN ORT_VERSION=1.99.0 python3 scripts/ci/ort_nuget_install.py"
            ' --package cpu --version "${ORT_VERSION}" --prefix /a \\\n'
            ' && python3 scripts/ci/ort_nuget_install.py --package cpu --version "${ORT_VERSION}" --prefix /b\n'
        )
        self.assertEqual(
            guard.check_tarball_pins(files=[container]),
            (1, [f"{container}:2: unpinned ORT_VERSION '1.99.0' for package 'cpu'"]),
        )

    def test_container_multiple_pinned_calls_and_continued_version_accepted(self) -> None:
        container = Path(self.temp.name) / "Containerfile"
        cases = (
            "ARG ORT_VERSION=1.30.0\n"
            'RUN python3 scripts/ci/ort_nuget_install.py --package cpu --version "${ORT_VERSION}" --prefix /a \\\n'
            " && python3 scripts/ci/ort_nuget_install.py --package gpu --version 1.22.0 --prefix /b\n",
            "RUN python3 scripts/ci/ort_nuget_install.py --package cpu --version 1.30.0 \\\n"
            "--prefix /usr/local\n",
        )
        for text in cases:
            with self.subTest(text=text):
                container.write_text(text)
                self.assertEqual(guard.check_tarball_pins(files=[container]), (0, []))

    def test_container_three_calls_middle_unpinned_refused(self) -> None:
        container = Path(self.temp.name) / "Containerfile"
        container.write_text(
            "ARG ORT_VERSION=1.30.0\n"
            'RUN python3 scripts/ci/ort_nuget_install.py --package cpu --version "${ORT_VERSION}" --prefix /a \\\n'
            " && python3 scripts/ci/ort_nuget_install.py --package cpu --version 1.99.0 --prefix /b \\\n"
            " && python3 scripts/ci/ort_nuget_install.py --package gpu --version 1.22.0 --prefix /c\n"
        )
        self.assertEqual(
            guard.check_tarball_pins(files=[container]),
            (1, [f"{container}:3: unpinned ORT_VERSION '1.99.0' for package 'cpu'"]),
        )

    def test_cba_guard(self) -> None:
        tmp_path = Path(self.temp.name)
        source = (ROOT / "dev/Containerfile").read_text(encoding="utf-8")
        container = tmp_path / "Containerfile"
        container.write_text(source, encoding="utf-8")
        assert guard.check_tarball_pins(files=[container])[0] == 0

    def test_cba_digest_and_order_boundaries(self) -> None:
        tmp_path = Path(self.temp.name)
        container = tmp_path / "Containerfile"
        pin = "a" * 64
        check = "    && sha256sum --check /tmp/check \\\n"
        extract = "    && tar -xzf /tmp/cba.tar.gz \\\n"
        source = (
            f"ARG CLANGBUILDANALYZER_SHA256={pin}\n"
            "RUN curl https://github.com/aras-p/ClangBuildAnalyzer/archive/v1.tar.gz \\\n"
            + check
            + extract
            + "    && true\n"
        )
        for mutated, finding in (
            (
                source.replace("CLANGBUILDANALYZER_SHA256=", "REMOVED="),
                "missing CLANGBUILDANALYZER_SHA256",
            ),
            (source.replace(pin, "a" * 63), "malformed CLANGBUILDANALYZER_SHA256"),
            (source.replace(check, ""), "missing sha256sum --check"),
            (source.replace(check + extract, extract + check), "tar extraction occurs before"),
        ):
            container.write_text(mutated, encoding="utf-8")
            rc, findings = guard.check_tarball_pins(files=[container])
            assert rc == 1
            assert finding in "\n".join(findings)

    def test_package_argument_forms_and_literal_version(self) -> None:
        workflow = Path(self.temp.name) / "test.yml"
        for arg in ('--package "gpu"', "--package 'gpu'", "--package gpu", "--package=gpu"):
            workflow.write_text(
                f'- name: install\n  env:\n    ORT_VERSION: "1.29.0"\n'
                f'  run: python3 scripts/ci/ort_nuget_install.py {arg} --version "${{ORT_VERSION}}"\n'
            )
            rc, findings = guard.check_tarball_pins(files=[workflow])
            self.assertEqual(rc, 1)
            self.assertIn("package 'gpu'", "\n".join(findings))
        workflow.write_text(
            '- name: install\n  env:\n    ORT_VERSION: "1.29.0"\n'
            "  run: python3 scripts/ci/ort_nuget_install.py --version 1.99.0\n"
        )
        self.assertIn("1.99.0", "\n".join(guard.check_tarball_pins(files=[workflow])[1]))

    def test_pin_schema_and_targeted_scan(self) -> None:
        root = Path(self.temp.name)
        pins = root / "scripts/ci/ort-nuget-pins.json"
        pins.parent.mkdir(parents=True)
        workflow = root / "test.yaml"
        workflow.write_text("- run: python3 scripts/ci/ort_nuget_install.py --version 1.0\n")
        pkg: dict[str, Any] = {
            "source": "https://example.test",
            "header_dir": "headers",
            "libraries": ["lib"],
            "versions": {"1.0": {"sha256": "a" * 64, "size": 1}},
        }
        for field in ("source", "header_dir", "libraries", "versions"):
            broken = dict(pkg)
            broken.pop(field)
            pins.write_text(json.dumps({"packages": {"cpu": broken}}))
            rc, findings = guard.check_tarball_pins(root=root, files=[workflow])
            self.assertEqual(rc, 1)
            self.assertIn(field, "\n".join(findings))
        pins.write_text(json.dumps({"packages": None, "versions": pkg["versions"]}))
        rc, findings = guard.check_tarball_pins(root=root, files=[workflow])
        self.assertEqual(rc, 1)
        self.assertIn("missing packages table", "\n".join(findings))
        invalid_values: tuple[Any, ...] = (None, [], "bad")
        for invalid in invalid_values:
            broken = dict(pkg, versions=invalid)
            pins.write_text(json.dumps({"packages": {"cpu": broken}}))
            rc, findings = guard.check_tarball_pins(root=root, files=[workflow])
            self.assertEqual(rc, 1)
            self.assertIn("missing versions", "\n".join(findings))
        pkg["versions"]["1.0"]["size"] = 0
        pins.write_text(json.dumps({"packages": {"cpu": pkg}}))
        self.assertIn(
            "invalid size", "\n".join(guard.check_tarball_pins(root=root, files=[workflow])[1])
        )

    def test_comments_and_unrelated_packages(self) -> None:
        workflow = Path(self.temp.name) / "test.yml"
        workflow.write_text(
            "# curl https://example.test/microsoft.ml.onnxruntime.nupkg\n"
            "run: curl https://example.test/unrelated.nupkg # microsoft.ml.onnxruntime\n"
        )
        self.assertEqual(guard.check_tarball_pins(files=[workflow])[0], 0)

    def test_ort_archive_order_and_discovery(self) -> None:
        root = Path(self.temp.name)
        pins = root / "scripts/ci/ort-nuget-pins.json"
        pins.parent.mkdir(parents=True)
        pins.write_text((ROOT / "scripts/ci/ort-nuget-pins.json").read_text())
        container = root / "Containerfile"
        container.write_text(
            "RUN curl https://github.com/microsoft/onnxruntime/releases/download/v1/file\n"
        )
        self.assertEqual(
            guard.check_tarball_pins(root=root),
            (1, [f"{container}:1: old ONNX Runtime release source forbidden"]),
        )
        container.unlink()
        workflows = root / ".github/workflows"
        workflows.mkdir(parents=True)
        workflow = workflows / "test.yaml"
        workflow.write_text(
            "run: curl https://github.com/microsoft/onnxruntime/releases/download/v1/file\n"
        )
        self.assertEqual(
            guard.check_tarball_pins(root=root),
            (1, [f"{workflow}:1: old ONNX Runtime release source forbidden"]),
        )

    def test_workflow_rebind_after_and_refused(self) -> None:
        workflow = Path(self.temp.name) / "rebind_and.yml"
        packages: dict[str, dict[str, Any]] = {"cpu": {"versions": {"1.0": {}}}}
        call = '    python3 ort_nuget_install.py --version "$ORT_VERSION"\n'
        for header, line_no in (
            ('- name: install\n  env:\n    ORT_VERSION: "1.0"\n  run: |\n', 6),
            ("- name: install\n  run: |\n", 4),
        ):
            workflow.write_text(header + '    true && ORT_VERSION="$(cat v)"\n' + call)
            self.assertEqual(
                guard.scan_file(workflow, packages)[0],
                [f"{workflow}:{line_no}: ambiguous ORT_VERSION in step"],
            )

    def test_workflow_export_after_and_refused(self) -> None:
        workflow = Path(self.temp.name) / "export_and.yml"
        packages: dict[str, dict[str, Any]] = {"cpu": {"versions": {"1.0": {}}}}
        call = '    python3 ort_nuget_install.py --version "$ORT_VERSION"\n'
        for header, line_no in (
            ('- name: install\n  env:\n    ORT_VERSION: "1.0"\n  run: |\n', 6),
            ("- name: install\n  run: |\n", 4),
        ):
            workflow.write_text(header + "    true && export ORT_VERSION=1.0\n" + call)
            self.assertEqual(
                guard.scan_file(workflow, packages)[0],
                [f"{workflow}:{line_no}: ambiguous ORT_VERSION in step"],
            )

    def test_workflow_read_ort_version_refused(self) -> None:
        workflow = Path(self.temp.name) / "read_var.yml"
        packages: dict[str, dict[str, Any]] = {"cpu": {"versions": {"1.0": {}}}}
        call = '    python3 ort_nuget_install.py --version "$ORT_VERSION"\n'
        for rebind in (
            "    read ORT_VERSION\n",
            "    declare ORT_VERSION=1.0\n",
            "    printf -v ORT_VERSION 1.0\n",
        ):
            for header, line_no in (
                ('- name: install\n  env:\n    ORT_VERSION: "1.0"\n  run: |\n', 6),
                ("- name: install\n  run: |\n", 4),
            ):
                workflow.write_text(header + rebind + call)
                self.assertEqual(
                    guard.scan_file(workflow, packages)[0],
                    [f"{workflow}:{line_no}: ambiguous ORT_VERSION in step"],
                )

    def test_workflow_echo_prefix_binding_refused(self) -> None:
        workflow = Path(self.temp.name) / "echo_prefix.yml"
        packages: dict[str, dict[str, Any]] = {"cpu": {"versions": {"1.0": {}}}}
        workflow.write_text(
            '- run: ORT_VERSION=1.0 echo ok && python3 ort_nuget_install.py --version "$ORT_VERSION"\n'
        )
        self.assertEqual(
            guard.scan_file(workflow, packages)[0],
            [f"{workflow}:1: ambiguous ORT_VERSION in step"],
        )

    def test_workflow_inline_prefix_binding_refused(self) -> None:
        workflow = Path(self.temp.name) / "inline_prefix.yml"
        packages: dict[str, dict[str, Any]] = {"cpu": {"versions": {"1.0": {}}}}
        workflow.write_text(
            '- run: ORT_VERSION=1.0 python3 ort_nuget_install.py --version "$ORT_VERSION"\n'
        )
        self.assertEqual(
            guard.scan_file(workflow, packages)[0],
            [f"{workflow}:1: ambiguous ORT_VERSION in step"],
        )

    def test_workflow_quoted_hash_before_unpinned_call_refused(self) -> None:
        workflow = Path(self.temp.name) / "quoted_hash.yml"
        packages: dict[str, dict[str, Any]] = {"cpu": {"versions": {"1.0": {}}}}
        workflow.write_text('- run: echo "step #1" && python3 ort_nuget_install.py --version 9.9\n')
        self.assertEqual(
            guard.scan_file(workflow, packages)[0],
            [f"{workflow}:1: unpinned ORT_VERSION '9.9' for package 'cpu'"],
        )

    def test_workflow_command_substitution_boundary_refused(self) -> None:
        workflow = Path(self.temp.name) / "cmd_sub.yml"
        packages: dict[str, dict[str, Any]] = {"cpu": {"versions": {"1.0": {}}}}
        for line, expected in (
            (
                "- run: echo $(printf '%s' #1) && python3 ort_nuget_install.py --version 9.9\n",
                "unpinned ORT_VERSION '9.9' for package 'cpu'",
            ),
            (
                "- run: echo ${STEP_NAME:- #1} && python3 ort_nuget_install.py --version 9.9\n",
                "unpinned ORT_VERSION '9.9' for package 'cpu'",
            ),
            (
                "- run: python3 ort_nuget_install.py --version 1.0 --prefix $(echo /a; echo /b)\n",
                "invalid ort_nuget_install.py arguments in step",
            ),
        ):
            workflow.write_text(line)
            self.assertEqual(guard.scan_file(workflow, packages)[0], [f"{workflow}:1: {expected}"])

    def test_workflow_backtick_boundary_refused(self) -> None:
        workflow = Path(self.temp.name) / "backticks.yml"
        packages: dict[str, dict[str, Any]] = {"cpu": {"versions": {"1.0": {}}}}
        for line, expected in (
            (
                "- run: echo `printf '%s' #1` && python3 ort_nuget_install.py --version 9.9\n",
                "unpinned ORT_VERSION '9.9' for package 'cpu'",
            ),
            (
                "- run: python3 ort_nuget_install.py --version 1.0 --prefix `echo /a && echo /b`\n",
                "invalid ort_nuget_install.py arguments in step",
            ),
        ):
            workflow.write_text(line)
            self.assertEqual(guard.scan_file(workflow, packages)[0], [f"{workflow}:1: {expected}"])

    def test_workflow_prefix_package_flag_refused(self) -> None:
        workflow = Path(self.temp.name) / "prefix_pkg.yml"
        packages: dict[str, dict[str, Any]] = {
            "cpu": {"versions": {"1.0": {}}},
            "gpu": {"versions": {"2.0": {}}},
        }
        workflow.write_text(
            '- run: FOO="--package cpu" python3 ort_nuget_install.py --package gpu --version 1.0\n'
        )
        self.assertEqual(
            guard.scan_file(workflow, packages)[0],
            [f"{workflow}:1: unpinned ORT_VERSION '1.0' for package 'gpu'"],
        )

    def test_workflow_duplicate_version_flag_refused(self) -> None:
        workflow = Path(self.temp.name) / "dup_ver.yml"
        packages: dict[str, dict[str, Any]] = {"cpu": {"versions": {"1.0": {}}}}
        workflow.write_text("- run: python3 ort_nuget_install.py --version 1.0 --version 9.9\n")
        self.assertEqual(
            guard.scan_file(workflow, packages)[0],
            [f"{workflow}:1: invalid ort_nuget_install.py arguments in step"],
        )

    def test_workflow_default_expansion_version_refused(self) -> None:
        workflow = Path(self.temp.name) / "default_ver.yml"
        packages: dict[str, dict[str, Any]] = {"cpu": {"versions": {"1.0": {}}}}
        for arg in ("${ORT_VERSION:-1.0}", '"${ORT_VERSION:-1.0}"'):
            workflow.write_text(
                '- name: install\n  env:\n    ORT_VERSION: "1.0"\n'
                f"  run: python3 scripts/ci/ort_nuget_install.py --version {arg}\n"
            )
            self.assertEqual(
                guard.scan_file(workflow, packages)[0],
                [f"{workflow}:4: invalid ort_nuget_install.py arguments in step"],
            )

    def test_workflow_env_and_whole_line_two_sites_refused(self) -> None:
        workflow = Path(self.temp.name) / "two_sites.yml"
        for assign in ("    ORT_VERSION=1.22.0\n", '    export ORT_VERSION="1.22.0"\n'):
            workflow.write_text(
                '- name: Install ORT\n  env:\n    ORT_VERSION: "1.22.0"\n  run: |\n'
                + assign
                + '    python3 scripts/ci/ort_nuget_install.py --version "${ORT_VERSION}"'
                " --prefix /opt/onnxruntime\n"
            )
            self.assertEqual(
                guard.check_tarball_pins(files=[workflow]),
                (1, [f"{workflow}:6: ambiguous ORT_VERSION in step"]),
            )

    def test_nuget_download_multiple_or_noncanonical_sites_refused(self) -> None:
        workflow = Path(self.temp.name) / "nuget_sites.yml"
        url = "https://api.nuget.org/v3-flatcontainer/${OTHER}/file"
        for body, line_no in (
            (
                "- name: dl\n  env:\n    OTHER: unrelated\n  run: |\n"
                f"    OTHER=unrelated\n    curl {url}\n",
                6,
            ),
            (f"- name: dl\n  run: |\n    true && OTHER=unrelated\n    curl {url}\n", 4),
            (f"- name: dl\n  run: |\n    read OTHER\n    curl {url}\n", 4),
        ):
            workflow.write_text(body)
            self.assertEqual(
                guard.scan_file(workflow, {})[0],
                [f"{workflow}:{line_no}: NuGet download with unresolved package"],
            )

    def test_workflow_helper_continuation_limits(self) -> None:
        workflow = Path(self.temp.name) / "continuation_limit.yml"
        head = "- run: |\n    python3 scripts/ci/ort_nuget_install.py --version 1.30.0 \\\n"
        tail = "      --prefix /opt/onnxruntime\n"
        workflow.write_text(head + "      \\\n" * (guard.MAX_COMMAND_LINES - 2) + tail)
        self.assertEqual(guard.check_tarball_pins(files=[workflow]), (0, []))
        workflow.write_text(head + "      \\\n" * (guard.MAX_COMMAND_LINES - 1) + tail)
        self.assertEqual(
            guard.check_tarball_pins(files=[workflow]),
            (1, [f"{workflow}:2: helper command continuation exceeds limit"]),
        )
        call = (
            "python3 scripts/ci/ort_nuget_install.py --version 1.30.0 --prefix /opt/onnxruntime\n"
        )
        workflow.write_text("- run: " + "true; " * (guard.MAX_STEP_LINES - 1) + call)
        self.assertEqual(guard.check_tarball_pins(files=[workflow]), (0, []))
        workflow.write_text("- run: " + "true; " * guard.MAX_STEP_LINES + call)
        self.assertEqual(
            guard.check_tarball_pins(files=[workflow]),
            (1, [f"{workflow}:1: helper command continuation exceeds limit"]),
        )

    def test_workflow_step_binding_limits(self) -> None:
        workflow = Path(self.temp.name) / "step_limit.yml"
        helper_head = '- name: install\n  env:\n    ORT_VERSION: "1.30.0"\n  run: |\n'
        helper_call = (
            '    python3 scripts/ci/ort_nuget_install.py --version "${ORT_VERSION}"'
            " --prefix /opt/onnxruntime\n"
        )
        workflow.write_text(
            helper_head + "    echo ok\n" * (guard.MAX_STEP_LINES - 5) + helper_call
        )
        self.assertEqual(guard.check_tarball_pins(files=[workflow]), (0, []))
        workflow.write_text(
            helper_head + "    echo ok\n" * (guard.MAX_STEP_LINES - 4) + helper_call
        )
        self.assertEqual(
            guard.check_tarball_pins(files=[workflow]),
            (1, [f"{workflow}:{guard.MAX_STEP_LINES + 1}: step binding limit exceeded"]),
        )
        nuget_head = "- name: dl\n  env:\n    OTHER: unrelated\n  run: |\n"
        nuget_call = "    curl https://api.nuget.org/v3-flatcontainer/${OTHER}/file\n"
        workflow.write_text(nuget_head + "    echo ok\n" * (guard.MAX_STEP_LINES - 5) + nuget_call)
        self.assertEqual(guard.check_tarball_pins(files=[workflow]), (0, []))
        workflow.write_text(nuget_head + "    echo ok\n" * (guard.MAX_STEP_LINES - 4) + nuget_call)
        self.assertEqual(
            guard.check_tarball_pins(files=[workflow]),
            (1, [f"{workflow}:{guard.MAX_STEP_LINES + 1}: step binding limit exceeded"]),
        )

    def test_workflow_nuget_address_limit_and_v2_package(self) -> None:
        workflow = Path(self.temp.name) / "nuget_limit.yml"
        unit = " https://api.nuget.org/v3-flatcontainer/other.pkg/file"
        workflow.write_text("run: curl" + unit * guard.MAX_COMMAND_LINES + "\n")
        self.assertEqual(guard.check_tarball_pins(files=[workflow]), (0, []))
        workflow.write_text("run: curl" + unit * (guard.MAX_COMMAND_LINES + 1) + "\n")
        self.assertEqual(
            guard.check_tarball_pins(files=[workflow]),
            (1, [f"{workflow}:1: NuGet address limit exceeded"]),
        )
        workflow.write_text(
            "run: curl https://www.nuget.org/api/v2/package/Microsoft.ML.OnnxRuntime/1.99.0\n"
        )
        self.assertEqual(
            guard.check_tarball_pins(files=[workflow]),
            (1, [f"{workflow}:1: ONNX Runtime download must use helper"]),
        )
        workflow.write_text(
            "run: curl https://www.nuget.org/api/v2/package/${UNPINNED_PKG}/1.99.0\n"
        )
        self.assertEqual(
            guard.check_tarball_pins(files=[workflow]),
            (1, [f"{workflow}:1: NuGet download with unresolved package"]),
        )
        workflow.write_text(
            "run: curl https://www.nuget.org/api/v2/package/Newtonsoft.Json/13.0.3\n"
        )
        self.assertEqual(guard.check_tarball_pins(files=[workflow]), (0, []))

    def test_workflow_five_canonical_call_site_shapes_accepted(self) -> None:
        workflow = Path(self.temp.name) / "canonical.yml"
        sites = (
            ("1.30.0", "", ""),
            ("1.29.0", "", ""),
            ("1.22.0", "", ""),
            ("1.22.0", "", ""),
            ("1.22.0", "--package gpu ", ' --cache-dir "${RUNNER_TEMP}/ort-cache"'),
        )
        steps = [
            f"      - name: Install ORT {idx}\n"
            "        env:\n"
            f'          ORT_VERSION: "{ver}"\n'
            "        run: |\n"
            f'          python3 scripts/ci/ort_nuget_install.py {pkg}--version "${{ORT_VERSION}}" \\\n'
            f"            --prefix /opt/onnxruntime{cache}\n"
            for idx, (ver, pkg, cache) in enumerate(sites)
        ]
        workflow.write_text("jobs:\n  build:\n    steps:\n" + "".join(steps))
        self.assertEqual(guard.check_tarball_pins(files=[workflow]), (0, []))

    def test_workflow_whole_line_binding_quoted_hash_and_real_tree(self) -> None:
        workflow = Path(self.temp.name) / "whole_line.yml"
        for assign in ("    ORT_VERSION=1.22.0\n", "    export ORT_VERSION=1.22.0\n"):
            workflow.write_text(
                "- name: Install ORT\n  run: |\n"
                + assign
                + '    echo "step #1"\n'
                + '    python3 scripts/ci/ort_nuget_install.py --version "${ORT_VERSION}" \\\n'
                + "      --prefix /opt/onnxruntime\n"
            )
            self.assertEqual(guard.check_tarball_pins(files=[workflow]), (0, []))
        workflow.write_text(
            "- name: Install ORT\n  run: |\n    ORT_VERSION=1.99.0\n"
            '    echo "step #1"\n'
            '    python3 scripts/ci/ort_nuget_install.py --version "${ORT_VERSION}" \\\n'
            "      --prefix /opt/onnxruntime\n"
        )
        self.assertEqual(
            guard.check_tarball_pins(files=[workflow]),
            (1, [f"{workflow}:5: unpinned ORT_VERSION '1.99.0' for package 'cpu'"]),
        )
        self.assertEqual(guard.check_tarball_pins(root=ROOT), (0, []))
