"""Validate the pwnable.tw migration manifest and generated casebook."""

import hashlib
import json
import os
import re
from collections import Counter
from pathlib import Path
import unittest


REPO_ROOT = Path(__file__).resolve().parent.parent
CASE_ROOT = REPO_ROOT / "ctf-pwn/references/linux-userland/pwnable-tw"
MANIFEST_PATH = CASE_ROOT / "migration-manifest.json"
SOURCE_RED_FLAGS = CASE_ROOT / "source-red-flags.md"

CASE_FILES = {
    "stack-control-cases.md": [
        "3x17", "babystack", "calc", "de_aslr", "dubblesort", "kidding",
        "printable", "silver_bullet", "spirited_away", "start", "starbound",
        "unexploitable",
    ],
    "heap-object-cases.md": [
        "applestore", "babyallocator", "caov", "criticalheap",
        "criticalheap_pp", "digimon", "ghost_party", "hacknote", "omegago",
        "stupid_boss",
    ],
    "allocator-file-cases.md": [
        "bookwriter", "break_out", "bounty_program_a", "bounty_program_b",
        "food_store", "heap_paradise", "hitcon_ftp", "re_alloc",
        "re_alloc_revenge", "secret_garden", "secret_of_my_heart", "seethefile",
        "tcache_tear", "wannaheap",
    ],
    "shellcode-sandbox-cases.md": [
        "alive_note", "death_note", "mno2", "orw", "seccomptools",
    ],
    "restricted-shell-cases.md": ["bash", "bash_revenge"],
}
CASE_CHALLENGES = {
    challenge: filename
    for filename, challenges in CASE_FILES.items()
    for challenge in challenges
}
CASE_H3S = ["Metadata", "Facts", "Exploit Paths", "Assets and Provenance"]
# Protection/libc summaries repeat in source challenge overviews. The complete
# target-specific sentences remain distinct; only this short factual phrase is
# approved for reuse.
APPROVED_PROSE_DUPLICATES = {
    ("i386", "no", "pie", "partial", "relro", "nx", "stack", "canary",
     "built", "against", "glibc", "2", "23"),
}
FRONTMATTER_FIELDS = {
    "tags", "platform", "points", "arch", "libc", "relro", "canary", "nx",
    "pie", "references", "description", "proof-of-concept",
}
EXPECTED_TAGS = {
    "alpha-shellcode", "arbitrary-write", "brute-force-oracle",
    "canary-bypass", "command-injection", "double-free", "fastbin-dup",
    "file-descriptor-leak", "fini-array-overwrite", "format-string",
    "got-overwrite", "heap-buffer-overflow", "heap-consolidation",
    "heap-overlap", "house-of-orange", "house-of-spirit",
    "information-leak", "integer-overflow", "integer-underflow",
    "io-file-exploit", "logic-flaw", "off-by-null", "off-by-one",
    "one-gadget", "out-of-bounds-write", "race-condition",
    "ret2dlresolve", "ret2libc", "reverse-shell", "rop",
    "seccomp-bypass", "shellcode", "srop", "stack-buffer-overflow",
    "stack-exhaustion", "stack-pivoting", "static-binary",
    "tcache-poisoning", "timing-side-channel", "type-confusion",
    "unsorted-bin-attack", "use-after-free", "vtable-hijack",
}
ALLOWED_CLASSES = {
    "case-metadata", "case-facts", "case-paths", "case-assets", "pattern",
    "index", "routing",
}


def slugify(heading: str) -> str:
    """Apply the repository's GitHub-style anchor approximation."""
    slug = heading.lower().strip()
    slug = re.sub(r"[*`~]", "", slug)
    slug = re.sub(r"<[^>]+>", "", slug)
    slug = re.sub(r"[^\w\s-]", "", slug)
    return slug.replace(" ", "-")


def strip_fenced(text: str) -> str:
    """Replace fenced code with blank lines while retaining line count."""
    output = []
    fenced = False
    for line in text.splitlines():
        if line.lstrip().startswith("```"):
            fenced = not fenced
            output.append("")
            continue
        output.append("" if fenced else line)
    return "\n".join(output)


def headings(text: str) -> list[tuple[int, int, str]]:
    """Return (line number, level, title) for non-code ATX headings."""
    result = []
    for line_number, line in enumerate(text.splitlines(), 1):
        match = re.match(r"^(#{1,6})\s+(.+?)\s*$", line)
        if match:
            result.append(
                (line_number, len(match.group(1)), match.group(2).strip())
            )
    return result


def heading_anchors(path: Path) -> set[str]:
    return {
        slugify(title)
        for _, _, title in headings(strip_fenced(path.read_text(encoding="utf-8")))
    }


def fenced_blocks(text: str) -> list[str]:
    blocks = []
    current = None
    language = ""
    for line in text.splitlines():
        if current is None:
            match = re.match(r"^```(\S*)\s*$", line)
            if match:
                current = []
                language = match.group(1)
            continue
        if line.lstrip().startswith("```"):
            if current:
                blocks.append((language, "\n".join(current).strip()))
            current = None
        else:
            current.append(line)
    return blocks


def prose_sequences(path: Path, length: int = 12) -> set[tuple[str, ...]]:
    """Extract ordinary paragraph prose; headings, lists, tables and code excluded."""
    text = path.read_text(encoding="utf-8")
    output = []
    fenced = False
    paragraph: list[str] = []

    def emit() -> None:
        words = re.findall(r"\b[\w'’-]+\b", " ".join(paragraph).lower())
        output.extend(
            tuple(words[i : i + length]) for i in range(len(words) - length + 1)
        )
        paragraph.clear()

    for line in text.splitlines():
        if line.lstrip().startswith("```"):
            if not fenced:
                emit()
            fenced = not fenced
            continue
        if fenced:
            continue
        if not line.strip() or re.match(r"^(#|>|\s*[-*+]|\s*\d+[.]|\s*\|)", line):
            emit()
            continue
        paragraph.append(line)
    emit()
    return set(output)


class TestMigrationManifest(unittest.TestCase):
    def setUp(self):
        self.manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))

    def test_manifest_schema(self):
        self.assertEqual(self.manifest["schema_version"], 1)
        self.assertIsInstance(self.manifest["source_files"], list)
        self.assertIsInstance(self.manifest["coverage"], list)
        self.assertEqual(
            set(self.manifest),
            {"schema_version", "source_root", "source_files", "coverage"},
        )

        required = {"source_path", "sha256", "bytes", "lines"}
        paths = []
        for row in self.manifest["source_files"]:
            with self.subTest(source=row.get("source_path")):
                self.assertEqual(set(row), required)
                self.assertRegex(row["sha256"], r"^[0-9a-f]{64}$")
                self.assertGreater(row["bytes"], 0)
                self.assertGreaterEqual(row["lines"], 1)
                paths.append(row["source_path"])
        self.assertEqual(len(paths), len(set(paths)))

        required = {
            "source_path", "source_line", "source_heading",
            "destination_path", "destination_anchor", "class",
        }
        coverage_keys = []
        for row in self.manifest["coverage"]:
            with self.subTest(heading=row.get("source_heading")):
                self.assertEqual(set(row), required)
                self.assertGreater(row["source_line"], 0)
                self.assertRegex(
                    row["source_heading"], r"^#{1,6}\s+\S"
                )
                self.assertIn(row["class"], ALLOWED_CLASSES)
                coverage_keys.append((row["source_path"], row["source_line"]))
        self.assertEqual(len(coverage_keys), len(set(coverage_keys)))

    def test_all_45_source_files_are_hashed(self):
        sources = {
            row["source_path"] for row in self.manifest["source_files"]
        }
        challenges = {
            f"linux-userland-ctf/pwnable.tw/{name}/README.md"
            for name in CASE_CHALLENGES
        }
        expected = challenges | {
            "linux-userland-ctf/pwnable.tw/index.md",
            "linux-userland-ctf/pwnable.tw/patterns_archive.md",
        }
        self.assertEqual(sources, expected)
        self.assertEqual(len(self.manifest["source_files"]), 45)

    def test_coverage_has_one_row_per_challenge_heading(self):
        rows = {
            row["source_path"].split("/")[-2]: row
            for row in self.manifest["coverage"]
            if row["source_path"].endswith("/README.md")
            and row["source_heading"].startswith("# ")
            and not row["source_heading"].startswith("## ")
        }
        self.assertEqual(set(rows), set(CASE_CHALLENGES))
        for challenge, row in rows.items():
            with self.subTest(challenge=challenge):
                self.assertTrue(row["source_heading"].startswith("# "), challenge)
                self.assertFalse(row["source_heading"].startswith("## "), challenge)
                self.assertEqual(row["class"], "case-metadata")
                self.assertEqual(
                    row["destination_path"],
                    f"references/linux-userland/pwnable-tw/{CASE_CHALLENGES[challenge]}",
                )
                self.assertEqual(row["destination_anchor"], challenge)

    def test_destination_paths_and_anchors_resolve(self):
        for row in self.manifest["coverage"]:
            destination = REPO_ROOT / "ctf-pwn" / row["destination_path"]
            with self.subTest(destination=str(destination), anchor=row["destination_anchor"]):
                self.assertTrue(destination.is_file())
                self.assertIn(row["destination_anchor"], heading_anchors(destination))

    def test_source_tag_index_is_complete(self):
        readme = (CASE_ROOT / "README.md").read_text(encoding="utf-8")
        section = re.search(
            r"^## Source Tag Index\s*$(.*?)(?=^## |\Z)", readme,
            re.M | re.S,
        )
        self.assertIsNotNone(section)
        indexed = set(re.findall(r"^-\s+`([^`]+)`:", section.group(1), re.M))
        expected = EXPECTED_TAGS
        self.assertEqual(indexed, expected)
        self.assertGreater(len(expected), 0)


class TestCaseFiles(unittest.TestCase):
    def test_each_challenge_has_one_h2_and_exact_h3_sequence(self):
        seen = {}
        for filename, expected in CASE_FILES.items():
            path = CASE_ROOT / filename
            self.assertTrue(path.is_file(), filename)
            text = strip_fenced(path.read_text(encoding="utf-8"))
            matches = list(re.finditer(r"^## (.+)$", text, re.M))
            matches = [
                match for match in matches
                if match.group(1).strip() not in {"How To Use This File", "Case Index"}
            ]
            self.assertEqual(
                [match.group(1).strip() for match in matches], expected
            )
            for match in matches:
                challenge = match.group(1).strip()
                self.assertNotIn(challenge, seen)
                seen[challenge] = filename
                start = match.end()
                next_match = re.search(r"^## ", text[start:], re.M)
                block = text[start : start + next_match.start()] if next_match else text[start:]
                actual = re.findall(r"^### (.+)$", block, re.M)
                self.assertEqual(actual, CASE_H3S, challenge)

        self.assertEqual(seen, CASE_CHALLENGES)

    def test_each_metadata_block_preserves_all_source_fields(self):
        for filename in CASE_FILES:
            text = (CASE_ROOT / filename).read_text(encoding="utf-8")
            blocks = []
            for challenge in CASE_FILES[filename]:
                section = re.search(
                    rf"^## {re.escape(challenge)}\s*$(.*?)(?=^## |\Z)",
                    text, re.M | re.S,
                )
                self.assertIsNotNone(section, challenge)
                yaml_match = re.search(r"```yaml\n(.*?)\n```", section.group(1), re.S)
                self.assertIsNotNone(yaml_match, challenge)
                blocks.append((challenge, yaml_match.group(1)))
            self.assertEqual(len(blocks), len(CASE_FILES[filename]), filename)
            for challenge, yaml_text in blocks:
                with self.subTest(challenge=challenge):
                    fields = set(re.findall(r"^([a-z][a-z-]*):", yaml_text, re.M))
                    self.assertEqual(fields, FRONTMATTER_FIELDS)

    def test_shellcode_sandbox_has_only_five_owned_challenges(self):
        text = strip_fenced(
            (CASE_ROOT / "shellcode-sandbox-cases.md").read_text(encoding="utf-8")
        )
        challenges = [
            item for item in re.findall(r"^## (.+)$", text, re.M)
            if item not in {"How To Use This File", "Case Index"}
        ]
        self.assertEqual(challenges, CASE_FILES["shellcode-sandbox-cases.md"])

    def test_source_red_flags_has_28_pattern_h2s(self):
        text = strip_fenced(SOURCE_RED_FLAGS.read_text(encoding="utf-8"))
        h2s = [
            item for item in re.findall(r"^## (.+)$", text, re.M)
            if re.match(r"^Pattern \d+\.\d+:", item)
        ]
        self.assertEqual(len(h2s), 28)
        self.assertTrue(all(re.match(r"^Pattern \d+\.\d+:", item) for item in h2s))

    def test_new_markdown_has_no_unapproved_12_word_prose_duplicate(self):
        owners = {}
        for path in CASE_ROOT.glob("*.md"):
            for sequence in prose_sequences(path):
                if any(
                    sequence == approved[i : i + 12]
                    for approved in APPROVED_PROSE_DUPLICATES
                    for i in range(len(approved) - 11)
                ):
                    continue
                if sequence in owners:
                    raise AssertionError(
                        f"duplicate 12-word prose in {owners[sequence]} and {path.name}: "
                        + " ".join(sequence)
                    )
                owners[sequence] = path.name

    def test_case_files_do_not_duplicate_generic_pattern_fences(self):
        pattern_text = SOURCE_RED_FLAGS.read_text(encoding="utf-8")
        patterns = {block for block in fenced_blocks(pattern_text)}
        for filename in CASE_FILES:
            text = (CASE_ROOT / filename).read_text(encoding="utf-8")
            for language, block in fenced_blocks(text):
                self.assertNotIn(
                    (language, block), patterns,
                    f"generic pattern fence duplicated in {filename}",
                )


class TestNavigation:
    @staticmethod
    def decision_rows():
        readme = CASE_ROOT / "README.md"
        text = readme.read_text(encoding="utf-8")
        match = re.search(
            r"^## Decision Router\s*$(.*?)^## Search Cookbook$",
            text, re.M | re.S,
        )
        assert match, "Decision Router section is missing"
        rows = []
        data_rows = [
            line for line in match.group(1).splitlines()
            if line.startswith("|") and "---" not in line
            and not line.startswith("| Challenge |")
        ]
        for line in data_rows:
            cells = [cell.strip() for cell in re.split(r"(?<!\\)\|", line.strip("|"))]
            assert len(cells) == 6, line
            challenge_match = re.match(r"\[`([^`]+)`\]", cells[0])
            assert challenge_match, line
            challenge = challenge_match.group(1)
            link_match = re.search(r"\]\(([^)#]+)#([^)]+)\)", cells[1])
            assert link_match, line
            rows.append({
                "challenge": challenge,
                "file": link_match.group(1),
                "anchor": link_match.group(2),
                "read": cells[2],
                "route": cells[3],
                "search": cells[4],
                "variant": cells[5],
            })
        return rows


class TestExplicitRouting(unittest.TestCase):
    def test_skill_has_high_visibility_router(self):
        text = (REPO_ROOT / "ctf-pwn/SKILL.md").read_text(encoding="utf-8")
        self.assertIn("## pwnable.tw Router", text)
        self.assertIn("known or reasonably suspected to be pwnable.tw", text)
        self.assertIn("README.md#decision-router", text)
        self.assertIn("trigger, root-cause defect, exploit primitive", text)
        self.assertIn("Known-platform Decision Router for all 43 pwnable.tw exploitation routes", text)
        for phrase in ("ret2libc", "SROP", "ret2dlresolve", "format string", "tcache", "House attacks", "vtable confusion", "fake `_IO_FILE`", "alphanumeric/printable/RWX shellcode", "seccomp/BPF/ORW", "restricted-bash/chroot/FD escape"):
            self.assertIn(phrase, text)
        self.assertIn("Source-audit router for all 28 archived vulnerability patterns", text)
        for phrase in ("oversized `read`/`memcpy`", "`realloc(ptr,0)`", "missing C++ copy constructor", "direct `printf`", "attacker-length `strncmp`", "termination/timing oracles"):
            self.assertIn(phrase, text)

    def test_casebook_has_navigation_workflow(self):
        text = (CASE_ROOT / "README.md").read_text(encoding="utf-8")
        for section in (
            "## How To Use This Casebook", "## Decision Router",
            "## Search Cookbook", "## Misrouting Rules",
        ):
            self.assertIn(section, text)
        self.assertIn("Points are historical metadata, not exploit selectors", text)
        self.assertIn("generic technique files explain reusable background", text.lower())
        self.assertIn("Route by the first exploitable defect", text)
        for phrase in (
            "Case Files and Technique Routes",
            "If You Do Not Know The Technique Yet",
            "stack overflow, canary bypass, partial overwrite, stack pivot",
            "UAF, dangling pointer, double free, fastbin/tcache reuse",
            "FILE structure exploitation/FSOP",
            "constrained/RWX shellcode, stager, self-modifying code",
            "restricted-shell escape, loader bypass, controlled free, FD recovery",
        ):
            self.assertIn(phrase, text)

    def test_decision_router_has_43_unique_resolving_rows(self):
        rows = TestNavigation.decision_rows()
        self.assertEqual(len(rows), 43)
        self.assertEqual({row["challenge"] for row in rows}, set(CASE_CHALLENGES))
        for row in rows:
            with self.subTest(challenge=row["challenge"]):
                self.assertEqual(row["file"], CASE_CHALLENGES[row["challenge"]])
                self.assertEqual(row["anchor"], row["challenge"])
                for key in ("read", "route", "search", "variant"):
                    self.assertTrue(row[key], (row["challenge"], key))
                destination = CASE_ROOT / row["file"]
                self.assertTrue(destination.is_file())
                self.assertIn(row["anchor"], heading_anchors(destination))

    def test_every_case_has_verbose_matching_route_card_and_index(self):
        rows = {row["challenge"]: row for row in TestNavigation.decision_rows()}
        for filename, challenges in CASE_FILES.items():
            path = CASE_ROOT / filename
            text = path.read_text(encoding="utf-8")
            with self.subTest(file=filename):
                self.assertIn("## How To Use This File", text)
                self.assertIn("## Case Index", text)
            index = re.search(
                r"^## Case Index\s*$(.*?)(?=^## |\Z)", text, re.M | re.S,
            )
            self.assertIsNotNone(index, filename)
            index_rows = [
                line for line in index.group(1).splitlines()
                if line.startswith("|") and "---" not in line
            and not line.startswith("| Challenge |")
            ]
            self.assertEqual(len(index_rows), len(challenges), filename)
            for challenge in challenges:
                row = rows[challenge]
                section = re.search(
                    rf"^## {re.escape(challenge)}\s*$(.*?)(?=^### Metadata$)",
                    text, re.M | re.S,
                )
                self.assertIsNotNone(section, challenge)
                card = section.group(1)
                expected = {
                    "Canonical route": row["route"],
                    "Read this case when": row["read"],
                    "Search terms": row["search"],
                    "Variant boundary": row["variant"],
                }
                for label in (
                    "Canonical route", "Read this case when", "Primary defect",
                    "Exploit primitive/result", "Search terms",
                    "Version/protection clue", "Variant boundary",
                ):
                    with self.subTest(challenge=challenge, label=label):
                        field = re.search(rf"> \*\*{re.escape(label)}:\*\* (.+)", card)
                        self.assertIsNotNone(field, challenge)
                        if label in expected:
                            self.assertEqual(field.group(1).strip(), expected[label])
                with self.subTest(challenge=challenge, part="index"):
                    self.assertIn(f"](#{challenge})", index.group(1))
                    self.assertIn(row["route"], index.group(1))

    def test_source_red_flag_router_has_28_resolving_rows(self):
        text = SOURCE_RED_FLAGS.read_text(encoding="utf-8")
        for section in ("## How To Use", "## Red-Flag Router"):
            self.assertIn(section, text)
        router = re.search(
            r"^## Red-Flag Router\s*$(.*?)(?=^## Pattern )", text, re.M | re.S,
        )
        self.assertIsNotNone(router)
        rows = [
            line for line in router.group(1).splitlines()
            if line.startswith("|") and "---" not in line
            and not line.startswith("| Pattern |")
        ]
        self.assertEqual(len(rows), 28)
        anchors = heading_anchors(SOURCE_RED_FLAGS)
        for line in rows:
            cells = [cell.strip() for cell in line.strip("|").split("|")]
            self.assertEqual(len(cells), 4, line)
            link = re.search(r"\]\(#([^)]+)\)", cells[0])
            self.assertIsNotNone(link, line)
            self.assertIn(link.group(1), anchors)
            self.assertTrue(all(cells[1:]), line)


class TestSourceManifest(unittest.TestCase):
    def setUp(self):
        if not os.environ.get("PWNABLE_TW_SOURCE"):
            self.skipTest("PWNABLE_TW_SOURCE is not set")

    def test_source_hashes_line_counts_and_headings(self):
        configured = Path(os.environ["PWNABLE_TW_SOURCE"]).resolve()
        source_root = (
            configured
            if configured.name == "pwnable.tw"
            else configured / "linux-userland-ctf/pwnable.tw"
        )
        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        hashed = {
            row["source_path"].removeprefix("linux-userland-ctf/pwnable.tw/"): row
            for row in manifest["source_files"]
        }
        actual_paths = {
            str(path.relative_to(source_root)) for path in source_root.rglob("*.md")
        }
        self.assertEqual(set(hashed), actual_paths)

        for relative, row in hashed.items():
            data = (source_root / relative).read_bytes()
            line_count = data.count(b"\n") + (0 if data.endswith(b"\n") or not data else 1)
            with self.subTest(source=relative):
                self.assertEqual(row["sha256"], hashlib.sha256(data).hexdigest())
                self.assertEqual(row["bytes"], len(data))
                self.assertEqual(row["lines"], line_count)

        actual_headings = set()
        for relative in actual_paths:
            text = (source_root / relative).read_text(encoding="utf-8")
            for line_number, level, title in headings(strip_fenced(text)):
                actual_headings.add(
                    (
                        f"linux-userland-ctf/pwnable.tw/{relative}",
                        line_number,
                        f"{'#' * level} {title}",
                    )
                )
        manifest_headings = {
            (row["source_path"], row["source_line"], row["source_heading"])
            for row in manifest["coverage"]
        }
        self.assertEqual(manifest_headings, actual_headings)


if __name__ == "__main__":
    unittest.main()
