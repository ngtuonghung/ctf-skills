"""Validate the pwnable.tw migration into ctf-pwn with full content fidelity."""

import os
import re
import unittest
from pathlib import Path
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
PWNABLE_TW_DIR = REPO_ROOT / "ctf-pwn/references/linux-userland/pwnable-tw"
README_PATH = PWNABLE_TW_DIR / "README.md"
DEFAULT_SOURCE_DIR = Path("/home/hungnt/pwn-knowledge-base/linux-userland-ctf/pwnable.tw")

EXPECTED_CHALLENGES = {
    "3x17", "alive_note", "applestore", "babyallocator", "babystack",
    "bash", "bash_revenge", "bookwriter", "bounty_program_a", "bounty_program_b",
    "break_out", "calc", "caov", "criticalheap", "criticalheap_pp",
    "de_aslr", "death_note", "digimon", "dubblesort", "food_store",
    "ghost_party", "hacknote", "heap_paradise", "hitcon_ftp", "kidding",
    "mno2", "omegago", "orw", "printable", "re_alloc",
    "re_alloc_revenge", "seccomptools", "secret_garden", "secret_of_my_heart",
    "seethefile", "silver_bullet", "spirited_away", "starbound", "start",
    "stupid_boss", "tcache_tear", "unexploitable", "wannaheap",
}

SYNTHETIC_FILES = [
    "allocator-file-cases.md",
    "heap-object-cases.md",
    "restricted-shell-cases.md",
    "shellcode-sandbox-cases.md",
    "stack-control-cases.md",
    "source-red-flags.md",
    "migration-manifest.json",
]

FRONTMATTER_FIELDS = {
    "tags", "platform", "points", "arch", "libc", "relro", "canary", "nx", "pie", "description",
}


class TestPwnableTwMigration(unittest.TestCase):
    def test_all_43_challenges_exist(self):
        actual_files = {
            p.stem for p in PWNABLE_TW_DIR.glob("*.md")
            if p.name != "README.md"
        }
        self.assertEqual(actual_files, EXPECTED_CHALLENGES)
        self.assertEqual(len(actual_files), 43)

    def test_patterns_archive_excluded(self):
        patterns_archive = PWNABLE_TW_DIR / "patterns_archive.md"
        self.assertFalse(patterns_archive.exists(), "patterns_archive.md must be excluded")
        
        readme_text = README_PATH.read_text(encoding="utf-8")
        self.assertNotIn("patterns_archive", readme_text)

    def test_synthetic_files_removed(self):
        for synth in SYNTHETIC_FILES:
            path = PWNABLE_TW_DIR / synth
            self.assertFalse(path.exists(), f"Synthetic file {synth} should be removed")

    def test_frontmatter_schema(self):
        for chall in EXPECTED_CHALLENGES:
            file_path = PWNABLE_TW_DIR / f"{chall}.md"
            self.assertTrue(file_path.is_file(), f"File {file_path} missing")
            content = file_path.read_text(encoding="utf-8")
            self.assertTrue(content.startswith("---"), f"{chall}.md missing frontmatter start")
            parts = content.split("---", 2)
            self.assertGreaterEqual(len(parts), 3, f"{chall}.md malformed frontmatter")
            fm = yaml.safe_load(parts[1])
            self.assertIsInstance(fm, dict, f"{chall}.md frontmatter not a dict")
            for req in FRONTMATTER_FIELDS:
                self.assertIn(req, fm, f"{chall}.md missing required frontmatter key: {req}")
            self.assertEqual(fm["platform"], "pwnable.tw")
            self.assertIsInstance(fm["tags"], list)
            self.assertGreater(len(fm["tags"]), 0)

    def test_breadcrumb_link_in_challenges(self):
        for chall in EXPECTED_CHALLENGES:
            file_path = PWNABLE_TW_DIR / f"{chall}.md"
            content = file_path.read_text(encoding="utf-8")
            self.assertIn("[← Back to pwnable.tw Challenge Index](README.md)", content)

    def test_readme_structure_and_links(self):
        self.assertTrue(README_PATH.is_file())
        text = README_PATH.read_text(encoding="utf-8")
        
        # Verify single unified table header
        self.assertIn("# pwnable.tw Challenge Directory", text)
        self.assertIn("| Challenge | Points | Arch | Libc | Protections | Tags | Observed Clues & Triggers | Root Cause Defects | Exploitation Chains & Keywords |", text)
        
        # Verify table rows count (exactly 43 challenge rows + header + separator = 45 rows)
        table_rows = [line for line in text.splitlines() if line.startswith("| [`")]
        self.assertEqual(len(table_rows), 43)
            
        # Verify all 43 challenges are linked
        for chall in EXPECTED_CHALLENGES:
            self.assertIn(f"[`{chall}`]({chall}.md)", text)
            
        # Verify local markdown links in README.md resolve
        links = re.findall(r"\[([^\]]+)\]\(([^)]+)\)", text)
        for label, target in links:
            if target.startswith("http") or target.startswith("#"):
                continue
            file_part = target.split("#")[0]
            target_path = PWNABLE_TW_DIR / file_part
            self.assertTrue(target_path.exists(), f"Broken link in README.md: {target} (label: {label})")

    def test_skill_md_integration(self):
        skill_text = (REPO_ROOT / "ctf-pwn/SKILL.md").read_text(encoding="utf-8")
        self.assertIn("references/linux-userland/pwnable-tw/README.md", skill_text)
        self.assertNotIn("source-red-flags.md", skill_text)

    def test_content_fidelity_against_source(self):
        source_dir = Path(os.environ.get("PWNABLE_TW_SOURCE", DEFAULT_SOURCE_DIR))
        if not source_dir.is_dir():
            self.skipTest(f"Source directory {source_dir} not available")

        for chall in EXPECTED_CHALLENGES:
            src_file = source_dir / chall / "README.md"
            self.assertTrue(src_file.is_file(), f"Source file {src_file} missing")
            src_text = src_file.read_text(encoding="utf-8")
            dest_text = (PWNABLE_TW_DIR / f"{chall}.md").read_text(encoding="utf-8")
            
            # Remove the inserted breadcrumb link and compare
            cleaned_dest = dest_text.replace("\n\n[← Back to pwnable.tw Challenge Index](README.md)", "")
            self.assertEqual(
                src_text.strip(),
                cleaned_dest.strip(),
                f"Content difference found in migrated file {chall}.md",
            )


if __name__ == "__main__":
    unittest.main()
