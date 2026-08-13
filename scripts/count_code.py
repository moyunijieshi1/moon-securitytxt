from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

core_files = [
    "model.mbt",
    "error.mbt",
    "limits.mbt",
    "datetime.mbt",
    "field.mbt",
    "parser.mbt",
    "signed.mbt",
    "validator.mbt",
    "context.mbt",
    "serializer.mbt",
    "audit.mbt",
]

test_files = sorted(p for p in ROOT.glob("test_*.mbt"))
cli_example_files = sorted((ROOT / "cmd").rglob("*.mbt")) + sorted((ROOT / "examples").rglob("*.mbt"))


def count(paths):
    total = 0
    for p in paths:
        total += len(p.read_text(encoding="utf-8").splitlines())
    return total


core_paths = [ROOT / name for name in core_files]
test_paths = test_files
other_paths = cli_example_files
all_paths = core_paths + test_paths + other_paths

named_tests = 0
for p in test_paths:
    for line in p.read_text(encoding="utf-8").splitlines():
        if line.strip().startswith('test "'):
            named_tests += 1

# Deterministic property cases (see test_property.mbt for the grids).
property_cases = 72 + 90 + 24 + 40 + 25 + 25 + 150

# Deterministic truncation cases: the fixtures the truncation tests use.
VALID = (
    "# A valid example security.txt\n"
    "Contact: mailto:security@example.com\n"
    "Expires: 2027-01-01T00:00:00.000Z\n"
    "Preferred-Languages: en, de\n"
)
SIGNED = (
    "-----BEGIN PGP SIGNED MESSAGE-----\n"
    "Hash: SHA256\n\n"
    "Contact: mailto:security@example.com\n"
    "Expires: 2027-01-01T00:00:00Z\n"
    "-----BEGIN PGP SIGNATURE-----\n\n"
    "iQEzBAABCAAdFiEEfake-signature-block\n"
    "=\n"
    "-----END PGP SIGNATURE-----\n"
)
positions = (len(VALID) + 7) // 8
truncation_cases = (
    (len(VALID) + 1)              # every prefix of the valid document
    + positions * 4               # single-byte mutations
    + positions * 5               # UTF-8 byte grids
    + (len(SIGNED) + 1) // 2 + 1  # sampled prefixes of the signed envelope
)

todo_words = ("TO" + "DO", "FIX" + "ME")
todo_count = 0
for p in ROOT.rglob("*"):
    if p.is_file() and "_build" not in p.parts and p.suffix in {".mbt", ".md", ".ps1", ".py"}:
        data = p.read_text(encoding="utf-8", errors="ignore")
        todo_count += data.count(todo_words[0]) + data.count(todo_words[1])

print(f"core LOC: {count(core_paths)}")
print(f"test LOC: {count(test_paths)}")
print(f"CLI/examples LOC: {count(other_paths)}")
print(f"total MoonBit LOC: {count(all_paths)}")
print(f"named tests: {named_tests}")
print(f"property cases: {property_cases}")
print(f"truncation cases: {truncation_cases}")
print(f"deterministic cases total: {property_cases + truncation_cases}")
print(f"{todo_words[0]}/{todo_words[1]} count: {todo_count}")
print("runtime dependencies: MoonBit standard library only")
