"""Brand check: no real company names in code/tests/demos/docs.

The blocklist is stored as SHA-256 hashes only (never plain names).
knowledge/ is excluded: crediting a vendor as a source by name is allowed
there. Scans .py/.md/.yml files, skipping knowledge/, .git and caches.
"""
import hashlib
import pathlib
import re
import sys

# SHA-256 hashes of lowercased brand tokens. Plain names are intentionally
# absent from this file.
BLOCKED_HASHES = {
    "712c9df0397999977db3d6223cddf2d8eddce63c1cde2773242f2d805f14cacf",
    "6c4e02093d91827019c136ebe2d063fecee73cb9e56dcdb96b0a3df52f38682d",
    "50c1eb1290b1e4e0e231d60dcca45d9e0a5d402c651f12276537e7a3cbabc026",
    "1264de97e7d46db15cc30796eeb6138a68431cd581ba51706517c86a65821278",
    "7c2dddc2c2580ab843ee18b40ed448ac82ef5a01435e525248b6cea29930da1e",
    "1e3a83b84b726c6c175acddd78d0e7a497df3c31f6e75606846a7e3b92200952",
    "3e808ece8227f5d4fda47690aed90895fc56881b6335d39ace7e8078b240164c",
    "4d748ebd71af03a7c325a5ecef86e3768b71597ba3c08dc26624bfdbd84a0a34",
    "de5a1adf4fedcce1533915edc60177547f1057b61b7119fd130e1f7428705f73",
}


def main():
    root = pathlib.Path(".")
    hits = []
    scanned = 0
    skip_dirs = {"knowledge", ".git", "__pycache__", ".pytest_cache", ".venv"}
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix not in {".py", ".md", ".yml",
                                                     ".yaml", ".txt"}:
            continue
        if any(part in skip_dirs for part in path.parts):
            continue
        scanned += 1
        text = path.read_text(errors="ignore").lower()
        for token in re.findall(r"[a-z0-9]+(?:-[a-z0-9]+)?", text):
            if hashlib.sha256(token.encode()).hexdigest() in BLOCKED_HASHES:
                hits.append(str(path))
                break
    if hits:
        print("BRAND CHECK FAILED:")
        for path in hits:
            print("  " + path)
        return 1
    print("brand check clean: %d files scanned" % scanned)
    return 0


if __name__ == "__main__":
    sys.exit(main())
