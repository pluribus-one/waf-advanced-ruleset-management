import csv
import re
import random
from pathlib import Path

ROOT = Path("PayloadsAllTheThings")

TRAIN_RATIO = 0.8
RANDOM_SEED = 42

EXCLUDED = {
    "sql injection",
    "mssql injection",
    "mysql injection",
    "postgresql injection",
    "sqlite injection",
    "oraclesql injection",
    "cassandra injection",
    "db2 injection",
    "insecure source code management",
    "web cache deception",
    "mass assignment",
    "insecure deserialization",
    "json web token",
    "dependency confusion",
    "java rmi",
    "upload insecure files",
    "brute force rate limit",
    "ldap injection",
    "api key leaks",
    "account takeover"
}

TEXT_PATTERNS = (
    "*.txt",
    "*.lst",
    "*.payload",
    "*.fuzz",
    "*.dict",
    "*.wordlist",
)

HTTP_METHOD_RE = re.compile(r"^(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\s", re.I)
HTTP_HEADER_RE = re.compile(r"^[A-Za-z0-9\-]+:\s")
COMMENT_RE = re.compile(r"^\s*(#|//|/\*|\*)")
CODE_RE = re.compile(r"^\s*(import |from .* import |class |def |function )", re.I)

SQLI_RE = re.compile(
    r"""
    union\s+select|
    information_schema|
    pg_sleep\s*\(|
    sleep\s*\(|
    benchmark\s*\(|
    load_file\s*\(|
    xp_cmdshell|
    into\s+outfile|
    group_concat\s*\(|
    waitfor\s+delay|
    select\s+.+\s+from
    """,
    re.I | re.X,
)

BAD_EXACT = {
    "",
    "---",
    "```",
    "payload",
    "payloads",
    "example",
    "examples",
    "description",
    "references",
    "reference",
}


def normalize_label(name):
    return name.lower().replace(" ", "_").replace("-", "_")


def clean(text):
    text = text.strip()
    text = text.replace("\x00", "")
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def is_sqli(text):
    return bool(SQLI_RE.search(text))


def obvious_noise(line):
    if not line:
        return True
    if len(line) < 3:
        return True
    if len(line) > 8000:
        return True
    if line.lower() in BAD_EXACT:
        return True
    if COMMENT_RE.match(line):
        return True
    if HTTP_METHOD_RE.match(line):
        return True
    if HTTP_HEADER_RE.match(line):
        return True
    if line.startswith("HTTP/"):
        return True
    if CODE_RE.match(line):
        return True
    if line.startswith("|---"):
        return True
    return False


def extract_code_blocks(text):
    return re.findall(r"```(?:[^\n]*)\n(.*?)```", text, flags=re.S)


def extract_inline_code(text):
    return re.findall(r"`([^`\n]{3,5000})`", text)


def process_candidate(candidate):
    out = []

    candidate = candidate.strip()
    if not candidate:
        return out

    if (
        len(candidate.splitlines()) > 1
        and len(candidate) < 4000
        and not obvious_noise(candidate)
        and not is_sqli(candidate)
    ):
        out.append(clean(candidate))

    for line in candidate.splitlines():
        line = clean(line)

        if obvious_noise(line):
            continue
        if is_sqli(line):
            continue

        out.append(line)

    return out


def extract_from_markdown(path):
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return []

    payloads = []

    for block in extract_code_blocks(text):
        payloads.extend(process_candidate(block))

    for inline in extract_inline_code(text):
        payloads.extend(process_candidate(inline))

    return payloads


def extract_from_wordlist(path):
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return []

    payloads = []

    for line in text.splitlines():
        line = clean(line)

        if obvious_noise(line):
            continue
        if is_sqli(line):
            continue

        payloads.append(line)

    return payloads


# ----------------------------
# BUILD DATASET
# ----------------------------

rows = set()

for category in ROOT.iterdir():

    if not category.is_dir():
        continue

    category_name = category.name.lower().strip()

    if category_name in EXCLUDED:
        continue

    label = normalize_label(category.name)

    print(f"[+] {category.name}")

    for md in category.rglob("README.md"):
        for payload in extract_from_markdown(md):
            rows.add((payload, label))

    for pattern in TEXT_PATTERNS:
        for f in category.rglob(pattern):
            for payload in extract_from_wordlist(f):
                rows.add((payload, label))


rows = list(rows)

print()
print(f"Totale payload: {len(rows)}")


# ----------------------------
# SPLIT
# ----------------------------

random.Random(RANDOM_SEED).shuffle(rows)

split_idx = int(len(rows) * TRAIN_RATIO)

train_rows = rows[:split_idx]
test_rows = rows[split_idx:]


# ----------------------------
# WRITE CSV
# ----------------------------

def write_csv(path, data):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["payload", "label"])
        writer.writerows(data)


write_csv("malicious_train.csv", train_rows)
write_csv("malicious_test.csv", test_rows)

print()
print("Completed successfully")
print(f"train={len(train_rows)} test={len(test_rows)}")