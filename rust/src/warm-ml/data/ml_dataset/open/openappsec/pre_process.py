import json
import random
from pathlib import Path


LEGITIMATE_DIR = "Legitimate"
MALICIOUS_DIR = "Malicious"

TRAIN_RATIO = 0.8
RANDOM_SEED = 42

MAX_BODY_SIZE = 100_000
MAX_URL_SIZE = 8_192
MAX_NON_ASCII_RATIO = 0.30


def is_suspicious_text(text: str) -> bool:
    if not text:
        return False

    if len(text) > MAX_BODY_SIZE:
        return True

    non_ascii = sum(1 for c in text if ord(c) > 127)

    if non_ascii / len(text) > MAX_NON_ASCII_RATIO:
        return True

    non_printable = sum(
        1
        for c in text
        if ord(c) < 32 and c not in ("\n", "\r", "\t")
    )

    if non_printable / len(text) > 0.05:
        return True

    return False


def is_valid_request(req):
    url = req.get("url", "") or ""
    body = req.get("data", "") or ""

    if len(url) > MAX_URL_SIZE:
        return False

    if is_suspicious_text(body):
        return False

    return True


def normalize_request(req: dict) -> dict:
    return {
        "method": req.get("method", "") or "",
        "url": req.get("url", "") or "",
        "headers": req.get("headers", {}) or {},
        "data": req.get("data", "") or ""
    }


def load_dataset(directory):
    rows = []

    loaded = 0
    skipped = 0

    for json_file in Path(directory).rglob("*.json"):

        try:
            with open(json_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            if not isinstance(data, list):
                print(f"Skipping {json_file}: root is not a list")
                continue

            for req in data:

                if not isinstance(req, dict):
                    skipped += 1
                    continue

                if not is_valid_request(req):
                    skipped += 1
                    continue

                rows.append(normalize_request(req))
                loaded += 1

        except Exception as e:
            print(f"Error reading {json_file}: {e}")

    print(f"{directory}: loaded={loaded}, skipped={skipped}")

    return rows


def train_test_split(rows, train_ratio=0.8, seed=42):
    rows = list(rows)
    random.Random(seed).shuffle(rows)

    split_index = int(len(rows) * train_ratio)

    return rows[:split_index], rows[split_index:]


def write_json(path, rows):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(rows, f, ensure_ascii=False, indent=2)


# --------------------------------------------------
# Load datasets
# --------------------------------------------------

legitimate_rows = load_dataset(LEGITIMATE_DIR)
malicious_rows = load_dataset(MALICIOUS_DIR)

# --------------------------------------------------
# Train/Test split
# --------------------------------------------------

legitimate_train, legitimate_test = train_test_split(
    legitimate_rows,
    TRAIN_RATIO,
    RANDOM_SEED
)

malicious_train, malicious_test = train_test_split(
    malicious_rows,
    TRAIN_RATIO,
    RANDOM_SEED
)

# --------------------------------------------------
# Save JSON files
# --------------------------------------------------

write_json("legitimate_train.json", legitimate_train)
write_json("legitimate_test.json", legitimate_test)
write_json("malicious_train.json", malicious_train)
write_json("malicious_test.json", malicious_test)

print()
print("Completed successfully")
print(
    f"legitimate: train={len(legitimate_train)}, test={len(legitimate_test)}"
)
print(
    f"malicious: train={len(malicious_train)}, test={len(malicious_test)}"
)