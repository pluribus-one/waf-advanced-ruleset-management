import csv
import random

INPUT_FILE = "input.csv"

LEGITIMATE_FILE = "legitimate.csv"
MALICIOUS_FILE = "malicious.csv"

TRAIN_RATIO = 0.8
RANDOM_SEED = 42


def split_row(row):
    """
    Dataset-specific classification logic.

    Return:
        "legitimate" -> row belongs to the legitimate dataset
        "malicious"  -> row belongs to the malicious dataset
    """

    attack_type = row["attack_type"].strip()

    if attack_type == "norm":
        return "legitimate"

    return "malicious"


def write_csv(path, fieldnames, rows):
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def train_test_split(rows, train_ratio=0.8, seed=42):
    """
    Generic train/test split logic.
    """

    rows = list(rows)

    random.Random(seed).shuffle(rows)

    split_index = int(len(rows) * train_ratio)

    train_rows = rows[:split_index]
    test_rows = rows[split_index:]

    return train_rows, test_rows


# ------------------------------------------------------------------
# Load and classify rows
# ------------------------------------------------------------------

legitimate_rows = []
malicious_rows = []

with open(INPUT_FILE, "r", encoding="utf-8", newline="") as infile:

    reader = csv.DictReader(infile)
    fieldnames = reader.fieldnames

    for row in reader:

        dataset = split_row(row)

        if dataset == "legitimate":
            legitimate_rows.append(row)

        elif dataset == "malicious":
            malicious_rows.append(row)

        else:
            raise ValueError(f"Unknown dataset type: {dataset}")


# ------------------------------------------------------------------
# Generic train/test split
# ------------------------------------------------------------------

legitimate_train, legitimate_test = train_test_split(
    legitimate_rows,
    train_ratio=TRAIN_RATIO,
    seed=RANDOM_SEED
)

malicious_train, malicious_test = train_test_split(
    malicious_rows,
    train_ratio=TRAIN_RATIO,
    seed=RANDOM_SEED
)


# ------------------------------------------------------------------
# Save datasets
# ------------------------------------------------------------------

write_csv("legitimate_train.csv", fieldnames, legitimate_train)
write_csv("legitimate_test.csv", fieldnames, legitimate_test)

write_csv("malicious_train.csv", fieldnames, malicious_train)
write_csv("malicious_test.csv", fieldnames, malicious_test)


print("Completed successfully.")