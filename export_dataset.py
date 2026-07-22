# EXPORT_DATASET.PY

import firebase_admin
from firebase_admin import credentials, firestore
import pandas as pd
from datetime import datetime
import os
import re
import sys

# =========================
# FIREBASE
# =========================

cred = credentials.Certificate(
    "uthm-quishread-firebase-adminsdk-fbsvc-8a04c1071f.json"
)

try:
    firebase_admin.get_app()
except ValueError:
    firebase_admin.initialize_app(cred)

db = firestore.client()

merge = False

if len(sys.argv) > 1:

    merge = (
        sys.argv[1].lower()
        == "true"
    )

def merge_with_dataset(old_dataset_path, scan_df):

    old_df = pd.read_csv(
        old_dataset_path
    )

    old_df = old_df.loc[
        :,
        ~old_df.columns.str.contains(
            "^Unnamed"
        )
    ]

    old_df = old_df[
        ["URL", "label"]
    ]

    scan_df = scan_df[
        ["URL", "label"]
    ]

    merged_df = pd.concat(
        [old_df, scan_df],
        ignore_index=True
    )

    before = len(merged_df)

    merged_df.drop_duplicates(
        subset=["URL"],
        inplace=True
    )

    after = len(merged_df)

    duplicates_removed = (
        before - after
    )

    return merged_df, duplicates_removed

def get_next_version():

    files = os.listdir("datasets")

    versions = []

    for file in files:

        match = re.match(
            r"QUISHREAD_dataset_v(\d+)\.csv",
            file
        )

        if match:

            versions.append(
                int(match.group(1))
            )

    if not versions:

        return 1

    return max(versions) + 1

# =========================
# FILE NAME
# =========================

date_str = datetime.now().strftime("%Y%m%d")

filename = f"QUISHREAD_dataset_{date_str}.csv"

# =========================
# READ SCANS COLLECTION
# =========================

docs = db.collection("scans").stream()

rows = []

for doc in docs:

    data = doc.to_dict()

    url = str(
        data.get("url", "")
    ).strip()

    result = str(
        data.get("finalResult", "")
    ).strip().upper()

    if not url:
        continue

    if result == "SAFE":

        label = 1

    elif result == "SUSPICIOUS":

        label = 0

    else:

        continue

    rows.append({
        "URL": url,
        "label": label
    })

# =========================
# CREATE DATAFRAME
# =========================

before_count = len(rows)

df = pd.DataFrame(rows)

# =========================
# REMOVE DUPLICATE URLS
# =========================

df.drop_duplicates(
    subset=["URL"],
    inplace=True
)

after_count = len(df)

duplicates_removed = (
    before_count - after_count
)

# =========================
# EXPORT CSV
# =========================

#df.to_csv(
#    filename,
#    index=False
#)

# =========================
# EXPORT DATASET
# =========================

if merge:

    merged_df, dup = merge_with_dataset(
        "datasets/LegitPhish_dataset.csv",
        df
    )

    version = get_next_version()

    output_file = (
        f"datasets/QUISHREAD_dataset_v{version}.csv"
    )

    merged_df.to_csv(
        output_file,
        index=False
    )

else:

    output_file = (
        "datasets/QUISHREAD_scan_results.csv"
    )

    df.to_csv(
        output_file,
        index=False
    )

    dup = 0
    
# =========================
# OUTPUT
# =========================

print("\n================================")
print("CSV GENERATED SUCCESSFULLY")
print("================================")
print("Scan Records        :", before_count)
print("Unique Scan URLs    :", after_count)
print("Merged Duplicates   :", dup)
print(
    "CSV File             :",
    os.path.basename(output_file)
)
print("================================")