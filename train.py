# TRAIN.PY
import pandas as pd
import pickle
import os
import re
import math
import sys


from datetime import datetime
from urllib.parse import urlparse

import seaborn as sns
import matplotlib.pyplot as plt

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier

from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix
)

# ==================================
# TIMESTAMP
# ==================================

timestamp = datetime.now().strftime(
    "%Y%m%d_%H%M%S"
)

save_dir = os.path.join(
    "results",
    timestamp
)

os.makedirs(
    save_dir,
    exist_ok=True
)

os.makedirs(
    "models",
    exist_ok=True
)

# ==================================
# LOAD DATASET
# ==================================

dataset_path = sys.argv[1]

data = pd.read_csv(
    dataset_path,
    low_memory=False
)

print("==================================")
print("DATASET LOADED")
print("==================================")

print("Total Rows:", len(data))

# ==================================
# CLEAN DATASET
# ==================================

data.dropna(
    subset=[
        "URL",
        "label"
    ],
    inplace=True
)

data.drop_duplicates(
    subset=["URL"],
    inplace=True
)

print("Rows After Cleaning:", len(data))

print("\nLABEL DISTRIBUTION")
print(data["label"].value_counts())

print("\nSAMPLE LEGITIMATE URLS")
print(
    data[
        data["label"] == 1
    ]["URL"].head(20)
)

print("\nSAMPLE PHISHING URLS")
print(
    data[
        data["label"] == 0
    ]["URL"].head(20)
)

# ==================================
# FEATURE EXTRACTION
# ==================================

def calculate_entropy(text):

    if len(text) == 0:
        return 0

    probabilities = [

        float(text.count(c)) / len(text)

        for c in dict.fromkeys(text)

    ]

    entropy = -sum(

        p * math.log2(p)

        for p in probabilities

    )

    return entropy


SHORTENED_DOMAINS = [
    "bit.ly",
    "tinyurl.com",
    "goo.gl",
    "ow.ly",
    "cutt.ly",
    "forms.gle",
    "t.co",
    "is.gd"
]

SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "secure",
    "account",
    "update",
    "password",
    "bank",
    "paypal",
    "signin",
    "confirm"
]


def extract_features(url):

    url = str(url)

    url = str(url).strip().rstrip("/")
    
    parsed = urlparse(url)
    
    domain = parsed.netloc.lower()

    # Domain Length
    domain_length = len(domain)

    # Path Length
    path_length = len(parsed.path)

    # Query Count
    query_count = len(
        parsed.query.split("&")
    ) if parsed.query else 0

    # Special Character Count
    special_char_count = len(
        re.findall(
            r'[^a-zA-Z0-9]',
            url
        )
    )

    # TLD Length
    parts = domain.split(".")

    if len(parts) > 1:

        tld_length = len(
            parts[-1]
        )

    else:

        tld_length = 0

    # Suspicious Keyword Count
    keyword_count = 0

    for keyword in SUSPICIOUS_KEYWORDS:

        if keyword in url.lower():

            keyword_count += 1

    # URL Length
    url_length = len(url)

    # URL Depth
    url_depth = len(

        [x for x in parsed.path.split("/")
         if x]

    )

    # Have IP Address
    has_ip = 1 if re.search(

        r'(\d{1,3}\.){3}\d{1,3}',

        domain

    ) else 0

    # Have @ Symbol
    has_at = 1 if "@" in url else 0

    # Double Slash Redirect
    double_slash_redirect = (

        1

        if url.rfind("//") > 7

        else 0

    )

    # Is URL scheme HTTPS
    is_https = 1 if parsed.scheme == "https" else 0

    # Port number
    port = parsed.port if parsed.port else 0

    # Fragment Length
    fragment_length = len(parsed.fragment)

    # Hyphen in Domain
    has_hyphen = (

        1

        if "-" in domain

        else 0

    )

    # Subdomain Count
    subdomain_count = domain.count(".")

    # Digit Count
    digit_count = sum(

        c.isdigit()

        for c in url

    )

    # URL Entropy
    url_entropy = calculate_entropy(url)

    return {

        "url_length":
            url_length,

        "url_depth":
            url_depth,

        "has_ip":
            has_ip,

        "has_at":
            has_at,

        "double_slash_redirect":
            double_slash_redirect,

        

        "has_hyphen":
            has_hyphen,

        "subdomain_count":
            subdomain_count,

        "digit_count":
            digit_count,

        "url_entropy":
            round(
                url_entropy,
                6
            ),

        "domain_length":
            domain_length,

        "path_length":
            path_length,

        "query_count":
            query_count,

        "special_char_count":
            special_char_count,

        "tld_length":
            tld_length,

        "keyword_count":
            keyword_count,

        "port":
            port,

        "fragment_length":
            fragment_length,

        "is_https":
            is_https,
    }

# ==================================
# EXTRACT FEATURES
# ==================================

print("\n==================================")
print("EXTRACTING FEATURES")
print("==================================")

feature_list = []

for url in data["URL"]:

    try:

        feature_list.append(
            extract_features(
                url
            )
        )

    except:

        continue

X = pd.DataFrame(
    feature_list
)

y = data["label"].iloc[
    :len(X)
]

print("Features Created")

print(X.head())

print("\n==================================")
print("FEATURES USED")
print("==================================")

for feature in X.columns:

    print(feature)

# ==================================
# TRAIN TEST SPLIT
# ==================================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y,
    shuffle=True
)

print("\n==================================")
print("SPLIT INFORMATION")
print("==================================")

print(
    "Training Samples:",
    len(X_train)
)

print(
    "Testing Samples:",
    len(X_test)
)

# ==================================
# RANDOM FOREST
# ==================================

rf_model = RandomForestClassifier(
    n_estimators=200,
    max_depth=20,
    min_samples_split=5,
    min_samples_leaf=2,
    random_state=42,
    n_jobs=-1
)

# ==================================
# TRAIN MODEL
# ==================================

print("\n==================================")
print("TRAINING MODEL")
print("==================================")

rf_model.fit(
    X_train,
    y_train
)

print(
    "Training Complete"
)

# ==================================
# TRAINING PREDICTION
# ==================================

y_train_pred = rf_model.predict(
    X_train
)

train_acc = accuracy_score(
    y_train,
    y_train_pred
)

# ==================================
# TESTING PREDICTION
# ==================================

y_pred = rf_model.predict(
    X_test
)

test_acc = accuracy_score(
    y_test,
    y_pred
)

# ==================================
# TRAINING CONFUSION MATRIX
# ==================================

cm_train = confusion_matrix(
    y_train,
    y_train_pred
)

TN_tr, FP_tr, FN_tr, TP_tr = (
    cm_train.ravel()
)

# ==================================
# TESTING CONFUSION MATRIX
# ==================================

cm_test = confusion_matrix(
    y_test,
    y_pred
)

TN, FP, FN, TP = (
    cm_test.ravel()
)

# ==================================
# CLASSIFICATION REPORT
# ==================================

report = classification_report(
    y_test,
    y_pred,
    target_names=[
        "Phishing 0",
        "Legitimate 1"
    ],
    digits=4
)

print("\n==================================")
print("CLASSIFICATION REPORT")
print("==================================")

print(report)

print("\n==================================")
print("FEATURE IMPORTANCE")
print("==================================")

importance_df = pd.DataFrame({

    "Feature": X.columns,

    "Importance":
        rf_model.feature_importances_

})

importance_df = importance_df.sort_values(

    by="Importance",

    ascending=False

)

print(
    importance_df
)

# ==================================
# TRAINING CM IMAGE
# ==================================

train_labels = [
    [
        f"TN\n{TN_tr}",
        f"FP\n{FP_tr}"
    ],
    [
        f"FN\n{FN_tr}",
        f"TP\n{TP_tr}"
    ]
]

plt.figure(figsize=(8,6))

sns.heatmap(
    cm_train,
    annot=train_labels,
    fmt='',
    cmap='Blues',
    xticklabels=[
        "Suspicious",
        "Legitimate"
    ],
    yticklabels=[
        "Suspicious",
        "Legitimate"
    ]
)

plt.xlabel("Predicted")
plt.ylabel("Actual")

plt.title(
    f"Training Confusion Matrix\nAccuracy: {train_acc*100:.2f}%"
)

plt.tight_layout()

plt.savefig(
    os.path.join(
        save_dir,
        "training_confusion_matrix.png"
    ),
    dpi=300
)

plt.close()

# ==================================
# TESTING CM IMAGE
# ==================================

test_labels = [
    [
        f"TN\n{TN}",
        f"FP\n{FP}"
    ],
    [
        f"FN\n{FN}",
        f"TP\n{TP}"
    ]
]

plt.figure(figsize=(8,6))

sns.heatmap(
    cm_test,
    annot=test_labels,
    fmt='',
    cmap='Blues',
    xticklabels=[
        "Suspicious",
        "Legitimate"
    ],
    yticklabels=[
        "Suspicious",
        "Legitimate"
    ]
)

plt.xlabel("Predicted")
plt.ylabel("Actual")

plt.title(
    f"Testing Confusion Matrix\nAccuracy: {test_acc*100:.2f}%"
)

plt.tight_layout()

plt.savefig(
    os.path.join(
        save_dir,
        "testing_confusion_matrix.png"
    ),
    dpi=300
)

plt.close()

# ==================================
# CLASSI# ==================================
# CLASSIFICATION REPORT IMAGE
# ==================================

fig, ax = plt.subplots(
    figsize=(10,6)
)

ax.axis("off")

summary = (
    "Classification Report:\n\n"
    + report +
    f"\nModel Training Completed Successfully.\n"
    f"Accuracy: {test_acc*100:.2f}%"
)

ax.text(
    0.03,
    0.95,
    summary,
    fontsize=12,
    family="monospace",
    verticalalignment="top",
    bbox=dict(
        facecolor="white",
        edgecolor="black",
        boxstyle="square,pad=1"
    )
)

plt.tight_layout()

plt.savefig(
    os.path.join(
        save_dir,
        "classification_report.png"
    ),
    dpi=300,
    bbox_inches="tight"
)

plt.close()

# ==================================
# FEATURE IMPORTANCE IMAGE
# ==================================

importance_df = pd.DataFrame({

    "Feature": X.columns,

    "Importance":
        rf_model.feature_importances_

})

importance_df = importance_df.sort_values(

    by="Importance",

    ascending=True

)

plt.figure(
    figsize=(10,6)
)

plt.barh(

    importance_df["Feature"],

    importance_df["Importance"]

)

plt.title(
    "Random Forest Feature Importance"
)

plt.xlabel(
    "Importance Score"
)

plt.tight_layout()

plt.savefig(

    os.path.join(

        save_dir,

        "feature_importance.png"

    ),

    dpi=300

)

plt.close()

# ==================================
# OVERFITTING CHECK
# ==================================

gap = train_acc - test_acc

print("\n==================================")
print("MODEL ANALYSIS")
print("==================================")

print(
    f"Training Accuracy : {train_acc*100:.2f}%"
)

print(
    f"Testing Accuracy : {test_acc*100:.2f}%"
)

print(
    f"Accuracy Gap : {gap*100:.2f}%"
)

if gap > 0.05:

    print(
        "WARNING: Possible Overfitting"
    )

else:

    print(
        "Model Generalization Good"
    )

# ==================================
# SAVE MODEL
# ==================================

with open(
    "models/rf_qr_model.pkl",
    "wb"
) as f:

    pickle.dump(
        rf_model,
        f
    )

with open(
    "models/feature_names.pkl",
    "wb"
) as f:

    pickle.dump(
        X.columns.tolist(),
        f
    )

print("\n==================================")
print("FILES GENERATED")
print("==================================")

print("rf_qr_model.pkl")
print("feature_names.pkl")
print("training_confusion_matrix.png")
print("testing_confusion_matrix.png")
print("classification_report.png")
print("feature_importance.png")

print("\nResults Folder:")
print(save_dir)
