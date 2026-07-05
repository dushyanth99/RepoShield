import re
import sqlite3
import hashlib
import pandas as pd
import pickle
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from transformers import AutoTokenizer
from utils.logging_utils import setup_logger
from config import MAX_TRAIN_SAMPLES

logger = setup_logger("data-loader")

# Language tokens injected as a prefix to help CodeBERT learn language-specific patterns
LANG_TOKENS = {
    "Python": "<PYTHON>",
    "Java": "<JAVA>",
    "JavaScript": "<JAVASCRIPT>",
    "TypeScript": "<TYPESCRIPT>",
    "C": "<C>",
    "C++": "<CPP>",
    "Go": "<GO>",
    "Rust": "<RUST>",
    "PHP": "<PHP>",
}

# Regex patterns for comment stripping per language style
_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_LINE_COMMENT_C_RE = re.compile(r"//.*")
_LINE_COMMENT_PY_RE = re.compile(r"#.*")
_DOCSTRING_RE = re.compile(r'""".*?"""|\'\'\'.*?\'\'\'', re.DOTALL)
_MULTI_BLANK_RE = re.compile(r"\n{3,}")


def clean_code(code: str) -> str:
    """Basic code snippet cleaning — strips leading/trailing whitespace and normalises newlines.

    Retained for backward compatibility with existing tests and callers.
    """
    if not code:
        return ""
    return code.strip()


def advanced_clean_code(code: str, language: str = "") -> str:
    """Advanced code cleaning pipeline.

    Steps:
    1. Strip docstrings / block comments / line comments.
    2. Collapse 3+ consecutive blank lines to 2.
    3. Strip leading/trailing whitespace.
    4. Normalise Windows-style line endings.

    Args:
        code: Raw source code string.
        language: Optional programming language hint (used for comment style).

    Returns:
        Cleaned source code string, or empty string for invalid input.
    """
    if not code or not code.strip():
        return ""

    lang_lower = language.lower()

    # Remove Python docstrings first (before line-comment stripping)
    if lang_lower in ("python", ""):
        code = _DOCSTRING_RE.sub("", code)
        code = _LINE_COMMENT_PY_RE.sub("", code)

    # Remove C/Java/JS style block and line comments
    if lang_lower not in ("python",):
        code = _BLOCK_COMMENT_RE.sub("", code)
        code = _LINE_COMMENT_C_RE.sub("", code)

    # Normalise line endings and collapse excessive blank lines
    code = code.replace("\r\n", "\n").replace("\r", "\n")
    code = _MULTI_BLANK_RE.sub("\n\n", code)

    return code.strip()


def inject_language_token(code: str, language: str) -> str:
    """Prepends a language-specific marker token to code.

    This helps the model learn language-specific vulnerability patterns
    without requiring separate per-language fine-tuned models.

    Args:
        code: Source code string.
        language: Programming language name.

    Returns:
        Code prefixed with language token, e.g. '<PYTHON> def foo(): ...'.
    """
    token = LANG_TOKENS.get(language, "<UNKNOWN>")
    return f"{token} {code}"


def deduplicate_by_hash(df: pd.DataFrame, code_col: str = "code") -> pd.DataFrame:
    """Removes exact duplicate code samples using SHA-256 content hashing.

    Duplicate code samples can bias training since the model sees identical
    examples multiple times. This keeps one representative row per unique snippet.

    Args:
        df: Input DataFrame with a code column.
        code_col: Name of the column containing source code.

    Returns:
        Deduplicated DataFrame.
    """
    before = len(df)
    df = df.copy()
    df["_code_hash"] = df[code_col].apply(
        lambda c: hashlib.sha256(c.encode("utf-8", errors="replace")).hexdigest()
    )
    df = df.drop_duplicates(subset=["_code_hash"]).drop(columns=["_code_hash"])
    after = len(df)
    logger.info(f"Deduplication: {before} -> {after} rows (removed {before - after} duplicates).")
    return df


def load_dataset_from_db(db_path: str, max_samples: int = MAX_TRAIN_SAMPLES) -> pd.DataFrame:
    """Loads a balanced, deduplicated dataset of method changes from the SQLite database.

    Pipeline:
    1. Query method_change joined with CVE/CWE metadata (DISTINCT + LIMIT).
    2. Standardise labels.
    3. Apply advanced code cleaning.
    4. Inject language tokens.
    5. Deduplicate by code hash.
    6. Filter minimum code length (< 20 chars is useless noise).
    7. Balance vulnerable vs. non-vulnerable samples.

    Args:
        db_path: Path to the CVEfixes SQLite database.
        max_samples: Maximum total balanced samples to return.

    Returns:
        Balanced, cleaned pandas DataFrame ready for tokenization.
    """
    if not Path(db_path).exists():
        raise FileNotFoundError(f"SQLite DB not found at {db_path}")

    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA cache_size = 100000;")
    conn.execute("PRAGMA temp_store = MEMORY;")

    # Fetch a capped set of distinct method changes with vulnerability metadata.
    # DISTINCT prevents row explosion from the one-to-many cwe_classification join.
    # LIMIT is 4x max_samples so that after label-balancing we always have enough rows.
    row_limit = max(max_samples * 4, 20000)
    query = f"""
    SELECT DISTINCT
        m.code,
        m.before_change,
        f.programming_language,
        cc.cwe_id,
        cv.cvss3_base_score,
        cv.cvss3_base_severity
    FROM method_change m
    JOIN file_change f ON m.file_change_id = f.file_change_id
    JOIN commits c ON f.hash = c.hash
    JOIN fixes fx ON c.hash = fx.hash
    JOIN cve cv ON fx.cve_id = cv.cve_id
    LEFT JOIN cwe_classification cc ON cv.cve_id = cc.cve_id
    WHERE m.code IS NOT NULL AND m.code != ''
    LIMIT {row_limit}
    """

    logger.info(f"Executing database query (LIMIT={row_limit}) to load training data...")
    df = pd.read_sql_query(query, conn)
    conn.close()

    logger.info(f"Loaded {len(df)} total rows from database.")

    if len(df) == 0:
        return df

    # Standardise labels — m.before_change == True means this is the BEFORE (vulnerable) version
    df["label"] = df["before_change"].apply(
        lambda x: 1 if str(x).strip().lower() in ("true", "1") else 0
    )

    # Fill missing language
    df["programming_language"] = df["programming_language"].fillna("").str.strip()

    # Apply advanced cleaning + language token injection
    logger.info("Applying advanced code cleaning and language token injection...")
    df["code"] = df.apply(
        lambda row: inject_language_token(
            advanced_clean_code(row["code"], row["programming_language"]),
            row["programming_language"],
        ),
        axis=1,
    )

    # Filter minimum code length (< 20 chars after cleaning is noise)
    df = df[df["code"].str.len() >= 20]

    # Deduplicate
    df = deduplicate_by_hash(df)

    # Separate vulnerable and non-vulnerable rows to enforce strict balance
    vuln_df = df[df["label"] == 1]
    fixed_df = df[df["label"] == 0]

    logger.info(f"Available vulnerable samples: {len(vuln_df)}, fixed samples: {len(fixed_df)}")

    sample_size = min(len(vuln_df), len(fixed_df), max_samples // 2)

    if sample_size == 0:
        logger.warning("No samples found matching balanced conditions!")
        return df.head(0)

    # Sample balanced sets
    vuln_sampled = vuln_df.sample(n=sample_size, random_state=42)
    fixed_sampled = fixed_df.sample(n=sample_size, random_state=42)

    balanced_df = (
        pd.concat([vuln_sampled, fixed_sampled])
        .sample(frac=1.0, random_state=42)
        .reset_index(drop=True)
    )
    logger.info(
        f"Created balanced dataset with {len(balanced_df)} samples "
        f"({sample_size} vulnerable, {sample_size} fixed)."
    )

    return balanced_df


def train_cwe_classifier(df: pd.DataFrame, save_dir: Path) -> None:
    """Trains a TF-IDF + Random Forest model to predict CWE categories on vulnerable functions.

    Only trained on positive (vulnerable) samples that have a known CWE ID.
    Saves both the fitted vectorizer and classifier to disk for use during inference.

    Args:
        df: Balanced dataset DataFrame containing 'code', 'label', and 'cwe_id' columns.
        save_dir: Directory where CWE classifier assets will be saved.
    """
    cwe_df = df[(df["label"] == 1) & (df["cwe_id"].notna()) & (df["cwe_id"] != "")]
    if len(cwe_df) < 50:
        logger.warning(
            "Too few vulnerable samples with CWE categories to train a reliable CWE classifier. Skipping."
        )
        return

    logger.info(f"Training CWE classifier on {len(cwe_df)} vulnerable samples...")

    X = cwe_df["code"]
    y = cwe_df["cwe_id"]

    # TF-IDF features — 8000 features to capture more code vocabulary
    vectorizer = TfidfVectorizer(
        max_features=8000,
        stop_words="english",
        ngram_range=(1, 2),  # include bigrams for better code pattern capture
        analyzer="word",
    )
    X_tfidf = vectorizer.fit_transform(X)

    # Random Forest with more estimators for a production-quality classifier
    clf = RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1, max_depth=20)
    clf.fit(X_tfidf, y)

    save_dir.mkdir(parents=True, exist_ok=True)
    with open(save_dir / "cwe_vectorizer.pkl", "wb") as f:
        pickle.dump(vectorizer, f)
    with open(save_dir / "cwe_classifier.pkl", "wb") as f:
        pickle.dump(clf, f)

    logger.info("CWE classifier training complete and saved.")


def prepare_splits(
    df: pd.DataFrame, test_size: float = 0.1, val_size: float = 0.1
) -> tuple:
    """Splits the dataframe into train, validation, and test sets with stratification.

    Args:
        df: Balanced DataFrame with a 'label' column.
        test_size: Fraction to hold out as test set.
        val_size: Fraction of the full dataset to hold out as validation set.

    Returns:
        Tuple of (train_df, val_df, test_df).
    """
    train_val_df, test_df = train_test_split(
        df, test_size=test_size, stratify=df["label"], random_state=42
    )

    # Adjust validation size relative to remaining train_val
    adjusted_val_size = val_size / (1.0 - test_size)
    train_df, val_df = train_test_split(
        train_val_df,
        test_size=adjusted_val_size,
        stratify=train_val_df["label"],
        random_state=42,
    )

    logger.info(f"Dataset split: Train={len(train_df)}, Val={len(val_df)}, Test={len(test_df)}")
    return train_df, val_df, test_df


def tokenize_data(texts: list, tokenizer: AutoTokenizer, max_length: int = 512) -> dict:
    """Tokenizes a list of code strings for transformer input.

    Args:
        texts: List of source code strings.
        tokenizer: Hugging Face tokenizer instance.
        max_length: Maximum token sequence length (truncated/padded to this).

    Returns:
        Batch encoding dict with 'input_ids', 'attention_mask', etc.
    """
    return tokenizer(
        texts,
        padding="max_length",
        truncation=True,
        max_length=max_length,
        return_tensors="pt",
    )
