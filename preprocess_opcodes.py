# preprocess_opcodes.py

import os
import re
import math
import pandas as pd
from sklearn.feature_extraction.text import CountVectorizer

# ========= CONFIG =========
INPUT_DIR = "raw_opcodes"         # folder with raw opcode text files
OUTPUT_DIR = "dataset"

CHUNK_SIZE = 200                  # number of opcodes per chunk
CHUNK_STEP = 100                  # sliding window step size
MIN_CHUNK_LENGTH = 50             # discard chunks smaller than this

MAX_1GRAM_FEATURES = 300
MAX_2GRAM_FEATURES = 500

SAVE_CHUNK_TEXT = True            # save chunk text for inspection
# ==========================


def extract_opcodes(filepath):
    """
    Extract only opcode mnemonics from a raw opcode file.
    Attempts to handle lines such as:
        00401000 mov eax, ebx
        push ebp
        loc_401000: call sub_402000
    """
    opcodes = []

    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()

            if not line:
                continue

            # Remove comments after ';' or '#'
            line = re.split(r"[;#]", line)[0].strip()
            if not line:
                continue

            # Remove labels like loc_401000:
            line = re.sub(r"^\S+:\s*", "", line)

            # Remove leading addresses like 00401000 or 0x401000
            line = re.sub(r"^(0x[0-9A-Fa-f]+|[0-9A-Fa-f]{6,})\s+", "", line)

            tokens = line.split()
            if not tokens:
                continue

            candidate = tokens[0].lower()

            # Keep opcode-like tokens only
            if re.fullmatch(r"[a-z][a-z0-9_.]*", candidate):
                opcodes.append(candidate)

    return opcodes


def chunk_opcode_sequence(opcodes, chunk_size=200, step=100, min_len=50):
    """
    Split opcode list into overlapping chunks.
    """
    chunks = []

    if len(opcodes) < min_len:
        return chunks

    if len(opcodes) <= chunk_size:
        chunks.append(opcodes)
        return chunks

    for start in range(0, len(opcodes) - chunk_size + 1, step):
        chunk = opcodes[start:start + chunk_size]
        if len(chunk) >= min_len:
            chunks.append(chunk)

    # Add final tail chunk if needed
    last_start = max(0, len(opcodes) - chunk_size)
    last_chunk = opcodes[last_start:last_start + chunk_size]

    if len(last_chunk) >= min_len:
        if not chunks or chunks[-1] != last_chunk:
            chunks.append(last_chunk)

    return chunks


def get_label_from_filename(filename):
    """
    Example:
        APT28_sample1.txt -> APT28
        FIN4.bin.opcodes.txt -> FIN4
    Uses text before first underscore if present,
    otherwise text before first dot.
    """
    base = os.path.basename(filename)
    if "_" in base:
        return base.split("_")[0]
    return base.split(".")[0]


def build_chunk_dataset():
    """
    Read all files, extract opcodes, split into chunks,
    and return chunk texts + labels + metadata.
    """
    texts = []
    labels = []
    metadata = []

    files = sorted(os.listdir(INPUT_DIR))

    for file in files:
        path = os.path.join(INPUT_DIR, file)

        if not os.path.isfile(path):
            continue

        label = get_label_from_filename(file)
        opcodes = extract_opcodes(path)

        if not opcodes:
            print(f"[WARNING] No opcodes extracted from {file}")
            continue

        chunks = chunk_opcode_sequence(
            opcodes,
            chunk_size=CHUNK_SIZE,
            step=CHUNK_STEP,
            min_len=MIN_CHUNK_LENGTH
        )

        if not chunks:
            print(f"[WARNING] No valid chunks produced from {file}")
            continue

        for idx, chunk in enumerate(chunks):
            chunk_text = " ".join(chunk)
            texts.append(chunk_text)
            labels.append(label)
            metadata.append({
                "source_file": file,
                "label": label,
                "chunk_id": idx,
                "chunk_length": len(chunk)
            })

        print(f"[INFO] {file}: {len(opcodes)} opcodes -> {len(chunks)} chunks")

    return texts, labels, metadata


def vectorize_texts(texts, ngram_range, max_features):
    """
    Convert opcode chunk texts into feature vectors.
    """
    vectorizer = CountVectorizer(
        ngram_range=ngram_range,
        lowercase=False,
        token_pattern=r"(?u)\b[a-z][a-z0-9_.]*\b",
        max_features=max_features
    )

    X = vectorizer.fit_transform(texts)
    df = pd.DataFrame(X.toarray(), columns=vectorizer.get_feature_names_out())
    return df, vectorizer


def save_chunk_metadata(texts, labels, metadata):
    """
    Save chunk-level inspection file.
    """
    if not SAVE_CHUNK_TEXT:
        return

    rows = []
    for text, label, meta in zip(texts, labels, metadata):
        rows.append({
            "source_file": meta["source_file"],
            "label": label,
            "chunk_id": meta["chunk_id"],
            "chunk_length": meta["chunk_length"],
            "opcode_text": text
        })

    df = pd.DataFrame(rows)
    df.to_csv(os.path.join(OUTPUT_DIR, "chunk_metadata.csv"), index=False)


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    print("[INFO] Building chunked opcode dataset...")
    texts, labels, metadata = build_chunk_dataset()

    if not texts:
        print("[ERROR] No chunk samples were created. Check your raw files.")
        return

    print(f"[INFO] Total chunk samples: {len(texts)}")
    print(f"[INFO] Total classes: {len(set(labels))}")
    print(f"[INFO] Labels: {sorted(set(labels))}")

    save_chunk_metadata(texts, labels, metadata)

    print("[INFO] Creating 1-gram dataset...")
    df1, vec1 = vectorize_texts(
        texts,
        ngram_range=(1, 1),
        max_features=MAX_1GRAM_FEATURES
    )

    print("[INFO] Creating 2-gram dataset...")
    df2, vec2 = vectorize_texts(
        texts,
        ngram_range=(2, 2),
        max_features=MAX_2GRAM_FEATURES
    )

    meta_df = pd.DataFrame(metadata)

    df1 = pd.concat([meta_df.reset_index(drop=True), df1], axis=1)
    df2 = pd.concat([meta_df.reset_index(drop=True), df2], axis=1)

    df1.to_csv(os.path.join(OUTPUT_DIR, "opcode_1gram.csv"), index=False)
    df2.to_csv(os.path.join(OUTPUT_DIR, "opcode_2gram.csv"), index=False)

    with open(os.path.join(OUTPUT_DIR, "feature_summary.txt"), "w", encoding="utf-8") as f:
        f.write("Opcode Dataset Summary\n")
        f.write("======================\n")
        f.write(f"Chunk size: {CHUNK_SIZE}\n")
        f.write(f"Chunk step: {CHUNK_STEP}\n")
        f.write(f"Minimum chunk length: {MIN_CHUNK_LENGTH}\n")
        f.write(f"Total chunk samples: {len(texts)}\n")
        f.write(f"Classes: {', '.join(sorted(set(labels)))}\n")
        f.write(f"1-gram features: {len(vec1.get_feature_names_out())}\n")
        f.write(f"2-gram features: {len(vec2.get_feature_names_out())}\n")

    print("[INFO] Done.")
    print(f"[INFO] Saved: {os.path.join(OUTPUT_DIR, 'opcode_1gram.csv')}")
    print(f"[INFO] Saved: {os.path.join(OUTPUT_DIR, 'opcode_2gram.csv')}")
    print(f"[INFO] Saved: {os.path.join(OUTPUT_DIR, 'chunk_metadata.csv')}")
    print(f"[INFO] Saved: {os.path.join(OUTPUT_DIR, 'feature_summary.txt')}")


if __name__ == "__main__":
    main()
