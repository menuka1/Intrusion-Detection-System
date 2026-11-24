"""Dataset ingestion and preprocessing orchestration (files + database)."""
import logging
import uuid
from pathlib import Path

from database.repositories import Datasets
from models.trainer import load_prepared
from preprocessing.cleaning import column_overview, duplicate_count, infer_column_types, missing_summary
from preprocessing.dataset_loader import (DatasetError, binarize_labels, detect_dataset_type, get_profile,
                                          read_dataset, unique_label_values, validate_dataset)

log = logging.getLogger(__name__)
DATASET_TYPES = ("auto", "nsl-kdd", "unsw-nb15", "custom")


def build_metadata(df, label, warnings):
    numeric, categorical = infer_column_types(df, exclude=[label] if label else ())
    meta = {"missing": missing_summary(df), "duplicate_rows": duplicate_count(df),
            "numeric_columns": numeric, "categorical_columns": categorical,
            "columns": column_overview(df, label), "warnings": warnings}
    if label:
        y = binarize_labels(df[label])
        meta["class_counts"] = {"normal": int((y == 0).sum()), "malicious": int((y == 1).sum()),
                                "missing_label": int(y.isna().sum())}
        meta["label_values"] = unique_label_values(df[label])
    return meta


def ingest_file(src_path, original_filename, name, dataset_type, label_column, user_id, upload_dir):
    """Validate a file on disk and register it as a dataset. Raises DatasetError on invalid input."""
    src_path = Path(src_path)
    if dataset_type not in DATASET_TYPES:
        raise DatasetError("Dataset type must be one of: " + ", ".join(DATASET_TYPES))
    if dataset_type == "auto":
        dataset_type = detect_dataset_type(src_path)
    df = read_dataset(src_path, dataset_type)
    label, warnings = validate_dataset(df, dataset_type, label_column or None)
    meta = build_metadata(df, label, warnings)
    if label and meta["class_counts"]["missing_label"] == len(df):
        raise DatasetError("The label column contains no usable values.")
    if label and (meta["class_counts"]["normal"] == 0 or meta["class_counts"]["malicious"] == 0):
        warnings.append("Only one traffic class is present in the label column; training will not be possible.")
    dest = Path(upload_dir) / f"{uuid.uuid4().hex}.csv"
    df.to_csv(dest, index=False)  # normalised copy: always has a header row
    try:
        did = Datasets.create(
            dataset_name=name, original_filename=original_filename, dataset_type=dataset_type, file_path=str(dest),
            file_size=src_path.stat().st_size, uploaded_by=user_id, row_count=int(len(df)),
            column_count=int(df.shape[1]), label_column=label, processing_status="Uploaded", metadata=meta)
    except Exception:
        dest.unlink(missing_ok=True)
        raise
    return Datasets.get(did)


def preprocess_dataset(dataset_id, cfg_dict, processed_dir):
    """Background job: run the full preprocessing pipeline and persist config + before/after summary."""
    try:
        dataset = Datasets.get(dataset_id)
        prepared, cfg, _ = load_prepared(dataset, cfg_dict, return_clean=True)
        out = Path(processed_dir) / f"dataset_{dataset_id}_clean.csv"
        prepared.clean_df.drop(columns="__label__").to_csv(out, index=False)
        summary = {**prepared.summary, "processed_file": out.name}
        Datasets.update(dataset_id, label_column=cfg.label_column, preprocess_config=cfg.to_dict(),
                        preprocess_summary=summary, processing_status="Preprocessed", error_message=None)
    except (DatasetError, ValueError) as exc:
        Datasets.update(dataset_id, processing_status="Failed", error_message=str(exc)[:480])
    except Exception as exc:  # noqa: BLE001 - background boundary
        log.exception("Preprocessing dataset %s failed", dataset_id)
        Datasets.update(dataset_id, processing_status="Failed", error_message=f"Preprocessing failed: {exc}"[:480])


def remove_dataset_files(dataset, processed_dir):
    Path(dataset["file_path"]).unlink(missing_ok=True)
    (Path(processed_dir) / f"dataset_{dataset['dataset_id']}_clean.csv").unlink(missing_ok=True)
