# ML-IDS: Machine Learning Based Intrusion Detection System

A Flask + MySQL web application that trains and compares **Decision Tree**, **Random Forest** and **ANN (Keras)**
classifiers on NSL-KDD / UNSW-NB15 style data, classifies traffic records as *Normal* or *Malicious*,
raises alerts, and reports on everything from stored data.

> **Scope and honesty notes**
> * ML-IDS is a **detection** system. It never blocks traffic or changes a firewall.
> * "Traffic Replay" is a **simulation**: recorded dataset rows are sent through the real, trained model.
>   It is not live capture. Dataset labels are never given to the model (only used to report agreement).
> * Benchmark datasets have no IP addresses; replay then uses clearly flagged *simulated* private addresses.
> * The repository ships **synthetic** sample files (`datasets/sample/`) that only mimic the NSL-KDD / UNSW-NB15
>   column structure so the app runs offline. **They are not the real datasets**; numbers obtained on them
>   say nothing about real detection quality. Download the real files for your evaluation (below).
> * Generalisation to unseen/zero-day attacks is not claimed; it must be measured experimentally
>   (e.g. train on `KDDTrain+`, test on `KDDTest+` through the "official test dataset" option).
> * Model files (`.joblib`) are pickles: only the app writes/loads them, from `models/saved_models/`.

## 1. Requirements
Python 3.10+ (tested 3.11), MySQL 8 (or MariaDB 10.6+), ~8 GB RAM. Windows 10/11 or Linux.

## 2. Install
```bash
python -m venv .venv
# Windows:  .venv\Scripts\activate        Linux/macOS:  source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env        # Windows: copy .env.example .env
```
Edit `.env`: set `SECRET_KEY` (`python -c "import secrets; print(secrets.token_hex(32))"`) and the `MYSQL_*` values.

## 3. MySQL
```sql
CREATE USER 'mlids'@'localhost' IDENTIFIED BY 'choose-a-strong-password';
GRANT ALL PRIVILEGES ON ml_ids.* TO 'mlids'@'localhost';
GRANT CREATE ON *.* TO 'mlids'@'localhost';   -- only needed for `init-db` to create the database
```
```bash
python app.py init-db        # creates database `ml_ids` and all tables (database/schema.sql)
python app.py init-admin     # prompts for username / email / password (nothing is hard-coded)
python app.py run            # http://127.0.0.1:5000
```
Extra users: `python app.py create-user --role analyst`.
Roles: **admin** (everything) and **analyst** (read, run predictions, acknowledge/resolve alerts, reports).

> No MySQL available? `DB_BACKEND=sqlite` in `.env` runs the same code on SQLite. This is meant for tests and offline
> demos only; MySQL is the supported backend.

## 4. Datasets
* NSL-KDD: <https://www.unb.ca/cic/datasets/nsl.html> (`KDDTrain+.txt`, `KDDTest+.txt`, headerless: handled).
* UNSW-NB15: <https://research.unsw.edu.au/projects/unsw-nb15-dataset> (`UNSW_NB15_training-set.csv` / `testing-set.csv`).
* Custom CSV: any CSV with a label column (values like `normal/benign/0` are Normal, everything else Malicious).

Leakage guards: NSL-KDD `difficulty`, UNSW `id` and `attack_cat` are never used as features.
Only upload data you are authorised to analyse. Max upload size: `MAX_UPLOAD_MB`.

## 5. Typical workflow
1. **Datasets**: upload; the file is validated and previewed (rows, columns, label, missing, duplicates, class counts).
2. **Preprocessing**: confirm the label, drop columns, choose scaling / feature selection / split; imputers, encoders,
   scalers and selectors are **fitted on the training split only**. Official train/test files are supported.
3. **Model Training**: pick algorithm + hyper-parameters; a background job reports real progress.
4. **Model Comparison**: Accuracy, malicious-class Precision/Recall/F1, FPR, FNR, confusion matrices, durations.
   Best model is highlighted by F1 (default) or another metric; **Activate** the one to use.
5. **Traffic Monitoring**: start a replay (simulation) or `POST /api/detection/predict`; results, alerts and the
   dashboard update from MySQL.
6. **Alerts / Reports**: acknowledge or resolve alerts; six report types with CSV export and print-to-PDF.

Each model is stored with its own fitted preprocessing pipeline (`*_pipeline.joblib`), feature schema, training
configuration, threshold and metrics in `model_registry`.

### Severity (separate from confidence)
Confidence = model probability of the predicted class. Severity is rule based: Medium by default; Low for isolated
small flows (< `severity_small_size` bytes); +1 for large transfers (>= `severity_size_threshold`); +1 when a source
triggers >= `severity_burst_count` detections within 60 s (+2 at 3x). Thresholds are editable in **Settings**.
The binary classifier does not know the attack family, so these are triage heuristics only.

## 6. API (JSON, session cookie + `X-CSRF-Token` header on non-GET)
Success: `{"ok": true, "data": ...}`; error: `{"ok": false, "error": "..."}`.

| Area | Endpoints |
|---|---|
| Auth | `POST /api/auth/login`, `POST /api/auth/logout`, `GET /api/auth/me`, `POST /api/auth/change-password` |
| Dashboard | `GET /api/dashboard/statistics`, `/traffic-summary`, `/alert-summary`; `GET /api/system/status`; `GET /healthz` |
| Datasets | `POST /api/datasets/upload`, `POST /api/datasets/load-sample`, `GET /api/datasets`, `GET/DELETE /api/datasets/{id}`, `POST /api/datasets/{id}/preprocess` |
| Models | `POST /api/models/train`, `GET /api/models`, `/api/models/metrics`, `/comparison`, `/algorithms`, `/jobs`, `/jobs/{id}`, `GET /api/models/{id}`, `POST /api/models/{id}/activate` |
| Traffic | `GET /api/traffic`, `GET /api/traffic/{id}`, `POST /api/traffic/replay/start`, `/replay/stop`, `GET /replay/status` |
| Detection | `POST /api/detection/predict` (`record` or `records`), `GET /api/detection/history` |
| Alerts | `GET /api/alerts`, `GET /api/alerts/{id}`, `PATCH /api/alerts/{id}/status` |
| Reports | `GET /api/reports/summary?type=`, `GET /api/reports/export?type=` (CSV) |
| Settings | `GET/PUT /api/settings` |

Report types: `traffic, intrusion, threat_summary, ml_performance, dataset_analysis, alert_history`.

## 7. Security measures
Hashed passwords (Werkzeug), session fixation protection, login lock-out, CSRF tokens, role checks on every route,
parameterised SQL only, upload extension/size/binary checks with server-generated file names, CSP and security
headers, CSV-formula neutralising on export, secrets only in `.env`, no payload storage (feature rows only),
HTML-escaped rendering. For anything beyond a local demo, serve behind HTTPS (set `SESSION_COOKIE_SECURE=true`)
with a production WSGI server (e.g. `waitress-serve --port 5000 --call app:create_app`).

## 8. Tests
```bash
python -m pytest tests -q
```
94 tests cover authentication/CSRF/roles, dataset validation, preprocessing (leakage, encoding, selection), real
training of all three models, evaluation, detection, replay, alerts, reports, settings, every page, and the full
20-step acceptance workflow. They run on the SQLite fallback with the synthetic samples, so **MySQL itself was not
exercised by this suite**; follow section 3 and run through the workflow once on your MySQL server.
Usability/responsive checks are manual (the layout collapses to an off-canvas menu below 900 px).

## 9. Layout
`app.py` entry/CLI · `config.py` · `database/` (schema, connection, repositories) · `preprocessing/` ·
`models/` (3 algorithms, registry, background trainer) · `detection/` (engine, predictor, replay, alerts) ·
`dashboard/` (blueprints) · `templates/` · `static/` · `scripts/generate_sample_data.py` · `tests/`.
Optional authorised PCAP input would be added as another input adapter that must extract the *same* features the
model was trained on; arbitrary packet fields are never fed to an incompatible model.
