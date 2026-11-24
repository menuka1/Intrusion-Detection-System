-- ML-IDS MySQL schema (MySQL 8 / InnoDB). Timestamps are stored in UTC.
-- Run with:  python app.py init-db      (creates the database if needed, then this file)

CREATE TABLE users (
    user_id        INT AUTO_INCREMENT PRIMARY KEY,
    username       VARCHAR(64)  NOT NULL,
    email          VARCHAR(255) NOT NULL,
    password_hash  VARCHAR(255) NOT NULL,
    role           VARCHAR(20)  NOT NULL DEFAULT 'analyst',
    created_at     DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_login_at  DATETIME     NULL,
    CONSTRAINT uq_users_username UNIQUE (username),
    CONSTRAINT uq_users_email UNIQUE (email)
) ENGINE=InnoDB;

CREATE TABLE datasets (
    dataset_id         INT AUTO_INCREMENT PRIMARY KEY,
    dataset_name       VARCHAR(150) NOT NULL,
    original_filename  VARCHAR(255) NOT NULL,
    dataset_type       VARCHAR(20)  NOT NULL,            -- nsl-kdd | unsw-nb15 | custom
    file_path          VARCHAR(500) NOT NULL,
    file_size          BIGINT       NOT NULL DEFAULT 0,
    uploaded_by        INT          NULL,
    row_count          INT          NOT NULL DEFAULT 0,
    column_count       INT          NOT NULL DEFAULT 0,
    label_column       VARCHAR(100) NULL,
    processing_status  VARCHAR(20)  NOT NULL DEFAULT 'Uploaded',
    metadata           LONGTEXT     NULL,                -- JSON: column stats, class counts, ...
    preprocess_config  LONGTEXT     NULL,                -- JSON
    preprocess_summary LONGTEXT     NULL,                -- JSON before/after summary
    error_message      VARCHAR(500) NULL,
    created_at         DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_datasets_user FOREIGN KEY (uploaded_by) REFERENCES users(user_id) ON DELETE SET NULL
) ENGINE=InnoDB;
CREATE INDEX idx_datasets_status ON datasets (processing_status);
CREATE INDEX idx_datasets_created ON datasets (created_at);

CREATE TABLE network_logs (
    log_id          BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id         INT          NULL,
    `timestamp`     DATETIME     NOT NULL,
    source_ip       VARCHAR(45)  NULL,
    destination_ip  VARCHAR(45)  NULL,
    protocol        VARCHAR(20)  NULL,
    packet_size     BIGINT       NULL,
    raw_data        LONGTEXT     NULL,                   -- JSON feature record (no payload data)
    source          VARCHAR(20)  NOT NULL DEFAULT 'api', -- api | replay
    dataset_id      INT          NULL,
    CONSTRAINT fk_logs_user FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE SET NULL
) ENGINE=InnoDB;
CREATE INDEX idx_logs_timestamp ON network_logs (`timestamp`);
CREATE INDEX idx_logs_src ON network_logs (source_ip);
CREATE INDEX idx_logs_dst ON network_logs (destination_ip);
CREATE INDEX idx_logs_protocol ON network_logs (protocol);

CREATE TABLE predictions (
    prediction_id          BIGINT AUTO_INCREMENT PRIMARY KEY,
    log_id                 BIGINT       NOT NULL,
    model_id               INT          NULL,
    model_name             VARCHAR(50)  NOT NULL,
    model_version          VARCHAR(20)  NOT NULL,
    prediction_result      VARCHAR(16)  NOT NULL,        -- Normal | Malicious
    confidence_score       DOUBLE       NOT NULL,        -- probability of the predicted class
    malicious_probability  DOUBLE       NOT NULL,
    created_at             DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_predictions_log UNIQUE (log_id),
    CONSTRAINT fk_predictions_log FOREIGN KEY (log_id) REFERENCES network_logs(log_id) ON DELETE CASCADE
) ENGINE=InnoDB;
CREATE INDEX idx_predictions_result ON predictions (prediction_result);
CREATE INDEX idx_predictions_model ON predictions (model_name);
CREATE INDEX idx_predictions_created ON predictions (created_at);

CREATE TABLE alerts (
    alert_id         BIGINT AUTO_INCREMENT PRIMARY KEY,
    prediction_id    BIGINT       NOT NULL,
    alert_type       VARCHAR(60)  NOT NULL,
    threat_level     VARCHAR(10)  NOT NULL,              -- Low | Medium | High | Critical
    alert_message    VARCHAR(500) NOT NULL,
    status           VARCHAR(15)  NOT NULL DEFAULT 'Open', -- Open | Acknowledged | Resolved
    updated_by       INT          NULL,
    updated_at       DATETIME     NULL,
    created_at       DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_alerts_prediction UNIQUE (prediction_id),
    CONSTRAINT fk_alerts_prediction FOREIGN KEY (prediction_id) REFERENCES predictions(prediction_id) ON DELETE CASCADE
) ENGINE=InnoDB;
CREATE INDEX idx_alerts_status ON alerts (status);
CREATE INDEX idx_alerts_level ON alerts (threat_level);
CREATE INDEX idx_alerts_created ON alerts (created_at);

CREATE TABLE model_registry (
    model_id          INT AUTO_INCREMENT PRIMARY KEY,
    algorithm         VARCHAR(30)  NOT NULL,             -- decision_tree | random_forest | ann
    dataset_id        INT          NULL,
    dataset_name      VARCHAR(150) NULL,
    version           INT          NOT NULL,
    model_path        VARCHAR(500) NOT NULL,
    pipeline_path     VARCHAR(500) NOT NULL,
    feature_schema    LONGTEXT     NOT NULL,             -- JSON
    training_config   LONGTEXT     NOT NULL,             -- JSON
    accuracy          DOUBLE       NOT NULL,
    precision_score   DOUBLE       NOT NULL,             -- malicious class
    recall_score      DOUBLE       NOT NULL,             -- malicious class
    f1_score          DOUBLE       NOT NULL,             -- malicious class
    fpr               DOUBLE       NOT NULL,
    fnr               DOUBLE       NOT NULL,
    metrics           LONGTEXT     NOT NULL,             -- JSON: full evaluation incl. confusion matrix
    training_seconds  DOUBLE       NOT NULL DEFAULT 0,
    prediction_seconds DOUBLE      NOT NULL DEFAULT 0,
    threshold         DOUBLE       NOT NULL DEFAULT 0.5,
    is_active         TINYINT      NOT NULL DEFAULT 0,
    created_by        INT          NULL,
    created_at        DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_model_version UNIQUE (algorithm, dataset_id, version),
    CONSTRAINT fk_model_dataset FOREIGN KEY (dataset_id) REFERENCES datasets(dataset_id) ON DELETE SET NULL
) ENGINE=InnoDB;
CREATE INDEX idx_model_active ON model_registry (is_active);
CREATE INDEX idx_model_algorithm ON model_registry (algorithm);

CREATE TABLE training_jobs (
    job_id            INT AUTO_INCREMENT PRIMARY KEY,
    dataset_id        INT          NULL,
    algorithm         VARCHAR(30)  NOT NULL,
    job_status        VARCHAR(15)  NOT NULL DEFAULT 'Pending',  -- Pending|Running|Completed|Failed
    progress          INT          NOT NULL DEFAULT 0,
    progress_message  VARCHAR(255) NULL,
    config            LONGTEXT     NULL,
    error_message     VARCHAR(1000) NULL,
    model_id          INT          NULL,
    created_by        INT          NULL,
    created_at        DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    started_at        DATETIME     NULL,
    completed_at      DATETIME     NULL,
    CONSTRAINT fk_jobs_dataset FOREIGN KEY (dataset_id) REFERENCES datasets(dataset_id) ON DELETE SET NULL
) ENGINE=InnoDB;
CREATE INDEX idx_jobs_status ON training_jobs (job_status);

CREATE TABLE app_settings (
    setting_key    VARCHAR(64) PRIMARY KEY,
    setting_value  TEXT        NULL,
    updated_at     DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;
