"""Artificial Neural Network (TensorFlow / Keras) for binary traffic classification."""
import os

import numpy as np

from models.base import ParamError, as_choice, as_float, as_int

os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "2")
os.environ.setdefault("TF_ENABLE_ONEDNN_OPTS", "0")


def _parse_layers(value):
    if value in (None, ""):
        return [64, 32]
    if isinstance(value, str):
        value = [v for v in value.replace(" ", "").split(",") if v]
    try:
        layers = [int(v) for v in value]
    except (TypeError, ValueError) as exc:
        raise ParamError("'hidden_layers' must be a list of integers, e.g. 64,32.") from exc
    if not 1 <= len(layers) <= 6 or any(not 2 <= n <= 1024 for n in layers):
        raise ParamError("'hidden_layers' needs 1-6 layers with 2-1024 neurons each.")
    return layers


class NeuralNetworkModel:
    algorithm = "ann"
    display_name = "Artificial Neural Network"
    description = ("A feed-forward neural network (Keras) with ReLU hidden layers and a sigmoid "
                   "output, trained with early stopping on a validation split.")
    artifact_ext = ".keras"

    @staticmethod
    def default_params():
        return {"hidden_layers": [64, 32], "activation": "relu", "dropout": 0.2,
                "learning_rate": 0.001, "epochs": 30, "batch_size": 256, "patience": 5,
                "random_state": 42}

    @classmethod
    def validate_params(cls, params):
        p = params or {}
        return {
            "hidden_layers": _parse_layers(p.get("hidden_layers")),
            "activation": as_choice(p, "activation", "relu", ["relu", "tanh", "elu"]),
            "dropout": as_float(p, "dropout", 0.2, 0.0, 0.8),
            "learning_rate": as_float(p, "learning_rate", 0.001, 1e-5, 0.5),
            "epochs": as_int(p, "epochs", 30, 1, 500),
            "batch_size": as_int(p, "batch_size", 256, 8, 8192),
            "patience": as_int(p, "patience", 5, 1, 100),
            "random_state": as_int(p, "random_state", 42, 0, 2**31 - 1),
        }

    def __init__(self, params=None):
        self.params = self.validate_params(params)
        self.model = None
        self.history = {}

    def _build(self, n_features):
        import tensorflow as tf
        from tensorflow import keras
        tf.keras.utils.set_random_seed(self.params["random_state"])
        layers = [keras.Input(shape=(n_features,))]
        for n in self.params["hidden_layers"]:
            layers.append(keras.layers.Dense(n, activation=self.params["activation"]))
            if self.params["dropout"] > 0:
                layers.append(keras.layers.Dropout(self.params["dropout"]))
        layers.append(keras.layers.Dense(1, activation="sigmoid"))
        model = keras.Sequential(layers)
        model.compile(optimizer=keras.optimizers.Adam(self.params["learning_rate"]),
                      loss="binary_crossentropy", metrics=["accuracy"])
        return model

    def train(self, X_train, y_train, X_val=None, y_val=None, progress=None):
        from tensorflow import keras
        self.model = self._build(X_train.shape[1])
        epochs = self.params["epochs"]

        class _Progress(keras.callbacks.Callback):
            def on_epoch_end(cb, epoch, logs=None):  # noqa: N805
                if progress:
                    progress(30 + int(60 * (epoch + 1) / epochs),
                             f"Epoch {epoch + 1}/{epochs} - val_loss {logs.get('val_loss', float('nan')):.4f}")

        cbs = [keras.callbacks.EarlyStopping(monitor="val_loss", patience=self.params["patience"],
                                             restore_best_weights=True), _Progress()]
        hist = self.model.fit(X_train, np.asarray(y_train), validation_data=(X_val, np.asarray(y_val)),
                              epochs=epochs, batch_size=self.params["batch_size"], callbacks=cbs, verbose=0)
        self.history = {k: [float(x) for x in v] for k, v in hist.history.items()}
        return {"epochs_run": len(self.history.get("loss", [])), "final_val_loss": self.history["val_loss"][-1]}

    def predict_proba(self, X):
        return self.model.predict(X, verbose=0, batch_size=2048).ravel()

    def predict(self, X, threshold=0.5):
        return (self.predict_proba(X) >= threshold).astype(int)

    def save(self, path):
        self.model.save(path)

    @classmethod
    def load(cls, path, params=None):
        from tensorflow import keras
        obj = cls(params)
        obj.model = keras.models.load_model(path, compile=False)
        return obj
