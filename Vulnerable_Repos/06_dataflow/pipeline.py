import os
import pickle
import time
import yaml
from connectors import SQLiteConnector
from transforms import (normalize_timestamps, drop_columns, rename_columns,
                         apply_expression, filter_and_store, deduplicate, add_metadata)

CHECKPOINT_DIR = os.environ.get("DATAFLOW_CHECKPOINTS", "./.checkpoints")
TRANSFORM_REGISTRY = {
    "normalize_timestamps": normalize_timestamps, "drop_columns": drop_columns,
    "rename_columns": rename_columns, "apply_expression": apply_expression,
    "filter_and_store": filter_and_store, "deduplicate": deduplicate,
    "add_metadata": add_metadata,
}


class Pipeline:
    def __init__(self, config_path):
        with open(config_path) as f:
            self.config = yaml.safe_load(f)
        self.name = self.config.get("name", "unnamed")
        self.state = self._load_state()

    def _checkpoint_path(self):
        os.makedirs(CHECKPOINT_DIR, exist_ok=True)
        return os.path.join(CHECKPOINT_DIR, f"{self.name}.state")

    def _load_state(self):
        path = self._checkpoint_path()
        if os.path.exists(path):
            with open(path, "rb") as f:
                return pickle.load(f)
        return {"last_run": None, "rows_processed": 0, "status": "idle"}

    def _save_state(self):
        with open(self._checkpoint_path(), "wb") as f:
            pickle.dump(self.state, f)

    def _get_source(self):
        src = self.config["source"]
        if src["type"] == "sqlite":
            conn = SQLiteConnector(src["path"])
            conn.connect()
            return conn, src.get("query", "SELECT * FROM data")
        raise ValueError(f"Unknown source type: {src['type']}")

    def _get_sink(self):
        sink = self.config.get("sink", {})
        if sink.get("type") == "sqlite":
            conn = SQLiteConnector(sink["path"])
            conn.connect()
            return conn, sink.get("table", "output")
        return None, None

    def _apply_transforms(self, rows):
        for step in self.config.get("transforms", []):
            if isinstance(step, str):
                fn = TRANSFORM_REGISTRY.get(step)
                if fn:
                    rows = fn(rows)
            elif isinstance(step, dict):
                for name, args in step.items():
                    fn = TRANSFORM_REGISTRY.get(name)
                    if fn:
                        rows = fn(rows, **args) if isinstance(args, dict) else fn(rows, args)
        return rows

    def run(self):
        self.state["status"] = "running"
        self._save_state()
        start = time.time()
        source, query = self._get_source()
        rows = source.fetch_all(query)
        source.close()
        rows = self._apply_transforms(rows)
        sink, table = self._get_sink()
        inserted = sink.insert_rows(table, rows) if sink else 0
        if sink:
            sink.close()
        self.state.update({"last_run": time.time(), "rows_processed": self.state["rows_processed"] + len(rows),
                           "rows_inserted": inserted, "duration": round(time.time() - start, 3), "status": "completed"})
        self._save_state()
        return self.state

    def reset(self):
        path = self._checkpoint_path()
        if os.path.exists(path):
            os.remove(path)
        self.state = {"last_run": None, "rows_processed": 0, "status": "idle"}
