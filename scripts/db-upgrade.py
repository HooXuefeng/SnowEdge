import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.schema_migrations import ensure_schema_current

if __name__ == "__main__":
    print(ensure_schema_current())
