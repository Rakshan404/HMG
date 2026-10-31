
"""Load schema-compatible HTTP events and pass them to Member 3's pipeline."""

import json
from pathlib import Path

from backend.engine.pipeline import process_events

PROJECT_ROOT = Path(__file__).resolve().parents[1]
EVENTS_FILE = PROJECT_ROOT / "data" / "http_events.jsonl"

REQUIRED_FIELDS = {
    "event_id",
    "timestamp",
    "source_ip",
    "source_mac",
    "honeypot",
    "event",
    "details",
}


def load_http_events(file_path=EVENTS_FILE):
    """Load compatible events and report legacy records without modifying them."""

    events = []
    legacy_lines = []

    if not file_path.exists():
        raise FileNotFoundError(f"HTTP event file not found: {file_path}")

    with file_path.open("r", encoding="utf-8") as event_file:
        for line_number, line in enumerate(event_file, start=1):
            if not line.strip():
                continue

            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Invalid JSON on line {line_number}: {exc}"
                ) from exc

            if not isinstance(event, dict):
                raise ValueError(
                    f"Line {line_number} must contain a JSON object."
                )

            missing_fields = REQUIRED_FIELDS - event.keys()

            if missing_fields:
                legacy_lines.append({
                    "line": line_number,
                    "missing_fields": sorted(missing_fields),
                })
                continue

            events.append(event)

    return events, legacy_lines


def process_http_events(file_path=EVENTS_FILE):
    events, legacy_lines = load_http_events(file_path)

    if not events:
        results = {
            "events_processed": 0,
            "device_groups": 0,
            "incidents": [],
        }
    else:
        # Member 3's normalizer still validates every accepted event.
        results = process_events(events)

    results["legacy_records_skipped"] = len(legacy_lines)
    results["legacy_line_numbers"] = [
        record["line"] for record in legacy_lines
    ]

    return results


def main():
    print("HMG HTTP → Intelligence Pipeline")
    print("-" * 40)

    try:
        results = process_http_events()

        print(json.dumps(results, indent=4, default=str))

        print("\nIngestion summary:")
        print(f"Compatible events processed: {results['events_processed']}")
        print(f"Legacy records skipped: {results['legacy_records_skipped']}")

        if results["legacy_line_numbers"]:
            print(
                "Legacy line numbers:",
                ", ".join(map(str, results["legacy_line_numbers"]))
            )

        print("\nProcessing completed.")

    except (OSError, ValueError) as exc:
        print(f"\nIngestion failed: {exc}")

    except Exception as exc:
        print(f"\nPipeline processing failed: {exc}")
        raise


if __name__ == "__main__":
    main()
