import ast
import json
import sqlite3


DATABASE_PATH = "phishing_detection.db"


connection = sqlite3.connect(DATABASE_PATH)

try:
    cursor = connection.cursor()

    cursor.execute("SELECT id, reasons FROM scans")
    scans = cursor.fetchall()

    migrated = 0

    for scan_id, reasons in scans:
        if reasons is None:
            continue

        try:
            parsed_reasons = ast.literal_eval(reasons)

            json_reasons = json.dumps(parsed_reasons)

            cursor.execute(
                "UPDATE scans SET reasons = ? WHERE id = ?",
                (json_reasons, scan_id),
            )

            migrated += 1

        except (ValueError, SyntaxError) as exc:
            print(
                f"Could not migrate Scan #{scan_id}: {exc}"
            )

    connection.commit()

    print(
        f"Migration completed successfully. "
        f"Records migrated: {migrated}"
    )

finally:
    connection.close()