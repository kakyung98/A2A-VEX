from __future__ import annotations

import json
from typing import Any

from cve_genie_web.database import db_session, utc_now_iso
from cve_genie_web.models import Job


class JobRepository:
    def create(
        self,
        *,
        job_id: str,
        cve_id: str,
        input_json_path: str,
        log_path: str,
        run_type: str,
    ) -> Job:
        now = utc_now_iso()

        with db_session() as connection:
            connection.execute(
                """
                INSERT INTO jobs (
                    job_id, cve_id, status, stage, message,
                    input_json_path, log_path, result_path, exit_code,
                    created_at, updated_at, started_at, finished_at,
                    run_type, missing_fields_json,
                    reproduction_status, exploitable,
                    verifier_passed, final_reason
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    job_id,
                    cve_id,
                    "queued",
                    "queued",
                    "Job created",
                    input_json_path,
                    log_path,
                    None,
                    None,
                    now,
                    now,
                    None,
                    None,
                    run_type,
                    "[]",
                    "unknown",
                    None,
                    None,
                    None,
                ),
            )

        return self.get(job_id)

    def get(self, job_id: str) -> Job:
        with db_session() as connection:
            row = connection.execute(
                "SELECT * FROM jobs WHERE job_id = ?",
                (job_id,),
            ).fetchone()

        if row is None:
            raise KeyError(job_id)

        return Job.from_row(row)

    def list(self, limit: int = 100) -> list[Job]:
        with db_session() as connection:
            rows = connection.execute(
                """
                SELECT * FROM jobs
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()

        return [Job.from_row(row) for row in rows]

    def update(self, job_id: str, **fields: Any) -> Job:
        if not fields:
            return self.get(job_id)

        if "missing_fields" in fields:
            fields["missing_fields_json"] = json.dumps(
                fields.pop("missing_fields"),
                ensure_ascii=False,
            )

        for boolean_field in ("exploitable", "verifier_passed"):
            if boolean_field in fields:
                value = fields[boolean_field]
                fields[boolean_field] = (
                    None if value is None else int(bool(value))
                )

        fields["updated_at"] = utc_now_iso()

        allowed_columns = {
            "cve_id",
            "status",
            "stage",
            "message",
            "input_json_path",
            "log_path",
            "result_path",
            "exit_code",
            "created_at",
            "updated_at",
            "started_at",
            "finished_at",
            "run_type",
            "missing_fields_json",
            "reproduction_status",
            "exploitable",
            "verifier_passed",
            "final_reason",
        }

        invalid = set(fields) - allowed_columns
        if invalid:
            raise ValueError(
                f"Unsupported job fields: {sorted(invalid)}"
            )

        columns = ", ".join(f"{name} = ?" for name in fields)
        values = list(fields.values()) + [job_id]

        with db_session() as connection:
            cursor = connection.execute(
                f"UPDATE jobs SET {columns} WHERE job_id = ?",
                values,
            )
            if cursor.rowcount == 0:
                raise KeyError(job_id)

        return self.get(job_id)
