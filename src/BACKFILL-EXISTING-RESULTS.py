from pathlib import Path

from cve_genie_web.database import initialize_database
from cve_genie_web.repository import JobRepository
from cve_genie_web.services.reproduction_result_service import (
    parse_reproduction_result,
)


def main() -> None:
    initialize_database()
    repository = JobRepository()

    for job in repository.list(limit=10000):
        if not job.log_path:
            continue

        result = parse_reproduction_result(
            Path(job.log_path)
        )

        if result.reproduction_status == "unknown":
            continue

        repository.update(
            job.job_id,
            reproduction_status=result.reproduction_status,
            exploitable=result.exploitable,
            verifier_passed=result.verifier_passed,
            final_reason=result.final_reason,
        )

        print(
            f"{job.cve_id} {job.job_id}: "
            f"{result.reproduction_status}"
        )


if __name__ == "__main__":
    main()
