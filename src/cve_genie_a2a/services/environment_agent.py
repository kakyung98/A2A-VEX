from cve_genie_a2a.config import settings
from cve_genie_a2a.service_factory import create_phase_agent

app = create_phase_agent(
    name="CVE-Genie Environment Agent",
    description=(
        "Builds CVE knowledge, prerequisites, vulnerable repository, "
        "and repository-critic evidence."
    ),
    skill_id="cve.environment.build",
    skill_name="Build vulnerable environment",
    run_type="build",
    public_url=settings.environment_agent_url,
)
