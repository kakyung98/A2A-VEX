from cve_genie_a2a.config import settings
from cve_genie_a2a.service_factory import create_phase_agent

app = create_phase_agent(
    name="CVE-Genie Verification Agent",
    description=(
        "Creates a CTF verifier, validates exploit behavior, and runs "
        "the SanityGuy consistency review."
    ),
    skill_id="cve.verification.verify",
    skill_name="Verify CVE reproduction",
    run_type="verify",
    public_url=settings.verification_agent_url,
)
