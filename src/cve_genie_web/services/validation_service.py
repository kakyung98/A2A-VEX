from __future__ import annotations

import subprocess
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse


class SourceAvailability(str, Enum):
    """
    CVE 대상 소스코드의 확보 가능 상태.
    """

    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    UNCERTAIN = "uncertain"


class AnalysisMode(str, Enum):
    """
    작업이 진행될 분석 경로.
    """

    SOURCE_REPRODUCTION = "source_reproduction"
    ASSET_CONTEXT_ASSESSMENT = "asset_context_assessment"


@dataclass(frozen=True)
class RepositoryProbeResult:
    """
    원격 Git 저장소 접근성 검사 결과.
    """

    repository_url: str
    reachable: bool
    reason: str


@dataclass(frozen=True)
class ValidationResult:
    """
    CVE 입력 데이터의 검증 결과.

    기존 코드와의 호환성을 위해 다음 필드는 유지한다.

    - valid
    - missing_fields
    - unsupported_reasons

    추가 필드는 소스코드 가용성과 분석 모드를 나타낸다.
    """

    valid: bool
    missing_fields: list[str]
    unsupported_reasons: list[str]

    source_availability: SourceAvailability
    analysis_mode: AnalysisMode

    repository_urls: list[str]
    source_archive_urls: list[str]
    patch_urls: list[str]

    source_reasons: list[str]
    repository_probes: list[RepositoryProbeResult]

    @property
    def requires_asset_input(self) -> bool:
        """
        공개 소스를 확보하지 못해 자산 운영 정보가 필요한지 반환한다.
        """

        return (
            self.analysis_mode
            == AnalysisMode.ASSET_CONTEXT_ASSESSMENT
        )

    @property
    def requires_reproduction_input(self) -> bool:
        """
        소스는 확인했지만 버전 등의 재현 정보가 부족한지 반환한다.
        """

        return (
            self.analysis_mode
            == AnalysisMode.SOURCE_REPRODUCTION
            and not self.valid
        )


SOURCE_HOSTS = {
    "github.com",
    "www.github.com",
    "gitlab.com",
    "www.gitlab.com",
    "bitbucket.org",
    "www.bitbucket.org",
    "codeberg.org",
    "www.codeberg.org",
    "sourceforge.net",
    "www.sourceforge.net",
    "git.kernel.org",
    "git.savannah.gnu.org",
    "gitlab.freedesktop.org",
    "invent.kde.org",
}


SOURCE_KEY_NAMES = {
    "repository",
    "repository_url",
    "repository_urls",
    "repo",
    "repo_url",
    "repo_urls",
    "source",
    "source_url",
    "source_urls",
    "source_code",
    "source_code_url",
    "source_code_urls",
    "source_repository",
    "source_repository_url",
    "git",
    "git_url",
    "git_urls",
    "upstream",
    "upstream_url",
    "project_url",
    "project_urls",
}


SOURCE_ARCHIVE_KEY_NAMES = {
    "source_archive",
    "source_archive_url",
    "source_archive_urls",
    "archive",
    "archive_url",
    "archive_urls",
    "download",
    "download_url",
    "download_urls",
    "tarball",
    "tarball_url",
}


PATCH_KEY_NAMES = {
    "patch",
    "patch_url",
    "patch_urls",
    "patch_commit",
    "patch_commits",
    "patch_commit_url",
    "patch_commit_urls",
    "commit",
    "commit_url",
    "commit_urls",
    "fix",
    "fix_url",
    "fix_urls",
    "fix_commit",
    "fix_commits",
}


VERSION_KEY_NAMES = {
    "version",
    "versions",
    "vulnerable_version",
    "vulnerable_versions",
    "affected_version",
    "affected_versions",
    "version_data",
    "affected",
}


CHECKOUT_KEY_NAMES = {
    "tag",
    "tags",
    "git_tag",
    "git_tags",
    "commit",
    "commits",
    "commit_hash",
    "commit_sha",
    "checkout",
    "checkout_ref",
    "checkout_reference",
    "revision",
    "ref",
}


DESCRIPTION_KEY_NAMES = {
    "description",
    "descriptions",
    "summary",
    "details",
    "problem_description",
    "vulnerability_description",
}


BUILD_KEY_NAMES = {
    "build",
    "build_command",
    "build_commands",
    "build_instruction",
    "build_instructions",
    "install",
    "install_command",
    "install_commands",
    "setup",
    "setup_command",
    "setup_commands",
    "prerequisites",
    "pre_requisites",
    "requirements",
}


ARCHIVE_SUFFIXES = (
    ".tar",
    ".tar.gz",
    ".tar.bz2",
    ".tar.xz",
    ".tgz",
    ".tbz",
    ".tbz2",
    ".txz",
    ".zip",
)


def _normalize_key(key: Any) -> str:
    """
    JSON 키를 비교 가능한 형식으로 정규화한다.
    """

    return (
        str(key)
        .strip()
        .lower()
        .replace("-", "_")
        .replace(" ", "_")
    )


def _walk(
    value: Any,
) -> Iterable[tuple[str, Any]]:
    """
    중첩된 dict와 list를 순회하면서
    정규화된 키와 값을 반환한다.
    """

    if isinstance(value, dict):
        for key, child in value.items():
            normalized_key = _normalize_key(key)

            yield normalized_key, child
            yield from _walk(child)

    elif isinstance(value, list):
        for child in value:
            yield from _walk(child)


def _is_non_empty(value: Any) -> bool:
    """
    값이 실제 정보를 포함하는지 검사한다.
    """

    if value is None:
        return False

    if isinstance(value, str):
        normalized = value.strip().lower()

        return normalized not in {
            "",
            "none",
            "null",
            "unknown",
            "n/a",
            "na",
            "not available",
            "not_available",
            "undefined",
        }

    if isinstance(value, dict):
        return any(
            _is_non_empty(child)
            for child in value.values()
        )

    if isinstance(value, list):
        return any(
            _is_non_empty(child)
            for child in value
        )

    return True


def _has_any_key(
    data: Any,
    key_names: set[str],
) -> bool:
    """
    지정된 키들 중 하나라도 유효한 값을 갖는지 검사한다.
    """

    for key, value in _walk(data):
        if key in key_names and _is_non_empty(value):
            return True

    return False


def _collect_strings(value: Any) -> list[str]:
    """
    중첩된 데이터에서 모든 문자열을 추출한다.
    """

    values: list[str] = []

    if isinstance(value, str):
        stripped = value.strip()

        if stripped:
            values.append(stripped)

    elif isinstance(value, dict):
        for child in value.values():
            values.extend(_collect_strings(child))

    elif isinstance(value, list):
        for child in value:
            values.extend(_collect_strings(child))

    return values


def _looks_like_url(value: str) -> bool:
    """
    문자열이 HTTP 또는 Git URL인지 검사한다.
    """

    normalized = value.strip().lower()

    return normalized.startswith(
        (
            "https://",
            "http://",
            "git://",
            "ssh://",
            "git@",
        )
    )


def _normalize_repository_url(url: str) -> str:
    """
    GitHub SSH 형식 등을 일반적인 URL 형식으로 정규화한다.
    """

    stripped = url.strip()

    if stripped.startswith("git@github.com:"):
        path = stripped.removeprefix("git@github.com:")

        return f"https://github.com/{path}"

    if stripped.startswith("git@gitlab.com:"):
        path = stripped.removeprefix("git@gitlab.com:")

        return f"https://gitlab.com/{path}"

    return stripped


def _extract_urls(value: Any) -> list[str]:
    """
    중첩 데이터에서 URL로 보이는 문자열을 추출한다.
    """

    urls: list[str] = []

    for candidate in _collect_strings(value):
        if _looks_like_url(candidate):
            urls.append(
                _normalize_repository_url(candidate)
            )

    return urls


def _get_host(url: str) -> str:
    """
    URL에서 호스트 이름을 추출한다.
    """

    normalized = _normalize_repository_url(url)

    try:
        parsed = urlparse(normalized)
    except ValueError:
        return ""

    return parsed.netloc.lower().split(":", maxsplit=1)[0]


def _get_path(url: str) -> str:
    """
    URL에서 경로를 추출한다.
    """

    normalized = _normalize_repository_url(url)

    try:
        parsed = urlparse(normalized)
    except ValueError:
        return ""

    return parsed.path.lower()


def _is_source_archive_url(url: str) -> bool:
    """
    URL이 소스 아카이브를 가리키는지 검사한다.
    """

    path = _get_path(url)

    return path.endswith(ARCHIVE_SUFFIXES)


def _is_probable_repository_url(url: str) -> bool:
    """
    URL이 공개 소스 저장소를 가리킬 가능성이 있는지 검사한다.
    """

    host = _get_host(url)
    path = _get_path(url)

    if not host:
        return False

    if host in SOURCE_HOSTS:
        if "/issues/" in path:
            return False

        if "/pull/" in path or "/pulls/" in path:
            return False

        if "/releases/" in path and not _is_source_archive_url(url):
            return False

        return True

    repository_markers = (
        ".git",
        "/git/",
        "/repo/",
        "/repos/",
        "/repository/",
        "/repositories/",
        "/source/",
        "/sources/",
        "/src/",
        "/code/",
    )

    return any(
        marker in path
        for marker in repository_markers
    )


def _is_probable_patch_url(url: str) -> bool:
    """
    URL이 패치 또는 수정 커밋을 가리킬 가능성이 있는지 검사한다.
    """

    path = _get_path(url)

    patch_markers = (
        "/commit/",
        "/commits/",
        "/patch/",
        "/patches/",
        ".patch",
        ".diff",
    )

    return any(
        marker in path
        for marker in patch_markers
    )


def _deduplicate(values: Iterable[str]) -> list[str]:
    """
    입력 순서를 보존하면서 중복 문자열을 제거한다.
    """

    result: list[str] = []
    seen: set[str] = set()

    for value in values:
        normalized = value.strip()

        if not normalized:
            continue

        if normalized in seen:
            continue

        seen.add(normalized)
        result.append(normalized)

    return result


def _collect_source_references(
    data: dict[str, Any],
) -> tuple[list[str], list[str], list[str]]:
    """
    CVE 입력 데이터에서 저장소, 소스 아카이브,
    패치 URL을 수집한다.
    """

    repository_urls: list[str] = []
    source_archive_urls: list[str] = []
    patch_urls: list[str] = []

    for key, value in _walk(data):
        urls = _extract_urls(value)

        if key in SOURCE_KEY_NAMES:
            for url in urls:
                if _is_source_archive_url(url):
                    source_archive_urls.append(url)
                elif _is_probable_repository_url(url):
                    repository_urls.append(url)

        if key in SOURCE_ARCHIVE_KEY_NAMES:
            for url in urls:
                if _is_source_archive_url(url):
                    source_archive_urls.append(url)
                elif _is_probable_repository_url(url):
                    repository_urls.append(url)

        if key in PATCH_KEY_NAMES:
            for url in urls:
                if _is_probable_patch_url(url):
                    patch_urls.append(url)

    # 키 이름을 자동 추출기가 다르게 생성했을 가능성이 있으므로,
    # 전체 URL을 대상으로 한 번 더 보수적으로 검사한다.
    for url in _extract_urls(data):
        if _is_source_archive_url(url):
            source_archive_urls.append(url)
            continue

        if _is_probable_patch_url(url):
            patch_urls.append(url)

            # GitHub/GitLab commit URL이면 저장소 루트도 유추할 수 있다.
            inferred_repository = _infer_repository_from_commit_url(
                url
            )

            if inferred_repository:
                repository_urls.append(inferred_repository)

            continue

        if _is_probable_repository_url(url):
            repository_urls.append(url)

    return (
        _deduplicate(repository_urls),
        _deduplicate(source_archive_urls),
        _deduplicate(patch_urls),
    )


def _infer_repository_from_commit_url(
    url: str,
) -> str | None:
    """
    GitHub 또는 GitLab 커밋 URL에서 저장소 루트 URL을 유추한다.
    """

    normalized = _normalize_repository_url(url)

    try:
        parsed = urlparse(normalized)
    except ValueError:
        return None

    host = parsed.netloc.lower()
    parts = [
        part
        for part in parsed.path.split("/")
        if part
    ]

    if host in {
        "github.com",
        "www.github.com",
        "gitlab.com",
        "www.gitlab.com",
    }:
        if len(parts) < 2:
            return None

        return (
            f"{parsed.scheme or 'https'}://"
            f"{parsed.netloc}/"
            f"{parts[0]}/{parts[1]}"
        )

    return None


def _probe_git_repository(
    repository_url: str,
    timeout_seconds: int,
) -> RepositoryProbeResult:
    """
    git ls-remote로 원격 Git 저장소가 실제 접근 가능한지 검사한다.

    이 함수는 clone하지 않으므로 전체 소스를 내려받지 않는다.
    """

    normalized_url = _normalize_repository_url(
        repository_url
    )

    try:
        process = subprocess.run(
            [
                "git",
                "ls-remote",
                "--heads",
                "--tags",
                normalized_url,
            ],
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            shell=False,
            check=False,
        )

    except subprocess.TimeoutExpired:
        return RepositoryProbeResult(
            repository_url=normalized_url,
            reachable=False,
            reason=(
                "Repository availability check timed out."
            ),
        )

    except FileNotFoundError:
        return RepositoryProbeResult(
            repository_url=normalized_url,
            reachable=False,
            reason=(
                "The git executable is not installed "
                "or is not available in PATH."
            ),
        )

    except OSError as exc:
        return RepositoryProbeResult(
            repository_url=normalized_url,
            reachable=False,
            reason=(
                "Repository availability check failed: "
                f"{exc}"
            ),
        )

    if process.returncode != 0:
        error_message = (
            process.stderr.strip()
            or process.stdout.strip()
            or "The repository did not respond successfully."
        )

        return RepositoryProbeResult(
            repository_url=normalized_url,
            reachable=False,
            reason=error_message,
        )

    if not process.stdout.strip():
        return RepositoryProbeResult(
            repository_url=normalized_url,
            reachable=False,
            reason=(
                "The repository returned no branches or tags."
            ),
        )

    return RepositoryProbeResult(
        repository_url=normalized_url,
        reachable=True,
        reason="The remote Git repository is reachable.",
    )


def _probe_repositories(
    repository_urls: list[str],
    timeout_seconds: int,
) -> list[RepositoryProbeResult]:
    """
    발견된 저장소 URL들을 순서대로 검사한다.

    하나라도 접근 가능하면 나머지 검사는 수행하지 않는다.
    불필요한 외부 요청과 지연을 줄이기 위함이다.
    """

    results: list[RepositoryProbeResult] = []

    for repository_url in repository_urls:
        result = _probe_git_repository(
            repository_url=repository_url,
            timeout_seconds=timeout_seconds,
        )

        results.append(result)

        if result.reachable:
            break

    return results


def _has_reachable_repository(
    probes: list[RepositoryProbeResult],
) -> bool:
    """
    접근 가능한 저장소가 하나 이상 있는지 반환한다.
    """

    return any(
        probe.reachable
        for probe in probes
    )


def _validate_base_context(
    data: dict[str, Any],
) -> tuple[list[str], list[str]]:
    """
    모든 분석 모드에 공통으로 필요한 기본 CVE 정보를 검사한다.
    """

    missing_fields: list[str] = []
    unsupported_reasons: list[str] = []

    if not isinstance(data, dict) or not data:
        return (
            ["cve_data"],
            ["The extracted CVE input is empty or invalid."],
        )

    if not _has_any_key(
        data,
        DESCRIPTION_KEY_NAMES,
    ):
        missing_fields.append("description")

    return missing_fields, unsupported_reasons


def _validate_reproduction_context(
    data: dict[str, Any],
    repository_urls: list[str],
    source_archive_urls: list[str],
) -> list[str]:
    """
    CVE-Genie 소스 재현에 필요한 정보를 검사한다.
    """

    missing_fields: list[str] = []

    if not repository_urls and not source_archive_urls:
        missing_fields.append("source.repository_or_archive")

    if not _has_any_key(
        data,
        VERSION_KEY_NAMES,
    ):
        missing_fields.append("affected.version")

    # 버전 정보가 있으면 tag나 commit이 반드시 필요한 것은 아니다.
    # CVE-Genie가 버전 기반 checkout을 시도할 수 있기 때문이다.
    has_version = _has_any_key(
        data,
        VERSION_KEY_NAMES,
    )

    has_checkout_reference = _has_any_key(
        data,
        CHECKOUT_KEY_NAMES,
    )

    if not has_version and not has_checkout_reference:
        missing_fields.append(
            "source.version_or_checkout_reference"
        )

    # 빌드 정보는 LLM이 저장소를 분석해 유추할 수 있으므로
    # 자동 실행을 막는 필수 조건으로 두지 않는다.
    #
    # 다만 대시보드 안내를 위해 필요하다면 아래 조건을
    # optional_missing_fields 같은 별도 필드로 확장할 수 있다.
    _ = _has_any_key(
        data,
        BUILD_KEY_NAMES,
    )

    return _deduplicate(missing_fields)


def validate_cve_input(
    data: dict[str, Any],
    *,
    probe_remote_repositories: bool = True,
    repository_probe_timeout_seconds: int = 20,
) -> ValidationResult:
    """
    추출되거나 사용자가 수정한 CVE 입력 JSON을 검증한다.

    처리 기준:

    1. 저장소 또는 소스 아카이브가 확보 가능하면
       SOURCE_REPRODUCTION 모드로 분류한다.

    2. 소스 참조가 없으면
       ASSET_CONTEXT_ASSESSMENT 모드로 분류한다.

    3. 패치 URL만 있고 저장소를 유추할 수 없으면
       소스 상태를 UNCERTAIN으로 분류한다.

    4. 저장소는 있지만 취약 버전 등의 정보가 부족하면
       기존 needs_input 경로로 보낼 수 있도록 valid=False를 반환한다.

    5. 소스가 없으면 asset 입력 화면으로 보낼 수 있도록
       requires_asset_input=True가 되는 결과를 반환한다.
    """

    base_missing_fields, unsupported_reasons = (
        _validate_base_context(data)
    )

    (
        repository_urls,
        source_archive_urls,
        patch_urls,
    ) = _collect_source_references(data)

    source_reasons: list[str] = []
    repository_probes: list[RepositoryProbeResult] = []

    if (
        repository_urls
        and probe_remote_repositories
    ):
        repository_probes = _probe_repositories(
            repository_urls=repository_urls,
            timeout_seconds=(
                repository_probe_timeout_seconds
            ),
        )

    reachable_repository = (
        _has_reachable_repository(repository_probes)
    )

    if source_archive_urls:
        source_availability = (
            SourceAvailability.AVAILABLE
        )
        analysis_mode = (
            AnalysisMode.SOURCE_REPRODUCTION
        )
        source_reasons.append(
            "A source archive reference was found."
        )

    elif repository_urls and not probe_remote_repositories:
        source_availability = (
            SourceAvailability.AVAILABLE
        )
        analysis_mode = (
            AnalysisMode.SOURCE_REPRODUCTION
        )
        source_reasons.append(
            "A source repository reference was found. "
            "Remote reachability was not checked."
        )

    elif reachable_repository:
        source_availability = (
            SourceAvailability.AVAILABLE
        )
        analysis_mode = (
            AnalysisMode.SOURCE_REPRODUCTION
        )
        source_reasons.append(
            "At least one public source repository is reachable."
        )

    elif repository_urls:
        source_availability = (
            SourceAvailability.UNCERTAIN
        )
        analysis_mode = (
            AnalysisMode.ASSET_CONTEXT_ASSESSMENT
        )
        source_reasons.append(
            "Source repository references were found, "
            "but none could be reached."
        )

    elif patch_urls:
        source_availability = (
            SourceAvailability.UNCERTAIN
        )
        analysis_mode = (
            AnalysisMode.ASSET_CONTEXT_ASSESSMENT
        )
        source_reasons.append(
            "Patch evidence was found, but a complete "
            "source repository or source archive "
            "could not be identified."
        )

    else:
        source_availability = (
            SourceAvailability.UNAVAILABLE
        )
        analysis_mode = (
            AnalysisMode.ASSET_CONTEXT_ASSESSMENT
        )
        source_reasons.append(
            "No public source repository, source archive, "
            "or usable source reference was identified."
        )

    if (
        analysis_mode
        == AnalysisMode.ASSET_CONTEXT_ASSESSMENT
    ):
        asset_missing_fields = [
            "asset.product_name",
            "asset.installed_version",
            "asset.deployment_type",
            "asset.runtime.service_running",
            "asset.runtime.vulnerable_feature_enabled",
            "asset.runtime.component_loaded",
            "asset.runtime.component_reachable",
            "asset.exposure.internet_exposed",
            "asset.exposure.listening_ports",
            "asset.patch_status",
            "asset.security_controls",
        ]

        return ValidationResult(
            valid=False,
            missing_fields=_deduplicate(
                base_missing_fields
                + asset_missing_fields
            ),
            unsupported_reasons=unsupported_reasons,
            source_availability=source_availability,
            analysis_mode=analysis_mode,
            repository_urls=repository_urls,
            source_archive_urls=source_archive_urls,
            patch_urls=patch_urls,
            source_reasons=source_reasons,
            repository_probes=repository_probes,
        )

    reproduction_missing_fields = (
        _validate_reproduction_context(
            data=data,
            repository_urls=repository_urls,
            source_archive_urls=source_archive_urls,
        )
    )

    all_missing_fields = _deduplicate(
        base_missing_fields
        + reproduction_missing_fields
    )

    return ValidationResult(
        valid=not all_missing_fields
        and not unsupported_reasons,
        missing_fields=all_missing_fields,
        unsupported_reasons=unsupported_reasons,
        source_availability=source_availability,
        analysis_mode=analysis_mode,
        repository_urls=repository_urls,
        source_archive_urls=source_archive_urls,
        patch_urls=patch_urls,
        source_reasons=source_reasons,
        repository_probes=repository_probes,
    )


def validate_input(
    data: dict[str, Any],
) -> ValidationResult:
    """
    기존 코드에서 validate_input()을 호출하는 경우를 위한 호환 함수.
    """

    return validate_cve_input(data)


def validate(
    data: dict[str, Any],
) -> ValidationResult:
    """
    기존 코드에서 validate()를 호출하는 경우를 위한 호환 함수.
    """

    return validate_cve_input(data)


def validate_input_file(
    input_path: str | Path,
) -> ValidationResult:
    """
    JSON 파일을 직접 검증하기 위한 편의 함수.

    일반적인 웹 작업 흐름에서는 input_service에서 JSON을 읽은 뒤
    validate_cve_input()을 호출하는 방식을 권장한다.
    """

    import json

    path = Path(input_path)

    if not path.exists():
        return ValidationResult(
            valid=False,
            missing_fields=["input_file"],
            unsupported_reasons=[
                f"Input file does not exist: {path}"
            ],
            source_availability=(
                SourceAvailability.UNAVAILABLE
            ),
            analysis_mode=(
                AnalysisMode.ASSET_CONTEXT_ASSESSMENT
            ),
            repository_urls=[],
            source_archive_urls=[],
            patch_urls=[],
            source_reasons=[
                "The CVE input file could not be read."
            ],
            repository_probes=[],
        )

    try:
        with path.open(
            "r",
            encoding="utf-8",
        ) as file:
            data = json.load(file)

    except json.JSONDecodeError as exc:
        return ValidationResult(
            valid=False,
            missing_fields=["input_json"],
            unsupported_reasons=[
                f"Invalid JSON input: {exc}"
            ],
            source_availability=(
                SourceAvailability.UNAVAILABLE
            ),
            analysis_mode=(
                AnalysisMode.ASSET_CONTEXT_ASSESSMENT
            ),
            repository_urls=[],
            source_archive_urls=[],
            patch_urls=[],
            source_reasons=[
                "The CVE input file contains invalid JSON."
            ],
            repository_probes=[],
        )

    except OSError as exc:
        return ValidationResult(
            valid=False,
            missing_fields=["input_file"],
            unsupported_reasons=[
                f"Could not read input file: {exc}"
            ],
            source_availability=(
                SourceAvailability.UNAVAILABLE
            ),
            analysis_mode=(
                AnalysisMode.ASSET_CONTEXT_ASSESSMENT
            ),
            repository_urls=[],
            source_archive_urls=[],
            patch_urls=[],
            source_reasons=[
                "The CVE input file could not be read."
            ],
            repository_probes=[],
        )

    if not isinstance(data, dict):
        return ValidationResult(
            valid=False,
            missing_fields=["cve_data"],
            unsupported_reasons=[
                "The top-level JSON value must be an object."
            ],
            source_availability=(
                SourceAvailability.UNAVAILABLE
            ),
            analysis_mode=(
                AnalysisMode.ASSET_CONTEXT_ASSESSMENT
            ),
            repository_urls=[],
            source_archive_urls=[],
            patch_urls=[],
            source_reasons=[
                "The CVE input has an unsupported JSON structure."
            ],
            repository_probes=[],
        )

    return validate_cve_input(data)

def validate_reproduction_input(
    data: dict[str, Any],
    *,
    expected_cve_id: str | None = None,
    probe_remote_repositories: bool = True,
    repository_probe_timeout_seconds: int = 20,
) -> ValidationResult:
    """
    기존 routes/jobs.py 및 job_worker.py와의 호환을 위한 함수.

    기존 코드가 validate_reproduction_input()을 호출해도
    새 validate_cve_input() 검증 로직을 사용하도록 연결한다.
    """

    result = validate_cve_input(
        data,
        probe_remote_repositories=(
            probe_remote_repositories
        ),
        repository_probe_timeout_seconds=(
            repository_probe_timeout_seconds
        ),
    )

    if expected_cve_id is None:
        return result

    normalized_expected = (
        expected_cve_id
        .strip()
        .upper()
    )

    document_strings = [
        value.strip().upper()
        for value in _collect_strings(data)
        if isinstance(value, str)
    ]

    cve_id_found = (
        normalized_expected in document_strings
        or normalized_expected in {
            str(key).strip().upper()
            for key in data.keys()
        }
    )

    if cve_id_found:
        return result

    missing_fields = _deduplicate(
        list(result.missing_fields)
        + ["cve_id"]
    )

    unsupported_reasons = _deduplicate(
        list(result.unsupported_reasons)
        + [
            (
                "The input JSON does not contain the "
                f"expected CVE identifier: "
                f"{normalized_expected}"
            )
        ]
    )

    return ValidationResult(
        valid=False,
        missing_fields=missing_fields,
        unsupported_reasons=unsupported_reasons,
        source_availability=(
            result.source_availability
        ),
        analysis_mode=result.analysis_mode,
        repository_urls=list(
            result.repository_urls
        ),
        source_archive_urls=list(
            result.source_archive_urls
        ),
        patch_urls=list(
            result.patch_urls
        ),
        source_reasons=list(
            result.source_reasons
        ),
        repository_probes=list(
            result.repository_probes
        ),
    )