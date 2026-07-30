from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path
from typing import Any

import requests
from playwright.sync_api import sync_playwright


CVE_DIR = (
    Path(__file__).resolve().parent
    / ".."
    / "cvelistV5"
    / "cves"
).resolve()


def fetch_references(
    data: dict[str, Any],
) -> tuple[list[dict[str, str]], list[str]]:
    """
    CVE 레코드의 참조 URL에서 Git 저장소 패치 커밋과
    기타 참조 URL을 분리한다.
    """

    cna = (
        data.get("containers", {})
        .get("cna", {})
    )

    references = cna.get("references", [])

    if not isinstance(references, list):
        return [], []

    git_re = (
        r"(((?P<repo>(https|http):\/\/"
        r"(bitbucket|github|gitlab)\.(org|com)\/"
        r"(?P<owner>[^\/]+)\/(?P<project>[^\/]*))\/"
        r"(commit|commits)\/(?P<hash>\w+)#?)+)"
    )

    patch_commit_data: list[dict[str, str]] = []
    other_urls: list[str] = []

    for reference in references:
        if not isinstance(reference, dict):
            continue

        reference_url = reference.get("url")

        if not isinstance(reference_url, str):
            continue

        match = re.search(
            git_re,
            reference_url,
        )

        if match:
            repository_url = match.group("repo")

            if repository_url.startswith("http:"):
                repository_url = (
                    "https:"
                    + repository_url[len("http:"):]
                )

            patch_commit_data.append(
                {
                    "owner": match.group("owner"),
                    "project": match.group("project"),
                    "hash": match.group("hash"),
                    "repo_url": repository_url,
                    "patch_commit_url": reference_url,
                }
            )
        else:
            other_urls.append(reference_url)

    return patch_commit_data, other_urls


def get_cwe_info(
    data: dict[str, Any],
) -> list[dict[str, str]]:
    """
    CVE JSON에서 CWE 정보를 안전하게 추출한다.

    CVE List V5 레코드는 CWE 정보를 다음과 같이 서로 다른
    필드에 저장할 수 있다.

    - cweId
    - description
    - value

    필드가 없거나 자료형이 예상과 다른 경우 해당 항목을
    건너뛴다.
    """

    cwes: list[dict[str, str]] = []

    cna = (
        data.get("containers", {})
        .get("cna", {})
    )

    problem_types = cna.get(
        "problemTypes",
        [],
    )

    if not isinstance(problem_types, list):
        return cwes

    for problem_type in problem_types:
        if not isinstance(problem_type, dict):
            continue

        descriptions = problem_type.get(
            "descriptions",
            [],
        )

        if not isinstance(descriptions, list):
            continue

        for description in descriptions:
            if not isinstance(description, dict):
                continue

            description_type = description.get("type")

            if (
                isinstance(description_type, str)
                and description_type.lower() != "cwe"
            ):
                continue

            language = description.get("lang")

            if (
                isinstance(language, str)
                and language.lower() != "en"
            ):
                continue

            cwe_id = description.get("cweId")
            description_text = description.get(
                "description"
            )
            value_text = description.get("value")

            if not isinstance(cwe_id, str):
                cwe_id = ""

            if not isinstance(description_text, str):
                description_text = ""

            if not isinstance(value_text, str):
                value_text = ""

            searchable_text = " ".join(
                part
                for part in (
                    cwe_id,
                    description_text,
                    value_text,
                )
                if part
            )

            cwe_match = re.search(
                r"CWE-(\d+)",
                searchable_text,
                flags=re.IGNORECASE,
            )

            if cwe_id:
                normalized_id = cwe_id.upper()
            elif cwe_match:
                normalized_id = (
                    f"CWE-{cwe_match.group(1)}"
                )
            else:
                normalized_id = "not provided"

            if description_text:
                normalized_value = description_text
            elif value_text:
                normalized_value = value_text
            else:
                normalized_value = "not provided"

            cwe_info = {
                "id": normalized_id,
                "value": normalized_value,
            }

            if cwe_info not in cwes:
                cwes.append(cwe_info)

    return cwes


def get_version_info(
    data: dict[str, Any],
) -> tuple[str, str]:
    """
    CVE 레코드에서 재현에 사용할 영향을 받는 버전 정보를
    추출한다.
    """

    cna = (
        data.get("containers", {})
        .get("cna", {})
    )

    vendor_data = cna.get("affected", [])

    if not isinstance(vendor_data, list):
        return "n/a", "n/a"

    invalid_versions = {
        "",
        "unspecified",
        "*",
        "0",
        "n/a",
    }

    for vendor in vendor_data:
        if not isinstance(vendor, dict):
            continue

        versions = vendor.get("versions", [])

        if not isinstance(versions, list):
            continue

        for version in versions:
            if not isinstance(version, dict):
                continue

            status = version.get("status")

            if (
                isinstance(status, str)
                and status.lower() != "affected"
            ):
                continue

            less_than = version.get("lessThan")

            if (
                isinstance(less_than, str)
                and less_than.strip()
            ):
                return less_than.strip(), "lessThan"

            less_than_or_equal = version.get(
                "lessThanOrEqual"
            )

            if (
                isinstance(less_than_or_equal, str)
                and less_than_or_equal.strip()
            ):
                return (
                    less_than_or_equal.strip(),
                    "lessThanOrEqual",
                )

            version_value = version.get("version")

            if not isinstance(version_value, str):
                continue

            normalized_version = version_value.strip()

            if (
                normalized_version.lower()
                not in invalid_versions
            ):
                return normalized_version, "equal"

    return "n/a", "n/a"


def process_cve_data(
    data: dict[str, Any],
) -> dict[str, Any]:
    """
    CVE List V5 레코드를 CVE-Genie 입력에 필요한
    데이터 구조로 변환한다.
    """

    cve_data: dict[str, Any] = {}

    metadata = data.get("cveMetadata", {})

    if not isinstance(metadata, dict):
        return {}

    cve_id = metadata.get("cveId")

    if not isinstance(cve_id, str):
        return {}

    cve_data["id"] = cve_id

    containers = data.get("containers", {})

    if not isinstance(containers, dict):
        return cve_data

    cna = containers.get("cna", {})

    if not isinstance(cna, dict):
        return cve_data

    descriptions = cna.get("descriptions", [])
    english_descriptions: list[str] = []

    if isinstance(descriptions, list):
        for description in descriptions:
            if not isinstance(description, dict):
                continue

            language = description.get("lang")
            value = description.get("value")

            if (
                isinstance(language, str)
                and language.lower() == "en"
                and isinstance(value, str)
                and value.strip()
            ):
                english_descriptions.append(
                    value.strip()
                )

    cve_data["description"] = (
        english_descriptions[0]
        if english_descriptions
        else ""
    )

    published_date = metadata.get("datePublished")

    cve_data["published_date"] = (
        published_date
        if isinstance(published_date, str)
        else ""
    )

    cve_data["cwes"] = get_cwe_info(data)

    patch_urls, other_urls = fetch_references(data)

    # 패치 커밋이 없더라도 부분 JSON을 반환할 수 있도록
    # 항상 필드를 저장한다.
    cve_data["patch_urls"] = patch_urls
    cve_data["other_urls"] = other_urls

    version, version_type = get_version_info(data)

    if (
        version != "n/a"
        and version_type != "n/a"
    ):
        cve_data["version_data"] = {
            "version": version,
            "version_type": version_type,
        }
    else:
        cve_data["version_data"] = {}

    return cve_data


def get_cve_by_id(
    cve_id: str,
) -> dict[str, Any] | None:
    """
    로컬 cvelistV5 저장소에서 CVE ID에 해당하는
    JSON 파일을 찾아 가공된 CVE 정보를 반환한다.
    """

    normalized_cve_id = cve_id.strip().upper()

    cve_match = re.fullmatch(
        r"CVE-(\d{4})-(\d{4,})",
        normalized_cve_id,
    )

    if not cve_match:
        raise ValueError(
            "Invalid CVE ID format. "
            "Expected format: CVE-YYYY-NNNN"
        )

    year = int(cve_match.group(1))
    number = int(cve_match.group(2))

    subdirectory = (
        Path(str(year))
        / f"{number // 1000}xxx"
    )

    file_path = (
        CVE_DIR
        / subdirectory
        / f"{normalized_cve_id}.json"
    )

    if not file_path.exists():
        print(f"{file_path} does not exist")
        return None

    try:
        with file_path.open(
            "r",
            encoding="utf-8",
        ) as file:
            raw_cve_data = json.load(file)
    except UnicodeDecodeError:
        with file_path.open(
            "r",
            encoding="ISO-8859-1",
        ) as file:
            raw_cve_data = json.load(file)

    if not isinstance(raw_cve_data, dict):
        print(
            "Invalid CVE JSON root type: "
            f"{type(raw_cve_data).__name__}"
        )
        return None

    return process_cve_data(raw_cve_data)


def affected_version_exist(
    repo_owner: str,
    repo_name: str,
    version: str,
    version_type: str,
) -> str:
    """
    GitHub 저장소의 태그 목록에서 영향을 받는 버전에
    사용할 수 있는 태그를 찾는다.
    """

    github_token = os.getenv("GITHUB_TOKEN", "")

    headers = {
        "Accept": "application/vnd.github.v3+json",
    }

    if github_token:
        headers["Authorization"] = (
            f"Bearer {github_token}"
        )

    tag = ""

    if "equal" in version_type.lower():
        candidate_tags = [
            f"v{version}",
            version,
        ]

        for candidate_tag in candidate_tags:
            url = (
                "https://api.github.com/repos/"
                f"{repo_owner}/{repo_name}/git/ref/tags/"
                f"{candidate_tag}"
            )

            response = requests.get(
                url,
                headers=headers,
                timeout=30,
            )

            if response.status_code == 200:
                return candidate_tag

            print(
                f"{candidate_tag} does not exist as "
                f"a tag. Error: {response.status_code}"
            )

    if (
        not tag
        and "lessthan" in version_type.lower()
    ):
        page = 1
        found_boundary = False

        while True:
            url = (
                "https://api.github.com/repos/"
                f"{repo_owner}/{repo_name}/tags"
            )

            params = {
                "per_page": 100,
                "page": page,
            }

            response = requests.get(
                url,
                headers=headers,
                params=params,
                timeout=30,
            )

            if response.status_code != 200:
                print(
                    "Failed to retrieve tags. "
                    f"Status: {response.status_code}, "
                    f"response: {response.text}"
                )
                break

            tags = response.json()

            if not isinstance(tags, list) or not tags:
                break

            for tag_info in tags:
                if not isinstance(tag_info, dict):
                    continue

                tag_name = tag_info.get("name")

                if not isinstance(tag_name, str):
                    continue

                if found_boundary:
                    return tag_name

                if tag_name in {
                    version,
                    f"v{version}",
                }:
                    found_boundary = True

            page += 1

    return tag


def get_commit_data(
    repo_owner: str,
    repo_name: str,
    commit_hash: str,
) -> dict[str, Any] | None:
    """
    GitHub API를 사용하여 커밋과 파일 변경 정보를 가져온다.
    """

    url = (
        "https://api.github.com/repos/"
        f"{repo_owner}/{repo_name}/commits/"
        f"{commit_hash}"
    )

    github_token = os.getenv("GITHUB_TOKEN", "")

    headers = {
        "Accept": "application/vnd.github.v3+json",
    }

    if github_token:
        headers["Authorization"] = (
            f"token {github_token}"
        )

    response: requests.Response | None = None

    while True:
        try:
            response = requests.get(
                url,
                headers=headers,
                timeout=30,
            )
        except requests.RequestException as error:
            print(
                "Failed to request commit data: "
                f"{error}"
            )
            return None

        if response.status_code == 403:
            print(
                "GitHub rate limit exceeded. "
                "Waiting for 60 seconds..."
            )
            time.sleep(60)
            continue

        break

    if response.status_code != 200:
        print(
            "Failed to fetch commit data. "
            f"Status code: {response.status_code}"
        )
        return None

    commit_data = response.json()

    if not isinstance(commit_data, dict):
        return None

    commit_info = commit_data.get("commit", {})
    commit_message = ""

    if isinstance(commit_info, dict):
        message = commit_info.get("message")

        if isinstance(message, str):
            commit_message = message

    result: dict[str, Any] = {
        "url": commit_data.get("html_url", url),
        "msg": commit_message,
        "file_patch": [],
    }

    files = commit_data.get("files", [])

    if not isinstance(files, list):
        return result

    for changed_file in files:
        if not isinstance(changed_file, dict):
            continue

        filename = changed_file.get(
            "filename",
            "unknown",
        )

        file_patch: dict[str, Any] = {
            "file_name": filename,
            "hunks": [],
        }

        patch = changed_file.get("patch")

        if isinstance(patch, str):
            patch_sections = patch.split("@@")

            patch_indexes = range(
                2,
                len(patch_sections),
                2,
            )

            for index in patch_indexes:
                header = (
                    "@@"
                    + patch_sections[index - 1]
                    + "@@"
                )

                patch_text = (
                    patch_sections[index].strip()
                )

                file_patch["hunks"].append(
                    {
                        "header": header,
                        "patch": patch_text,
                    }
                )

        result["file_patch"].append(file_patch)

    return result


def get_patch_content(
    owner: str,
    project: str,
    hash: str,
) -> str | None:
    """
    GitHub 커밋 정보를 CVE-Genie가 사용할 수 있는
    텍스트 패치 표현으로 변환한다.
    """

    patch_data = get_commit_data(
        owner,
        project,
        hash,
    )

    if not patch_data:
        return None

    sections: list[str] = []

    commit_message = patch_data.get("msg", "")

    if isinstance(commit_message, str):
        sections.append(commit_message)

    file_patches = patch_data.get(
        "file_patch",
        [],
    )

    if isinstance(file_patches, list):
        for file_data in file_patches:
            if not isinstance(file_data, dict):
                continue

            filename = file_data.get(
                "file_name",
                "unknown",
            )

            hunk_contents: list[str] = []
            hunks = file_data.get("hunks", [])

            if isinstance(hunks, list):
                for hunk in hunks:
                    if not isinstance(hunk, dict):
                        continue

                    header = hunk.get("header", "")
                    patch = hunk.get("patch", "")

                    hunk_contents.append(
                        f"{header}\n{patch}"
                    )

            sections.append(
                "\nFilename: "
                f"{filename}:\n```\n"
                + "\n\n".join(hunk_contents)
                + "\n```"
            )

    return "\n".join(sections)


def scrape(
    url: str,
) -> str | None:
    """
    Playwright Chromium을 사용하여 URL의 본문 텍스트를
    가져온다.
    """

    playwright = sync_playwright().start()
    browser = None

    try:
        browser = playwright.chromium.launch(
            headless=True
        )

        page = browser.new_page()

        page.goto(
            url,
            wait_until="domcontentloaded",
            timeout=30000,
        )

        try:
            page.wait_for_load_state(
                "networkidle",
                timeout=10000,
            )
        except Exception as error:
            print(
                "Error waiting for load state: "
                f"{error}"
            )

        content = page.locator("body").inner_text()

        if (
            "sign in" in content.lower()
            and len(content) < 500
        ):
            print(
                f"Error: {url} is a sign-in page"
            )
            return None

        return content

    except Exception as error:
        print(
            f"Error: {url} has this error: "
            f"{error}"
        )
        return None

    finally:
        if browser is not None:
            browser.close()

        playwright.stop()