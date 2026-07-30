import argparse
import json
import os
import traceback
from typing import Any

from dotenv import load_dotenv

from cve_processor import (
    affected_version_exist,
    get_cve_by_id,
    get_patch_content,
    scrape,
)


load_dotenv()


def load_existing_data(path: str) -> dict[str, Any]:
    """
    Load an existing output JSON file when possible.

    Invalid, empty, or non-object JSON files are treated as empty data so
    that extraction can continue safely.
    """
    if not os.path.exists(path):
        return {}

    try:
        with open(path, "r", encoding="utf-8") as file:
            value = json.load(file)
    except (OSError, json.JSONDecodeError):
        return {}

    return value if isinstance(value, dict) else {}


def normalize_dict_list(value: Any) -> list[dict[str, Any]]:
    """
    Convert an optional value into a list containing dictionary items only.
    """
    if not isinstance(value, list):
        return []

    return [item for item in value if isinstance(item, dict)]


def normalize_string_list(value: Any) -> list[str]:
    """
    Convert an optional value into a list containing non-empty strings only.
    """
    if not isinstance(value, list):
        return []

    return [
        item.strip()
        for item in value
        if isinstance(item, str) and item.strip()
    ]


def collect_patch_commits(
    patch_urls: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Retrieve patch content for patch records that contain all required fields.

    A failure to retrieve an individual patch does not abort extraction.
    """
    patch_commits: list[dict[str, Any]] = []

    for patch in patch_urls:
        patch_commit_url = patch.get("patch_commit_url")
        owner = patch.get("owner")
        project = patch.get("project")
        commit_hash = patch.get("hash")

        if not all(
            isinstance(value, str) and value.strip()
            for value in (
                patch_commit_url,
                owner,
                project,
                commit_hash,
            )
        ):
            continue

        try:
            patch_content = get_patch_content(
                owner.strip(),
                project.strip(),
                commit_hash.strip(),
            )
        except Exception as exc:
            print(
                "[!] Failed to retrieve patch content "
                f"from {patch_commit_url}: {exc}"
            )
            patch_content = None

        patch_commits.append(
            {
                "url": patch_commit_url,
                "content": patch_content,
            }
        )

    return patch_commits


def resolve_vulnerable_version(
    patch_urls: list[dict[str, Any]],
    version_data: dict[str, Any],
) -> tuple[str | None, str | None]:
    """
    Resolve a vulnerable GitHub tag and its downloadable archive URL.

    Missing patch or version information is considered incomplete context,
    not a fatal extraction error.
    """
    if not patch_urls:
        return None, None

    version = version_data.get("version")
    version_type = version_data.get("version_type")

    if not (
        isinstance(version, str)
        and version.strip()
        and isinstance(version_type, str)
        and version_type.strip()
    ):
        return None, None

    first_patch = patch_urls[0]

    owner = first_patch.get("owner")
    project = first_patch.get("project")
    repo_url = first_patch.get("repo_url")

    if not all(
        isinstance(value, str) and value.strip()
        for value in (owner, project, repo_url)
    ):
        return None, None

    try:
        tag = affected_version_exist(
            owner.strip(),
            project.strip(),
            version.strip(),
            version_type.strip(),
        )
    except Exception as exc:
        print(f"[!] Failed to resolve affected version: {exc}")
        return None, None

    if not tag:
        return None, None

    normalized_repo_url = repo_url.rstrip("/")
    archive_url = (
        f"{normalized_repo_url}/archive/refs/tags/{tag}.zip"
    )

    return str(tag), archive_url


def collect_security_advisories(
    potential_advisories: list[str],
) -> list[dict[str, Any]]:
    """
    Scrape likely security advisory or issue URLs.

    Individual scraping failures are logged and skipped.
    """
    keywords = {
        "security",
        "advisory",
        "advisories",
        "bounties",
        "bounty",
        "issue",
        "issues",
    }

    excluded_suffixes = (
        ".patch",
        ".txt",
        ".pdf",
        ".zip",
    )

    sec_advs: list[dict[str, Any]] = []

    for url in potential_advisories:
        normalized_url = url.strip()

        if normalized_url.lower().endswith(excluded_suffixes):
            continue

        url_words = {
            word.lower()
            for word in normalized_url.split("/")
            if word
        }

        if not keywords.intersection(url_words):
            continue

        try:
            sec_adv_content = scrape(normalized_url)
        except Exception as exc:
            print(
                "[!] Failed to scrape advisory "
                f"{normalized_url}: {exc}"
            )
            continue

        if sec_adv_content:
            sec_advs.append(
                {
                    "url": normalized_url,
                    "content": sec_adv_content,
                }
            )

    return sec_advs


def get_data(cve_id: str, path: str) -> None:
    """
    Extract CVE reproduction context and save it as JSON.

    Partial records are always saved when the CVE exists. Missing source,
    patch, or version information is reported for manual completion rather
    than causing a TypeError.
    """
    normalized_cve_id = cve_id.strip().upper()
    output_path = os.path.abspath(path)
    output_directory = os.path.dirname(output_path)

    if output_directory:
        os.makedirs(output_directory, exist_ok=True)

    data = load_existing_data(output_path)

    software_code_provided = False
    software_version_provided = False
    software_version_available = False
    security_advisories_provided = False

    try:
        cve = get_cve_by_id(normalized_cve_id)

        if not isinstance(cve, dict) or not cve:
            raise ValueError(
                f"CVE {normalized_cve_id} not found"
            )

        resolved_cve_id = (
            cve.get("id")
            if isinstance(cve.get("id"), str)
            and cve.get("id").strip()
            else normalized_cve_id
        )

        patch_urls = normalize_dict_list(
            cve.get("patch_urls")
        )

        raw_version_data = cve.get("version_data")
        version_data = (
            raw_version_data
            if isinstance(raw_version_data, dict)
            else {}
        )

        potential_advisories = normalize_string_list(
            cve.get("other_urls")
        )

        patch_commits = collect_patch_commits(
            patch_urls
        )

        software_code_provided = bool(
            patch_commits
        )

        version = version_data.get("version")
        software_version_provided = bool(
            isinstance(version, str)
            and version.strip()
        )

        tag, archive_url = resolve_vulnerable_version(
            patch_urls,
            version_data,
        )

        software_version_available = bool(
            tag and archive_url
        )

        sec_advs = collect_security_advisories(
            potential_advisories
        )

        security_advisories_provided = bool(
            sec_advs
        )

        record: dict[str, Any] = {
            "description": cve.get("description"),
            "cwes": cve.get("cwes") or [],
            "patch_commits": patch_commits,
            "patch_urls": patch_urls,
            "version_data": version_data,
            "other_urls": potential_advisories,
            "sec_adv": sec_advs,
        }

        if tag:
            record["sw_version"] = tag

        if archive_url:
            record["sw_version_wget"] = archive_url

        data[resolved_cve_id] = record

        with open(
            output_path,
            "w",
            encoding="utf-8",
        ) as file:
            json.dump(
                data,
                file,
                indent=4,
                ensure_ascii=False,
            )

        print(
            f"Data for {normalized_cve_id} "
            f"saved to {output_path}"
        )
        print(
            "    - Software code can be obtained "
            "from patch commits (required): "
            f"{software_code_provided}"
        )
        print(
            "    - Software version provided "
            "in CVE data (required): "
            f"{software_version_provided}"
        )
        print(
            "    - Software vulnerable version "
            "source code available on GitHub "
            "(required): "
            f"{software_version_available}"
        )
        print(
            "    - Security advisories provided "
            "(optional): "
            f"{security_advisories_provided}"
        )

        if (
            software_code_provided
            and software_version_provided
            and software_version_available
        ):
            print("✅ Ready to reproduce!!")
        else:
            print(
                "⚠️ Missing required data. "
                "The generated JSON was saved for "
                "manual completion in the web UI."
            )

    except Exception as exc:
        print(
            f"[!] Error processing "
            f"{normalized_cve_id}: {exc}"
        )
        traceback.print_exc()
        raise


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Get CVE data and save it to a JSON file."
        )
    )

    parser.add_argument(
        "--cve_id",
        required=True,
        type=str,
        help=(
            "CVE ID to process "
            "(e.g., CVE-2025-0001)"
        ),
    )

    parser.add_argument(
        "--output_path",
        required=True,
        type=str,
        help="Path for the output JSON file",
    )

    return parser.parse_args()


if __name__ == "__main__":
    arguments = parse_arguments()

    get_data(
        arguments.cve_id,
        arguments.output_path,
    )
