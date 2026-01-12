import json
import argparse
from dotenv import load_dotenv
from cve_processor import (
                                    get_software_versions, 
                                    affected_version_exist,
                                    get_patch_content,
                                    get_cve_by_id
                                )
from scraper_utils import scrape

load_dotenv()

def get_data(cve_id: str, path: str):
    '''
    "CVE-2025-0001": {
        "cwe": [
            {
                "id": "CWE-23",
                "value": "CWE-23 Relative Path Traversal"
            }
        ],
        "patch_commits": [
            {
                "url": "https://github.com/mlflow/mlflow/commit/400c226953b4568f4361bc0a0c223511652c2b9d",
                "content": "..."
            }
        ],
        "sw_version": "v2.8.1",
        "sw_version_wget": "https://github.com/mlflow/mlflow/archive/refs/tags/v2.8.1.zip",
        "description": "...",
        "sec_adv": [
            {
                "url": "...",
                "content": "...",
                "effective": true
            }
        ]
    }
    '''
    data = {}
    software_code_provided = False
    software_version_provided = False
    software_version_extractable = False
    software_version_available = False
    security_advisories_provided = False

    try:
        cve = get_cve_by_id(cve_id)
        data[cve['id']] = {
            "description": cve.get('description')
        }

        # 1) source code provided
        patch_commits = [
                {
                    "url": patch['patch_commit_url'],
                    "content": get_patch_content(patch['owner'], patch['project'], patch['hash'])
                }
                for patch in cve.get('patch_urls')
            ]

        if patch_commits:
            data[cve['id']]["patch_commits"] = patch_commits
            software_code_provided = True
        
        # 2) software version provided
        version_data = cve.get("version_data")
        if version_data:
            software_version_provided = True
            try:
                version = get_software_versions(cve['id'])[0]
                data[cve['id']]["sw_version"] = f"v{version[1]}"
                software_version_extractable = True
            except Exception as e:
                version = (False, 'anomaly')
                print(f"[!] Error getting software version for {cve['id']}: {e}")
                
        # 3) software version extractable
        if version_data and version[1] != 'n/a' and version[1] != 'anomaly' and patch_commits:
            patch_urls = cve.get('patch_urls')
            # 4) software version available on github
            tag = affected_version_exist(patch_urls[0]['owner'], patch_urls[0]['project'], version[1], version[0])
            if tag:
                software_version_available = True
                data[cve['id']]["sw_version_wget"] = f"{patch_urls[0]['repo_url']}/archive/refs/tags/v{version[1]}.zip",
                    
        # 5) security advisories
        potential_advisories = cve.get("other_urls")
        sec_advs = []
        if potential_advisories:
            keywords = ['security', 'advisory', 'advisories', 'bounties', 'bounty']
            for url in potential_advisories:
                url_words = url.split('/')
                if any(keyword in url_words for keyword in keywords):
                    sec_adv_content = scrape(url)
                    sec_advs.append({
                        "url": url,
                        "content": sec_adv_content
                    })
        if sec_advs:
            security_advisories_provided = True
        data[cve['id']]["sec_adv"] = sec_advs

        # save data
        with open(path, 'w') as f:
            json.dump(data, f, indent=4)

        print(f"[+] Data for {cve_id} saved to {path}")
        print(f"    - Software code provided: {software_code_provided}")
        print(f"    - Software version provided: {software_version_provided}")
        print(f"    - Software version extractable: {software_version_extractable}")
        print(f"    - Software version available: {software_version_available}")
        print(f"    - Security advisories provided: {security_advisories_provided}")

    except Exception as e:
        print(f"[!] Error processing {cve_id}: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Get CVE data and save to JSON file.")
    parser.add_argument("--cve_id", type=str, help="CVE ID to process (e.g., CVE-2025-0001)")
    parser.add_argument("--output_path", type=str, help="Path to save the output JSON file")
    args = parser.parse_args()

    get_data(args.cve_id, args.output_path)