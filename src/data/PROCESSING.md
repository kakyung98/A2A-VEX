# CVE Data

To run CVE-Genie the extracted data `<json-file-path>` should look like this:

```json
{  
    "CVE-2024-4340": {
        "description": "Passing a heavily nested list to sqlparse.parse() leads to a Denial of Service due to RecursionError.\n\n",
        "cwe": [
            {
                "id": "CWE-674",
                "value": "CWE-674 Uncontrolled Recursion"
            }
        ],
        "patch_commits": [
            {
                "url": "https://github.com/andialbrecht/sqlparse/commit/b4a39d9850969b4e1d6940d32094ee0b42a2cf03",
                "content": "..."
            }
        ],
        "sw_version": "...[Missing]...",
        "sw_version_wget": "...[Missing]...",
        "sec_adv": [
            {
                "url": "https://github.com/advisories/GHSA-2m57-hf25-phgg",
                "content": "..."
            }
        ]
    }
}
```

1. You can see the vulnerable version provided in the security advisory `https://github.com/advisories/GHSA-2m57-hf25-phgg` and it is `v0.4.4`
2. So you can add `"sw_version": "v0.4.4"`
3. Also add `"sw_version_wget": "https://github.com/andialbrecht/sqlparse/archive/refs/tags/0.4.4.zip"` 
4. Now, you are ready to move to Step Number 2 of running CVE-Genie to reproduce CVE-2024-4340