import os, requests, time

DATA_DIR = os.path.join(os.path.dirname(__file__), '..', 'data')

def get_commit_data(repo_owner: str, repo_name: str, commit_hash: str) -> dict | None:
    """
    Fetches commit data from the GitHub API.
    """
    url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/commits/{commit_hash}"
    headers = {
        "Authorization": f"token {os.environ['GITHUB_TOKEN']}",
        "Accept": "application/vnd.github.v3+json"
    }
    response = None
    while True:
        response = requests.get(url, headers=headers)

        if response.status_code == 403:
            print("Rate limit exceeded. Waiting for 60 seconds...")
            time.sleep(60)
        else:
            break
    
    # 1) Check if commits still exist and their information can be extracted
    if response.status_code == 200:
        commit_data = response.json()
        data = None
        
        # 2) Collect file changes
        data = {
            'url': commit_data['html_url'],
            'msg': commit_data['commit']['message'],
            'file_patch': []
        }
        for file in commit_data['files']:
            file_patch = {
                'file_name': file['filename'],
                'hunks': []
            }
            if 'patch' in file:
                patches = file['patch'].split('@@')
                patches_ix = [i for i in range(2, len(patches), 2)]
                for ix in patches_ix:
                    file_patch['hunks'].append({
                        'header': '@@' + patches[ix-1] + '@@',
                        'patch': patches[ix].strip(),
                    })
            data['file_patch'].append(file_patch)
        return data
    else:
        print("Failed to fetch commit data. Status Code:", response.status_code)
        return None
