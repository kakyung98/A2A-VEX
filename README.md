# CVE-Genie

An LLM-based multi-agent framework for end-to-end reproduction of CVEs.

See end-to-end reproduction logs and outputs of CVE-2024-4340 [here](src/results/CVE-2024-4340) and Figure 2 in the paper.

# 🏃‍♂️ How to Run

## 1) Extract CVE Data
1. Install necessary packages
   ```bash
   python3 -m venv env
   pip install -r src/data/requirements.txt
   ```

2. Clone the `cvelist` repository
   ```bash
   cd src/
   git clone https://github.com/CVEProject/cvelist.git data/
   ```

3. Create `.env` in `src/` and make sure it has your `GITHUB_TOKEN`

4. Run the following script to extract the given CVE data
   ```bash
   python ./data/scripts/cve_data.py --cve_id <cve-id> --output_path <json-file-path>
   # e.g., python ./data/scripts/cve_data.py --cve_id CVE-2024-4340 --output_path ./data/cve_data/data.json
   ```

5. If the above script returns `✅ Ready to reproduce!!` you can move to next step, otherwise go to [PROCESSING.md](src/data/PROCESSING.md), you might have to add some data content manually
   > 🚨 This can happen because the CVEs in `cvelist` might get modified, and some content might not be automatically extracted. Due to change of CVE data for CVE-2024-4340, the vulnerable software version could not be extracted automatically and the [PROCESSING.md](src/data/PROCESSING.md) explains how you can add it to the `./data/cve_data/data.json`

## 2) Runn CVE-Genie on the Extracted CVE Data

You have the following two options to run CVE-Genie:

### ❶ In DevContainer
> ‼️ Easy to setup but it might not be compatible for CVEs that require running multiple services, as it can crash the DevContainer

1. Start the `devcontainer` in VS Code
2. `cd` into the `src` directory
3. Create `.env` file in `src`, and add the `OPENAI_API_KEY` to use
4. Run the following command to reproduce the given CVE (e.g., CVE-2024-4340)
   ```bash
   ENV_PATH=.env MODEL=example_run python3 main.py --cve CVE-2024-4340 --json ./data/cve_data/data.json --run-type build,exploit,verify
   ```
5. The final results will be stored in `shared/CVE-2024-4340/`

### ❷ In a Virtual Machine
Read the [VM Library Documentation](vm_library/README.md) on how to run it in a VM.