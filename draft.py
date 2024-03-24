import customtkinter as ctk
from tkinter import scrolledtext, filedialog
import requests
import json
import base64
import io
import tempfile
import subprocess
import os

# Replace 'your_github_token_here' with your actual GitHub Personal Access Token
GITHUB_TOKEN = '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'

ctk.set_appearance_mode("Dark")  # 'Dark' or 'Light' mode
ctk.set_default_color_theme("dark-blue")  # Theme

def fetch_security_vulnerabilities(owner, repo):
    query = """
    query($owner: String!, $repo: String!, $cursor: String) {
        repository(owner: $owner, name: $repo) {
            vulnerabilityAlerts(first: 100, after: $cursor) {
                edges {
                    node {
                        securityVulnerability {
                            package {
                                name
                            }
                            severity
                            advisory {
                                description
                            }
                        }
                    }
                }
                pageInfo {
                    endCursor
                    hasNextPage
                }
            }
        }
    }
    """
    variables = {"owner": owner, "repo": repo}
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Content-Type": "application/json",
    }
    response = requests.post(
        "https://api.github.com/graphql",
        headers=headers,
        json={"query": query, "variables": json.dumps(variables)},
    )
    response.raise_for_status()
    return response.json()

def download_python_files_from_repo(owner, repo):
    api_url = f"https://api.github.com/repos/{owner}/{repo}/git/trees/main?recursive=1"
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json",
    }
    response = requests.get(api_url, headers=headers)
    response.raise_for_status()
    tree = response.json()['tree']
    files = []
    for item in tree:
        if item['path'].endswith('.py') and item['type'] == 'blob':
            file_content = requests.get(item['url'], headers=headers).json()['content']
            decoded_content = base64.b64decode(file_content).decode('utf-8')
            files.append((item['path'], io.StringIO(decoded_content)))
    return files

def run_bandit_on_files(files):
    with tempfile.TemporaryDirectory() as temp_dir:
        for file_path, file_content in files:
            temp_file_path = os.path.join(temp_dir, file_path)
            os.makedirs(os.path.dirname(temp_file_path), exist_ok=True)
            with open(temp_file_path, "w") as temp_file:
                temp_file.write(file_content.read())
        bandit_executable = "bandit"
        results_path = os.path.join(temp_dir, "results.json")
        bandit_command = [bandit_executable, "-r", temp_dir, "-f", "json", "-o", results_path]
        result = subprocess.run(bandit_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode not in [0, 1]:
            raise Exception("Bandit failed")
        with open(results_path, "r") as results_file:
            results_data = results_file.read()
        if not results_data.strip():
            return json.dumps({"results": []})
        return results_data

def analyze_repository(owner, repo):
    try:
        files = download_python_files_from_repo(owner, repo)
        scanner_results = run_bandit_on_files(files)
        vulnerabilities = fetch_security_vulnerabilities(owner, repo)
    except Exception as e:
        return str(e)
    return scanner_results, vulnerabilities

def analyze_button_clicked():
    repo_url = repo_url_entry.get()
    if not repo_url.startswith("https://github.com/"):
        ctk.CTkMessageBox.show_error("Error", "Invalid GitHub repository URL.")
        return
    repo_path = repo_url.replace("https://github.com/", "")
    owner, repo = repo_path.strip("/").split("/", 1)
    try:
        scanner_results, vulnerabilities = analyze_repository(owner, repo)
        scanner_data = json.loads(scanner_results)
        vulnerability_alerts = vulnerabilities["data"]["repository"]["vulnerabilityAlerts"]["edges"]
        output_text.delete(1.0, "end")
        output_text.insert("end", "Python code scanning results:\n")
        for issue in scanner_data["results"]:
            filename = issue['filename']
            line_number = issue['line_number']
            issue_text = issue['issue_text']
            severity = issue.get('issue_severity', 'N/A')
            confidence = issue.get('issue_confidence', 'N/A')
            output_text.insert("end", f"File: {filename}\nLine: {line_number}\nIssue: {issue_text}\nSeverity: {severity}\nConfidence: {confidence}\n\n")
        output_text.insert("end", "\nDependency vulnerability alerts:\n")
        for alert in vulnerability_alerts:
            node = alert["node"]
            package_name = node["securityVulnerability"]["package"]["name"]
            severity = node["securityVulnerability"]["severity"]
            description = node["securityVulnerability"]["advisory"]["description"]
            output_text.insert("end", f"Package: {package_name}\nSeverity: {severity}\nDescription: {description}\n\n")
    except Exception as e:
        ctk.CTkMessageBox.show_error("Error during analysis", str(e))

def save_report():
    report_text = output_text.get("1.0", "end")
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Documents", "*.txt"), ("All Files", "*.*")])
    if file_path:
        with open(file_path, "w") as file:
            file.write(report_text)
        ctk.CTkMessageBox.show_info("Save Successful", "The report was successfully saved.")

root = ctk.CTk()
root.title("GitHub Repository Analyzer")
root.geometry("800x800")

header_frame = ctk.CTkFrame(root, height=100)
header_frame.pack(fill="x", padx=20, pady=10)
header_label = ctk.CTkLabel(header_frame, text="STATIC CODE SECURITY ANALYSER", font=("Roboto", 25,"bold"))
header_label.pack(pady=20, )

frame = ctk.CTkFrame(root)
frame.pack(padx=10, pady=10, fill="both", expand=True)

repo_url_label = ctk.CTkLabel(frame, text="GitHub Repository URL:",font=("", 20,"bold"))
repo_url_label.pack()

repo_url_entry = ctk.CTkEntry(frame, width=800, height=60, corner_radius=10)
repo_url_entry.pack(pady=10)

analyze_button = ctk.CTkButton(frame, text="Analyze Repository", command=analyze_button_clicked, width=200, height=40, corner_radius=10, font=("",15, "bold"))
analyze_button.pack(pady=20)
save_report_button = ctk.CTkButton(frame, text="Save Report", command=save_report, width=200, height=40, corner_radius=10, font=("",15, "bold"))
save_report_button.pack(pady=10)

output_text = scrolledtext.ScrolledText(frame, width=100, height=60, font=("Roboto", 20,"bold"), bg="black", fg="white")
output_text.pack(pady=10)

root.mainloop()
