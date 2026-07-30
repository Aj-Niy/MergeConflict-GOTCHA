import os
from pathlib import Path

import requests
from dotenv import load_dotenv

from .parser import parse_github_url

load_dotenv()

GITHUB_API = "https://api.github.com"

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")

#github username alt-test(0)
HEADERS = {
    "User-Agent": "GOTCHA-AI",
}

if GITHUB_TOKEN:
    HEADERS["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    

# test line
print("GitHub token loaded:", bool(GITHUB_TOKEN))
print("Token starts with:", GITHUB_TOKEN[:10] if GITHUB_TOKEN else None)


SUPPORTED_EXTENSIONS = {
    ".py",
    ".js",
    ".ts",
    ".tsx",
    ".java",
    ".cpp",
    ".c",
    ".go",
    ".rs",
}


def fetch_readme(url: str):

    owner, repo = parse_github_url(url)

    endpoint = f"{GITHUB_API}/repos/{owner}/{repo}/readme"

    response = requests.get(
        endpoint,
        headers={
            **HEADERS,
            "Accept": "application/vnd.github.raw",
        },
    )

    if response.status_code != 200:
        print("Status:", response.status_code)
        print("Response:", response.text)

        raise Exception(
            f"Unable to fetch README. Status: {response.status_code}"
        )

    return response.text


def fetch_repository_code(url: str):

    owner, repo = parse_github_url(url)

    collected = []

    def walk(path=""):

        endpoint = f"{GITHUB_API}/repos/{owner}/{repo}/contents/{path}"

        response = requests.get(
            endpoint,
            headers=HEADERS,
        )

        if response.status_code != 200:
            raise Exception(f"GitHub API Error: {response.status_code}")

        items = response.json()

        if isinstance(items, dict):
            items = [items]

        for item in items:

            if item["type"] == "dir":
                walk(item["path"])

            elif item["type"] == "file":

                ext = Path(item["name"]).suffix.lower()

                if ext not in SUPPORTED_EXTENSIONS:
                    continue

                raw = requests.get(
                    item["download_url"],
                    headers=HEADERS,
                )

                if raw.status_code == 200:
                    collected.append(
                        {
                            "path": item["path"],
                            "code": raw.text,
                        }
                    )
                else:
                    print(f"Skipping {item['path']}")

    walk()

    print(f"Downloaded {len(collected)} source files.")

    return collected