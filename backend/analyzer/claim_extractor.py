import json
import os
import traceback

from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()

XAI_API_KEY = os.getenv("XAI_API_KEY")

client = None

if XAI_API_KEY:
    client = OpenAI(
        api_key=XAI_API_KEY,
        base_url="https://api.x.ai/v1"
    )

MODEL = os.getenv(
    "MODEL_NAME",
    "grok-4.5"
)

SYSTEM_PROMPT = """
You are a security capability classifier.

Return ONLY valid JSON.

Possible capabilities:

Filesystem
Network
Environment
Database
Shell
Subprocess

Example:

{
  "claims": [
    "Filesystem",
    "Network"
  ]
}
"""


def extract_claims(description: str):

    description = description[:12000]

    if client is None:
        return [
            "Repository functionality inferred from README.",
            "LLM analysis unavailable (demo mode)."
        ]

    try:

        response = client.chat.completions.create(

            model=MODEL,

            messages=[
                {
                    "role": "system",
                    "content": SYSTEM_PROMPT
                },
                {
                    "role": "user",
                    "content": description
                }
            ],

            temperature=0

        )

        content = response.choices[0].message.content.strip()

        data = json.loads(content)

        return data.get("claims", [])

    except Exception:

        traceback.print_exc()

        return []