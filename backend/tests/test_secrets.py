from app.analyzers.secrets.secret_scanner import SecretScanner, redact_secret

def test_secret_scanner_redacts_tokens():
    raw_key = "sk-proj-1234567890abcdef1234567890abcdef"
    code = f'OPENAI_API_KEY = "{raw_key}"'
    scanner = SecretScanner()
    findings, secret_models = scanner.scan_content(code, "config.py")

    assert len(secret_models) == 1
    assert secret_models[0].secret_type == "OpenAI API Key"
    assert raw_key not in secret_models[0].redacted_value
    assert "sk-" in secret_models[0].redacted_value

def test_redact_utility():
    assert redact_secret("ghp_1234567890abcdef1234567890abcdef") == "ghp...def"
