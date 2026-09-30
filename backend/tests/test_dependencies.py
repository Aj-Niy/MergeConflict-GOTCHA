from app.analyzers.dependencies.dependency_scanner import parse_requirements_txt, parse_package_json

def test_parse_requirements():
    content = """
fastapi==0.115.12
requests>=2.31.0
# some comment
urllib3<=1.26.5
"""
    pkgs = parse_requirements_txt(content)
    names = {p["name"] for p in pkgs}
    assert "fastapi" in names
    assert "requests" in names
    assert "urllib3" in names

def test_parse_package_json():
    content = """
{
  "dependencies": {
    "axios": "^1.6.0",
    "express": "4.18.2"
  }
}
"""
    pkgs = parse_package_json(content)
    assert len(pkgs) == 2
    assert pkgs[0]["ecosystem"] == "npm"
