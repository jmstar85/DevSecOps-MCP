// DevSecOps MCP Server 사용 예제

// 1. SAST 스캔 예제 (취약한 코드 샘플)
const userInput = req.query.id;
const query = "SELECT * FROM users WHERE id = " + userInput; // SQL Injection 취약점

// 2. 하드코딩된 시크릿 예제
const apiKey = "sk-1234567890abcdef"; // 하드코딩된 API 키

// 3. XSS 취약점 예제
function renderHTML(data) {
    document.innerHTML = data; // XSS 취약점
}

// 4. 명령어 주입 취약점 예제
const exec = require('child_process').exec;
function executeCommand(userCmd) {
    exec('ls ' + userCmd); // 명령어 주입 취약점
}

// 5. 경로 순회 취약점 예제
const fs = require('fs');
function readFile(filename) {
    return fs.readFileSync('./uploads/' + filename); // 경로 순회 취약점
}

// 6. 복잡한 함수 (코드 품질 이슈)
function complexFunction(a, b, c, d, e, f, g, h) { // 너무 많은 매개변수
    if (a > 0) {
        if (b > 0) {
            if (c > 0) {
                if (d > 0) {
                    if (e > 0) {
                        if (f > 0) {
                            if (g > 0) {
                                if (h > 0) {
                                    return a + b + c + d + e + f + g + h;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    return 0;
}