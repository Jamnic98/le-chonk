from __future__ import annotations

CWE_URL = "https://cwe.mitre.org/data/definitions/{}.html"


def _ref(cwe: str, extra: str = "") -> list[str]:
    urls = [CWE_URL.format(cwe.split("-")[1])]
    if extra:
        urls.append(extra)
    return urls


PLAYBOOK: dict[str, dict] = {
    "cobol-hardcoded-secret": {
        "summary": "Move the credential out of source into a secure vault / environment and rotate it.",
        "steps": [
            "Rotate the exposed credential immediately; treat it as compromised.",
            "Retrieve it at runtime from a secrets manager (e.g. RACF-backed vault, HashiCorp Vault) or via JCL DD / environment override.",
            "Remove the literal from WORKING-STORAGE and from any CONNECT ... USING clause.",
            "Add a pre-commit/secret-scan gate so literals like this are blocked.",
        ],
        "patch": "- 01  WS-DB-PASSWORD          PIC X(20) VALUE \"...\".\n+ 01  WS-DB-PASSWORD          PIC X(64).\n  ...\n+           CALL 'GETSECRET' USING 'PAYDB/PASSWORD' WS-DB-PASSWORD",
        "tests": ["Static scan finds no credential literals in the module.", "Program connects using vault-issued credential in test region."],
        "references": _ref("CWE-798", "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"),
    },
    "cobol-string-sql": {
        "summary": "Replace the concatenated dynamic SQL with a static statement using host variables (parameter markers).",
        "steps": [
            "Rewrite the query as a static EXEC SQL statement with host variables (e.g. WHERE ID = :WS-USER-ID).",
            "Delete the STRING ... INTO WS-QUERY assembly.",
            "Validate/whitelist WS-USER-ID after ACCEPT (PIC X field, length, allowed characters).",
        ],
        "patch": "-           STRING \"SELECT SSN, SALARY FROM EMP WHERE ID = '\" WS-USER-ID \"'\" INTO WS-QUERY.\n-           EXEC SQL PREPARE Q FROM :WS-QUERY END-EXEC.\n+           EXEC SQL SELECT SSN, SALARY INTO :WS-SSN, :WS-SAL FROM EMP WHERE ID = :WS-USER-ID END-EXEC.",
        "tests": ["Injection payloads in the ID field return no rows and no error-based leaks.", "Happy-path query returns the same rows as before."],
        "references": _ref("CWE-89", "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"),
    },
    "cobol-display-pii": {
        "summary": "Stop logging PII/secrets; mask or drop the field.",
        "steps": [
            "Remove SSN/PIN/card fields from DISPLAY statements or mask them (e.g. show last 4).",
            "Route audit output through a controlled logging facility with access controls.",
        ],
        "patch": "-           DISPLAY \"SSN: \" WS-SSN.\n+           DISPLAY \"SSN: ***-**-\" WS-SSN(8:2).",
        "tests": ["Job log contains no full SSN after the change."],
        "references": _ref("CWE-532"),
    },
    "php-sqli-concat": {
        "summary": "Use prepared statements with bound parameters (PDO or mysqli).",
        "steps": [
            "Replace string-built SQL with a prepared statement: $stmt = $pdo->prepare('SELECT ... WHERE id = ?'); $stmt->execute([$id]);",
            "Validate $id (e.g. ctype_digit) before use.",
        ],
        "patch": "- $sql = \"SELECT * FROM customers WHERE id = '\" . $id . \"'\";\n- $res = mysql_query($sql, $db);\n+ $stmt = $pdo->prepare('SELECT * FROM customers WHERE id = ?');\n+ $stmt->execute([$id]);",
        "tests": ["' OR '1'='1 payload returns zero rows.", "Unit test asserts the query uses bound parameters."],
        "references": _ref("CWE-89", "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"),
    },
    "php-sqli-request": {
        "summary": "Never pass superglobals into query calls; read, validate, then bind.",
        "steps": ["Read $_GET/$_POST into typed variables with validation.", "Use prepared statements with bound parameters."],
        "patch": "+ $id = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT);\n+ $stmt = $pdo->prepare('SELECT ... WHERE id = ?'); $stmt->execute([$id]);",
        "tests": ["Fuzz the parameter; no SQL errors, no unauthorized rows."],
        "references": _ref("CWE-89"),
    },
    "php-eval": {
        "summary": "Delete eval(); replace with an explicit allowlist dispatch.",
        "steps": ["Remove eval($_POST[...]).", "Map allowed operations to named functions via a switch/allowlist."],
        "patch": "- eval($_POST['expr']);\n+ $allowed = ['status' => 'op_status', 'ping' => 'op_ping'];\n+ if (isset($allowed[$_POST['expr']])) { $allowed[$_POST['expr']](); }",
        "tests": ["Submitting PHP code as expr does nothing."],
        "references": _ref("CWE-95"),
    },
    "php-command": {
        "summary": "Remove shell execution of user input; use an allowlist and escapeshellarg.",
        "steps": ["Replace system('convert ' . $cmd) with a fixed command and escapeshellarg($cmd), or better, a library call.", "Allowlist the expected subcommands."],
        "patch": "- system(\"convert \" . $cmd);\n+ if (!in_array($tool, ['convert','identify'], true)) { http_response_code(400); exit; }\n+ system('convert ' . escapeshellarg($input));",
        "tests": ["cmd='x; rm -rf /' is rejected or neutralized."],
        "references": _ref("CWE-78", "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html"),
    },
    "php-unserialize": {
        "summary": "Replace unserialize on user input with JSON.",
        "steps": ["Store preferences as JSON; decode with json_decode($cookie, true).", "If objects are unavoidable, use allowed_classes: false."],
        "patch": "- $prefs = unserialize($_COOKIE['prefs']);\n+ $prefs = json_decode($_COOKIE['prefs'] ?? '{}', true);",
        "tests": ["Serialized PHP object payload in cookie is ignored."],
        "references": _ref("CWE-502"),
    },
    "php-include-get": {
        "summary": "Never include request-controlled paths.",
        "steps": ["Map page names to a fixed allowlist of templates.", "Render the chosen template server-side."],
        "patch": "- include($_GET['page'] . \".php\");\n+ $pages = ['home' => 'home.php', 'about' => 'about.php'];\n+ include($pages[$_GET['page'] ?? 'home']);",
        "tests": ["?page=../../../../etc/passwd renders home, no file read."],
        "references": _ref("CWE-98"),
    },
    "php-weak-hash": {
        "summary": "Use password_hash()/password_verify() (argon2id/bcrypt).",
        "steps": ["Replace md5/sha1 token or password hashing with password_hash($pw, PASSWORD_DEFAULT).", "Verify with password_verify()."],
        "patch": "- $check = md5($token . \"pepper\");\n+ $check = password_verify($token, $storedHash);",
        "tests": ["Legacy hashes are re-hashed on next successful login (migration path)."],
        "references": _ref("CWE-327", "https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html"),
    },
    "php-hardcoded-secret": {
        "summary": "Move secrets to environment/config outside the repo and rotate them.",
        "steps": ["Rotate the key.", "Load from getenv()/$_ENV with a .env excluded by .gitignore.", "Add a secret scanner to CI."],
        "patch": "- $api_key = \"sk_live_...\";\n+ $api_key = getenv('PORTAL_API_KEY');",
        "tests": ["Repo scan finds no secret literals."],
        "references": _ref("CWE-798"),
    },
    "php-connect-creds": {
        "summary": "Externalize DB credentials.",
        "steps": ["Rotate DB password.", "Use a config file outside webroot or env vars."],
        "patch": "- mysql_connect(\"db.internal\", \"portal_user\", \"portal_pass_123\");\n+ $pdo = new PDO($dsn, getenv('DB_USER'), getenv('DB_PASS'));",
        "tests": ["App connects in staging with env-provided creds."],
        "references": _ref("CWE-798"),
    },
    "py-eval-exec": {
        "summary": "Remove eval/exec; dispatch via an allowlist.",
        "steps": ["Delete eval(spec['code']).", "Map allowed operations to functions."],
        "patch": "- return eval(spec[\"code\"])\n+ HANDLERS = {'run_report': run_report, 'send_email': send_email}\n+ return HANDLERS[spec['op']](spec['args'])",
        "tests": ["op containing Python code raises KeyError/no-op."],
        "references": _ref("CWE-95"),
    },
    "py-pickle": {
        "summary": "Replace pickle with JSON (or sign/encrypt if binary needed).",
        "steps": ["Use json.load for the cache file.", "If pickle is required, use HMAC-signed payloads and restrict classes."],
        "patch": "- return pickle.load(f)\n+ return json.load(f)",
        "tests": ["Crafted pickle payload in cache file is rejected."],
        "references": _ref("CWE-502"),
    },
    "py-shell-true": {
        "summary": "Use subprocess with an argument list and shell=False.",
        "steps": ["Replace shell=True string with [binary, arg1, arg2].", "Validate inputs against an allowlist."],
        "patch": "- subprocess.call(\"chmod \" + cmd, shell=True)\n+ subprocess.run(['chmod', mode, path], check=True)",
        "tests": ["path with shell metacharacters is treated as a literal filename."],
        "references": _ref("CWE-78"),
    },
    "py-os-system": {
        "summary": "Replace os.system with subprocess.run([...]).",
        "steps": ["Use subprocess with a list, check=True."],
        "patch": "- os.system(\"echo \" + cmd)\n+ subprocess.run(['echo', cmd], check=True)",
        "tests": ["Metacharacters are not interpreted."],
        "references": _ref("CWE-78"),
    },
    "py-sqli-fstring": {
        "summary": "Use bound parameters instead of f-string SQL.",
        "steps": ["Replace f-string SQL with placeholders and a params tuple."],
        "patch": "- cur.execute(f\"SELECT * FROM users WHERE name = '{name}'\")\n+ cur.execute(\"SELECT * FROM users WHERE name = ?\", (name,))",
        "tests": ["name=\"x' OR '1'='1\" returns no rows."],
        "references": _ref("CWE-89"),
    },
    "py-sqli-concat": {
        "summary": "Use bound parameters instead of concatenated SQL.",
        "steps": ["Replace concatenation with placeholders + params."],
        "patch": "- cur.execute(\"SELECT ... WHERE id = \" + uid)\n+ cur.execute(\"SELECT ... WHERE id = ?\", (uid,))",
        "tests": ["Injection strings are treated as data."],
        "references": _ref("CWE-89"),
    },
    "py-hardcoded-secret": {
        "summary": "Move the secret to env/secret manager and rotate it.",
        "steps": ["Rotate.", "os.environ['...'] / SecretStr + pydantic-settings."],
        "patch": "- AWS_SECRET = \"...\"\n+ AWS_SECRET = os.environ['AWS_SECRET_ACCESS_KEY']",
        "tests": ["CI secret scan passes."],
        "references": _ref("CWE-798"),
    },
    "py-aws-key": {
        "summary": "Revoke the key in IAM, then remove from source.",
        "steps": ["Deactivate the AKIA key in AWS IAM now.", "Load from env/secrets manager; add pre-commit secret scanning."],
        "patch": "- AWS_ACCESS_KEY_ID = \"AKIA...\"\n+ AWS_ACCESS_KEY_ID = os.environ['AWS_ACCESS_KEY_ID']",
        "tests": ["Repo scan finds no AKIA pattern."],
        "references": _ref("CWE-798"),
    },
    "py-yaml-unsafe": {
        "summary": "Use yaml.safe_load.",
        "steps": ["Replace yaml.load(f) with yaml.safe_load(f)."],
        "patch": "- return yaml.load(f)\n+ return yaml.safe_load(f)",
        "tests": ["!!python/object payload raises ConstructorError."],
        "references": _ref("CWE-502"),
    },
    "py-verify-false": {
        "summary": "Re-enable TLS verification.",
        "steps": ["Remove verify=False; fix the CA bundle instead."],
        "patch": "- requests.get(url, verify=False)\n+ requests.get(url, timeout=10)",
        "tests": ["Connection to a self-signed-cert host fails loudly."],
        "references": _ref("CWE-295"),
    },
    "py-weak-hash": {
        "summary": "Use a modern hash/KDF.",
        "steps": ["hashlib.sha256 for integrity; hashlib.scrypt/argon2 via passlib for passwords."],
        "patch": "- hashlib.md5(...).hexdigest()\n+ hashlib.sha256(...).hexdigest()",
        "tests": ["Token comparison uses constant-time compare (hmac.compare_digest)."],
        "references": _ref("CWE-327"),
    },
}


def remediation_for(finding: dict) -> dict:
    pb = PLAYBOOK.get(finding["rule_id"])
    if pb:
        return {
            "finding_id": finding["id"],
            "rule_id": finding["rule_id"],
            "summary": pb["summary"],
            "steps": pb["steps"],
            "patch": pb["patch"],
            "tests": pb["tests"],
            "references": pb["references"],
        }
    return {
        "finding_id": finding["id"],
        "rule_id": finding["rule_id"],
        "summary": f"Fix {finding['cwe']}: {finding['title']}.",
        "steps": ["Eliminate the tainted flow described in the finding.", "Add a regression test."],
        "patch": "",
        "tests": [],
        "references": _ref(finding["cwe"]),
    }
