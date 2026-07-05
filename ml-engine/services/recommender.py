from typing import Dict

class SecurityRecommender:
    """Generates detailed remediation advice and secure coding patterns based on predicted CWEs."""
    
    # Secure templates database by CWE and language
    SECURE_TEMPLATES = {
        "CWE-89": {
            "root_cause": "Dynamic construction of SQL query strings using unsanitized user inputs.",
            "danger": "Allows attackers to inject malicious SQL commands, bypass authentication, retrieve unauthorized data, or modify database entries.",
            "recommendation": "Use parameterized queries, prepared statements, or an Object-Relational Mapper (ORM) library.",
            "languages": {
                "python": "# Secure pattern using parameterized query\nquery = \"SELECT * FROM users WHERE username = %s AND password = %s\"\ncursor.execute(query, (username, password))",
                "javascript": "// Secure pattern using pg-promise parameterized query\ndb.query('SELECT * FROM users WHERE id = $1', [userId]);",
                "java": "// Secure pattern using PreparedStatement\nString query = \"SELECT * FROM users WHERE id = ?\";\nPreparedStatement pstmt = conn.prepareStatement(query);\npstmt.setInt(1, userId);\nResultSet results = pstmt.executeQuery();",
                "default": "Always separate query structure from user input parameters using database-supported parameter binding interfaces."
            }
        },
        "CWE-79": {
            "root_cause": "Echoing untrusted user input directly into web templates or browser document interfaces without proper character escaping.",
            "danger": "Allows execution of arbitrary client-side script code (XSS), session hijacking (cookie theft), or phishing page injections.",
            "recommendation": "Encode all user inputs before rendering them, restrict content types, and configure strict Content Security Policy headers.",
            "languages": {
                "javascript": "// Secure client-side DOM insertion\nconst el = document.createElement('div');\nel.textContent = userInput; // Automatically encodes inputs (do NOT use innerHTML)\ncontainer.appendChild(el);",
                "python": "# Secure HTML response rendering using Jinja2 escaping\nfrom markupsafe import escape\nsafe_html = f\"<div>Hello, {escape(user_input)}</div>\"",
                "default": "Ensure output escaping is context-aware (HTML body, HTML attribute, CSS, JavaScript, or URL context)."
            }
        },
        "CWE-78": {
            "root_cause": "Invoking operating system commands by concatenating string inputs directly.",
            "danger": "Allows OS command injection: attackers can run arbitrary commands as the application process user, leading to remote code execution (RCE).",
            "recommendation": "Use built-in framework APIs instead of executing OS shell programs. If inevitable, disable shell execution and pass parameters in list format.",
            "languages": {
                "python": "# Secure subprocess execution (shell=False)\nimport subprocess\nsubprocess.run([\"ping\", \"-c\", \"1\", target_host], shell=False, capture_output=True)",
                "javascript": "// Secure child_process spawning without shell context\nconst { spawn } = require('child_process');\nconst ls = spawn('ls', ['-lh', '/usr']);",
                "default": "Never execute commands through system shell interpreters (e.g. /bin/sh or cmd.exe) if inputs are dynamic."
            }
        },
        "CWE-502": {
            "root_cause": "Deserializing serialized data structures from untrusted or unauthenticated origins.",
            "danger": "Allows arbitrary code execution at the moment of reconstruction (gadget chain exploitation) or memory corruption.",
            "recommendation": "Avoid native object serialization mechanisms entirely. Use safe, standard data interchange layouts like JSON or YAML with safe-load options.",
            "languages": {
                "python": "# Secure serialization using json or safe_load\nimport json\ndata = json.loads(untrusted_payload)  # JSON is safe and lacks execution contexts\n\n# Or if using PyYAML:\nimport yaml\ndata = yaml.safe_load(untrusted_yaml_payload) # Safe parser",
                "default": "Always sign and encrypt serialized byte arrays if native deserialization is unavoidable, verifying signatures prior to decoding."
            }
        },
        "CWE-22": {
            "root_cause": "Retrieving or writing files using path names constructed from user inputs that may contain directory navigation keywords (e.g. '../').",
            "danger": "Allows Path Traversal: attackers can access or modify arbitrary files outside the intended sandboxed directories (e.g., config, credentials, system binaries).",
            "recommendation": "Resolve files to canonical absolute paths and check if they exist strictly within a designated sandbox directory path prefix.",
            "languages": {
                "python": "# Secure path validation\nimport os\n\nbase_dir = os.path.abspath(\"/var/www/uploads\")\ntarget_path = os.path.abspath(os.path.join(base_dir, user_input_path))\n\n# Enforce sandboxing\nif not target_path.startswith(base_dir):\n    raise PermissionError(\"Path traversal attempt detected!\")",
                "default": "Strip out traversal components, resolve target targets to absolute canonical forms, and restrict filesystem access permissions."
            }
        },
        "CWE-798": {
            "root_cause": "Storing sensitive access control secrets or keys inside static source repository code files.",
            "danger": "Exposes credentials to any user/system with code access, creating a vector for unauthorized resource access when code is shared/pushed.",
            "recommendation": "Store credentials outside source trees inside environment variables, configuration files ignored by Git, or secret management vaults.",
            "languages": {
                "python": "# Secure credential retrieval from environment variables\nimport os\napi_token = os.getenv(\"API_SECRET_TOKEN\")",
                "javascript": "// Secure credential retrieval\nconst apiToken = process.env.API_SECRET_TOKEN;",
                "default": "Utilize credential management wrappers (e.g. AWS Secrets Manager, HashiCorp Vault) for production systems."
            }
        }
    }

    @classmethod
    def generate(cls, cwe_id: str, code: str, severity: str, language: str = "") -> Dict:
        """Returns detailed, structural remediation recommendations matching the target CWE and language.
        
        Args:
            cwe_id: The predicted CWE identifier (e.g. CWE-89).
            code: The source code containing the finding.
            severity: Severity rating of the finding.
            language: Programming language name (for custom secure template examples).
            
        Returns:
            Dict containing detailed remediation advice.
        """
        cwe_data = cls.SECURE_TEMPLATES.get(cwe_id)
        lang_key = (language or "").strip().lower()
        
        # Priority mapping based on severity
        priority_map = {
            "Critical": "P0 (Immediate Fix Required)",
            "High": "P1 (High Priority Fix)",
            "Medium": "P2 (Standard Fix)",
            "Low": "P3 (Low Priority / Info)"
        }
        priority = priority_map.get(severity, "P2 (Standard Fix)")
        
        if cwe_data:
            templates = cwe_data["languages"]
            example_fix = templates.get(lang_key, templates.get("default", ""))
            
            return {
                "root_cause": cwe_data["root_cause"],
                "why_dangerous": cwe_data["danger"],
                "secure_coding_recommendation": cwe_data["recommendation"],
                "example_secure_implementation": example_fix,
                "priority_level": priority
            }
        else:
            # Generic fallback recommendation
            return {
                "root_cause": f"A potential {cwe_id or 'security vulnerability'} pattern was detected in the code structure.",
                "why_dangerous": "Could allow attackers to execute unauthorized commands, read protected state data, or bypass access control gates.",
                "secure_coding_recommendation": "Enforce strict input validations, use established frameworks instead of custom code blocks, and validate permissions.",
                "example_secure_implementation": "# Ensure all user variables undergo strict checks before system utilization.\nassert isinstance(user_input, expected_type)\n# Use system libraries with built-in protections.",
                "priority_level": priority
            }
