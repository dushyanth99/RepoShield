import torch
import pickle
from pathlib import Path
from transformers import AutoTokenizer
from models.codebert_classifier import CodeBERTClassifier
from models.download_model import check_model
from config import MODEL_CHECKPOINT, SAVED_MODEL_DIR
from utils.logging_utils import setup_logger
from services.explainer import VulnerabilityExplainer
from services.hybrid_detector import HybridDetector

logger = setup_logger("predictor")

# Expanded CWE database for mapping classification findings to standard indices
CWE_INFO = {
    "CWE-89": {
        "name": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
        "severity": "Critical",
        "score": 9.8,
        "owasp": "A03:2021-Injection",
        "description": "The application constructs SQL commands dynamically using input from untrusted sources, allowing attackers to manipulate queries.",
        "recommendation": "Use parameterized queries, prepared statements, or ORM frameworks instead of raw string concatenation."
    },
    "CWE-79": {
        "name": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
        "severity": "High",
        "score": 8.0,
        "owasp": "A03:2021-Injection",
        "description": "Unsanitized user inputs are echoed back into web templates or browsers, potentially executing arbitrary script payloads.",
        "recommendation": "Implement context-aware escaping/encoding on all outputs and define strict Content Security Policies (CSP)."
    },
    "CWE-119": {
        "name": "Improper Restriction of Operations within the Bounds of a Memory Buffer",
        "severity": "Critical",
        "score": 9.8,
        "owasp": "A06:2021-Vulnerable and Outdated Components",
        "description": "Buffer memory bounds are not verified before copying/manipulating contents, leading to potential buffer overflow exploits.",
        "recommendation": "Use bounded memory manipulation operations (e.g. strncpy, memcpy_s) and memory-safe abstractions."
    },
    "CWE-20": {
        "name": "Improper Input Validation",
        "severity": "Medium",
        "score": 5.3,
        "owasp": "A03:2021-Injection",
        "description": "The application accepts input without full validation of type, format, length, or boundary values.",
        "recommendation": "Enforce strict positive input validation patterns (whitelists) using sanitizers or schema validators."
    },
    "CWE-22": {
        "name": "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
        "severity": "High",
        "score": 7.5,
        "owasp": "A01:2021-Broken Access Control",
        "description": "The application accepts filename parameters containing directory navigation characters (e.g. '../'), permitting arbitrary read/write access.",
        "recommendation": "Sanitize inputs, resolve targets to absolute canonical paths, and verify target resides inside sandboxed folders."
    },
    "CWE-502": {
        "name": "Deserialization of Untrusted Data",
        "severity": "Critical",
        "score": 9.8,
        "owasp": "A08:2021-Software and Data Integrity Failures",
        "description": "Deserializing input streams from untrusted origins can trigger unexpected instantiation and execution of arbitrary system operations.",
        "recommendation": "Avoid serializing custom objects. Use simpler structured representations like JSON, Protocol Buffers, or safe-load libraries."
    },
    "CWE-78": {
        "name": "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
        "severity": "Critical",
        "score": 9.8,
        "owasp": "A03:2021-Injection",
        "description": "Operating system command wrappers dynamically concatenate parameters, allowing execution of arbitrary terminal instructions.",
        "recommendation": "Avoid wrapping OS terminal binaries. Use library APIs, or strictly sanitize inputs through subprocess shell=False parameters."
    },
    "CWE-352": {
        "name": "Cross-Site Request Forgery (CSRF)",
        "severity": "Medium",
        "score": 6.5,
        "owasp": "A01:2021-Broken Access Control",
        "description": "Web apps process state-changing actions from authenticated user agents without verifying the integrity/origin of the action trigger.",
        "recommendation": "Implement unique cryptographically signed anti-CSRF request tokens and leverage SameSite cookie behaviors."
    },
    "CWE-798": {
        "name": "Use of Hardcoded Credentials",
        "severity": "High",
        "score": 8.9,
        "owasp": "A07:2021-Identification and Authentication Failures",
        "description": "Passwords, encryption keys, or API tokens are embedded statically in source files, risking configuration exposure.",
        "recommendation": "Extract credentials to environmental context variables, secret vault stores, or external runtime parameters."
    },
    "CWE-287": {
        "name": "Improper Authentication",
        "severity": "High",
        "score": 9.1,
        "owasp": "A07:2021-Identification and Authentication Failures",
        "description": "The system fails to thoroughly verify identity claims on access checkpoints, letting callers impersonate sessions.",
        "recommendation": "Enforce strict session confirmation rules, MFA workflows, and leverage standard identity provider standards (OAuth, SAML)."
    },
    "CWE-276": {
        "name": "Incorrect Default Permissions",
        "severity": "Medium",
        "score": 5.0,
        "owasp": "A01:2021-Broken Access Control",
        "description": "Resources are provisioned with overly permissive defaults (e.g. read/write permissions for all users), allowing unauthorized data access.",
        "recommendation": "Adopt the principle of least privilege: assign restricted access rights by default and expand permissions explicitly."
    },
    "CWE-312": {
        "name": "Cleartext Storage of Sensitive Information",
        "severity": "High",
        "score": 7.5,
        "owasp": "A02:2021-Cryptographic Failures",
        "description": "Sensitive application settings, PII data, or keys are kept in unencrypted plaintext inside cache logs or files.",
        "recommendation": "Encrypt sensitive data both at rest and in transit using modern, industry-standard cryptographic algorithms."
    },
    "CWE-327": {
        "name": "Use of a Broken or Risky Cryptographic Algorithm",
        "severity": "High",
        "score": 7.4,
        "owasp": "A02:2021-Cryptographic Failures",
        "description": "The application relies on weak or deprecated cryptographic mechanisms (e.g., MD5, SHA1, DES) that are susceptible to collisions.",
        "recommendation": "Migrate system configurations to modern cryptographic standards like AES-256-GCM and SHA-256 / SHA-3."
    },
    "CWE-611": {
        "name": "Improper Neutralization of XML External Entity Reference ('XXE')",
        "severity": "High",
        "score": 7.5,
        "owasp": "A05:2021-Security Misconfiguration",
        "description": "XML parser settings let external entities resolve files or make requests, presenting information disclosure or SSRF risks.",
        "recommendation": "Disable external entity resolution (DTD processing) on all parsing engine initializers."
    },
    "CWE-862": {
        "name": "Missing Authorization",
        "severity": "High",
        "score": 8.5,
        "owasp": "A01:2021-Broken Access Control",
        "description": "Access tokens verify authentication, but fail to check if the actor holds correct policy authorization rules for execution.",
        "recommendation": "Enforce Role-Based Access Control (RBAC) or Attribute-Based Access Control (ABAC) filters on all service controller gateways."
    },
    "CWE-94": {
        "name": "Improper Neutralization of Directives in Dynamically Evaluated Code ('Code Injection')",
        "severity": "Critical",
        "score": 9.8,
        "owasp": "A03:2021-Injection",
        "description": "Input directly goes into dynamic interpreter execution segments (e.g., eval(), exec()), enabling unauthorized arbitrary system code execution.",
        "recommendation": "Refactor logic to pass configuration variables through structured APIs instead of interpreting string payloads."
    },
    "CWE-400": {
        "name": "Uncontrolled Resource Consumption ('Resource Exhaustion')",
        "severity": "Medium",
        "score": 6.5,
        "owasp": "A05:2021-Security Misconfiguration",
        "description": "System processes allocate resources without limiting allocation bounds, leading to potential denial of service conditions.",
        "recommendation": "Configure strict memory, cpu, and storage allocation caps along with client rate-limiting configurations."
    },
    "CWE-295": {
        "name": "Improper Certificate Validation",
        "severity": "Medium",
        "score": 5.9,
        "owasp": "A02:2021-Cryptographic Failures",
        "description": "External SSL/TLS host verification is disabled or ignored, exposing communication channels to MITM attacks.",
        "recommendation": "Enforce strict host matching and validate authority credentials against reputable system certificate pools."
    },
    "CWE-330": {
        "name": "Use of Insufficiently Random Values",
        "severity": "Medium",
        "score": 5.9,
        "owasp": "A02:2021-Cryptographic Failures",
        "description": "The application relies on predictable pseudo-random generator algorithms for crypto tokens or salts.",
        "recommendation": "Use cryptographically secure pseudo-random generators (CSPRNG), such as Python's secrets module."
    },
    "CWE-918": {
        "name": "Server-Side Request Forgery (SSRF)",
        "severity": "High",
        "score": 8.6,
        "owasp": "A10:2021-Server-Side Request Forgery",
        "description": "Client inputs form target endpoints that the server calls, allowing requests to private internal host systems.",
        "recommendation": "Define strict IP destination whitelists, refuse connection delegation, and restrict request schema bindings."
    }
}

class VulnerabilityPredictor:
    """Predicts vulnerability metrics on raw code strings using hybrid detection and explainability."""
    
    def __init__(self, saved_model_dir: str = str(SAVED_MODEL_DIR)):
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.model_path = check_model()
        
        # 1. Load Tokenizer & CodeBERT
        if (self.model_path / "config.json").exists():
            logger.info("Loading tokenizer...")
            self.tokenizer = AutoTokenizer.from_pretrained(str(self.model_path))
            logger.info("Loading fine-tuned CodeBERT...")
            self.model = CodeBERTClassifier.from_pretrained(str(self.model_path))
        else:
            logger.warning(f"No fine-tuned model found at {self.model_path}. Falling back to pre-trained base model {MODEL_CHECKPOINT}...")
            logger.info("Loading tokenizer...")
            self.tokenizer = AutoTokenizer.from_pretrained(MODEL_CHECKPOINT)
            logger.info("Loading CodeBERT model...")
            self.model = CodeBERTClassifier(MODEL_CHECKPOINT)
            
        self.model.to(self.device)
        self.model.eval()
        
        # 2. Load CWE Classifier (Random Forest + TF-IDF Vectorizer)
        cwe_clf_path = Path(saved_model_dir) / "cwe_classifier.pkl"
        cwe_vec_path = Path(saved_model_dir) / "cwe_vectorizer.pkl"
        
        if cwe_clf_path.exists() and cwe_vec_path.exists():
            logger.info("Loading CWE classifier...")
            with open(cwe_clf_path, "rb") as f:
                self.cwe_classifier = pickle.load(f)
            with open(cwe_vec_path, "rb") as f:
                self.cwe_vectorizer = pickle.load(f)
        else:
            logger.warning("CWE Classifier assets not found. Fallback heuristic matching will be used for CWE predictions.")
            self.cwe_classifier = None
            self.cwe_vectorizer = None

        # 3. Instantiate helper services
        self.explainer = VulnerabilityExplainer(model=self.model, tokenizer=self.tokenizer)
        self.hybrid_detector = HybridDetector()

    def predict(self, code: str, file_path: str = "") -> dict:
        """Runs model inference, hybrid checks, and explainability on a single code snippet.
        
        Args:
            code: Source code string.
            file_path: Optional context path of code file.
            
        Returns:
            Dict containing detailed vulnerability report conforming to standard schemas.
        """
        if not code or not code.strip():
            return {
                "vulnerable": False,
                "confidence": 0.0,
                "predicted_cwe": None,
                "cwe_name": None,
                "severity": "None",
                "recommendation": "No code provided.",
                "cvss_score": 0.0,
                "owasp": None,
                "explanation": {
                    "vulnerable_lines": [],
                    "reason": "Snippet is empty.",
                    "highlighted_tokens": []
                }
            }

        # Tokenize code
        inputs = self.tokenizer(
            code,
            padding="max_length",
            truncation=True,
            max_length=512,
            return_tensors="pt"
        )
        
        input_ids = inputs['input_ids'].to(self.device)
        attention_mask = inputs['attention_mask'].to(self.device)
        
        # Model forward
        with torch.no_grad():
            logits, _ = self.model(input_ids, attention_mask)
            probabilities = torch.softmax(logits, dim=1).cpu().numpy()[0]
            
        # Class 1 is vulnerable, Class 0 is safe
        vulnerable_prob = float(probabilities[1])
        is_vuln = vulnerable_prob >= 0.5
        
        predicted_cwe = None
        
        # Step 1: CWE prediction if model flagged it as vulnerable
        if is_vuln:
            if self.cwe_classifier and self.cwe_vectorizer:
                try:
                    features = self.cwe_vectorizer.transform([code])
                    predicted_cwe = str(self.cwe_classifier.predict(features)[0])
                except Exception as e:
                    logger.error(f"CWE prediction failed: {e}")
                    predicted_cwe = self._heuristic_cwe_match(code)
            else:
                predicted_cwe = self._heuristic_cwe_match(code)
        
        # Step 2: Combine with static code logic
        ml_prediction = {
            "vulnerable": is_vuln,
            "confidence": vulnerable_prob,
            "predicted_cwe": predicted_cwe
        }
        
        aggregate = self.hybrid_detector.analyze(code, ml_prediction, file_path=file_path)
        is_vuln = aggregate["vulnerable"]
        confidence = aggregate["confidence"]
        predicted_cwe = aggregate["predicted_cwe"]
        
        cwe_name = None
        severity = "None"
        recommendation = "No security issues detected."
        cvss_score = 0.0
        owasp = None
        description = "No vulnerability identified."
        explanation = {
            "vulnerable_lines": [],
            "reason": "Model evaluated snippet as safe.",
            "highlighted_tokens": []
        }
        
        # Step 3: Populate details if aggregated assessment is vulnerable
        if is_vuln:
            # Re-verify predicted_cwe is mapped, fallback to generic if not
            if not predicted_cwe:
                predicted_cwe = self._heuristic_cwe_match(code)
                
            if predicted_cwe in CWE_INFO:
                cwe_name = CWE_INFO[predicted_cwe]["name"]
                severity = CWE_INFO[predicted_cwe]["severity"]
                recommendation = CWE_INFO[predicted_cwe]["recommendation"]
                cvss_score = CWE_INFO[predicted_cwe]["score"]
                owasp = CWE_INFO[predicted_cwe]["owasp"]
                description = CWE_INFO[predicted_cwe]["description"]
            else:
                cwe_name = "Vulnerability identified"
                severity = "High" if confidence > 0.8 else "Medium"
                recommendation = "Inspect inputs, enforce validation boundaries, and audit logical access control policies."
                cvss_score = round(confidence * 10, 1)
                owasp = "A03:2021-Injection"
                description = "General vulnerability detected in snippet code structure."
            
            # Retrieve attention-based explanation
            try:
                explanation = self.explainer.explain(
                    code, 
                    confidence, 
                    file_path=file_path, 
                    cwe_id=predicted_cwe, 
                    cwe_name=cwe_name, 
                    severity=severity
                )
            except Exception as e:
                logger.error(f"Failed to generate explainability details: {e}")
                explanation = {
                    "vulnerable_lines": [],
                    "reason": f"Explainer encountered an error: {e}",
                    "highlighted_tokens": []
                }
                
        return {
            "vulnerable": bool(is_vuln),
            "confidence": round(confidence, 4),
            "predicted_cwe": predicted_cwe,
            "cwe_name": cwe_name,
            "severity": severity,
            "recommendation": recommendation,
            "cvss_score": cvss_score,
            "owasp": owasp,
            "description": description,
            "explanation": explanation
        }

    @torch.inference_mode()
    def predict_batch(self, codes: list, file_paths: list = None) -> list:
        """Executes efficient batch inference on multiple code snippets.
        
        Args:
            codes: List of code strings.
            file_paths: Optional matching list of file path contexts.
            
        Returns:
            List of result dictionaries.
        """
        if not codes:
            return []
            
        if file_paths is None:
            file_paths = [""] * len(codes)
            
        results = []
        
        # We chunk batch processing to prevent memory spikes
        chunk_size = 32
        for i in range(0, len(codes), chunk_size):
            chunk_codes = codes[i:i + chunk_size]
            chunk_paths = file_paths[i:i + chunk_size]
            
            inputs = self.tokenizer(
                chunk_codes,
                padding=True,
                truncation=True,
                max_length=512,
                return_tensors="pt"
            )
            
            input_ids = inputs['input_ids'].to(self.device)
            attention_mask = inputs['attention_mask'].to(self.device)
            
            logits, _ = self.model(input_ids, attention_mask)
            probabilities = torch.softmax(logits, dim=1).cpu().numpy()
            
            for j, (code, path) in enumerate(zip(chunk_codes, chunk_paths)):
                prob = float(probabilities[j][1])
                is_vuln = prob >= 0.5
                
                # Direct prediction generation on each item
                pred_cwe = self._heuristic_cwe_match(code) if is_vuln else None
                ml_pred = {
                    "vulnerable": is_vuln,
                    "confidence": prob,
                    "predicted_cwe": pred_cwe
                }
                
                aggregate = self.hybrid_detector.analyze(code, ml_pred, file_path=path)
                is_vuln = aggregate["vulnerable"]
                confidence = aggregate["confidence"]
                predicted_cwe = aggregate["predicted_cwe"]
                
                # Fetch details
                cwe_name = None
                severity = "None"
                recommendation = "No security issues detected."
                cvss_score = 0.0
                owasp = None
                description = "No vulnerability identified."
                explanation = {"vulnerable_lines": [], "reason": "Model evaluated snippet as safe.", "highlighted_tokens": []}
                
                if is_vuln:
                    if not predicted_cwe:
                        predicted_cwe = self._heuristic_cwe_match(code)
                        
                    if predicted_cwe in CWE_INFO:
                        cwe_name = CWE_INFO[predicted_cwe]["name"]
                        severity = CWE_INFO[predicted_cwe]["severity"]
                        recommendation = CWE_INFO[predicted_cwe]["recommendation"]
                        cvss_score = CWE_INFO[predicted_cwe]["score"]
                        owasp = CWE_INFO[predicted_cwe]["owasp"]
                        description = CWE_INFO[predicted_cwe]["description"]
                    else:
                        cwe_name = "Vulnerability identified"
                        severity = "High" if confidence > 0.8 else "Medium"
                        recommendation = "Inspect inputs, enforce validation boundaries, and audit logical access control policies."
                        cvss_score = round(confidence * 10, 1)
                        owasp = "A03:2021-Injection"
                        description = "General vulnerability detected in snippet code structure."
                        
                    try:
                        explanation = self.explainer.explain(
                            code, 
                            confidence, 
                            file_path=path, 
                            cwe_id=predicted_cwe, 
                            cwe_name=cwe_name, 
                            severity=severity
                        )
                    except Exception:
                        pass
                        
                results.append({
                    "vulnerable": bool(is_vuln),
                    "confidence": round(confidence, 4),
                    "predicted_cwe": predicted_cwe,
                    "cwe_name": cwe_name,
                    "severity": severity,
                    "recommendation": recommendation,
                    "cvss_score": cvss_score,
                    "owasp": owasp,
                    "description": description,
                    "explanation": explanation
                })
                
        return results

    def _heuristic_cwe_match(self, code: str) -> str:
        """Fallback rule-based CWE matching when ML CWE classifier is not trained."""
        code_lower = code.lower()
        if "select " in code_lower and ("where" in code_lower or "join" in code_lower or "%s" in code_lower or "format" in code_lower or "like" in code_lower):
            return "CWE-89"  # SQL Injection
        if "script" in code_lower or "html" in code_lower or "render" in code_lower or "innerhtml" in code_lower:
            return "CWE-79"  # XSS
        if "strcpy" in code_lower or "memcpy" in code_lower or "malloc" in code_lower or "buffer" in code_lower or "strncpy" not in code_lower:
            # Check context of unsafe copy
            if "strcpy" in code_lower or "strcat" in code_lower:
                return "CWE-119" # Buffer Overflow
        if "exec(" in code_lower or "system(" in code_lower or "subprocess.run(" in code_lower or "subprocess.popen(" in code_lower:
            return "CWE-78"  # OS command injection
        if "pickle.load" in code_lower or "pickle.loads" in code_lower or "marshal.loads" in code_lower or "yaml.load" in code_lower:
            return "CWE-502" # Deserialization
        if "path" in code_lower or "open(" in code_lower or "file" in code_lower or "directory" in code_lower:
            if ".." in code_lower or "filename" in code_lower or "path" in code_lower:
                return "CWE-22"  # Path traversal
        if "api_key" in code_lower or "secret" in code_lower or "password" in code_lower or "token" in code_lower:
            return "CWE-798" # Hardcoded Secrets
        return "CWE-20"      # Input Validation default
