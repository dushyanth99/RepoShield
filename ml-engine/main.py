import json
import time
from fastapi import FastAPI, BackgroundTasks, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from pathlib import Path
from utils.logging_utils import setup_logger
from train import run_train_pipeline
from predict import VulnerabilityPredictor
from services.scanner import RepositoryScanner
from services.agent_orchestrator import AgentOrchestrator
from services.reporter import ExecutiveReporter

# Import the new audited modules
from services.embeddings import EmbeddingService
from services.knowledge_graph import SecurityKnowledgeGraph
from services.patch_generator import AIPatchGenerator
from services.simulation import AttackSimulator
from utils.monitoring import SystemMonitor
from tests.benchmark_suite import BenchmarkSuite

from config import SAVED_MODEL_DIR, FASTAPI_HOST, FASTAPI_PORT
import schemas

logger = setup_logger("fastapi-app")

app = FastAPI(
    title="RepoShield ML Vulnerability Detection Engine",
    description="An enterprise-grade security analysis service using CodeBERT and static patterns to scan codebases.",
    version="1.0.0"
)

# Start time tracking for uptime
APP_START_TIME = time.time()

# Request timing middleware to record SystemMonitor statistics
@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    start_time = time.perf_counter()
    response = await call_next(request)
    process_time = time.perf_counter() - start_time
    # Accumulate metrics in SystemMonitor
    SystemMonitor.record_request(process_time)
    response.headers["X-Process-Time"] = f"{process_time:.4f}"
    return response

# Enable CORS for communication with frontend/backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
async def startup_event():
    logger.info("Application Starts")
    
    # 1 & 2. Check Dataset and Download Dataset if Required
    from dataset.download_dataset import download_dataset
    try:
        logger.info("Check Dataset...")
        download_dataset()
    except Exception as e:
        logger.error(f"Dataset Download Failure: {e}")
        # Not raising, we can fail gracefully if needed, or raise depending on strictness.
        
    # 3. Open SQLite
    from utils.db import init_db
    try:
        logger.info("Open SQLite...")
        init_db()
    except Exception as e:
        logger.error(f"SQLite Failure: {e}")
        
    # 4. Load ML Models
    try:
        logger.info("Load ML Models...")
        # Trigger the lazy loading
        get_predictor()
    except Exception as e:
        logger.error(f"Missing Model or Load Failure: {e}")
        
    # 5. Initialize Services
    try:
        logger.info("Initialize Services...")
        get_scanner()
        get_orchestrator()
    except Exception as e:
        logger.error(f"Service initialization error: {e}")
        
    logger.info("FastAPI Starts")


# Global lazy-loaded predictors/scanners/orchestrators/services
predictor_instance = None
scanner_instance = None
orchestrator_instance = None
embedding_instance = None
graph_instance = None
benchmark_instance = None

def get_predictor() -> VulnerabilityPredictor:
    global predictor_instance
    if predictor_instance is None:
        logger.info("Initializing VulnerabilityPredictor (lazy-load)...")
        predictor_instance = VulnerabilityPredictor()
    return predictor_instance

def get_scanner() -> RepositoryScanner:
    global scanner_instance
    if scanner_instance is None:
        logger.info("Initializing RepositoryScanner (lazy-load)...")
        scanner_instance = RepositoryScanner(get_predictor())
    return scanner_instance

def get_orchestrator() -> AgentOrchestrator:
    global orchestrator_instance
    if orchestrator_instance is None:
        logger.info("Initializing AgentOrchestrator (lazy-load)...")
        orchestrator_instance = AgentOrchestrator(get_predictor())
    return orchestrator_instance

def get_embedding_service() -> EmbeddingService:
    global embedding_instance
    if embedding_instance is None:
        logger.info("Initializing EmbeddingService (lazy-load)...")
        embedding_instance = EmbeddingService()
    return embedding_instance

def get_knowledge_graph() -> SecurityKnowledgeGraph:
    global graph_instance
    if graph_instance is None:
        logger.info("Initializing SecurityKnowledgeGraph (lazy-load)...")
        graph_instance = SecurityKnowledgeGraph()
    return graph_instance

def get_benchmark_suite() -> BenchmarkSuite:
    global benchmark_instance
    if benchmark_instance is None:
        logger.info("Initializing BenchmarkSuite (lazy-load)...")
        benchmark_instance = BenchmarkSuite(get_predictor())
    return benchmark_instance


@app.get("/health")
def health_check():
    """Checks the health of the API, active hardware info, and runtime metrics."""
    status_file = Path(SAVED_MODEL_DIR) / "train_status.json"
    training_info = {"status": "not_started"}
    
    if status_file.exists():
        try:
            with open(status_file, "r") as f:
                training_info = json.load(f)
        except Exception as e:
            logger.error(f"Failed to read training status file: {e}")
            training_info = {"status": "error", "message": str(e)}
            
    model_loaded = (Path(SAVED_MODEL_DIR) / "best_model").exists()
    
    # Query performance metrics via SystemMonitor
    monitoring_stats = SystemMonitor.get_metrics()

    return {
        "status": "healthy",
        "model_loaded": model_loaded,
        "memory_usage_mb": monitoring_stats["system_resources"]["ram_usage_mb"],
        "training_job": training_info,
        "metrics": monitoring_stats
    }


@app.post("/train")
def train_model(background_tasks: BackgroundTasks):
    """Triggers the ML Engine CodeBERT model training pipeline in the background."""
    status_file = Path(SAVED_MODEL_DIR) / "train_status.json"
    
    if status_file.exists():
        try:
            with open(status_file, "r") as f:
                status_data = json.load(f)
                if status_data.get("status") in ("running", "starting"):
                    return {
                        "status": "already_running",
                        "message": "Training is already in progress.",
                        "details": status_data
                    }
        except Exception:
            pass

    logger.info("Enqueuing training pipeline execution...")
    background_tasks.add_task(run_train_pipeline)
    
    return {
        "status": "training_started",
        "message": "Model training has been initiated in the background. Use GET /health to monitor progress."
    }


@app.post("/predict")
def predict_vulnerability(request: schemas.CodeSnippetRequest, predictor: VulnerabilityPredictor = Depends(get_predictor)):
    """Predicts if a single function/code snippet contains a vulnerability."""
    try:
        prediction = predictor.predict(request.code)
        return {
            "status": "success",
            "vulnerable": prediction["vulnerable"],
            "confidence": prediction["confidence"],
            "severity": prediction["severity"],
            "predicted_cwe": prediction["predicted_cwe"],
            "cwe_name": prediction["cwe_name"],
            "recommendations": prediction["recommendation"],
            "business_impact_score": round(prediction["confidence"] * 0.9, 2) if prediction["vulnerable"] else 0.0,
            "owasp": prediction.get("owasp"),
            "description": prediction.get("description"),
            "explanation": prediction.get("explanation")
        }
    except Exception as e:
        logger.error(f"Prediction API error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/agent-analyze", response_model=schemas.MultiAgentAssessmentResponse)
def agent_analyze_snippet(request: schemas.CodeSnippetRequest, orchestrator: AgentOrchestrator = Depends(get_orchestrator)):
    """Evaluates a code snippet using Multi-Agent consensus and Regulatory Compliance auditing."""
    try:
        logger.info("Executing Multi-Agent assessment run...")
        assessment = orchestrator.analyze_snippet(request.code)
        return assessment
    except Exception as e:
        logger.error(f"Agent-analyze API error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/scan-file")
def scan_single_file(request: schemas.ScanFileRequest, scanner: RepositoryScanner = Depends(get_scanner)):
    """Scans a single file path locally and returns full structural vulnerability details."""
    file_path = Path(request.path)
    if not file_path.exists() or not file_path.is_file():
        raise HTTPException(status_code=404, detail=f"File not found: {request.path}")
        
    logger.info(f"Scanning single file path: {file_path}")
    try:
        findings = scanner.scan_file(file_path)
        vuln_findings = [f for f in findings if f["vulnerable"]]
        
        # Format list to map VulnerabilitySchema
        formatted_vulns = []
        for f in vuln_findings:
            formatted_vulns.append({
                "type": f["cwe_name"] or "Security Risk",
                "severity": f["severity"],
                "confidence": f["confidence"],
                "predicted_cwe": f["predicted_cwe"],
                "owasp": f.get("owasp") or "Unknown",
                "file": file_path.name,
                "function": f"{f['function_name']}()",
                "lines": f"{f['line_number']}-{f['line_number'] + f['explanation']['vulnerable_lines'][-1] - f['explanation']['vulnerable_lines'][0] if f['explanation']['vulnerable_lines'] else f['line_number']}",
                "reason": f["explanation"]["reason"],
                "recommendation": f["recommendation"],
                "remediation": f.get("remediation")
            })
            
        return {
            "status": "completed",
            "file": str(file_path),
            "vulnerabilities": formatted_vulns,
            "metrics": {
                "functions_scanned": len(findings),
                "total_vulnerabilities": len(formatted_vulns)
            }
        }
    except Exception as e:
        logger.error(f"Scan-file API error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/scan-repository", response_model=schemas.RepositoryScanResponse)
def scan_repository(request: schemas.ScanRepositoryRequest, scanner: RepositoryScanner = Depends(get_scanner)):
    """Scans all supported files in a repository recursively and aggregates risk metrics."""
    logger.info(f"Received scan request for path: {request.path}")
    try:
        results = scanner.scan_directory(request.path)
        if results.get("status") == "error":
            raise HTTPException(status_code=400, detail=results.get("message"))
        return results
    except Exception as e:
        logger.error(f"Scan API error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/scan-report")
def scan_repository_and_report(request: schemas.ScanRepositoryRequest, scanner: RepositoryScanner = Depends(get_scanner)):
    """Scans a repository recursively and compiles a Markdown Executive Security Report."""
    logger.info(f"Generating Executive Security Report for path: {request.path}")
    try:
        results = scanner.scan_directory(request.path)
        if results.get("status") == "error":
            raise HTTPException(status_code=400, detail=results.get("message"))
            
        # Write report to repository logs directory as a persistent artifact
        output_report_file = Path(request.path) / "RepoShield_Executive_Report.md"
        report_md = ExecutiveReporter.generate_report(results, output_path=str(output_report_file))
        
        return {
            "status": "success",
            "report_path": str(output_report_file),
            "security_grade": results.get("security_grade"),
            "repository_score": results.get("repository_score"),
            "vulnerabilities_found": results["metrics"]["total_vulnerabilities"],
            "report_preview": report_md[:1500] + "\n\n... [Report Truncated, Full Markdown saved locally] ..."
        }
    except Exception as e:
        logger.error(f"Scan-report API error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/repository-risk", response_model=schemas.RiskSummaryResponse)
def get_repository_risk(request: schemas.ScanRepositoryRequest, scanner: RepositoryScanner = Depends(get_scanner)):
    """Scans a repository but returns ONLY aggregated risk and severity grades."""
    logger.info(f"Calculating repository risk metrics for path: {request.path}")
    try:
        results = scanner.scan_directory(request.path)
        if results.get("status") == "error":
            raise HTTPException(status_code=400, detail=results.get("message"))
            
        from services.risk_scorer import RepositoryRiskScorer
        vulnerabilities = results.get("vulnerabilities", [])
        
        metrics = RepositoryRiskScorer.calculate_scores(
            vulnerabilities, 
            results["metrics"]["files_scanned"], 
            results["metrics"]["functions_scanned"]
        )
        
        return {
            "repository_score": metrics["repository_score"],
            "security_grade": metrics["security_grade"],
            "business_impact": metrics["business_impact"],
            "business_impact_score": metrics["business_impact_score"],
            "confidence": metrics["confidence"],
            "critical_issues": metrics["critical_issues"],
            "high_issues": metrics["high_issues"],
            "medium_issues": metrics["medium_issues"],
            "low_issues": metrics["low_issues"]
        }
    except Exception as e:
        logger.error(f"Repository-risk API error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# --- Newly Added Hackathon Modules Endpoint Mappings ---

@app.post("/embeddings")
def get_code_embedding(request: schemas.EmbeddingRequest, service: EmbeddingService = Depends(get_embedding_service)):
    """Extracts CodeBERT CLS embeddings representation for a function."""
    try:
        embedding = service.get_embedding(request.code)
        return {"embedding": embedding, "dimensions": len(embedding)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/similarity")
def get_code_similarity(request: schemas.SimilarityRequest, service: EmbeddingService = Depends(get_embedding_service)):
    """Calculates cosine similarity distance between two code snippets."""
    try:
        v1 = service.get_embedding(request.code_1)
        v2 = service.get_embedding(request.code_2)
        score = service.cosine_similarity(v1, v2)
        return {"cosine_similarity": score}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/graph-query")
def query_knowledge_graph(request: schemas.GraphQueryRequest, graph: SecurityKnowledgeGraph = Depends(get_knowledge_graph)):
    """Queries security relationships, mitigations, or standards mapping from the compliance graph."""
    try:
        entities = graph.get_related_entities(request.entity_id, request.relation_type)
        return {"entity_id": request.entity_id, "related_entities": entities}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/attack-simulation")
def run_attack_simulation(request: schemas.AttackSimulationRequest):
    """Evaluates a code block against simulated exploit payloads and registers bypass mitigations."""
    try:
        simulation_res = AttackSimulator.simulate_attack(request.code, request.cwe_id)
        return simulation_res
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/generate-patch")
def generate_patch_diff(request: schemas.PatchGenerationRequest):
    """Suggests corrected code templates and computes a unified git-compatible patch diff."""
    try:
        patch_res = AIPatchGenerator.generate_patch(request.code, request.cwe_id, request.language)
        return patch_res
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/benchmark")
def run_stress_benchmark(background_tasks: BackgroundTasks, suite: BenchmarkSuite = Depends(get_benchmark_suite)):
    """Triggers performance and throughput benchmarking under iteration load."""
    try:
        logger.info("Executing Benchmark suite run...")
        metrics = suite.run_inference_benchmark(iterations=10)
        return metrics
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn
    logger.info(f"Starting server on {FASTAPI_HOST}:{FASTAPI_PORT}... ")
    uvicorn.run("main:app", host=FASTAPI_HOST, port=FASTAPI_PORT, reload=False)

