import time
import os
import psutil
from typing import Dict, Any
from predict import VulnerabilityPredictor
from utils.logging_utils import setup_logger

logger = setup_logger("benchmark-suite")


class BenchmarkSuite:
    """Measures model prediction latency, CPU/RAM loads, and throughput parameters."""

    def __init__(self, predictor: VulnerabilityPredictor = None):
        self.predictor = predictor or VulnerabilityPredictor()

    def run_inference_benchmark(self, iterations: int = 10) -> Dict[str, Any]:
        """Runs batch inference iterations to check performance metrics under stress.

        Args:
            iterations: Number of sequential prediction iterations to run.

        Returns:
            Dict containing latency, throughput, and memory consumption details.
        """
        code_snippet = (
            "def test_sqli(user_input):\n"
            "    query = 'SELECT * FROM users WHERE name = ' + user_input\n"
            "    return db.execute(query)\n"
        )
        
        process = psutil.Process(os.getpid())
        ram_start = process.memory_info().rss / (1024 * 1024)
        
        logger.info("Starting inference benchmark (%d iterations)...", iterations)
        start_time = time.perf_counter()
        
        for _ in range(iterations):
            self.predictor.predict(code_snippet, file_path="benchmark.py")
            
        end_time = time.perf_counter()
        ram_end = process.memory_info().rss / (1024 * 1024)
        
        total_time = end_time - start_time
        avg_latency = total_time / iterations
        throughput = iterations / total_time
        ram_diff = ram_end - ram_start
        
        metrics = {
            "iterations": iterations,
            "total_duration_sec": round(total_time, 4),
            "average_latency_sec": round(avg_latency, 4),
            "throughput_req_per_sec": round(throughput, 2),
            "memory_usage_start_mb": round(ram_start, 2),
            "memory_usage_end_mb": round(ram_end, 2),
            "memory_diff_mb": round(ram_diff, 2)
        }
        
        logger.info(
            "Benchmark completed. Throughput: %.2f req/sec, Avg Latency: %.4f sec.",
            throughput,
            avg_latency,
        )
        return metrics
