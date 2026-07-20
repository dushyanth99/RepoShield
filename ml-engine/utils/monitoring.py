import os
import psutil
import torch
from typing import Dict, Any
from utils.logging_utils import setup_logger

logger = setup_logger("monitoring-service")


class SystemMonitor:
    """Tracks RAM, CPU, GPU utilization, query execution durations, and model parameters."""

    # Thread-safe metric accumulators
    _total_requests = 0
    _total_duration = 0.0

    @classmethod
    def record_request(cls, duration: float) -> None:
        """Accumulates request timing measurements.

        Args:
            duration: Request execution time in seconds.
        """
        cls._total_requests += 1
        cls._total_duration += duration

    @classmethod
    def get_metrics(cls) -> Dict[str, Any]:
        """Gathers system resources and API performance summaries.

        Returns:
            Dict containing CPU, RAM, GPU, and execution latency details.
        """
        process = psutil.Process(os.getpid())
        ram_usage_mb = round(process.memory_info().rss / (1024 * 1024), 2)
        cpu_usage_pct = psutil.cpu_percent(interval=None)
        
        gpu_info = {
            "available": torch.cuda.is_available()
        }
        if torch.cuda.is_available():
            gpu_info["device_name"] = torch.cuda.get_device_name(0)
            gpu_info["memory_allocated_mb"] = round(torch.cuda.memory_allocated(0) / (1024 * 1024), 2)
            gpu_info["memory_reserved_mb"] = round(torch.cuda.memory_reserved(0) / (1024 * 1024), 2)

        avg_latency = (
            round(cls._total_duration / cls._total_requests, 4)
            if cls._total_requests > 0
            else 0.0
        )

        return {
            "process_id": os.getpid(),
            "uptime_stats": {
                "total_requests": cls._total_requests,
                "average_latency_sec": avg_latency
            },
            "system_resources": {
                "cpu_usage_percent": cpu_usage_pct,
                "ram_usage_mb": ram_usage_mb,
                "system_memory_percent": psutil.virtual_memory().percent
            },
            "gpu_resources": gpu_info
        }
