"""
Professional Python Profiling Infrastructure
Supports multiple profiling backends with toggleable instrumentation

Supports:
- cProfile: Built-in deterministic profiler
- py-spy: Low-overhead statistical profiler
- line_profiler: Line-by-line analysis
- Memory profiling with tracemalloc
- Real-time performance monitoring
"""

import os
import sys
import time
import threading
import tracemalloc
import functools
import cProfile
import pstats
import io
from pathlib import Path
from typing import Optional, Dict, Any, List, Callable, Union
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime

try:
    import psutil

    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

try:
    import line_profiler

    LINE_PROFILER_AVAILABLE = True
except ImportError:
    LINE_PROFILER_AVAILABLE = False


@dataclass
class ProfileStats:
    """Container for profiling statistics"""

    function_name: str
    call_count: int = 0
    total_time: float = 0.0
    avg_time: float = 0.0
    max_time: float = 0.0
    min_time: float = float("inf")
    memory_peak: int = 0  # bytes
    memory_current: int = 0  # bytes
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class ProfilingConfig:
    """Configuration for profiling behavior"""

    enabled: bool = False
    output_dir: str = "profiling_output"
    backends: List[str] = field(default_factory=lambda: ["cprofile"])
    sample_interval: float = 0.01  # seconds
    memory_tracking: bool = True
    real_time_stats: bool = True
    auto_save: bool = True
    max_memory_samples: int = 1000

    # Backend-specific settings
    cprofile_sort_by: str = "cumulative"
    line_profiler_functions: List[str] = field(default_factory=list)
    py_spy_duration: int = 30  # seconds


class ProfilerManager:
    """
    Centralized profiler management with support for multiple backends
    """

    def __init__(self, config: Optional[ProfilingConfig] = None):
        self.config = config or ProfilingConfig()
        self.active_profilers: Dict[str, Any] = {}
        self.stats_cache: Dict[str, ProfileStats] = {}
        self.memory_samples: List[tuple] = []  # (timestamp, memory_mb)

        # Real-time monitoring
        self._monitoring_thread: Optional[threading.Thread] = None
        self._stop_monitoring = threading.Event()

        # Setup output directory
        self.output_dir = Path(self.config.output_dir)
        self.output_dir.mkdir(exist_ok=True)

        # Session ID for file naming
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Initialize memory tracking if enabled
        if self.config.memory_tracking:
            tracemalloc.start()

    def enable(self, backends: Optional[List[str]] = None):
        """Enable profiling with specified backends"""
        self.config.enabled = True
        if backends:
            self.config.backends = backends

        print(f"🔬 Profiling enabled with backends: {', '.join(self.config.backends)}")

        # Start real-time monitoring if requested
        if self.config.real_time_stats:
            self.start_monitoring()

    def disable(self):
        """Disable profiling and save results"""
        self.config.enabled = False
        self.stop_monitoring()

        if self.config.auto_save:
            self.save_all_results()

        print("🔬 Profiling disabled and results saved")

    def start_monitoring(self):
        """Start real-time performance monitoring in background thread"""
        if self._monitoring_thread and self._monitoring_thread.is_alive():
            return

        self._stop_monitoring.clear()
        self._monitoring_thread = threading.Thread(
            target=self._monitoring_worker, daemon=True, name="ProfilerMonitor"
        )
        self._monitoring_thread.start()

    def stop_monitoring(self):
        """Stop background monitoring thread"""
        if self._monitoring_thread:
            self._stop_monitoring.set()
            self._monitoring_thread.join(timeout=1.0)

    def _monitoring_worker(self):
        """Background worker for real-time monitoring"""
        while not self._stop_monitoring.wait(self.config.sample_interval):
            if not self.config.enabled:
                continue

            # Sample memory usage
            if self.config.memory_tracking and tracemalloc.is_tracing():
                current, peak = tracemalloc.get_traced_memory()
                timestamp = time.time()

                # Convert to MB for readability
                current_mb = current / 1024 / 1024
                self.memory_samples.append((timestamp, current_mb))

                # Limit samples to prevent unbounded growth
                if len(self.memory_samples) > self.config.max_memory_samples:
                    self.memory_samples = self.memory_samples[
                        -self.config.max_memory_samples :
                    ]

    @contextmanager
    def profile_context(self, name: str, backend: str = "cprofile"):
        """Context manager for profiling code blocks"""
        if not self.config.enabled or backend not in self.config.backends:
            yield
            return

        start_time = time.perf_counter()
        start_memory = 0

        if self.config.memory_tracking and tracemalloc.is_tracing():
            start_memory = tracemalloc.get_traced_memory()[0]

        # Initialize profiler based on backend
        profiler = None
        profiler_enabled = False

        if backend == "cprofile":
            profiler = cProfile.Profile()
            try:
                profiler.enable()
                profiler_enabled = True
            except ValueError:
                # Another profiler is already active - just track timing
                profiler = None
                profiler_enabled = False
        elif backend == "line_profiler" and LINE_PROFILER_AVAILABLE:
            profiler = line_profiler.LineProfiler()
            # Note: line_profiler requires function decoration, not context management

        try:
            yield profiler
        finally:
            end_time = time.perf_counter()
            execution_time = end_time - start_time

            # Stop profiler only if we successfully enabled it
            if profiler and backend == "cprofile" and profiler_enabled:
                profiler.disable()

            # Calculate memory delta
            memory_delta = 0
            if self.config.memory_tracking and tracemalloc.is_tracing():
                end_memory = tracemalloc.get_traced_memory()[0]
                memory_delta = end_memory - start_memory

            # Update stats
            self._update_stats(name, execution_time, memory_delta)

            # Save profiler results if auto-save enabled and we have a valid profiler
            if (
                self.config.auto_save
                and profiler
                and backend == "cprofile"
                and profiler_enabled
            ):
                self._save_cprofile_results(name, profiler)

    def profile_function(self, name: Optional[str] = None, backend: str = "cprofile"):
        """Decorator for profiling functions"""

        def decorator(func: Callable) -> Callable:
            prof_name = name or f"{func.__module__}.{func.__qualname__}"

            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                with self.profile_context(prof_name, backend):
                    return func(*args, **kwargs)

            return wrapper

        return decorator

    def _update_stats(self, name: str, execution_time: float, memory_delta: int):
        """Update cached statistics for a profiled function"""
        if name not in self.stats_cache:
            self.stats_cache[name] = ProfileStats(function_name=name)

        stats = self.stats_cache[name]
        stats.call_count += 1
        stats.total_time += execution_time
        stats.avg_time = stats.total_time / stats.call_count
        stats.max_time = max(stats.max_time, execution_time)
        stats.min_time = min(stats.min_time, execution_time)

        if memory_delta > 0:
            stats.memory_current = memory_delta
            stats.memory_peak = max(stats.memory_peak, memory_delta)

    def _save_cprofile_results(self, name: str, profiler: cProfile.Profile):
        """Save cProfile results to file"""
        timestamp = datetime.now().strftime("%H%M%S")
        filename = f"cprofile_{name}_{timestamp}_{self.session_id}.prof"
        filepath = self.output_dir / filename

        profiler.dump_stats(str(filepath))

        # Also save human-readable version
        s = io.StringIO()
        ps = pstats.Stats(profiler, stream=s)
        ps.sort_stats(self.config.cprofile_sort_by)
        ps.print_stats(30)  # Top 30 functions

        txt_filepath = filepath.with_suffix(".txt")
        with open(txt_filepath, "w") as f:
            f.write(s.getvalue())

    def get_stats_summary(self) -> Dict[str, Any]:
        """Get a summary of all profiling statistics"""
        summary = {
            "session_id": self.session_id,
            "enabled": self.config.enabled,
            "backends": self.config.backends,
            "functions": {},
            "memory": {
                "samples_count": len(self.memory_samples),
                "peak_mb": max([s[1] for s in self.memory_samples])
                if self.memory_samples
                else 0,
                "current_mb": self.memory_samples[-1][1] if self.memory_samples else 0,
            },
        }

        # Add function statistics
        for name, stats in self.stats_cache.items():
            summary["functions"][name] = {
                "calls": stats.call_count,
                "total_time": f"{stats.total_time:.4f}s",
                "avg_time": f"{stats.avg_time:.4f}s",
                "max_time": f"{stats.max_time:.4f}s",
                "min_time": f"{stats.min_time:.4f}s",
                "memory_peak_mb": stats.memory_peak / 1024 / 1024,
            }

        return summary

    def print_stats(self):
        """Print formatted statistics to console"""
        summary = self.get_stats_summary()

        print("\n" + "=" * 60)
        print(f"🔬 PROFILING SUMMARY - Session {summary['session_id']}")
        print("=" * 60)

        if not summary["functions"]:
            print("No profiling data collected.")
            return

        print(f"Memory Peak: {summary['memory']['peak_mb']:.2f} MB")
        print(f"Memory Current: {summary['memory']['current_mb']:.2f} MB")
        print(f"Memory Samples: {summary['memory']['samples_count']}")
        print()

        # Function statistics table
        print(f"{'Function':<40} {'Calls':<8} {'Total':<10} {'Avg':<10} {'Max':<10}")
        print("-" * 80)

        # Sort by total time descending
        sorted_functions = sorted(
            summary["functions"].items(),
            key=lambda x: float(x[1]["total_time"].rstrip("s")),
            reverse=True,
        )

        for name, stats in sorted_functions[:20]:  # Top 20
            short_name = name.split(".")[-1][:38]  # Truncate long names
            print(
                f"{short_name:<40} {stats['calls']:<8} {stats['total_time']:<10} "
                f"{stats['avg_time']:<10} {stats['max_time']:<10}"
            )

    def save_all_results(self):
        """Save all profiling results to files"""
        # Save summary as JSON
        import json

        summary_file = self.output_dir / f"summary_{self.session_id}.json"
        with open(summary_file, "w") as f:
            json.dump(self.get_stats_summary(), f, indent=2)

        # Save memory samples as CSV
        if self.memory_samples:
            csv_file = self.output_dir / f"memory_{self.session_id}.csv"
            with open(csv_file, "w") as f:
                f.write("timestamp,memory_mb\n")
                for timestamp, memory_mb in self.memory_samples:
                    f.write(f"{timestamp},{memory_mb:.3f}\n")

        print(f"📊 Profiling results saved to {self.output_dir}/")

    def generate_py_spy_command(self, pid: Optional[int] = None) -> str:
        """Generate py-spy command for external profiling"""
        if pid is None:
            pid = os.getpid()

        output_file = self.output_dir / f"pyspy_{self.session_id}.svg"
        duration = self.config.py_spy_duration

        return f"py-spy record -o {output_file} -d {duration} -f speedscope --pid {pid}"

    def start_external_profilers(self):
        """Start external profilers like py-spy"""
        if "py-spy" in self.config.backends:
            command = self.generate_py_spy_command()
            print(f"🔬 To run py-spy externally, execute:")
            print(f"   {command}")

    def __enter__(self):
        """Context manager entry"""
        if self.config.enabled:
            self.start_monitoring()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.disable()


# Global profiler instance
_global_profiler: Optional[ProfilerManager] = None


def init_profiling(config: Optional[ProfilingConfig] = None) -> ProfilerManager:
    """Initialize global profiling manager"""
    global _global_profiler
    _global_profiler = ProfilerManager(config)
    return _global_profiler


def get_profiler() -> Optional[ProfilerManager]:
    """Get the global profiler instance"""
    return _global_profiler


def profile(name: Optional[str] = None, backend: str = "cprofile"):
    """Decorator for profiling functions (uses global profiler)"""
    if _global_profiler is None:
        # Return no-op decorator if profiling not initialized
        return lambda func: func

    return _global_profiler.profile_function(name, backend)


@contextmanager
def profile_block(name: str, backend: str = "cprofile"):
    """Context manager for profiling code blocks (uses global profiler)"""
    if _global_profiler is None or not _global_profiler.config.enabled:
        yield
        return

    with _global_profiler.profile_context(name, backend):
        yield


def print_profiling_stats():
    """Print profiling statistics (uses global profiler)"""
    if _global_profiler:
        _global_profiler.print_stats()


def save_profiling_results():
    """Save profiling results (uses global profiler)"""
    if _global_profiler:
        _global_profiler.save_all_results()


# Specialized profilers for animation performance
class AnimationProfiler:
    """Specialized profiler for animation performance analysis"""

    def __init__(self, profiler_manager: ProfilerManager):
        self.profiler = profiler_manager
        self.frame_times: List[float] = []
        self.fps_history: List[float] = []
        self.last_frame_time = time.perf_counter()

    def start_frame(self):
        """Mark the start of a new frame"""
        current_time = time.perf_counter()
        if self.last_frame_time > 0:
            frame_time = current_time - self.last_frame_time
            self.frame_times.append(frame_time)

            # Calculate FPS
            if frame_time > 0:
                fps = 1.0 / frame_time
                self.fps_history.append(fps)

            # Keep only recent samples
            if len(self.frame_times) > 1000:
                self.frame_times = self.frame_times[-1000:]
            if len(self.fps_history) > 1000:
                self.fps_history = self.fps_history[-1000:]

        self.last_frame_time = current_time

    def get_performance_stats(self) -> Dict[str, float]:
        """Get animation performance statistics"""
        if not self.frame_times:
            return {}

        avg_frame_time = sum(self.frame_times) / len(self.frame_times)
        max_frame_time = max(self.frame_times)
        min_frame_time = min(self.frame_times)

        stats = {
            "avg_frame_time_ms": avg_frame_time * 1000,
            "max_frame_time_ms": max_frame_time * 1000,
            "min_frame_time_ms": min_frame_time * 1000,
            "avg_fps": 1.0 / avg_frame_time if avg_frame_time > 0 else 0,
        }

        if self.fps_history:
            stats["current_fps"] = self.fps_history[-1]
            stats["max_fps"] = max(self.fps_history)
            stats["min_fps"] = min(self.fps_history)

        return stats


# Convenience functions for animation profiling
def create_animation_profiler() -> Optional[AnimationProfiler]:
    """Create an animation profiler if global profiler is available"""
    global_prof = get_profiler()
    if global_prof and global_prof.config.enabled:
        return AnimationProfiler(global_prof)
    return None
