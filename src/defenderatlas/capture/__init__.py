"""ProcMon and ETW capture modules - the DefenderAtlas Collector."""

from __future__ import annotations

from defenderatlas.capture.collector import (
    COLLECTOR_VERSION,
    CollectionSummary,
    Collector,
    CollectorConfig,
)
from defenderatlas.capture.dataset import Sample, enumerate_samples
from defenderatlas.capture.filter import CsvFilterStats, ProcmonFilter
from defenderatlas.capture.procmon import ProcmonController, find_procmon
from defenderatlas.capture.taskscheduler import (
    DEFAULT_TASK_NAME,
    install_procmon_task,
    is_task_running,
    launch_procmon_task,
    task_exists,
    uninstall_procmon_task,
)
from defenderatlas.capture.trigger import AttachmentTrigger, find_trigger_worker

__all__ = [
    "COLLECTOR_VERSION",
    "DEFAULT_TASK_NAME",
    "AttachmentTrigger",
    "CollectionSummary",
    "Collector",
    "CollectorConfig",
    "CsvFilterStats",
    "ProcmonController",
    "ProcmonFilter",
    "Sample",
    "enumerate_samples",
    "find_procmon",
    "find_trigger_worker",
    "install_procmon_task",
    "is_task_running",
    "launch_procmon_task",
    "task_exists",
    "uninstall_procmon_task",
]
