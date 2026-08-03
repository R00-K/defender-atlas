"""The DefenderAtlas Collector engine.

The Collector is responsible only for capture and experiment generation: it
discovers samples, reproduces Defender's download scan, captures the resulting
activity with ProcMon, and writes a self-contained experiment per sample. It
does NOT perform PE analysis.

A failure in any step never aborts the run: the Collector logs the problem,
records the experiment as failed and continues with the next sample.
"""

from __future__ import annotations

import logging
import shutil
import time
from dataclasses import dataclass
from pathlib import Path

from defenderatlas.capture.dataset import Sample, enumerate_samples
from defenderatlas.capture.experiment import ExperimentDirectory
from defenderatlas.capture.filter import ProcmonFilter
from defenderatlas.capture.metadata import (
    build_manifest,
    build_metadata,
    build_trigger_info,
    write_json,
)
from defenderatlas.capture.procmon import ProcmonController
from defenderatlas.capture.taskscheduler import DEFAULT_TASK_NAME
from defenderatlas.capture.trigger import AttachmentTrigger

log = logging.getLogger(__name__)

COLLECTOR_VERSION = "1.0"

DEFAULT_SOURCE_URL = "https://example.com/download"


@dataclass(frozen=True)
class CollectorConfig:
    """Runtime configuration for a collection run."""

    dataset_root: Path
    experiment_root: Path = Path("experiments")
    working_directory: Path = Path.home() / "Downloads"
    procmon_path: Path | None = None
    trigger_worker_path: Path | None = None
    source_url: str = DEFAULT_SOURCE_URL
    trigger_timeout_ms: int = 8000
    trigger_worker_timeout_ms: int = 30000
    completion_strategy: str = "timeout"
    procmon_profile: str = "minimal"
    procmon_ready_timeout_ms: int = 15000
    procmon_stop_timeout_ms: int = 15000
    procmon_export_timeout_ms: int = 120000
    procmon_launch_method: str = "auto"
    scheduled_task_name: str = DEFAULT_TASK_NAME


@dataclass(frozen=True)
class CollectionSummary:
    """Aggregate result of a collection run."""

    processed: int
    successful: int
    failed: int
    skipped: int
    elapsed_seconds: float
    experiment_root: Path


class Collector:
    """Runs the per-sample collection pipeline for a dataset."""

    def __init__(self, config: CollectorConfig) -> None:
        self.config = config
        self.trigger = AttachmentTrigger(
            worker_path=config.trigger_worker_path or Path("trigger_worker.exe"),
            source_url=config.source_url,
            timeout=config.trigger_worker_timeout_ms / 1000,
        )

    def run(self) -> CollectionSummary:
        """Collect experiments for every supported sample in the dataset."""
        start = time.perf_counter()
        samples, skipped = enumerate_samples(self.config.dataset_root)
        if not samples:
            log.warning(
                "No supported samples discovered under: %s", self.config.dataset_root
            )
        else:
            log.info(
                "Discovered %d samples under %s", len(samples), self.config.dataset_root
            )

        successful = 0
        failed = 0
        for sample in samples:
            log.info(
                "Processing sample: %s (%d bytes)", sample.relative_path, sample.size
            )
            if self.collect_sample(sample):
                successful += 1
            else:
                failed += 1
            log.info("Progress: %d succeeded, %d failed", successful, failed)

        elapsed = time.perf_counter() - start
        log.info(
            "Collection finished: %d succeeded, %d failed, %d skipped out of %d",
            successful,
            failed,
            skipped,
            len(samples),
        )
        return CollectionSummary(
            processed=len(samples),
            successful=successful,
            failed=failed,
            skipped=skipped,
            elapsed_seconds=elapsed,
            experiment_root=self.config.experiment_root,
        )

    def collect_sample(self, sample: Sample) -> bool:
        """Collect one experiment for *sample*; never raises."""
        experiment = ExperimentDirectory(self.config.experiment_root)
        procmon_filter = ProcmonFilter(self.config.procmon_profile, sample.path.name)
        result = "failed"
        success = False

        try:
            log.info(
                "Experiment %d started for %s", experiment.id, sample.relative_path
            )
            shutil.copy2(sample.path, experiment.sample_path)

            work_dir = self.working_copy_directory(experiment.id)
            work_dir.mkdir(parents=True, exist_ok=True)
            trigger_path = work_dir / sample.path.name
            shutil.copy2(sample.path, trigger_path)

            try:
                ready, trigger_ok, exported = self._run_pipeline(
                    experiment, procmon_filter, trigger_path
                )
                success = ready and trigger_ok and exported
                result = "success" if success else "failed"
            finally:
                shutil.rmtree(work_dir, ignore_errors=True)
        except Exception as exc:
            log.error("Experiment %d aborted: %s", experiment.id, exc)
            result = "failed"

        self._write_artifacts(experiment, sample, procmon_filter, result)
        log.info("Experiment %d completed: %s", experiment.id, result)
        return success

    def _run_pipeline(
        self,
        experiment: ExperimentDirectory,
        procmon_filter: ProcmonFilter,
        trigger_path: Path,
    ) -> tuple[bool, bool, bool]:
        """Run capture → trigger → wait → export → filter for one experiment.

        Returns ``(ready, trigger_ok, exported)``. Individual failures are
        logged, never raised, so a broken capture still yields a recorded
        experiment.
        """
        procmon: ProcmonController | None = None
        if self.config.procmon_path is not None:
            procmon = ProcmonController(
                self.config.procmon_path,
                launch_method=self.config.procmon_launch_method,
                scheduled_task_name=self.config.scheduled_task_name,
            )

        ready = False
        exported = False
        if procmon is not None:
            started = procmon.start(experiment.pml_path)
            ready = started and procmon.wait_until_ready(
                self._seconds(self.config.procmon_ready_timeout_ms)
            )
            if not ready:
                log.warning("ProcMon did not confirm readiness; triggering anyway")

        log.info("Triggering sample (attachment): %s", trigger_path)
        trigger_result = self.trigger.run(trigger_path)
        trigger_ok = trigger_result.success
        if trigger_ok:
            log.info("Trigger completed: %s", trigger_result.message)
        else:
            log.warning("Trigger failed: %s", trigger_result.message)

        log.info(
            "Waiting for completion (strategy: %s)", self.config.completion_strategy
        )
        self._wait_for_completion()

        if procmon is not None:
            log.info("Stopping ProcMon")
            procmon.stop(self._seconds(self.config.procmon_stop_timeout_ms))
            log.info("Exporting CSV")
            exported = started and procmon.export_csv(
                experiment.pml_path,
                experiment.csv_path,
                self._seconds(self.config.procmon_export_timeout_ms),
            )
            if not exported:
                log.error("ProcMon CSV export failed for experiment %d", experiment.id)

        if exported:
            log.info("Generating filtered.csv")
            procmon_filter.filter_csv(experiment.csv_path, experiment.filtered_csv_path)

        return ready, trigger_ok, exported

    def _wait_for_completion(self) -> None:
        time.sleep(self._seconds(self.config.trigger_timeout_ms))

    def working_copy_directory(self, experiment_id: int) -> Path:
        """Subdirectory under the working directory used as the trigger target."""
        return self.config.working_directory / f"defenderatlas_{experiment_id:06d}"

    def _write_artifacts(
        self,
        experiment: ExperimentDirectory,
        sample: Sample,
        procmon_filter: ProcmonFilter,
        result: str,
    ) -> None:
        status = "completed" if result == "success" else "failed"
        try:
            write_json(
                experiment.metadata_path,
                build_metadata(
                    experiment_id=experiment.id,
                    sample=sample.path.name,
                    relative_path=sample.relative_path,
                    sha256=sample.sha256,
                    size=sample.size,
                    trigger=self.trigger.name,
                    completion_strategy=self.config.completion_strategy,
                    collector_version=COLLECTOR_VERSION,
                    procmon_profile=procmon_filter.profile,
                    category=sample.category,
                    result=result,
                ),
            )
            write_json(
                experiment.manifest_path,
                build_manifest(
                    experiment_id=experiment.id,
                    status=status,
                    sample=sample.path.name,
                ),
            )
            write_json(
                experiment.trigger_info_path,
                build_trigger_info(
                    trigger=self.trigger.name,
                    source_url=self.config.source_url,
                    working_copy=sample.path.name,
                    completion_strategy=self.config.completion_strategy,
                    procmon_profile=procmon_filter.profile,
                    collector_version=COLLECTOR_VERSION,
                ),
            )
        except OSError as exc:
            log.error("Could not write experiment artifacts: %s", exc)

    @staticmethod
    def _seconds(milliseconds: int) -> float:
        return milliseconds / 1000.0
