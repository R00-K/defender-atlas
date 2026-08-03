#pragma once

/// \file collector.h
/// \brief Orchestrates the whole per-sample collection pipeline.
///
/// The Collector is the permanent collection engine of DefenderAtlas. It is
/// deliberately decoupled from every concrete collaborator:
///
///   - DatasetEnumerator     (sample discovery)
///   - ProcmonController     (capture lifecycle)
///   - ITrigger              (how the download event is reproduced)
///   - ICompletionStrategy   (when the scan is considered finished)
///
/// The per-sample flow is:
///
///   1. Allocate an experiment directory
///   2. Apply the configured ProcMon filter profile (dynamic path filter based
///      on the sample file name) and save it as procmon_filter.pmc
///   3. Copy the sample into the experiment directory and the working directory
///   4. Start ProcMon capturing to the experiment's capture.pml
///   5. Wait until ProcMon is ready
///   6. Trigger the download event on the working copy
///   7. Wait for the completion strategy
///   8. Stop ProcMon
///   9. Export capture.csv (raw, never overwritten)
///  10. Generate filtered.csv from the selected profile
///  11. Run the DefenderAtlas Analyzer on filtered.csv to produce report.md
///  12. Write metadata.json, manifest.json and trigger.json
///
/// A failure in any step never aborts the whole run: the Collector logs the
/// problem, records a "failed" experiment and continues with the next sample.

#include "config.h"
#include "dataset.h"
#include "experiment.h"
#include "istrategy.h"
#include "itrigger.h"
#include "metadata.h"

#include <memory>

namespace defenderatlas {

/// The collection engine. Owns its trigger and completion strategy.
class Collector {
public:
    /// \param config Runtime configuration.
    /// \param trigger Concrete trigger (must not be null).
    /// \param completion Concrete completion strategy (must not be null).
    Collector(Config config, std::unique_ptr<ITrigger> trigger,
              std::unique_ptr<ICompletionStrategy> completion);

    Collector(const Collector&) = delete;
    Collector& operator=(const Collector&) = delete;

    /// Enumerate the dataset and collect an experiment per sample.
    /// Returns true when every sample was collected successfully.
    bool Run();

private:
    /// Run the full collection pipeline for one sample.
    /// Never throws; returns true when the experiment succeeded.
    bool CollectSample(const Sample& sample);

    /// Build the metadata payload for an experiment.
    ExperimentMetadata BuildMetadata(const ExperimentDirectory& experiment,
                                     const Sample& sample,
                                     const std::string& result,
                                     const std::string& procmon_profile,
                                     const std::string& analysis) const;

    Config config_;
    std::unique_ptr<ITrigger> trigger_;
    std::unique_ptr<ICompletionStrategy> completion_;
};

} // namespace defenderatlas
