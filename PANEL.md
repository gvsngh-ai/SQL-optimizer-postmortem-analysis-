# The Panel — Methodological Provenance

This document maps each diagnostic module to the publicly known specialty of
the practitioner whose methodology most directly inspired it. This is not a
simulation of these people, and no module fabricates quotes or claims their
endorsement — it is an honest map of "whose well-documented public technique
does this check operationalize," so the reasoning stays traceable to real,
verifiable methodology rather than invented authority.

| Specialist          | Publicly known focus                                          | Module(s) it informs |
|----------------------|----------------------------------------------------------------|------------------------|
| Jonathan Lewis       | CBO internals, cost formulas, "Cost-Based Oracle Fundamentals" | CardinalityExpert, JoinStrategyExpert — cost/cardinality mechanics |
| Maria Colgan         | Optimizer product management, official CBO feature explainers  | AdaptiveFeaturesExpert, SqlPlanDirectivesExpert |
| Nigel Bayliss        | Optimizer product management, stats/plan stability guidance    | StatisticsHealthExpert, PlanStabilityExpert |
| Christian Antognini  | "Troubleshooting Oracle Performance," execution plan reading   | AccessPathExpert, PredicateTransformationExpert |
| Randolf Geist        | Parallel execution, adaptive plans deep-dives                  | ParallelismExpert, AdaptiveFeaturesExpert |
| Wolfgang Breitling   | Method R lineage, response-time/wait analysis                  | ResourceProfileExpert |
| Tanel Poder           | Diagnostic scripting (ASH/AWR mining), systemic troubleshooting| ResourceProfileExpert, wait-event-per-plan-step collection |
| Kerry Osborne         | SQL profiles, plan baselines, hint-based tuning in practice     | PlanStabilityExpert, HintAdvisorExpert |
| Carlos Sierra         | SQLT / SQLHC diagnostic methodology (Oracle Support)            | Overall bundle shape — "collect everything relevant before diagnosing" |
| Mauro Pagano          | SQLd360, SQL Health Check tooling                                | Overall report shape / HTML output design intent |
| Franck Pachot         | Cross-engine performance comparison, execution plan tooling      | PredicateTransformationExpert, plan step interpretation |
| Richard Foote         | Indexing internals (B-tree, clustering factor, index health)     | AccessPathExpert clustering-factor checks |
| Tim Gorman            | Partitioning strategy and internals                              | PartitioningExpert |
| Tom Kyte              | "Ask Tom," foundational CBO/data-access reasoning                | AccessPathExpert, general diagnostic philosophy |
| Roger MacNicol        | Smart Scan / Exadata storage-layer optimization                  | AccessPathExpert (offload/storage-index awareness, ADB context) |

## What this panel model does NOT do
- It does not generate fictional dialogue or quotes attributed to these people.
- It does not claim any of them reviewed or endorsed this tool.
- It uses their public technical territory as an organizing structure for
  the diagnostic modules, the same way a textbook bibliography credits
  where a methodology comes from.
