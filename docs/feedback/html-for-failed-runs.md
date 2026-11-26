# Generate an HTML report for every run

Generate the main offline HTML even when a run fails. Include safely reportable data gathered before the failure, the run outcome, completed and skipped workloads, and available failure details. If no benchmark measurements were gathered, still show the run status. Preserve private evidence and do not fall back to another run.

## Review check

Verify that a failed Extended run with completed short workloads produces HTML showing those results and the sustained CPU stop.

