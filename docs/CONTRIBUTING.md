# Development and validation workflow

1. Use focused feature branches and issues linked to the phase roadmap.
2. Keep the Dialog interface independent of benchmark implementation.
3. All modules document dependencies, privilege requirements, resource limits, fixture needs and units.
4. Validate shell code with `bash -n` and ShellCheck when available; Python code with tests.
5. Unit tests and CI do not substitute for measured hardware validation on Bodhi or Basement.
6. Preserve raw benchmark evidence and never create fictional measured numbers.
7. Before merging, confirm offline reporting, missing-hardware behavior, cleanup and error paths.
8. Request explicit confirmation before any destructive or high-impact host operation.
