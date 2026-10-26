# CodeQL

Best for: deep inter-procedural taint tracking, framework-aware modeling, and variant analysis ("find every place this bug pattern occurs"). Heavier setup: it builds a queryable database from the code.

## Run

```bash
# 1. Build a database (compiled languages need the build command)
codeql database create db --language=python --source-root .
codeql database create db --language=java-kotlin --command="mvn -q -DskipTests package"
codeql database create db --language=javascript-typescript --source-root .

# 2. Analyze with the standard security suite
codeql database analyze db codeql/python-queries:codeql-suites/python-security-extended.qls \
  --format=sarif-latest --output=codeql.sarif

# Suites: <lang>-code-scanning.qls (low noise), <lang>-security-extended.qls (more recall),
#         <lang>-security-and-quality.qls (adds quality)
```

GitHub users: `github/codeql-action` handles database + upload; pin the action to a commit SHA.

## Custom taint query (modern shared-flow API)

```ql
/**
 * @name Request data flows to custom exec wrapper
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.8
 * @precision high
 * @id py/custom-run-cmd-injection
 * @tags security external/cwe/cwe-078
 */
import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.dataflow.new.RemoteFlowSources

module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof RemoteFlowSource }

  predicate isSink(DataFlow::Node n) {
    exists(API::CallNode c |
      c = API::moduleImport("internal_utils").getMember("run_cmd").getACall() and
      n = c.getArg(0)
    )
  }

  predicate isBarrier(DataFlow::Node n) {
    n = API::moduleImport("shlex").getMember("quote").getACall()
  }
}

module Flow = TaintTracking::Global<Config>;
import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flow(source, sink)
select sink.getNode(), source, sink, "Command built from $@.", source.getNode(), "user input"
```

Key predicates: `isSource`, `isSink`, `isBarrier` (sanitizer), `isAdditionalFlowStep` (teach custom propagation, e.g. through a queue or DTO).

## Workflow for variant analysis
1. Start from one confirmed bug. Write the sink as a CodeQL predicate.
2. Run across all repos/databases; inspect the path explanations.
3. Add barriers for validated cases; keep the query in `queries/` with a `.qlref` test.

## Testing queries
`codeql test run queries/tests/` with `.expected` files. Cover vulnerable, sanitized, and unrelated-code cases.

## Limits and tips
- Compiled-language databases fail silently if the build didn't compile everything; check extraction stats.
- Generated code, reflection and runtime config can break flow; add manual models or models-as-data (YAML extensible predicates) rather than rewriting QL.
- Slower than Semgrep; run on main/nightly and a diff-scoped subset on PRs.
