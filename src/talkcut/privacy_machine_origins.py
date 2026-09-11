"""Closed historical machine-field derivations, without execution approval.

Only registered original source/producer/output relationships are inputs. This
module parses retained code; it never executes it or an argv stored in evidence.
"""
from __future__ import annotations

import ast
import copy
import hashlib
import json
import re
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from . import privacy_machine_grammar as grammar
from .project import TalkCutError

Read = Callable[[Any], tuple[Path, bytes]]
Document = Callable[[Any], dict[str, Any]]


def require(value: Any, message: str) -> None:
    if not value:
        raise TalkCutError("PUBLICATION_PRIVACY_UNVERIFIED", message)


def same(left: Any, right: Any) -> bool:
    return json.dumps(left, sort_keys=True) == json.dumps(right, sort_keys=True)


def syntax(data: bytes) -> ast.Module:
    """Bind a UTF-8 observation to Python's actual source-byte decoding."""
    try:
        observed = ast.parse(data.decode("utf-8-sig"))
        loaded = ast.parse(data)
    except (SyntaxError, UnicodeError, LookupError) as exc:
        raise TalkCutError("PUBLICATION_PRIVACY_UNVERIFIED", "Machine origin producer is not supported Python source bytes") from exc
    require(ast.dump(observed) == ast.dump(loaded),
            "Machine origin producer coding declaration changes the observed Python syntax")
    return loaded


def syntax_text(text: str) -> ast.Module:
    """An exec string has already been decoded; coding comments are inert."""
    try:
        return ast.parse(text)
    except (SyntaxError, UnicodeError) as exc:
        raise TalkCutError("PUBLICATION_PRIVACY_UNVERIFIED", "Machine origin producer text is not Python") from exc


def helper_prefix(data: bytes, delimiter: str) -> ast.Module:
    # Original no-argument read_text records do not declare a locale. Their
    # complete ASCII bytes avoid inventing a historical non-ASCII decoder.
    require(data.isascii(), "Machine original read_text helper requires complete ASCII source bytes")
    text = data.decode("ascii").replace("\r\n", "\n").replace("\r", "\n")
    require(text.count(delimiter) == 1, "Machine origin helper prefix is ambiguous")
    return syntax_text(text.split(delimiter)[0])


def named_function(tree: ast.Module | ast.FunctionDef, name: str) -> ast.FunctionDef:
    found = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == name]
    require(len(found) == 1, "Machine origin has no unique original producer function")
    return found[0]


def dict_fields(node: ast.AST) -> dict[str, ast.expr]:
    require(isinstance(node, ast.Dict), "Machine origin writer is not a dictionary")
    assert isinstance(node, ast.Dict)
    keys = [key.value for key in node.keys if isinstance(key, ast.Constant) and isinstance(key.value, str)]
    require(len(keys) == len(set(keys)) and len(keys) == len([key for key in node.keys if key is not None]),
            "Machine origin writer has nonliteral or duplicate field names")
    return {key.value: value for key, value in zip(node.keys, node.values, strict=True)
            if isinstance(key, ast.Constant) and isinstance(key.value, str)}


def assignment(tree: ast.Module | ast.FunctionDef, name: str) -> ast.expr:
    found = [node.value for node in tree.body if isinstance(node, ast.Assign)
             and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) and node.targets[0].id == name]
    require(len(found) == 1, "Machine origin variable has no unique original assignment")
    return found[0]


def expression(text: str) -> ast.expr:
    return ast.parse(text, mode="eval").body


def matches(node: ast.AST, text: str) -> bool:
    def structure(value: Any) -> Any:
        if isinstance(value, ast.AST):
            return type(value).__name__, tuple((name, structure(child)) for name, child in ast.iter_fields(value)
                                               if not (name == "ctx" and isinstance(child, ast.expr_context)))
        if isinstance(value, list):
            return tuple(structure(child) for child in value)
        return value
    return structure(node) == structure(expression(text))


def path_value(node: ast.AST, values: dict[str, Path], root: Path, script: Path) -> Path:
    if isinstance(node, ast.Name) and node.id in values:
        return values[node.id]
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return Path(node.value)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "Path" and len(node.args) == 1 and not node.keywords:
        if isinstance(node.args[0], ast.Name) and node.args[0].id == "__file__":
            return script
        return path_value(node.args[0], values, root, script)
    if isinstance(node, ast.Call) and not node.args and not node.keywords:
        if matches(node, "Path.cwd()"):
            return root
        if isinstance(node.func, ast.Attribute) and node.func.attr == "resolve":
            return path_value(node.func.value, values, root, script).resolve()
    if isinstance(node, ast.Attribute) and node.attr == "parent":
        return path_value(node.value, values, root, script).parent
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
        left = path_value(node.left, values, root, script)
        require(isinstance(node.right, ast.Constant) and isinstance(node.right.value, str),
                "Machine origin path has a nonliteral suffix")
        assert isinstance(node.right, ast.Constant) and isinstance(node.right.value, str)
        return left / node.right.value
    raise TalkCutError("PUBLICATION_PRIVACY_UNVERIFIED", "Machine origin path expression is unsupported")


def path_assignments(tree: ast.Module, root: Path, script: Path) -> dict[str, Path]:
    values: dict[str, Path] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            try:
                value = path_value(node.value, values, root, script)
            except TalkCutError:
                continue
            require(node.targets[0].id not in values, "Machine origin path variable is reassigned")
            values[node.targets[0].id] = value
    return values


def references(value: Any) -> list[dict[str, Any]]:
    result = []
    if isinstance(value, dict):
        if set(value) == {"path", "sha256"}:
            result.append(value)
        for child in value.values():
            result.extend(references(child))
    elif isinstance(value, list):
        for child in value:
            result.extend(references(child))
    return result


def loader(tree: ast.Module, root: Path, script: Path, source: dict[str, Any], *, hash_guard: bool = True) -> str:
    values = path_assignments(tree, root, script)
    specs = []
    for node in tree.body:
        if not (isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
                and isinstance(node.value, ast.Call) and matches(node.value.func, "importlib.util.spec_from_file_location")):
            continue
        call = node.value
        if len(call.args) == 2 and not call.keywords:
            observed = path_value(call.args[1], values, root, script)
            if str(observed) == source["path"]:
                specs.append((node.targets[0].id, call.args[1]))
    require(len(specs) == 1, "Machine origin loader does not select one exact original source")
    spec_name, source_expr = specs[0]
    modules = [node.targets[0].id for node in tree.body if isinstance(node, ast.Assign) and len(node.targets) == 1
               and isinstance(node.targets[0], ast.Name) and matches(node.value, f"importlib.util.module_from_spec({spec_name})")]
    require(len(modules) == 1, "Machine origin loader has no unique module binding")
    module = modules[0]
    require(any(isinstance(node, ast.Expr) and matches(node.value, f"{spec_name}.loader.exec_module({module})") for node in tree.body),
            "Machine origin source loader is not called at the recorded top-level boundary")
    # The independent probe performs this exact original digest assertion before loading.
    expected = expression("hashlib.sha256(SOURCE.read_bytes()).hexdigest() == " + repr(source["sha256"]))
    if hash_guard:
        require(isinstance(source_expr, ast.Name) and source_expr.id == "SOURCE"
                and any(isinstance(node, ast.Assert) and ast.dump(node.test) == ast.dump(expected) for node in tree.body),
                "Machine origin probe lacks its original source digest assertion")
    else:
        require(isinstance(source_expr, ast.Name), "Machine origin source observation has an unsupported expression")
        assert isinstance(source_expr, ast.Name)
        require(matches(assignment(tree, "before"), f"artifact_ref({source_expr.id})")
                and any(isinstance(node, ast.Assert) and matches(node.test, f"before == artifact_ref({source_expr.id})") for node in tree.body),
                "Machine origin source observation lacks its original before/after writer")
    return module


def invocation_shape(node: ast.AST, role: str) -> str:
    """Canonical complete syntax shape, never a caller-supplied source hash.

    Only separately checked reference paths and original return-field data are
    abstracted. Every other statement, call, branch and helper body remains.
    The closed shapes have readable original-source witnesses in validation.
    """
    shaped = copy.deepcopy(node)
    if role == "known":
        require(isinstance(shaped, ast.FunctionDef) and isinstance(shaped.body[-1], ast.Return),
                "Machine known producer has no final direct return")
        assert isinstance(shaped, ast.FunctionDef) and isinstance(shaped.body[-1], ast.Return)
        value = shaped.body[-1].value
        require(isinstance(value, ast.Tuple) and len(value.elts) == 3 and isinstance(value.elts[2], ast.Dict),
                "Machine known producer has no original three-value return")
        assert isinstance(value, ast.Tuple)
        fields = value.elts[2]
        assert isinstance(fields, ast.Dict)
        kept = []
        for key, item in zip(fields.keys, fields.values, strict=True):
            if isinstance(key, ast.Constant) and key.value in {"scope", "reason"}:
                require(isinstance(item, ast.Constant) and isinstance(item.value, str),
                        "Machine returned metadata has a computed replacement expression")
            elif isinstance(key, ast.Constant) and key.value == "unresolved_source_candidates":
                require(matches(item, "list(unresolved_sources.values())"),
                        "Machine returned unresolved rows do not use the original collection")
            elif isinstance(key, ast.Constant) and key.value == "auxiliary_execution_sources":
                require(matches(item, "auxiliary_source_current"),
                        "Machine returned auxiliary rows do not use the original collection")
            else:
                kept.append((key, item))
        fields.keys = [key for key, _ in kept]
        fields.values = [item for _, item in kept]
    elif role in {"helper", "probe"}:
        require(isinstance(shaped, ast.Module), "Machine helper shape is not a module")
        assert isinstance(shaped, ast.Module)
        names = {"ROOT", "SOURCE"} if role == "helper" else {"ref", "runref"}
        for statement in shaped.body:
            if isinstance(statement, ast.Assign) and len(statement.targets) == 1 and isinstance(statement.targets[0], ast.Name):
                name = statement.targets[0].id
                if name in names:
                    statement.value = ast.Name(id="VERIFIED_REFERENCE_" + name, ctx=ast.Load())
            if isinstance(statement, ast.Assert) and isinstance(statement.test, ast.Compare):
                test = statement.test
                if len(test.ops) == len(test.comparators) == 1 and isinstance(test.ops[0], ast.Eq):
                    wanted = "hashlib.sha256(SOURCE.read_bytes()).hexdigest()" if role == "helper" else "ref['sha256']"
                    if matches(test.left, wanted):
                        test.comparators[0] = ast.Name(id="VERIFIED_REFERENCE_DIGEST", ctx=ast.Load())
    return ast.dump(shaped, include_attributes=False)


def require_invocation_shape(node: ast.AST, role: str) -> None:
    digest = hashlib.sha256(invocation_shape(node, role).encode()).hexdigest()
    require(digest in grammar.INVOCATION_SHAPES[role],
            "Machine producer differs from the complete supported original invocation-scope grammar")


def reference_root(node: ast.AST) -> str | None:
    while isinstance(node, (ast.Attribute, ast.Subscript)):
        node = node.value
    return node.id if isinstance(node, ast.Name) else None


def preserve_binding(tree: ast.Module, name: str, *, assignment_count: int, mutable_methods: set[str] | None = None) -> None:
    nodes = lexical(tree)
    stores = [node for node in nodes if isinstance(node, ast.Name) and node.id == name and isinstance(node.ctx, (ast.Store, ast.Del))]
    require(len(stores) == assignment_count and all(isinstance(node.ctx, ast.Store) for node in stores),
            "Machine producer rebinds or removes an original invocation/output value")
    for node in nodes:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            require(all((alias.asname or (alias.name.split('.')[0] if isinstance(node, ast.Import) else alias.name)) != name for alias in node.names),
                    "Machine producer replaces its original module with another import")
        if isinstance(node, (ast.Attribute, ast.Subscript)) and isinstance(node.ctx, (ast.Store, ast.Del)):
            require(reference_root(node) != name, "Machine producer overwrites the original callable or returned object")
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and reference_root(node.func) == name:
            require(mutable_methods is not None and node.func.attr in mutable_methods,
                    "Machine producer mutates its original returned object before preservation")


def direct_script_control_flow(tree: ast.Module, *, original_exec: ast.Call | None = None) -> None:
    nodes = lexical(tree)
    require(not any(isinstance(node, (ast.Raise, ast.Return, ast.Yield, ast.YieldFrom, ast.Await)) for node in nodes),
            "Machine probe has an early exit before its original output boundary")
    for node in nodes:
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id == "exec":
                require(node is original_exec, "Machine probe has a second dynamic binding operation")
            require(node.func.id not in {"eval", "globals", "locals", "exit", "quit"},
                    "Machine probe has an unsupported dynamic binding or exit")


def independent_case_path(script: ast.Module, prefix: ast.Module, root: Path, script_path: Path) -> Path:
    setups = [node for node in script.body if isinstance(node, ast.Assign) and len(node.targets) == 1
              and isinstance(node.targets[0], ast.Tuple) and isinstance(node.value, ast.Call) and matches(node.value.func, "setup")]
    require(len(setups) == 1 and isinstance(setups[0].targets[0], ast.Tuple)
            and isinstance(setups[0].targets[0].elts[0], ast.Name) and setups[0].targets[0].elts[0].id == "case",
            "Machine probe has no exact original setup-to-case binding")
    call = setups[0].value
    assert isinstance(call, ast.Call)
    require(len(call.args) == 1 and not call.keywords and isinstance(call.args[0], ast.Constant)
            and isinstance(call.args[0].value, str) and Path(call.args[0].value).name == call.args[0].value,
            "Machine probe setup selects an unsupported case path")
    setup = named_function(prefix, "setup")
    require(setup.args.args and setup.args.args[0].arg == "name" and len(setup.args.defaults) == len(setup.args.args) - 1
            and not setup.args.vararg and not setup.args.kwarg and not setup.args.kwonlyargs and not setup.args.posonlyargs,
            "Machine original setup has an ambiguous case parameter")
    name = setup.args.args[0].arg
    returns = [node.value for node in setup.body if isinstance(node, ast.Return) and isinstance(node.value, ast.Tuple)]
    require(len(returns) == 1 and matches(returns[0].elts[0], "case"), "Machine setup does not return the original case path")
    case = assignment(setup, "case")
    require(matches(case, f"HERE / {name}"), "Machine setup case is outside its original direct helper directory")
    values = path_assignments(prefix, root, script_path)
    assert isinstance(call.args[0], ast.Constant) and isinstance(call.args[0].value, str)
    require("HERE" in values, "Machine setup has no original helper directory binding")
    return values["HERE"] / call.args[0].value


def scan_script_flow(script: ast.Module, *, staged: bool, call: ast.Call, output: dict[str, Any]) -> None:
    """Require the complete original direct wrapper, without executing Python."""
    replacements: dict[str, ast.AST] = {"ROOT_PATH": assignment(script, "root")}
    if staged:
        replacements.update({name: assignment(script, original) for name, original in
                             (("DIRECTORY_PATH", "directory"), ("SOURCE_PATH", "module_path"),
                              ("INPUT_PATH", "input_path"), ("PROJECT_PATH", "project"))})
        extra = output.get("staged_execution")
        require(isinstance(extra, dict) and set(extra) == {"module", "module_unchanged", "public_code_modified", "scope"}
                and extra["public_code_modified"] is False and isinstance(extra["scope"], str),
                "Machine staged wrapper output has an unrelated observation field")
        assert isinstance(extra, dict)
        replacements["SCOPE_VALUE"] = ast.Constant(extra["scope"])
        template = """
import importlib.util
import json
import sys
from pathlib import Path
from talkcut.project import artifact_ref
root = ROOT_PATH
directory = DIRECTORY_PATH
module_path = SOURCE_PATH
before = artifact_ref(module_path)
spec = importlib.util.spec_from_file_location('talkcut.privacy_checks_staged', module_path)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
input_path = INPUT_PATH
project = PROJECT_PATH
sources = {r: s['sha256'] for r, s in json.loads((project / 'project.json').read_text())['sources'].items()}
result = module.verify_release_privacy(artifact_ref(input_path), root, project_dir=project, expected_source_hashes=sources)
assert before == artifact_ref(module_path)
result['staged_execution'] = {'module': before, 'module_unchanged': True, 'public_code_modified': False, 'scope': SCOPE_VALUE}
print(json.dumps(result, indent=2))
"""
    else:
        replacements["PROJECT_PATH"] = assignment(script, "p")
        require(isinstance(call.args[0], ast.Call) and len(call.args[0].args) == 1,
                "Machine direct scan wrapper lacks its original input path")
        assert isinstance(call.args[0], ast.Call)
        replacements["INPUT_PATH"] = call.args[0].args[0]
        template = """
import json
from pathlib import Path
from talkcut.project import artifact_ref
from talkcut.privacy_checks import verify_release_privacy
root = ROOT_PATH
p = PROJECT_PATH
sources = {k: v['sha256'] for k, v in json.loads((p / 'project.json').read_text())['sources'].items()}
print(json.dumps(verify_release_privacy(artifact_ref(INPUT_PATH), root, project_dir=p, expected_source_hashes=sources), sort_keys=True))
"""
    class Substitute(ast.NodeTransformer):
        def visit_Name(self, node: ast.Name) -> ast.AST:
            return copy.deepcopy(replacements[node.id]) if node.id in replacements else node
    expected = Substitute().visit(ast.parse(template))
    require(ast.dump(script) == ast.dump(expected),
            "Machine scan wrapper changes the complete original statement order, binding or invocation path")


def verify_independent_inventory(selected: dict[str, Any], root: Path, read: Read, document: Document) -> dict[str, Any]:
    fields = {"schema_version", "family", "review", "result", "source", "script", "helper"}
    require(set(selected) == fields and selected["schema_version"] == "review-machine-field-authority/v1"
            and selected["family"] == "independent_privacy_inventory", "Machine origin authority family or fields are unsupported")
    review, result = document(selected["review"]), document(selected["result"])
    require(review.get("schema_version") == "independent-staged-privacy-review/v1"
            and review.get("source_before") == review.get("source_after") == selected["source"],
            "Machine origin review does not bind the unchanged original source")
    owned = references([review.get("independent_executions"), review.get("independent_results"), review.get("independent_scripts")])
    require(all(ref in owned for ref in (selected["result"], selected["script"], selected["helper"])),
            "Machine origin script, helper or result is outside the original independent records")
    require(result.get("schema_version") == "independent-execution-tool-alias-inventory/v1"
            and result.get("source") == selected["source"] and result.get("script") == selected["script"],
            "Machine origin result has a different original source or producer")
    script_path, script_bytes = read(selected["script"])
    helper_path, helper_bytes = read(selected["helper"])
    _, source_bytes = read(selected["source"])
    require_invocation_shape(syntax(source_bytes), "module")
    script = syntax(script_bytes)
    calls = [node.value for node in script.body if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)
             and isinstance(node.value.func, ast.Name) and node.value.func.id == "exec"]
    require(len(calls) == 1 and len(calls[0].args) == 1 and not calls[0].keywords,
            "Machine origin probe has no unique original helper bootstrap")
    boot = calls[0].args[0]
    require(isinstance(boot, ast.Subscript) and isinstance(boot.slice, ast.Constant) and type(boot.slice.value) is int and boot.slice.value == 0
            and isinstance(boot.value, ast.Call) and isinstance(boot.value.func, ast.Attribute) and boot.value.func.attr == "split"
            and len(boot.value.args) == 1 and isinstance(boot.value.args[0], ast.Constant) and isinstance(boot.value.args[0].value, str),
            "Machine origin helper bootstrap has an unsupported bounded-prefix shape")
    assert isinstance(boot, ast.Subscript) and isinstance(boot.value, ast.Call) and isinstance(boot.value.func, ast.Attribute)
    split = boot.value
    assert isinstance(split.func, ast.Attribute)
    read_call = split.func.value
    require(isinstance(read_call, ast.Call) and isinstance(read_call.func, ast.Attribute)
            and read_call.func.attr == "read_text" and not read_call.args and not read_call.keywords,
            "Machine origin helper bootstrap does not read its exact script")
    assert isinstance(read_call, ast.Call) and isinstance(read_call.func, ast.Attribute)
    require(path_value(read_call.func.value, path_assignments(script, root, script_path), root, script_path) == helper_path,
            "Machine origin helper bootstrap names another source")
    assert isinstance(split.args[0], ast.Constant) and isinstance(split.args[0].value, str)
    delimiter = split.args[0].value
    prefix = helper_prefix(helper_bytes, delimiter)
    module = loader(prefix, root, script_path, selected["source"])
    require_invocation_shape(prefix, "helper")
    require_invocation_shape(script, "probe")
    direct_script_control_flow(prefix)
    direct_script_control_flow(script, original_exec=calls[0])
    preserve_binding(prefix, module, assignment_count=1,
                     mutable_methods={"_known_private_inventory", "_auxiliary_json", "build_private_inventory", "_verified_synthetic_replay"})
    preserve_binding(script, module, assignment_count=0,
                     mutable_methods={"_known_private_inventory", "_auxiliary_json", "build_private_inventory", "_verified_synthetic_replay"})
    report = dict_fields(assignment(script, "report"))
    paths = path_assignments(script, root, script_path)
    paths["case"] = independent_case_path(script, prefix, root, script_path)
    paths.update({key: value for key, value in path_assignments(prefix, root, script_path).items() if key not in paths})
    require(paths.get("ROOT") == root, "Machine helper uses a different original repository root")
    bundle = result.get("bundle")
    row_identity(bundle)
    require(isinstance(bundle, dict) and set(bundle) == {"path", "sha256"},
            "Machine original result has no exact replay bundle reference")
    assert isinstance(bundle, dict)
    replay_ref = assignment(script, "ref")
    require(isinstance(replay_ref, ast.Call) and matches(replay_ref.func, "artifact_ref") and len(replay_ref.args) == 1
            and not replay_ref.keywords and path_value(replay_ref.args[0], paths, root, script_path) == Path(bundle["path"])
            and any(isinstance(node, ast.Assert) and matches(node.test, "ref['sha256'] == " + repr(bundle["sha256"])) for node in script.body),
            "Machine helper replay invocation differs from its recorded original bundle")
    read(bundle)
    require(any(isinstance(node, ast.Expr) and isinstance(node.value, ast.Call) and matches(node.value.func, "atomic_json")
                and len(node.value.args) == 2 and matches(node.value.args[1], "report")
                and path_value(node.value.args[0], paths, root, script_path) == Path(selected["result"]["path"])
                for node in script.body), "Machine origin result is not the original emitted report")
    parents = {}
    for key in ("first_inventory", "second_inventory"):
        written = report.get(key)
        require(isinstance(written, ast.Call) and matches(written.func, "artifact_ref")
                and len(written.args) == 1, "Machine origin report omits the exact inventory reference writer")
        assert isinstance(written, ast.Call)
        target_expr = written.args[0]
        writes = [node.value for node in script.body if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)
                  and matches(node.value.func, "atomic_json") and len(node.value.args) == 2
                  and ast.dump(node.value.args[0]) == ast.dump(target_expr)]
        require(len(writes) == 1 and isinstance(writes[0].args[1], ast.Name), "Machine origin inventory has no unique unchanged writer")
        assert isinstance(writes[0].args[1], ast.Name)
        value = assignment(script, writes[0].args[1].id)
        preserve_binding(script, writes[0].args[1].id, assignment_count=1)
        require(isinstance(value, ast.Call) and matches(value.func, f"{module}.build_private_inventory"),
                "Machine origin recorded inventory does not flow from its loaded producer")
        parent_ref = result.get(key)
        parent = document(parent_ref)
        assert isinstance(parent_ref, dict)
        require(path_value(target_expr, paths, root, script_path) == Path(parent_ref["path"]),
                "Machine recorded inventory parent is not the original resolved output path")
        known_graph = parent.get("known_graph")
        require(isinstance(known_graph, dict), "Machine inventory has no typed original known graph")
        assert isinstance(known_graph, dict)
        observations = known_graph.get("synthetic_failure_fixtures")
        require(isinstance(observations, list) and len(observations) == 1 and isinstance(observations[0], dict),
                "Machine inventory differs from its original single declared failure run")
        assert isinstance(observations, list)
        run = observations[0].get("run")
        row_identity(run)
        require(isinstance(run, dict) and set(run) == {"path", "sha256"}
                and isinstance(observations[0].get("current_reproduction"), dict)
                and observations[0]["current_reproduction"].get("bundle") == bundle,
                "Machine inventory failure observation uses a different original replay bundle")
        assert isinstance(run, dict)
        run_call = assignment(script, "runref")
        require(isinstance(run_call, ast.Call) and matches(run_call.func, "artifact_ref") and len(run_call.args) == 1
                and not run_call.keywords and path_value(run_call.args[0], paths, root, script_path) == Path(run["path"]),
                "Machine inventory invocation selects a different original failure run")
        read(run)
        source = syntax(source_bytes)
        builder = named_function(source, "build_private_inventory")
        require_invocation_shape(builder, "builder")
        outputs = [node.value for node in ast.walk(builder) if isinstance(node, ast.Return) and isinstance(node.value, ast.Dict)
                   and any(isinstance(k, ast.Constant) and k.value == "schema_version" and isinstance(v, ast.Constant)
                           and v.value == "private-task-inventory/v1" for k, v in zip(node.value.keys, node.value.values, strict=True))]
        require(len(outputs) == 1 and set(parent) == set(dict_fields(outputs[0]))
                and parent.get("schema_version") == "private-task-inventory/v1",
                "Machine origin parent differs from the complete original inventory schema")
        bindings = [node for node in builder.body if isinstance(node, ast.Assign) and len(node.targets) == 1
                    and isinstance(node.targets[0], ast.Tuple) and len(node.targets[0].elts) == 3
                    and isinstance(node.value, ast.Call) and matches(node.value.func, "_known_private_inventory")]
        require(len(bindings) == 1 and isinstance(bindings[0].targets[0], ast.Tuple)
                and isinstance(bindings[0].targets[0].elts[2], ast.Name),
                "Machine inventory builder does not call the original known-graph producer")
        assert isinstance(bindings[0].targets[0], ast.Tuple) and isinstance(bindings[0].targets[0].elts[2], ast.Name)
        require(matches(dict_fields(outputs[0])["known_graph"], bindings[0].targets[0].elts[2].id),
                "Machine inventory builder does not emit its exact original known-graph return")
        require(parent_ref["path"] not in parents, "Machine origin inventory parent is duplicated")
        parents[parent_ref["path"]] = {"ref": parent_ref, "prefix": ["known_graph"], "value": parent}
    return {"source": selected["source"], "source_data": source_bytes, "source_tree": syntax(source_bytes), "parents": parents,
            "refs": [selected[name] for name in ("review", "result", "source", "script", "helper")]
                    + [row["ref"] for row in parents.values()] + [bundle, run]}


def verify_privacy_scan(selected: dict[str, Any], root: Path, read: Read, document: Document) -> dict[str, Any]:
    fields = {"schema_version", "family", "record", "source", "script", "input", "command", "output"}
    require(set(selected) == fields and selected["schema_version"] == "review-machine-field-authority/v1"
            and selected["family"] in {"staged_privacy_scan", "revision_privacy_scan"},
            "Machine scan authority family or fields are unsupported")
    record, output, command = document(selected["record"]), document(selected["output"]), document(selected["command"])
    staged = selected["family"] == "staged_privacy_scan"
    actual = record.get("actual_scan")
    require(isinstance(actual, dict), "Machine scan record has no original output observation")
    assert isinstance(actual, dict)
    if staged:
        require(record.get("schema_version") == "private-staged-privacy-handoff/v1"
                and record.get("staged_source") == selected["source"]
                and all(actual.get(key) == selected[name] for key, name in
                        (("driver", "script"), ("input", "input"), ("receipt", "command"), ("stdout", "output"))),
                "Machine staged scan differs from its exact original source/driver/input/output chain")
    else:
        require(record.get("schema_version") == "privacy-revision-handoff/v1"
                and record.get("implementation_snapshot") == selected["source"]
                and actual.get("command") == selected["command"] and actual.get("result") == selected["output"],
                "Machine revision scan differs from its original source and output record")
    command_fields = {"argv", "cwd", "error", "exit_code", "finished_at", "interrupted", "name", "schema_version",
                      "started_at", "status", "stderr", "stdout", "timed_out", "timeout_seconds", "wall_seconds"}
    require(set(command) == command_fields and command.get("schema_version") == "verification-command/v1"
            and command.get("cwd") == str(root) and command.get("stdout") == selected["output"]
            and isinstance(command.get("argv"), list) and len(command["argv"]) == 2
            and isinstance(command["argv"][0], str) and Path(command["argv"][0]).is_absolute()
            and command["argv"][1] == selected["script"]["path"] and command["error"] is None
            and command["interrupted"] is False and command["timed_out"] is False
            and type(command["exit_code"]) is int and command["exit_code"] == 0,
            "Machine scan command does not bind the exact completed original output and script path")
    read(command["stderr"])
    raw = document(selected["input"])
    require(isinstance(output.get("evidence_refs"), list) and selected["input"] in output["evidence_refs"],
            "Machine scan output does not bind the exact original input bytes")
    script_path, script_bytes = read(selected["script"])
    _, source_bytes = read(selected["source"])
    script, source = syntax(script_bytes), syntax(source_bytes)
    require_invocation_shape(source, "module")
    paths = path_assignments(script, root, script_path)
    if staged:
        module = loader(script, root, script_path, selected["source"], hash_guard=False)
        call = assignment(script, "result")
        require(isinstance(call, ast.Call) and matches(call.func, f"{module}.verify_release_privacy"),
                "Machine staged scan does not call its exact loaded producer")
        require(any(isinstance(node, ast.Expr) and isinstance(node.value, ast.Call) and matches(node.value.func, "print")
                    and len(node.value.args) == 1 and isinstance(node.value.args[0], ast.Call)
                    and matches(node.value.args[0].func, "json.dumps") and len(node.value.args[0].args) == 1
                    and matches(node.value.args[0].args[0], "result") for node in script.body),
                "Machine staged scan does not emit its original result object")
        extra = output.get("staged_execution")
        require(isinstance(extra, dict) and extra.get("module") == selected["source"] and extra.get("module_unchanged") is True,
                "Machine staged output source observation differs from the original module")
    else:
        require(any(isinstance(node, ast.ImportFrom) and node.module == "talkcut.privacy_checks"
                    and any(alias.name == "verify_release_privacy" and alias.asname is None for alias in node.names)
                    for node in script.body), "Machine revision wrapper does not use its recorded public producer API")
        prints = [node.value for node in script.body if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)
                  and matches(node.value.func, "print") and len(node.value.args) == 1]
        require(len(prints) == 1 and isinstance(prints[0].args[0], ast.Call), "Machine revision wrapper has no unique result emitter")
        encoded = prints[0].args[0]
        assert isinstance(encoded, ast.Call)
        require(matches(encoded.func, "json.dumps") and len(encoded.args) == 1 and isinstance(encoded.args[0], ast.Call)
                and matches(encoded.args[0].func, "verify_release_privacy"),
                "Machine revision wrapper does not emit the original producer return value")
        call = encoded.args[0]
    assert isinstance(call, ast.Call)
    require(len(call.args) == 2 and isinstance(call.args[0], ast.Call) and matches(call.args[0].func, "artifact_ref")
            and len(call.args[0].args) == 1
            and path_value(call.args[0].args[0], paths, root, script_path) == Path(selected["input"]["path"])
            and path_value(call.args[1], paths, root, script_path) == root,
            "Machine scan producer invocation selects different input or repository bytes")
    # Every substituted path expression has already passed the closed path
    # interpreter. No other top-level statement or expression is substituted.
    for name in (("root", "directory", "module_path", "input_path", "project") if staged else ("root", "p")):
        path_value(assignment(script, name), paths, root, script_path)
    scan_script_flow(script, staged=staged, call=call, output=output)
    producer = named_function(source, "verify_release_privacy")
    require_invocation_shape(producer, "scan")
    assignments = [node for node in producer.body if isinstance(node, ast.Assign) and len(node.targets) == 1
                   and isinstance(node.targets[0], ast.Tuple) and len(node.targets[0].elts) == 3
                   and isinstance(node.value, ast.Call) and matches(node.value.func, "_known_private_inventory")]
    require(len(assignments) == 1 and isinstance(assignments[0].targets[0], ast.Tuple)
            and isinstance(assignments[0].targets[0].elts[2], ast.Name),
            "Machine scan source has no original inventory-return binding")
    assert isinstance(assignments[0].targets[0], ast.Tuple) and isinstance(assignments[0].targets[0].elts[2], ast.Name)
    invocation = assignments[0].value
    assert isinstance(invocation, ast.Call)
    publication_args = [item.value for item in invocation.keywords if item.arg == "publication_bodies"]
    require(matches(assignment(producer, "raw"), "_json(raw_ref)") and len(publication_args) == 1
            and matches(publication_args[0], '{role: raw[role] for role in ("pr_body", "release_body")}'),
            "Machine scan source does not pass the original declared body references to its inventory")
    bodies = {role: raw.get(role) for role in ("pr_body", "release_body")}
    for body in bodies.values():
        row_identity(body)
        require(isinstance(body, dict) and set(body) == {"path", "sha256"}, "Machine scan body reference has extra fields")
    known_name = assignments[0].targets[0].elts[2].id
    returns = [node.value for node in producer.body if isinstance(node, ast.Return) and isinstance(node.value, ast.Dict)]
    require(len(returns) == 1, "Machine scan source has no unique original result writer")
    written = dict_fields(returns[0])
    require("private_inventory" in written and matches(written["private_inventory"], known_name)
            and output.get("schema_version") == literal(written["schema_version"])
            and set(output) == set(written) | ({"staged_execution"} if staged else set()),
            "Machine scan result differs from the complete original returned schema and inventory field")
    additions = [node for node in producer.body if isinstance(node, ast.Assign) and len(node.targets) == 1
                 and isinstance(node.targets[0], ast.Subscript) and matches(node.targets[0].value, known_name)]
    require(len(additions) == 1 and matches(additions[0].targets[0], f'{known_name}["missing_from_submitted_corpus"]')
            and matches(additions[0].value, "sorted(set(known) - submitted)"),
            "Machine scan known-inventory augmentation differs from the original fixed writer")
    missing = output["private_inventory"].get("missing_from_submitted_corpus")
    require(isinstance(missing, list) and all(isinstance(value, str) and re.fullmatch(r"[a-f0-9]{64}", value) for value in missing)
            and missing == sorted(set(missing)), "Machine scan retained missing-corpus rows are malformed")
    return {"source": selected["source"], "source_data": source_bytes, "source_tree": source,
            "parents": {selected["output"]["path"]: {"ref": selected["output"], "prefix": ["private_inventory"], "value": output}},
            "refs": [selected[name] for name in ("record", "source", "script", "input", "command", "output")] + [command["stderr"]],
            "wrapper_original_hash_bound": staged,
            "publication_bodies": bodies,
            "extra_known_fields": {"missing_from_submitted_corpus"},
            "scope": "Recorded source/output field relationship; named-only wrappers remain corroboration, not authenticated past execution"}


def literal(node: ast.AST) -> str:
    require(isinstance(node, ast.Constant) and isinstance(node.value, str), "Machine field is not an original fixed string value")
    assert isinstance(node, ast.Constant) and isinstance(node.value, str)
    return node.value


def row_identity(value: Any) -> None:
    require(isinstance(value, dict) and isinstance(value.get("path"), str)
            and isinstance(value.get("sha256"), str) and re.fullmatch(r"[a-f0-9]{64}", value["sha256"]),
            "Machine field row has no complete typed original artifact identity")


def known_output(tree: ast.Module, known: Any, extra_fields: set[str]) -> tuple[ast.FunctionDef, dict[str, ast.expr]]:
    producer = named_function(tree, "_known_private_inventory")
    inventory_control_flow(producer)
    returns = [node.value.elts[2] for node in producer.body if isinstance(node, ast.Return)
               and isinstance(node.value, ast.Tuple) and len(node.value.elts) == 3 and isinstance(node.value.elts[2], ast.Dict)]
    require(len(returns) == 1, "Machine field has no unique original known-inventory return writer")
    fields = dict_fields(returns[0])
    require(isinstance(known, dict) and set(known) == set(fields) | extra_fields, "Machine field known inventory does not retain every original field")
    require(known.get("completeness") == literal(fields["completeness"])
            and isinstance(known.get("known_refs"), list) and type(known.get("known_ref_count")) is int
            and known["known_ref_count"] == len(known["known_refs"]),
            "Machine field known inventory has inconsistent original metadata")
    return producer, fields


def inventory_control_flow(producer: ast.FunctionDef) -> None:
    """Refuse contradictory exits and mutations before the original walker."""
    require_invocation_shape(producer, "known")
    nodes = lexical(producer)
    require(not producer.decorator_list and not any(isinstance(node, (ast.Yield, ast.YieldFrom, ast.Await)) for node in nodes),
            "Machine inventory producer has an unsupported execution form")
    require(producer.body and isinstance(producer.body[-1], ast.Return), "Machine inventory output is not the final direct return")
    allowed_returns = {id(producer.body[-1])}
    node: ast.AST
    for node in producer.body:
        if isinstance(node, ast.If) and matches(node.test, "project_dir is None or not expected_source_hashes"):
            require(block_matches([node], "if project_dir is None or not expected_source_hashes:\n    return {}, [], unavailable"),
                    "Machine inventory unavailable-input branch differs from its fixed original return")
            allowed_returns.add(id(node.body[0]))
    require(all(id(node) in allowed_returns for node in nodes if isinstance(node, ast.Return)),
            "Machine inventory contains an earlier or conditional replacement return")
    functions = {node.name for node in producer.body if isinstance(node, ast.FunctionDef)}
    require(not any(isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)) and node.id in functions for node in nodes),
            "Machine inventory rebinds an original producer helper")
    # Direct raises and raises outside the original source parsing handlers
    # contradict a reached output. Existing guarded parser refusals remain.
    guarded_raises = set()
    for node in nodes:
        if isinstance(node, ast.ExceptHandler):
            for child in lexical(node):
                if isinstance(child, ast.Raise):
                    guarded_raises.add(id(child))
    require(all(id(node) in guarded_raises for node in nodes if isinstance(node, ast.Raise)),
            "Machine inventory has an unconditional or unrelated early raise")
    stores = [node for node in nodes if isinstance(node, ast.Name) and node.id == "pending" and isinstance(node.ctx, (ast.Store, ast.Del))]
    initializers = [node for node in producer.body if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name)
                    and node.target.id == "pending" and node.value is not None and matches(node.value, "[]")]
    require(len(stores) == len(initializers) == 1, "Machine inventory resets or replaces its original pending collection")
    pending = [node for node in producer.body if isinstance(node, ast.While) and matches(node.test, "pending")]
    require(len(pending) == 1 and producer.body.index(initializers[0]) < producer.body.index(pending[0]),
            "Machine inventory does not reach its original pending loop after initialization")
    for name in ("walk", "collect_candidate"):
        definitions = [node for node in producer.body if isinstance(node, ast.FunctionDef) and node.name == name]
        require(len(definitions) == 1 and producer.body.index(definitions[0]) < producer.body.index(pending[0]),
                "Machine inventory helper is not defined before its original invocation")
    allowed_pending = {id(initializers[0].target), id(pending[0].test)}
    for node in lexical(pending[0]):
        if isinstance(node, ast.Call) and matches(node, "pending.pop()"):
            allowed_pending.update(id(child) for child in ast.walk(node))
    require(all(id(node) in allowed_pending for node in nodes if isinstance(node, ast.Name) and node.id == "pending"),
            "Machine inventory aliases or mutates its pending collection outside the original drain")
    for node in nodes:
        if isinstance(node, ast.Call):
            require(not (isinstance(node.func, ast.Name) and node.func.id in {"exec", "eval", "globals", "locals", "exit", "quit"}),
                    "Machine inventory contains an unsupported dynamic binding or exit")
            if matches(node.func, "_require") and node.args:
                require(not (isinstance(node.args[0], ast.Constant) and not node.args[0].value),
                        "Machine inventory has an unconditional failing guard before its output")


def block_matches(nodes: Sequence[ast.stmt], text: str) -> bool:
    return ast.dump(ast.Module(body=list(nodes), type_ignores=[])) == ast.dump(ast.parse(text))


def lexical(tree: ast.AST) -> list[ast.AST]:
    """Visit one invoked lexical scope, excluding dormant nested definitions."""
    result = [tree]
    for child in ast.iter_child_nodes(tree):
        if not isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            result.extend(lexical(child))
    return result


def instantiate(text: str, values: dict[str, str]) -> ast.FunctionDef:
    class ReplaceFields(ast.NodeTransformer):
        def visit_Name(self, node: ast.Name) -> ast.AST:
            return ast.Constant(values[node.id]) if node.id in values else node
    tree = ReplaceFields().visit(ast.parse(text))
    assert isinstance(tree, ast.Module) and isinstance(tree.body[0], ast.FunctionDef)
    return tree.body[0]


def inventory_writers(producer: ast.FunctionDef, known_fields: dict[str, ast.expr]) -> dict[str, Any]:
    require(matches(known_fields["public_work_candidates"], '[row for row in public_candidates.values() if row["sha256"] not in known]'),
            "Machine candidate field does not flow through the original output collection")
    collector = named_function(producer, "collect_candidate")
    assignments = [node.value for node in lexical(collector) if isinstance(node, ast.Assign) and len(node.targets) == 1
                   and matches(node.targets[0], "candidate") and isinstance(node.value, ast.Dict)]
    require(len(assignments) == 1, "Machine candidate has no unique original dictionary assignment")
    fields = dict_fields(assignments[0])
    unpacks = [value for key, value in zip(assignments[0].keys, assignments[0].values, strict=True) if key is None]
    require(set(fields) == {"classification", "reason", "matching_git_source_bytes"}
            and len(unpacks) == 1 and matches(unpacks[0], "ref")
            and matches(fields["matching_git_source_bytes"], 'source_candidates.get(ref["sha256"], [])'),
            "Machine candidate dictionary differs from the closed original producer shape")
    reason = fields["reason"]
    require(isinstance(reason, ast.IfExp) and matches(reason.test, "role"),
            "Machine candidate reason lacks the original role conditional")
    assert isinstance(reason, ast.IfExp)
    preservation = [node.value for node in lexical(collector) if isinstance(node, ast.Assign) and len(node.targets) == 1
                    and matches(node.targets[0], 'candidate["preservation"]')]
    require(len(preservation) == 1, "Machine candidate preservation has no unique original field writer")
    strings = {"BODY_REASON": literal(reason.body), "CODE_REASON": literal(reason.orelse), "PRESERVATION": literal(preservation[0])}
    require(ast.dump(collector) == ast.dump(instantiate(grammar.CANDIDATE, strings)),
            "Machine candidate complete writer differs from the closed original branch and copy grammar")
    walk = named_function(producer, "walk")
    reasons = {}
    for node in lexical(walk):
        if isinstance(node, ast.Dict):
            written = dict_fields(node)
            if "reason" in written:
                name = "UNRESOLVED_REASON" if "current_ref" in written else "EXTERNAL_REASON"
                require(name not in reasons, "Machine walk has duplicate original reason writers")
                reasons[name] = literal(written["reason"])
    require(set(reasons) == {"UNRESOLVED_REASON", "EXTERNAL_REASON"}, "Machine walk lacks its original complete reference writers")
    expected_walk = instantiate(grammar.WALK, reasons)
    # The earlier revision predates the explicit synthetic-fixture branch. Only
    # that complete branch and its exact assignment may be absent.
    if not any(isinstance(node, ast.Name) and node.id == "fixture" for node in lexical(walk)):
        for node in ast.walk(expected_walk):
            if isinstance(node, ast.If) and matches(node.test, 'isinstance(value.get("path"), str) and isinstance(value.get("sha256"), str)'):
                node.body = [item for item in node.body if not (isinstance(item, ast.Assign) and len(item.targets) == 1
                             and matches(item.targets[0], "fixture"))]
                for index, item in enumerate(node.body):
                    if isinstance(item, ast.If) and matches(item.test, "fixture is not None"):
                        require(len(item.orelse) == 1 and isinstance(item.orelse[0], ast.If), "Invalid built-in fixture branch grammar")
                        node.body[index] = item.orelse[0]
    require(ast.dump(walk) == ast.dump(expected_walk),
            "Machine reference walker differs from the complete original branch and recursive-call grammar")
    pending = [node for node in producer.body if isinstance(node, ast.While) and matches(node.test, "pending")]
    require(len(pending) == 1 and block_matches(pending, """
while pending:
    path, kind = pending.pop()
    try:
        value = json.loads(path.read_text())
    except (ValueError, UnicodeDecodeError):
        continue
    walk(value)
"""), "Machine reference walker is not called by the original direct pending loop")
    # Collection identities may not be aliased, reset or mutated by another
    # helper. Exact sanctioned subtrees contain every use of these two names.
    allowed = [collector, walk, known_fields["public_work_candidates"], known_fields["unfollowed_refs"]]
    for node in producer.body:
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id in {"public_candidates", "unfollowed"}:
            require(node.value is not None and matches(node.value, "{}" if node.target.id == "public_candidates" else "[]"),
                    "Machine original collection is initialized with unrelated values")
            allowed.append(node)
        if isinstance(node, ast.If) and matches(node.test, "fixture_observations"):
            require(matches(assignment(ast.Module(body=node.body, type_ignores=[]), "replay"),
                            'fixture_observations[0]["current_reproduction"]'),
                    "Machine literal-link loop does not use the original retained replay observation")
            loops = [item for item in node.body if isinstance(item, ast.For) and matches(item.iter, 'replay["external_tool_links"]')]
            for loop in loops:
                require(isinstance(loop.target, ast.Name) and loop.target.id == "link" and len(loop.body) == 1
                        and isinstance(loop.body[0], ast.Expr) and isinstance(loop.body[0].value, ast.Call),
                        "Machine literal-link row has an unsupported original loop")
                assert isinstance(loop.body[0], ast.Expr) and isinstance(loop.body[0].value, ast.Call)
                append = loop.body[0].value
                require(matches(append.func, "unfollowed.append") and len(append.args) == 1 and not append.keywords,
                        "Machine literal-link row has an unrelated collection writer")
                link_fields = dict_fields(append.args[0])
                require(set(link_fields) == {"path", "sha256", "reason"}, "Machine literal-link row has extra fields")
                link_reason = literal(link_fields["reason"])
                require("LINK_REASON" not in strings, "Machine literal-link reason has duplicate original writers")
                strings["LINK_REASON"] = link_reason
                require(block_matches([loop], 'for link in replay["external_tool_links"]:\n'
                        '    unfollowed.append({"path": link["link_path"], "sha256": link["link_bytes_sha256"], "reason": ' + repr(link_reason) + '})'),
                        "Machine literal-link row differs from its original field projection")
                allowed.append(loop)
    permitted = {id(node) for subtree in allowed for node in ast.walk(subtree)}
    require(all(id(node) in permitted for node in ast.walk(producer)
                if isinstance(node, ast.Name) and node.id in {"public_candidates", "unfollowed"}),
            "Machine inventory contains an unrelated collection writer or alias")
    return {**strings, **reasons, "classification": literal(fields["classification"])}


def candidate_reason(producer: ast.FunctionDef, known_fields: dict[str, ast.expr], row: Any) -> str:
    strings = inventory_writers(producer, known_fields)
    row_identity(row)
    base_keys = {"path", "sha256", "classification", "reason", "matching_git_source_bytes"}
    extra_keys = ({"publication_role"} if "publication_role" in row else set()) | ({"original_reference", "preservation"} if "original_reference" in row else set())
    require(set(row) == base_keys | extra_keys and row["classification"] == strings["classification"]
            and isinstance(row["matching_git_source_bytes"], list), "Machine candidate row differs from its complete original schema")
    git_rows = row["matching_git_source_bytes"]
    for origin in git_rows:
        require(isinstance(origin, dict) and set(origin) == {"commit", "git_path", "git_blob"}
                and all(isinstance(origin[key], str) and re.fullmatch(r"[a-f0-9]{40}", origin[key]) for key in ("commit", "git_blob"))
                and isinstance(origin["git_path"], str) and origin["git_path"] and not Path(origin["git_path"]).is_absolute()
                and all(part not in {"", ".", ".."} for part in origin["git_path"].split("/")),
                "Machine candidate original Git member row is malformed")
    require(len({json.dumps(value, sort_keys=True) for value in git_rows}) == len(git_rows),
            "Machine candidate original Git member rows are duplicated")
    if "original_reference" in row:
        row_identity(row["original_reference"])
        require(set(row["original_reference"]) == {"path", "sha256"} and row["preservation"] == strings["PRESERVATION"],
                "Machine candidate original reference or preservation differs from its complete writer")
    if "publication_role" in row:
        require(row["publication_role"] in {"pr_body", "release_body"}, "Machine candidate publication role is not an original supported value")
    return str(strings["BODY_REASON"] if "publication_role" in row else strings["CODE_REASON"])


def filtered_candidate_reason(bound: dict[str, Any], producer: ast.FunctionDef, fields: dict[str, ast.expr],
                              known: dict[str, Any], row: dict[str, Any], strings: dict[str, Any]) -> str:
    """Derive a retained reason whose candidate was filtered by a private hash."""
    require(matches(fields["known_refs"], "list(refs.values())"), "Machine filtered candidate lacks the original private-reference output")
    private_rows = [value for value in known["known_refs"] if isinstance(value, dict) and value.get("sha256") == row["sha256"]]
    require(private_rows and all(set(value) == {"path", "sha256", "kind"} and value["kind"] in {"media", "review", "transcript"}
                                for value in private_rows), "Machine filtered candidate hash has no complete original private rows")
    for private in private_rows:
        row_identity(private)
    bodies = bound.get("publication_bodies")
    require(isinstance(bodies, dict) and set(bodies) == {"pr_body", "release_body"}
            and all(value["sha256"] != row["sha256"] for value in bodies.values()),
            "Machine filtered candidate cannot establish the original non-body branch")
    body_loops = [node for node in producer.body if isinstance(node, ast.For)
                  and matches(node.iter, "(publication_bodies or {}).items()")]
    require(len(body_loops) == 1 and block_matches(body_loops, """
for role, ref in (publication_bodies or {}).items():
    _require(role in {"pr_body", "release_body"}, "Unknown publication body role")
    path = _file(ref)
    body_candidates[str(path), ref["sha256"]] = role
"""), "Machine filtered candidate role map differs from the original bound body-input writer")
    return str(strings["CODE_REASON"])


def link_reason(producer: ast.FunctionDef, fields: dict[str, ast.expr], known: dict[str, Any],
                row: dict[str, Any], strings: dict[str, Any]) -> str:
    require(matches(fields["synthetic_failure_fixtures"], "fixture_observations"),
            "Machine literal-link reason has no original fixture-observation output")
    bindings = [node for node in producer.body if isinstance(node, ast.Assign) and len(node.targets) == 1
                and matches(node.targets[0], "(fixture_claims, fixture_observations)") and isinstance(node.value, ast.Call)
                and matches(node.value.func, "_synthetic_failure_inventory")]
    require(len(bindings) == 1, "Machine literal-link row has no original fixed replay-producer binding")
    observations = known["synthetic_failure_fixtures"]
    require(isinstance(observations, list) and observations and isinstance(observations[0], dict),
            "Machine literal-link row has no complete original observation")
    replay = observations[0].get("current_reproduction")
    require(isinstance(replay, dict) and isinstance(replay.get("external_tool_links"), list),
            "Machine literal-link row has no original explicit tool-link table")
    assert isinstance(replay, dict)
    links = replay["external_tool_links"]
    selected = []
    identities = set()
    for link in links:
        require(isinstance(link, dict) and set(link) == {"actual_target", "declared_target_sha256", "link_bytes_sha256", "link_path", "link_target"}
                and isinstance(link["link_path"], str) and Path(link["link_path"]).is_absolute()
                and isinstance(link["link_target"], str)
                and hashlib.sha256(link["link_target"].encode()).hexdigest() == link["link_bytes_sha256"],
                "Machine original replay tool-link table has malformed literal identity")
        row_identity(link["actual_target"])
        require(set(link["actual_target"]) == {"path", "sha256"}
                and link["declared_target_sha256"] == link["actual_target"]["sha256"],
                "Machine original replay tool target differs from its complete declared identity")
        require(link["link_path"] not in identities, "Machine original replay has duplicate literal-link rows")
        identities.add(link["link_path"])
        if link["link_path"] == row["path"] and link["link_bytes_sha256"] == row["sha256"]:
            selected.append(link)
    require(len(selected) == 1, "Machine selected literal-link row differs from its original complete replay projection")
    return str(strings["LINK_REASON"])


def fixed_inventory_field(bound: dict[str, Any], parent_ref: dict[str, Any], selector: list[Any]) -> dict[str, Any]:
    parent = bound["parents"].get(parent_ref.get("path"))
    require(parent is not None and parent["ref"] == parent_ref, "Machine field parent is outside its exact original output roots")
    prefix = parent["prefix"]
    require(isinstance(selector, list) and selector[:len(prefix)] == prefix,
            "Machine field selector is outside the original output prefix")
    edge = selector[len(prefix):]
    known = parent["value"]
    for part in prefix:
        require(isinstance(known, dict) and part in known, "Machine field output prefix is missing")
        known = known[part]
    producer, fields = known_output(bound["source_tree"], known, bound.get("extra_known_fields", set()))
    if len(edge) == 1 and type(edge[0]) is str and edge[0] in {"scope", "reason"}:
        require(edge[0] in fields and isinstance(known[edge[0]], str) and known[edge[0]] == literal(fields[edge[0]]),
                "Machine inventory metadata differs from the exact original return field")
        return {"value": known[edge[0]], "row": known, "source": bound["source"],
                "extractions": [{"edge": selector, "value": known[edge[0]]}]}
    require(len(edge) == 3 and type(edge[0]) is str and type(edge[1]) is int and edge[1] >= 0 and type(edge[2]) is str
            and ((edge[0] in {"public_work_candidates", "unfollowed_refs", "unresolved_source_candidates"} and edge[2] == "reason")
                 or (edge[0] == "public_work_candidates" and edge[2] == "preservation")
                 or (edge[0] == "auxiliary_execution_sources" and edge[2] == "scope")),
            "Machine field selector is outside the closed original inventory-field grammar")
    rows = known[edge[0]]
    require(isinstance(rows, list) and edge[1] < len(rows), "Machine field selected row is absent")
    row = rows[edge[1]]
    if edge[0] == "auxiliary_execution_sources":
        require(matches(fields[edge[0]], "auxiliary_source_current"), "Machine auxiliary source output differs")
        loops = [node for node in producer.body if isinstance(node, ast.For) and matches(node.iter, "source_snapshots or []")]
        require(len(loops) == 1 and matches(loops[0].target, "locator"), "Machine auxiliary source has no original direct locator loop")
        source_pairs = [node for node in loops[0].body if isinstance(node, ast.Assign) and len(node.targets) == 1
                        and matches(node.targets[0], "(original, snapshot)")]
        require(len(source_pairs) == 1 and matches(source_pairs[0].value, '(locator["original"], locator["snapshot"])')
                and matches(assignment(ast.Module(body=loops[0].body, type_ignores=[]), "origin"), 'Path(original["path"])'),
                "Machine auxiliary scope does not use the original complete locator identities")
        blocks = [node for node in loops[0].body if isinstance(node, ast.If)
                  and matches(node.test, 'locator.get("scope") == "auxiliary_execution_source"') and len(node.body) == 1
                  and isinstance(node.body[0], ast.Expr) and isinstance(node.body[0].value, ast.Call)
                  and matches(node.body[0].value.func, "auxiliary_source_current.append")]
        require(len(blocks) == 1, "Machine auxiliary scope has no unique original complete row writer")
        assert isinstance(blocks[0].body[0], ast.Expr) and isinstance(blocks[0].body[0].value, ast.Call)
        append = blocks[0].body[0].value
        require(len(append.args) == 1 and not append.keywords, "Machine auxiliary scope append is malformed")
        written = dict_fields(append.args[0])
        require(set(written) == {"original_reference", "preserved_ref", "current_ref", "classification", "scope"},
                "Machine auxiliary source row has unrelated fields")
        derived = literal(written["scope"])
        expected = ('auxiliary_source_current.append({"original_reference": original, "preserved_ref": snapshot, '
                    '"current_ref": artifact_ref(origin), "classification": "UNCLASSIFIED", "scope": ' + repr(derived) + '})')
        require(matches(append, expected) and isinstance(row, dict) and set(row) == set(written)
                and row["classification"] == "UNCLASSIFIED" and row["scope"] == derived,
                "Machine auxiliary scope differs from its complete source projection")
        for key in ("original_reference", "preserved_ref", "current_ref"):
            row_identity(row[key])
            require(set(row[key]) == {"path", "sha256"}, "Machine auxiliary source identity has extra fields")
        require(row["original_reference"]["sha256"] == row["preserved_ref"]["sha256"]
                and row["original_reference"]["path"] == row["current_ref"]["path"],
                "Machine auxiliary source row does not preserve its exact original identity relationships")
    elif edge[0] == "unresolved_source_candidates":
        strings = inventory_writers(producer, fields)
        row_identity(row)
        require(matches(fields[edge[0]], "list(unresolved_sources.values())")
                and set(row) == {"path", "sha256", "classification", "status", "current_ref", "reason"}
                and row["classification"] == "UNCLASSIFIED" and row["status"] == "UNVERIFIED",
                "Machine unresolved source row differs from its original complete projection")
        row_identity(row["current_ref"])
        require(set(row["current_ref"]) == {"path", "sha256"} and row["current_ref"]["path"] == row["path"]
                and row["current_ref"]["sha256"] != row["sha256"], "Machine unresolved source identity is inconsistent")
        derived = strings["UNRESOLVED_REASON"]
    elif edge[0] == "public_work_candidates":
        row_identity(row)
        derived = candidate_reason(producer, fields, row)
        require(row["reason"] == derived, "Machine candidate reason differs from its original source")
        if edge[2] == "preservation":
            require("preservation" in row, "Machine candidate has no exact original preservation field")
            derived = row["preservation"]
    else:
        row_identity(row)
        require(matches(fields["unfollowed_refs"], "unfollowed") and set(row) == {"path", "sha256", "reason"},
                "Machine reference row differs from its original complete writer")
        candidates = [value for value in known["public_work_candidates"] if isinstance(value, dict)
                      and value.get("path") == row["path"] and value.get("sha256") == row["sha256"]]
        require(len(candidates) <= 1, "Machine reference row has ambiguous candidate origins")
        if candidates:
            derived = candidate_reason(producer, fields, candidates[0])
            collector = named_function(producer, "collect_candidate")
            require(any(isinstance(node, ast.Call) and matches(node, 'unfollowed.append({**ref, "reason": candidate["reason"]})')
                        for node in ast.walk(collector)), "Machine reference reason is not copied from the exact candidate writer")
        else:
            strings = inventory_writers(producer, fields)
            if row["reason"] == strings["EXTERNAL_REASON"]:
                derived = strings["EXTERNAL_REASON"]
            elif "LINK_REASON" in strings and row["reason"] == strings["LINK_REASON"]:
                derived = link_reason(producer, fields, known, row, strings)
            else:
                derived = filtered_candidate_reason(bound, producer, fields, known, row, strings)
    require(isinstance(row[edge[2]], str) and row[edge[2]] == derived, "Machine field differs from the original typed producer derivation")
    return {"value": derived, "row": row, "source": bound["source"], "extractions": [{"edge": selector, "value": derived}]}
