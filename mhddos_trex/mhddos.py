"""Read MHDDoS's own source so this package never carries a second copy of its data.

MHDDoS is a single-file tool whose attack constants are module-level literals. Rather than
transcribe them here (where they would silently rot), parse ``start.py`` and pull the same
values out. One source of truth, and an upstream update needs no code change here.
"""

import ast
import os
from dataclasses import dataclass
from pathlib import Path

ENV_VAR = "MHDDOS_DIR"
DEFAULT_CANDIDATES = (Path("../MHDDoS"), Path("../../MHDDoS"))


class MHDDoSNotFound(RuntimeError):
    pass


def locate(explicit: str | os.PathLike | None = None) -> Path:
    for candidate in (explicit, os.environ.get(ENV_VAR), *DEFAULT_CANDIDATES):
        if not candidate:
            continue
        path = Path(candidate).expanduser().resolve()
        if (path / "start.py").is_file():
            return path
    raise MHDDoSNotFound(
        "MHDDoS checkout not found; pass --mhddos-dir or set "
        f"{ENV_VAR} to the directory holding start.py"
    )


def _static_parts(node: ast.AST) -> str:
    """Gather the literal sub-strings of a chain that also concatenates runtime values.

    ``HttpFlood._payload`` is ``<request line built at runtime> + "<fixed header block>"``;
    the fixed block is what a replay needs, so collect the constants and drop the rest.
    """
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _static_parts(node.left) + _static_parts(node.right)
    return ""


def _class_assigns(cls: ast.ClassDef) -> dict[str, ast.AST]:
    return {
        item.targets[0].id: item.value
        for item in cls.body
        if isinstance(item, ast.Assign) and isinstance(item.targets[0], ast.Name)
    }


def _resolve(node: ast.AST, known: dict[str, object]) -> object:
    """Evaluate a literal collection, expanding ``*NAME`` against earlier class names."""
    if isinstance(node, ast.Name) and node.id in known:
        return known[node.id]
    if isinstance(node, (ast.Set, ast.List, ast.Tuple)):
        items: list[object] = []
        for element in node.elts:
            if isinstance(element, ast.Starred):
                items.extend(_resolve(element.value, known))
            else:
                items.append(ast.literal_eval(element))
        return set(items) if isinstance(node, ast.Set) else items
    return ast.literal_eval(node)


def class_values(cls: ast.ClassDef) -> dict[str, object]:
    """Resolve a class body's assignments in order, so later names see earlier ones."""
    known: dict[str, object] = {}
    for item in cls.body:
        if isinstance(item, ast.Assign) and isinstance(item.targets[0], ast.Name):
            try:
                known[item.targets[0].id] = _resolve(item.value, known)
            except (ValueError, TypeError):
                continue
    return known


def _func_assign(func: ast.FunctionDef, name: str) -> ast.AST | None:
    for stmt in ast.walk(func):
        if isinstance(stmt, ast.Assign) and isinstance(stmt.targets[0], ast.Name):
            if stmt.targets[0].id == name:
                return stmt.value
    return None


@dataclass(frozen=True)
class Source:
    """Everything the stream builder needs, lifted verbatim from MHDDoS."""

    methods: frozenset[str]
    layer4: frozenset[str]
    layer7: frozenset[str]
    amplifiers: dict[str, tuple[bytes, int]]
    protocol_payloads: dict[str, bytes]
    ovh_udp_methods: tuple[str, ...]
    ovh_udp_paths: tuple[str, ...]
    stomp_hex: str
    browser_headers: str
    user_agents: tuple[str, ...]
    referers: tuple[str, ...]


def load(directory: Path) -> Source:
    root = directory
    tree = ast.parse((root / "start.py").read_text(encoding="utf-8"))
    classes = {n.name: n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)}
    funcs = {n.name: n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}

    methods_cls = class_values(classes["Methods"])
    layer4 = frozenset(methods_cls["LAYER4_METHODS"])
    layer7 = frozenset(methods_cls["LAYER7_METHODS"])

    layer4_cls = class_values(classes["Layer4"])
    amplifiers = layer4_cls["AMP_PAYLOADS"]

    protocol_payloads = {}
    for method, func_name in (
        ("VSE", "_vse"),
        ("TS3", "_ts3"),
        ("MCPE", "_mcpe"),
        ("FIVEM", "_fivem"),
    ):
        node = _func_assign(funcs[func_name], "payload")
        protocol_payloads[method] = ast.literal_eval(node)

    ovh = funcs["_generate_ovh_udp"]
    ovh_methods = tuple(ast.literal_eval(_func_assign(ovh, "methods")))
    ovh_paths = tuple(ast.literal_eval(_func_assign(ovh, "paths")))

    stomp = funcs["_stomp"]
    stomp_hex = ast.literal_eval(_func_assign(stomp, "hex_header"))

    browser_headers = ""
    for node in ast.walk(classes["HttpFlood"]):
        if isinstance(node, ast.FunctionDef) and node.name == "__init__":
            for stmt in node.body:
                if isinstance(stmt, ast.Assign) and getattr(stmt.targets[0], "attr", "") == "_payload":
                    browser_headers = _static_parts(stmt.value)

    files = root / "files"
    return Source(
        methods=frozenset({*layer4, *layer7}),
        layer4=layer4,
        layer7=layer7,
        amplifiers=amplifiers,
        protocol_payloads=protocol_payloads,
        ovh_udp_methods=ovh_methods,
        ovh_udp_paths=ovh_paths,
        stomp_hex=stomp_hex,
        browser_headers=browser_headers,
        user_agents=_words(files / "useragent.txt"),
        referers=_words(files / "referers.txt"),
    )


def _words(path: Path) -> tuple[str, ...]:
    if not path.is_file():
        return ()
    return tuple(line.strip() for line in path.read_text(errors="ignore").splitlines() if line.strip())
