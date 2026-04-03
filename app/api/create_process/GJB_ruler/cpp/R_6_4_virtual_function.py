import re
from typing import Dict, List, Set, Tuple, Union


RULES_6_4 = [
    {"rule_id": "R-2-4-1", "message": "GJB R-2-4-1: 基类虚拟函数参数缺省值在派生类重写中禁止改变", "severity": "高危"},
    {"rule_id": "R-2-4-2", "message": "GJB R-2-4-2: 派生类对基类虚拟函数重写声明必须使用virtual显示说明", "severity": "高危"},
    {"rule_id": "R-2-4-3", "message": "GJB R-2-4-3: 禁止非纯虚函数被纯虚拟函数重写", "severity": "高危"},
]

RULE_META: Dict[str, dict] = {x["rule_id"]: x for x in RULES_6_4}


def extract_rule_id(message: str) -> str:
    m = re.search(r"[RA]-\d+-\d+-\d+", message or "")
    if m:
        return m.group(0)
    return "R-2-4-UNKNOWN"


def get_code_snippet(node_or_span: Union[Tuple[int, int], object], code: str, context_lines: int = 2) -> str:
    lines = code.split("\n")
    if isinstance(node_or_span, tuple):
        s, e = node_or_span
    else:
        s = getattr(node_or_span, "start_point", (0, 0))[0]
        e = getattr(node_or_span, "end_point", (s, 0))[0]
    start = max(0, s - context_lines)
    end = min(len(lines), e + context_lines + 1)
    snippet = "\n".join(lines[start:end])
    if len(snippet) > 300:
        snippet = snippet[:300] + "..."
    return snippet


def _add_violation(
    violations: List[dict],
    seen: Set[Tuple[int, str]],
    line: int,
    rule_id: str,
    code_snippet: str,
    suffix: str = "",
):
    if (line, rule_id) in seen:
        return
    seen.add((line, rule_id))
    msg = RULE_META[rule_id]["message"]
    if suffix:
        msg = f"{msg} ({suffix})"
    violations.append(
        {
            "line": line,
            "code_snippet": code_snippet,
            "violation_type": "编码规范",
            "severity": RULE_META[rule_id]["severity"],
            "rule_id": rule_id,
            "message": msg,
        }
    )


def _strip_line_comment(line: str) -> str:
    in_str = False
    q = ""
    out = []
    i = 0
    while i < len(line):
        ch = line[i]
        nxt = line[i + 1] if i + 1 < len(line) else ""
        if not in_str and ch == "/" and nxt == "/":
            break
        if ch in ('"', "'"):
            if not in_str:
                in_str = True
                q = ch
            elif i > 0 and line[i - 1] != "\\" and ch == q:
                in_str = False
                q = ""
        out.append(ch)
        i += 1
    return "".join(out)


def _collect_classes(lines: List[str]) -> Dict[str, dict]:
    class_pat = re.compile(r"^\s*class\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?::\s*public\s+(?:virtual\s+)?([A-Za-z_][A-Za-z0-9_]*))?")
    method_pat = re.compile(
        r"^\s*(virtual\s+)?(?:[A-Za-z_][A-Za-z0-9_:\<\>\s\*&]+)\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^\)]*)\)\s*(?:=\s*0)?\s*;"
    )
    pure_tail_pat = re.compile(r"=\s*0\s*;")

    classes: Dict[str, dict] = {}

    i = 0
    while i < len(lines):
        s = _strip_line_comment(lines[i])
        m = class_pat.match(s)
        if not m:
            i += 1
            continue

        cls = m.group(1)
        base = m.group(2) or ""
        start = i + 1

        while i < len(lines) and "{" not in lines[i]:
            i += 1
        if i >= len(lines):
            break

        depth = lines[i].count("{") - lines[i].count("}")
        body_start = i
        i += 1
        while i < len(lines) and depth > 0:
            depth += lines[i].count("{") - lines[i].count("}")
            i += 1
        end = i

        methods: Dict[str, dict] = {}
        for ln in range(body_start, min(end, len(lines))):
            line = _strip_line_comment(lines[ln]).strip()
            mm = method_pat.match(line)
            if not mm:
                continue
            is_virtual = bool(mm.group(1))
            name = mm.group(2)
            args = mm.group(3).strip()
            pure = bool(pure_tail_pat.search(line))

            # 读取缺省参数字符串（简单按 a=... 提取）
            defaults = re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^,\)]+)", args)
            default_map = {k: v.strip() for k, v in defaults}

            methods[name] = {
                "line": ln + 1,
                "virtual": is_virtual,
                "pure": pure,
                "args": args,
                "default_map": default_map,
            }

        classes[cls] = {"base": base, "start": start, "end": end, "methods": methods}

    return classes


def _scan_rules(lines: List[str], code: str, language: str, violations: List[dict], seen: Set[Tuple[int, str]]):
    classes = _collect_classes(lines)

    for cls, info in classes.items():
        base = info["base"]
        if not base or base not in classes:
            continue

        base_methods = classes[base]["methods"]
        drv_methods = info["methods"]

        for mname, dmeta in drv_methods.items():
            if mname not in base_methods:
                continue
            bmeta = base_methods[mname]

            # 仅在基类该方法为virtual语义下检查重写
            if not bmeta["virtual"]:
                continue

            # R-2-4-1: 缺省参数不得变化
            bdef = bmeta["default_map"]
            ddef = dmeta["default_map"]
            # 派生类可省略缺省值；仅当派生类显式给出且与基类不一致时判违背。
            changed = False
            for k, v in ddef.items():
                if k not in bdef or bdef[k] != v:
                    changed = True
                    break
            if changed:
                _add_violation(
                    violations,
                    seen,
                    dmeta["line"],
                    "R-2-4-1",
                    get_code_snippet((dmeta["line"] - 1, dmeta["line"] - 1), code),
                    f"{base}::{mname}",
                )

            # R-2-4-2: 重写声明必须显式virtual
            if not dmeta["virtual"]:
                _add_violation(
                    violations,
                    seen,
                    dmeta["line"],
                    "R-2-4-2",
                    get_code_snippet((dmeta["line"] - 1, dmeta["line"] - 1), code),
                    f"{cls}::{mname}",
                )

            # R-2-4-3: 基类非纯虚，派生改成纯虚
            if (not bmeta["pure"]) and dmeta["pure"]:
                _add_violation(
                    violations,
                    seen,
                    dmeta["line"],
                    "R-2-4-3",
                    get_code_snippet((dmeta["line"] - 1, dmeta["line"] - 1), code),
                    f"{base}::{mname}",
                )


def detect_cpp_gjb_6_4_violations(code: str, language: str = "cpp") -> List[dict]:
    """
    检测GJB 8114-2013中6.4（虚拟函数）条款的违规。

    Args:
        code: C++源码字符串
        language: 语言类型，支持"cpp"和"c++"

    Returns:
        list[dict]: 违规列表
    """
    if language not in ("cpp", "c++"):
        return []

    lines = code.split("\n")
    violations: List[dict] = []
    seen: Set[Tuple[int, str]] = set()

    _scan_rules(lines, code, language, violations, seen)

    return sorted(violations, key=lambda x: (x["line"], x["rule_id"]))


def analyze_cpp_gjb_6_4(code_string: str, language: str = "cpp") -> List[dict]:
    return detect_cpp_gjb_6_4_violations(code_string, language)


if __name__ == "__main__":
    test_cases = [
        (
            "cpp_basic_violations",
            "cpp",
            """
class Base {
public:
    virtual int g(int a = 0);
    virtual void foo();
};

class Derived : public Base {
public:
    virtual int g(int a = 1);   // R-2-4-1
    int foo();                  // R-2-4-2
};

class B {
public:
    virtual void f();
};

class C : public B {
public:
    virtual void f() = 0;       // R-2-4-3
};
""",
        ),
        (
            "cpp_compliant_sample",
            "cpp",
            """
class Base {
public:
    virtual int g1(int a = 0);
    virtual int g2(int a = 0);
};

class Derived : public Base {
public:
    virtual int g1(int a = 0);
    virtual int g2(int a);
};

class B {
public:
    virtual void f() = 0;
};

class C : public B {
public:
    virtual void f() = 0;
};
""",
        ),
    ]

    for name, lang, src in test_cases:
        print("=" * 70)
        print(f"CASE: {name} ({lang})")
        results = analyze_cpp_gjb_6_4(src, lang)
        if not results:
            print("未检测到违规")
            continue
        print(f"检测到 {len(results)} 个违规")
        for item in results:
            print(
                f"line={item['line']} | rule_id={item['rule_id']} | "
                f"message={item['message']} | code_snippet={item['code_snippet'].replace(chr(10), ' ')}"
            )
