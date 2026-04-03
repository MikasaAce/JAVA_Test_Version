import re
from typing import Dict, List, Set, Tuple, Union


RULES_6_3 = [
    {"rule_id": "R-2-3-1", "message": "GJB R-2-3-1: 具有虚拟成员函数的类，析构函数必须是虚拟的", "severity": "高危"},
    {"rule_id": "R-2-3-2", "message": "GJB R-2-3-2: 析构函数中禁止存在不是由自身捕获处理的异常", "severity": "高危"},
]

RULE_META: Dict[str, dict] = {x["rule_id"]: x for x in RULES_6_3}


def extract_rule_id(message: str) -> str:
    m = re.search(r"[RA]-\d+-\d+-\d+", message or "")
    if m:
        return m.group(0)
    return "R-2-3-UNKNOWN"


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
    quote = ""
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
                quote = ch
            elif i > 0 and line[i - 1] != "\\" and ch == quote:
                in_str = False
                quote = ""
        out.append(ch)
        i += 1
    return "".join(out)


def _collect_class_blocks(lines: List[str]) -> Dict[str, Tuple[int, int, List[str]]]:
    blocks: Dict[str, Tuple[int, int, List[str]]] = {}
    class_pat = re.compile(r"^\s*class\s+([A-Za-z_][A-Za-z0-9_]*)\b")

    i = 0
    while i < len(lines):
        s = _strip_line_comment(lines[i])
        m = class_pat.match(s)
        if not m:
            i += 1
            continue

        name = m.group(1)
        start = i

        while i < len(lines) and "{" not in lines[i]:
            i += 1
        if i >= len(lines):
            break

        depth = lines[i].count("{") - lines[i].count("}")
        i += 1
        while i < len(lines) and depth > 0:
            depth += lines[i].count("{") - lines[i].count("}")
            i += 1
        end = i - 1

        blocks[name] = (start + 1, end + 1, lines[start:end + 1])

    return blocks


def _scan_r231(lines: List[str], code: str, violations: List[dict], seen: Set[Tuple[int, str]]):
    classes = _collect_class_blocks(lines)

    for cls, (s, _e, body_lines) in classes.items():
        body = "\n".join(_strip_line_comment(x) for x in body_lines)
        has_virtual_func = bool(re.search(r"\bvirtual\b\s+[^;]*\([^\)]*\)\s*(?:=\s*0)?\s*;", body))
        if not has_virtual_func:
            continue

        # 类内析构函数声明
        dtor_decl = re.search(rf"\b(virtual\s+)?~\s*{re.escape(cls)}\s*\([^\)]*\)\s*;", body)
        if dtor_decl:
            if not dtor_decl.group(1):
                _add_violation(violations, seen, s, "R-2-3-1", get_code_snippet((s - 1, s - 1), code), cls)
            continue

        # 类外声明（极少见）保持保守：未找到虚析构直接告警
        _add_violation(violations, seen, s, "R-2-3-1", get_code_snippet((s - 1, s - 1), code), cls)


def _find_destructor_defs(lines: List[str], cls: str) -> List[Tuple[int, int, int, str]]:
    defs = []
    pat = re.compile(rf"^\s*{re.escape(cls)}\s*::\s*~\s*{re.escape(cls)}\s*\([^\)]*\)\s*\{{")

    i = 0
    while i < len(lines):
        s = _strip_line_comment(lines[i]).strip()
        if not pat.match(s):
            i += 1
            continue

        start = i
        line_no = i + 1
        depth = lines[i].count("{") - lines[i].count("}")
        i += 1
        while i < len(lines) and depth > 0:
            depth += lines[i].count("{") - lines[i].count("}")
            i += 1
        end = i - 1
        body = "\n".join(_strip_line_comment(x) for x in lines[start:end + 1])
        defs.append((line_no, start + 1, end + 1, body))

    return defs


def _scan_r232(lines: List[str], code: str, violations: List[dict], seen: Set[Tuple[int, str]]):
    classes = _collect_class_blocks(lines)

    for cls in classes.keys():
        defs = _find_destructor_defs(lines, cls)
        for line_no, s, e, body in defs:
            throw_count = len(re.findall(r"\bthrow\b", body))
            if throw_count == 0:
                continue

            # 近似判定：若析构体存在 try{...} catch(...) 包裹，则认为已自身捕获
            has_try_catch = bool(re.search(r"\btry\b[\s\S]*\bcatch\s*\(", body))
            if not has_try_catch:
                _add_violation(violations, seen, line_no, "R-2-3-2", get_code_snippet((s - 1, e - 1), code), cls)


def detect_cpp_gjb_6_3_violations(code: str, language: str = "cpp") -> List[dict]:
    """
    检测GJB 8114-2013中6.3（析构函数）条款的违规。

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

    _scan_r231(lines, code, violations, seen)
    _scan_r232(lines, code, violations, seen)

    return sorted(violations, key=lambda x: (x["line"], x["rule_id"]))


def analyze_cpp_gjb_6_3(code_string: str, language: str = "cpp") -> List[dict]:
    return detect_cpp_gjb_6_3_violations(code_string, language)


if __name__ == "__main__":
    test_cases = [
        (
            "cpp_basic_violations",
            "cpp",
            """
class B {
public:
    B() {}
    ~B();
    virtual void f(int a) = 0;
};

B::~B() {}

class D : public B {
public:
    D() {}
    ~D();
    virtual void f(int a) { (void)a; }
};

D::~D() {
    throw 0;
}
""",
        ),
        (
            "cpp_compliant_sample",
            "cpp",
            """
class B {
public:
    B() {}
    virtual ~B();
    virtual void f(int a) = 0;
};

B::~B() {}

class D : public B {
public:
    D() {}
    virtual ~D();
    virtual void f(int a) { (void)a; }
};

D::~D() {
    try {
        throw 0;
    } catch (int) {
    }
}
""",
        ),
    ]

    for name, lang, src in test_cases:
        print("=" * 70)
        print(f"CASE: {name} ({lang})")
        results = analyze_cpp_gjb_6_3(src, lang)
        if not results:
            print("未检测到违规")
            continue
        print(f"检测到 {len(results)} 个违规")
        for item in results:
            print(
                f"line={item['line']} | rule_id={item['rule_id']} | "
                f"message={item['message']} | code_snippet={item['code_snippet'].replace(chr(10), ' ')}"
            )
