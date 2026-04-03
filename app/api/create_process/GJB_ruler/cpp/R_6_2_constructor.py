import re
from typing import Dict, List, Set, Tuple, Union


RULES_6_2 = [
    {"rule_id": "R-2-2-1", "message": "GJB R-2-2-1: 构造函数中禁止使用全局变量", "severity": "高危"},
    {"rule_id": "R-2-2-2", "message": "GJB R-2-2-2: 类中必须明确定义缺省构造函数", "severity": "高危"},
    {"rule_id": "R-2-2-3", "message": "GJB R-2-2-3: 单参数构造函数必须使用explicit声明", "severity": "高危"},
    {"rule_id": "R-2-2-4", "message": "GJB R-2-2-4: 类中所有成员变量必须在构造函数中初始化", "severity": "高危"},
    {"rule_id": "R-2-2-5", "message": "GJB R-2-2-5: 派生类构造函数必须在初始化列表中说明直接基类构造函数", "severity": "高危"},
]

RULE_META: Dict[str, dict] = {x["rule_id"]: x for x in RULES_6_2}


def extract_rule_id(message: str) -> str:
    m = re.search(r"[RA]-\d+-\d+-\d+", message or "")
    if m:
        return m.group(0)
    return "R-2-2-UNKNOWN"


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


def _collect_class_info(lines: List[str]):
    class_info: Dict[str, dict] = {}
    class_pat = re.compile(r"^\s*class\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?::\s*public\s+([A-Za-z_][A-Za-z0-9_]*))?")

    i = 0
    while i < len(lines):
        s = _strip_line_comment(lines[i])
        m = class_pat.match(s)
        if not m:
            i += 1
            continue

        cls = m.group(1)
        base = m.group(2) or ""
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

        body_lines = lines[start:end + 1]
        body_text = "\n".join(_strip_line_comment(x) for x in body_lines)

        members: Set[str] = set()
        constructors: List[Tuple[int, str, bool]] = []  # line, arg_text, has_explicit
        has_default_ctor_decl = False

        for off, raw in enumerate(body_lines):
            line_no = start + off + 1
            t = _strip_line_comment(raw).strip()

            # member variable
            m_mem = re.match(r"^(?:public:|private:|protected:)?\s*(?:static\s+)?(?:unsigned\s+|signed\s+)?(?:char|short|int|long|float|double|bool|[A-Za-z_][A-Za-z0-9_]*)\s+([A-Za-z_][A-Za-z0-9_]*)\s*;", t)
            if m_mem and "(" not in t:
                members.add(m_mem.group(1))

            # constructor declaration
            m_ctor = re.match(rf"^(explicit\s+)?{re.escape(cls)}\s*\(([^\)]*)\)\s*;", t)
            if m_ctor:
                arg_text = m_ctor.group(2).strip()
                has_explicit = bool(m_ctor.group(1))
                constructors.append((line_no, arg_text, has_explicit))
                if arg_text in ("", "void"):
                    has_default_ctor_decl = True

        class_info[cls] = {
            "base": base,
            "start": start + 1,
            "end": end + 1,
            "members": members,
            "constructors": constructors,
            "has_default_ctor_decl": has_default_ctor_decl,
            "body_text": body_text,
        }

    return class_info


def _collect_global_vars(lines: List[str], class_ranges: List[Tuple[int, int]]) -> Set[str]:
    globals_: Set[str] = set()

    def in_class(line_no: int) -> bool:
        for s, e in class_ranges:
            if s <= line_no <= e:
                return True
        return False

    decl_pat = re.compile(r"^\s*(?:static\s+)?(?:unsigned\s+|signed\s+)?(?:char|short|int|long|float|double|bool)\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:=.*)?;\s*$")
    func_head = re.compile(r"\)\s*\{")

    for i, raw in enumerate(lines, 1):
        if in_class(i):
            continue
        s = _strip_line_comment(raw).strip()
        if not s or func_head.search(s):
            continue
        m = decl_pat.match(s)
        if m:
            globals_.add(m.group(1))
    return globals_


def _find_constructor_defs(lines: List[str], cls: str) -> List[dict]:
    defs = []
    pat = re.compile(rf"^\s*{re.escape(cls)}\s*::\s*{re.escape(cls)}\s*\(([^\)]*)\)\s*(?::\s*([^\{{]*))?\s*\{{")

    i = 0
    while i < len(lines):
        s = _strip_line_comment(lines[i])
        m = pat.match(s.strip())
        if not m:
            i += 1
            continue

        line_no = i + 1
        init_list = (m.group(2) or "").strip()

        depth = lines[i].count("{") - lines[i].count("}")
        start = i
        i += 1
        while i < len(lines) and depth > 0:
            depth += lines[i].count("{") - lines[i].count("}")
            i += 1
        end = i - 1
        body = "\n".join(_strip_line_comment(x) for x in lines[start:end + 1])

        defs.append({"line": line_no, "init_list": init_list, "body": body, "start": start + 1, "end": end + 1})

    return defs


def _scan_rules(lines: List[str], code: str, language: str, violations: List[dict], seen: Set[Tuple[int, str]]):
    classes = _collect_class_info(lines)
    class_ranges = [(info["start"], info["end"]) for info in classes.values()]
    globals_ = _collect_global_vars(lines, class_ranges)

    # R-2-2-2 / R-2-2-3
    for cls, info in classes.items():
        ctors = info["constructors"]
        has_default = info["has_default_ctor_decl"]
        if ctors and not has_default:
            _add_violation(violations, seen, info["start"], "R-2-2-2", get_code_snippet((info["start"] - 1, info["start"] - 1), code), cls)

        for ln, arg_text, has_explicit in ctors:
            args = [x.strip() for x in arg_text.split(",") if x.strip() and x.strip() != "void"]
            if len(args) == 1 and not has_explicit:
                _add_violation(violations, seen, ln, "R-2-2-3", get_code_snippet((ln - 1, ln - 1), code), cls)

    # constructor definitions based rules
    for cls, info in classes.items():
        ctor_defs = _find_constructor_defs(lines, cls)
        members = info["members"]
        base = info["base"]

        for d in ctor_defs:
            body = d["body"]
            init_list = d["init_list"]
            ln = d["line"]

            # R-2-2-1: ctor uses global variable
            for gv in globals_:
                if re.search(rf"\b{re.escape(gv)}\b", body):
                    _add_violation(violations, seen, ln, "R-2-2-1", get_code_snippet((ln - 1, ln - 1), code), gv)
                    break

            # R-2-2-4: all members initialized in each ctor (assignment or init list)
            initialized: Set[str] = set()
            for m in members:
                if re.search(rf"\b{re.escape(m)}\s*\(", init_list):
                    initialized.add(m)
                elif re.search(rf"\b{re.escape(m)}\s*=", body):
                    initialized.add(m)
            missing = sorted(list(members - initialized))
            if missing:
                _add_violation(violations, seen, ln, "R-2-2-4", get_code_snippet((ln - 1, ln - 1), code), ",".join(missing))

            # R-2-2-5: derived ctor must init direct base in init list
            if base and not re.search(rf"\b{re.escape(base)}\s*\(", init_list):
                _add_violation(violations, seen, ln, "R-2-2-5", get_code_snippet((ln - 1, ln - 1), code), f"base={base}")


def detect_cpp_gjb_6_2_violations(code: str, language: str = "cpp") -> List[dict]:
    """
    检测GJB 8114-2013中6.2（构造函数）条款的违规。

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


def analyze_cpp_gjb_6_2(code_string: str, language: str = "cpp") -> List[dict]:
    return detect_cpp_gjb_6_2_violations(code_string, language)


if __name__ == "__main__":
    test_cases = [
        (
            "cpp_basic_violations",
            "cpp",
            """
int gVar = 10;

class Base {
public:
    Base(int x) {}
};

class Foo {
public:
    Foo(int v);
private:
    int a;
    int b;
};

Foo::Foo(int v) {
    a = gVar;
}

class Book : public Base {
public:
    Book();
private:
    int id;
};

Book::Book() : id(1) {
}
""",
        ),
        (
            "cpp_compliant_sample",
            "cpp",
            """
int gVar = 10;

class Base {
public:
    Base() {}
    explicit Base(int x) { (void)x; }
};

class Foo {
public:
    Foo();
    explicit Foo(int v);
private:
    int a;
    int b;
};

Foo::Foo() : a(0), b(0) {
}

Foo::Foo(int v) : a(v), b(0) {
}

class Book : public Base {
public:
    Book();
private:
    int id;
};

Book::Book() : Base(1), id(1) {
}
""",
        ),
    ]

    for name, lang, src in test_cases:
        print("=" * 70)
        print(f"CASE: {name} ({lang})")
        results = analyze_cpp_gjb_6_2(src, lang)
        if not results:
            print("未检测到违规")
            continue
        print(f"检测到 {len(results)} 个违规")
        for item in results:
            print(
                f"line={item['line']} | rule_id={item['rule_id']} | "
                f"message={item['message']} | code_snippet={item['code_snippet'].replace(chr(10), ' ')}"
            )
