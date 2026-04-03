import re
from typing import Dict, List, Set, Tuple, Union


RULES_6_1 = [
    {"rule_id": "R-2-1-1", "message": "GJB R-2-1-1: 含有动态分配成员的类必须编写拷贝构造函数并重载赋值操作符", "severity": "高危"},
    {"rule_id": "R-2-1-2", "message": "GJB R-2-1-2: 虚拟基类指针转换为派生类指针必须使用dynamic_cast", "severity": "高危"},
    {"rule_id": "R-2-1-3", "message": "GJB R-2-1-3: 菱形层次结构中对基类派生必须使用virtual说明", "severity": "高危"},
    {"rule_id": "R-2-1-4", "message": "GJB R-2-1-4: 抽象类中的复制操作符重载必须是protected或private", "severity": "高危"},
    {"rule_id": "A-2-1-1", "message": "GJB A-2-1-1: 谨慎使用派生类由虚拟基类派生", "severity": "建议"},
    {"rule_id": "A-2-1-2", "message": "GJB A-2-1-2: 谨慎使用内联函数", "severity": "建议"},
]

RULE_META: Dict[str, dict] = {x["rule_id"]: x for x in RULES_6_1}


def extract_rule_id(message: str) -> str:
    m = re.search(r"[RA]-\d+-\d+-\d+", message or "")
    if m:
        return m.group(0)
    return "R-2-1-UNKNOWN"


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


def _collect_class_blocks(lines: List[str]) -> Dict[str, Tuple[int, int, List[str]]]:
    class_blocks: Dict[str, Tuple[int, int, List[str]]] = {}
    class_pat = re.compile(r"^\s*class\s+([A-Za-z_][A-Za-z0-9_]*)\b([^\{;]*)\{?")

    i = 0
    while i < len(lines):
        line = _strip_line_comment(lines[i])
        m = class_pat.match(line)
        if not m:
            i += 1
            continue

        name = m.group(1)
        start = i

        # 定位类体开始
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

        class_blocks[name] = (start + 1, end + 1, lines[start:end + 1])

    return class_blocks


def _scan_r211(lines: List[str], code: str, violations: List[dict], seen: Set[Tuple[int, str]]):
    classes = _collect_class_blocks(lines)

    for cls, (s, _e, body_lines) in classes.items():
        body = "\n".join(_strip_line_comment(x) for x in body_lines)

        has_dynamic_member = bool(re.search(r"\b[A-Za-z_][A-Za-z0-9_]*\s*\*\s*[A-Za-z_][A-Za-z0-9_]*\s*;", body))
        uses_new = bool(re.search(rf"\b{re.escape(cls)}\s*::.*\bnew\b", code)) or bool(re.search(r"\bnew\b", body))
        if not (has_dynamic_member and uses_new):
            continue

        has_copy_ctor = bool(re.search(rf"\b{re.escape(cls)}\s*\(\s*const\s+{re.escape(cls)}\s*&", body)) or bool(re.search(rf"\b{re.escape(cls)}\s*::\s*{re.escape(cls)}\s*\(\s*const\s+{re.escape(cls)}\s*&", code))
        has_assign = bool(re.search(r"operator\s*=\s*\(", body)) or bool(re.search(rf"{re.escape(cls)}\s*&\s*{re.escape(cls)}\s*::\s*operator\s*=", code))

        if not (has_copy_ctor and has_assign):
            _add_violation(violations, seen, s, "R-2-1-1", get_code_snippet((s - 1, s - 1), code), cls)


def _scan_r212(lines: List[str], code: str, violations: List[dict], seen: Set[Tuple[int, str]]):
    for i, raw in enumerate(lines, 1):
        s = _strip_line_comment(raw)
        if re.search(r"\breinterpret_cast\s*<\s*[A-Za-z_][A-Za-z0-9_]*\s*\*\s*>\s*\(", s):
            _add_violation(violations, seen, i, "R-2-1-2", get_code_snippet((i - 1, i - 1), code), "reinterpret_cast-to-derived-pointer")
        if re.search(r"\bstatic_cast\s*<\s*[A-Za-z_][A-Za-z0-9_]*\s*\*\s*>\s*\(", s) and "dynamic_cast" not in s:
            _add_violation(violations, seen, i, "R-2-1-2", get_code_snippet((i - 1, i - 1), code), "static_cast-to-derived-pointer")


def _scan_r213(lines: List[str], code: str, violations: List[dict], seen: Set[Tuple[int, str]]):
    # 近似识别菱形：同一基类A被B1/B2继承，再被D多继承。
    direct_inherit: Dict[str, List[Tuple[str, bool, int]]] = {}
    class_inherit_pat = re.compile(r"^\s*class\s+([A-Za-z_][A-Za-z0-9_]*)\s*:\s*public\s+(virtual\s+)?([A-Za-z_][A-Za-z0-9_]*)")

    for i, raw in enumerate(lines, 1):
        s = _strip_line_comment(raw)
        m = class_inherit_pat.match(s)
        if not m:
            continue
        c = m.group(1)
        is_virtual = bool(m.group(2))
        b = m.group(3)
        direct_inherit.setdefault(c, []).append((b, is_virtual, i))

    # 找到同一个基类被两个派生类继承且均非virtual的情况
    base_to_derived: Dict[str, List[Tuple[str, bool, int]]] = {}
    for d, bases in direct_inherit.items():
        for b, is_v, ln in bases:
            base_to_derived.setdefault(b, []).append((d, is_v, ln))

    for b, ds in base_to_derived.items():
        if len(ds) < 2:
            continue
        non_virtual = [x for x in ds if not x[1]]
        if len(non_virtual) >= 2:
            # 若存在另一个类多继承这两个派生类，认为接近菱形
            for i, raw in enumerate(lines, 1):
                s = _strip_line_comment(raw)
                names = [x[0] for x in non_virtual]
                if len(names) >= 2 and re.search(rf"class\s+[A-Za-z_][A-Za-z0-9_]*\s*:\s*public\s+{re.escape(names[0])}\s*,\s*public\s+{re.escape(names[1])}", s):
                    for _, _, ln in non_virtual[:2]:
                        _add_violation(violations, seen, ln, "R-2-1-3", get_code_snippet((ln - 1, ln - 1), code), b)
                    break

        if len(ds) >= 1 and any(x[1] for x in ds):
            # A-2-1-1: 使用虚拟基类给建议
            ln = ds[0][2]
            _add_violation(violations, seen, ln, "A-2-1-1", get_code_snippet((ln - 1, ln - 1), code), b)


def _scan_r214(lines: List[str], code: str, violations: List[dict], seen: Set[Tuple[int, str]]):
    classes = _collect_class_blocks(lines)
    for cls, (s, _e, body_lines) in classes.items():
        body = "\n".join(_strip_line_comment(x) for x in body_lines)
        is_abstract = bool(re.search(r"virtual\s+[^;=]+\s*=\s*0\s*;", body))
        if not is_abstract:
            continue

        # 若抽象类在public下声明operator=，则违背。
        current_access = "private"  # class默认private
        for idx, raw in enumerate(body_lines):
            line = _strip_line_comment(raw).strip()
            if re.match(r"public\s*:", line):
                current_access = "public"
                continue
            if re.match(r"protected\s*:", line):
                current_access = "protected"
                continue
            if re.match(r"private\s*:", line):
                current_access = "private"
                continue
            if "operator=" in line and current_access == "public":
                _add_violation(violations, seen, s + idx, "R-2-1-4", get_code_snippet((s + idx - 1, s + idx - 1), code), cls)


def _scan_a212(lines: List[str], code: str, violations: List[dict], seen: Set[Tuple[int, str]]):
    for i, raw in enumerate(lines, 1):
        s = _strip_line_comment(raw)
        if re.search(r"\binline\b\s+", s):
            _add_violation(violations, seen, i, "A-2-1-2", get_code_snippet((i - 1, i - 1), code))


def detect_cpp_gjb_6_1_violations(code: str, language: str = "cpp") -> List[dict]:
    """
    检测GJB 8114-2013中6.1（类与对象）条款的违规。

    Args:
        code: C++源码字符串
        language: 语言类型，支持"cpp"或"c++"

    Returns:
        list[dict]: 违规列表
    """
    if language not in ("cpp", "c++"):
        return []

    lines = code.split("\n")
    violations: List[dict] = []
    seen: Set[Tuple[int, str]] = set()

    _scan_r211(lines, code, violations, seen)
    _scan_r212(lines, code, violations, seen)
    _scan_r213(lines, code, violations, seen)
    _scan_r214(lines, code, violations, seen)
    _scan_a212(lines, code, violations, seen)

    return sorted(violations, key=lambda x: (x["line"], x["rule_id"]))


def analyze_cpp_gjb_6_1(code_string: str, language: str = "cpp") -> List[dict]:
    return detect_cpp_gjb_6_1_violations(code_string, language)


if __name__ == "__main__":
    test_cases = [
        (
            "cpp_basic_violations",
            "cpp",
            """
class B { public: virtual ~B(){} virtual void f() = 0; B& operator=(const B& rhs); };
class D: public virtual B {};

class A {
public:
    A(){ str = new char[8]; }
    ~A(){ delete[] str; }
private:
    char *str;
};

class B1: public A {};
class B2: public A {};
class DD: public B1, public B2 {};

int main(){
    B* pb = 0;
    D* pd = reinterpret_cast<D*>(pb);
    return 0;
}

inline int addv(int a, int b){ return a + b; }
""",
        ),
        (
            "cpp_compliant_sample",
            "cpp",
            """
class B {
public:
    virtual ~B(){}
    virtual void f() = 0;
protected:
    B& operator=(const B& rhs);
};

class D: public virtual B {};

class A {
public:
    A(){ str = new char[8]; }
    A(const A& other){ str = new char[8]; (void)other; }
    A& operator=(const A& rhs){ (void)rhs; return *this; }
    ~A(){ delete[] str; }
private:
    char *str;
};

class B1: public virtual A {};
class B2: public virtual A {};
class DD: public B1, public B2 {};

int main(){
    D d;
    B* pb = &d;
    D* pd = dynamic_cast<D*>(pb);
    (void)pd;
    return 0;
}
""",
        ),
    ]

    for name, lang, src in test_cases:
        print("=" * 70)
        print(f"CASE: {name} ({lang})")
        results = analyze_cpp_gjb_6_1(src, lang)
        if not results:
            print("未检测到违规")
            continue
        print(f"检测到 {len(results)} 个违规")
        for item in results:
            print(
                f"line={item['line']} | rule_id={item['rule_id']} | "
                f"message={item['message']} | code_snippet={item['code_snippet'].replace(chr(10), ' ')}"
            )
