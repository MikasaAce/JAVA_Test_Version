import re
from typing import Dict, List, Set, Tuple, Union


RULES_6_7 = [
    {"rule_id": "R-2-7-1", "message": "GJB R-2-7-1: 函数中固定长度数组变量的传递必须使用引用方式", "severity": "高危"},
    {"rule_id": "R-2-7-2", "message": "GJB R-2-7-2: 定义为const的成员函数禁止返回非const的指针或引用", "severity": "高危"},
    {"rule_id": "R-2-7-3", "message": "GJB R-2-7-3: 禁止可导致非资源性对象数据被外部修改的成员函数返回", "severity": "高危"},
    {"rule_id": "A-2-7-1", "message": "GJB A-2-7-1: 类中函数的实现代码避免在类定义的内部定义", "severity": "建议"},
    {"rule_id": "A-2-7-2", "message": "GJB A-2-7-2: 函数中的指针或引用参数如果不是修改项建议使用const说明", "severity": "建议"},
]

RULE_META: Dict[str, dict] = {x["rule_id"]: x for x in RULES_6_7}


def extract_rule_id(message: str) -> str:
    m = re.search(r"[RA]-\d+-\d+-\d+", message or "")
    if m:
        return m.group(0)
    return "R-2-7-UNKNOWN"


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
        if ch in ('\"', "'"):
            if not in_str:
                in_str = True
                q = ch
            elif i > 0 and line[i - 1] != "\\" and ch == q:
                in_str = False
                q = ""
        out.append(ch)
        i += 1
    return "".join(out)


def _split_params(params: str) -> List[str]:
    parts: List[str] = []
    cur = []
    depth = 0
    for ch in params:
        if ch == "<":
            depth += 1
        elif ch == ">" and depth > 0:
            depth -= 1
        if ch == "," and depth == 0:
            p = "".join(cur).strip()
            if p:
                parts.append(p)
            cur = []
            continue
        cur.append(ch)
    p = "".join(cur).strip()
    if p:
        parts.append(p)
    return parts


def _extract_param_name(param: str) -> str:
    p = param.strip()
    p = re.sub(r"=.*$", "", p).strip()
    m = re.search(r"([A-Za-z_][A-Za-z0-9_]*)\s*(?:\[[^\]]*\])?$", p)
    return m.group(1) if m else ""


def _is_nonconst_ptr_or_ref(type_text: str) -> bool:
    t = " ".join(type_text.split())
    if "*" not in t and "&" not in t:
        return False
    return "const" not in t


def _collect_fixed_arrays(lines: List[str]) -> Set[str]:
    arr_vars: Set[str] = set()
    pat = re.compile(r"\b[A-Za-z_][A-Za-z0-9_:\s<>\*&]*\b([A-Za-z_][A-Za-z0-9_]*)\s*\[\s*\d+\s*\]")
    for raw in lines:
        s = _strip_line_comment(raw)
        m = pat.search(s)
        if m:
            arr_vars.add(m.group(1))
    return arr_vars


def _scan_rules(lines: List[str], code: str, language: str, violations: List[dict], seen: Set[Tuple[int, str]]):
    function_params: Dict[str, List[str]] = {}
    fixed_arrays = _collect_fixed_arrays(lines)

    class_depth = 0
    in_class = False
    class_block_depth = 0

    for i, raw in enumerate(lines, 1):
        s = _strip_line_comment(raw)
        st = s.strip()
        if not st:
            continue
        st_norm = re.sub(r"([*&])([A-Za-z_])", r"\1 \2", st)

        if re.search(r"^\s*class\s+[A-Za-z_][A-Za-z0-9_]*", s):
            in_class = True

        if in_class:
            class_block_depth += s.count("{") - s.count("}")
            if class_block_depth <= 0 and "};" in s:
                in_class = False
                class_block_depth = 0

        sig_m = re.match(
            r"^\s*([A-Za-z_][A-Za-z0-9_:\s<>\*&~]*)\s+([A-Za-z_][A-Za-z0-9_:]*)\s*\(([^\)]*)\)\s*(const)?\b",
            st_norm,
        )
        if not sig_m:
            sig_m = re.match(
                r"^\s*([A-Za-z_][A-Za-z0-9_:\s<>\*&~]*)\s+([A-Za-z_][A-Za-z0-9_:]*)\s*\(([^\)]*)\)",
                st_norm,
            )
        if not sig_m:
            continue

        ret_t = " ".join(sig_m.group(1).split())
        fname = sig_m.group(2)
        params = sig_m.group(3).strip()
        is_const_member = bool(sig_m.group(4)) if (sig_m.lastindex or 0) >= 4 else False
        tail = "{" if "{" in st else (";" if ";" in st else "")
        param_list = _split_params(params)

        # 记录函数参数用于调用点分析（R-2-7-1）
        pure_name = fname.split("::")[-1]
        function_params[pure_name] = param_list

        # R-2-7-1: 固定长度数组参数必须引用
        for p in param_list:
            if re.search(r"\[[^\]]*\d+[^\]]*\]", p) and "&" not in p:
                _add_violation(
                    violations,
                    seen,
                    i,
                    "R-2-7-1",
                    get_code_snippet((i - 1, i - 1), code),
                    p.strip(),
                )

        # R-2-7-2: const成员函数返回非const指针/引用
        if is_const_member and _is_nonconst_ptr_or_ref(ret_t):
            _add_violation(
                violations,
                seen,
                i,
                "R-2-7-2",
                get_code_snippet((i - 1, i - 1), code),
                f"{ret_t} {fname}",
            )

        # R-2-7-3: 返回可写引用导致对象状态可被外部修改
        if ("::" in fname or in_class) and "&" in ret_t and "const" not in ret_t:
            _add_violation(
                violations,
                seen,
                i,
                "R-2-7-3",
                get_code_snippet((i - 1, i - 1), code),
                f"{ret_t} {fname}",
            )

        # A-2-7-1: 类内实现函数体
        if in_class and tail == "{" and re.search(r"\([^\)]*\)\s*(?:const\s*)?\{", st):
            _add_violation(
                violations,
                seen,
                i,
                "A-2-7-1",
                get_code_snippet((i - 1, i - 1), code),
                fname,
            )

    # R-2-7-1: 固定长度数组实参传给指针形参
    call_pat = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(([^\)]*)\)")
    for i, raw in enumerate(lines, 1):
        s = _strip_line_comment(raw)
        for m in call_pat.finditer(s):
            fn = m.group(1)
            args = [x.strip() for x in _split_params(m.group(2))]
            if fn not in function_params:
                continue
            params = function_params[fn]
            for idx, arg in enumerate(args):
                if idx >= len(params):
                    break
                if arg not in fixed_arrays:
                    continue
                ptxt = params[idx]
                if "*" in ptxt and "&" not in ptxt:
                    _add_violation(
                        violations,
                        seen,
                        i,
                        "R-2-7-1",
                        get_code_snippet((i - 1, i - 1), code),
                        f"{fn}({arg})",
                    )

    # A-2-7-2: 指针/引用参数未修改可加const
    i = 0
    sig_with_body = re.compile(
        r"^\s*([A-Za-z_][A-Za-z0-9_:\s<>\*&~]*)\s+([A-Za-z_][A-Za-z0-9_:]*)\s*\(([^\)]*)\)\s*(?:const\s*)?\{"
    )
    while i < len(lines):
        s = _strip_line_comment(lines[i])
        m = sig_with_body.match(s.strip())
        if not m:
            i += 1
            continue

        params = _split_params(m.group(3))
        start_line = i + 1
        depth = lines[i].count("{") - lines[i].count("}")
        j = i + 1
        body_parts = []
        if "{" in lines[i]:
            body_after_open = lines[i].split("{", 1)[1]
            if "}" in body_after_open:
                body_parts.append(_strip_line_comment(body_after_open.split("}", 1)[0]))
            else:
                body_parts.append(_strip_line_comment(body_after_open))
        while j < len(lines) and depth > 0:
            body_parts.append(_strip_line_comment(lines[j]))
            depth += lines[j].count("{") - lines[j].count("}")
            j += 1
        body = "\n".join(body_parts)

        for p in params:
            name = _extract_param_name(p)
            if not name:
                continue
            if not _is_nonconst_ptr_or_ref(p):
                continue

            modified = False
            modify_patterns = [
                rf"\*\s*{name}\s*=",
                rf"\b{name}\s*\[[^\]]*\]\s*=",
                rf"\b{name}\s*(?:\+\+|--|[+\-*/%]?=)",
                rf"(?:\+\+|--)\s*{name}\b",
            ]
            for mp in modify_patterns:
                if re.search(mp, body):
                    modified = True
                    break

            if not modified:
                _add_violation(
                    violations,
                    seen,
                    start_line,
                    "A-2-7-2",
                    get_code_snippet((start_line - 1, start_line - 1), code),
                    p.strip(),
                )

        i = max(j, i + 1)


def detect_cpp_gjb_6_7_violations(code: str, language: str = "cpp") -> List[dict]:
    """
    检测GJB 8114-2013中6.7（函数定义与使用）条款的违规。

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


def analyze_cpp_gjb_6_7(code_string: str, language: str = "cpp") -> List[dict]:
    return detect_cpp_gjb_6_7_violations(code_string, language)


if __name__ == "__main__":
    test_cases = [
        (
            "cpp_basic_violations",
            "cpp",
            """
class Foo {
public:
    void SetVar(int var) { a = var; }   // A-2-7-1
    int *get_b(void) const;             // R-2-7-2
private:
    int a;
};

int *Foo::get_b(void) const { return 0; }

class A {
public:
    int &get_n(void);
private:
    int n;
};

int &A::get_n(void) { return n; }       // R-2-7-3

void fun1(int p[10]) { p[0] = 1; }      // R-2-7-1
void fun2(int *p) { p[0] = 1; }         // R-2-7-1 when called by fixed array

int read_only(int *p) { return p[0]; }  // A-2-7-2

int main() {
    int a[10] = {0};
    fun1(a);
    fun2(a);
    return read_only(a);
}
""",
        ),
        (
            "cpp_compliant_sample",
            "cpp",
            """
class Foo {
public:
    void SetVar(int var);
    const int *get_b(void) const;
private:
    int a;
    int b;
};

void Foo::SetVar(int var) { a = var; }
const int *Foo::get_b(void) const { return &b; }

class A {
public:
    int get_n(void);
private:
    int n;
};

int A::get_n(void) { return n; }

void fun(int (&p)[10]) { p[0] = 1; }
int read_only(const int *p) { return p[0]; }

int main() {
    int a[10] = {0};
    fun(a);
    return read_only(a);
}
""",
        ),
    ]

    for name, lang, src in test_cases:
        print("=" * 70)
        print(f"CASE: {name} ({lang})")
        results = analyze_cpp_gjb_6_7(src, lang)
        if not results:
            print("未检测到违规")
            continue
        print(f"检测到 {len(results)} 个违规")
        for item in results:
            print(
                f"line={item['line']} | rule_id={item['rule_id']} | "
                f"message={item['message']} | code_snippet={item['code_snippet'].replace(chr(10), ' ')}"
            )