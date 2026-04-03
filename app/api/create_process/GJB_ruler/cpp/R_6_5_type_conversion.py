import re
from typing import Dict, List, Set, Tuple, Union


RULES_6_5 = [
    {"rule_id": "R-2-5-1", "message": "GJB R-2-5-1: 禁止将不相关的指针类型强制转换为对象指针类型", "severity": "高危"},
    {"rule_id": "R-2-5-2", "message": "GJB R-2-5-2: 指针或引用类型转换中禁止移除const或volatile属性", "severity": "高危"},
    {"rule_id": "A-2-5-1", "message": "GJB A-2-5-1: 建议使用C++类型转换操作符，避免C风格类型转换", "severity": "建议"},
]

RULE_META: Dict[str, dict] = {x["rule_id"]: x for x in RULES_6_5}

BUILTIN_TYPES = {
    "char", "short", "int", "long", "float", "double", "bool", "void",
    "unsigned", "signed", "size_t", "wchar_t",
}



def extract_rule_id(message: str) -> str:
    m = re.search(r"[RA]-\d+-\d+-\d+", message or "")
    if m:
        return m.group(0)
    return "R-2-5-UNKNOWN"


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


def _normalize_type(t: str) -> str:
    return " ".join(t.split())


def _collect_var_types(lines: List[str]) -> Dict[str, str]:
    var_types: Dict[str, str] = {}

    # 支持 class/struct 名作为类型；支持 const/volatile 与 * / &
    decl_pat = re.compile(
        r"^\s*((?:const\s+|volatile\s+)?(?:[A-Za-z_][A-Za-z0-9_:<>]*)(?:\s+[A-Za-z_][A-Za-z0-9_:<>]*)*(?:\s*[*&])?)\s+([A-Za-z_][A-Za-z0-9_]*)\b"
    )

    for raw in lines:
        s = _strip_line_comment(raw).strip().rstrip(";")
        if not s:
            continue
        # 过滤函数声明/定义头，保留类似 "const C c = C()" 的变量初始化。
        if re.match(r"^\s*[A-Za-z_][A-Za-z0-9_:\<\>\s*&]*\s+[A-Za-z_][A-Za-z0-9_]*\s*\([^\)]*\)\s*\{?$", s):
            continue
        m = decl_pat.match(s)
        if not m:
            continue
        t = _normalize_type(m.group(1))
        n = m.group(2)
        var_types[n] = t

    return var_types


def _base_type_no_cv(t: str) -> str:
    tt = t.replace("const", "").replace("volatile", "").replace("*", "").replace("&", "")
    return _normalize_type(tt)


def _is_object_type(base_t: str) -> bool:
    if base_t in BUILTIN_TYPES:
        return False
    if base_t.startswith("unsigned") or base_t.startswith("signed"):
        return False
    return bool(base_t)


def _has_const_or_volatile(t: str) -> bool:
    return ("const" in t) or ("volatile" in t)


def _scan_rules(lines: List[str], code: str, language: str, violations: List[dict], seen: Set[Tuple[int, str]]):
    var_types = _collect_var_types(lines)

    cpp_cast_pat = re.compile(r"\b(reinterpret_cast|static_cast|const_cast|dynamic_cast)\s*<\s*([^>]+)\s*>\s*\(\s*([^\)]+)\s*\)")
    c_cast_pat = re.compile(r"\(\s*([A-Za-z_][A-Za-z0-9_\s:*&<>]*)\s*\)\s*([A-Za-z_][A-Za-z0-9_]*)")

    for i, raw in enumerate(lines, 1):
        s = _strip_line_comment(raw)
        if not s.strip():
            continue

        # C++ 风格 cast
        for m in cpp_cast_pat.finditer(s):
            cast_kind = m.group(1)
            target_t = _normalize_type(m.group(2))
            source_expr = m.group(3).strip()
            source_expr_norm = source_expr.lstrip("&* ")
            src_var_m = re.match(r"([A-Za-z_][A-Za-z0-9_]*)", source_expr_norm)
            src_var = src_var_m.group(1) if src_var_m else ""
            source_t = var_types.get(src_var, "")

            target_base = _base_type_no_cv(target_t)
            source_base = _base_type_no_cv(source_t)

            # R-2-5-1: 不相关指针 -> 对象指针
            if "*" in target_t and source_t and "*" in source_t:
                if cast_kind in {"reinterpret_cast", "static_cast", "dynamic_cast"}:
                    if _is_object_type(target_base) and _is_object_type(source_base) and target_base != source_base:
                        _add_violation(
                            violations,
                            seen,
                            i,
                            "R-2-5-1",
                            get_code_snippet((i - 1, i - 1), code),
                            f"{source_base}*->{target_base}*",
                        )

            # R-2-5-2: 去除const/volatile
            if cast_kind == "const_cast" and source_t:
                if _has_const_or_volatile(source_t) and (not _has_const_or_volatile(target_t)):
                    _add_violation(
                        violations,
                        seen,
                        i,
                        "R-2-5-2",
                        get_code_snippet((i - 1, i - 1), code),
                        f"{source_t}->{target_t}",
                    )

        # C 风格 cast：建议项 A-2-5-1
        # 仅在赋值/调用参数语境中提示，尽量避免声明语句误报
        if "(" in s and ")" in s and re.search(r"=|,|\(|\)", s):
            for m in c_cast_pat.finditer(s):
                target_t = _normalize_type(m.group(1))
                src_var = m.group(2)

                if re.match(r"^(if|for|while|switch|return)$", src_var):
                    continue
                if re.match(r"^(?:unsigned|signed|char|short|int|long|float|double|bool|void)$", target_t):
                    continue

                _add_violation(
                    violations,
                    seen,
                    i,
                    "A-2-5-1",
                    get_code_snippet((i - 1, i - 1), code),
                    target_t,
                )

                source_t = var_types.get(src_var, "")
                source_base = _base_type_no_cv(source_t)
                target_base = _base_type_no_cv(target_t)

                # R-2-5-1: C风格不相关指针强转为对象指针
                if "*" in target_t and source_t and "*" in source_t and _is_object_type(target_base) and _is_object_type(source_base):
                    if source_base != target_base:
                        _add_violation(
                            violations,
                            seen,
                            i,
                            "R-2-5-1",
                            get_code_snippet((i - 1, i - 1), code),
                            f"{source_base}*->{target_base}*",
                        )

                # R-2-5-2: C风格去掉const/volatile
                if source_t and _has_const_or_volatile(source_t) and (not _has_const_or_volatile(target_t)):
                    if "*" in target_t or "&" in target_t:
                        _add_violation(
                            violations,
                            seen,
                            i,
                            "R-2-5-2",
                            get_code_snippet((i - 1, i - 1), code),
                            f"{source_t}->{target_t}",
                        )


def detect_cpp_gjb_6_5_violations(code: str, language: str = "cpp") -> List[dict]:
    """
    检测GJB 8114-2013中6.5（类型转换）条款的违规。

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

    _scan_rules(lines, code, language, violations, seen)

    return sorted(violations, key=lambda x: (x["line"], x["rule_id"]))


def analyze_cpp_gjb_6_5(code_string: str, language: str = "cpp") -> List[dict]:
    return detect_cpp_gjb_6_5_violations(code_string, language)


if __name__ == "__main__":
    test_cases = [
        (
            "cpp_basic_violations",
            "cpp",
            """
struct S { int i; int j; int k; };
class C {
public:
    int i; int j; int k;
};

int main(){
    S* s = new S;
    C* c = reinterpret_cast<C*>(s);  // R-2-5-1

    const C c1 = C();
    C* c2 = const_cast<C*>(&c1);     // R-2-5-2
    C& c3 = (C&)c1;                  // R-2-5-2 + A-2-5-1

    return 0;
}
""",
        ),
        (
            "cpp_compliant_sample",
            "cpp",
            """
class C { public: int i; };

int main(){
    const C c1 = C();
    const C* p = &c1;

    // 使用C++风格转换且不移除const
    const C* p2 = static_cast<const C*>(p);
    (void)p2;

    return 0;
}
""",
        ),
    ]

    for name, lang, src in test_cases:
        print("=" * 70)
        print(f"CASE: {name} ({lang})")
        results = analyze_cpp_gjb_6_5(src, lang)
        if not results:
            print("未检测到违规")
            continue
        print(f"检测到 {len(results)} 个违规")
        for item in results:
            print(
                f"line={item['line']} | rule_id={item['rule_id']} | "
                f"message={item['message']} | code_snippet={item['code_snippet'].replace(chr(10), ' ')}"
            )
