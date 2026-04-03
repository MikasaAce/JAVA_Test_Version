import re
from typing import Dict, List, Set, Tuple, Union


RULES_5_10 = [
    {"rule_id": "R-1-10-1", "message": "GJB R-1-10-1: 浮点数变量赋给整型变量必须强制转换", "severity": "高危"},
    {"rule_id": "R-1-10-2", "message": "GJB R-1-10-2: 长整数变量赋给短整数变量必须强制转换", "severity": "高危"},
    {"rule_id": "R-1-10-3", "message": "GJB R-1-10-3: double型变量赋给float型变量必须强制转换", "severity": "高危"},
    {"rule_id": "R-1-10-4", "message": "GJB R-1-10-4: 指针变量的赋值类型必须与指针变量类型一致", "severity": "高危"},
    {"rule_id": "R-1-10-5", "message": "GJB R-1-10-5: 指针量与非指针量互相赋值必须使用强制转换", "severity": "高危"},
    {"rule_id": "R-1-10-6", "message": "GJB R-1-10-6: 禁止使用无实质作用的类型转换", "severity": "中危"},
    {"rule_id": "A-1-10-1", "message": "GJB A-1-10-1: 浮点型数转换成整型数应考虑是否需要四舍五入", "severity": "建议"},
    {"rule_id": "A-1-10-2", "message": "GJB A-1-10-2: 谨慎将double型数转换成float型数", "severity": "建议"},
    {"rule_id": "A-1-10-3", "message": "GJB A-1-10-3: 谨慎将长整型数转换成短整型数", "severity": "建议"},
    {"rule_id": "A-1-10-4", "message": "GJB A-1-10-4: 谨慎将指针量赋予非指针变量或非指针量赋予指针变量", "severity": "建议"},
]

RULE_META: Dict[str, dict] = {x["rule_id"]: x for x in RULES_5_10}

INT_TYPES = {
    "char", "signed char", "unsigned char", "short", "unsigned short", "signed short",
    "int", "unsigned int", "signed int", "long", "unsigned long", "signed long",
    "long long", "unsigned long long", "signed long long",
}

SHORT_TYPES = {"char", "signed char", "unsigned char", "short", "unsigned short", "signed short"}
LONG_TYPES = {"long", "unsigned long", "signed long", "long long", "unsigned long long", "signed long long"}
FLOAT_TYPES = {"float", "double"}


def extract_rule_id(message: str) -> str:
    m = re.search(r"[RA]-\d+-\d+-\d+", message or "")
    if m:
        return m.group(0)
    return "R-1-10-UNKNOWN"


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
    if len(snippet) > 280:
        snippet = snippet[:280] + "..."
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
    message = RULE_META[rule_id]["message"]
    if suffix:
        message = f"{message} ({suffix})"
    violations.append(
        {
            "line": line,
            "code_snippet": code_snippet,
            "violation_type": "编码规范",
            "severity": RULE_META[rule_id]["severity"],
            "rule_id": rule_id,
            "message": message,
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


def _normalize_type(t: str) -> str:
    return " ".join(t.replace("const", "").replace("volatile", "").split())


def _has_explicit_cast(expr: str) -> bool:
    e = expr.strip()
    return bool(re.match(r"^\(\s*[A-Za-z_][A-Za-z0-9_\s\*]*\s*\)", e) or re.match(r"^(static_cast|reinterpret_cast|const_cast|dynamic_cast)\s*<", e))


def _leading_cast_type(expr: str) -> str:
    e = expr.strip()
    m = re.match(r"^\(\s*([A-Za-z_][A-Za-z0-9_\s\*]*)\s*\)", e)
    if m:
        return _normalize_type(m.group(1))
    m2 = re.match(r"^(?:static_cast|reinterpret_cast|const_cast|dynamic_cast)\s*<\s*([^>]+)\s*>", e)
    if m2:
        return _normalize_type(m2.group(1))
    return ""


def _collect_var_types(lines: List[str]) -> Dict[str, str]:
    var_types: Dict[str, str] = {}
    base_type_pat = r"(?:unsigned\s+long\s+long|signed\s+long\s+long|long\s+long|unsigned\s+long|signed\s+long|unsigned\s+short|signed\s+short|unsigned\s+int|signed\s+int|unsigned\s+char|signed\s+char|long|short|int|char|float|double|void)"

    for raw in lines:
        line = _strip_line_comment(raw).strip().rstrip(";")
        if not line or "(" in line:
            continue

        m_ptr = re.match(rf"^\s*({base_type_pat}(?:\s+{base_type_pat})*)\s*\*\s*([A-Za-z_][A-Za-z0-9_]*)\b", line)
        if m_ptr:
            t = _normalize_type(m_ptr.group(1)) + " *"
            var_types[m_ptr.group(2)] = t
            continue

        m_var = re.match(rf"^\s*({base_type_pat}(?:\s+{base_type_pat})*)\s+([A-Za-z_][A-Za-z0-9_]*)\b", line)
        if m_var:
            t = _normalize_type(m_var.group(1))
            var_types[m_var.group(2)] = t

    return var_types


def _is_pointer_type(t: str) -> bool:
    return t.strip().endswith("*")


def _base_pointer_type(t: str) -> str:
    return _normalize_type(t.replace("*", "").strip())


def _scan_rules(lines: List[str], code: str, language: str, violations: List[dict], seen: Set[Tuple[int, str]]):
    var_types = _collect_var_types(lines)

    for i, raw in enumerate(lines, 1):
        s = _strip_line_comment(raw)
        m_asg = re.search(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^;]+);", s)
        if not m_asg:
            continue

        lhs = m_asg.group(1)
        rhs = m_asg.group(2).strip()
        lhs_t = var_types.get(lhs, "")
        rhs_var_m = re.match(r"^\(?\s*([A-Za-z_][A-Za-z0-9_]*)\b", rhs)
        rhs_var = rhs_var_m.group(1) if rhs_var_m else ""
        rhs_t = var_types.get(rhs_var, "")
        casted = _has_explicit_cast(rhs)
        cast_type = _leading_cast_type(rhs)

        # R-1-10-1: 浮点变量 -> 整型变量必须强转
        if lhs_t in INT_TYPES and rhs_t in FLOAT_TYPES and not casted:
            _add_violation(violations, seen, i, "R-1-10-1", get_code_snippet((i - 1, i - 1), code), f"{rhs_t}->{lhs_t}")

        # R-1-10-2: 长整型 -> 短整型必须强转
        if lhs_t in SHORT_TYPES and rhs_t in LONG_TYPES and not casted:
            _add_violation(violations, seen, i, "R-1-10-2", get_code_snippet((i - 1, i - 1), code), f"{rhs_t}->{lhs_t}")

        # R-1-10-3: double -> float 必须强转
        if lhs_t == "float" and rhs_t == "double" and not casted:
            _add_violation(violations, seen, i, "R-1-10-3", get_code_snippet((i - 1, i - 1), code))

        # R-1-10-4: 指针类型赋值必须一致
        if lhs_t and rhs_t and _is_pointer_type(lhs_t) and _is_pointer_type(rhs_t):
            if _base_pointer_type(lhs_t) != _base_pointer_type(rhs_t) and not casted:
                _add_violation(violations, seen, i, "R-1-10-4", get_code_snippet((i - 1, i - 1), code), f"{rhs_t}->{lhs_t}")

        # R-1-10-5: 指针与非指针互赋必须强转
        if lhs_t and rhs_t and _is_pointer_type(lhs_t) != _is_pointer_type(rhs_t):
            if not casted:
                _add_violation(violations, seen, i, "R-1-10-5", get_code_snippet((i - 1, i - 1), code), f"{rhs_t}->{lhs_t}")
            else:
                _add_violation(violations, seen, i, "A-1-10-4", get_code_snippet((i - 1, i - 1), code), f"{rhs_t}->{lhs_t}")

        # R-1-10-6: 无实质作用类型转换
        if casted and rhs_var and cast_type:
            rhs_raw_t = _normalize_type(rhs_t)
            if rhs_raw_t and _normalize_type(cast_type) == rhs_raw_t:
                _add_violation(violations, seen, i, "R-1-10-6", get_code_snippet((i - 1, i - 1), code), cast_type)

        # A-1-10-1: 浮点转整型建议考虑四舍五入
        if casted and lhs_t in INT_TYPES and (rhs_t in FLOAT_TYPES or re.search(r"\d+\.\d+", rhs)):
            if "0.5" not in rhs and "Round" not in rhs and "round" not in rhs:
                _add_violation(violations, seen, i, "A-1-10-1", get_code_snippet((i - 1, i - 1), code), lhs)

        # A-1-10-2: double 转 float 建议
        if casted and lhs_t == "float" and (rhs_t == "double" or "double" in cast_type):
            _add_violation(violations, seen, i, "A-1-10-2", get_code_snippet((i - 1, i - 1), code), lhs)

        # A-1-10-3: 长整转短整建议
        if casted and lhs_t in SHORT_TYPES and (rhs_t in LONG_TYPES or "long" in cast_type):
            _add_violation(violations, seen, i, "A-1-10-3", get_code_snippet((i - 1, i - 1), code), lhs)


def detect_c_cpp_gjb_5_10_violations(code: str, language: str = "cpp") -> List[dict]:
    """
    检测GJB 8114-2013中5.10（类型转换）条款的违规。

    Args:
        code: C/C++源码字符串
        language: 语言类型，支持"c"和"cpp"

    Returns:
        list[dict]: 违规列表
    """
    if language not in ("c", "cpp"):
        return []

    lines = code.split("\n")
    violations: List[dict] = []
    seen: Set[Tuple[int, str]] = set()

    _scan_rules(lines, code, language, violations, seen)

    return sorted(violations, key=lambda x: (x["line"], x["rule_id"]))


def analyze_c_cpp_gjb_5_10(code_string: str, language: str = "cpp") -> List[dict]:
    return detect_c_cpp_gjb_5_10_violations(code_string, language)


if __name__ == "__main__":
    test_cases = [
        (
            "c_basic_violations",
            "c",
            """
int main(void){
    int ix = 0;
    float fx = 1.85;
    ix = fx;

    short sVar = 0;
    long lVar = 0;
    sVar = lVar;

    double dData = 0.0;
    float fData = 0.0f;
    fData = dData;

    unsigned int *ptr = 0;
    unsigned short *sp = 0;
    ptr = sp;

    unsigned int adr = 0;
    ptr = adr;

    unsigned int sx = 10;
    sx = (unsigned int)sx;

    return 0;
}
""",
        ),
        (
            "cpp_compliant_sample",
            "cpp",
            """
#define Round(x) ((x)>=0?(int)((x)+0.5):(int)((x)-0.5))
int main(){
    int ix = 0;
    float fx = 1.85f;
    ix = Round(fx);

    short sVar = 0;
    long lVar = 0;
    sVar = (short)lVar;

    double dData = 0.0;
    float fData = 0.0f;
    fData = (float)dData;

    unsigned int *ptr = 0;
    unsigned int *up = 0;
    ptr = up;

    return 0;
}
""",
        ),
    ]

    for name, lang, src in test_cases:
        print("=" * 70)
        print(f"CASE: {name} ({lang})")
        results = analyze_c_cpp_gjb_5_10(src, lang)
        if not results:
            print("未检测到违规")
            continue
        print(f"检测到 {len(results)} 个违规")
        for item in results:
            print(
                f"line={item['line']} | rule_id={item['rule_id']} | "
                f"message={item['message']} | code_snippet={item['code_snippet'].replace(chr(10), ' ')}"
            )
