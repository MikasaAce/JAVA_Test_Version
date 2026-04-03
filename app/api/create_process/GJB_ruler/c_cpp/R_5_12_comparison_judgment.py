import re
from typing import Dict, List, Set, Tuple, Union


RULES_5_12 = [
    {"rule_id": "R-1-12-1", "message": "GJB R-1-12-1: 禁止对逻辑量进行大于或小于的逻辑比较", "severity": "高危"},
    {"rule_id": "R-1-12-2", "message": "GJB R-1-12-2: 禁止对指针进行大于或小于的逻辑比较", "severity": "高危"},
    {"rule_id": "R-1-12-3", "message": "GJB R-1-12-3: 禁止对浮点数进行是否相等的比较", "severity": "高危"},
    {"rule_id": "R-1-12-4", "message": "GJB R-1-12-4: 禁止对无符号数进行大于等于零或小于零的比较", "severity": "高危"},
    {"rule_id": "R-1-12-5", "message": "GJB R-1-12-5: 禁止无符号数与有符号数之间的直接比较", "severity": "高危"},
    {"rule_id": "A-1-12-1", "message": "GJB A-1-12-1: 与常数进行是否相等判别时建议常数在左变量在右", "severity": "建议"},
]

RULE_META: Dict[str, dict] = {x["rule_id"]: x for x in RULES_5_12}

SIGNED_TYPES = {
    "char", "short", "int", "long", "long long", "signed char", "signed short", "signed int", "signed long", "signed long long",
}
UNSIGNED_TYPES = {
    "unsigned char", "unsigned short", "unsigned int", "unsigned long", "unsigned long long", "unsigned",
}
FLOAT_TYPES = {"float", "double"}
BOOL_TYPES = {"bool"}


def extract_rule_id(message: str) -> str:
    m = re.search(r"[RA]-\d+-\d+-\d+", message or "")
    if m:
        return m.group(0)
    return "R-1-12-UNKNOWN"


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


def _normalize_type(t: str) -> str:
    return " ".join(t.replace("const", "").replace("volatile", "").split())


def _collect_var_types(lines: List[str]) -> Dict[str, str]:
    var_types: Dict[str, str] = {}
    typedef_bool_alias: Set[str] = {"bool"}

    base = (
        r"unsigned\s+long\s+long|signed\s+long\s+long|long\s+long|unsigned\s+long|signed\s+long|"
        r"unsigned\s+int|signed\s+int|unsigned\s+short|signed\s+short|unsigned\s+char|signed\s+char|"
        r"unsigned|signed|long|short|int|char|float|double|bool"
    )

    typedef_pat = re.compile(rf"^\s*typedef\s+({base}(?:\s+{base})*)\s+([A-Za-z_][A-Za-z0-9_]*)\s*;\s*$")
    decl_pat = re.compile(rf"^\s*({base}(?:\s+{base})*|[A-Za-z_][A-Za-z0-9_]*)\s+(.+);\s*$")

    for raw in lines:
        line = _strip_line_comment(raw).strip()
        if not line:
            continue

        mtd = typedef_pat.match(line)
        if mtd:
            lhs_t = _normalize_type(mtd.group(1))
            alias = mtd.group(2)
            if "unsigned" in lhs_t and "int" in lhs_t:
                # 支持用户用 typedef unsigned int bool;
                typedef_bool_alias.add(alias)
            continue

        m = decl_pat.match(line)
        if not m:
            continue

        head_t = _normalize_type(m.group(1))
        if head_t not in typedef_bool_alias and not re.match(rf"^(?:{base})$", head_t):
            continue

        tail = m.group(2)
        chunks = [x.strip() for x in tail.split(",") if x.strip()]
        for c in chunks:
            if "(" in c and ")" in c:
                continue
            ptr = "*" in c.split("=", 1)[0]
            nm = re.match(r"\*?\s*([A-Za-z_][A-Za-z0-9_]*)", c)
            if not nm:
                continue
            n = nm.group(1)
            t = "bool" if head_t in typedef_bool_alias else head_t
            if ptr:
                t = t + " *"
            var_types[n] = t

    return var_types


def _is_float_expr(expr: str, var_types: Dict[str, str]) -> bool:
    if re.search(r"\d+\.\d+", expr):
        return True
    names = re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", expr)
    for n in names:
        if var_types.get(n, "") in FLOAT_TYPES:
            return True
    return False


def _scan_rules(lines: List[str], code: str, language: str, violations: List[dict], seen: Set[Tuple[int, str]]):
    var_types = _collect_var_types(lines)

    cmp_pat = re.compile(r"([A-Za-z_][A-Za-z0-9_]*|\([^\)]+\)|-?\d+(?:\.\d+)?)\s*(==|!=|>=|<=|>|<)\s*([A-Za-z_][A-Za-z0-9_]*|\([^\)]+\)|-?\d+(?:\.\d+)?)")

    for i, raw in enumerate(lines, 1):
        line = _strip_line_comment(raw)
        if not line.strip():
            continue

        for m in cmp_pat.finditer(line):
            left = m.group(1).strip()
            op = m.group(2)
            right = m.group(3).strip()

            l_name = re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", left)
            r_name = re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", right)
            lt = var_types.get(left, "") if l_name else ""
            rt = var_types.get(right, "") if r_name else ""

            # R-1-12-1: 逻辑量 >/< 比较
            if op in {">", "<", ">=", "<="} and (lt == "bool" or rt == "bool"):
                _add_violation(violations, seen, i, "R-1-12-1", get_code_snippet((i - 1, i - 1), code), f"{left}{op}{right}")

            # R-1-12-2: 指针 >/< 比较
            if op in {">", "<", ">=", "<="} and ((lt.endswith("*") and lt) or (rt.endswith("*") and rt)):
                _add_violation(violations, seen, i, "R-1-12-2", get_code_snippet((i - 1, i - 1), code), f"{left}{op}{right}")

            # R-1-12-3: 浮点 ==/!= 比较
            if op in {"==", "!="} and (_is_float_expr(left, var_types) or _is_float_expr(right, var_types)):
                _add_violation(violations, seen, i, "R-1-12-3", get_code_snippet((i - 1, i - 1), code), f"{left}{op}{right}")

            # R-1-12-4: 无符号与0比较
            if (lt in UNSIGNED_TYPES and re.match(r"^0(?:\.0+)?$", right)) or (rt in UNSIGNED_TYPES and re.match(r"^0(?:\.0+)?$", left)):
                if op in {">=", "<=", "<"}:
                    _add_violation(violations, seen, i, "R-1-12-4", get_code_snippet((i - 1, i - 1), code), f"{left}{op}{right}")

            # R-1-12-5: 有符号与无符号直接比较
            if lt and rt:
                if ((lt in SIGNED_TYPES and rt in UNSIGNED_TYPES) or (lt in UNSIGNED_TYPES and rt in SIGNED_TYPES)) and op in {"==", "!=", ">", "<", ">=", "<="}:
                    # 忽略显式强转情形
                    cast_left = re.search(r"\([A-Za-z_][A-Za-z0-9_\s\*]*\)\s*" + re.escape(left), line)
                    cast_right = re.search(r"\([A-Za-z_][A-Za-z0-9_\s\*]*\)\s*" + re.escape(right), line)
                    if not cast_left and not cast_right:
                        _add_violation(violations, seen, i, "R-1-12-5", get_code_snippet((i - 1, i - 1), code), f"{left}{op}{right}")

            # A-1-12-1: 常量应在左
            if op in {"==", "!="}:
                if l_name and re.match(r"^-?\d+(?:\.\d+)?$", right):
                    _add_violation(violations, seen, i, "A-1-12-1", get_code_snippet((i - 1, i - 1), code), f"{left}{op}{right}")


def detect_c_cpp_gjb_5_12_violations(code: str, language: str = "cpp") -> List[dict]:
    """
    检测GJB 8114-2013中5.12（比较判断）条款的违规。

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


def analyze_c_cpp_gjb_5_12(code_string: str, language: str = "cpp") -> List[dict]:
    return detect_c_cpp_gjb_5_12_violations(code_string, language)


if __name__ == "__main__":
    test_cases = [
        (
            "c_basic_violations",
            "c",
            """
typedef unsigned int bool;
int fsub(int *a, int *b){
    int sub = 0;
    if(a > b){ sub = (*a) - (*b); }
    if(a < b){ sub = (*b) - (*a); }
    return sub;
}

int main(void){
    bool outReg1, outReg2;
    unsigned int x = 1;
    int y = -2;
    float d = 0.435f;

    if(outReg1 > outReg2){ y = 1; }
    if(d == 0.435f){ y = 2; }
    if(x >= 0){ y++; }
    if(y < x){ y = 0; }
    if(y == 0){ y = 3; }
    return 0;
}
""",
        ),
        (
            "cpp_compliant_sample",
            "cpp",
            """
#include <math.h>
int fsub(int *a, int *b){
    int sub = 0;
    if((*a) > (*b)){ sub = (*a) - (*b); }
    if((*a) < (*b)){ sub = (*b) - (*a); }
    return sub;
}

int main(){
    unsigned int x = 1;
    int y = -2;
    float d = 0.435f;
    if(fabs(d - 0.435f) < 1e-4f){ y = 2; }
    if((int)x > y){ y = 0; }
    if(0 == y){ y = 3; }
    return 0;
}
""",
        ),
    ]

    for name, lang, src in test_cases:
        print("=" * 70)
        print(f"CASE: {name} ({lang})")
        results = analyze_c_cpp_gjb_5_12(src, lang)
        if not results:
            print("未检测到违规")
            continue
        print(f"检测到 {len(results)} 个违规")
        for item in results:
            print(
                f"line={item['line']} | rule_id={item['rule_id']} | "
                f"message={item['message']} | code_snippet={item['code_snippet'].replace(chr(10), ' ')}"
            )
