import re
from typing import Dict, List, Set, Tuple, Union


RULES_5_13 = [
    {"rule_id": "R-1-13-1", "message": "GJB R-1-13-1: 禁止局部变量与全局变量同名", "severity": "高危"},
    {"rule_id": "R-1-13-2", "message": "GJB R-1-13-2: 禁止函数形参与全局变量同名", "severity": "高危"},
    {"rule_id": "R-1-13-3", "message": "GJB R-1-13-3: 禁止变量名与函数名同名", "severity": "高危"},
    {"rule_id": "R-1-13-4", "message": "GJB R-1-13-4: 禁止变量名与标识名同名", "severity": "中危"},
    {"rule_id": "R-1-13-5", "message": "GJB R-1-13-5: 禁止变量名与枚举元素同名", "severity": "中危"},
    {"rule_id": "R-1-13-6", "message": "GJB R-1-13-6: 禁止变量名与typedef自定义类型名同名", "severity": "中危"},
    {"rule_id": "R-1-13-7", "message": "GJB R-1-13-7: 禁止在内部块中重定义已有变量名", "severity": "高危"},
    {"rule_id": "R-1-13-8", "message": "GJB R-1-13-8: 禁止仅依赖大小写区分变量", "severity": "中危"},
    {"rule_id": "R-1-13-9", "message": "GJB R-1-13-9: 禁止仅依赖小写l与数字1区分变量", "severity": "中危"},
    {"rule_id": "R-1-13-10", "message": "GJB R-1-13-10: 禁止仅依赖大写O与数字0区分变量", "severity": "中危"},
    {"rule_id": "R-1-13-11", "message": "GJB R-1-13-11: 禁止单独使用小写l或大写O作为变量名", "severity": "低危"},
    {"rule_id": "R-1-13-12", "message": "GJB R-1-13-12: 程序外部可改写变量必须使用volatile说明", "severity": "高危"},
    {"rule_id": "R-1-13-13", "message": "GJB R-1-13-13: 禁止在表达式中出现多个同一volatile变量运算", "severity": "高危"},
    {"rule_id": "R-1-13-14", "message": "GJB R-1-13-14: 禁止将NULL作为整型数0使用", "severity": "高危"},
    {"rule_id": "R-1-13-15", "message": "GJB R-1-13-15: 禁止给无符号类型变量赋负值", "severity": "高危"},
    {"rule_id": "R-1-13-16", "message": "GJB R-1-13-16: 字符串数组必须以'\\0'结束", "severity": "高危"},
    {"rule_id": "A-1-13-1", "message": "GJB A-1-13-1: 推荐使用带类型前缀的变量命名", "severity": "建议"},
    {"rule_id": "A-1-13-2", "message": "GJB A-1-13-2: 谨慎使用寄存器变量", "severity": "建议"},
]

RULE_META: Dict[str, dict] = {x["rule_id"]: x for x in RULES_5_13}

TYPE_PREFIX = {
    "char": "c",
    "signed char": "sc",
    "unsigned char": "uc",
    "int": "i",
    "signed int": "si",
    "unsigned int": "ui",
    "short": "s",
    "signed short": "ss",
    "unsigned short": "us",
    "long": "l",
    "signed long": "sl",
    "unsigned long": "ul",
    "float": "f",
    "double": "d",
}


def extract_rule_id(message: str) -> str:
    m = re.search(r"[RA]-\d+-\d+-\d+", message or "")
    if m:
        return m.group(0)
    return "R-1-13-UNKNOWN"


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


def _add_violation(violations: List[dict], seen: Set[Tuple[int, str]], line: int, rule_id: str, code_snippet: str, suffix: str = ""):
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


def _norm_type(t: str) -> str:
    return " ".join(t.replace("const", "").replace("volatile", "").replace("register", "").split())


def _collect_symbols(lines: List[str]):
    globals_: Dict[str, Tuple[str, int]] = {}
    functions: Dict[str, int] = {}
    typedef_names: Set[str] = set()
    tag_names: Set[str] = set()
    enum_values: Set[str] = set()
    volatile_vars: Set[str] = set()

    in_func = False
    brace = 0
    func_start_line = 0
    func_ranges: List[Tuple[int, int]] = []

    typedef_pat = re.compile(r"^\s*typedef\s+.+\s+([A-Za-z_][A-Za-z0-9_]*)\s*;")
    tag_pat = re.compile(r"\b(struct|union|enum)\s+([A-Za-z_][A-Za-z0-9_]*)")
    func_pat = re.compile(r"^\s*(?:static\s+|inline\s+|extern\s+)?[A-Za-z_][A-Za-z0-9_\s\*:&<>]*\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^;]*\)\s*\{")
    decl_pat = re.compile(r"^\s*((?:volatile\s+|register\s+|static\s+)?(?:unsigned\s+|signed\s+)?(?:char|short|int|long|float|double|bool)\b(?:\s+(?:unsigned|signed|long|short|int|char))*)\s+(.+);\s*$")

    # first pass: typedef/tags/functions and function ranges
    for i, raw in enumerate(lines, 1):
        line = _strip_line_comment(raw)

        m_typedef = typedef_pat.match(line.strip())
        if m_typedef:
            typedef_names.add(m_typedef.group(1))

        for m in tag_pat.finditer(line):
            tag_names.add(m.group(2))

        if not in_func:
            m_func = func_pat.match(line.strip())
            if m_func:
                in_func = True
                func_start_line = i
                brace = line.count("{") - line.count("}")
                functions[m_func.group(1)] = i
                continue
        else:
            brace += line.count("{") - line.count("}")
            if brace <= 0:
                in_func = False
                func_ranges.append((func_start_line, i))

    def in_any_func(line_no: int) -> bool:
        for s, e in func_ranges:
            if s <= line_no <= e:
                return True
        return False

    # enum values
    in_enum = False
    enum_buf = []
    for line in lines:
        s = _strip_line_comment(line)
        if not in_enum and "enum" in s and "{" in s:
            in_enum = True
            enum_buf = [s]
            if "}" in s:
                in_enum = False
        elif in_enum:
            enum_buf.append(s)
            if "}" in s:
                in_enum = False
        if enum_buf and not in_enum:
            txt = " ".join(enum_buf)
            if "{" in txt and "}" in txt:
                inside = txt.split("{", 1)[1].split("}", 1)[0]
                for p in inside.split(","):
                    name = p.split("=", 1)[0].strip()
                    if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", name):
                        enum_values.add(name)
            enum_buf = []

    # global vars + volatile vars
    for i, raw in enumerate(lines, 1):
        line = _strip_line_comment(raw)
        m_decl = decl_pat.match(line.strip())
        if not m_decl:
            continue
        t_raw = m_decl.group(1)
        names = [x.strip() for x in m_decl.group(2).split(",") if x.strip()]
        for n in names:
            if "(" in n and ")" in n:
                continue
            m_nm = re.match(r"\*?\s*([A-Za-z_][A-Za-z0-9_]*)", n)
            if not m_nm:
                continue
            nm = m_nm.group(1)
            t = _norm_type(t_raw)
            if "volatile" in t_raw:
                volatile_vars.add(nm)
            if not in_any_func(i):
                globals_[nm] = (t, i)

    return globals_, functions, typedef_names, tag_names, enum_values, volatile_vars, func_ranges


def _normalize_case_name(name: str) -> str:
    return name.lower()


def _normalize_l1(name: str) -> str:
    return name.replace("l", "1")


def _normalize_o0(name: str) -> str:
    return name.replace("O", "0")


def _scan_rules(lines: List[str], code: str, language: str, violations: List[dict], seen: Set[Tuple[int, str]]):
    globals_, functions, typedef_names, tag_names, enum_values, volatile_vars, func_ranges = _collect_symbols(lines)

    # Collect variable declarations with scope depth
    scope_stack: List[Set[str]] = [set()]
    all_var_names: List[Tuple[str, str, int]] = []  # (name, type, line)

    decl_pat = re.compile(r"^\s*((?:volatile\s+|register\s+|static\s+)?(?:unsigned\s+|signed\s+)?(?:char|short|int|long|float|double|bool)\b(?:\s+(?:unsigned|signed|long|short|int|char))*)\s+(.+);\s*$")
    func_sig_pat = re.compile(r"^\s*(?:static\s+|inline\s+|extern\s+)?[A-Za-z_][A-Za-z0-9_\s\*:&<>]*\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^;{}]*)\)\s*\{?")

    def in_any_func(line_no: int) -> bool:
        for s, e in func_ranges:
            if s <= line_no <= e:
                return True
        return False

    for i, raw in enumerate(lines, 1):
        line = _strip_line_comment(raw)
        s = line.strip()

        # scope update
        open_b = line.count("{")
        close_b = line.count("}")
        for _ in range(open_b):
            scope_stack.append(set())
        for _ in range(close_b):
            if len(scope_stack) > 1:
                scope_stack.pop()

        # function parameters: R-1-13-2
        m_sig = func_sig_pat.match(s)
        if m_sig and "(" in s and ")" in s and not s.endswith(";"):
            params = [p.strip() for p in m_sig.group(2).split(",") if p.strip() and p.strip() != "void"]
            for p in params:
                nm_m = re.match(r".*\b([A-Za-z_][A-Za-z0-9_]*)\s*(?:\[.*\])?$", p)
                if nm_m:
                    pn = nm_m.group(1)
                    if pn in globals_:
                        _add_violation(violations, seen, i, "R-1-13-2", get_code_snippet((i - 1, i - 1), code), pn)

        # variable declaration
        m_decl = decl_pat.match(s)
        if m_decl:
            t_raw = m_decl.group(1)
            t = _norm_type(t_raw)
            names = [x.strip() for x in m_decl.group(2).split(",") if x.strip()]
            for n in names:
                if "(" in n and ")" in n:
                    continue
                m_nm = re.match(r"\*?\s*([A-Za-z_][A-Za-z0-9_]*)", n)
                if not m_nm:
                    continue
                nm = m_nm.group(1)
                all_var_names.append((nm, t, i))

                # R-1-13-1
                if in_any_func(i) and nm in globals_:
                    _add_violation(violations, seen, i, "R-1-13-1", get_code_snippet((i - 1, i - 1), code), nm)

                # R-1-13-3
                if nm in functions:
                    _add_violation(violations, seen, i, "R-1-13-3", get_code_snippet((i - 1, i - 1), code), nm)

                # R-1-13-4
                if nm in tag_names:
                    _add_violation(violations, seen, i, "R-1-13-4", get_code_snippet((i - 1, i - 1), code), nm)

                # R-1-13-5
                if nm in enum_values:
                    _add_violation(violations, seen, i, "R-1-13-5", get_code_snippet((i - 1, i - 1), code), nm)

                # R-1-13-6
                if nm in typedef_names:
                    _add_violation(violations, seen, i, "R-1-13-6", get_code_snippet((i - 1, i - 1), code), nm)

                # R-1-13-7 internal block redefine
                for scope in scope_stack[:-1]:
                    if nm in scope:
                        _add_violation(violations, seen, i, "R-1-13-7", get_code_snippet((i - 1, i - 1), code), nm)
                        break
                scope_stack[-1].add(nm)

                # R-1-13-11
                if nm in {"l", "O", "I"}:
                    _add_violation(violations, seen, i, "R-1-13-11", get_code_snippet((i - 1, i - 1), code), nm)

                # A-1-13-1
                pref = TYPE_PREFIX.get(t, "")
                if pref and not nm.startswith(pref):
                    _add_violation(violations, seen, i, "A-1-13-1", get_code_snippet((i - 1, i - 1), code), f"{nm}:{t}")

                # R-1-13-12 (extern non-volatile)
                if s.startswith("extern") and "volatile" not in s:
                    _add_violation(violations, seen, i, "R-1-13-12", get_code_snippet((i - 1, i - 1), code), nm)

                # R-1-13-15 unsigned assign negative
                if "unsigned" in t and re.search(rf"\b{re.escape(nm)}\s*=\s*-\d+", s) and "(" not in s.split("=", 1)[1]:
                    _add_violation(violations, seen, i, "R-1-13-15", get_code_snippet((i - 1, i - 1), code), nm)

                # A-1-13-2 register
                if "register" in t_raw:
                    _add_violation(violations, seen, i, "A-1-13-2", get_code_snippet((i - 1, i - 1), code), nm)

        # R-1-13-13 multiple same volatile variable in expression
        for vv in volatile_vars:
            hits = len(re.findall(rf"\b{re.escape(vv)}\b", s))
            if hits >= 2 and re.search(r"[+\-*/%]", s):
                _add_violation(violations, seen, i, "R-1-13-13", get_code_snippet((i - 1, i - 1), code), vv)

        # R-1-13-14 NULL as int zero (heuristic)
        if re.search(r"\b[A-Za-z_][A-Za-z0-9_]*\s*=\s*NULL\s*;", s):
            lhs = re.search(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*NULL\s*;", s).group(1)
            if lhs in globals_ and "*" not in globals_[lhs][0]:
                _add_violation(violations, seen, i, "R-1-13-14", get_code_snippet((i - 1, i - 1), code), lhs)
        if re.search(r"\w+\s*\(\s*NULL\s*\)", s):
            _add_violation(violations, seen, i, "R-1-13-14", get_code_snippet((i - 1, i - 1), code))

    # R-1-13-8/9/10 across all variable names
    for i in range(len(all_var_names)):
        n1, _, l1 = all_var_names[i]
        for j in range(i + 1, len(all_var_names)):
            n2, _, l2 = all_var_names[j]
            if n1 == n2:
                continue
            if _normalize_case_name(n1) == _normalize_case_name(n2):
                _add_violation(violations, seen, l2, "R-1-13-8", get_code_snippet((l2 - 1, l2 - 1), code), f"{n1}/{n2}")
            if _normalize_l1(n1) == _normalize_l1(n2):
                _add_violation(violations, seen, l2, "R-1-13-9", get_code_snippet((l2 - 1, l2 - 1), code), f"{n1}/{n2}")
            if _normalize_o0(n1) == _normalize_o0(n2):
                _add_violation(violations, seen, l2, "R-1-13-10", get_code_snippet((l2 - 1, l2 - 1), code), f"{n1}/{n2}")

    # R-1-13-16 string buffer must end with '\0' (heuristic)
    for i, raw in enumerate(lines, 1):
        s = _strip_line_comment(raw)
        m = re.search(r"\bchar\s+([A-Za-z_][A-Za-z0-9_]*)\s*\[\s*\d+\s*\]\s*;", s)
        if not m:
            continue
        name = m.group(1)
        used_as_string = False
        set_nul = False
        for k in range(i, min(i + 25, len(lines))):
            ln = _strip_line_comment(lines[k])
            if re.search(rf"%s[^\"]*\"\s*,\s*{re.escape(name)}\b", ln) or re.search(rf"\bprintf\s*\(.*{re.escape(name)}", ln):
                used_as_string = True
            if re.search(rf"\b{re.escape(name)}\s*\[\s*\d+\s*\]\s*=\s*'\\0'", ln):
                set_nul = True
        if used_as_string and not set_nul:
            _add_violation(violations, seen, i, "R-1-13-16", get_code_snippet((i - 1, i - 1), code), name)


def detect_c_cpp_gjb_5_13_violations(code: str, language: str = "cpp") -> List[dict]:
    """
    检测GJB 8114-2013中5.13（变量使用）条款的违规。

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


def analyze_c_cpp_gjb_5_13(code_string: str, language: str = "cpp") -> List[dict]:
    return detect_c_cpp_gjb_5_13_violations(code_string, language)


if __name__ == "__main__":
    test_cases = [
        (
            "c_basic_violations",
            "c",
            """
int sign = 0;
typedef unsigned int TData;
struct POINTA { unsigned int x; unsigned int y; };
enum Name_type { first=0, second } EnumVar;

int fun(int x){ return x+1; }

int main(void){
    int sign = 0;
    int fun = 0;
    unsigned int POINTA = 1;
    unsigned int second = 0;
    unsigned int TData = 0;
    int l = 1;
    int O = 0;
    int fSpeed = 0;
    int fspeed = 1;
    int fSpeedl = 1;
    int fSpeed1 = 2;
    int fSpeedO = 3;
    int fSpeed0 = 4;
    {
        int sign = 2;
    }
    volatile unsigned int v = 1;
    int z = 3*v*v + 2*v;
    unsigned short usX;
    usX = -10;
    char buf[8];
    buf[0] = 'y'; buf[1] = 'e'; buf[2] = 's';
    printf("%s\\n", buf);
    return 0;
}
""",
        ),
        (
            "cpp_compliant_sample",
            "cpp",
            """
typedef unsigned int uiData;
struct PointA { unsigned int x; unsigned int y; };
enum NameType { first = 0, second = 1 } enumVar;

int fCalc(int iVal){ return iVal + 1; }

int main(){
    int iLocal = 0;
    unsigned int uiPointA = 1;
    unsigned int uiSecond = 0;
    uiData uiTData = 0;
    volatile unsigned int uiV = 1;
    unsigned int uiTmp = uiV;
    unsigned short usX = (unsigned short)(-10);
    char cBuf[8];
    cBuf[0] = 'y'; cBuf[1] = 'e'; cBuf[2] = 's'; cBuf[3] = '\\0';
    printf("%s\\n", cBuf);
    return fCalc(iLocal + (int)uiPointA + (int)uiSecond + (int)uiTData + (int)uiTmp + (int)usX);
}
""",
        ),
    ]

    for name, lang, src in test_cases:
        print("=" * 70)
        print(f"CASE: {name} ({lang})")
        results = analyze_c_cpp_gjb_5_13(src, lang)
        if not results:
            print("未检测到违规")
            continue
        print(f"检测到 {len(results)} 个违规")
        for item in results:
            print(
                f"line={item['line']} | rule_id={item['rule_id']} | "
                f"message={item['message']} | code_snippet={item['code_snippet'].replace(chr(10), ' ')}"
            )
