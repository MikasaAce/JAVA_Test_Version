import re
from typing import Dict, List, Set, Tuple, Union


RULES_5_11 = [
    {"rule_id": "R-1-11-1", "message": "GJB R-1-11-1: 变量禁止未赋值就使用", "severity": "高危"},
    {"rule_id": "R-1-11-2", "message": "GJB R-1-11-2: 变量初始化禁止隐含依赖于系统的缺省值", "severity": "高危"},
    {"rule_id": "R-1-11-3", "message": "GJB R-1-11-3: 结构体初始化的嵌套结构必须与定义一致", "severity": "中危"},
    {"rule_id": "R-1-11-4", "message": "GJB R-1-11-4: 枚举元素定义中的初始化必须完整", "severity": "中危"},
    {"rule_id": "A-1-11-1", "message": "GJB A-1-11-1: 建议变量在声明的同时进行初始化", "severity": "建议"},
    {"rule_id": "A-1-11-2", "message": "GJB A-1-11-2: 建议所有全局变量在统一设计的初始化模块中进行初始化", "severity": "建议"},
]

RULE_META: Dict[str, dict] = {x["rule_id"]: x for x in RULES_5_11}

BASIC_TYPES = {
    "char", "short", "int", "long", "float", "double", "bool", "unsigned", "signed",
    "unsigned char", "unsigned short", "unsigned int", "unsigned long",
    "signed char", "signed short", "signed int", "signed long",
}


def extract_rule_id(message: str) -> str:
    m = re.search(r"[RA]-\d+-\d+-\d+", message or "")
    if m:
        return m.group(0)
    return "R-1-11-UNKNOWN"


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


def _collect_declared_variables(lines: List[str]) -> Dict[str, Dict[str, Union[bool, int]]]:
    vars_info: Dict[str, Dict[str, Union[bool, int]]] = {}
    type_pat = (
        r"(?:unsigned\s+long\s+long|signed\s+long\s+long|long\s+long|"
        r"unsigned\s+long|signed\s+long|unsigned\s+int|signed\s+int|"
        r"unsigned\s+short|signed\s+short|unsigned\s+char|signed\s+char|"
        r"long|int|short|char|float|double|bool)"
    )
    decl_pat = re.compile(rf"^\s*(static\s+)?({type_pat}(?:\s+{type_pat})*)\s+(.+);\s*$")
    type_block_depth = 0

    for i, raw in enumerate(lines, 1):
        line = _strip_line_comment(raw).strip()
        if re.search(r"\b(struct|enum|union)\b", line) and "{" in line:
            type_block_depth += line.count("{") - line.count("}")
            continue
        if type_block_depth > 0:
            type_block_depth += line.count("{") - line.count("}")
            if type_block_depth < 0:
                type_block_depth = 0
            continue

        m = decl_pat.match(line)
        if not m:
            continue
        is_static = bool(m.group(1))
        decls = m.group(3)

        # 拆分同一行多个声明
        chunks = [x.strip() for x in decls.split(",") if x.strip()]
        for c in chunks:
            # 忽略函数声明
            if "(" in c and ")" in c:
                continue

            c = c.split("[", 1)[0].strip()
            vm = re.match(r"\*?\s*([A-Za-z_][A-Za-z0-9_]*)\s*(=\s*.+)?$", c)
            if not vm:
                continue
            name = vm.group(1)
            has_init = vm.group(2) is not None
            vars_info[name] = {
                "decl_line": i,
                "initialized": has_init,
                "is_global_or_static": is_static,
            }
    return vars_info


def _scan_uninitialized_use(lines: List[str], code: str, violations: List[dict], seen: Set[Tuple[int, str]]):
    vars_info = _collect_declared_variables(lines)

    for i, raw in enumerate(lines, 1):
        line = _strip_line_comment(raw)
        if not line.strip():
            continue

        # 赋值视为初始化
        asg = re.search(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=", line)
        if asg:
            lhs = asg.group(1)
            if lhs in vars_info:
                vars_info[lhs]["initialized"] = True

        # 读使用检测
        for name, info in vars_info.items():
            if int(info["decl_line"]) >= i:
                continue
            if re.search(rf"\b{re.escape(name)}\b", line):
                # 如果该行是给自己赋值，视为写操作
                if re.search(rf"\b{re.escape(name)}\b\s*=", line):
                    continue
                if not bool(info["initialized"]):
                    _add_violation(
                        violations,
                        seen,
                        i,
                        "R-1-11-1",
                        get_code_snippet((i - 1, i - 1), code),
                        name,
                    )
                break

    # A-1-11-1 + R-1-11-2
    for name, info in vars_info.items():
        if not bool(info["initialized"]):
            line_no = int(info["decl_line"])
            _add_violation(
                violations,
                seen,
                line_no,
                "A-1-11-1",
                get_code_snippet((line_no - 1, line_no - 1), code),
                name,
            )
            if bool(info["is_global_or_static"]):
                _add_violation(
                    violations,
                    seen,
                    line_no,
                    "R-1-11-2",
                    get_code_snippet((line_no - 1, line_no - 1), code),
                    name,
                )


def _scan_struct_enum_rules(lines: List[str], code: str, violations: List[dict], seen: Set[Tuple[int, str]]):
    # R-1-11-3: 结构体嵌套初始化一致性（近似）
    for i, raw in enumerate(lines, 1):
        line = _strip_line_comment(raw)
        if re.search(r"\bstruct\s+[A-Za-z_][A-Za-z0-9_]*\s+[A-Za-z_][A-Za-z0-9_]*\s*=\s*\{", line):
            # 若出现多个逗号但缺少嵌套花括号，认为可能与嵌套结构不一致
            init_part = line.split("=", 1)[1]
            if init_part.count(",") >= 2 and init_part.count("{") <= 1:
                _add_violation(
                    violations,
                    seen,
                    i,
                    "R-1-11-3",
                    get_code_snippet((i - 1, i - 1), code),
                )

    # R-1-11-4: 枚举初始化完整性（近似：混合初始化）
    in_enum = False
    enum_lines: List[Tuple[int, str]] = []
    for i, raw in enumerate(lines, 1):
        line = _strip_line_comment(raw)
        if re.search(r"\benum\b", line) and "{" in line:
            in_enum = True
            enum_lines = [(i, line)]
            if "}" in line:
                in_enum = False
        elif in_enum:
            enum_lines.append((i, line))
            if "}" in line:
                in_enum = False

        if not in_enum and enum_lines:
            body = " ".join(x[1] for x in enum_lines)
            inside = body.split("{", 1)[1].split("}", 1)[0]
            elems = [e.strip() for e in inside.split(",") if e.strip()]
            has_assign = ["=" in e for e in elems]
            if any(has_assign) and not all(has_assign):
                # 允许仅第一个初始化
                if not (has_assign and has_assign[0] and all(not x for x in has_assign[1:])):
                    _add_violation(
                        violations,
                        seen,
                        enum_lines[0][0],
                        "R-1-11-4",
                        get_code_snippet((enum_lines[0][0] - 1, enum_lines[-1][0] - 1), code),
                    )
            enum_lines = []


def _scan_global_init_module(lines: List[str], code: str, violations: List[dict], seen: Set[Tuple[int, str]]):
    # A-1-11-2：如果存在多个全局变量，且无明显 init 函数，给建议。
    global_decl_count = 0
    global_uninit_count = 0
    type_head = re.compile(r"^\s*(?:static\s+)?(?:unsigned\s+|signed\s+)?(?:char|short|int|long|float|double|bool)\b")
    has_init_func = False
    in_global_area = True

    for raw in lines:
        line = _strip_line_comment(raw).strip()
        if not line:
            continue
        if re.match(r"^(?:static\s+)?(?:unsigned\s+|signed\s+)?(?:char|short|int|long|float|double|bool)\b\s+[A-Za-z_][A-Za-z0-9_]*\s*\([^;]*\)\s*\{", line):
            in_global_area = False
        if not in_global_area:
            if re.search(r"\b(init|initialize)\w*\s*\([^)]*\)\s*\{", line, re.IGNORECASE):
                has_init_func = True
            continue

        if re.match(r"^(?:static\s+)?(?:unsigned\s+|signed\s+)?(?:char|short|int|long|float|double|bool)\b.*;", line) and "(" not in line:
            global_decl_count += 1
            if "=" not in line:
                global_uninit_count += 1
        if re.search(r"\b(init|initialize)\w*\s*\([^)]*\)\s*\{", line, re.IGNORECASE):
            has_init_func = True

    if global_decl_count >= 2 and global_uninit_count >= 1 and not has_init_func:
        _add_violation(violations, seen, 1, "A-1-11-2", get_code_snippet((0, min(3, len(lines) - 1)), code))


def detect_c_cpp_gjb_5_11_violations(code: str, language: str = "cpp") -> List[dict]:
    """
    检测GJB 8114-2013中5.11（初始化）条款的违规。

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

    _scan_uninitialized_use(lines, code, violations, seen)
    _scan_struct_enum_rules(lines, code, violations, seen)
    _scan_global_init_module(lines, code, violations, seen)

    return sorted(violations, key=lambda x: (x["line"], x["rule_id"]))


def analyze_c_cpp_gjb_5_11(code_string: str, language: str = "cpp") -> List[dict]:
    return detect_c_cpp_gjb_5_11_violations(code_string, language)


if __name__ == "__main__":
    test_cases = [
        (
            "c_basic_violations",
            "c",
            """
int Gstate;

int main(void){
    int i;
    float x, y, z;
    x = z;
    if(0 == i){
        y = z;
    }

    struct Spixel {
        unsigned int colour;
        struct Scoords {
            unsigned int x;
            unsigned int y;
        } coords;
    };
    struct Spixel pixel = {1,2,3};

    enum Etype {
        RED,
        WHITE = 0,
        BLUE
    } e;

    return 0;
}
""",
        ),
        (
            "cpp_compliant_sample",
            "cpp",
            """
int Gstate = 0;

int main(){
    int i = 0;
    float x = 0.0f, y = 0.0f, z = 0.0f;
    x = z;
    if (0 == i) {
        y = z;
    }

    struct Spixel {
        unsigned int colour;
        struct Scoords {
            unsigned int x;
            unsigned int y;
        } coords;
    };
    struct Spixel pixel = {1, {2, 3}};

    enum Etype {
        RED = 0,
        WHITE = 1,
        BLUE = 2
    } e;

    return 0;
}
""",
        ),
    ]

    for name, lang, src in test_cases:
        print("=" * 70)
        print(f"CASE: {name} ({lang})")
        results = analyze_c_cpp_gjb_5_11(src, lang)
        if not results:
            print("未检测到违规")
            continue
        print(f"检测到 {len(results)} 个违规")
        for item in results:
            print(
                f"line={item['line']} | rule_id={item['rule_id']} | "
                f"message={item['message']} | code_snippet={item['code_snippet'].replace(chr(10), ' ')}"
            )
