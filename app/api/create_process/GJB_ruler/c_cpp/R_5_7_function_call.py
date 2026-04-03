import re
from typing import Dict, List, Set, Tuple, Union


RULES_5_7 = [
    {"rule_id": "R-1-7-1", "message": "GJB R-1-7-1: 函数调用前必须有声明或定义", "severity": "高危"},
    {"rule_id": "R-1-7-2", "message": "GJB R-1-7-2: 函数调用实参与形参的个数应匹配", "severity": "高危"},
    {"rule_id": "R-1-7-3", "message": "GJB R-1-7-3: 非void返回值函数调用结果不应被忽略", "severity": "中危"},
    {"rule_id": "R-1-7-4", "message": "GJB R-1-7-4: 禁止递归调用", "severity": "高危"},
    {"rule_id": "R-1-7-5", "message": "GJB R-1-7-5: 函数指针调用前应进行有效性检查", "severity": "高危"},
    {"rule_id": "R-1-7-6", "message": "GJB R-1-7-6: printf/scanf类格式化参数数量应与格式符匹配", "severity": "中危"},
    {"rule_id": "R-1-7-7", "message": "GJB R-1-7-7: scanf对字符串输入应限制宽度", "severity": "高危"},
    {"rule_id": "R-1-7-8", "message": "GJB R-1-7-8: 禁止调用system/popen等高风险命令执行接口", "severity": "高危"},
    {"rule_id": "A-1-7-1", "message": "GJB A-1-7-1: 建议控制函数参数个数不超过7个", "severity": "建议"},
    {"rule_id": "A-1-7-2", "message": "GJB A-1-7-2: 建议避免在单条语句中嵌套多层函数调用", "severity": "建议"},
    {"rule_id": "A-1-7-3", "message": "GJB A-1-7-3: 建议检查关键函数返回值", "severity": "建议"},
]

RULE_META: Dict[str, dict] = {x["rule_id"]: x for x in RULES_5_7}

CPP_KEYWORDS = {
    "if", "for", "while", "switch", "return", "sizeof", "catch", "new", "delete",
    "else", "do", "case", "typedef", "class", "struct", "enum", "union",
}

KNOWN_VOID_FUNCS = {
    "free", "memcpy", "memset", "strcpy", "strncpy", "strcat", "strncat",
}

CRITICAL_RET_FUNCS = {
    "fopen", "fclose", "read", "write", "send", "recv", "pthread_create", "pthread_join",
}

KNOWN_EXTERN_FUNCS = {
    "printf", "fprintf", "sprintf", "snprintf", "scanf", "sscanf", "fscanf",
    "fopen", "fclose", "system", "popen", "_popen", "malloc", "calloc", "realloc", "free",
}


def extract_rule_id(message: str) -> str:
    m = re.search(r"[RA]-\d+-\d+-\d+", message or "")
    if m:
        return m.group(0)
    return "R-1-7-UNKNOWN"


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


def _split_args(args_text: str) -> List[str]:
    args = []
    cur = []
    depth = 0
    in_str = False
    quote = ""
    i = 0
    while i < len(args_text):
        ch = args_text[i]
        if ch in ('"', "'"):
            if not in_str:
                in_str = True
                quote = ch
            elif i > 0 and args_text[i - 1] != "\\" and ch == quote:
                in_str = False
                quote = ""
            cur.append(ch)
            i += 1
            continue
        if in_str:
            cur.append(ch)
            i += 1
            continue
        if ch == "(":
            depth += 1
        elif ch == ")" and depth > 0:
            depth -= 1
        elif ch == "," and depth == 0:
            text = "".join(cur).strip()
            if text:
                args.append(text)
            cur = []
            i += 1
            continue
        cur.append(ch)
        i += 1
    tail = "".join(cur).strip()
    if tail:
        args.append(tail)
    if len(args) == 1 and args[0] == "void":
        return []
    return args


def _collect_function_signatures(lines: List[str]) -> Tuple[Dict[str, int], Dict[str, bool], Set[str], Set[str]]:
    decl_arg_count: Dict[str, int] = {}
    non_void_funcs: Dict[str, bool] = {}
    declared_funcs: Set[str] = set()
    func_pointer_vars: Set[str] = set()

    sig_pat = re.compile(
        r"^\s*(?:static\s+|inline\s+|extern\s+|constexpr\s+|virtual\s+|friend\s+)*"
        r"([A-Za-z_][A-Za-z0-9_:\<\>\s\*&]*)\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^;{}]*)\)\s*([;{])"
    )
    fp_pat = re.compile(r"\(\s*\*\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)\s*\([^\)]*\)")

    for raw in lines:
        line = _strip_line_comment(raw).strip()
        if not line:
            continue
        for mfp in fp_pat.finditer(line):
            func_pointer_vars.add(mfp.group(1))

        m = sig_pat.match(line)
        if not m:
            continue
        ret_type = " ".join(m.group(1).split())
        name = m.group(2)
        args_text = m.group(3).strip()
        declared_funcs.add(name)
        decl_arg_count[name] = 0 if not args_text else len(_split_args(args_text))
        non_void_funcs[name] = ("void" not in ret_type.split())

    return decl_arg_count, non_void_funcs, declared_funcs, func_pointer_vars


def _find_function_blocks(lines: List[str]) -> Dict[int, str]:
    """返回行号到所属函数名的映射（1-based 行号）。"""
    line_to_func: Dict[int, str] = {}
    sig_start_pat = re.compile(
        r"^\s*(?:static\s+|inline\s+|extern\s+|constexpr\s+|virtual\s+|friend\s+)*"
        r"[A-Za-z_][A-Za-z0-9_:\<\>\s\*&]*\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^\)]*\)\s*(\{)?\s*$"
    )

    current_func = ""
    brace_depth = 0
    pending_func = ""

    for i, raw in enumerate(lines, 1):
        line = _strip_line_comment(raw).strip()
        m = sig_start_pat.match(line)
        if m and not re.match(r"^(if|for|while|switch)\b", line):
            pending_func = m.group(1)
            if m.group(2) == "{":
                current_func = pending_func
                brace_depth = 1
                line_to_func[i] = current_func
                pending_func = ""
                continue

        if pending_func and line == "{":
            current_func = pending_func
            brace_depth = 1
            line_to_func[i] = current_func
            pending_func = ""
            continue

        if current_func:
            line_to_func[i] = current_func
            brace_depth += line.count("{")
            brace_depth -= line.count("}")
            if brace_depth <= 0:
                current_func = ""
                brace_depth = 0

    return line_to_func


def _find_calls_in_line(line: str) -> List[Tuple[str, str, int, int]]:
    calls = []
    text = _strip_line_comment(line)
    for m in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", text):
        name = m.group(1)
        if name in CPP_KEYWORDS:
            continue

        start_paren = m.end() - 1
        depth = 0
        end_paren = -1
        i = start_paren
        while i < len(text):
            ch = text[i]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    end_paren = i
                    break
            i += 1

        if end_paren == -1:
            continue
        args_text = text[start_paren + 1:end_paren]
        calls.append((name, args_text, m.start(), end_paren))
    return calls


def _scan_rules(lines: List[str], code: str, language: str, violations: List[dict], seen: Set[Tuple[int, str]]):
    decl_arg_count, non_void_funcs, declared_funcs, func_ptr_vars = _collect_function_signatures(lines)
    line_to_func = _find_function_blocks(lines)
    in_null_checked_scope: Set[str] = set()
    sig_line_pat = re.compile(
        r"^\s*(?:static\s+|inline\s+|extern\s+|constexpr\s+|virtual\s+|friend\s+)*"
        r"[A-Za-z_][A-Za-z0-9_:\<\>\s\*&]*\s+[A-Za-z_][A-Za-z0-9_]*\s*\([^\)]*\)\s*[;{]\s*$"
    )
    sig_inline_def_pat = re.compile(
        r"^\s*(?:static\s+|inline\s+|extern\s+|constexpr\s+|virtual\s+|friend\s+)*"
        r"[A-Za-z_][A-Za-z0-9_:\<\>\s\*&]*\s+[A-Za-z_][A-Za-z0-9_]*\s*\([^\)]*\)\s*\{"
    )

    for i, raw in enumerate(lines, 1):
        line = _strip_line_comment(raw)
        stripped = line.strip()

        # 跳过函数声明/定义行，避免被误识别为函数调用。
        if sig_line_pat.match(stripped) or (
            sig_inline_def_pat.match(stripped) and not re.match(r"^(if|for|while|switch)\b", stripped)
        ):
            # A-1-7-1: 形参数目建议仍在声明行检测
            m_sig = re.match(
                r"^\s*(?:static\s+|inline\s+|extern\s+)?[A-Za-z_][A-Za-z0-9_\s\*&:<>]*\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^\)]*)\)\s*[;{]\s*$",
                stripped,
            )
            if m_sig:
                params = _split_args(m_sig.group(2).strip()) if m_sig.group(2).strip() else []
                if len(params) > 7:
                    _add_violation(violations, seen, i, "A-1-7-1", get_code_snippet((i - 1, i - 1), code), f"params={len(params)}")
            continue

        # 追踪函数指针空检查作用域（近似）
        m_check = re.search(r"\bif\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?:!=\s*NULL|!=\s*0|\)\s*\{?)", stripped)
        if m_check:
            in_null_checked_scope.add(m_check.group(1))
        if "}" in stripped and in_null_checked_scope:
            in_null_checked_scope.clear()

        calls = _find_calls_in_line(line)
        if not calls:
            continue

        # A-1-7-2: 单行多层调用（近似）
        if len(calls) >= 3:
            _add_violation(violations, seen, i, "A-1-7-2", get_code_snippet((i - 1, i - 1), code), f"nested-calls={len(calls)}")

        for name, args_text, call_start, _ in calls:
            args = _split_args(args_text)
            argc = len(args)

            # R-1-7-1: 调用前声明/定义
            if name not in declared_funcs and name not in KNOWN_EXTERN_FUNCS:
                _add_violation(violations, seen, i, "R-1-7-1", get_code_snippet((i - 1, i - 1), code), name)

            # R-1-7-2: 参数个数匹配
            if name in decl_arg_count and decl_arg_count[name] != argc:
                _add_violation(
                    violations,
                    seen,
                    i,
                    "R-1-7-2",
                    get_code_snippet((i - 1, i - 1), code),
                    f"{name}: expect {decl_arg_count[name]}, got {argc}",
                )

            # R-1-7-3: 非void返回值未使用（近似）
            left = line[:call_start].strip()
            if name in non_void_funcs and non_void_funcs[name]:
                if "=" not in left and not left.startswith("return"):
                    _add_violation(violations, seen, i, "R-1-7-3", get_code_snippet((i - 1, i - 1), code), name)

            # R-1-7-4: 递归调用（近似，函数名同名调用）
            cur_func = line_to_func.get(i)
            if cur_func and name == cur_func:
                _add_violation(violations, seen, i, "R-1-7-4", get_code_snippet((i - 1, i - 1), code), name)

            # R-1-7-5: 函数指针调用前检查
            if name in func_ptr_vars and name not in in_null_checked_scope:
                _add_violation(violations, seen, i, "R-1-7-5", get_code_snippet((i - 1, i - 1), code), name)

            # R-1-7-6: printf/scanf格式参数计数
            if name in {"printf", "fprintf", "sprintf", "snprintf", "scanf", "sscanf", "fscanf"} and args:
                fmt = args[0] if name in {"printf", "scanf", "sscanf"} else (args[1] if len(args) > 1 else "")
                if fmt.startswith('"') and fmt.endswith('"'):
                    fmt_lit = fmt[1:-1]
                    spec = re.findall(r"%(?:\d+\$)?[-+ #0]*\d*(?:\.\d+)?[hlLzjt]*[diuoxXfFeEgGaAcspn]", fmt_lit)
                    arg_need = len(spec)
                    arg_have = len(args) - (1 if name in {"printf", "scanf", "sscanf"} else 2)
                    if arg_need != arg_have:
                        _add_violation(
                            violations,
                            seen,
                            i,
                            "R-1-7-6",
                            get_code_snippet((i - 1, i - 1), code),
                            f"{name}: fmt={arg_need}, args={arg_have}",
                        )

            # R-1-7-7: scanf字符串宽度
            if name in {"scanf", "sscanf", "fscanf"} and args:
                fmt = args[0] if name in {"scanf", "sscanf"} else (args[1] if len(args) > 1 else "")
                if fmt.startswith('"') and fmt.endswith('"'):
                    fmt_lit = fmt[1:-1]
                    if re.search(r"%s", fmt_lit) and not re.search(r"%\d+s", fmt_lit):
                        _add_violation(violations, seen, i, "R-1-7-7", get_code_snippet((i - 1, i - 1), code), name)

            # R-1-7-8: 高风险命令执行
            if name in {"system", "popen", "_popen"}:
                _add_violation(violations, seen, i, "R-1-7-8", get_code_snippet((i - 1, i - 1), code), name)

            # A-1-7-3: 关键函数返回值建议检查
            if name in CRITICAL_RET_FUNCS:
                left = line[:call_start].strip()
                if "=" not in left and not left.startswith("return"):
                    _add_violation(violations, seen, i, "A-1-7-3", get_code_snippet((i - 1, i - 1), code), name)

        # A-1-7-1 在声明/定义行分支里处理


def detect_c_cpp_gjb_5_7_violations(code: str, language: str = "cpp") -> List[dict]:
    """
    检测GJB 8114-2013中5.7（函数调用）条款的违规。

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


def analyze_c_cpp_gjb_5_7(code_string: str, language: str = "cpp") -> List[dict]:
    return detect_c_cpp_gjb_5_7_violations(code_string, language)


if __name__ == "__main__":
    test_cases = [
        (
            "c_basic_violations",
            "c",
            """
#include <stdio.h>
#include <stdlib.h>

int add2(int a, int b);
int bad_many_params(int a,int b,int c,int d,int e,int f,int g,int h){ return a+b+c+d+e+f+g+h; }
int add2(int a, int b){ return a+b; }

int main(void){
    int x = 0;
    add2(1);                       // R-1-7-2
    unknown_api(3);                // R-1-7-1
    add2(1,2);                     // R-1-7-3
    printf("%d %d", x);           // R-1-7-6
    scanf("%s", (char*)&x);       // R-1-7-7
    system("ls");                 // R-1-7-8
    fopen("a.txt", "r");         // A-1-7-3
    x = bad_many_params(1,2,3,4,5,6,7,8);
    return 0;
}
""",
        ),
        (
            "cpp_compliant_sample",
            "cpp",
            """
#include <stdio.h>
int add2(int a, int b){ return a+b; }

int main(){
    int x = 0;
    x = add2(1, 2);
    printf("%d", x);
    return 0;
}
""",
        ),
    ]

    for name, lang, src in test_cases:
        print("=" * 70)
        print(f"CASE: {name} ({lang})")
        results = analyze_c_cpp_gjb_5_7(src, lang)
        if not results:
            print("未检测到违规")
            continue
        print(f"检测到 {len(results)} 个违规")
        for item in results:
            print(
                f"line={item['line']} | rule_id={item['rule_id']} | "
                f"message={item['message']} | code_snippet={item['code_snippet'].replace(chr(10), ' ')}"
            )
