import re
from typing import Dict, List, Set, Tuple, Union


RULES_5_3 = [
    {
        "rule_id": "R-1-3-1",
        "message": "GJB R-1-3-1: 禁止指针的指针超过两级",
        "severity": "中危",
    },
    {
        "rule_id": "R-1-3-2",
        "message": "GJB R-1-3-2: 函数指针使用必须加以&明确说明",
        "severity": "低危",
    },
    {
        "rule_id": "R-1-3-3",
        "message": "GJB R-1-3-3: 禁止对参数指针进行赋值",
        "severity": "中危",
    },
    {
        "rule_id": "R-1-3-4",
        "message": "GJB R-1-3-4: 禁止将局部变量地址作为函数返回值返回",
        "severity": "高危",
    },
    {
        "rule_id": "R-1-3-5",
        "message": "GJB R-1-3-5: 禁止使用或释放未分配空间或已被释放的指针",
        "severity": "高危",
    },
    {
        "rule_id": "R-1-3-6",
        "message": "GJB R-1-3-6: 指针变量被释放后必须置为NULL",
        "severity": "中危",
    },
    {
        "rule_id": "R-1-3-7",
        "message": "GJB R-1-3-7: 动态分配指针定义时未分配空间必须初始化为NULL",
        "severity": "中危",
    },
    {
        "rule_id": "R-1-3-8",
        "message": "GJB R-1-3-8: 动态分配指针第一次使用前必须判别是否为NULL",
        "severity": "高危",
    },
    {
        "rule_id": "R-1-3-9",
        "message": "GJB R-1-3-9: 空指针必须使用NULL，禁止使用整型数0",
        "severity": "中危",
    },
    {
        "rule_id": "R-1-3-10",
        "message": "GJB R-1-3-10: 禁止文件指针在退出时没有关闭文件",
        "severity": "中危",
    },
    {
        "rule_id": "A-1-3-1",
        "message": "GJB A-1-3-1: 谨慎使用函数指针",
        "severity": "建议",
    },
    {
        "rule_id": "A-1-3-2",
        "message": "GJB A-1-3-2: 谨慎使用无类型指针",
        "severity": "建议",
    },
    {
        "rule_id": "A-1-3-3",
        "message": "GJB A-1-3-3: 谨慎对指针进行算术运算",
        "severity": "建议",
    },
]

RULE_META: Dict[str, dict] = {x["rule_id"]: x for x in RULES_5_3}


def extract_rule_id(message: str) -> str:
    match = re.search(r"[RA]-\d+-\d+-\d+", message or "")
    if match:
        return match.group(0)
    return "R-1-3-UNKNOWN"


def get_code_snippet(node_or_span: Union[Tuple[int, int], object], code: str, context_lines: int = 2) -> str:
    lines = code.split("\n")
    if isinstance(node_or_span, tuple):
        start_line, end_line = node_or_span
    else:
        start_line = getattr(node_or_span, "start_point", (0, 0))[0]
        end_line = getattr(node_or_span, "end_point", (start_line, 0))[0]

    start = max(0, start_line - context_lines)
    end = min(len(lines), end_line + context_lines + 1)
    snippet = "\n".join(lines[start:end])
    if len(snippet) > 260:
        snippet = snippet[:260] + "..."
    return snippet


def _add_violation(
    violations: List[dict],
    seen: Set[Tuple[int, str]],
    line: int,
    rule_id: str,
    code_snippet: str,
    message_suffix: str = "",
):
    if (line, rule_id) in seen:
        return
    seen.add((line, rule_id))

    meta = RULE_META[rule_id]
    message = meta["message"]
    if message_suffix:
        message = f"{message} ({message_suffix})"

    violations.append(
        {
            "line": line,
            "code_snippet": code_snippet,
            "violation_type": "编码规范",
            "severity": meta["severity"],
            "rule_id": rule_id,
            "message": message,
        }
    )


def _strip_line_comment(line: str) -> str:
    in_string = False
    quote = ""
    out = []
    i = 0
    while i < len(line):
        ch = line[i]
        nxt = line[i + 1] if i + 1 < len(line) else ""
        if not in_string and ch == "/" and nxt == "/":
            break
        if ch in ('"', "'"):
            if not in_string:
                in_string = True
                quote = ch
            elif i > 0 and line[i - 1] != "\\" and ch == quote:
                in_string = False
                quote = ""
        out.append(ch)
        i += 1
    return "".join(out)


def _find_function_blocks(lines: List[str]) -> List[Tuple[int, int]]:
    blocks = []
    start = None
    brace = 0
    pending_sig = None
    for i, raw in enumerate(lines):
        line = _strip_line_comment(raw)
        if start is None:
            if re.search(r"\)\s*\{\s*$", line) and not re.match(r"\s*(if|for|while|switch)\b", line):
                start = i
                brace = line.count("{") - line.count("}")
                pending_sig = None
            elif re.search(r"\)\s*$", line) and not re.match(r"\s*(if|for|while|switch)\b", line):
                pending_sig = i
            elif pending_sig is not None and re.match(r"^\s*\{\s*$", line):
                start = pending_sig
                brace = 1
                pending_sig = None
            elif pending_sig is not None and line.strip():
                pending_sig = None
        else:
            brace += line.count("{") - line.count("}")
            if brace <= 0:
                blocks.append((start, i))
                start = None
    return blocks


def _scan_pointer_level(lines: List[str], violations: List[dict], seen: Set[Tuple[int, str]], code: str):
    # R-1-3-1: 指针级数超过2级
    for i, raw in enumerate(lines, 1):
        line = _strip_line_comment(raw)
        m = re.search(r"\b[A-Za-z_][A-Za-z0-9_\s]*\*{3,}\s*[A-Za-z_][A-Za-z0-9_]*", line)
        if m:
            _add_violation(violations, seen, i, "R-1-3-1", get_code_snippet((i - 1, i - 1), code))


def _scan_function_pointer_usage(lines: List[str], violations: List[dict], seen: Set[Tuple[int, str]], code: str):
    # R-1-3-2 与 A-1-3-1
    for i, raw in enumerate(lines, 1):
        line = _strip_line_comment(raw)

        # 建议：函数指针定义
        if re.search(r"\(\s*\*\s*[A-Za-z_][A-Za-z0-9_]*\s*\)\s*\(", line):
            _add_violation(violations, seen, i, "A-1-3-1", get_code_snippet((i - 1, i - 1), code))

            # 近似检测策略：函数指针赋值右值是标识符且未使用&
            m_assign = re.search(r"=\s*([A-Za-z_][A-Za-z0-9_]*)\s*;", line)
            if m_assign and "=&" not in line and "=& " not in line and "=&".replace("&", ""):
                if not re.search(r"=\s*&\s*[A-Za-z_][A-Za-z0-9_]*\s*;", line):
                    _add_violation(violations, seen, i, "R-1-3-2", get_code_snippet((i - 1, i - 1), code))


def _scan_param_pointer_assign(lines: List[str], violations: List[dict], seen: Set[Tuple[int, str]], code: str):
    # R-1-3-3 近似检测策略：识别形参中的指针变量并检测对其整体赋值
    ptr_params = {}  # func_name -> set(param)

    sig_pat = re.compile(r"^\s*[A-Za-z_][\w\s\*]*\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)")
    for i, raw in enumerate(lines, 1):
        line = _strip_line_comment(raw)
        m = sig_pat.match(line)
        if not m:
            continue
        fname = m.group(1)
        params = m.group(2)
        if not params.strip():
            continue
        names = set()
        for p in params.split(","):
            p = p.strip()
            if "*" in p:
                n = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", p)
                if n:
                    names.add(n[-1])
        if names:
            ptr_params[fname] = names

    blocks = _find_function_blocks(lines)
    for s, e in blocks:
        head = _strip_line_comment(lines[s])
        m = sig_pat.match(head)
        if not m:
            continue
        fname = m.group(1)
        params = ptr_params.get(fname, set())
        if not params:
            continue
        for idx in range(s, e + 1):
            line = _strip_line_comment(lines[idx])
            for p in params:
                if re.search(rf"\b{re.escape(p)}\s*=\s*&?\s*[A-Za-z_][A-Za-z0-9_]*\s*;", line):
                    _add_violation(
                        violations,
                        seen,
                        idx + 1,
                        "R-1-3-3",
                        get_code_snippet((idx, idx), code),
                        p,
                    )


def _scan_return_local_addr(lines: List[str], violations: List[dict], seen: Set[Tuple[int, str]], code: str):
    # R-1-3-4 近似检测策略：return &local_var; 且 local_var 在本函数中声明
    blocks = _find_function_blocks(lines)
    decl_pat = re.compile(r"^\s*[A-Za-z_][\w\s\*]*\s+([A-Za-z_][A-Za-z0-9_]*)\s*(=|;|,)" )
    ret_pat = re.compile(r"\breturn\s*&\s*([A-Za-z_][A-Za-z0-9_]*)\s*;")

    for s, e in blocks:
        locals_in_func = set()
        for idx in range(s, e + 1):
            line = _strip_line_comment(lines[idx]).strip()
            m_decl = decl_pat.match(line)
            if m_decl and "(" not in line:
                locals_in_func.add(m_decl.group(1))

        for idx in range(s, e + 1):
            line = _strip_line_comment(lines[idx])
            m_ret = ret_pat.search(line)
            if not m_ret:
                continue
            var = m_ret.group(1)
            if var in locals_in_func:
                _add_violation(
                    violations,
                    seen,
                    idx + 1,
                    "R-1-3-4",
                    get_code_snippet((idx, idx), code),
                    var,
                )


def _scan_malloc_free_usage(lines: List[str], violations: List[dict], seen: Set[Tuple[int, str]], code: str):
    # R-1-3-5 / R-1-3-6 / R-1-3-7 / R-1-3-8 / R-1-3-9 / R-1-3-10
    ptr_state: Dict[str, Dict[str, Union[bool, int]]] = {}
    fp_state: Dict[str, Dict[str, Union[bool, int]]] = {}

    for i, raw in enumerate(lines, 1):
        line = _strip_line_comment(raw)

        # R-1-3-7: 动态指针定义时未初始化为NULL（近似）
        m_decl_ptr = re.search(r"\b[A-Za-z_][\w\s]*\*\s*([A-Za-z_][A-Za-z0-9_]*)\s*(=\s*[^;]+)?;", line)
        if m_decl_ptr:
            p = m_decl_ptr.group(1)
            init = m_decl_ptr.group(2) or ""
            if "malloc" in init or "calloc" in init:
                ptr_state[p] = {"allocated": True, "checked": False, "freed": False, "last_alloc_line": i}
            else:
                ptr_state.setdefault(p, {"allocated": False, "checked": False, "freed": False, "last_alloc_line": i})
                if init == "":
                    _add_violation(violations, seen, i, "R-1-3-7", get_code_snippet((i - 1, i - 1), code), p)

            # R-1-3-9: 使用0判空
            if re.search(r"=\s*0\s*;", init):
                _add_violation(violations, seen, i, "R-1-3-9", get_code_snippet((i - 1, i - 1), code), p)

        # 记录动态分配
        m_alloc = re.search(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\([^)]*\)\s*(malloc|calloc)\s*\(", line)
        if not m_alloc:
            m_alloc = re.search(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(malloc|calloc)\s*\(", line)
        if m_alloc:
            p = m_alloc.group(1)
            ptr_state[p] = {"allocated": True, "checked": False, "freed": False, "last_alloc_line": i}

        # NULL判别
        for p in list(ptr_state.keys()):
            if re.search(rf"\bif\s*\(\s*NULL\s*!=\s*{re.escape(p)}\s*\)", line) or re.search(
                rf"\bif\s*\(\s*{re.escape(p)}\s*!=\s*NULL\s*\)", line
            ):
                ptr_state[p]["checked"] = True

            # R-1-3-9: x != 0
            if re.search(rf"\bif\s*\(\s*{re.escape(p)}\s*!=\s*0\s*\)", line) or re.search(
                rf"\bif\s*\(\s*0\s*!=\s*{re.escape(p)}\s*\)", line
            ):
                _add_violation(violations, seen, i, "R-1-3-9", get_code_snippet((i - 1, i - 1), code), p)

        # R-1-3-8: 第一次解引用前未判NULL（近似）
        for p, st in ptr_state.items():
            if st.get("allocated") and not st.get("checked") and not st.get("freed"):
                if re.search(rf"\*\s*{re.escape(p)}\b", line) or re.search(rf"\b{re.escape(p)}\s*\[", line):
                    _add_violation(violations, seen, i, "R-1-3-8", get_code_snippet((i - 1, i - 1), code), p)
                    st["checked"] = True  # 防止重复刷屏

        # free调用
        m_free = re.search(r"\bfree\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)\s*;", line)
        if m_free:
            p = m_free.group(1)
            st = ptr_state.setdefault(p, {"allocated": False, "checked": False, "freed": False, "last_alloc_line": i})

            # R-1-3-5: 未分配就释放 / 重复释放
            if not st.get("allocated") or st.get("freed"):
                _add_violation(violations, seen, i, "R-1-3-5", get_code_snippet((i - 1, i - 1), code), p)

            st["freed"] = True

            # R-1-3-6: 释放后未置NULL（近似，查看后续3行）
            null_set = False
            for j in range(i, min(i + 3, len(lines))):
                nxt = _strip_line_comment(lines[j])
                if re.search(rf"\b{re.escape(p)}\s*=\s*NULL\s*;", nxt):
                    null_set = True
                    break
            if not null_set:
                _add_violation(violations, seen, i, "R-1-3-6", get_code_snippet((i - 1, min(i + 1, len(lines) - 1)), code), p)

        # R-1-3-5: 释放后继续使用
        for p, st in ptr_state.items():
            if st.get("freed"):
                if re.search(rf"\*\s*{re.escape(p)}\b", line) or re.search(rf"\b{re.escape(p)}\s*\[", line):
                    _add_violation(violations, seen, i, "R-1-3-5", get_code_snippet((i - 1, i - 1), code), f"use-after-free:{p}")

        # R-1-3-10: 文件指针close
        m_fopen = re.search(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*fopen\s*\(", line)
        if m_fopen:
            fp = m_fopen.group(1)
            fp_state[fp] = {"opened": True, "closed": False, "open_line": i}

        m_fclose = re.search(r"\bfclose\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)", line)
        if m_fclose:
            fp = m_fclose.group(1)
            if fp in fp_state:
                fp_state[fp]["closed"] = True

    for fp, st in fp_state.items():
        if st.get("opened") and not st.get("closed"):
            open_line = int(st.get("open_line", 1))
            _add_violation(
                violations,
                seen,
                open_line,
                "R-1-3-10",
                get_code_snippet((max(0, open_line - 1), min(len(lines) - 1, open_line + 1)), code),
                fp,
            )


def _scan_pointer_advisory(lines: List[str], violations: List[dict], seen: Set[Tuple[int, str]], code: str):
    for i, raw in enumerate(lines, 1):
        line = _strip_line_comment(raw)

        # A-1-3-2: void* 使用
        if re.search(r"\bvoid\s*\*\s*[A-Za-z_][A-Za-z0-9_]*", line):
            _add_violation(violations, seen, i, "A-1-3-2", get_code_snippet((i - 1, i - 1), code))

        # A-1-3-3: 指针算术
        if re.search(r"\b[A-Za-z_][A-Za-z0-9_]*\s*(\+\+|--|\+=|-=)\s*", line) and "*" in line:
            _add_violation(violations, seen, i, "A-1-3-3", get_code_snippet((i - 1, i - 1), code))
        if re.search(r"\*\s*\(\s*[A-Za-z_][A-Za-z0-9_]*\s*[+\-]\s*\d+\s*\)", line):
            _add_violation(violations, seen, i, "A-1-3-3", get_code_snippet((i - 1, i - 1), code))


def detect_c_cpp_gjb_5_3_violations(code: str, language: str = "cpp") -> List[dict]:
    """
    检测GJB 8114-2013中5.3（指针使用）条款的违规。

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

    _scan_pointer_level(lines, violations, seen, code)
    _scan_function_pointer_usage(lines, violations, seen, code)
    _scan_param_pointer_assign(lines, violations, seen, code)
    _scan_return_local_addr(lines, violations, seen, code)
    _scan_malloc_free_usage(lines, violations, seen, code)
    _scan_pointer_advisory(lines, violations, seen, code)

    return sorted(violations, key=lambda x: (x["line"], x["rule_id"]))


def analyze_c_cpp_gjb_5_3(code_string: str, language: str = "cpp") -> List[dict]:
    return detect_c_cpp_gjb_5_3_violations(code_string, language)


if __name__ == "__main__":
    test_cases = [
        (
            "c_pointer_level_and_return_local",
            "c",
            """
int*** p3 = 0;
int* f(void){
    int x = 0;
    return &x;
}
""",
        ),
        (
            "c_free_and_null",
            "c",
            """
#include <malloc.h>
int main(void){
    int *x;
    int *y = (int*)malloc(sizeof(int));
    *y = 1;
    free(y);
    *y = 2;
    return 0;
}
""",
        ),
        (
            "c_func_ptr_and_void_ptr",
            "c",
            """
int fun(int a, int b){ return a-b; }
int main(void){
    int (*p)(int,int)=fun;
    void *u = 0;
    return p(1,2);
}
""",
        ),
        (
            "c_file_pointer_not_closed",
            "c",
            """
#include <stdio.h>
int main(void){
    FILE *stream = fopen("data", "r");
    if(stream==NULL){ return -1; }
    return 0;
}
""",
        ),
        (
            "cpp_param_pointer_assign",
            "cpp",
            """
unsigned int pfun(unsigned int *pa){
    static unsigned int i = 10;
    pa = &i;
    return i;
}
""",
        ),
        (
            "cpp_compliant_sample",
            "cpp",
            """
#include <malloc.h>
int fun(int a,int b){ return a+b; }
int main(void){
    int *x = NULL;
    x = (int*)malloc(sizeof(int));
    if(NULL != x){
        *x = 1;
        free(x);
        x = NULL;
    }
    int (*p)(int,int)=&fun;
    return p(1,2);
}
""",
        ),
    ]

    for name, lang, src in test_cases:
        print("=" * 70)
        print(f"CASE: {name} ({lang})")
        results = analyze_c_cpp_gjb_5_3(src, lang)
        if not results:
            print("未检测到违规")
            continue
        print(f"检测到 {len(results)} 个违规")
        for item in results:
            print(
                f"line={item['line']} | rule_id={item['rule_id']} | "
                f"message={item['message']} | code_snippet={item['code_snippet'].replace(chr(10), ' ')}"
            )
