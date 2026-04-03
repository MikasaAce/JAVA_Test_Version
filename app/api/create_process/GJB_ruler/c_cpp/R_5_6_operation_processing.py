import re
from typing import Dict, List, Set, Tuple, Union


RULES_5_6 = [
    {"rule_id": "R-1-6-1", "message": "GJB R-1-6-1: 禁止将浮点常数赋给整型变量", "severity": "中危"},
    {"rule_id": "R-1-6-2", "message": "GJB R-1-6-2: 禁止将越界整数赋给整型变量", "severity": "高危"},
    {"rule_id": "R-1-6-3", "message": "GJB R-1-6-3: 禁止在逻辑表达式中使用赋值语句", "severity": "高危"},
    {"rule_id": "R-1-6-4", "message": "GJB R-1-6-4: 禁止对逻辑表达式进行位运算", "severity": "中危"},
    {"rule_id": "R-1-6-5", "message": "GJB R-1-6-5: 禁止在运算表达式中或函数调用参数中使用++或--", "severity": "中危"},
    {"rule_id": "R-1-6-6", "message": "GJB R-1-6-6: 对变量进行移位运算禁止超出变量长度", "severity": "高危"},
    {"rule_id": "R-1-6-7", "message": "GJB R-1-6-7: 禁止移位操作中的移位数为负数", "severity": "高危"},
    {"rule_id": "R-1-6-8", "message": "GJB R-1-6-8: 数组禁止越界使用", "severity": "高危"},
    {"rule_id": "R-1-6-9", "message": "GJB R-1-6-9: 数组下标必须是大于等于零的整型数", "severity": "高危"},
    {"rule_id": "R-1-6-10", "message": "GJB R-1-6-10: 禁止对常数值做逻辑非运算", "severity": "中危"},
    {"rule_id": "R-1-6-11", "message": "GJB R-1-6-11: 禁止非枚举类型变量使用枚举类型值", "severity": "中危"},
    {"rule_id": "R-1-6-12", "message": "GJB R-1-6-12: 除法运算中禁止被零除", "severity": "高危"},
    {"rule_id": "R-1-6-13", "message": "GJB R-1-6-13: 禁止在sizeof中使用赋值", "severity": "中危"},
    {"rule_id": "R-1-6-14", "message": "GJB R-1-6-14: 缓冲区读取操作禁止越界", "severity": "高危"},
    {"rule_id": "R-1-6-15", "message": "GJB R-1-6-15: 缓冲区写入操作禁止越界", "severity": "高危"},
    {"rule_id": "R-1-6-16", "message": "GJB R-1-6-16: 禁止使用已被释放的内存空间", "severity": "高危"},
    {"rule_id": "R-1-6-17", "message": "GJB R-1-6-17: 被free的指针必须指向最初malloc/calloc分配地址", "severity": "高危"},
    {"rule_id": "R-1-6-18", "message": "GJB R-1-6-18: 禁止使用gets函数，应使用fgets替代", "severity": "高危"},
    {"rule_id": "R-1-6-19", "message": "GJB R-1-6-19: 字符串赋值/拷贝/追加时禁止目标越界", "severity": "高危"},
    {"rule_id": "A-1-6-1", "message": "GJB A-1-6-1: 谨慎对有符号整型量进行位运算", "severity": "建议"},
    {"rule_id": "A-1-6-2", "message": "GJB A-1-6-2: 谨慎做整型量除以整型变量的除法", "severity": "建议"},
    {"rule_id": "A-1-6-3", "message": "GJB A-1-6-3: 动态申请的内存空间用完后及时释放", "severity": "建议"},
    {"rule_id": "A-1-6-4", "message": "GJB A-1-6-4: 避免使用strcpy，应使用strncpy", "severity": "建议"},
    {"rule_id": "A-1-6-5", "message": "GJB A-1-6-5: 避免使用strcat，应使用strncat", "severity": "建议"},
    {"rule_id": "A-1-6-6", "message": "GJB A-1-6-6: 谨慎使用逗号操作符", "severity": "建议"},
]

RULE_META: Dict[str, dict] = {x["rule_id"]: x for x in RULES_5_6}

TYPE_BITS = {
    "unsigned char": (0, 255),
    "signed char": (-128, 127),
    "char": (-128, 255),
    "unsigned short": (0, 65535),
    "short": (-32768, 32767),
    "signed short": (-32768, 32767),
}


def extract_rule_id(message: str) -> str:
    m = re.search(r"[RA]-\d+-\d+-\d+", message or "")
    if m:
        return m.group(0)
    return "R-1-6-UNKNOWN"


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


def _collect_arrays(lines: List[str]) -> Dict[str, int]:
    arrays = {}
    for line in lines:
        s = _strip_line_comment(line)
        for m in re.finditer(
            r"\b(?:const\s+)?(?:unsigned\s+|signed\s+)?(?:char|short|int|long|float|double|bool|size_t)\b(?:\s+[A-Za-z_][A-Za-z0-9_]*)*\s+([A-Za-z_][A-Za-z0-9_]*)\s*\[\s*(\d+)\s*\]",
            s,
        ):
            arrays[m.group(1)] = int(m.group(2))
    return arrays


def _collect_enums(lines: List[str]) -> Set[str]:
    enum_values = set()
    buf = []
    in_enum = False
    for line in lines:
        s = _strip_line_comment(line)
        if "enum" in s and "{" in s:
            in_enum = True
            buf = [s]
            if "}" in s:
                in_enum = False
                text = " ".join(buf)
                inside = text.split("{", 1)[1].split("}", 1)[0]
                for p in inside.split(","):
                    name = p.split("=", 1)[0].strip()
                    if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", name):
                        enum_values.add(name)
        elif in_enum:
            buf.append(s)
            if "}" in s:
                in_enum = False
                text = " ".join(buf)
                inside = text.split("{", 1)[1].split("}", 1)[0]
                for p in inside.split(","):
                    name = p.split("=", 1)[0].strip()
                    if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", name):
                        enum_values.add(name)
    return enum_values


def _scan_rules(lines: List[str], code: str, language: str, violations: List[dict], seen: Set[Tuple[int, str]]):
    arrays = _collect_arrays(lines)
    enum_values = _collect_enums(lines)

    ptr_state: Dict[str, Dict[str, Union[bool, int]]] = {}

    for i, raw in enumerate(lines, 1):
        s = _strip_line_comment(raw)
        decl_arrays_on_line = set(
            m.group(1)
            for m in re.finditer(
                r"\b(?:const\s+)?(?:unsigned\s+|signed\s+)?(?:char|short|int|long|float|double|bool|size_t)\b(?:\s+[A-Za-z_][A-Za-z0-9_]*)*\s+([A-Za-z_][A-Za-z0-9_]*)\s*\[\s*\d+\s*\]",
                s,
            )
        )

        # R-1-6-1
        if re.search(r"\b(?:int|short|long|unsigned\s+int|unsigned\s+short|signed\s+int|signed\s+short)\b\s+[A-Za-z_][A-Za-z0-9_]*\s*=\s*-?\d+\.\d+\b", s):
            _add_violation(violations, seen, i, "R-1-6-1", get_code_snippet((i - 1, i - 1), code))

        # R-1-6-2
        m_bound = re.search(r"\b(unsigned\s+char|signed\s+char|unsigned\s+short|signed\s+short|short|char)\b\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(-?\d+)\b", s)
        if m_bound:
            t = m_bound.group(1)
            v = int(m_bound.group(3))
            lo, hi = TYPE_BITS.get(t, (-10**18, 10**18))
            if v < lo or v > hi:
                _add_violation(violations, seen, i, "R-1-6-2", get_code_snippet((i - 1, i - 1), code), f"{v} out-of-range")

        # R-1-6-3
        if re.search(r"\b(if|while)\s*\([^\)]*[^=!<>]=[^=][^\)]*\)", s):
            _add_violation(violations, seen, i, "R-1-6-3", get_code_snippet((i - 1, i - 1), code))

        # R-1-6-4
        if re.search(r"\b(if|while)\s*\([^\)]*(\|\||&&)[^\)]*[&|][^\)]*\)", s):
            _add_violation(violations, seen, i, "R-1-6-4", get_code_snippet((i - 1, i - 1), code))

        # R-1-6-5
        if "++" in s or "--" in s:
            standalone_inc = re.match(r"^\s*(?:\+\+|--)?\s*[A-Za-z_][A-Za-z0-9_]*\s*(?:\+\+|--)\s*;\s*$", s)
            if not standalone_inc:
                in_func_args = re.search(r"\w+\s*\([^\)]*(\+\+|--)[^\)]*\)", s)
                in_arith_expr = re.search(r"=\s*[^;]*(\+\+|--)[^;]*[+\-*/%][^;]*;", s) or re.search(r"[+\-*/%]\s*[^;]*(\+\+|--)", s)
                if in_func_args or in_arith_expr:
                    _add_violation(violations, seen, i, "R-1-6-5", get_code_snippet((i - 1, i - 1), code))

        # R-1-6-6 / R-1-6-7
        m_shift = re.search(r"<<\s*(-?\d+)|>>\s*(-?\d+)", s)
        if m_shift:
            n = int((m_shift.group(1) or m_shift.group(2)))
            if n < 0:
                _add_violation(violations, seen, i, "R-1-6-7", get_code_snippet((i - 1, i - 1), code), str(n))
            if n > 31:
                _add_violation(violations, seen, i, "R-1-6-6", get_code_snippet((i - 1, i - 1), code), str(n))

        # R-1-6-8 / R-1-6-9 direct
        for m in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\[\s*(-?\d+)\s*\]", s):
            arr = m.group(1)
            idx = int(m.group(2))
            if arr in decl_arrays_on_line:
                continue
            if idx < 0:
                _add_violation(violations, seen, i, "R-1-6-9", get_code_snippet((i - 1, i - 1), code), arr)
            if arr in arrays and idx >= arrays[arr]:
                _add_violation(violations, seen, i, "R-1-6-8", get_code_snippet((i - 1, i - 1), code), f"{arr}[{idx}] >= {arrays[arr]}")

        # R-1-6-10
        if re.search(r"!\s*(0x[0-9A-Fa-f]+|\d+)\b", s):
            _add_violation(violations, seen, i, "R-1-6-10", get_code_snippet((i - 1, i - 1), code))

        # R-1-6-11
        if enum_values and re.search(r"\b(?:int|unsigned\s+int|short|long|char)\b\s+[A-Za-z_][A-Za-z0-9_]*\s*=\s*([A-Za-z_][A-Za-z0-9_]*)\s*;", s):
            e = re.search(r"=\s*([A-Za-z_][A-Za-z0-9_]*)\s*;", s).group(1)
            if e in enum_values:
                _add_violation(violations, seen, i, "R-1-6-11", get_code_snippet((i - 1, i - 1), code), e)

        # R-1-6-12
        if re.search(r"/\s*0\b|%\s*0\b", s):
            _add_violation(violations, seen, i, "R-1-6-12", get_code_snippet((i - 1, i - 1), code))

        # R-1-6-13
        if re.search(r"sizeof\s*\([^\)]*[^=!<>]=[^=][^\)]*\)", s):
            _add_violation(violations, seen, i, "R-1-6-13", get_code_snippet((i - 1, i - 1), code))

        # R-1-6-14 / 15 memcpy size
        m_memcpy = re.search(r"memcpy\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*,\s*([A-Za-z_][A-Za-z0-9_]*)\s*,\s*sizeof\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)\s*\)", s)
        if m_memcpy:
            des, src, sz = m_memcpy.group(1), m_memcpy.group(2), m_memcpy.group(3)
            if des in arrays and src in arrays and sz == des and arrays[src] < arrays[des]:
                _add_violation(violations, seen, i, "R-1-6-14", get_code_snippet((i - 1, i - 1), code))
            if des in arrays and src in arrays and sz == src and arrays[src] > arrays[des]:
                _add_violation(violations, seen, i, "R-1-6-15", get_code_snippet((i - 1, i - 1), code))

        # memory lifecycle for R-1-6-16/17/A-1-6-3
        m_alloc = re.search(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\([^\)]*\)\s*(malloc|calloc)\s*\(", s)
        if not m_alloc:
            m_alloc = re.search(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(malloc|calloc)\s*\(", s)
        if m_alloc:
            p = m_alloc.group(1)
            ptr_state[p] = {"allocated": True, "freed": False, "origin_ok": True, "line": i, "shifted": False}

        # pointer moved then free: R-1-6-17
        if re.search(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*(\+\+|--|\+=|-=)", s):
            p = re.search(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*(\+\+|--|\+=|-=)", s).group(1)
            if p in ptr_state and ptr_state[p]["allocated"] and not ptr_state[p]["freed"]:
                ptr_state[p]["shifted"] = True

        m_free = re.search(r"\bfree\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)", s)
        if m_free:
            p = m_free.group(1)
            if p in ptr_state and ptr_state[p].get("shifted"):
                _add_violation(violations, seen, i, "R-1-6-17", get_code_snippet((i - 1, i - 1), code), p)
            if p in ptr_state:
                ptr_state[p]["freed"] = True

        for p, st in ptr_state.items():
            if st.get("freed") and (re.search(rf"\*\s*{re.escape(p)}\b", s) or re.search(rf"\b{re.escape(p)}\s*\[", s)):
                _add_violation(violations, seen, i, "R-1-6-16", get_code_snippet((i - 1, i - 1), code), p)

        # R-1-6-18
        if re.search(r"\bgets\s*\(", s):
            _add_violation(violations, seen, i, "R-1-6-18", get_code_snippet((i - 1, i - 1), code))

        # R-1-6-19
        if re.search(r"\b(strncpy|strcpy|strcat|strncat)\s*\(", s):
            m_call = re.search(r"\b(strncpy|strcpy|strcat|strncat)\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*,\s*([^,\)]*)(?:,\s*([^\)]*))?\)", s)
            if m_call:
                fn = m_call.group(1)
                des = m_call.group(2)
                n = m_call.group(4)
                if des in arrays and n and re.match(r"\s*\d+\s*$", n):
                    if int(n) > arrays[des]:
                        _add_violation(violations, seen, i, "R-1-6-19", get_code_snippet((i - 1, i - 1), code), f"{fn}:{des}")
                elif fn in ("strcpy", "strcat"):
                    _add_violation(violations, seen, i, "R-1-6-19", get_code_snippet((i - 1, i - 1), code), fn)

        # A-1-6-1
        if "unsigned" not in s and re.search(r"\b(signed\s+)?(int|short|long)\b[^;]*[&|^~<>]{1,2}", s):
            _add_violation(violations, seen, i, "A-1-6-1", get_code_snippet((i - 1, i - 1), code))

        # A-1-6-2
        if re.search(r"\b\d+\s*/\s*[A-Za-z_][A-Za-z0-9_]*\b", s):
            _add_violation(violations, seen, i, "A-1-6-2", get_code_snippet((i - 1, i - 1), code))

        # A-1-6-4 / A-1-6-5
        if re.search(r"\bstrcpy\s*\(", s):
            _add_violation(violations, seen, i, "A-1-6-4", get_code_snippet((i - 1, i - 1), code))
        if re.search(r"\bstrcat\s*\(", s):
            _add_violation(violations, seen, i, "A-1-6-5", get_code_snippet((i - 1, i - 1), code))

        # A-1-6-6
        if re.search(r"=\s*\([^\)]*,[^\)]*\)", s):
            _add_violation(violations, seen, i, "A-1-6-6", get_code_snippet((i - 1, i - 1), code))

    # A-1-6-3
    for p, st in ptr_state.items():
        if st.get("allocated") and not st.get("freed"):
            line = int(st.get("line", 1))
            _add_violation(violations, seen, line, "A-1-6-3", get_code_snippet((line - 1, line - 1), code), p)


def detect_c_cpp_gjb_5_6_violations(code: str, language: str = "cpp") -> List[dict]:
    """
    检测GJB 8114-2013中5.6（运算处理）条款的违规。

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


def analyze_c_cpp_gjb_5_6(code_string: str, language: str = "cpp") -> List[dict]:
    return detect_c_cpp_gjb_5_6_violations(code_string, language)


if __name__ == "__main__":
    test_cases = [
        (
            "c_basic_violations",
            "c",
            """
#include <string.h>
#include <malloc.h>
int main(void){
    int idata = 2.5;
    unsigned char uc = 256;
    int i=0,j=0;
    if(i=1){ j++; }
    if(i==1 || j==2 & i==0){ j=3; }
    int x=1,y=2,z=3;
    y = y + (x++);
    unsigned int a = 1;
    unsigned int b = a << 33;
    unsigned int c = a >> -1;
    int arr[3] = {0,1,2};
    arr[3] = 1;
    arr[-1] = 2;
    if(i==!1){ j=1; }
    enum E {EA=0, EB};
    int t = EB;
    int d = 5 / 0;
    int e = sizeof(i=j);
    int src[4]={1,2,3,4};
    int des[2]={0,0};
    memcpy(des, src, sizeof(src));
    char *p = (char*)malloc(16);
    free(p);
    *p = 'a';
    gets(p);
    char string1[10]={0};
    strncpy(string1, "hello world", 11);
    strcpy(string1, "abc");
    int m,n,o;
    m = (n=1, o=2);
    return 0;
}
""",
        ),
        (
            "cpp_compliant_sample",
            "cpp",
            """
#include <string.h>
#include <malloc.h>
int main(void){
    int idata = 3;
    unsigned short us = 256;
    int i=0,j=0;
    if(i==1){ j++; }
    int x=1,y=2,z=3;
    y = y + x;
    x++;
    unsigned int a = 1;
    unsigned int b = a << 1;
    int arr[3] = {0,1,2};
    arr[2] = 1;
    if(i!=1){ j=1; }
    int d = 5 / 1;
    int e = sizeof(i);
    int src[2]={1,2};
    int des[4]={0,0,0,0};
    memcpy(des, src, sizeof(src));
    char *p = (char*)malloc(16);
    if(NULL != p){
        p[0] = 'a';
        free(p);
        p = NULL;
    }
    char string1[12]={0};
    strncpy(string1, "hello", 5);
    return 0;
}
""",
        ),
    ]

    for name, lang, src in test_cases:
        print("=" * 70)
        print(f"CASE: {name} ({lang})")
        results = analyze_c_cpp_gjb_5_6(src, lang)
        if not results:
            print("未检测到违规")
            continue
        print(f"检测到 {len(results)} 个违规")
        for item in results:
            print(
                f"line={item['line']} | rule_id={item['rule_id']} | "
                f"message={item['message']} | code_snippet={item['code_snippet'].replace(chr(10), ' ')}"
            )
