import importlib.util
import inspect
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set, Tuple


RULE_ID_PATTERN = re.compile(r"[RA]-\d+-\d+-\d+", re.IGNORECASE)


@dataclass
class RuleModule:
    module_name: str
    file_path: Path
    analyzer: Callable
    declared_rule_ids: Set[str]


def extract_rule_id_from_name(file_name: str) -> Optional[str]:
    m = RULE_ID_PATTERN.search(file_name)
    if not m:
        return None
    return m.group(0).upper()


def load_module_from_file(file_path: Path):
    spec = importlib.util.spec_from_file_location(file_path.stem, str(file_path))
    if spec is None or spec.loader is None:
        raise RuntimeError(f"无法加载模块: {file_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def choose_analyzer(module) -> Optional[Callable]:
    funcs = inspect.getmembers(module, inspect.isfunction)
    analyze_candidates = [f for n, f in funcs if n.startswith("analyze_")]
    detect_candidates = [f for n, f in funcs if n.startswith("detect_") and "violation" in n]

    for fn in analyze_candidates + detect_candidates:
        try:
            sig = inspect.signature(fn)
        except (TypeError, ValueError):
            continue
        if len(sig.parameters) >= 1:
            return fn
    return None


def extract_declared_rule_ids(module) -> Set[str]:
    found: Set[str] = set()
    for attr_name in dir(module):
        if not attr_name.startswith("RULES_"):
            continue
        value = getattr(module, attr_name, None)
        if isinstance(value, list):
            for item in value:
                if isinstance(item, dict) and "rule_id" in item:
                    rid = str(item["rule_id"]).upper()
                    if RULE_ID_PATTERN.fullmatch(rid):
                        found.add(rid)
    return found


def discover_rule_modules(base_dir: Path) -> Tuple[List[RuleModule], List[str]]:
    errors: List[str] = []
    modules: List[RuleModule] = []

    rule_files: List[Path] = []
    for sub in ("c_cpp", "cpp"):
        rule_files.extend(sorted((base_dir / sub).glob("R_*.py")))

    for file_path in rule_files:
        try:
            module = load_module_from_file(file_path)
            analyzer = choose_analyzer(module)
            if analyzer is None:
                errors.append(f"[跳过] {file_path.name}: 未找到可调用分析函数")
                continue

            modules.append(
                RuleModule(
                    module_name=file_path.stem,
                    file_path=file_path,
                    analyzer=analyzer,
                    declared_rule_ids=extract_declared_rule_ids(module),
                )
            )
        except Exception as exc:
            errors.append(f"[加载失败] {file_path.name}: {exc}")

    return modules, errors


def run_analyzer(analyzer: Callable, code: str) -> List[dict]:
    # 绝大多数规则函数支持 language 关键字；不支持时自动降级。
    try:
        result = analyzer(code, language="cpp")
    except TypeError:
        result = analyzer(code)

    if isinstance(result, list):
        return [x for x in result if isinstance(x, dict)]
    return []


def evaluate_samples(base_dir: Path) -> Dict:
    sample_root = base_dir / "GJB_test_sample"
    compliant_dir = sample_root / "compliant"
    violation_dir = sample_root / "violation"

    modules, module_errors = discover_rule_modules(base_dir)

    all_files: List[Path] = sorted(compliant_dir.rglob("*.cpp")) + sorted(violation_dir.rglob("*.cpp"))

    false_positives: List[Dict] = []
    false_negatives: List[Dict] = []
    unexpected_hits: List[Dict] = []
    file_errors: List[Dict] = []

    per_file_results: List[Dict] = []

    for cpp_file in all_files:
        scope = "compliant" if compliant_dir in cpp_file.parents else "violation"
        expected_rule_id = extract_rule_id_from_name(cpp_file.stem)

        try:
            code = cpp_file.read_text(encoding="utf-8", errors="ignore")
        except Exception as exc:
            file_errors.append({"file": str(cpp_file), "error": f"读取失败: {exc}"})
            continue

        detected_rule_ids: Set[str] = set()
        detailed_hits: List[Dict] = []

        for rm in modules:
            try:
                hits = run_analyzer(rm.analyzer, code)
                for hit in hits:
                    rid = str(hit.get("rule_id", "")).upper()
                    if RULE_ID_PATTERN.fullmatch(rid):
                        detected_rule_ids.add(rid)
                        detailed_hits.append(
                            {
                                "module": rm.module_name,
                                "rule_id": rid,
                                "line": hit.get("line"),
                                "message": hit.get("message", ""),
                            }
                        )
            except Exception as exc:
                file_errors.append(
                    {
                        "file": str(cpp_file),
                        "error": f"规则执行失败: {rm.module_name}: {exc}",
                    }
                )

        detected_sorted = sorted(detected_rule_ids)

        if expected_rule_id:
            if scope == "compliant" and expected_rule_id in detected_rule_ids:
                false_positives.append(
                    {
                        "file": str(cpp_file),
                        "expected_rule_id": expected_rule_id,
                        "detected_rule_ids": detected_sorted,
                    }
                )

            if scope == "violation" and expected_rule_id not in detected_rule_ids:
                false_negatives.append(
                    {
                        "file": str(cpp_file),
                        "expected_rule_id": expected_rule_id,
                        "detected_rule_ids": detected_sorted,
                    }
                )

            extras = sorted([x for x in detected_rule_ids if x != expected_rule_id and not x.startswith("A-")])
            if extras:
                unexpected_hits.append(
                    {
                        "file": str(cpp_file),
                        "scope": scope,
                        "expected_rule_id": expected_rule_id,
                        "extra_rule_ids": extras,
                    }
                )

        per_file_results.append(
            {
                "file": str(cpp_file),
                "scope": scope,
                "expected_rule_id": expected_rule_id,
                "detected_rule_ids": detected_sorted,
                "hit_count": len(detailed_hits),
            }
        )

    summary = {
        "total_rule_modules": len(modules),
        "total_cpp_files": len(all_files),
        "compliant_files": len(list(compliant_dir.rglob("*.cpp"))),
        "violation_files": len(list(violation_dir.rglob("*.cpp"))),
        "false_positive_count": len(false_positives),
        "false_negative_count": len(false_negatives),
        "unexpected_hit_count": len(unexpected_hits),
        "module_error_count": len(module_errors),
        "file_error_count": len(file_errors),
    }

    module_overview = [
        {
            "module": rm.module_name,
            "file": str(rm.file_path),
            "declared_rule_ids": sorted(rm.declared_rule_ids),
        }
        for rm in modules
    ]

    return {
        "summary": summary,
        "module_overview": module_overview,
        "module_errors": module_errors,
        "file_errors": file_errors,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "unexpected_hits": unexpected_hits,
        "per_file_results": per_file_results,
    }


def build_markdown_report(result: Dict) -> str:
    s = result["summary"]
    lines: List[str] = []

    lines.append("# GJB 样例批量检测报告")
    lines.append("")
    lines.append("## 1. 汇总")
    lines.append(f"- 规则模块数: {s['total_rule_modules']}")
    lines.append(f"- 样例总数: {s['total_cpp_files']} (compliant={s['compliant_files']}, violation={s['violation_files']})")
    lines.append(f"- 误报数(同rule_id): {s['false_positive_count']}")
    lines.append(f"- 漏报数(同rule_id): {s['false_negative_count']}")
    lines.append(f"- 非对应rule_id命中记录数: {s['unexpected_hit_count']}")
    lines.append(f"- 模块加载错误数: {s['module_error_count']}")
    lines.append(f"- 文件执行错误数: {s['file_error_count']}")
    lines.append("")

    lines.append("## 2. 规则模块")
    for m in result["module_overview"]:
        rid_text = ", ".join(m["declared_rule_ids"]) if m["declared_rule_ids"] else "(未声明RULES_xxx)"
        lines.append(f"- {m['module']} -> {rid_text}")
    lines.append("")

    lines.append("## 3. 误报清单(compliant中检出同rule_id)")
    if not result["false_positives"]:
        lines.append("- 无")
    else:
        for item in result["false_positives"]:
            lines.append(f"- {item['file']} | expected={item['expected_rule_id']} | detected={item['detected_rule_ids']}")
    lines.append("")

    lines.append("## 4. 漏报清单(violation中未检出同rule_id)")
    if not result["false_negatives"]:
        lines.append("- 无")
    else:
        for item in result["false_negatives"]:
            lines.append(f"- {item['file']} | expected={item['expected_rule_id']} | detected={item['detected_rule_ids']}")
    lines.append("")

    lines.append("## 5. 非对应rule_id命中清单")
    if not result["unexpected_hits"]:
        lines.append("- 无")
    else:
        for item in result["unexpected_hits"]:
            lines.append(
                f"- {item['file']} | scope={item['scope']} | expected={item['expected_rule_id']} | extras={item['extra_rule_ids']}"
            )
    lines.append("")

    lines.append("## 6. 模块与执行错误")
    if not result["module_errors"] and not result["file_errors"]:
        lines.append("- 无")
    else:
        for e in result["module_errors"]:
            lines.append(f"- module_error: {e}")
        for e in result["file_errors"]:
            lines.append(f"- file_error: {e['file']} | {e['error']}")
    lines.append("")

    return "\n".join(lines)


def main():
    base_dir = Path(__file__).resolve().parent
    result = evaluate_samples(base_dir)

    report_md = build_markdown_report(result)
    report_path = base_dir / "GJB_test_sample_evaluation_report.md"
    report_json_path = base_dir / "GJB_test_sample_evaluation_report.json"

    report_path.write_text(report_md, encoding="utf-8")
    report_json_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")

    s = result["summary"]
    print("评测完成")
    print(f"规则模块: {s['total_rule_modules']}")
    print(f"样例总数: {s['total_cpp_files']}")
    print(f"误报: {s['false_positive_count']} | 漏报: {s['false_negative_count']} | 非对应命中: {s['unexpected_hit_count']}")
    print(f"报告文件: {report_path}")
    print(f"明细文件: {report_json_path}")


if __name__ == "__main__":
    main()
