import os
import re
from tree_sitter import Language, Parser

# 假设language_path已经在配置中定义
from .config_path import language_path

# 导入GJB检测模块
from .cpp_gjb_memory import detect_cpp_gjb_memory_violations
from .cpp_gjb_type import detect_cpp_gjb_type_violations
from .cpp_gjb_coding import detect_cpp_gjb_coding_violations

# 加载C++语言
LANGUAGES = {
    'cpp': Language(language_path, 'cpp'),
}


def detect_cpp_gjb_violations(code, language='cpp'):
    """
    综合检测C++代码中GJB 8114-2013规则违规
    
    Args:
        code: C++源代码字符串
        language: 语言类型，默认为'cpp'
    
    Returns:
        dict: 检测结果字典，包含各类违规和汇总统计
    """
    if language not in LANGUAGES:
        return {
            'memory_safety': [],
            'type_safety': [],
            'coding_standard': [],
            'summary': {
                'total_violations': 0,
                'by_severity': {'高危': 0, '中危': 0, '低危': 0, '建议': 0},
                'by_type': {'内存安全': 0, '类型安全': 0, '编码规范': 0},
                'compliance_rate': 100.0
            }
        }
    
    # 运行各个检测模块
    memory_violations = detect_cpp_gjb_memory_violations(code, language)
    type_violations = detect_cpp_gjb_type_violations(code, language)
    coding_violations = detect_cpp_gjb_coding_violations(code, language)
    
    # 汇总统计
    all_violations = memory_violations + type_violations + coding_violations
    total_lines = len(code.split('\n'))
    
    # 统计按严重程度
    by_severity = {'高危': 0, '中危': 0, '低危': 0, '建议': 0}
    for violation in all_violations:
        severity = violation.get('severity', '低危')
        if severity in by_severity:
            by_severity[severity] += 1
    
    # 统计按违规类型
    by_type = {'内存安全': 0, '类型安全': 0, '编码规范': 0}
    for violation in all_violations:
        violation_type = violation.get('violation_type', '编码规范')
        if violation_type in by_type:
            by_type[violation_type] += 1
    
    # 计算合规率（简化版本）
    # 假设每100行代码平均有20个需要检查的点
    check_points = max(1, total_lines * 0.2)
    violation_rate = min(100.0, len(all_violations) / check_points * 100)
    compliance_rate = 100.0 - violation_rate
    
    return {
        'memory_safety': memory_violations,
        'type_safety': type_violations,
        'coding_standard': coding_violations,
        'summary': {
            'total_violations': len(all_violations),
            'by_severity': by_severity,
            'by_type': by_type,
            'compliance_rate': round(compliance_rate, 2),
            'quality_grade': get_quality_grade(compliance_rate),
            'total_lines': total_lines
        }
    }


def get_quality_grade(compliance_rate):
    """根据合规率获取质量等级"""
    if compliance_rate >= 95.0:
        return '非常好'
    elif compliance_rate >= 90.0:
        return '好'
    elif compliance_rate >= 80.0:
        return '一般'
    elif compliance_rate >= 70.0:
        return '较差'
    elif compliance_rate >= 60.0:
        return '差'
    else:
        return '非常差'


def analyze_cpp_gjb_comprehensive(code_string):
    """
    综合分析C++代码字符串中的GJB规则违规
    """
    return detect_cpp_gjb_violations(code_string, 'cpp')


def generate_gjb_report(results, output_file=None):
    """
    生成GJB检测报告
    
    Args:
        results: 检测结果字典
        output_file: 输出文件路径（可选）
    
    Returns:
        str: 报告文本
    """
    report_lines = []
    
    # 报告头部
    report_lines.append("=" * 80)
    report_lines.append("GJB 8114-2013 C/C++语言编程安全子集检测报告")
    report_lines.append("=" * 80)
    
    # 汇总信息
    summary = results['summary']
    report_lines.append(f"\n📊 汇总统计")
    report_lines.append(f"   总行数: {summary['total_lines']}")
    report_lines.append(f"   总违规数: {summary['total_violations']}")
    report_lines.append(f"   合规率: {summary['compliance_rate']}%")
    report_lines.append(f"   质量等级: {summary['quality_grade']}")
    
    # 按严重程度统计
    report_lines.append(f"\n⚠️ 按严重程度分布:")
    for severity, count in summary['by_severity'].items():
        if count > 0:
            report_lines.append(f"   {severity}: {count} 个")
    
    # 按违规类型统计
    report_lines.append(f"\n📋 按违规类型分布:")
    for violation_type, count in summary['by_type'].items():
        if count > 0:
            report_lines.append(f"   {violation_type}: {count} 个")
    
    # 详细违规列表
    report_lines.append(f"\n🔍 详细违规列表:")
    
    # 内存安全违规
    if results['memory_safety']:
        report_lines.append(f"\n💾 内存安全违规 ({len(results['memory_safety'])} 个):")
        for i, violation in enumerate(results['memory_safety'], 1):
            report_lines.append(f"  {i}. 行 {violation['line']}: [{violation['rule_id']}] {violation['message']}")
            report_lines.append(f"     严重程度: {violation['severity']}, 代码: {violation['code_snippet'][:80]}...")
    
    # 类型安全违规
    if results['type_safety']:
        report_lines.append(f"\n🔢 类型安全违规 ({len(results['type_safety'])} 个):")
        for i, violation in enumerate(results['type_safety'], 1):
            report_lines.append(f"  {i}. 行 {violation['line']}: [{violation['rule_id']}] {violation['message']}")
            report_lines.append(f"     严重程度: {violation['severity']}, 代码: {violation['code_snippet'][:80]}...")
    
    # 编码规范违规
    if results['coding_standard']:
        report_lines.append(f"\n📝 编码规范违规 ({len(results['coding_standard'])} 个):")
        for i, violation in enumerate(results['coding_standard'], 1):
            report_lines.append(f"  {i}. 行 {violation['line']}: [{violation['rule_id']}] {violation['message']}")
            report_lines.append(f"     严重程度: {violation['severity']}, 代码: {violation['code_snippet'][:80]}...")
    
    # 改进建议
    report_lines.append(f"\n💡 改进建议:")
    if summary['total_violations'] == 0:
        report_lines.append("   代码完全符合GJB 8114-2013规范，继续保持！")
    else:
        if summary['by_severity']['高危'] > 0:
            report_lines.append("   1. 优先修复高危违规（内存安全、类型安全相关）")
        if summary['by_severity']['中危'] > 0:
            report_lines.append("   2. 修复中危违规（编码规范、潜在安全隐患）")
        if summary['by_severity']['低危'] > 0 or summary['by_severity']['建议'] > 0:
            report_lines.append("   3. 改进低危和建议项（代码质量优化）")
        
        # 具体建议
        if results['memory_safety']:
            report_lines.append("   📌 内存安全建议：")
            report_lines.append("     - 确保指针在使用前初始化")
            report_lines.append("     - 检查缓冲区操作边界")
            report_lines.append("     - 内存分配后及时释放")
        
        if results['type_safety']:
            report_lines.append("   📌 类型安全建议：")
            report_lines.append("     - 避免被零除操作")
            report_lines.append("     - 使用显式类型转换")
            report_lines.append("     - 检查整数溢出风险")
        
        if results['coding_standard']:
            report_lines.append("   📌 编码规范建议：")
            report_lines.append("     - 使用有意义的变量名")
            report_lines.append("     - 避免使用goto语句")
            report_lines.append("     - 魔数应定义为常量")
    
    report_lines.append(f"\n" + "=" * 80)
    report_lines.append("检测完成时间: 请填写实际检测时间")
    report_lines.append("=" * 80)
    
    report_text = '\n'.join(report_lines)
    
    # 如果需要输出到文件
    if output_file:
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(report_text)
            print(f"报告已保存到: {output_file}")
        except Exception as e:
            print(f"保存报告失败: {e}")
    
    return report_text


# 示例使用
if __name__ == "__main__":
    # 测试C++代码（综合示例）
    test_cpp_code = """
#include <iostream>
#include <cstring>
#include <climits>

using namespace std;

// 测试各种GJB违规
void test_gjb_violations() {
    // 内存安全违规
    char buffer[10];
    strcpy(buffer, "This is too long");  // 缓冲区溢出
    
    int* ptr;
    *ptr = 100;  // 未初始化指针
    
    // 类型安全违规
    int a = 10;
    int b = 0;
    int result = a / b;  // 被零除
    
    unsigned int u = 5;
    if (u >= 0) {  // 无符号数>=0比较
        cout << "Always true" << endl;
    }
    
    // 编码规范违规
    int x = 100;  // 单字符变量名
    int timeout = 5000;  // 魔数
    
    // goto语句
    goto label;
    
    // 条件表达式中赋值
    int value;
    if ((value = get_value()) > 0) {
        cout << value << endl;
    }
    
label:
    cout << "Jumped here" << endl;
}

// 安全示例
void safe_gjb_compliance() {
    // 安全的内存操作
    char safe_buffer[100];
    strncpy(safe_buffer, "Safe string", sizeof(safe_buffer) - 1);
    safe_buffer[sizeof(safe_buffer) - 1] = '\\0';
    
    // 安全的类型操作
    int numerator = 10;
    int denominator = 2;
    if (denominator != 0) {
        int quotient = numerator / denominator;
    }
    
    // 良好的编码规范
    int student_count = 0;
    const int MAX_TIMEOUT_MS = 5000;
    int current_timeout = MAX_TIMEOUT_MS;
    
    // 使用循环而非goto
    for (int i = 0; i < 10; i++) {
        cout << "Iteration " << i << endl;
    }
}

int get_value() {
    return 42;
}

int main() {
    test_gjb_violations();
    safe_gjb_compliance();
    return 0;
}
"""
    
    print("=" * 80)
    print("GJB 8114-2013 综合检测示例")
    print("=" * 80)
    
    # 运行检测
    results = analyze_cpp_gjb_comprehensive(test_cpp_code)
    
    # 生成并显示报告
    report = generate_gjb_report(results)
    print(report)
    
    # 保存报告到文件
    generate_gjb_report(results, "gjb_detection_report.txt")
    
    print("\n✅ GJB检测模块已成功创建并测试！")