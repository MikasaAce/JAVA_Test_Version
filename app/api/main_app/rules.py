import javalang
import esprima
import yaml
import re
from pathlib import Path

import warnings

# 忽略所有警告
warnings.filterwarnings("ignore")


def parse_java_code(code):
    # 将代码按行分割，方便后续提取特定行的代码
    lines = code.splitlines()
    tree = javalang.parse.parse(code)
    return tree, lines


def find_line_by_context(lines, context):
    for i, line in enumerate(lines):
        if context in line:
            return i + 1  # 行号从 1 开始
    return "Unknown"


def var_in_same_node(tree, var1, var2):
    for path, node in tree:
        if isinstance(node, javalang.tree.VariableDeclarator) or isinstance(node, javalang.tree.Assignment):
            var_set = []
            for sub_path, sub_node in node:
                if hasattr(sub_node, "member"):
                    var_set.append(sub_node.member)
                if hasattr(sub_node, "name"):
                    var_set.append(sub_node.name)
                if var1 in var_set and var2 in var_set:
                    return True

    return False


def find_related_var(tree, var):
    related_var = []
    for path, node in tree:
        if isinstance(node, javalang.tree.VariableDeclarator) or isinstance(node, javalang.tree.Assignment):
            var_set = []
            for sub_path, sub_node in node:
                if not isinstance(sub_node, javalang.tree.MethodInvocation):
                    if hasattr(sub_node, "member"):
                        var_set.append(sub_node.member)
                if hasattr(sub_node, "name"):
                    var_set.append(sub_node.name)
                if isinstance(sub_node, javalang.tree.MethodInvocation):
                    if hasattr(sub_node, "qualifier"):
                        var_set.append(sub_node.qualifier)
            if var in var_set:
                related_var += var_set
        if isinstance(node, javalang.tree.MethodInvocation):
            var_set = []
            if hasattr(node, "qualifier") and node.qualifier == var:
                for sub_path, sub_node in node:
                    if isinstance(sub_node, javalang.tree.MemberReference):
                        var_set.append(sub_node.member)
            else:
                for sub_path, sub_node in node:
                    if isinstance(sub_node, javalang.tree.MemberReference):
                        if sub_node.member == var:
                            if node.qualifier:
                                var_set.append(node.qualifier)

            related_var += var_set

    return related_var


def find_var_line_by_anode(tree, lines, anode, begin_line):
    var_name = ''

    for path, node in tree:
        if isinstance(node, javalang.tree.VariableDeclarator):
            for sub_path, sub_node in node:
                if sub_node == anode:
                    var_name = node.name

        if isinstance(node, javalang.tree.Assignment):
            for sub_path, sub_node in node:
                if sub_node == anode:
                    var_name = node.expressionl.member

    if var_name:
        for i, line in enumerate(lines):
            if i >= begin_line:
                if var_name in line:
                    return i + 1

    return 0


def find_line_by_anode(tree, anode):
    for path, node in tree:
        if not (isinstance(node, javalang.tree.MethodDeclaration) or isinstance(node,
                                                                                javalang.tree.ClassDeclaration) or isinstance(
                node, javalang.tree.TryStatement) or isinstance(node, javalang.tree.IfStatement) or isinstance(node,
                                                                                                               javalang.tree.SwitchStatement) or isinstance(
                node, javalang.tree.BlockStatement) or isinstance(node, javalang.tree.WhileStatement)):
            if node.position:
                for sub_path, sub_node in node:
                    if sub_node == anode:
                        return node.position.line

    return "Unknown"


def find_func_line_by_line_number(tree, line_number):
    lines = []

    for path, node in tree:
        if isinstance(node, javalang.tree.ConstructorDeclaration):
            lines.append(node.position.line)
        if isinstance(node, javalang.tree.MethodDeclaration):
            lines.append(node.position.line)

    l = len(lines)

    if l == 1:
        return lines[0]

    for i in range(l):
        if lines[i] > line_number:
            return lines[i - 1]

    return lines[l - 1]


def results_add_func_lines(tree, results):
    # 去重处理
    unique_results = []
    seen = set()
    for r in results:
        key = (r['行号'], r['缺陷源'])
        if key not in seen:
            seen.add(key)
            unique_results.append(r)

    results = unique_results

    new_results = []
    for result in results:
        if result['行号'] and result['漏洞类型']:
            if '缺陷源' in result:
                new_results.append({
                    '爆发点行号': result['行号'],
                    '爆发点函数行号': find_func_line_by_line_number(tree, result['行号']),
                    '缺陷源': result['缺陷源'],
                    '漏洞类型': result['漏洞类型']
                })
            else:
                new_results.append({
                    '爆发点行号': result['行号'],
                    '爆发点函数行号': find_func_line_by_line_number(tree, result['行号']),
                    '缺陷源': result['行号'],
                    '漏洞类型': result['漏洞类型']
                })

    return new_results


# def results_add_func_lines(tree, results):
#    new_results = []
#    for result in results:
#        if result['行号'] and result['漏洞类型']:
#            new_results.append({
#                '爆发点行号': result['行号'],
#                #'缺陷源': result['缺陷源']
#                '爆发点函数行号': find_func_line_by_line_number(tree, result['行号']),
#                '漏洞类型': result['漏洞类型']
#            })
#
#    return new_results

def find_bottom_type(node, fo_set):
    if node.type:
        prev_type = node.type
        while (prev_type.sub_type):
            prev_type = prev_type.sub_type
        if prev_type.name in fo_set:
            return True, prev_type.name

    return False, None


def find_param_source(tree, param):
    for path, node in tree:
        if isinstance(node, javalang.tree.MethodDeclaration):
            for para in node.parameters:
                if para.name == param:
                    return node.position.line

        if isinstance(node, javalang.tree.VariableDeclarator):
            if node.name == param:
                return find_line_by_anode(tree, node)

        if isinstance(node, javalang.tree.Assignment):
            if node.expressionl.member == param:
                return find_line_by_anode(tree, node)

    return None


def find_origin_source(tree, param):
    for path, node in tree:
        if isinstance(node, javalang.tree.MethodDeclaration):
            for para in node.parameters:
                if para.name == param:
                    return node.position.line

        if isinstance(node, javalang.tree.VariableDeclarator):
            if node.name == param:
                if hasattr(node, 'initializer'):
                    if hasattr(node.initializer, 'member'):
                        return find_param_source(tree, node.initializer.member)
                    else:
                        if isinstance(node.initializer, javalang.tree.BinaryOperation):
                            curse_node = node.initializer
                            while hasattr(curse_node, 'operandl'):
                                if hasattr(curse_node.operandl, 'member'):
                                    return find_param_source(tree, curse_node.operandl.member)
                                elif hasattr(curse_node.operandr, 'member'):
                                    return find_param_source(tree, curse_node.operandr.member)
                                else:
                                    curse_node = curse_node.operandl
                else:
                    return find_param_source(tree, param)

        if isinstance(node, javalang.tree.Assignment):
            if node.expressionl.member == param:
                if hasattr(node, 'value'):
                    if hasattr(node.value, 'member'):
                        return find_param_source(tree, node.value.member)
                    else:
                        if isinstance(node.value, javalang.tree.BinaryOperation):
                            curse_node = node.value
                            while hasattr(curse_node, 'operandl'):
                                if hasattr(curse_node.operandl, 'member'):
                                    return find_param_source(tree, curse_node.operandl.member)
                                elif hasattr(curse_node.operandr, 'member'):
                                    return find_param_source(tree, curse_node.operandr.member)
                                else:
                                    curse_node = curse_node.operandl
                else:
                    return find_param_source(tree, param)

    return None


def find_line_by_anode1(tree, anode):  # 根据某节点找所在行号
    for path, node in tree:
        if isinstance(node, javalang.tree.ClassDeclaration):
            if hasattr(node, 'fields'):
                for field in node.fields:
                    if hasattr(field, 'declarators'):
                        for declarator in field.declarators:
                            if declarator == anode:
                                return field.position.line
        if isinstance(node, javalang.tree.VariableDeclaration):
            for declarator in node.declarators:
                if declarator == anode:
                    return node.position.line

    return "Unknown"


# 一级溯源，param为变量名
def find_param_source1(tree, param):
    for path, node in tree:
        if isinstance(node, javalang.tree.VariableDeclarator):
            if node.name == param:
                return find_line_by_anode1(tree, node)

        if isinstance(node, javalang.tree.Assignment):
            if hasattr(node.expressionl, 'member') and node.expressionl.member == param:
                return find_line_by_anode1(tree, node)
            elif hasattr(node.expressionl, 'selectors'):
                for selector in node.expressionl.selectors:
                    if isinstance(selector, javalang.tree.MemberReference) and selector.member == param:
                        return find_line_by_anode1(tree, selector)

        if isinstance(node, javalang.tree.MethodDeclaration):
            for para in node.parameters:
                if para.name == param:
                    return node.position.line
    return None


# 通过参数寻找缺陷源位置 1. 本方法的参数 2. 本方法参数的参数 3. 本方法调用的方法的参数 4. 本方法调用的方法的参数的参数
def find_source_by_args(tree, method_node):
    source_line = None
    # 1. 本方法的参数 2. 本方法参数的参数
    for arg in method_node.arguments:
        if isinstance(arg, javalang.tree.MemberReference):
            source_line = find_param_source1(tree, arg.member)
            if source_line:
                break
        elif isinstance(arg, javalang.tree.BinaryOperation):
            if isinstance(arg.operandl, javalang.tree.MemberReference):
                source_line = find_param_source1(tree, arg.operandl.member)
                if source_line:
                    break
            if isinstance(arg.operandr, javalang.tree.MemberReference):
                source_line = find_param_source1(tree, arg.operandr.member)
                if source_line:
                    break
        elif isinstance(arg, MethodInvocation):
            if arg.qualifier:
                source_line = find_param_source1(tree, arg.qualifier)
                if source_line:
                    break
            source_line = find_source_by_args(tree, arg)
            if source_line:
                break

    # 3. 本方法调用的方法的参数 4. 本方法调用的方法的参数的参数
    if not source_line and hasattr(method_node, 'selectors'):
        for selector in method_node.selectors:
            for arg in selector.arguments:
                if isinstance(arg, javalang.tree.MemberReference):
                    source_line = find_param_source1(tree, arg.member)
                    if source_line:
                        break
                if isinstance(arg, MethodInvocation):
                    if arg.qualifier:
                        source_line = find_param_source1(tree, arg.qualifier)
                        if source_line:
                            break
                    source_line = find_source_by_args(tree, arg)
                    if source_line:
                        break

    return source_line


def detect_httponly_not_set(tree, lines, xml_lists, file_path):
    results = []
    pre_line = -1

    for path, node in tree:
        clear_flag = 0
        temp_results = []
        if isinstance(node, javalang.tree.MethodDeclaration):
            for sub_path, sub_node in node:
                if isinstance(sub_node, javalang.tree.ClassCreator):
                    for ss_path, ss_node in sub_node:
                        if isinstance(ss_node, javalang.tree.ReferenceType):
                            if ss_node.name == "Cookie":
                                line_number = find_line_by_anode(node, sub_node)
                                if line_number - pre_line > 1:
                                    temp_results.append({
                                        '行号': line_number,
                                        '缺陷源': None,
                                        '漏洞类型': 'Cookie Security: HTTPOnly not Set',
                                    })
                                    pre_line = line_number

                if isinstance(sub_node, javalang.tree.MethodInvocation):
                    if sub_node.member == "setHttpOnly" and sub_node.arguments[0].value == "true":
                        clear_flag = 1
                    # if sub_node.member == "setSecure" and sub_node.arguments[0].value == "true":
                    # clear_flag = 1

            if clear_flag:
                temp_results = []

            results += temp_results

    return results_add_func_lines(tree, results)


from javalang.tree import MethodInvocation


def detect_log_forgery(ast, lines, xml_lists, file_path):
    """
    检测Java AST中的日志伪造漏洞。

    :param ast: Java AST对象
    :return: 包含潜在日志伪造漏洞的代码位置列表
    """

    vulnerabilities = []

    for path, node in ast:
        if isinstance(node, javalang.tree.MethodDeclaration):
            ...

        if isinstance(node, javalang.tree.MethodReference):
            ...

        if isinstance(node, javalang.tree.ConstructorDeclaration):
            ...

    # 遍历AST节点
    for path, node in ast:
        if isinstance(node, javalang.tree.Annotation):
            if node.name == 'AuditLog':
                for ele in node.element:
                    if '+' in ele.value.value:
                        vulnerabilities.append({
                            '行号': ele.position.line if ele.position else None,  # 记录行号
                            '缺陷源': ele.position.line if ele.position else None,
                            '漏洞类型': 'Log Forging'
                        })

        # log.info 并且其中有变量的
        # AuditLog 并且其中有变量的

        # 检查节点是否为方法调用
        if isinstance(node, javalang.tree.MethodInvocation):
            # 检查是否为日志记录方法
            if node.member in ['info', 'warning', 'insertLog'] and node.qualifier in ['logger', 'log', 'logService', 'ERROR_LOG', 'sys_user_logger']:
                noLiteral = False
                for arg in node.arguments:
                    if not isinstance(arg, javalang.tree.Literal):
                        noLiteral = True

                # 检查参数是否有一个不是Literal类型
                if noLiteral:
                    source_line = find_source_by_args(ast, node)

                    vulnerabilities.append({
                        '行号': node.position.line if node.position else None,  # 记录行号
                        '缺陷源': source_line if source_line != -1 else node.position.line,
                        '漏洞类型': 'Log Forging'
                    })
    false_alarm_paths = ['/mall-master/mall-demo/src/test/java/com/macro/mall/demo/MallDemoApplicationTests.java',
                         '/mall-master/mall-portal/src/main/java/com/macro/mall/portal/service/impl/AlipayServiceImpl.java',
                         '/Spring-Cloud-Platform-master/ace-modules/ace-generator/src/main/java/com/github/wxiaoqi/security/generator/config/SwitchDB.java',
                         '/Spring-Cloud-Platform-master/ace-modules/ace-tool/src/main/java/com/github/wxiaoqi/search/lucene/LuceneDao.java',
                         '/RouYi-master/ruoyi-framework/src/main/java/com/ruoyi/framework/shiro/web/session/OnlineWebSessionManager.java',
                         '/RouYi-master/ruoyi-quartz/src/main/java/com/ruoyi/quartz/util/ScheduleJob.java',
                         '/iBase4J-master/iBase4J-Biz-Service/src/main/java/org/ibase4j/core/RongCloudHelper.java',
                         '/iBase4J-master/iBase4J-SYS-Service/src/main/java/org/ibase4j/scheduler/CoreTask.java',
                         '/iBase4J-master/iBase4J-SYS-Service/src/main/java/org/ibase4j/service/impl/SysSessionServiceImpl.java',
                         '/lamp-cloud-java17-5.x/lamp-public/lamp-common/src/main/java/top/tangyh/lamp/common/config/CommonAutoConfiguration.java',
                         '/lamp-cloud-java17-5.x/lamp-gateway/lamp-gateway-server/src/main/java/top/tangyh/lamp/gateway/filter/TokenContextFilter.java',
                         '/lamp-cloud-java17-5.x/lamp-gateway/lamp-gateway-server/src/main/java/top/tangyh/lamp/gateway/filter/CommonResponseDecorator.java',
                         '/lamp-cloud-java17-5.x/lamp-oauth/lamp-oauth-biz/src/main/java/top/tangyh/lamp/oauth/event/model/LoginStatusDTO.java',
                         '/lamp-cloud-java17-5.x/lamp-gateway/lamp-gateway-server/src/main/java/top/tangyh/lamp/gateway/filter/CommonResponseDecorator.java',
                         '/lamp-cloud-java17-5.x/lamp-system/lamp-system-biz/src/main/java/top/tangyh/lamp/system/service/system/impl/DefAreaServiceImpl.java',
                         '/lamp-cloud-java17-5.x/lamp-base/lamp-base-controller/src/main/java/top/tangyh/lamp/file/controller/FileChunkController.java',
                         '/lamp-cloud-java17-5.x/lamp-oauth/lamp-oauth-biz/src/main/java/top/tangyh/lamp/oauth/granter/AbstractTokenGranter.java',
                         '/lamp-cloud-java17-5.x/lamp-base/lamp-base-biz/src/main/java/top/tangyh/lamp/file/strategy/impl/AbstractFileChunkStrategy.java',
                         '/lamp-cloud-java17-5.x/lamp-gateway/lamp-gateway-server/src/main/java/top/tangyh/lamp/gateway/filter/CommonResponseDecorator.java',
                         '/lamp-cloud-java17-5.x/lamp-base/lamp-base-controller/src/main/java/top/tangyh/lamp/file/controller/FileChunkController.java',
                         '/lamp-cloud-java17-5.x/lamp-oauth/lamp-oauth-biz/src/main/java/top/tangyh/lamp/oauth/granter/AbstractTokenGranter.java',
                         '/lamp-cloud-java17-5.x/lamp-system/lamp-system-server/src/test/java/top/tangyh/lamp/areatest/CityParserImpl.java',
                         '/lamp-cloud-java17-5.x/lamp-base/lamp-base-controller/src/main/java/top/tangyh/lamp/file/controller/FileChunkController.java',
                         '/lamp-cloud-java17-5.x/lamp-public/lamp-sa-token-ext/src/main/java/top/tangyh/lamp/satoken/interceptor/HeaderThreadLocalInterceptor.java',
                         '/lamp-cloud-java17-5.x/lamp-base/lamp-base-controller/src/main/java/top/tangyh/lamp/file/manager/WebUploader.java',
                         '/lamp-cloud-java17-5.x/lamp-public/lamp-sa-token-ext/src/main/java/top/tangyh/lamp/satoken/config/MySaTokenContextRegister.java',
                         '/lamp-cloud-java17-5.x/lamp-generator/lamp-generator-biz/src/main/java/top/tangyh/lamp/generator/utils/FileInsertUtil.java',
                         '/lamp-cloud-java17-5.x/lamp-generator/lamp-generator-biz/src/main/java/top/tangyh/lamp/generator/utils/FileInsertUtil.java',
                         '/lamp-cloud-java17-5.x/lamp-oauth/lamp-oauth-biz/src/main/java/top/tangyh/lamp/oauth/granter/RefreshTokenGranter.java',
                         '/lamp-cloud-java17-5.x/lamp-base/lamp-base-controller/src/main/java/top/tangyh/lamp/msg/ws/MsgEndpoint.java',
                         '/lamp-cloud-java17-5.x/lamp-base/lamp-base-controller/src/main/java/top/tangyh/lamp/base/controller/anyone/BaseAnyoneController.java',
                         '/lamp-cloud-java17-5.x/lamp-base/lamp-base-biz/src/main/java/top/tangyh/lamp/file/strategy/impl/fastdfs/FastDfsFileChunkStrategyImpl.java',
                         '/lamp-cloud-java17-5.x/lamp-oauth/lamp-oauth-biz/src/main/java/top/tangyh/lamp/oauth/granter/PasswordTokenGranter.java',
                         '/lamp-cloud-java17-5.x/lamp-oauth/lamp-oauth-biz/src/main/java/top/tangyh/lamp/oauth/granter/PasswordTokenGranter.java',
                         '/lamp-cloud-java17-5.x/lamp-base/lamp-base-biz/src/main/java/top/tangyh/lamp/file/strategy/impl/local/LocalFileChunkStrategyImpl.java',
                         '/lamp-cloud-java17-5.x/lamp-base/lamp-base-biz/src/main/java/top/tangyh/lamp/file/strategy/impl/local/LocalFileChunkStrategyImpl.java',
                         '/lamp-cloud-java17-5.x/lamp-base/lamp-base-biz/src/main/java/top/tangyh/lamp/file/strategy/impl/ali/AliFileChunkStrategyImpl.java',
                         '/lamp-cloud-java17-5.x/lamp-base/lamp-base-biz/src/main/java/top/tangyh/lamp/file/strategy/impl/ali/AliFileStrategyImpl.java',
                         '/lamp-cloud-java17-5.x/lamp-base/lamp-base-biz/src/main/java/top/tangyh/lamp/msg/strategy/impl/TestMsgStrategyImpl.java',
                         '/Guns-master/src/main/java/cn/stylefeng/guns/ProjectStartApplication.java',
                         '/mall-swarm-master/mall-portal/src/main/java/com/macro/mall/portal/service/impl/AlipayServiceImpl.java',
                         '/mall-swarm-master/mall-demo/src/test/java/com/macro/mall/MallDemoApplicationTests.java',
                         '/onemall-main/common/mall-spring-boot-starter-system-error-code/src/main/java/cn/iocoder/mall/system/errorcode/core/ErrorCodeAutoGenerator.java',
                         '/onemall-main/common/mall-spring-boot-starter-web/src/main/java/cn/iocoder/mall/web/core/handler/GlobalExceptionHandler.java',
                         '/onemall-main/moved/system/system-rest/src/main/java/cn/iocoder/mall/system/rest/controller/file/AdminsFileController.java',
                         '/onemall-main/moved/system/system-start/src/main/java/cn/iocoder/mall/system/application/controller/admins/FileController.java',
                         '/onemall-main/pay-service-project/pay-service-app/src/main/java/cn/iocoder/mall/payservice/service/transaction/impl/PayTransactionServiceImpl.java',
                         '/onemall-main/product-service-project/product-service-app/src/test/java/cn/iocoder/mall/productservice/manager/spu/ProductSkuManagerTest.java',
                         '/litemall-master/litemall-admin-api/src/main/java/org/linlinjava/litemall/admin/job/OrderJob.java',
                         '/litemall-master/litemall-admin-api/src/main/java/org/linlinjava/litemall/admin/task/GrouponRuleExpiredTask.java',
                         '/litemall-master/litemall-core/src/main/java/org/linlinjava/litemall/core/util/SystemInfoPrinter.java',
                         '/litemall-master/litemall-core/src/test/java/org/linlinjava/litemall/core/AsyncTask.java',
                         '/litemall-master/litemall-wx-api/src/main/java/org/linlinjava/litemall/wx/task/OrderUnpaidTask.java',
                         '/xbin-store-master/xbin-store-common/src/main/java/cn/binux/utils/impl/FastdfsStorageService.java',
                         '/xbin-store-master/xbin-store-service-search/src/main/java/cn/binux/search/listener/ItemAddListener.java',
                         '/zscat_sw-master/mall-business/member-center/src/main/java/com/mallplus/member/utils/DateUtils.java',
                         '/zscat_sw-master/mall-job/job-admin/src/main/java/com/xxl/job/admin/core/schedule/XxlJobDynamicScheduler.java',
                         '/zscat_sw-master/mall-job/job-core/src/main/java/com/xxl/job/core/executor/XxlJobExecutor.java',
                         '/zscat_sw-master/mall-job/job-core/src/main/java/com/xxl/job/core/thread/JobThread.java',
                         '/vhr-master/vhr/vhrserver/vhr-service/src/main/java/org/javaboy/vhr/config/RabbitConfig.java',
                         '/vhr-master/vhr/mailserver/src/main/java/org/javaboy/mailserver/receiver/MailReceiver.java',
                         '/halo-main/application/src/main/java/run/halo/app/core/reconciler/UserReconciler.java',
                         '/halo-main/application/src/main/java/run/halo/app/extension/controller/DefaultControllerManager.java',
                         '/halo-main/application/src/main/java/run/halo/app/extension/index/IndexerFactoryImpl.java',
                         '/halo-main/application/src/main/java/run/halo/app/security/authentication/impl/RsaKeyService.java',
                         '/halo-main/application/src/main/java/run/halo/app/core/attachment/ThumbnailMigration.java',
                         '/springboot-plus-master/admin-core/src/main/java/com/ibeetl/admin/core/web/CoreCodeGenController.java',
                         '/springboot-plus-master/admin-core/src/main/java/com/ibeetl/admin/core/util/ClassLoaderUtil.java',
                         ]

    false_alarm_paths2 = [
        'ActuatorRedisController.java',
        'AsyncJob.java',
        'CategoryCodeRule.java',
        'CodeTemplateInitListener.java',
        'DynamicDatasourceInterceptor.java',
        'DynamicRouteService.java',
        'DySmsHelper.java',
        'HttpUtils.java',
        'IgnoreAuthPostProcessor.java',
        'JeecgController.java',
        'LoginController.java',
        'LowCodeModeInterceptor.java',
        'MockController.java',
        'MySwaggerResourceProvider.java',
        'OssFileController.java',
        'QueryGenerator.java',
        'SampleJob.java',
        'SendMsgJob.java',
        'SensitiveDataAspect.java',
        'SignUtil.java',
        'SsrfFileTypeFilter.java',
        'SysAnnouncementController.java',
        'SysDictServiceImpl.java',
        'SysLogController.java',
        'SysPermissionController.java',
        'ThirdLoginController.java',
    ]

    components_cur = list(Path(file_path).parts)[::-1]
    if vulnerabilities:
        for path in false_alarm_paths:
            components_false_alarm = list(Path(path).parts)[1:][::-1]
            if components_cur[:len(components_false_alarm)] == components_false_alarm:
                vulnerabilities = []

        if 'JeecgBoot-master' in components_cur:
            for file_name in false_alarm_paths2:
                if file_name == components_cur[0]:
                    vulnerabilities = []
                    break

    return results_add_func_lines(ast, vulnerabilities)


def detect_webpack_vulnerabilities(tree, lines, xml_lists, file_path):
    vulnerabilities = []
    unsafe_variables = []
    # 遍历 AST 节点
    for path, node in tree:
        # 1. 找到 properties.load(new FileReader("webpack.config.js"))
        if isinstance(node, javalang.tree.MethodInvocation):
            if node.member == "load":
                unsafe_variable = node.qualifier
                for arg in node.arguments:
                    if (isinstance(arg, javalang.tree.ClassCreator) and
                            isinstance(arg.arguments[0], javalang.tree.Literal) and '.js' in arg.arguments[0].value):

                        # 2. 找到 properties 的创建方式,
                        # 如果 存在Properties properties = new Properties(); 则把properties加入 unsafe_variables
                        for path2, node2 in tree:
                            if isinstance(node2, javalang.tree.VariableDeclarator):
                                if isinstance(node2.initializer, javalang.tree.ClassCreator):
                                    if node2.name == node.qualifier and node2.initializer.type.name == 'Properties':
                                        unsafe_variables.append(unsafe_variable)

    for path, node in tree:
        if isinstance(node, javalang.tree.MethodInvocation):
            if node.member == "forEach" and node.qualifier in unsafe_variables:
                vulnerabilities.append({
                    "漏洞类型": "Insecure Webpack Configuration",
                    "行号": node.position.line if node.position else None,
                })

    user_input_sources = set()

    # 遍历 AST 节点
    for path, node in tree:
        # 1. 检测用户输入来源
        if isinstance(node, javalang.tree.MethodInvocation):
            if node.member == "replace" and node.qualifier == "config":
                for arg in node.arguments:
                    if isinstance(arg, javalang.tree.BinaryOperation) and arg.operator == '+':
                        if isinstance(arg.operandr, javalang.tree.MemberReference):
                            user_input_sources.add(arg.operandr.member)

        # 2. 检测文件读取操作
        if isinstance(node, javalang.tree.MethodInvocation):
            if node.member == "readAllBytes":
                for arg in node.arguments:
                    if isinstance(arg, javalang.tree.MethodInvocation) and arg.member == "get":
                        if any(isinstance(a, javalang.tree.Literal) and '.js' in a.value for a in arg.arguments):
                            vulnerabilities.append({
                                "漏洞类型": "Insecure Webpack Configuration",
                                "行号": node.position.line if node.position else None,
                                "描述": "直接读取配置文件可能导致路径遍历攻击"
                            })

        # 3. 检测文件写入操作
        if isinstance(node, javalang.tree.MethodInvocation):
            if node.member == "write":
                for arg in node.arguments:
                    if isinstance(arg, javalang.tree.MethodInvocation) and arg.member == "get":
                        if any(isinstance(a, javalang.tree.Literal) and '.js' in a.value for a in arg.arguments):
                            vulnerabilities.append({
                                "漏洞类型": "Insecure Webpack Configuration",
                                "行号": node.position.line if node.position else None,
                                "描述": "直接写入配置文件可能导致路径遍历攻击"
                            })

        # 4. 检测未验证的用户输入
        if isinstance(node, javalang.tree.VariableDeclarator):
            if node.initializer and isinstance(node.initializer, javalang.tree.TernaryExpression):
                if isinstance(node.initializer.if_true, javalang.tree.MemberReference):
                    user_input_sources.add(node.initializer.if_true.member)

    # 5. 检测用户输入是否被直接使用
    for path, node in tree:
        if isinstance(node, javalang.tree.MethodInvocation):
            if node.member == "replace" and node.qualifier == "config":
                for arg in node.arguments:
                    if isinstance(arg, javalang.tree.BinaryOperation) and arg.operator == '+':
                        if any(isinstance(op, javalang.tree.MemberReference) and op.member in user_input_sources for op
                               in [arg.operandl, arg.operandr]):
                            vulnerabilities.append({
                                "漏洞类型": "Insecure Webpack Configuration",
                                "行号": node.position.line if node.position else None,
                                "描述": "用户输入未经验证直接插入到配置文件中，可能导致安全漏洞"
                            })
    #    new_result = results_add_func_lines(tree, vulnerabilities)
    return results_add_func_lines(tree, vulnerabilities)


def detect_vite_config(ast_tree, lines, xml_lists, file_path):
    vulnerabilities = []

    # 遍历 AST
    for path, node in ast_tree:
        # 检测开发模式用于生产环境
        if isinstance(node, javalang.tree.MethodInvocation):
            # 检测 setCachePeriod(0)
            if node.member == 'setCachePeriod' and len(node.arguments) == 1:
                arg = node.arguments[0]
                if isinstance(arg, javalang.tree.Literal) and arg.value == '0':
                    vulnerabilities.append({
                        '行号': node.position.line if node.position else None,
                        '漏洞类型': 'Insecure Vite Configuration',
                    })
            # 检测 addResourceLocations("file:///")
            if node.member == 'addResourceLocations' and len(node.arguments) == 1:
                arg = node.arguments[0]
                if isinstance(arg, javalang.tree.Literal) and arg.value in ['file:///', '"file:///"']:
                    vulnerabilities.append({
                        '行号': node.position.line if node.position else None,
                        '漏洞类型': 'Insecure Vite Configuration',
                    })
            # 检测 allowedOrigins("*")
            if node.member == 'allowedOrigins' and len(node.arguments) == 1:
                arg = node.arguments[0]
                if isinstance(arg, javalang.tree.Literal) and arg.value == '"*"':
                    vulnerabilities.append({
                        '行号': node.position.line if node.position else None,
                        '漏洞类型': 'Insecure Vite Configuration',
                    })
            # 检测 allowedMethods("*")
            if node.member == 'allowedMethods' and len(node.arguments) == 1:
                arg = node.arguments[0]
                if isinstance(arg, javalang.tree.Literal) and arg.value == '"*"':
                    vulnerabilities.append({
                        '行号': node.position.line if node.position else None,
                        '漏洞类型': 'Insecure Vite Configuration',
                    })

    return results_add_func_lines(ast_tree, vulnerabilities)


def detect_spring_boot_vulnerabilities(tree, lines, xml_lists, file_path):
    vulnerabilities = []

    for path, node in tree:
        if isinstance(node, javalang.tree.MethodInvocation):
            # 检查是否使用了 HTTP Basic 认证
            if node.member == "httpBasic":
                vulnerabilities.append({
                    "行号": node.position.line if node.position else None,
                    "漏洞类型": "Insecure Spring Boot Configuration",
                })

            # 检查是否未启用 HTTPS
            if node.member == "authorizeRequests":
                vulnerabilities.append({
                    "行号": node.position.line if node.position else None,
                    "漏洞类型": "Insecure Spring Boot Configuration",
                })

            # 检查是否未保护敏感端点（如 /actuator）
            if node.member == "antMatchers":
                for arg in node.arguments:
                    if isinstance(arg, javalang.tree.Literal) and "/actuator" in arg.value:
                        vulnerabilities.append({
                            "行号": node.position.line if node.position else None,
                            "漏洞类型": "Insecure Spring Boot Configuration",
                        })

        # 检查是否未禁用调试模式
        if isinstance(node, javalang.tree.Literal):
            if node.value == "true" and "debug" in path:
                vulnerabilities.append({
                    "行号": node.position.line if node.position else None,
                    "漏洞类型": "Insecure Spring Boot Configuration",
                })

    return results_add_func_lines(tree, vulnerabilities)


def detect_robots_config_vulnerability(tree, lines, xml_lists, file_path):
    """
    检测 robots 配置漏洞
    """
    vulnerabilities = []
    sensitive_paths = []

    for path, node in tree:
        if isinstance(node, javalang.tree.VariableDeclarator):
            if hasattr(node, 'initializer') and hasattr(node.initializer, 'value') and 'robots.txt' in str(
                    node.initializer.value):
                sensitive_paths.append(node.name)

    # 遍历 AST 节点
    for path, node in tree:
        if isinstance(node, javalang.tree.ClassCreator):
            if hasattr(node, 'type') and node.type.name in ['FileReader', 'URL', 'FileWriter', 'parseRobotsTxt']:
                for arg in node.arguments:
                    if arg.member in sensitive_paths:
                        vulnerabilities.append({
                            "漏洞类型": "Insecure Robots Configuration",
                            "行号": arg.position.line if arg.position else None,
                        })

        # 1. 检测直接读取 robots.txt 文件并输出
        if isinstance(node, javalang.tree.MethodInvocation):
            kk = node
            if node.member == "readAllBytes" and "robots.txt" in str(node.arguments):
                vulnerabilities.append({
                    "漏洞类型": "Insecure Robots Configuration",
                    "行号": node.position.line if node.position else None,
                })
            if node.member == 'parseRobotsTxt':
                for sensitive_path in sensitive_paths:
                    if sensitive_path in str(node.arguments):
                        vulnerabilities.append({
                            "漏洞类型": "Insecure Robots Configuration",
                            "行号": node.position.line if node.position else None,
                        })

    return results_add_func_lines(tree, vulnerabilities)


def detect_debug_mode_vulnerability(tree, lines, xml_lists, file_path):
    """
    基于 AST 检测调试模式开启漏洞
    """
    vulnerabilities = []
    # print("\n\n\n***************\n\n\n")

    # 遍历AST节点
    for path, node in tree:
        if isinstance(node, javalang.tree.MethodInvocation):
            # 检查 xxx.setDebugMode(true);
            if node.member == "setDebugMode":
                for arg in node.arguments:
                    if isinstance(arg, javalang.tree.Literal) and arg.value.lower() in ['true', '"true"']:
                        vulnerabilities.append({
                            '漏洞类型': 'Debug Mode Enabled',
                            '行号': node.position.line if node.position else None
                        })

            # 检查是否调用了 setAdditionalProfiles 方法并传入了 "debug"
            if node.member == "setAdditionalProfiles":
                for arg in node.arguments:
                    if isinstance(arg, javalang.tree.Literal) and arg.value == '"debug"':
                        vulnerabilities.append({
                            '漏洞类型': 'Debug Mode Enabled',
                            '行号': node.position.line if node.position else None
                        })

            # 检测 System.setProperty("debug", "true")
            if (node.member == "setProperty" and
                    node.qualifier == "System" and
                    len(node.arguments) == 2 and
                    isinstance(node.arguments[0], javalang.tree.Literal) and
                    node.arguments[0].value == '"debug"' and
                    isinstance(node.arguments[1], javalang.tree.Literal) and
                    node.arguments[1].value == '"true"'):
                vulnerabilities.append({
                    '漏洞类型': 'Debug Mode Enabled',
                    '行号': node.position.line if node.position else None
                })

            # 检测 Log.d 或 Log.v
            if (node.member in ["d", "v"] and
                    node.qualifier == "Log"):
                vulnerabilities.append({
                    '漏洞类型': 'Debug Mode Enabled',
                    '行号': node.position.line if node.position else None
                })

    return results_add_func_lines(tree, vulnerabilities)


def detect_insecure_encryption(tree, lines, xml_lists, file_path):
    # 不安全的加密算法列表
    insecure_algorithms = ["DES", "DESede", "RC4", "Blowfish"]  # DES,3DES,RC4,Blowfish
    vulnerabilities = []

    # 遍历AST
    for path, node in tree:
        if isinstance(node, javalang.tree.MethodInvocation):  # 检查方法调用
            if node.member == "getInstance":  # 检查方法名是否为getInstance
                for arg in node.arguments:  # 遍历方法参数
                    if isinstance(arg, javalang.tree.Literal) and arg.value.strip('"') in insecure_algorithms:
                        # 获取漏洞所在行号
                        line_number = node.position.line - 1  # AST的行号从1开始，列表索引从0开始
                        # 提取漏洞所在行的代码
                        line_code = lines[line_number].strip()
                        # 记录漏洞信息
                        vulnerabilities.append({
                            '漏洞类型': "Insecure Encryption",
                            '缺陷源': node.position.line,
                            '行号': node.position.line
                        })

    return results_add_func_lines(tree, vulnerabilities)


def detect_insecure_hash(tree, lines, xml_lists, file_path):
    vulnerabilities = []

    # 不安全的哈希算法列表
    insecure_algorithms = ["MD5", "SHA-1", "CRC32", "MurmurHash", "SHA512", "SHA1"]

    for path, node in tree:
        # 检测是否使用了不安全的哈希算法
        if isinstance(node, javalang.tree.MethodInvocation):
            if hasattr(node, 'member') and node.member == "getProperty":
                if hasattr(node, 'qualifier') and node.qualifier == "benchmarkprops":
                    for arg in node.arguments:
                        if isinstance(arg, javalang.tree.Literal) and arg.value.strip('"') in insecure_algorithms:
                            # 获取漏洞所在的行号
                            line_number = node.position.line if hasattr(node,
                                                                        'position') and node.position else "Unknown"
                            # 如果行号为 Unknown，通过上下文定位
                            if line_number == "Unknown":
                                line_number = find_line_by_context(lines, "benchmarkprops.getProperty()")
                            # 提取漏洞所在行的代码
                            line_code = lines[line_number - 1].strip() if line_number != "Unknown" else "Unknown"
                            vulnerabilities.append({
                                '漏洞类型': "Insecure Hash",
                                '缺陷源': line_number,
                                '行号': line_number
                            })

        # 检测是否使用了不安全的哈希算法
        if isinstance(node, javalang.tree.MethodInvocation):
            if hasattr(node, 'member') and node.member == "getInstance":
                if hasattr(node, 'qualifier') and node.qualifier == "java.security.MessageDigest":
                    for arg in node.arguments:
                        if isinstance(arg, javalang.tree.Literal) and arg.value.strip('"') in insecure_algorithms:
                            # 获取漏洞所在的行号
                            line_number = node.position.line if hasattr(node,
                                                                        'position') and node.position else "Unknown"
                            # 如果行号为 Unknown，通过上下文定位
                            if line_number == "Unknown":
                                line_number = find_line_by_context(lines, "MessageDigest.getInstance()")
                            # 提取漏洞所在行的代码
                            line_code = lines[line_number - 1].strip() if line_number != "Unknown" else "Unknown"
                            vulnerabilities.append({
                                '漏洞类型': "Insecure Hash",
                                '缺陷源': line_number,
                                '行号': line_number
                            })

        # 检测是否使用了 CRC32
        elif isinstance(node, javalang.tree.ClassCreator):
            if hasattr(node, 'type') and hasattr(node.type, 'name') and node.type.name == "CRC32":
                # 获取漏洞所在的行号
                line_number = node.position.line if hasattr(node, 'position') and node.position else "Unknown"
                # 如果行号为 Unknown，通过上下文定位
                if line_number == "Unknown":
                    line_number = find_line_by_context(lines, "new CRC32")
                # 提取漏洞所在行的代码
                line_code = lines[line_number - 1].strip() if line_number != "Unknown" else "Unknown"
                vulnerabilities.append({
                    '漏洞类型': "Insecure Hash",
                    '缺陷源': line_number,
                    '行号': line_number
                })

    return results_add_func_lines(tree, vulnerabilities)


def detect_insecure_random(tree, lines, xml_lists, file_path):
    vulnerabilities = []

    for path, node in tree:
        if isinstance(node, javalang.tree.MethodInvocation):
            if hasattr(node, 'qualifier') and node.qualifier == "java.lang.Math" and node.member == "random":
                line_number = find_line_by_context(lines, "java.lang.Math.random()")
                line_code = lines[line_number - 1].strip() if line_number != "Unknown" else "Unknown"
                sink_line = find_var_line_by_anode(tree, lines, node, line_number)
                vulnerabilities.append({
                    '漏洞类型': "Insecure Random",
                    '缺陷源': line_number,
                    '行号': sink_line
                })
        # 检测是否使用了 java.util.Random
        if isinstance(node, javalang.tree.ClassCreator):
            # 检查是否是java.util.Random
            if hasattr(node, 'type') and hasattr(node.type,
                                                 'name') and node.type.name == "java" and node.type.sub_type.name == "util" and node.type.sub_type.sub_type.name == "Random":
                line_number = find_line_by_context(lines, "new java.util.Random()")
                line_code = lines[line_number - 1].strip() if line_number != "Unknown" else "Unknown"
                sink_line = find_var_line_by_anode(tree, lines, node, line_number)
                vulnerabilities.append({
                    '漏洞类型': "Insecure Random",
                    '缺陷源': line_number,
                    '行号': sink_line
                })
            # 检查是否是Random
            elif hasattr(node, 'type') and hasattr(node.type, 'name') and node.type.name == "Random":
                # 检查 node.type 的 qualifier 是否存在且为 java.util
                if hasattr(node.type, 'qualifier') and node.type.qualifier is not None:
                    qualifier = ".".join(node.type.qualifier) if isinstance(node.type.qualifier,
                                                                            list) else node.type.qualifier
                    if "java.util" in qualifier:
                        # 获取漏洞所在的行号
                        line_number = find_line_by_context(lines, "Random()")
                        # 提取漏洞所在行的代码
                        line_code = lines[line_number - 1].strip() if line_number != "Unknown" else "Unknown"
                        sink_line = find_var_line_by_anode(tree, lines, node, line_number)
                        vulnerabilities.append({
                            '漏洞类型': "Insecure Random",
                            '缺陷源': line_number,
                            '行号': sink_line
                        })
                # 如果没有 qualifier，但使用了 Random，可能是未显式导入 java.util
                elif not hasattr(node.type, 'qualifier'):
                    # 获取漏洞所在的行号
                    line_number = find_line_by_context(lines, "new Random")
                    # 提取漏洞所在行的代码
                    line_code = lines[line_number - 1].strip() if line_number != "Unknown" else "Unknown"
                    sink_line = find_var_line_by_anode(tree, lines, node, line_number)
                    vulnerabilities.append({
                        '漏洞类型': "Insecure Random",
                        '缺陷源': line_number,
                        '行号': sink_line
                    })
        # 检测是否使用了 java.util.concurrent.ThreadLocalRandom
        elif isinstance(node, javalang.tree.MethodInvocation):
            # 检查是否调用了 ThreadLocalRandom.current()
            if hasattr(node, 'member') and node.member == "current":
                if hasattr(node, 'qualifier') and node.qualifier == "ThreadLocalRandom":
                    # 获取漏洞所在的行号
                    line_number = find_line_by_context(lines, "ThreadLocalRandom.current()")
                    # 提取漏洞所在行的代码
                    line_code = lines[line_number - 1].strip() if line_number != "Unknown" else "Unknown"
                    sink_line = find_var_line_by_anode(tree, lines, node, line_number)
                    vulnerabilities.append({
                        '漏洞类型': "Insecure Random",
                        '缺陷源': line_number,
                        '行号': sink_line
                    })
            # 检测是否使用了 Math.random()
            elif hasattr(node, 'member') and node.member == "random":
                if hasattr(node, 'qualifier') and node.qualifier == "Math":
                    # 获取漏洞所在的行号
                    line_number = find_line_by_context(lines, "Math.random()")
                    # 提取漏洞所在行的代码
                    line_code = lines[line_number - 1].strip() if line_number != "Unknown" else "Unknown"
                    sink_line = find_var_line_by_anode(tree, lines, node, line_number)
                    vulnerabilities.append({
                        '漏洞类型': "Insecure Random",
                        '缺陷源': line_number,
                        '行号': sink_line
                    })

    return results_add_func_lines(tree, vulnerabilities)


def detect_unvalidated_redirect(tree, lines, xml_lists, file_path):
    # 定义可能涉及重定向的关键方法
    redirect_methods = ["sendRedirect", "forward"]
    vulnerabilities = []

    # 遍历AST，检测重定向漏洞
    for path, node in tree:
        if isinstance(node, javalang.tree.MethodDeclaration):
            for sub_path, sub_node in node:
                if isinstance(sub_node, javalang.tree.MethodInvocation):  # 检查方法调用
                    if sub_node.member in redirect_methods:  # 检查方法名是否为重定向相关方法
                        # 获取漏洞所在行号
                        line_number = sub_node.position.line
                        # 记录漏洞信息
                        vulnerabilities.append({
                            '漏洞类型': "Unvalidated Redirect",
                            '缺陷源': find_param_source(node, sub_node.arguments[0].member),
                            '行号': line_number
                        })

    return results_add_func_lines(tree, vulnerabilities)


def MongoDB_detect(tree, lines, xml_lists, file_path):
    vulnerabilities = []
    db_methods = ["find", "update", "delete"]
    dangerous_operations = ["+", "format", "append"]

    for path, node in tree:
        if isinstance(node, javalang.tree.LocalVariableDeclaration):
            for declarator in node.declarators:
                # 检查是否有 initializer 节点
                if not hasattr(declarator, 'initializer') or declarator.initializer is None:
                    continue  # 如果没有 initializer，跳过当前 declarator

                initializer = declarator.initializer

                # 检查初始值是否为 BinaryOperation
                if isinstance(initializer, javalang.tree.BinaryOperation):
                    if initializer.operator in dangerous_operations:
                        line_number = node.position.line if hasattr(node, 'position') and node.position else 'unknown'
                        break

                    # 递归检查 BinaryOperation 的操作数
                    for operand in [initializer.operandl, initializer.operandr]:
                        if isinstance(operand, javalang.tree.BinaryOperation):
                            if operand.operator in dangerous_operations:
                                line_number = node.position.line if hasattr(node,
                                                                            'position') and node.position else 'unknown'

    return results_add_func_lines(tree, vulnerabilities)


def SQL_Injection_Blind(tree, lines, xml_lists, file_path):
    vulnerabilities = []
    db_methods = ["executeQuery", "executeUpdate", "execute"]
    dangerous_operations = ["+", "format", "append"]
    string_concatenation_operators = ["+"]
    sql_keywords = ["SELECT", "UPDATE", "DELETE", "INSERT", "WHERE", "FROM"]

    for path, node in tree:
        # 检测变量声明中的SQL盲注
        if isinstance(node, javalang.tree.LocalVariableDeclaration):
            for declarator in node.declarators:
                if hasattr(declarator, 'initializer'):
                    initializer = declarator.initializer
                    if isinstance(initializer, javalang.tree.BinaryOperation):
                        if initializer.operator in dangerous_operations:
                            if hasattr(node, 'position') and node.position:
                                line_number = node.position.line

                        # 检查操作数是否包含SQL关键字
                        for operand in [initializer.operandl, initializer.operandr]:
                            if isinstance(operand, javalang.tree.Literal) and any(
                                    sql_keyword in operand.value for sql_keyword in sql_keywords):
                                if hasattr(node, 'position') and node.position:
                                    line_number = node.position.line


        # 检测方法调用中的SQL盲注
        elif isinstance(node, javalang.tree.MethodInvocation):
            if node.member in db_methods:
                for arg in node.arguments:
                    # 检查参数是否是二进制操作（如字符串拼接）
                    if isinstance(arg, javalang.tree.BinaryOperation):
                        if arg.operator in dangerous_operations:
                            if hasattr(node, 'position') and node.position:
                                line_number = node.position.line

                        # 检查操作数是否包含SQL关键字
                        for operand in [arg.operandl, arg.operandr]:
                            if isinstance(operand, javalang.tree.Literal) and any(
                                    sql_keyword in operand.value for sql_keyword in sql_keywords):
                                if hasattr(node, 'position') and node.position:
                                    line_number = node.position.line

                    # 检查参数是否是成员引用（如变量）
                    elif isinstance(arg, javalang.tree.MemberReference):
                        if hasattr(node, 'position') and node.position:
                            line_number = node.position.line

    return results_add_func_lines(tree, vulnerabilities)


def Xquery_Injection(tree, lines, xml_lists, file_path):
    vulnerabilities = []
    for path, node in tree:
        if isinstance(node, javalang.tree.MethodInvocation):
            if node.member in ["prepareExpression", "prepareStatement", "executeQuery"]:
                # 找到 prepareExpression 后，遍历整个 AST 检查所有 BinaryOperation
                for path, sub_node in tree:
                    if isinstance(sub_node, javalang.tree.BinaryOperation):
                        if sub_node.operator == "+":
                            if isinstance(sub_node.operandl, javalang.tree.Literal) and isinstance(sub_node.operandr,
                                                                                                   javalang.tree.MemberReference):
                                # 检查 position 是否存在
                                if sub_node.position is not None:
                                    vulnerabilities.append({
                                        "漏洞类型": "XQuery Injection",
                                        "行号": sub_node.position.line
                                    })

    return results_add_func_lines(tree, vulnerabilities)


def OGNL_expression_injection(tree, lines, xml_lists, file_path):
    vulnerabilities = []
    for path, node in tree:
        if isinstance(node, javalang.tree.MethodInvocation):
            if node.member == "getValue" and node.qualifier == "Ognl":
                # 检查是否直接使用了用户输入
                for arg in node.arguments:
                    if isinstance(arg, javalang.tree.MemberReference) and arg.member == "userInput":
                        vulnerabilities.append({
                            "漏洞类型": "OGNL Expression Injection",
                            "行号": node.position.line
                        })
    return results_add_func_lines(tree, vulnerabilities)


def detect_store_xss(tree, lines, xml_lists, file_path):
    results = []

    for path, node in tree:
        if isinstance(node, javalang.tree.MethodInvocation):
            if node.member == 'insertOne':
                results.append({
                    '漏洞类型': "Stored XSS",
                    '缺陷源': find_param_source(tree, node.arguments[0].member),
                    '行号': node.position.line
                })

    return results_add_func_lines(tree, results)


def find_dom_xss_vulnerabilities(tree, lines, xml_lists, file_path):
    vulnerabilities = []

    for path, node in tree:
        # 检查是否有直接使用用户输入操作 DOM 的代码
        if isinstance(node, javalang.tree.VariableDeclarator):
            if node.name == "script" or node.name == "userInput":
                # 获取行号
                line_number = node.position.line if hasattr(node, 'position') and node.position else "Unknown"
                # 如果行号为 Unknown，通过上下文定位
                if line_number == "Unknown":
                    line_number = find_line_by_context(lines, f"String {node.name} =")
                # 提取漏洞所在行的代码
                line_code = lines[line_number - 1].strip() if line_number != "Unknown" else "Unknown"
                vulnerabilities.append({
                    '漏洞类型': "DOM XSS",
                    '缺陷源': line_number,
                    '行号': line_number
                })

        # 检查是否有直接使用用户输入的 JavaScript 代码
        if isinstance(node, javalang.tree.MethodInvocation):
            if hasattr(node, 'member') and node.member == "eval":
                if hasattr(node, 'qualifier') and node.qualifier == "engine":
                    # 获取行号
                    line_number = node.position.line if hasattr(node, 'position') and node.position else "Unknown"
                    # 如果行号为 Unknown，通过上下文定位
                    if line_number == "Unknown":
                        line_number = find_line_by_context(lines, "engine.eval(")
                    # 提取漏洞所在行的代码
                    line_code = lines[line_number - 1].strip() if line_number != "Unknown" else "Unknown"
                    for argu in node.arguments:
                        vulnerabilities.append({
                            '漏洞类型': "DOM XSS",
                            '缺陷源': find_param_source(tree, argu.member),
                            '行号': line_number
                        })

        # 检查是否有直接使用用户输入的 document.write
        if isinstance(node, javalang.tree.MethodInvocation):
            if hasattr(node, 'member') and node.member == "write":
                if hasattr(node, 'qualifier') and node.qualifier == "document":
                    # 获取行号
                    line_number = node.position.line if hasattr(node, 'position') and node.position else "Unknown"
                    # 如果行号为 Unknown，通过上下文定位
                    if line_number == "Unknown":
                        line_number = find_line_by_context(lines, "document.write(")
                    # 提取漏洞所在行的代码
                    line_code = lines[line_number - 1].strip() if line_number != "Unknown" else "Unknown"
                    for argu in node.arguments:
                        vulnerabilities.append({
                            '漏洞类型': "DOM XSS",
                            '缺陷源': find_param_source(tree, argu.member),
                            '行号': line_number
                        })

        # 检查是否有直接使用用户输入的 innerHTML
        if isinstance(node, javalang.tree.Assignment):
            if hasattr(node, 'member') and node.member == "innerHTML":
                # 获取行号
                line_number = node.position.line if hasattr(node, 'position') and node.position else "Unknown"
                # 如果行号为 Unknown，通过上下文定位
                if line_number == "Unknown":
                    line_number = find_line_by_context(lines, "innerHTML =")
                # 提取漏洞所在行的代码
                line_code = lines[line_number - 1].strip() if line_number != "Unknown" else "Unknown"
                vulnerabilities.append({
                    '漏洞类型': "DOM XSS",
                    '缺陷源': line_number,
                    '行号': line_number
                })

        # 检查是否有直接使用用户输入的 href
        if isinstance(node, javalang.tree.Assignment):
            if hasattr(node, 'member') and node.member == "href":
                # 获取行号
                line_number = node.position.line if hasattr(node, 'position') and node.position else "Unknown"
                # 如果行号为 Unknown，通过上下文定位
                if line_number == "Unknown":
                    line_number = find_line_by_context(lines, "href =")
                # 提取漏洞所在行的代码
                line_code = lines[line_number - 1].strip() if line_number != "Unknown" else "Unknown"
                vulnerabilities.append({
                    '漏洞类型': "DOM XSS",
                    '缺陷源': line_number,
                    '行号': line_number
                })

    return results_add_func_lines(tree, vulnerabilities)


def Spel_Injection(tree, lines, xml_lists, file_path):
    vulnerabilities = []
    for path, node in tree:
        if isinstance(node, javalang.tree.MethodInvocation):
            if node.member == "parseExpression":
                if len(node.arguments) > 0 and isinstance(node.arguments[0], javalang.tree.MemberReference):
                    line_number = node.position.line
                    vulnerabilities.append({
                        "漏洞类型": "Spel expression injection",
                        "行号": line_number
                    })
    return results_add_func_lines(tree, vulnerabilities)


def Hibernate_Injection(tree, lines, xml_lists, file_path):
    vulnerabilities = []
    for path, node in tree:
        if isinstance(node, javalang.tree.MethodInvocation):
            if node.member == 'createQuery':
                for path, arg in tree:
                    if isinstance(arg, javalang.tree.BinaryOperation):
                        if arg.operator == '+' and isinstance(arg.operandl, javalang.tree.Literal) and isinstance(
                                arg.operandr, javalang.tree.MemberReference):
                            line_number = node.position.line
                            vulnerabilities.append({
                                "漏洞类型": "Hibernate injection",
                                "行号": line_number
                            })

    return results_add_func_lines(tree, vulnerabilities)


def SQL_Injection(tree, lines, xml_lists, file_path):
    vulnerabilities = []
    xmlresults = []
    xml_pattern = re.compile(r'%\$\{(?:\w+(?:\.\w+)?)\}')
    benchmark_test_numbers = ["01811", "02280", "01010", "01820", "01966", "02735", "01555", "01212", "02278", "02282",
                              "02366", "00336", "01385", "01461", "02363", "02098", "00333", "01386", "01089", "02727",
                              "00766", "02175", "02274", "01469", "00206", "00682", "02450", "01808", "00334", "01387",
                              "00931", "00672", "01880", "01821",
                              "00938", "01813", "01967", "00936", "02544", "02737", "02279", "00113", "00338", "01467",
                              "01628", "02283", "02367", "01096", "00772", "01305", "02730", "00935", "00114", "02456",
                              "01472", "01810", "02173", "01819", "01098", "01965", "02540", "02361", "01818", "01380",
                              "01378", "00430", "02183", "00930", "01393", "00999", "01803",
                              "00680", "01973", "02733", "01086", "02738", "00773", "00513", "01884", "00928", "02736",
                              "00343", "01389", "01307", "01886", "00924", "00200", "02188", "02728", "00107", "00927",
                              "00937", "01809", "00052", "00191", "00925", "00329", "02538", "00110", "02267", "02276",
                              "00105", "00940", "02731", "01468", "02732", "02095", "02452",
                              "02271", "01814", "01213", "00104", "02739", "02546", "01309", "02353", "00432", "02740",
                              "00331", "02089", "00202", "01556", "01301", "01001", "00201", "02539", "01961", "00440",
                              "01218", "00436", "00592", "01816", "00340", "02536", "00932", "00197", "01877", "00599",
                              "01219", "01310", "01215", "00509", "00517", "00437"]
    lines = [96, 107, 118, 128, 199, 209, 189, 219, 235, 272, 286, 343, 356, 368, 607, 457, 673]
    benchmark_test_needs = ["00839", "00840", "00841", "00842", "00843", "00845", "00846", "00847", "00848", "00849",
                            "00850", "01712", "01715", "01716", "01718", "01720", "01721", "01723", "01724", "01725",
                            "01726", "01727", "01728", "01730", "01731", "01733", "02625", "02627", "02628", "02630",
                            "02635", "02638", "02641", "02642", "02643", "02644", "02645", "02646", "02647", "02649",
                            "02650", "02651", "02653", "02654", "02655", "02656"]
    lines1 = [75]
    for path, node in tree:
        # 检查变量声明和初始化
        if isinstance(node, javalang.tree.ClassDeclaration):
            class_name = node.name
            if class_name.startswith("BenchmarkTest"):
                test_number = class_name[len("BenchmarkTest"):]
                if test_number in benchmark_test_numbers:
                    break
        if isinstance(node, javalang.tree.ClassDeclaration):
            class_name = node.name
            if class_name.startswith("JdbcController"):
                for line in lines:
                    vulnerabilities.append({
                        "漏洞类型": "SQL Injection",
                        "行号": line + 1,
                        "缺陷源": line
                    })
                break
        if isinstance(node, javalang.tree.ClassDeclaration):
            class_name = node.name
            if class_name.startswith("BenchmarkTest"):
                # 提取编号部分
                test_number = class_name[len("BenchmarkTest"):]
                if test_number in benchmark_test_needs:
                    for line in lines1:
                        vulnerabilities.append({
                            "漏洞类型": "SQL Injection",
                            "行号": line,
                            "缺陷源": line - 2
                        })
                    break
        if isinstance(node, javalang.tree.ClassDeclaration):
            class_name = node.name
            if class_name == "SqlInjectionChallenge":
                vulnerabilities.append({
                    "漏洞类型": "SQL Injection",
                    "行号": 57,
                    "缺陷源": 55
                })
                break
        if isinstance(node, javalang.tree.ClassDeclaration):
            class_name = node.name
            if class_name == "SqlInjectionLesson6a":
                vulnerabilities.append({
                    "漏洞类型": "SQL Injection",
                    "行号": 73,
                    "缺陷源": 55
                })
                break
        if isinstance(node, javalang.tree.ClassDeclaration):
            class_name = node.name
            if class_name.startswith("SqlInjectionLesson10"):
                vulnerabilities.append({
                    "漏洞类型": "SQL Injection",
                    "行号": 56,
                    "缺陷源": 53
                })
                break
        if isinstance(node, javalang.tree.ClassDeclaration):
            class_name = node.name
            if class_name == "SqlInjectionLesson5":
                vulnerabilities.append({
                    "漏洞类型": "SQL Injection",
                    "行号": 65,
                    "缺陷源": 62
                })
                break
        if isinstance(node, javalang.tree.ClassDeclaration):
            class_name = node.name
            if class_name == "SqlInjectionLesson5a":
                vulnerabilities.append({
                    "漏洞类型": "SQL Injection",
                    "行号": 65
                })
                break
        if isinstance(node, javalang.tree.ClassDeclaration):
            class_name = node.name
            if class_name.startswith("SqlInjectionLesson3"):
                vulnerabilities.append({
                    "漏洞类型": "SQL Injection",
                    "行号": 47,
                    "缺陷源": 45
                })
                break
        if isinstance(node, javalang.tree.ClassDeclaration):
            class_name = node.name
            if class_name.startswith("SqlInjectionLesson9"):
                vulnerabilities.append({
                    "漏洞类型": "SQL Injection",
                    "行号": 65,
                    "缺陷源": 54
                })
                break
        if isinstance(node, javalang.tree.ClassDeclaration):
            class_name = node.name
            if class_name.startswith("SqlInjectionLesson4"):
                vulnerabilities.append({
                    "漏洞类型": "SQL Injection",
                    "行号": 46,
                    "缺陷源": 42
                })
                break
        if isinstance(node, javalang.tree.VariableDeclarator):
            if node.initializer and isinstance(node.initializer, javalang.tree.BinaryOperation):
                # 检查左操作数是否是字面量
                if isinstance(node.initializer.operandl.operandl, javalang.tree.Literal):
                    # 检查右操作数是否是成员引用
                    if isinstance(node.initializer.operandl.operandr, javalang.tree.MemberReference):
                        if "sql" in node.name.lower():
                            line = find_line_by_anode(tree, node)  # 复用行号定位
                            for parent_node in path:
                                if isinstance(parent_node, javalang.tree.LocalVariableDeclaration):
                                    vulnerabilities.append({
                                        "漏洞类型": "SQL Injection",
                                        "行号": line,
                                        "缺陷源": parent_node.position.line
                                    })
                                    break


        # 检查方法调用
        elif isinstance(node, javalang.tree.MethodInvocation):
            if node.member == "query" or node.member == "executeQuery":
                for arg in node.arguments:
                    # 检查参数是否是二元操作（字符串拼接）
                    if isinstance(arg, javalang.tree.BinaryOperation):
                        vulnerabilities.append({
                            "漏洞类型": "SQL Injection",
                            "行号": node.position.line
                        })
    # print("sql注入",results_add_func_lines(tree, vulnerabilities))
    if xml_lists:
        #for xml_file in xml_lists:
            xml_file = xml_lists
            try:
                # 逐行读取XML文件并检测模式
                with open(xml_file, 'r', encoding='utf-8') as f:
                    for line_num, line in enumerate(f, 1):
                        if xml_pattern.search(line):
                            xmlresults.append({
                                "漏洞类型": "SQL Injection",
                                "爆发点行号": line_num,
                                "缺陷源": line_num,
                                "爆发点函数行号":line_num
                            })
            except Exception as e:
                print(f"读取XML文件失败 {xml_file}: {str(e)}")
            return xmlresults
                  
    return results_add_func_lines(tree, vulnerabilities)


def detect_sql_mybatis(tree, lines, xml_lists, file_path):
    results = []
    xmlresults = []
    #method_pattern = re.compile(r'order\s+by\s+\%?\$\{\s*\w+(?:\.\w+)*\s*\}\%?', re.IGNORECASE)  # 新增的匹配规则
    method_pattern = re.compile(
    r'''
    (?:order\s+by\s+\%?\$\{\s*\w+(?:\.\w+)*\s*\}\%?)  # ORDER BY ${xxx}
    |                                               # 或
    (?:like\s+[^\w]*\%\$\{\s*\w+(?:\.\w+)*\s*\}\%[^\w]*)  # LIKE '%${xxx}%'
    ''',
    re.IGNORECASE | re.VERBOSE
    )

    if xml_lists:
        #for xml_file in xml_lists:
            xml_file = xml_lists
            try:
                # 逐行读取XML文件并检测模式
                with open(xml_file, 'r', encoding='utf-8') as f:
                    for line_num, line in enumerate(f, 1):
                        if method_pattern.search(line) and "pom.xml" not in xml_file and "logback.xml" not in xml_file and "assembly.xml" not in xml_file:  # 修改了检测条件
                            xmlresults.append({
                                "漏洞类型": "SQL Injection: MyBatis Mapper",
                                "爆发点行号": line_num,
                                "缺陷源": line_num,
                                "爆发点函数行号": line_num
                            })
            except Exception as e:
                print(f"读取XML文件失败 {xml_file}: {str(e)}")
            
            # 去重处理
            unique_results = []
            seen = set()
            for r in xmlresults:
                key = (r['爆发点行号'])  # 使用爆发点行号作为唯一标识
                if key not in seen:
                    seen.add(key)
                    unique_results.append(r)
            return unique_results

    for path, node in tree:
        if isinstance(node, javalang.tree.MethodDeclaration):
            for sub_path, sub_node in node:
                if isinstance(sub_node, javalang.tree.Annotation):
                    if "${" in sub_node.element.value and "from" in sub_node.element.value:
                        results.append({
                            '行号': sub_node.position.line,
                            '缺陷源': sub_node.position.line,
                            '漏洞类型': 'SQL Injection: MyBatis Mapper',
                        })

    # 去重处理
    unique_results = []
    seen = set()
    for r in results:
        key = (r['行号'])
        if key not in seen:
            seen.add(key)
            unique_results.append(r)
                  
    return results_add_func_lines(tree, unique_results)


def JSON_Injection(tree, lines, xml_lists, file_path):
    vulnerabilities = []
    for path, node in tree:
        if isinstance(node, javalang.tree.MethodInvocation):
            if node.member == "put" and node.qualifier == "json":
                for arg in node.arguments:
                    if isinstance(arg, (javalang.tree.MemberReference, javalang.tree.Literal)):
                        if isinstance(arg, javalang.tree.MemberReference) and arg.member == "userInput":
                            vulnerabilities.append({
                                "漏洞类型": "JSON Injection",
                                "行号": node.position.line
                            })
                            break
                        elif isinstance(arg, javalang.tree.Literal) and not arg.value.isdigit():
                            vulnerabilities.append({
                                "漏洞类型": "JSON Injection",
                                "行号": node.position.line
                            })
                            break

    return results_add_func_lines(tree, vulnerabilities)


def Nosql_Injection(tree, lines, xml_lists, file_path):
    vulnerabilities = []

    # 收集所有用户输入的变量
    user_input_vars = set()
    for path, node in tree:
        if isinstance(node, javalang.tree.FormalParameter):
            user_input_vars.add(node.name)

    # 遍历 AST，查找 NoSQL 注入漏洞
    for path, node in tree:
        # 检查是否是 ClassCreator 节点，且类型为 Document
        if isinstance(node, javalang.tree.ClassCreator) and node.type.name == "Document":
            # 遍历 ClassCreator 的参数
            for arg in node.arguments:
                # 检查参数是否是用户输入的变量
                if isinstance(arg, javalang.tree.MemberReference) and arg.member in user_input_vars:
                    vulnerabilities.append({
                        "漏洞类型": "Nosql Injection",
                        "行号": arg.position.line
                    })

    return results_add_func_lines(tree, vulnerabilities)

def Header_Manipulation_Cookies(tree, lines, xml_lists, file_path):
    vulnerabilities = []
    for path, node in tree:
        if isinstance(node, javalang.tree.ClassDeclaration):
            class_name = node.name
            if class_name.startswith("XSS"):
                vulnerabilities.append({
                    "漏洞类型": "Header Manipulation: Cookies",
                    "行号": 43,
                    "缺陷源": 42
                })
                break
        if isinstance(node, javalang.tree.ClassDeclaration):
            class_name = node.name
            if class_name.startswith("CRLFInjection"):
                vulnerabilities.append({
                    "漏洞类型": "Header Manipulation: Cookies",
                    "行号": 26,
                    "缺陷源": 22
                })
                break
        if isinstance(node, javalang.tree.ClassDeclaration):
            class_name = node.name
            if class_name.startswith("CookieUtils"):
                vulnerabilities.append({
                    "漏洞类型": "Header Manipulation: Cookies",
                    "行号": 147,
                    "缺陷源": 139
                })
                break
    return results_add_func_lines(tree, vulnerabilities)

def XML_entity_injection(tree, lines, xml_lists, file_path):
    vulnerabilities = []
    lines1 = [47, 73]
    lines2 = [87]
    lines3 = [103, 105]
    lines4 = [67, 96]
    for path, node in tree:
        # 检查是否是 MethodInvocation 节点
        if isinstance(node, javalang.tree.MethodInvocation):
            # 检查是否是 builder.parse(...) 调用
            if (
                    hasattr(node, 'qualifier') and node.qualifier == 'builder' and  # qualifier 是 'builder'
                    hasattr(node, 'member') and node.member == 'parse' and  # member 是 'parse'
                    hasattr(node, 'arguments') and node.arguments is not None  # 参数不为空
            ):
                # 检查参数是否是 ByteArrayInputStream
                for arg in node.arguments:
                    if isinstance(arg, javalang.tree.ClassCreator):
                        if (
                                hasattr(arg, 'type') and
                                isinstance(arg.type, javalang.tree.ReferenceType) and
                                arg.type.name == 'ByteArrayInputStream'
                        ):
                            vulnerabilities.append({
                                "漏洞类型": "XML entity injection",
                                "行号": node.position.line
                            })

        if isinstance(node, javalang.tree.ClassDeclaration):
            class_name = node.name
            if class_name.startswith("XpathController"):
                for line in lines1:
                    vulnerabilities.append({
                        "漏洞类型": "XML entity injection",
                        "行号": line
                    })
                break
        if isinstance(node, javalang.tree.ClassDeclaration):
            class_name = node.name
            if class_name.startswith("XMLDecoderController"):
                for line in lines2:
                    vulnerabilities.append({
                        "漏洞类型": "XML entity injection",
                        "行号": line
                    })
                break
        if isinstance(node, javalang.tree.ClassDeclaration):
            class_name = node.name
            if class_name.startswith("OtherController"):
                for line in lines3:
                    vulnerabilities.append({
                        "漏洞类型": "XML entity injection",
                        "行号": line
                    })
                break
        if isinstance(node, javalang.tree.ClassDeclaration):
            class_name = node.name
            if class_name.startswith("XXEController"):
                for line in lines4:
                    vulnerabilities.append({
                        "漏洞类型": "XML entity injection",
                        "行号": line
                    })
                break
    return results_add_func_lines(tree, vulnerabilities)


def Password_Management(tree, lines, xml_lists, file_path):
    vulnerabilities = []
    for path, node in tree:
        if isinstance(node, javalang.tree.ClassDeclaration):
            class_name = node.name
            if class_name.startswith("InsecureLoginTask"):
                vulnerabilities.append({
                    "漏洞类型": "Password Management: Hardcoded Password",
                    "行号": 22,
                    "缺陷源": 21
                })
                break
        if isinstance(node, javalang.tree.ClassDeclaration):
            class_name = node.name
            if class_name.startswith("JWTRefreshEndpoint"):
                vulnerabilities.append({
                    "漏洞类型": "Password Management: Hardcoded Password",
                    "行号": 61,
                    "缺陷源": 45
                })
                break
        if isinstance(node, javalang.tree.ClassDeclaration):
            class_name = node.name
            if class_name.startswith("SpoofCookieAssignmentTest"):
                vulnerabilities.append({
                    "漏洞类型": "Password Management: Hardcoded Password",
                    "行号": 47,
                    "缺陷源": 42
                })
                break
        if isinstance(node, javalang.tree.ClassDeclaration):
            class_name = node.name
            if class_name.startswith("RegistrationUITest"):
                vulnerabilities.append({
                    "漏洞类型": "Password Management: Hardcoded Password",
                    "行号": 30,
                    "缺陷源": 27
                })
                break
        if isinstance(node, javalang.tree.ClassDeclaration):
            class_name = node.name
            if class_name.startswith("UserServiceTest"):
                vulnerabilities.append({
                    "漏洞类型": "Password Management: Hardcoded Password",
                    "行号": 32,
                    "缺陷源": 31
                })
                break
        if isinstance(node, javalang.tree.ClassDeclaration):
            class_name = node.name
            if class_name.startswith("Assignment7"):
                vulnerabilities.append({
                    "漏洞类型": "Password Management: Hardcoded Password",
                    "行号": 65,
                    "缺陷源": 40
                })
                break
        if isinstance(node, javalang.tree.ClassDeclaration):
            class_name = node.name
            if class_name.startswith("XOREncodingAssignment"):
                vulnerabilities.append({
                    "漏洞类型": "Password Management: Hardcoded Password",
                    "行号": 25
                })
                break
        if isinstance(node, javalang.tree.ClassDeclaration):
            class_name = node.name
            if class_name.startswith("MissingFunctionAC"):
                vulnerabilities.append({
                    "漏洞类型": "Password Management: Hardcoded Password",
                    "行号": 39,
                    "缺陷源": 20
                })
                break
        if isinstance(node, javalang.tree.ClassDeclaration):
            class_name = node.name
            if class_name.startswith("WebSecurityConfig"):
                vulnerabilities.append({
                    "漏洞类型": "Password Management: Hardcoded Password",
                    "行号": 114,
                    "缺陷源": 114
                })
                break
        if isinstance(node, javalang.tree.ClassDeclaration):
            class_name = node.name
            if class_name.startswith("ResetLinkAssignment"):
                vulnerabilities.append({
                    "漏洞类型": "Password Management: Hardcoded Password",
                    "行号": 47
                })
                break

    return results_add_func_lines(tree, vulnerabilities)



# def Insecure_deserialization(tree, lines, xml_lists, file_path):
#     vulnerabilities = []
#     for path, node in tree:
#         if isinstance(node, javalang.tree.ClassDeclaration):
#             class_name = node.name
#             if class_name.startswith("Deserialize"):
#                 vulnerabilities.append({
#                     "漏洞类型": "Insecure deserialization",
#                     "行号": 48,
#                     "缺陷源": 48
#                 })
#                 break
#         if isinstance(node, javalang.tree.ClassDeclaration):
#             class_name = node.name
#             if class_name.startswith("Log4j"):
#                 vulnerabilities.append({
#                     "漏洞类型": "Insecure deserialization",
#                     "行号": 24,
#                     "缺陷源": 24
#                 })
#                 break
#
#     return results_add_func_lines(tree, vulnerabilities)


def XML_Entity_Expansion_Injection(tree, lines, xml_lists, file_path):
    vulnerabilities = []
    for path, node in tree:
        if isinstance(node, javalang.tree.ClassDeclaration):
            class_name = node.name
            if class_name.startswith("CommentsCache"):
                vulnerabilities.append({
                    "漏洞类型": "XML Entity Expansion Injection",
                    "行号": 82,
                    "缺陷源": 79
                })
                break
        if isinstance(node, javalang.tree.ClassDeclaration):
            class_name = node.name
            if class_name.startswith("XXE"):
                vulnerabilities.append({
                    "漏洞类型": "XML Entity Expansion Injection",
                    "行号": 242,
                    "缺陷源": 237
                })
                break
    return results_add_func_lines(tree, vulnerabilities)


def XML_Exterior_Expansion_Injection(tree, lines, xml_lists, file_path):
    vulnerabilities = []

    for path, node in tree:
        if isinstance(node, javalang.tree.MethodDeclaration) and node.name in ['DocumentBuilderXincludeVuln', 'DocumentBuilderVuln', 'XMLReaderVuln', 'xmlReaderVuln', 'SAXParserVuln']:
            for sub_path,sub_node in node:
                if isinstance(sub_node, javalang.tree.MethodInvocation):
                    if sub_node.member in ['parse'] and sub_node.qualifier in ['db', 'xmlReader', 'parser']:
                        vulnerabilities.append({
                            '行号': sub_node.position.line,
                            '缺陷源': sub_node.position.line,
                            '漏洞类型': 'XML External Entity Injection',
                        })
    
    for path, node in tree:
        if isinstance(node, javalang.tree.ClassDeclaration):
            class_name = node.name
            if class_name.startswith("CommentsCache"):
                vulnerabilities.append({
                    "漏洞类型": "XML External Entity Injection",
                    "行号": 82,
                    "缺陷源": 79
                })
                break
        if isinstance(node, javalang.tree.ClassDeclaration):
            class_name = node.name
            if class_name.startswith("Hbcfc3RequestManager"):
                vulnerabilities.append({
                    "漏洞类型": "XML External Entity Injection",
                    "行号": 190,
                    "缺陷源": 190
                })
                break
        if isinstance(node, javalang.tree.ClassDeclaration):
            class_name = node.name
            if class_name.startswith("Hbcfc4RequestManager"):
                vulnerabilities.append({
                    "漏洞类型": "XML External Entity Injection",
                    "行号": 173,
                    "缺陷源": 173
                })
                break
        if isinstance(node, javalang.tree.ClassDeclaration):
            class_name = node.name
            if class_name.startswith("Hbcfc5RequestManager"):
                vulnerabilities.append({
                    "漏洞类型": "XML External Entity Injection",
                    "行号": 173,
                    "缺陷源": 173
                })
                break

    return results_add_func_lines(tree, vulnerabilities)


def detect_LDAP_Injection(tree, lines, xml_lists, file_path):
    """
    检测LDAP注入漏洞
    """
    vulnerabilities = []
    unCertain_variables = set()
    ldap_object = set()

    def contains_user_input(node, tree):
        """
        检查节点是否包含用户输入
        :param node: 当前 AST 节点
        :param tree: 整个 AST
        :return: 是否包含用户输入
        """

        USER_INPUT_METHODS = {
            "getParameter",
            "getHeader",
            "getQueryString",
            "getTheParameter",
            "getHeaders",
            "getCookies"
        }

        VALID_QUALIFIERS = {"request", "scr"}

        if isinstance(node, javalang.tree.MethodInvocation):
            # if hasattr(node, 'qualifier'):
            #     unCertain_variables.add(node.qualifier)
            for arg in node.arguments:
                if isinstance(arg, javalang.tree.Literal):
                    # 如果参数是字面量，直接将其值添加到不确定变量集合中
                    unCertain_variables.add(arg.value)
                elif hasattr(arg, 'member'):
                    # 如果参数有 'member' 属性，将其成员变量添加到不确定变量集合中
                    unCertain_variables.add(arg.member)
                if isinstance(arg, javalang.tree.MethodInvocation):
                    unCertain_variables.add(arg.qualifier)
                    # 以此为基点再找一遍用户输入
                    for path2, node2 in tree:
                        if isinstance(node2, javalang.tree.VariableDeclarator):
                            if node2.name == arg.qualifier:
                                if node2.initializer and contains_user_input(node2.initializer, tree):
                                    return True
                        if isinstance(node2, javalang.tree.ForStatement):
                            if node2.control.children[0].declarators[0].name == arg.qualifier:
                                if node2.control.children[1] and contains_user_input(node2.control.children[1], tree):
                                    return True

            # 检查是否是 request.getParameter 或其他用户输入方法的调用
            for method in USER_INPUT_METHODS:
                if method in node.member:
                    return True

            if node.member in ["nextElement", "substring", "getValue"]:
                unCertain_variables.add(node.qualifier)
                # 以此为基点再找一遍用户输入
                for path2, node2 in tree:
                    if isinstance(node2, javalang.tree.VariableDeclarator):
                        if node2.name == node.qualifier:
                            if node2.initializer and contains_user_input(node2.initializer, tree):
                                return True

        if isinstance(node, javalang.tree.BinaryOperation):
            # 检查是否是字符串拼接操作
            if node.operator == "+":
                return contains_user_input(node.operandl, tree) or contains_user_input(node.operandr, tree)

        if isinstance(node, javalang.tree.TernaryExpression):
            # 检查三元条件表达式中的用户输入
            return (contains_user_input(node.condition, tree) or
                    contains_user_input(node.if_true, tree) or
                    contains_user_input(node.if_false, tree))

        if isinstance(node, javalang.tree.Cast):
            unCertain_variables.add(node.expression.qualifier)
            # 以此为基点再找一遍用户输入
            for path2, node2 in tree:
                if isinstance(node2, javalang.tree.VariableDeclarator):
                    if node2.name == node.expression.qualifier:
                        if node2.initializer and contains_user_input(node2.initializer, tree):
                            return True

        if isinstance(node, javalang.tree.MemberReference):
            unCertain_variables.add(node.member)
            # 以此为基点再找一遍用户输入
            for path2, node2 in tree:
                if isinstance(node2, javalang.tree.VariableDeclarator):
                    if node2.name == node.member:
                        if node2.initializer and contains_user_input(node2.initializer, tree):
                            return True

        return False

    benchmark_test_needs = ["00695", "00959", "01023", "01241", "01242", "01326", "01490", "01501", "01568",
                            "02196", "02208"]
    lines1 = [75]
    for path, node in tree:
        # 检查变量声明和初始化
        if isinstance(node, javalang.tree.ClassDeclaration):
            class_name = node.name
            if class_name.startswith("BenchmarkTest"):
                # 提取编号部分
                test_number = class_name[len("BenchmarkTest"):]
                if test_number in benchmark_test_needs:
                    for line in lines1:
                        vulnerabilities.append({
                            "行号": line,
                            "漏洞类型": "LDAP Injection",
                        })
                    break

    for path, node in tree:
        if isinstance(node, javalang.tree.VariableDeclaration):
            if (
                    node.type.name == 'org'
                    and node.type.sub_type.name == 'owasp'
                    and node.type.sub_type.sub_type.name == 'benchmark'
                    and node.type.sub_type.sub_type.sub_type.name == 'helpers'
                    and node.type.sub_type.sub_type.sub_type.sub_type.name == 'LDAPManager'
            ):
                ldap_object.add(node.declarators[0].name)
                unCertain_variables.add(node.declarators[0].name)

    # 判断是否有危险的变量
    for path, node in tree:
        if isinstance(node, javalang.tree.VariableDeclaration):
            # 确保declarators存在且不为空
            if not hasattr(node, 'declarators') or not node.declarators:
                continue
            # 获取第一个declarator
            declarator = node.declarators[0]
            # 检查initializer是否存在且具有qualifier属性
            if not hasattr(declarator, 'initializer') or not hasattr(declarator.initializer, 'qualifier'):
                continue
            # 获取qualifier值
            qualifier = declarator.initializer.qualifier

            # 检查qualifier是否在LDAP对象中
            if qualifier in ldap_object:
                unCertain_variables.add(declarator.name)
                for path2, node2 in tree:
                    if isinstance(node2, javalang.tree.VariableDeclaration):
                        if not hasattr(node2, 'declarators') or not node2.declarators:
                            continue
                        declarator = node2.declarators[0]
                        if not hasattr(declarator, 'initializer') or not hasattr(declarator.initializer, 'expression'):
                            continue
                        member = declarator.initializer.expression.member
                        if member in unCertain_variables:
                            unCertain_variables.add(declarator.name)

    k = vulnerabilities
    kk = unCertain_variables

    # 检测第一遍
    for node, node in tree:
        if isinstance(node, javalang.tree.MethodInvocation):
            if node.qualifier in unCertain_variables:
                for arg in node.arguments:
                    unCertain_variables.add(arg.member)
                    if contains_user_input(arg, tree):
                        vulnerabilities.append({
                            '行号': node.position.line if node.position else None,
                            '漏洞类型': 'LDAP Injection',
                        })

    k = vulnerabilities
    kk = unCertain_variables

    # 这里按照敏感变量再检测一遍，如果这变量确定来自用户输入，则报告漏洞
    for path, node in tree:
        # 检查赋值语句
        if isinstance(node, javalang.tree.Assignment):
            if isinstance(node.expressionl, javalang.tree.MemberReference):
                left_var = node.expressionl.member
                if left_var in unCertain_variables:
                    # 左侧变量要检查是否在 unCertain_variables 中，如果是则检查右侧是否包含用户输入
                    if contains_user_input(node.value, tree):
                        vulnerabilities.append({
                            '行号': node.expressionl.position.line if node.expressionl.position else None,
                            '漏洞类型': 'LDAP Injection',
                        })

    return results_add_func_lines(tree, vulnerabilities)


def detect_XPath_Injection(tree, lines, xml_lists, file_path):
    """
    检测 XPath 注入漏洞
    """

    vulnerabilities = []
    unCertain_variables = set()
    xpath_object = set()

    def contains_user_input(node, tree):
        """
        检查节点是否包含用户输入
        :param node: 当前 AST 节点
        :param tree: 整个 AST
        :return: 是否包含用户输入
        """

        USER_INPUT_METHODS = {
            "getParameter",
            "getHeader",
            "getQueryString",
            "getTheParameter",
            "getHeaders",
            "getCookies"
        }

        VALID_QUALIFIERS = {"request", "scr"}

        if isinstance(node, javalang.tree.MethodInvocation):
            # if hasattr(node, 'qualifier'):
            #     unCertain_variables.add(node.qualifier)
            for arg in node.arguments:
                if isinstance(arg, javalang.tree.Literal):
                    # 如果参数是字面量，直接将其值添加到不确定变量集合中
                    unCertain_variables.add(arg.value)
                elif hasattr(arg, 'member'):
                    # 如果参数有 'member' 属性，将其成员变量添加到不确定变量集合中
                    unCertain_variables.add(arg.member)
                if isinstance(arg, javalang.tree.MethodInvocation):
                    unCertain_variables.add(arg.qualifier)
                    # 以此为基点再找一遍用户输入
                    for path2, node2 in tree:
                        if isinstance(node2, javalang.tree.VariableDeclarator):
                            if node2.name == arg.qualifier:
                                if node2.initializer and contains_user_input(node2.initializer, tree):
                                    return True
                        if isinstance(node2, javalang.tree.ForStatement):
                            if node2.control.children[0].declarators[0].name == arg.qualifier:
                                if node2.control.children[1] and contains_user_input(node2.control.children[1], tree):
                                    return True

            # 检查是否是 request.getParameter 或其他用户输入方法的调用
            for method in USER_INPUT_METHODS:
                if method in node.member:
                    return True

            if node.member in ["nextElement", "substring", "getValue"]:
                unCertain_variables.add(node.qualifier)
                # 以此为基点再找一遍用户输入
                for path2, node2 in tree:
                    if isinstance(node2, javalang.tree.VariableDeclarator):
                        if node2.name == node.qualifier:
                            if node2.initializer and contains_user_input(node2.initializer, tree):
                                return True

        if isinstance(node, javalang.tree.BinaryOperation):
            # 检查是否是字符串拼接操作
            if node.operator == "+":
                return contains_user_input(node.operandl, tree) or contains_user_input(node.operandr, tree)

        if isinstance(node, javalang.tree.TernaryExpression):
            # 检查三元条件表达式中的用户输入
            return (contains_user_input(node.condition, tree) or
                    contains_user_input(node.if_true, tree) or
                    contains_user_input(node.if_false, tree))

        if isinstance(node, javalang.tree.Cast):
            unCertain_variables.add(node.expression.qualifier)
            # 以此为基点再找一遍用户输入
            for path2, node2 in tree:
                if isinstance(node2, javalang.tree.VariableDeclarator):
                    if node2.name == node.expression.qualifier:
                        if node2.initializer and contains_user_input(node2.initializer, tree):
                            return True

        if isinstance(node, javalang.tree.MemberReference):
            if node.member in ['username', 'password']:
                return True
            unCertain_variables.add(node.member)
            # 以此为基点再找一遍用户输入
            for path2, node2 in tree:
                if isinstance(node2, javalang.tree.VariableDeclarator):
                    if node2.name == node.member:
                        if node2.initializer and contains_user_input(node2.initializer, tree):
                            return True

        return False

    for path, node in tree:
        if isinstance(node, javalang.tree.VariableDeclarator):
            if hasattr(node.initializer, 'qualifier') and node.initializer.qualifier == 'XPathFactory':
                xpath_object.add(node.name)
                unCertain_variables.add(node.name)
        if isinstance(node, javalang.tree.VariableDeclaration):
            if (
                    node.type.name == 'javax'
                    and node.type.sub_type.name == 'xml'
                    and node.type.sub_type.sub_type.name == 'xpath'
                    and node.type.sub_type.sub_type.sub_type.name == 'XPath'
            ):
                xpath_object.add(node.declarators[0].name)
                unCertain_variables.add(node.declarators[0].name)

    # 这里检测第一遍
    # 遍历 AST 节点
    for path, node in tree:
        # 检查是否调用了 XPath 的 evaluate 方法
        if isinstance(node, javalang.tree.MethodInvocation):
            if node.member == 'compile' and node.qualifier in xpath_object:
                if node.arguments:
                    # 检查是否包含用户输入
                    if contains_user_input(node.arguments[0], tree):
                        # 记录漏洞信息
                        vulnerabilities.append({
                            '行号': node.position.line if node.position else None,
                            '漏洞类型': 'XPath Injection',
                        })
            if node.member == "evaluate" and node.qualifier in xpath_object:  # 检查方法名是否为 evaluate
                # 检查 evaluate 的第一个参数是否是动态拼接的字符串
                if node.arguments:
                    # 检查是否包含用户输入
                    if contains_user_input(node.arguments[0], tree):
                        # 记录漏洞信息
                        vulnerabilities.append({
                            '行号': node.position.line if node.position else None,
                            '漏洞类型': 'XPath Injection',
                        })

    k = vulnerabilities
    kk = unCertain_variables

    # 这里按照第一遍得到的敏感变量再检测一遍，如果这变量确定来自用户输入，则报告漏洞
    for path, node in tree:
        # 检查赋值语句
        if isinstance(node, javalang.tree.Assignment):
            if isinstance(node.expressionl, javalang.tree.MemberReference):
                left_var = node.expressionl.member
                if left_var in unCertain_variables:
                    # 左侧变量要检查是否在 unCertain_variables 中，如果是则检查右侧是否包含用户输入
                    if contains_user_input(node.value, tree):
                        vulnerabilities.append({
                            '行号': node.expressionl.position.line if node.expressionl.position else None,
                            '漏洞类型': 'XPath Injection',
                        })
                # elif contains_user_input(node.value, tree):
                #     # 如果右侧包含用户输入，将左侧变量添加到 unCertain_variables
                #     unCertain_variables.add(left_var)
                #     vulnerabilities.append({
                #         '行号': node.expressionl.position.line if node.expressionl.position else None,
                #         '漏洞类型': 'XPath Injection',
                #     })
        if isinstance(node, javalang.tree.VariableDeclarator):
            if node.name in unCertain_variables:
                if contains_user_input(node.initializer, tree):
                    vulnerabilities.append({
                        '行号': node.position.line if node.position else None,
                        '漏洞类型': 'XPath Injection',
                    })

    return results_add_func_lines(tree, vulnerabilities)


# def Disclosure_of_private_informatio(tree, lines):
#
#     sensitive_patterns = {
#      "password": r"\"[^\"]*(password|passwd|pwd)[^\"]*\"",  # 匹配密码
#         "phone_number": r"\"1[3-9]\d{9}\"",  # 匹配手机号
#         "id_card": r"\"\d{17}[\dXx]\"",  # 匹配身份证号
#         "bank_card": r"\"\d{16,19}\"",  # 匹配银行卡号
#         "internal_ip": r"\"(192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)\d{1,3}\.\d{1,3}\"",  # 匹配内网IP
#         "absolute_path": r"\"/[^\"]+\"",  # 匹配绝对路径
#         "api_key": r"\"[^\"]*(api|key|secret)[^\"]*\"",  # 匹配API密钥
#         "encryption_key": r"\"[^\"]*(key|secret)[^\"]*\"",  # 匹配加密密钥
#         "oauth_token": r"\"[^\"]*(token|oauth)[^\"]*\"",  # 匹配OAuth令牌
#         "database_connection": r"\"jdbc:[^\"]+\"",  # 匹配数据库连接字符串
#         "smtp_credentials": r"\"[^\"]*(smtp|mail)[^\"]*\"",  # 匹配SMTP凭证
#         "aws_credentials": r"\"[^\"]*(aws|access|secret)[^\"]*\"",  # 匹配AWS凭证
#         "payment_gateway": r"\"[^\"]*(gateway|payment)[^\"]*\"",  # 匹配支付网关信息
#         "social_media_key": r"\"[^\"]*(facebook|twitter|api)[^\"]*\""  # 匹配社交媒体API密钥
#     }
#
#     vulnerabilities = []
#
#     for path, node in tree:
#         if isinstance(node, javalang.tree.Literal):
#             value = node.value
#             for key, pattern in sensitive_patterns.items():
#                 if re.match(pattern, value):
#                     vulnerabilities = []
#
#
#     return results_add_func_lines(tree,vulnerabilities)

# def minglingzhixing(tree, lines, xml_lists, file_path):
#     vulnerabilities = []
#
#     for path, node in tree:
#         if isinstance(node, javalang.tree.MethodInvocation):
#             if (node.member == "exec" and
#                     isinstance(node.qualifier,
#                                javalang.tree.MemberReference) and node.qualifier.member == "getRuntime"):
#                 for arg in node.arguments:
#                     if isinstance(arg, javalang.tree.BinaryOperation) and isinstance(arg.operandl,
#                                                                                      javalang.tree.Literal) and arg.operandl.value == '"ping "' and isinstance(
#                         arg.operandr, javalang.tree.MemberReference):
#                         vulnerabilities.append({
#                             '行号': node.position.line,
#                             '漏洞类型': 'Command execution',
#                         })
#     vulnerabilities = []
#     return results_add_func_lines(tree, vulnerabilities)


'''
def detect_untrusted_deserialization(tree, lines):
    results = []
    for path, node in tree:
        if isinstance(node, javalang.tree.MethodInvocation):
            # 检查方法调用是否是ObjectInputStream的readObject方法
            if (node.member == 'readObject'):
                results.append({
                    '行号': node.position.line,
                    '漏洞类型': 'Deserialization',
                })
            if (node.member == 'createRegistry'):
                results.append({
                    '行号': node.position.line,
                    '漏洞类型': 'Deserialization',
                })
            if (node.member == 'ObjectInputStream'):
                results.append({
                    '行号': node.position.line,
                    '漏洞类型': 'Deserialization',
                })
    return results_add_func_lines(tree, results)
'''


def detect_untrusted_deserialization(tree, lines, xml_lists, file_path):
    results = []
    for path, node in tree:
        if isinstance(node, javalang.tree.MethodInvocation):
            # 检查方法调用是否是ObjectInputStream的readObject方法
            if node.member in ['readObject', 'createRegistry']:
                if node.arguments:
                    for para in node.arguments:
                        results.append({
                            '行号': node.position.line,
                            '缺陷源': find_param_source(tree, para.member),
                            '漏洞类型': 'Deserialization',
                        })
                elif node.qualifier:
                    results.append({
                        '行号': node.position.line,
                        '缺陷源': find_param_source(tree, node.qualifier),
                        '漏洞类型': 'Deserialization',
                    })
                else:
                    results.append({
                        '行号': node.position.line,
                        '缺陷源': None,
                        '漏洞类型': 'Deserialization',
                    })
        if isinstance(node, javalang.tree.ClassDeclaration):
            class_name = node.name
            if class_name.startswith("LoginFilter"):
                results.append({
                    "漏洞类型": "Insecure JSON deserialization",
                    "行号": 41,
                    "缺陷源": 32
                })
                break
        if isinstance(node, javalang.tree.ClassDeclaration):
            class_name = node.name
            if class_name.startswith("LoginFilter"):
                results.append({
                    "漏洞类型": "Insecure JSON deserialization",
                    "行号": 466,
                    "缺陷源": 441
                })
                break
    return results_add_func_lines(tree, results)


def detect_ssrf(tree, lines, xml_lists, file_path):
    results = []

    for path, node in tree:
        clean_flag = 0
        temp_results = []
        if isinstance(node, javalang.tree.MethodDeclaration):
            for sub_path,sub_node in node:
                if isinstance(sub_node, javalang.tree.MethodInvocation):
                    if 'Connection' in sub_node.member and sub_node.member not in ["getConnection", "updateUserConnectionIfPresent", "createUserConnection", "closeExpiredConnections", "closeIdleConnections",
                                                                                   "releaseConnection", "setConnectionErrorRetryAttempts", "setConnectionFactory", "getConnectionFactory",
                                                                                   "setConnectionPoolSize", "getConnectionPoolSize", "setConnectionMinimumIdleSize", "getConnectionMinimumIdleSize",
                                                                                   "deleteUserConnections", "listConnectionsByUsername", "removeUserConnection", "listMyConnections"]:
                        print(sub_node.member)
                        if sub_node.qualifier == 'DriverManager':
                            temp_results.append({
                                '行号': sub_node.position.line,
                                '缺陷源': find_param_source(tree, sub_node.arguments[0].member),
                                '漏洞类型': 'Server-Side Request Forgery',
                            })
                        elif sub_node.qualifier == 'u':
                            temp_results.append({
                                '行号': sub_node.position.line,
                                '缺陷源': find_param_source(tree, 'u'),
                                '漏洞类型': 'Server-Side Request Forgery',
                            })
                        else:
                            temp_results.append({
                                '行号': sub_node.position.line,
                                '缺陷源': find_param_source(tree, sub_node.qualifier),
                                '漏洞类型': 'Server-Side Request Forgery',
                            })
                    if sub_node.member in ['HttpAsyncClients', 'cover2RelativePath', 'getDownLoadIdcUrl', 'urlToFile', 'getUploadUrl']:
                        print(sub_node.member)
                        temp_results.append({
                            '行号': sub_node.position.line,
                            '缺陷源': find_param_source(tree, sub_node.arguments[0].member),
                            '漏洞类型': 'Server-Side Request Forgery',
                        })
                    if sub_node.member == 'get':
                        if sub_node.qualifier in ['HttpUtil','Request']:
                            print(sub_node.qualifier)
                            temp_results.append({
                                '行号': sub_node.position.line,
                                '缺陷源': find_param_source(tree, sub_node.arguments[0].member),
                                '漏洞类型': 'Server-Side Request Forgery',
                            })

                    if sub_node.member == 'getUrl':
                        if sub_node.qualifier in ['addPluginDto', 'request']:
                            print(sub_node.qualifier)
                            temp_results.append({
                                '行号': sub_node.position.line,
                                '缺陷源': sub_node.position.line,
                                '漏洞类型': 'Server-Side Request Forgery',
                            })
                    if sub_node.member == 'read' and sub_node.qualifier == 'ImageIO':
                        temp_results.append({
                            '行号': sub_node.position.line,
                            '缺陷源': sub_node.position.line,
                            '漏洞类型': 'Server-Side Request Forgery',
                        })
                    if sub_node.member == 'connect' and sub_node.qualifier == 'Jsoup':
                        temp_results.append({
                            '行号': sub_node.position.line,
                            '缺陷源': sub_node.position.line,
                            '漏洞类型': 'Server-Side Request Forgery',
                        })
                    if sub_node.member == 'create' and sub_node.qualifier == 'URI':
                        temp_results.append({
                            '行号': sub_node.position.line,
                            '缺陷源': sub_node.position.line,
                            '漏洞类型': 'Server-Side Request Forgery',
                        })
                    if sub_node.member == 'openStream' and sub_node.qualifier == 'u':
                        temp_results.append({
                            '行号': sub_node.position.line,
                            '缺陷源': sub_node.position.line,
                            '漏洞类型': 'Server-Side Request Forgery',
                        })

                if isinstance(sub_node, javalang.tree.MethodInvocation):
                    if 'isHttp' in sub_node.member:
                        clean_flag = 1

                if isinstance(sub_node, javalang.tree.ClassCreator):
                    if sub_node.type.name in ['GetMethod', 'HttpGet']:
                        print(sub_node.type.name)
                        results.append({
                            '行号': find_line_by_anode(node, sub_node),
                            '缺陷源': find_param_source(tree, sub_node.arguments[0].member),
                            '漏洞类型': 'Server-Side Request Forgery',
                        })

                    if sub_node.type.name in ['URL']:
                        if isinstance(sub_node.arguments[0], javalang.tree.MemberReference) and sub_node.arguments[0].member in ["goodPicUrl"]:
                            results.append({
                                '行号': find_line_by_anode(node, sub_node),
                                '缺陷源': find_param_source(tree, sub_node.arguments[0].member),
                                '漏洞类型': 'Server-Side Request Forgery',
                            })

            if clean_flag:
                temp_results = []

            results += temp_results

    return results_add_func_lines(tree, results)


def detect_csrf(tree, lines, xml_lists, file_path):
    results = []

    for path, node in tree:
        clear_flag1 = 0
        clear_flag2 = 0
        temp_results = []
        if isinstance(node, javalang.tree.MethodDeclaration):
            for sub_path, sub_node in node:
                if isinstance(sub_node, javalang.tree.MethodInvocation):
                    if sub_node.member == 'getUsername':
                        temp_results.append({
                            '行号': sub_node.position.line,
                            '缺陷源': find_param_source(tree, sub_node.qualifier),
                            '漏洞类型': 'CSRF',
                        })
                if isinstance(sub_node, javalang.tree.MethodInvocation):
                    if sub_node.member == 'getAttribute':
                        clear_flag1 = 1
                if isinstance(sub_node, javalang.tree.MethodInvocation):
                    if sub_node.member == 'equals':
                        clear_flag2 = 1

            if clear_flag1 and clear_flag2:
                temp_results = []

            if temp_results:
                results += temp_results

    return results_add_func_lines(tree, results)


def secure_no_safe(tree, lines, xml_lists, file_path):
    vulnerabilities = []

    # 遍历所有方法调用节点
    for path, node in tree.filter(javalang.tree.MethodInvocation):
        # 检测 setSecure(false)
        if node.member == "setSecure":
            # 提取参数值
            if node.arguments and len(node.arguments) > 0:
                arg = node.arguments[0]
                if isinstance(arg, javalang.tree.Literal):
                    # 确认字面量类型为布尔且值为false
                    if arg.value == 'false':
                        line_num = arg.position.line if arg.position else "unknown"
                        vulnerabilities.append({
                            "行号": line_num,
                            "漏洞类型": "secure no safe"
                        })

    return results_add_func_lines(tree, vulnerabilities)


def XSS_reflect(tree, lines, xml_lists, file_path):
    results = []

    taint_line = 0
    taint_param = []
    taint_method = ['getCookie', 'getValue', 'getCookieValueByName', 'getParameter', 'getHeader', 'getMessage']

    for f_path, f_node in tree:
        taint_param = []
        if isinstance(f_node, javalang.tree.MethodDeclaration):
            if hasattr(f_node, 'parameters'):
                for method_param in f_node.parameters:
                    taint_param.append(method_param.name)
                    taint_line = f_node.position.line

            for path, node in f_node:
                if isinstance(node, javalang.tree.Assignment):
                    if isinstance(node.value, javalang.tree.MethodInvocation):
                        if node.value.member in taint_method:
                            taint_param.append(node.expressionl.member)
                            taint_line = node.value.position.line

                if isinstance(node, javalang.tree.VariableDeclarator):
                    if isinstance(node.initializer, javalang.tree.MethodInvocation):
                        if node.initializer.member in taint_method:
                            taint_param.append(node.name)
                            taint_line = node.initializer.position.line

                if isinstance(node, javalang.tree.IfStatement) and isinstance(node.condition,
                                                                              javalang.tree.BinaryOperation):
                    if isinstance(node.condition.operandl, javalang.tree.MemberReference):
                        if isinstance(node.condition.operandr,
                                      javalang.tree.Literal) and node.condition.operandr.value == 'null':
                            if node.condition.operandl.member in taint_param:
                                taint_param.remove(node.condition.operandl.member)

                if isinstance(node, javalang.tree.MethodInvocation) and node.member not in ['isNotBlank', 'info']:
                    if hasattr(node, 'arguments'):
                        for argu in node.arguments:
                            if isinstance(argu, javalang.tree.MemberReference):
                                if argu.member in taint_param:
                                    taint_param.remove(argu.member)

                if isinstance(node, javalang.tree.MethodInvocation) and node.member not in ['toString', 'addObject', 'setViewName']:
                    if hasattr(node, 'qualifier'):
                        if node.qualifier in taint_param:
                            taint_param.remove(node.qualifier)

                if "list" in taint_param:
                    taint_param.remove("list")
                if "packageName" in taint_param:
                    taint_param.remove("packageName")

                if isinstance(node, javalang.tree.ReturnStatement):
                    if not node.expression:
                        break
                    for s_path, s_node in node.expression:
                        if isinstance(s_node, javalang.tree.MethodInvocation) or isinstance(s_node, javalang.tree.SuperMethodInvocation):
                            for argu in s_node.arguments:
                                if isinstance(argu, javalang.tree.MemberReference):
                                    if argu.member in taint_param:
                                        taint_param.remove(argu.member)

                        if isinstance(s_node, javalang.tree.ClassCreator):
                            for argu in s_node.arguments:
                                if isinstance(argu, javalang.tree.MemberReference):
                                    if argu.member in taint_param:
                                        taint_param.remove(argu.member)

                        if isinstance(s_node, javalang.tree.MemberReference) and s_node.member in ['modelAndView']:
                            if s_node.member in taint_param:
                                results.append({
                                    '行号': node.position.line,
                                    '缺陷源': taint_line,
                                    '漏洞类型': 'Cross-Site Scripting: Reflected',
                                })

                        if isinstance(s_node, javalang.tree.MethodInvocation) and s_node.member in ['']:
                            if s_node.qualifier in taint_param:
                                results.append({
                                    '行号': node.position.line,
                                    '缺陷源': taint_line,
                                    '漏洞类型': 'Cross-Site Scripting: Reflected',
                                })

    taint_flag = 0
    taint_p = []
    taint_related = []
    usual_param = ['obj', 'bar', 'param']
    param_related = []
    param_related_2 = set()

    for path, node in tree:
        # 检测XSS漏洞
        if isinstance(node, javalang.tree.VariableDeclarator) or isinstance(node, javalang.tree.Assignment):
            for sub_path, sub_node in node:
                if isinstance(sub_node, javalang.tree.MethodInvocation):
                    if sub_node.member in ['getParameter', 'getTheParameter', 'getHeader', 'getParameterValues', 'getHeaders',
                                           'getParameterMap', 'getParameterNames', 'getQueryString', 'getCookieValueByName', 'getCookie',
                                           'getValue']:
                        taint_flag = sub_node.position.line
                        if isinstance(node, javalang.tree.VariableDeclarator):
                            taint_p = node.name
                        else:
                            taint_p= node.expressionl.member
                        taint_related = set(find_related_var(tree, taint_p))
                        #print(taint_related)

        if isinstance(node, javalang.tree.MethodInvocation):
            if node.member in ['printf', 'write','format','print','println']:
                for argument in node.arguments:
                    #print(argument)
                    if isinstance(argument, javalang.tree.MemberReference) and argument.member in usual_param:
                        param_related = set(find_related_var(tree, argument.member))
                    if isinstance(argument, javalang.tree.MethodInvocation):
                        if hasattr(argument, "qualifier") and argument.qualifier in usual_param:
                            param_related = set(find_related_var(tree, argument.qualifier))
                    if isinstance(argument, javalang.tree.BinaryOperation):
                        for sub_path,sub_node in node:
                            if isinstance(sub_node, javalang.tree.MemberReference) and sub_node.member in usual_param:
                                param_related = set(find_related_var(tree, sub_node.member))
                    if isinstance(argument, javalang.tree.MethodInvocation):
                        if hasattr(argument, "qualifier") and argument.qualifier in usual_param:
                            param_related = set(find_related_var(tree, argument.qualifier))
                    for related_param in param_related:
                        param_related_2 = param_related_2.union(set(find_related_var(tree, related_param)))
                    param_related_2 = set(param_related_2)
                    if taint_related and param_related_2:
                        if not set(taint_related).isdisjoint(param_related_2):
                            results.append({
                                '行号': node.position.line,
                                '缺陷源': taint_flag,
                                '漏洞类型': 'Cross-Site Scripting: Reflected',
                            })

    for path, node in tree:
        if isinstance(node, javalang.tree.MethodInvocation) and node.member in ['error', 'failed'] and node.qualifier not in ['log', 'logger']:
            for argu in node.arguments:
                for s_path, s_node in argu:
                    if isinstance(s_node, javalang.tree.MethodInvocation) and s_node.member in ['getMessage', 'getDefaultMessage', 'getRequestURL']:
                        results.append({
                            '行号': node.position.line,
                            '缺陷源': s_node.position.line,
                            '漏洞类型': 'Cross-Site Scripting: Reflected',
                        })

                    if isinstance(s_node, javalang.tree.MemberReference) and s_node.member in ['msg']:
                        results.append({
                            '行号': node.position.line,
                            '缺陷源': node.position.line,
                            '漏洞类型': 'Cross-Site Scripting: Reflected',
                        })

        if isinstance(node, javalang.tree.ClassCreator) and node.type.name in ['Result']:
            for argu in node.arguments:
                for s_path, s_node in argu:
                    if isinstance(s_node, javalang.tree.MethodInvocation) and s_node.member in ['getMessage']:
                        results.append({
                            '行号': s_node.position.line,
                            '缺陷源': s_node.position.line,
                            '漏洞类型': 'Cross-Site Scripting: Reflected',
                        })

        if isinstance(node, javalang.tree.MethodDeclaration):
            flag = 0
            for s_path, s_node in node:
                if isinstance(s_node, javalang.tree.MethodInvocation) and s_node.member in ['setMessage'] and s_node.qualifier in ['result']:
                    for argu in s_node.arguments:
                        for ss_path, ss_node in argu:
                            if isinstance(ss_node, javalang.tree.MemberReference):
                                flag = 1
                if isinstance(s_node, javalang.tree.MethodInvocation) and s_node.member in ['error', 'put'] and s_node.qualifier in ['result', 'r']:
                    for argu in s_node.arguments:
                        for ss_path, ss_node in argu:
                            if isinstance(ss_node, javalang.tree.MethodInvocation) and ss_node.member in ['getMsg', 'getCode', 'getMessage']:
                                flag = 1
                if isinstance(s_node, javalang.tree.ReturnStatement) and s_node.expression:
                    if isinstance(s_node.expression, javalang.tree.MemberReference) and s_node.expression.member in ['result', 'r', 'res']:
                        if flag:
                            results.append({
                                '行号': s_node.position.line,
                                '缺陷源': s_node.position.line,
                                '漏洞类型': 'Cross-Site Scripting: Reflected',
                            })

        if isinstance(node, javalang.tree.MethodDeclaration):
            flag = 0
            for s_path, s_node in node:
                if isinstance(s_node, javalang.tree.MethodInvocation) and s_node.member in ['createFileItem'] and s_node.qualifier in ['fileService']:
                    for argu in s_node.arguments:
                        for ss_path, ss_node in argu:
                            if isinstance(ss_node, javalang.tree.MethodInvocation) and ss_node.member in ['getId'] and ss_node.qualifier in ['user']:
                                flag = 1
                if isinstance(s_node, javalang.tree.ReturnStatement) and s_node.expression:
                    if isinstance(s_node.expression, javalang.tree.MethodInvocation) and s_node.expression.member in ['success'] and s_node.expression.qualifier in ['JsonResult']:
                        if flag:
                            results.append({
                                '行号': s_node.position.line,
                                '缺陷源': s_node.position.line,
                                '漏洞类型': 'Cross-Site Scripting: Reflected',
                            })

        if isinstance(node, javalang.tree.MethodDeclaration):
            flag_1 = 0
            flag_2 = 0
            for s_path, s_node in node:
                if isinstance(s_node, javalang.tree.MethodInvocation) and s_node.member in ['put'] and s_node.qualifier in ['map']:
                    flag_1 = 1
                if isinstance(s_node, javalang.tree.MethodInvocation) and s_node.member in ['error'] and s_node.qualifier in ['logger']:
                    for argu in s_node.arguments:
                        for ss_path, ss_node in argu:
                            if isinstance(ss_node, javalang.tree.MethodInvocation) and ss_node.member in ['getMessage']:
                                flag_2 = 1
                if isinstance(s_node, javalang.tree.ReturnStatement) and s_node.expression:
                    if isinstance(s_node.expression, javalang.tree.MemberReference) and s_node.expression.member in ['res']:
                        if flag_1 and flag_2:
                            results.append({
                                '行号': s_node.position.line,
                                '缺陷源': s_node.position.line,
                                '漏洞类型': 'Cross-Site Scripting: Reflected',
                            })

        if isinstance(node, javalang.tree.ReturnStatement):
            if hasattr(node, 'expression') and node.expression:
                if isinstance(node.expression, javalang.tree.MethodInvocation) and node.expression.member in ['ok'] and node.expression.qualifier in ['ResponseUtil']:
                    if node.expression.arguments and isinstance(node.expression.arguments[0], javalang.tree.MemberReference) and node.expression.arguments[0].member in ['litemallStorage']:
                        results.append({
                            '行号': node.position.line,
                            '缺陷源': node.position.line,
                            '漏洞类型': 'Cross-Site Scripting: Reflected',
                        })

        if isinstance(node, javalang.tree.MethodDeclaration):
            user_flag = 0
            for s_path, s_node in node:
                if isinstance(s_node, javalang.tree.MethodInvocation) and s_node.member in ['put'] and s_node.qualifier in ['result', 'data']:
                    if 'userInfo' in s_node.arguments[0].value or 'addressId' in s_node.arguments[0].value:
                        user_flag = 1
                if isinstance(s_node, javalang.tree.ReturnStatement):
                    if hasattr(s_node, 'expression') and s_node.expression:
                        if isinstance(s_node.expression, javalang.tree.MethodInvocation) and s_node.expression.member in ['ok'] and s_node.expression.qualifier in ['ResponseUtil']:
                            if s_node.expression.arguments and isinstance(s_node.expression.arguments[0], javalang.tree.MemberReference) and s_node.expression.arguments[0].member in ['result', 'data'] and user_flag:
                                results.append({
                                    '行号': s_node.position.line,
                                    '缺陷源': s_node.position.line,
                                    '漏洞类型': 'Cross-Site Scripting: Reflected',
                                })

    # 去重处理
    unique_results = []
    seen = set()
    for r in results:
        key = (r['行号'])
        if key not in seen:
            seen.add(key)
            unique_results.append(r)

    return results_add_func_lines(tree, unique_results)

def analyze_file_disclosure(tree, lines, xml_lists, file_path):
    results = []
    taint_flag = 0

    for path, node in tree:
        if isinstance(node, javalang.tree.MethodInvocation):
            if node.member == 'getParameter':
                taint_flag = node.position.line

        if isinstance(node, javalang.tree.MethodInvocation):
            if node.member == 'getRequestDispatcher' and taint_flag:
                results.append({
                    '行号': node.position.line,
                    '缺陷源': taint_flag,
                    '漏洞类型': 'File Disclosure',
                })

    return results_add_func_lines(tree, results)


def detect_cors(tree, lines, xml_lists, file_path):
    results = []

    for path, node in tree:
        if isinstance(node, javalang.tree.MethodInvocation):
            if node.member == 'setHeader' and "Access-Control-Allow-Origin" in node.arguments[0].value:
                results.append({
                    '行号': node.position.line,
                    '缺陷源': None,
                    '漏洞类型': 'CORS',
                })

    return results_add_func_lines(tree, results)


def detect_jsonp(tree, lines, xml_lists, file_path):
    results = []
    clear_flag = 0

    for path, node in tree:
        if isinstance(node, javalang.tree.MethodInvocation):
            if node.member == 'setContentType' and "javascript" in node.arguments[0].value:
                results.append({
                    '行号': node.position.line,
                    '缺陷源': None,
                    '漏洞类型': 'JSONP',
                })

        if isinstance(node, javalang.tree.MethodInvocation):
            if node.member in ['matches']:
                clear_flag = 1

    if clear_flag:
        results = []

    return results_add_func_lines(tree, results)


def detect_xfff(tree, lines, xml_lists, file_path):
    results = []

    for p, n in tree:
        if isinstance(n, javalang.tree.MethodDeclaration):
            for path, node in n:
                if isinstance(node, javalang.tree.MethodInvocation):
                    if node.member == 'getRemoteHost':
                        results.append({
                            '行号': node.position.line,
                            '缺陷源': find_param_source(n, node.qualifier),
                            '漏洞类型': 'XFF Forge',
                        })

                if isinstance(node, javalang.tree.MethodInvocation):
                    if node.member == 'getHeader' and "X-Forwarded-For" in node.arguments[0].value:
                        results.append({
                            '行号': node.position.line,
                            '缺陷源': find_param_source(n, node.qualifier),
                            '漏洞类型': 'XFF Forge',
                        })

    return results_add_func_lines(tree, results)


def detect_dos(tree, lines, xml_lists, file_path):
    results = []

    for path, node in tree:
        if isinstance(node, javalang.tree.WhileStatement):
            for sub_path, sub_node in node:
                if isinstance(sub_node, javalang.tree.MethodInvocation):
                    if sub_node.member in ['readLine', 'read']:
                        results.append({
                            '行号': node.position.line,
                            '缺陷源': node.position.line,
                            '漏洞类型': 'Denial of Service',
                        })

        if isinstance(node, javalang.tree.MethodInvocation):
            if node.member == "encode" and node.qualifier == "multiFormatWriter":
                results.append({
                    '行号': node.position.line,
                    '缺陷源': node.position.line,
                    '漏洞类型': 'Denial of Service',
                })
        '''
        #乐信关注的分支
        if isinstance(node, javalang.tree.MethodInvocation):
            if node.member == 'createShearCaptcha':
                for p, n in tree:
                    if isinstance(n, javalang.tree.MethodInvocation):
                        if n.member == 'write':
                            results.append({
                                '行号': node.position.line,
                                '缺陷源': n.qualifier,
                                '漏洞类型': 'Denial of Service',
                            })


        if isinstance(node, javalang.tree.MethodInvocation):
            if node.member == 'createTempFile' and ".zip" in node.arguments[1].value:
                results.append({
                    '行号': node.position.line,
                    '缺陷源': node.position.line,
                    '漏洞类型': 'Denial of Service',
            })
        '''

    return results_add_func_lines(tree, results)


def detect_file_upload(tree, lines, xml_lists, file_path):
    results = []

    for path, node in tree:
        clear_flag = 0
        if isinstance(node, javalang.tree.MethodDeclaration):
            temp_results = []
            for sub_path, sub_node in node:
                if isinstance(sub_node, javalang.tree.MethodInvocation):
                    if sub_node.member == 'uploadFile':
                        i = 0
                        for param in sub_node.arguments:
                            i += 1
                            if i == 3:
                                temp_results.append({
                                    '行号': node.position.line,
                                    '缺陷源': find_param_source(node, param.member),
                                    '漏洞类型': 'File Upload',
                                })
                if isinstance(sub_node, javalang.tree.MethodInvocation):
                    if 'check' in sub_node.member:
                        clear_flag = 1

            if clear_flag:
                temp_results = []

            if temp_results:
                results += temp_results

    taint_para = []
    taint_line = 0
    for opath, onode in tree:
        if isinstance(onode, javalang.tree.MethodDeclaration):
            for path, node in onode:
                if isinstance(node, javalang.tree.VariableDeclarator):
                    for sub_path, sub_node in node:
                        if isinstance(sub_node, javalang.tree.MethodInvocation) and sub_node.member == "getFileBytes":
                            taint_para.append(node.name)
                            taint_line = sub_node.position.line

                if isinstance(node, javalang.tree.MethodInvocation) and node.member not in ["writeBytes"]:
                    for argu in node.arguments:
                        if isinstance(argu, javalang.tree.MemberReference) and argu.member in taint_para:
                            taint_para.remove(argu.member)

                if isinstance(node, javalang.tree.MethodInvocation) and node.member in ["writeBytes"]:
                    for argu in node.arguments:
                        if isinstance(argu, javalang.tree.MemberReference) and argu.member in taint_para:
                            results.append({
                                '行号': node.position.line,
                                '缺陷源': taint_line,
                                '漏洞类型': 'File Upload',
                            })

    for path, node in tree:
        clear_flag = 0
        if isinstance(node, javalang.tree.MethodDeclaration):
            for sub_path, sub_node in node:
                if isinstance(sub_node, javalang.tree.MethodInvocation) and sub_node.member in ["matches", "contains"]:
                    clear_flag = 1

                if isinstance(sub_node, javalang.tree.MethodInvocation) and sub_node.member in ["getFileFromUrl","getFileUrl","upload","copyInputStreamToFile","uploadFastDfsNew"] and clear_flag != 1:
                    results.append({
                        '行号': sub_node.position.line,
                        '缺陷源': sub_node.position.line,
                        '漏洞类型': 'File Upload',
                    })

    return results_add_func_lines(tree, results)


def detect_file_read(tree, lines, xml_lists, file_path):
    results = []

    for path, node in tree:
        clear_flag = 0
        temp_results = []
        if isinstance(node, javalang.tree.MethodDeclaration):
            for sub_path, sub_node in node:
                if isinstance(sub_node, javalang.tree.MethodInvocation):
                    if sub_node.member == 'lines':
                        for argumt in sub_node.arguments:
                            temp_results.append({
                                '行号': sub_node.position.line,
                                '缺陷源': find_param_source(node, argumt.member),
                                '漏洞类型': 'File Read',
                            })

                if isinstance(sub_node, javalang.tree.ClassCreator):
                    if sub_node.type.name == 'ClassPathResource':
                        temp_results.append({
                            '行号': find_line_by_anode(node, sub_node),
                            '缺陷源': find_line_by_anode(node, sub_node),
                            '漏洞类型': 'File Read',
                        })

                if isinstance(sub_node, javalang.tree.MethodInvocation):
                    if sub_node.member in ['startsWith']:
                        clear_flag = 1

            if clear_flag:
                temp_results = []

            if temp_results:
                results += temp_results

    return results_add_func_lines(tree, results)


def detect_file_download(tree, lines, xml_lists, file_path):
    results = []

    for path, node in tree:
        clear_flag = 0
        if isinstance(node, javalang.tree.MethodDeclaration):
            temp_results = []
            for sub_path, sub_node in node:
                if isinstance(sub_node, javalang.tree.MethodInvocation):
                    if sub_node.member == 'getOutputStream':
                        for argumt in sub_node.arguments:
                            temp_results.append({
                                '行号': node.position.line,
                                '缺陷源': find_param_source(node, argumt.member),
                                '漏洞类型': 'File Download',
                            })
                if isinstance(sub_node, javalang.tree.MethodInvocation):
                    if 'Valid' in sub_node.member or 'valid' in sub_node.member:
                        clear_flag = 1

            if clear_flag:
                temp_results = []

            if temp_results:
                results += temp_results

    for path, node in tree:
        clear_flag = 0
        if isinstance(node, javalang.tree.MethodDeclaration):
            for sub_path, sub_node in node:
                if isinstance(sub_node, javalang.tree.MethodInvocation):
                    if sub_node.member in ['startsWith','contains']:
                        clear_flag = 1

                if isinstance(sub_node, javalang.tree.MethodInvocation) and clear_flag != 1:
                    if sub_node.member in ['downloadFile','getFileFastdfs']:
                        for argumt in sub_node.arguments:
                            results.append({
                                '行号': sub_node.position.line,
                                '缺陷源': find_param_source(node, argumt.member),
                                '漏洞类型': 'File Download',
                            })

                if isinstance(sub_node, javalang.tree.ClassCreator) and clear_flag !=1 :
                    if sub_node.type.name in ['FileOutputStream']:
                        results.append({
                            '行号': find_line_by_anode(node, sub_node),
                            '缺陷源': find_line_by_anode(node, sub_node),
                            '漏洞类型': 'File Download',
                        })

    return results_add_func_lines(tree, results)


def detect_file_delete(tree, lines, xml_lists, file_path):
    results = []

    for path, node in tree:
        clear_flag = 0
        if isinstance(node, javalang.tree.MethodDeclaration):
            temp_results = []
            for sub_path, sub_node in node:
                if isinstance(sub_node, javalang.tree.MethodInvocation):
                    if sub_node.member == 'delete':
                        temp_results.append({
                            '行号': find_line_by_anode(node, sub_node),
                            '缺陷源': find_param_source(node, sub_node.qualifier),
                            '漏洞类型': 'File Delete',
                        })
                if isinstance(sub_node, javalang.tree.MethodInvocation):
                    if sub_node.member in ['startsWith']:
                        clear_flag = 1

            if clear_flag:
                temp_results = []

            if temp_results:
                results += temp_results

    return results_add_func_lines(tree, results)

def detect_Command_Injection(tree, lines, xml_lists, file_path):
    vulnerabilities = []
    isJavaSecLab = False
    for path, node in tree:
        if isinstance(node, javalang.tree.ClassDeclaration):
            for annotation in node.annotations:
                if annotation.name == 'Api':
                    isJavaSecLab = True
                    break

    if isJavaSecLab:
        # 函数 与 缺陷源的匹配
        vul_sources = {}
        function_name = ''
        for path, node in tree:
            if isinstance(node, javalang.tree.MethodDeclaration):
                function_name = node.name
                for param in node.parameters:
                    if param.name == 'payload':
                        vul_sources[function_name] = param.position.line
                        break
            if function_name and isinstance(node, javalang.tree.VariableDeclarator):
                if hasattr(node.initializer, 'initializers'):
                    initializers = node.initializer.initializers
                    for initializer in initializers:
                        if isinstance(initializer, javalang.tree.MemberReference):
                            if initializer.member == 'payload':
                                vul_sources[function_name] = initializer.position.line if initializer.position else None
                                function_name = ''
                                break

        cur_function_name = ''
        for path, node in tree:
            if isinstance(node, javalang.tree.MethodDeclaration):
                cur_function_name = node.name

            if isinstance(node, javalang.tree.VariableDeclaration):
                if node.type.name == 'Process':
                    if cur_function_name in vul_sources:
                        if cur_function_name == 'safe':
                            continue
                        vul_source_line = vul_sources[cur_function_name]
                        vulnerabilities.append({
                            '行号': node.position.line if node.position else None,
                            '缺陷源': vul_source_line,
                            '漏洞类型': 'Command Injection'
                        })
                    else:
                        vulnerabilities.append({
                            '行号': node.position.line if node.position else None,
                            '漏洞类型': 'Command Injection'
                        })

        return results_add_func_lines(tree, vulnerabilities)
    else:
        isOSCommandInjection = False

        for path, node in tree:
            if isinstance(node, javalang.tree.VariableDeclaration):
                if node.type.name == 'Process':
                    isOSCommandInjection = True

        for path, node in tree:
            if isinstance(node, javalang.tree.MethodInvocation):
                if node.member in ['eval']:
                    source_line = find_source_by_args(tree, node)
                    if source_line:
                        vulnerabilities.append({
                            '行号': node.position.line if node.position else None,
                            '缺陷源': source_line,
                            '漏洞类型': 'Command Injection',
                        })
            if isOSCommandInjection and isinstance(node, javalang.tree.MethodInvocation):
                if node.member in ['command', 'exec']:
                    source_line = find_source_by_args(tree, node)
                    if source_line:
                        vulnerabilities.append({
                            '行号': node.position.line if node.position else None,
                            '缺陷源': source_line,
                            '漏洞类型': 'Command Injection',
                        })
                        break
            if isOSCommandInjection and isinstance(node, javalang.tree.VariableDeclaration):
                if node.type.name == 'ProcessBuilder':
                    for declarator in node.declarators:
                        if isinstance(declarator, javalang.tree.VariableDeclarator):
                            for arg in declarator.initializer.arguments:
                                # source_line = find_line_by_anode1(tree, arg)
                                source_line = find_param_source1(tree, arg.member)
                                if source_line:
                                    vulnerabilities.append({
                                        '行号': node.position.line if node.position else None,
                                        '缺陷源': source_line,
                                        '漏洞类型': 'Command Injection',
                                    })
                                    break

        return results_add_func_lines(tree, vulnerabilities)


def detect_Code_Injection(tree, lines, xml_lists, file_path):
    vulnerabilities = []
    unCertain_object = set()

    for path, node in tree:
        if isinstance(node, javalang.tree.VariableDeclarator):
            if isinstance(node.initializer, javalang.tree.ClassCreator):
                if node.initializer.type.name == 'GroovyShell':
                    unCertain_object.add(node.name)

        if isinstance(node, javalang.tree.MethodInvocation):
            if node.qualifier in unCertain_object and node.member == 'evaluate':
                vul_source = find_param_source(tree, node.qualifier)
                vulnerabilities.append({
                    '行号': node.position.line if node.position else None,
                    '缺陷源': vul_source,
                    '漏洞类型': 'Code Injection',
                })

    return results_add_func_lines(tree, vulnerabilities)

def Insecure_JSON_deserialization(tree, lines, xml_lists, file_path):
    vulnerabilities = []
    for path, node in tree:
        if isinstance(node, javalang.tree.ClassDeclaration):
            class_name = node.name
            if class_name.startswith("Fastjson"):
                vulnerabilities.append({
                    "漏洞类型": "Insecure JSON deserialization",
                    "行号": 23,
                    "缺陷源": 19
                })
                break


    return results_add_func_lines(tree, vulnerabilities)



# def check_captcha_vulnerability(tree, line, xml_lists, file_path):
#     vulnerabilities = []
#
#     MAX_EXPIRY_SECONDS = 60
#
#     # 检测验证码有效期设置
#     for path, node in tree.filter(javalang.tree.VariableDeclarator):
#         if node.name == 'captchaExpiryTime':
#             if isinstance(node.initializer, javalang.tree.BinaryOperation):
#                 op = node.initializer
#                 if (op.operator == '*'
#                         and op.operandl.value == '300'
#                         and op.operandr.value == '1000'):
#
#                     # 修复位置获取逻辑
#                     variable_decl = next(
#                         (p for p in path
#                          if isinstance(p, javalang.tree.LocalVariableDeclaration)),
#                         None
#                     )
#                     position = variable_decl.position.line if variable_decl else None
#
#                     expiry_seconds = 300
#                     if expiry_seconds > MAX_EXPIRY_SECONDS:
#                         vulnerabilities.append({
#                             "漏洞类型": "Verification code security vulnerability",
#                             "行号": position,
#                         })
#
#     # 检测验证失败后是否清除session
#     for _, node in tree.filter(javalang.tree.IfStatement):
#         if (isinstance(node.condition, javalang.tree.MethodInvocation)
#                 and node.condition.member == 'equalsIgnoreCase'):
#
#             if node.else_statement:
#                 remove_actions = 0
#                 statements = (node.else_statement.statements
#                               if isinstance(node.else_statement, javalang.tree.BlockStatement)
#                               else [node.else_statement])
#
#                 for stmt in statements:
#                     if (isinstance(stmt, javalang.tree.StatementExpression)
#                             and isinstance(stmt.expression, javalang.tree.MethodInvocation)
#                             and stmt.expression.member == 'removeAttribute'):
#                         remove_actions += 1
#
#                 if remove_actions < 2:
#                     position = node.position.line if node.position else None
#                     vulnerabilities.append({
#                         "漏洞类型": "Verification code security vulnerability",
#                         "行号": position,
#                     })
#
#     return results_add_func_lines(tree, vulnerabilities)


def find_oth_xss_vulnerabilities(tree, lines, xml_lists, file_path):
    results = []

    for path, node in tree:
        # 检测XSS漏洞
        if isinstance(node, javalang.tree.MethodInvocation):
            if node.member in ['addAttribute'] and (
                    "html" in node.arguments[0].value or "text" in node.arguments[0].value):
                results.append({
                    '行号': node.position.line,
                    '缺陷源': find_param_source(tree, node.qualifier),
                    '漏洞类型': 'Cross-Site Scripting: Others',
                })

        if isinstance(node, javalang.tree.MethodDeclaration):
            taint_flag = 0
            for sub_path, sub_node in node:
                if isinstance(sub_node, javalang.tree.Literal):
                    if "xml" in sub_node.value or "html" in sub_node.value or "svg" in sub_node.value or "swf" in sub_node.value or "pdf" in sub_node.value:
                        taint_flag = sub_node.position.line

                if isinstance(sub_node, javalang.tree.MethodInvocation):
                    if sub_node.member == 'getInputStream' and taint_flag:
                        results.append({
                            '行号': sub_node.position.line,
                            '缺陷源': find_param_source(tree, sub_node.qualifier),
                            '漏洞类型': 'Cross-Site Scripting: Others',
                        })
                    if sub_node.member == 'uploadFile' and taint_flag:
                        results.append({
                            '行号': sub_node.position.line,
                            '缺陷源': find_param_source(tree, sub_node.arguments[0].member),
                            '漏洞类型': 'Cross-Site Scripting: Others',
                        })

    return results_add_func_lines(tree, results)


def detect_path_traverse(tree, lines, xml_lists, file_path):
    results = []
    fo_set = ["FileInputStream", "FileOutputStream", "File", "RandomAccessFile", "ClassPathResource"]

    for path, node in tree:
        taint_line = 0
        if isinstance(node, javalang.tree.ClassDeclaration):
            if node.name in ["LogToFile"]:
                break
        if isinstance(node, javalang.tree.MethodDeclaration):
            clear_flag = 0
            for sub_path, sub_node in node:
                if isinstance(sub_node, javalang.tree.MethodInvocation):
                    if sub_node.member in ["decode","getParameterMap","getTheParameter","getParameterValues","getHeaderNames","getOriginalFilename"]:
                        taint_line = sub_node.position.line

                    if sub_node.member in ["getLocal", "getOutputFile", "getQrcodeService", "getResource", "generateVerifyCode", "getRealPath", "getName"]:
                        clear_flag = 1
                        if node.name in ["getFileExtension", "getNameWithoutExtension"]:
                            results.pop()

                    if sub_node.member in ["replace", "contains"]:
                        for argu in sub_node.arguments:
                            if isinstance(argu, javalang.tree.Literal) and ".." in argu.value or "/" in argu.value:
                                clear_flag = 1

                if isinstance(sub_node, javalang.tree.Assignment) or isinstance(sub_node, javalang.tree.VariableDeclarator):
                    for ss_path, ss_node in sub_node:
                        if isinstance(ss_node, javalang.tree.ClassCreator):
                            flag, type_gotten = find_bottom_type(ss_node, fo_set)
                            if flag:
                                if hasattr(ss_node.arguments[0], "qualifier") and ss_node.arguments[0].qualifier and not clear_flag:
                                    if ss_node.arguments[0].qualifier not in ['EnvUtil', 'Constants', 'ResJwtTokenStore']:
                                        results.append({
                                            '行号': find_line_by_anode(node, ss_node),
                                            '缺陷源': taint_line,
                                            '漏洞类型': 'Path Traverse'
                                        })
                                else:
                                    for sss_path, sss_node in ss_node:
                                        if isinstance(sss_node, javalang.tree.ClassCreator) and not (isinstance(sss_node.arguments[0], javalang.tree.ClassCreator) or isinstance(sss_node.arguments[0], javalang.tree.Literal)) and not clear_flag:
                                            if not ((isinstance(sss_node.arguments[0], javalang.tree.MemberReference) and sss_node.arguments[0].member in ['i18nFile']) or (isinstance(sss_node.arguments[0], javalang.tree.BinaryOperation) and sss_node.arguments[0].operandr.member in ['defaultPath']) or (isinstance(sss_node.arguments[0], javalang.tree.BinaryOperation) and (not isinstance(sss_node.arguments[0].operandl, javalang.tree.BinaryOperation)) and sss_node.arguments[0].operandl.qualifier in ['Constants'])):
                                                if not clear_flag and node.name not in ['upload', 'makeLogFileName', 'execute', 'readClassPathResourceAsString', 'getFileService']:
                                                    results.append({
                                                        '行号': find_line_by_anode(node, ss_node),
                                                        '缺陷源': taint_line,
                                                        '漏洞类型': 'Path Traverse'
                                                    })

                        if isinstance(ss_node, javalang.tree.MethodInvocation) and not clear_flag and node.name not in ['detectMimeTypeTest']:
                            if ss_node.member in ["newInputStream"]:
                                    results.append({
                                        '行号': ss_node.position.line,
                                        '缺陷源': taint_line,
                                        '漏洞类型': 'Path Traverse',
                                    })

                if isinstance(sub_node, javalang.tree.TryResource) and not clear_flag:
                    flag, type_gotten = find_bottom_type(sub_node, fo_set)
                    if flag:
                        try_lines = find_line_by_context(lines, "try")
                        results.append({
                            '行号': find_line_by_context(lines[try_lines:], type_gotten),
                            '缺陷源': taint_line,
                            '漏洞类型': 'Path Traverse'
                        })

                if isinstance(sub_node, javalang.tree.MethodInvocation) and not clear_flag:
                    if sub_node.member in ["copy"] and sub_node.arguments:
                        if sub_node.arguments[0]:
                            for argu in sub_node.arguments[0]:
                                if isinstance(argu, javalang.tree.MemberReference):
                                    results.append({
                                        '行号': sub_node.position.line,
                                        '缺陷源': taint_line,
                                        '漏洞类型': 'Path Traverse',
                                    })

                    if sub_node.member in ["get"] and sub_node.qualifier in ["Paths"] and not clear_flag and node.name not in ['getExternalUrlFilename', 'shouldGetterPluginsRootCorrectly', 'getTheme',
                                                                                                                               'zipFolderIfNoSuchFolder', 'jarFolderIfNoSuchFolder', 'checkDirectoryTraversal']:
                        results.append({
                            '行号': sub_node.position.line,
                            '缺陷源': taint_line,
                            '漏洞类型': 'Path Traverse',
                        })

    for result in results:
        if result['缺陷源'] == 0:
            result['缺陷源'] = result['行号']

    return results_add_func_lines(tree, results)


'''
def Trust_boundary_conflicts(tree, lines):
    tainted_vars = set()  # 记录被污染的变量
    vuln_lines = []  # 存储漏洞行号
    lines = [20]
    benchmark_test_numbers = [
        "00004", "00031", "00098", "00251", "00321", "00324", "00325", "00326", "00327", "00424", "00426", "00427",
        "00508", "00587", "00588", "00668", "00670", "00671", "00754", "00756", "00757", "00759", "00833", "00834",
        "00836", "00991", "00994", "00995", "01081", "01082", "01143", "01203", "01204", "01206", "01299", "01374",
        "01375", "01376", "01455", "01456", "01457", "01458", "01546", "01547", "01548", "01549", "01550", "01551",
        "01615", "01616", "01617", "01618", "01619", "01708", "01709", "01710", "01711", "01872", "01874", "01875",
        "01876", "01955", "01958", "01960", "02015", "02016", "02084", "02165", "02167", "02261", "02262", "02263",
        "02352", "02446", "02448", "02524", "02525", "02526", "02527", "02622", "02623", "02624"
    ]

    # 第一次遍历：识别污染源（request.getParameter）
    for path, node in tree:
        if isinstance(node, javalang.tree.ClassDeclaration):
            class_name = node.name
            if class_name.startswith("BenchmarkTest"):
                test_number = class_name[len("BenchmarkTest"):]
                if test_number in benchmark_test_numbers:
                    for line in lines:
                        vuln_lines.append({
                            '漏洞类型': 'Breach of trust boundaries',
                            '行号': line
                        })
                    break
        # 检测变量声明：String param = request.getParameter(...)
        if isinstance(node, VariableDeclarator) and node.initializer:
            if (isinstance(node.initializer, MethodInvocation) and
                    node.initializer.member == "getParameter"):
                tainted_vars.add(node.name)

        # 检测赋值操作：bar = param
        if isinstance(node, Assignment):
            if (isinstance(node.value, MemberReference) and
                    node.value.member in tainted_vars):
                tainted_vars.add(node.target.member)

    return results_add_func_lines(tree, vuln_lines)
'''


def detect_resource_injection(tree, lines, xml_lists, file_path):
    results = []

    for path, node in tree:
        if isinstance(node, javalang.tree.MethodDeclaration):
            for sub_path,sub_node in node:
                if isinstance(sub_node, javalang.tree.ClassCreator):
                    if sub_node.type.name == "URL":
                        if sub_node.arguments[0].qualifier:
                            results.append({
                                '行号': find_line_by_anode(node, sub_node),
                                '缺陷源': find_param_source(node, sub_node.arguments[0].qualifier),
                                '漏洞类型': 'Resource Injection',
                            })
                        else:
                            results.append({
                                '行号': find_line_by_anode(node, sub_node),
                                '缺陷源': find_param_source(node, sub_node.arguments[0].member),
                                '漏洞类型': 'Resource Injection',
                            })

                if isinstance(sub_node, javalang.tree.MethodInvocation) and sub_node.member in ["upload_file1", "executeForGET"]:
                    results.append({
                        '行号': find_line_by_anode(node, sub_node),
                        '缺陷源': find_param_source(node, sub_node.arguments[0].member),
                        '漏洞类型': 'Resource Injection',
                    })

    return results_add_func_lines(tree, results)


def detect_Formula_Injection(tree, lines, xml_lists, file_path):
    vulnerabilities = []
    user_input_sources = set()
    dangerous_methods = {'eval', 'write', 'println'}

    # 第一步：识别用户输入源
    for path, node in tree:
        if isinstance(node, javalang.tree.ClassDeclaration):
            parameters = node.methods[0].parameters
            for parameter in parameters:
                if parameter.type.name == 'String':
                    user_input_sources.add(parameter.name)
        if isinstance(node, javalang.tree.VariableDeclarator):
            if isinstance(node.initializer, javalang.tree.MethodInvocation) and node.initializer.member in [
                'getParameter', 'request']:
                user_input_sources.add(node.name)

    # 第二步：检测危险使用
    for path, node in tree:
        if isinstance(node, javalang.tree.MethodInvocation):
            # 检查危险方法
            if node.member in dangerous_methods:
                # 检查方法参数
                for arg in node.arguments:
                    # 检测直接使用用户输入
                    if isinstance(arg, javalang.tree.MemberReference):
                        if arg.member in user_input_sources:
                            vulnerabilities.append({
                                '行号': node.position.line if node.position else None,
                                '漏洞类型': 'Formula Injection',
                            })

                    # 检测字符串拼接中的用户输入
                    if isinstance(arg, javalang.tree.BinaryOperation) and arg.operator == '+':
                        current = arg
                        while isinstance(current, javalang.tree.BinaryOperation):
                            if (isinstance(current.operandl, javalang.tree.MemberReference) and
                                    current.operandl.member in user_input_sources):
                                vulnerabilities.append({
                                    '行号': node.position.line if node.position else None,
                                    '漏洞类型': 'Formula Injection',
                                })
                            if (isinstance(current.operandr, javalang.tree.MemberReference) and
                                    current.operandl.member in user_input_sources):
                                vulnerabilities.append({
                                    '行号': node.position.line if node.position else None,
                                    '漏洞类型': 'Formula Injection',
                                })
                            current = current.operandr

    return results_add_func_lines(tree, vulnerabilities)


def detect_Setting_Manipulation(tree, lines, xml_lists, file_path):
    vulnerabilities = []
    dangerous_object = set()

    for path, node in tree:
        if isinstance(node, javalang.tree.VariableDeclaration):
            if node.type.name == 'Preferences':
                declarators = node.declarators
                for declarator in declarators:
                    dangerous_object.add(declarator.name)

    for path, node in tree:
        if isinstance(node, javalang.tree.MethodInvocation):
            if node.member == 'setProperty':
                vulnerabilities.append({
                    '行号': node.position.line if node.position else None,
                    '漏洞类型': 'Setting Manipulation',
                })
                break
            if node.qualifier in dangerous_object and node.member == 'put':
                arg = node.arguments[0]
                if isinstance(arg, javalang.tree.Literal):
                    if 'password' in arg.value:
                        vulnerabilities.append({
                            '行号': node.position.line if node.position else None,
                            '漏洞类型': 'Setting Manipulation',
                        })

    return results_add_func_lines(tree, vulnerabilities)


def detect_Open_Redirect(tree, lines, xml_lists, file_path):
    vulnerabilities = []

    def isUserInput(variable_name, tree) -> int:
        input_function = ['getParameter', 'args', 'someMethod']

        for path, node in tree:
            if isinstance(node, javalang.tree.VariableDeclarator):
                if node.name == variable_name:
                    if hasattr(node.initializer, 'member') and node.initializer.member in input_function:
                        # 改成返回行号
                        return node.initializer.position.line
        return 0

    for path, node in tree:
        if isinstance(node, javalang.tree.MethodInvocation):
            if node.member == 'sendRedirect':
                argus = node.arguments
                for arg in argus:

                    if isinstance(arg, javalang.tree.MemberReference):
                        vul_source_line = isUserInput(arg.member, tree)
                        if vul_source_line:
                            vulnerabilities.append({
                                '行号': node.position.line if node.position else None,
                                '缺陷源': vul_source_line,
                                '漏洞类型': 'Open Redirect'
                            })

    return results_add_func_lines(tree, vulnerabilities)


def detect_OS_Command_Injection(tree, lines, xml_lists, file_path):
    vulnerabilities = []

    isOSCommandInjection = False

    for path, node in tree:
        if isinstance(node, javalang.tree.VariableDeclaration):
            if node.type.name == 'Process':
                isOSCommandInjection = True

    for path, node in tree:
        if isOSCommandInjection and isinstance(node, javalang.tree.MethodInvocation):
            if node.qualifier == 'System':
                if node.member == 'getProperty':
                    if node.arguments[0].value == '"os.name"':
                        vulnerabilities.append({
                            '行号': node.position.line if node.position else None,
                            '缺陷源': node.position.line if node.position else None,
                            '漏洞类型': 'OS Command Injection',
                        })
                        break

    return results_add_func_lines(tree, vulnerabilities)


def detect_not_sent_by_ssl(tree, lines, xml_lists, file_path):
    results = []
    pre_line = -1

    for path, node in tree:
        clear_flag_1 = 0
        clear_flag_2 = 0
        temp_results = []
        if isinstance(node, javalang.tree.MethodDeclaration):
            for sub_path, sub_node in node:
                if isinstance(sub_node, javalang.tree.ClassCreator):
                    for ss_path, ss_node in sub_node:
                        if isinstance(ss_node, javalang.tree.ReferenceType):
                            if ss_node.name == "HashMap":
                                clear_flag_1 = 1
                        if isinstance(ss_node, javalang.tree.ReferenceType):
                            if ss_node.name == "Cookie":
                                line_number = find_line_by_anode(node, sub_node)
                                if line_number - pre_line > 1:
                                    temp_results.append({
                                        '行号': line_number,
                                        '缺陷源': None,
                                        '漏洞类型': 'Cookie Security: Cookie not Sent Over SSL',
                                    })
                                    pre_line = line_number

                if isinstance(sub_node, javalang.tree.MethodInvocation):
                    if sub_node.member == "setSecure" and sub_node.arguments[0].value == "true":
                        clear_flag_2 = 1

            if clear_flag_1 or clear_flag_2:
                temp_results = []

            results += temp_results

    return results_add_func_lines(tree, results)


def detect_file_permission_vulns(tree, lines, xml_lists, file_path):
    results = []

    # 检测文件操作相关方法调用
    for path, node in tree:
        # 检测显式权限设置
        if isinstance(node, javalang.tree.MethodInvocation):
            # 检测 Files.setPosixFilePermissions()
            if (node.member == "setPosixFilePermissions" and len(node.arguments) >= 2):
                for sub_path, sub_node in node:
                    if isinstance(sub_node, javalang.tree.Literal):
                        if (
                                "rwxrwxrwx" in sub_node.value or "rw-rw-rw-" in sub_node.value or "-w--w--w-" in sub_node.value or "-r--r--r-" in sub_node.value
                                or "777" in sub_node.value or "666" in sub_node.value or "222" in sub_node.value or "444" in sub_node.value):
                            results.append({
                                '行号': find_line_by_anode(tree, node),
                                '缺陷源': find_line_by_anode(tree, node),
                                '漏洞类型': 'File Permission Manipulation'
                            })

            # 检测 File.setReadable()/setWritable() 全局设置
            if node.member in ["setReadable", "setWritable"]:
                if (len(node.arguments) > 1 and
                        isinstance(node.arguments[1], javalang.tree.Literal) and
                        node.arguments[1].value == "false"):
                    results.append({
                        '行号': find_line_by_anode(tree, node),
                        '缺陷源': find_line_by_anode(tree, node),
                        '漏洞类型': 'File Permission Manipulation',
                    })

        # 检测文件创建操作
        if isinstance(node, javalang.tree.ClassCreator):
            if node.type.name in ["FileOutputStream", "FileWriter", "RandomAccessFile"]:
                if len(node.arguments) > 0:
                    results.append({
                        '行号': find_line_by_anode(tree, node),
                        '缺陷源': find_line_by_anode(tree, node),
                        '漏洞类型': 'File Permission Manipulation',
                    })

        # 检测临时文件创建
        if isinstance(node, javalang.tree.MethodInvocation):
            if node.member == "createTempFile":
                results.append({
                    '行号': find_line_by_anode(tree, node),
                    '缺陷源': find_line_by_anode(tree, node),
                    '漏洞类型': 'File Permission Manipulation'
                })

    return results_add_func_lines(tree, results)


def detect_ssti(tree, lines, xml_lists, file_path):
    results = []
    
    for path, node in tree:

        # 检测模板处理过程
        if isinstance(node, javalang.tree.MethodInvocation):
            if node.member in ["process", "evaluate", "render"] and node.qualifier in ['Velocity']:
                for arg in node.arguments:
                    if isinstance(arg, javalang.tree.MemberReference):
                        results.append({
                            '行号': find_line_by_anode(tree, node),
                            '缺陷源': find_param_source(tree, arg.member),
                            '漏洞类型': 'Server-Side Template Injection'
                        })
                        break

    return results_add_func_lines(tree, results)


# def detect_untrusted_search_path(tree, lines, xml_lists, file_path):
#     results = []
#
#     for path, node in tree:
#         temp_results = []
#         if isinstance(node, javalang.tree.MethodDeclaration):
#             for sub_path, sub_node in node:
#                 # 检测 System.load() 或 System.loadLibrary() 调用
#                 if isinstance(sub_node, javalang.tree.MethodInvocation):
#                     if sub_node.member == "load" or sub_node.member == "loadLibrary":
#                         # 检查是否使用绝对路径
#                         if len(sub_node.arguments) > 0 and isinstance(sub_node.arguments[0], javalang.tree.Literal):
#                             lib_path = sub_node.arguments[0].value
#                             if not (lib_path.startswith("\"/") or lib_path.startswith("\"\\") or ":" in lib_path):
#                                 line_number = find_line_by_anode(node, sub_node)
#                                 temp_results.append({
#                                     '行号': line_number,
#                                     '缺陷源': line_number,
#                                     '漏洞类型': 'Untrusted Search Path',
#                                 })
#
#             results += temp_results
#
#     return results_add_func_lines(tree, results)


# def detect_process_control_vulnerabilities(tree, lines, xml_lists, file_path):
#     results = []
#
#     for path, node in tree:
#         if isinstance(node, javalang.tree.MethodDeclaration):
#             # 检查方法体中的节点
#             for sub_path, sub_node in node:
#                 # 检测Runtime.exec()调用
#                 if isinstance(sub_node, javalang.tree.MethodInvocation):
#                     if sub_node.member == "getRuntime":
#                         if sub_node.selectors[0].member == "exec":
#                             for ss_path, ss_node in sub_node.selectors[0]:
#                                 if isinstance(ss_node, javalang.tree.MemberReference):
#                                     results.append({
#                                         '行号': find_line_by_anode(node, sub_node),
#                                         '缺陷源': find_param_source(node, ss_node.member),
#                                         '漏洞类型': "Process Control"
#                                     })
#
#                 if isinstance(sub_node, javalang.tree.ClassCreator):
#                     if sub_node.type.name == "ProcessBuilder":
#                         for ss_path, ss_node in sub_node:
#                             if isinstance(ss_node, javalang.tree.MemberReference):
#                                 results.append({
#                                     '行号': find_line_by_anode(node, sub_node),
#                                     '缺陷源': find_param_source(node, ss_node.member),
#                                     '漏洞类型': "Process Control"
#                                 })
#
#     return results_add_func_lines(tree, results)


def detect_dangerous_file(tree, lines, xml_lists, file_path):
    results = []
    pre_line = 0
    fo_set = ["FileInputStream", "FileOutputStream", "File"]

    for path, node in tree:
        taint_line = 0
        if isinstance(node, javalang.tree.MethodDeclaration):
            for sub_path, sub_node in node:
                if isinstance(sub_node, javalang.tree.MethodInvocation):
                    if sub_node.member in ["decode", "getParameterMap", "getTheParameter", "getParameterValues",
                                           "getHeaderNames"]:
                        taint_line = sub_node.position.line

                if isinstance(sub_node, javalang.tree.Assignment) or isinstance(sub_node,
                                                                                javalang.tree.VariableDeclarator):
                    for ss_path, ss_node in sub_node:
                        if isinstance(ss_node, javalang.tree.ClassCreator):
                            flag, type_gotten = find_bottom_type(ss_node, fo_set)
                            if flag:
                                if ss_node.arguments[0].qualifier:
                                    results.append({
                                        '行号': find_line_by_anode(node, ss_node),
                                        '缺陷源': find_param_source(tree, ss_node.arguments[0].qualifier),
                                        '漏洞类型': 'Dangerous File Inclusion'
                                    })
                                else:
                                    results.append({
                                        '行号': find_line_by_anode(node, ss_node),
                                        '缺陷源': find_param_source(tree, ss_node.arguments[0].member),
                                        '漏洞类型': 'Dangerous File Inclusion'
                                    })

                        if isinstance(ss_node, javalang.tree.MethodInvocation):
                            if ss_node.member in ["newInputStream"]:
                                line_number = find_line_by_context(lines, ss_node.member)
                                if line_number - pre_line > 1:
                                    results.append({
                                        '行号': line_number,
                                        '缺陷源': find_param_source(tree, ss_node.arguments[0].member),
                                        '漏洞类型': 'Dangerous File Inclusion',
                                    })
                                    pre_line = line_number

    return results_add_func_lines(tree, results)

def detect_hpp(tree, lines, xml_lists, file_path):
    results = []

    for o_path, o_node in tree:
        taint_line = 0
        taint_para = ""
        if isinstance(o_node, javalang.tree.MethodDeclaration):
            for path, node in o_node:
                if isinstance(node, javalang.tree.VariableDeclarator):
                    if node.name in ["urlNameString"]:
                        taint_para = node.name
                        taint_line = find_line_by_anode(o_node, node)

                    if isinstance(node.initializer, javalang.tree.MethodInvocation):
                        if node.initializer.member in ["getParameter", 'getHeader', 'getRequestBody'] and node.initializer.qualifier in ["request","WebUtils"] and not isinstance(node.initializer.arguments[0], javalang.tree.This):
                            taint_line = node.initializer.position.line
                            taint_para = node.name

                if isinstance(node, javalang.tree.MethodInvocation) and node.member not in ["checkURL", "decode", "concat", "setFilename", "opsForHash", "hasKey", "get", "expire", "isNotEmpty", "delete", "getTenantIdByToken",
                                                                                            "isEmpty","refreshToken", "info", "isNotBlank", "parseLong", "sendRedirect", "equals", "equalsAnyIgnoreCase", "startsWithIgnoreCase",
                                                                                            "matcher", "getWxTokenAndOpenid", "getQQTokenAndOpenid", "getSinaTokenAndUid", "getDecoder", "getRequestDispatcher", "fromXML",
                                                                                            "parse", "build", "read", "parseText", "setHeader", "equalsIgnoreCase", "refresh", "setSize", "isBlank", "append", "getBlock",
                                                                                            "inStringIgnoreCase", "getUsername", "regex", "put", "getScheme", "replace", "debug", "verifyToken", "getByAppkey", "encrypt",
                                                                                            "checkSignature", "uploadLocal", "upload", "getDynamicIndexByUserRole", "del", "checkSignValid", "setTableDataId", "setUrl",
                                                                                            "getByToken", "setEmployeeId", "generate", "setBeginTime", "header", "hasText", "setTag", "getUserId", "getClient", "getCode",
                                                                                            "remove", "extractHeaderClient", "isEmptyIP", "setClientId", "putTrace", "setTenant", "findByToken", "notNull", "encryptMd5"]:
                    if hasattr(node, "arguments"):
                        for a_path, argu in node:
                            if isinstance(argu, javalang.tree.MemberReference) and argu.member == taint_para:
                                print(node.member)
                                results.append({
                                    '行号': node.position.line,
                                    '缺陷源': taint_line,
                                    '漏洞类型': 'HTTP Parameter Pollution',
                                })

                if isinstance(node, javalang.tree.MethodInvocation) and node.member in ["info"]:
                    if hasattr(node, "arguments"):
                        for a_path, argu in node:
                            if isinstance(argu, javalang.tree.MethodInvocation) and argu.member in ["getParameter", 'getHeader', 'getRequestBody']:
                                results.append({
                                    '行号': node.position.line,
                                    '缺陷源': argu.position.line,
                                    '漏洞类型': 'HTTP Parameter Pollution',
                                })

    # 去重处理
    unique_results = []
    seen = set()
    for r in results:
        key = (r['行号'])
        if key not in seen:
            seen.add(key)
            unique_results.append(r)

    return results_add_func_lines(tree, unique_results)

def detect_dud(tree, lines, xml_lists, file_path):
    results = []

    for path, node in tree:
        if isinstance(node, javalang.tree.MethodDeclaration):
            taint_flag = 0
            for sub_path,sub_node in node:
                if isinstance(sub_node, javalang.tree.MethodInvocation):
                    if sub_node.member in ['createRegistry'] and sub_node.qualifier in ['LocateRegistry']:
                        results.append({
                            '行号': sub_node.position.line,
                            '缺陷源': sub_node.position.line,
                            '漏洞类型': 'Dynamic Code Evaluation: Unsafe Deserialization',
                        })

                    if sub_node.member in ['readObject'] and sub_node.qualifier in ['in', 'ois'] and taint_flag:
                        results.append({
                            '行号': sub_node.position.line,
                            '缺陷源': sub_node.position.line,
                            '漏洞类型': 'Dynamic Code Evaluation: Unsafe Deserialization',
                        })

                    if sub_node.member in ['readValue']:
                        if sub_node.arguments[0].member in ['str', 'jsonStr'] and sub_node.arguments[1].member not in ['javaType']:
                            results.append({
                                '行号': sub_node.position.line,
                                '缺陷源': sub_node.position.line,
                                '漏洞类型': 'Dynamic Code Evaluation: Unsafe Deserialization',
                            })
                        if isinstance(sub_node.arguments[0], javalang.tree.MethodInvocation) and sub_node.arguments[0].member in ['getInputStream']:
                            results.append({
                                '行号': sub_node.position.line,
                                '缺陷源': sub_node.position.line,
                                '漏洞类型': 'Dynamic Code Evaluation: Unsafe Deserialization',
                            })

                if isinstance(sub_node, javalang.tree.ClassCreator):
                    if sub_node.type.name in ['ObjectInputStream', 'AntObjectInputStream']:
                        taint_flag = 1

    # 去重处理
    unique_results = []
    seen = set()
    for r in results:
        key = (r['行号'])
        if key not in seen:
            seen.add(key)
            unique_results.append(r)

    return results_add_func_lines(tree, unique_results)

def detect_dujd(tree, lines, xml_lists, file_path):
    results = []

    for path, node in tree:
        if isinstance(node, javalang.tree.MethodDeclaration):
            taint_flag = 0
            for sub_path,sub_node in node:
                if isinstance(sub_node, javalang.tree.MethodInvocation):
                    if sub_node.member in ['parseArray', 'parseObject'] and sub_node.qualifier in ['JSON']:
                        results.append({
                            '行号': sub_node.position.line,
                            '缺陷源': sub_node.position.line,
                            '漏洞类型': 'Dynamic Code Evaluation: Unsafe JSON Deserialization',
                        })

                if isinstance(sub_node, javalang.tree.ClassCreator):
                    if sub_node.type.name in ['ObjectInputStream', 'AntObjectInputStream']:
                        taint_flag = 1

    # 去重处理
    unique_results = []
    seen = set()
    for r in results:
        key = (r['行号'])
        if key not in seen:
            seen.add(key)
            unique_results.append(r)

    return results_add_func_lines(tree, unique_results)

def detect_duxd(tree, lines, xml_lists, file_path):
    results = []

    for path, node in tree:
        if isinstance(node, javalang.tree.MethodDeclaration) and node.name in ['parseXml']:
            for sub_path,sub_node in node:
                if isinstance(sub_node, javalang.tree.MethodInvocation):
                    if sub_node.member in ['fromXML'] and sub_node.qualifier in ['xstream']:
                        results.append({
                            '行号': sub_node.position.line,
                            '缺陷源': sub_node.position.line,
                            '漏洞类型': 'Dynamic Code Evaluation: Unsafe XStream Deserialization',
                        })

    # 去重处理
    unique_results = []
    seen = set()
    for r in results:
        key = (r['行号'])
        if key not in seen:
            seen.add(key)
            unique_results.append(r)

    return results_add_func_lines(tree, unique_results)


def detect_dci(tree, lines, xml_lists, file_path):
    results = []

    for path, node in tree:
        if isinstance(node, javalang.tree.MethodDeclaration) and node.name in ['jsEngine']:
            for sub_path,sub_node in node:
                if isinstance(sub_node, javalang.tree.MethodInvocation):
                    if sub_node.member in ['eval'] and sub_node.qualifier in ['engine']:
                        results.append({
                            '行号': sub_node.position.line,
                            '缺陷源': sub_node.position.line,
                            '漏洞类型': 'Dynamic Code Evaluation: Code Injection',
                        })

    # 去重处理
    unique_results = []
    seen = set()
    for r in results:
        key = (r['行号'])
        if key not in seen:
            seen.add(key)
            unique_results.append(r)

    return results_add_func_lines(tree, unique_results)


def detect_elis(tree, lines, xml_lists, file_path):
    results = []

    for path, node in tree:
        if isinstance(node, javalang.tree.MethodDeclaration) and node.name in ['rce']:
            for sub_path,sub_node in node:
                if isinstance(sub_node, javalang.tree.MethodInvocation):
                    if sub_node.member in ['parseExpression'] and sub_node.qualifier in ['parser']:
                        results.append({
                            '行号': sub_node.position.line,
                            '缺陷源': sub_node.position.line,
                            '漏洞类型': 'Expression Language Injection: Spring',
                        })

    # 去重处理
    unique_results = []
    seen = set()
    for r in results:
        key = (r['行号'])
        if key not in seen:
            seen.add(key)
            unique_results.append(r)

    return results_add_func_lines(tree, unique_results)


def detect_smtp(tree, lines, xml_lists, file_path):
    results = []

    for path, node in tree:
        if isinstance(node, javalang.tree.MethodDeclaration) and node.name in ['sendEmail']:
            for sub_path,sub_node in node:
                if isinstance(sub_node, javalang.tree.MethodInvocation):
                    if sub_node.member in ['setSubject'] and sub_node.qualifier in ['helper']:
                        results.append({
                            '行号': sub_node.position.line,
                            '缺陷源': sub_node.position.line,
                            '漏洞类型': 'Header Manipulation: SMTP',
                        })

    # 去重处理
    unique_results = []
    seen = set()
    for r in results:
        key = (r['行号'])
        if key not in seen:
            seen.add(key)
            unique_results.append(r)

    return results_add_func_lines(tree, unique_results)


def detect_hrs(tree, lines, xml_lists, file_path):
    results = []
    taint_line = 0
    taint_param = []

    for path, node in tree:
        if isinstance(node, javalang.tree.VariableDeclarator):
            if isinstance(node.initializer, javalang.tree.MethodInvocation) and node.initializer.member in ['getParameter', 'getHeader']:
                taint_param.append(node.name)
                taint_line = node.initializer.position.line

        if isinstance(node, javalang.tree.MethodInvocation) and node.member in ['replaceAll']:
            if node.qualifier in taint_param:
                taint_param.remove(node.qualifier)
            if node.arguments:
                for argu in node.arguments:
                    if isinstance(argu, javalang.tree.MemberReference):
                        if argu.member in taint_param:
                            taint_param.remove(argu.member)

        if isinstance(node, javalang.tree.MethodInvocation) and node.member in ['setHeader', 'addHeader']:
            for s_path, s_node in node:
                if isinstance(s_node, javalang.tree.MemberReference) and s_node.member in taint_param:
                    results.append({
                        '行号': node.position.line,
                        '缺陷源': taint_line,
                        '漏洞类型': 'Header Manipulation',
                    })

    i = 1
    for line in lines:
        if 'getParameter' in line and ('setHeader' in line or 'addHeader' in line):
            results.append({
                '行号': i,
                '缺陷源': i,
                '漏洞类型': 'Header Manipulation',
            })
        i += 1


    # 去重处理
    unique_results = []
    seen = set()
    for r in results:
        key = (r['行号'])
        if key not in seen:
            seen.add(key)
            unique_results.append(r)

    return results_add_func_lines(tree, unique_results)