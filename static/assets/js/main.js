/** EasyWeb spa v3.1.8 date:2020-05-04 License By http://easyweb.vip */
layui.config({
    version: '318',   // 更新组件缓存，设为true不缓存，也可以设一个固定值
//    base: "http://10.99.16.24:8088/static/assets/module/"

    base: "/static/assets/module/"
}).extend({
    steps: 'steps/steps',
    notice: 'notice/notice',
    cascader: 'cascader/cascader',
    dropdown: 'dropdown/dropdown',
    fileChoose: 'fileChoose/fileChoose',
    Split: 'Split/Split',
    Cropper: 'Cropper/Cropper',
    tagsInput: 'tagsInput/tagsInput',
    citypicker: 'city-picker/city-picker',
    introJs: 'introJs/introJs',
    zTree: 'zTree/zTree'
}).use(['layer', 'setter', 'index', 'admin'], function () {
    var $ = layui.jquery;
    var layer = layui.layer;
    var setter = layui.setter;
    var index = layui.index;
    var admin = layui.admin;



    var res = {
        "code": 0,
        "data": [
            {
                "title": "首页",
                "icon": "layui-icon layui-icon-home",
                "path": "#/HomePage",
                "component": "/static/linkPage/modules/main/HomePage/homePage.html"
            },
            {
                "icon": "layui-icon layui-icon-user",
                "title": "用户管理",
                "path": "#/UserManage",
                "component": "/static/linkPage/modules/main/AccountManage/User/AccountManageUser.html"
            },
            {
                "icon": "layui-icon layui-icon-template-1",
                "title": "代码项目管理",
                "path": "#/ProjectManage",
                "component": "/static/linkPage/modules/main/ProjectManage/ProjectList.html",
            },
		  {
                "icon": "layui-icon layui-icon-senior",
                "title": "扫描策略管理",
                "path": "#/vulnerability",
                "component": "/static/linkPage/modules/main/vulnerability/newvulnerability.html"
            },
             {
             
                "icon": "layui-icon layui-icon-edit",
                "title": "自定义规则",
                "path": "#/user-definedRule",
                "component": "/static/linkPage/modules/main/customRule/user-defined_rules.html"
            },
             {
                "icon": "layui-icon layui-icon-fonts-code",
                "title": "自定义清洁函数",
                "path": "#/customRule",
                "component": "/static/linkPage/modules/main/customRule/cleaningFunction.html"
            },
            {
                "icon": "layui-icon layui-icon-tips",
                "title": "告警设置",
                "path": "#/projectGAOJING",
                "component": "/static/linkPage/modules/main/projectGAOJING/gaojing.html"
            },
             {
                "icon": "layui-icon layui-icon-file",
                "title": "报告管理",
                "path": "#/ReportManage",
                "component": "/static/linkPage/modules/main/ReportManage/ReportManage.html"
            },
//		  {
//                "icon": "layui-icon layui-icon-senior",
//                "title": "特征模型训练",
//                "path": "#/GetFeature",
//                "component": "/static/linkPage/modules/main/ModelIteration/feature.html"
//            },
           {
               "icon": "layui-icon layui-icon-senior",
               "title": "配置策略",
               "path": "#/config",
               "component": "/static/linkPage/modules/main/config/config.html"
           },
//            {
//                "icon": "layui-icon layui-icon-dialogue",
//                "title": "代码生成",
//                "path": "#/chatHome",
//                "component": "/static/linkPage/modules/main/chatHome/chatHome.html"
//            },
            {
                "icon": "layui-icon layui-icon-search",
                "title": "代码缺陷知识库",
                "path": "#/knowledge_base",
                "component": "/static/linkPage/modules/main/vulnerability/knowledge_base.html"
            },
            {
                "icon": "layui-icon layui-icon-dialogue",
                "title": "大模型问答",
                "path": "#/chatHome",
                "component": "/static/linkPage/modules/main/chatHome/chatHome.html"
            },
//            {
//                "icon": "layui-icon layui-icon-user",
//                "title": "知识库权限管理",
//                "path": "#/projectKnowManage",
//                "component": "/static/linkPage/modules/main/projectKnowManage/knowmanage.html"
//            },
//            {
//                "icon": "layui-icon layui-icon-dialogue",
//                "title": "知识库问答",
//                "path": "#/projectknowledge_base",
//                "component": "/static/linkPage/modules/main/projectknowledge_base/knowledge_base.html"
//            },


        ],
        "data1": [
//            {
//                "title": "首页",
//                "icon": "layui-icon layui-icon-home",
//                "path": "#/HomePage",
//                "component": "/static/linkPage/modules/main/HomePage/homePage.html"
//            },
//            {
//                "icon": "layui-icon layui-icon-set",
//                "title": "用户管理",
//                "path": "#/UserManage",
//                "component": "/static/linkPage/modules/main/AccountManage/User/AccountManageUser.html"
//            },
		  {
                "title": "首页",
                "icon": "layui-icon layui-icon-home",
                "path": "#/HomePage",
                "component": "/static/linkPage/modules/main/HomePage/homePage.html"
            },
             {
                "icon": "layui-icon layui-icon-template-1",
                "title": "代码项目管理",
                "path": "#/ProjectManage",
                "component": "/static/linkPage/modules/main/ProjectManage/ProjectList.html",
            },
            {
                "icon": "layui-icon layui-icon-senior",
                "title": "扫描策略管理",
                "path": "#/vulnerability",
                "component": "/static/linkPage/modules/main/vulnerability/newvulnerability.html"
            },
            {
                "icon": "layui-icon layui-icon-senior",
                "title": "配置策略",
                "path": "#/config",
                "component": "/static/linkPage/modules/main/config/config.html"
           },
		  {
                "icon": "layui-icon layui-icon-dialogue",
                "title": "代码生成",
                "path": "#/chatHome",
                "component": "/static/linkPage/modules/main/chatHome/chatHome.html"
            },
            {
                "icon": "layui-icon layui-icon-set",
                "title": "报告管理",
                "path": "#/ReportManage",
                "component": "/static/linkPage/modules/main/ReportManage/ReportManage.html"
            },
            {
                "icon": "layui-icon layui-icon-file",
                "title": "漏洞类型",
                "path": "#/vulnerability",
                "component": "/static/linkPage/modules/main/vulnerability/newvulnerability.html"
            },
            {
                "icon": "layui-icon layui-icon-file",
                "title": "代码缺陷知识库",
                "path": "#/knowledge_base",
                "component": "/static/linkPage/modules/main/vulnerability/knowledge_base.html"
            },
            {
                "icon": "layui-icon layui-icon-file",
                "title": "自定义清洁函数",
                "path": "#/customRule",
                "component": "/static/linkPage/modules/main/customRule/cleaningFunction.html"
            },
             {
                "icon": "layui-icon layui-icon-file",
                "title": "告警设置",
                "path": "#/projectGAOJING",
                "component": "/static/linkPage/modules/main/projectGAOJING/gaojing.html"
            },
            {
                "icon": "layui-icon layui-icon-dialogue",
                "title": "大模型问答",
                "path": "#/chatHome",
                "component": "/static/linkPage/modules/main/chatHome/chatHome.html"
            },
//            {
//                "icon": "layui-icon layui-icon-dialogue",
//                "title": "知识库问答",
//                "path": "#/projectknowledge_base",
//                "component": "/static/linkPage/modules/main/projectknowledge_base/knowledge_base.html"
//            },
            
            
//            {
//                "icon": "layui-icon layui-icon-senior",
//                "title": "模型迭代",
//                "path": "#/ModelIteration",
//                "component": "/static/linkPage/modules/main/ModelIteration/iteration2.html"
//            },
//            {
//                "icon": "layui-icon layui-icon-senior",
//                "title": "特征模型训练",
//                "path": "#/GetFeature",
//                "component": "/static/linkPage/modules/main/ModelIteration/feature.html"
//            },
        ]
    }

    /* 加载侧边栏 */
    if (localUser.role === '0'){
        if (0 === res.code) {
            index.regRouter(res.data, function (data) {
                data.name = data.title;
                data.url = data.path;
                data.iframe = data.component;
                data.show = !data.hide;
                data.subMenus = data.children;
                return data;
            });  // 注册路由
            index.renderSide(res.data);  // 渲染侧边栏
            console.log(res.data);
            // 加载主页
            index.loadHome({
                url: "#/HomePage",
                iframe: "/static/linkPage/modules/main/HomePage/homePage.html",
                name: '<i class="layui-icon layui-icon-home"></i>'

            });
        } else {
            layer.msg('获取菜单列表失败', { icon: 2, anim: 6 });
        }
    }else {
        if (0 === res.code) {
            index.regRouter(res.data1, function (data) {
                data.name = data.title;
                data.url = data.path;
                data.iframe = data.component;
                data.show = !data.hide;
                data.subMenus = data.children;
                return data;
            });  // 注册路由
            
            index.renderSide(res.data1);  // 渲染侧边栏
            console.log(res.data1);
            // 加载主页
            index.loadHome({
                url: "#/HomePage",
                iframe: "/static/linkPage/modules/main/HomePage/homePage.html",
                name: '<i class="layui-icon layui-icon-home"></i>'
            });
        } else {
            layer.msg('获取菜单列表失败', { icon: 2, anim: 6 });
        }
    }

    document.getElementById('userName').innerText=localUser.username;
});
