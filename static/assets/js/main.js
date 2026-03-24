/** EasyWeb spa v3.1.8 date:2020-05-04 License By http://easyweb.vip */
layui.config({
    version: '318',   // 更新组件缓存，设为true不缓存，也可以设一个固定值


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



  // 完整的菜单映射表*********************如果数据库修改也要进行对应修改**************************
  var allMenusMap = {
    1: {
      id: 1,
      title: "首页",
      icon: "layui-icon layui-icon-home",
      path: "#/HomePage",
      component: "/static/linkPage/modules/main/HomePage/homePage.html"
    },
    2: {
      id: 2,
      icon: "layui-icon layui-icon-user",
      title: "用户管理",
      path: "#/UserManage",
      component: "/static/linkPage/modules/main/AccountManage/User/AccountManageUser.html"
    },
    3: {
      id: 3,
      icon: "layui-icon layui-icon-template-1",
      title: "代码项目管理",
      path: "#/ProjectManage",
      component: "/static/linkPage/modules/main/ProjectManage/ProjectList.html"
    },
    4: {
      id: 4,
      icon: "layui-icon layui-icon-senior",
      title: "扫描策略管理",
      path: "#/vulnerability",
      component: "/static/linkPage/modules/main/vulnerability/newvulnerability.html"
    },
    5: {
      id: 5,
      icon: "layui-icon layui-icon-edit",
      title: "自定义规则",
      path: "#/user-definedRule",
      component: "/static/linkPage/modules/main/customRule/user-defined_rules.html"
    },
    6: {
      id: 6,
      icon: "layui-icon layui-icon-fonts-code",
      title: "自定义清洁函数",
      path: "#/customRule",
      component: "/static/linkPage/modules/main/customRule/cleaningFunction.html"
    },
    7: {
      id: 7,
      icon: "layui-icon layui-icon-tips",
      title: "告警设置",
      path: "#/projectGAOJING",
      component: "/static/linkPage/modules/main/projectGAOJING/gaojing.html"
    },

    8: {
      id: 8,
      icon: "layui-icon layui-icon-file",
      title: "报告管理",
      path: "#/ReportManage",
      component: "/static/linkPage/modules/main/ReportManage/ReportManage.html"
    },
    9: {
      id: 9,
      icon: "layui-icon layui-icon-senior",
      title: "配置策略",
      path: "#/config",
      component: "/static/linkPage/modules/main/config/config.html"
    },
    10: {
      id: 10,
      icon: "layui-icon layui-icon-search",
      title: "知识库",
      path: "#/knowledge_base",
      component: "/static/linkPage/modules/main/vulnerability/knowledge_base.html"
    },
    11: {
      id: 11,
      icon: "layui-icon layui-icon-dialogue",
      title: "大模型问答",
      path: "#/chatHome",
      component: "/static/linkPage/modules/main/chatHome/chatHome.html"
    },
    12: {
      id: 12,
      title: "联系人管理",
      icon: "layui-icon layui-icon-user",
      path: "#/ContactManagement",
      component: "/static/linkPage/modules/main/ContactManagement/ContactManagement.html"
    },
  };

  // 获取用户名并显示
  document.getElementById('userName').innerText = localUser.username;

  // 获取动态菜单
  function fetchMenu() {
    $.ajax({
      url: http_head + '/login/', // 替换为实际接口地址
      data: {
        method: 'check',
        username: localUser.account
      },
      type: 'post',
      dataType: 'JSON',
      success: function(res) {
        if (res.code === 200|| res.code === "200") {
          // 提取用户有权限的菜单ID
          const menuIds = res.menu.map(item => item.menuId);

          // 生成动态菜单数组
          const dynamicMenu = [];

          // 保持菜单顺序，只添加有权限的菜单
          [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12].forEach(id => {
            if (menuIds.includes(id) && allMenusMap[id]) {
              dynamicMenu.push(allMenusMap[id]);
            }
          });

          // 注册路由并渲染菜单
          registerMenu(dynamicMenu);
        } else {
          layer.msg('获取菜单失败: ' + (res.msg || '未知错误'), { icon: 2 });
          // 失败时使用默认菜单
          useFallbackMenu();
        }
      },
      error: function() {
        layer.msg('网络错误，获取菜单失败', { icon: 2 });
        // 失败时使用默认菜单
        useFallbackMenu();
      }
    });
  }

  // 注册菜单和路由
  function registerMenu(menuData) {
    // 注册路由
    index.regRouter(menuData, function (data) {
      data.name = data.title;
      data.url = data.path;
      data.iframe = data.component;
      data.show = !data.hide;
      data.subMenus = data.children;
      return data;
    });

    // 渲染侧边栏
    index.renderSide(menuData);

    // 加载主页（总是加载首页）
    const homePage = menuData.find(item => item.id === 1) || menuData[0];
    if (homePage) {
      index.loadHome({
        url: homePage.path,
        iframe: homePage.component,
        name: '<i class="' + homePage.icon + '"></i>'
      });
    } else if (menuData.length > 0) {
      // 如果没有首页项，则使用第一个菜单项
      index.loadHome({
        url: menuData[0].path,
        iframe: menuData[0].component,
        name: '<i class="' + menuData[0].icon + '"></i>'
      });
    } else {
      layer.msg('没有可用的菜单', { icon: 2, anim: 6 });
    }
  }

  // 备用菜单方案（当接口失败时使用）
  function useFallbackMenu() {
    // 创建默认菜单配置
    const adminMenu = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    const userMenu = [1, 3, 4, 10, 12, 9, 4, 11, 6, 7];

    const defaultMenuIds = localUser.role === 1 ? adminMenu : userMenu;
    const defaultMenu = defaultMenuIds.map(id => allMenusMap[id]).filter(Boolean);

    registerMenu(defaultMenu);
  }

  // 初始化：获取菜单
  fetchMenu();
});
