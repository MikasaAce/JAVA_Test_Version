// const mainUrl = "http://180.76.225.239:8030/"
// const mainUrl = "http://10.99.16.24:8088"
let vm = new Vue({
  el: '#app',
  data() {
    // 确认修改密码
    var validatePass = (rule, value, callback) => {
      if (value === '') {
        callback(new Error('请输入密码'));
      } else {
        let ls = 0;
        if (value.match(/([a-z])+/)) ls++;
        if (value.match(/([0-9])+/)) ls++;
        if (value.match(/([A-Z])+/)) ls++;
        if (value.match(/([\W])+/) && !value.match(/(![\u4E00-\u9FA5])+/)) ls++;    //包含特殊字符， 不包含中文字符
        if (ls >= 2) {
          callback();
        } else {
          callback(new Error('至少需要包含两种字符类型'));
        }
      }
    };
    // 修改密码
    var validatePass2 = (rule, value, callback) => {
      if (value !== this.changeform.passNew) {
        callback(new Error('两次输入的密码不一致'));
      } else {
        callback();
      }
    };
    //新增时
    var validatePassword = (rule, value, callback) => {
      if (value === '') {
        callback(new Error('请输入密码'));
      } else {
        let ls = 0;
        if (value.match(/([a-z])+/)) ls++;
        if (value.match(/([0-9])+/)) ls++;
        if (value.match(/([A-Z])+/)) ls++;
        if (value.match(/([\W])+/) && !value.match(/(![\u4E00-\u9FA5])+/)) ls++;    //包含特殊字符， 不包含中文字符
        if (ls >= 2) {
          callback();
        } else {
          callback(new Error('至少需要包含两种字符类型'));
        }
      }
    };
    //新增确认
    const validateConfirm = (rule, value, callback) => {
      if (value !== this.addform.password) {
        callback(new Error('两次输入的密码不一致'));
      } else {
        callback();
      }
    };
    return {
      query:{
        name: '',
        account : '',
      },

      addUserDialog: false,
      isshow : 1,
      addUserTitle : '新建用户',
      pwdDialog :false,
      tableData: [],
      currentPage: 1, //当前页 刷新后默认显示第一页
      pageSize: 10, //每一页显示的数据量 此处每页显示6条数据
      count:10,
      addform:{
        username:'',
        password:'',
        confirmPassword: '', // 新增字段
        selectedRoleId: ''
      },
      rules1:{
        username: [
          { required: true, message: '请输入用户名', trigger: 'blur' },
          // { min: 3, max: 6, message: '用户名长度在 3 到 6 个字符', trigger: 'blur' }
        ],
        account: [
          { required: true, message: '请输入登录账号', trigger: 'blur' },
          // { min: 3, max: 6, message: '用户名长度在 3 到 6 个字符', trigger: 'blur' }
        ],
        password: [
          { required: true, message: '请输入密码', trigger: 'blur' },
          { min: 8,max: 20, message: '密码长度在8到20位之间', trigger: 'blur' },
          { validator: validatePassword, trigger: 'blur' }
        ],
        confirmPassword: [
          { required: true, message: '请确认密码', trigger: 'blur' },
          { validator: validateConfirm, trigger: 'blur' }
        ],
        // selectedRoleId: [
        //   { required: true, message: '请选择角色', trigger: 'change' }
        // ]
        selectedRoleId: [
          {
            required: true,
            message: '请选择角色',
            trigger: 'change',
            // 只在新建和编辑状态下验证
            validator: (rule, value, callback) => {
              if (this.isshow !== '1' && this.isshow !== '2') {
                callback();
                return;
              }
              if (!value) {
                callback(new Error('请选择角色'));
              } else {
                callback();
              }
            }
          }
        ]
      },
      passwordPercent: 0,
      customColors: [
        {color: '#f56c6c', percentage: 20 },
        {color: '#e6a23c', percentage: 50},
        {color: '#5cb87a', percentage: 75},
        {color: '#6f7ad3', percentage: 100}
      ],
      changeform:{},
      rules2:{
        pwd: [
          { required: true, message: '请输密码', trigger: 'blur' },
        ],
        passNew: [
          { required: true, message: '请输入密码', trigger: 'blur' },
          { min: 8,max: 20, message: '密码长度在8到20位之间', trigger: 'blur' },
          { validator: validatePass, trigger: 'blur' },
        ],
        checkPassNew: [
          { required: true, message: '请确认密码', trigger: 'blur' },
          { validator: validatePass2, trigger: 'blur' },
        ]
      },
      // 新增角色管理相关数据
      roleDialogVisible: false,
      roleFormVisible: false,
      assignRoleDialogVisible: false,
      roleSearch: '',
      roleFormTitle: '新建角色',
      isEditingRole: false,
      currentRole: {
        roleId: '',
        roleName: '',
        menus: []
      },
      allRoles: [], // 所有角色
      // 创建菜单映射对象
      menuMap: {},
      roleOptions: [], // 存储角色列表数据
      allMenus: [ // 菜单数据，如果数据库修改也要进行对应修改**************************
        { id: '1', label: '首页'},
        { id: '2', label: '用户管理'},
        { id: '3', label: '代码项目管理'},
        { id: '4', label: '扫描漏洞策略'},
        { id: '5', label: '自定义规则'},
        { id: '6', label: '清洁函数'},
        { id: '7', label: '告警设置'},
        { id: '8', label: '报告管理'},
        { id: '9', label: '配置策略'},
        { id: '10', label: '知识库'},
        { id: '11', label: '大模型问答'},
        { id: '12', label: '联系人管理'}
      ],
      menuProps: {
        children: 'children',
        label: 'label'
      },
      defaultExpandedKeys: ['0', '1', '2'],
      assignRoleForm: {
        userId: '',
        username: '',
        account: '',
        selectedRoles: []
      },
      availableRoles: [] // 可供分配的角色列表

    }
  },
  computed: {
    // 创建菜单映射关系
    menuMap() {
      const map = {};
      // 使用正确的变量名 allMenus 而不是 menuData
      this.allMenus.forEach(menu => {
        map[menu.id] = menu.label;
      });
      return map;
    },
    // 过滤后的角色列表
    filteredRoles() {
      // 如果不需要搜索功能，直接返回所有角色
      return this.allRoles;

      // 如果需要搜索功能，取消注释以下代码
      /*
      if (!this.roleSearch) return this.allRoles;
      return this.allRoles.filter(role =>
        role.id.toString().includes(this.roleSearch) ||
        role.roleName.includes(this.roleSearch)
      */
    },
  },
  create(){

  },
  methods: {
    open1(msg) {
      this.$message({
        message: msg,
        type: 'success'
      });
    },
    open2(msg) {
      this.$message({
        message: msg,
        type: 'warning'
      });
    },
    open3(msg) {
      this.$message.error(msg);
    },

    // getTableData(){
    //   var that = this;
    //   $.ajax({
    //     url:  (http_head + '/login/'),
    //     data:{
    //       method: 'account_getall',
    //       teamId: localUser.teamId,
    //       username : that.query.name,
    //       account : that.query.account,
    //       page   :  that.currentPage,
    //       rows   :  that.pageSize,
    //     },
    //     type : 'post',
    //     dataType : 'JSON',
    //     success : function (res){
    //       console.log(res);
    //       if (res){
    //         that.tableData = res.data
    //         that.count = parseInt(res.count)
    //         // that.open1("获取成功")
    //       }
    //     },
    //     error: function (err) {
    //       console.log(err)
    //       that.open3("获取失败")
    //     }
    //   })
    // },
    getTableData() {
      var that = this;

      // 先加载角色列表
      this.loadRolesForSelect().then(() => {
        // 角色列表加载完成后，再加载用户数据
        $.ajax({
          url: (http_head + '/login/'),
          data: {
            method: 'account_getall',
            teamId: localUser.teamId,
            username: that.query.name,
            account: that.query.account,
            page: that.currentPage,
            rows: that.pageSize,
          },
          type: 'post',
          dataType: 'JSON',
          success: function(res) {
            if (res) {
              that.tableData = res.data;
              that.count = parseInt(res.count);
            }
          },
          error: function(err) {
            console.log(err);
            that.open3("获取用户列表失败");
          }
        });
      });
    },
    handleSizeChange(val) {
      console.log(`每页 ${val} 条`);
      this.pageSize = val;
      this.getTableData()
    },
    //点击按钮切换页面
    handleCurrentChange(currentPage) {
      this.currentPage = currentPage; //每次点击分页按钮，当前页发生变化
      this.getTableData();
    },
    checkFormData(){
      this.getTableData()
    },

    initaddForm(){
      this.addform = {
        username: '',
        account: '',
        password: '',
        confirmPassword: '',
        selectedRoleId: '' // 添加角色ID字段
      }
    },
    //输入密码时同步更新进度条
    // updatePasswordStrength(value) {
    //   if (!value) {
    //     this.passwordPercent = 0;
    //     return;
    //   }
    //
    //   let strength = 0;
    //   // 检测小写字母
    //   if (/[a-z]/.test(value)) strength++;
    //   // 检测大写字母
    //   if (/[A-Z]/.test(value)) strength++;
    //   // 检测数字
    //   if (/[0-9]/.test(value)) strength++;
    //   // 检测特殊字符（排除中文）
    //   if (/[\W_]/.test(value) && !/[\u4E00-\u9FA5]/.test(value)) strength++;
    //
    //   this.passwordPercent = strength > 0
    //       ? Math.max(25, strength * 25)  // 保证最低25%显示
    //       : 0;
    // },
    // 进度条
    // formatPasswordStrength(percentage) {
    //   const strengthLevel = Math.floor(percentage / 25);
    //   const levels = {
    //     25: { text: '密码太弱', color: '#f56c6c' },
    //     50: { text: '密码较弱', color: '#e6a23c' },
    //     75: { text: '密码较强', color: '#5cb87a' },
    //     100: { text: '密码很强', color: '#1989fa' }
    //   };
    //   return levels[percentage]?.text || '';
    // },

    //新增
    addUser(){
      this.initaddForm()
      this.addUserDialog = true
      this.isshow  = '1'
      this.addUserTitle = '新建用户'
      this.loadRolesForSelect(); // 加载角色列表
    },
    createUser(){
      var that = this;
      this.$refs.addform.validate((valid) => {
        if (valid) {
          // 验证是否选择了角色
          if (!that.addform.selectedRoleId) {
            that.open3("请选择角色");
            return false;
          }
          $.ajax({
            url:  (http_head + '/login/'),
            data:{
              username  : that.addform.username,
              teamId    : localUser.teamId ,
              role     : that.addform.selectedRoleId,
              account        : that.addform.account ,
              password      : that.addform.password,
              createTime     : getCurrentDate(2),
              method        : 'account_insert',
            },
            type : 'post',
            dataType : 'JSON',
            success : function (res){
              console.log(res);
              if (res.msg == '插入成功'){
                that.open1("新增成功")
                that.addUserDialog = false
                that.getTableData()
              }else {
                that.open3(res.msg)
              }
            },
            error: function (err) {
              console.log(err)
              that.open3("新增失败")
            }
          })
        } else {
          console.log('error submit!!');
          return false;
        }
      });

    },
    //编辑
    handleEdit(row){
      this.initaddForm()
      sessionStorage.setItem('editdata',JSON.stringify(row))
      this.addUserDialog = true
      this.isshow  = '2'
      this.addUserTitle = '编辑'
      var rows = JSON.parse(sessionStorage.getItem('editdata'))
      // 设置当前用户的角色ID
      this.addform = {
        ...rows, // 复制所有属性
        selectedRoleId: rows.role // 设置角色ID
      };
      // 确保角色列表已加载
      this.loadRolesForSelect();
    },
    //确认更新
    //确认更新
    editUser() {
      var row = JSON.parse(sessionStorage.getItem('editdata'));
      var that = this;

      // 获取当前登录用户（管理员）
      const currentUserAccount = localUser.account;

      // 确保已获取当前用户
      if (!currentUserAccount) {
        that.open3("未获取到当前登录用户信息");
        return;
      }

      // 确保已选择新角色
      if (!that.addform.selectedRoleId) {
        that.open3("请选择角色");
        return;
      }

      // 更新用户基本信息
      $.ajax({
        url: (http_head + '/login/'),
        data: {
          id: row.id,
          username: that.addform.username,
          method: 'account_update',
        },
        type: 'post',
        dataType: 'JSON',
        success: function(res) {
          console.log(res);
          if (res) {
            // 更新角色信息
            $.ajax({
              url: (http_head + '/login/'),
              data: {
                username: currentUserAccount, // 当前登录用户（管理员）
                user_update: that.addform.username,     // 被修改用户的账号
                role_update: that.addform.selectedRoleId, // 新角色ID
                method: 'user_role_update'
              },
              type: 'post',
              dataType: 'JSON',
              success: function(resRole) {
                if (resRole.msg === '更新成功') {
                  that.open1("用户信息更新成功");
                  that.addUserDialog = false;
                  that.getTableData();
                } else {
                  that.open3(resRole.msg || "更新角色失败");
                }
              },
              error: function(err) {
                console.log(err);
                that.open3("更新角色失败");
              }
            });
          } else {
            that.open3("更新失败");
          }
        },
        error: function(err) {
          console.log(err);
          that.open3("编辑失败");
        }
      })
    },
    // editUser(){
    //   var row = JSON.parse(sessionStorage.getItem('editdata'))
    //   var that = this;
    //
    //   $.ajax({
    //     url:  (http_head + '/login/'),
    //     data:{
    //       id : row.id,
    //       username  : that.addform.username,
    //       // account    : that.addform.account ,
    //       method     : 'account_update',
    //     },
    //     type : 'post',
    //     dataType : 'JSON',
    //     success : function (res){
    //       console.log(res);
    //       if (res){
    //         // 更新角色信息
    //         that.updateUserRole(row);
    //         // that.open1("编辑成功")
    //         // that.addUserDialog = false
    //         // that.getTableData()
    //       }
    //     },
    //     error: function (err) {
    //       console.log(err)
    //       that.open3("编辑失败")
    //     }
    //   })
    // },
    //修改密码
    handleResetPassword(row){
      this.changeform ={}
      sessionStorage.setItem('editdata',JSON.stringify(row))
      this.pwdDialog =true
    },
    changePwd(){
      var row = JSON.parse(sessionStorage.getItem('editdata'))
      var that = this;
      this.$refs.changeform.validate((valid) => {
        if (valid) {
          $.ajax({
            url:  (http_head + '/login/'),
            data:{
              account    : row.account,
              password : that.changeform.pwd,
              password_n: that.changeform.passNew,
              method     : 'account_update_pass',
            },
            type : 'post',
            dataType : 'JSON',
            success : function (res){
              console.log(res);
              if (res){
                if (res.msg == '更新成功'){
                  that.open1("密码修改成功")
                  that.pwdDialog = false
                }else {
                  that.open3(res.msg)
                }

              }
            },
            error: function (err) {
              console.log(err)
              that.open3("编辑失败")
            }
          })
        } else {
          console.log('error submit!!');
          return false;
        }
      });

    },
    //删除
    delopen(row) {
      this.$confirm('此操作将永久删除该账号, 是否继续?', '提示', {
        confirmButtonText: '确定',
        cancelButtonText: '取消',
        type: 'warning'
      }).then(() => {
        this.handleDelete(row)
      }).catch(() => {
        this.$message({
          type: 'info',
          message: '已取消删除'
        });
      });
    },
    handleDelete(row){
      var that = this;
      $.ajax({
        url:  (http_head + '/login/'),
        data:{
          id : row.id,
          method: 'account_delete',
        },
        type : 'post',
        dataType : 'JSON',
        success : function (res){
          console.log(res);
          if (res){
            that.open1("删除成功")
            that.getTableData()
          }
        },
        error: function (err) {
          console.log(err)
          that.open3("删除失败")
        }
      })
    },
    resetForm(formName) {
      this.$refs[formName].resetFields();
    },

    // 获取角色名称
    getRoleName(roleId) {
      const role = this.allRoles.find(r => r.roleId === roleId);
      return role ? role.roleName : roleId;
    },


    // 根据角色ID获取角色名称
    getRoleNameById(roleId) {
      // 将数字ID转换为字符串（因为角色选项中的ID可能是字符串）
      const idStr = String(roleId);

      // 在角色选项列表中查找匹配的角色
      const role = this.roleOptions.find(r => String(r.id) === idStr);

      // 如果找到则返回角色名称，否则返回原始ID
      return role ? role.roleName : `角色(${roleId})`;
    },

    // 打开角色管理对话框
    openRoleManager() {
      this.roleDialogVisible = true;
      this.loadRoles();
    },

    // 加载角色列表
    loadRoles() {
      const that = this;
      $.ajax({
        url: http_head + '/login/',
        data: {
          method: 'get_all_roles',
        },
        type: 'post',
        dataType: 'JSON',
        success: function(res) {
          if (res && res.rolelist) {
            // 将角色数据转换为需要的格式
            that.allRoles = res.rolelist.map(role => ({
              id: role.id,
              roleName: role.roleName,
              menuIds: role.menuIds || []
            }));
            console.log("加载的角色数据:", that.allRoles); // 调试用
          } else {
            that.open3("获取角色列表失败: " + (res.msg || '未知错误'));
          }
        },
        error: function(err) {
          console.log(err);
          that.open3("获取角色列表失败");
        }
      });
    },
    // 获取菜单名称（根据ID）
    getMenuName(menuId) {
      // 1. 处理空值情况
      if (menuId === null || menuId === undefined) {
        return "空菜单ID";
      }

      // 2. 将ID转换为字符串
      const idStr = String(menuId);

      // 3. 从菜单映射中查找
      if (this.menuMap[idStr]) {
        return this.menuMap[idStr];
      }

      // 4. 处理未找到的情况
      console.warn(`未找到菜单ID: ${menuId} (字符串形式: ${idStr})`);
      console.warn("当前菜单映射:", this.menuMap);

      // 5. 尝试在原始菜单数据中查找（备用方案）
      const foundMenu = this.allMenus.find(menu => String(menu.id) === idStr);
      if (foundMenu) {
        return foundMenu.label;
      }

      return `未知菜单(${menuId})`;
    },

    // 打开创建角色对话框
    openCreateRoleDialog() {
      this.roleFormTitle = '新建角色';
      this.isEditingRole = false;
      this.currentRole = {
        id: '',
        roleName: '',
        menuIds: []
      };
      this.$nextTick(() => {
        this.$refs.permissionTree.setCheckedKeys([]);
      });
      this.roleFormVisible = true;
    },

    // 编辑角色权限
    editRolePermissions(role) {
      this.roleFormTitle = '编辑角色';
      this.isEditingRole = true;
      this.currentRole = {...role};
      this.$nextTick(() => {
        // 将数字ID转换为字符串（如果菜单树使用字符串ID）
        const checkedKeys = role.menuIds.map(id => id.toString());
        this.$refs.permissionTree.setCheckedKeys(checkedKeys);
      });
      this.roleFormVisible = true;
    },

    // 创建角色
    createRole() {
      var that = this;
      // 获取选中的菜单ID（字符串数组）
      const checkedKeys = this.$refs.permissionTree.getCheckedKeys();

      // 转换为数字数组（如果需要）
      const menuIds = checkedKeys.map(id => parseInt(id, 10));

      $.ajax({
        url: (http_head + '/login/'),
        data: {
          rolename: that.currentRole.roleName,
          menuIds: checkedKeys.join(','),
          method: 'create_role'
        },
        type: 'post',
        dataType: 'JSON',
        success: function(res) {
          if (res.msg === '新增成功') {
            that.open1("角色创建成功");
            that.loadRoles();
            // 新增：立即刷新角色选项列表
            that.loadRolesForSelect().then(() => {
              // 角色列表加载完成后可以执行其他操作
            });
          } else {
            that.open3(res.msg);
          }
          that.roleFormVisible = false;
        },
        error: function(err) {
          console.log(err);
          that.open3("创建角色失败");
          that.roleFormVisible = false;
        }
      });
    },

    // 更新角色权限
    updateRolePermissions() {
      var that = this;
      // 获取所有选中的节点（包括半选中父节点）
      const checkedKeys = this.$refs.permissionTree.getCheckedKeys();
      const halfCheckedKeys = this.$refs.permissionTree.getHalfCheckedKeys();
      const allCheckedKeys = [...checkedKeys, ...halfCheckedKeys];

      $.ajax({
        url: (http_head + '/login/'),
        data: {
          role_update: that.currentRole.id,
          menu_update: checkedKeys.join(','),
          method: 'role_menu_update'
        },
        type: 'post',
        dataType: 'JSON',
        success: function(res) {
          if (res.msg === '更新成功') {
            that.open1("角色权限更新成功");
            that.loadRoles();
          } else {
            that.open3(res.msg);
          }
          that.roleFormVisible = false;
        },
        error: function(err) {
          console.log(err);
          that.open3("更新角色权限失败");
          that.roleFormVisible = false;
        }
      });
    },

    // 删除角色
    deleteRole(role) {
      var that = this;
      $.ajax({
        url: (http_head + '/login/'),
        data: {
          roleId: role.id,
          method: 'delete_role'
        },
        type: 'post',
        dataType: 'JSON',
        success: function(res) {
          if (res.msg === '删除成功') {
            that.open1("角色删除成功");
            that.loadRoles();
          } else {
            that.open3(res.msg);
          }
        },
        error: function(err) {
          console.log(err);
          that.open3("删除角色失败");
        }
      });
    },

    // 保存角色（创建或更新）
    saveRole() {
      if (this.isEditingRole) {
        this.updateRolePermissions();
      } else {
        this.createRole();
      }
    },

    // 获取角色列表
    loadRolesForSelect() {
      var that = this;

      return new Promise((resolve, reject) => {
        // 如果已经加载过角色列表，直接解析
        if (that.roleOptions.length > 0) {
          resolve();
          return;
        }

        $.ajax({
          url: (http_head + '/login/'),
          data: {
            method: 'get_all_roles',
          },
          type: 'post',
          dataType: 'JSON',
          success: function(res) {
            if (res && res.rolelist) {
              that.roleOptions = res.rolelist;
              resolve();
            } else {
              that.open3("获取角色列表失败");
              reject("获取角色列表失败");
            }
          },
          error: function(err) {
            console.log(err);
            that.open3("获取角色列表失败");
            reject(err);
          }
        });
      });
    },

    // 分配角色给用户
    assignRoles(user) {
      this.assignRoleForm = {
        userId: user.id,
        username: user.username,
        account: user.account,
        selectedRoles: user.roles || []
      };

      // 加载可用角色（排除管理员角色）
      this.availableRoles = this.allRoles.filter(role => role.roleId !== '0');
      this.assignRoleDialogVisible = true;
    },

    // 更新用户角色
    updateUserRole() {
      var that = this;
      const currentUserAccount = localUser.account;// 当前登录用户
      // 确保已获取当前用户
      if (!currentUserAccount) {
        that.open3("未获取到当前登录用户信息");
        return;
      }

      // 确保已选择新角色
      if (!that.addform.selectedRoleId) {
        that.open3("请选择角色");
        return;
      }
      $.ajax({
        url: (http_head + '/login/'),
        data: {
          username: currentUserAccount, // 当前登录用户账号
          user_update: user.account, // 被修改用户的账号
          role_update: that.addform.selectedRoleId, // 角色ID列表
          method: 'user_role_update'
        },
        type: 'post',
        dataType: 'JSON',
        success: function(res) {
          if (res.msg === '更新成功') {
            that.open1("用户信息更新成功");
            that.addUserDialog = false;
            that.getTableData();
          } else {
            that.open3(res.msg || "更新角色失败");
          }
          that.assignRoleDialogVisible = false;
        },
        error: function(err) {
          console.log(err);
          that.open3("分配角色失败");
          that.assignRoleDialogVisible = false;
        }
      });
    },

    // 获取用户可访问菜单（可选实现）
    getUserAccessibleMenus(account) {
      var that = this;
      $.ajax({
        url: (http_head + '/login/'),
        data: {
          account: account,
          method: 'check_user_role_menu'
        },
        type: 'post',
        dataType: 'JSON',
        success: function(res) {
          if (res && res.data) {
            // 处理用户可访问的菜单数据
            console.log('用户可访问菜单:', res.data.menu_ids);
          }
        },
        error: function(err) {
          console.log('获取用户菜单失败:', err);
        }
      });
    },

    //当前获取菜单列表是前端写死了，缺乏获取菜单列表接口，下述代码属于参考，如后续编写接口可参考该注释代码
    // 加载菜单数据（缺乏接口从后端获取）11111111111111111111111111111
    // GetAllMenus() {
    //   var that = this;
    //   $.ajax({
    //     url: (http_head + '/login/'),
    //     data: {
    //       method: 'get_all_menus' // 假设后端有获取菜单的接口
    //     },
    //     type: 'post',
    //     dataType: 'JSON',
    //     success: function(res) {
    //       if (res && res.data) {
    //         that.allMenus = res.data;
    //         // 设置默认展开的菜单项
    //         if (res.data.length > 0) {
    //           that.defaultExpandedKeys = res.data.map(menu => menu.id);
    //         }
    //       }
    //     },
    //     error: function(err) {
    //       console.log('获取菜单数据失败:', err);
    //     }
    //   });
    // },

  },
  mounted() {
    // 先加载角色列表
    this.loadRolesForSelect().then(() => {
      // 角色列表加载完成后，再加载用户数据
      this.getTableData();
    }).catch(err => {
      console.error("加载角色列表失败:", err);
      this.getTableData(); // 即使角色加载失败，也尝试加载用户数据
    });
  },
})

function getCurrentDate(format) {
  var now = new Date();
  var year = now.getFullYear(); //得到年份
  var month = now.getMonth();//得到月份
  var date = now.getDate();//得到日期
  var day = now.getDay();//得到周几
  var hour = now.getHours();//得到小时
  var minu = now.getMinutes();//得到分钟
  var sec = now.getSeconds();//得到秒
  month = month + 1;
  if (month < 10) month = "0" + month;
  if (date < 10) date = "0" + date;
  if (hour < 10) hour = "0" + hour;
  if (minu < 10) minu = "0" + minu;
  if (sec < 10) sec = "0" + sec;
  var time = "";
  //精确到天
  if(format==1){
    time = year + "-" + month + "-" + date;
  }
  //精确到分
  else if(format==2){
    time = year + "-" + month + "-" + date+ " " + hour + ":" + minu + ":" + sec;
  }
  return time;
}
