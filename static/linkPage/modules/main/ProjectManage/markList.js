let mymessage = {}

var vm = new Vue({
  el: "#app",
  created() {
    mymessage = {
      info: (options, single = true) => {
        this.$message({message: options, type: 'info'})
      },
      warning: (options, single = true) => {
        this.$message({message: options, type: 'warning'})
      },
      error: (options, single = true) => {
        this.$message({message: options, type: 'error'})
      },
      success: (options, single = true) => {
        this.$message({message: options, type: 'success'})
      },
    };
    this.isload = JSON.parse(sessionStorage.getItem('source') || '本地上传')
    this.currentPage = JSON.parse(sessionStorage.getItem('project_page2') || '1')
    this.pageSize = JSON.parse(sessionStorage.getItem('project_rows2') || '10')
    this.itemname = JSON.parse(sessionStorage.getItem('itemname') || '')
    this.itemid = JSON.parse(sessionStorage.getItem('itemid') || '')
    this.language = JSON.parse(sessionStorage.getItem('language') || '')
    sessionStorage.removeItem('project_page2')
    sessionStorage.removeItem('project_rows2')
    this.getTableData()
    this.getConfig()
    this.getUpload()
    // 初始化文件类型
    this.fileType = 'source';
  },
  data() {
    return {
      pullSvnSuccess:false,
      language:'',
      query:{
        project_name:''
      },
      isload :'本地上传',
      // 新增：上传完成状态
      isUploadCompleted: false, // 上传和解压是否完成
      fileType: 'source', // 文件类型：source-源代码, excel-Excel清单
      tableData: [],
      currentPage: 1, //当前页 刷新后默认显示第一页
      oldcurrentPage: 1,
      pageSize: 10, //每一页显示的数据量 此处每页显示6条数据
      count:0,
      itemname:'',
      itemName:'',
      itemid:'',
      ifSuccess:true,
      ifidshowtag:false,
      idshowtext:'',
      getAlert:false,
      pullSuccess:false,
      pullFtpSuccess:false,
      // 扫描模式选择
      scanMode: 'rule5', // 默认快速扫描
      defaultScanMode: 'rule5', // 存储从get_Pol获取的默认模式
      scanModeOptions: [
        { label: '快速扫描', value: 'rule5', desc: '扫描速度快，适合常规检测' },
        { label: '降误报模型', value: 'rule6', desc: '降低误报率，结果更准确' },
        { label: '思考模式', value: 'rule7', desc: '深度分析，检测更全面' }
      ],
      form:{
        taskName:'',
        description:'',
        language: 'java',
        source:'本地',
        url_git:'',
        key_git:'',
        branch:'',
        taskName:'',
        description:'',
        url_svn:'',
        zhanghao:'',
        key_svn:'',
        taskName:'',
        description:'',
        username_git:'',
        password_git:'',


      },
      uploadURL:http_head + '/Muti/',
      uploadURLData:{method:'decompression',item_name:'',},
      uploadFileList: [],
      policy:'',
      folder_name:'',

      isShowList: true,
      fileListTrain: [],
      rules:{
        // 修改任务名称验证规则，只在非Git下载源代码模式下必填
        taskName: [
          { 
            required: function() {
              // 只在非Git下载源代码模式下要求必填
              return !(this.isload == 'Git下载' && this.fileType === 'source');
            }, 
            message: '请输入任务名称', 
            trigger: 'blur' 
          },
        ],
        // language: [
        //   { required: true, message: '请选择代码语言', trigger: 'blur' },
        // ],
        // source: [
        //   { required: true, message: '请选择代码来源', trigger: 'blur' },
        // ],
        url_git: [
          { required: true, message: '请输入URL', trigger: 'blur' },
        ],
        // key_git: [
        //   { required: true, message: '请输入密码', trigger: 'blur' },
        // ],
        url_svn: [
          { required: true, message: '请输入URL', trigger: 'blur' },
        ],
        zhanghao: [
          { required: true, message: '请输入账号', trigger: 'blur' },
        ],
        key_svn: [
          { required: true, message: '请输入密码', trigger: 'blur' },
        ],

        source_ftp_host: [
          { required: true, message: '请输入主机地址', trigger: 'blur' },
        ],
        source_ftp_user: [
          { required: true, message: '请输入用户名', trigger: 'blur' },
        ],
        source_ftp_password: [
          { required: true, message: '请输入密码', trigger: 'blur' },
        ],
        source_remote_directory: [
          { required: true, message: '请输入路径', trigger: 'blur' },
        ],
        source_file_name: [
          { required: true, message: '请输入文件名', trigger: 'blur' },
        ],
        target_ftp_host: [
          { required: true, message: '请输入目标主机地址', trigger: 'blur' },
        ],
        target_ftp_user: [
          { required: true, message: '请输入用户名', trigger: 'blur' },
        ],
        target_ftp_password: [
          { required: true, message: '请输入密码', trigger: 'blur' },
        ],
        target_remote_directory: [
          { required: true, message: '请输入路径', trigger: 'blur' },
        ],

      },
      loading:false,
      folder_name_git:'',
      folder_name_svn:'',
      folder_name_ftp:'',
      logVisible:false,
      auditLog:[],
      logQuery:{
        filename:'',
        filepath:'',
        logtime:'',
      },
      currentLog_id:'',
      pollingInterval: null, // 定时器变量
      isRequestInProgress: false, // 是否有请求正在进行
      existingItem:[],
      ifDeepSeek:'false',
      delFlag:false,

      // 新增数据
      multipleSelection: [], // 存储选中的任务
      batchDeleteLoading: false, // 批量删除加载状态

      // 批量新建相关数据
      batchDialogVisible: false,
      batchForm: {
        username_git: '',
        password_git: '',
        key_git: '',
        branch: ''
      },
      batchFileList: [],
      // batchUploadURL: http_head + '/process_excel_and_extract_git_urls/',
      batchUploadURL:http_head + '/Muti/',
      uploadBatchURLData:{method:'decompression_excel'},
      gitUrlList: [], // 存储从Excel中提取的Git地址
      batchLoading: false,
      totalProgress: 0, // 总体进度
      processedCount: 0, // 已处理数量
      batchStatus: '', // 批量处理状态: processing, completed, error
      currentProcessingIndex: 0, // 当前处理的索引
    }
  },
  methods: {
    // 获取扫描模式描述
    getScanModeDesc(mode) {
      const option = this.scanModeOptions.find(opt => opt.value === mode);
      return option ? option.desc : '';
    },

    // 添加文件类型切换处理方法
    handleFileTypeChange() {
      // 当文件类型改变时重置相关表单
      if (this.fileType === 'source') {
        // 切换到源代码模式时重置批量相关数据
        this.gitUrlList = [];
        this.totalProgress = 0;
        this.processedCount = 0;
        this.batchStatus = '';
      } else {
        // 切换到Excel模式时重置单个任务相关数据
        this.pullSuccess = false;
      }
    },

    // 修改handleSubmit方法，处理Git下载的提交逻辑
    handleSubmit() {
      if (this.isload == 'Git下载' && this.fileType === 'excel') {
        // Excel清单模式 - 批量处理
        this.batchPullGit();
      } else if (this.isload == 'Git下载' && this.fileType === 'source') {
        // Git下载的源代码模式 - 调用pull_git_and_scan（包含拉取和扫描）
        this.pull_git_and_scan();
      } else {
        // 其他模式 - 直接开始扫描
        this.clickCreate();
      }
    },

    // 新增方法 - Git拉取和扫描集成
    pull_git_and_scan() {
      this.loading = true;
      var that = this;
      
      this.$refs.form.validate((valid) => {
        if (valid) {
          // 先执行Git拉取
          var folder_path = this.getPath();
          $.ajax({
            url: (http_head + '/Muti/'),
            data: {
              method: 'clone_git_repository',
              url: that.form.url_git,
              folder_path: folder_path,
              token: that.form.key_git,
              branch: that.form.branch,
              username: that.form.username_git,
              password: that.form.password_git,
              item_name: that.itemname,
            },
            type: 'post',
            dataType: 'JSON',
            success: function(res) {
              console.log('Git拉取响应:', res);
              
              if (res.code === '200') {
                // 使用后端返回的project_name作为任务名称
                that.form.taskName = res.project_name;
                that.folder_name_git = res.folder_name;
                that.url_git = res.url_git;
                
                mymessage.success("代码拉取成功，开始扫描...");
                
                // 拉取成功后立即开始扫描
                var strategy = that.policy.split(',');
                if (strategy[0] === 'Muti_transformer') {
                  that.Muti_detection();
                } else {
                  that.Muti_cus_detection(strategy[0]);
                }
              } else {
                that.loading = false;
                mymessage.error(res.msg || "拉取失败");
              }
            },
            error: function(err) {
              console.log(err);
              that.loading = false;
              mymessage.error("拉取失败");
            }
          });
        } else {
          this.loading = false;
          mymessage.error("请先填写必要信息");
        }
      });
    },

    // 新增方法 - 处理表格选择项变化
    handleSelectionChange(val) {
      this.multipleSelection = val;
    },

    // 新增方法 - 批量删除确认
    batchDeleteConfirm() {
      if (this.multipleSelection.length === 0) {
        this.$message.warning('请至少选择一个任务');
        return;
      }

      this.$confirm(`确定要删除选中的 ${this.multipleSelection.length} 个任务吗?`, '提示', {
        confirmButtonText: '确定',
        cancelButtonText: '取消',
        type: 'warning',
        beforeClose: (action, instance, done) => {
          if (action === 'confirm') {
            instance.confirmButtonLoading = true;
            this.batchDeleteTasks().finally(() => {
              instance.confirmButtonLoading = false;
              done();
            });
          } else {
            done();
          }
        }
      }).catch(() => {
        this.$message.info('已取消删除');
      });
    },

    // 新增方法 - 执行批量删除
    batchDeleteTasks() {
      this.batchDeleteLoading = true;
      const taskIds = this.multipleSelection.map(item => item.taskid).join(',');

      return new Promise((resolve, reject) => {
        $.ajax({
          url: (http_head + '/login/'),
          type: 'post',
          data: {
            method: 'tasks_batch_delete',
            taskid_list: taskIds
          },
          dataType: 'JSON',
          success: (res) => {
            if (res.code === '200') {
              this.$message.success(res.msg);
              this.getTableData(); // 刷新列表
              this.multipleSelection = []; // 清空选择

              // 清除本地存储中的进度
              const savedProgress = JSON.parse(localStorage.getItem("taskProgress") || "{}");
              this.multipleSelection.forEach(task => {
                delete savedProgress[task.taskid];
              });
              localStorage.setItem("taskProgress", JSON.stringify(savedProgress));
            } else {
              this.$message.error(res.msg || '删除失败');
            }
            resolve();
          },
          error: (err) => {
            console.error(err);
            this.$message.error('批量删除请求失败');
            reject(err);
          },
          complete: () => {
            this.batchDeleteLoading = false;
          }
        });
      });
    },

    goback(){
      sessionStorage.removeItem('config');
      sessionStorage.removeItem('itemname');
      window.location.href = 'ProjectList.html'
    },
    //上传文件
    getUpload(){
      this.uploadURLData = {method:'decompression', item_name: this.itemname,}
    },
    //刷新
    reload(){
      window.location.reload()
    },
    //查询
    checkFormData(){
      this.pageSize = 10;
      this.currentPage = 1;
      this.getTableData()
      this.ifidshowtag=true;
    },
    //获取保存的配置策略
    getConfig() {
      const that = this
      $.ajax({
        url:  (http_head + '/login/'),
        data:{
          method: 'get_Pol',
          account: localUser.account,
        },
        type : 'post',
        dataType : 'JSON',
        success : function (res){
          console.log('policy:',res)
          if(res) {
            that.policy = res.policy
            
            // 根据后端返回的policy设置默认扫描模式
            let defaultMode = 'rule5'; // 默认值
            
            // 解析policy字符串，设置对应的扫描模式
            if (res.policy.includes('rule7')) {
              defaultMode = 'rule7'; // 思考模式
            } else if (res.policy.includes('rule6')) {
              defaultMode = 'rule6'; // 降误报模型
            } else if (res.policy.includes('rule5')) {
              defaultMode = 'rule5'; // 快速扫描
            }
            // 如果有其他策略映射关系，可以在这里添加
            
            // 设置默认扫描模式
            that.defaultScanMode = defaultMode;
            that.scanMode = defaultMode;
            
            console.log('根据策略设置默认扫描模式为:', defaultMode);
          }
        },
        error: function (err) {
          console.log(err)
        }
      })
    },
    //上传成功时的钩子函数
    uploadSuccess(response, file, fileList){
      console.log(response)
      this.folder_name = response.folder_name
      // 根据接口返回判断是否完成
      if (response.code === '200') {
        this.isUploadCompleted = true;
        this.$message.success('文件上传并解压成功');
      } else {
        this.isUploadCompleted = false;
        this.$message.error(response.msg || '上传失败');
      }
    },
    handleRemove(file, fileList) {
      console.log(fileList);
      // 文件被移除时重置上传完成状态
      this.isUploadCompleted = false;
      this.folder_name = '';
    },
    handlePreview(file) {
      console.log(file);
    },
    beforeRemove(file, fileList) {
      return this.$confirm(`确定移除 ${ file.name }？`);
    },

    // 返回文件路径
    getPath(){
      var folder_path = ''
      if (this.isload == '本地上传') {
        folder_path = this.folder_name
      } else if (this.isload == 'SVN下载') {
        folder_path = this.folder_name_svn
      } else if (this.isload == 'Git下载') {
        folder_path = this.folder_name_git
      } else if (this.isload == 'FTP下载') {
        folder_path = this.form.target_remote_directory
      }
      return folder_path
    },
    // 点击“立即创建”
    clickCreate(){
      // 如果是本地上传模式，检查上传是否完成
      if (this.isload == '本地上传' && !this.isUploadCompleted) {
        this.$message.warning('请先上传并解压文件');
        return;
      }
      var folder_path = this.getPath()
      console.log(folder_path)
      var strategy = this.policy.split(',')
      if (strategy[0] === 'Muti_transformer') {
        this.Muti_detection()
      } else {
        // console.log(this.language)
        this.Muti_cus_detection(strategy[0])
      }
    },

//纯fortify扫描
    ruleScan(){
      var that = this
      // var str = this.policy.split(',')
      // var str1 = str[1]
      // var str2 = str[2]
      var folder_path = this.getPath()
      this.$refs.form.validate((valid) => {
        if (valid) {
          $.ajax({
            url:  (http_head + '/Muti/'),
            data:{
              method: 'fortify_only',
              template: 'Developer Workbook',    //没有配置选择界面后，固定传参，这是所有类型的漏洞
              version: 'Developer Workbook',
              folder_path: folder_path,
              item_id: that.itemid,
              task_name: that.form.taskName ? that.form.taskName : '',
              model_name: '1',
            },
            type : 'post',
            dataType : 'JSON',
            success : function (res){
              console.log(res)
              // mymessage.success("创建成功")
              if(res.code === '500'){
                that.ifSuccess = false      //?????这个东西哪来的
                mymessage.error(res.msg)
              }
            },
            error: function (err) {
              console.log(err)
              mymessage.error("创建失败")
            }
          })
          setTimeout(() => {
            if (this.ifSuccess === true){
              this.getTableData();
              // this.getAlert = false;
            }
            this.ifSuccess = true     //不然直接改名字之后，ifSuccess值还是false，弹窗不会消失
          }, 500);

        } else {
          mymessage.error("请先填写信息");
          return false;
        }

      })
    },


// 自定义规则单独扫描
    async customRule(){
      var folder_path = this.getPath()
      var that = this
      this.$refs.form.validate((valid) => {
        if (valid) {
          $.ajax({
            url:  (http_head + '/Muti/'),
            data:{
              method: 'rule_detection',
              folder_name: folder_path,
              item_id: that.itemid,
              task_name: that.form.taskName ? that.form.taskName : '',
              language:that.language,
            },
            type : 'post',
            dataType : 'JSON',
            success : function (res){
              console.log(res)
              // mymessage.success("创建成功")
              if(res.code === '500'){
                that.ifSuccess = false
                mymessage.error(res.msg)
                // mymessage.error("任务名称已存在，请修改任务名")
              }
            },
            error: function (err) {
              console.log(err)
              mymessage.error("创建失败")
            }
          })
        } else {
          mymessage.error("请先填写信息");
          return false;
        }
      })
      try {
        await this.getTableData();
        this.getAlert = false;
      } catch (err) {

      }
    },

// 多分类检测
    Muti_detection(){
      var folder_path = this.getPath()
      var that = this
      this.$refs.form.validate((valid) => {
        if (valid) {
          $.ajax({
            url:  (http_head + '/Muti_transformer/'),
            data:{
              method:'muti_transformer_detection',
              folder_path: folder_path,
              item_id: that.itemid,
              task_name:that.form.taskName ? that.form.taskName : '',
              language:that.language,
            },
            type : 'post',
            dataType : 'JSON',
            success : function (res){
              console.log(res)
              // mymessage.success("创建成功")
              if(res.code === '500'){
                that.ifSuccess = false
                mymessage.error(res.msg)
              }
            },
            error: function (err) {
              console.log(err)
              mymessage.error("创建失败")
            }
          })
          setTimeout(() => {
            if (this.ifSuccess === true){
              this.getTableData();
              // this.getAlert = false;    //弹窗消失后form的数据就消失了
            }
            this.ifSuccess = true     //不然直接改名字之后，ifSuccess值还是false，弹窗不会消失
          }, 200);

        } else {
          mymessage.error("请先填写信息");
          return false;
        }
      })
    },
// 多分类模型和自定义规则和fortify合并   now
    async Muti_cus_detection(type) {
      var folder_path = this.getPath();
      var that = this;

      // 只在非Git下载源代码模式下检查任务名称
      if (!(this.isload == 'Git下载' && this.fileType === 'source') && this.form.taskName == '') {
        mymessage.error("尚未填写任务名！");
        return false;
      }

      let model = '';
      let deepseek = 'false';
      switch (this.scanMode) {
        case 'rule5': // 快速扫描
          deepseek = 'false';
          model = 'rule';
          break;
        case 'rule6': // 降误报模型
          deepseek = 'true';
          model = 'rule';
          break;
        case 'rule7': // 思考模式
          deepseek = 'true';
          model = 'r4';
          break;
        default:
          deepseek = 'false';
          model = 'rule';
      }
      // if (type === 'rule3') {
      //   model = 'fortify';
      // } else
      // if (type === 'rule5') {
      //   deepseek = 'false';
      //   model = 'rule'
      // } else if (type === 'rule6') {
      //   deepseek = 'true';
      //   model = 'rule'
      // } else if (type === 'Muti_transformer') {
      //   model = 'small_model'
      //   deepseek = 'false'
      // } else if (type === 'rule7') {
      //   model = 'r4'
      //   deepseek = 'true'
      // }

      this.$refs.form.validate(async (valid) => {
        if (valid) {
          try {
            // 在调用 $.ajax 之前设置 setTimeout
            setTimeout(async () => {
              await that.getTableData();
              // 在 getTableData 完成后执行 this.getAlert = false
              that.getAlert = false;
            }, 500); // 0.5 秒

            // 调用 $.ajax
            const res = await $.ajax({
              url: http_head + '/create_process/',
              data: {
                method: 'create_queue',
                folder_path: folder_path,
                item_id: that.itemid,
                task_name: that.form.taskName ? that.form.taskName : '',
                template: 'Developer Workbook',
                version: 'Developer Workbook',
                language: that.language,
                branch: that.form.branch ? that.form.branch : '',
                deepseek: deepseek,
                model: model,
                url_git: that.url_git
              },
              type: 'post',
              dataType: 'JSON',
            });

            console.log(res);
            if (res.code === '500'|| res.code === '400') {
              that.ifSuccess = false;
              mymessage.error(res.msg);
            }
            // 扫描成功后重置为默认模式
            that.scanMode = that.defaultScanMode;
          } catch (err) {
            console.log(err);
            mymessage.error("创建失败");
          }
        } else {
          mymessage.error("请先填写信息");
          return false;
        }
      });
    },
//git拉取
    pull_git() {
      this.loading = true
      var that = this
      var folder_path = this.getPath();
      $.ajax({
        url:  (http_head + '/Muti/'),
        data:{
          method:'clone_git_repository',
          url: that.form.url_git,
          folder_path: folder_path,
          token: that.form.key_git,    //密钥
          branch: that.form.branch,   //分支
          username:that.form.username_git,   //账号
          password:that.form.password_git,   //密码
          item_name: that.itemname,   //项目名
        },
        type : 'post',
        dataType : 'JSON',
        success : function (res){
          console.log('form: ',that.form)
          console.log(res)
          // mymessage.success("创建成功")
          that.loading = false
          that.pullSuccess = true   //拉取成功之后才可以填任务名称和任务描述
          mymessage.success("拉取成功！")
          that.folder_name_git = res.folder_name
          that.url_git = res.url_git
          console.log(that.url_git)
        },
        error: function (err) {
          console.log(err)
          mymessage.error("创建失败")
        }
      })
    },
//svn拉取
    pull_svn() {
      this.loading = true
      var that = this
      $.ajax({
        url:  (http_head + '/Muti/'),
        data:{
          method:'clone_svn_repository',
          url: that.form.url_svn,
          username: that.form.zhanghao,
          password: that.form.key_svn,
          item_name: that.itemname,   //项目名
        },
        type : 'post',
        dataType : 'JSON',
        success : function (res){
          console.log(res)
          that.loading = false
          if(res.code === '200'){
            mymessage.success("拉取成功！")
            that.pullSvnSuccess = true
            that.folder_name_svn = res.folder_name
          }
        },
        error: function (err) {
          console.log(err)
          mymessage.error("创建失败")
        }
      })
    },
    // ftp传输
    pull_ftp(){
      this.loading = true
      var that = this
      $.ajax({
        url:  (http_head + '/login/'),
        data:{
          method:'transfer_file_via_ftp',
          source_ftp_host: that.form.source_ftp_host,
          source_ftp_user: that.form.source_ftp_user,
          source_ftp_password: that.form.source_ftp_password,
          source_remote_directory: that.form.source_remote_directory,
          source_file_name: that.form.source_file_name,
          target_ftp_host: that.form.target_ftp_host,
          target_ftp_user: that.form.target_ftp_user,
          target_ftp_password: that.form.target_ftp_password,
          target_remote_directory: that.form.target_remote_directory,
        },
        type : 'post',
        dataType : 'JSON',
        success : function (res){
          console.log(res)
          that.loading = false
          if(res.msg === '文件传输成功'){
            mymessage.success(res.msg)
            that.pullFtpSuccess = true
          } else {
            mymessage.error(res.msg)
          }
        },
        error: function (err) {
          console.log(err)
          mymessage.error("创建失败")
        }
      })
    },

    resetForm() {   //不刷新页面再次点击时不会出现上一次填的内容
      this.form = {
        taskName:'',
        description:'',
        language: '',
        source:'',
        url_git:'',
        key_git:'',
        branch:'',
        taskName:'',
        description:'',
        url_svn:'',
        zhanghao:'',
        key_svn:'',
        taskName:'',
        description:'',
        username_git:'',
        password_git:'',

        source_ftp_host:'',
        source_ftp_user:'',
        source_ftp_password:'',
        source_remote_directory:'',
        source_file_name:'',
        target_ftp_host:'',
        target_ftp_user:'',
        target_ftp_password:'',
        target_remote_directory:'',
      }
      this.uploadFileList = [];
      this.pullSuccess = false;
      // 重置上传完成状态
      this.isUploadCompleted = false;
      // 重置文件类型为默认值
      this.fileType = 'source';
      // 重置扫描模式为默认值
      this.scanMode = this.defaultScanMode;
    },

    // deepSeek扫描 svn
    deepScansvn(){
      var that = this
      var modelName
      if(this.policy === 'deepSeek'){
        modelName = 'deepseek-1.3b'
      } else if(this.policy === 'deepSeek_6.7b'){
        modelName = 'deepseek-6.7b'
      } else if(this.policy === 'rule4'){
        modelName = 'qwen-7b'
      }
      $.ajax({
        url:  (http_head + '/Muti/'),
        data:{
          method:'deepseek_detection',
          folder_name: that.folder_name_svn,
          item_id: that.itemid,
          task_name: that.form.taskName ? that.form.taskName : '',   //任务名
          model_name: modelName,
        },
        type : 'post',
        dataType : 'JSON',
        success : function (res){
          console.log(res)
          // mymessage.success("创建成功")

          if(res.code === '500'){
            mymessage.error(res.msg)
            that.ifSuccess = false
          }
        },
        error: function (err) {
          console.log(err)
          mymessage.error("创建失败")
        }
      })

      setTimeout(() => {
        if (this.ifSuccess === true){
          this.getTableData();
          // this.getAlert = false;
        }
        this.ifSuccess = true
        // debugger
      }, 200);

    },
    // deepSeek扫描 本地
    deepScan(){
      var that = this
      var modelName
      if(this.policy === 'deepSeek'){
        modelName = 'deepseek-1.3b'
      } else if(this.policy === 'deepSeek_6.7b'){
        modelName = 'deepseek-6.7b'
      } else if(this.policy === 'rule4'){
        modelName = 'qwen-7b'
      }
      $.ajax({
        url:  (http_head + '/Muti/'),
        data:{
          method:'deepseek_detection',
          folder_name: that.folder_name,
          item_id: that.itemid,
          task_name: that.form.taskName ? that.form.taskName : '',   //任务名
          model_name: modelName,
        },
        type : 'post',
        dataType : 'JSON',
        success : function (res){
          console.log(res)
          // mymessage.success("创建成功")

          if(res.code === '500'){
            mymessage.error(res.msg)
            that.ifSuccess = false
          }
        },
        error: function (err) {
          console.log(err)
          mymessage.error("创建失败")
        }
      })

      setTimeout(() => {
        if (this.ifSuccess === true){
          this.getTableData();
          // this.getAlert = false;
        }
        this.ifSuccess = true
        // debugger
      }, 200);

    },
    // deepSeek扫描 git
    create_deepSeek2(){
      var that = this
      var modelName
      if(this.policy === 'deepSeek'){
        modelName = 'deepseek-1.3b'
      } else if(this.policy === 'deepSeek_6.7b'){
        modelName = 'deepseek-6.7b'
      } else if(this.policy === 'rule4'){
        modelName = 'qwen-7b'
      }
      $.ajax({
        url:  (http_head + '/Muti/'),
        data:{
          method:'deepseek_detection',
          folder_name: that.folder_name_git,
          item_id: that.itemid,
          task_name: that.form.taskName ? that.form.taskName : '',   //任务名
          model_name: modelName,
        },
        type : 'post',
        dataType : 'JSON',
        success : function (res){
          console.log(res)
          // mymessage.success("创建成功")
        },
        error: function (err) {
          console.log(err)
          mymessage.error("创建失败")
        }
      })
      setTimeout(() => {
        this.getTableData();
        // this.getAlert = false;
      }, 200);
    },

    getTableData() {
      var that = this;
      function stopPolling() {
        if (that.pollingInterval) {
          clearInterval(that.pollingInterval); // 清除定时器
          that.pollingInterval = null; // 重置变量
        }
      }
      function startPolling() {
        stopPolling(); // 先停止任何现有的定时器
        that.pollingInterval = setInterval(() => {
          that.getTableData(); // 定期调用函数
        }, 5000); // 每5秒调用一次
      }
      // 从 localStorage 获取进度
      const savedProgress = JSON.parse(localStorage.getItem("taskProgress") || "{}");
      // 防止并发请求
      if (this.isRequestInProgress) {
        console.log("已有请求进行中，跳过本次调用");
        return;
      }
      this.isRequestInProgress = true; // 标记请求开始
      $.ajax({
        url: (http_head + '/login/'),
        data: {
          method : 'task_list',
          taskid : '',
          taskname : that.query.project_name ,
          itemid : that.itemid,
          itemname : '',
          language : '',
          type : '',
          review_status : '',
          source : '',
          creator : '',
          starttime : '',
          page : that.currentPage,
          rows : that.pageSize,
        },
        type: 'post',
        dataType: 'JSON',
        success: function (res) {
          // console.log(res);
          that.isRequestInProgress = false; // 标记请求结束
          // that.itemName = that.itemname; // 确保 this.itemname 是正确的
          if (res.count > 0) {
            const newData = res.data.map((item) => {
              // 如果任务已经存在于当前数据中，保留其 progress
              const existingItem = that.tableData.find((t) => t.taskid === item.taskid);
              if (existingItem) {
                item.progress = existingItem.progress;
                item.interval = existingItem.interval;
              } else {
                // 从本地存储恢复进度
                item.progress = savedProgress[item.taskid] || 0;
              }
              return item;
            });
            // 深度比较新数据与当前数据
            // if (JSON.stringify(newData) !== JSON.stringify(that.tableData)) {
            // 浅比较
            if (!that.tableData || that.tableData.length !== newData.length || that.delFlag === true || that.oldcurrentPage != that.currentPage ||
              that.tableData.some((item, index) => item.statues !== newData[index].statues)) {
              // console.log("数据发生变化，更新表格");
              that.tableData = newData; // 只有在数据变化时更新
              that.count = res.count;
              that.idshowtext = newData[0].taskid;
              that.oldcurrentPage = that.currentPage;
            } else {
              console.log("数据未发生变化，无需更新表格");
            }
            that.delFlag = false
            // 更新进度条
            newData.forEach((item) => {
              if (item.statues === "正在检测") {
                if (!item.interval) {
                  item.interval = setInterval(() => {
                    if (item.progress < 95) {
                      item.progress += 1; // 增加进度
                      // 保存进度到 localStorage
                      savedProgress[item.taskid] = item.progress;
                      localStorage.setItem("taskProgress", JSON.stringify(savedProgress));
                      // console.log(`任务 ${item.taskid} 进度: ${item.progress}`);
                    } else if (item.statues === "检测完成") {
                      item.progress = 100; // 设置为100%
                      clearInterval(item.interval);
                      item.interval = null;
                      savedProgress[item.taskid] = item.progress;
                      localStorage.setItem("taskProgress", JSON.stringify(savedProgress));
                    }
                  }, 5000); // 每秒更新一次
                }
              } else {
                item.progress = item.statues === "检测完成" ? 100 : 0;
                clearInterval(item.interval);
                item.interval = null;
              }
            });
            // 检查是否有未完成的任务
            const hasIncompleteTasks = newData.some(
              (item) => item.statues !== "检测完成" && item.statues !== "检测失败"
            );
            // console.log('是否有正在检测', hasIncompleteTasks);

            // 根据是否有未完成的任务来启动或停止轮询
            if (hasIncompleteTasks) {
              startPolling();
            } else {
              stopPolling();
            }
          } else {
            that.tableData = [];
            that.count = 0
            stopPolling(); // 确保在没有数据时停止轮询
          }
          if (res.code === '500') {
            stopPolling(); // 扫描出错时停止轮询
          }
          // that.getAlert = false;
        },
        error: function (err) {
          that.getAlert = false;
          that.isRequestInProgress = false;
          console.log(err);
          mymessage.error("任务列表获取失败");
          stopPolling(); // 在出错时也停止轮询
        }
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
      this.getTableData()

    },
    //结果审核
    result(row){
      sessionStorage.setItem('taskid_result',JSON.stringify(row.taskid))
      // localStorage.removeItem("taskProgress")
      window.location.href = 'resultReview.html'
    },
    //任务详情
    view(row){
      console.log(row)
      sessionStorage.setItem('taskid',JSON.stringify(row.taskid))
      sessionStorage.setItem('itemid',JSON.stringify(row.itemid))
      sessionStorage.setItem('project_page2',JSON.stringify(this.currentPage))
      sessionStorage.setItem('project_rows2',JSON.stringify(this.pageSize))
      window.open('ProjectDetail.html')
    },

    //跳转到圈复杂度页面
    gotoCCN(row){
      sessionStorage.setItem('taskid',JSON.stringify(row.taskid))
      window.location.href = '../ccn/taskCCN.html'
    },

    //删除
    delopen(row) {
      const that = this;
      this.$confirm('此操作将删除该任务, 是否继续?', '提示', {
        confirmButtonText: '确定',
        cancelButtonText: '取消',
        type: 'warning',
        beforeClose: (action, instance, done) => {
          if (action === 'confirm') {
            instance.confirmButtonLoading = true;
            that.del(row)
              .then(() => {
                done();
              })
              .catch(() => {
                done();
              })
              .finally(() => {
                instance.confirmButtonLoading = false;
              });
          } else {
            done();
          }
        }
      }).catch(() => {
        this.$message({
          type: 'info',
          message: '已取消删除'
        });
      });
    },
    del(row) {
      console.log(row)
      var that = this;
      return new Promise((resolve, reject) => {
        $.ajax({
          url: (http_head + '/login/'),
          data: {
            method: 'task_delete',
            taskid: row.taskid,
          },
          type: 'post',
          dataType: 'JSON',
          success: function(res) {
            console.log(res);
            if (res.code == '200') {
              mymessage.success(res.msg)
              //删除之后下一个新增的任务,任务id和上一个一样，会保持删掉的任务的进度，所以得置0
              const savedProgress = JSON.parse(localStorage.getItem("taskProgress") || "{}");
              savedProgress[row.taskid] = 0;
              localStorage.setItem("taskProgress", JSON.stringify(savedProgress));

              that.delFlag = true
              that.getTableData()
              resolve(); // 成功时resolve
            } else {
              mymessage.error(res.msg)
              reject(res.msg); // 失败时reject
            }
          },
          error: function(err) {
            console.log(err)
            mymessage.error("删除失败")
            reject(err); // 出错时reject
          }
        });
      });
    },

    // 重新扫描
    doubleScan(row){
      console.log(row)
      let ds, md;
      try {
        const type = JSON.parse(row.type.replace(/'/g, '"'));
        if (Array.isArray(type) && type.length >= 2) {
          if (type[0] === 'true' || type[0] === 'false'){
            ds = type[0];
            md = type[1];
          } else {
            ds = type[1];
            md = type[0];
          }
        } else {
          console.warn('策略返回错误');
          return;
          // 可以在这里设置默认值
          ds = null;
          md = null;
        }
      } catch (e) {
        mymessage.error("当前任务不支持重新扫描！")
        return
        // 解析失败时的处理
        ds = null;
        md = null;
      }
      console.log('deepseek,model:',ds,md)
      if (row.folder_path === '' || row.itemid === '' || row.taskname === '' || row.language === '' || !row.folder_path) {
        mymessage.error("当前任务不支持重新扫描！")
        return;
      }
      if (ds !== 'true' && ds !== 'false') {
        mymessage.error("当前任务不支持重新扫描！")
        return;
      }
      var that = this;
      $.ajax({
        url: http_head + '/create_process/',
        data: {
          method: 'create_queue',
          folder_path: row.folder_path,
          item_id: row.itemid,
          task_name: row.taskname + ' (' + getCurrentDate(2) + ')重新扫描',
          template: 'Developer Workbook',
          version: 'Developer Workbook',
          language: row.language,
          branch: row.branch,
          model: md,
          deepseek: ds,
          url_git: row.url_git || ''  // 如果 row.url_git 存在就传递，否则传空字符串
        },
        type: 'post',
        dataType: 'JSON',
        success : function (res){
          console.log(res)
          that.getTableData()
          // mymessage.success("创建成功")
        },
        error: function (err) {
          // console.log(err)
          mymessage.error("创建失败")
        }
      })

    },

    // 点击任务日志
    clickLog(row){
      this.currentLog_id = row.taskid;
      console.log(this.currentLog_id)
      this.getLog()
      this.logVisible = true

    },
    // 获取任务日志
    getLog(){
      var start_time = this.logQuery.logtime ? this.logQuery.logtime[0] : ''
      var end_time = this.logQuery.logtime ? this.logQuery.logtime[1] : ''
      var that = this;
      $.ajax({
        url:  (http_head + '/login/'),
        data:{
          method : 'query_audit_log',
          taskid : that.currentLog_id,
          fileid:'',
          filename: that.logQuery.filename ? that.logQuery.filename : '',
          filepath: that.logQuery.filepath ? that.logQuery.filepath : '',
          start_time: start_time,
          end_time: end_time,
        },
        type : 'post',
        dataType : 'JSON',
        success : function (res){
          console.log(111);
          console.log(res);
          if(res.data){
            res.data.forEach(item => {
              const date = new Date(item.update_time);
              const newDateString = date.toLocaleString("zh-CN", {
                year: "numeric",
                month: "2-digit",
                day: "2-digit",
                hour: "2-digit",
                minute: "2-digit",
                second: "2-digit",
                hour12: false, // 使用 24 小时制
              });
              item.update_time = newDateString
            })
            that.auditLog = res.data;
          }
        },
        error: function (err) {
          console.log(err)
          mymessage.error("日志获取失败")
        }
      })
    },

  beforeDestroy() {
    if (this.pollingInterval) {
      clearInterval(this.pollingInterval);
    }
  },

  // 批量上传前的验证
  beforeBatchUpload(file) {
    const isExcel = file.type === 'application/vnd.ms-excel' || 
                   file.type === 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet';
    const isLt10M = file.size / 1024 / 1024 < 10;
    
    if (!isExcel) {
      this.$message.error('只能上传Excel文件!');
      return false;
    }
    if (!isLt10M) {
      this.$message.error('文件大小不能超过10MB!');
      return false;
    }
    return true;
  },
  
  // 批量上传成功处理方法
  handleBatchUploadSuccess(response, file, fileList) {
    console.log('批量上传响应:', response);
    if (response.code === '200') {
      this.$message.success(response.msg || `成功提取 ${response.count} 个Git仓库信息`);
      // 使用后端返回的git_repos数据，适配新的字段名
      this.gitUrlList = response.git_repos.map(item => ({
        url: item.git_url,  // 使用git_url字段
        username: item.username || '',
        password: item.password || '',
        key: item.key || '',
        branch: item.branch || '',  // 确保分支信息被正确映射
        row_number: item.row_number, // 保留行号信息
        status: '等待中',
        progress: 0,
        message: ''
      }));
    } else {
      this.$message.error(response.msg || '文件处理失败');
    }
  },
  
  // 批量文件移除
  handleBatchRemove(file, fileList) {
    this.gitUrlList = [];
    this.totalProgress = 0;
    this.processedCount = 0;
  },
  
  beforeBatchRemove(file, fileList) {
    return this.$confirm(`确定移除 ${file.name}？这将清空Git地址列表`);
  },
  
  // 清空Git地址列表
  clearGitUrlList() {
    this.$confirm('确定要清空Git地址列表吗？', '提示', {
      confirmButtonText: '确定',
      cancelButtonText: '取消',
      type: 'warning'
    }).then(() => {
      this.gitUrlList = [];
      this.totalProgress = 0;
      this.processedCount = 0;
    });
  },
  
  // 重置批量表单
  resetBatchForm() {
    this.batchForm = {
      username_git: '',
      password_git: '',
      key_git: '',
      branch: ''
    };
    this.batchFileList = [];
    this.gitUrlList = [];
    this.totalProgress = 0;
    this.processedCount = 0;
    this.batchStatus = '';
    this.currentProcessingIndex = 0;
  },
  
  // 批量拉取Git仓库
  async batchPullGit() {
    if (this.gitUrlList.length === 0) {
      this.$message.warning('请先上传Excel文件');
      return;
    }
    
    this.batchLoading = true;
    this.batchStatus = 'processing';
    this.processedCount = 0;
    this.totalProgress = 0;
    
    // 依次处理每个Git地址
    for (let i = 0; i < this.gitUrlList.length; i++) {
      this.currentProcessingIndex = i;
      const gitItem = this.gitUrlList[i];
      
      try {
        // 更新状态为处理中
        gitItem.status = '处理中';
        gitItem.progress = 0;
        
        // 模拟进度更新（实际调用接口时会根据实际情况更新）
        const progressInterval = setInterval(() => {
          if (gitItem.progress < 90) {
            gitItem.progress += 10;
          }
        }, 500);
        
        // 调用单个Git仓库处理接口
        const result = await this.processSingleGitRepository(gitItem, i);
        
        clearInterval(progressInterval);
        
        if (result.success) {
          gitItem.status = '成功';
          gitItem.progress = 100;
          gitItem.message = '处理完成';
        } else {
          gitItem.status = '失败';
          gitItem.progress = 100;
          gitItem.message = result.message || '处理失败';
        }
        
      } catch (error) {
        gitItem.status = '失败';
        gitItem.progress = 100;
        gitItem.message = '请求失败';
        console.error(`处理Git地址失败: ${gitItem.url}`, error);
      }
      
      // 更新总体进度
      this.processedCount++;
      this.totalProgress = Math.round((this.processedCount / this.gitUrlList.length) * 100);
      
      // 短暂延迟，避免请求过于频繁
      await this.delay(1000);
    }
    
    this.batchLoading = false;
    this.batchStatus = 'completed';
    this.$message.success('批量处理完成');
    // 批量扫描完成后重置为默认模式
    this.scanMode = this.defaultScanMode;
    
    // 处理完成后刷新任务列表
    setTimeout(() => {
      this.getTableData();
    }, 1000);
  },
  
  // 处理单个Git仓库
  processSingleGitRepository(gitItem, index) {
    return new Promise((resolve) => {
      const that = this;
      
      // 使用从Excel中获取的认证信息
      const username = gitItem.username;
      const password = gitItem.password;
      const key = gitItem.key;
      const branch = gitItem.branch;
      
      // 构建认证URL
      let authUrl = gitItem.url;
      if (username && password) {
        if (gitItem.url.startsWith('http://')) {
          authUrl = gitItem.url.replace('http://', `http://${username}:${password}@`);
        } else if (gitItem.url.startsWith('https://')) {
          authUrl = gitItem.url.replace('https://', `https://${username}:${password}@`);
        }
      }
      
      // 生成任务名称，使用行号来区分相同URL
      const baseName = gitItem.url.split('/').pop().replace('.git', '') || `repo_${gitItem.row_number}`;
      const taskName = `${baseName}_batch_${getCurrentDate(2)}`;
      
      // 调用批量克隆接口
      $.ajax({
        url: http_head + '/Muti/',
        data: {
          method: 'clone_git_repositories',
          urls: gitItem.url, 
          token: key,  // 使用Excel中的密钥
          item_name: this.itemname,
          username: username,  // 使用Excel中的用户名
          password: password,  // 使用Excel中的密码
          branch: branch,      // 使用Excel中的分支
        },
        type: 'post',
        dataType: 'JSON',
        success: function(res) {
          console.log(`Git仓库 ${index + 1} 处理结果:`, res);
          if (res.code === '200') {
            // 查找当前URL对应的结果
            const result = res.results.find(r => r.url === gitItem.url);
            if (result && result.success) {
              // 克隆成功后创建扫描任务
              that.createScanTask(result.folder, taskName, gitItem.url, branch)
                .then(scanRes => {
                  resolve({
                    success: true,
                    message: '扫描任务创建成功'
                  });
                })
                .catch(error => {
                  resolve({
                    success: false,
                    message: '扫描任务创建失败'
                  });
                });
            } else {
              resolve({
                success: false,
                message: result ? result.message : '克隆失败'
              });
            }
          } else {
            resolve({
              success: false,
              message: res.msg || '克隆失败'
            });
          }
        },
        error: function(err) {
          console.error(`Git仓库 ${index + 1} 请求失败:`, err);
          resolve({
            success: false,
            message: '请求失败'
          });
        }
      });
    });
  },
  
  // 创建扫描任务
  createScanTask(folderPath, taskName, gitUrl, branch) {
    return new Promise((resolve, reject) => {
      const that = this;
      
      // 使用与单个任务相同的扫描逻辑
      const strategy = this.policy.split(',');
      let model = '';
      let deepseek = 'false';
      switch (this.scanMode) {
        case 'rule5': // 快速扫描
          deepseek = 'false';
          model = 'rule';
          break;
        case 'rule6': // 降误报模型
          deepseek = 'true';
          model = 'rule';
          break;
        case 'rule7': // 思考模式
          deepseek = 'true';
          model = 'r4';
          break;
        default:
          deepseek = 'false';
          model = 'rule';
      }
      
      // if (strategy[0] === 'rule3') {
      //   model = 'fortify';
      // } else if (strategy[0] === 'rule5') {
      //   deepseek = 'false';
      //   model = 'rule';
      // } else if (strategy[0] === 'rule6') {
      //   deepseek = 'true';
      //   model = 'rule';
      // } else if (strategy[0] === 'Muti_transformer') {
      //   model = 'small_model';
      //   deepseek = 'false';
      // } else if (strategy[0] === 'rule7') {
      //   model = 'r4';
      //   deepseek = 'true';
      // }
      
      $.ajax({
        url: http_head + '/create_process/',
        data: {
          method: 'create_queue',
          folder_path: folderPath,
          item_id: that.itemid,
          task_name: `${taskName}_${getCurrentDate(2)}`,
          template: 'Developer Workbook',
          version: 'Developer Workbook',
          language: that.language,
          branch: branch || that.batchForm.branch,  // 使用传入的分支参数，如果没有则传空字符串
          deepseek: deepseek,
          model: model,
          url_git: gitUrl
        },
        type: 'post',
        dataType: 'JSON',
        success: function(res) {
          if (res.code === '200') {
            resolve(res);
          } else {
            reject(res);
          }
          // 扫描成功后重置为默认模式
          that.scanMode = that.defaultScanMode;
        },
        error: function(err) {
          reject(err);
        }
      });
    });
  },
  
  // 延迟函数
  delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  },

  },
});


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
};


