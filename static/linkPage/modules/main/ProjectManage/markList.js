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
    this.isload = JSON.parse(sessionStorage.getItem('source') || '本地')
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
  },
  data() {
    return {
      language:'',
      query:{
        project_name:''
      },
      isload :'本地',
      tableData: [],
      currentPage: 1, //当前页 刷新后默认显示第一页
      pageSize: 10, //每一页显示的数据量 此处每页显示6条数据
      count:10,
      itemname:'',
      itemName:'',
      itemid:'',
      ifSuccess:true,
      ifidshowtag:false,
      idshowtext:'',
      getAlert:false,
      pullSuccess:false,
      pullSvnsuccess:false,
      form:{
        taskName:'',
        description:'',
        language: 'java',
        source:'本地',

      },
      uploadURL:http_head + '/Muti/',
      uploadURLData:{method:'decompression',item_name:'',},
      uploadFileList: [],
      policy:'',
      folder_name:'',

      isShowList: true,
      fileListTrain: [],
      rules:{
        taskName: [
          { required: true, message: '请输入任务名称', trigger: 'blur' },
        ],
        language: [
          { required: true, message: '请选择代码语言', trigger: 'blur' },
        ],
        source: [
          { required: true, message: '请选择代码来源', trigger: 'blur' },
        ],
      },
      loading:false,
      form2:{
        url:'',
        key:'',
        branch:'',
        taskName:'',
        description:'',
      },
      folder_name_git:'',

      rules2:{
        url: [
          { required: true, message: '请输入地址', trigger: 'blur' },
        ],
        key: [
          { required: true, message: '请输入密钥', trigger: 'blur' },
        ],
        taskName: [
          { required: true, message: '请输入任务名', trigger: 'blur' },
        ]
      },

      form3:{
        url:'',
        zhanghao:'',
        key:'',
        taskName:'',
        description:''
      },
      folder_name_svn:'',
      rules3:{
        url: [
          { required: true, message: '请输入地址', trigger: 'blur' },
        ],
        zhanghao: [
          { required: true, message: '请输入账号', trigger: 'blur' },
        ],
        key: [
          { required: true, message: '请输入密码', trigger: 'blur' },
        ]
      },
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

    }
  },
  methods: {
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
          }
        },
        error: function (err) {
          console.log(err)
        }
      })
    },
    //上传成功时的钩子函数
    uploadSuccess(response,file,fileList){
      // console.log(fileList)
      console.log(response)
      this.folder_name = response.folder_name
    },
    handleRemove(file, fileList) {
      console.log(fileList);
      // this.uploadFileList = fileList
      // this.dataForm.file = fileList
    },
    handlePreview(file) {
      console.log(file);
    },
    beforeRemove(file, fileList) {
      return this.$confirm(`确定移除 ${ file.name }？`);
    },

    // 点击“立即创建”
    createLocal(){
      var strategy = this.policy.split(',')
      // console.log(strategy)
      if(strategy[0] === 'rule1' || strategy[0] === 'rule2' || strategy[0] === 'rule0'){
        this.genScan()
      } else if(strategy[0] === 'rule3') {
        this.ruleScan()
      }else if(strategy[0] === 'deepSeek' || strategy[0] === 'deepSeek_6.7b' || strategy[0] === 'rule4') {
        this.deepScan()
      } else if (strategy[0] === 'rule5') {
        this.customRule()
      } else if (strategy[0] === 'Muti_transformer') {
        this.Muti_detection()
      } else {
        this.smallScan()
      }
    },
    //创建SVN任务
    createSVN(){
      var strategy = this.policy.split(',')
      console.log(strategy)
      if(strategy[0] === 'rule1' || strategy[0] === 'rule2' || strategy[0] === 'rule0'){
        this.genScansvn()
      } else if(strategy[0] === 'rule3') {
        this.ruleScansvn()
      }else if(strategy[0] === 'deepSeek' || strategy[0] === 'deepSeek_6.7b' || strategy[0] === 'rule4') {
        this.deepScansvn()
      } else if (strategy[0] === 'rule5') {
        this.customRule()
      } else {
        this.smallScan()
      }
    },
    //fortify扫描   svn
    ruleScansvn(){
      var that = this
      var str = this.policy.split(',')
      var str1 = str[1]
      var str2 = str[2]
      this.$refs.form3.validate((valid) => {
        if (valid) {
          $.ajax({
            url:  (http_head + '/Muti/'),
            data:{
              method: 'fortify_only',
              template: str1,
              version: str2,
              folder_path: that.folder_name_svn,
              item_id: that.itemid,
              task_name: that.form3.taskName ? that.form3.taskName : '',
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
              this.getAlert = false;
            }
            this.ifSuccess = true     //不然直接改名字之后，ifSuccess值还是false，弹窗不会消失
          }, 200);

        } else {
          mymessage.error("请先填写信息");
          return false;
        }

      })
    },
    //fortify扫描   本地
    ruleScan(){
      var that = this
      var str = this.policy.split(',')
      var str1 = str[1]
      var str2 = str[2]
      this.$refs.form.validate((valid) => {
        if (valid) {
          $.ajax({
            url:  (http_head + '/Muti/'),
            data:{
              method: 'fortify_only',
              template: str1,
              version: str2,
              folder_path: that.folder_name,
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
              this.getAlert = false;
            }
            this.ifSuccess = true     //不然直接改名字之后，ifSuccess值还是false，弹窗不会消失
          }, 200);

        } else {
          mymessage.error("请先填写信息");
          return false;
        }

      })
    },
    // codegen扫描  svn
    genScansvn(){
      var that = this
      var str = this.policy.split(',')
      if(str[0] === 'rule1') {
        var modelName = '0'
      } else if(str[0] === 'rule2') {
        var modelName = '1'
      } else if(str[0] === 'rule0') {
        var modelName = '2'
      }
      var str1 = str[1]
      var str2 = str[2]
      this.$refs.form3.validate((valid) => {
        if (valid) {
          $.ajax({
            url:  (http_head + '/Muti/'),
            data:{
              method: 'fortify_01_detection',
              template: str1 ? str1 : '',
              version: str2 ? str2 : '',
              folder_path: that.folder_name_svn,
              item_id: that.itemid,
              task_name: that.form3.taskName ? that.form3.taskName : '',
              model_name: modelName,
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
          setTimeout(() => {
            if (this.ifSuccess === true){
              this.getTableData();
              this.getAlert = false;
            }
            this.ifSuccess = true     //不然直接改名字之后，ifSuccess值还是false，弹窗不会消失
          }, 200);

        } else {
          mymessage.error("请先填写信息");
          return false;
        }

      })
    },
    // codegen扫描  本地
    genScan(){
      var that = this
      var str = this.policy.split(',')
      if(str[0] === 'rule1') {
        var modelName = '0'
      } else if(str[0] === 'rule2') {
        var modelName = '1'
      } else if(str[0] === 'rule0') {
        var modelName = '2'
      }
      var str1 = str[1]
      var str2 = str[2]
      this.$refs.form.validate((valid) => {
        if (valid) {
          $.ajax({
            url:  (http_head + '/Muti/'),
            data:{
              method: 'fortify_01_detection',
              template: str1 ? str1 : '',
              version: str2 ? str2 : '',
              folder_path: that.folder_name,
              item_id: that.itemid,
              task_name: that.form.taskName ? that.form.taskName : '',
              model_name: modelName,
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
          setTimeout(() => {
            if (this.ifSuccess === true){
              this.getTableData();
              this.getAlert = false;
            }
            this.ifSuccess = true     //不然直接改名字之后，ifSuccess值还是false，弹窗不会消失
          }, 200);

        } else {
          mymessage.error("请先填写信息");
          return false;
        }

      })
    },
    // 自定义规则单独扫描  本地
    customRule(){
      var that = this
      this.$refs.form.validate((valid) => {
        if (valid) {
          $.ajax({
            url:  (http_head + '/Muti/'),
            data:{
              method: 'rule_detection',
              folder_name: that.folder_name,
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
          setTimeout(() => {
            if (this.ifSuccess === true){
              this.getTableData();
              this.getAlert = false;
            }
            this.ifSuccess = true     //不然直接改名字之后，ifSuccess值还是false，弹窗不会消失
          }, 200);

        } else {
          mymessage.error("请先填写信息");
          return false;
        }

      })
    },
    //最开始的模型
    smallScan(){
      var that = this
      this.$refs.form.validate((valid) => {
        if (valid) {
          $.ajax({
            url:  (http_head + '/Muti/'),
            data:{
              method:'upload',
              type: that.policy,
              item_name: that.itemname,
              item_id: that.itemid,
              task_name:that.form.taskName ? that.form.taskName : '',
              folder_name:that.folder_name,
            },
            type : 'post',
            dataType : 'JSON',
            success : function (res){
              console.log(res)
              // mymessage.success("创建成功")
              if(res.code === '500'){
                that.ifSuccess = false
                mymessage.error("任务名称已存在，请修改任务名")
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
              this.getAlert = false;
            }
            this.ifSuccess = true     //不然直接改名字之后，ifSuccess值还是false，弹窗不会消失
          }, 200);

        } else {
          mymessage.error("请先填写信息");
          return false;
        }

      })
    },
// 多分类检测
    Muti_detection(){
      var that = this
      this.$refs.form.validate((valid) => {
        if (valid) {
          $.ajax({
            url:  (http_head + '/Muti_transformer/'),
            data:{
              method:'muti_transformer_detection',
              folder_path:that.folder_name,
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
                mymessage.error("任务名称已存在，请修改任务名")
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
              this.getAlert = false;
            }
            this.ifSuccess = true     //不然直接改名字之后，ifSuccess值还是false，弹窗不会消失
          }, 200);

        } else {
          mymessage.error("请先填写信息");
          return false;
        }

      })
    },
    //git拉取 GITGITGITGITGITGITGITGITGITGITGITGITGITGITGITGITGITGITGITGITGITGITGITGITGITGITGITGITGITGITGITGIT
    pull_git() {
      this.loading = true
      var that = this
      $.ajax({
        url:  (http_head + '/Muti/'),
        data:{
          method:'git_clone',
          url: that.form2.url,
          token: that.form2.key,
          branch: that.form2.branch,
          item_name: that.itemname,   //项目名
        },
        type : 'post',
        dataType : 'JSON',
        success : function (res){
          console.log(res)
          // mymessage.success("创建成功")
          that.loading = false
          that.pullSuccess = true   //拉取成功之后才可以填任务名称和任务描述
          mymessage.success("拉取成功！")
          that.folder_name_git = res.folder_name
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
          url: that.form3.url,
          username: that.form3.zhanghao,
          password: that.form3.key,
          item_name: that.itemname,   //项目名
        },
        type : 'post',
        dataType : 'JSON',
        success : function (res){
          console.log(res)
          // mymessage.success("创建成功")
          that.loading = false
          if(res.code==="200"){
            mymessage.success("拉取成功！")
            that.pullSvnSuccess = true
          }
          that.folder_name_svn = res.folder_name
        },
        error: function (err) {
          console.log(err)
          mymessage.error("创建失败")
        }
      })
    },
    //git 创建
    create_git(){
      var that = this
      this.$refs.form2.validate((valid) => {
        if (valid) {
          $.ajax({
            url:  (http_head + '/Muti/'),
            data:{
              method:'upload',
              type: that.policy,
              item_name: that.itemname,
              item_id: that.itemid,
              task_name:that.form2.taskName ? that.form2.taskName : '',
              folder_name:that.folder_name_git,
            },
            type : 'post',
            dataType : 'JSON',
            success : function (res){
              console.log(res)

              if(res.code === '500'){
                that.ifSuccess = false
                if (res.msg === 'Error!No sample.') {
                  mymessage.error("代码语言错误！")
                } else {
                  mymessage.error("任务名称已存在，请修改任务名")
                }
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
              this.getAlert = false;
            }
            this.ifSuccess = true     //不然直接改名字之后，ifSuccess值还是false，弹窗不会消失
          }, 200);

        } else {
          mymessage.error("请先填写信息");
          return false;
        }

      })

    },
    //deepSeekdeepSeekdeepSeekdeepSeekdeepSeekdeepSeekdeepSeekdeepSeekdeepSeekdeepSeekdeepSeekdeepSeekdeepSeekdeepSeek
    resetForm() {   //不刷新页面再次点击时不会出现上一次填的内容
      this.form = {
        taskName: '',
        description: '',
      }
      this.uploadFileList = []
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
          task_name: that.form3.taskName ? that.form3.taskName : '',   //任务名
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
          this.getAlert = false;
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
          this.getAlert = false;
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
          task_name: that.form2.taskName ? that.form2.taskName : '',   //任务名
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
        this.getAlert = false;
      }, 200);
    },

    //获取项目列表
    // getTableData() {
    //   var that = this
    //   $.ajax({
    //     url: (http_head + '/login/'),
    //     data:{
    //       method : 'task_list',
    //       taskid : '',
    //       taskname : that.query.project_name ,
    //       itemid : that.itemid,
    //       itemname : '',
    //       language : '',
    //       type : '',
    //       review_status : '',
    //       source : '',
    //       creator : '',
    //       starttime : '',
    //       page : that.currentPage,
    //       rows : that.pageSize,
    //     },
    //     type: 'post',
    //     dataType: 'JSON',
    //     success: function (res){
    //       console.log(res)
    //       that.itemName = that.itemname
    //       if(res.count > 0){
    //         that.tableData = res.data
    //         that.count = res.count
    //         that.idshowtext=res.data[0].taskid
    //         //有文件没检测完成就一直刷新
    //         for (let i = 0; i < that.tableData.length; i++){
    //           if (that.tableData[i].statues === "检测完成" || that.tableData[i].statues === "检测失败") {
    //             // console.log(i)
    //
    //           }  else {
    //             setTimeout(() => {
    //               that.getTableData()
    //             }, 5000)
    //           }
    //         }
    //       } else if(res.count === 0) {    //只有一条数据时删除之后要赋值才能刷新
    //         that.tableData = []
    //       }
    //     },
    //     error: function (err) {
    //       console.log(err)
    //       mymessage.error("项目列表获取失败")
    //     }
    //   })
    // },

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
            const newData = res.data;

            // 深度比较新数据与当前数据
            // if (JSON.stringify(newData) !== JSON.stringify(that.tableData)) {
            // 浅比较
            if (!that.tableData || that.tableData.length !== newData.length ||
                that.tableData.some((item, index) => item.statues !== newData[index].statues)) {
              console.log("数据发生变化，更新表格");
              that.tableData = newData; // 只有在数据变化时更新
              that.count = res.count;
              that.idshowtext = newData[0].taskid;
            } else {
              console.log("数据未发生变化，无需更新表格");
            }


            // 检查是否有未完成的任务
            const hasIncompleteTasks = newData.some(
                (item) => item.statues !== "检测完成" && item.statues !== "检测失败"
            );
            console.log('是否有正在检测', hasIncompleteTasks);

            // 根据是否有未完成的任务来启动或停止轮询
            if (hasIncompleteTasks) {
              startPolling();
            } else {
              stopPolling();
            }
          } else {
            that.tableData = [];
            stopPolling(); // 确保在没有数据时停止轮询
          }
        },
        error: function (err) {
          that.isRequestInProgress = false;
          console.log(err);
          mymessage.error("项目列表获取失败");
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

    //删除
    delopen(row) {
      this.$confirm('此操作将删除该任务, 是否继续?', '提示', {
        confirmButtonText: '确定',
        cancelButtonText: '取消',
        type: 'warning'
      }).then(() => {
        this.del(row)
      }).catch(() => {
        this.$message({
          type: 'info',
          message: '已取消删除'
        });
      });
    },
    del(row){
      console.log(row)
      var that = this;
      $.ajax({
        url:  (http_head + '/login/'),
        data:{
          method : 'task_delete',
          taskid : row.taskid,
        },
        type : 'post',
        dataType : 'JSON',
        success : function (res){
          console.log(res);
          if (res.code == '200'){

            mymessage.success(res.msg)
          }else{
            mymessage.error(res.msg)
          }
          that.getTableData()
        },
        error: function (err) {
          console.log(err)
          mymessage.error("删除失败")
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
          // console.log(res);
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

  },
  beforeDestroy() {
    if (this.pollingInterval) {
      clearInterval(this.pollingInterval);
    }
  }


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
}