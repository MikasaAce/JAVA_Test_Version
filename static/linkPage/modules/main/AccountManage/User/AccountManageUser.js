let vm = new Vue({
  el: '#app',
  data() {
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
        password:''
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
          { required: true, message: '请输密码', trigger: 'blur' },
          { min: 8, message: '密码长度最少为8字符', trigger: 'blur' }
        ]
      },
      changeform:{},
      rules2:{
        pwd: [
          { required: true, message: '请输密码', trigger: 'blur' },
        ],
        pwdnew: [
          { required: true, message: '请输密码', trigger: 'blur' },
          { min: 8, message: '密码长度最少为8字符', trigger: 'blur' }
        ]
      }

    }
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

    getTableData(){
      var that = this;
      $.ajax({
        url:  (http_head + '/login/'),
        data:{
          method: 'account_getall',
          teamId: localUser.teamId,
          username : that.query.name,
          account : that.query.account,
          page   :  that.currentPage,
          rows   :  that.pageSize,
        },
        type : 'post',
        dataType : 'JSON',
        success : function (res){
          console.log(res);
          if (res){
            that.tableData = res.data
            that.count = parseInt(res.count)
            that.open1("获取成功")
          }
        },
        error: function (err) {
          console.log(err)
          that.open3("获取失败")
        }
      })
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
      this.addform = {}
    },
    //新增
    addUser(){
      this.initaddForm()
      this.addUserDialog = true
      this.isshow  = '1'
      this.addUserTitle = '新建用户'
    },
    createUser(){
      var that = this;
      this.$refs.addform.validate((valid) => {
        if (valid) {
          $.ajax({
            url:  (http_head + '/login/'),
            data:{
              username  : that.addform.username,
              teamId    : localUser.teamId ,
              role     : '1',
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
      this.addform = rows
    },
    //确认更新
    editUser(){
      var row = JSON.parse(sessionStorage.getItem('editdata'))
      var that = this;
      $.ajax({
        url:  (http_head + '/login/'),
        data:{
          id : row.id,
          username  : that.addform.username,
          // account    : that.addform.account ,
          method     : 'account_update',
        },
        type : 'post',
        dataType : 'JSON',
        success : function (res){
          console.log(res);
          if (res){
            that.open1("编辑成功")
            that.addUserDialog = false
            that.getTableData()
          }
        },
        error: function (err) {
          console.log(err)
          that.open3("编辑失败")
        }
      })
    },
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
              password_n: that.changeform.pwdnew,
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
      this.$confirm('此操作将永久删除该文件, 是否继续?', '提示', {
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
          method     : 'account_delete',
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
  },
  mounted() {
    this.getTableData();
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
