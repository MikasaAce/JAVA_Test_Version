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
    this.currentPage1 = JSON.parse(sessionStorage.getItem('page2') || '1')
    this.pageSize1 = JSON.parse(sessionStorage.getItem('rows2') || '10')
    this.getvuelist()
  },
  data() {
    return {
      loading:false,
      loading1: false,
      prohibit:'false',
      query:{
        scan_type: '',
        project_name:'',
      },
      jumptable : [],
      currentPage1: 1, //当前页 刷新后默认显示第一页
      pageSize1: 10, //每一页显示的数据量 此处每页显示6条数据
      count1:10,

    };
  },

  methods: {
    goback(){
      sessionStorage.removeItem('page2')
      sessionStorage.removeItem('rows2')
      window.location.href = 'ProjectSummary.html'
    },
    reload(){
      window.location.reload()
    },
    //查询
    checkFormData(){

    },
    //查看
    view(row){
      sessionStorage.setItem('loopdata',JSON.stringify(row))
      sessionStorage.setItem('loopid',JSON.stringify(row.id))
      sessionStorage.setItem('page2',JSON.stringify(this.currentPage1))
      sessionStorage.setItem('rows2',JSON.stringify(this.pageSize1))
      window.location.href = 'SecurityProjectManageNew.html'
    },
    //获取项目中漏洞文件列表
    getvuelist(){
      var id = JSON.parse(sessionStorage.getItem('projectid'))
      var that = this;
      $.ajax({
        url:  (http_head + '/login/'),
        data:{
          method : 'vul_getall',
          itemId :  id,
          page   :  that.currentPage1,
          rows   :  that.pageSize1,
        },
        type : 'post',
        dataType : 'JSON',
        timeout : 1000,  //超时时间设置，单位毫秒
        success : function (res){
          console.log(res);
          if (res){
            that.jumptable =res.data
            that.count1 = parseInt(res.count)
          }
        },
        error: function (err) {
          console.log(err)
          mymessage.error("查看失败")
        }
      })
    },
    handleSizeChange1(val) {
      console.log(`每页 ${val} 条`);
      this.pageSize1 = val;
      this.getvuelist()
    },
    //点击按钮切换页面
    handleCurrentChange1(currentPage) {
      this.currentPage1 = currentPage; //每次点击分页按钮，当前页发生变化
      this.getvuelist();
    },

    //检测后点击修复按钮
    xiufu(row){
      var that = this;
      this.gettime(row)
      this.prohibit = 'true'
      $.ajax({
        url:  (http_head + '/qmq/'),
        data:{
          vulId         : row.id,
          method        : 'location_web'
        },
        type : 'post',
        dataType : 'JSON',
        async: 'true',
        success : function (res){
          console.log(res);
          if (res){
            that.getvuelist()
          }
        },
        error: function (err) {
          console.log(err)
          mymessage.error("修复失败")
          that.prohibit = 'false'
        }
      })
    },
    //获取修复时间
    gettime(row){
      var that = this;
      $.ajax({
        url:  (http_head + '/qmq/'),
        data:{
          vulId         : row.id,
          method        : 'time_all'
        },
        type : 'post',
        dataType : 'JSON',
        async: 'true',
        success : function (res){
          console.log(res);
          if (res){
            // mymessage.success(res.msg)
            that.$confirm(res.msg + '提示', {
              confirmButtonText: '确定',
              cancelButtonText: '取消',
              type: 'warning'
            }).then(() => {
            }).catch(() => {
              that.$message({
                type: 'info',
                message: '已取消删除'
              });
            });
          }
        },
        error: function (err) {
          console.log(err)
        }
      })
    },
    //生成execl文件
    generateFile(row){
      var toExportPage = {flag :'excel', id:row.id}
      sessionStorage.setItem('toExportPage',JSON.stringify(toExportPage))
      var that = this;
      $.ajax({
        url:  (http_head + '/login/'),
        data:{
          method : 'export_getall',
          vulId     : row.id,
          accountId  : '',
          itemName    : '' ,
          dataSetName  : '',
          file_startTime : '' ,
          file_endTime : '' ,
          fileType : 'excel',
          vul_startTime: '' ,
          vul_endTime : '' ,
          page   : '1'    ,
          rows   : '10' ,
        },
        type : 'post',
        dataType : 'JSON',
        success : function (res){
          console.log(res);
          if(res.code == '500'){
            mymessage.error(res.msg)
          }else {
            if (res.count == '0'){
              that.exportFile(row)
            }else {
              window.location.href = '../ReportManage/ReportManage.html'
            }
          }
        },
        error: function (err) {
          console.log(err)
          mymessage.error("生成失败")
        }
      })
    },
    //导出execl文件
    exportFile(row){
      this.loading1 = true
      console.log(row)
      var that = this;
      $.ajax({
        url:  (http_head + '/login/'),
        data:{
          method : 'vulfile_export',
          vulId     : row.id,
          itemId: row.itemId,
          createTime : getCurrentDate(2),
          itemName : row.dataSetName,
          vul_startTime : '',
        },
        type : 'post',
        dataType : 'JSON',
        success : function (res){
          console.log(res);
          if(res.code == '500'){
            mymessage.error(res.msg)
          }else if (res.code == '200'){
            window.setTimeout(window.location.href = '../ReportManage/ReportManage.html',1000);
          }
        },
        error: function (err) {
          console.log(err)
          mymessage.error("导出失败")
        }
      })
      this.loading1 = false
    },
    //生成pdf文件
    generatePDF(row){
      var toExportPage = {flag :'pdf', id:row.id}
      sessionStorage.setItem('toExportPage',JSON.stringify(toExportPage))
      this.loading1 = true
      var that = this;
      $.ajax({
        url:  (http_head + '/login/'),
        data:{
          method : 'export_getall',
          vulId     : row.id,
          accountId  : '',
          itemName    : '' ,
          dataSetName  : '',
          file_startTime : '' ,
          file_endTime : '' ,
          fileType : 'pdf',
          vul_startTime: '' ,
          vul_endTime : '' ,
          page   : '1'    ,
          rows   : '10' ,
        },
        type : 'post',
        dataType : 'JSON',
        success : function (res){
          console.log(res);
          if (res.count == '0'){
            that.exportPDF(row)
          }else {
            window.location.href = '../ReportManage/ReportManage.html'
          }
        },
        error: function (err) {
          console.log(err)
          mymessage.error("生成失败")
        }
      })
    },
    //导出PDF
    exportPDF(row){
      var that = this;
      $.ajax({
        url:  (http_head + '/login/'),
        data:{
          method : 'export_pdf',
          teamName : localUser.teamName,                 //项目团队
          itemName : row.name,                           //项目名称
          zipName :  row.dataSetName,                    //检测文件名称
          vulFileNumber : row.vulFileNumber,             //有漏洞文件数量
          language :row.language,                        //开发语言
          type :row.data1,                               //扫描类型
          createTime :row.createTime,                    //项目创建时间(kong )
          startTime :row.startTime,                      //检测开始时间
          lastTime :row.lastTime,                        //检测耗时jian
          vuls : row.vulTypes,                           //所有的漏洞类型
          vulId : row.id,                                //漏洞页面id
          itemId: row.itemId,
          pdf_Time : getCurrentDate(2),          //文档生成时间
        },
        type : 'post',
        dataType : 'JSON',
        success : function (res){
          console.log(res.code);
          if(res.code == '500'){
            mymessage.error(res.msg)
          }else if (res.code == '200'){
            window.setTimeout(window.location.href = '../ReportManage/ReportManage.html',1000);
          }
        },
        error: function (err) {
          console.log(err)
          mymessage.error("导出失败")
        }
      })
      this.loading1 = false
    },
    //删除漏洞文件
    delcweopen(row){
      console.log(row)
      this.$confirm('此操作将永久删除该文件, 是否继续?', '提示', {
        confirmButtonText: '确定',
        cancelButtonText: '取消',
        type: 'warning'
      }).then(() => {
        this.delcwe(row)
      }).catch(() => {
        this.$message({
          type: 'info',
          message: '已取消删除'
        });
      });
    },
    delcwe(row){
      console.log(row)
      this.loading = true;
      var that = this;
      $.ajax({
        url:  (http_head + '/login/'),
        data:{
          method : 'vul_delete',
          id     : row.id,
        },
        type : 'post',
        dataType : 'JSON',
        success : function (res){
          console.log(res);
          if (res){
            if(res.code == '500'){
              mymessage.error(res.msg)
            }else {
              mymessage.success("删除成功")
              that.getvuelist()
            }
          }
        },
        error: function (err) {
          console.log(err)
          mymessage.error("删除失败")
        }
      })
      this.loading = false
    },

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