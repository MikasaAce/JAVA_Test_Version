let mymessage = {}
const vueListData = [
  {"id":"","name":""},
  {"id":"无漏洞","name":"无漏洞"},
  {"id":"cwe787"  ,"name":"cwe787-越界读取"},
  {"id":"cwe79"   ,"name":"cwe79-在网页生成过程中对输入的处理不当（跨站脚本攻击）"},
  {"id":"cwe125"  ,"name":"cwe125-越界读取"},
  {"id":"cwe20"	,"name":"cwe20-输入验证不当"},
  {"id":"cwe78"	,"name":"cwe78-多OS命令中使用的特殊元素处理不当（OS命令注入）"},
  {"id":"cwe89"	,"name":"cwe89-对SQL命令中使用的特殊元素处理不当(SQL注入)"},
  {"id":"cwe416"	,"name":"cwe416-释放后使用"},
  {"id":"cwe22"	,"name":"cwe22-对受限制目录的路径名的限制不当（“路径遍历”）"},
  {"id":"cwe352"	,"name":"cwe352-跨站点请求伪造（CSRF）"},
  {"id":"cwe434"	,"name":"cwe434-危险类型文件的不加限制上传"},
  {"id":"cwe306"	,"name":"cwe306-关键功能的认证机制缺失"},
  {"id":"cwe190"	,"name":"cwe190-整数溢出或回绕"},
  {"id":"cwe502"	,"name":"cwe502-不受信任的数据的反序列化"},
  {"id":"cwe287"	,"name":"cwe287-身份认证不当"},
  {"id":"cwe476"	,"name":"cwe476-空指针解引用"},
  {"id":"cwe798"	,"name":"cwe798-使用硬编码凭据"},
  {"id":"cwe119"	,"name":"cwe119-对超出界限的内存访问限制不当"},
  {"id":"cwe862"	,"name":"cwe862-缺少授权"},
  {"id":"cwe276"	,"name":"cwe276-默认权限不正确"},
  {"id":"cwe200"	,"name":"cwe200-将敏感信息暴露给未经授权的参与者"},
  {"id":"cwe522"	,"name":"cwe522-不充分的凭证保护机制"},
  {"id":"cwe732"	,"name":"cwe732-关键资源的权限分配不正确"},
  {"id":"cwe611"	,"name":"cwe611-XML外部实体引用的限制不当（XXE）"},
  {"id":"cwe918"	,"name":"cwe918-服务器端请求伪造（SSRF）"},
  {"id":"cwe77"	,"name":"cwe77-在命令中使用的特殊元素转义处理不当（命令注入）"},
  {"id":"cwe295"	,"name":"cwe295-不正确的证书验证"},
  {"id":"cwe400"	,"name":"cwe400-未加控制的资源消耗（资源穷尽）"},
  {"id":"cwe94"	,"name":"cwe94-对生成代码的控制不恰当（代码注入）"},
  {"id":"cwe269"	,"name":"cwe269-权限管理不当"},
  {"id":"cwe917"	,"name":"cwe917-表达式语言语句中使用的特殊元素的不当中和（表达式语言注入）"},
  {"id":"cwe59"	,"name":"cwe59-在文件访问前对链接解析不恰当（链接跟随）"},
  {"id":"cwe401"	,"name":"cwe401-在移除最后引用时对内存的释放不恰当（内存泄露）"},
  {"id":"cwe362"	,"name":"cwe362-使用共享资源进行同步不正确的并发执行（争用条件）"},
  {"id":"cwe427"	,"name":"cwe427-对搜索路径元素未加控制"},
  {"id":"cwe319"	,"name":"cwe319-敏感信息的明文传输"},
  {"id":"cwe843"	,"name":"cwe843-使用不兼容类型访问资源（类型混淆）"},
  {"id":"cwe601"	,"name":"cwe601-URL重定向漏洞"},
  {"id":"cwe863"	,"name":"cwe863-授权机制不正确"},
  {"id":"cwe532"	,"name":"cwe532-在日志文件中包含敏感信息"},
  {"id":"cwe770"	,"name":"cwe770-不加限制或调节的资源分配"},
  {"id":"cwe327"	,"name":"cwe327-使用被破解或有风险的加密算法"},
  {"id":"cwe90"	,"name":"cwe90-LDAP注⼊"},
];

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
    this.getFeedbackList()

  },
  data() {
    return {
      query:{
        project_name: ''
      },
      vueList: vueListData,

      tableList_feedback : [],  //反馈列表
      currentPage3: 1, //当前页 刷新后默认显示第一页
      pageSize3: 10, //每一页显示的数据量 此处每页显示6条数据
      count3:10,

      dialogTableVisible1 : false,
      gridData1 :[],
      currentRow1: null,
      currentPage1: 1, //当前页 刷新后默认显示第一页
      pageSize1: 5, //每一页显示的数据量 此处每页显示6条数据
      count1:10,
      query1:{
        project_name: ''
      },

      dialogTableVisible2 : false,
      gridData2 :[],
      currentRow2: null,
      currentPage2: 1, //当前页 刷新后默认显示第一页
      pageSize2: 5, //每一页显示的数据量 此处每页显示6条数据
      count2:10,
      query2:{
        project_name: ''
      },

    };
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
    goback(){
      window.location.href = 'SecurityProjectManageNew.html'
    },
    reload(){
      window.location.reload()
    },
    //查询
    checkFormData(){

    },
//获取反馈列表
    getFeedbackList(){
      var id = JSON.parse(sessionStorage.getItem('loopid'))
      var that = this;
      $.ajax({
        url:  (http_head + '/login/'),
        data:{
          method :  'feedback_getall',
          vulId  :  id,
          page   :  that.currentPage3,
          rows   :  that.pageSize3,
        },
        type : 'post',
        dataType : 'JSON',
        success : function (res){
          console.log(res);
          if (res.msg =='查询结果为空'){
            that.count3 = 0
          }else {
            that.tableList_feedback = res.data
            that.count3 = parseInt(res.count)
          }
        },
        error: function (err) {
          console.log(err)
          that.open2("查看失败")
        }
      })
    },
    handleSizeChange3(val) {
      console.log(`每页 ${val} 条`);
      this.pageSize3 = val;
      this.getFeedbackList()
    },
    //点击按钮切换页面
    handleCurrentChange3(currentPage) {
      this.currentPage3 = currentPage; //每次点击分页按钮，当前页发生变化
      this.getFeedbackList();
    },

    //删除
    delopen(row) {
      this.$confirm('此操作将永久删除该文件, 是否继续?', '提示', {
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
          method : 'feedback_delete',
          id     : row.id,
        },
        type : 'post',
        dataType : 'JSON',
        success : function (res){
          console.log(res);
          if (res){
            that.open1("删除成功")
            that.getFeedbackList()
          }
        },
        error: function (err) {
          console.log(err)
          that.open2("删除失败")
        }
      })

    },

    //*********************误报反馈*******************//
    //*********************误报反馈*******************//
    //*********************误报反馈*******************//
    opentable1(){
      this.dialogTableVisible1 =true
      this.getTableData1()
    },
    getTableData1(){
      var id = JSON.parse(sessionStorage.getItem('loopid'))
      var that = this;
      $.ajax({
        url:  (http_head + '/login/'),
        data:{
          method :  'vulfile_getall',
          types : '1',
          vulFileName : that.query1.project_name,
          vulId  :  id,
          page   :  that.currentPage1,
          rows   :  that.pageSize1,
        },
        type : 'post',
        dataType : 'JSON',
        success : function (res){
          console.log(res);
          console.log(typeof res.data);
          if (res){
            that.gridData1 = res.data
            that.count1 = parseInt(res.count)
            // that.query1.project_name = ''
          }
        },
        error: function (err) {
          console.log(err)
          that.open2("查看失败")
        }
      })
    },
    //查询
    checkFormData1(){
      this.getTableData1()
    },
    handleSizeChange1(val) {
      console.log(`每页 ${val} 条`);
      this.pageSize1 = val;
      this.getTableData1()
    },
    //点击按钮切换页面
    handleCurrentChange1(currentPage) {
      this.currentPage1 = currentPage; //每次点击分页按钮，当前页发生变化
      this.getTableData1();
    },

    insertAttr1(row){
      console.log(row)
      if (row.data1 == ''){
        row.data1 = '1'
        row.data2 = ''
        row.data3 = ''
      }else if (row.data1 == '1'){
        row.data1 = ''
      }
      this.currentRow1 = row;
    },
    insertAttr2(row){
      console.log(row)
      if (row.data2 == ''){
        row.data2 = '1'
        row.data1 = ''
      }else if (row.data2 == '1'){
        row.data2 = ''
      }
      this.currentRow1 = row;
    },
    cwechange1(row){
      console.log(row)
      this.currentRow1 = row;
    },

    onchange1(row) {
      this.currentRow1 = row;

      const selectData = this.gridData1
      this.$refs.gridData1.clearSelection()
      if( selectData.length == 1 ) {
        selectData.forEach(item => {
          // 判断 如果当前的一行被勾选, 再次点击的时候就会取消选中
          if (item == row) {
            this.$refs.gridData1.toggleRowSelection(row, false);
          }
          // 不然就让当前的一行勾选
          else {
            this.$refs.gridData1.toggleRowSelection(row, true);
          }
        })
      }
      else {
        this.$refs.gridData1.toggleRowSelection(row, true);
      }

    },
    select1(selection, row) {
      // 清除 所有勾选项
      this.$refs.gridData1.clearSelection()
      // 当表格数据都没有被勾选的时候 就返回
      // 主要用于将当前勾选的表格状态清除
      if(selection.length == 0) return
      this.$refs.gridData1.toggleRowSelection(row, true);
      this.$refs.gridData1.setCurrentRow(row)
    },

    onsubmit1(){
      console.log(this.currentRow1)
      var that = this;
      var reason = ''
      if (this.currentRow1.data1 == '1'){
        reason = '1'
      }else if (this.currentRow1.data2 == '1'){
        reason = '0'
      }
      var id = JSON.parse(sessionStorage.getItem('loopid'))
      var itemId = JSON.parse(sessionStorage.getItem('projectid'))
      if (this.currentRow1.data1==''&&this.currentRow1.data2==''&&this.currentRow1.data3==''){
        that.open3("请先评价或者选择所属类型！")
      }else{
        $.ajax({
          url:  (http_head + '/login/'),
          data:{
            method :  'feedback_insert',
            itemId  :  itemId,
            vulId :   id,
            fileName :   that.currentRow1.vulFileName,
            vulType :   that.currentRow1.vulType,
            feedType :   '1',
            newType :   that.currentRow1.data3,
            reason :   reason,
            reason_url   :  '',
            time   :   getCurrentDate(2)  ,
          },
          type : 'post',
          dataType : 'JSON',
          success : function (res){
            console.log(res.msg);
            if (res.msg == '插入成功'){
              that.open1("提交成功")
              that.dialogTableVisible1 =false
              that.getFeedbackList()
            }else {
              that.open3("提交失败")
            }
          },
          error: function (err) {
            console.log(err)
            that.open2("查看失败")
          }
        })
      }
    },
    //*********************漏报反馈*******************//
    //*********************漏报反馈*******************//
    //*********************漏报反馈*******************//
    opentable2(){
      this.dialogTableVisible2 =true
      this.getTableData2()
    },

    getTableData2(){
      var id = JSON.parse(sessionStorage.getItem('loopid'))
      var that = this;
      $.ajax({
        url:  (http_head + '/login/'),
        data:{
          method :  'vulfile_getall',
          types : '0',
          vulFileName : that.query2.project_name,
          vulId  :  id,
          page   :  that.currentPage2,
          rows   :  that.pageSize2,
        },
        type : 'post',
        dataType : 'JSON',
        success : function (res){
          console.log(res);
          console.log(typeof res.data);
          if (res){
            that.gridData2 = res.data
            that.count2 = parseInt(res.count)
            // that.query2.project_name = ''
          }
        },
        error: function (err) {
          console.log(err)
          that.open2("查看失败")
        }
      })
    },
    checkFormData2(){
      this.getTableData2()
    },
    handleSizeChange2(val) {
      console.log(`每页 ${val} 条`);
      this.pageSize2 = val;
      this.getTableData2()
    },
    //点击按钮切换页面
    handleCurrentChange2(currentPage) {
      this.currentPage2 = currentPage; //每次点击分页按钮，当前页发生变化
      this.getTableData2();
    },
    insertAttr3(row){
      console.log(row)
      if (row.data1 == ''){
        row.data1 = '1'
        row.data2 = ''
        row.data3 = ''
      }else if (row.data1 == '1'){
        row.data1 = ''
      }
      this.currentRow2 = row;
    },
    insertAttr4(row){
      console.log(row)
      if (row.data2 == ''){
        row.data2 = '1'
        row.data1 = ''
      }else if (row.data2 == '1'){
        row.data2 = ''
      }
      this.currentRow2 = row;
    },
    cwechange2(row){
      console.log(row)
      this.currentRow2 = row;
    },

    onchange2(row) {
      this.currentRow2 = row;

      const selectData = this.gridData2
      this.$refs.gridData2.clearSelection()
      if( selectData.length == 1 ) {
        selectData.forEach(item => {
          // 判断 如果当前的一行被勾选, 再次点击的时候就会取消选中
          if (item == row) {
            this.$refs.gridData2.toggleRowSelection(row, false);
          }
          // 不然就让当前的一行勾选
          else {
            this.$refs.gridData2.toggleRowSelection(row, true);
          }
        })
      }
      else {
        this.$refs.gridData2.toggleRowSelection(row, true);
      }

    },
    select2(selection, row) {
      // 清除 所有勾选项
      this.$refs.gridData2.clearSelection()
      // 当表格数据都没有被勾选的时候 就返回
      // 主要用于将当前勾选的表格状态清除
      if(selection.length == 0) return
      this.$refs.gridData2.toggleRowSelection(row, true);
      this.$refs.gridData2.setCurrentRow(row)
    },
    onsubmit2(){
      var that = this;
      var id = JSON.parse(sessionStorage.getItem('loopid'))
      var itemId = JSON.parse(sessionStorage.getItem('projectid'))
      var reason = ''
      if (this.currentRow2.data1 == '1'){
        reason = '1'
      }else if (this.currentRow2.data2 == '1'){
        reason = '0'
      }

      if (this.currentRow2.data1==''&&this.currentRow2.data2==''&&this.currentRow2.data3==''){
        that.open3("请先评价或者选择所属类型！")
      }else {
        $.ajax({
          url:  (http_head + '/login/'),
          data:{
            method :  'feedback_insert',
            itemId  :  itemId,
            vulId :   id,
            fileName :   that.currentRow2.vulFileName,
            vulType :   that.currentRow2.vulType,
            feedType :   '0',
            newType :   that.currentRow2.data3,
            reason :   reason,
            reason_url   :  '',
            time   :   getCurrentDate(2)  ,
          },
          type : 'post',
          dataType : 'JSON',
          success : function (res){
            console.log(res.msg);
            if (res.msg == '插入成功'){
              that.open1("提交成功")
              that.dialogTableVisible2 =false
              that.getFeedbackList()
            }else {
              that.open2("提交失败")
            }
          },
          error: function (err) {
            console.log(err)
            that.open2("查看失败")
          }
        })
      }
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