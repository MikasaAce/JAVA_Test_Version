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

let vm = new Vue({
  el: '#app',
  data() {
    return {
      uploadFlag :false,
      vueList: vueListData,
      tableList_bugsFile : [],
      currentPage: 1, //当前页 刷新后默认显示第一页
      pageSize: 10, //每一页显示的数据量 此处每页显示6条数据
      count:10,

      loading: false,

      bugsFile:'',
      bugsType:'',
      census_FNP:'',
      census_FPR:'',
      census_acc:'',
      high_num:'',
      low_num:'',
      mid_num:'',
      ruleForm: {
        dataRadio:'',
      },
    }
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
      window.location.href = 'FileSummart.html'
    },
    reload(){
      window.location.reload()
    },

    handleSizeChange(val) {
      console.log(`每页 ${val} 条`);
      this.pageSize = val;
      this.getLoopList()
    },
    //点击按钮切换页面
    handleCurrentChange(currentPage) {
      this.currentPage = currentPage; //每次点击分页按钮，当前页发生变化
      this.getLoopList();
    },

    //获取漏洞列表
    getLoopList(){
      var id = JSON.parse(sessionStorage.getItem('loopid'))
      var that = this;
      $.ajax({
        url:  (http_head + '/login/'),
        data:{
          method :  'vulfile_getall',
          types : '',
          vulFileName : '',
          vulId  :  id,
          page   :  that.currentPage,
          rows   :  that.pageSize,
        },
        type : 'post',
        dataType : 'JSON',
        success : function (res){
          console.log(res);
          console.log(typeof res.data);
          if (res){
            that.tableList_bugsFile = res.data
            that.count = parseInt(res.count)
          }
        },
        error: function (err) {
          console.log(err)
          that.open2("查看失败")
        }
      })
    },
    //基本信息显示
    computedData(res1){
      var that = this
      that.save_file = res1.dataSetName;
      that.bugsFile = res1.vulFileNumber;
      that.census_FNP = (Math.round(res1.falseNegatives*10000))/100+'%';
      that.census_FPR = (Math.round(res1.falsePositives*10000))/100+'%';
      that.census_acc = (Math.round(res1.accuracy*10000))/100+'%';
      that.bugsType = res1.vulTypes
      that.high_num = res1.highNumber
      that.mid_num = res1.mediumNumber
      that.low_num = res1.lowNumber
    },

    opentable1(){
      window.location.href = 'Feedback.html'
    },

    //一键修复
    repair(row){
      var that = this;
      $.ajax({
        url:  (http_head + '/login/'),
        data:{
          method :  'repair_java_file',
          id : row.id,
        },
        type : 'post',
        dataType : 'JSON',
        success : function (res){
          if (res.code == '200'){
            that.open1("修复成功")
            setTimeout(() => {
              window.location.reload()
            }, 1000);
          }else{
            that.open2("修复失败")
          }
        },
        error: function (err) {
          console.log(err)
          that.open2("修复失败")
        }
      })
    },
    //下载
    download(row){
      if (row.url) {
        var fileUrl = row.url
        console.log(fileUrl)
        const link = document.createElement('a')
        link.href =fileUrl
        link.setAttribute('download','修复结果') // 下载文件的名称及文件类型后缀
        document.body.appendChild(link)
        link.click()
        document.body.removeChild(link) // 下载完成移除元素
        setTimeout(() => {
          // window.close() // 关闭新标签页
        }, 1000) // 设置5秒延迟，确保下载完成后再关闭标签页
      }
      else {
        this.open2("下载失败")
      }
    }



  },
  created() {
    var loopdata = JSON.parse(sessionStorage.getItem('loopdata'))
    this.computedData(loopdata)
    this.getLoopList()
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