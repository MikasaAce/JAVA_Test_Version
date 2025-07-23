let mymessage = {}
let mapping = {
  '1': '768',
  '2': '256',
  '3': '512',
  '4': '768',
  '5': '1024',
  '6': '1024',
  '7': '2048',
  '8': '2560',
}

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
  },
  data() {
    return {
      tabPosition: 'left',
      activeName1: 'first',
      activeName2: 'first',

      classification:{
        type : '1',
        feature : '1',
      },

      //json格式文件上传
      uploadURL1: http_head + '/interface/',
      uploadURLData1:{method:'feature_json',type: '1'},
      uploadFileList1: [],

      //本地压缩包文件上传
      uploadURL: http_head + '/interface/',
      uploadURLData:{method:'upload',type: '1'},
      uploadFileList: [],

      date_PositiveUpload:'',
      feature_log :[],
      feature_url : http_head + '/static/xsy_log/feature.txt',

      train:{
        classification:'1',
        model:'1',
        type:'1',
        feature1:'1',
        feature2:'2',
        dim:'768',
        num:'2',
        name:'codebert',
      },
      train_log :[],
      train_url : http_head + '/static/xsy_log/train.txt',
    }
  },
  methods: {
    //正样本标签页
    handleClick(tab, event) {
      // console.log(tab, event);
    },
    change(val){
      this.uploadURLData1.type = val
      this.uploadURLData.type = val
      console.log(this.uploadURLData1)
    },
    //json文件格式处理
    uploadSuccess1(response,file,fileList){
      console.log(fileList)
      mymessage.success(response.msg);
      this.feature_url = response.url
      this.feature_log.push(response.msg)
      this.feature_log.push('构建完成时间：' + getCurrentDate(2))
      this.feature_log.push(response.my_label)
      this.feature_log.push(response.cwe_counts)
    },
    handleRemove1(file, fileList) {
      // console.log(fileList);
    },
    handlePreview1(file) {
      console.log(file);
    },
    beforeRemove1(file, fileList) {
      return this.$confirm(`确定移除 ${ file.name }？`);
    },

    //本地压缩文件格式处理
    uploadSuccess(response,file,fileList){
      console.log(fileList)
      mymessage.success(response.msg);
      this.feature_url = response.url
      this.feature_log.push(response.msg)
      this.feature_log.push('构建完成时间：' + getCurrentDate(2))
      this.feature_log.push(response.my_label)
      this.feature_log.push(response.cwe_counts)
    },
    handleRemove(file, fileList) {
      // console.log(fileList);
    },
    handlePreview(file) {
      console.log(file);
    },
    beforeRemove(file, fileList) {
      return this.$confirm(`确定移除 ${ file.name }？`);
    },

    //多分类特征转为二分类特征
    transfrom(){
      var that = this;
      $.ajax({
        url:  (http_head + '/interface/'),
        data:{
          method : 'getfeature_two',
          type : that.classification.feature,
        },
        type : 'post',
        dataType : 'JSON',
        success : function (res){
          console.log(res);
          that.feature_log.push(res.msg)
        },
        error: function (err) {
          console.log(err)
          mymessage.error("转化失败")
        }
      })
    },
    //下载feature记录文件
    feature_downLoad(){
      const fileUrl = this.feature_url
      console.log(fileUrl)
      if (fileUrl) {
        const link = document.createElement('a')
        //_blank表示在新窗口打开链接
        link.target = '_blank'
        link.href = fileUrl
        link.setAttribute('download', '文件' + Date.now()) // 下载文件的名称及文件类型后缀
        document.body.appendChild(link)
        link.click()
        document.body.removeChild(link) // 下载完成移除元素

      }
    },

    //选择特征模型类型
    changeValue1(val){
      if (val === '1'){
        this.train.dim = 768
        this.train.name = 'codebert'
      }else if(val === '2'){
        this.train.dim = 256
        this.train.name = 'codet5p'
      }else if(val === '3'){
        this.train.dim = 512
        this.train.name = 'codet5small'
      }else if(val === '4'){
        this.train.dim = 768
        this.train.name = 'codet5base'
      }else if(val === '5'){
        this.train.dim = 1024
        this.train.name = 'codet5large'
      }else if(val === '6'){
        this.train.dim = 1024
        this.train.name = 'codegen'
      }else if(val === '7'){
        this.train.dim = 2048
        this.train.name = 'deepseek'
      }else if(val === '8'){
        this.train.dim = 2560
        this.train.name = 'codegen2b'
      }
    },
    // 选择特征模型类型
    changeValue2(val){
      this.train.dim = Number(get_dim(this.train.feature1)) + Number(get_dim(this.train.feature2))
    },
    // 选择特征模型类型
    changeValue3(val){
      this.train.dim = Number(get_dim(this.train.feature1)) + Number(get_dim(this.train.feature2))
    },
    //单模型训练
    startProcess1(){
      var that = this;
      $.ajax({
        url:  (http_head + '/interface/'),
        data:{
          method : 'train',
          classification : that.train.classification,
          type : that.train.type,
          dim : that.train.dim,
          num : that.train.num,
          name : that.train.name,
        },
        type : 'post',
        dataType : 'JSON',
        success : function (res){
          console.log(res);
          that.train_url = res.url
          that.train_log.push(res.msg)
          that.train_log.push('训练完成时间：' + getCurrentDate(2))
          that.train_log.push('准确率：' +res.acc)
          that.train_log.push('精确率：' +res.precision)
          that.train_log.push('召回率：' +res.recall)
          that.train_log.push('F1分数：' +res.F1)
        },
        error: function (err) {
          console.log(err)
          mymessage.error("训练失败")
        }
      })
    },
    //混合特征模型训练
    startProcess2(){
      var that = this;
      $.ajax({
        url:  (http_head + '/interface/'),
        data:{
          method : 'train2',
          classification : that.train.classification,
          feature1 : that.train.feature1,
          feature2 : that.train.feature2,
          dim : that.train.dim,
          num : that.train.num,
          name : that.train.name,
        },
        type : 'post',
        dataType : 'JSON',
        success : function (res){
          console.log(res);
          that.train_url = res.url
          that.train_log.push(res.msg)
          that.train_log.push('训练完成时间：' + getCurrentDate(2))
          that.train_log.push('准确率：' +res.acc)
          that.train_log.push('精确率：' +res.precision)
          that.train_log.push('召回率：' +res.recall)
          that.train_log.push('F1分数：' +res.F1)
        },
        error: function (err) {
          console.log(err)
          mymessage.error("训练失败")
        }
      })
    },

    //下载训练记录文件
    train_downLoad(){
      const fileUrl = this.train_url
      console.log(fileUrl)
      if (fileUrl) {
        const link = document.createElement('a')
        //_blank表示在新窗口打开链接
        link.target = '_blank'
        link.href = fileUrl
        link.setAttribute('download', '文件' + Date.now()) // 下载文件的名称及文件类型后缀
        document.body.appendChild(link)
        link.click()
        document.body.removeChild(link) // 下载完成移除元素

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

function get_dim(type){
  let mapping = {
    '1': '768',
    '2': '256',
    '3': '512',
    '4': '768',
    '5': '1024',
    '6': '1024',
    '7': '2048',
    '8': '2560',
  }
  return mapping[type]
}
