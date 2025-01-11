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
        this.uploadData = {method:'upload',itemId: 6}
        this.currentPage = JSON.parse(sessionStorage.getItem('page1') || '1')
        this.pageSize = JSON.parse(sessionStorage.getItem('rows1') || '10')
        this.getAllList();
        this.getModelList()

    },
    data() {
        return {
            loading:false,
            loading1: false,
            isshow : '1',
            getAlert: false,
            getupload : false,
            modelIteration : false,   //模型迭代
            tojump : false,
            query:{
                scan_type: '',
                project_name:'',
            },
            options:[],
            formConfig:{

            },
            formIteration:{},
            configs: false,
            config1:'',
            tableConfig:[],
            selectedModel:'',
            currentRow: null,
            highlightedRow:'',
            form:{
                name:'',     //项目名字
                createTime: '',  //创建时间
                lastScanTime:'',      //最后一次扫描时间
                riskLevel:'',         //风险等级
                status:'',            //扫描状态
                vulTotal:'',          //漏洞总数量
                team:'7',              //所属团队
                description:'',       //项目描述
                person:'',            //创建人
                language: 'java',          //开发语言
                type:'',              //类型（快速扫描、深度扫描）
            },
            rules:{
                name: [
                    { required: true, message: '请输入项目名称', trigger: 'blur' },
                ],
                type: [
                    { required: true, message: '请选择扫描类型', trigger: 'blur' },
                ],
                language: [
                    { required: true, message: '请选择代码语言', trigger: 'blur' },
                ],
            },
            radio:'检测',

            mutilab:'True',
            showmutilab:false,
            itemIds:'',
            tableData: [],
            currentPage: 1, //当前页 刷新后默认显示第一页
            pageSize: 10, //每一页显示的数据量 此处每页显示6条数据
            count:10,
            jumptable : [],
            // currentPage1: 1, //当前页 刷新后默认显示第一页
            pageSize1: 10, //每一页显示的数据量 此处每页显示6条数据
            count1:10,
            
            trainUrl: '',
            uploadData: '',
            iterateUrl:'',
            iterateData:'',
            fileListTrain: [],
            isShowList: true,
        };
    },

    methods: {
        initform(){
            this.form={
                name:'',
                createTime: getCurrentDate(2),
                lastScanTime:'',
                riskLevel:'',
                status:'',
                vulTotal:'',
                team:'7',
                description:'',
                person:'',
                language:'',
                type:'',
            }
        },
        //"配置策略“
        config(){
            this.configs = true
            this.getConfig()
            // this.getModelList()
        },
        //获取已有的模型
        getModelList() {
            const that = this
            $.ajax({
                url:  (http_head + '/qmq/'),
                type:'post',
                dataType: 'JSON',
                data:{
                    method:'get_list',
                },
                success:function (res){
                    console.log(res);
                    if (res){
                        var models = [];
                        var descriptions = [];
                        for(var key in res){
                            descriptions.push(key);
                            models.push(res[key]);
                        }
                        //选择模型策略
                        var result1 = models.map((model, index) => ({ model, description: descriptions[index] }));
                        result1 = result1.map(item => ({ model: `${item.model}`, description: item.description }));
                        that.tableConfig = result1
                        console.log(that.tableConfig)
                        //模型迭代
                        var result2 = descriptions.map((description, index) => ({ description, model: models[index] }));
                        result2 = result2.map(item => ({ description: `${item.description}: ${item.model}`, model: item.model}));
                        that.options = result2
                        console.log(that.options)


                    }
                },
                error: function (err) {
                    console.log(err)
                    mymessage.error("获取失败")
                }
            })
        },
        //获取策略选中的模型
        handleTableChange(val) {
            this.currentRow = val;
            console.log(this.currentRow)
            this.selectedModel = this.currentRow.description+'/'+this.currentRow.model
            // 假设你有一个包含类为 'highlight' 的父元素
            var parentElement = document.querySelector('.highlight');
            // 在该父元素下查找类为 'highlighted-row' 的子元素
            var highlightedRowElement = parentElement.querySelector('.highlighted-row');
            // 移除该子元素的所有样式
            highlightedRowElement.removeAttribute('style')
            console.log(highlightedRowElement.backgroundColor)
        },
        //高亮选中的配置（模型选择）
        rowClassName({ row }) {
            // 根据条件返回不同的类名
            // console.log(this.highlightedRow.model)
            // console.log(row.model)
            if (row.model === this.highlightedRow.model){
                console.log(row.model)
                return 'highlighted-row'
            }
            return '';

        },
        //获取项目列表
        getAllList(){
            this.loading = true;
            var that = this;
            $.ajax({
                url:  (http_head + '/login/'),
                data:{
                    method : 'project_getall',
                    accountId : localUser.accountId,
                    page   :  that.currentPage,
                    rows   :  that.pageSize,
                },
                type : 'post',
                dataType : 'JSON',
                success : function (res){
                    console.log(res);
                    if (res){
                        that.tableData = res.data
                        that.count  = parseInt(res.count)
                        // mymessage.success("获取成功")
                    }
                },
                error: function (err) {
                    console.log(err)
                    mymessage.error("获取失败")
                }
            })
            this.loading = false
        },
        handleSizeChange(val) {
            console.log(`每页 ${val} 条`);
            this.pageSize = val;
            sessionStorage.setItem('rows1',JSON.stringify(this.pageSize))
            this.getAllList()
        },
        //点击按钮切换页面
        handleCurrentChange(currentPage) {
            this.currentPage = currentPage; //每次点击分页按钮，当前页发生变化
            sessionStorage.setItem('page1',JSON.stringify(this.currentPage))
            this.getAllList();
        },
        //查询
        checkFormData(){
            this.loading = true;
            var that = this;
            $.ajax({
                url:  (http_head + '/login/'),
                data:{
                    method : 'project_query',
                    name : that.query.project_name,
                    type : that.query.scan_type,
                    accountId : localUser.accountId,
                },
                type : 'post',
                dataType : 'JSON',
                success : function (res){
                    console.log(res);
                    if (res){
                        that.tableData = res
                        mymessage.success("查询成功")
                        console.log(res.msg)
                        if (res.msg == '查询结果为空'){
                            that.tableData = []
                            mymessage.success(res.msg)
                        }
                    }
                },
                error: function (err) {
                    console.log(err)
                    mymessage.error("查询失败")
                }
            })
            this.loading = false
        },
        //新增项目
        createPro(){
            this.isshow = '1'
            this.getAlert = true;
            this.initform()
        },
        create(){
            this.loading = true;
            var that = this;
            this.$refs.form.validate((valid) => {
                if (valid) {
                    $.ajax({
                        url:  (http_head + '/login/'),
                        data:{
                            project_name  : that.form.name,                 //项目名字
                            createTime    : getCurrentDate(2)  ,                 //创建时间
                            lastScanTime  : that.form.lastScanTime,                 //最后一次扫描时间
                            riskLevel     : that.form.riskLevel   ,                 //风险等级
                            status        : that.form.status      ,                 //扫描状态
                            vulTotal      : that.form.vulTotal    ,                 //漏洞总数量
                            accountId     : localUser.accountId   ,                 //所属团队
                            description   : that.form.description ,                 //项目描述
                            person        : that.form.person      ,                 //创建人
                            language      : that.form.language    ,                 //开发语言
                            type          : that.form.type        ,                 //类型（快速扫描、深度扫描）
                            method        : 'project_insert',
                        },
                        type : 'post',
                        dataType : 'JSON',
                        success : function (res){
                            console.log(res);
                            if (res){
                                if(res.code === '500'){
                                    mymessage.error(res.msg)
                                }else {
                                    mymessage.success("新增成功")
                                    that.getAlert = false
                                    that.getAllList()
                                }
                            }
                        },
                        error: function (err) {
                            console.log(err)
                            mymessage.error("新增失败")
                        }
                    })
                } else {
                    console.log('error submit!!');
                    return false;
                }
            });

            this.loading = false
        },

        //更新
        edit(row){
            sessionStorage.setItem('editdata',JSON.stringify(row))
            this.getAlert = true;
            this.isshow = '2'
            var rows = JSON.parse(sessionStorage.getItem('editdata'))
            console.log(rows)
            this.form = rows
        },
        editsubmit(){
            var row = JSON.parse(sessionStorage.getItem('editdata'))
            this.loading = true;
            var that = this;
            this.$refs.form.validate((valid) => {
                if (valid) {
                    $.ajax({
                        url:  (http_head + '/login/'),
                        data:{
                            id            : row.id,
                            project_name  : that.form.name,                 //项目名字
                            createTime    : that.form.createTime  ,                 //创建时间
                            lastScanTime  : that.form.lastScanTime,                 //最后一次扫描时间
                            riskLevel     : that.form.riskLevel   ,                 //风险等级
                            status        : that.form.status      ,                 //扫描状态
                            vulTotal      : that.form.vulTotal    ,                 //漏洞总数量
                            // accountId     : that.form.team        ,                 //所属团队
                            description   : that.form.description ,                 //项目描述
                            person        : that.form.person      ,                 //创建人
                            language      : that.form.language    ,                 //开发语言
                            type          : that.form.type        ,                 //类型（快速扫描、深度扫描）
                            method        : 'project_update'
                        },
                        type : 'post',
                        dataType : 'JSON',
                        success : function (res){
                            console.log(res);
                            if (res){
                                mymessage.success("修改成功")
                                sessionStorage.clear()
                                that.getAlert = false
                                that.getAllList()
                            }
                        },
                        error: function (err) {
                            console.log(err)
                            mymessage.error("修改失败")
                        }
                    })
                } else {
                    console.log('error submit!!');
                    return false;
                }
            });

            this.loading = false
            this.initform()
        },

        //查看
        view(row){
            sessionStorage.setItem('projectid',JSON.stringify(row.id))
            sessionStorage.setItem('page1',JSON.stringify(this.currentPage))
            sessionStorage.setItem('rows1',JSON.stringify(this.pageSize))
            window.location.href = 'FileSummart.html'
        },
        //删除
        delopen(row) {
            this.$confirm('此操作将永久删除该项目文件, 是否继续?', '提示', {
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
            this.loading = true;
            var that = this;
            $.ajax({
                url:  (http_head + '/login/'),
                data:{
                    method : 'project_delete',
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
                            that.getAllList()
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

        //一键删除
        delAllopen(row) {
            this.$confirm('此操作将永久删除该项目及其所有检测文件, 是否继续?', '提示', {
                confirmButtonText: '确定',
                cancelButtonText: '取消',
                type: 'warning'
            }).then(() => {
                this.delAll(row)
            }).catch(() => {
                this.$message({
                    type: 'info',
                    message: '已取消删除'
                });
            });
        },
        delAll(row){
            console.log(row)
            this.loading = true;
            var that = this;
            $.ajax({
                url:  (http_head + '/login/'),
                data:{
                    method : 'vul_delete_all',
                    itemId  : row.id,
                },
                type : 'post',
                dataType : 'JSON',
                success : function (res){
                    console.log(res);
                    if (res){
                        if(res.code == '500'){
                            mymessage.error(res.msg)
                        }else {
                            mymessage.success("删除检测数据成功")
                            that.del(row)
                        }
                    }
                },
                error: function (err) {
                    console.log(err)
                    mymessage.error("删除检测数据失败")
                }
            })
            this.loading = false
        },

        //任务更改时参数  快速检测，修复
        // handleChange1(val){
        //     console.log(val)
        //     // this.uploadData = {method:'upload',itemId: this.itemIds, startTime:getCurrentDate(2),task:this.radio}
        //     this.uploadData.task = this.radio
        // },
        //任务更改时参数  单标签，多标签
        // handleChange2(val){
        //     console.log(val)
        //     // this.uploadData = {method:'upload',itemId: this.itemIds, startTime:getCurrentDate(2),task:this.radio}
        //     this.uploadData.muti_class = this.mutilab
        // },
        //保存配置
        save() {
            // console.log(username)
            const that = this
            this.configs = false
            console.log(that.config1,that.currentRow.model)
             $.ajax({
                 url:  (http_head + '/login/'),
                 data:{
                     method: 'insert_Pol',
                     account: username,
                     policy: that.config1,
                     model: that.selectedModel,
                 },

                 type : 'post',
                 dataType : 'JSON',
                 success : function (res){
                     console.log(res);
                     mymessage.success("保存成功")
                 },
                 error: function (err) {
                     console.log(err)
                     mymessage.error("保存失败")
                 }
             })
            this.getConfig()
        },
        //获取之前保存的配置
        getConfig() {
            const that = this
            $.ajax({
                url:  (http_head + '/login/'),
                data:{
                    method: 'get_Pol',
                    account: username,
                },
                type : 'post',
                dataType : 'JSON',
                success : function (res){
                    console.log(res);
                    if(res) {
                        that.config1 = res.policy
                        that.selectedModel = res.model

                        that.tableConfig.model = res.model.split('/')[2]
                        that.tableConfig.description = res.model.split('/')[0] + '/' + res.model.split('/')[1]
                        //高亮的行
                        that.highlightedRow = { description:that.tableConfig.description,
                            model: that.tableConfig.model, },
                        console.log(that.highlightedRow)
                    }
                },
                error: function (err) {
                    console.log(err)
                }
            })
        },

        //选择要进行迭代的模型
        chooseModel(){
            // console.log(this.formIteration.source)
            this.timeDate = this.formIteration.source.split(':')[0]
            console.log(this.timeDate)
            this.iterateData = {
                method:'re_train',
                model: this.timeDate,
            }
        },
        //模型迭代de上传
        uploadModel() {
            this.$refs.iterate.submit()
            this.modelIteration = false
        },
        beforeUpload(file) {
            console.log(file);
            if (!file.name.includes('.zip')) {
                mymessage.error('请上传zip类型压缩文件...')
                return false
            }
        },
        uploadSuccess(response, file, fileList) {
           this.fileList = []
            console.log(response)
            if (response){
                this.getAllList()
            }
        },
        removeList(file, fileList) {
            this.file = []
        },
        submitUpload() {
            this.$refs.upload.submit()
            this.getupload = false
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
}