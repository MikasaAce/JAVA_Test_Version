let mymessage = {}

var vm = new Vue({
    el: "#app",
    // router,
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
        this.currentPage = JSON.parse(sessionStorage.getItem('project_page1') || '1')
        this.pageSize = JSON.parse(sessionStorage.getItem('project_rows1') || '10')
        sessionStorage.removeItem('project_page1')
        sessionStorage.removeItem('project_rows1')
        this.getTableData()
        this.getInfoData()
    },
    data() {
        return {
            data1:'',
            data2:'',
            data3:'',
            data4:'',
            data5:'',
            data6:'',
            query:{
                project_name:''
            },
            tableData: [],
            currentPage: 1, //当前页 刷新后默认显示第一页
            pageSize: 10, //每一页显示的数据量 此处每页显示6条数据
            count:0,

            configs: false,
            config1:'',
            tableConfig:[],
            selectedModel:'',

            highlightedRow:'',

            getAlert:false,
            form:{
                item_name:'',
                description:'',
                language: '混合模式',
                source:'本地上传',

            },
            languages: scanLanguages,
            rules:{
                item_name: [
                    { required: true, message: '请输入项目名称', trigger: 'blur' },
                ],
                language: [
                    { required: true, message: '请选择代码语言', trigger: 'blur' },
                ],
                source: [
                    { required: true, message: '请选择代码来源', trigger: 'blur' },
                ],
            },
            countLoading:false,

            // 新增数据
            multipleSelection: [], // 存储选中的项目
            batchDeleteLoading: false, // 批量删除加载状态
        }

    },
    methods: {
        //查询
        checkFormData(){
            this.pageSize = 10;
            this.currentPage = 1;
            this.getTableData()
        },
        //新建项目
        createPro(){
            this.getAlert = true
        },
        //创建项目
        create(){
            var that = this
            console.log(localUser)
            
            // 处理语言参数：如果是"混合模式"则转换为"mix"
		  let languageParam = that.form.language;
		  if (that.form.language === '混合模式') {
		      languageParam = 'mixed';
		  }
		  
            $.ajax({
                url: (http_head + '/login/'),
                data:{
                    method : 'itemdetail_insert',
                    item_name : that.form.item_name,
                    language : languageParam,  // 使用处理后的参数
                    source : that.form.source,
                    description : that.form.description,
                    creator_id : localUser.accountId,
                    url:'',
                    createTime : getCurrentDate(2),
                    creator: localUser.username,
                },
                type: 'post',
                dataType: 'JSON',
                success: function (res){
                    console.log(res)
                    if(res.code === '200'){
                        mymessage.success("创建成功")
                        that.getTableData()
                        that.getAlert = false
                    }
                    if(res.msg === '项目名称已存在，请修改项目名之后新增'){
                        mymessage.error("项目名称已存在，请修改项目名后新增")
                    }

                },
                error: function (err) {
                    console.log(err)
                    mymessage.error("创建失败")
                }
            })
        },

        resetForm() {
            this.form = {
                item_name: '',
                description: '',
                language: '混合模式',
                source: '本地上传',
            }
        },
        //获取策略选中的模型
        handleTableChange(val) {
            this.currentRow = val;
            console.log(this.currentRow)
            this.selectedModel = this.currentRow.model_id
            // 假设你有一个包含类为 'highlight' 的父元素
            var parentElement = document.querySelector('.highlight');
            // 在该父元素下查找类为 'highlighted-row' 的子元素
            var highlightedRowElement = parentElement.querySelector('.highlighted-row');
            // 移除该子元素的所有样式
            // highlightedRowElement.removeAttribute('style')
            // console.log(highlightedRowElement.backgroundColor)
        },

        setCurrent(row) {
            this.$refs.singleTable.setCurrentRow(row);
        },
        //获取之前保存的配置
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
                    console.log(res);
                    sessionStorage.setItem('config',JSON.stringify(res))
                    if(res) {
                        that.config1 = res.policy
                        that.selectedModel = res.model

                        that.tableConfig.model_name = res.model
                        //高亮的行
                        that.highlightedRow = { model_name:that.tableConfig.model_name,
                        }
                        // console.log(that.highlightedRow)
                    }
                },
                error: function (err) {
                    console.log(err)
                }
            })
        },

        //获取项目统计信息
        getInfoData() {
            this.countLoading = true
            var that = this
            $.ajax({
                url: (http_head + '/login/'),
                data:{
                    method : 'project_statistics',
                },
                type: 'post',
                dataType: 'JSON',
                success: function (res){
                    // console.log(res)
                    if(res){
                        that.data1 = res[0].itemnum
                        that.data2 = res[1].tasknum
                        that.data3 = res[2].filenum
                        that.data4 = res[3].detecting
                        that.data5 = res[4].detected
                        that.data6 = res[5].Detection_failed
                    }
                    that.countLoading = false
                },
                error: function (err) {
                    console.log(err)
                    that.countLoading = false
                    // mymessage.error("获取失败")
                }
            })
        },

        //获取项目列表
        getTableData() {
            var that = this
            $.ajax({
                url: (http_head + '/login/'),
                data:{
                    method : 'item_list',
                    itemid : '',
                    itemname : that.query.project_name,
                    description : '',
                    language : '',
                    source : '',
                    createtime : '',
                    page : that.currentPage,
                    rows : that.pageSize,
                },
                type: 'post',
                dataType: 'JSON',
                success: function (res){
                    // console.log(res)
                    if(res.count > 0){
                        res.data.forEach(item => {
                            if (item.high == null) {
                                item.high = 0
                            }
                            if (item.med == null) {
                                item.med = 0
                            }
                            if (item.low == null) {
                                item.low = 0
                            }
                        })
                        that.tableData = res.data
                        that.count = res.count
                    } else {
                        that.tableData = [];
                        that.count = 0
                    }
                },
                error: function (err) {
                    console.log(err)
                    mymessage.error("项目列表获取失败")
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
            this.getTableData()

        },
        //查看详情
        view(row){
            console.log(row)
            sessionStorage.setItem('source',JSON.stringify(row.source))
            sessionStorage.setItem('itemid',JSON.stringify(row.itemid))
            sessionStorage.setItem('itemname',JSON.stringify(row.itemname))
            sessionStorage.setItem('language',JSON.stringify(row.language))
            sessionStorage.setItem('project_page1',JSON.stringify(this.currentPage))
            sessionStorage.setItem('project_rows1',JSON.stringify(this.pageSize))
            // window.location.href= './markList.html'
            window.open('./markList.html')

        },
        //缺陷统计
        account(row){
            console.log(row)
            sessionStorage.setItem('itemid',JSON.stringify(row.itemid))
            sessionStorage.setItem('project_page1',JSON.stringify(this.currentPage))
            sessionStorage.setItem('project_rows1',JSON.stringify(this.pageSize))
            window.location.href = 'bugAccount.html'
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
        del(row, instance) {
            console.log(row)
            var that = this;
            return new Promise((resolve, reject) => {
                $.ajax({
                    url: (http_head + '/login/'),
                    data: {
                        method: 'project_delete',
                        itemid: row.itemid,
                    },
                    type: 'post',
                    dataType: 'JSON',
                    success: function(res) {
                        console.log(res);
                        if (res.code === '200') {
                            mymessage.success(res.msg)
                        } else {
                            mymessage.error(res.msg)
                        }
                        that.getTableData()
                        that.getInfoData()
                        resolve(); // 确保Promise被resolve
                    },
                    error: function(err) {
                        console.log(err)
                        mymessage.error("删除失败")
                        reject(err); // 出错时reject
                    }
                });
            });
        },
        // 新增方法 - 处理表格选择项变化
        handleSelectionChange(val) {
            this.multipleSelection = val;
        },

        // 新增方法 - 批量删除确认
        batchDeleteConfirm() {
            if (this.multipleSelection.length === 0) {
                this.$message.warning('请至少选择一个项目');
                return;
            }

            this.$confirm(`确定要删除选中的 ${this.multipleSelection.length} 个项目吗?`, '提示', {
                confirmButtonText: '确定',
                cancelButtonText: '取消',
                type: 'warning',
                dangerouslyUseHTMLString: true,
                beforeClose: (action, instance, done) => {
                    if (action === 'confirm') {
                        instance.confirmButtonLoading = true;
                        this.batchDeleteProjects().finally(() => {
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
        batchDeleteProjects() {
            this.batchDeleteLoading = true;
            const itemIds = this.multipleSelection.map(item => item.itemid).join(',');

            return new Promise((resolve, reject) => {
                $.ajax({
                    url: (http_head + '/login/'),
                    type: 'post',
                    data: {
                        method: 'projects_batch_delete',
                        itemid_list: itemIds
                    },
                    dataType: 'JSON',
                    success: (res) => {
                        if (res.code === '200') {
                            this.$message.success(res.msg);
                            this.getTableData(); // 刷新列表
                            this.getInfoData(); // 刷新统计数据
                            this.multipleSelection = []; // 清空选择
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

        // 修改原有删除方法，保持一致性
        delopen(row) {
            this.$confirm(`确定要删除项目"${row.itemname}"吗?`, '提示', {
                confirmButtonText: '确定',
                cancelButtonText: '取消',
                type: 'warning',
                beforeClose: (action, instance, done) => {
                    if (action === 'confirm') {
                        instance.confirmButtonLoading = true;
                        this.del(row, instance).finally(() => {
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