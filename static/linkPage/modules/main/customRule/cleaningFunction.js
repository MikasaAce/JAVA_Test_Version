let mymessage = {}
var vm = new Vue({
    el: "#app",
    created(){
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

        this.getTableData()
        this.getAllVuls()
    },
    data() {
        return {
            relatedVul:[],
            current_policy_name:'',
            current_policy_id:'',
            query: {
                strategy_name:'',
            },
            editVul:[],
            allVuls:[],
            dialogTitle:'',
            loading1: false,
            edit_drawer:false,
            isFormDisabled:false,

            tableData:[],//存所有的漏洞类型
            iscreate: false,
            newConfigName:'',
            searchQuery: '',
            value:'',
            dialogVisible:false,
            changeVisible:false,
            currentPage: 1,
            pageSize: 10, // 每页显示的条数
            count:0,
            createForm:{
                name:'',
                language:'',
                vul_id:'',
                func_name:'',
                notes:'',
                status:'',
            },
            createRules: {
                name: [
                    { required: true, message: '请输入策略名称', trigger: 'blur' },
                ],
                language: [
                    { required: true, message: '请选择代码语言', trigger: 'blur' }
                ],
                vul_id: [
                    { required: true, message: '请选择缺陷类型', trigger: 'blur' }
                ],
                func_name: [
                    { required: true, message: '请输入清洁函数名称', trigger: 'blur' }
                ],
            },
            isNew: true,
            currentRowId:'',
            popoverVisible:false,
        };


    },

    methods:{
        getTableData(val){
            var that = this;
            if (val === 'chaxun') {
                this.currentPage = 1
            }
            $.ajax({
                url: (http_head + '/login/'),
                data:{
                    method : 'select_clean_func',
                    vul_name: that.query.strategy_name ? that.query.strategy_name : '',
                    language: that.query.language ? that.query.language : '',
                    status: that.query.status ? that.query.status : '',
                    id:'',
                    rows: that.pageSize,
                    page: that.currentPage,
                },
                type: 'post',
                dataType: 'JSON',
                success: function (res){
                    // console.log(res)
                    if(res.fileList.length > 0){
                        that.tableData = res.fileList
                        that.count = res.pagination.total
                    } else {
                        that.tableData = []
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
            this.pageSize = val;
            this.currentPage = 1;
            this.getTableData()

        },
        handleCurrentChange(val) {
            this.currentPage = val;
            this.getTableData()
        },

// 点击"新增"
        clickAdd(){
            this.dialogTitle = '新增策略'
            this.iscreate = true   //出现弹窗
            this.isNew = true     //新增时，下面的按钮是“立即创建”；编辑时，下面的按钮是“更新”
            this.isFormDisabled = false    //新增和编辑时，弹窗的表单可编辑，详情不可编辑
        },
        // "立即创建"
        submitForm(){
            var that = this;
            $.ajax({
                url: (http_head + '/login/'),
                data:{
                    method : 'insert_clean_func',
                    language: that.createForm.language ? that.createForm.language : '',
                    name: that.createForm.name ? that.createForm.name : '',
                    vul_id: that.createForm.vul_id ? that.createForm.vul_id : '',
                    func_name: that.createForm.func_name ? that.createForm.func_name : '',
                    notes: that.createForm.notes ? that.createForm.notes : '',
                    status: that.createForm.status ? that.createForm.status : '',
                },
                type: 'post',
                dataType: 'JSON',
                success: function (res){
                    // console.log(res)
                    if(res.msg){
                        mymessage.success(res.msg)
                        that.iscreate = false
                        that.getTableData()
                    }
                },
                error: function (err) {
                    console.log(err)
                    mymessage.error("项目列表获取失败")
                }
            })
        },
        // 获取所有的缺陷类型
        getAllVuls(){
            var that = this;
            $.ajax({
                url: (http_head + '/login/'),
                data:{
                    method : 'offer_subVul',
                },
                type: 'post',
                dataType: 'JSON',
                success: function (res){
                    // console.log(res)
                    if(res.vulList){
                        that.allVuls = res.vulList
                    }
                },
                error: function (err) {
                    console.log(err)
                }
            })
        },

        // 查看详情
        getDetails(row){
            var id = row.id
            const that = this;
            $.ajax({
                url: (http_head + '/login/'),
                data:{
                    method : 'select_clean_func',
                    id: id,
                    rows: 10,
                    page: 1,
                },
                type: 'post',
                dataType: 'JSON',
                success: function (res){
                    // console.log(res)
                    if(res.fileList){
                        that.createForm = res.fileList[0]
                        // 通过 vul_id 匹配到对应的 vul_name
                        const matchedItem = that.allVuls.find(item => item.id == res.fileList[0].vul_id); //一个是数字，一个是字符
                        // console.log(matchedItem)
                        if (matchedItem) {
                            that.createForm.vul_id = matchedItem.name; // 匹配到的名称
                        }
                    }
                },
                error: function (err) {
                    console.log(err)
                }
            })
        },
        //点击“详情”
        clickDetails(row){
            this.dialogTitle = '详情'
            this.getDetails(row)
            this.isFormDisabled = true
            this.iscreate = true
        },
//删除的弹窗
        delopen(row) {
            this.$confirm('此操作将删除该条缺陷处理策略, 是否继续?', '提示', {
                confirmButtonText: '确定',
                cancelButtonText: '取消',
                type: 'warning'
            }).then(() => {
                this.deleteStrategy(row)
            }).catch(() => {
                this.$message({
                    type: 'info',
                    message: '已取消删除'
                });
            });
        },
        // 确认删除
        deleteStrategy(row){
            console.log(row)
            const that = this
            var id = row.id
            $.ajax({
                url:  (http_head + '/login/'),
                data:{
                    method: 'delete_clean_func',
                    id: id,
                },
                type : 'post',
                dataType : 'JSON',
                success : function (res){
                    console.log(res)
                    if (res.msg) {
                        mymessage.success(res.msg)
                        that.getTableData()
                    }
                },
                error: function (err) {
                    console.log(err)
                }
            })
        },

// 点编辑
        handleChange(row) {
            this.dialogTitle = '编辑'
            this.getDetails(row)
            this.isFormDisabled = false
            this.iscreate = true
            this.isNew = false
            this.currentRowId = row.id
        },
        // 提交编辑
        submit_edit(){
            var that = this;
            $.ajax({
                url: (http_head + '/login/'),
                data:{
                    method : 'update_clean_func',
                    id: that.currentRowId,
                    language: that.createForm.language ? that.createForm.language : '',
                    name: that.createForm.name ? that.createForm.name : '',
                    vul_id: that.createForm.vul_id ? that.createForm.vul_id : '',
                    func_name: that.createForm.func_name ? that.createForm.func_name : '',
                    notes: that.createForm.notes ? that.createForm.notes : '',
                    status: that.createForm.status ? that.createForm.status : '',
                },
                type: 'post',
                dataType: 'JSON',
                success: function (res){
                    console.log(res)
                    if (res.msg) {
                        mymessage.success(res.msg)
                        that.iscreate = false
                        that.getTableData()
                    }
                },
                error: function (err) {
                    console.log(err)
                    mymessage.error("更新失败")
                }
            })
        },
        // 重置
        resetForm(){
            this.createForm.name = ''
            this.createForm.language = ''
            this.createForm.vul_id = ''
            this.createForm.func_name = ''
            this.createForm.notes = ''
            this.createForm.status = ''
        },
// 点击启用和停用
        ifUse(row){
            // row.popoverVisible = true;
            //启用状态status是1，停用状态是0
            console.log(row)
            if (row.status == '1'){
                this.$confirm('此操作将停用该条策略, 是否继续?', '提示', {
                    confirmButtonText: '确定',
                    cancelButtonText: '取消',
                }).then(() => {
                    this.switchingState(row)
                    this.resetForm()
                }).catch(() => {
                    this.$message({
                        type: 'info',
                        message: '已取消操作'
                    });
                });
            } else {
                this.$confirm('此操作将启用该条策略, 是否继续?', '提示', {
                    confirmButtonText: '确定',
                    cancelButtonText: '取消',
                }).then(() => {
                    this.switchingState(row)
                    this.resetForm()
                }).catch(() => {
                    this.$message({
                        type: 'info',
                        message: '已取消操作'
                    });
                });
            }
        },
        //切换启用和停用的状态
        switchingState(row){
            // console.log(row)
            const that = this
            this.createForm = row
            this.currentRowId = row.id    //如果不定义全局变量的话
            // console.log(this.createForm)
            if (row.status == '1'){
                var status = '0'
            } else if (row.status == '0'){
                var status = '1'
            }
            $.ajax({
                url: (http_head + '/login/'),
                data:{
                    method : 'update_clean_func',
                    id: that.currentRowId,
                    language: that.createForm.language ? that.createForm.language : '',
                    name: that.createForm.name ? that.createForm.name : '',
                    vul_id: that.createForm.vul_id ? that.createForm.vul_id : '',
                    func_name: that.createForm.func_name ? that.createForm.func_name : '',
                    notes: that.createForm.notes ? that.createForm.notes : '',
                    status: status,
                },
                type: 'post',
                dataType: 'JSON',
                success: function (res){
                    console.log(res)
                    if (res.msg) {
                        mymessage.success(res.msg)
                        that.iscreate = false
                        that.getTableData()
                    }
                },
                error: function (err) {
                    console.log(err)
                    mymessage.error("更新失败")
                }
            })
        },



    },
    // mounted() {
    //     // 初始化表格数据
    //     this.tableData = this.tableData.map(row => ({ ...row, popoverVisible: false }));
    // },


})