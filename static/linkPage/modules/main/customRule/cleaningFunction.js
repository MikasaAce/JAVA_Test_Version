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
        this.getAppList()
    },
    data() {
        return {
            appOptions: [],
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
                class: '',
                method_desc: '',
                return_value: '',
                type: '0',
                range: [],
                create_time: '',
                creator: 'admin', // 实际项目中应从登录信息获取
                update_time: '',
                range_str: ''
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
                    { required: true, message: '请输入清洁规则', trigger: 'blur' }
                ],
                // class: [
                //     { required: true, message: '请输入类名', trigger: 'blur' }
                // ],
                // method_desc: [
                //     { required: true, message: '请输入方法描述', trigger: 'blur' }
                // ],
                // return_value: [
                //     { required: true, message: '请输入输出值', trigger: 'blur' }
                // ],
                type: [
                    { required: true, message: '请选择下发方式', trigger: 'change' }
                ],
                range: [
                    {
                        validator: (rule, value, callback) => {
                            if (this.createForm.type === '1' && value.length === 0) {
                                callback(new Error('请选择应用范围'));
                            } else {
                                callback();
                            }
                        },
                        trigger: 'change'
                    }
                ],
            },
            isNew: true,
            currentRowId:'',
            popoverVisible:false,
        };

    },

    computed: {
        selectedApps() {
            return this.createForm.range.map(id => {
                const app = this.appOptions.find(a => a.value === id);
                return {
                    value: id,
                    label: app ? app.label : '未知应用'
                };
            });
        }
    },

    methods:{
        getTableData(val){
            var that = this;
            if (val === 'chaxun') {
                this.currentPage = 1
            }
            // 确保页码不会小于1
            if (that.currentPage < 1) {
                that.currentPage = 1;
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
                        // 格式化时间
                        res.fileList.forEach(item => {
                            if (item.create_time) {
                                item.create_time = that.formatTime(item.create_time);
                            }
                            if (item.update_time) {
                                item.update_time = that.formatTime(item.update_time);
                            }
                        });

                        that.tableData = res.fileList
                        that.count = res.pagination.total
                    } else {
                        that.tableData = []
                        that.count = 0
                        // 重置到第一页
                        that.currentPage = 1;
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
        // 处理启用状态变更
        handleStatusChange(row, newStatus) {
            const action = newStatus === '1' ? '启用' : '停用';
            this.$confirm(`确定${action}该策略吗？`, '提示', {
                confirmButtonText: '确定',
                cancelButtonText: '取消',
                type: 'warning'
            }).then(() => {
                // 调用后端API更新状态
                this.updateStrategyStatus(row.id, newStatus).then(() => {
                    this.$message.success(`${action}成功`);
                }).catch(() => {
                    // 操作失败时恢复原状态
                    row.status = row.status === '1' ? '0' : '1';
                });
            }).catch(() => {
                // 取消操作时恢复原状态
                row.status = row.status === '1' ? '0' : '1';
            });
        },

        formatTime(timeStr) {
            if (!timeStr) return '';
            const date = new Date(timeStr);
            return date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
        },
        getAppList() {
            var that = this;
            $.ajax({
                url: (http_head + '/login/'),
                data: {
                    method: 'item_list',
                    itemid: '',
                    itemname: '',
                    description: '',
                    language: '',
                    source: '',
                    createtime: '',
                    page: 1,
                    rows: 1000 // 获取足够多的项目
                },
                type: 'post',
                dataType: 'JSON',
                success: function (res) {
                    if (res.count > 0) {
                        that.appOptions = res.data.map(item => ({
                            value: item.itemid,
                            label: item.itemname
                        }));
                    } else {
                        that.appOptions = [];
                    }
                },
                error: function (err) {
                    console.log(err);
                    mymessage.error("应用列表获取失败");
                }
            });
        },
        removeApp(appId) {
            this.createForm.range = this.createForm.range.filter(id => id !== appId);
        },

// 点击"新增"
        clickAdd(){
            this.dialogTitle = '新增策略'
            this.iscreate = true   //出现弹窗
            this.isNew = true     //新增时，下面的按钮是“立即创建”；编辑时，下面的按钮是“更新”
            this.isFormDisabled = false    //新增和编辑时，弹窗的表单可编辑，详情不可编辑
        },

        // 格式化日期时间为 "YYYY-MM-DD HH:mm:ss" 格式
        formatDateTime(date) {
            const d = date ? new Date(date) : new Date();
            const year = d.getFullYear();
            const month = String(d.getMonth() + 1).padStart(2, '0');
            const day = String(d.getDate()).padStart(2, '0');
            const hours = String(d.getHours()).padStart(2, '0');
            const minutes = String(d.getMinutes()).padStart(2, '0');
            const seconds = String(d.getSeconds()).padStart(2, '0');
            return `${year}-${month}-${day} ${hours}:${minutes}:${seconds}`;
        },
        // "立即创建"
        submitForm(){
            var that = this;
            this.$refs.ruleForm.validate((valid) => {
                if (!valid) {
                    return false;
                }

                const rangeStr = that.createForm.type === '1'
                  ? that.createForm.range.join(',')
                  : '';

                const postData = {
                    method: 'insert_clean_func',
                    language: that.createForm.language ? that.createForm.language : '',
                    name: that.createForm.name ? that.createForm.name : '',
                    vul_id: that.createForm.vul_id ? that.createForm.vul_id : '',
                    func_name: that.createForm.func_name ? that.createForm.func_name : '',
                    notes: that.createForm.notes ? that.createForm.notes : '',
                    status: that.createForm.status ? that.createForm.status : '',
                    class: that.createForm.class ? that.createForm.class : '',
                    method_desc: that.createForm.method_desc ? that.createForm.method_desc : '',
                    return_value: that.createForm.return_value ? that.createForm.return_value : '',
                    type: that.createForm.type ? that.createForm.type : '',
                    create_time: this.formatDateTime(new Date()), // 使用格式化后的时间
                    // creator: that.createForm.creator,
                    creator: localUser.account,
                    range: rangeStr,
                    task_name: that.createForm.task_name ? that.createForm.task_name : '',
                };

                $.ajax({
                    url: (http_head + '/login/'),
                    data: postData,
                    type: 'post',
                    dataType: 'JSON',
                    success: function (res){
                        if(res.msg){
                            mymessage.success(res.msg);
                            that.iscreate = false;
                            that.getTableData();
                        }
                    },
                    error: function (err) {
                        console.log(err);
                        mymessage.error("创建失败");
                    }
                });
            });
        },
        // submitForm(){
        //     var that = this;
        //     $.ajax({
        //         url: (http_head + '/login/'),
        //         data:{
        //             method : 'insert_clean_func',
        //             language: that.createForm.language ? that.createForm.language : '',
        //             name: that.createForm.name ? that.createForm.name : '',
        //             vul_id: that.createForm.vul_id ? that.createForm.vul_id : '',
        //             func_name: that.createForm.func_name ? that.createForm.func_name : '',
        //             notes: that.createForm.notes ? that.createForm.notes : '',
        //             status: that.createForm.status ? that.createForm.status : '0',
        //         },
        //         type: 'post',
        //         dataType: 'JSON',
        //         success: function (res){
        //             // console.log(res)
        //             if(res.msg){
        //                 mymessage.success(res.msg)
        //                 that.iscreate = false
        //                 that.getTableData()
        //             }
        //         },
        //         error: function (err) {
        //             console.log(err)
        //             mymessage.error("项目列表获取失败")
        //         }
        //     })
        // },

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
                        // that.createForm = res.fileList[0]
                        const data = res.fileList[0];
                        that.createForm = {
                            ...data,
                            range: data.range_str ? data.range_str.split(',') : []
                        };
                        // 通过 vul_id 匹配到对应的 vul_name
                        const matchedItem = that.allVuls.find(item => item.id == res.fileList[0].vul_id); //一个是数字，一个是字符
                        // console.log(matchedItem)
                        if (matchedItem) {
                            // that.createForm.vul_id = matchedItem.name; // 匹配到的名称
                            that.createForm.vul_id = matchedItem.id; // 保持ID
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
                        // 关键修改：更新总计数并重新计算分页
                        that.count = that.count - 1;  // 更新总条数

                        // 计算删除后的总页数
                        const totalPages = Math.ceil(that.count / that.pageSize);

                        // 修正当前页码
                        if (that.currentPage > totalPages && totalPages > 0) {
                            that.currentPage = totalPages;
                        }

                        // 重新获取数据
                        that.getTableData();
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
            this.$refs.ruleForm.validate((valid) => {
                if (!valid) {
                    return false;
                }

                const rangeStr = that.createForm.type === '1'
                  ? that.createForm.range.join(',')
                  : '';

                const postData = {
                    method: 'update_clean_func',
                    id: that.currentRowId,
                    language: that.createForm.language ? that.createForm.language : '',
                    name: that.createForm.name ? that.createForm.name : '',
                    vul_id: that.createForm.vul_id ? that.createForm.vul_id : '',
                    func_name: that.createForm.func_name ? that.createForm.func_name : '',
                    notes: that.createForm.notes ? that.createForm.notes : '',
                    status: that.createForm.status ? that.createForm.status : '',
                    class: that.createForm.class ? that.createForm.class : '',
                    method_desc: that.createForm.method_desc ? that.createForm.method_desc : '',
                    return_value: that.createForm.return_value ? that.createForm.return_value : '',
                    type: that.createForm.type ? that.createForm.type : '',
                    update_time: this.formatDateTime(new Date()), // 使用格式化后的时间
                    range: rangeStr,
                    task_name: that.createForm.task_name ? that.createForm.task_name : '',
                };

                $.ajax({
                    url: (http_head + '/login/'),
                    data: postData,
                    type: 'post',
                    dataType: 'JSON',
                    success: function (res){
                        if (res.msg) {
                            mymessage.success(res.msg);
                            that.iscreate = false;
                            that.getTableData();
                        }
                    },
                    error: function (err) {
                        console.log(err);
                        mymessage.error("更新失败");
                    }
                });
            });
        },
        // submit_edit(){
        //     var that = this;
        //     $.ajax({
        //         url: (http_head + '/login/'),
        //         data:{
        //             method : 'update_clean_func',
        //             id: that.currentRowId,
        //             language: that.createForm.language ? that.createForm.language : '',
        //             name: that.createForm.name ? that.createForm.name : '',
        //             vul_id: that.createForm.vul_id ? that.createForm.vul_id : '',
        //             func_name: that.createForm.func_name ? that.createForm.func_name : '',
        //             notes: that.createForm.notes ? that.createForm.notes : '',
        //             status: that.createForm.status ? that.createForm.status : '',
        //         },
        //         type: 'post',
        //         dataType: 'JSON',
        //         success: function (res){
        //             console.log(res)
        //             if (res.msg) {
        //                 mymessage.success(res.msg)
        //                 that.iscreate = false
        //                 that.getTableData()
        //             }
        //         },
        //         error: function (err) {
        //             console.log(err)
        //             mymessage.error("更新失败")
        //         }
        //     })
        // },

        // 重置
        // resetForm(){
        //     this.createForm.name = ''
        //     this.createForm.language = ''
        //     this.createForm.vul_id = ''
        //     this.createForm.func_name = ''
        //     this.createForm.notes = ''
        //     this.createForm.status = ''
        //
        // },
        resetForm(){
            this.createForm = {
                name: '',
                language: '',
                vul_id: '',
                func_name: '',
                notes: '',
                status: '0',
                class: '',
                method_desc: '',
                return_value: '',
                type: '0',
                range: [],
                task_name: '' ,// 新增任务名称字段
                create_time: '',
                creator: 'admin',
                update_time: '',
                range_str: ''
            };
            if (this.$refs.ruleForm) {
                this.$refs.ruleForm.clearValidate();
            }
        },


        // 处理状态切换
        handleStatusChange(row) {
            const action = row.status === '1' ? '启用' : '停用';
            const newStatus = row.status;
            const oldStatus = row.status === '1' ? '0' : '1';

            this.$confirm(`确定${action}该策略吗？`, '提示', {
                confirmButtonText: '确定',
                cancelButtonText: '取消',
                type: 'warning'
            }).then(() => {
                // 保存当前页码和总条数
                const currentPage = this.currentPage;
                const totalItems = this.count;
                // 发送状态更新请求
                this.updateStatus(row.id, newStatus, oldStatus, row);
                // 计算新的总页数
                const totalPages = Math.ceil(totalItems / this.pageSize);

                // 如果当前页大于总页数（说明最后一页数据被删光了）
                if (currentPage > totalPages && totalPages > 0) {
                    this.currentPage = totalPages; // 跳转到最后一页
                }
                // 重新获取数据
                this.getTableData();
                this.resetForm()
            }).catch(() => {
                // 取消操作时恢复原状态
                row.status = oldStatus;
                this.$message({
                    type: 'info',
                    message: '已取消操作'
                });
            });
        },

        // 更新状态的方法
        updateStatus(id, newStatus, oldStatus, row) {
            const that = this;
            this.createForm = row;
            $.ajax({
                url: (http_head + '/login/'),
                data: {
                    method: 'update_clean_func',
                    id: id,
                    language: that.createForm.language ? that.createForm.language : '',
                    name: that.createForm.name ? that.createForm.name : '',
                    vul_id: that.createForm.vul_id ? that.createForm.vul_id : '',
                    func_name: that.createForm.func_name ? that.createForm.func_name : '',
                    notes: that.createForm.notes ? that.createForm.notes : '',
                    status: newStatus,
                    task_name: that.createForm.task_name ? that.createForm.task_name : '',
                },
                type: 'post',
                dataType: 'JSON',
                success: function(res) {
                    if (res.msg) {
                        mymessage.success(res.msg);
                        // 更新本地数据状态
                        row.status = newStatus;
                        that.getTableData()
                    } else {
                        // 失败时恢复原状态
                        row.status = oldStatus;
                        that.getTableData()
                    }
                    // that.getTableData()
                },
                error: function(err) {
                    console.log(err);
                    mymessage.error("状态更新失败");
                    // 失败时恢复原状态
                    row.status = oldStatus;
                }
            });
        },
        // // 点击启用和停用
        // ifUse(row){
        //     // row.popoverVisible = true;
        //     //启用状态status是1，停用状态是0
        //     console.log(row)
        //     if (row.status == '1'){
        //         this.$confirm('此操作将停用该条策略, 是否继续?', '提示', {
        //             confirmButtonText: '确定',
        //             cancelButtonText: '取消',
        //         }).then(() => {
        //             this.switchingState(row)
        //             this.resetForm()
        //         }).catch(() => {
        //             this.$message({
        //                 type: 'info',
        //                 message: '已取消操作'
        //             });
        //         });
        //     } else {
        //         this.$confirm('此操作将启用该条策略, 是否继续?', '提示', {
        //             confirmButtonText: '确定',
        //             cancelButtonText: '取消',
        //         }).then(() => {
        //             this.switchingState(row)
        //             this.resetForm()
        //         }).catch(() => {
        //             this.$message({
        //                 type: 'info',
        //                 message: '已取消操作'
        //             });
        //         });
        //     }
        // },
        // //切换启用和停用的状态
        // switchingState(row){
        //     // console.log(row)
        //     const that = this
        //     this.createForm = row
        //     this.currentRowId = row.id    //如果不定义全局变量的话
        //     // console.log(this.createForm)
        //     if (row.status == '1'){
        //         var status = '0'
        //     } else if (row.status == '0'){
        //         var status = '1'
        //     }
        //     $.ajax({
        //         url: (http_head + '/login/'),
        //         data:{
        //             method : 'update_clean_func',
        //             id: that.currentRowId,
        //             language: that.createForm.language ? that.createForm.language : '',
        //             name: that.createForm.name ? that.createForm.name : '',
        //             vul_id: that.createForm.vul_id ? that.createForm.vul_id : '',
        //             func_name: that.createForm.func_name ? that.createForm.func_name : '',
        //             notes: that.createForm.notes ? that.createForm.notes : '',
        //             status: status,
        //         },
        //         type: 'post',
        //         dataType: 'JSON',
        //         success: function (res){
        //             console.log(res)
        //             if (res.msg) {
        //                 mymessage.success(res.msg)
        //                 that.iscreate = false
        //                 that.getTableData()
        //             }
        //         },
        //         error: function (err) {
        //             console.log(err)
        //             mymessage.error("更新失败")
        //         }
        //     })
        // },



    },
    // mounted() {
    //     // 初始化表格数据
    //     this.tableData = this.tableData.map(row => ({ ...row, popoverVisible: false }));
    // },


})