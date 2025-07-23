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
        this.getModel()
    },
    data() {
        return {
            tabPosition: 'left',
            modelAll:[],
            dialogFormVisible:false,
            formEdit:{
                model_name:'',
                remarks:'',
            },
            editModel:'',
            activeName1: 'first',
            activeName2: 'first',

            transferData1: [],
            transferData2: [],

            positiveSample: [],
            positiveSample1: [],

            negativeSample: [],
            negativeSample2: [],
            //本地上传
            uploadURL:http_head + '/Muti/',
            uploadURLData:{method:'positive_get',upload_id:'2',},
            uploadFileList: [],
            //负样本本地上传
            uploadURL_Negative:http_head + '/Muti/',
            uploadURLData_Negative:{method:'negative_get',},
            uploadFileList_Negative: [],

            selectedModel:'',
            formPositive:{
                date1:'',
                url:'',
                key:'',
            },
            formNegative:{
                date:'',
            },
            date_PositiveUpload:'',

            log:'',
            checkIndex: 0,
        }

    },
    methods: {
        //获取模型
        getModel(){
            const that = this
            $.ajax({
                url:  (http_head + '/login/'),
                type:'post',
                dataType: 'JSON',
                data:{
                    method:'get_model_id',
                },
                success:function (res){
                    // console.log(res);
                    // if (that.log.indexOf('模型迭代完成') !== -1) {
                    //     console.log(1111111111111111111111111111)
                    // }
                    if (res){
                        for (let i = 0;i < res.length; i++){

                            res[i].cwe_id = eval ("(" + res[i].cwe_id + ")")   //转成对象
                            res[i].model_path = String(Object.keys(res[i].cwe_id).length)   //识别漏洞数量
                            //拼接cwe   识别漏洞种类
                            var type = ''
                            for (var key in res[i].cwe_id) {
                                type += key + ', '
                            }
                            res[i].cwe_id = type
                            //训练时长
                            // 将日期字符串转换为Date对象
                            var date1 = new Date(res[i].model_train_start);
                            var date2 = new Date(res[i].model_train_end);

                            // 计算时间差（单位：毫秒）
                            var timeDiff = Math.abs(date2 - date1);

                            // 将时间差转换为小时、分钟和秒
                            var hoursDiff = Math.floor(timeDiff / (1000 * 60 * 60));
                            var minutesDiff = Math.floor((timeDiff % (1000 * 60 * 60)) / (1000 * 60));
                            var secondsDiff = Math.floor((timeDiff % (1000 * 60)) / 1000);

                            // 格式化时间差字符串
                            res[i].model_train_end = hoursDiff + "小时" + minutesDiff + "分" + secondsDiff + "秒";
                        }
                        that.modelAll = res

                    }
                },
                error: function (err){
                    console.log(err)
                    mymessage.error("模型获取失败")
                }
            })
        },
        //表格编辑
        handleEdit(index, row) {
            console.log(index, row);
            this.dialogFormVisible = true
            this.formEdit.model_name = row.model_name
            this.formEdit.remarks = row.remarks

            this.editModel = row.model_id
        },
        identifyEdit() {
            this.dialogFormVisible = false
            const that = this
            $.ajax({
                url:  (http_head + '/login/'),
                type:'post',
                dataType: 'JSON',
                data:{
                    method: 'update_model',
                    model_id: that.editModel,
                    model_name: that.formEdit.model_name ? that.formEdit.model_name : '',
                    model_remarks: that.formEdit.remarks ? that.formEdit.remarks : '',
                },
                success:function (res){
                    console.log(res)
                    that.getModel()
                },
                error: function (err){
                    console.log(err)
                    mymessage.error("修改失败")
                }
            })
        },
        //表格删除
        handleDelete(index, row) {
            console.log(index, row);
            this.$confirm('此操作将删除该模型, 是否继续?', '提示', {
                confirmButtonText: '确定',
                cancelButtonText: '取消',
                type: 'error'
            }).then(() => {
                const that = this
                $.ajax({
                    url:  (http_head + '/login/'),
                    type:'post',
                    dataType: 'JSON',
                    data:{
                        method: 'delete_model',
                        model_id: row.model_id,
                    },
                    success:function (res){
                        mymessage.success("删除成功")
                        that.getModel()
                    },
                    error: function (err){
                        // console.log(err)
                        mymessage.error("删除失败")
                    }
                })
            }).catch(() => {
                this.$message({
                    type: 'info',
                    message: '已取消删除'
                });
            });
        },
        //正样本标签页
        handleClick(tab, event) {
            // console.log(tab, event);
        },

        //上传成功时的钩子函数
        uploadSuccess(response,file,fileList){
            console.log(fileList)
            // console.log(response)
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
        //这里是负样本的上传
        uploadSuccess_Negative(response,file,fileList){
            // console.log(fileList)
            console.log(response)
            if (response.msg === '文件名不符合规范'){
                mymessage.error('文件名不符合规范')
            } else if (response.msg === '所有负样本数据插入成功') {
                mymessage.success('文件上传成功')
            }

        },
        handleRemove_Negative(file, fileList) {
            // console.log(fileList);
        },
        handlePreview_Negative(file) {
            console.log(file);
        },
        beforeRemove_Negative(file, fileList) {
            return this.$confirm(`确定移除 ${ file.name }？`);
        },
        //-----------------------------------------------------------------
        //获取git拉取的正样本列表
        getPositiveGit(){

        },
        //获取本地上传的正样本列表
        getPositiveUpload(){
            const that = this
            // console.log(this.date_PositiveUpload)
            $.ajax({
                url:  (http_head + '/login/'),
                type:'post',
                dataType: 'JSON',
                data:{
                    method: 'positive_list',
                    starttime: that.date_PositiveUpload[0],
                    endtime: that.date_PositiveUpload[1],
                    account: localUser.accountId,
                },
                success:function (res){
                    // console.log(res)
                    if(res.msg === '统计结果为空'){
                        mymessage.success("统计结果为空")
                    } else {
                        that.transferData1 = res
                    }
                },
                error: function (err){
                    console.log(err)
                    mymessage.error("负样本获取失败")
                }
            })
        },
        //获取负样本列表
        getNegative(){
            const that = this
            $.ajax({
                url:  (http_head + '/login/'),
                type:'post',
                dataType: 'JSON',
                data:{
                    method: 'negative_list',
                    starttime: that.formNegative.date[0],
                    endtime: that.formNegative.date[1],
                    // starttime: '2024-03-11',
                    // endtime: '2024-03-12',
                    account: localUser.accountId,
                },
                success:function (res){
                    // console.log(res)
                    if(res.msg === '统计结果为空'){
                        mymessage.success("统计结果为空")
                    } else {
                        that.transferData2 = res
                    }

                },
                error: function (err){
                    console.log(err)
                    mymessage.error("负样本获取失败")
                }
            })
        },

        //获取选中的模型
        handleTableChange(val) {
            console.log(val)
            if (val) {
                this.selectedModel = val.model_id
            }
        },
        //获取选中的正样本
        handleTransferChange1(value, direction, movedKeys){
            console.log(value, direction, movedKeys);
            this.positiveSample = value
            this.positiveSample1 = JSON.stringify(value)
            this.positiveSample1 = this.positiveSample1.replace(/\"/g,"")
            // console.log(this.positiveSample1)

        },
        //获取选中的负样本
        handleTransferChange2(value, direction, movedKeys) {
            console.log(value, direction, movedKeys);
            this.negativeSample = value
            this.negativeSample1 = JSON.stringify(value)
            this.negativeSample1 = this.negativeSample1.replace(/\"/g,"")
        },
        startProcess(){
            this.startTraing()
            this.getLog()
        },
        //开始训练
        startTraing(){
            const that = this
            $.ajax({
                url:  (http_head + '/Muti/'),
                type:'post',
                dataType: 'JSON',
                data:{
                    method: 're_train',
                    model_id: that.selectedModel,
                    positive_data: that.positiveSample1,
                    negative_data: that.negativeSample1,
                },
                success:function (res){
                    console.log(res)
                    mymessage.success("模型迭代完成！")
                },
                error: function (err){
                    console.log(err)
                    mymessage.error("训练失败")
                }
            })
        },
        //获取日志
        getLog(){
            const that = this
            $.ajax({
                url:  (http_head + '/Muti/'),
                type:'post',
                dataType: 'JSON',
                data:{
                    method: 'get_log',
                },
                success:function (res){
                    console.log(res)

                    if (res.log && res.log.indexOf('Model iteration completed!') !== -1) {
                        that.log = res.log
                        mymessage.success('训练已经成功!');
                    }
                    else if(that.checkIndex >= 100){
                        that.checkIndex = 0
                        mymessage.error("连接失败")
                    }
                    else {
                            if(res.log){
                                that.log = res.log
                            }
                            that.checkIndex++
                            // 继续轮询
                            setTimeout(that.getLog(), 1500); // 5秒后再次轮询
                    }


                },
                error: function (err){
                    console.log(err)
                    mymessage.error("日志获取失败")
                }
            })
        },


    }

})