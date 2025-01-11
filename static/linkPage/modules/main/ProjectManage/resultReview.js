
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
        this.taskid = JSON.parse(sessionStorage.getItem('taskid_result') || '')
        this.getVulList()
        this.getConfig()
        this.ifDescription()
    },
    data() {
        return {
            isRouterAlive : true,
            // fileList: [
            //     { name: "CWE 235", files: [{ name: "brackets.java" }, { name: "checkdll.java" }, { name: "comment_save.java" }] },
            //     { name: "CWE 89", files: [{ name: "内容4" }, { name: "内容5" }] },
            // ],
            fileList:[],
            firstFile:'',
            moren: true,
            currentFileId:'',
            currentFileIds:[],
            pp:[],
            allFileId:[],
            // value: '',
            // input: '',
            activeName: 'first',
            descriptionOrNot:true,
            taskid:'',
            showDialog: false,
            fileidid:'',
            form: {
                Question:'',
                list1:'',
                list2:'',
            },
            form1: {
                Question:'',
                list1:'',
                list2:'',
            },
            isDisabled1:false,
            isDisabled2:false,
            // options:[],
            checkList1:[],
            checkList2:[],
            descriptions:{},
            details:{
                filepath:'',
                source_code:'',
                repair_code:'',
            },
            dialogVisible:false,
            textarea:'',
            ifDeepSeek:false,
            loading:false,
            tabflag:'代码详情',
        }
    },
    provide() {
        //提供
        return {
            reload: this.reload,
        };
    },
    methods: {
        goBack(){
            window.location.href = 'markList.html'
        },
        getCheckedKeys(leafOnly){
            console.log(leafOnly);
        },
        shenhe(){
            this.showDialog = true
            //点击所有会产生undefined导致报错，需要去除
            this.pp=this.$refs.tree.getCheckedKeys()
            this.allFileId= this.pp.filter(item => {
                // 检查item不是null、undefined、NaN，也不是空字符串或仅包含空格的字符串
                return item !== null && item !== undefined && !isNaN(item) && item.trim() !== '';
            });
            console.log(this.allFileId);
        },

        //局部刷新
        reload() {
            this.isRouterAlive = false;
            this.$nextTick(function () {
                this.isRouterAlive = true;
            });
        },
        provide() {
            //提供
            return {
                reload: this.reload,
            };
        },

        //为了获取这个任务的扫描策略
        ifDescription(){
            var that = this
            $.ajax({
                url: (http_head + '/login/'),
                data:{
                    method : 'Task_Detail_1',
                    task_id: that.taskid,
                },
                type: 'post',
                dataType: 'JSON',
                success: function (res){
                    console.log('策略',res)
                    if (res[0].type === 'deepseek1.3b检测' || res[0].type === 'deepseek6.7b检测' || res[0].type === 'qwen7b检测' || res[0].type === '组合扫描-3'){
                        that.descriptionOrNot = false

                    }
                    console.log(that.descriptionOrNot)

                },
                error: function (err) {
                    console.log(err)
                    mymessage.error("获取失败")
                }
            })
        },
        //左侧漏洞列表
        getVulList() {
            const that = this
            $.ajax({
                url: (http_head + '/login/'),
                type: 'post',
                dataType: 'json',
                data: {
                    method: 'get_all_vultype_files',
                    task_id: that.taskid,
                },
                success: function (res) {
                    if(res.fileList[0]){
                        // console.log('列表',res.fileList)
                        that.fileList = res.fileList
                        for (let i = 0;i<res.fileList.length;i++){
                            var filesArray = res.fileList[i].files;
                            // 提取 files 数组中的 name 属性
                            var fileNamesArray = filesArray.map(function(file) {
                                return file.name;
                            });
                            var result = fileNamesArray.join(", ");
                            // console.log(res.fileList[i].name,result); // 输出字符串
                        }

                        //默认显示的文件
                        that.firstFile = res.fileList[0].files[0].fileid
                        that.currentFileId = that.firstFile
                    }
                    that.getDetails()
                    that.getDescriptions()
                    that.getRepair()
                    // that.reload()
                },
                error: function (err) {
                    console.log(err)
                    mymessage.error("列表获取失败")
                }
            })
        },
        //tabs标签页
        handleClick(tab, event) {
            // console.log(tab.label)
            this.tabflag = tab.label
            if(tab.label === '代码详情') {
                // this.reload()
                this.getDetails()
            } else if(tab.label === '缺陷描述') {
                // this.reload()
                this.getDescriptions()
            } else if(tab.label === '代码修复') {
                // this.reload()
                this.getRepair()
            }
        },
        //左侧树形控件
        handleNodeClick(data, node,nodeData) {
            // console.log(data);
            // console.log(nodeData)
            // console.log(node.level);  //第几层
            //如果点的是文件
            if (node.level === 2){
                console.log('当前的tab:',this.tabflag)
                this.currentFileId = data.fileid
                if(this.tabflag === '代码详情') {
                    this.reload()
                    this.getDetails()
                } else if(this.tabflag === '缺陷描述') {
                    // this.reload()
                    this.getDescriptions()
                } else if(this.tabflag === '代码修复') {
                    // this.reload()
                    this.getRepair()
                    // this.equalLength()
                }
                // this.reload()
            }

        },


        //代码详情
        getDetails(){
            const that = this
            $.ajax({
                url: (http_head + '/login/'),
                type: 'post',
                datatype: 'json',
                data: {
                    method: 'VulType_get',
                    fileid: that.currentFileId,
                },
                success: function (res){
                    res = JSON.parse(res)

                    console.log('代码详情',res)

                    if(res.fileList[0]){
                        that.details = res.fileList[0]
                        // 获取代码块元素
                        var codeBlock = document.getElementById("codeBlock");
                        // 要高亮的行字符串，例如 "37,38,40"
                        var highlightedLinesString = res.fileList[0].code_location
                        // 将字符串拆分成行号数组
                        var highlightedLines = highlightedLinesString.split(",").map(Number);
                        // 获取代码块的内容
                        var code = res.fileList[0].source_code;
                        // 将代码内容拆分成行数组
                        var lines = code.split("\n");
                        // 遍历要高亮的行号数组
                        highlightedLines.forEach(function(lineNumber) {
                            // 确保行号有效且未高亮过
                            if (lineNumber >= 1 && lineNumber <= lines.length && !lines[lineNumber - 1].includes("line-highlight")) {
                                // 在要高亮的行前后添加 span 元素
                                lines[lineNumber - 1] = "<span class='line-highlight'>"  + lines[lineNumber - 1] + "</span>";
                            }
                        });
                        // 更新代码块内容
                        codeBlock.innerHTML = "<code>" + lines.join("\n") + "</code>";
                        // console.log(codeBlock)

                        //提交的修复反馈的内容
                        that.textarea = res.fileList[0].repair_feedback
                        //回显提交的审核
                        if (res.fileList[0].is_question === '是问题') {
                            that.form.Question = '是问题'
                            if (res.fileList[0].risk_level === '高危') {
                                that.form.list1 = 1
                            } else if (res.fileList[0].risk_level === '中危') {
                                that.form.list1 = 2
                            }  else if (res.fileList[0].risk_level === '低危') {
                                that.form.list1 = 3
                            }
                        } else if (res.fileList[0].is_question === '不是问题') {
                            that.form.Question = '不是问题'
                            if (res.fileList[0].is_fp === '是误报') {
                                that.form.list2 = 1
                            } else if (res.fileList[0].is_fp === '不是误报') {
                                that.form.list2 = 2
                            }
                        }
                    }
                },
                error: function (res){
                    mymessage.error('代码详情获取失败')
                },
            })

        },
        //因为一个id只能绑定一个元素，所以为了让代码修复模块的修复前代码也能显示行号，需要再调一次接口
        //代码修复
        getRepair(){
            const that = this
            $.ajax({
                url: (http_head + '/login/'),
                type: 'post',
                datatype: 'json',
                data: {
                    method: 'VulType_get',
                    fileid: that.currentFileId,
                },
                success: function (res){
                    res = JSON.parse(res)

                    console.log('代码修复',res)
                    if(res.fileList[0]){
                        that.details = res.fileList[0]

                        // 获取代码块元素
                        var codeBlock2 = document.getElementById("codeBlock2");
                        // 要高亮的行字符串，例如 "37,38,40"
                        var highlightedLinesString = res.fileList[0].code_location
                        // 将字符串拆分成行号数组
                        var highlightedLines = highlightedLinesString.split(",").map(Number);
                        // 获取代码块的内容
                        var code = res.fileList[0].source_code;
                        // 将代码内容拆分成行数组
                        var lines = code.split("\n");
                        // 遍历要高亮的行号数组
                        highlightedLines.forEach(function(lineNumber) {
                            // 确保行号有效且未高亮过
                            if (lineNumber >= 1 && lineNumber <= lines.length && !lines[lineNumber - 1].includes("line-highlight")) {
                                // 在要高亮的行前后添加 span 元素
                                lines[lineNumber - 1] = "<span class='line-highlight'>" + lines[lineNumber - 1] + "</span>";
                            }
                        });
                        // 更新代码块内容
                        codeBlock2.innerHTML = "<code>" + lines.join("\n") + "</code>";
                        // that.equalLength()


                    }
                },
                error: function (res){
                    mymessage.error('代码修复获取失败')
                },
            })

        },
        //使修复前后的代码块的长度相等
        // equalLength(){
        //     var BoxHeight2 = document.getElementById('codeBlock2').offsetHeight;
        //     var BoxHeight3 = document.getElementById('codeBlock3').offsetHeight;
        //     console.log(BoxHeight2,BoxHeight3)
        //     if (BoxHeight2 > BoxHeight3) {
        //         // 设置第一个方块的高度为和第二个方块相同  减去的是内边距的长度
        //         document.getElementById('codeBlock3').style.height = `${BoxHeight2 - 20}px`;
        //     } else if (BoxHeight3 > BoxHeight2) {
        //         document.getElementById('codeBlock2').style.height = `${BoxHeight3 - 20}px`;
        //     }
        //
        // },

        //是不是问题
        handleRadioChange(value){
            // console.log(value)
            this.form.Question = value

            if(this.form.Question === '是问题'){
                this.isDisabled2 = true
                this.isDisabled1 = false
                this.form.list2 = ''
            } else if(this.form.Question === '不是问题'){
                this.isDisabled1 = true
                this.isDisabled2 = false
                this.form.list1 = ''
            }
        },
        //是不是问题
        handleRadioChange1(value){
            // console.log(value)
            this.form1.Question = value

            if(this.form1.Question === '是问题'){
                this.isDisabled2 = true
                this.isDisabled1 = false
                this.form1.list2 = ''
            } else if(this.form1.Question === '不是问题'){
                this.isDisabled1 = true
                this.isDisabled2 = false
                this.form1.list1 = ''
            }
        },
        //提交批量审核
        submit1(){
            const that = this
            if (this.form1.list1 === 1){
                this.form1.list1 = '高危'
            } else if (this.form1.list1 === 2){
                this.form1.list1 = '中危'
            } else if (this.form1.list1 === 3){
                this.form1.list1 = '低危'
            }
            if (this.form1.list2 === 1) {
                this.form1.list2 = '是误报'
            } else if (this.form1.list2 === 2) {
                this.form1.list2 = '不是误报'
            }
            // console.log(this.form.list1)
            $.ajax({
                url: (http_head + '/login/'),
                type: 'post',
                dataType: 'json',
                data: {
                    method: 'review_update',
                    taskid:that.taskid,
                    fileid:that.allFileId.toString(),
                    is_question:that.form1.Question,      //是不是问题
                    risk_level:that.form1.list1 ? that.form1.list1 : '',    //等级
                    is_fp:that.form1.list2 ? that.form1.list2 : '',     //误报
                    remarks:that.form1.remarks ? that.form1.remarks : '',    //备注
                    data1: '1',
                },
                success: function (res){
                    console.log(res)
                    mymessage.success('提交成功')
                    that.getDetails()
                },
                error: function (res){
                    mymessage.error('提交失败')
                },
            })
        },

        //提交审核
        submit(){
            const that = this
            if (this.form.list1 === 1){
                this.form.list1 = '高危'
            } else if (this.form.list1 === 2){
                this.form.list1 = '中危'
            } else if (this.form.list1 === 3){
                this.form.list1 = '低危'
            }
            if (this.form.list2 === 1) {
                this.form.list2 = '是误报'
            } else if (this.form.list2 === 2) {
                this.form.list2 = '不是误报'
            }
            // console.log(this.form.list1)
            //接口被更改为接受string类型的所以这里需要进行改变
            this.currentFileIds.push(this.currentFileId)
            $.ajax({
                url: (http_head + '/login/'),
                type: 'post',
                dataType: 'json',
                data: {
                    method: 'review_update',
                    taskid:that.taskid,
                    fileid:that.currentFileIds.toString(),
                    is_question:that.form.Question,      //是不是问题
                    risk_level:that.form.list1 ? that.form.list1 : '',    //等级
                    is_fp:that.form.list2 ? that.form.list2 : '',     //误报
                    remarks:that.form.remarks ? that.form.remarks : '',    //备注
                    data1: '1',
                },
                success: function (res){
                    console.log(res)
                    mymessage.success('提交成功')
                    that.getDetails()
                },
                error: function (res){
                    mymessage.error('提交失败')
                },
            })
        },
        //缺陷描述
        getDescriptions(){
            const that = this
            $.ajax({
                url: (http_head + '/login/'),
                type: 'post',
                dataType: 'json',
                data: {
                    method: 'file_detail',
                    file_id: that.currentFileId,
                },
                success: function (res){
                    console.log('缺陷描述',res)
                    if(res[0]){

                        that.descriptions = res[0]
                    }

                },
                error: function (res){
                    mymessage.error('缺陷描述获取失败')
                },
            })
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
                    // console.log('celue',res)
                    if (res.policy === 'deepSeek') {
                        that.ifDeepSeek = true
                    }
                },
                error: function (err) {
                    console.log(err)
                }
            })
        },
        //修复。这个是生成修复代码
        repair1(){
            const that = this
            this.loading = true
            // var modelName = 'deepseek'
            // if (this.ifDeepSeek === true) {
            //     modelName = 'deepseek'
            // } else if (this.ifDeepSeek === false) {
            //     modelName = 'CodeLlama'
            // }
            // $.ajax({
            //     url: (http_head + '/Muti/'),
            //     type: 'post',
            //     dataType: 'json',
            //     data: {
            //         method: 'location_web',
            //         vulId: that.currentFileId,
            //         modelName: modelName,
            //     },
            //     success: function (res){
            //         console.log('修复1',res)
            //         that.repair2()
            //     },
            //     error: function (res){
            //         mymessage.error('修复失败')
            //     },
            // })
            $.ajax({
                url: (http_head + '/Muti/'),
                type: 'post',
                dataType: 'json',
                data: {
                    method: 'deepseek_repair',
                    file_id: that.currentFileId,
                    task_id: that.taskid,
                    code: that.details.source_code,
                    vultype: that.details.vultype,
                    model_name: 'deepseek-6.7b',
                },
                    success: function (res){
                    console.log('修复1',res)
                    that.repair2()
                },
                error: function (res){
                    mymessage.error('修复失败')
                },
            })
        },
        //这个是获取修复代码
        repair2(){
            const that = this
            $.ajax({
                url: (http_head + '/login/'),
                type: 'post',
                dataType: 'json',
                data: {
                    method: 'get_repair_code',
                    fileid: that.currentFileId,
                },
                success: function (res){
                    console.log('修复2',res)
                    if (res[0]){
                        that.details.repair_code = res[0].repair_code
                    }
                    that.loading = false
                },
                error: function (res){
                    mymessage.error('修复失败')
                },
            })
        },
        //修复反馈
        get_repair_feedback(){
            this.dialogVisible = true
            this.getDetails()
        },
        //提交修复反馈
        submit_repair_feedback(){
            this.dialogVisible = false
            const that = this
            $.ajax({
                url: (http_head + '/login/'),
                type: 'post',
                dataType: 'json',
                data: {
                    method: 'repair_update',
                    fileId: that.currentFileId,
                    repair_feedback:that.textarea,
                },
                success: function (res){
                    console.log('修复2',res)
                    that.details.repair_code = res[0].repair_code

                },
                error: function (res){
                    mymessage.error('修复失败')
                },
            })
        },

    },
    mounted(){
        this.getDetails()

            // this.$nextTick(() => {
            //     this.$refs.tabs.$children[0].$refs.tabs[1].style.display = 'none';
            //     console.log(this.$refs.tabs.$children[0].$refs);
            //     console.log(this.$refs.tabs.$children[0].$refs.tabs);
            // })


    },


})