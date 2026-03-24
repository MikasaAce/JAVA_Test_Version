
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
        // this.ifDescription()

    },
    data() {
        return {
            isRouterAlive : true,
            // fileList: [
            //     { name: "CWE 235", files: [{ fileid: "596589" ,name: "BenchmarkTest00075.java"}, {fileid: "596580" , name: "checkdll.java" }, { fileid: "596580" ,name: "comment_save.java" }] },
            //     { name: "CWE 89", files: [{fileid: "596583" , name: "内容4" }, {fileid: "596582" , name: "内容5" }] },
            // ],
            fileList:[],
            firstFile:'',
            moren: true,
            currentFileId:'',
            currentFileIds:[],
            expandedKeys: [], // 维护展开状态的数组
            allFileId:[],
            lastSelectedId:[],
            // value: '',
            // input: '',
            activeName: 'first',
            descriptionOrNot:true,
            taskid:'',
            status:'未修复',
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
                Interpretation: '',
                source_code:'',
                repair_code:'',
            },
            dialogVisible:false,
            textarea:'',
            ifDeepSeek:false,
            loading:false,
            loading1:false,
            tabflag:'代码详情',
            codeAnalysis:'',
            fileRepairs: {}, // 存储各文件的修复代码
            pollingInterval1: null, // 定时器变量
            pollingInterval2: null, // 定时器变量
            // 使用对象存储各文件的加载状态，键为文件ID
            fileLoadingMap: {},
            pollingIntervals: {}, // 格式: { [fileId]: intervalId }
            fileLoadingMap2: {},
            pollingIntervals2: {}, // 格式: { [fileId]: intervalId }
            filterText: '',

            currentRequests: {},  // 进行中的请求 { [fileId]: xhr }
            fileInterpretations:{},
            fileXHRs: {},              // 存储各文件的XHR对象
            currentRepairs: {},  // 进行中的请求 { [fileId]: xhr }
            fileRepairs:{},
            repairXHRs: {},              // 存储各文件的XHR对象
            // 追踪图相关数据
            traceData: {
            referenced_by: [],
            imports: []
            },
            currentFileName: '',
            sink_line:'',
            src_line:'',
        }
    },
    provide() {
        //提供
        return {
            reload: this.reload,
        };
    },
    methods: {
        // 提取文件名（从完整路径中提取）
        extractFileName(fullPath) {
            if (!fullPath) return '';
            // 从完整路径中提取文件名
            const parts = fullPath.split('/');
            return parts[parts.length - 1] || fullPath;
        },
        // 加载追踪图数据
        loadTraceGraph() {
            const currentFile = this.details.filepath;
            
            if (!currentFile) {
            console.log('当前文件路径为空，无法生成追踪图');
            return;
            }
            
            // 获取taskid
            const taskid = this.taskid;
            if (!taskid) {
            console.log('未找到任务ID，无法生成追踪图');
            return;
            }
            
            this.currentFileName = this.details.filename;
            
            // 调用两个接口获取引用关系
            Promise.all([
            this.getReferencedByFiles(taskid, currentFile),
            this.getImportedFiles(taskid, currentFile)
            ]).then(([referencedBy, imports]) => {
            this.traceData = {
                referenced_by: referencedBy,
                imports: imports
            };
            
            }).catch(error => {
            console.error('获取追踪图数据失败:', error);
            });
        },
        
        // 获取引用该文件的文件
        getReferencedByFiles(taskid, currentFile) {
            return new Promise((resolve, reject) => {
            $.ajax({
                url: (http_head + '/login/'),
                data:{
                    method : 'get_source_files',
                    task_id: taskid,
                    imported_file: currentFile
                },
                type: 'post',
                dataType: 'JSON',
                success: function(res) {
                if (res.code === 200) {
                    resolve(res.source_files || []);
                } else {
                    reject(new Error(res.error || '获取引用文件失败'));
                }
                },
                error: function(err) {
                reject(err);
                }
            });
            });
        },
        
        // 获取该文件引用的文件
        getImportedFiles(taskid, currentFile) {
            return new Promise((resolve, reject) => {
            $.ajax({
                url: (http_head + '/login/'),
                data:{
                    method : 'get_imported_files',
                    task_id: taskid,
                    source_file: currentFile
                },
                type: 'post',
                dataType: 'JSON',
                success: function(res) {
                if (res.code === 200) {
                    resolve(res.imported_files || []);
                } else {
                    reject(new Error(res.error || '获取被引用文件失败'));
                }
                },
                error: function(err) {
                reject(err);
                }
            });
            });
        },

        goBack(){
            //如果是从任务详情页跳转过来
            if (sessionStorage.getItem('iftaskdescrip') === 'true')  {
                window.location.href = 'ProjectDetail.html'
            } else {
                window.location.href = 'markList.html'
            }
        },
        getCheckedKeys(leafOnly){
            console.log(leafOnly);
        },
        // 处理复选框状态变化
        handleCheckChange(checkedData, checkedStates) {
            // checkedData: 当前点击的节点数据
            // checkedStates: 包含 checkedKeys, halfCheckedKeys 等状态信息
            
            // 获取所有选中的节点key（包括半选中的父节点）
            const checkedKeys = this.$refs.tree.getCheckedKeys();
            // 获取所有选中的节点（包括半选中的父节点）
            const checkedNodes = this.$refs.tree.getCheckedNodes();
            
            console.log('选中的keys:', checkedKeys);
            console.log('选中的nodes:', checkedNodes);
            
            // 只保留文件节点的ID（过滤掉分类节点）
            this.allFileId = checkedKeys.filter(key => {
                return key !== null && key !== undefined && !isNaN(key) && key.toString().trim() !== '';
            });
            
            console.log('过滤后的文件ID:', this.allFileId);
        },
        // 修改现有的 shenhe 方法
        shenhe(){
            // 确保获取最新的选中状态
            const checkedKeys = this.$refs.tree.getCheckedKeys();
            this.allFileId = checkedKeys.filter(item => {
                return item !== null && item !== undefined && !isNaN(item) && item.toString().trim() !== '';
            });
            
            console.log('批量审核选中的文件ID:', this.allFileId);
            
            // 如果没有选中任何文件，给出提示
            if (this.allFileId.length === 0) {
                this.$message.warning('请先勾选需要审核的文件');
                this.showDialog = false;
                return;
            }
            this.showDialog = true;
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
                    // console.log(that.descriptionOrNot)

                },
                error: function (err) {
                    console.log(err)
                    mymessage.error("获取失败")
                }
            })
        },
        //获取左侧漏洞列表
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
                        // for (let i = 0;i<res.fileList.length;i++){
                        //     var filesArray = res.fileList[i].files;
                        //     // 提取 files 数组中的 name 属性
                        //     var fileNamesArray = filesArray.map(function(file) {
                        //         return file.name;
                        //     });
                        //     var result = fileNamesArray.join(", ");
                        //     console.log(res.fileList[i].name,result); // 输出所有漏洞文件名时用
                        // }
                        // 为分类节点添加 (数量)
                        that.fileList.forEach((category) => {
                            if (category.files && category.files.length > 0) {
                                category.name = `${category.name} (${category.files.length})`;
                            }
                        });
                        // 为分类节点添加 fileid（如果接口未返回）
                        // that.fileList.forEach((category, index) => {
                        //     if (!category.fileid) {
                        //         category.fileid = `100${index + 1}`; // 生成唯一的 fileid
                        //     }
                        // });

                        // 初始化 expandedKeys，展开第一个分类节点
                        // if (that.fileList.length > 0) {
                        //     that.expandedKeys = [that.fileList[0].files[0].fileid]; // 使用分类节点的 fileid
                        // }
                        //默认显示的文件
                        that.firstFile = res.fileList[0].files[0].fileid
                        that.currentFileId = that.firstFile
                    }
                    that.getDetails()
                    //this.getDetails()
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
                // 切换时检查是否有缓存的修复代码
                if (this.fileRepairs[this.currentFileId]) {
                    this.details.repair_code = this.fileRepairs[this.currentFileId];
                }
                this.getRepair()
            }
        },
        //左侧树形控件
        async handleNodeClick(data, node,nodeData) {
            // console.log(data);
            // console.log(node.level);  //第几层
            //如果点的是文件
            if (node.level === 2){
                // console.log('当前的tab:',this.tabflag)
                const oldFileId = this.currentFileId;
                this.currentFileId = data.fileid;

                if (oldFileId !== this.currentFileId) {
                    this.$emit('file-changed'); // 触发请求取消
                }

                try {
                    if(this.tabflag === '代码详情') {
                        this.reload()
                        await  this.getDetails()
                    } else if(this.tabflag === '缺陷描述') {
                        // this.reload()
                        await  this.getDescriptions()
                    } else if(this.tabflag === '代码修复') {
                        // this.reload()
                        // 切换文件时检查是否有缓存的修复代码
                        if (this.fileRepairs[this.currentFileId]) {
                            this.details.repair_code = this.fileRepairs[this.currentFileId];
                        }
                        await this.getRepair()
                        // this.equalLength()
                    }
                } catch (err) {
                    console.error('数据加载失败:', err);
                }

            }

        },
        // 手动维护展开状态
        handleNodeExpand(data) {
            const index = this.expandedKeys.indexOf(data.fileid);
            // console.log(index)
            // console.log(this.expandedKeys)
            if (index === -1) {
                this.expandedKeys.push(data.fileid);
            }
        },
        handleNodeCollapse(data) {
            const index = this.expandedKeys.indexOf(data.fileid);
            console.log(index)
            if (index !== -1) {
                this.expandedKeys.splice(index, 1);
            }
        },

        //对xml文件做转义处理
        // 确保 escapeHtml 函数正确处理 XML 文件
        escapeHtml(unsafe, isXml = false) {
            // XML 文件不进行转义
            if (isXml) {
                // 但需要处理 XML 实体编码问题
                return unsafe
                  .replace(/&amp;/g, "&")
                  .replace(/&lt;/g, "<")
                  .replace(/&gt;/g, ">")
                  .replace(/&quot;/g, '"')
                  .replace(/&#039;/g, "'");
            }
            // 非 XML 文件正常转义
            return unsafe
              .replace(/&/g, "&amp;")
              .replace(/</g, "&lt;")
              .replace(/>/g, "&gt;")
              .replace(/"/g, "&quot;")
              .replace(/'/g, "&#039;");
        },
        // escapeHtml(unsafe) {
        //     return unsafe
        //       .replace(/&/g, "&amp;")
        //       .replace(/</g, "&lt;")
        //       .replace(/>/g, "&gt;")
        //       .replace(/"/g, "&quot;")
        //       .replace(/'/g, "&#039;");
        // },
        //代码详情
        // getDetails(){
        //     const that = this
        //     // return new Promise((resolve, reject) => {
        //     $.ajax({
        //         url: (http_head + '/login/'),
        //         type: 'post',
        //         datatype: 'json',
        //         data: {
        //             method: 'VulType_get',
        //             fileid: that.currentFileId,
        //         },
        //         success: function (res){
        //             res = JSON.parse(res)
        //
        //             console.log('代码详情',res)
        //
        //             if(res.fileList[0]){
        //                 //去掉开头的空白
        //                 res.fileList[0].Sink = res.fileList[0].Sink.replace(/^\s+/, '')
        //                 res.fileList[0].Source = res.fileList[0].Source.replace(/^\s+/, '')
        //                 res.fileList[0].Enclosing_Method = res.fileList[0].Enclosing_Method.replace(/^\s+/, '')
        //
        //                 if (res.fileList[0].Interpretation){
        //                     res.fileList[0].Interpretation = res.fileList[0].Interpretation.replace(/^<think>\s*|<\/think>/g, '').replace(/^[\r\n]+/, '');
        //                 }
        //                 if (res.fileList[0].repair_code){
        //                     res.fileList[0].repair_code = res.fileList[0].repair_code.replace(/^<think>\s*|<\/think>/g, '')
        //                 }
        //
        //                 that.details = res.fileList[0]
        //
        //
        //                 // that.details.Sink = res.fileList[0].Sink.replace(/^\s+/, '')
        //                 // 获取代码块元素
        //                 var codeBlock = document.getElementById("codeBlock");
        //
        //                 // 要高亮的行字符串，例如 "37,38,40"
        //                 var highlightedLinesString = res.fileList[0].code_location
        //                 // 将字符串拆分成行号数组
        //                 var highlightedLines = highlightedLinesString.split(",").map(Number);
        //                 // 获取代码块的内容
        //                 var code = res.fileList[0].source_code;
        //                 // 将代码内容拆分成行数组
        //                 var lines = code.split("\n");
        //
        //                 // 先对每一行代码进行转义
        //                 var escapedLines = lines.map(line => that.escapeHtml(line));
        //                 // console.log(escapedLines)
        //
        //                 // 遍历要高亮的行号数组
        //                 highlightedLines.forEach(function(lineNumber) {
        //                     // 确保行号有效且未高亮过
        //                     if (lineNumber >= 1 && lineNumber <= escapedLines.length && !escapedLines[lineNumber - 1].includes("line-highlight")) {
        //                         // 在要高亮的行前后添加 span 元素
        //                         escapedLines[lineNumber - 1] = "<span class='line-highlight'>"  + escapedLines[lineNumber - 1] + "</span>";
        //                     }
        //                 });
        //                 // console.log(escapedLines)
        //                 // 更新代码块内容
        //                 codeBlock.innerHTML = "<code>" + escapedLines.join("\n") + "</code>";
        //
        //                 // console.log(codeBlock)
        //
        //                 //提交的修复反馈的内容
        //                 that.textarea = res.fileList[0].repair_feedback
        //                 //回显提交的审核
        //                 if (res.fileList[0].is_question === '是问题') {
        //                     that.form.Question = '是问题'
        //                     if (res.fileList[0].risk_level === '高危') {
        //                         that.form.list1 = 1
        //                     } else if (res.fileList[0].risk_level === '中危') {
        //                         that.form.list1 = 2
        //                     }  else if (res.fileList[0].risk_level === '低危') {
        //                         that.form.list1 = 3
        //                     }
        //                 } else if (res.fileList[0].is_question === '不是问题') {
        //                     that.form.Question = '不是问题'
        //                     if (res.fileList[0].is_fp === '是误报') {
        //                         that.form.list2 = 1
        //                     } else if (res.fileList[0].is_fp === '不是误报') {
        //                         that.form.list2 = 2
        //                     }
        //                 }
        //             }
        //         },
        //         error: function (res){
        //             mymessage.error('代码详情获取失败')
        //             reject(res); // 传递错误
        //         },
        //     })
        //     // });
        //
        // },

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
                        //存储原来的爆发点与缺陷源
                        that.sink_line = res.fileList[0].Sink
                        that.src_line = res.fileList[0].Source

                        //去掉开头的空白
                        res.fileList[0].Sink = res.fileList[0].Sink.replace(/^\s+/, '')
                        res.fileList[0].Source = res.fileList[0].Source.replace(/^\s+/, '')
                        res.fileList[0].Enclosing_Method = res.fileList[0].Enclosing_Method.replace(/^\s+/, '')

                        if (res.fileList[0].Interpretation){
                            res.fileList[0].Interpretation = res.fileList[0].Interpretation.replace(/^<think>\s*|<\/think>/g, '').replace(/^[\r\n]+/, '');
                        }
                        if (res.fileList[0].repair_code){
                            res.fileList[0].repair_code = res.fileList[0].repair_code.replace(/^<think>\s*|<\/think>/g, '')
                        }

                        that.details = res.fileList[0]

                        var now_repair_status = that.details.repair_status
                        console.log("old:",now_repair_status)
                        if(now_repair_status === '未修复'){
                            that.status = "已修复"
                        }
                        else if (now_repair_status === '已修复'){
                            that.status = "未修复"
                        }
                        console.log("new:",that.status)
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

                        // 判断是否为 XML 文件 (新增代码)
                        const isXmlFile = res.fileList[0].filename.toLowerCase().endsWith('.xml');


                        // 清空容器
                        codeBlock.innerHTML = "";

                        // 添加行号
                        lines.forEach((line, index) => {
                            var lineNumber = index + 1;
                            var lineElement = document.createElement("div");
                            lineElement.className = "code-line";

                            // 添加行号
                            var numberSpan = document.createElement("span");
                            numberSpan.className = "line-number";
                            numberSpan.textContent = lineNumber;

                            // 添加代码内容
                            var contentSpan = document.createElement("span");
                            contentSpan.className = "line-content";

                            // 处理高亮行
                            if (highlightedLines.includes(lineNumber)) {
                                contentSpan.className += " line-highlight";
                            }

                            // // 转义HTML特殊字符
                            // contentSpan.textContent = that.escapeHtml(line);
                            // 修改这行代码：添加 isXmlFile 参数
                            //contentSpan.textContent = that.escapeHtml(line, isXmlFile);
                            contentSpan.textContent = line;
                            
                            lineElement.appendChild(numberSpan);
                            lineElement.appendChild(contentSpan);
                            codeBlock.appendChild(lineElement);
                        });

                        // 使用 $nextTick 确保DOM更新完成后再计算行号
                        that.$nextTick(() => {
                            // 添加行号到漏洞信息
                            that.addLineNumbersToVulInfo(that.details, code);
                        });

                        //提交的修复反馈的内容
                        that.textarea = res.fileList[0].repair_feedback

                        // // 重置表单状态
                        // that.isDisabled1 = false;
                        // that.isDisabled2 = false;
                        // 重置表单状态
                        // that.isDisabled1 = true;  // 默认都禁用
                        // that.isDisabled2 = true;  // 默认都禁用

                        // 先重置表单
                        that.form = {
                            Question: '',
                            list1: '',
                            list2: '',
                            remarks: that.form.remarks // 保留原有的备注信息
                        };
                        //回显提交的审核
                        if (res.fileList[0].is_question === '是问题') {
                            // that.form.Question = '是问题';
                            // that.isDisabled2 = true;    // 禁用误报选项
                            // that.isDisabled1 = false;   // 启用风险等级选项
                            if (res.fileList[0].risk_level === '高危') {
                                that.form.list1 = 1
                            } else if (res.fileList[0].risk_level === '中危') {
                                that.form.list1 = 2
                            }  else if (res.fileList[0].risk_level === '低危') {
                                that.form.list1 = 3
                            } else {
                                that.form.list1 = null
                            }
                        } else if (res.fileList[0].is_question === '不是问题') {
                            // that.form.Question = '不是问题'
                            // that.isDisabled1 = true;    // 禁用风险等级选项
                            // that.isDisabled2 = false;   // 启用误报选项
                            if (res.fileList[0].is_fp === '是误报' || res.fileList[0].is_fp === '误报') {
                                that.form.list1 = 5
                            } else if (res.fileList[0].is_fp === '不是误报' || res.fileList[0].is_fp === '忽略') {
                                that.form.list1 = 4
                            }
                            // that.isDisabled1 = true; // 确保"是问题"相关选项被禁用
                        }
                        // 在获取到文件详情后自动加载追踪图
                        that.loadTraceGraph();
                    }
                },
                error: function (res){
                    mymessage.error('代码详情获取失败')
                },
            })
        },

// 添加新方法：计算并添加行号到漏洞信息（使用响应式更新）
        addLineNumbersToVulInfo(vulData, sourceCode) {
            // 辅助函数：查找文本在源代码中的行号
            // const findLineNumber = (text) => {
            //     if (!text) return "";
            //
            //     const lines = sourceCode.split("\n");
            //     for (let i = 0; i < lines.length; i++) {
            //         // 检查是否包含目标文本（忽略首尾空格）
            //         if (lines[i].includes(text.trim())) {
            //             return i + 1;
            //         }
            //     }
            //     return ""; // 找不到行号时返回空字符串
            // };
            //
            // // 添加行号到各个漏洞信息
            // const sinkLine = findLineNumber(vulData.Sink);
            // const sourceLine = findLineNumber(vulData.Source);
            // const methodLine = findLineNumber(vulData.Enclosing_Method);

            // 添加行号到各个漏洞信息
            const sinkLine = vulData.location;
            const sourceLine = vulData.src_location;
            const methodLine = vulData.func_location;

            // 使用 Vue.set 确保响应式更新
            this.$set(this.details, 'Sink', sinkLine ? `${vulData.Sink} [行号: ${sinkLine}]` : vulData.Sink);
            this.$set(this.details, 'Source', sourceLine ? `${vulData.Source} [行号: ${sourceLine}]` : vulData.Source);
            this.$set(this.details, 'Enclosing_Method', methodLine ? `${vulData.Enclosing_Method} [行号: ${methodLine}]` : vulData.Enclosing_Method);

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
                        if (res.fileList[0].Interpretation){
                            res.fileList[0].Interpretation = res.fileList[0].Interpretation.replace(/^<think>\s*|<\/think>/g, '').replace(/^[\r\n]+/, '');
                        }
                        
                        // 优先使用缓存的修复代码，如果没有则使用接口返回的
                        let repairCode = '';
                        if (that.fileRepairs[that.currentFileId]) {
                            repairCode = that.fileRepairs[that.currentFileId];
                        } else if (res.fileList[0].repair_code) {
                            repairCode = res.fileList[0].repair_code.replace(/^<think>\s*|<\/think>/g, '');
                        }

                        //存储原来的爆发点与缺陷源
                        that.sink_line = res.fileList[0].Sink
                        that.src_line = res.fileList[0].Source

                        res.fileList[0].Sink = res.fileList[0].Sink.replace(/^\s+/, '')
                        res.fileList[0].Source = res.fileList[0].Source.replace(/^\s+/, '')
                        res.fileList[0].Enclosing_Method = res.fileList[0].Enclosing_Method.replace(/^\s+/, '')

                        that.details = res.fileList[0]
                        // 设置修复代码
                        that.details.repair_code = repairCode;

                        // 获取代码修复模块的代码块元素
                        var codeBlock2 = document.getElementById("codeBlock2");

                        // 要高亮的行字符串，例如 "37,38,40"
                        var highlightedLinesString = res.fileList[0].code_location
                        // 将字符串拆分成行号数组
                        var highlightedLines = highlightedLinesString.split(",").map(Number);
                        // 获取代码块的内容
                        var code = res.fileList[0].source_code;
                        // 将代码内容拆分成行数组
                        var lines = code.split("\n");

                        // 判断是否为 XML 文件
                        const isXmlFile = res.fileList[0].filename.toLowerCase().endsWith('.xml');

                        // 清空容器
                        codeBlock2.innerHTML = "";

                        // 添加行号
                        lines.forEach((line, index) => {
                            var lineNumber = index + 1;
                            var lineElement = document.createElement("div");
                            lineElement.className = "code-line";

                            // 添加行号
                            var numberSpan = document.createElement("span");
                            numberSpan.className = "line-number";
                            numberSpan.textContent = lineNumber;

                            // 添加代码内容
                            var contentSpan = document.createElement("span");
                            contentSpan.className = "line-content";

                            // 处理高亮行
                            if (highlightedLines.includes(lineNumber)) {
                                contentSpan.className += " line-highlight";
                            }

                            // 显示代码内容
                            contentSpan.textContent = line;
                            
                            lineElement.appendChild(numberSpan);
                            lineElement.appendChild(contentSpan);
                            codeBlock2.appendChild(lineElement);
                        });
                    }
                },
                error: function (res){
                    mymessage.error('代码修复获取失败')
                },
            })
        },

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
            }else {
                // 如果没有选择任何选项，两个都禁用
                this.isDisabled1 = true
                this.isDisabled2 = true
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
            }else {
                // 如果没有选择任何选项，两个都禁用
                this.isDisabled1 = true
                this.isDisabled2 = true
            }
        },

        //提交批量审核
        submit1(){
            const that = this
            let isQuestion = ''
            if (this.form1.list1 === 1){
                this.form1.list1 = '高危'
                isQuestion = '是问题'
            } else if (this.form1.list1 === 2){
                this.form1.list1 = '中危'
                isQuestion = '是问题'
            } else if (this.form1.list1 === 3){
                this.form1.list1 = '低危'
                isQuestion = '是问题'
            }else if (this.form1.list1 === 4) {
                this.form1.list2 = '忽略'
                isQuestion = '不是问题'
            } else if (this.form1.list1 === 5) {
                this.form1.list2 = '误报'
                isQuestion = '不是问题'
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
                    is_question:isQuestion,      //是不是问题
                    risk_level:that.form1.list1 ? that.form1.list1 : '',    //等级
                    is_fp:that.form1.list2 ? that.form1.list2 : '',     //误报
                    remarks:that.form1.remarks ? that.form1.remarks : '',    //备注
                    data1: '1',
                },
                success: function (res){
                    console.log(res)
                    // 审核成功后自动关闭弹窗
                    that.showDialog = false;
                    // 清空树形控件的选中状态
                    if (that.$refs.tree) {
                        that.$refs.tree.setCheckedKeys([]);
                    }
                    
                    // 清空选中的文件ID数组
                    that.allFileId = [];
                    // 清空表单
                    that.form1 = {
                        Question: '',
                        list1: '',
                        list2: '',
                        remarks: ''
                    };
                    
                    // 重置单选按钮状态
                    that.isDisabled1 = true;
                    that.isDisabled2 = true;
                    mymessage.success('提交成功')
                    that.getDetails()
                },
                error: function (res){
                    mymessage.error('提交失败')
                },
            })
        },
        updateRepairStatus(){
            const that = this
            $.ajax({
                url: (http_head + '/login/'),
                type: 'post',
                dataType: 'json',
                data: {
                    method: 'status_update',
                    fileId: that.details.id,
                    status: that.status,
                },
                success: function (res){
                    console.log(res)
                    mymessage.success('更新成功')
                    that.getDetails()
                },
                error: function (res){
                    mymessage.error('更新失败')
                },
            })
        },
        //提交审核
        submit(){
            const that = this
            let isQuestion = ''
            if (this.form.list1 === 1){
                this.form.list1 = '高危'
                isQuestion = '是问题'
            } else if (this.form.list1 === 2){
                this.form.list1 = '中危'
                isQuestion = '是问题'
            } else if (this.form.list1 === 3){
                this.form.list1 = '低危'
                isQuestion = '是问题'
            }else if (this.form.list1 === 4) {
                this.form.list2 = '忽略'
                isQuestion = '不是问题'
            } else if (this.form.list1 === 5) {
                this.form.list2 = '误报'
                isQuestion = '不是问题'
            }
            // console.log(this.form.list1)
            //接口被更改为接受string类型的所以这里需要进行改变
            // this.currentFileIds.push(this.currentFileId)
            console.log(this.currentFileIds)
            $.ajax({
                url: (http_head + '/login/'),
                type: 'post',
                dataType: 'json',
                data: {
                    method: 'review_update',
                    taskid:that.taskid,
                    fileid:that.currentFileId.toString(),
                    is_question:isQuestion,      //是不是问题
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
                    // console.log('缺陷描述',res)
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
        //生成修复代码
        xiufu(){
            var that = this;

            const currentId = this.currentFileId; // 保存当前文件ID
            // 终止该文件之前的请求
            if (this.repairXHRs[currentId]) {
                this.repairXHRs[currentId].abort();
            }

            // 立即清空当前文件解析内容
            this.$set(this.fileRepairs, currentId, '');
            this.details.repair_code = this.fileRepairs[currentId] || '';

            // 创建一个新的 XMLHttpRequest 对象来处理流式请求
            var xhr = new XMLHttpRequest();
            this.repairXHRs[currentId] = xhr; // 存储XHR实例

            xhr.open('POST', http_head + '/Muti/', true);
            xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded'); // 设置为表单提交的格式

            // 当有新数据到达时触发该回调
            var fullMessage = ''; // 用于存储完整的流式数据
            xhr.onprogress = function (event) {

                fullMessage = event.target.responseText
                .replace(/(\r\n|\n)?data:\s*/g, '')　　 // 过滤掉前面的 "data: " 前缀并拼接流式数据
                .replace(/^<think>\s*|<\/think>/g, '')　　// 去除 < think >和</think>
                .trim();　　　　　　　　　　　　　　　　　　　　　　　　//　　去掉字符串开头和结尾的空白字符

                // 更新对应文件的修复代码
                that.$set(that.fileRepairs, currentId, fullMessage);

                // 仅当当前查看的是本文件时更新展示
                if (that.currentFileId === currentId) {
                    that.details.repair_code = fullMessage;
                    that.$forceUpdate();
                    that.scrollTop22();
                }
            };

            xhr.onerror = function (err) {
                console.log(err);
            };

            xhr.onloadend = function () {
                delete that.repairXHRs[currentId]; // 清理已完成请求
            };

            // 将数据编码为表单格式并发送
            const formData = `method=deepseek_repair&file_id=${encodeURIComponent(currentId)}&code=${encodeURIComponent(that.details.source_code)}&vultype=${encodeURIComponent(that.details.vultype)}&task_id=${encodeURIComponent(that.taskid)}&sink_line=${encodeURIComponent(that.sink_line)}&src_line=${encodeURIComponent(that.src_line)}&model_name=${encodeURIComponent('deepseek')}`;
            xhr.send(formData); // 发送表单格式的数据
        },
        // 处理滚动条一直保持最上方
        scrollTop22() {
            let div = document.getElementById("repairBox");
            div.scrollTop = div.scrollHeight;
        },

        //这个是获取修复代码
        repair2(){
            const that = this
            const currentFileId = this.currentFileId;
            $.ajax({
                url: (http_head + '/login/'),
                type: 'post',
                dataType: 'json',
                data: {
                    method: 'get_repair_code',
                    fileid: currentFileId,
                },
                success: function (res){
                    console.log('修复2',res)
                    if (res[0].repair_code){
                        that.details.repair_code = res[0].repair_code.replace(/^<think>\s*|<\/think>/g, '').replace(/^[\r\n]+/, '');
                    } else {
                        that.details.repair_code = ''
                    }
                    that.loading = false
                },
                error: function (res){
                    // that.loading1 = false
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
                    mymessage.error('提交失败')
                },
            })
        },
        //获取代码解析
        getCodeAnalysis(fileId){
            // const that = this
            const currentFileId = this.currentFileId;
            $.ajax({
                url: (http_head + '/login/'),
                type: 'post',
                dataType: 'json',
                data: {
                    method: 'get_Interpretation',
                    id: currentFileId,
                },
                success: function (res){
                    console.log('代码解析',res)
                    // 仅处理当前选中文件
                    // console.log(that.currentFileId,currentFileId)
                    if (that.currentFileId === currentFileId) {
                        if (res[0].Interpretation && res[0].Interpretation !== null) {
                            // console.log('ok')
                            that.stopPollingForFile(currentFileId); // 停止轮询
                            that.$set(that.fileLoadingMap, currentFileId, false);
                            //开头的回车
                            that.details.Interpretation = res[0].Interpretation.replace(/^<think>\s*|<\/think>/g, '').replace(/^[\r\n]+/, '');

                        } else {
                            // console.log(000)
                            // that.$set(that.fileLoadingMap, currentFileId, false);
                            that.details.Interpretation = ''
                        }
                    }
                    // console.log('get',that.fileLoadingMap)
                },
                error: function (res){
                    that.stopPollingForFile(currentFileId);
                    // that.loading1 = false
                    that.$set(that.fileLoadingMap, currentFileId, false);
                    // mymessage.error('获取失败')
                },
            })
        },
        // 生成代码解析  流式输出
        getAnalysis() {
            var that = this;
            const currentId = this.currentFileId; // 保存当前文件ID
            // 终止该文件之前的请求
            if (this.fileXHRs[currentId]) {
                this.fileXHRs[currentId].abort();
            }

            // 立即清空当前文件解析内容
            this.$set(this.fileInterpretations, currentId, '');
            this.details.Interpretation = this.fileInterpretations[currentId] || '';

            // 创建一个新的 XMLHttpRequest 对象来处理流式请求
            var xhr = new XMLHttpRequest();
            this.fileXHRs[currentId] = xhr; // 存储XHR实例

            xhr.open('POST', http_head + '/Muti/', true);
            xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded'); // 设置为表单提交的格式

            // 当有新数据到达时触发该回调
            var fullMessage = ''; // 用于存储完整的流式数据
            xhr.onprogress = function (event) {

                fullMessage = event.target.responseText
                  .replace(/(\r\n|\n)?data:\s*/g, '')　　 // 过滤掉前面的 "data: " 前缀并拼接流式数据
                  .replace(/^<think>\s*|<\/think>/g, '')　　// 去除 < think >和</think>
                  // .replace(/\n+/g, '')　　　　//换行符
                  // .replace(/\n{3,}/g, '\n\n')    // 多个换行变两个
                  // .replace(/\s+/g, ' ')　　　　　//空白字符
                  // .replace(/(\r\n|\n|\r)/gm, "<br>")
                  .trim();　　　　　　　　　　　　　　　　　　　　　　　　//　　去掉字符串开头和结尾的空白字符

                // console.log(fullMessage)
                // 更新对应文件的解析内容
                that.$set(that.fileInterpretations, currentId, fullMessage);

                // 仅当当前查看的是本文件时更新展示
                if (that.currentFileId === currentId) {
                    that.details.Interpretation = fullMessage;
                    that.$forceUpdate();
                    that.scrollTop11();
                }
            };

            xhr.onerror = function (err) {
                console.log(err);
                // that.loading = false;
            };

            xhr.onloadend = function () {
                // console.log('加载结束');
                delete that.fileXHRs[currentId]; // 清理已完成请求
            };

            // 将数据编码为表单格式并发送
            const formData = `method=deepseek_chat2&id=${encodeURIComponent(currentId)}&code=${encodeURIComponent(that.details.source_code)}&vultype=${encodeURIComponent(that.details.vultype)}&Sink=${encodeURIComponent(that.details.Sink)}`;
            xhr.send(formData); // 发送表单格式的数据
        },

        // 处理滚动条一直保持最上方
        scrollTop11() {
            let div = document.getElementById("bigBox");
            div.scrollTop = div.scrollHeight;
        },
        processText(text) {
            // 替换其他 HTML 标签为转义字符，使其显示为纯文本
            let safeText = text.replace(/</g, "&lt;").replace(/>/g, "&gt;");
            // 将 <br> 转换回原始的 HTML 标签
            return safeText.replace(/&lt;br&gt;/g, "<br>");
        },
        filterNode(value, data) {
            if (!value) return true;
            return data.name.indexOf(value) !== -1;
        }


    },
    beforeDestroy() {

    },
    watch: {
        filterText(val) {
            this.$refs.tree.filter(val);
        },
        currentFileId(newVal) {
            // 切换时立即显示该文件的已有内容
            this.details.Interpretation = this.fileInterpretations[newVal] || '';

            // 如果有进行中的请求，继续在后台更新fileInterpretations但不影响active
        }
    },

    mounted(){

    },
})
