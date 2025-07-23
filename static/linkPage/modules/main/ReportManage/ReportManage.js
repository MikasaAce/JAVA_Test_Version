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
        var toExportPage = JSON.parse(sessionStorage.getItem("toExportPage"))
        if (toExportPage){
            this.isback = true
            this.getAllList1(toExportPage)
            sessionStorage.removeItem("toExportPage")
        }else {
            this.getAllList()
        }

    },
    data() {
        return {
            isback: false,
            query:{
                type: '',
                name:'',
                fileDate:'',
            },

            tableData: [],
            currentPage: 1, //当前页 刷新后默认显示第一页
            pageSize: 10, //每一页显示的数据量 此处每页显示6条数据
            count:10,

        };
    },

    methods: {
        goback(){
            window.location.href = '../ProjectSummary/FileSummart.html'
        },
        getAllList1(row){
            var that = this;
            $.ajax({
                url:  (http_head + '/login/'),
                data:{
                    method : 'export_getall',
                    vulId     : row.id,
                    accountId  : '',
                    itemName    : '' ,
                    dataSetName  : '',
                    file_startTime : '' ,
                    file_endTime : '' ,
                    fileType : row.flag,
                    vul_startTime: '' ,
                    vul_endTime : '' ,
                    page   : '1'    ,
                    rows   : '10' ,
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
                    mymessage.error("查看失败")
                }
            })
        },
        //获取项目列表
        getAllList(){
            this.loading = true;
            var that = this;
            $.ajax({
                url:  (http_head + '/login/'),
                data:{
                    method : 'export_getall',
                    vulId     : '',
                    accountId  : localUser.accountId,
                    // itemName    : '' ,
                    itemName    : that.query.name ? that.query.name : '' ,
                    taskname : '',
                    // dataSetName  : '',
                    file_startTime : '' ,
                    file_endTime : '' ,
                    // fileType : '',
                    fileType : that.query.type,
                    // vul_startTime: '' ,
                    // vul_endTime : '' ,
                    vul_startTime: that.query.fileDate?that.query.fileDate[0]:'' ,
                    vul_endTime : that.query.fileDate?that.query.fileDate[1]:'' ,
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
            this.getAllList()
        },
        //点击按钮切换页面
        handleCurrentChange(currentPage) {
            this.currentPage = currentPage; //每次点击分页按钮，当前页发生变化
            this.getAllList();
        },

        //下载
        downLoad(row){
            const fileUrl = row.url
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
            this.loading = true;
            var that = this;
            $.ajax({
                url:  (http_head + '/login/'),
                data:{
                    method : 'export_delete',
                    id  : row.id,
                    export_name : row.export_name ,
                    fileType : row.fileType,
                },
                type : 'post',
                dataType : 'JSON',
                success : function (res){
                    console.log(res);
                    if (res.code == '200'){
                        mymessage.success("删除成功")
                        that.getAllList()
                    }else {
                        mymessage.error(res.msg)
                    }
                },
                error: function (err) {
                    console.log(err)
                    mymessage.error("删除失败")
                }
            })
            this.loading = false
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