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
        this.getTableData()
    },
    data() {
        return {
            query:{
                name:'',
                filename:'',
                risk_level:'',
                repair_status:'',
            },
            tableData: [],
            currentPage: 1, //当前页 刷新后默认显示第一页
            pageSize: 10, //每一页显示的数据量 此处每页显示6条数据
            count:2,
        }
    },
    methods: {
        goback(){
            window.location.href = 'ProjectList.html'
        },
        //刷新
        reload(){
            window.location.reload()
        },
        //查询
        checkFormData(){
            this.pageSize = 10;
            this.currentPage = 1;
            this.getTableData()
        },
        //获取列表
        getTableData() {
            var itemid = JSON.parse(sessionStorage.getItem('itemid') || '')
            var that = this
            $.ajax({
                url: (http_head + '/login/'),
                data:{
                    method : 'vul_statistics',
                    itemid : itemid,
                    vulname : that.query.name,
                    filename : that.query.filename,
                    risk_level : that.query.risk_level,
                    repair_status : that.query.repair_status,
                    starttime : '',
                    page : that.currentPage,
                    rows : that.pageSize,
                },
                type: 'post',
                dataType: 'JSON',
                success: function (res){
                    console.log(res)
                    if(res){
                        that.tableData = res.data
                        that.count = res.count
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