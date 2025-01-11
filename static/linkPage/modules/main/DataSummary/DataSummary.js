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
        // var timer = setInterval(() => {  //注意这里要用ES6的箭头函数，否则this会找不到
        //     this.getAllList()
        // },5000)
        this.getAllList();
    },
    data() {
        return {
            query:{
                name:'',
            },

            tableData: [],
            currentPage: 1, //当前页 刷新后默认显示第一页
            pageSize: 10, //每一页显示的数据量 此处每页显示6条数据
            count:10,

        };
    },

    methods: {
        //获取项目列表
        getAllList(){
            this.loading = true;
            var that = this;
            $.ajax({
                url:  (http_head + '/login/'),
                data:{
                    method : 'count_team',
                    username:that.query.name,
                    teamId : localUser.teamId,
                    page   :  that.currentPage,
                    rows   :  that.pageSize,
                },
                type : 'post',
                dataType : 'JSON',
                success : function (res){
                    console.log(res);
                    if (res){
                        that.tableData = res.data
                        that.count  = parseInt(res.counts)
                        mymessage.success("获取成功")
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
        //查询
        checkFormData(){
            this.getAllList()
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