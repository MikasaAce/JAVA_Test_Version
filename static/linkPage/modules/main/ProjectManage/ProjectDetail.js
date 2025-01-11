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
        this.taskid = JSON.parse(sessionStorage.getItem('taskid') || '')
        this.itemid = JSON.parse(sessionStorage.getItem('itemid') || '')
        this.getInfoData()
        this.getConfig()
    },
    mounted(){
        this.getList1()
        this.getMajor()
    },
    data() {
        return {
            taskid:'', //上一级任务id
            taskname:'',
            itemname:'',
            language:'',
            type:'',
            file_size:'',
            code_size:'',
            lasttime:'',
            vulTypes:'',
            review_status:'',
            source:'',
            file_num:'',
            creator:'',
            startTime:'',
            url:'',
            policy:'',
            itemid:'',

            vueNum1:[],
            vueNum2:[],
        }
    },
    methods: {
        goback(){
            window.location.href = 'markList.html'
            sessionStorage.removeItem('ifDescription')
        },
        // result(){
        //     window.location.href = 'resultReview.html'
        // },
        //获取保存的配置策略
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
                    // console.log(res)
                    if(res.policy === 'fortify') {
                        that.policy = '规则扫描'
                    } else if(res.policy === 'deepSeek') {
                        that.policy = '大模型扫描'
                    } else if(res.policy === 'deepSeek_6.7b') {
                        that.policy = '大模型扫描(large)'
                    }
                },
                error: function (err) {
                    console.log(err)
                }
            })
        },
        //生成报告
        exportReport(){
            var that = this
            $.ajax({
                url: (http_head + '/login/'),
                data:{
                    method : 'vulfile_export',
                    createTime: '',
                    taskId: that.taskid,
                    itemName: that.taskname,
                },
                type: 'post',
                dataType: 'JSON',
                success: function (res){
                    // console.log(res);
                    if(res.code == '500'){
                        mymessage.error(res.msg)
                    }else if (res.code == '200'){
                        // window.setTimeout(window.location.href = '../ReportManage/ReportManage.html',1000);
                        var filename = Object.keys(res)[0]
                        var fileUrl = Object.values(res)[0]
                        // console.log(filename)
                        // console.log(fileUrl)
                        const link = document.createElement('a')
                        link.href =fileUrl
                        link.setAttribute('download',filename) // 下载文件的名称及文件类型后缀
                        document.body.appendChild(link)
                        link.click()
                        document.body.removeChild(link) // 下载完成移除元素
                        setTimeout(() => {
                            // window.close() // 关闭新标签页
                        }, 1000) // 设置5秒延迟，确保下载完成后再关闭标签页
                    }
                },
                error: function (err) {
                    console.log(err)
                    mymessage.error("导出失败")
                }
            })
        },
        //导出PDF
        exportPDF(){
            var that = this
            $.ajax({
                url: (http_head + '/login/'),
                data:{
                    method : 'export_pdf',
                    zipName: that.taskname,
                    vulFileNumber: that.file_num,         //有漏洞文件数量
                    language: that.language,
                    type: that.policy,
                    // createTime: '',
                    startTime: that.startTime,   //检测开始时间
                    lastTime: that.lasttime,    //检测耗时时长1
                    vuls: that.vulTypes,
                    taskId: that.taskid,
                    pdf_Time: getCurrentDate(2),   //文档生成时间
                    itemName: that.taskname,
                    itemId: that.itemid,
                },
                type: 'post',
                dataType: 'JSON',
                success: function (res){
                    console.log(res);
                    if(res.code == '500'){
                        mymessage.error(res.msg)
                    }else if (res.code == '200'){
                        // window.setTimeout(window.location.href = '../ReportManage/ReportManage.html',1000);
                        var filename = Object.keys(res)[0]
                        var fileUrl = Object.values(res)[0]
                        console.log(filename)
                        console.log(fileUrl)
                        const link = document.createElement('a')
                        link.href =fileUrl
                        link.setAttribute('download',filename) // 下载文件的名称及文件类型后缀
                        document.body.appendChild(link)
                        link.click()
                        document.body.removeChild(link) // 下载完成移除元素
                        setTimeout(() => {
                            // window.close() // 关闭新标签页
                        }, 1000) // 设置5秒延迟，确保下载完成后再关闭标签页
                    }
                },
                error: function (err) {
                    console.log(err)
                    mymessage.error("导出失败")
                }
            })
        },

        //获取任务详情基本信息
        getInfoData(){
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
                    console.log(res)
                    // sessionStorage.setItem('ifDescription',JSON.stringify(res[0].type))
                    that.taskname = res[0].taskname
                    that.itemname = res[0].itemname
                    that.language = res[0].language
                    that.type = res[0].type
                    that.file_size = res[0].file_size
                    that.code_size = res[0].code_size
                    that.lasttime = res[0].lasttime
                    that.review_status = res[0].review_status
                    that.source = res[0].source
                    that.file_num = res[0].file_num
                    that.creator = res[0].creator
                    that.startTime = res[0].startTime
                    that.url = res[0].url
                },
                error: function (err) {
                    console.log(err)
                    mymessage.error("获取失败")
                }
            })
        },
        // 请求代码漏洞等级分布数据
        getList1 () {
            var that = this;
            $.ajax({
                url: (http_head + '/login/'),
                data:{
                    method : 'Task_Detail_2',
                    task_id: that.taskid,
                },
                type: 'post',
                dataType: 'JSON',
                async:false,
                success: function (res){
                    // console.log(res)
                    if(res){
                        that.vueNum1 = res[0]
                        // console.log(that.vueNum1)
                    }
                },
                error: function (err) {
                    console.log(err)
                    mymessage.error("代码漏洞等级分布获取失败")
                }
            })
            this.$nextTick(function () {
                this.getechart1()
                this.randerEcharts1()
            })
        },
        //代码漏洞等级分布参数配置
        getechart1() {
            const that = this;
            /*const data = this.agedata.map((item) => ({
                value: item.percentage,
                name: item.age_group,
            }));*/
            const data = [
                {name: '高危',value:this.vueNum1.high_risk},
                {name: '中危',value:this.vueNum1.med_risk},
                {name: '低危',value:this.vueNum1.low_risk},
            ]

            // 指定图表的配置项和数据
            this.option1 = {
                color:[
                    "#D13622",
                    "#EEB26C",
                    "#3fd527",
                ],
                tooltip: {
                    trigger: 'item',
                    formatter: '{a} <br/>{b} : {c} ({d}%)'
                },
                legend:{
                    show:false,
                },
                series: [{
                    name: '等级分布',
                    type: 'pie',
                    // 设置饼形图在容器中的位置
                    center: ["50%", "50%"],
                    //内圆半径和外圆半径
                    radius: ['40%', '60%'],
                    hoverAnimation:true,
                    avoidLabelOverlap: false,
                    //显示标签文字
                    label: {
                        show: true,
                        normal: {
                            show: true,
                            formatter: "{b} : {c}个",//视觉引导线内容格式器,{a}（系列名称），{b}（数据项名称），{c}（数值）, {d}（百分比）
                            color:'rgba(19,16,14)',
                            fontSize: '16',
                        },
                    },
                    // 显示连接线(图形和文字之间的线)
                    labelLine: {
                        show: true,
                        lineStyle: {
                            color: 'rgba(19,16,14, 0.5)'
                        },
                        smooth: 0.2,
                        //以下两个指线的长度
                        length: 10, //连接扇形图线长
                        length2: 20 //连接文字线长
                    },
                    data: data
                }]
            };
        },
        // 渲染图表
        randerEcharts1() {
            const boxsSex = echarts.init(document.getElementById('echarts1'));
            boxsSex.resize();
            boxsSex.clear();
            boxsSex.setOption(this.option1, true);
        },

        //获得漏洞信息统计信息（柱状图）
        getMajor(){
            var that = this
            $.ajax({
                url: (http_head + '/login/'),
                data:{
                    method : 'Task_Detail_3',
                    task_id: that.taskid,
                },
                type: 'post',
                dataType: 'JSON',
                async:false,
                success: function (res){
                    // console.log(res)
                    if(res.msg !== '统计结果为空'){
                        that.vueNum2 = res
                        that.vulTypes = that.vueNum2.map(obj => obj.vultype).join(", ");
                        // console.log(that.vulTypes)
                        // console.log(that.vueNum2)
                    }
                },
                error: function (err) {
                    console.log(err)
                    mymessage.error("漏洞信息统计获取失败")
                }
            })
            this.$nextTick(function () {
                this.getechart5()
                this.randerEcharts5()
            })
        },
        //漏洞信息统计参数配置
        getechart5(){
            var majordata = this.vueNum2
            var data_x = majordata.map(item=>item.vultype)
            var data_y = majordata.map(item=>item.count)
            this.option5 =   {
                tooltip: {
                    trigger: 'item',
                    formatter: '{a} <br/>{b} : {c}'
                },
                toolbox:{// 工具栏。内置有导出图片，数据视图，动态类型切换，数据区域缩放，重置五个工具。
                    feature:{
                        saveAsImage: {},//导出图片
                        magicType: {//动态类型切换
                            type:['bar','line']
                        }
                    }
                },
                label:{ // 柱状图 内部 显示数值
                    show:true,
                    // rotate:30,
                },
                legend: {//图例组件。图例组件展现了不同系列的标记(symbol)，颜色和名字。可以通过点击图例控制哪些系列不显示。
                    data: ['数量']
                },
                xAxis: { // X Y 轴数据互换可以 变成横向柱状图
                    data: data_x
                },
                yAxis: {

                },
                series: [// 核心设置  系列
                    {
                        name: '数量',
                        type: 'bar',
                        data: data_y,
                    }
                ]
            };
        },
        // 渲染图表
        randerEcharts5() {
            const boxsSex = echarts.init(document.getElementById('echarts2'));
            boxsSex.resize();
            boxsSex.clear();
            boxsSex.setOption(this.option5, true);
        },

    }

});
//获取当前时间
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
