let mymessage = {}

var a = new Vue({
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
        this.getNumber()
    },
    data(){
        return {
            count: {
            },
            year:'',
            years:[],
            data1:[0,0,0,0,0],
            data2:[0,0,0,0,0],
            data3:[0,0,0,0,0],
            data4:[0,0,0,0,0],
            data5:[0,0,0,0,0,0,0,0,0,0,0,0],
            data6:{},



        }
    },
    methods:{

        //第二行的数据
        getNumber() {
            const that = this
            $.ajax({
                url: (http_head + '/login/'),
                type: 'post',
                dataType: 'json',
                data: {
                    method: 'get_item_num',
                },
                success: function (res) {
                    console.log(res.data);
                    that.count = res.data
                },
                error: function (err) {
                    console.log(err)
                    mymessage.error("获取失败")
                }
            })
        },


        //第一行的数据
        getList1 () {
            var that = this;
            $.ajax({
                url: (http_head + '/login/'),
                type: 'post',
                dataType: 'json',
                async:false,
                data: {
                    method: 'Homepage_statistics',
                },
                success: function (res) {
                    console.log(res)
                    if (res.filelist1.length){
                        var n = res.filelist1.length    //有n年的数据
                        var nn = res.filelist2.length
                        var nnn = res.filelist3.length
                        var nnnn = res.filelist4.length

                        that.year = res.filelist1[n-1].year     //最近的年份
                        that.years = [that.year-4,that.year-3,that.year-2,that.year-1,that.year]
                        // console.log(that.years)
                        //第一个图
                        for (let i = 0;i < n ;i++) {
                            if(res.filelist1[i].year == that.years[0]){
                                that.data1[0] = res.filelist1[i].item_sum
                            } else if(res.filelist1[i].year == that.years[1]){
                                that.data1[1] = res.filelist1[i].item_sum
                            }else if(res.filelist1[i].year == that.years[2]){
                                that.data1[2] = res.filelist1[i].item_sum
                            }else if(res.filelist1[i].year == that.years[3]){
                                that.data1[3] = res.filelist1[i].item_sum
                            }else if(res.filelist1[i].year == that.years[4]){
                                that.data1[4] = res.filelist1[i].item_sum
                            }
                        }
                        // console.log(that.data1)
                        // 第二个图
                        for (let i = 0;i < nn ;i++) {
                            if(res.filelist2[i].year == that.years[0]){
                                that.data2[0] = res.filelist2[i].task_sum
                            } else if(res.filelist2[i].year == that.years[1]){
                                that.data2[1] = res.filelist2[i].task_sum
                            }else if(res.filelist2[i].year == that.years[2]){
                                that.data2[2] = res.filelist2[i].task_sum
                            }else if(res.filelist2[i].year == that.years[3]){
                                that.data2[3] = res.filelist2[i].task_sum
                            }else if(res.filelist2[i].year == that.years[4]){
                                that.data2[4] = res.filelist2[i].task_sum
                            }
                            // console.log(that.data2)
                        }

                        // 第三个图
                        for (let i = 0;i < nnn ;i++) {
                            if(res.filelist3[i].year == that.years[0]){
                                that.data3[0] = res.filelist3[i].code_sum
                            } else if(res.filelist3[i].year == that.years[1]){
                                that.data3[1] = res.filelist3[i].code_sum
                            }else if(res.filelist3[i].year == that.years[2]){
                                that.data3[2] = res.filelist3[i].code_sum
                            }else if(res.filelist3[i].year == that.years[3]){
                                that.data3[3] = res.filelist3[i].code_sum
                            }else if(res.filelist3[i].year == that.years[4]){
                                that.data3[4] = res.filelist3[i].code_sum
                            }
                            // console.log(that.data3)
                        }
                        // 第四个图
                        for (let i = 0;i < nnnn ;i++) {
                            if(res.filelist4[i].year == that.years[0]){
                                that.data4[0] = res.filelist4[i].vul_sum
                            } else if(res.filelist4[i].year == that.years[1]){
                                that.data4[1] = res.filelist4[i].vul_sum
                            }else if(res.filelist4[i].year == that.years[2]){
                                that.data4[2] = res.filelist4[i].vul_sum
                            }else if(res.filelist4[i].year == that.years[3]){
                                that.data4[3] = res.filelist4[i].vul_sum
                            }else if(res.filelist4[i].year == that.years[4]){
                                that.data4[4] = res.filelist4[i].vul_sum
                            }
                        }

                    } else {     //如果没有数据
                        var now = new Date();
                        var yearnow = now.getFullYear() //得到年份
                        var year1 = String(yearnow - 1)
                        var year2 = String(yearnow - 2)
                        var year3 = String(yearnow - 3)
                        var year4 = String(yearnow - 4)
                        that.years = [year4,year3,year2,year1,String(yearnow)]
                    }


                },
                error: function (err) {
                    console.log(err)
                    mymessage.error("获取失败")
                }
            })
            this.$nextTick(function () {
                this.getechart1()
                this.renderEcharts1()
            })
        },
        //代码漏洞等级分布参数配置
        getechart1() {
            const that = this;
            // 指定图表的配置项和数据
            this.option1 = {
                //网格
                grid: {
                    bottom: '5%',
                    containLabel: true,  //刻度标签,常用于『防止标签溢出』
                },
                //提示框
                tooltip: {
                    trigger: 'axis',  //坐标轴触发
                    axisPointer: {
                        type: 'none'  //指示器类型
                    },
                    //提示框浮层内容格式器
                    formatter: function (params) {
                        return params[0].name + ': ' + params[0].value;
                    }
                },
                xAxis: {
                    //横坐标的内容
                    data: that.years,
                    axisLine: {
                        lineStyle: {
                            color: '#808080'  // X轴线条颜色
                        },
                    },
                    axisLabel: {
                        textStyle: {
                            color: '#808080'    // 文本颜色  灰色
                        }
                    },
                },
                yAxis: {
                    type: 'value',
                    axisLine: {
                        show: true,  //坐标轴轴线
                        lineStyle: {
                            color: '#808080'  // Y轴线条颜色
                        },
                    },
                    axisLabel: {
                        textStyle: {
                            color: '#808080'   // Y轴文本颜色
                        }
                    },
                    min: 0,   //坐标轴刻度最小值。
                    // splitNumber: 8,     //坐标轴的分割段数
                    max: 'dataMax',   //自动取数据在该轴上的最大值作为最大刻度。
                },
                //在系列中设置数据
                series: [{
                    type: 'pictorialBar',  //具象图形元素的柱状图
                    symbol: 'triangle', // 三角形
                    //图形宽度
                    barWidth: '80%',
                    //柱条样式
                    itemStyle: {
                        //平常
                        normal: {
                            opacity: 0.7,  //透明度
                            color: function (params) {
                                //注意，如果颜色太少的话，后面颜色不会自动循环，最好多定义几个颜色
                                var colorList = ['#78a5ff', '#82be66', '#f2b912', '#f56648', '#6bc3e7'];
                                return colorList[params.dataIndex]
                            }
                        },
                        //高亮状态
                        emphasis: {
                            opacity: 1   //实心
                        },
                    },
                    data: that.data1,
                }]
            };
        },
        // 渲染图表
        renderEcharts1() {
            const boxsSex = echarts.init(document.getElementById('echarts1'));
            // window.addEventListener('resize', function() {
            //     boxsSex.resize();
            // });
            boxsSex.resize();  //当容器大小改变时，图表的大小也相应地改变。  ???好像没执行
            boxsSex.clear();
            boxsSex.setOption(this.option1, true);
        },
        getList2 () {
            var that = this;
            this.$nextTick(function () {
                this.getechart2()
                this.renderEcharts2()
            })
        },
        getechart2() {
            const that = this;
            this.option2 = {
                grid: {
                    bottom: '5%',
                    containLabel: true,
                },
                tooltip : {
                    trigger: 'item'
                },
                xAxis: {
                    data: that.years,
                },
                yAxis: {
                    type : 'value',//数值轴
                    min: 0,   //坐标轴刻度最小值。
                    max: 'dataMax',   //自动取数据在该轴上的最大值作为最大刻度。
                },
                series: [{
                    type: 'scatter',
                    itemStyle: {
                        color: 'rgb(118,141,209)',
                    },
                    data: that.data2,
                    symbolSize: function(value) {
                        return 15;
                    }
                }]
            };


        },
        // 渲染图表
        renderEcharts2() {
            const boxsSex = echarts.init(document.getElementById('echarts2'));
            boxsSex.resize();
            boxsSex.clear();
            boxsSex.setOption(this.option2, true);
        },
        getList3 () {
            var that = this;
            this.$nextTick(function () {
                this.getechart3()
                this.renderEcharts3()
            })
        },
        getechart3() {
            const that = this;
            this.option3 = {
                grid: {
                    bottom: '5%',
                    containLabel: true,
                },
                tooltip : {
                    trigger: 'axis'
                },
                calculable : true,
                xAxis : {
                    type : 'category',
                    data : that.years,
                    axisLine: {
                        lineStyle: {
                            color: '#808080'  // X轴线条颜色
                        },
                    },
                    axisLabel: {
                        textStyle: {
                            color: '#808080'    // 文本颜色  灰色
                        }
                    },
                },
                yAxis : {
                    type : 'value',
                    min: 0,   //坐标轴刻度最小值。
                    max: 'dataMax',   //自动取数据在该轴上的最大值作为最大刻度。
                    axisLine: {
                        show: true,  //坐标轴轴线
                        lineStyle: {
                            color: '#808080'  // Y轴线条颜色
                        },
                    },
                    axisLabel: {
                        textStyle: {
                            color: '#808080'   // Y轴文本颜色
                        }
                    },
                },
                series : [
                    {
                        name:'总代码量',
                        type:'bar',    //柱状图
                        data:that.data3,
                        markPoint : {
                            data : [
                                {type : 'max', name: '最大值'},
                                {type : 'min', name: '最小值'}
                            ]
                        },

                        itemStyle: {
                            opacity: 0.7,
                            color: '#f4b7b7',
                        }
                    },

                ]
            };


        },
        // 渲染图表
        renderEcharts3() {
            const boxsSex = echarts.init(document.getElementById('echarts3'));
            boxsSex.resize();
            boxsSex.clear();
            boxsSex.setOption(this.option3, true);
        },
        getList4 () {
            var that = this;
            this.$nextTick(function () {
                this.getechart4()
                this.renderEcharts4()
            })
        },
        getechart4() {
            const that = this;

            this.option4 = {
                tooltip: {
                    trigger: 'axis',
                    axisPointer: {
                        lineStyle: {
                            width: 3,
                            color: '#019688',
                        },
                    },
                },
                grid: {
                    bottom: '5%',
                    containLabel: true,
                },
                color: ['#019688', '#119AC2'],
                xAxis: [
                    {
                        type: 'category',
                        boundaryGap: false,
                        data: that.years,
                        axisLabel: {
                            // rotate: 25,   //倾斜
                            color: '#808080'
                        },
                        splitLine: {
                            show: true,
                            lineStyle: {
                                width: 1,
                                type: 'solid',
                                color: 'rgba(226,226,226,0.5)',
                            },
                        },
                        axisTick: { // 轴刻度线
                            show: false,
                        },
                    },
                ],
                yAxis: [
                    {
                        type: 'value',
                        name: '',
                        min: 0,   //坐标轴刻度最小值。
                        max: 'dataMax',   //自动取数据在该轴上的最大值作为最大刻度。
                        axisTick: { // 轴刻度线
                            // show: false,
                        },
                        // 刻度文字颜色
                        axisLabel: { color: '#808080' },
                        // y轴刻度设置
                        axisLine: {
                            lineStyle: {
                                color: '#a2a2a2',
                            },
                        },
                        // y轴分隔线设置
                        splitLine: {
                            lineStyle: {
                                color: 'rgba(226,226,226,0.5)',
                            },
                        },
                        // y轴分隔区域设置
                        splitArea: {
                            show: true,
                            areaStyle: {
                                color: ['rgba(250,250,250,0.3)', 'rgba(226,226,226,0.3)'],
                            },
                        },
                    },

                ],
                series: [
                    {
                        name: '缺陷总数',
                        type: 'line',
                        data: that.data4,
                        smooth: true,   //相当于0.5
                        symbolSize: 6,
                        areaStyle: {},  //填充
                        itemStyle: {
                        },
                    },
                ],
            };

        },
        // 渲染图表
        renderEcharts4() {
            const boxsSex = echarts.init(document.getElementById('echarts4'));
            boxsSex.resize();
            boxsSex.clear();
            boxsSex.setOption(this.option4, true);
        },
        //第三行，第一个图（第五个图）
        getList5 () {
            var that = this;
            $.ajax({
                url: (http_head + '/login/'),
                type: 'post',
                dataType: 'json',
                async:false,
                data: {
                    method: 'TaskNum_Time',
                    year: that.year,
                },
                success: function (res) {
                    console.log(res)
                    //看返回的数据是哪几个月的，然后赋值对应月份的数据
                    for (let i = 0;i < res.length ;i++) {
                        if(res[i].month === 1){
                            that.data5[0] = res[i].task_count
                        } else if(res[i].month === 2){
                            that.data5[1] = res[i].task_count
                        }else if(res[i].month === 3){
                            that.data5[2] = res[i].task_count
                        }else if(res[i].month === 4){
                            that.data5[3] = res[i].task_count
                        }else if(res[i].month === 5){
                            that.data5[4] = res[i].task_count
                        } else if(res[i].month === 6){
                            that.data5[5] = res[i].task_count
                        }else if(res[i].month === 7){
                            that.data5[6] = res[i].task_count
                        }else if(res[i].month === 8){
                            that.data5[7] = res[i].task_count
                        }else if(res[i].month === 9){
                            that.data5[8] = res[i].task_count
                        } else if(res[i].month === 10){
                            that.data5[9] = res[i].task_count
                        }else if(res[i].month === 11){
                            that.data5[10] = res[i].task_count
                        }else if(res[i].month === 12){
                            that.data5[11] = res[i].task_count
                        }
                    }
                    // console.log(that.data5)
                },
                error: function (err) {
                    console.log(err)
                    mymessage.error("获取失败")
                }
            })
            this.$nextTick(function () {
                this.getechart5()
                this.renderEcharts5()
            })
        },
        getechart5() {
            const that = this;
            this.option5 = {
                grid: {
                    bottom: '5%',
                    containLabel: true,
                },
                tooltip : {
                    trigger: 'axis'
                },
                xAxis : {
                    type : 'category',           //类目轴，适用于离散的类目数据
                    boundaryGap : false,    // boundaryGap值为false的时候，折线第一个点在y轴上
                    data : ['1月','2月','3月','4月','5月','6月','7月','8月','9月','10月','11月','12月']
                },
                yAxis : {
                    type : 'value',//数值轴
                    min: 0,   //坐标轴刻度最小值。
                    max: 'dataMax',   //自动取数据在该轴上的最大值作为最大刻度。
                },
                series : [
                    {
                        name:'检测任务数',         //用于tooltip的显示
                        type:'line',            //折线/面积图
                        symbolSize:8,          // 设置折线上圆点大小
                        symbol: 'none',       // 设置小圆点消失,注意：设置symbol: 'none'以后，拐点不存在了，设置拐点上显示数值无效
                        smooth: 0.5,         // 设置折线弧度，取值：0-1之间
                        data: this.data5,
                        markPoint : {
                            data : [
                                {type : 'max', name: '最大值'},
                                // {type : 'min', name: '最小值'}
                            ]
                        },
                        markLine:{
                            data:[
                                {type:'average',name:'平均值'}
                            ]
                        }
                    },
                ]
            };

        },
        // 渲染图表
        renderEcharts5() {
            const boxsSex = echarts.init(document.getElementById('echarts5'));
            boxsSex.resize();
            boxsSex.clear();
            boxsSex.setOption(this.option5, true);
        },

        //第三行，第二个图（第六个图）
        getList6 () {
            var that = this;
            $.ajax({
                url: (http_head + '/login/'),
                type: 'post',
                dataType: 'json',
                async:false,          //!!!先执行接口函数再执行图表函数
                data: {
                    method: 'LevelNum_Time',
                    year: that.year,
                },
                success: function (res) {
                    console.log(res)
                    if (res[0]){
                        that.data6 = res[0]
                    } else {
                        that.data6 = {
                            high:0,
                            low:0,
                            med:0,
                        }
                    }
                },
                error: function (err) {
                    console.log(err)
                    mymessage.error("获取失败")
                }
            })
            this.$nextTick(function () {
                this.getechart6()
                this.renderEcharts6()
            })
        },
        getechart6() {
            const that = this;
            // console.log(this.data6)
            const data = [
                {name: '高危',value:that.data6.high},
                {name: '中危',value:that.data6.low},
                {name: '低危',value:that.data6.med},
            ]


            // 指定图表的配置项和数据
            this.option6 = {
                legend: {
                    orient: 'vertical',
                    x: 'left',
                    data: ['高危', '中危', '低危',]
                },
                color:[
                    "#ff7070",
                    "#EEB26C",
                    "#7ed3f4",
                ],
                tooltip: {
                    trigger: 'item',
                    formatter: '{a} <br/>{b} : {c} ({d}%)'
                },
                // legend:{
                //     show:false,
                // },
                series: [{
                    name: '等级分布',
                    type: 'pie',
                    // 设置饼形图在容器中的位置
                    center: ["50%", "50%"],
                    //内圆半径和外圆半径
                    radius: ['50%', '70%'],
                    // hoverAnimation:true,
                    avoidLabelOverlap: false,
                    //显示标签文字
                    label: {
                        show: false,
                        position: 'center'
                    },
                    labelLine: {
                        show: false
                    },
                    emphasis: {
                        label: {
                            show: true,
                            fontSize: '20',
                            fontWeight: 'bold'
                        }
                    },
                    // label: {
                    //     show: true,
                    //     normal: {
                    //         show: true,
                    //         formatter: "{b} : {c}个",//视觉引导线内容格式器,{a}（系列名称），{b}（数据项名称），{c}（数值）, {d}（百分比）
                    //         color:'rgba(19,16,14)',
                    //         fontSize: '16',
                    //     },
                    // },
                    // 显示连接线(图形和文字之间的线)
                    // labelLine: {
                    //     show: true,
                    //     lineStyle: {
                    //         color: 'rgba(19,16,14, 0.5)'
                    //     },
                    //     smooth: 0.2,
                    //     //以下两个指线的长度
                    //     length: 10, //连接扇形图线长
                    //     length2: 20 //连接文字线长
                    // },
                    data: data
                }]
            };

        },
        // 渲染图表
        renderEcharts6() {
            const boxsSex = echarts.init(document.getElementById('echarts6'));
            boxsSex.resize();
            boxsSex.clear();
            boxsSex.setOption(this.option6, true);
        },

    },
    mounted(){
        this.getList1()
        this.getList2()
        this.getList3()
        this.getList4()
        this.getList5()
        this.getList6()

    }
})