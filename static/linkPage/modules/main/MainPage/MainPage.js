let vm = new Vue({
  el: "#app",
  data() {
    return {
      projectNum: "",
      loopholeNum: "",
      filenum:"",
      highNum:"",
      mediumNun:"",
      lowNum:"",
      vueList: [],
      projectList: [],
      option1: {},
      option2: {},
      tuandui: [],
      high: [],
      medium: [],
      low: [],
    };
  },
  created() {
    mymessage = {
      info: (options, single = true) => {
        this.$message({ message: options, type: "info" });
      },
      warning: (options, single = true) => {
        this.$message({ message: options, type: "warning" });
      },
      error: (options, single = true) => {
        this.$message({ message: options, type: "error" });
      },
      success: (options, single = true) => {
        this.$message({ message: options, type: "success" });
      },
    };
    this.getBaseData();
  },
  methods: {
    //获取基本信息
    getBaseData() {
      var that = this;
      $.ajax({
        url: (http_head + '/login/'),
        data: {
          method: "count",
          accountId: localUser.accountId,
        },
        type: "post",
        dataType: "JSON",
        success: function (res) {
          console.log(res);
          if (res) {
            that.projectNum = res[0].item;
            that.loopholeNum = res[0].vul;
            that.filenum = res[0].filenum;
            that.highNum = res[0].highNum;
            that.mediumNun = res[0].mediumNun;
            that.lowNum = res[0].lowNum;
            mymessage.success("基本信息获取成功");
          }
        },
        error: function (err) {
          console.log(err);
          mymessage.error("获取失败");
        },
      });
    },
    getdata1() {
      var that = this;
      $.ajax({
        url: (http_head + '/login/'),
        data: {
          method: "count_left",
          accountId: localUser.accountId,
        },
        type: "post",
        dataType: "JSON",
        async: false,
        success: function (res) {
          console.log(res);
          if (res) {
            that.vueList = res;
            mymessage.success("获取成功");
          }
        },
        error: function (err) {
          console.log(err);
          mymessage.error("获取失败");
        },
      });
      this.$nextTick(function () {
        this.getSecurityMessageCensus();
        this.randerEcharts1();
      });
    },

    getdata2() {
      var that = this;
      $.ajax({
        url: (http_head + '/login/'),
        data: {
          method: "count_right",
          accountId: localUser.accountId,
        },
        type: "post",
        dataType: "JSON",
        async: false,
        success: function (res) {
          console.log(res);
          if (res) {
            that.projectList = res;
            mymessage.success("获取成功");
          }
        },
        error: function (err) {
          console.log(err);
          mymessage.error("获取失败");
        },
      });
      // if (this.$refs.chart) {
      this.$nextTick(function () {
        this.getSecurityBugsNumCensus();
        this.randerEcharts2();
      });
      // }
    },

    //图表一设置参数
    getSecurityMessageCensus() {
      const that = this;
      const echartsData = this.vueList.map((item) => ({
        value: item.count,
        name: item.vultype,
      }));
      console.log(echartsData);

      // 指定图表的配置项和数据
      this.option1 = {
        tooltip: {
          trigger: "item",
        },
        legend: {
          orient: "vertical",
          left: "left",
        },
        series: [
          {
            name: "漏洞编号",
            type: "pie",
            radius: "50%",
            data: echartsData,
            emphasis: {
              itemStyle: {
                shadowBlur: 10,
                shadowOffsetX: 0,
                shadowColor: "rgba(0, 0, 0, 0.5)",
              },
            },
          },
        ],
      };
    },

    // 渲染图表
    randerEcharts1() {
      const boxsSex = echarts.init(this.$refs.SecurityMessageCensus);
      boxsSex.resize();
      boxsSex.clear();
      boxsSex.setOption(this.option1, true);
    },

    getSecurityBugsNumCensus() {
      const that = this;     
      console.log(this.projectList);      
      for (let i = 0; i < this.projectList.length; i++) {
        this.tuandui[i] = this.projectList[i].name;
      }
      for (let i = 0; i < this.projectList.length; i++) {
        this.high[i] = this.projectList[i].highNumber;
      }
      for (let i = 0; i < this.projectList.length; i++) {
        this.medium[i] = this.projectList[i].mediumNumber;
      }
      for (let i = 0; i < this.projectList.length; i++) {
        this.low[i] = this.projectList[i].lowNumber;
      }
      tuandui = this.tuandui
      high = this.high
      medium = this.medium
      low = this.low
      console.log(tuandui)
      // 指定图表的配置项和数据
      this.option2 = {
        tooltip: {
          trigger: "axis",
          axisPointer: {
            type: "shadow",
          },
        },
        textStyle: {
          color: '#466293'
        },
        legend: {
          data: ['高危', '中危', '低危'],
          textStyle: {
            color: '#8db0ef',
            fontFamily: 'DINProRegular',
          },
          //图例标记宽高
          itemWidth: 15,
          itemHeight: 7,
          itemGap: 15,
          top: 15
        },
        grid: {
          left: "3%",
          right: "4%",
          bottom: "3%",
          containLabel: true,
        },
        xAxis: [
          {
            type: "category",
            data: tuandui,
          },
        ],
        yAxis: [
          {
            type: "value",
          },
        ],
        series: [          
          {
            name: "高危",
            type: "bar",
            itemStyle: {
              //柱条渐变色
              color:new echarts.graphic.LinearGradient(
                  1, 0, 0, 1,
                  [
                    {offset: 0, color: '#0090ff'},
                    {offset: 1, color: '#0075d0'}
                  ]
              )
            },
            data: high,
          },
          {
            name: "中危",
            type: "bar",
            data: medium,
            itemStyle: {
              //柱条渐变色
              color:new echarts.graphic.LinearGradient(
                  1, 0, 0, 1,
                  [
                    {offset: 0, color: '#ffb746'},
                    {offset: 1, color: '#ffb034'}
                  ]
              )
            }
          },
          {
            name: "低危",
            type: "bar",
            data: low,
            itemStyle: {
              //柱条渐变色
              color:new echarts.graphic.LinearGradient(
                  1, 0, 0, 1,
                  [
                    {offset: 0, color: '#ff605f'},
                    {offset: 1, color: '#ff504f'}
                  ]
              )
            }
          },         
        ],
      };

    },

    // 渲染图表
    randerEcharts2() {
      const boxsSex = echarts.init(this.$refs.SecurityBugsNumCensus);
      boxsSex.resize();
      boxsSex.clear();
      boxsSex.setOption(this.option2, true);
    },
  },
  mounted() {
    this.getdata1();
    this.getdata2();
  },
});


