
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
        this.getConfig()
    },
    data() {
        return {
            config1:'',
            version:'',
            options: [
                {
                    value: 'CWE Top 25',
                    label: 'CWE Top 25',
                    children: [{
                        value: 'CWE Top 25 2019',
                        label: 'CWE Top 25 2019',
                    }, {
                        value: 'CWE Top 25 2020',
                        label: 'CWE Top 25 2020',
                    },],
                },
                {
                    value: 'CWE/SANS Top 25',
                    label: 'CWE/SANS Top 25',
                    children: [{
                        value: '2011 CWE/SANS Top 25',
                        label: '2011 CWE/SANS Top 25',
                    },{
                        value: '2010 CWE/SANS Top 25',
                        label: '2010 CWE/SANS Top 25',
                    },{
                        value: '2009 CWE/SANS Top 25',
                        label: '2009 CWE/SANS Top 25',
                    }]
                },
                {
                    value: 'OWASP Top 10',
                    label: 'OWASP Top 10',
                    children: [{
                        value: 'OWASP Top 10 2017',
                        label: 'OWASP Top 10 2017',
                    },{
                        value: 'OWASP Top 10 2013',
                        label: 'OWASP Top 10 2013',
                    },{
                        value: 'OWASP Top 10 2010',
                        label: 'OWASP Top 10 2010',
                    }]
                },
                {
                    value: 'Developer Workbook',
                    label: 'Developer Workbook',
                    children: [{
                        value: 'Developer Workbook',
                        label: 'Developer Workbook',
                    }]
                },

            ],


            ruuule: false,       //是否显示检测规范
        }

    },
    methods: {
        //保存配置
        save() {
            // console.log(username)
            const that = this
            if (this.config1){
                // rule1，2，3需要选规则
                // if((this.config1 === 'rule1' || this.config1 === 'rule2' || this.config1 === 'rule3') && this.version == ''){
                //     mymessage.error("检测规范未选择！")
                // } else {
                //     if(this.config1 === 'rule1' || this.config1 === 'rule2' || this.config1 === 'rule3') {
                //         var policy = this.config1 + ',' + this.version[0] + ',' + this.version[1]
                //         // console.log(policy)
                //     } else {
                        var policy = this.config1
                    // }
                    $.ajax({
                        url:  (http_head + '/login/'),
                        data:{
                            method: 'insert_Pol',
                            account: localUser.account,
                            policy: policy,
                        },
                        type : 'post',
                        dataType : 'JSON',
                        success : function (res){
                            // console.log(res);
                            mymessage.success("保存成功")
                            that.getConfig()
                        },
                        error: function (err) {
                            console.log(err)
                            mymessage.error("保存失败")
                        }
                    })
                // }
            } else { mymessage.error("模型未选择！") }
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

                    if(res.policy) {
                        console.log('policy:',res.policy)
                        // var str = res.policy.split(',')
                        // if (str[0] === 'rule1' || str[0] === 'rule2' || str[0] === 'rule3') {
                        //     that.config1 = str[0]     //模型
                        //     that.version = str.slice(1)       //规范
                            // console.log(that.version)

                        // } else {
                            that.config1 = res.policy
                        // }

                    }
                },
                error: function (err) {
                    console.log(err)
                }
            })
        },
        //漏洞规范
        handleChange(value) {
            // console.log(value);
            // console.log(this.version)
        },
        //模型选择
        // input(label){
        //     // console.log(label)
        //     if (label === 'rule1' || label === 'rule2' || label === 'rule3') {
        //         this.ruuule = true
        //     } else {
        //         this.ruuule = false
        //     }
        // },
        // 重置
        reset(){
            this.config1 = ''
            this.version = ''
        },

    }

})