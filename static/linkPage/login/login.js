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
    },
    data() {
        return {
            loginForm:{
                name:'',
                password:'',
                authorization:''
            },
            rules:{
                name: [
                    { required: true, message: '请输入用户名', trigger: 'blur' },
                    // { min: 3, max: 6, message: '用户名长度在 3 到 6 个字符', trigger: 'blur' }
                ],
                password: [
                    { required: true, message: '请输入密码', trigger: 'blur' },
                    // { min: 3, max: 6, message: '密码长度在 3 到 6 个字符', trigger: 'blur' }
                ]

            },
            logStatus:'',
        }
    },

    methods: {
        // 点击登录
        confirm(){
            if (this.loginForm.name == "") {
                alert("请输入您的用户账号！");
                return false
            }
            if (this.loginForm.password == "") {
                alert("请输入您的登录密码！");
                return false
            }
            let flag1 = this.checkSqlsIn(this.loginForm.name);
            let flag2 = this.checkSqlsIn(this.loginForm.password);
            
            console.log(flag1,flag2)
            if(flag1 || flag2){
                mymessage.error("存在非法输入！")
                return
            } else {
                this.loginLog(this.logStatus)
            }
        },
        loginLog(status){
            var that = this

            $.ajax({
                url:  'http://10.99.16.24:8088/access_log/',
                data:{
                    method : 'access_log',
                    username: that.loginForm.name,
                    status: status,
                },
                type : 'post',
                dataType : 'JSON',
                success : function (res){

                },
                error: function (err) {
                    console.log(err)
                    that.login()
                    // mymessage.error("登陆失败")
                }
            })
        },
        login(){
            var that = this
            debugger
            $.ajax({
                url:  'http://10.99.16.24:8088/login/',
                data:{
                    method : 'login',
                    username: that.loginForm.name,
                    password: that.loginForm.password,
                    authorization: that.loginForm.authorization
                },
                type : 'post',
                dataType : 'JSON',
                success : function (res){
                    console.log(res);
                    if (res.code == '200'){
                        mymessage.success("登陆成功");
                        sessionStorage.setItem('info',JSON.stringify(that.loginForm))
                        that.logStatus = '1'
                        that.loginLog(that.logStatus)
                        debugger
                        // window.location.href = 'http://10.99.16.24:8088/static/python/index.html'
                        window.location.href = 'http://10.99.16.24:8088/static/linkPage/login/index.html'
                    }
                    else if(res.code == '500'){
                        mymessage.error("登陆失败")
                    }
                },
                error: function (err) {
                    that.logStatus = '0'
                    that.loginLog(that.logStatus)
                    mymessage.error("登陆失败")
                }
            })
        },
        // 防止sql注入
        checkSqlsIn(_obj) {
            //SQL注入常见字符
            var sqlKeyWords = "select ,union ,asc ,desc ,in ,like ,into ,exec ,from ";
            sqlKeyWords += ",select,union,asc,desc,in,like,into,exec,from";
            sqlKeyWords += ",update ,insert ,delete ,count ,asc( ,char( ,chr( ,drop ,table ,truncat ";
            sqlKeyWords += ",mid( ,abs( ,= ,-- ,<script ,/script ";
            sqlKeyWords += ",where ,join ,create ,alter ,cast ,exists ,; , or , and ,order by ,group by ";
            //分割成数组
            var sqls = sqlKeyWords.split(",");
            // console.log(sqls)

            let lxdInput = JSON.stringify(_obj);
            let invalid = false;
            let chkInput = (lxdInput + "").toLowerCase();
            let pos = -1;
            for (let i = 0, n = sqls.length; i < n; i++) {
                pos = chkInput.indexOf(sqls[i]);
                if (pos != -1) {
                    invalid = true;
                    break;
                }
            }
            return invalid;
        },

    }
});


