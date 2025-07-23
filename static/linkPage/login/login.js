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
        // this.url()

    },
    data() {
        return {
            loginForm:{
                name:'',
                password:'',
                captcha:'',
            },
            captchaText: '',

            logStatus:'',
        }
    },

    methods: {
        // 生成验证码
        generateCaptcha() {
            const canvas = this.$refs.captchaCanvas;
            const ctx = canvas.getContext('2d');

            // 设置 canvas 宽高
            canvas.width = 120;
            canvas.height = 40;

            // 清空画布
            ctx.clearRect(0, 0, canvas.width, canvas.height);

            // 生成随机验证码
            const chars = '0123456789';
            let captcha = '';
            for (let i = 0; i < 4; i++) {
                captcha += chars[Math.floor(Math.random() * chars.length)];
            }
            this.captchaText = captcha;

            // 绘制背景
            ctx.fillStyle = '#f0f0f0';
            ctx.fillRect(0, 0, canvas.width, canvas.height);

            // 绘制随机线条
            for (let i = 0; i < 3; i++) {
                ctx.strokeStyle = this.getRandomColor();
                ctx.beginPath();
                ctx.moveTo(Math.random() * canvas.width, Math.random() * canvas.height);
                ctx.lineTo(Math.random() * canvas.width, Math.random() * canvas.height);
                ctx.stroke();
            }

            // 绘制验证码文本
            for (let i = 0; i < captcha.length; i++) {
                ctx.font = `${this.getRandomFontSize()}px Arial`; // 随机字体大小
                ctx.fillStyle = this.getRandomColor();
                ctx.fillText(captcha[i], 10 + i * 25, 30); // 每个字符间隔 25px
            }
        },
        // 获取随机颜色
        getRandomColor() {
            const r = Math.floor(Math.random() * 256);
            const g = Math.floor(Math.random() * 256);
            const b = Math.floor(Math.random() * 256);
            return `rgb(${r},${g},${b})`;
        },
        // 获取随机字体大小
        getRandomFontSize() {
            return Math.floor(Math.random() * 10) + 20; // 字体大小在 20-30px 之间
        },
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
            if (this.loginForm.captcha == "") {
                alert("请输入验证码！");
                return false
            }
            if(this.loginForm.captcha !== this.captchaText) {
                alert("验证码错误！请重新输入");
                this.generateCaptcha()
                this.loginForm.captcha = ''
                return false
            }
            let flag1 = this.checkSqlsIn(this.loginForm.name);
            let flag2 = this.checkSqlsIn(this.loginForm.password);
            // console.log(flag1,flag2)
            if(flag1 || flag2){
                mymessage.error("存在非法输入！")
                return
            } else {
                this.loginLog(this.logStatus)
            }
        },
        reset(){
            this.loginForm = {
                name:'',
                password: '',
                captcha: '',
            }
        },
        url(){
            const currentUrl = window.location.href;
            // console.log('当前网址链接:', currentUrl);
        },
        loginLog(status){
            var that = this

            $.ajax({
                url:  http_head + '/access_log/',
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
            
            $.ajax({
                url:  http_head + '/login/',
                data:{
                    method : 'login',
                    username: that.loginForm.name,
                    password: that.loginForm.password,
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
                        window.location.href = http_head + '/static/linkPage/login/index.html'
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

    },
    mounted(){
        this.generateCaptcha()
    }
});


