
let mymessage = {}
const vueListData = [
  {"id":"cwe787"    ,"name":"cwe787-越界读取"},
  {"id":"cwe79"     ,"name":"cwe79-在网页生成过程中对输入的处理不当（跨站脚本攻击）"},
  {"id":"cwe125"    ,"name":"cwe125-越界读取"},
  {"id":"cwe20"   	,"name":"cwe20-输入验证不当"},
  {"id":"cwe78"	    ,"name":"cwe78-多OS命令中使用的特殊元素处理不当（OS命令注入）"},
  {"id":"cwe89"	    ,"name":"cwe89-对SQL命令中使用的特殊元素处理不当(SQL注入)"},
  {"id":"cwe416"	,"name":"cwe416-释放后使用"},
  {"id":"cwe22"	    ,"name":"cwe22-对受限制目录的路径名的限制不当（“路径遍历”）"},
  {"id":"cwe352"	,"name":"cwe352-跨站点请求伪造（CSRF）"},
  {"id":"cwe434"	,"name":"cwe434-危险类型文件的不加限制上传"},
  {"id":"cwe306"	,"name":"cwe306-关键功能的认证机制缺失"},
  {"id":"cwe190"	,"name":"cwe190-整数溢出或回绕"},
  {"id":"cwe502"	,"name":"cwe502-不受信任的数据的反序列化"},
  {"id":"cwe287"	,"name":"cwe287-身份认证不当"},
  {"id":"cwe476"	,"name":"cwe476-空指针解引用"},
  {"id":"cwe798"	,"name":"cwe798-使用硬编码凭据"},
  {"id":"cwe119"	,"name":"cwe119-对超出界限的内存访问限制不当"},
  {"id":"cwe862"	,"name":"cwe862-缺少授权"},
  {"id":"cwe276"	,"name":"cwe276-默认权限不正确"},
  {"id":"cwe200"	,"name":"cwe200-将敏感信息暴露给未经授权的参与者"},
  {"id":"cwe522"	,"name":"cwe522-不充分的凭证保护机制"},
  {"id":"cwe732"	,"name":"cwe732-关键资源的权限分配不正确"},
  {"id":"cwe611"	,"name":"cwe611-XML外部实体引用的限制不当（XXE）"},
  {"id":"cwe918"	,"name":"cwe918-服务器端请求伪造（SSRF）"},
  {"id":"cwe77"	    ,"name":"cwe77-在命令中使用的特殊元素转义处理不当（命令注入）"},
  {"id":"cwe295"	,"name":"cwe295-不正确的证书验证"},
  {"id":"cwe400"	,"name":"cwe400-未加控制的资源消耗（资源穷尽）"},
  {"id":"cwe94" 	,"name":"cwe94-对生成代码的控制不恰当（代码注入）"},
  {"id":"cwe269"	,"name":"cwe269-权限管理不当"},
  {"id":"cwe917"	,"name":"cwe917-表达式语言语句中使用的特殊元素的不当中和（表达式语言注入）"},
  {"id":"cwe59"	    ,"name":"cwe59-在文件访问前对链接解析不恰当（链接跟随）"},
  {"id":"cwe401"	,"name":"cwe401-在移除最后引用时对内存的释放不恰当（内存泄露）"},
  {"id":"cwe362"	,"name":"cwe362-使用共享资源进行同步不正确的并发执行（争用条件）"},
  {"id":"cwe427"	,"name":"cwe427-对搜索路径元素未加控制"},
  {"id":"cwe319"	,"name":"cwe319-敏感信息的明文传输"},
  {"id":"cwe843"	,"name":"cwe843-使用不兼容类型访问资源（类型混淆）"},
  {"id":"cwe601"	,"name":"cwe601-URL重定向漏洞"},
  {"id":"cwe863"	,"name":"cwe863-授权机制不正确"},
  {"id":"cwe532"	,"name":"cwe532-在日志文件中包含敏感信息"},
  {"id":"cwe770"	,"name":"cwe770-不加限制或调节的资源分配"},
  {"id":"cwe327"	,"name":"cwe327-使用被破解或有风险的加密算法"},
  {"id":"cwe90" 	,"name":"cwe90-LDAP注⼊"},
];

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

    document.addEventListener("keydown", (e) => {
      let key = window.event.keyCode;
      if (key == 13 && !this.loading) {
        // 13是enter键的键盘码 如果等于13 就调用click的登录方法
        this.handleMsg();
      }
    });

  },
  data() {
    return {
      vueList: vueListData,
      menuName:'AIsecurity',
      input3: "",
      task:'代码漏洞检测',
      language:'',
      cwe:'',
      list: [],
      loading: false,
      display:true,
      example1: '写一个防止sql注入的登录程序',
      example2: '请分析以下代码有什么漏洞并修复它：public class BenchmarkTest00023 extends HttpServlet {\n' +
          '\n' +
          '    private static final long serialVersionUID = 1L;\n' +
          '\n' +
          '    @Override\n' +
          '    public void doGet(HttpServletRequest request, HttpServletResponse response)\n' +
          '            throws ServletException, IOException {\n' +
          '        doPost(request, response);\n' +
          '    }\n' +
          '\n' +
          '    @Override\n' +
          '    public void doPost(HttpServletRequest request, HttpServletResponse response)\n' +
          '            throws ServletException, IOException {\n' +
          '        // some code\n' +
          '        response.setContentType("text/html;charset=UTF-8");\n' +
          '\n' +
          '        String param = request.getParameter("BenchmarkTest00023");\n' +
          '        if (param == null) param = "";\n' +
          '\n' +
          '        float rand = new java.util.Random().nextFloat();\n' +
          '        String rememberMeKey = Float.toString(rand).substring(2); // Trim off the 0. at the front.\n' +
          '\n' +
          '        String user = "Floyd";\n' +
          '        String fullClassName = this.getClass().getName();\n' +
          '        String testCaseNumber =\n' +
          '                fullClassName.substring(\n' +
          '                        fullClassName.lastIndexOf(\'.\') + 1 + "BenchmarkTest".length());\n' +
          '        user += testCaseNumber;\n' +
          '\n' +
          '        String cookieName = "rememberMe" + testCaseNumber;\n' +
          '\n' +
          '        boolean foundUser = false;\n' +
          '        javax.servlet.http.Cookie[] cookies = request.getCookies();\n' +
          '        if (cookies != null) {\n' +
          '            for (int i = 0; !foundUser && i < cookies.length; i++) {\n' +
          '                javax.servlet.http.Cookie cookie = cookies[i];\n' +
          '                if (cookieName.equals(cookie.getName())) {\n' +
          '                    if (cookie.getValue().equals(request.getSession().getAttribute(cookieName))) {\n' +
          '                        foundUser = true;\n' +
          '                    }\n' +
          '                }\n' +
          '            }\n' +
          '        }\n' +
          '\n' +
          '        if (foundUser) {\n' +
          '            response.getWriter().println("Welcome back: " + user + "<br/>");\n' +
          '        } else {\n' +
          '            javax.servlet.http.Cookie rememberMe =\n' +
          '                    new javax.servlet.http.Cookie(cookieName, rememberMeKey);\n' +
          '            rememberMe.setSecure(true);\n' +
          '            rememberMe.setHttpOnly(true);\n' +
          '            rememberMe.setDomain(new java.net.URL(request.getRequestURL().toString()).getHost());\n' +
          '            rememberMe.setPath(request.getRequestURI()); // i.e., set path to JUST this servlet\n' +
          '            // e.g., /benchmark/sql-01/BenchmarkTest01001\n' +
          '            request.getSession().setAttribute(cookieName, rememberMeKey);\n' +
          '            response.addCookie(rememberMe);\n' +
          '            response.getWriter()\n' +
          '                    .println(\n' +
          '                            user\n' +
          '                                    + " has been remembered with cookie: "\n' +
          '                                    + rememberMe.getName()\n' +
          '                                    + " whose value is: "\n' +
          '                                    + rememberMe.getValue()\n' +
          '                                    + "<br/>");\n' +
          '        }\n' +
          '\n' +
          '        response.getWriter().println("Weak Randomness Test java.util.Random.nextFloat() executed");\n' +
          '    }\n' +
          '}\n',
      example3:'请解释一下这段代码的功能以及它是如何实现的：' +
          'private void setupSwiper() {\n' +
          '        SwipeLayout swipeLayout = buildSwipeLayout();\n' +
          '        if (swipeLayout == null) return;\n' +
          '\n' +
          '        TypedArray a = mActivity.getTheme().obtainStyledAttributes(new int[]{\n' +
          '                android.R.attr.windowBackground\n' +
          '        });\n' +
          '        int background = a.getResourceId(0, 0);\n' +
          '        a.recycle();\n' +
          '        // replace content view\n' +
          '        ViewGroup decor = (ViewGroup) mActivity.getWindow().getDecorView();\n' +
          '        decor.setBackgroundColor(ContextCompat.getColor(mContext, android.R.color.transparent));\n' +
          '        ViewGroup decorChild = (ViewGroup) decor.getChildAt(0);\n' +
          '        if (SwipeLayout.class.isInstance(decorChild)) {\n' +
          '            return;\n' +
          '        }\n' +
          '        decorChild.setBackgroundResource(background);\n' +
          '        decor.removeView(decorChild);\n' +
          '        swipeLayout.addView(decorChild);\n' +
          '        decor.addView(swipeLayout);\n' +
          '    }',
      example4 : '请将这个java函数用python实现：' +
          'private void setupSwiper() {\n' +
          '        SwipeLayout swipeLayout = buildSwipeLayout();\n' +
          '        if (swipeLayout == null) return;\n' +
          '\n' +
          '        TypedArray a = mActivity.getTheme().obtainStyledAttributes(new int[]{\n' +
          '                android.R.attr.windowBackground\n' +
          '        });\n' +
          '        int background = a.getResourceId(0, 0);\n' +
          '        a.recycle();\n' +
          '        // replace content view\n' +
          '        ViewGroup decor = (ViewGroup) mActivity.getWindow().getDecorView();\n' +
          '        decor.setBackgroundColor(ContextCompat.getColor(mContext, android.R.color.transparent));\n' +
          '        ViewGroup decorChild = (ViewGroup) decor.getChildAt(0);\n' +
          '        if (SwipeLayout.class.isInstance(decorChild)) {\n' +
          '            return;\n' +
          '        }\n' +
          '        decorChild.setBackgroundResource(background);\n' +
          '        decor.removeView(decorChild);\n' +
          '        swipeLayout.addView(decorChild);\n' +
          '        decor.addView(swipeLayout);\n' +
          '    }',
    };
  },

  methods: {
    initform(){
      this.language =''
      this.cwe =''
      this.task = ''
    },
    handleOpen(){

    },
    handleClose(){

    },
    // 左侧切换栏
    handleMenuClick(menuName) {
      console.log('点击了菜单:', menuName);
      this.menuName = menuName
      this.initform()
      this.task = menuName
      // 在这里可以执行其他逻辑操作
    },

    truncateFileName(fileName,n) {
      if (!fileName) return ""
      if (fileName.length > n) {
        return fileName.substring(0, n) + '...'
      } else {
        return fileName
      }
    },
    async exam1(){
      this.display = false;
      this.loading = true;
      this.input3 = this.example1

      await this.list.push({ align: "right", text: this.input3 });
      await this.scrollTop11();
      this.getMsg()
      this.input3 = ''
    },
    async exam2(){
      this.display = false;
      this.loading = true;
      this.input3 = this.example2

      await this.list.push({ align: "right", text: this.input3 });
      await this.scrollTop11();
      this.getMsg()
      this.input3 = ''
    },
    async exam3(){
      this.display = false;
      this.loading = true;
      this.input3 = this.example3

      await this.list.push({ align: "right", text: this.input3 });
      await this.scrollTop11();
      this.getMsg()
      this.input3 = ''
    },
    async exam4(){
      this.display = false;
      this.loading = true;
      this.input3 = this.example4

      await this.list.push({ align: "right", text: this.input3 });
      await this.scrollTop11();
      this.getMsg()
      this.input3 = ''
    },

    //发送
    async handleMsg() {
      console.log("发送信息:",this.input3 );
      if (this.input3 !== "") {
        this.display = false
        this.loading = true;
        await this.list.push({ align: "right", text: this.input3 });
        await this.scrollTop11();
        this.getMsg();
        this.input3 = ''
      }
    },
    // 发送信息获取数据
  /*  getMsg() {
      var that = this
      // 处理自己的接口请求 返回需要的数据
      $.ajax({
        url:  (http_head + '/Muti/'),
        data:{
          method:'deepseek_chat',
          prompt: that.input3,
        },
        type : 'post',
        dataType : 'JSON',
        async: 'true',
        success :  function (res){
          console.log(res);
          if (res.code == 200) {
            // 自行处理需要的数据
            // console.log(res.response)
            //↵替换成<br> （不是通过 ↵去替换，而是在html中会被识别为\r,\n等转义字符，所以需要使用\r\n去替换。）
            var msg = res.response.replace(/(\r\n|\n|\r)/gm, "<br>")
            // \s是指空白，包括空格、换行、tab缩进等所有的空白
            msg = msg.replace(/\s/gm,'&nbsp')
            //过滤掉最开头的回车<br和空格&nbsp
            msg = msg.replace(/^<br\s*\/?>/i, '')
            msg = msg.replace(/^(&nbsp)+/i, '');

            let listMsg = {
              align: "left",
              text: that.processText(msg),
              link: "",
            };
            console.log(listMsg)
            that.list.push(listMsg);
            that.scrollTop11();
          }
          that.loading = false;

        },
        error: function (err) {
          console.log(err)
          that.loading = false;
        }
      })

      // 模拟信息返回
      // setTimeout(async () => {
      //   let listMsg = {
      //     align: "left",
      //     text: "模拟信息返回",
      //     link: "",
      //   };
      //   await this.list.push(listMsg);
      //   await this.scrollTop11();
      //   this.loading = false;
      // }, 1000);
    },*/
    getMsg() {
      var that = this;
      // 创建一个新的 XMLHttpRequest 对象来处理流式请求
      var xhr = new XMLHttpRequest();

      xhr.open('POST', http_head + '/Muti/', true);
      xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded'); // 设置为表单提交的格式
      // 先添加一条空的消息到 that.list 中，用于后续更新
      let initialMsg = {
        align: "left",
        text: "", // 初始内容为空
        link: "",
      };
      that.list.push(initialMsg); // 先推入一条空消息
      var lastIndex = that.list.length - 1; // 获取当前插入消息的索引
      // 当有新数据到达时触发该回调
      var fullMessage = ''; // 用于存储完整的流式数据
      xhr.onprogress = function (event) {
        var chunk = event.target.responseText;
        // console.log(chunk)
        // 过滤掉前面的 "data: " 前缀并拼接流式数据
        fullMessage = chunk.replace(/data:\s*/g, '');
        //↵替换成<br> （不是通过 ↵去替换，而是在html中会被识别为\r,\n等转义字符，所以需要使用\r\n去替换。）
        // var msg = fullMessage.replace(/(\r\n|\n|\r)/gm, "<br>")
        // console.log(fullMessage)
        // \s是指空白，包括空格、换行、tab缩进等所有的空白
        var msg = fullMessage.replace(/\s/gm,'&nbsp')
        // console.log(msg)
        //过滤掉最开头的回车<br和空格&nbsp
        // msg = msg.replace(/^<br\s*\/?>/i, '')
        fullMessage = msg.replace(/&nbsp;/g, '');
        // 可以在这里输出拼接后的消息
        // console.log(fullMessage);

        // 实时更新消息列表，展示已经拼接的部分
        let listMsg = {
          align: "left",
          text: that.processText(fullMessage), // 处理后赋值给text
          link: "",
        };
        // that.list.push(listMsg);
        // 实时更新已经插入的消息，而不是每次都插入新的
        that.list[lastIndex].text = that.processText(fullMessage); // 更新文本
        that.$forceUpdate(); // 强制 Vue 重新渲染列表
        that.scrollTop11();
      };

      xhr.onerror = function (err) {
        console.log(err);
        that.loading = false;
      };

      xhr.onloadend = function () {
        that.loading = false;
      };

      // 将数据编码为表单格式并发送
      var formData = `method=deepseek_chat&prompt=${encodeURIComponent(that.input3)}`;
      xhr.send(formData); // 发送表单格式的数据
      that.loading = true;
    },


    processText(text) {
      // 替换其他 HTML 标签为转义字符，使其显示为纯文本
      let safeText = text.replace(/</g, "&lt;").replace(/>/g, "&gt;");
      // 将 <br> 转换回原始的 HTML 标签
      return safeText.replace(/&lt;br&gt;/g, "<br>");
    },
    // 处理滚动条一直保持最上方
    scrollTop11() {
      let div = document.getElementById("bigBox");
      div.scrollTop = div.scrollHeight;
    },
  }
});
