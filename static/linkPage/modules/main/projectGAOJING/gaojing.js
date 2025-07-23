
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
    this.getTableData();
    this.fetchWechatContacts();
    this.fetchemailContacts();
    this.fetcheContacts();
  },
  data() {
    return {
      config1:'',
      config2:'',
      query:{
        project_name:''
      },
      tableData: [],
      currentPage: 1, //当前页 刷新后默认显示第一页
      pageSize: 200, //每一页显示的数据量 此处每页显示6条数据
      count:10,
      multipleSelection: [],
      wechatDialogVisible: false, // 是否显示微信联系人弹窗
      emailDialogVisible: false, // 是否显示邮箱收件人弹窗
      contactDialogVisible: false, // 控制新建联系人弹窗显示
      contactType: 'wechat', // 联系人类型（微信或邮箱）
      wechatName: '', // 微信名
      webhookUrl: '', // 微信地址
      emailName: '', // 用户名
      receiverEmail: '', // 邮箱地址

      wechatContacts: [], // 微信联系人列表
      selectedWechatContacts: '', // 选中的微信联系人
      emailRecipients: [], // 邮箱收件人列表
      selectedEmailRecipients: '', // 选中的邮箱收件人
      DialogVisible: false,
      Recipients: [], // 邮箱收件人列表
      selectedRecipients: '',

      manualInputDialogVisible: false,
      manualInputForm: {
        summary: '',
        content: ''
      }

    }

  },
  methods: {
    openManualInputDialog() {
      this.manualInputDialogVisible = true;
    },
    // 确认手动录入
    confirmManualInput() {
      // 检查摘要和内容是否同时为空
      if (!this.manualInputForm.summary && !this.manualInputForm.content) {
        mymessage.error("请输入标题或者内容！");
        return; // 如果两者都为空，弹出提示并终止执行
      }
      // 如果录入了摘要或内容，弹出成功提示
      mymessage.success("录入成功！");
      this.manualInputDialogVisible = false; // 关闭弹窗
    },
    // 打开新建联系人弹窗
    openContactDialog() {
      this.contactDialogVisible = true;
      this.contactType = 'wechat'; // 默认选择微信
      this.wechatContact = ''; // 清空输入
      this.emailContact = ''; // 清空输入
    },
    // 保存联系人
    saveContact() {
      if (this.contactType === 'wechat') {
        if (!this.wechatName || !this.webhookUrl) {
          this.$message.warning("请输入微信名和微信地址！");
          return;
        }
        const newWechatContact = {
          wechat_name: this.wechatName,
          webhook_url: this.webhookUrl,
        };
        console.log("新建微信联系人：", newWechatContact);
        // 调用保存微信联系人接口
        this.saveWechatContact(newWechatContact);
      } else if (this.contactType === 'email') {
        if (!this.emailName || !this.receiverEmail) {
          this.$message.warning("请输入用户名和邮箱地址！");
          return;
        }
        const newEmailContact = {
          email_name: this.emailName,
          receiver_email: this.receiverEmail,
        };
        console.log("新建邮箱联系人：", newEmailContact);
        // 调用接口保存邮箱联系人
        this.saveEmailContact(newEmailContact);
      }

      // 清空输入框
      this.wechatName = '';
      this.webhookUrl = '';
      this.emailName = '';
      this.receiverEmail = '';

      this.contactDialogVisible = false; // 关闭弹窗
    },
    // 保存微信联系人
    saveWechatContact(contact) {
      const formData = new FormData();
      formData.append('method', 'add_wechat_info'); // 接口方法
      formData.append('wechat_name', contact.wechat_name); // 微信名
      formData.append('webhook_url', contact.webhook_url); // 微信地址
      // 发送 AJAX 请求
      $.ajax({
        url: (http_head + '/login/'),
        type: 'POST',
        data: formData,
        processData: false, // 禁止 jQuery 处理数据
        contentType: false, // 禁止 jQuery 设置 Content-Type
        success: (res) => {
          if (res && res['msg-code'] === '200') {
            this.$message.success("微信联系人保存成功！");
          } else {
            this.$message.error("微信联系人保存失败：" + (res.message || "未知错误"));
          }
          this.fetchWechatContacts();
        },
        error: (err) => {
          console.error("接口调用失败：", err);
        }
      });
    },

    // 保存邮箱联系人
    saveEmailContact(contact) {
      const formData = new FormData();
      formData.append('method', 'add_email_info'); // 接口方法
      formData.append('email_name', contact.email_name); // 用户名
      formData.append('receiver_email', contact.receiver_email); // 邮箱地址
      // 发送 AJAX 请求
      $.ajax({
        url: (http_head + '/login/'),
        type: 'POST',
        data: formData,
        processData: false, // 禁止 jQuery 处理数据
        contentType: false, // 禁止 jQuery 设置 Content-Type
        success: (res) => {
          if (res && res['msg-code'] === '200') {
            this.$message.success("邮箱联系人保存成功！");
          } else {
            this.$message.error("邮箱联系人保存失败：" + (res.message || "未知错误"));
          }
          this.fetchemailContacts();
        },
        error: (err) => {
          console.error("接口调用失败：", err);
        }
      });
    },

    // 获取微信联系人数据
    fetchWechatContacts() {
      const formData = new FormData();
      formData.append('method', 'get_wechat_info'); // 接口方法

      // 发送 AJAX 请求
      $.ajax({
        url: (http_head + '/login/'),
        type: 'POST',
        data: formData,
        processData: false, // 禁止 jQuery 处理数据
        contentType: false, // 禁止 jQuery 设置 Content-Type
        success: (res) => {
          console.log(res);
          if (res && res['msg-code'] === '200') {
            this.wechatContacts = res.data; // 将接口返回的数据赋值给 wechatContacts
          } else {
            console.error("获取微信联系人失败：", res.message || "未知错误");
          }
        },
        error: (err) => {
          console.error("接口调用失败：", err);
        }
      });
    },
    fetchemailContacts() {
      const formData = new FormData();
      formData.append('method', 'get_email_info'); // 接口方法

      // 发送 AJAX 请求
      $.ajax({
        url: (http_head + '/login/'),
        type: 'POST',
        data: formData,
        processData: false, // 禁止 jQuery 处理数据
        contentType: false, // 禁止 jQuery 设置 Content-Type
        success: (res) => {
          console.log(res);
          if (res && res['msg-code'] === '200') {
            this.emailRecipients = res.data; // 将接口返回的数据赋值给 wechatContacts
          } else {
            console.error("获取邮箱联系人失败：", res.message || "未知错误");
          }
        },
        error: (err) => {
          console.error("接口调用失败：", err);
        }
      });
    },
    fetcheContacts(){
      var that = this;
      $.ajax({
        url:  (http_head + '/login/'),
        data:{
          method: 'account_getall',
          teamId: localUser.teamId,
          username : '',
          account : '',
          page   :  that.currentPage,
          rows   :  that.pageSize,
        },
        type : 'post',
        dataType : 'JSON',
        success: (res) => {  // 使用箭头函数
          console.log(res);
          this.Recipients = res.data;  // 这里的 this 仍然指向 Vue 组件实例
          console.log(this.Recipients);
        },
        error: function (err) {
          console.log(err)
        }
      })
    },

    getTableData() {
      var that = this;
      $.ajax({
        url: (http_head + '/login/'),
        data: {
          method: 'item_list',
          itemid: '',
          itemname: '',
          description: '',
          language: '',
          source: '',
          createtime: '',
          page: that.currentPage,
          rows: that.pageSize,
        },
        type: 'post',
        dataType: 'JSON',
        success: function (res) {
          console.log(res);
          if (res && res.data) {
            // 将接口返回的数据映射到 tableData
            that.tableData = res.data.map(item => ({
              export_name: item.itemname, // 对应表格的 export_name 列
              itemname: item.language,    // 对应表格的 itemname 列
              fileType: item.createTime,  // 对应表格的 fileType 列
              high: item.high,
              med: item.med,
              low: item.low,
            }));
            that.count = res.count
          } else {
            that.tableData = []; // 如果返回数据为空，清空表格
          }
        },
        error: function (err) {
          console.log(err);
          mymessage.error("项目列表获取失败");
        }
      });
    },
    // 处理发送途径变化
    handleSendMethodChange(value) {
      if (value === 'value1') {
        this.wechatDialogVisible = true; // 显示微信联系人弹窗
      } else if (value === 'value2') {
        this.emailDialogVisible = true; // 显示邮箱收件人弹窗
      }else if (value === 'value3') {
        this.fetcheContacts();
        this.DialogVisible = true; // 显示邮箱收件人弹窗
      }
    },
    // 确认选择的微信联系人
    confirmWechatContacts() {
      if (!this.selectedWechatContacts || this.selectedWechatContacts.length === 0) {
        this.$message.error("请选择微信联系人！"); // 弹出错误提示
        return; // 如果未选择，直接返回
      }
      this.$message.success(`已选择微信联系人`);
      // this.$message.success(`已选择微信联系人：${this.selectedWechatContacts}`);
      console.log('当前选中：', this.selectedWechatContacts);
      this.wechatDialogVisible = false; // 关闭弹窗
    },
    // 确认选择的邮箱收件人
    confirmEmailRecipients() {
      if (!this.selectedEmailRecipients || this.selectedEmailRecipients.length === 0) {
        this.$message.error("请选择邮箱收件人！"); // 弹出错误提示
        return; // 如果未选择，直接返回
      }

      this.$message.success(`已选择邮箱收件人：${this.selectedEmailRecipients}`);
      console.log('当前选中：', this.selectedEmailRecipients);
      this.emailDialogVisible = false; // 关闭弹窗
    },
    confirmRecipients() {
      if (!this.selectedRecipients || this.selectedRecipients.length === 0) {
        this.$message.error("请选择站内用户！"); // 弹出错误提示
        return; // 如果未选择，直接返回
      }

      this.$message.success(`已选择用户`);
      console.log('当前选中：', this.selectedRecipients);
      this.DialogVisible = false; // 关闭弹窗
    },
    handleWechatCancel() {
      this.wechatDialogVisible = false; // 关闭微信弹窗
      this.selectedWechatContacts = ''; // 清空选中值
      this.config2 = ''; // 将 config2 重置为空
    },
    // 处理邮箱弹窗的取消操作
    handleEmailCancel() {
      this.emailDialogVisible = false; // 关闭邮箱弹窗
      this.selectedEmailRecipients = '';
      this.config2 = ''; // 将 config2 重置为空
    },
    handleCancel() {
      this.DialogVisible = false; // 关闭邮箱弹窗
      this.selectedRecipients = '';
      this.config2 = ''; // 将 config2 重置为空
    },

    handleSelectionChange(selection) {
      console.log('当前发送内容选中的行：', selection);
    },


    send() {
      // 判断是否选择了发送途径
      if (!this.config2) {
        mymessage.error("发送途径未选择！");
        return; // 如果未选择发送途径，直接返回
      }

      const selectedRows = this.$refs.multipleTable.selection;
      // 判断是否录入了标题摘要或选择了告警内容
      if (!this.manualInputForm.summary && selectedRows.length === 0 && !this.manualInputForm.content ) {
        mymessage.error("请输入或者选择告警内容！");
        return; // 如果两者都为空，弹出提示并终止执行
      }

      // 根据发送途径执行不同逻辑
      if (this.config2 === 'value1') {
        console.log("发送途径：", this.config2);
        console.log("发送联系人：", this.selectedWechatContacts);
        console.log("发送内容：", selectedRows);
        const webhook_url = this.selectedWechatContacts;
        // const webhook_url = this.selectedWechatContacts.join(';');
        console.log("webhook_url：", webhook_url);
        // 拼接手动录入的信息和选择的告警内容
        let message = '';
        // 如果有录入标题摘要，添加到 message
        if (this.manualInputForm.summary || this.manualInputForm.content) {
          message += `${this.manualInputForm.summary}\n${this.manualInputForm.content}\n\n`;
        }
        // 如果有选择告警内容，添加到 message
        if (selectedRows.length > 0) {
          const tableContent = selectedRows.map(row => {
            return `项目名称：${row.export_name}\n扫描语言：${row.itemname}\n创建时间：${row.fileType}\n高危数量：${row.high}\n中危数量：${row.med}\n低危数量：${row.low}`;
          }).join('\n\n');
          message += tableContent;
        }
        console.log("发送内容：", message);

        // 构造 form-data 数据
        const formData = new FormData();
        formData.append('method', 'send_wechat_work_message'); // 接口方法
        formData.append('webhook_url', webhook_url); // Webhook URL
        formData.append('message', message); // 消息内容
        // 发送 AJAX 请求
        $.ajax({
          url: (http_head + '/login/'),
          type: 'POST',
          data: formData,
          processData: false, // 禁止 jQuery 处理数据
          contentType: false, // 禁止 jQuery 设置 Content-Type
          success: function (res) {
            console.log("接口调用成功：", res);
            if (res && res['msg-code'] === '200') {
              mymessage.success("发送成功！");
            } else {
              mymessage.error("发送失败：" + (res.message || "未知错误"));
            }
          },
          error: function (err) {
            console.error("接口调用失败：", err);
          }
        });

      } else if(this.config2 === 'value2') {
        console.log("发送途径：", this.config2);
        console.log("发送联系人：", this.selectedEmailRecipients);
        console.log("发送内容：", selectedRows);
        const receiver_email = this.selectedEmailRecipients;
        // const receiver_email = this.selectedEmailRecipients.join(';');
        console.log("receiver_email：", receiver_email);
        let message = '';
        // 如果有录入标题摘要，添加到 message
        if (this.manualInputForm.summary || this.manualInputForm.content) {
          message += `${this.manualInputForm.summary}\n${this.manualInputForm.content}\n\n`;
        }
        // 如果有选择告警内容，添加到 message
        if (selectedRows.length > 0) {
          const tableContent = selectedRows.map(row => {
            return `项目名称：${row.export_name}\n扫描语言：${row.itemname}\n创建时间：${row.fileType}\n高危数量：${row.high}\n中危数量：${row.med}\n低危数量：${row.low}`;
          }).join('\n\n');
          message += tableContent;
        }
        console.log("发送内容：", message);
        // 构造 form-data 数据
        const formData1 = new FormData();
        formData1.append('method', 'send_email'); // 接口方法
        formData1.append('receiver_email', receiver_email); // Webhook URL
        formData1.append('message', message); // 消息内容
        // 发送 AJAX 请求
        $.ajax({
          url: (http_head + '/login/'),
          type: 'POST',
          data: formData1,
          processData: false, // 禁止 jQuery 处理数据
          contentType: false, // 禁止 jQuery 设置 Content-Type
          success: function (res) {
            console.log("接口调用成功：", res);
            mymessage.success("发送邮箱");
            if (res && res['msg-code'] === '200') {
              mymessage.success("发送成功！");
            } else {
              console.log("接口调用成功：", res);
            }
          },
          error: function (err) {
            console.error("接口调用失败：", err);
          }
        });

      }else if(this.config2 === 'value3') {
        console.log("发送途径：", this.config2);
        console.log("发送联系人：", this.selectedRecipients);
        console.log("发送内容：", selectedRows);
        const receiver = this.selectedRecipients;
        // const receiver_email = this.selectedEmailRecipients.join(';');
        console.log("receiver：", receiver);
        let message = '';
        // 如果有录入标题摘要，添加到 message
        if (this.manualInputForm.summary || this.manualInputForm.content) {
          message += `${this.manualInputForm.summary}\n${this.manualInputForm.content}\n\n`;
        }
        // 如果有选择告警内容，添加到 message
        if (selectedRows.length > 0) {
          const tableContent = selectedRows.map(row => {
            return `项目名称：${row.export_name}\n扫描语言：${row.itemname}\n创建时间：${row.fileType}\n高危数量：${row.high}\n中危数量：${row.med}\n低危数量：${row.low}`;
          }).join('\n\n');
          message += tableContent;
        }
        console.log("发送内容：", message);
        // 构造 form-data 数据
        const formData1 = new FormData();
        formData1.append('method', 'send_station_mail'); // 接口方法
        formData1.append('sender', this.selectedRecipients); // Webhook URL
        formData1.append('message', message); // 消息内容
        // 发送 AJAX 请求
        $.ajax({
          url: (http_head + '/login/'),
          type: 'POST',
          data: formData1,
          processData: false, // 禁止 jQuery 处理数据
          contentType: false, // 禁止 jQuery 设置 Content-Type
          success: function (res) {
            console.log("接口调用成功：", res);
            mymessage.success("发送邮箱");
            if (res && res['msg-code'] === '200') {
              mymessage.success("发送成功！");
            } else {
              console.log("接口调用成功：", res);
            }
          },
          error: function (err) {
            console.error("接口调用失败：", err);
          }
        });

      }

    },
    // 重置
    reset(){
      this.config2 = ''
      this.$refs.multipleTable.clearSelection();
      this.selectedEmailRecipients = '';
      this.selectedWechatContacts = '';
      this.selectedRecipients = '';

      // 清空输入框
      this.wechatName = '';
      this.webhookUrl = '';
      this.emailName = '';
      this.receiverEmail = '';

      this.manualInputForm.summary= '';
      this.manualInputForm.content= '';
    },

  }

})