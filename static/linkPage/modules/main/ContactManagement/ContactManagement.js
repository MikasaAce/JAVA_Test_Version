
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

    this.fetchWechatContacts();

  },
  data() {
    return {
      config1:'',
      config2:'',

      contactType: 'wechat', // 当前选择的联系人类型
      contacts: [],          // 联系人列表

      // 新增联系人弹窗相关数据
      contactDialogVisible: false,
      newContactType: 'wechat',
      newWechatName: '',
      newWebhookUrl: '',
      newEmailName: '',
      newReceiverEmail: '',
      // 编辑联系人相关数据
      editDialogVisible: false,
      currentContact: null
    }

  },
  methods: {

    // 获取联系人数据
    fetchContacts() {
      if (this.contactType === 'wechat') {
        this.fetchWechatContacts();
      } else {
        this.fetchEmailContacts();
      }
    },

    // 获取微信联系人
    fetchWechatContacts() {
      const formData = new FormData();
      formData.append('method', 'get_wechat_info');

      $.ajax({
        url: (http_head + '/login/'),
        type: 'POST',
        data: formData,
        processData: false,
        contentType: false,
        context: this,
        success: function(res) {
          if (res && res['msg-code'] === '200') {
            this.contacts = res.data.map(item => ({
              id: item.wechat_id,
              name: item.wechat_name,
              address: item.webhook_url,
              type: 'wechat'  // 添加类型标识
            }));
          } else {
            // mymessage.error("获取微信联系人失败");
            this.contacts = [];
          }
        },
        error: function(err) {
          console.error("接口调用失败：", err);
          // mymessage.error("获取微信联系人失败");
          this.contacts = [];
        }
      });
    },

    // 获取邮箱联系人
    fetchEmailContacts() {
      const formData = new FormData();
      formData.append('method', 'get_email_info');

      $.ajax({
        url: (http_head + '/login/'),
        type: 'POST',
        data: formData,
        processData: false,
        contentType: false,
        context: this,
        success: function(res) {
          if (res && res['msg-code'] === '200') {
            this.contacts = res.data.map(item => ({
              id: item.email_id,
              name: item.email_name,
              address: item.receiver_email,
              type: 'email'  // 添加类型标识
            }));
          } else {
            mymessage.error("获取邮箱联系人失败");
            this.contacts = [];
          }
        },
        error: function(err) {
          console.error("接口调用失败：", err);
          mymessage.error("获取邮箱联系人失败");
          this.contacts = [];
        }
      });
    },

    // 打开新增联系人弹窗
    openContactDialog() {
      this.contactDialogVisible = true;
      this.newContactType = this.contactType;
      this.clearForm();
    },

    // 清空表单
    clearForm() {
      this.newWechatName = '';
      this.newWebhookUrl = '';
      this.newEmailName = '';
      this.newReceiverEmail = '';
    },

    // 保存联系人
    saveContact() {
      if (this.newContactType === 'wechat') {
        this.saveWechatContact();
      } else {
        this.saveEmailContact();
      }
    },

    // 保存微信联系人
    saveWechatContact() {
      if (!this.newWechatName || !this.newWebhookUrl) {
        this.$message.warning('请填写群名称和Webhook地址');
        return;
      }

      const formData = new FormData();
      formData.append('method', 'add_wechat_info');
      formData.append('wechat_name', this.newWechatName);
      formData.append('webhook_url', this.newWebhookUrl);

      $.ajax({
        url: (http_head + '/login/'),
        type: 'POST',
        data: formData,
        processData: false,
        contentType: false,
        context: this,
        success: function(res) {
          if (res && res['msg-code'] === '200') {
            this.$message.success('企业微信联系人添加成功');
            this.fetchWechatContacts();
            this.contactDialogVisible = false;
          } else {
            this.$message.error('添加失败: ' + (res.message || '未知错误'));
          }
        },
        error: function(err) {
          console.error("接口调用失败：", err);
          this.$message.error('添加失败');
        }
      });
    },

    // 保存邮箱联系人
    saveEmailContact() {
      if (!this.newEmailName || !this.newReceiverEmail) {
        this.$message.warning('请填写联系人名称和邮箱地址');
        return;
      }

      const formData = new FormData();
      formData.append('method', 'add_email_info');
      formData.append('email_name', this.newEmailName);
      formData.append('receiver_email', this.newReceiverEmail);

      $.ajax({
        url: (http_head + '/login/'),
        type: 'POST',
        data: formData,
        processData: false,
        contentType: false,
        context: this,
        success: function(res) {
          if (res && res['msg-code'] === '200') {
            this.$message.success('邮箱联系人添加成功');
            this.fetchEmailContacts();
            this.contactDialogVisible = false;
          } else {
            this.$message.error('添加失败: ' + (res.message || '未知错误'));
          }
        },
        error: function(err) {
          console.error("接口调用失败：", err);
          this.$message.error('添加失败');
        }
      });
    },

    // 打开编辑联系人弹窗
    openEditDialog(contact) {
      // 深拷贝联系人对象，避免直接修改原数据
      this.currentContact = JSON.parse(JSON.stringify(contact));
      this.editDialogVisible = true;
    },

    // 更新联系人信息
    updateContact() {
      if (this.currentContact.type === 'wechat') {
        this.updateWechatContact();
      } else {
        this.updateEmailContact();
      }
    },

    // 更新微信联系人
    updateWechatContact() {

      if (!this.currentContact.name || !this.currentContact.address) {
        this.$message.warning('请填写群名称和Webhook地址');
        return;
      }

      const formData = new FormData();
      formData.append('method', 'update_wechat_info');
      // formData.append('wechat_id', this.currentContact.id);
      formData.append('wechat_id', this.currentContact.id);  // 使用wechat_id
      formData.append('wechat_name', this.currentContact.name);
      formData.append('webhook_url', this.currentContact.address);

      $.ajax({
        url: (http_head + '/login/'),
        type: 'POST',
        data: formData,
        processData: false,
        contentType: false,
        context: this,
        success: function(res) {
          if (res && res['msg-code'] === '200') {
            this.$message.success('企业微信联系人更新成功');
            this.editDialogVisible = false;
            this.fetchWechatContacts();
          } else {
            this.$message.error('更新失败: ' + (res.message || '未知错误'));
          }
        },
        error: function(err) {
          console.error("接口调用失败：", err);
          this.$message.error('更新失败');
        }
      });
    },

    // 更新邮箱联系人
    updateEmailContact() {
      if (!this.currentContact.name || !this.currentContact.address) {
        this.$message.warning('请填写联系人名称和邮箱地址');
        return;
      }

      const formData = new FormData();
      formData.append('method', 'update_email_info');
      formData.append('email_id', this.currentContact.id);
      formData.append('email_name', this.currentContact.name);
      formData.append('receiver_email', this.currentContact.address);

      $.ajax({
        url: (http_head + '/login/'),
        type: 'POST',
        data: formData,
        processData: false,
        contentType: false,
        context: this,
        success: function(res) {
          if (res && res['msg-code'] === '200') {
            this.$message.success('邮箱联系人更新成功');
            this.editDialogVisible = false;
            this.fetchEmailContacts();
          } else {
            this.$message.error('更新失败: ' + (res.message || '未知错误'));
          }
        },
        error: function(err) {
          console.error("接口调用失败：", err);
          this.$message.error('更新失败');
        }
      });
    },

    // 删除联系人
    handleDelete(contact) {
      this.$confirm('此操作将删除该联系人, 是否继续?', '提示', {
        confirmButtonText: '确定',
        cancelButtonText: '取消',
        type: 'warning',
        beforeClose: (action, instance, done) => {
          if (action === 'confirm') {
            instance.confirmButtonLoading = true;
            const deletePromise = contact.type === 'wechat'
              ? this.deleteWechatContact(contact)
              : this.deleteEmailContact(contact);

            deletePromise
              .then(() => {
                done();
                this.$message({
                  type: 'success',
                  message: '删除成功'
                });
                this.fetchContacts();
              })
              .catch(() => {
                done();
                this.$message({
                  type: 'error',
                  message: '删除失败'
                });
              })
              .finally(() => {
                instance.confirmButtonLoading = false;
              });
          } else {
            done();
          }
        }
      }).catch(() => {
        this.$message({
          type: 'info',
          message: '已取消删除'
        });
      });
    },

    // 删除微信联系人
    deleteWechatContact(contact) {
      return new Promise((resolve, reject) => {
        const formData = new FormData();
        formData.append('method', 'delete_wechat_info');
        formData.append('wechat_id', contact.id);

        $.ajax({
          url: (http_head + '/login/'),
          type: 'POST',
          data: formData,
          processData: false,
          contentType: false,
          context: this,
          success: function(res) {
            if (res && res['msg-code'] === '200') {
              resolve();
            } else {
              reject();
            }
          },
          error: function(err) {
            console.error("接口调用失败：", err);
            reject();
          }
        });
      });
    },

    // 删除邮箱联系人
    deleteEmailContact(contact) {
      return new Promise((resolve, reject) => {
        const formData = new FormData();
        formData.append('method', 'delete_email_info');
        formData.append('email_id', contact.id);

        $.ajax({
          url: (http_head + '/login/'),
          type: 'POST',
          data: formData,
          processData: false,
          contentType: false,
          context: this,
          success: function(res) {
            if (res && res['msg-code'] === '200') {
              resolve();
            } else {
              reject();
            }
          },
          error: function(err) {
            console.error("接口调用失败：", err);
            reject();
          }
        });
      });
    },
  }
});