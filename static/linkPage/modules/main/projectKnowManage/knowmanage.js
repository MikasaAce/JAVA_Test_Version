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
    this.fetchKnowledgeBases();
  },

  data() {
    return {
      loading: false,
        dialogVisible: false,
        saving: false,
        dialogTitle: '编辑权限',
        knowledgeBases: [],
        currentKnowledgeBase: {
          kb_id: '',
          kb_name: '',
          visible_users: []
        },
      permissionOptions: ['管理员', '普通用户']
    }
  },
  methods: {
    // 获取知识库列表
    async fetchKnowledgeBases() {
      this.loading = true;
      try {
        const formData = new FormData();
        formData.append('method', 'get_all_knowledge_bases');

        const response = await fetch('http://10.99.16.24:8088/login/', {
          method: 'POST',
          body: formData
        });

        const result = await response.json();

        if (result.code === "200") {
          this.knowledgeBases = result.data;
        } else {
          throw new Error(result.msg || '获取知识库列表失败');
        }
      } catch (error) {
        this.$message.error(error.message);
      } finally {
        this.loading = false;
      }
    },

    // 显示编辑弹窗
    showEditDialog(row) {
      this.currentKnowledgeBase = {
        kb_id: row.kb_id,
        kb_name: row.kb_name,
        visible_users: [...row.visible_users]
      };
      this.dialogVisible = true;
    },

    // 保存权限设置
    async savePermission() {
      this.saving = true;
      try {
        const formData = new FormData();
        formData.append('method', 'update_kb_visibility');
        formData.append('kb_id', this.currentKnowledgeBase.kb_id);
        formData.append('visible_to_usernames', JSON.stringify(this.currentKnowledgeBase.visible_users));

        const response = await fetch('http://10.99.16.24:8088/login/', {
          method: 'POST',
          body: formData
        });

        const result = await response.json();

        if (result.code === "200") {
          this.$message.success(result.msg);
          this.dialogVisible = false;
          await this.fetchKnowledgeBases(); // 刷新列表
        } else {
          throw new Error(result.msg || '更新权限失败');
        }
      } catch (error) {
        this.$message.error(error.message);
      } finally {
        this.saving = false;
      }
    },

    // 重置表单
    resetForm() {
      this.currentKnowledgeBase = {
        kb_id: '',
        kb_name: '',
        visible_users: []
      };
    },

    // 获取权限标签样式
    getPermissionTagType(user) {
      return user === '管理员' ? 'success' : 'primary';
    }

  },

});

