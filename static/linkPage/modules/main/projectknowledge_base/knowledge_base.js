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
    // 先加载本地存储的对话历史
    this.loadChatFromsessionStorage();
    this.fetchKnowledgeBases();
  },

  data() {
    return {
      activeMode: 'chat', // 'chat' 或 'knowledge'

      // 对话模式数据
      selectedKnowledgeBase: '',
      inputQuestion: '',
      chatMessages: [],
      isLoading: false,

      // 知识库管理数据
      selectedKnowledgeBaseForManage: '',
      newKnowledgeBase: {
        name: '',
        description: '',
        is_public: true // 新增公开选项，默认true
      },
      currentKnowledgeBase: {
        id: '',
        name: '',
        description: '',
        files: []
      },
      selectedFiles: [],
      uploadURL: 'http://10.99.16.24:8088/medical/',
      uploadData: { // 上传附加数据
        method: 'upload_file'
      },
      addToKBURL: 'http://10.99.16.24:57861/knowledge_base/upload_docs', // 添加到知识库接口
      isAddingToKB: false, // 添加到知识库的加载状态
      uploadFileList: [], // 上传文件列表
      uploadedFiles: [], // 存储已上传成功的文件
      isAddingFiles: false, // 添加文件到知识库的状态
      isUploading: false, // 上传状态
      fileLinks: {}, // 存储文件链接

      // 模拟知识库数据
      knowledgeBases: [],
    }
  },
  methods: {
    // 切换模式
    switchMode(mode) {
      this.activeMode = mode;
      if (mode === 'chat') {
        this.selectedKnowledgeBaseForManage = '';
      } else {
        this.selectedKnowledgeBase = '';
      }
    },

    // 发送问题
    sendQuestion() {
      if (!this.inputQuestion.trim()) {
        this.$message.warning('请输入问题');
        return;
      }

      if (!this.selectedKnowledgeBase) {
        this.$message.warning('请先选择知识库');
        return;
      }

      this.isLoading = true;
      const question = this.inputQuestion;
      const knowledgeBaseName = this.selectedKnowledgeBase;
      // const knowledgeBaseName = this.getKnowledgeBaseName(this.selectedKnowledgeBase);
      console.log("********选择知识库名称：", knowledgeBaseName);
      this.chatMessages.push({
        question: question,
        answer: '思考中...',
        docs: []
      });

      this.inputQuestion = '';

      const requestData = {
        query: question,
        mode: "local_kb",
        kb_name: knowledgeBaseName,
        top_k: 3,
        score_threshold: 0.6,
        history:[],
        stream: false,
        model: "deepseek-r1",
        temperature: 0.4,
        max_tokens: 0,
        prompt_name: "default",
        return_direct: false
      };

      fetch('http://10.99.16.24:57861/chat/kb_chat', {
        method: 'POST',
        headers: {
          'accept': 'application/json',
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(requestData)
      })
        .then(response => {
          if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
          }
          return response.json(); // 直接解析为JSON，因为返回的是JSON字符串
        })
        .then(data => {
          // 处理返回的JSON字符串
          let responseData;
          try {
            responseData = typeof data === 'string' ? JSON.parse(data) : data;
          } catch (e) {
            throw new Error('解析响应数据失败');
          }

          if (!responseData.choices || !responseData.choices[0].message.content) {
            throw new Error('返回数据格式不正确');
          }

          const lastIndex = this.chatMessages.length - 1;
          const answerContent = responseData.choices[0].message.content;

          // 清理回答内容中的标记
          const cleanedAnswer = answerContent
            .replace(/<\/?think>/g, '') // 去除<think>标签
            .replace(/\n{3,}/g, '\n\n'); // 减少多余空行

          this.chatMessages[lastIndex] = {
            question: question,
            answer: cleanedAnswer,
            docs: [] // 根据实际返回数据调整，如果有参考文献的话
          };
        })
        .catch(error => {
          console.error('API调用失败:', error);
          const lastIndex = this.chatMessages.length - 1;
          this.chatMessages[lastIndex].answer = `回答失败`;
          this.$message.error(`获取回答失败`);
        })
        .finally(() => {
          this.isLoading = false;
          this.$nextTick(() => {
            this.$refs.messagesContainer.scrollTop = this.$refs.messagesContainer.scrollHeight;
          });
          // 保存对话到本地存储
          this.saveChatTosessionStorage();
        });
    },

    formatAnswer(answer) {
      // 将换行符转换为HTML换行标签
      return answer.replace(/\n/g, '<br>');
    },


    // 清空对话
    clearChat() {
      this.chatMessages = [];
      this.saveChatTosessionStorage();
    },

    // 知识库选择变化
    onKnowledgeBaseChange() {
      this.$message.success(`已切换到知识库: ${this.selectedKnowledgeBase}`);
    },

    // 知识库管理选择变化
    async onKnowledgeBaseForManageChange(value) {
      if (value === 'new') {
        // 新建知识库模式
        this.currentKnowledgeBase = {
          id: '',
          name: '',
          description: '',
          files: []
        };
        return;
      }

      if (value) {
        try {
          // 查找选中的知识库
          const selectedKb = this.knowledgeBases.find(item => item.name === value);
          if (!selectedKb) {
            this.$message.warning('未找到选中的知识库');
            return;
          }

          // 更新当前知识库信息
          this.currentKnowledgeBase = {
            ...JSON.parse(JSON.stringify(selectedKb)),
            files: [] // 先清空文件列表，等待加载
          };

          // 显示加载状态
          this.isLoading = true;

          // 获取该知识库的文件列表
          const files = await this.fetchKnowledgeBaseFiles(value);
          this.currentKnowledgeBase.files = files;

          this.$message.success(`已切换到知识库: ${value}`);
        } catch (error) {
          console.error('切换知识库失败:', error);
          this.$message.error(`切换知识库失败: ${error.message}`);
        } finally {
          this.isLoading = false;
        }
      }
    },


    // 获取知识库名称
    getKnowledgeBaseName(id) {
      const kb = this.knowledgeBases.find(item => item.id === id);
      return kb ? kb.name : '';
    },



    handlePreview(file) {
      console.log(file);
    },
    beforeRemove(file, fileList) {
      return this.$confirm(`确定移除 ${file.name}？`);
    },
// 上传成功处理
    uploadSuccess(response, file, fileList) {
      this.uploadedFiles.push({
        name: file.name,
        raw: file.raw // 保存原始文件对象
      });
      this.$message.success(`${file.name} 上传成功`);
    },

    // 文件移除处理
    handleRemove(file, fileList) {
      this.uploadedFiles = this.uploadedFiles.filter(f => f.name !== file.name);
    },

    // 添加文件到知识库
    async addFilesToKnowledgeBase() {
      if (!this.currentKnowledgeBase.name) {
        this.$message.warning('请先选择知识库');
        return;
      }

      if (this.uploadedFiles.length === 0) {
        this.$message.warning('请先上传文件');
        return;
      }

      try {
        this.isAddingToKB = true;

        const formData = new FormData();
        formData.append('knowledge_base_name', this.currentKnowledgeBase.name);
        formData.append('to_vector_store', 'true');
        formData.append('override', 'false');
        formData.append('not_refresh_vs_cache', 'false');
        formData.append('chunk_size', '750');
        formData.append('chunk_overlap', '150');
        formData.append('zh_title_enhance', 'false');
        formData.append('docs', '');

        // 添加所有已上传的文件
        this.uploadedFiles.forEach(file => {
          formData.append('files', file.raw, file.name);
        });

        const response = await fetch(this.addToKBURL, {
          method: 'POST',
          body: formData
          // headers会自动设置为multipart/form-data
        });

        const result = await response.json();

        if (result.code === 200) {
          // 处理可能的失败文件
          if (result.data && result.data.failed_files) {
            const failedFiles = Object.keys(result.data.failed_files);
            if (failedFiles.length > 0) {
              const errorMsg = failedFiles.map(name =>
                `${name}: ${result.data.failed_files[name]}`
              ).join('; ');

              this.$message.error(`部分文件添加失败: ${errorMsg}`);

              // 从已上传列表中移除失败的文件
              this.uploadedFiles = this.uploadedFiles.filter(
                f => !failedFiles.includes(f.name)
              );
            }
          }

          // 显示成功信息
          if (!result.data.failed_files ||
            Object.keys(result.data.failed_files).length < this.uploadedFiles.length) {
            this.$message.success('文件已成功添加到知识库');
            // 清空已上传文件列表
            this.uploadedFiles = [];
            this.uploadFileList = [];
          }

          // 刷新知识库文件列表
          this.currentKnowledgeBase.files = await this.fetchKnowledgeBaseFiles(this.currentKnowledgeBase.name);
        } else {
          throw new Error(result.msg || '添加文件到知识库失败');
        }
      } catch (error) {
        console.error('添加文件到知识库失败:', error);
        this.$message.error(`添加文件到知识库失败: ${error.message}`);
      } finally {
        this.isAddingToKB = false;
      }
    },

    // 创建知识库
    async createKnowledgeBase() {
      if (!this.newKnowledgeBase.name.trim()) {
        this.$message.warning('请输入知识库名称');
        return;
      }

      try {
        // 第一步：在第一个系统中创建知识库
        const formData = new FormData();
        formData.append('method', 'save_knowledge_bases');
        formData.append('user_id', localUser.accountId); // 从本地存储获取
        formData.append('is_public', this.newKnowledgeBase.is_public);
        formData.append('kb_name', this.newKnowledgeBase.name);

        const response = await fetch('http://10.99.16.24:8088/login/', {
          method: 'POST',
          body: formData
        });

        const result = await response.json();

        if (result.code === "200") {
          // this.$message.success('知识库创建成功');

          // 第二步：在第二个系统中创建知识库
          try {
            const syncResponse = await fetch(
              'http://10.99.16.24:57861/knowledge_base/create_knowledge_base',
              {
                method: 'POST',
                headers: {
                  'accept': 'application/json',
                  'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                  knowledge_base_name: this.newKnowledgeBase.name,
                  vector_store_type: "faiss",
                  kb_info: this.newKnowledgeBase.description || "",
                  embed_model: "bge-large-zh-v1.5"
                })
              }
            );

            const syncResult = await syncResponse.json();

            if (syncResult.code === 200) {
              this.$message.success(`知识库创建成功: ${syncResult.msg}`);
            } else {
              throw new Error(syncResult.msg || '知识库创建失败');
            }
          } catch (syncError) {
            console.error('同步到langchain系统失败:', syncError);
            // this.$message.warning(`主知识库创建成功，但同步到第二个系统失败: ${syncError.message}`);
          }

          // 创建成功后添加到本地列表
          const newKb = {
            id: localUser.accountId, // 临时ID，实际应从接口返回
            name: this.newKnowledgeBase.name,
            description: this.newKnowledgeBase.description,
            is_public: this.newKnowledgeBase.is_public,
            files: []
          };

          this.knowledgeBases.push(newKb);
          this.selectedKnowledgeBaseForManage = newKb.name;
          this.currentKnowledgeBase = JSON.parse(JSON.stringify(newKb));
          this.newKnowledgeBase = { name: '', description: '', is_public: true };

          // 刷新知识库列表
          await this.fetchKnowledgeBases();
        } else {
          throw new Error(result.msg || '创建知识库失败');
        }
      } catch (error) {
        console.error('创建知识库失败:', error);
        this.$message.error(`创建知识库失败: ${error.message}`);
      }
    },

    // 获取知识库列表
    async fetchKnowledgeBases() {
      try {
        this.isLoading = true;
        const formData = new FormData();
        formData.append('method', 'get_knowledge_bases');
        formData.append('user_id', localUser.accountId); // 从localStorage获取

        const response = await fetch('http://10.99.16.24:8088/login/', {
          method: 'POST',
          body: formData
        });

        const result = await response.json();

        if (result.code === "200") {
          // 将接口返回的数据转换为前端需要的格式
          this.knowledgeBases = result.data.map(kb => ({
            id: kb.kb_name, // 使用kb_name作为ID
            name: kb.kb_name,
            description: kb.description || '暂无描述', // 如果接口没有返回description，设置默认值
            is_public: kb.is_public || false, // 如果接口没有返回is_public，默认false
            files: kb.files || [] // 如果接口没有返回files，默认空数组
          }));

          // 初始化选择第一个知识库
          if (this.knowledgeBases.length > 0) {
            this.selectedKnowledgeBase = this.knowledgeBases[0].id;
          }
        } else {
          throw new Error(result.msg || '获取知识库列表失败');
        }
      } catch (error) {
        console.error('获取知识库列表失败:', error);
        this.$message.error(`获取知识库数据失败`);
      } finally {
        this.isLoading = false;
      }
    },
    // 获取知识库文件列表
    async fetchKnowledgeBaseFiles(kbName) {
      try {
        this.isLoading = true;
        const response = await fetch(
          `http://10.99.16.24:57861/knowledge_base/list_files?knowledge_base_name=${encodeURIComponent(kbName)}`,
          {
            method: 'GET',
            headers: {
              'accept': 'application/json'
            }
          }
        );

        const result = await response.json();

        if (result.code === 200) {
          // 转换接口数据为前端需要的格式
          return result.data.map(file => ({
            id: file.No, // 使用序号作为唯一ID
            name: file.file_name,
            type: file.file_ext,
            size: file.file_size || 0,
            uploadTime: file.create_time ?
              file.create_time.replace('T', '  -  ').replace(/\.\d+Z$/, '') : '未知时间',
            rawData: file // 保留原始数据
          }));
        } else {
          throw new Error(result.msg || '获取文件列表失败');
        }
      } catch (error) {
        console.error('获取文件列表失败:', error);
        // this.$message.error(`获取文件列表失败: ${error.message}`);
        return [];
      } finally {
        this.isLoading = false;
      }
    },

    // 删除文件（增强版，带加载状态）
    async deleteFile(file) {
      try {
        // 设置删除状态
        this.$set(file, 'deleting', true);

        await this.$confirm(`确定要删除文件 "${file.name}" 吗?`, '提示', {
          confirmButtonText: '确定',
          cancelButtonText: '取消',
          type: 'warning'
        });

        const requestData = {
          knowledge_base_name: this.currentKnowledgeBase.name,
          file_names: [file.name],
          delete_content: true,
          not_refresh_vs_cache: true
        };

        const response = await fetch(
          'http://10.99.16.24:57861/knowledge_base/delete_docs',
          {
            method: 'POST',
            headers: {
              'accept': 'application/json',
              'Content-Type': 'application/json'
            },
            body: JSON.stringify(requestData)
          }
        );

        const result = await response.json();

        if (result.code === 200) {
          this.$message.success(result.msg || '文件删除成功');

          // 使用Vue.set确保响应式更新
          const index = this.currentKnowledgeBase.files.findIndex(f => f.name === file.name);
          if (index !== -1) {
            this.currentKnowledgeBase.files.splice(index, 1);
          }
        } else {
          throw new Error(result.msg || '删除文件失败');
        }
      } catch (error) {
        if (error !== 'cancel') {
          console.error('删除文件失败:', error);
          this.$message.error(`删除文件失败: ${error.message}`);
        }
      } finally {
        // 清除删除状态
        if (file.deleting !== undefined) {
          this.$set(file, 'deleting', false);
        }
      }
    },

    // 格式化文件大小
    formatFileSize(bytes) {
      if (!bytes || bytes === 0) return '0 Bytes';
      const k = 1024;
      const sizes = ['Bytes', 'KB', 'MB', 'GB'];
      const i = Math.floor(Math.log(bytes) / Math.log(k));
      return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    },
    // 保存对话到本地存储
    saveChatTosessionStorage() {
      sessionStorage.setItem('chatHistory', JSON.stringify({
        messages: this.chatMessages,
        selectedKnowledgeBase: this.selectedKnowledgeBase
      }));
    },

    // 从本地存储加载对话
    loadChatFromsessionStorage() {
      const savedChat = sessionStorage.getItem('chatHistory');
      if (savedChat) {
        try {
          const parsedData = JSON.parse(savedChat);
          this.chatMessages = parsedData.messages || [];
          this.selectedKnowledgeBase = parsedData.selectedKnowledgeBase || '';
        } catch (e) {
          console.error('解析本地存储的对话数据失败:', e);
        }
      }
    },

  },
  mounted() {
    // 初始化选择第一个知识库
    if (this.knowledgeBases.length > 0) {
      this.selectedKnowledgeBase = this.knowledgeBases[0].name;
    }
  },

});

