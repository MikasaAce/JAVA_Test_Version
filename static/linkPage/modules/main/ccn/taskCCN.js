var vm = new Vue({
    el: "#app",
    created(){
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
        this.itemname = JSON.parse(sessionStorage.getItem('itemname') || '')
        this.getTableData()
    },
    data(){
        return {
            tableData:[],
            query:{
                fileName:'',
            },
            taskid:'',
            itemname:'',
        }
    },
    methods: {
        check(){

        },

        goto(){
            history.go(-1)
        },

        //获取文件列表
        getTableData() {
            var that = this
            this.taskid = JSON.parse(sessionStorage.getItem('taskid') || '')
            $.ajax({
                url: (http_head + '/ccn/'),
                data:{
                    method : 'get_ccnList',
                    taskid : that.taskid,
                    // page : that.currentPage,
                    // rows : that.pageSize,
                },
                type: 'post',
                dataType: 'JSON',
                success: function (res){
                    console.log(res)
                    that.tableData = res.fileList
                },
                error: function (err) {
                    console.log(err)
                    mymessage.error("获取失败")
                }
            })
        },
    },
})