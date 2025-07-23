var vm = new Vue({
    el: "#app",
    created() {
    },
    data() {
        return {
            fileList: [
                { name: "CWE 235", files: [{ name: "brackets.java" }, { name: "checkdll.java" }, { name: "comment_save.java" }] },
                { name: "CWE 89", files: [{ name: "内容4" }, { name: "内容5" }] },
                { name: "CWE 120", files: [{ name: "内容6" }, { name: "内容7" }, { name: "内容8" }] }
            ],
            value: '',
            input: '',
            activeName: 'first',
        //
            radio: 3,
            data: '\n' +
                '    if (getpidcon_raw(pid, &srccon) < 0)\n' +
                '    {\n' +
                '        <span class="highlight">perror_msg("getpidcon_raw(%d)", pid);</span>\n' +
                '        return -1;\n' +
                '    }',
            form: {
                name: '',
                radio:'',

            },
            checkList1:[],
            checkList2:[],
        }
    },
    methods: {
        handleClick(tab, event) {
            console.log(tab, event);
        }
    }

})