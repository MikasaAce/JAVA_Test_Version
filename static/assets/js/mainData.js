var http_head = '';
if (url().includes ('10.99.16.24:8088'))
{
	http_head = 'http://10.99.16.24:8088';
}
console.log(http_head)

let localUser = {
    messages: [] // 存放消息列表
};

//获取cookie信息
var cookie_value = getCookieValue('username')
console.log(cookie_value)

if(cookie_value){
    $.ajax({
        url: http_head + '/login/',
        type: 'POST',
        data:{
            method : 'check',
            username : cookie_value,
        },
        dataType: 'json',
        async: false,
        success: function (res) {
            console.log(res);
            if (res.isLogin === 'false') {
                console.log('没有登录');
            } else {//登陆成功了
                localUser = res;
            }
        }, error: function () {

        }
    });
}else{
    // window.location.href = 'http://10.99.16.24:8088/static/linkPage/login/index.html'

}


function timeControl(time) {
    var urlRequest = http_head + '/v1/EnfoAshx/ashx/TimeControl.ashx';
    var submit = {
        method: encrypt('TimeControl'),
        time: encrypt(time)
    };
    var res = {};
    $.ajax({
        url: urlRequest,
        dataType: "json",
        type: "POST",
        async: false,
        data: submit,
        success: function (response) {
            console.log(response)
            res = response;
        }
    });
    return res;
}

function url(){
    const currentUrl = window.location.href;
    console.log('当前网址链接:', currentUrl);
    return currentUrl;
}

function getCookieValue (cookieName) {
    let cookieString = document.cookie;
    console.log(cookieString)
    // 将cookie字符串拆分成多个键值对
    let cookieArray = cookieString.split('; ');
    console.log(cookieArray)
    // 遍历键值对数组，找到匹配的cookie
    for (let i = 0; i < cookieArray.length; i++) {
        let cookiePair = cookieArray[i].split('=');
        console.log(cookiePair)
        // 去除空格并判断cookie名称是否匹配
        if (cookiePair[0].trim() === cookieName) {
            return cookiePair[1];
        }
    }
    // 若未找到匹配的cookie，则返回null或者其他你认为适合的默认值
    return null;
}


// 获取消息列表的函数
function fetchMessageList() {
    $.ajax({
        url: http_head + '/login/', // 接口地址
        data: {
            method: 'query_alarm_logs', // 修改为新的方法名
            sender: localUser.accountId // 传递 accountId
        },
        type: 'post',
        dataType: 'JSON',
        success: function (res) {
            if (res && res.data && res.data.length > 0) {
                localUser.messages = res.data; // 更新消息列表
                renderMessageList(res.data); // 渲染消息列表
            } else {
                renderMessageList([]); // 如果没有消息，渲染空列表
            }
        },
        error: function () {
            layer.msg('获取消息列表失败', { icon: 2 });
        }
    });
}
// 渲染消息列表的函数
function renderMessageList(messages) {
    var $messageList = $('.message-list');
    $messageList.empty(); // 清空原有内容

    if (messages && messages.length > 0) {
        console.log('messages:', messages); // 打印整个 messages 数组
        // 如果有消息，渲染每条消息
        messages.forEach(function (message) {
            // 将 create_time 中的 T 替换为空格或 —
            var formattedTime = message.create_time.replace('T', ' '); // 替换为空格
            // var formattedTime = message.create_time.replace('T', '—'); // 替换为 —

            $messageList.append(
              '<div class="message-item" data-message="' + message.message + '" data-create_time="' + message.create_time + '">' +
              '<div class="message-text">' + message.message + '</div>' +
              '<div class="message-time">' + formattedTime + '</div>' +
              '</div>'
            );
        });
    } else {
        // 如果没有消息，显示“没有新消息”
        $messageList.append(
          '<div class="message-item no-message">没有新消息</div>'
        );
    }
}

// 初始化：页面加载时获取消息列表
fetchMessageList();

// 鼠标移动到消息图标上时显示消息列表
$('.message-icon').hover(function () {
    fetchMessageList(); // 每次悬停时重新获取消息列表
    $(this).find('.message-list').show();
}, function () {
    $(this).find('.message-list').hide();
});

// 点击消息列表项时显示弹窗
$('.message-list').on('click', '.message-item', function () {
    if ($(this).hasClass('no-message')) return; // 如果是“没有新消息”，不触发弹窗

    var message = $(this).data('message'); // 获取消息内容
    var create_time = $(this).data('create_time'); // 获取创建时间

    // 将 create_time 中的 T 替换为空格或 —
    var formattedTime = create_time.replace('T', ' '); // 替换为空格
    // var formattedTime = create_time.replace('T', '—'); // 替换为 —

    // 格式化消息内容，将 \r\n 替换为 <br>
    var formattedMessage = message.replace(/\r\n/g, '<br>');

    // 在“项目名称”前面添加换行符
    formattedMessage = formattedMessage.replace(/项目名称/g, '<br><br>项目名称');

    layer.open({
        type: 1,
        title: '消息详情',
        content: '<div class="message-detail-content">' +
          '<p class="message-text1">' + formattedMessage + '</p>' +
          '<p class="message-time1">' + formattedTime + '</p>' +
          '</div>',
        area: ['550px', 'auto'], // 宽度固定为 500px，高度自适应
        shadeClose: true,
    });
});
