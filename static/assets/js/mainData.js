var http_head = '';

if (url().includes ('10.99.16.24:8089'))
{
	http_head = 'http://10.99.16.24:8089';
} else {
    debugger;
    const fullUrl = url();
    const urlObj = new URL(fullUrl);
    http_head = urlObj.origin; // 自动提取协议+域名+端口
    console.log('Base URL:', http_head);
}

//console.log(http_head)

let localUser = {
    messages: [] // 存放消息列表
};

let scanLanguages = [
    'java',
//    'android',
//    'javascript',
//    'objective-c',
//    'go',
    'python',
    'c/c++',
//    'php',
//    'ruby',
//    'SQL',
//  以下不是安信和乐信需要的语言类型，并且暂时不支持扫描
//    'C#',
//    'Swift',
//    'Cobol',
//    'Fortran',
//    'shell',
//    'Node.js',
//    'Kotlin',
//    'Scala',
//    'Lua',
    '混合模式',  // 多语言混合模式
]

//获取cookie信息
var cookie_value = getCookieValue('username')
//console.log(cookie_value)

// 获取当前页面路径
const currentPath = window.location.pathname

// 如果当前已经是登录页，则跳过检查
if (currentPath === '/') {
    // 登录页不需要检查，跳过
} else if(cookie_value){
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
} else {
    window.location.href = http_head

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
//    console.log('当前网址链接:', currentUrl);
    return currentUrl;
}

function getCookieValue (cookieName) {
    let cookieString = document.cookie;
//    console.log(cookieString)
    // 将cookie字符串拆分成多个键值对
    let cookieArray = cookieString.split('; ');
//    console.log(cookieArray)
    // 遍历键值对数组，找到匹配的cookie
    for (let i = 0; i < cookieArray.length; i++) {
        let cookiePair = cookieArray[i].split('=');
//        console.log(cookiePair)
        // 去除空格并判断cookie名称是否匹配
        if (cookiePair[0].trim() === cookieName) {
            return cookiePair[1];
        }
    }
    // 若未找到匹配的cookie，则返回null或者其他你认为适合的默认值
    return null;
}


// 定义 renderMessageList 函数
function renderMessageList(messages) {
    var $messageList = $('.message-list');
    $messageList.empty(); // 清空原有内容

    if (messages && messages.length > 0) {
        console.log('messages:', messages); // 打印整个 messages 数组
        // 如果有消息，渲染每条消息
        messages.forEach(function (message) {
            // 将 create_time 中的 T 替换为空格
            var formattedTime = message.create_time.replace('T', ' ');

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
// 更新角标
function updateMessageBadge(totalCount, unreadCount) {
    var $badge = $('.message-badge');
    if (unreadCount > 0) {
        $badge.text(unreadCount)
          .removeClass('read')
          .addClass('unread');
    } else {
        $badge.text(totalCount)
          .removeClass('unread')
          .addClass('read');
    }
    $badge.show();
}

// 获取未读消息数量
function getUnreadCount(messages) {
    return messages.filter(message => message.is_read === 0).length;
}

// 获取消息列表
function fetchMessageList(callback) {
    $.ajax({
        url: http_head + '/login/',
        data: {
            method: 'query_alarm_logs',
            sender: localUser.accountId
        },
        type: 'post',
        dataType: 'JSON',
        success: function (res) {
            if (res && res.data && res.data.length > 0) {
                localUser.messages = res.data;
                if (typeof callback === 'function') {
                    callback(res.data);
                }
                // 更新角标
                updateMessageBadge(res.data.length, getUnreadCount(res.data));
            } else {
                if (typeof callback === 'function') {
                    callback([]);
                }
                // 更新角标
                updateMessageBadge(0, 0);
            }
        },
        error: function () {
            layer.msg('获取消息列表失败', { icon: 2 });
        }
    });
}

// 标记消息为已读
function markMessagesAsRead() {
    $.ajax({
        url: http_head + '/login/',
        type: 'POST',
        data: {
            method: 'mark_logs_as_read',
            sender: localUser.accountId
        },
        success: function (res) {
            if (res['msg-code'] === '200') {
                console.log('消息已标记为已读');
            } else {
                console.error('标记消息为已读失败');
            }
        },
        error: function () {
            console.error('请求失败');
        }
    });
}

// 渲染消息列表到弹窗
function renderMessageListInPopup(messages) {
    var popupContent = '<div class="message-popup-content">';

    if (messages && messages.length > 0) {
        messages.forEach(function (message) {
            var formattedTime = message.create_time.replace('T', ' ');
            var formattedMessage = message.message.replace(/\r\n/g, '<br>');
            var unreadClass = message.is_read === 0 ? 'unread-item' : '';

            popupContent +=
              '<div class="message-item ' + unreadClass + '" data-message="' + message.message + '" data-create_time="' + message.create_time + '">' +
              '<div class="message-text">' + formattedMessage + '</div>' +
              '<div class="message-time">' + formattedTime + '</div>' +
              '</div>';
        });
    } else {
        popupContent += '<div class="message-item no-message">没有新消息</div>';
    }

    popupContent += '</div>';

    // 显示弹窗
    layer.open({
        type: 1,
        title: '消息列表',
        content: popupContent,
        area: ['500px', '650px'],
        shadeClose: true,
        end: function () {
            markMessagesAsRead(); // 弹窗关闭后调用接口
        }
    });
}

// 初始化：页面加载时获取消息列表
fetchMessageList(function (messages) {
    renderMessageList(messages);
});

// 点击消息图标时显示弹窗
$('.message-icon').on('click', function () {
    fetchMessageList(function (messages) {
        renderMessageListInPopup(messages);
    });
});
