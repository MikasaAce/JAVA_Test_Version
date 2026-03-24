// static/linkPage/login/auth.js
class AuthService {
    constructor() {
        this.token = localStorage.getItem('access_token');
        this.refreshToken = localStorage.getItem('refresh_token');
        this.clientId = 'nAGcVMZlaD8hYwSADk8IVdTFc8B0Tw6pJnl3vDYV'; // 你的client_id
        this.clientSecret = 'Q2mlaf4lPfoU9mvDwFoqavxrO3IJfr8HwP7dlwsBBEaOBTbGs1LjSpan2kljNKyGE5zmOZn3AyJEN6E81zCyxAUnAJjxQS8ZTMQ52G7ScbMLdkh4eOtwdOw5W7OiJpkc'; // 你的client_secret
        this.baseURL = 'http://10.99.16.24:8089';
        this.tokenExpiry = localStorage.getItem('token_expiry') || 0;
    }

    // 登录获取token - 替换原来的login方法
    async login(username, password) {
        try {
            const response = await $.ajax({
                url: `${this.baseURL}/o/token/`,
                type: 'POST',
                data: {
                    grant_type: 'password',
                    username: username,
                    password: password,
                    client_id: this.clientId,
                    client_secret: this.clientSecret,
                },
                dataType: 'json'
            });

            this.setTokens(response);
            
            // 调用原来的成功逻辑
            mymessage.success("登陆成功");
            sessionStorage.setItem('info', JSON.stringify({name: username}));
            
            // 跳转到首页
            window.location.href = 'http://10.99.16.24:8089/static/linkPage/login/index.html';
            
            return response;
        } catch (error) {
            console.error('OAuth Login failed:', error);
            mymessage.error("登陆失败");
            throw error;
        }
    }

    // 刷新token
    async refreshTokens() {
        if (!this.refreshToken) {
            this.logout();
            return;
        }

        try {
            const response = await $.ajax({
                url: `${this.baseURL}/o/token/`,
                type: 'POST',
                data: {
                    grant_type: 'refresh_token',
                    refresh_token: this.refreshToken,
                    client_id: this.clientId,
                    client_secret: this.clientSecret,
                },
                dataType: 'json'
            });

            this.setTokens(response);
            return response;
        } catch (error) {
            console.error('Refresh token failed:', error);
            this.logout();
            throw error;
        }
    }

    // 保存token到localStorage
    setTokens(tokenData) {
        this.token = tokenData.access_token;
        this.refreshToken = tokenData.refresh_token;
        
        localStorage.setItem('access_token', tokenData.access_token);
        localStorage.setItem('refresh_token', tokenData.refresh_token);
        
        // 设置token过期时间（提前2分钟刷新）
        const expiresIn = (tokenData.expires_in - 120) * 1000;
        this.tokenExpiry = Date.now() + expiresIn;
        localStorage.setItem('token_expiry', this.tokenExpiry);
    }

    // 获取当前token
    getToken() {
        return this.token;
    }

    // 检查token是否需要刷新
    shouldRefreshToken() {
        return !this.token || Date.now() >= this.tokenExpiry;
    }

    // 检查是否已登录
    isAuthenticated() {
        return !!this.token && Date.now() < this.tokenExpiry;
    }

    // 登出
    logout() {
        this.token = null;
        this.refreshToken = null;
        this.tokenExpiry = 0;
        localStorage.removeItem('access_token');
        localStorage.removeItem('refresh_token');
        localStorage.removeItem('token_expiry');
        sessionStorage.removeItem('info');
        
        // 跳转到登录页
        window.location.href = 'http://10.99.16.24:8089/static/linkPage/login/login.html';
    }
}

// 创建全局实例
window.authService = new AuthService();