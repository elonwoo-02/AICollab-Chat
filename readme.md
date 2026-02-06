## 智聊协作平台（AICollab Chat）
这个程序是一个基于 Golang 和 Gin 框架实现的聊天室应用。聊天室支持登录、注册、聊天等功能，并集成了 OpenAI 的 GPT-3 模型进行聊天自动回复。下面是程序的文档说明：

### 项目命名
**智聊协作平台（AICollab Chat）**：强调“AI + 协作”的产品定位，既体现智能对话能力，也突出多人实时交流场景，适合作为对外展示的专业名称。

### 修改建议
* **配置与部署**：将数据库与 API Key 改为环境变量或配置文件读取，提供示例配置与启动脚本，便于多环境部署与 CI 集成。
* **安全与权限**：对密码使用 bcrypt/argon2 加密；对 WebSocket 与接口加入鉴权与频率限制；增加 CSRF/会话管理策略。
* **可观测性**：引入结构化日志与请求追踪（如 zap + trace id），并补充关键错误监控与告警。
* **可维护性**：按“路由/服务/存储/模型”分层重构；为 AI 请求抽象接口，便于切换模型或接入多供应商。
* **产品体验**：支持消息多行显示、消息搜索与会话归档；在聊天区加入“正在输入/已读”等状态提示。

### 主要功能

* 提供聊天室服务
* 集成 OpenAI GPT-3 模型实现自动聊天回复

### 具体功能
该程序的需求是实现一个简单的聊天室应用，用户可以通过网页界面进行注册、登录、发送消息、接收消息等操作。聊天室应用包括以下主要功能：

* 用户注册和登录功能：用户可以通过注册页面进行注册，或者通过登录页面登录聊天室。

* 实时聊天功能：已登录的用户可以在聊天室内发送消息，其他用户可以实时接收到消息。在发送消息时，用户可以输入文本信息并发送，也可以与AI进行聊天，AI会返回回答。聊天记录将保存在数据库中。

* 在线用户列表：聊天室界面将显示当前在线的所有用户的列表。

* 聊天室界面：聊天室的界面需要具有良好的用户体验，包括输入框、发送按钮、消息显示框、在线用户列表等元素。

* 数据库支持：程序需要使用 MySQL 数据库来存储用户信息和聊天记录。

* WebSocket 支持：程序需要使用 WebSocket 技术来实现实时聊天功能。

* AI对话支持：用户可以选择与AI进行聊天，AI返回的回答将显示在聊天室中。

* 前端页面：聊天室需要一个漂亮的前端页面来增强用户体验。

### 程序文件

* main.go: 程序的主入口文件
* main_test.go: 程序的测试文件
* templates/: 存放 HTML 模板文件
* static/: 存放静态资源文件
* 设计报告.pdf：程序的设计报告

### 代码结构

#### 聊天室服务
* 定义了全局变量，包括 WebSocket 连接映射、消息结构体（包含发送者和消息内容）以及消息通道。
* 在 `main()` 函数中，首先建立数据库连接并测试连接。接着，配置了 Gin 路由以处理登录、注册和聊天页面的请求。定义了处理 WebSocket 连接的 `wshandler()` 函数，用于处理客户端发送的消息并广播到所有在线用户。
* 定义了 `sendUserList()` 函数，用于获取在线用户列表并发送给所有连接的客户端。
* 在 `main()` 函数中启动了一个协程，用于从全局消息通道中读取消息并将消息保存到数据库以及广播给所有在线用户。
* 最后，运行 Gin 路由，监听 8080 端口。

#### chatgpt服务
* 创建请求体：首先，函数创建一个 `RequestBody` 结构体，其中包含了要发送给 GPT 的消息。这个结构体将被序列化为 JSON 格式，然后作为 HTTP 请求的 body 发送给 OpenAI。
* 创建 HTTP 请求：然后，函数创建一个 HTTP POST 请求，目标 URL 是 OpenAI 的 API。请求的 header 包括了 "Content-Type" 和 "Authorization" 两个字段。
* 发送 HTTP 请求：函数通过一个 HTTP 客户端发送请求，然后接收响应。响应的 body 是一个 JSON 格式的字符串，需要被反序列化为 `ResponseBody` 结构体。
* 处理响应：函数从响应体中提取 GPT 的回复消息，并将其添加到 `UserMessage` 结构体中，然后返回。这个消息将被发送到全局消息通道，然后广播给所有连接的 WebSocket 客户端。

### 改进方向
* 增加错误处理、日志记录、安全性方面的改进等。
* 对于数据库设计应考虑更多的因素，比如数据的一致性、完整性、安全性等，需要设计更复杂的表结构和更完善的字段。密码的存储应使用加密方法（如 bcrypt 等）以保证安全性
* 代码重构

### 目录结构
``` arduino
.
├── main.go
├── main_test.go
├── readme.md
├── 设计报告.pdf
├── static
│   ├── css
│   │   └── ...
│   ├── images
│   │   └── avator.png
│   └── js
│       └── ...
└── templates
├── chat.html
├── index.html
├── login.html
└── register.html
```


### 教程
#### 将代码克隆到本地
```
git clone git@github.com:ElandWoo/chatroom.git
```

#### 安装必要的依赖项

代码使用了以下Go的第三方库：

* Gin: Gin 框架
* github.com/go-sql-driver/mysql: MySQL 数据库驱动
* github.com/gorilla/websocket: WebSocket 库


使用go get命令安装这些包，例如：

``` go 
go get -u github.com/gin-gonic/gin
go get -u github.com/go-sql-driver/mysql
go get -u github.com/gorilla/websocket
```

#### 数据库配置
确保您的MySQL数据库已设置并运行。
建立chatroom数据库
``` sql
CREATE DATABASE chatroom;
```
并在其中创建users和messages表:
``` sql
USE chatroom;
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL
);

CREATE TABLE messages (
    id INT AUTO_INCREMENT PRIMARY KEY,
    sender VARCHAR(255) NOT NULL,
    message TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);


USE chatroom;
SHOW TABLES;
SELECT * FROM users;
SELECT * FROM messages;
```

将main.go:39行配置成自己的mysql数据库
``` go
db, err := sql.Open("mysql", "user:password@tcp(username:port)/chatroom")
```

#### 添加静态文件
如果你想在项目中添加自己的静态文件，确保你的静态文件（CSS、JavaScript、图片等）位于正确的目录中。
代码将静态文件目录设置为./static，你还需要确保模板文件位于名为templates的目录中。

#### api key
在代码第41行填入gpt api key
``` go
const (
	openaiURL    = "https://api.openai.com/v1/chat/completions"
	openaiAPIKey = ""
) 
```
#### 编译运行
1. 在浏览器中输入[http://localhost:8080](http://localhost:8080)查看是否正常启动；
   ![./static/images/index.png](./static/images/index.png)
2. 运行您的程序并尝试使用Web浏览器访问应用程序。首先访问[http://localhost:8080/register](http://localhost:8080/register), 尝试注册一个新用户；
   ![./static/images/register.png](./static/images/register.png)
3. 然后，访问[http://localhost:8080/register](http://localhost:8080/register), 尝试使用刚刚注册的用户登录。
   ![./static/images/login.png](./static/images/login.png)
   
4. 开始[聊天](http://localhost:8080/chat) 
   

   ![./static/images/chat.png](./static/images/chat.png)


### 后续更新

#### v0.0.2 支持接入chat-gpt

利用api调用chatgpt的[代码示例](chatgpt)；

在main.go第41行填入gpt api key
``` go
const (
	openaiURL    = "https://api.openai.com/v1/chat/completions"
	openaiAPIKey = ""
) 
```

##### 问题：
待解决：聊天区文本不能多行显示
