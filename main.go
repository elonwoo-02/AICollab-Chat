package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/bcrypt"
)

type Config struct {
	Addr        string
	DBDSN       string
	OpenAIKey   string
	OpenAIURL   string
	OpenAIModel string
}

type UserMessage struct {
	Sender  string
	Content string
	Display string
}

type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type RequestBody struct {
	Model    string    `json:"model"`
	Messages []Message `json:"messages"`
}

type ResponseBody struct {
	Choices []struct {
		Message Message `json:"message"`
	} `json:"choices"`
}

type Store interface {
	CreateUser(ctx context.Context, username, passwordHash string) error
	GetUserPassword(ctx context.Context, username string) (string, error)
	SaveMessage(ctx context.Context, sender, message string) error
}

type MemoryStore struct {
	mu       sync.RWMutex
	users    map[string]string
	messages []UserMessage
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{users: make(map[string]string)}
}

func (m *MemoryStore) CreateUser(_ context.Context, username, passwordHash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.users[username]; exists {
		return fmt.Errorf("user already exists")
	}
	m.users[username] = passwordHash
	return nil
}

func (m *MemoryStore) GetUserPassword(_ context.Context, username string) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	password, exists := m.users[username]
	if !exists {
		return "", sql.ErrNoRows
	}
	return password, nil
}

func (m *MemoryStore) SaveMessage(_ context.Context, sender, message string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.messages = append(m.messages, UserMessage{Sender: sender, Content: message})
	return nil
}

type MySQLStore struct {
	db *sql.DB
}

func NewMySQLStore(dsn string) (*MySQLStore, error) {
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}

	if err := db.Ping(); err != nil {
		return nil, err
	}

	store := &MySQLStore{db: db}
	if err := store.ensureTables(); err != nil {
		return nil, err
	}
	return store, nil
}

func (m *MySQLStore) ensureTables() error {
	userTable := `CREATE TABLE IF NOT EXISTS users (
		id INT AUTO_INCREMENT PRIMARY KEY,
		username VARCHAR(255) UNIQUE NOT NULL,
		password VARCHAR(255) NOT NULL
	);`
	messageTable := `CREATE TABLE IF NOT EXISTS messages (
		id INT AUTO_INCREMENT PRIMARY KEY,
		sender VARCHAR(255) NOT NULL,
		message TEXT NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);`

	if _, err := m.db.Exec(userTable); err != nil {
		return err
	}
	if _, err := m.db.Exec(messageTable); err != nil {
		return err
	}
	return nil
}

func (m *MySQLStore) CreateUser(ctx context.Context, username, passwordHash string) error {
	_, err := m.db.ExecContext(ctx, "INSERT INTO users (username, password) VALUES (?, ?)", username, passwordHash)
	return err
}

func (m *MySQLStore) GetUserPassword(ctx context.Context, username string) (string, error) {
	var password string
	err := m.db.QueryRowContext(ctx, "SELECT password FROM users WHERE username = ?", username).Scan(&password)
	return password, err
}

func (m *MySQLStore) SaveMessage(ctx context.Context, sender, message string) error {
	_, err := m.db.ExecContext(ctx, "INSERT INTO messages (sender, message) VALUES (?, ?)", sender, message)
	return err
}

type OpenAIClient struct {
	apiKey string
	url    string
	model  string
	client *http.Client
}

func NewOpenAIClient(cfg Config) *OpenAIClient {
	return &OpenAIClient{
		apiKey: cfg.OpenAIKey,
		url:    cfg.OpenAIURL,
		model:  cfg.OpenAIModel,
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

func (o *OpenAIClient) Enabled() bool {
	return o != nil && o.apiKey != ""
}

func (o *OpenAIClient) Chat(ctx context.Context, msg string) (string, error) {
	if !o.Enabled() {
		return "", errors.New("openai api key not configured")
	}

	reqBody := RequestBody{
		Model: o.model,
		Messages: []Message{
			{Role: "user", Content: msg},
		},
	}

	payload, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.url, strings.NewReader(string(payload)))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+o.apiKey)

	resp, err := o.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("openai error: %s", strings.TrimSpace(string(body)))
	}

	var respBody ResponseBody
	if err := json.Unmarshal(body, &respBody); err != nil {
		return "", err
	}
	if len(respBody.Choices) == 0 {
		return "", errors.New("openai response missing choices")
	}
	return strings.TrimSpace(respBody.Choices[0].Message.Content), nil
}

type App struct {
	router   *gin.Engine
	store    Store
	aiClient *OpenAIClient
	msgChan  chan UserMessage
	mu       sync.RWMutex
	conns    map[*websocket.Conn]string
}

func NewApp(store Store, aiClient *OpenAIClient) *App {
	if aiClient == nil {
		aiClient = &OpenAIClient{}
	}
	app := &App{
		router:   gin.Default(),
		store:    store,
		aiClient: aiClient,
		msgChan:  make(chan UserMessage, 32),
		conns:    make(map[*websocket.Conn]string),
	}
	app.registerRoutes()
	return app
}

func (a *App) registerRoutes() {
	a.router.LoadHTMLGlob("templates/*.html")
	a.router.Static("/static", "./static")

	a.router.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", nil)
	})

	a.router.GET("/login", func(c *gin.Context) {
		c.HTML(http.StatusOK, "login.html", nil)
	})

	a.router.POST("/login", func(c *gin.Context) {
		username := strings.TrimSpace(c.PostForm("username"))
		password := c.PostForm("password")

		if username == "" || password == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Username and password are required"})
			return
		}

		storedPassword, err := a.store.GetUserPassword(c.Request.Context(), username)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to query user information"})
			return
		}

		if !checkPassword(storedPassword, password) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
			return
		}

		setUsernameCookie(c, username)
		c.Redirect(http.StatusMovedPermanently, "/chat")
	})

	a.router.GET("/register", func(c *gin.Context) {
		c.HTML(http.StatusOK, "register.html", nil)
	})

	a.router.POST("/register", func(c *gin.Context) {
		username := strings.TrimSpace(c.PostForm("username"))
		password := c.PostForm("password")
		confirmPassword := c.PostForm("confirm_password")

		if username == "" || password == "" || confirmPassword == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Username and password are required"})
			return
		}
		if password != confirmPassword {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Passwords do not match"})
			return
		}

		passwordHash, err := hashPassword(password)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to secure password"})
			return
		}

		if err := a.store.CreateUser(c.Request.Context(), username, passwordHash); err != nil {
			if strings.Contains(err.Error(), "exists") {
				c.JSON(http.StatusConflict, gin.H{"error": "User already exists"})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to register user"})
			return
		}

		setUsernameCookie(c, username)
		c.Redirect(http.StatusMovedPermanently, "/chat")
	})

	a.router.GET("/chat", func(c *gin.Context) {
		if _, err := c.Request.Cookie("username"); err != nil {
			c.Redirect(http.StatusFound, "/login")
			return
		}
		c.HTML(http.StatusOK, "chat.html", nil)
	})

	a.router.GET("/ws", func(c *gin.Context) {
		a.handleWebSocket(c.Writer, c.Request)
	})
}

func (a *App) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin: func(_ *http.Request) bool {
			return true
		},
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		fmt.Printf("Failed to set websocket upgrade: %+v\n", err)
		return
	}
	defer conn.Close()

	cookie, err := r.Cookie("username")
	if err != nil {
		fmt.Println("Error getting username from cookie:", err)
		return
	}
	username := cookie.Value
	ip := r.RemoteAddr

	a.mu.Lock()
	a.conns[conn] = username
	a.mu.Unlock()

	a.sendUserList()

	defer func() {
		a.mu.Lock()
		delete(a.conns, conn)
		a.mu.Unlock()
		a.sendUserList()
	}()

	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			break
		}
		content := strings.TrimSpace(string(msg))
		if content == "" {
			continue
		}
		message := UserMessage{
			Sender:  username,
			Content: content,
			Display: formatMessage(username, ip, content),
		}
		a.msgChan <- message

		go a.handleAIMessage(content)
	}
}

func (a *App) handleAIMessage(content string) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	response, err := a.aiClient.Chat(ctx, content)
	if err != nil {
		if a.aiClient.Enabled() {
			response = "AI 服务暂时不可用，请稍后再试。"
		} else {
			response = "AI 服务未配置，请设置 OPENAI_API_KEY。"
		}
	}

	message := UserMessage{
		Sender:  "AI",
		Content: response,
		Display: formatMessage("AI", "0.0.0.0", response),
	}
	a.msgChan <- message
}

func (a *App) sendUserList() {
	a.mu.RLock()
	defer a.mu.RUnlock()

	var userList []string
	for _, username := range a.conns {
		userList = append(userList, username)
	}

	userListMessage := strings.Join(userList, ", ")
	for conn := range a.conns {
		if err := conn.WriteMessage(websocket.TextMessage, []byte("Online users: "+userListMessage)); err != nil {
			fmt.Printf("Failed to send user list: %+v\n", err)
		}
	}
}

func (a *App) broadcastLoop() {
	for msg := range a.msgChan {
		if err := a.store.SaveMessage(context.Background(), msg.Sender, msg.Content); err != nil {
			log.Printf("Failed to insert message to database: %v", err)
		}
		a.mu.RLock()
		for conn := range a.conns {
			if err := conn.WriteMessage(websocket.TextMessage, []byte(msg.Display)); err != nil {
				fmt.Printf("Failed to broadcast message: %+v\n", err)
			}
		}
		a.mu.RUnlock()
	}
}

func (a *App) Run(addr string) error {
	go a.broadcastLoop()
	return a.router.Run(addr)
}

func loadConfig() Config {
	addr := os.Getenv("CHATROOM_ADDR")
	if addr == "" {
		addr = ":8080"
	}

	openAIURL := os.Getenv("OPENAI_API_URL")
	if openAIURL == "" {
		openAIURL = "https://api.openai.com/v1/chat/completions"
	}
	openAIModel := os.Getenv("OPENAI_MODEL")
	if openAIModel == "" {
		openAIModel = "gpt-3.5-turbo"
	}

	return Config{
		Addr:        addr,
		DBDSN:       os.Getenv("CHATROOM_DB_DSN"),
		OpenAIKey:   os.Getenv("OPENAI_API_KEY"),
		OpenAIURL:   openAIURL,
		OpenAIModel: openAIModel,
	}
}

func formatMessage(username, ip, message string) string {
	return fmt.Sprintf("%s (%s): %s", username, ip, message)
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

func checkPassword(stored, provided string) bool {
	if strings.HasPrefix(stored, "$2a$") || strings.HasPrefix(stored, "$2b$") || strings.HasPrefix(stored, "$2y$") {
		return bcrypt.CompareHashAndPassword([]byte(stored), []byte(provided)) == nil
	}
	return stored == provided
}

func setUsernameCookie(c *gin.Context, username string) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "username",
		Value:    username,
		Path:     "/",
		HttpOnly: true,
	})
}

func main() {
	cfg := loadConfig()

	var store Store
	if cfg.DBDSN != "" {
		mysqlStore, err := NewMySQLStore(cfg.DBDSN)
		if err != nil {
			log.Fatalf("Failed to connect to MySQL: %v", err)
		}
		store = mysqlStore
		log.Println("Connected to MySQL database.")
	} else {
		store = NewMemoryStore()
		log.Println("Using in-memory store (set CHATROOM_DB_DSN to enable MySQL persistence).")
	}

	app := NewApp(store, NewOpenAIClient(cfg))
	if err := app.Run(cfg.Addr); err != nil {
		log.Fatalf("Failed to run server: %v", err)
	}
}
