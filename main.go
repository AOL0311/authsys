package main

import (
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type Claims struct {
	Username string `json:"username"`
	IsAdmin  bool   `json:"is_admin"`
	jwt.RegisteredClaims
}

type User struct {
	ID       uint   `gorm:"primaryKey"`
	Username string `gorm:"uniqueIndex"`
	Password string
	IsAdmin  bool `gorm:"default:false"`
}

var db *gorm.DB
var jwtSecret = []byte("your-super-secret-key")

func ConnectDB() {
	err := godotenv.Load()
	if err != nil {
		log.Println("Error loading .env file, assuming environment variables are set.")
	}

	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		log.Fatal("DATABASE_URL environment variable is not set.")
	}

	db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}

	db.AutoMigrate(&User{})

	var adminUser User
	if db.Where("username = ?", "admin").First(&adminUser).RowsAffected == 0 {
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("adminpassword"), bcrypt.DefaultCost)
		db.Create(&User{
			Username: "admin",
			Password: string(hashedPassword),
			IsAdmin:  true,
		})
		log.Println("Admin user 'admin' created with password 'adminpassword'")
	}
}

func Register(c *gin.Context) {
	var input User
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	var existingUser User
	if db.Where("username = ?", input.Username).First(&existingUser).RowsAffected > 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Username already exists"})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}

	user := User{
		Username: input.Username,
		Password: string(hashedPassword),
	}
	db.Create(&user)

	c.JSON(http.StatusOK, gin.H{"message": "Registration successful"})
}

func Login(c *gin.Context) {
	var input User
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	var user User
	if db.Where("username = ?", input.Username).First(&user).RowsAffected == 0 {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(input.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
		return
	}

	claims := &Claims{
		Username: user.Username,
		IsAdmin:  user.IsAdmin,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 24)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": tokenString, "message": "Login successful"})
}

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authorization header missing"})
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid Authorization header format"})
			return
		}
		tokenString := parts[1]

		token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})

		if err != nil || !token.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			return
		}

		claims, ok := token.Claims.(*Claims)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
			return
		}

		c.Set("user", claims)
		c.Next()
	}
}

func AdminMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, exists := c.Get("user")
		if !exists {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			return
		}

		userClaims, ok := claims.(*Claims)
		if !ok || !userClaims.IsAdmin {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Forbidden: Admin access required"})
			return
		}
		c.Next()
	}
}

func GetProfile(c *gin.Context) {
	claims, exists := c.Get("user")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"user": claims})
}

func GetAllUsers(c *gin.Context) {
	var users []User
	db.Find(&users)
	c.JSON(http.StatusOK, gin.H{"users": users})
}

func main() {
	ConnectDB()

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("zxcvb123"), bcrypt.DefaultCost)
	log.Println("New hash for 'zxcvb123': ", string(hashedPassword))

	r := gin.Default()

	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"GET", "POST"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	r.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "Welcome to the Go Auth System API"})
	})

	r.POST("/register", Register)
	r.POST("/login", Login)

	api := r.Group("/api")
	api.Use(AuthMiddleware())
	{
		api.GET("/profile", GetProfile)
	}

	adminApi := api.Group("/admin")
	adminApi.Use(AdminMiddleware())
	{
		adminApi.GET("/users", GetAllUsers)
	}

	r.Run(":8080")
}
