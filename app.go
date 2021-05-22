package main

import (
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"time"

	_ "net/http/pprof"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"github.com/lolmourne/go-accounts/model"
	"github.com/lolmourne/go-accounts/resource/acc"
	"github.com/lolmourne/go-accounts/resource/monitoring"
	"github.com/lolmourne/go-accounts/usecase/userauth"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var db *sqlx.DB
var dbResource acc.DBItf
var userAuthUsecase userauth.UsecaseItf
var addr = flag.String("listen-address", ":7171", "The address to listen on for HTTP requests.")
var prometheusMonitoring monitoring.IMonitoring

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	cfgFile, err := os.Open("config.json")
	if err != nil {
		log.Fatal(err)
	}
	defer cfgFile.Close()

	cfgByte, _ := ioutil.ReadAll(cfgFile)

	var cfg model.Config
	err = json.Unmarshal(cfgByte, &cfg)
	if err != nil {
		log.Fatal(err)
	}

	dbConStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable", cfg.DB.Address, cfg.DB.Port, cfg.DB.User, cfg.DB.Password, cfg.DB.DBName)

	dbInit, err := sqlx.Connect("postgres", dbConStr)
	if err != nil {
		log.Fatalln(err)
	}

	rdb := redis.NewClient(&redis.Options{
		Addr:     cfg.Redis.Host,
		Password: cfg.Redis.Password, // no password set
		DB:       0,                  // use default DB
	})

	dbRsc := acc.NewDBResource(dbInit)
	dbRsc = acc.NewRedisResource(rdb, dbRsc)

	dbResource = dbRsc
	db = dbInit

	userAuthUsecase = userauth.NewUsecase(dbRsc, cfg.JWT.SignKey)

	corsOpts := cors.Config{
		AllowAllOrigins:  true,
		AllowMethods:     []string{"HEAD", "GET", "POST", "PUT", "PATCH", "DELETE"},
		AllowCredentials: true,
		AllowHeaders:     []string{"x-access-token"},
	}
	cors := cors.New(corsOpts)
	r := gin.Default()
	r.Use(cors)
	r.POST("/register", register)
	r.POST("/login", login)
	r.GET("/usr/:user_id", getUser)
	r.GET("/profile/:username", getProfile)
	r.PUT("/profile", validateSession(updateProfile))
	r.PUT("/password", validateSession(changePassword))
	r.GET("/user/info", validateSession(getUserInfo))

	http.Handle("/metrics", promhttp.Handler())
	go func() {
		log.Fatal(http.ListenAndServe(*addr, nil))
	}()
	go func() {
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()

	prometheusMonitoring = monitoring.NewPrometheusMonitoring()

	r.Run(":7070")
}

func validateSession(handlerFunc gin.HandlerFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		accessToken := c.Request.Header["X-Access-Token"]

		if len(accessToken) < 1 {
			c.JSON(403, StandardAPIResponse{
				Err: "No access token provided",
			})
			return
		}

		userID, err := userAuthUsecase.ValidateSession(accessToken[0])
		if err != nil {
			c.JSON(400, StandardAPIResponse{
				Err: "Cannot validate session",
			})
			return
		}
		c.Set("uid", userID)
		handlerFunc(c)
	}
}

func getUserInfo(c *gin.Context) {
	userID := c.GetInt64("uid")
	if userID < 1 {
		c.JSON(401, StandardAPIResponse{
			Err: "Unauthorized",
		})
		return
	}

	user, err := dbResource.GetUserByUserID(userID)
	if err != nil {
		c.JSON(500, StandardAPIResponse{
			Err: "Internal Server Error",
		})
		return
	}

	c.JSON(200, StandardAPIResponse{
		Err:  "",
		Data: user,
	})
}

func register(c *gin.Context) {
	username := c.Request.FormValue("username")
	password := c.Request.FormValue("password")
	confirmPassword := c.Request.FormValue("confirm_password")

	err := userAuthUsecase.Register(username, password, confirmPassword)
	if err != nil {
		c.JSON(400, StandardAPIResponse{
			Err:     err.Error(),
			Message: "Failed",
		})
		return
	}

	c.JSON(201, StandardAPIResponse{
		Err:     "null",
		Message: "Success create new user",
	})
}

func login(c *gin.Context) {
	startTime := time.Now()
	username := c.Request.FormValue("username")
	password := c.Request.FormValue("password")

	user, err := userAuthUsecase.Login(username, password)
	if err != nil {
		processTime := time.Since(startTime).Milliseconds()

		prometheusMonitoring.CountLogin("/login", 400, err.Error(), float64(processTime))
		c.JSON(400, StandardAPIResponse{
			Err:     err.Error(),
			Message: "Failed",
		})

		return
	}
	processTime := time.Since(startTime).Milliseconds()
	prometheusMonitoring.CountLogin("/login", 200, "nil", float64(processTime))
	c.JSON(200, StandardAPIResponse{
		Data: user,
	})
}

func getUser(c *gin.Context) {
	userIDStr := c.Param("user_id")

	userID, err := strconv.ParseInt(userIDStr, 10, 64)
	if err != nil {
		c.JSON(500, StandardAPIResponse{
			Err: "Internal Server Error",
		})
		return
	}

	if userID < 1 {
		c.JSON(401, StandardAPIResponse{
			Err: "Unauthorized",
		})
		return
	}

	user, err := dbResource.GetUserByUserID(userID)
	if err != nil {
		c.JSON(400, StandardAPIResponse{
			Err: "Unauthorized",
		})
		return
	}

	if user.UserID == 0 {
		c.JSON(http.StatusNotFound, StandardAPIResponse{
			Err: "user not found",
		})
		return
	}

	user.Salt = ""
	user.Password = ""

	c.JSON(200, StandardAPIResponse{
		Err:  "null",
		Data: user,
	})
}

func getProfile(c *gin.Context) {
	username := c.Param("username")

	user, err := dbResource.GetUserByUserName(username)
	if err != nil {
		c.JSON(400, StandardAPIResponse{
			Err: "Unauthorized",
		})
		return
	}

	if user.UserID == 0 {
		c.JSON(http.StatusNotFound, StandardAPIResponse{
			Err: "user not found",
		})
		return
	}

	user.Password = ""
	user.Salt = ""

	c.JSON(200, StandardAPIResponse{
		Err:  "null",
		Data: user,
	})
}

func updateProfile(c *gin.Context) {
	userID := c.GetInt64("uid")
	if userID < 1 {
		c.JSON(400, StandardAPIResponse{
			Err: "no user founds",
		})
		return
	}

	profilepic := c.Request.FormValue("profile_pic")
	err := dbResource.UpdateProfile(userID, profilepic)
	if err != nil {
		c.JSON(400, StandardAPIResponse{
			Err: err.Error(),
		})
		return
	}

	c.JSON(201, StandardAPIResponse{
		Err:     "null",
		Message: "Success update profile picture",
	})

}

func changePassword(c *gin.Context) {
	userID := c.GetInt64("uid")

	oldpass := c.Request.FormValue("old_password")
	newpass := c.Request.FormValue("new_password")

	user, err := dbResource.GetUserByUserID(userID)
	if err != nil {
		c.JSON(400, StandardAPIResponse{
			Err: err.Error(),
		})
		return
	}

	oldpass += user.Salt
	h := sha256.New()
	h.Write([]byte(oldpass))
	hashedOldPassword := fmt.Sprintf("%x", h.Sum(nil))

	if user.Password != hashedOldPassword {
		c.JSON(401, StandardAPIResponse{
			Err: "old password is wrong!",
		})
		return
	}

	//new pass
	salt := RandStringBytes(32)
	newpass += salt

	h = sha256.New()
	h.Write([]byte(newpass))
	hashedNewPass := fmt.Sprintf("%x", h.Sum(nil))

	err2 := dbResource.UpdateUserPassword(userID, hashedNewPass)

	if err2 != nil {
		c.JSON(400, StandardAPIResponse{
			Err: err.Error(),
		})
		return
	}

	c.JSON(201, StandardAPIResponse{
		Err:     "null",
		Message: "Success update password",
	})

}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func RandStringBytes(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}

type StandardAPIResponse struct {
	Err     string      `json:"err"`
	Message string      `json:"message"`
	Data    interface{} `json:"data"`
}
