package main

import (
	"log"
	"net/http"
	"strconv"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"github.com/lolmourne/go-accounts/resource/acc"
	"github.com/lolmourne/go-accounts/usecase/userauth"
)

var dbResource acc.DBItf
var userAuthUsecase userauth.UsecaseItf

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	dbInit, err := sqlx.Connect("postgres", "host=34.101.216.10 user=skilvul password=skilvul123apa dbname=skilvul-groupchat sslmode=disable")
	if err != nil {
		log.Fatalln(err)
	}

	rdb := redis.NewClient(&redis.Options{
		Addr:     "34.101.216.10:6379",
		Password: "skilvulredis", // no password set
		DB:       0,              // use default DB
	})

	dbRsc := acc.NewDBResource(dbInit)
	dbRsc = acc.NewRedisResource(rdb, dbRsc)

	dbResource = dbRsc

	userAuthUsecase = userauth.NewUsecase(dbRsc, "signedK3y")

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
	r.GET("/profile/", getUser)             // get other user by ID
	r.GET("/profile/:username", getProfile) // get other user by username
	r.PUT("/update-photo", validateSession(updatePhotoProfile))
	r.PUT("/password", validateSession(changePassword))
	r.PUT("/username", validateSession(changeUsername))
	r.GET("/user/info", validateSession(getUserInfo))

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
	username := c.Request.FormValue("username")
	password := c.Request.FormValue("password")

	user, err := userAuthUsecase.Login(username, password)
	if err != nil {
		c.JSON(400, StandardAPIResponse{
			Err:     err.Error(),
			Message: "Failed",
		})
		return
	}

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

func updatePhotoProfile(c *gin.Context) {
	userID := c.GetInt64("uid")
	if userID < 1 {
		c.JSON(400, StandardAPIResponse{
			Err: "no user founds",
		})
		return
	}

	profilepic := c.Request.FormValue("profile_pic")
	err := dbResource.UpdatePhotoProfile(userID, profilepic)
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

func changeUsername(c *gin.Context) {
	userID := c.GetInt64("uid")
	if userID < 1 {
		c.JSON(400, StandardAPIResponse{
			Err: "no user founds",
		})
		return
	}
	username := c.Request.FormValue("username")
	err := userAuthUsecase.ChangeUsername(userID, username)
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
	confirmpass := c.Request.FormValue("confirm_password")

	err := userAuthUsecase.ChangePassword(userID, oldpass, newpass, confirmpass)
	if err != nil {
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

type StandardAPIResponse struct {
	Err     string      `json:"err"`
	Message string      `json:"message"`
	Data    interface{} `json:"data"`
}
