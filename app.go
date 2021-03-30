package main

import (
	"crypto/sha256"
	"database/sql"
	"fmt"
	"log"
	"math/rand"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"github.com/lolmourne/go-groupchat/resource"
)

var db *sqlx.DB
var dbResource resource.DBItf

func main() {
	dbInit, err := sqlx.Connect("postgres", "host=34.101.216.10 user=skilvul password=skilvul123apa dbname=skilvul-groupchat sslmode=disable")
	if err != nil {
		log.Fatalln(err)
	}

	dbRsc := resource.NewDBResource(dbInit)
	dbResource = dbRsc
	db = dbInit

	r := gin.Default()
	r.POST("/register", register)
	r.POST("/login", login)
	r.GET("/profile/:username", getProfile)
	r.PUT("/profile", updateProfile)
	r.PUT("/password", changePassword)
	r.PUT("/room", joinRoom)
	r.POST("/room", createRoom)
	r.Run()
}

func register(c *gin.Context) {
	username := c.Request.FormValue("username")
	password := c.Request.FormValue("password")
	confirmPassword := c.Request.FormValue("confirm_password")

	if confirmPassword != password {
		c.JSON(400, StandardAPIResponse{
			Err: "Confirmed password is not matched",
		})
		return
	}
	salt := RandStringBytes(32)
	password += salt

	h := sha256.New()
	h.Write([]byte(password))
	password = fmt.Sprintf("%x", h.Sum(nil))

	err := dbResource.Register(username, password, salt)
	if err != nil {
		c.JSON(400, StandardAPIResponse{
			Err: "Bad Request",
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

	user, err := dbResource.GetUserByUserName(username)
	if err != nil {
		c.JSON(400, StandardAPIResponse{
			Err: "Unauthorized",
		})
		return
	}

	password += user.Salt
	h := sha256.New()
	h.Write([]byte(password))
	hashedPassword := fmt.Sprintf("%x", h.Sum(nil))

	if user.Password != hashedPassword {
		c.JSON(401, StandardAPIResponse{
			Err: "password mismatch",
		})
		return
	}

	resp := User{
		Username:   user.Username,
		ProfilePic: user.ProfilePic,
		CreatedAt:  user.CreatedAt.UnixNano(),
	}

	c.JSON(200, StandardAPIResponse{
		Err:  "null",
		Data: resp,
	})
}

func getProfile(c *gin.Context) {
	query := `
	SELECT 
		user_id,
		username,
		password,
		salt,
		created_at,
		profile_pic
	FROM
		account
	WHERE
		username = $1
	`

	username := c.Param("username")

	var user UserDB
	err := db.Get(&user, query, username)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(404, StandardAPIResponse{
				Err: "Not found!",
			})
			return
		}

		c.JSON(400, StandardAPIResponse{
			Err: err.Error(),
		})
		return
	}

	resp := User{
		Username:   user.UserName.String,
		ProfilePic: user.ProfilePic.String,
		CreatedAt:  user.CreatedAt.UnixNano(),
	}

	c.JSON(200, StandardAPIResponse{
		Err:  "null",
		Data: resp,
	})
}

func updateProfile(c *gin.Context) {
	username := c.Request.FormValue("username")
	profilepic := c.Request.FormValue("imageURL")

	query := `
		UPDATE
			account
		SET 
		    profile_pic = $1
		WHERE
			username = $2
	`

	_, err := db.Exec(query, profilepic, username)
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
	username := c.Request.FormValue("username")
	oldpass := c.Request.FormValue("old_password")
	newpass := c.Request.FormValue("new_password")

	query := `
	SELECT 
		password,
	    salt
	FROM
		account
	WHERE
		username = $1
	`

	var user UserDB
	err := db.Get(&user, query, username)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(400, StandardAPIResponse{
				Err: "Not authorized",
			})
			return
		}

		c.JSON(400, StandardAPIResponse{
			Err: err.Error(),
		})
		return
	}

	oldpass += user.Salt.String
	h := sha256.New()
	h.Write([]byte(oldpass))
	hashedOldPassword := fmt.Sprintf("%x", h.Sum(nil))

	if user.Password.String != hashedOldPassword {
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

	query = `
		UPDATE
			account
		SET 
		    password = $1
		WHERE
			username = $2
	`

	_, err = db.Exec(query, hashedNewPass, username)
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

func createRoom(c *gin.Context) {
	name := c.Request.FormValue("name")
	desc := c.Request.FormValue("desc")
	categoryId := c.Request.FormValue("category_id")
	adminId := c.Request.FormValue("admin_id")

	query := `
		INSERT INTO
			room
		(
			name,
			admin_user_id,
			description,
			category_id,
			created_at
		)
		VALUES
		(
			$1,
			$2,
			$3,
			$4,
			$5
		)
	`

	_, err := db.Exec(query, name, adminId, desc, categoryId, time.Now())
	if err != nil {
		c.JSON(400, StandardAPIResponse{
			Err: err.Error(),
		})
		return
	}

	c.JSON(201, StandardAPIResponse{
		Err:     "null",
		Message: "Success create new room",
	})
}

func joinRoom(c *gin.Context) {
	roomID := c.Request.FormValue("room_id")
	userID := c.Request.FormValue("user_id")

	query := `
		INSERT INTO
			room_participant
		(
			room_id,
			user_id
		)
		VALUES
		(
			$1,
			$2
		)
	`

	_, err := db.Exec(query, roomID, userID)
	if err != nil {
		c.JSON(400, StandardAPIResponse{
			Err: err.Error(),
		})
		return
	}

	c.JSON(201, StandardAPIResponse{
		Err:     "null",
		Message: "Success join to room with ID " + roomID,
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

type User struct {
	Username   string `json:"username"`
	ProfilePic string `json:"profile_pic"`
	CreatedAt  int64  `json:"created_at"`
}

type UserDB struct {
	UserID     sql.NullInt64  `db:"user_id"`
	UserName   sql.NullString `db:"username"`
	ProfilePic sql.NullString `db:"profile_pic"`
	Salt       sql.NullString `db:"salt"`
	Password   sql.NullString `db:"password"`
	CreatedAt  time.Time      `db:"created_at"`
}

//TODO complete all API request
type RoomDB struct {
	RoomID      sql.NullInt64  `db:room_id`
	Name        sql.NullString `db:name`
	Admin       sql.NullInt64  `db:admin_user_id`
	Description sql.NullString `db:description`
	CategoryID  sql.NullInt64  `db:category_id`
	CreatedAt   time.Time      `db:"created_at"`
}

type Room struct {
	RoomID      int64  `json:"room_id"`
	Name        string `json:"name"`
	Admin       int64  `json:"admin"`
	Description string `json:"description"`
}
