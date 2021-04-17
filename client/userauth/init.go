package userauth

import (
	"time"
)

type AuthClient struct {
	host    string
	timeout time.Duration
}

type User struct {
	UserID     int64     `json:"user_id"`
	Username   string    `json:"username"`
	CreatedAt  time.Time `json:"created_at"`
	ProfilePic string    `json:"profile_pic"`
}

type ClientItf interface {
	GetUserInfo(accessToken string) *User
}

func NewClient(host string, timeout time.Duration) ClientItf {
	return &AuthClient{
		host:    host,
		timeout: timeout,
	}
}
