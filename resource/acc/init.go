package acc

import (
	"github.com/go-redis/redis/v8"
	"github.com/jmoiron/sqlx"
	"github.com/lolmourne/go-accounts/model"
)

type RedisResource struct {
	rdb  *redis.Client
	next DBItf
}

type DBResource struct {
	db *sqlx.DB
}

type DBItf interface {
	Register(username string, password string, salt string) error
	GetUserByUserID(userID int64) (model.User, error)
	GetUserByUserName(userName string) (model.User, error)
	UpdatePhotoProfile(userID int64, profilePic string) error
	UpdateUserName(userID int64, username string) error
	UpdateUserPassword(userID int64, password string) error
}

func NewRedisResource(rdb *redis.Client, next DBItf) DBItf {
	return &RedisResource{
		rdb:  rdb,
		next: next,
	}
}

func NewDBResource(dbParam *sqlx.DB) DBItf {
	return &DBResource{
		db: dbParam,
	}
}
