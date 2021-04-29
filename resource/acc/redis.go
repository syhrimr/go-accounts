package acc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/lolmourne/go-accounts/model"
)

func (dbr *RedisResource) Register(username string, password string, salt string) error {
	return dbr.next.Register(username, password, salt)
}

func (dbr *RedisResource) GetUserByUserID(userID int64) (model.User, error) {
	val, err := dbr.rdb.Get(context.Background(), fmt.Sprintf("user:%d", userID)).Result()
	if err != nil {
		usr, err := dbr.next.GetUserByUserID(userID)
		if err != nil {
			return model.User{}, errors.New("User not found")
		}
		usrJSON, err := json.Marshal(usr)
		if err != nil {
			return model.User{}, errors.New("Fail to marshall")
		}
		stats := dbr.rdb.Set(context.Background(), fmt.Sprintf("user:%d", userID), usrJSON, time.Duration(0))
		log.Println(stats.Result())

		return usr, err
	}

	var user model.User
	json.Unmarshal([]byte(val), &user)

	return user, nil
}

func (dbr *RedisResource) GetUserByUserName(userName string) (model.User, error) {
	return dbr.next.GetUserByUserName(userName)
}

func (dbr *RedisResource) UpdatePhotoProfile(userID int64, profilePic string) error {
	return dbr.next.UpdatePhotoProfile(userID, profilePic)
}

func (dbr *RedisResource) UpdateUserPassword(userID int64, password string) error {
	return dbr.next.UpdateUserPassword(userID, password)
}

func (dbr *RedisResource) UpdateUserName(userID int64, username string) error {
	return dbr.next.UpdateUserName(userID, username)
}
