package userauth

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"log"
	"math/rand"

	jwt "github.com/dgrijalva/jwt-go"
)

func (u *Usecase) Register(username, password, confirmPassword string) error {
	if confirmPassword != password {
		return errors.New("confirm password is mismatched")
	}

	salt := RandStringBytes(32)
	password += salt

	h := sha256.New()
	h.Write([]byte(password))
	password = fmt.Sprintf("%x", h.Sum(nil))

	err := u.dbRsc.Register(username, password, salt)
	if err != nil {
		return err
	}

	return nil
}

func (u *Usecase) Login(username, password string) (string, error) {
	user, err := u.dbRsc.GetUserByUserName(username)
	if err != nil {
		return "", errors.New("user not found or password is incorrect")
	}

	password += user.Salt
	h := sha256.New()
	h.Write([]byte(password))
	hashedPassword := fmt.Sprintf("%x", h.Sum(nil))

	if user.Password != hashedPassword {
		return "", errors.New("user not found or password is incorrect")
	}

	user.Password = ""
	user.Salt = ""

	if user.ProfilePic == "" {
		user.ProfilePic = "https://i.imgur.com/cINvch3.png"
	}

	token := jwt.New(jwt.GetSigningMethod("HS256"))
	tokenClaim := jwt.MapClaims{}
	tokenClaim["user_id"] = user.UserID
	tokenClaim["profile_pic"] = user.ProfilePic
	token.Claims = tokenClaim

	tokenString, err := token.SignedString(u.signingKey)
	if err != nil {
		log.Println(err)
		return "", errors.New("internal server error")
	}
	return tokenString, nil
}

func (u *Usecase) ValidateSession(accessToken string) (int64, error) {
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(accessToken, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return u.signingKey, nil
	})

	if err != nil {
		return 0, errors.New("invalid token")
	}

	userID := int64(claims["user_id"].(float64))
	return userID, nil
}

func (u *Usecase) ChangeUsername(userID int64, username string) error {
	userInfo, err := u.dbRsc.GetUserByUserID(userID)
	if err != nil {
		return err
	}
	
	if username == "" {
		return errors.New("new username cannot be empty")
	}

	if username == userInfo.Username {
		return errors.New("new username cannot be the same as old one")
	}

	err = u.dbRsc.UpdateUserName(userID, username)
	if err != nil {
		return err
	}

	return nil
}

func (u *Usecase) ChangePassword(userID int64, oldPassword, newPassword, confirmPassword string) error {
	user, err := u.dbRsc.GetUserByUserID(userID)
	if err != nil {
		return err
	}

	oldPassword += user.Salt
	h := sha256.New()
	h.Write([]byte(oldPassword))
	hashedOldPassword := fmt.Sprintf("%x", h.Sum(nil))

	if user.Password != hashedOldPassword {
		return errors.New("old password is wrong")
	}

	if confirmPassword != newPassword {
		return errors.New("confirm password is not matched")
	}

	// change to new password
	salt := RandStringBytes(32)
	newPassword += salt

	h = sha256.New()
	h.Write([]byte(newPassword))
	hashedNewPass := fmt.Sprintf("%x", h.Sum(nil))

	err = u.dbRsc.UpdateUserPassword(userID, hashedNewPass)
	if err != nil {
		return err
	}

	return nil
}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func RandStringBytes(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}
