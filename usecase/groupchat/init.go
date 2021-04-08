package groupchat

import (
	"github.com/lolmourne/go-accounts/model"
	"github.com/lolmourne/go-accounts/resource/groupchat"
)

type UseCase struct {
	dbRoomRsc  groupchat.DBItf
	signingKey []byte
}

type UsecaseItf interface {
	CreateGroupchat(name, adminID, desc, categoryID string) (model.Room, error)
	EditGroupchat(name, desc, categoryID string) (model.Room, error)
	JoinRoom(roomID, userID int64) error
}

func NewUseCase(dbRsc groupchat.DBItf, signingKey string) UsecaseItf {
	return UseCase{
		dbRoomRsc:  dbRsc,
		signingKey: []byte(signingKey),
	}

}
