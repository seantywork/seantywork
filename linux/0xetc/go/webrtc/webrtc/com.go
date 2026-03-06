package webrtc

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

type CLIENT_REQ struct {
	Data string `json:"data"`
}

type SERVER_RE struct {
	Status string `json:"status"`
	Reply  string `json:"reply"`
}

type RT_REQ_DATA struct {
	Command string `json:"command"`
	Data    string `json:"data"`
}

type RT_RESP_DATA struct {
	Status string `json:"status"`
	Data   string `json:"data"`
}

var CHANNEL_ADDR string = "0.0.0.0"

var CHANNEL_PORT string

var USER_CHANNEL = make(map[string]*websocket.Conn)

var CH_CALLBACKS []func()

var ListLock sync.RWMutex

type ThreadSafeWriter struct {
	*websocket.Conn
	sync.Mutex
}

func GetRtmp(c *gin.Context) {

	c.HTML(200, "rtmp.html", gin.H{})
}

func GetRoom(c *gin.Context) {

	roomId := c.Param("roomId")

	userId := c.Param("userId")

	p_users, okay := ROOMREG[roomId]

	if !okay {
		fmt.Printf("view room: no such room\n")

		c.JSON(http.StatusForbidden, SERVER_RE{Status: "error", Reply: "not allowed"})

		return
	}

	pu_len := len(p_users)

	allowed := 0

	user_index := -1

	for i := 0; i < pu_len; i++ {

		if p_users[i].User == userId {

			allowed = 1

			user_index = i

			break
		}

	}

	if allowed != 1 {

		fmt.Printf("view room: user not allowed\n")

		c.JSON(http.StatusForbidden, SERVER_RE{Status: "error", Reply: "not allowed"})

		return

	}

	var pj PeersJoin

	pj.RoomName = roomId
	pj.User = p_users[user_index].User
	pj.UserKey = p_users[user_index].UserKey

	jb, err := json.Marshal(pj)

	if err != nil {

		fmt.Printf("view room: marshal\n")

		c.JSON(http.StatusInternalServerError, SERVER_RE{Status: "error", Reply: "failed to get room"})

		return

	}

	c.HTML(200, "room.html", gin.H{
		"room_code": string(jb),
	})

}

func (t *ThreadSafeWriter) WriteJSON(v interface{}) error {
	t.Lock()
	defer t.Unlock()

	return t.Conn.WriteJSON(v)
}

func AddChannelHandler(channelPath string, channelHandler func(w http.ResponseWriter, r *http.Request)) {

	http.HandleFunc(channelPath, channelHandler)

}

func AddChannelCallback(channelFunction func()) {

	CH_CALLBACKS = append(CH_CALLBACKS, channelFunction)
}

func StartAllChannelHandlers() {

	callback_count := len(CH_CALLBACKS)

	for i := 0; i < callback_count; i++ {

		go CH_CALLBACKS[i]()

	}

	channel_addr := CHANNEL_ADDR + ":" + CHANNEL_PORT

	log.Fatal(http.ListenAndServe(channel_addr, nil))

}
