package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/gin-gonic/contrib/sessions"
	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"

	"0xgo/webrtc/webrtc"
)

type Config struct {
	TurnServerAddr []struct {
		Addr string `yaml:"addr"`
		Id   string `yaml:"id"`
		Pw   string `yaml:"pw"`
	} `yaml:"turnServerAddr"`
	Rooms []struct {
		Key     string   `yaml:"key"`
		Members []string `yaml:"members"`
	} `yaml:"rooms"`
	Url                   string `yaml:"url"`
	SignalPort            int    `yaml:"signalPort"`
	RtpReceivePort        int    `yaml:"rtpReceivePort"`
	PeerSignalAttemptSync int    `yaml:"peerSignalAttemptSync"`
	PeerSignalAddr        string `yaml:"peerSignalAddr"`
	RtcpPLIInterval       int    `yaml:"rtcpPLIInterval"`
	UdpMuxPort            int    `yaml:"udpMuxPort"`
	UdpEphemeralPortMin   int    `yaml:"udpEphemeralPortMin"`
	UdpEphemeralPortMax   int    `yaml:"udpEphemeralPortMax"`
}

func GetIndex(c *gin.Context) {

	c.HTML(200, "index.html", gin.H{})

}

func main() {

	file_b, err := os.ReadFile("config.yaml")

	if err != nil {

		log.Printf("failed to read config.yaml: %v", err)

		os.Exit(-1)
	}

	conf := Config{}

	err = yaml.Unmarshal(file_b, &conf)

	if err != nil {
		log.Printf("failed to unmarshal: %v\n", err)

		os.Exit(-1)
	}

	turnlen := len(conf.TurnServerAddr)

	for i := 0; i < turnlen; i++ {

		addr := struct {
			Addr string `json:"addr"`
			Id   string `json:"id"`
			Pw   string `json:"pw"`
		}{}

		addr.Addr = conf.TurnServerAddr[i].Addr
		addr.Id = conf.TurnServerAddr[i].Id
		addr.Pw = conf.TurnServerAddr[i].Pw

		webrtc.TURN_SERVER_ADDR = append(webrtc.TURN_SERVER_ADDR, addr)

	}

	roomlen := len(conf.Rooms)

	for i := 0; i < roomlen; i++ {

		pc := webrtc.PeersCreate{}

		pc.RoomName = conf.Rooms[i].Key

		pc.Users = conf.Rooms[i].Members

		webrtc.CreatePeers(&pc)

	}

	webrtc.URL = conf.Url
	webrtc.CHANNEL_PORT = fmt.Sprintf("%d", conf.SignalPort)
	webrtc.RTP_RECEIVE_PORT = fmt.Sprintf("%d", conf.RtpReceivePort)
	webrtc.PEER_SIGNAL_ATTEMPT_SYNC = conf.PeerSignalAttemptSync
	webrtc.PEERS_SIGNAL_PATH = conf.PeerSignalAddr
	webrtc.RTCP_PLI_INTERVAL = time.Second * time.Duration(conf.RtcpPLIInterval)
	webrtc.UDP_MUX_PORT = conf.UdpMuxPort
	webrtc.UDP_EPHEMERAL_PORT_MIN = conf.UdpEphemeralPortMin
	webrtc.UDP_EPHEMERAL_PORT_MAX = conf.UdpEphemeralPortMax

	webrtc.InitWebRTCApi()

	server := gin.Default()

	store := sessions.NewCookieStore([]byte("WEBRTC"))

	server.Use(sessions.Sessions("WEBRTC", store))

	server.LoadHTMLGlob("view/*")

	server.Static("/public", "./public")

	server.GET("/", GetIndex)

	server.GET("/rtmp", webrtc.GetRtmp)

	server.POST("/api/rtmp/open", webrtc.RtmpOpen)

	server.GET("/room/:roomId/:userId", webrtc.GetRoom)

	server.GET("/api/peers/signal/address", webrtc.GetPeersSignalAddress)

	go webrtc.InitRTMPServer()

	webrtc.AddChannelHandler(conf.PeerSignalAddr, webrtc.RoomSignalHandler)

	webrtc.AddChannelCallback(webrtc.SignalDispatcher)

	go webrtc.StartAllChannelHandlers()

	server.Run("0.0.0.0:8000")
}
