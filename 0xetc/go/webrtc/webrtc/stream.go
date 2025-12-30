package webrtc

import (
	"log"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pion/ice/v3"
	"github.com/pion/webrtc/v4"
)

var DEBUG bool = false

var RTCP_PLI_INTERVAL time.Duration

var UDP_MUX_PORT int

var UDP_EPHEMERAL_PORT_MIN int

var UDP_EPHEMERAL_PORT_MAX int

var TIMEOUT_SEC int = 30

var TURN_SERVER_ADDR []struct {
	Addr string `json:"addr"`
	Id   string `json:"id"`
	Pw   string `json:"pw"`
}

var api *webrtc.API

type SIGNAL_INFO struct {
	Command string `json:"command"`
	Status  string `json:"status"`
	Data    string `json:"data"`
}

var UPGRADER = websocket.Upgrader{}

var roomPeerConnections = make(map[string][]peerConnectionState)

var roomTrackLocals = make(map[string]map[string]*webrtc.TrackLocalStaticRTP)

type peerConnectionState struct {
	peerConnection *webrtc.PeerConnection
	websocket      *ThreadSafeWriter
}

func InitWebRTCApi() {

	settingEngine := webrtc.SettingEngine{}

	var filterFunc func(string) bool = func(ifname string) bool {

		if strings.HasPrefix(ifname, "br-") {

			return false
		} else if strings.HasPrefix(ifname, "vir") {

			return false
		} else if strings.HasPrefix(ifname, "docker") {

			return false
		}

		return true

	}

	ifaceFilter := ice.UDPMuxFromPortWithInterfaceFilter(filterFunc)
	mux, err := ice.NewMultiUDPMuxFromPort(UDP_MUX_PORT, ifaceFilter)

	log.Println("creating webrtc api")

	settingEngine.SetICEUDPMux(mux)
	if err != nil {
		panic(err)
	}

	log.Println("created webrtc api")

	settingEngine.SetEphemeralUDPPortRange(uint16(UDP_EPHEMERAL_PORT_MIN), uint16(UDP_EPHEMERAL_PORT_MAX))

	api = webrtc.NewAPI(webrtc.WithSettingEngine(settingEngine))

}

func SignalDispatcher() {

	for range time.NewTicker(time.Second * RTCP_PLI_INTERVAL).C {

		for k, _ := range roomPeerConnections {

			dispatchKeyFrame(k)
		}

	}
}

func addTrack(k string, t *webrtc.TrackRemote) *webrtc.TrackLocalStaticRTP {
	ListLock.Lock()
	defer func() {
		ListLock.Unlock()
		signalPeerConnections(k)
	}()

	trackLocal, err := webrtc.NewTrackLocalStaticRTP(t.Codec().RTPCodecCapability, t.ID(), t.StreamID())
	if err != nil {
		panic(err)
	}

	if roomTrackLocals[k] == nil {
		roomTrackLocals[k] = make(map[string]*webrtc.TrackLocalStaticRTP)
	}

	roomTrackLocals[k][t.ID()] = trackLocal
	return trackLocal
}

func removeTrack(k string, t *webrtc.TrackLocalStaticRTP) {
	ListLock.Lock()
	defer func() {
		ListLock.Unlock()
		signalPeerConnections(k)
	}()

	delete(roomTrackLocals, k)
}
