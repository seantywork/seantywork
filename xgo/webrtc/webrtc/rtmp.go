package webrtc

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pion/webrtc/v4"
	"github.com/pion/webrtc/v4/pkg/media"
	"github.com/pkg/errors"

	flvtag "github.com/yutopp/go-flv/tag"
	"github.com/yutopp/go-rtmp"
	rtmpmsg "github.com/yutopp/go-rtmp/message"
)

var RTP_RECEIVE_ADDR string = "0.0.0.0"

var RTP_RECEIVE_PORT string

var RTP_CONSUMERS = make(map[string]RTMPWebRTCPeer)

const RTP_HEADER_LENGTH_FIELD = 4

var TEST_KEY string = "foobar"

var UDP_BUFFER_BYTE_SIZE int = 65536

var RECV_STARTED int = 0

type RTMPHandler struct {
	rtmp.DefaultHandler
	PublisherKey string
}

type RTMPWebRTCPeer struct {
	peerConnection *webrtc.PeerConnection
	videoTrack     *webrtc.TrackLocalStaticSample
	audioTrack     *webrtc.TrackLocalStaticSample
}

type CCTVStruct struct {
	Location     string `json:"location"`
	StreamingKey string `json:"streaming_key"`
	Description  string `json:"description"`
}

func RtmpOpen(c *gin.Context) {

	log.Println("incoming rtmp open request")

	peerConnection, err := api.NewPeerConnection(webrtc.Configuration{
		ICEServers: []webrtc.ICEServer{
			{
				URLs:       []string{TURN_SERVER_ADDR[0].Addr},
				Username:   TURN_SERVER_ADDR[0].Id,
				Credential: TURN_SERVER_ADDR[0].Pw,
			},
		},
	})
	if err != nil {
		panic(err)
	}
	/*
		peerConnection.OnICEConnectionStateChange(func(connectionState webrtc.ICEConnectionState) {
			fmt.Printf("Connection State has changed %s \n", connectionState.String())

			if connectionState == webrtc.ICEConnectionStateFailed {
				if closeErr := peerConnection.Close(); closeErr != nil {
					panic(closeErr)
				}
			}
		})
	*/
	videoTrack, err := webrtc.NewTrackLocalStaticSample(webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeH264}, "video", "pion")
	if err != nil {
		panic(err)
	}
	if _, err = peerConnection.AddTrack(videoTrack); err != nil {
		panic(err)
	}

	audioTrack, err := webrtc.NewTrackLocalStaticSample(webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypePCMA}, "audio", "pion")
	if err != nil {
		panic(err)
	}
	if _, err = peerConnection.AddTrack(audioTrack); err != nil {
		panic(err)
	}

	var req CLIENT_REQ

	var offer webrtc.SessionDescription

	if err := c.BindJSON(&req); err != nil {

		panic(err)

	}

	err = json.Unmarshal([]byte(req.Data), &offer)

	if err != nil {

		panic(err)
	}

	if err := peerConnection.SetRemoteDescription(offer); err != nil {
		panic(err)
	}

	gatherComplete := webrtc.GatheringCompletePromise(peerConnection)
	answer, err := peerConnection.CreateAnswer(nil)
	if err != nil {
		panic(err)
	} else if err = peerConnection.SetLocalDescription(answer); err != nil {
		panic(err)
	}
	<-gatherComplete

	streamingKey, err := GetRandomHex(32)

	if err != nil {

		panic(err)
	}

	log.Printf("rtmp key: %s\n", streamingKey)

	RTP_CONSUMERS[streamingKey] = RTMPWebRTCPeer{
		peerConnection: peerConnection,
		videoTrack:     videoTrack,
		audioTrack:     audioTrack,
	}

	desc_b, err := json.Marshal(peerConnection.LocalDescription())

	if err != nil {
		panic(err)
	}

	var resp SERVER_RE

	var cs CCTVStruct

	cs.Location = "rtmp://" + URL + ":" + string(RTP_RECEIVE_PORT) + "/publish/" + streamingKey

	cs.StreamingKey = streamingKey

	cs.Description = string(desc_b)

	cs_b, err := json.Marshal(cs)

	if err != nil {

		panic(err)

	}

	resp.Status = "success"
	resp.Reply = string(cs_b)

	c.JSON(200, resp)

}

func InitRTMPServer() {
	log.Println("starting RTMP Server")

	tcpAddr, err := net.ResolveTCPAddr("tcp", RTP_RECEIVE_ADDR+":"+RTP_RECEIVE_PORT)
	if err != nil {
		log.Panicf("Failed: %+v", err)
	}

	listener, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		log.Panicf("Failed: %+v", err)
	}

	srv := rtmp.NewServer(&rtmp.ServerConfig{
		OnConnect: func(conn net.Conn) (io.ReadWriteCloser, *rtmp.ConnConfig) {
			return conn, &rtmp.ConnConfig{
				Handler: &RTMPHandler{},

				ControlState: rtmp.StreamControlStateConfig{
					DefaultBandwidthWindowSize: 6 * 1024 * 1024 / 8,
				},
			}
		},
	})
	if err := srv.Serve(listener); err != nil {
		log.Panicf("Failed: %+v", err)
	}
}

func (h *RTMPHandler) OnServe(conn *rtmp.Conn) {
}

func (h *RTMPHandler) OnConnect(timestamp uint32, cmd *rtmpmsg.NetConnectionConnect) error {
	log.Printf("OnConnect: %#v", cmd)
	return nil
}

func (h *RTMPHandler) OnCreateStream(timestamp uint32, cmd *rtmpmsg.NetConnectionCreateStream) error {
	log.Printf("OnCreateStream: %#v", cmd)
	return nil
}

func (h *RTMPHandler) OnPublish(ctx *rtmp.StreamContext, timestamp uint32, cmd *rtmpmsg.NetStreamPublish) error {
	log.Printf("OnPublish: %#v", cmd)

	if cmd.PublishingName == "" {

		log.Printf("publishing name is empty")

		return errors.New("publishing name is empty")
	}

	_, okay := RTP_CONSUMERS[cmd.PublishingName]

	if !okay {

		log.Printf("publishing name doesn't exist")

		return errors.New("publishing name doesn't exist")

	}

	h.PublisherKey = cmd.PublishingName

	return nil
}

func (h *RTMPHandler) OnAudio(timestamp uint32, payload io.Reader) error {
	var audio flvtag.AudioData

	consumer, okay := RTP_CONSUMERS[h.PublisherKey]

	if !okay {

		return fmt.Errorf("invalid publisher")

	}

	consumerAudioTrack := consumer.audioTrack

	if err := flvtag.DecodeAudioData(payload, &audio); err != nil {
		return err
	}

	data := new(bytes.Buffer)
	if _, err := io.Copy(data, audio.Data); err != nil {
		return err
	}

	return consumerAudioTrack.WriteSample(media.Sample{
		Data:     data.Bytes(),
		Duration: 128 * time.Millisecond,
	})
}

func (h *RTMPHandler) OnVideo(timestamp uint32, payload io.Reader) error {
	var video flvtag.VideoData

	consumer, okay := RTP_CONSUMERS[h.PublisherKey]

	if !okay {

		return fmt.Errorf("invalid publisher")

	}

	consumerVideoTrack := consumer.videoTrack

	if err := flvtag.DecodeVideoData(payload, &video); err != nil {
		return err
	}

	data := new(bytes.Buffer)
	if _, err := io.Copy(data, video.Data); err != nil {
		return err
	}

	outBuf := []byte{}
	videoBuffer := data.Bytes()
	for offset := 0; offset < len(videoBuffer); {
		bufferLength := int(binary.BigEndian.Uint32(videoBuffer[offset : offset+RTP_HEADER_LENGTH_FIELD]))
		if offset+bufferLength >= len(videoBuffer) {
			break
		}

		offset += RTP_HEADER_LENGTH_FIELD
		outBuf = append(outBuf, []byte{0x00, 0x00, 0x00, 0x01}...)
		outBuf = append(outBuf, videoBuffer[offset:offset+bufferLength]...)

		offset += int(bufferLength)
	}

	return consumerVideoTrack.WriteSample(media.Sample{
		Data:     outBuf,
		Duration: time.Second / 30,
	})
}

func (h *RTMPHandler) OnClose() {
	log.Printf("OnClose")
}
