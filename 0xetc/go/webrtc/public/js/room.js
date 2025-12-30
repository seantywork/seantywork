

pc = {}
ws = {}

PEERS_SIGNAL_ADDRESS = ""

TURN_SERVER_ADDRESS= {}

ICE_SENT = 0

MESSAGE_FORMAT = {

    command: "",
    data: ""

}

async function initPeers(){



    let roomInfo = JSON.stringify(ROOM_INFO)

    if(roomInfo == ""){

        alert("no room info provided")

        return
    }

    await init()



    navigator.mediaDevices.getUserMedia({ video: true, audio: true })
        .then(function(stream){

            pc = new RTCPeerConnection({
//                        iceServers: [
//                            {
//                                urls: TURN_SERVER_ADDRESS.addr,
//                                username: TURN_SERVER_ADDRESS.id,
//                                credential: TURN_SERVER_ADDRESS.pw
//                            }
//                        ]
                    })
                
            document.getElementById('localVideo').srcObject = stream
            stream.getTracks().forEach(function(track) {pc.addTrack(track, stream)})
        
            if (location.protocol !== 'https:') {

                ws = new WebSocket("ws://" + PEERS_SIGNAL_ADDRESS + ROOM_INFO.room_name)
        
            } else {
        
                ws = new WebSocket("wss://" + PEERS_SIGNAL_ADDRESS + ROOM_INFO.room_name)
        
        
            }

            ws.onopen = function(evt){

                ws.send(JSON.stringify({command: 'auth', data: roomInfo}))

            }
            
            ws.onclose = function(evt) {
                alert("Websocket has closed")
            }
        
            ws.onmessage = function(evt) {
                let msg = JSON.parse(evt.data)
        
                if (!msg) {
                    return console.log('failed to parse msg')
                }
        
        
                switch (msg.command) {
                    case 'offer':
                    let offer = JSON.parse(atob(msg.data))
                    if (!offer) {
                        return console.log('failed to parse answer')
                    }
                    
                    console.log("got offer")

                    pc.setRemoteDescription(offer)
                    pc.createAnswer().then(function(answer) {
                        pc.setLocalDescription(answer)
                        ws.send(JSON.stringify({command: 'answer', data: btoa(JSON.stringify(answer))}))
                    })

                    console.log("sent answer")

                    return
        
                    case 'candidate':
                    
                    console.log("got candidate")

                    let candidate = JSON.parse(atob(msg.data))
                    if (!candidate) {
                        return console.log('failed to parse candidate')
                    }

                    pc.addIceCandidate(candidate)

                    console.log("added candidate")

                    return

                    case 'chat':
                    
                    let chatData = msg.data

                    let chatMessage = JSON.parse(chatData) 

                    document.getElementById("chat-reader").innerText += `<${chatMessage.user}> ${chatMessage.message} \n`

                    return
                }
            }

            ws.onerror = function(evt) {
                console.log("ERROR: " + evt.data)
            }

            pc.ontrack = function (event) {
                if (event.track.kind === 'audio') {
                    return
                }
        
                let el = document.createElement(event.track.kind)
                el.srcObject = event.streams[0]
                el.autoplay = true
                el.controls = true
                document.getElementById('remoteVideos').appendChild(el)
        
                event.track.onmute = function(event) {
                    el.play()
                }
                
                event.streams[0].onremovetrack = function({track}) {

                    if (el.parentNode) {
                        el.parentNode.removeChild(el)
                    }
                }
            }
        
        
            pc.onicecandidate = function(e){
                
                if (!e.candidate) {
        
                    console.log("not a candidate")
        
                    return
                }
        
 
                ws.send(JSON.stringify({command: 'candidate', data: btoa(JSON.stringify(e.candidate))}))
                console.log("sent ice candidate")


            }
                
        
        
            console.log("opened peer connection ready")

        })
        .catch(function(e){

            alert(e)
        })



}

function sendChat(){

    let chatConent = document.getElementById("chat-sender").value

    document.getElementById("chat-sender").value = ""

    let req = JSON.parse(JSON.stringify(MESSAGE_FORMAT))

    req.command = "chat"
    req.data = chatConent

    ws.send(JSON.stringify(req))

}


async function init(){

    let options = {
        method: "GET"
    }
    let result = await fetch("/api/peers/signal/address", options)

    let data = await result.json()

    if(data.status != "success"){

        alert("failed to get peers signal address")

        return
    }


    PEERS_SIGNAL_ADDRESS = data.reply 

    console.log("peersSignalAddr: " + PEERS_SIGNAL_ADDRESS + ROOM_INFO.room_name)


    console.log("opened channel for peer signal")

}


(async function (){

    await initPeers()

})()