pc = {}

ws = {}



TURN_SERVER_ADDRESS = {}


STREAMING_KEY = ""

CLIENT_REQ = {
    "data":""
}

SERVER_RE = {
    "status": "",
    "reply": ""
}



RTMP_STRUCT = {

    "streaming_key":"",
    "description": ""

}



async function initRTMP(){


    pc = new RTCPeerConnection({
//        iceServers: [
//            {
//                urls: TURN_SERVER_ADDRESS.addr,
//                username: TURN_SERVER_ADDRESS.id,
//                credential: TURN_SERVER_ADDRESS.pw
//            }
//        ]
    })

    pc.oniceconnectionstatechange = function(e) {console.log(pc.iceConnectionState)}

    pc.onicecandidate = async function(event){

        if (event.candidate === null){


            let req = {
                data: JSON.stringify(pc.localDescription)
            }

            let options = {
                method: "POST",
                headers: {
                  "Content-Type": "application/json" 
                },
                body: JSON.stringify(req) 
            }

            let resp = await fetch("/api/rtmp/open", options)

            let data = await resp.json()

            if (data.status != "success") {

                alert("failed to start cctv offer")
            }
            try {
            
                cs = JSON.parse(data.reply)

                console.log(cs)

                let remoteDesc = JSON.parse(cs.description)
                
                pc.setRemoteDescription(new RTCSessionDescription(remoteDesc))
            
                STREAMING_KEY = cs.streaming_key

                alert("streaming address: " + cs.location)
                
            
            } catch (e){

                alert(e)
            }

        }


    }

    pc.ontrack = function (event) {

        var el = document.createElement(event.track.kind)
        el.srcObject = event.streams[0]
        el.autoplay = true
        el.controls = true

        document.getElementById('cctv-reader').appendChild(el)

    }

    pc.addTransceiver('video')
    pc.addTransceiver('audio')
    
    let offer = await pc.createOffer()

    pc.setLocalDescription(offer)

    console.log("init success")

}








