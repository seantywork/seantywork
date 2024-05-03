
let wsio = require("socket.io-client");




let socket = wsio("http://127.0.0.1:3000");


socket.on('msg', async function (data){

    console.log(data);

    console.log("wait 5 seconds before leave...");

    console.log("hit Ctrl + C to disconnect ");

    await sleep(5000);

    socket.emit("leave", {"msg":"bye"});

});


function sleep(ms) {
    return new Promise((resolve) => {
      setTimeout(resolve, ms);
    });
  }