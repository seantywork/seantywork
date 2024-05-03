let axios = require("axios");

let testVal = {"msg":"hi"}


axios.post("http://127.0.0.1:3000/test",testVal)
    .then(function (resp){

        console.log(resp.data);

    })
    .catch(function (err){

        console.log(err);
    });




