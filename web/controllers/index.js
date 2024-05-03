



function PostTest(req, res, next){

    let recvMsg = req.body.msg;

    let retJson = {
        "msg":"hello",
        "recv_msg":recvMsg,
    };

    res.send(retJson);

}








module.exports = {

    PostTest: PostTest

}