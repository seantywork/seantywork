let wsindex = require('./wsockets') 

module.exports = function(wsio) {

    // maybe for later use?
    // wsio.adapter(redis({host: config.socket_host.host, port: 6379}));

    wsio.on('connection', function (socket) {
        
        console.log(socket.id, 'Connected');
    
        if(socket.id != ''){
            let data = {'conn': true, 'socketId': socket.id};
            socket.emit('msg', data);
            // socket.leave(socket.id);    
        }
    
        socket.on('disconnect', function(){
            console.log('socket disconnect : ', socket.id);
        });
    
        socket.on('leave', function(data){

            socket.leave(socket.id);

            console.log('socket leave : ', socket.id);
        
            console.log(data);

            socket.disconnect();
        });
    });



}
