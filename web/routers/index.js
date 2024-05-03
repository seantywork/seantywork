let express = require('express');
let ctrlindex = require('../controllers');

module.exports = function () {

    let router = express.Router();
    
    router.post('/test', ctrlindex.PostTest);

    return router;
};


