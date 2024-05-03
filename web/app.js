let createrror = require('http-errors');
let express = require('express');
let path = require('path');
let cookieparser = require('cookie-parser');
let logger = require('morgan');


let rtindex = require('./routers/index');

let app = express();

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'jade');

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieparser());
app.use(express.static(path.join(__dirname, 'public')));

app.use('/', rtindex());

/*

	TODO: 
		1. how do we mangage sessions?
		2. what DB are we going to use?

*/

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  next(createrror(404));
});

// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});

module.exports = app;