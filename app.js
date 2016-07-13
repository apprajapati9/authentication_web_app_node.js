
var bodyParser = require('body-parser');
var mongoose = require('mongoose');
var sessions = require('client-sessions');
var bcrypt = require('bcryptjs');
var tokens = require('csurf');
//including express package.
var express = require('express');

//Import schema 
var Schema = mongoose.Schema;
var objectId = Schema.ObjectId;


//Connect to database
mongoose.connect('mongodb://localhost/auth');

var User = mongoose.model('User', new Schema({
    id: objectId,
    firstName: String,
    lastName: String,
    email: { type: String, unique: true },
    password: String,
}));



//firing up express app.
var app = express();

//Telling the web server to look for jade file for rendering web page. 
app.set('view engine', 'jade');
app.use(express.static('./public'));
app.locals.pretty = true;
app.use(bodyParser.urlencoded({ extended: true }));

app.use(sessions({
    //name of cookie to use in our web application
    cookieName : 'session',
    //this string will be used by the application to 
    // encrypt or decrypt the information stored in cookie
    secret : 'iw090909jo32032re2e2e2e32e23ee23',
    //amount of milliseconds ! expiry duration
    duration : 30*60*1000,
    //min active duration.
    activeDuration : 5*6*1000,
     
}));
app.use(tokens());
//This is going to run everytime user visits any page
app.use(function(req, res, next){

    if(req.session && req.session.user){
        User.findOne({email: req.session.user.email}, function(err, user) {
            
            if(user){
                //setting up the user variable to req.
                req.user = user; 
                //deleting the password from session  
                delete req.user.password;
                //refresh the session value
                req.session.user = user;
                //making the user available for the dashboard 
                res.locals.user = user;
            }
            next();
        });
    }else{
        next();
    }

});

function requiredLogin(req, res, next){

    if(!req.user){
        res.redirect('/login');
    }else{
        next();
    }

}



// ----------> ALL GET REQUESTS ----------------//

//basic route  localhost:3000/ = index.jade
// this will tell to open index.jade file when localhost is opened. 
app.get('/', function (req, res) {
    res.render('index.jade');
});

//triggers when typed - localhost:3000/register
// tells server to render register.jade file
app.get('/register',function (req, res) {
    res.render('register.jade', {csrfToken : req.csrfToken()});
});

//localhost:3000/login 
// tells server to open login page 
app.get('/login',  function (req, res) {
    if(req.session && req.session.user){
        res.redirect('dashboard');     
    }else{
res.render('login.jade',{csrfToken : req.csrfToken()});
    }
    
});

//localhost:3000/dashboard
// tells server to render dashboard.js
app.get('/dashboard',requiredLogin,  function (req, res) {
    //if user exits in session 
    // if(req.session && req.session.user){
    //    //if yes! then extract the email from session and compare it to database
    //     User.findOne({email : req.session.user.email}, function(err, user){
    //         if(!user){
    //             req.session.reset();
    //             res.redirect('/login');
    //         }
    //         else{
    //             //if user match with sessions email and database's email then 
    //             //set to local variable so we can render the data in jade 
    //             res.locals.user = user;
    //             res.render('dashboard.jade');
    //         }
    //     });
    // }else{
    //     res.redirect('/login');  
    // }
    res.render('dashboard.jade');
});

//if logout , redirect to Home page
app.get('/logout', function (req, res) {
    req.session.reset();
    res.redirect('/');
});

// ----------> ALL GET REQUESTS ----------------//

app.post('/register', function (req, res) {
    //generating password hash of what user sent us!
    var hashPassword = bcrypt.hashSync(req.body.password, bcrypt.genSaltSync(10));

    //getting the user's information from body parser 
    var currentUser = new User({
        firstName: req.body.firstName,
        lastName: req.body.lastName,
        email: req.body.email,
        //storing the hashed password instead of storing plain text into the database!
        password: hashPassword,
    });
    currentUser.save(function (err) {

        if (err) {
            var error = 'Something went Wrong! Try again';
            if (err.code === 11000) {
                error = 'This email is already taken! Try another!';
            }
            res.render('register.jade', { error: error });
        }
        else {
            res.redirect('/dashboard');
        }
    });
});

app.post('/login', function (req, res) {

    //User object contains all the users from MongoDb
    //findOne( match value, function(err, user_Returned))
    // we are passing email that we got from body parser 
    // req.body.email is the name specified in login.jade with name - email.
    // it will fetch its value and find one with that email.
    User.findOne({ email: req.body.email }, function (err, user) {

        //if user doesn't exist then Invalid Error
        if (!user) {
            res.render('login.jade', { error: 'Invalid Email Address or Password' });
        }
        //if user exists check for password
        else {
            //if email exists, then match with password entered 
            // got the password entered by user using body parser req.body.password
            if (bcrypt.compareSync(req.body.password, user.password)) {
                //passing the object to session cookie! 
                //when user is logged in, that user is passed to session's user
                // this will set the set-cookie header in http request 
                // cookie will be named session and it will have data of user object retrieved!
                // currently if user is valid then store in cookie all infor of user
                req.session.user = user; 
                res.redirect('/dashboard');
            }
            //if password doesn't match, redirect to loing page!
            else {
                res.render('login.jade', { error: 'Invalid Email Address or Password' });
            } 
        }
    });
});


//finally listen on port 3000 
app.listen(3000);