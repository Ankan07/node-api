var mongoose=require('mongoose');
var validator=require('validator');
var a=require('lodash');
var bcrypt=require('bcryptjs');

const jwt=require('jsonwebtoken');
const express=require('express');
var app=express();
const bodyParser = require('body-parser');
app.use(bodyParser.json());

mongoose.Promise=global.Promise;
mongoose.connect('mongodb://localhost:27017/TodoApp');


var UserSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    trim: true,
    minlength: 1,
    unique: true,
    validate: {
      validator: validator.isEmail,
      message: '{VALUE} is not a valid email'
    }
  },
  password: {
    type: String,
    require: true,
    minlength: 6
  },
  tokens: [{
    access: {
      type: String,
      required: true
    },
    token: {
      type: String,
      required: true
    }
  }]
});
UserSchema.methods.generateAuthToken = function () {
  var user = this;
  var access = 'auth';
  var token = jwt.sign({_id: user._id.toHexString(), access}, 'abc123').toString();

  user.tokens.push({access, token});

  return user.save().then(() => {
    return token;
  });
};

UserSchema.statics.findByToken = function (token) {
  var User = this;
  var decoded;

  try {
    decoded = jwt.verify(token, 'abc123');
  } catch (e) {
    return Promise.reject();
  }

  return User.findOne({
    '_id': decoded._id,
    'tokens.token': token,
    'tokens.access': 'auth'
  });
};
UserSchema.statics.findByCredentials= function(email,password){
  var User=this;

  return User.findOne({email}).then((user)=>{
    if(!user){
    return  Promise.reject();
    }
    return new Promise((resolve,reject)=>{

bcrypt.compare(password,user.password,(err,res)=>{
  if(res){
    resolve(user);
  }
  else{
    reject();
  }
});
    });

  });

};
UserSchema.pre('save',function(next){
  var user=this;
  if(user.isModified('password')){
bcrypt.genSalt(10,(err,salt)=>{
  bcrypt.hash(user.password,salt,(err,hash)=>{
    user.password=hash;
    next();
  });
});

  }else {
    next();
  }
});
var User = mongoose.model('User', UserSchema);

app.post('/users', (req, res) => {
  var body = a.pick(req.body, ['email', 'password']);
  var user = new User(body);

  user.save().then(() => {
    return user.generateAuthToken();

  }).then((token) => {
    res.header('x-auth', token).send(user);
  }).catch((e) => {
    console.log(e);
    res.status(400).send(e);
  })
});
app.post('/users/login',(req,res)=>{
  var body = a.pick(req.body, ['email', 'password']);
  // res.send(body);
  User.findByCredentials(body.email,body.password).then((user)=>{
    // res.send(user);

user.generateAuthToken().then((token)=>{
res.header('x-auth', token).send(user);

});

  }).catch((e)=>{
    res.status(400).send();

  });
});

app.get('/users/me',(req,res)=>{
  var token=req.header('x-auth');
  User.findByToken(token).then((user)=>{
    if(!user){
      return Promise.reject();
    }
    res.send(user);

  }).catch((e)=>{
    res.status(401).send();
  });

});
app.listen(3000,()=>{
  console.log('Started at port 3000');
console.log('server started');
});
