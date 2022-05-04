const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const { append } = require('express/lib/response');
const saltRounds = 10 // salt 생성, 이후 이를 통해 비밀번호 암호화(saltRounds : salt를 몇자리 만들것인가)
const jwt = require('jsonwebtoken');
const userSchema = mongoose.Schema({
    name: {
        type: String,
        maxlength: 50
    },
    email: {
        type: String,
        trim: true, //스페이스 제거 역할
        unique: 1
    },
    password: {
        type: String,
        minlength: 5
    },
    lastname: {
        type: String,
        maxlength: 50
    },
    role: {
        type: Number,
        default: 0, // 기본값 : 0
    },
    image: String,
    token: {
        type: String
    },
    tokenExp: {
        type: Number
    }
})

userSchema.pre('save', function(next){

    var user = this; //userSchema를 가리킴


    if(user.isModified('password')){ //비밀번호가 수정될 경우만
        bcrypt.genSalt(saltRounds, function(err, salt){
            if(err) return next(err)
            bcrypt.hash(user.password, salt, function(err, hash){
                if(err) return next(err) //function(err, hash)에서 실패시 err, 성공시 hash
                user.password = hash
                next() //이제 save로 넘어감
            })
        })
    }
    //비밀번호 암호화시킴
    else{
        next()
    }
}) //save 전에 무엇을 하겠다(pre)

userSchema.methods.comparePassword = function(plainPassword, cb){
    //plainPassword 1234567
    bcrypt.compare(plainPassword, this.password, function(err, isMatch){
        if(err) return cb(err);
            cb(null, isMatch);
    })
}

userSchema.methods.generateToken = function(cb){
    //jsonwebtoken을 이용해서 token 생성
    var user = this;
    var token = jwt.sign(user._id.toHexString(), 'secretToken')

    user.token = token;
    user.save(function(err, user){
        if(err) return cb(err);
        cb(null, user);
    })
}

userSchema.statics.findByToken = function(token, cb){
    var user = this;
    //토큰 decode
    jwt.verify(token, 'secretToken', function(err, decoded){
        //userid를 이용해서 유저 찾은 후 클라이언트에서 가져온 token과 db 토큰 일치하는지 확인
        user.findOne({"_id": decoded, "token": token}, function(err, user){
            if(err) return cb(err);
            cb(null, user)
        })
    }) //decoded : user._id
}



const User = mongoose.model('User', userSchema) //몽구스에 유저 스키마 입력

module.exports = { User } //다른곳에서도 쓸수있게