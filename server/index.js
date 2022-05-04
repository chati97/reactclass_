const express = require('express')
const app = express()
const port = 5000
const bodyParser = require('body-parser');
const {auth} = require("./middleware/auth");
const {User} = require("./models/User");
const config = require('./config/key');
const cookieParser = require('cookie-parser');
//application/x-www-form-urlencoded
app.use(bodyParser.urlencoded({extended : true}));

//application/json
app.use(bodyParser.json());
app.use(cookieParser());
const mongoose = require('mongoose');
const { application, response } = require('express');
mongoose.connect(config.mongoURI)
    .then(() => console.log('MongoDB Connected...'))
    .catch(err => console.log(err))


app.get('/', (req, res) => res.send('Hello World! Hi'))

app.get('/api/hello', (req,res)=>{
    res.send("안녕하세요~")
})

app.post('/api/users/register', (req, res) =>{
    //회원가입시 필요한 정보를 client에서 가져오면 그것들을 Db에 넣어줌

    const user = new User(req.body)

    user.save((err, userInfo)=> {
        if(err) return res.json({success: false, err})
        return res.status(200).json({success: true})
    })


})
app.post('/api/users/login', (req, res)=>{
    //요청된 이메일이 db에 있는지 찾는다
    User.findOne({email: req.body.email}, (err, user)=>{
        if(!user)
        {
            return res.json({
                loginSuccess: false,
                message: "이메일이 존재하지 않습니다"
            })
        }
        user.comparePassword(req.body.password, (err, isMatch)=>{
            if(!isMatch)
                return res.json({loginSuccess: false, message: "비밀번호가 일치하지 않습니다"})
            //비밀번호 일치시
            user.generateToken((err, user)=>{
                if(err) return res.status(400).send(err);
                
                //토큰을 저장한다. 어디에? 쿠키, 로컬 스토리지
                res.cookie("x_auth", user.token)
                .status(200)
                .json({loginSuccess: true, userID: user._id})
            })
        })
    })
    //요청된 이메일이 db에 있다면 비밀번호가 일치하는지 확인
    //비밀번호가 맞다면 토큰 생성

})
//role : 0-> 일반유저 0 아니면 관리자
app.get('/api/users/auth', auth, (req, res) =>{
    //여기까지 미들웨어를 통과해서 왔다 = authentication이 통과
    res.status(200).json({
        _id: req.user._id,
        isAdmin: req.user.role === 0 ? false : true,
        isAuth: true,
        email: req.user.email,
        name: req.user.name,
        lastname: req.user.lastname,
        role: req.user.role,
        image: req.user.image
    })
})

app.get('/api/users/logout', auth, (req, res) =>{
    User.findOneAndUpdate({_id: req.user._id},
        {token: ""},
        (err, user)=>{
            if(err) return res.json({success: false, err});
            return res.status(200).send({
                success: true
            })
        })
})

app.listen(port, () => console.log(`Example app listening on port ${port}!`))