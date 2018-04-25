var express = require('express');
var router = express.Router();
// var ONE = require("./ONE");
var AV = require('leanengine');
var charset = require('superagent-charset');
var superagent = require('superagent');
var crypto = require('crypto');
var algorithm = 'aes-128-ecb';
var key = '3e5626542add0a5e';
var clearEncoding = 'utf8';
var iv = "";
//var cipherEncoding = 'hex';
//If the next line is uncommented, the final cleartext is wrong.
var cipherEncoding = 'base64';
var cipher = crypto.createCipheriv(algorithm, key, iv);

// var cipherChunks = 'vRkOZvodtY9K4k+obFEsUw=='
// var decipher = crypto.createDecipheriv(algorithm, key,iv);
// var plainChunks = [];
// plainChunks.push(decipher.update(cipherChunks, cipherEncoding, clearEncoding));
// plainChunks.push(decipher.final(clearEncoding));
// console.log("UTF8 plaintext deciphered: " + plainChunks.join(''));


/* GET users listing. */
// router.get('/:id', function(req, res, next) {
//  var id = req.params.id;
//  var user = req.session.user;
//  // if(!req.session.user){
//  //  res.redirect('/admin/login');
//  //  return;
//  // }

//  if(!id){
//      res.redirect('/admin/goods');
//  }else{
//      res.render('admin/user',{id:id,user:user});
//  }
// });

// var Query = new ONE.Query("User");
// Query.equalTo("phoneNum","18408251158");
//     Query.findOne({
//      success:function(result){
//          if(result.data){
//              console.log("exit");
//          }else{
//              console.log("dont exit");
//          }
//      },
//      error:function(error){

//      }
//     })

//user signup
router.post('/findpw', function(req, res, next) {
    var phoneNum = req.body.phoneNum;
    var password = req.body.password;
    // var deviceToken = req.body.devicetoken;

    try {
        var cipherChunks = password;
        var decipher = crypto.createDecipheriv(algorithm, key, iv);
        var plainChunks = [];
        plainChunks.push(decipher.update(cipherChunks, cipherEncoding, clearEncoding));
        plainChunks.push(decipher.final(clearEncoding));
        var depassword = plainChunks.join('');
    } catch (err) {
        var result = {
            code: 500,
            message: err.message
        }
        res.send(result);
        return;
    }

    var phone = /^1([38]\d|4[57]|5[0-35-9]|7[06-8]|8[89])\d{8}$/;
    if (!phone.test(phoneNum)) {
        var result = {
            code: 457,
            message: "手机号格式不正确"
        }
        res.send(result);
        return false;
    }

    if (depassword.length < 6) {
        var result = {
            code: 511,
            message: "密码太短"
        }
        res.send(result);
        return false;
    }

    if (depassword.indexOf(" ") != -1) {
        var result = {
            code: 512,
            message: "密码存在空格"
        }
        res.send(result);
        return false;
    }

    var Query = new AV.Query("User");
    Query.equalTo("phoneNum", phoneNum);
    Query.findOne({
        success: function(result) {
            if (result.data) {
                //get userId
                var userId = result.data._id;
                var User = new AV.Object("User",userId);
                User.set("password", password);
                User.save({
                    success: function(result) {
                        // req.session.token = result.data[0];

                        var userId = userId;
                        var date = new Date().getTime();

                        var Query = new AVAV.Query("Token");
                        Query.equalTo("userId", userId);
                        Query.findOne({
                            success: function(result) {
                                //if exit token
                                //生成token
                                try {
                                    var dateString = date.toString();
                                    var phone = phoneNum;
                                    var text = date + phone;
                                    var hasher = crypto.createHash("md5");
                                    hasher.update(text);
                                    var token = hasher.digest('hex');
                                } catch (err) {
                                    var result = {
                                        code: 500,
                                        message: err.message
                                    }
                                    res.send(result);
                                    return;
                                }
                                //计算过期时间 3个月
                                var expire = date + 1000 * 3600 * 24 * 30 * 3;
                                if (!result.data) {
                                    var Token = new AV.Object("Token");
                                    Token.set("value", token);
                                    Token.set("expire", expire);
                                    Token.set("userId", userId);
                                    // Token.set("deviceToken", deviceToken);
                                    Token.save({
                                        success: function(result) {
                                            var result = {
                                                code: 200,
                                                message: "signup success",
                                                data: result.data[0]
                                            }
                                            req.session.token = result.data[0];
                                            res.send(result);
                                        },
                                        error: function(error) {
                                            res.send(error);
                                        }
                                    })
                                }else{
                                    var tokenData = result.data;
                                    var tokenid = result.data._id;
                                    // console.log(tokenid);
                                    var Token = new AV.Object("Token",tokenid);
                                    Token.set("value", token);
                                    Token.set("expire", expire);
                                    // Token.set("deviceToken", deviceToken);
                                    Token.save({
                                        success: function(result) {
                                            var data = tokenData;
                                            data.value = token;
                                            data.expire = expire;
                                            var result = {
                                                code: 200,
                                                message: "update success",
                                                data: data
                                            }
                                            req.session.token = result.data;
                                            res.send(result);
                                        },
                                        error: function(error) {
                                            res.send(error);
                                        }
                                    })
                                }
                            },
                            error:function(error){
                                res.send(error);
                            }
                        })
                    },
                    error: function(error) {
                        res.send(error);
                    }
                })
            } else {
                var result = {
                    code: 521,
                    message: "用户已存在"
                }
                res.send(result);
                return;
            }
        },
        error: function(error) {
            res.send(error);
        }
    })
});

function getCheckSum(AppSecret,Nonce,CurTime){
    var sha1 = crypto.createHash('sha1');
    sha1.update(AppSecret + Nonce + CurTime);
    return sha1.digest('hex');
}

function getToken(token,callback){
    if(!token){
        var result = {
            code : 600,
            message : "token is null"
        }
        return callback.error(result);
    }
    var Query = new AV.Query("Token");
    Query.equalTo("value",token);
    Query.findOne({
        success:function(result){
            var data = result.data;
            if(data){
                var now = new Date().getTime();
                var expire = parseInt(data.expire);
                if (now > expire) {
                    var result = {
                        code: 601,
                        message: "token expired"
                    }
                    return callback.error(result);
                }
                return callback.success(result);
            }else{
                var result = {
                    code: 604,
                    message: "token does not exit"
                }
                return callback.error(result);
            }
        },
        error:function(error){
            return callback.error(error);
        }
    })
}

router.get('/info', function(req, res, next) {
    var token = req.query.token;
    if(!token){
        //token exit
        var tokenData = req.session.token;
        if(!tokenData){
            var result = {
                code : 501,
                message : "用户未登录"
            }
            res.send(result);
            return;
        }else{
            token = tokenData.value;
        }
    }
    getToken(token,{
        success:function(result){
            var data = result.data;
            var userId = data.userId;
            var Query = new AV.Query("User");
            Query.get(userId,{
                success:function(result){
                    res.send(result);
                },
                error:function(err){
                    res.send(err);
                }
            })
        },
        error:function(error){
            res.send(error);
        }
    })
})


//获取验证码
router.post('/getsmscode', function(req, res, next) {
    var mobile = req.body.mobile;
    // var mobile = req.query.mobile;
    var tpl_id = "25698";
    // var tpl_value = "#code#=431515&#min#=30";
    var key = "449a07400cd1fae43b876db41bc978dd";
    var dtype = "json";

    var phone = /^1([38]\d|4[57]|5[0-35-9]|7[06-8]|8[89])\d{8}$/;
    if (!phone.test(mobile)) {
        var result = {
            code: 457,
            message: "手机号格式不正确"
        }
        res.send(result);
        return false;
    }

    if(!mobile){
        var result = {
            code : 456,
            message:"手机号码为空"
        }
        res.send(result);
        return;
    }

    var Query = new AV.Query("SmsCode");
    Query.equalTo("mobile",mobile);
    Query.findOne({
        success:function(result){
            console.log(result);
            var data = result.data;
            if(data){
                //请求过
                //判断是否频繁请求
                var createAt = new Date(data.createAt).getTime();
                var expired = data.expired;
                var nowDate = new Date().getTime();
                if(nowDate - createAt < 60000){
                    var result = {
                        code : 467,
                        message : "请求校验验证码频繁"
                    }
                    res.send(result);
                    return;
                }else{
                    if(nowDate < expired){
                        //在过期时间内,将原来的验证码发到用户手上
                        var code = data.code;
                        var SmsCodeId = data._id;
                        var tpl_value = "#code#="+code+"&#min#=30";
                        tpl_value = encodeURIComponent(tpl_value);
                        var postData = "mobile="+mobile+"&tpl_id="+tpl_id+"&tpl_value="+tpl_value+"&key="+key;
                        var url = "http://v.juhe.cn/sms/send?"+postData;
                        superagent.get(url)
                            .end((err, result) => {
                                var data = result.text;
                                try{
                                    var data = JSON.parse(data);
                                }catch(err){
                                    var result = {
                                        code : 500,
                                        message:err.message
                                    }
                                    res.send(result);
                                    return;
                                }
                                var error_code = data.error_code;
                                if(error_code){
                                    var result = {
                                        code : error_code,
                                        message:data.reason
                                    }
                                    res.send(result);
                                    return;
                                }else{
                                    //发送成功
                                    //保存数据库
                                    //生成过期时间
                                    var date = new Date().getTime();
                                    var expired = date + 1000 * 60 * 30;
                                    var SmsCode = new AV.Object("SmsCode",SmsCodeId);
                                    SmsCode.set("expired",expired);
                                    SmsCode.save({
                                        success:function(result){
                                            var result = {
                                                code : 200,
                                                message:"发送验证码成功"
                                            }
                                            res.send(result);
                                            return;
                                        },
                                        error:function(error){
                                            res.send(error);
                                            return;
                                        }
                                    })
                                }
                            })
                    }else{
                        //生成新的验证码
                        //生成6为验证码
                        var code = '';
                        for(var i = 0; i < 6; i++){
                            code +=  Math.floor(Math.random()*10);
                        }
                        var SmsCodeId = data._id;
                        var tpl_value = "#code#="+code+"&#min#=30";
                        tpl_value = encodeURIComponent(tpl_value);
                        var postData = "mobile="+mobile+"&tpl_id="+tpl_id+"&tpl_value="+tpl_value+"&key="+key;
                        var url = "http://v.juhe.cn/sms/send?"+postData;
                        superagent.get(url)
                            .end((err, result) => {
                                var data = result.text;
                                try{
                                    var data = JSON.parse(data);
                                }catch(err){
                                    var result = {
                                        code : 500,
                                        message:err.message
                                    }
                                    res.send(result);
                                    return;
                                }
                                var error_code = data.error_code;
                                if(error_code){
                                    var result = {
                                        code : error_code,
                                        message:data.reason
                                    }
                                    res.send(result);
                                    return;
                                }else{
                                    //发送成功
                                    //保存数据库
                                    //生成过期时间
                                    var date = new Date().getTime();
                                    var expired = date + 1000 * 60 * 30;
                                    var SmsCode = new AV.Object("SmsCode",SmsCodeId);
                                    SmsCode.set("code",code);
                                    SmsCode.set("expired",expired);
                                    SmsCode.save({
                                        success:function(result){
                                            var result = {
                                                code : 200,
                                                message:"发送验证码成功"
                                            }
                                            res.send(result);
                                            return;
                                        },
                                        error:function(error){
                                            res.send(error);
                                            return;
                                        }
                                    })
                                }
                            })
                    }
                }
            }else{
                //没有请求
                //生成验证码 并保存到数据库中

                //生成6为验证码
                var code = '';
                for(var i = 0; i < 6; i++){
                    code +=  Math.floor(Math.random()*10);
                }

                var tpl_value = "#code#="+code+"&#min#=30";
                tpl_value = encodeURIComponent(tpl_value);
                var postData = "mobile="+mobile+"&tpl_id="+tpl_id+"&tpl_value="+tpl_value+"&key="+key;
                var url = "http://v.juhe.cn/sms/send?"+postData;
                console.log(url);
                superagent.get(url)
                    .end((err, result) => {
                        var data = result.text;
                        try{
                            var data = JSON.parse(data);
                        }catch(err){
                            var result = {
                                code : 500,
                                message:err.message
                            }
                            res.send(result);
                            return;
                        }
                        var error_code = data.error_code;
                        if(error_code){
                            var result = {
                                code : error_code,
                                message:data.reason
                            }
                            res.send(result);
                            return;
                        }else{
                            //发送成功
                            //保存数据库
                            //生成过期时间
                            var date = new Date().getTime();
                            var expired = date + 1000 * 60 * 30;
                            var SmsCode = new AV.Object("SmsCode");
                            SmsCode.set("mobile",mobile);
                            SmsCode.set("code",code);
                            SmsCode.set("expired",expired);
                            SmsCode.save({
                                success:function(result){
                                    var result = {
                                        code : 200,
                                        message:"发送验证码成功"
                                    }
                                    res.send(result);
                                    return;
                                },
                                error:function(error){
                                    res.send(error);
                                    return;
                                }
                            })
                        }
                    })
            }
        },
        error:function(error){
            res.send(error)
        }   
    })
})


//user findpw
router.post('/signup', function(req, res, next) {
    var phoneNum = req.body.phoneNum;
    var password = req.body.password;

    try {
        var cipherChunks = password;
        var decipher = crypto.createDecipheriv(algorithm, key, iv);
        var plainChunks = [];
        plainChunks.push(decipher.update(cipherChunks, cipherEncoding, clearEncoding));
        plainChunks.push(decipher.final(clearEncoding));
        var depassword = plainChunks.join('');
    } catch (err) {
        var result = {
            code: 500,
            message: err.message
        }
        res.send(result);
        return;
    }

    var phone = /^1([38]\d|4[57]|5[0-35-9]|7[06-8]|8[89])\d{8}$/;
    if (!phone.test(phoneNum)) {
        var result = {
            code: 457,
            message: "手机号格式不正确"
        }
        res.send(result);
        return false;
    }

    if (depassword.length < 6) {
        var result = {
            code: 511,
            message: "密码太短"
        }
        res.send(result);
        return false;
    }

    if (depassword.indexOf(" ") != -1) {
        var result = {
            code: 512,
            message: "密码存在空格"
        }
        res.send(result);
        return false;
    }

    var Query = new AV.Query("User");
    Query.equalTo("phoneNum", phoneNum);
    Query.findOne({
        success: function(result) {
            if (!result.data) {
                var User = new AV.Object("User");
                User.set("phoneNum", phoneNum);
                User.set("password", password);
                User.save({
                    success: function(result) {
                        // req.session.token = result.data[0];
                        // res.send(result);
                        if(!result.data){
                            var result = {
                                code: 803,
                                message: "save error"
                            }
                            res.send(result);
                            return false;
                        }

                        var userId = result.data[0]._id;
                        var date = new Date().getTime();
                        //生成token
                        try {
                            var dateString = date.toString();
                            var phone = result.data[0].phoneNum;
                            var text = date + phone;
                            var hasher = crypto.createHash("md5");
                            hasher.update(text);
                            var token = hasher.digest('hex');
                        } catch (err) {
                            var result = {
                                code: 500,
                                message: err.message
                            }
                            res.send(result);
                            return;
                        }
                        //计算过期时间 3个月
                        var expire = date + 1000 * 3600 * 24 * 30 * 3;
                        var Token = new AV.Object("Token");
                        Token.set("value", token);
                        Token.set("expire", expire);
                        Token.set("userId", userId);
                        Token.save({
                            success: function(result) {
                                var result = {
                                    code: 200,
                                    message: "signup success",
                                    data: result.data[0]
                                }
                                req.session.token = result.data[0];
                                res.send(result);
                            },
                            error: function(error) {
                                res.send(error);
                            }
                        })
                    },
                    error: function(error) {
                        res.send(error);
                    }
                })
            } else {
                var result = {
                    code: 522,
                    message: "用户不存在"
                }
                res.send(result);
                return;
            }
        },
        error: function(error) {
            res.send(error);
        }
    })
});

// var Query = new ONE.Query("Token");
// Query.find({
//     success: function(result) {
//         console.log(result);
//     },
//     error: function(error) {

//     }
// })

//user login
router.post('/login', function(req, res, next) {
    var phoneNum = req.body.phoneNum;
    var password = req.body.password;
    var deviceToken = req.body.devicetoken;
    console.log(deviceToken);

    try {
        var cipherChunks = password;
        var decipher = crypto.createDecipheriv(algorithm, key, iv);
        var plainChunks = [];
        plainChunks.push(decipher.update(cipherChunks, cipherEncoding, clearEncoding));
        plainChunks.push(decipher.final(clearEncoding));
        var depassword = plainChunks.join('');
        // console.log(depassword);
    } catch (err) {
        var result = {
            code: 500,
            message: err.message
        }
        res.send(result);
        return;
    }

    var phone = /^1([38]\d|4[57]|5[0-35-9]|7[06-8]|8[89])\d{8}$/;
    if (!phone.test(phoneNum)) {
        var result = {
            code: 457,
            message: "手机号格式不正确"
        }
        res.send(result);
        return false;
    }

    if (depassword.length < 6) {
        var result = {
            code: 511,
            message: "密码太短"
        }
        res.send(result);
        return false;
    }

    if (depassword.indexOf(" ") != -1) {
        var result = {
            code: 512,
            message: "密码存在空格"
        }
        res.send(result);
        return false;
    }

    var Query = new AV.Query("User");
    Query.equalTo("phoneNum", phoneNum);
    Query.findOne({
        success: function(result) {
            if (result.data) {
                if (result.data.password == password) {
                    var user = result.data;
                    var Query = new AV.Query("Token");
                    Query.equalTo("userId", result.data._id);
                    Query.findOne({
                        success: function(result) {
                            //if exit token
                            if (!result.data) {
                                //获取用户Id
                                var userId = user._id;
                                var date = new Date().getTime();
                                //生成token
                                try {
                                    var dateString = date.toString();
                                    var phone = user.phoneNum;
                                    var text = dateString + phone;
                                    var hasher = crypto.createHash("md5");
                                    hasher.update(text);
                                    var token = hasher.digest('hex');
                                } catch (err) {
                                    var result = {
                                        code: 500,
                                        message: err.message
                                    }
                                    res.send(result);
                                    return;
                                }
                                //计算过期时间 3个月
                                var expire = date + 1000 * 3600 * 24 * 30 * 3;
                                var Token = new AV.Object("Token");
                                Token.set("value", token);
                                Token.set("expire", expire);
                                Token.set("userId", userId);
                                // Token.set("deviceToken", deviceToken);
                                if(deviceToken){
                                    Token.set("deviceToken", deviceToken);
                                }
                                Token.save({
                                    success: function(result) {
                                        // console.log(result);
                                        var result = {
                                            code: 200,
                                            message: "login success",
                                            data: result.data[0]
                                        }
                                        req.session.token = result.data[0];
                                        res.send(result);
                                    },
                                    error: function(error) {
                                        res.send(error);
                                    }
                                })
                            } else {
                                // if token expired
                                var now = new Date().getTime();
                                // var data = result.data.;
                                try {
                                    var tokenData = result.data;
                                    var expire = tokenData.expire;
                                    var tokenid = tokenData._id
                                    var phone = tokenData.phoneNum;
                                } catch (err) {
                                    var result = {
                                        code: 500,
                                        message: err.message
                                    }
                                    res.send(result);
                                    return;
                                }
                                if (now <= expire) {
                                    //no expired
                                    req.session.token = result.data;
                                    // res.send(result);
                                    var date = new Date().getTime();
                                    //更新过期时间 3个月
                                    var expire = date + 1000 * 3600 * 24 * 30 * 3;
                                    // console.log(tokenid);
                                    var Token = new AV.Object("Token",tokenid);
                                    Token.set("expire", expire);
                                    if(deviceToken){
                                        Token.set("deviceToken", deviceToken);
                                    }
                                    
                                    Token.save({
                                        success: function(result) {
                                            var data = tokenData;
                                            data.expire = expire;
                                            var result = {
                                                code: 200,
                                                message: "update success",
                                                data: data
                                            }
                                            req.session.token = result.data;
                                            res.send(result);
                                        },
                                        error: function(error) {
                                            res.send(error);
                                        }
                                    })
                                }else{
                                    //update token;
                                    var date = new Date().getTime();
                                    //生成token
                                    try {
                                        var dateString = date.toString();
                                        var text = dateString + phone;
                                        var hasher = crypto.createHash("md5");
                                        hasher.update(text);
                                        var token = hasher.digest('hex');
                                    } catch (err) {
                                        var result = {
                                            code: 500,
                                            message: err.message
                                        }
                                        res.send(result);
                                        return;
                                    }
                                    //计算过期时间 3个月
                                    var expire = date + 1000 * 3600 * 24 * 30 * 3;
                                    // console.log(tokenid);
                                    var Token = new AV.Object("Token",tokenid);
                                    Token.set("value", token);
                                    Token.set("expire", expire);
                                    if(deviceToken){
                                        Token.set("deviceToken", deviceToken);
                                    }
                                    
                                    Token.save({
                                        success: function(result) {
                                            var data = tokenData;
                                            data.value = token;
                                            data.expire = expire;
                                            var result = {
                                                code: 200,
                                                message: "update success",
                                                data: data
                                            }
                                            req.session.token = result.data;
                                            res.send(result);
                                        },
                                        error: function(error) {
                                            res.send(error);
                                        }
                                    })
                                }
                                
                            }
                        },
                        error: function(error) {
                            // console.log(rror);
                            res.send(error)
                        }
                    })

                    // var result = {
                    //      code    : 200,
                    //      message : "登录成功"
                    //    }
                    //    res.send(result);
                    //    return;
                } else {
                    var result = {
                        code: 523,
                        message: "密码错误"
                    }
                    res.send(result);
                    return;
                }
            } else {
                var result = {
                    code: 522,
                    message: "用户不存在"
                }
                res.send(result);
                return;
            }
        },
        error: function(error) {
            res.send(error);
        }
    })
});

// var Query = new ONE.Query("User");
// Query.removeAll({
//     success:function(){

//     },
//     error:function(){

//     }
// })

//sms login
router.post('/m/signup', function(req, res, next) {
    var phone = req.body.phone,
        code = req.body.code;

    var password = req.body.password;
    var deviceToken = req.body.devicetoken;

    try {
        var cipherChunks = password;
        var decipher = crypto.createDecipheriv(algorithm, key, iv);
        var plainChunks = [];
        plainChunks.push(decipher.update(cipherChunks, cipherEncoding, clearEncoding));
        plainChunks.push(decipher.final(clearEncoding));
        var depassword = plainChunks.join('');
    } catch (err) {
        var result = {
            code: 500,
            message: err.message
        }
        res.send(result);
        return;
    }

    if (depassword.length < 6) {
        var result = {
            code: 511,
            message: "密码太短"
        }
        res.send(result);
        return false;
    }
    if (depassword.indexOf(" ") != -1) {
        var result = {
            code: 512,
            message: "密码存在空格"
        }
        res.send(result);
        return false;
    }

    //查询用户表是否存在该用户
    var Query = new AV.Query("User");
    Query.equalTo("phoneNum", phone);
    Query.findOne({
        success: function(result) {
            // var userId = result.data._id;
            if (!result.data) {

                var Query = new AV.Query("SmsCode");
                Query.equalTo("mobile", phone);
                Query.findOne({
                    success:function(result){
                        var data = result.data;
                        if(data){
                            var SmsCodeId = data._id;
                            //请求过验证码
                            var expired = data.expired;
                            var nowDate = new Date().getTime();
                            if(nowDate < expired){
                                //在过期时间内
                                var smsCode = data.code;
                                if(smsCode == code){
                                    //将验证码清除
                                    var Query = new AV.Query("SmsCode");
                                    Query.removeId(SmsCodeId,{});

                                    var User = new AV.Object("User");
                                    User.set("phoneNum", phone);
                                    //使用AES加密
                                    // var cipherChunks = [];
                                    // cipherChunks.push(cipher.update(password, clearEncoding, cipherEncoding));
                                    // cipherChunks.push(cipher.final(cipherEncoding));
                                    // console.log(cipherChunks.join(''));
                                    // return;
                                    User.set("password", password);
                                    User.save({
                                        success: function(result) {
                                            // console.log(result);
                                            // req.session.user = result.data[0];
                                            // res.send(result);
                                            if (result.data[0]) {
                                                //获取用户Id
                                                var userId = result.data[0]._id;
                                                var date = new Date().getTime();
                                                //生成token
                                                try {
                                                    var dateString = date.toString();
                                                    var phone = result.data[0].phoneNum;
                                                    var text = date + phone;
                                                    var hasher = crypto.createHash("md5");
                                                    hasher.update(text);
                                                    var token = hasher.digest('hex');
                                                } catch (err) {
                                                    var result = {
                                                        code: 500,
                                                        message: err.message
                                                    }
                                                    res.send(result);
                                                    return;
                                                }
                                                //计算过期时间 3个月
                                                var expire = date + 1000 * 3600 * 24 * 30 * 3;
                                                var Token = new AV.Object("Token");
                                                Token.set("value", token);
                                                Token.set("expire", expire);
                                                Token.set("userId", userId);
                                                Token.set("deviceToken", deviceToken);
                                                Token.save({
                                                    success: function(result) {
                                                        var result = {
                                                            code: 200,
                                                            message: "signup success",
                                                            data: result.data[0]
                                                        }
                                                        res.send(result);
                                                    },
                                                    error: function(error) {
                                                        res.send(error);
                                                    }
                                                })

                                            } else {
                                                var result = {
                                                    code: 540,
                                                    message: "signup error"
                                                }
                                                res.send(result);
                                            }
                                        },
                                        error: function(error) {
                                            res.send(error);
                                        }
                                    })
                                }else{
                                    //没有请求验证码
                                    var result = {
                                        code : 468,
                                        message : "验证码错误"
                                    }
                                    res.send(result);
                                    return;
                                }
                            }else{
                                //已经过期
                                var result = {
                                    code : 469,
                                    message : "验证码过期"
                                }
                                res.send(result);
                                return;
                            }
                        }else{
                            //没有请求验证码
                            var result = {
                                code : 468,
                                message : "验证码错误"
                            }
                            res.send(result);
                            return;
                        }
                    },
                    error:function(error){
                        res.send(error);
                    }
                })
            } else {
                var result = {
                    code: 521,
                    message: "用户已存在"
                }
                res.send(result);
                return;
            }
        },
        error: function(error) {
            res.send(error);
            return;
        }
    })
});

router.post('/check', function(req, res, next) {
    var phone = req.body.phone;
    //查询用户表是否存在该用户
    var Query = new AV.Query("User");
    Query.equalTo("phoneNum", phone);
    Query.findOne({
        success: function(result) {
            if(result.data){
                var result = {
                    code: 200,
                    message: "用户存在"
                }
                res.send(result);
                return;
            }else{
                var result = {
                    code: 522,
                    message: "用户不存在"
                }
                res.send(result);
                return;
            }
        },
        error:function(error){
            res.send(error);
        }
    })
});

//sms findpw
router.post('/m/findpw', function(req, res, next) {
    var phone = req.body.phone,
        code = req.body.code;

    var password = req.body.password;
    var deviceToken = req.body.devicetoken;

    try {
        var cipherChunks = password;
        var decipher = crypto.createDecipheriv(algorithm, key, iv);
        var plainChunks = [];
        plainChunks.push(decipher.update(cipherChunks, cipherEncoding, clearEncoding));
        plainChunks.push(decipher.final(clearEncoding));
        var depassword = plainChunks.join('');
    } catch (err) {
        var result = {
            code: 500,
            message: err.message
        }
        res.send(result);
        return;
    }

    if (depassword.length < 6) {
        var result = {
            code: 511,
            message: "密码太短"
        }
        res.send(result);
        return false;
    }
    if (depassword.indexOf(" ") != -1) {
        var result = {
            code: 512,
            message: "密码存在空格"
        }
        res.send(result);
        return false;
    }

    //查询用户表是否存在该用户
    var Query = new AV.Query("User");
    Query.equalTo("phoneNum", phone);
    Query.findOne({
        success: function(result) {
            // console.log(result);
            if (result.data) {
                var userId = result.data._id;

                var Query = new AV.Query("SmsCode");
                Query.equalTo("mobile", phone);
                Query.findOne({
                    success:function(result){
                        var data = result.data;
                        if(data){
                            var SmsCodeId = data._id;
                            //请求过验证码
                            var expired = data.expired;
                            var nowDate = new Date().getTime();
                            if(nowDate < expired){
                                //在过期时间内
                                var smsCode = data.code;
                                if(smsCode == code){
                                    //将验证码清除
                                    var Query = new AV.Query("SmsCode");
                                    Query.removeId(SmsCodeId,{});

                                    var User = new AV.Object("User",userId);
                                    User.set("password", password);
                                    User.save({
                                        success: function(result) {
                                            var date = new Date().getTime();
                                            var Query = new AV.Query("Token");
                                            Query.equalTo("userId", userId);
                                            Query.findOne({
                                                success: function(result) {
                                                    //if exit token
                                                    //生成token
                                                    try {
                                                        var dateString = date.toString();
                                                        var text = dateString + phone;
                                                        var hasher = crypto.createHash("md5");
                                                        hasher.update(text);
                                                        var token = hasher.digest('hex');
                                                    } catch (err) {
                                                        var result = {
                                                            code: 500,
                                                            message: err.message
                                                        }
                                                        res.send(result);
                                                        return;
                                                    }
                                                    //计算过期时间 3个月
                                                    var expire = date + 1000 * 3600 * 24 * 30 * 3;
                                                    if (!result.data) {
                                                        var Token = new AV.Object("Token");
                                                        Token.set("value", token);
                                                        Token.set("expire", expire);
                                                        Token.set("userId", userId);
                                                        Token.set("deviceToken", deviceToken);
                                                        Token.save({
                                                            success: function(result) {
                                                                var result = {
                                                                    code: 200,
                                                                    message: "signup success",
                                                                    data: result.data[0]
                                                                }
                                                                req.session.token = result.data[0];
                                                                res.send(result);
                                                            },
                                                            error: function(error) {
                                                                res.send(error);
                                                            }
                                                        })
                                                    }else{
                                                        var tokenData = result.data;
                                                        var tokenid = result.data._id;
                                                        // console.log(tokenid);
                                                        var Token = new AV.Object("Token",tokenid);
                                                        Token.set("value", token);
                                                        Token.set("expire", expire);
                                                        Token.set("deviceToken", deviceToken);
                                                        Token.save({
                                                            success: function(result) {
                                                                var data = tokenData;
                                                                data.value = token;
                                                                data.expire = expire;
                                                                data.userId = userId;
                                                                var result = {
                                                                    code: 200,
                                                                    message: "update success",
                                                                    data: data
                                                                }
                                                                req.session.token = result.data;
                                                                res.send(result);
                                                            },
                                                            error: function(error) {
                                                                res.send(error);
                                                            }
                                                        })
                                                    }
                                                },
                                                error:function(error){
                                                    res.send(error);
                                                }
                                            })
                                        },
                                        error: function(error) {
                                            res.send(error);
                                        }
                                    })
                                }else{
                                    //没有请求验证码
                                    var result = {
                                        code : 468,
                                        message : "验证码错误"
                                    }
                                    res.send(result);
                                    return;
                                }
                            }else{
                                //已经过期
                                var result = {
                                    code : 469,
                                    message : "验证码过期"
                                }
                                res.send(result);
                                return;
                            }
                        }else{
                            //没有请求验证码
                            var result = {
                                code : 468,
                                message : "验证码错误"
                            }
                            res.send(result);
                            return;
                        }
                    },
                    error:function(error){
                        res.send(error);
                    }
                })
            } else {
                var result = {
                    code: 522,
                    message: "用户不存在"
                }
                res.send(result);
                return;
            }
        },
        error: function(error) {
            res.send(error);
        }
    })
});

//user quit
router.get('/quit', function(req, res, next) {
    var token = req.query.token;
    if(!token){
        req.session.token = '';
        if (req.session.token) {
            var result = {
                code: 541,
                message: "登出失败"
            }
        } else {
            var result = {
                code: 200,
                message: "登出成功"
            }
        }
        res.send(result);
    }else{
        req.session.token = '';
        var Query = new AV.Query("Token");
        Query.equalTo("value",token);
        Query.findOne({
            success:function(result){
                var data = result.data;
                if(data){
                    try{
                        var Token = new AV.Object("Token",data._id);
                    }catch(err){
                        var result = {
                            code: 500,
                            message: err.message
                        }
                        res.send(result);
                    }
                    Token.set("expire",0);
                    Token.save({
                        success:function(result){
                            res.send(result);
                        },
                        error:function(error){
                            res.send(error);
                        }
                    })
                    
                }else{
                    var result = {
                        code: 604,
                        message: "token does not exit"
                    }
                    res.send(result);
                }
            },
            error:function(error){
                res.send(error);
            }
        })
    }
    
});

module.exports = router;
