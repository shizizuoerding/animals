'use strict';
var router = require('express').Router();
var AV = require('leanengine');
var http = require('http');

function sendError(res,code,message){
    var result = {
        code:code,
        message:message,
        data:[]
    }
    res.send(result);
}

function validate(res,req,data){
    for(var i in data){
        if(req.method == 'GET'){
            var value = req.query[i];
        }else{
            var value = req.body[i];
        }
        if(data[i]){
            //必须值
            if(!value){
                var result = {
                    code : '302',
                    message : '缺少'+data[i],
                    data : []
                }
                res.send(result);
                return '';
            }
        }
        data[i] = value;
    }
    return data;
}

// 新建 AVUser 对象实例,
       // birth : '生日',
        //sex: '性别',
        //area:"地区"
  
  // 新增
router.post('/signUp', function(req, res, next) {
    var data = {
        userName : '用户名',
        passWord : '密码',
        birth : '生日',
        sex: '性别',
        area:"地区"
    }
    var data = validate(res,req,data);
    if(!data){
        return;
    }
    console.log(data);
    var user = new AV.User();
  // 设置用户名
  user.setUsername(data.userName);
  // 设置密码
  user.setPassword(data.passWord);
  // 设置邮箱
  // user.setEmail('tom@leancloud.cn');
  user.signUp().then(function (loginedUser) {
      // console.log(loginedUser);
      loginedUser.set('birth', data.birth);
      loginedUser.set('sex', data.sex);
      loginedUser.set('area', data.area);
      loginedUser.save();
      var result = {
                    code : 200,
                    data : loginedUser,
                    message : '保存成功'
                }
                res.send(result);
        }, function (error) {
            console.log(error);
            var result = {
                    code : 500,
                    message : '保存出错'
                }
                res.send(result);

    });
})



module.exports = router;