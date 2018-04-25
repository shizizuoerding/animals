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

//解析数据
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

var Goods = AV.Object.extend('Goods');

// 新增
router.post('/add', function(req, res, next) {
	/*
	商品图片链接: goods_pic json
	商品类别: goods_type  string
	商品名称: goods_name string
	商品价格: goods_price float
	商品数量: goods_amount num
	商品编号: goods_num string
	商品规格: goods_size string
	商品是否是出租: rent
	*/
	var data = {
		goodsPic     : '缺少商品链接',
		goodsType    : '缺少商品类别',
		goodsName    : '缺少商品名称',
		goodsPrice   : "缺少商品价格",
		goodsAmount  : "缺少商品数量", 
		goodsSize    : "",
		oriPrice     : "缺少商品原价",
		rent         : ""
	}

	var data = validate(res,req,data);

	if(!data){
		return;
	}
	//生成商品编号
	//生成当前时间戳
	var date = new Date().getTime();
	var goodsNum = date;
	data["goodsNum"] = goodsNum;
	data["status"] = 2;
	data["buyNum"] = 0;
	data["oriBuyNum"] = 0;

	data["goodsAmount"] = parseInt(data["goodsAmount"]);
	//设置两位小数
	data["goodsPrice"] = parseFloat(data["goodsPrice"]).toFixed(2);
	data["oriPrice"] = parseFloat(data["oriPrice"]).toFixed(2);

	data["rent"] = data["rent"];

	//创建一个数据库对象
	var goods = new Goods();
	for(var key in data){
		goods.set(key,data[key]);
	}
	goods.save().then(function (addResult) {
				    	var result = {
				    		code : 200,
				    		data : addResult,
				    		message : '保存成功'
				    	}
				    	res.send(result);
					}, function (error) {
				    	var result = {
				    		code : 500,
				    		message : '保存出错'
				    	}
				    	res.send(result);
					});
})

// 删除
router.post('/delete', function(req, res, next) {
	var id = req.body.id;
	//创建一个数据库对象
	if(!id){
		var result = {
			code    :  731,
			message :  "no goods id"
		}
		res.send(result);
		return;
	}
	var delObj = AV.Object.createWithoutData('Goods', data.id);
	delObj.destroy().then(function (success) {
		// 删除成功
		var result = {
		   	code : 200,
		   	data : [],
		    message : '删除成功'
		}
		res.send(result);
	}, function(error) {
		res.send(error);
	}).catch(next);
})

// 编辑
router.post('/edit', function(req, res, next) {
	/*
	商品图片链接: goods_pic json
	商品类别: goods_type  string
	商品名称: goods_name string
	商品价格: goods_price float
	商品数量: goods_amount num
	商品编号: goods_num string
	商品规格: goods_size string
	*/
	var id = req.body.id;
	if(!id){
		var result = {
			code : 731,
			message : "no goods id"
		}
		res.send(result);
		return;
	}

	var data = {
		goodsPic     : '缺少商品链接',
		goodsType    : '缺少商品类别',
		goodsName    : '缺少商品名称',
		goodsPrice   : "缺少商品价格",
		goodsAmount  : "缺少商品数量", 
		goodsSize    : "",
		buyNum       : "",
		oriPrice     : "缺少商品原价",
		rent         : ""
	}

	var data = validate(res,req,data);

	if(!data){
		var result = {
			code : 704,
			message : "缺少参数"
		}
		res.send(result);
		return;
	}
	data["status"] = 2;
	data["goodsAmount"] = parseInt(data["goodsAmount"]);
	data["buyNum"] = parseInt(data["buyNum"]);
	//设置两位小数
	data["goodsPrice"] = parseFloat(data["goodsPrice"]).toFixed(2);
	data["oriPrice"] = parseFloat(data["oriPrice"]).toFixed(2);
	data["rent"] = data["rent"];

	//创建一个数据库对象
	var goods = new Goods();
	for(var key in data){
		goods.set(key,data[key]);
	}
	goods.save().then(function (addResult) {
				    	var result = {
				    		code : 200,
				    		data : addResult,
				    		message : '保存成功'
				    	}
				    	res.send(result);
					}, function (error) {
				    	var result = {
				    		code : 500,
				    		message : '保存出错'
				    	}
				    	res.send(result);
					});
})

// 查找
router.get('/list', function(req, res, next) {
	//创建一个数据库对象
	var status  = req.query.status ? req.query.status : 2;
	var limit = req.query.limit ? req.query.limit : 1000;
	var skip = req.query.skip ? req.query.skip : 0;
	var all = req.query.all;
	var rent = req.query.rent ? req.query.rent : 0;
	// var rent = req.query.rent;

	var status = parseInt(status);
	var Query = new AV.Query("Goods");
	if(status != 0){
		Query.equalTo("status",status);
	}

	// console.log(rent);
	// Query.equalTo("rent",rent);

	//type 默认1 1：创建时间升 -1：创建时间降  2：销量升  -2：销量降  3：价格升 -3：销量降
	// var type = req.query.type ? req.query.type : -1;
	// type = parseInt(type);
	// switch(type){
	// 	case 1:
	// 		Query.sort("createAt",1);
	// 		break;
	// 	case 2:
	// 		Query.sort("buyNum",1);
	// 		break;
	// 	case -2:
	// 		Query.sort("buyNum");
	// 		break;
	// 	case 3:
	// 		Query.sort("goodsPrice",1);
	// 		break;
	// 	case -3:
	// 		Query.sort("goodsPrice");
	// 		break;
	// 	default:
	// 		Query.sort("createAt");
	// 		break;
	// }
	// //小于0不显示
	// if(!all){
	// 	if(rent==1){
	// 		Query.equalTo("rent",1);
	// 	}else{
	// 		Query.noEqualTo("rent",1);
	// 	}
	// 	Query.equalTo("goodsAmount",{$gt:0});
	// }else{
	// 	Query.equalTo("goodsAmount",{$gt:-20});
	// }
	
	Query.limit(limit);
	Query.skip(skip);
	Query.find().then(function (results) {
		// 删除成功
		var result = {
		   	code : 200,
		   	data : results,
		    message : '获取成功'
		}
		res.send(result);
	}, function(error) {
		res.send(error);
	}).catch(next);
})

// 详情
router.get('/detail', function(req, res, next) {
	var id = req.query.id;
	//创建一个数据库对象
	if(!id){
		var result = {
			code    :  731,
			message :  "no goods id"
		}
		res.send(result);
		return;
	}
	var Query = new AV.Query("Goods");
	Query.get(id,{
		success:function(result){
			res.send(result);
		},
		error:function(err){
			res.send(err);
		}
	})
})

module.exports = router;