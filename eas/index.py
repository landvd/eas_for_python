#!/usr/bin/python
# -*- coding: UTF-8 -*-  #设置编码为utf-8
import re#导入正则表达式库
import collections#导入计算重复数库
import os#导入系统操作库
from flask import Flask,request,render_template,redirect,url_for#导入Flask框架
app=Flask(__name__)

@app.route('/',methods=['GET'])
def index():#主页面
	client_ip=request.remote_addr   #获取客户端ip地址
	if client_ip in '192.168.1.1':#如果IP地址是路由器，即直接跳转到管理界面
		return redirect('/system')
	mac_status=True   #设置MAC状态为真
	with open('/run/dhcpd.leases','r') as dhcp_handle: #读取dhcp文件
		dhcp_str=dhcp_handle.read()
	ip_pattern = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b") #正则表达式，匹配IP地址
	ip_str=ip_pattern.findall(dhcp_str) #根据表达式查找出数据
	ip_index=ip_str.index(client_ip) #获取ip地址下标
	mac_pattern=re.compile("\s[a-f\\d]{2}(?:\:[a-f\\d]{2}){5}")#正则表达式，匹配MAC地址
	mac_str=mac_pattern.findall(dhcp_str) #根据表达式查找出数据
	client_mac=mac_str[ip_index].strip() #根据IP下标，获取设备MAC
	#return render_template('index.html',ip_strs=client_mac,mac_strs=mac_str)
	with open('/usr/local/eas/white_list','r') as white_handle: #读取dhcp文件
		for line in white_handle.readlines():#读取dhcp文件
			if line[0:17]==client_mac:#如果文件内MAC等于客户MAC
				mac_status=False#状态为flase
				return redirect(url_for('status',mac=client_mac))#否则跳转到验证成功页面
				break
		if mac_status==True:#如果为真
			return redirect(url_for('login',mac=client_mac))#跳到成功登陆页面
	white_handle.close()
	dhcp_handle.close()
@app.route('/status',methods=['GET'])#成功登陆函数
def status():
	mac=request.args.get("mac")#获取参数mac
	return render_template('status.html',mac=mac)#跳转到成功页面
@app.route('/wx',methods=['GET'])
def wx():#微信登陆函数
	return redirect('/')
@app.route('/clear_info',methods=['GET'])#清除系统信息函数
def clear_info():
	fo = open("/var/log/messages", "r+")#清除系统信息
	fo.truncate()
	return redirect('/info/system_info')
@app.route('/login',methods=['GET'])#登陆函数，显示登陆界面
def login():
	mac=request.args.get("mac")#获取mac参数
	return render_template('login.html',mac=mac)#将参数传递给渲染页面login.html
@app.route('/check',methods=['GET'])
def check():#检查函数，检查是否白名单用户
	mac=request.args.get("mac")#获取mac参数
	if len(mac) == 12:
		mac = ':'.join(re.findall(r'.{2}',mac))#如果mac等于12位，就将:加到中间
	tmp_mac = mac
	client_user = request.args.get("user")#获取user参数
	if client_user == None:#如果user参数为空
		client_user = 'tmp_user'#就赋值tmp_user给client_user变量
	with open('/usr/local/eas/white_list','a+') as mac_handle: #写入mac到白名单文件
		mac_handle.write(mac.encode('utf-8')+'#'+client_user.encode('utf-8')+'\n')#整理命令行参数
	tmp_mac = 1 * '01' + mac[2:]#执行iptables，将mac添加入防火墙
	os.popen("iptables -I white_list -m mac --mac-source "+tmp_mac.encode('utf-8')+" -m comment --comment "+client_user.encode('utf-8')+" -j RETURN")#执行iptables，将mac添加入防火墙
	os.popen("iptables -I white_list -m mac --mac-source "+mac.encode('utf-8')+" -m comment --comment "+client_user.encode('utf-8')+" -j RETURN")#执行iptables，将mac添加入防火墙
	return redirect(url_for('status'))#成功后跳转到成功页面
@app.route('/system')
def system():#后台系统主页面函数
	return render_template('system.html')#显示后台主界面
@app.route('/info/qr_info',methods=['GET'])
def info():#显示二维码函数
	return '<img src="/static/images/qr.png" />'
@app.route('/info/system_info',methods=['GET'])
def system_info():#显示系统信息函数
	mac_result = []#定义一空的数组
	messages_info = os.popen("cat /var/log/messages")#打开系统信息文件
	messages_info_result=messages_info.read()#读取系统信息文件
	time_pattern=re.compile("[\w]{3}\s{1,2}\d{1,2}\s\d{2}\:\d{2}\:\d{2}")#正则表达式，匹配时间
	time_result=time_pattern.findall(messages_info_result)#执行表达式
	mac_pattern=re.compile("[a-z\d]{2}(?:\:[a-z\d]{2}){13}")#正则表达式，匹配mac地址
	ip_pattern=re.compile("SRC=(.*?)\s")#执行表达式
	ip_result=ip_pattern.findall(messages_info_result)#正则表达式，区配IP地址
	for i in mac_pattern.findall(messages_info_result):#循环执行表达式，并且存入新数组
		mac_result.append(i[18:35])
	mac_acc_num=collections.Counter(mac_result)#计算MAC重复数量
	dst_pattern=re.compile("DST=(.*?)\s")#执行表达式
	dst_result=dst_pattern.findall(messages_info_result)#返回执行表达式数据
	dst_acc_num=collections.Counter(dst_result)#返回目标地址数量
	
	for key in dst_acc_num:#循环目的地址数量
		cmd = 'iptables -I white_list -d'+key+' -j RETURN'#加入链表
		cmd = cmd.encode('utf-8')
		os.popen(cmd)
	return render_template('system_info.html',time_results=time_result,mac_results=mac_result,ip_results=ip_result,mac_acc_nums=mac_acc_num,dst_results=dst_result,dst_acc_nums=dst_acc_num)#显示时间，MAC,目的地址信息
@app.route('/info/mac_info',methods=['GET'])
def mac_info():#mac地址信息函数
	log_list_result = []#定义空白数组
	with open('/usr/local/eas/log','r') as log_handle: #读取日志文件
		for line in log_handle.readlines():
			line=line.strip().decode('utf-8')
			log_list_result.append(line)
	return render_template('mac_info.html',log=log_list_result)	#显示MAC访问信息
@app.route('/info/white_list_info',methods=['GET'])
def white_list_info():
	white_list_result = []#定义空白数组
	with open('/usr/local/eas/white_list','r') as white_handle: #读取白名单文件
		for line in white_handle.readlines():
			line=line.strip().decode('utf-8')#去除空白
			white_list_result.append(line)#添加入新数组
	white_list_cmd = os.popen("iptables -L white_list -nv --line-numbers")#显示白名单链表
	white_list_cmd_result=white_list_cmd.read().decode('utf-8')#读取链表信息
	speed_pattern=re.compile("\d\s(.*?)\sRETURN")#匹配网速表达式
	speed_result=speed_pattern.findall(white_list_cmd_result)#执行表达式
	mac_pattern=re.compile("[a-z\d]{2}(?:\:[a-z\d]{2}){5}",re.IGNORECASE)#匹配MAC表达式
	mac_result=mac_pattern.findall(white_list_cmd_result)#执行MAC表达式
	name_pattern=re.compile("/\*(.*?)\*/")#匹配设备名表达式
	name_result=name_pattern.findall(white_list_cmd_result)#执行表达式
	white_handle.close()
	return render_template('white_list_info.html',white_list_results=white_list_result,speed_results=speed_result,mac_results=mac_result,name_results=name_result)#显示白名单列表
@app.route('/changemac',methods=['GET'])
def changemac():#置顶MAC函数
	if request.args.get("button") in u"置顶":#如果点击置顶按钮
		mac=request.args.get("mac")#获取提交的MAC
		mac_name=request.args.get("mac_name")#获取提交的名字
		white_list_result = []#定义一列表
		with open('/usr/local/eas/white_list','r+') as white_handle:#读取白名单
			for line in white_handle.readlines():
				line=line.strip().decode('utf-8')#将文件中的白名单去空格压入列表
				white_list_result.append(line)
			mac=mac+'#'+mac_name#MAC加姓名
			#mac2=1 * '01' + mac[2:]#MAC前2位变01
			white_list_result.remove(mac)#移除列表中提交的MAC
			white_list_result.insert(0,mac)#将提交的MAC置于列表的顶端
			white_handle.seek(0)#定位到文件开头
			white_handle.truncate()#清空文件
			for i in white_list_result:#将列表中的信息写入文本
				white_handle.write(i.encode('utf-8')+'\n')
			#white_list_result.insert(1,mac2)#将01的MAC加入到列表第二行
			os.popen("iptables -F white_list")#清空链表
			white_list_result.reverse()#将列表反转
			for i in white_list_result:#将列表写入链
				mac2=1 * '01' + i[0:17][2:]#将MAC转2位换成01
				cmd = 'iptables -I white_list -m mac --mac-source '+mac2+' -m comment --comment '+ i[18:]+' -j RETURN'#加入链表
				cmd = cmd.encode('utf-8')
				os.popen(cmd)
				cmd = 'iptables -I white_list -m mac --mac-source '+i[0:17]+' -m comment --comment '+ i[18:]+' -j RETURN'#加入链表
				cmd = cmd.encode('utf-8')
				os.popen(cmd)
			cmd = "/usr/local/eas/wx_iptables"#执行通用放行列表
			cmd = cmd.encode('utf-8')
			os.popen(cmd)
			white_handle.close()#关闭文件
		return redirect('/info/white_list_info')
	if request.args.get("button") in u"删除":# 如果点击删除按钮
		mac=request.args.get("mac")#获取提交的MAC
		mac_name=request.args.get("mac_name")#获取提交的名字
		white_list_result = []#定义一列表
		with open('/usr/local/eas/white_list','r+') as white_handle:#读取白名单
			for line in white_handle.readlines():#将文件中的白名单去空格压入列表n
				line=line.strip().decode('utf-8')
				white_list_result.append(line)
			mac=mac+'#'+mac_name#MAC加姓名
			#mac2=1 * '01' + mac[2:]
			white_list_result.remove(mac)#移除列表中提交的MAC
			white_handle.seek(0)#定位到文件开头
			white_handle.truncate()#清空文件
			for i in white_list_result:
				white_handle.write(i.encode('utf-8')+'\n')#将列表中的信息写入文本
			#white_list_result.insert(1,mac2)
			os.popen("iptables -F white_list")#清空链表
			white_list_result.reverse()#将列表反转
			for i in white_list_result:
				mac2=1 * '01' + i[0:17][2:]#将MAC转2位换成01
				cmd = 'iptables -I white_list -m mac --mac-source '+mac2+' -m comment --comment '+ i[18:]+' -j RETURN'#加入链表
				cmd = cmd.encode('utf-8')
				os.popen(cmd)
				cmd = 'iptables -I white_list -m mac --mac-source '+i[0:17]+' -m comment --comment '+ i[18:]+' -j RETURN'#加入链表
				cmd = cmd.encode('utf-8')
				os.popen(cmd)
			cmd = "/usr/local/eas/wx_iptables"#执行通用放行列表
			cmd = cmd.encode('utf-8')
			os.popen(cmd)
			white_handle.close()
		return redirect('/info/white_list_info')#跳转到白名单列表
	if request.args.get("button") in u"添加黑名单":#如果点击添加黑名单列表
		mac=request.args.get("mac")#获取MAC参数
		num=request.args.get("num")#获取访问数量
		if len(mac) == 12:
			mac = ':'.join(re.findall(r'.{2}',mac))#如果MAC等于12位，就在中间加:号
		black_list_result = []#定义一数组
		with open('/usr/local/eas/black_list','r+') as black_handle:#读取黑名单列表
			for line in black_handle.readlines():
				line=line.strip().decode('utf-8')
				black_list_result.append(line)#读取黑名单压入数组
			mac=mac+'#'+num#MAC+数量
			black_list_result.insert(0,mac)#插入数组0定位
			black_handle.seek(0)#偏移
			black_handle.truncate()#清空数组
			for i in black_list_result:#写入黑名单
				black_handle.write(i.encode('utf-8')+'\n')
			os.popen("iptables -F black_list")#清空链表
			black_list_result.reverse()#反转数组
			for i in black_list_result:#将数组赋值给i
				cmd = 'iptables -I black_list -m mac --mac-source '+i[0:17]+' -j DROP'#加入黑名单链
				cmd = cmd.encode('utf-8')
				os.popen(cmd)
			black_handle.close()
		return redirect('/info/black_list_info')#完成后跳转到黑名单页面
	if request.args.get("button") in u"删除黑名单":#如果点击删除黑名单
		mac=request.args.get("mac")#获取MAC参数
		num=request.args.get("num")#获取访问数量
		if len(mac) == 12:
			mac = ':'.join(re.findall(r'.{2}',mac))#如果MAC等于12位，就在中间加:号
		black_list_result = []#定义一数组
		with open('/usr/local/eas/black_list','r+') as black_handle:#读取黑名单列表
			for line in black_handle.readlines():#读取黑名单压入数组
				line=line.strip().decode('utf-8')
				black_list_result.append(line)
			mac=mac+'#'+num#MAC+数量
			black_list_result.remove(mac)#在数组中移除相关mac
			black_handle.seek(0)#偏移
			black_handle.truncate()#清空数组
			for i in black_list_result:
				black_handle.write(i.encode('utf-8')+'\n')
			os.popen("iptables -F black_list")#清空链表
			black_list_result.reverse()#反转数组
			for i in black_list_result:
				cmd = 'iptables -I black_list -m mac --mac-source '+i[0:17]+' -j DROP'#加入黑名单链
				cmd = cmd.encode('utf-8')
				os.popen(cmd)
			black_handle.close()
		return redirect('/info/black_list_info')#完成后跳转到黑名单页面
@app.route('/info/black_list_info',methods=['GET'])
def black_list_info():
	black_list_result = []
	with open('/usr/local/eas/black_list','r') as black_handle: #读取黑名单文件
		for line in black_handle.readlines():
			line=line.strip().decode('utf-8')
			black_list_result.append(line)
	black_list_cmd = os.popen("iptables -L black_list -nv --line-numbers")# 显示黑名单链数据
	black_list_cmd_result=black_list_cmd.read().decode('utf-8')
	black_handle.close()
	return render_template('black_list_info.html',black_list_results=black_list_result,black_list_cmd_results=black_list_cmd_result)#显示黑名单页面
if __name__=='__main__':
	app.run(host='0.0.0.0',port='80',debug=True)  #开启http服务器，端口为81,并且打开调试模式