#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH
#===================================================================#
#   System Required:  EdgeMax V1.9                                  #
#   Description: Install adbyby For EdgeMax1.9                      #
#   Author: landvd <5586822@qq.com>                                 #
#                                                                   #
#===================================================================#
function PidFind()  
{  
    PIDCOUNT=`ps -ef | grep $1 | grep -v "grep" | grep -v $0 | awk '{print $2}' | wc -l`;  
    if [ ${PIDCOUNT} -gt 1 ] ; then  
        echo "There are too many process contains name[$1]"  
    elif [ ${PIDCOUNT} -le 0 ] ; then  
        echo "No such process[$1]!"  
    else  
        PID=`ps -ef | grep $1 | grep -v "grep" | grep -v ".sh" | awk '{print $2}'` ;  
        echo "Find the PID of this progress!--- process:$1 PID=[${PID}] ";  
echo "Kill the process $1 ...";  
        kill -9  ${PID};  
        echo "kill -9 ${PID} $1 done!";  
    fi  
}  
PidFind /usr/sbin/lighttpd -f /etc/lighttpd/lighttpd.conf #关闭原厂lighttpd进程
PidFind python /var/www/python/gui.py #关闭原厂主进程
chmod +x /tmp/erx/get-pip.py #安装pip环境
python /tmp/erx/get-pip.py #安装pip环境
pip install flask #安装flask环境
pip install supervisor #安装进程管理软件supervisor
cp -f /tmp/erx/supervisord.conf /etc/supervisord.conf
cp -f /etc/lighttpd/conf-enabled/10-ssl.conf /etc/lighttpd/conf-enabled/10-ssl.confbak #备份原配置文件
cp -f /tmp/erx/eas/10-ssl.conf /etc/lighttpd/conf-enabled/10-ssl.conf #复盖文件
cp -f -r /tmp/erx/eas /usr/local #复制文件到指定目录
cp -f /tmp/erx/eas_startup /config/scripts/post-config.d #复制启动文件到启动目录
echo "Install Main File Success"
chmod +x /usr/local/eas/eas #授权权限
chmod +x /usr/local/eas/delay
chmod +x /usr/local/eas/loganalyzer
chmod +x /usr/local/eas/index.py
chmod +x /usr/local/eas/wx_iptables
chmod 777 /usr/local/eas/white_list
chmod 777 /usr/local/eas/black_list
chmod 777 /usr/local/eas/wx_iptables
chmod 777 /config/scripts/post-config.d/eas_startup
chmod 777 /usr/local/eas/log
chmod 644 /var/log/messages
echo "* */1 * * * /usr/local/eas/loganalyzer" >> /var/spool/cron/crontabs/root #启用定时任务，每1小时执行MAC访问量分析
echo "Set MainFile Permissions Success"
echo "Now eas install success,Enjoy!!!"
/config/scripts/post-config.d/eas_startup #启动主进程
/usr/sbin/lighttpd -f /etc/lighttpd/lighttpd.conf #启动原厂lighttpd进程