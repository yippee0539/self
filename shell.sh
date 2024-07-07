# 8.5p1 <= openssh < 9.8p1

get_suffix() {
	date +%Y%m%d
}
prompt() {
	read -p "$1: " input
	echo "$input"
}

sourceslist_config() {
	sourceslist_path=/etc/apt/sources.list
	sourcesurl=$(prompt "输入源地址")
	version=$(prompt "输入版本代号")
	if [ -e $sourceslist_path ]; then
		mv $sourceslist_path $sourceslist_path$(get_suffix)
	fi
	eval echo 'deb $sourcesurl $version main restricted universe multiverse' > $sourceslist_path
	eval echo 'deb-src $sourcesurl $version main restricted universe multiverse' >> $sourceslist_path
	eval echo 'deb $sourcesurl $version-security main restricted universe multiverse' >> $sourceslist_path
	eval echo 'deb-src $sourcesurl $version-security main restricted universe multiverse' >> $sourceslist_path
	eval echo 'deb $sourcesurl $version-updates main restricted universe multiverse' >> $sourceslist_path
	eval echo 'deb-src $sourcesurl $version-updates main restricted universe multiverse' >> $sourceslist_path
	eval echo 'deb $sourcesurl $version-backports main restricted universe multiverse' >> $sourceslist_path
	eval echo 'deb-src $sourcesurl $version-backports main restricted universe multiverse' >> $sourceslist_path
}

vim_config() {
	vim_path=/root/.vimrc
	if [ -e $vim_path ]; then
		mv $vim_path $vim_path$(get_suffix)
	fi
	echo 'syntax on' > $vim_path
	echo 'set incsearch' >> $vim_path
	echo 'set number' >> $vim_path
	echo 'hi comment ctermfg=6' >> $vim_path
	echo 'set tabstop=4' >> $vim_path
	echo 'set mouse-=a' >> $vim_path
}

bash_config() {
    bash_path=/root/.bashrc
    hostname=$(prompt "输入显示主机名")
    if [ -e $bash_path ]; then
        mv $bash_path $bash_path$(get_suffix)
    fi
    echo 'alias ll="ls -al --color=auto"' > $bash_path
    eval echo 'export HOSTNAME="$hostname"' >> $bash_path
    echo 'PS1="\[\e[37;1m\][\[\e[36;1m\]\u\[\e[31;1m\]@\[\e[36;1m\]\$HOSTNAME\[\e[31;1m\]:\[\e[34;1m\]\w\[\e[37;1m\]]\$ \[\e[m\]"' >> $bash_path
    source $bash_path
}

ssh_config() {
	public_key=$(prompt "输入公钥")
	key_file=authorized_keys
	key_dir=/root/.ssh
	ssh_path=/etc/ssh/sshd_config
	if [ -e $key_dir/$key_file ]; then
		cp $key_dir/$key_file $key_dir/$key_file$(get_suffix)
	fi

	mkdir -p $key_dir
	eval echo '$public_key' > $key_dir/$key_file
	sed -i -E '/^\s*#*\s*PubkeyAuthentication\s+(yes|no)\s*$/d' $ssh_path
	sed -i -E '/^\s*#*\s*PasswordAuthentication\s+(yes|no)\s*$/d' $ssh_path
	sed -i -E '/^\s*#*\s*PermitRootLogin\s+(yes|no)\s*$/d' $ssh_path
	echo 'PubkeyAuthentication yes' >> $ssh_path
	echo 'PasswordAuthentication yes' >> $ssh_path
	echo 'PermitRootLogin yes' >> $ssh_path
}

network_algorithm_config() {
	network_path=/etc/sysctl.conf
	if [ -e $network_path ]; then
		cp $network_path $network_path$(get_suffix)
	fi
	sed -i '/^\s*#*\s*net\.core\.default_qdisc=\w*\s*$/d' $network_path
	sed -i '/^\s*#*\s*net\.ipv4\.tcp_congestion_control=\w*\s*$/d' $network_path
	echo 'net.core.default_qdisc=fq' >> $network_path
	echo 'net.ipv4.tcp_congestion_control=bbr' >> $network_path
}

warp_config() {
	warp_home=/usr/bin/warp
	warp_url=''
	param=$(prompt "4/6/46, 4 优")
	if [ -e $warp_home ]; then
		warp $param
	else
		curl -sSL $warp_url | bash -s --$param
	fi
}

swap_config() {
	swap_path=/etc/fstab
	capacity=$(prompt "swap 大小(G)")
	if [ -e $swap_path ]; then
		cp $swap_path $swap_path$(get_suffix)
	fi
	if sed -n "/^\s*\/swapfile swap swap.*$/p" $swap_path | grep -q .; then
		swapoff /swapfile
		sed -i "/^\s*\/swapfile swap swap.*$/d" $swap_path
		rm /swapfile
	fi

	fallocate -l ${capacity}G /swapfile
	chmod 600 /swapfile
	mkswap /swapfile
	swapon /swapfile
	echo "/swapfile swap swap defaults 0 0" >> $swap_path
	swapon --show
}

iptables_config() {
	ipv4_sniffer=4.ipw.cn
	ipv6_sniffer=6.ipw.cn
	ipv4=$(curl -s $ipv4_sniffer)
	ipv6=$(curl -s $ipv6_sniffer)
	if [[ $ipv4 =~ ^((([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5]))$ ]]; then
		iptables -F

		iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
		iptables -A INPUT -p tcp --dport 22 -j ACCEPT
		iptables -A INPUT -p tcp --dport 80 -j ACCEPT
		iptables -A INPUT -p tcp --dport 443 -j ACCEPT
		iptables -A INPUT -p udp --sport 53 -j ACCEPT
		iptables -A INPUT -p tcp --sport 53 -j ACCEPT
		iptables -A INPUT -i lo -j ACCEPT

		iptables -P OUTPUT ACCEPT
		iptables -P INPUT DROP
		iptables -P FORWARD DROP
	fi
	if [[ $ipv6 =~ ^([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|([0-9A-Fa-f]{1,4}:){7}:|([0-9A-Fa-f]{1,4}:){6}:[0-9A-Fa-f]{1,4}|([0-9A-Fa-f]{1,4}:){5}(:[0-9A-Fa-f]{1,4}){1,2}|([0-9A-Fa-f]{1,4}:){4}(:[0-9A-Fa-f]{1,4}){1,3}|([0-9A-Fa-f]{1,4}:){3}(:[0-9A-Fa-f]{1,4}){1,4}|([0-9A-Fa-f]{1,4}:){2}(:[0-9A-Fa-f]{1,4}){1,5}|[0-9A-Fa-f]{1,4}:((:[0-9A-Fa-f]{1,4}){1,6})|:((:[0-9A-Fa-f]{1,4}){1,7})$ ]]; then
		ip6tables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
		ip6tables -A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
		ip6tables -A INPUT -p tcp -m tcp --dport 80 -j ACCEPT
		ip6tables -A INPUT -p tcp -m tcp --dport 443 -j ACCEPT
		ip6tables -A INPUT -p udp -m udp --sport 53 -j ACCEPT
		ip6tables -A INPUT -p tcp -m tcp --sport 53 -j ACCEPT

		ip6tables -A INPUT -p ipv6-icmp -m icmp6 --icmpv6-type 133 -j ACCEPT
		ip6tables -A INPUT -p ipv6-icmp -m icmp6 --icmpv6-type 134 -j ACCEPT
		ip6tables -A INPUT -p ipv6-icmp -m icmp6 --icmpv6-type 135 -j ACCEPT
		ip6tables -A INPUT -p ipv6-icmp -m icmp6 --icmpv6-type 136 -j ACCEPT
		ip6tables -A INPUT -p ipv6-icmp -m icmp6 --icmpv6-type 137 -j ACCEPT
		ip6tables -A INPUT -p udp -m udp --sport 547 --dport 546 -j ACCEPT

		ip6tables -A INPUT -i lo -j ACCEPT
	fi
}

oracle_alive_config() {
	source <(curl -sSL https://gitlab.com/spiritysdx/Oracle-server-keep-alive-script/-/raw/main/oalive.sh) <<EOF
1
n
1
y
n
EOF
}

go_naive_config() {
	domain=$(prompt "输入监听域名")
	userid=$(prompt "用户名(字母数字)")
	passwd=$(prompt "密码(字母数字)")
	reverse=$(prompt "反代地址")
	home_path=/home/go_naive
	caddyfile_path=$home_path/Caddyfile
	apt install git
	mkdir -p $home_path
	cd $home_path
	git clone https://github.com/udhos/update-golang
	./update-golang/update-golang.sh
	source /etc/profile.d/golang_path.sh

	go env -w GO111MODULE=on
	go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest

	~/go/bin/xcaddy build --with github.com/caddyserver/forwardproxy@caddy2=github.com/klzgrad/forwardproxy@naive

	eval echo ':443, $domain' > $caddyfile_path
	echo 'tls yippee@emple.com' >> $caddyfile_path
	echo 'route {' >> $caddyfile_path
	echo ' forward_proxy {' >> $caddyfile_path
	eval echo '   basic_auth $userid $passwd' >> $caddyfile_path
	echo '   hide_ip' >> $caddyfile_path
	echo '   hide_via' >> $caddyfile_path
	echo '   probe_resistance' >> $caddyfile_path
	echo '  }' >> $caddyfile_path
	eval echo ' reverse_proxy  $reverse  {' >> $caddyfile_path
	echo '   header_up  Host  {upstream_hostport}' >> $caddyfile_path
	echo '   header_up  X-Forwarded-Host  {host}' >> $caddyfile_path
	echo '  }' >> $caddyfile_path
	echo '}' >> $caddyfile_path

	./caddy start
}

serverstatus_config() {
        service_dir=/etc/systemd/system/
        service_file=serverstatus-client.service
        if [ -e $service_dir$service_file ]; then
                systemctl stop $service_file
                systemctl disable $service_file
                mv $service_dir$service_file $service_dir$service_file$(get_suffix)
        fi

        apt install python3
        user=$(prompt "输入用户名")
        passwd=$(prompt "输入密码")
        priority=$(prompt "优先级 4/6")
        server=$(prompt "服务器地址")

        if [ -e "/home/client-linux.py" ]; then
                mv /home/client-linux.py /home/client-linux.py$(get_suffix)
        fi

        curl -sSL https://github.com/cppla/ServerStatus/raw/master/clients/client-linux.py -o /home/client-linux.py
        sed -i "s/SERVER = \"127.0.0.1\"/SERVER = \"$server\"/g" /home/client-linux.py
        sed -i "s/USER = \"s01\"/USER = \"$user\"/g" /home/client-linux.py
        sed -i "s/PASSWORD = \"USER_DEFAULT_PASSWORD\"/PASSWORD = \"$passwd\"/g" /home/client-linux.py
        sed -i "s/PROBE_PROTOCOL_PREFER = \"ipv4\"/PROBE_PROTOCOL_PREFER = \"ipv$priority\"/g" /home/client-linux.py

        echo '[Unit]' > $service_dir$service_file
        echo 'Description=serverstatus-client Service' >> $service_dir$service_file
        echo 'After=network.target' >> $service_dir$service_file
        echo '' >> $service_dir$service_file
        echo '[Service]' >> $service_dir$service_file
        echo 'WorkingDirectory=/home' >> $service_dir$service_file
        echo 'ExecStart=python3 /home/client-linux.py' >> $service_dir$service_file
        echo 'Restart=always' >> $service_dir$service_file
        echo 'User=root' >> $service_dir$service_file
        echo '' >> $service_dir$service_file
        echo '[Install]' >> $service_dir$service_file
        echo 'WantedBy=multi-user.target' >> $service_dir$service_file

        systemctl enable $service_file
        systemctl start $service_file
}

openssh_update() {
        version=$(ssh -V 2>&1 | sed -n 's/^OpenSSH_\([0-9.]*p[0-9]*\).*$/\1/p')
        major=$(echo "$version" | cut -d '.' -f 1)
        minor=$(echo "$version" | cut -d '.' -f 2 | cut -d 'p' -f 1)
        patch=$(echo "$version" | cut -d 'p' -f 2)
        min_major=8
        min_minor=5
        min_patch=1
        max_major=9
        max_minor=8
        max_patch=1

        if [[ $major -gt $min_major ]] || ([[ $major -eq $min_major ]] && [[ $minor -gt $min_minor ]]) || ([[ $major -eq $min_major ]] && [[ $minor -eq $min_minor ]] && [[ $patch -ge $min_patch ]]); then
            if [[ $major -lt $max_major ]] || ([[ $major -eq $max_major ]] && [[ $minor -lt $max_minor ]]) || ([[ $major -eq $max_major ]] && [[ $minor -eq $max_minor ]] && [[ $patch -lt $max_patch ]]); then
                apt install openssh-server
            fi
        fi
}


}

menu=$(prompt "菜单
1.软件源配置
2.vim 配置
3.bash 配置
4.ssh 配置
5.拥塞算法配置
6.warp 配置
7.swap 配置
8.iptables 配置
9.oracle_alive 配置
a.go_naive 配置
b.添加 servicestatus 监控
c.openssh 漏洞升级
0. 全部配置
")

#while true; do
	case $menu in
		1) sourceslist_config;;
		2) vim_config;;
		3) bash_config;;
		4) ssh_config;;
		5) network_algorithm_config;;
		#6) warp_config;;
		7) swap_config;;
		8) iptables_config;;
		9) oracle_alive_config;;
		#a) go_naive_config;;
                b) serverstatus_config;;
		c) openssh_update;;
	#	*) ;;
	esac
#done
