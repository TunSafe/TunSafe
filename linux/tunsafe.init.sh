#/bin/bash
#
# chkconfig: - 99 01
# description: controls "TunSafe"
# config: /etc/sysconfig/TunSafe
#
### BEGIN INIT INFO
# Provides:          tunsafe
# Required-Start:    $network
# Short-Description: starts "TunSafe" in daemon mode
# Description:       starts "TunSafe" in daemon mode
### END INIT INFO
#
# (P) & (C) 2019 Peter Bieringer <pb@bieringer.de>
#
# at least supported:
#  QNAP 4.3.6 on TS-251+ (can use binary compiled on EL7)
#  EL7
#
# -------------------
# Supported commands:
# start
#  - add softlink /sbin/ip -> /bin/ip if missing and possible
#  - add iptables masquerading rule per peer (source) IP
#
# stop
#  - remove iptables masquerading rule per peer (source) IP
#
# autostart-add
#  - create softlink in rc directories
#
# autostart-remove
#  - remove softlink in rc directories
#
# status
#  - show status
#
# ------------
# Requirements
#  - lsof binary file
#  - sysctl binary file
#  - iptables binary file
#  - tunsafe binary file
#  - tunsafe configuration file
#
# ---------
# Changelog
# 20190728/PB: initial version

# source init configuration files, if existing
for config in /etc/sysconfig/TunSafe /etc/config/TunSafe.conf; do
	if [ -e "$config" ]; then
		echo "NOTICE: retrieve extra config from: $config"
		source "$config"
		break
	fi
done

TUNSAFE_BIN=${TUNSAFE_BIN:-/opt/sbin/tunsafe}
TUNSAFE_IFACE=${TUNSAFE_IFACE:-tun0}
TUNSAFE_CONF=${TUNSAFE_CONF:-/etc/TunSafe.conf}
TUNSAFE_RUN=${TUNSAFE_RUN:-/var/run/wireguard/$TUNSAFE_IFACE.sock}
TUNSAFE_INIT=${TUNSAFE_INIT:-/etc/init.d/tunsafe.init.sh}

# failsafe checks
if [ -z "$TUNSAFE_BIN" ]; then
	echo "ERROR : tunsafe binary variable is empty: TUNSAFE_BIN"
	exit 1
fi
if [ ! -e "$TUNSAFE_BIN" ]; then
	echo "ERROR : tunsafe binary is not existing: $TUNSAFE_BIN"
	exit 1
fi
if [ ! -x "$TUNSAFE_BIN" ]; then
	echo "ERROR : tunsafe binary is not executable: $TUNSAFE_BIN"
	exit 1
fi

if [ -z "$TUNSAFE_CONF" ]; then
	echo "ERROR : tunsafe configuration variable is empty: TUNSAFE_CONF"
	exit 1
fi
if [ ! -e "$TUNSAFE_CONF" ]; then
	echo "ERROR : tunsafe configuration is not existing: $TUNSAFE_CONF"
	exit 1
fi
if [ ! -r "$TUNSAFE_CONF" ]; then
	echo "ERROR : tunsafe configuration is not readable: $TUNSAFE_CONF"
	exit 1
fi
if [ ! -s "$TUNSAFE_CONF" ]; then
	echo "ERROR : tunsafe configuration is totally empty: $TUNSAFE_CONF"
	exit 1
fi

for bin in iptables lsof sysctl; do
	# check
	binary=$(which "$bin")
	if [ -z "$binary" ]; then
		echo "ERROR : '$bin' binary missing, can't proceed"
		exit 1
	fi
done

## functions
preparation()  {
	# check whether in binary hardcoded /sbin/ip is existing, in worst case create softlink
	if [ ! -e /sbin/ip ]; then
		if [ -x /bin/ip ]; then
			echo "NOTICE: softlink /sbin/ip -> /bin/ip is missing, create it now"
			ln -s /bin/ip /sbin
			if [ $? -ne 0 ]; then
				echo "ERROR : softlink /sbin/ip -> /bin/ip is missing, can't create ($!)"
				return 1
			else
				echo "NOTICE: softlink /sbin/ip -> /bin/ip is missing, successfully created"
			fi
		else
			echo "ERROR  : /sbin/ip missing, but /bin/ip is also missing, can't proceed"
			return 1
		fi
	fi

	# check whether IPv4 forwarding is active
	ip_forward=$(sysctl -n net.ipv4.ip_forward)
	if [ -z "$ip_forward" ]; then
		echo "ERROR : can't retrieve IPv4 forwarding status via sysctl"
		return 1
	fi
	if [ "$ip_forward" = "0" ]; then
		echo "NOTICE: IPv4 forwarding disabled, try to enable now"
		sysctl -q -w net.ipv4.ip_forward=1
		if [ $? -ne 0 ]; then
			echo "NOTICE: IPv4 forwarding disabled, can't enable ($!)"
		else
			echo "NOTICE: IPv4 forwarding disabled, successfully enabled"
		fi
	else
		echo "INFO  : IPv4 forwarding already enabled"
	fi
}


masquerade_peer() {
	# create/delete NAT rule per peer
	action=$1
	case $action in
	    add|delete)
		;;
	    *)
		echo "ERROR : unsupported or empty action: $action"
		return 1
	esac

	any="0.0.0.0/0"
	any_escaped=${any//./\.}
	grep ^AllowedIPs "$TUNSAFE_CONF" | awk -F= '{ print $2 }' | while read peer; do
		echo "INFO  : check NAT rule for peer: $peer"
		peer_escaped=${peer//./\.}
		# remove trailing /32
		peer_escaped=${peer_escaped/\/32}

		if iptables -n -t nat -L POSTROUTING | grep -wq "^MASQUERADE\s*all\s*--\s*$peer_escaped\s*$any_escaped\s*"; then
			case $action in
			    add)
				echo "NOTICE: NAT rule (source masquerading) already existing for peer: $peer"
				;;
			    delete)
				echo "INFO  : NAT rule (source masquerading) existing, delete now for peer: $peer"
				iptables -t nat -D POSTROUTING -s $peer -d $any -j MASQUERADE
				if [ $? -ne 0 ]; then
					echo "ERROR : NAT rule (source masquerading) existing for peer: $peer, can't delete ($!)"
				fi
				;;
			esac
		else
			case $action in
			    add)
				echo "INFO  : NAT rule (source masquerading) missing, create now for peer: $peer"
				iptables -t nat -I POSTROUTING -s $peer -d $any -j MASQUERADE
				if [ $? -ne 0 ]; then
					echo "ERROR : NAT rule (source masquerading) missing for peer: $peer, can't create ($!)"
					exit 1
				fi
				;;
			    delete)
				echo "NOTICE: NAT rule (source masquerading) not found for peer: $peer (already removed?)"
				;;
			esac
		fi
	done || return 1
}

## Status (start|stop|"default")
status() {
	action=$1

	if [ -e "$TUNSAFE_RUN" ]; then
		echo "INFO  : tunsafe socket found: $TUNSAFE_RUN"
		pid=$(lsof -t $TUNSAFE_RUN)
		if [ -n "$pid" ]; then
			echo "INFO  : tunsafe PID for socket found: $TUNSAFE_RUN -> $pid"
			return 0
		else
			case $action in
			    stop)
				echo "WARN  : tunsafe has socket, but no process: $TUNSAFE_RUN (already stopped?)"
				;;
			    start)
				echo "INFO  : tunsafe has socket, but no process: $TUNSAFE_RUN (ok)"
				return 1
				;;
			    *)
				echo "ERROR : tunsafe has socket, but no process: $TUNSAFE_RUN"
				return 1
				;;
			esac
		fi
	else
		echo "NOTICE: tunsafe socket not found: $TUNSAFE_RUN"
		return 1
	fi
}

## Start
start() {
	preparation || return 1
	masquerade_peer add || return 1
	
	if status start; then
		echo "NOTICE: tunsafe already running $TUNSAFE_RUN -> $pid"
	else
		$TUNSAFE_BIN start -n $TUNSAFE_IFACE -d $TUNSAFE_CONF
		if status; then
			echo "INFO  : tunsafe successfully started $TUNSAFE_RUN -> $pid"
		fi
	fi
}

## Stop
stop() {
	if status stop; then
		if [ -n "$pid" ]; then
			echo "INFO  : tunsafe PID for socket found: $TUNSAFE_RUN -> $pid - kill it now"
			kill $pid
		fi
	fi

	masquerade_peer delete
}

## Autostart (add|remove)
autostart() {
	action=$1

	case $action in
	    add|remove)
		;;
	    *)
		echo "ERROR : unsupported or empty action: $action"
		return 1
	esac

	if [ -z "$TUNSAFE_INIT" ]; then
		echo "ERROR : initscript variable empty: TUNSAFE_INIT (strange)"
		return 1
	fi
	if [ ! -x "$TUNSAFE_INIT" ]; then
		echo "ERROR : initscript missing: $TUNSAFE_INIT"
		return 1
	fi

	if [ -e	/sbin/qcfg ]; then
		# QNAP system
		init_start="/etc/rcS.d/S99$(basename $TUNSAFE_INIT)"
		init_stop="/etc/rcK.d/K01$(basename $TUNSAFE_INIT)"

		for entry in $init_start $init_stop; do
			if [ -e "$entry" ]; then
				case $action in
				    add)
					echo "NOTICE: softlink to $TUNSAFE_INIT already existing: $entry (nothing to do)"
					;;
				    remove)
					echo "INFO  : softlink to $TUNSAFE_INIT existing: $entry (remove it now)"
					rm -f "$entry"
					if [ $? -ne 0 ]; then
						echo "ERROR : softlink to $TUNSAFE_INIT existing: $entry (but can't be removed)"
					else
						echo "INFO  : softlink to $TUNSAFE_INIT existing: $entry (removed)"
					fi
					;;
				esac
			else
				case $action in
				    add)
					echo "NOTICE: softlink to $TUNSAFE_INIT missing: $entry (create it now)"
					ln -s $TUNSAFE_INIT $entry
					if [ $? -ne 0 ]; then
						echo "ERROR : softlink to $TUNSAFE_INIT missing: $entry, but can't create ($!)"
					else
						echo "NOTICE: softlink to $TUNSAFE_INIT missing: $entry (created)"
					fi
					;;
				    remove)
					echo "INFO  : softlink to $TUNSAFE_INIT already removed: $entry (nothing to do)"
					;;
				esac
			fi
		done
	elif [ -e /etc/redhat-release ]; then
		case $action in
		    add)
			echo "NOTICE: enable $TUNSAFE_INIT with chkconfig"
			chkconfig tunsafe.init.sh on
			;;
		    remove)
			echo "NOTICE: disable $TUNSAFE_INIT with chkconfig"
			chkconfig tunsafe.init.sh off
			;;
		esac
	else
		echo "ERROR : unsupported system"
	fi
}

## Main
case $1 in
    start)
	start || exit 1
	;;
    stop)
	stop
	;;
    restart)
	stop
	sleep 1
	start
	;;
    status)
	status
	;;
    autostart-add)
	autostart add
	;;
    autostart-remove)
	autostart remove
	;;
    *)
	echo "$0 start|stop|restart|status"
	echo "$0 autostart-add|autostart-remove"
	;;
esac

exit $?
