#!/bin/bash

format='telegraf'
# bpfscript='/usr/local/sbin/bpf-nfsd.bt'
bpfscript='bpftrace/nfsd-clients.bt'

# only used for graphite
graphiteify() {
	echo "$1" | tr '.' '_'
}
gtmpfile='/tmp/graphite-nfsclients'
gprefix="nfs.$(graphiteify "$(hostname -f)").clients"

HELP="Usage: collect-bpf-nfsd.sh [OPTIONS]

Optional:
    -f|--format FORMAT
        Output format (default: $format)
	Supported formats: telegraf, graphite
    --bpf-script PATH
        Location of the BPF script (default: $bpfscript)
    --graphite-prefix PREFIX
        Metric prefix for graphite output (default: $gprefix)
    --graphite-tmpfile PATH
        Temp file for graphite output (default: $gtmpfile)
    -h|--help
        Print this help message and exit
"

to_ipv4() {
	local num=$1
	local x1=$(( num & 0xff ))
	local x2=$(( (num >> 8) & 0xff ))
	local x3=$(( (num >> 16) & 0xff ))
	local x4=$(( (num >> 24) & 0xff ))

	echo "$x1.$x2.$x3.$x4"
}

to_ipv6() {
	# TODO Test if formatting is correct
	local hi=$1
	local lo=$2

	local x0=$(( (hi >> 48) & 0xffff ))
	local x1=$(( (hi >> 32) & 0xffff ))
	local x2=$(( (hi >> 16) & 0xffff ))
	local x3=$((  hi        & 0xffff ))
	local x4=$(( (lo >> 48) & 0xffff ))
	local x5=$(( (lo >> 32) & 0xffff ))
	local x6=$(( (lo >> 16) & 0xffff ))
	local x7=$((  lo        & 0xffff ))

	local ipv6
	printf -v ipv6 "%x:%x:%x:%x:%x:%x:%x:%x" \
		$x0 $x1 $x2 $x3 $x4 $x5 $x6 $x7

	echo "$ipv6"
}

telegraf() {
	echo "count,uid,ip"

	bpftrace -q - < "$bpfscript" | sed '/^$/d' | awk -F'[\\[,\\]: ]' '{print $9","$2","$4","$1","$6}' | \
	while IFS=, read -r count uid ip iptype iprest; do
		if [ "$iptype" = "@ip4" ]; then
			echo "${count},${uid},$(to_ipv4 "${ip}")"
		elif [ "$iptype" = "@ip6" ]; then
			#TODO Test if IPv6 formatting is correct
			echo "${count},${uid},$(to_ipv6 "${ip}" "${iprest}")"
		else
			echo "Error, invalid ip type: ${iptype}" >&2
		fi
	done
}

graphite() {
	timestamp=$(date +%s)

	# parse the bucketed format from bpftrace
	bpftrace -q - < "$bpfscript" | sed '/^$/d' | awk -F'[\\[,\\]: ]' '{print $9","$2","$4","$1","$6}' | \
	while IFS=, read -r count uid ip iptype iprest; do
		local ipaddr
		if [ "$iptype" = "@ip4" ]; then
			ipaddr=$(to_ipv4 "$ip")
		elif [ "$iptype" = "@ip6" ]; then
			ipaddr=$(to_ipv6 "$ip" "$iprest")
		else
			echo "Error, invalid ip type: ${iptype}" >&2
			continue
		fi
		echo "${uid} ${ipaddr} ${count}"
	done > "$gtmpfile"

	# try to resolve ip addresses
	for ipaddr in $(awk '{print $2}' "$gtmpfile" | sort | uniq); do
		host=$(graphiteify "$(dig +short -x "$ipaddr" | sed 's/\.$//')")
		if [ "$host" != "" ]; then
			sed -i "s/${ipaddr}/${host}/g" "$gtmpfile"
		else
			ip_under=$(graphiteify "$ipaddr")
			sed -i "s/${ipaddr}/${ip_under}/g" "$gtmpfile"
		fi
	done

	# try to resolve uids
	for uid in $(awk '{print $1}' "$gtmpfile" | sort | uniq); do
		uname=$(awk -F':' '{print $1, $3}' /etc/passwd | grep -w "$uid" | awk '{print $1}')
		if [ "$uname" != "" ]; then
			sed -i "s/${uid} /${uname} /g" "$gtmpfile"
		fi
	done

	while read -r uid ipaddr num; do
		echo "${gprefix}.by-client.${ipaddr}.${uid} $num $timestamp"
		echo "${gprefix}.by-user.${uid}.$ipaddr $num $timestamp"
	done < "$gtmpfile"

	rm -f "$gtmpfile"
}

while [[ "$#" -gt 0 ]]; do
	case $1 in
		-h|--help)
			echo "$HELP"
			exit 0
			;;
		-f|--format)
			format=$2
			shift; shift
			;;
		--bpf-script)
			bpfscript=$2
			shift; shift
			;;
		--graphite-prefix)
			gprefix=$2
			shift; shift
			;;
		--graphite-tmpfile)
			gtmpfile=$2
			shift; shift
			;;
		*)
			echo "Unrecognized option $1"
			echo "$HELP"
			exit 1
			;;
	esac
done

if [ ! -f "$bpfscript" ]; then
	echo "BPF script $bpfscript does not exist"
	exit 1
fi

case $format in
	telegraf)
		telegraf
		;;
	graphite)
		graphite
		;;
	*)
		echo "Unknown format $format"
		exit 1
		;;
esac
