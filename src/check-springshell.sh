#! /bin/sh
#
# Originally written by Jan Schaumann
# <jschauma@netmeister.org> in March 2022.
#
# This script attempts to determine whether the host
# it runs on is likely to be vulnerable to SpringShell RCE
# CVE-2022-22963.
#
# Derived from https://github.com/yahoo/check-log4j by
# the same author. (This should be abstracted into a
# more generic 'check for horrible jars' tool.)
#
# Copyright 2022 Yahoo Inc.
#
# Licensed under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in
# compliance with the License.  You may obtain a copy of
# the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in
# writing, software distributed under the License is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing
# permissions and limitations under the License.


set -eu
IFS="$(printf '\n\t')"

umask 077

###
### Globals
###

PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:/home/y/bin:/home/y/sbin

CVE="CVE-2022-22963"

# Per https://tanzu.vmware.com/security/cve-2022-22963:
MAJOR_WANTED="3"
MINOR_WANTED="1"
TINY_WANTED="7"

MAJOR_ALT_WANTED="3"
MINOR_ALT_WANTED="2"
TINY_ALT_WANTED="2"

FATAL_CLASS="CachedIntrospectionResults.class"

_TMPDIR=""
CHECK_JARS=""
ENV_VAR_SET="no"
FOUND_JARS=""
PROGNAME="${0##*/}"
RETVAL=1
SEARCH_PATHS=""
SKIP=""
SEEN_JARS=""
SUSPECT_CLASSES=""
SUSPECT_JARS=""
SUSPECT_PACKAGES=""
UNZIP="$(command -v unzip 2>/dev/null || true)"
VERBOSITY=0
VERSION="0.1"
YINST_PREFIX="/home/y"
YINST_SET_PACKAGES=""

LOGPREFIX="${PROGNAME} ${VERSION} ${HOSTNAME:-"localhost"}"

###
### Functions
###


cdtmp() {
	if [ -z "${_TMPDIR}" ]; then
		_TMPDIR=$(mktemp -d ${TMPDIR:-/tmp}/${PROGNAME}.XXXX)
	fi
	cd "${_TMPDIR}"
}

checkFilesystem() {
	local class=""
	local classes=""
	local okVersion=""
	local newjars=""
	local findCmd=""

	if expr "${SKIP}" : ".*files" >/dev/null; then
		verbose "Skipping files check." 2
		return
	fi

	verbose "Searching for java archives on the filesystem..." 3
	findCmd=$(echo find ${CHECK_SPRINGSHELL_FIND_OPTS_PRE:-""} "${SEARCH_PATHS:-/}" ${CHECK_SPRINGSHELL_FIND_OPTS_POST:-""})

	verbose "Running '${findCmd}'..." 4

	newjars=$(eval ${findCmd} -type f -iname \'*.[ejw]ar\' 2>/dev/null || true)
	FOUND_JARS="$(printf "${FOUND_JARS:+${FOUND_JARS}\n}${newjars}")"

	verbose "Searching for ${FATAL_CLASS} on the filesystem..." 3
	classes=$(eval ${findCmd} -type f -iname "${FATAL_CLASS}" 2>/dev/null || true)

	for class in ${classes}; do
		okVersion="$(checkFixedVersion "${class}")"
		if [ -z "${okVersion}" ]; then
			log "Possibly vulnerable class ${class}."
			SUSPECT_CLASSES="$(printf "${SUSPECT_CLASSES:+${SUSPECT_CLASSES}\n}${class}")"
		fi
	done
}

checkFixedVersion() {
	local file="${1}"
	local ver=""
	local mgrClass=""
	local suffix="${file##*.}"
	local dir=""

	set +e
	if [ x"${suffix##*[ejw]}" = x"ar" ]; then
		if [ -z "${UNZIP}" ]; then
			warn "Unable to check if ${suffix} contains a fixed version since unzip(1) is missing."
			return
		fi
		verbose "Checking for fixed classes in '${file}'..." 6
		if zeroSize "${file}"; then
			verbose "Skipping zero-size file '${file}'..." 6
			return
		fi

		mgrClass="$(${UNZIP} -q -l "${file}" 2>/dev/null | awk 'tolower($0) ~ /cachedintrospectionresults.class$/ { print $NF; }')"
		if [ -n "${mgrClass}" ]; then
			cdtmp
			${UNZIP} -o -q "${file}" "${mgrClass}" 2>/dev/null
		fi
	elif [ x"${suffix}" = x"class" ]; then
		# If we find the fatal class outside of a jar, let's guess that
		# there might be an accompanying CachedIntrospectionResuLts.class nearby...
		mgrClass="${file%/*}/../net/CachedIntrospectionResuLts.class"
	fi
	set -e
}

checkInJar() {
	local jar="${1}"
	local needle="${2}"
	local pid="${3}"
	local parent="${4:-""}"
	local msg=""
	local match=""
	local flags=""
	local okVersion=""
	local rval=0

	local thisJar="${parent:+${parent}:}${jar}"
	for j in $(echo "${SEEN_JARS}" | tr ' ' '\n'); do
		if [ x"${j}" = x"${thisJar}" ]; then
			verbose "Skipping already seen archive '${thisJar}'..." 6
			return
		fi
	done
	SEEN_JARS="${SEEN_JARS:+${SEEN_JARS} }${thisJar}"

	if [ -z "${parent}" ]; then
		if zeroSize "${thisJar}"; then
			verbose "Skipping zero-size file '${thisJar}'..." 6
			return
		fi
	fi

	verbose "Checking for '${needle}' inside of ${jar}..." 5

	set +e
	if [ -n "${UNZIP}" ]; then
		${UNZIP} -q -l "${jar}" 2>/dev/null | grep -q "${needle}"
	else
		warn "unzip(1) not found, trying to grep..."
		grep -q "${needle}" "${jar}"
	fi
	rval=$?
	set -e

	if [ ${rval} -eq 0 ]; then
		if [ -n "${parent}" ]; then
			msg=" (inside of ${parent})"
		fi
		if [ x"${jar}" != x"${pid}" ] && expr "${pid}" : "[0-9]*$" >/dev/null; then
			msg="${msg} used by process ${pid}"
		fi

		okVersion="$(checkFixedVersion "${jar}")"
		if [ -z "${flags}" ]; then
			log "Possibly vulnerable archive '${jar}'${msg}."
		fi
		SUSPECT_JARS="${SUSPECT_JARS} ${thisJar}"
	fi
}

checkJars() {
	local found jar jarjar msg pid

	if [ -z "${CHECK_JARS}" ]; then
		findJars
	fi

	if [ -z "${FOUND_JARS}" ]; then
		return
	fi

	verbose "Checking all found jars and wars..." 2

	if [ -z "${UNZIP}" ]; then
		warn "unzip(1) not found, unable to peek into jars inside of jar!"
	fi
	for found in ${FOUND_JARS}; do
		pid="${found%%--*}"
		jar="${found#*--}"

		if [ -n "${UNZIP}" ]; then
			if zeroSize "${jar}"; then
				verbose "Skipping zero-size file '${jar}'..." 3
				continue
			fi
			jarjar="$(${UNZIP} -q -l "${jar}" 2>/dev/null | awk 'tolower($0) ~ /^ .*spring-beans.*[ejw]ar$/ { print $NF; }')"
			if [ -n "${jarjar}" ]; then
				extractAndInspect "${jar}" "${jarjar}" ${pid}
			fi
		fi

		checkInJar "${jar}" "${FATAL_CLASS}" "${pid}"
	done
}

checkOnlyGivenJars() {
	verbose "Checking only given jars..." 1
	FOUND_JARS="${CHECK_JARS}"
	checkJars
}

checkRpms() {
	verbose "Checking rpms..." 4

	local pkg version

	for pkg in $(rpm -qa --queryformat '%{NAME}--%{VERSION}\n' | grep spring-beans); do
		version="${pkg##*--}"
		if ! isFixedVersion "${version}"; then
			# Squeeze '--' so users don't get confused.
			pkg="$(echo "${pkg}" | tr -s -)"
			SUSPECT_PACKAGES="${SUSPECT_PACKAGES} ${pkg}"
		fi
	done
}

checkPackages() {
	if expr "${SKIP}" : ".*packages" >/dev/null; then
		verbose "Skipping package check." 2
		return
	fi

	verbose "Checking for vulnerable packages..." 2

	if [ x"$(command -v rpm 2>/dev/null)" != x"" ]; then
		checkRpms
	fi
}

checkProcesses() {
	local jars
	if expr "${SKIP}" : ".*processes" >/dev/null; then
		verbose "Skipping process check." 2
		return
	fi

	verbose "Checking running processes..." 3
	local lsof="$(command -v lsof 2>/dev/null || true)"
	if [ -z "${lsof}" ]; then
		jars="$(ps -o pid,command= -wwwax | awk 'tolower($0) ~ /[ejw]ar$/ { print $1 "--" $NF; }' | uniq)"
	else
		jars="$(${lsof} -c java 2>/dev/null | awk 'tolower($0) ~ /reg.*[ejw]ar$/ { print $2 "--" $NF; }' | uniq)"
	fi
	FOUND_JARS="${FOUND_JARS:+${FOUND_JARS} }${jars}"
}

cleanup() {
	if [ -n "${_TMPDIR}" ]; then
		rm -fr "${_TMPDIR}"
	fi
}

extractAndInspect() {
	local jar="${1}"
	local jarjar="${2}"
	local pid="${3}"
	local f

	verbose "Extracting ${jar} to look inside jars inside of jars..." 5

	cdtmp
	if ${UNZIP} -o -q "${jar}" ${jarjar} 2>/dev/null; then
		for f in ${jarjar}; do
			checkInJar "${f}" "${FATAL_CLASS}" ${pid} "${jar}"
		done
	fi
}

findJars() {
	verbose "Looking for jars..." 2
	checkProcesses
	checkFilesystem
}

isFixedVersion () {
	local version="${1}"
	local major minor

	major="${version%%.*}"  # 2.15.0 => 2
	minor="${version#*.}"   # 2.15.0 => 15.0
	tiny="${minor#*.}"      # 15.0 => 0

	# strip off any possible other sub-versions
	# e.g., 2.15.0.12345
	tiny="${tiny%%.*}"     # 0.12345 => 0
	minor="${minor%%.*}"   # 15.0 => 15

	# NaN => unknown
	if ! expr "${major}" : "[0-9]*$" >/dev/null; then
		return 1
	fi
	if ! expr "${minor}" : "[0-9]*$" >/dev/null; then
		return 1
	fi

	if [ ${major} -lt ${MAJOR_WANTED} ] ||
		[ ${major} -eq ${MAJOR_WANTED} -a ${minor} -lt ${MINOR_WANTED} ] ||
		[ ${major} -eq ${MAJOR_WANTED} -a ${minor} -eq ${MINOR_WANTED} -a ${tiny} -lt ${TINY_WANTED} ] ||
		[ ${major} -eq ${MAJOR_ALT_WANTED} -a ${minor} -eq ${MINOR_ALT_WANTED} -a ${tiny} -lt ${TINY_ALT_WANTED} ]; then
		return 1
	fi

	return 0
}

log() {
	msg="${1}"
	echo "${LOGPREFIX}: ${msg}"
}

springshellCheck() {
	verbose "Running all checks..." 1

	checkPackages
	checkJars
}

usage() {
	cat <<EOH
Usage: ${PROGNAME} [-hv] [-j jar] [-s skip] [-p path]
	-h       print this help and exit
	-j jar   check only this jar
	-p path  limit filesystem traversal to this directory
	-s skip  skip these checks (files, packages, processes)
	-v       be verbose
EOH
}

verbose() {
	local readonly msg="${1}"
	local level="${2:-1}"
	local i=0

	if [ "${level}" -le "${VERBOSITY}" ]; then
		while [ ${i} -lt ${level} ]; do
			printf "=" >&2
			i=$(( ${i} + 1 ))
		done
		echo "> ${msg}" >&2
	fi
}

verdict() {
	if [ -z "${SUSPECT_JARS}" -a -z "${SUSPECT_PACKAGES}" -a -z "${SUSPECT_CLASSES}" ]; then
		log "No obvious indicators of vulnerability to ${CVE} found."
		RETVAL=0
	fi

	if [ -n "${SUSPECT_JARS}" ]; then
		echo
		echo "The following archives were found to include '${FATAL_CLASS}':"
		echo "${SUSPECT_JARS# *}" | tr ' ' '\n'
	fi

	if [ -n "${SUSPECT_PACKAGES}" ]; then
		echo
		echo "The following packages might still be vulnerable:"
		echo "${SUSPECT_PACKAGES}"
		RETVAL=1
	fi
}

warn() {
	msg="${1}"
	echo "${LOGPREFIX}: ${msg}" >&2
}

zeroSize() {
	local file="${1}"
	local size

	# stat(1) is not portable :-/
	size="$(ls -l "${file}" | awk '{print $5}')"
	if [ x"${size}" = x"0" ]; then
		return 0
	fi

	return 1
}

###
### Main
###

trap 'cleanup' 0

while getopts 'Vhj:s:p:v' opt; do
	case "${opt}" in
		V)
			echo "${PROGNAME} ${VERSION}"
			exit 0
			# NOTREACHED
		;;
		h\?)
			usage
			exit 0
			# NOTREACHED
		;;
		j)
			d="${OPTARG%/*}"
			if [ x"${d}" = x"${OPTARG}" ]; then
				d="."
			fi
			f="$(cd "${d}" && pwd)/${OPTARG##*/}"
			CHECK_JARS="${CHECK_JARS:+${CHECK_JARS} }${f}"
		;;
		p)
			SEARCH_PATHS="${SEARCH_PATHS:+${SEARCH_PATHS} }$(cd "${OPTARG}" && pwd)/."
		;;
		s)
			SKIP="${SKIP} ${OPTARG}"
		;;
		v)
			VERBOSITY=$(( ${VERBOSITY} + 1 ))
		;;
		*)
			usage
			exit 1
			# NOTREACHED
		;;
	esac
done
shift $(($OPTIND - 1))

if [ $# -gt 0 ]; then
	usage
	exit 1
	# NOTREACHED
fi

if [ -z "${CHECK_JARS}" ]; then
	springshellCheck
else
	checkOnlyGivenJars
fi
verdict

exit ${RETVAL}
