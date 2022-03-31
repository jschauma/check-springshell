#! /bin/sh
#
# Originally written by Jan Schaumann
# <jschauma@netmeister.org> in March 2022.
#
# This script attempts to determine whether the host
# it runs on is likely to be vulnerable to Spring
# Framework CVEs CVE-2022-22963 and CVE-2022-22965
# (aka "SpringShell").
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

CVES="CVE-2022-22963 and CVE-2022-22965"

# Per
# https://tanzu.vmware.com/security/cve-2022-22963, we
# are looking for Cloud Function spring-beans versions
# >= 3.1.6 or >= 3.2.2
SB_MAJOR_WANTED="3"
SB_MINOR_WANTED="1"
SB_TINY_WANTED="7"

SB_MAJOR_ALT_WANTED="3"
SB_MINOR_ALT_WANTED="2"
SB_TINY_ALT_WANTED="2"

SB_NAME="spring-beans"

# Per
# https://spring.io/blog/2022/03/31/spring-framework-rce-early-announcement,
# https://tanzu.vmware.com/security/cve-2022-22965
# we are looking for Spring Framework webmvc or
# webflux >= 5.3.18 or 5.2.20.
WEB_MAJOR_WANTED="5"
WEB_MINOR_WANTED="3"
WEB_TINY_WANTED="18"

WEB_MAJOR_ALT_WANTED="5"
WEB_MINOR_ALT_WANTED="2"
WEB_TINY_ALT_WANTED="20"

PACKAGE_NAMES="${SB_NAME} spring-webmvc spring-webflux"

FATAL_CLASSES="CachedIntrospectionResults.class EnableWebFlux.class EnableWebMvc.class"

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

	verbose "Searching for ${FATAL_CLASSES} on the filesystem..." 3
	for class in ${FATAL_CLASSES}; do
		classes=$(eval ${findCmd} -type f -iname "${class}" 2>/dev/null || true)

	for class in ${classes}; do
			log "Possibly vulnerable class ${class}."
			SUSPECT_CLASSES="$(printf "${SUSPECT_CLASSES:+${SUSPECT_CLASSES}\n}${class}")"
	done
	done
}

checkInJar() {
	local jar="${1}"
	local needle="${2}"
	local pid="${3}"
	local parent="${4:-""}"
	local msg=""
	local match=""
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
		${UNZIP} -q -l "${jar}" 2>/dev/null | egrep -q "${needle}"
	else
		warn "unzip(1) not found, trying to grep..."
		egrep -q "${needle}" "${jar}"
	fi
	rval=$?
	set -e

	if [ ${rval} -eq 0 ]; then
		if checkManifest "${jar}"; then
			return
		fi

		if [ -n "${parent}" ]; then
			msg=" (inside of ${parent})"
		fi
		if [ x"${jar}" != x"${pid}" ] && expr "${pid}" : "[0-9]*$" >/dev/null; then
			msg="${msg} used by process ${pid}"
		fi
		SUSPECT_JARS="${SUSPECT_JARS} ${thisJar}"
	fi
}

checkJars() {
	local classnames found jar jarjar msg names pid

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

	names="($(echo "${PACKAGE_NAMES}" | sed -e 's/ /|/g'))"
	classnames="$(echo ${FATAL_CLASSES} | sed -e 's/ /|/g')"

	for found in ${FOUND_JARS}; do
		pid="${found%%--*}"
		jar="${found#*--}"

		if [ -n "${UNZIP}" ]; then
			if zeroSize "${jar}"; then
				verbose "Skipping zero-size file '${jar}'..." 3
				continue
			fi
			jarjar="$(${UNZIP} -q -l "${jar}" 2>/dev/null | egrep -i "^ .*${names}-.*.[ejw]ar$" | awk '{ print $NF; }')"
			for j in ${jarjar}; do
				extractAndInspect "${jar}" "${j}" ${pid}
			done
		fi

		checkInJar "${jar}" "(${classnames})" "${pid}"
	done
}

checkManifest() {
	local jar="${1}"
	local manifest name version

	manifest="META-INF/MANIFEST.MF"

	verbose "Extracting ${jar} to check ${manifest}..." 5

	cdtmp
	if ${UNZIP} -o -q "${jar}" ${manifest} 2>/dev/null; then
		name="$(awk '/^Implementation-Title:/ { print $NF }' ${manifest} | tr -d [:space:])"
		version="$(awk '/^Implementation-Version:/ { print $NF }' ${manifest} | tr -d [:space:])"
		if echo "${PACKAGE_NAMES}" | grep -w -q "${name}" ; then
			if isFixedVersion "${name}" "${version}"; then
				return 0
			fi
		fi
	fi
	return 1
}

checkOnlyGivenJars() {
	verbose "Checking only given jars..." 1
	FOUND_JARS="${CHECK_JARS}"
	checkJars
}

checkRpms() {
	verbose "Checking rpms..." 4

	local name names pkg version

	names="($(echo "${PACKAGE_NAMES}" | sed -e 's/ /|/g'))"

	for pkg in $(rpm -qa --queryformat '%{NAME}--%{VERSION}\n' | egrep "${names}"); do
		name="${pkg%%--*}"
		version="${pkg##*--}"
		if ! isFixedVersion "${name}" "${version}"; then
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
	local classnames f

	verbose "Extracting ${jar} to look inside jars inside of jars..." 5
	classnames="$(echo ${FATAL_CLASSES} | sed -e 's/ /|/g')"

	cdtmp
	if ${UNZIP} -o -q "${jar}" ${jarjar} 2>/dev/null; then
		for f in ${jarjar}; do
			checkInJar "${f}" "(${classnames})" ${pid} "${jar}"
		done
	fi
}

findJars() {
	verbose "Looking for jars..." 2
	checkProcesses
	checkFilesystem
}

isFixedVersion() {
	local pkg="${1}"
	local version="${2}"
	local major minor tiny

	local wanted_major wanted_minor wanted_tiny
	local alt_wanted_major alt_wanted_minor alt_wanted_tiny

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

	wanted_major="${SB_MAJOR_WANTED}"
	wanted_minor="${SB_MINOR_WANTED}"
	wanted_tiny="${SB_TINY_WANTED}"
	alt_wanted_major="${SB_MAJOR_ALT_WANTED}"
	alt_wanted_minor="${SB_MINOR_ALT_WANTED}"
	alt_wanted_tiny="${SB_TINY_ALT_WANTED}"
	if [ x"${pkg}" != x"${SB_NAME}" ]; then
		wanted_major="${WEB_MAJOR_WANTED}"
		wanted_minor="${WEB_MINOR_WANTED}"
		wanted_tiny="${WEB_TINY_WANTED}"
		alt_wanted_major="${WEB_MAJOR_ALT_WANTED}"
		alt_wanted_minor="${WEB_MINOR_ALT_WANTED}"
		alt_wanted_tiny="${WEB_TINY_ALT_WANTED}"
	fi

	if [ ${major} -lt ${wanted_major} ] ||
		[ ${major} -eq ${wanted_major} -a ${minor} -lt ${wanted_minor} ] ||
		[ ${major} -eq ${wanted_major} -a ${minor} -eq ${wanted_minor} -a ${tiny} -lt ${wanted_tiny} ]; then

		if [ ${major} -lt ${alt_wanted_major} ] ||
			[ ${major} -eq ${alt_wanted_major} -a ${minor} -lt ${alt_wanted_minor} ] ||
			[ ${major} -eq ${alt_wanted_major} -a ${minor} -eq ${alt_wanted_minor} -a ${tiny} -lt ${alt_wanted_tiny} ]; then
			return 0
		fi
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
		log "No obvious indicators of vulnerability to ${CVES} found."
		RETVAL=0
	fi

	if [ -n "${SUSPECT_JARS}" ]; then
		echo
		echo "The following archives of likely vulnerable versions were found:"
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
